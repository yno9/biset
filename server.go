package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"biset/vault"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/webdav"
)

func startJMAPServer(cfg *vault.Config, pgpKey string) {
	srv := cfg.Server
	port := srv.Port
	bind := srv.Bind

	accountID := filepath.Base(cfg.Vault)

	hub := &sseHub{subs: map[chan string]bool{}}
	go watchVaultDir(cfg.Vault, hub)

	password := srv.Password
	nodeName := srv.RelayName
	checkAuth := func(r *http.Request) bool {
		if password == "" {
			return true
		}
		a := r.Header.Get("Authorization")
		if strings.HasPrefix(a, "Bearer ") {
			return strings.TrimPrefix(a, "Bearer ") == password
		}
		if user, pass, ok := r.BasicAuth(); ok {
			if nodeName != "" && user != nodeName {
				return false
			}
			return pass == password
		}
		return false
	}
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !checkAuth(r) {
				w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Header().Set("X-Vault-Name", accountID)
			next.ServeHTTP(w, r)
		})
	}

	// WKD public key
	var wkdPubKey []byte
	if pgpKey != "" {
		block, err := armor.Decode(bytes.NewBufferString(pgpKey))
		if err == nil {
			if entities, err := openpgp.ReadKeyRing(block.Body); err == nil && len(entities) > 0 {
				wkdPubKey = pgpPublicKeyBytes(entities[0])
			}
		}
	}

	uiPath := resolveUI(cfg.Server.Interface, cfg.Vault)

	davHandler := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: namedRootFS{webdav.Dir(cfg.Vault), accountID},
		LockSystem: webdav.NewMemLS(),
	}

	mux := http.NewServeMux()

	// ── WKD ──────────────────────────────────────────────────────────────────
	mux.HandleFunc("/.well-known/openpgpkey/policy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	if len(wkdPubKey) > 0 {
		mux.HandleFunc("/.well-known/openpgpkey/hu/", func(w http.ResponseWriter, r *http.Request) {
			hash := strings.TrimPrefix(r.URL.Path, "/.well-known/openpgpkey/hu/")
			localpart := r.URL.Query().Get("l")
			if localpart != "" && wkdHash(localpart) != hash {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Write(wkdPubKey) //nolint:errcheck
		})
	}

	// ── JMAP / DAV / UI ───────────────────────────────────────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || uiPath == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, uiPath)
	})
	mux.HandleFunc("/dav/", davHandler.ServeHTTP)
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"name": accountID}, 200)
	})
	handler := &jmapHandler{vaultDir: cfg.Vault, accountID: accountID}

	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		handler.serveSession(w, r, port)
	})
	mux.HandleFunc("/jmap/api/", handler.serveAPI)
	mux.HandleFunc("/jmap/eventsource/", func(w http.ResponseWriter, r *http.Request) {
		serveEventSource(w, r, hub)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		serveDovecotEvents(w, r, hub)
	})

	addr := fmt.Sprintf("%s:%d", bind, port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: authMiddleware(mux),
	}
	log.Printf("[jmap] listening on %s  vault=%s", addr, cfg.Vault)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("jmap: %v", err)
	}
}

// ── JMAP handler ──────────────────────────────────────────────────────────────

type jmapHandler struct {
	vaultDir  string
	accountID string
}

func (s *jmapHandler) serveSession(w http.ResponseWriter, r *http.Request, port int) {
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%d", port)
	}
	writeJSON(w, map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":         50_000_000,
				"maxConcurrentUpload":   4,
				"maxSizeRequest":        10_000_000,
				"maxConcurrentRequests": 4,
				"maxCallsInRequest":     16,
				"maxObjectsInGet":       500,
				"maxObjectsInSet":       500,
				"collationAlgorithms":   []string{},
			},
			"urn:ietf:params:jmap:mail": map[string]any{
				"maxMailboxesPerEmail":       nil,
				"maxMailboxDepth":            nil,
				"maxSizeMailboxName":         200,
				"maxDescendantMailboxes":     nil,
				"mayCreateTopLevelMailbox":   false,
				"maxSizeAttachmentsPerEmail": 50_000_000,
				"emailQuerySortOptions":      []string{"receivedAt"},
			},
			"urn:ietf:params:jmap:submission": map[string]any{
				"maxDelayedSend":       0,
				"submissionExtensions": map[string]any{},
			},
		},
		"accounts": map[string]any{
			s.accountID: map[string]any{
				"name":       s.accountID,
				"isPersonal": true,
				"isReadOnly": false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":       map[string]any{},
					"urn:ietf:params:jmap:submission": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]any{
			"urn:ietf:params:jmap:mail":       s.accountID,
			"urn:ietf:params:jmap:submission": s.accountID,
		},
		"username":       s.accountID,
		"apiUrl":         "/jmap/api/",
		"eventSourceUrl": "/jmap/eventsource/?types=*&closeAfter=no&ping=30",
		"uploadUrl":      "/jmap/upload/{accountId}/",
		"downloadUrl":    "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"state":          "1",
	}, 200)
}

func (s *jmapHandler) serveAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		MethodCalls [][]any `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	var results [][]any
	byID := map[string]any{}

	for _, call := range req.MethodCalls {
		if len(call) < 3 {
			continue
		}
		method, _ := call[0].(string)
		args := resolveRefs(call[1], byID)
		callID, _ := call[2].(string)

		var result map[string]any
		switch method {
		case "Mailbox/get":
			result = s.serveMailboxGet(args)
		case "Email/query":
			result = s.serveEmailQuery(args)
		case "Email/get":
			result = s.serveEmailGet(args)
		case "Email/set":
			result = s.serveEmailSet(args)
		case "Thread/get":
			result = s.serveThreadGet(args)
		case "Identity/get":
			result = s.serveIdentityGet()
		default:
			result = map[string]any{"type": "unknownMethod", "description": "not implemented: " + method}
			method = "error"
		}

		byID[callID] = result
		results = append(results, []any{method, result, callID})
	}

	if results == nil {
		results = [][]any{}
	}
	writeJSON(w, map[string]any{"methodResponses": results, "sessionState": "1"}, 200)
}

// ── JMAP methods ──────────────────────────────────────────────────────────────

func (s *jmapHandler) serveMailboxGet(args map[string]any) map[string]any {
	mailboxes := vault.GetInboxes(s.vaultDir)
	if idsRaw, ok := args["ids"]; ok && idsRaw != nil {
		if ids := toStringSlice(idsRaw); ids != nil {
			set := toSet(ids)
			var filtered []vault.Inbox
			for _, m := range mailboxes {
				if set[string(m.ID)] {
					filtered = append(filtered, m)
				}
			}
			mailboxes = filtered
		}
	}
	return map[string]any{
		"accountId": s.accountID,
		"state":     "1",
		"list":      orEmpty(mailboxes),
		"notFound":  []string{},
	}
}

func (s *jmapHandler) serveEmailQuery(args map[string]any) map[string]any {
	mailboxID := ""
	if filter, ok := args["filter"].(map[string]any); ok {
		mailboxID, _ = filter["inMailbox"].(string)
	}
	position := 0
	if p, ok := args["position"].(float64); ok {
		position = int(p)
	}
	limit := 0
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}
	ids, total := vault.QueryMessageIDs(s.vaultDir, mailboxID, position, limit)
	return map[string]any{
		"accountId":           s.accountID,
		"queryState":          "1",
		"canCalculateChanges": false,
		"position":            position,
		"total":               total,
		"ids":                 ids,
	}
}

func (s *jmapHandler) serveEmailGet(args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	propsRaw, _ := args["properties"].([]any)
	want := map[string]bool{}
	if len(propsRaw) == 0 {
		want["*"] = true
	} else {
		for _, p := range propsRaw {
			if str, ok := p.(string); ok {
				want[str] = true
			}
		}
	}
	has := func(p string) bool { return want["*"] || want[p] }

	var list []map[string]any
	var notFound []string
	for _, idRaw := range idsRaw {
		id, _ := idRaw.(string)
		e, err := vault.ReadMessage(s.vaultDir, vault.ID(id))
		if err != nil {
			notFound = append(notFound, id)
			continue
		}
		obj := map[string]any{"id": e.ID}
		if has("threadId") {
			obj["threadId"] = e.ThreadID
		}
		if has("mailboxIds") {
			obj["mailboxIds"] = e.MailboxIDs
		}
		if has("keywords") {
			obj["keywords"] = e.Keywords
		}
		if has("subject") {
			obj["subject"] = e.Subject
		}
		if has("from") {
			obj["from"] = e.From
		}
		if has("to") {
			obj["to"] = orEmpty(e.To)
		}
		if has("cc") {
			obj["cc"] = orEmpty(e.CC)
		}
		if has("receivedAt") {
			obj["receivedAt"] = vault.TimeVal(e.ReceivedAt).UTC().Format(time.RFC3339)
		}
		if has("messageId") {
			obj["messageId"] = orEmptyStrings(e.MessageID)
		}
		if has("inReplyTo") {
			obj["inReplyTo"] = orEmptyStrings(e.InReplyTo)
		}
		if has("preview") {
			obj["preview"] = e.Preview
		}
		if has("size") {
			obj["size"] = e.Size
		}
		if has("bodyValues") || has("textBody") {
			obj["bodyValues"] = e.BodyValues
			obj["textBody"] = orEmpty(e.TextBody)
			obj["htmlBody"] = []vault.BodyPart{}
		}
		list = append(list, obj)
	}
	return map[string]any{
		"accountId": s.accountID,
		"state":     "1",
		"list":      orEmpty(list),
		"notFound":  orEmptyStrings(notFound),
	}
}

func (s *jmapHandler) serveEmailSet(args map[string]any) map[string]any {
	created := map[string]any{}
	notCreated := map[string]any{}
	if createMap, ok := args["create"].(map[string]any); ok {
		for createID, raw := range createMap {
			obj, _ := raw.(map[string]any)
			if obj == nil {
				notCreated[createID] = map[string]any{"type": "invalidArguments"}
				continue
			}
			emailID, err := handleEmailCreate(s.vaultDir, obj)
			if err != nil {
				log.Printf("[jmap] Email/set create %q: %v", createID, err)
				notCreated[createID] = map[string]any{"type": "serverFail", "description": err.Error()}
			} else {
				created[createID] = map[string]any{"id": emailID}
			}
		}
	}
	updated := map[string]any{}
	if m, ok := args["update"].(map[string]any); ok {
		for id := range m {
			updated[id] = map[string]any{}
		}
	}
	return map[string]any{
		"accountId":    s.accountID,
		"oldState":     "1",
		"newState":     "2",
		"created":      created,
		"updated":      updated,
		"destroyed":    []string{},
		"notCreated":   notCreated,
		"notUpdated":   map[string]any{},
		"notDestroyed": map[string]any{},
	}
}

func handleEmailCreate(vaultDir string, obj map[string]any) (string, error) {
	mbxIDs, _ := obj["mailboxIds"].(map[string]any)
	inboxKey := ""
	for mbxID := range mbxIDs {
		inboxKey = vault.InboxKeyFromMailboxID(mbxID)
		break
	}
	if inboxKey == "" {
		return "", fmt.Errorf("mailboxIds required")
	}

	contact := ""
	if toRaw, ok := obj["to"].([]any); ok && len(toRaw) > 0 {
		if toObj, ok := toRaw[0].(map[string]any); ok {
			contact, _ = toObj["email"].(string)
		}
	}
	if contact == "" {
		return "", fmt.Errorf("to required")
	}

	body := ""
	bodyValues, _ := obj["bodyValues"].(map[string]any)
	if textBodyRaw, ok := obj["textBody"].([]any); ok && len(textBodyRaw) > 0 {
		if tbObj, ok := textBodyRaw[0].(map[string]any); ok {
			partID, _ := tbObj["partId"].(string)
			if bv, ok := bodyValues[partID].(map[string]any); ok {
				body, _ = bv["value"].(string)
			}
		}
	}

	inReplyTo := ""
	if irt, ok := obj["inReplyTo"].([]any); ok && len(irt) > 0 {
		inReplyTo, _ = irt[0].(string)
	}

	threadID, _ := obj["threadId"].(string)
	subject, _ := obj["subject"].(string)

	return vault.CreateDraftMD(vaultDir, inboxKey, contact, subject, body, threadID, inReplyTo)
}

func (s *jmapHandler) serveThreadGet(args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	var list []map[string]any
	var notFound []string
	for _, idRaw := range idsRaw {
		id, _ := idRaw.(string)
		t, err := vault.ReadThread(s.vaultDir, vault.ID(id))
		if err != nil {
			notFound = append(notFound, id)
			continue
		}
		list = append(list, map[string]any{"id": t.ID, "emailIds": t.EmailIDs})
	}
	return map[string]any{
		"accountId": s.accountID,
		"state":     "1",
		"list":      orEmpty(list),
		"notFound":  orEmptyStrings(notFound),
	}
}

func (s *jmapHandler) serveIdentityGet() map[string]any {
	return map[string]any{
		"accountId": s.accountID,
		"state":     "1",
		"list":      orEmpty(vault.GetIdentities(s.vaultDir)),
		"notFound":  []string{},
	}
}

// ── SSE hub ───────────────────────────────────────────────────────────────────

type sseHub struct {
	mu   sync.Mutex
	subs map[chan string]bool
}

func (h *sseHub) subscribe() chan string {
	ch := make(chan string, 8)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *sseHub) unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *sseHub) notify() {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- "changed":
		default:
		}
	}
	h.mu.Unlock()
}

func serveEventSource(w http.ResponseWriter, r *http.Request, hub *sseHub) {
	log.Printf("[sse] client connected from %s", r.RemoteAddr)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)
	fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ch:
			fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

func serveDovecotEvents(w http.ResponseWriter, r *http.Request, hub *sseHub) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(200)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ch:
			fmt.Fprint(w, "event: change\ndata: \n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}

// ── vault watcher ─────────────────────────────────────────────────────────────

func watchVaultDir(vaultDir string, hub *sseHub) {
	for {
		if err := watchVaultOnce(vaultSubdirs(vaultDir), hub); err != nil {
			log.Printf("[jmap] watch: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func vaultSubdirs(vaultDir string) []string {
	dirs := []string{vaultDir}
	entries, _ := os.ReadDir(vaultDir)
	for _, e := range entries {
		if e.IsDir() {
			sub := filepath.Join(vaultDir, e.Name())
			dirs = append(dirs, sub)
			subs, _ := os.ReadDir(sub)
			for _, s := range subs {
				if s.IsDir() {
					dirs = append(dirs, filepath.Join(sub, s.Name()))
				}
			}
		}
	}
	return dirs
}

func watchVaultOnce(dirs []string, hub *sseHub) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	for _, dir := range dirs {
		os.MkdirAll(dir, 0755) //nolint:errcheck
		if err := w.Add(dir); err != nil {
			return err
		}
	}

	var debounce *time.Timer
	fire := func() {
		if debounce != nil {
			debounce.Stop()
		}
		debounce = time.AfterFunc(200*time.Millisecond, hub.notify)
	}

	for {
		select {
		case e, ok := <-w.Events:
			if !ok {
				return nil
			}
			if e.Has(fsnotify.Write) || e.Has(fsnotify.Create) {
				fire()
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			log.Printf("[jmap] watcher error: %v", err)
		}
	}
}

// ── WebDAV ────────────────────────────────────────────────────────────────────

type namedRootFS struct {
	webdav.FileSystem
	rootName string
}

func (fs namedRootFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fi, err := fs.FileSystem.Stat(ctx, name)
	if err != nil || name != "/" {
		return fi, err
	}
	return namedFileInfo{fi, fs.rootName}, nil
}

type namedFileInfo struct {
	os.FileInfo
	name string
}

func (fi namedFileInfo) Name() string { return fi.name }

// ── WKD ───────────────────────────────────────────────────────────────────────

func wkdHash(localpart string) string {
	h := sha1.Sum([]byte(strings.ToLower(localpart)))
	const alpha = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var sb strings.Builder
	bits, cur := 0, 0
	for _, b := range h {
		cur = (cur << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alpha[(cur>>bits)&0x1f])
		}
	}
	if bits > 0 {
		sb.WriteByte(alpha[(cur<<(5-bits))&0x1f])
	}
	return sb.String()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func resolveUI(interfacePath, vaultDir string) string {
	if exe, err := os.Executable(); err == nil {
		if c := filepath.Join(filepath.Dir(exe), "index.html"); fileExists(c) {
			return c
		}
	}
	if c := filepath.Join(filepath.Dir(vaultDir), "index.html"); fileExists(c) {
		return c
	}
	if interfacePath != "" {
		if c, err := expandHome(interfacePath); err == nil && fileExists(c) {
			return c
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[2:]), nil
}

func writeJSON(w http.ResponseWriter, data any, status int) {
	b, _ := json.Marshal(data)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b) //nolint:errcheck
}

func resolveRefs(raw any, results map[string]any) map[string]any {
	args, _ := raw.(map[string]any)
	out := make(map[string]any, len(args))
	for k, v := range args {
		if strings.HasPrefix(k, "#") {
			ref, _ := v.(map[string]any)
			resultOf, _ := ref["resultOf"].(string)
			path, _ := ref["path"].(string)
			if prev, ok := results[resultOf]; ok {
				if resolved := resolvePath(prev, path); resolved != nil {
					out[strings.TrimPrefix(k, "#")] = resolved
				}
			}
		} else {
			out[k] = v
		}
	}
	return out
}

func resolvePath(obj any, path string) any {
	cur := obj
	for _, p := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if p == "" {
			continue
		}
		switch v := cur.(type) {
		case map[string]any:
			cur = v[p]
		case []any:
			var flat []any
			for _, elem := range v {
				if m, ok := elem.(map[string]any); ok {
					if val := m[p]; val != nil {
						if arr, ok := val.([]any); ok {
							flat = append(flat, arr...)
						} else {
							flat = append(flat, val)
						}
					}
				}
			}
			cur = flat
		default:
			return nil
		}
	}
	return cur
}

func toStringSlice(v any) []string {
	arr, _ := v.([]any)
	if arr == nil {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
