package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/yd7a/biset/core"
	"golang.org/x/net/webdav"
)

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

// ── runServe ──────────────────────────────────────────────────────────────────

func runServe(cfg *Config, port int, token string) error {
	return runServeContext(context.Background(), cfg, port, token)
}

func runServeContext(ctx context.Context, cfg *Config, port int, token string) error {
	hub := &sseHub{subs: map[chan string]bool{}}

	go watchVaultDir(cfg.Vault, hub)

	auth := func(r *http.Request) bool {
		if token == "" {
			return true
		}
		return r.Header.Get("Authorization") == "Bearer "+token
	}

	// ui: look for index.html next to binary, then ~/biset-ui/dist/
	uiPath := ""
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "index.html")
		if _, err := os.Stat(candidate); err == nil {
			uiPath = candidate
		}
	}
	if uiPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			candidate := filepath.Join(home, "biset-ui", "dist", "index.html")
			if _, err := os.Stat(candidate); err == nil {
				uiPath = candidate
			}
		}
	}

	davHandler := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: webdav.Dir(cfg.Vault),
		LockSystem: webdav.NewMemLS(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || uiPath == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, uiPath)
	})
	mux.HandleFunc("/dav/", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) { http.Error(w, "unauthorized", 401); return }
		davHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) { http.Error(w, "unauthorized", 401); return }
		serveSession(w, r, port)
	})
	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) { http.Error(w, "unauthorized", 401); return }
		serveAPI(w, r, cfg.Vault)
	})
	mux.HandleFunc("/jmap/eventsource/", func(w http.ResponseWriter, r *http.Request) {
		if !auth(r) { http.Error(w, "unauthorized", 401); return }
		serveEventSource(w, r, hub)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		serveDoucotEvents(w, r, hub)
	})

	srv := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background()) //nolint:errcheck
	}()

	log.Printf("[serve] JMAP listening on %s  vault=%s", srv.Addr, cfg.Vault)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ── session ───────────────────────────────────────────────────────────────────

func serveSession(w http.ResponseWriter, r *http.Request, port int) {
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
			"biset": map[string]any{
				"name":       "biset",
				"isPersonal": true,
				"isReadOnly": false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":       map[string]any{},
					"urn:ietf:params:jmap:submission": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]any{
			"urn:ietf:params:jmap:mail":       "biset",
			"urn:ietf:params:jmap:submission": "biset",
		},
		"username":       "biset",
		"apiUrl":         "/jmap/api/",
		"eventSourceUrl": "/jmap/eventsource/?types=*&closeAfter=no&ping=30",
		"uploadUrl":      "/jmap/upload/{accountId}/",
		"downloadUrl":    "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"state":          "1",
	}, 200)
}

// ── API ───────────────────────────────────────────────────────────────────────

func serveAPI(w http.ResponseWriter, r *http.Request, vaultDir string) {
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
			result = serveMailboxGet(vaultDir, args)
		case "Email/query":
			result = serveEmailQuery(vaultDir, args)
		case "Email/get":
			result = serveEmailGet(vaultDir, args)
		case "Email/set":
			result = serveEmailSet(vaultDir, args)
		case "Thread/get":
			result = serveThreadGet(vaultDir, args)
		case "Identity/get":
			result = serveIdentityGet(vaultDir)
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

// ── method implementations ────────────────────────────────────────────────────

func serveMailboxGet(vaultDir string, args map[string]any) map[string]any {
	mailboxes := core.ReadMailboxes(vaultDir)
	if len(mailboxes) == 0 {
		// fallback: derive from inbox dirs
		entries, _ := os.ReadDir(vaultDir)
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
				mailboxes = append(mailboxes, core.DefaultMailbox(e.Name()))
			}
		}
	}

	if idsRaw, ok := args["ids"]; ok && idsRaw != nil {
		ids := toStringSlice(idsRaw)
		if ids != nil {
			set := toSet(ids)
			var filtered []core.Mailbox
			for _, m := range mailboxes {
				if set[m.ID] {
					filtered = append(filtered, m)
				}
			}
			mailboxes = filtered
		}
	}
	if mailboxes == nil {
		mailboxes = []core.Mailbox{}
	}
	return map[string]any{
		"accountId": "biset",
		"state":     "1",
		"list":      mailboxes,
		"notFound":  []string{},
	}
}

func serveEmailQuery(vaultDir string, args map[string]any) map[string]any {
	emails, _ := core.ScanEmails(vaultDir)

	inboxFilter := ""
	if filter, ok := args["filter"].(map[string]any); ok {
		if v, ok := filter["inMailbox"].(string); ok {
			inboxFilter = v
		}
	}

	type entry struct {
		id         string
		receivedAt time.Time
	}
	var list []entry
	for _, e := range emails {
		if inboxFilter != "" && !e.MailboxIDs[inboxFilter] {
			continue
		}
		list = append(list, entry{e.ID, e.ReceivedAt})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].receivedAt.After(list[j].receivedAt)
	})

	position := 0
	if p, ok := args["position"].(float64); ok {
		position = int(p)
	}
	limit := len(list)
	if l, ok := args["limit"].(float64); ok && int(l) < limit {
		limit = int(l)
	}
	end := position + limit
	if end > len(list) {
		end = len(list)
	}
	if position > len(list) {
		position = len(list)
	}

	ids := make([]string, 0, end-position)
	for _, e := range list[position:end] {
		ids = append(ids, e.id)
	}
	return map[string]any{
		"accountId":           "biset",
		"queryState":          "1",
		"canCalculateChanges": false,
		"position":            position,
		"total":               len(list),
		"ids":                 ids,
	}
}

func serveEmailGet(vaultDir string, args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	propsRaw, _ := args["properties"].([]any)
	want := map[string]bool{}
	if len(propsRaw) == 0 {
		want["*"] = true
	} else {
		for _, p := range propsRaw {
			if s, ok := p.(string); ok {
				want[s] = true
			}
		}
	}
	has := func(p string) bool { return want["*"] || want[p] }

	var list []map[string]any
	var notFound []string
	for _, idRaw := range idsRaw {
		id, _ := idRaw.(string)
		e, err := core.ReadEmail(vaultDir, id)
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
			obj["cc"] = orEmpty(e.Cc)
		}
		if has("receivedAt") {
			obj["receivedAt"] = e.ReceivedAt.UTC().Format(time.RFC3339)
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
			obj["htmlBody"] = []core.BodyPart{}
		}
		list = append(list, obj)
	}
	return map[string]any{
		"accountId": "biset",
		"state":     "1",
		"list":      orEmpty(list),
		"notFound":  orEmptyStrings(notFound),
	}
}

func serveEmailSet(vaultDir string, args map[string]any) map[string]any {
	created := map[string]any{}
	notCreated := map[string]any{}
	if createMap, ok := args["create"].(map[string]any); ok {
		for createID, raw := range createMap {
			obj, _ := raw.(map[string]any)
			if obj == nil {
				notCreated[createID] = map[string]any{"type": "invalidArguments"}
				continue
			}
			emailID, err := handleEmailCreate(vaultDir, obj)
			if err != nil {
				log.Printf("[serve] Email/set create %q: %v", createID, err)
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
		"accountId":    "biset",
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
	// mailboxIds → inboxKey
	mbxIDs, _ := obj["mailboxIds"].(map[string]any)
	inboxKey := ""
	for mbxID := range mbxIDs {
		inboxKey = core.InboxKeyFromMailboxID(mbxID)
		break
	}
	if inboxKey == "" {
		return "", fmt.Errorf("mailboxIds required")
	}

	// to → contact
	contact := ""
	if toRaw, ok := obj["to"].([]any); ok && len(toRaw) > 0 {
		if toObj, ok := toRaw[0].(map[string]any); ok {
			contact, _ = toObj["email"].(string)
		}
	}
	if contact == "" {
		return "", fmt.Errorf("to required")
	}

	// bodyValues + textBody → body text
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

	// inReplyTo
	inReplyTo := ""
	if irt, ok := obj["inReplyTo"].([]any); ok && len(irt) > 0 {
		inReplyTo, _ = irt[0].(string)
	}

	// find threadId: explicit or via inReplyTo lookup
	threadID, _ := obj["threadId"].(string)
	if threadID == "" && inReplyTo != "" {
		emails, _ := core.ScanEmails(vaultDir)
	outer:
		for _, e := range emails {
			for _, msgID := range e.MessageID {
				if msgID == inReplyTo {
					threadID = e.ThreadID
					break outer
				}
			}
		}
	}

	inboxDir := filepath.Join(vaultDir, inboxKey)
	if err := os.MkdirAll(inboxDir, 0755); err != nil {
		return "", err
	}

	mdPath := ""
	if threadID != "" {
		if emails := core.ReadEmailsForThread(vaultDir, threadID); len(emails) > 0 {
			mdPath = core.FindThreadMD(inboxDir, core.ThreadShortID(emails))
		}
	}

	if mdPath != "" {
		// update existing MD: inject body + status: send
		b, err := os.ReadFile(mdPath)
		if err != nil {
			return "", err
		}
		content := setFMField(string(b), "status", "send")
		content = core.InjectBody(content, body)
		if err := os.WriteFile(mdPath, []byte(content), 0644); err != nil {
			return "", err
		}
	} else {
		// create new MD
		subject, _ := obj["subject"].(string)
		if threadID == "" {
			threadID = fmt.Sprintf("thr-ts-%d", time.Now().UnixMilli())
		}
		mbxID := core.MakeMailboxID(inboxKey)
		filename := fmt.Sprintf("%s_%s.md", core.SafeFilename(contact), time.Now().Local().Format("01021504"))
		mdPath = filepath.Join(inboxDir, filename)
		fm := fmt.Sprintf("---\nsubject: \"%s\"\ncontact: %s\nmailboxId: %s\nthreadId: %s\nprotocol: smtp\nseen: true\nstatus: send\n---\n%s\n\n",
			strings.ReplaceAll(subject, `"`, `\"`), contact, mbxID, threadID, body)
		if err := os.WriteFile(mdPath, []byte(fm), 0644); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("eml-draft-%d", time.Now().UnixMilli()), nil
}

func setFMField(content, key, value string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, key+":") {
			lines[i] = key + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func serveThreadGet(vaultDir string, args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	var list []map[string]any
	var notFound []string
	for _, idRaw := range idsRaw {
		id, _ := idRaw.(string)
		t, err := core.ReadThread(vaultDir, id)
		if err != nil {
			notFound = append(notFound, id)
			continue
		}
		list = append(list, map[string]any{"id": t.ID, "emailIds": t.EmailIDs})
	}
	return map[string]any{
		"accountId": "biset",
		"state":     "1",
		"list":      orEmpty(list),
		"notFound":  orEmptyStrings(notFound),
	}
}

func serveIdentityGet(vaultDir string) map[string]any {
	entries, _ := os.ReadDir(vaultDir)
	var list []core.Identity
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			list = append(list, core.Identity{
				ID:        "id-" + e.Name(),
				Name:      e.Name(),
				Email:     e.Name(),
				MayDelete: false,
			})
		}
	}
	return map[string]any{
		"accountId": "biset",
		"state":     "1",
		"list":      orEmpty(list),
		"notFound":  []string{},
	}
}

// ── EventSource ───────────────────────────────────────────────────────────────

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
			log.Printf("[sse] sending state event")
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

// serveDoucotEvents serves an SSE stream for doucot WebDAV mode.
// Sends "event: change\ndata: \n\n" whenever vault files change.
func serveDoucotEvents(w http.ResponseWriter, r *http.Request, hub *sseHub) {
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
		if err := watchOnce(vaultDirs(vaultDir), hub); err != nil {
			log.Printf("[serve] watch: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func vaultDirs(vaultDir string) []string {
	dirs := []string{vaultDir}
	entries, _ := os.ReadDir(vaultDir)
	for _, e := range entries {
		if e.IsDir() {
			sub := filepath.Join(vaultDir, e.Name())
			dirs = append(dirs, sub)
			// one more level deep (e.g. .data/emails/)
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

func watchOnce(dirs []string, hub *sseHub) error {
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

	// debounce: coalesce bursts into a single notify
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
			log.Printf("[serve] watcher error: %v", err)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

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
