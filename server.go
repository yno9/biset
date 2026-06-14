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

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/fsnotify/fsnotify"
	jmapserver "github.com/yno9/go-jmapserver"
	"golang.org/x/net/webdav"
)

func startJMAPServer(ctx context.Context, cfg *vault.Config, pgpKey string, store *jmapserver.Store) {
	srv := cfg.Server
	port := srv.Port
	bind := srv.Bind
	accountID := filepath.Base(cfg.Vault)

	jmapHub := jmapserver.NewHub()
	dovecotHub := &notifyHub{subs: map[chan struct{}]bool{}}
	go watchVaultDir(cfg.Vault, func() {
		jmapHub.Notify()
		dovecotHub.notify()
	})

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

	// go-jmapserver handles: /.well-known/jmap, /jmap/api/, /jmap/eventsource/
	handler := &jmapHandler{vaultDir: cfg.Vault, accountID: jmap.ID(accountID), store: store}
	jmapCfg := jmapserver.Config{Port: port, Bind: bind}
	mux := jmapserver.NewMux(jmapCfg, handler, jmapHub)

	// ── extra routes ──────────────────────────────────────────────────────────
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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || uiPath == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, uiPath)
	})
	mux.HandleFunc("/dav/", davHandler.ServeHTTP)
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(map[string]any{"name": accountID})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b) //nolint:errcheck
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		serveDovecotEvents(w, r, dovecotHub)
	})

	addr := fmt.Sprintf("%s:%d", bind, port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: authMiddleware(mux),
	}
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background()) //nolint:errcheck
	}()
	log.Printf("[jmap] listening on %s  vault=%s", addr, cfg.Vault)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[jmap] stopped: %v", err)
	}
}

// ── JMAP handler ──────────────────────────────────────────────────────────────

// jmapHandler implements jmapserver.Handler. It serves the biset JMAP server
// (toward dovecot / UI clients) using go-jmapserver Store for all mail methods.
type jmapHandler struct {
	vaultDir  string
	accountID jmap.ID
	store     *jmapserver.Store
}

func (s *jmapHandler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (s *jmapHandler) Accounts() []jmapserver.Account {
	return []jmapserver.Account{{ID: s.accountID, Name: string(s.accountID)}}
}

func (s *jmapHandler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Mailbox/get":
		return s.store.HandleMailboxGet(s.accountID, args)
	case "Mailbox/changes":
		return s.store.HandleMailboxChanges(s.accountID, args)
	case "Email/query":
		return s.store.HandleEmailQuery(s.accountID, args)
	case "Email/queryChanges":
		return s.store.HandleQueryChanges(s.accountID, args)
	case "Email/changes":
		return s.store.HandleEmailChanges(s.accountID, args)
	case "Email/get":
		return s.store.HandleEmailGet(s.accountID, args)
	case "Email/set":
		return s.serveEmailSet(args)
	case "Thread/get":
		return s.store.HandleThreadGet(s.accountID, args)
	case "Thread/changes":
		return s.store.HandleThreadChanges(s.accountID, args)
	case "Identity/get":
		return s.serveIdentityGet(), nil
	case "Identity/changes":
		return s.store.HandleIdentityChanges(s.accountID, args)
	default:
		return s.store.Dispatch(s.accountID, method, args)
	}
}

// ── JMAP methods ─────────────────────────────────────────────────────────────

// serveEmailSet handles Email/set: create (biset-specific draft MD), update (flag patches), destroy.
func (s *jmapHandler) serveEmailSet(args json.RawMessage) (any, error) {
	var req struct {
		Create  map[string]json.RawMessage `json:"create"`
		Update  map[string]json.RawMessage `json:"update"`
		Destroy []jmap.ID                  `json:"destroy"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	oldState := s.store.State()
	created := map[string]any{}
	notCreated := map[string]any{}
	for createID, raw := range req.Create {
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
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

	updated := map[string]any{}
	notUpdated := map[string]any{}
	for id, raw := range req.Update {
		var patch map[string]any
		if json.Unmarshal(raw, &patch) != nil {
			notUpdated[id] = map[string]any{"type": "invalidArguments"}
			continue
		}
		if err := s.store.PatchKeywords(jmap.ID(id), patch); err != nil {
			notUpdated[id] = map[string]any{"type": "serverFail", "description": err.Error()}
		} else {
			updated[id] = map[string]any{}
		}
	}

	notDestroyed := map[string]any{}
	for _, id := range req.Destroy {
		s.store.Delete(id)
		vault.DeleteMessage(s.vaultDir, id) //nolint:errcheck
	}

	return map[string]any{
		"accountId":    s.accountID,
		"oldState":     oldState,
		"newState":     s.store.State(),
		"created":      created,
		"updated":      updated,
		"destroyed":    orEmpty(req.Destroy),
		"notCreated":   notCreated,
		"notUpdated":   notUpdated,
		"notDestroyed": notDestroyed,
	}, nil
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

func (s *jmapHandler) serveIdentityGet() map[string]any {
	return map[string]any{
		"accountId": s.accountID,
		"state":     "1",
		"list":      orEmpty(vault.GetIdentities(s.vaultDir)),
		"notFound":  []string{},
	}
}

// ── SSE hub ───────────────────────────────────────────────────────────────────

// notifyHub is a lightweight SSE broadcaster for non-JMAP endpoints (dovecot).
type notifyHub struct {
	mu   sync.Mutex
	subs map[chan struct{}]bool
}

func (h *notifyHub) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *notifyHub) unsubscribe(ch chan struct{}) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *notifyHub) notify() {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

func serveDovecotEvents(w http.ResponseWriter, r *http.Request, hub *notifyHub) {
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

func watchVaultDir(vaultDir string, notify func()) {
	for {
		if err := watchVaultOnce(vaultSubdirs(vaultDir), notify); err != nil {
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

func watchVaultOnce(dirs []string, notify func()) error {
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
		debounce = time.AfterFunc(200*time.Millisecond, notify)
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
