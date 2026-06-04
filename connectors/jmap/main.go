package main

import (
	"bufio"
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

	"github.com/yd7a/biset/core"
)

// ── Config ────────────────────────────────────────────────────────────────────

type Config struct {
	Vault   string `json:"vault"`
	Port    int    `json:"port"`
	Token   string `json:"token"`
	UIHtml  string `json:"ui_html"`  // path to biset-ui dist/index.html
	Account string `json:"account"`  // JMAP account ID (e.g. user@example.com)
}

var (
	cfg     Config
	cfgDir  string
	vaultMu sync.RWMutex
)

// ── JSON-RPC over stdio ───────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Method string `json:"method,omitempty"`
	Params any    `json:"params,omitempty"`
}

var (
	outMu sync.Mutex
	enc   = json.NewEncoder(os.Stdout)
)

func respond(id *int64, result any, err error) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id}
	if err != nil {
		resp.Error = &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{-32000, err.Error()}
	} else {
		resp.Result = result
	}
	outMu.Lock()
	enc.Encode(resp) //nolint:errcheck
	outMu.Unlock()
}

func notify(event string) {
	outMu.Lock()
	enc.Encode(rpcResponse{ //nolint:errcheck
		JSONRPC: "2.0",
		Method:  "notify",
		Params:  map[string]string{"event": event},
	})
	outMu.Unlock()
}

// ── Vault helpers ─────────────────────────────────────────────────────────────

// vaultThread represents a thread loaded from a vault JSON file.
type vaultThread struct {
	inboxKey string
	filePath string
	data     struct {
		Inbox  string `json:"inbox"`
		Status string `json:"status"`
		Reply  string `json:"reply"`
		Thread struct {
			ID       string `json:"thread_id"`
			LastTime string `json:"last_time"`
			Messages []struct {
				From      string            `json:"from"`
				FromName  string            `json:"from_name"`
				Body      string            `json:"body"`
				Time      string            `json:"time"`
				MessageID string            `json:"message_id"`
				ParentID  string            `json:"parent_id"`
				Meta      map[string]string `json:"meta"`
			} `json:"messages"`
		} `json:"thread"`
	}
}

func loadThread(path, inboxKey string) (*vaultThread, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t := &vaultThread{inboxKey: inboxKey, filePath: path}
	if err := json.Unmarshal(b, &t.data); err != nil {
		return nil, err
	}
	return t, nil
}

// scanVault returns all threads from vault JSON files.
func scanVault() ([]*vaultThread, error) {
	vaultMu.RLock()
	vaultDir := cfg.Vault
	vaultMu.RUnlock()

	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return nil, err
	}
	var threads []*vaultThread
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		inboxKey := e.Name()
		dataDir := filepath.Join(vaultDir, inboxKey, ".data")
		files, err := os.ReadDir(dataDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			t, err := loadThread(filepath.Join(dataDir, f.Name()), inboxKey)
			if err != nil {
				continue
			}
			threads = append(threads, t)
		}
	}
	return threads, nil
}

// threadToMessages converts a vaultThread to core.Message slice.
func (t *vaultThread) toMessages() []core.Message {
	msgs := make([]core.Message, 0, len(t.data.Thread.Messages))
	for _, m := range t.data.Thread.Messages {
		meta := m.Meta
		if meta == nil {
			meta = map[string]string{}
		}
		if m.FromName != "" {
			meta[core.MetaFromName] = m.FromName
		}
		var ts int64
		if pt, err := time.Parse(time.RFC3339, m.Time); err == nil {
			ts = pt.UnixMilli()
		}
		msgs = append(msgs, core.Message{
			From:      m.From,
			Body:      m.Body,
			Ts:        ts,
			MessageID: m.MessageID,
			ParentID:  m.ParentID,
			Meta:      meta,
		})
	}
	return msgs
}

// ── JSON-RPC handlers ─────────────────────────────────────────────────────────

func handleRequest(req rpcRequest) {
	switch req.Method {
	case "ping":
		respond(req.ID, "pong", nil)

	case "fetch":
		threads, err := scanVault()
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		var all []core.Message
		for _, t := range threads {
			all = append(all, t.toMessages()...)
		}
		if all == nil {
			all = []core.Message{}
		}
		respond(req.ID, map[string]any{"messages": all}, nil)

	case "handle":
		var params struct {
			Inbox     string `json:"inbox"`
			MessageID string `json:"message_id"`
			Action    string `json:"action"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			respond(req.ID, nil, err)
			return
		}
		err := handleAction(params.Inbox, params.MessageID, params.Action)
		respond(req.ID, map[string]any{}, err)

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}

func handleAction(inboxKey, messageID, action string) error {
	vaultMu.RLock()
	vaultDir := cfg.Vault
	vaultMu.RUnlock()

	// find MD file containing this messageID
	inboxDir := filepath.Join(vaultDir, inboxKey)
	files, err := os.ReadDir(inboxDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		path := filepath.Join(inboxDir, f.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(b)
		if messageID != "" && !strings.Contains(content, strings.Trim(messageID, "<>")) {
			continue
		}
		fm := core.ParseFrontmatter(content)
		if strings.TrimSpace(fm["status"]) == action {
			return nil
		}
		newContent := strings.Replace(content, "\nstatus: \n", "\nstatus: "+action+"\n", 1)
		if newContent == content {
			// try replacing non-empty status
			oldStatus := "status: " + strings.TrimSpace(fm["status"])
			newContent = strings.Replace(content, oldStatus, "status: "+action, 1)
		}
		return os.WriteFile(path, []byte(newContent), 0644)
	}
	return fmt.Errorf("message not found")
}

// ── fs.Watch → notify ─────────────────────────────────────────────────────────

func watchVault() {
	vaultMu.RLock()
	vaultDir := cfg.Vault
	vaultMu.RUnlock()

	for {
		if err := watchDir(vaultDir); err != nil {
			log.Printf("[jmap] watch: %v — retrying in 5s", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func watchDir(vaultDir string) error {
	// Use polling since fsnotify is not in go.mod; use os.Stat mtime tracking.
	// We'll use a simple approach: stat all .json files every 2s.
	seen := map[string]time.Time{}
	for {
		time.Sleep(2 * time.Second)
		changed := false
		entries, err := os.ReadDir(vaultDir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dataDir := filepath.Join(vaultDir, e.Name(), ".data")
			files, _ := os.ReadDir(dataDir)
			for _, f := range files {
				if !strings.HasSuffix(f.Name(), ".json") && !strings.HasSuffix(f.Name(), ".md") {
					continue
				}
				p := filepath.Join(dataDir, f.Name())
				fi, err := os.Stat(p)
				if err != nil {
					continue
				}
				if prev, ok := seen[p]; !ok || fi.ModTime().After(prev) {
					seen[p] = fi.ModTime()
					if ok {
						changed = true
					}
				}
			}
			// also watch MD files in inbox dir
			mdFiles, _ := os.ReadDir(filepath.Join(vaultDir, e.Name()))
			for _, f := range mdFiles {
				if !strings.HasSuffix(f.Name(), ".md") {
					continue
				}
				p := filepath.Join(vaultDir, e.Name(), f.Name())
				fi, err := os.Stat(p)
				if err != nil {
					continue
				}
				if prev, ok := seen[p]; !ok || fi.ModTime().After(prev) {
					seen[p] = fi.ModTime()
					if ok {
						changed = true
					}
				}
			}
		}
		if changed {
			notify("changed")
			invalidateCache()
			sseNotify("changed")
		}
	}
}

// ── SSE ───────────────────────────────────────────────────────────────────────

var (
	sseMu   sync.Mutex
	sseSubs = map[chan string]bool{}
)

func sseSubscribe() chan string {
	ch := make(chan string, 8)
	sseMu.Lock()
	sseSubs[ch] = true
	sseMu.Unlock()
	return ch
}

func sseUnsubscribe(ch chan string) {
	sseMu.Lock()
	delete(sseSubs, ch)
	sseMu.Unlock()
}

func sseNotify(msg string) {
	sseMu.Lock()
	for ch := range sseSubs {
		select {
		case ch <- msg:
		default:
		}
	}
	sseMu.Unlock()
}

// ── Cache ─────────────────────────────────────────────────────────────────────

var (
	cacheMu     sync.RWMutex
	htmlCache   []byte
	threadsCache []*vaultThread
	cacheValid  bool
)

func invalidateCache() {
	cacheMu.Lock()
	cacheValid = false
	cacheMu.Unlock()
}

func getThreads() ([]*vaultThread, error) {
	cacheMu.RLock()
	if cacheValid && threadsCache != nil {
		t := threadsCache
		cacheMu.RUnlock()
		return t, nil
	}
	cacheMu.RUnlock()

	threads, err := scanVault()
	if err != nil {
		return nil, err
	}

	cacheMu.Lock()
	threadsCache = threads
	cacheValid = true
	cacheMu.Unlock()
	return threads, nil
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, data any, status int) {
	b, _ := json.Marshal(data)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b) //nolint:errcheck
}

func authOK(r *http.Request) bool {
	if cfg.Token == "" {
		return true
	}
	return r.Header.Get("Authorization") == "Bearer "+cfg.Token
}

func serveUI(w http.ResponseWriter) {
	cacheMu.RLock()
	cached := htmlCache
	cacheMu.RUnlock()
	if cached != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(cached) //nolint:errcheck
		return
	}

	htmlPath := cfg.UIHtml
	if htmlPath == "" {
		// look relative to connector dir, then ~/biset-ui/dist/index.html
		candidates := []string{
			filepath.Join(cfgDir, "index.html"),
			filepath.Join(cfgDir, "..", "..", "..", "biset-ui", "dist", "index.html"),
		}
		if home, err := os.UserHomeDir(); err == nil {
			candidates = append(candidates, filepath.Join(home, "biset-ui", "dist", "index.html"))
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				htmlPath = c
				break
			}
		}
	}
	if htmlPath == "" {
		http.Error(w, "index.html not found — set ui_html in config.json or run: cd ~/biset-ui && npm run build", 503)
		return
	}

	html, err := os.ReadFile(htmlPath)
	if err != nil {
		http.Error(w, "index.html read error: "+err.Error(), 503)
		return
	}
	token := cfg.Token
	if token == "" {
		token = "1"
	}
	inject := fmt.Sprintf(`<script>window.__BISET_SERVE=%s;</script>`, jsonString(token))
	patched := string(html)
	if strings.Contains(patched, "</head>") {
		patched = strings.Replace(patched, "</head>", inject+"</head>", 1)
	} else {
		patched = inject + patched
	}
	buf := []byte(patched)

	cacheMu.Lock()
	htmlCache = buf
	cacheMu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf) //nolint:errcheck
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ── /api/* — biset-ui REST API (mirrors serve.mjs) ───────────────────────────

func apiHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(204)
		return
	}
	if !authOK(r) {
		jsonResp(w, map[string]any{"error": "unauthorized"}, 401)
		return
	}

	path := r.URL.Path

	switch {
	case path == "/api/ping":
		jsonResp(w, map[string]any{"mode": "serve", "vault": cfg.Vault}, 200)

	case path == "/api/list":
		files := listJSONFiles(cfg.Vault, "")
		jsonResp(w, map[string]any{"files": files}, 200)

	case path == "/api/read":
		rel := r.URL.Query().Get("path")
		if rel == "" {
			jsonResp(w, map[string]any{"error": "missing path"}, 400)
			return
		}
		abs, err := safePath(cfg.Vault, rel)
		if err != nil {
			jsonResp(w, map[string]any{"error": err.Error()}, 403)
			return
		}
		content, err := os.ReadFile(abs)
		if err != nil {
			jsonResp(w, map[string]any{"error": err.Error()}, 404)
			return
		}
		jsonResp(w, map[string]any{"content": string(content)}, 200)

	case path == "/api/write" && r.Method == http.MethodPost:
		var body struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
			jsonResp(w, map[string]any{"error": "invalid body"}, 400)
			return
		}
		abs, err := safePath(cfg.Vault, body.Path)
		if err != nil {
			jsonResp(w, map[string]any{"error": err.Error()}, 403)
			return
		}
		os.MkdirAll(filepath.Dir(abs), 0755) //nolint:errcheck
		if err := os.WriteFile(abs, []byte(body.Content), 0644); err != nil {
			jsonResp(w, map[string]any{"error": err.Error()}, 500)
			return
		}
		invalidateCache()
		htmlCache = nil // bust UI cache if index.html overwritten
		jsonResp(w, map[string]any{"ok": true}, 200)

	case path == "/api/watch":
		ch := sseSubscribe()
		defer sseUnsubscribe(ch)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(200)
		fmt.Fprint(w, "data: connected\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		closed := r.Context().Done()
		for {
			select {
			case msg := <-ch:
				fmt.Fprintf(w, "data: %s\n\n", jsonString(msg))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			case <-closed:
				return
			}
		}

	default:
		jsonResp(w, map[string]any{"error": "not found"}, 404)
	}
}

func safePath(vaultDir, rel string) (string, error) {
	abs := filepath.Clean(filepath.Join(vaultDir, rel))
	if !strings.HasPrefix(abs, filepath.Clean(vaultDir)+string(filepath.Separator)) && abs != filepath.Clean(vaultDir) {
		return "", fmt.Errorf("path traversal")
	}
	return abs, nil
}

func listJSONFiles(dir, base string) []string {
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		rel := e.Name()
		if base != "" {
			rel = base + "/" + e.Name()
		}
		if e.IsDir() {
			out = append(out, listJSONFiles(filepath.Join(dir, e.Name()), rel)...)
		} else if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, rel)
		}
	}
	return out
}

// ── JMAP HTTP handlers ────────────────────────────────────────────────────────

// jmapSession returns the JMAP session discovery object.
func jmapSession(w http.ResponseWriter, r *http.Request) {
	if !authOK(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%d", cfg.Port)
	}
	accountID := cfg.Account
	if accountID == "" {
		accountID = "default"
	}
	session := map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":         50000000,
				"maxConcurrentUpload":   4,
				"maxSizeRequest":        10000000,
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
				"maxSizeAttachmentsPerEmail": 50000000,
				"emailQuerySortOptions":      []string{"receivedAt", "sentAt"},
			},
			"urn:ietf:params:jmap:submission": map[string]any{
				"maxDelayedSend":           0,
				"submissionExtensions":     map[string]any{},
			},
		},
		"accounts": map[string]any{
			accountID: map[string]any{
				"name":            accountID,
				"isPersonal":      true,
				"isReadOnly":      false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":       map[string]any{},
					"urn:ietf:params:jmap:submission": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]any{
			"urn:ietf:params:jmap:mail":       accountID,
			"urn:ietf:params:jmap:submission": accountID,
		},
		"username":  accountID,
		"apiUrl":    "/jmap/api/",
		"eventSourceUrl": fmt.Sprintf("/jmap/eventsource/?types=*&closeAfter=no&ping=30"),
		"uploadUrl": "/jmap/upload/{accountId}/",
		"downloadUrl": "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"state": "1",
	}
	jsonResp(w, session, 200)
}

// jmapAPI dispatches JMAP method calls.
func jmapAPI(w http.ResponseWriter, r *http.Request) {
	if !authOK(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	var req struct {
		Using       []string `json:"using"`
		MethodCalls [][]any  `json:"methodCalls"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	accountID := cfg.Account
	if accountID == "" {
		accountID = "default"
	}

	var results [][]any
	resultsByID := map[string]any{}

	for _, call := range req.MethodCalls {
		if len(call) < 3 {
			continue
		}
		method, _ := call[0].(string)
		argsRaw, _ := call[1].(map[string]any)
		callID, _ := call[2].(string)

		// resolve result references (#name/path)
		args := resolveResultRefs(argsRaw, resultsByID)

		var result map[string]any
		switch method {
		case "Mailbox/get":
			result = jmapMailboxGet(accountID, args)
		case "Email/query":
			result = jmapEmailQuery(accountID, args)
		case "Email/queryChanges":
			result = jmapEmailQueryChanges(accountID, args)
		case "Email/get":
			result = jmapEmailGet(accountID, args)
		case "Email/set":
			result = jmapEmailSet(accountID, args)
		case "Thread/get":
			result = jmapThreadGet(accountID, args)
		case "EmailSubmission/set":
			result = jmapEmailSubmissionSet(accountID, args)
		case "Identity/get":
			result = jmapIdentityGet(accountID, args)
		default:
			result = map[string]any{"type": "unknownMethod", "description": "method not implemented: " + method}
			method = "error"
		}

		resultsByID[callID] = result
		results = append(results, []any{method, result, callID})
	}

	if results == nil {
		results = [][]any{}
	}
	jsonResp(w, map[string]any{"methodResponses": results, "sessionState": "1"}, 200)
}

func resolveResultRefs(args map[string]any, results map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		if strings.HasPrefix(k, "#") {
			// result reference
			ref, ok := v.(map[string]any)
			if !ok {
				continue
			}
			resultOf, _ := ref["resultOf"].(string)
			name, _ := ref["name"].(string)
			path, _ := ref["path"].(string)
			prev, ok := results[resultOf]
			if !ok {
				continue
			}
			_ = name
			resolved := resolvePath(prev, path)
			if resolved != nil {
				out[strings.TrimPrefix(k, "#")] = resolved
			}
		} else {
			out[k] = v
		}
	}
	return out
}

func resolvePath(obj any, path string) any {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	cur := obj
	for _, p := range parts {
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

// ── JMAP method implementations ───────────────────────────────────────────────

func jmapMailboxGet(accountID string, args map[string]any) map[string]any {
	vaultMu.RLock()
	vaultDir := cfg.Vault
	vaultMu.RUnlock()

	entries, _ := os.ReadDir(vaultDir)
	var list []map[string]any
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		inboxKey := e.Name()
		id := mailboxID(inboxKey)
		list = append(list, map[string]any{
			"id":           id,
			"name":         inboxKey,
			"parentId":     nil,
			"role":         "inbox",
			"sortOrder":    0,
			"totalEmails":  0,
			"unreadEmails": 0,
			"totalThreads": 0,
			"unreadThreads": 0,
			"myRights": map[string]bool{
				"mayReadItems":   true,
				"mayAddItems":    true,
				"mayRemoveItems": true,
				"maySetSeen":     true,
				"maySetKeywords": true,
				"mayCreateChild": false,
				"mayRename":      false,
				"mayDelete":      false,
				"maySubmit":      true,
			},
			"isSubscribed": true,
		})
	}
	if idsRaw, ok := args["ids"]; ok && idsRaw != nil {
		ids, _ := idsRaw.([]any)
		if ids != nil {
			idSet := map[string]bool{}
			for _, id := range ids {
				if s, ok := id.(string); ok {
					idSet[s] = true
				}
			}
			var filtered []map[string]any
			for _, m := range list {
				if idSet[m["id"].(string)] {
					filtered = append(filtered, m)
				}
			}
			list = filtered
		}
	}
	if list == nil {
		list = []map[string]any{}
	}
	return map[string]any{
		"accountId": accountID,
		"state":     "1",
		"list":      list,
		"notFound":  []string{},
	}
}

func jmapEmailQuery(accountID string, args map[string]any) map[string]any {
	threads, err := getThreads()
	if err != nil {
		threads = nil
	}

	// filter by mailbox
	inboxFilter := ""
	if filter, ok := args["filter"].(map[string]any); ok {
		if mbxID, ok := filter["inMailbox"].(string); ok {
			inboxFilter = strings.TrimPrefix(mbxID, "mbx-")
		}
	}

	type emailEntry struct {
		id        string
		receivedAt time.Time
	}
	var emails []emailEntry

	for _, t := range threads {
		if inboxFilter != "" && t.inboxKey != inboxFilter {
			continue
		}
		for _, m := range t.data.Thread.Messages {
			ts, _ := time.Parse(time.RFC3339, m.Time)
			emails = append(emails, emailEntry{
				id:         emailID(t.inboxKey, m.MessageID, ts),
				receivedAt: ts,
			})
		}
	}

	// sort by receivedAt desc
	sort.Slice(emails, func(i, j int) bool {
		return emails[i].receivedAt.After(emails[j].receivedAt)
	})

	// pagination
	position := 0
	if p, ok := args["position"].(float64); ok {
		position = int(p)
	}
	limit := len(emails)
	if l, ok := args["limit"].(float64); ok && int(l) < limit {
		limit = int(l)
	}

	end := position + limit
	if end > len(emails) {
		end = len(emails)
	}
	if position > len(emails) {
		position = len(emails)
	}

	ids := make([]string, 0, end-position)
	for _, e := range emails[position:end] {
		ids = append(ids, e.id)
	}

	return map[string]any{
		"accountId":  accountID,
		"queryState": "1",
		"canCalculateChanges": false,
		"position":   position,
		"total":      len(emails),
		"ids":        ids,
	}
}

func jmapEmailQueryChanges(accountID string, _ map[string]any) map[string]any {
	return map[string]any{
		"accountId":   accountID,
		"oldQueryState": "1",
		"newQueryState": "1",
		"removed":     []string{},
		"added":       []map[string]any{},
		"total":       0,
	}
}

func jmapEmailGet(accountID string, args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	propertiesRaw, _ := args["properties"].([]any)
	wantProps := map[string]bool{}
	if len(propertiesRaw) == 0 {
		wantProps["*"] = true
	} else {
		for _, p := range propertiesRaw {
			if s, ok := p.(string); ok {
				wantProps[s] = true
			}
		}
	}
	want := func(p string) bool { return wantProps["*"] || wantProps[p] }

	// build email index from all threads
	type indexEntry struct {
		inboxKey string
		msg      struct {
			From      string            `json:"from"`
			FromName  string            `json:"from_name"`
			Body      string            `json:"body"`
			Time      string            `json:"time"`
			MessageID string            `json:"message_id"`
			ParentID  string            `json:"parent_id"`
			Meta      map[string]string `json:"meta"`
		}
		threadJSONID string
	}
	index := map[string]indexEntry{}

	threads, err := getThreads()
	if err == nil {
		for _, t := range threads {
			for _, m := range t.data.Thread.Messages {
				ts, _ := time.Parse(time.RFC3339, m.Time)
				id := emailID(t.inboxKey, m.MessageID, ts)
				index[id] = indexEntry{inboxKey: t.inboxKey, msg: m, threadJSONID: t.data.Thread.ID}
			}
		}
	}

	var list []map[string]any
	var notFound []string

	for _, idRaw := range idsRaw {
		id, _ := idRaw.(string)
		entry, ok := index[id]
		if !ok {
			notFound = append(notFound, id)
			continue
		}
		m := entry.msg
		ts, _ := time.Parse(time.RFC3339, m.Time)

		e := map[string]any{"id": id}
		if want("threadId") {
			e["threadId"] = vaultThreadID(entry.threadJSONID)
		}
		if want("mailboxIds") {
			e["mailboxIds"] = map[string]bool{mailboxID(entry.inboxKey): true}
		}
		if want("keywords") {
			e["keywords"] = map[string]bool{"$seen": true}
		}
		if want("subject") {
			subj := ""
			if m.Meta != nil {
				subj = m.Meta["subject"]
			}
			e["subject"] = subj
		}
		if want("from") {
			fromName := m.FromName
			if fromName == "" && m.Meta != nil {
				fromName = m.Meta["from_name"]
			}
			e["from"] = []map[string]any{{"email": m.From, "name": fromName}}
		}
		if want("to") {
			var toAddrs []map[string]any
			if m.Meta != nil {
				if raw := m.Meta["to_addrs"]; raw != "" && raw != "null" {
					var addrs []string
					json.Unmarshal([]byte(raw), &addrs) //nolint:errcheck
					for _, a := range addrs {
						toAddrs = append(toAddrs, map[string]any{"email": a, "name": ""})
					}
				}
			}
			if toAddrs == nil {
				toAddrs = []map[string]any{}
			}
			e["to"] = toAddrs
		}
		if want("cc") {
			var ccAddrs []map[string]any
			if m.Meta != nil {
				if raw := m.Meta["cc_addrs"]; raw != "" && raw != "null" {
					var addrs []string
					json.Unmarshal([]byte(raw), &addrs) //nolint:errcheck
					for _, a := range addrs {
						ccAddrs = append(ccAddrs, map[string]any{"email": a, "name": ""})
					}
				}
			}
			if ccAddrs == nil {
				ccAddrs = []map[string]any{}
			}
			e["cc"] = ccAddrs
		}
		if want("receivedAt") {
			e["receivedAt"] = ts.UTC().Format(time.RFC3339)
		}
		if want("sentAt") {
			e["sentAt"] = ts.UTC().Format(time.RFC3339)
		}
		if want("messageId") {
			msgID := m.MessageID
			if msgID == "" {
				msgID = id + "@biset"
			}
			e["messageId"] = []string{msgID}
		}
		if want("inReplyTo") {
			if m.ParentID != "" {
				e["inReplyTo"] = []string{m.ParentID}
			} else {
				e["inReplyTo"] = []string{}
			}
		}
		if want("references") {
			if m.ParentID != "" {
				e["references"] = []string{m.ParentID}
			} else {
				e["references"] = []string{}
			}
		}
		if want("bodyValues") || want("textBody") || want("bodyStructure") {
			partID := "1"
			e["bodyValues"] = map[string]any{
				partID: map[string]any{
					"value":             m.Body,
					"isEncodingProblem": false,
					"isTruncated":       false,
				},
			}
			part := map[string]any{
				"partId":  partID,
				"blobId":  "blob-" + id,
				"type":    "text/plain",
				"charset": "utf-8",
				"size":    len(m.Body),
			}
			e["textBody"] = []any{part}
			e["htmlBody"] = []any{}
			e["bodyStructure"] = part
		}
		if want("preview") {
			preview := m.Body
			if len([]rune(preview)) > 256 {
				preview = string([]rune(preview)[:256])
			}
			e["preview"] = preview
		}
		if want("size") {
			e["size"] = len(m.Body)
		}
		if want("attachments") {
			e["attachments"] = []any{}
		}
		if want("hasAttachment") {
			e["hasAttachment"] = false
		}
		list = append(list, e)
	}

	if list == nil {
		list = []map[string]any{}
	}
	if notFound == nil {
		notFound = []string{}
	}
	return map[string]any{
		"accountId": accountID,
		"state":     "1",
		"list":      list,
		"notFound":  notFound,
	}
}

func jmapEmailSet(accountID string, args map[string]any) map[string]any {
	// Handle keywords update ($seen) — just acknowledge, no actual storage
	updated := map[string]any{}
	notUpdated := map[string]any{}
	if updateMap, ok := args["update"].(map[string]any); ok {
		for emailID := range updateMap {
			updated[emailID] = map[string]any{}
		}
	}

	destroyed := []string{}
	notDestroyed := map[string]any{}
	if destroyRaw, ok := args["destroy"].([]any); ok {
		for _, idRaw := range destroyRaw {
			if id, ok := idRaw.(string); ok {
				// find and handle deletion via status
				notDestroyed[id] = map[string]any{"type": "serverFail", "detail": "delete not supported via JMAP — use biset handle"}
			}
		}
	}

	return map[string]any{
		"accountId":    accountID,
		"oldState":     "1",
		"newState":     "1",
		"created":      map[string]any{},
		"updated":      updated,
		"destroyed":    destroyed,
		"notCreated":   map[string]any{},
		"notUpdated":   notUpdated,
		"notDestroyed": notDestroyed,
	}
}

func jmapThreadGet(accountID string, args map[string]any) map[string]any {
	idsRaw, _ := args["ids"].([]any)
	threads, _ := getThreads()

	// build thread index: threadID → emailIDs
	threadEmails := map[string][]string{}
	for _, t := range threads {
		tID := vaultThreadID(t.data.Thread.ID)
		for _, m := range t.data.Thread.Messages {
			ts, _ := time.Parse(time.RFC3339, m.Time)
			eID := emailID(t.inboxKey, m.MessageID, ts)
			threadEmails[tID] = append(threadEmails[tID], eID)
		}
	}

	var list []map[string]any
	var notFound []string
	for _, idRaw := range idsRaw {
		tID, _ := idRaw.(string)
		eIDs, ok := threadEmails[tID]
		if !ok {
			notFound = append(notFound, tID)
			continue
		}
		list = append(list, map[string]any{
			"id":       tID,
			"emailIds": eIDs,
		})
	}
	if list == nil {
		list = []map[string]any{}
	}
	if notFound == nil {
		notFound = []string{}
	}
	return map[string]any{
		"accountId": accountID,
		"state":     "1",
		"list":      list,
		"notFound":  notFound,
	}
}

func jmapEmailSubmissionSet(accountID string, args map[string]any) map[string]any {
	createMap, _ := args["create"].(map[string]any)
	created := map[string]any{}
	notCreated := map[string]any{}

	threads, _ := getThreads()

	// build email index for lookup
	type eEntry struct {
		inboxKey string
		msg      struct {
			From      string            `json:"from"`
			FromName  string            `json:"from_name"`
			Body      string            `json:"body"`
			Time      string            `json:"time"`
			MessageID string            `json:"message_id"`
			ParentID  string            `json:"parent_id"`
			Meta      map[string]string `json:"meta"`
		}
	}
	eIndex := map[string]eEntry{}
	for _, t := range threads {
		for _, m := range t.data.Thread.Messages {
			ts, _ := time.Parse(time.RFC3339, m.Time)
			id := emailID(t.inboxKey, m.MessageID, ts)
			eIndex[id] = eEntry{inboxKey: t.inboxKey, msg: m}
		}
	}

	for createID, objRaw := range createMap {
		obj, _ := objRaw.(map[string]any)
		emailIDStr, _ := obj["emailId"].(string)

		entry, ok := eIndex[emailIDStr]
		if !ok {
			notCreated[createID] = map[string]any{"type": "notFound", "detail": "emailId not found"}
			continue
		}

		// write to vault MD with status: send so biset picks it up
		m := entry.msg
		subj := ""
		if m.Meta != nil {
			subj = m.Meta["subject"]
		}

		vaultMu.RLock()
		vaultDir := cfg.Vault
		vaultMu.RUnlock()

		// find matching MD file
		mdPath, err := findMDForMessage(vaultDir, entry.inboxKey, m.MessageID)
		if err != nil {
			notCreated[createID] = map[string]any{"type": "serverFail", "detail": err.Error()}
			continue
		}

		content, _ := os.ReadFile(mdPath)
		newContent := setFrontmatterStatus(string(content), "send")
		if err := os.WriteFile(mdPath, []byte(newContent), 0644); err != nil {
			notCreated[createID] = map[string]any{"type": "serverFail", "detail": err.Error()}
			continue
		}

		created[createID] = map[string]any{
			"id":     createID,
			"subject": subj,
			"sendAt": time.Now().UTC().Format(time.RFC3339),
		}
	}

	return map[string]any{
		"accountId":    accountID,
		"oldState":     "1",
		"newState":     "2",
		"created":      created,
		"notCreated":   notCreated,
		"updated":      map[string]any{},
		"notUpdated":   map[string]any{},
		"destroyed":    []string{},
		"notDestroyed": map[string]any{},
	}
}

func jmapIdentityGet(accountID string, _ map[string]any) map[string]any {
	return map[string]any{
		"accountId": accountID,
		"state":     "1",
		"list": []map[string]any{
			{
				"id":           "id-" + accountID,
				"name":         accountID,
				"email":        accountID,
				"mayDelete":    false,
			},
		},
		"notFound": []string{},
	}
}

// ── JMAP eventsource ──────────────────────────────────────────────────────────

func jmapEventSource(w http.ResponseWriter, r *http.Request) {
	if !authOK(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	ch := sseSubscribe()
	defer sseUnsubscribe(ch)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)

	fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()
	closed := r.Context().Done()

	for {
		select {
		case <-ch:
			invalidateCache()
			fmt.Fprint(w, "event: state\ndata: {\"changed\":{\"urn:ietf:params:jmap:mail\":null}}\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-pingTicker.C:
			fmt.Fprint(w, ": ping\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-closed:
			return
		}
	}
}

// ── ID helpers ────────────────────────────────────────────────────────────────

func mailboxID(inboxKey string) string {
	return "mbx-" + strings.ReplaceAll(inboxKey, "/", "~")
}

func emailID(inboxKey, messageID string, ts time.Time) string {
	if messageID != "" {
		return "eml-" + strings.ReplaceAll(strings.Trim(messageID, "<>"), "/", "_")
	}
	return fmt.Sprintf("eml-%s-%d", strings.ReplaceAll(inboxKey, "/", "-"), ts.UnixMilli())
}

func vaultThreadID(rawID string) string {
	id := strings.Trim(rawID, "<>")
	if id == "" {
		return "thr-unknown"
	}
	return "thr-" + strings.ReplaceAll(id, "/", "_")
}

// ── Vault MD helpers ──────────────────────────────────────────────────────────

func findMDForMessage(vaultDir, inboxKey, messageID string) (string, error) {
	inboxDir := filepath.Join(vaultDir, inboxKey)
	files, err := os.ReadDir(inboxDir)
	if err != nil {
		return "", err
	}
	needle := strings.Trim(messageID, "<>")
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".md") {
			continue
		}
		p := filepath.Join(inboxDir, f.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), needle) {
			return p, nil
		}
	}
	return "", fmt.Errorf("MD not found for message %q in %s", messageID, inboxKey)
}

func setFrontmatterStatus(content, status string) string {
	fm := core.ParseFrontmatter(content)
	old := "status: " + strings.TrimSpace(fm["status"])
	new := "status: " + status
	result := strings.Replace(content, old, new, 1)
	if result == content {
		result = strings.Replace(content, "\nstatus: \n", "\nstatus: "+status+"\n", 1)
	}
	return result
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}
	cfgDir = dir

	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.Vault == "" {
		cfg.Vault = dir
	} else if !filepath.IsAbs(cfg.Vault) {
		cfg.Vault = filepath.Join(dir, cfg.Vault)
	}

	// start vault watcher
	go watchVault()

	// start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jmap", jmapSession)
	mux.HandleFunc("/jmap/api/", jmapAPI)
	mux.HandleFunc("/jmap/eventsource/", jmapEventSource)
	mux.HandleFunc("/api/", apiHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		serveUI(w)
	})

	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
		log.Printf("[jmap] listening on %s  vault=%s", addr, cfg.Vault)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatalf("[jmap] HTTP: %v", err)
		}
	}()

	// JSON-RPC stdin loop
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		go handleRequest(req)
	}
}
