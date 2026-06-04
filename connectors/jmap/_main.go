package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	Vault   string `json:"vault"`
	Port    int    `json:"port"`
	Token   string `json:"token"`
	UIHtml  string `json:"ui_html"`
	Account string `json:"account"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Port: 8080}
	return cfg, json.Unmarshal(b, cfg)
}

// ── vault types ───────────────────────────────────────────────────────────────

type vaultMsg struct {
	From      string            `json:"from"`
	FromName  string            `json:"from_name"`
	Body      string            `json:"body"`
	Time      string            `json:"time"`
	MessageID string            `json:"message_id"`
	ParentID  string            `json:"parent_id"`
	Meta      map[string]string `json:"meta"`
}

type vaultThread struct {
	ID       string     `json:"thread_id"`
	LastTime string     `json:"last_time"`
	Messages []vaultMsg `json:"messages"`
}

type vaultFile struct {
	Inbox  string      `json:"inbox"`
	Status string      `json:"status"`
	Thread vaultThread `json:"thread"`
}

// ── vault scanning ────────────────────────────────────────────────────────────

func scanVault(vaultDir string) []vaultFile {
	var out []vaultFile
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dataDir := filepath.Join(vaultDir, e.Name(), ".data")
		files, err := os.ReadDir(dataDir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dataDir, f.Name()))
			if err != nil {
				continue
			}
			var vf vaultFile
			if err := json.Unmarshal(b, &vf); err != nil {
				continue
			}
			if vf.Inbox == "" {
				vf.Inbox = e.Name()
			}
			out = append(out, vf)
		}
	}
	return out
}

// ── ID helpers ────────────────────────────────────────────────────────────────

func emailID(inboxKey, msgID string) string {
	id := strings.Trim(msgID, "<>")
	if id == "" {
		return "eml-" + inboxKey + "-unknown"
	}
	return "eml-" + id
}

func threadID(rawID string) string {
	id := strings.Trim(rawID, "<>")
	if id == "" {
		return "thr-unknown"
	}
	return "thr-" + id
}

func mbxID(inboxKey string) string {
	return "mbx-" + strings.ReplaceAll(inboxKey, "/", "~")
}

// ── JMAP types ────────────────────────────────────────────────────────────────

type jmapRequest struct {
	Using       []string        `json:"using"`
	MethodCalls []methodCall    `json:"methodCalls"`
}

type methodCall [3]json.RawMessage // [name, args, tag]

type jmapResponse struct {
	MethodResponses []methodResult `json:"methodResponses"`
	SessionState    string         `json:"sessionState"`
}

type methodResult [3]any // [name, result, tag]

// ── server ────────────────────────────────────────────────────────────────────

type server struct {
	cfg     *Config
	mu      sync.RWMutex
	sseSubs map[chan string]struct{}
}

func newServer(cfg *Config) *server {
	return &server{cfg: cfg, sseSubs: map[chan string]struct{}{}}
}

func (s *server) authOK(r *http.Request) bool {
	if s.cfg.Token == "" {
		return true
	}
	if r.Header.Get("Authorization") == "Bearer "+s.cfg.Token {
		return true
	}
	return r.URL.Query().Get("token") == s.cfg.Token
}

func (s *server) json(w http.ResponseWriter, v any, status int) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func (s *server) broadcast(msg string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.sseSubs {
		select {
		case ch <- msg:
		default:
		}
	}
}

// ── well-known ────────────────────────────────────────────────────────────────

func (s *server) session() map[string]any {
	acct := s.cfg.Account
	return map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxCallsInRequest":    16,
				"maxObjectsInGet":      500,
				"maxObjectsInSet":      500,
				"maxSizeRequest":       10_000_000,
				"maxSizeUpload":        50_000_000,
				"maxConcurrentUpload":  4,
				"maxConcurrentRequests": 4,
				"collationAlgorithms":  []string{},
			},
			"urn:ietf:params:jmap:mail": map[string]any{
				"maxMailboxesPerEmail":       nil,
				"maxMailboxDepth":            nil,
				"maxSizeMailboxName":         200,
				"maxDescendantMailboxes":     nil,
				"mayCreateTopLevelMailbox":   false,
				"maxSizeAttachmentsPerEmail": 50_000_000,
				"emailQuerySortOptions":      []string{"receivedAt", "sentAt"},
			},
			"urn:ietf:params:jmap:submission": map[string]any{
				"maxDelayedSend":      0,
				"submissionExtensions": map[string]any{},
			},
		},
		"accounts": map[string]any{
			acct: map[string]any{
				"name":       acct,
				"isPersonal": true,
				"isReadOnly": false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":       map[string]any{},
					"urn:ietf:params:jmap:submission": map[string]any{},
				},
			},
		},
		"primaryAccounts": map[string]string{
			"urn:ietf:params:jmap:mail":       acct,
			"urn:ietf:params:jmap:submission": acct,
		},
		"username":       acct,
		"apiUrl":         "/jmap/api/",
		"downloadUrl":    "/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
		"uploadUrl":      "/jmap/upload/{accountId}/",
		"eventSourceUrl": "/jmap/eventsource/?types=*&closeAfter=no&ping=30",
		"state":          "1",
	}
}

// ── JMAP dispatch ─────────────────────────────────────────────────────────────

func (s *server) handleJMAP(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		s.json(w, map[string]string{"error": "unauthorized"}, 401)
		return
	}
	var req jmapRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.json(w, map[string]string{"error": "bad request"}, 400)
		return
	}

	vaultFiles := scanVault(s.cfg.Vault)
	resp := jmapResponse{SessionState: "1"}

	for _, mc := range req.MethodCalls {
		var name string
		var args map[string]json.RawMessage
		var tag string
		json.Unmarshal(mc[0], &name)
		json.Unmarshal(mc[1], &args)
		json.Unmarshal(mc[2], &tag)

		var result any
		switch name {
		case "Mailbox/get":
			result = s.mailboxGet(vaultFiles)
		case "Email/query":
			result = s.emailQuery(vaultFiles, args)
		case "Email/get":
			result = s.emailGet(vaultFiles, args)
		case "Email/set":
			result = s.emailSet(args)
		case "Thread/get":
			result = s.threadGet(vaultFiles, args)
		case "Identity/get":
			result = s.identityGet()
		case "EmailSubmission/set":
			result = map[string]any{"accountId": s.cfg.Account, "oldState": "1", "newState": "1",
				"created": map[string]any{}, "notCreated": map[string]any{},
				"updated": map[string]any{}, "notUpdated": map[string]any{},
				"destroyed": []any{}, "notDestroyed": map[string]any{}}
		default:
			result = map[string]any{"type": "unknownMethod", "description": name}
			name = "error"
		}
		resp.MethodResponses = append(resp.MethodResponses, methodResult{name, result, tag})
	}

	s.json(w, resp, 200)
}

// ── Mailbox/get ───────────────────────────────────────────────────────────────

func (s *server) mailboxGet(vaultFiles []vaultFile) map[string]any {
	seen := map[string]bool{}
	var list []map[string]any
	for _, vf := range vaultFiles {
		if seen[vf.Inbox] {
			continue
		}
		seen[vf.Inbox] = true
		list = append(list, map[string]any{
			"id":             mbxID(vf.Inbox),
			"name":           vf.Inbox,
			"parentId":       nil,
			"role":           "inbox",
			"sortOrder":      0,
			"totalEmails":    0,
			"unreadEmails":   0,
			"totalThreads":   0,
			"unreadThreads":  0,
			"isSubscribed":   true,
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
		})
	}
	return map[string]any{"accountId": s.cfg.Account, "state": "1", "list": list, "notFound": []any{}}
}

// ── Email/query ───────────────────────────────────────────────────────────────

func (s *server) emailQuery(vaultFiles []vaultFile, args map[string]json.RawMessage) map[string]any {
	// parse filter
	filterMbx := ""
	if raw, ok := args["filter"]; ok {
		var f map[string]json.RawMessage
		json.Unmarshal(raw, &f)
		if v, ok := f["inMailbox"]; ok {
			json.Unmarshal(v, &filterMbx)
		}
	}
	limit := 500
	if raw, ok := args["limit"]; ok {
		json.Unmarshal(raw, &limit)
	}

	var ids []string
	seen := map[string]bool{}
	for _, vf := range vaultFiles {
		if filterMbx != "" && mbxID(vf.Inbox) != filterMbx {
			continue
		}
		for _, m := range vf.Thread.Messages {
			id := emailID(vf.Inbox, m.MessageID)
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
			if len(ids) >= limit {
				break
			}
		}
		if len(ids) >= limit {
			break
		}
	}

	return map[string]any{
		"accountId":          s.cfg.Account,
		"ids":                ids,
		"canCalculateChanges": false,
	}
}

// ── Email/get ─────────────────────────────────────────────────────────────────

func (s *server) emailGet(vaultFiles []vaultFile, args map[string]json.RawMessage) map[string]any {
	var ids []string
	if raw, ok := args["ids"]; ok {
		json.Unmarshal(raw, &ids)
	}
	var props []string
	if raw, ok := args["properties"]; ok {
		json.Unmarshal(raw, &props)
	}
	wantAll := len(props) == 0
	want := map[string]bool{}
	for _, p := range props {
		want[p] = true
	}

	// build lookup: emailID → (vaultFile, vaultMsg)
	type emailEntry struct {
		vf  vaultFile
		msg vaultMsg
	}
	lookup := map[string]emailEntry{}
	for _, vf := range vaultFiles {
		for _, m := range vf.Thread.Messages {
			id := emailID(vf.Inbox, m.MessageID)
			if _, exists := lookup[id]; !exists {
				lookup[id] = emailEntry{vf, m}
			}
		}
	}

	var list []map[string]any
	var notFound []string
	for _, id := range ids {
		entry, ok := lookup[id]
		if !ok {
			notFound = append(notFound, id)
			continue
		}
		vf := entry.vf
		m := entry.msg

		ts, _ := time.Parse(time.RFC3339, m.Time)
		receivedAt := ""
		if !ts.IsZero() {
			receivedAt = ts.UTC().Format(time.RFC3339)
		}

		var toAddrs []string
		if raw := m.Meta["to_addrs"]; raw != "" {
			json.Unmarshal([]byte(raw), &toAddrs)
		}
		var ccAddrs []string
		if raw := m.Meta["cc_addrs"]; raw != "" {
			json.Unmarshal([]byte(raw), &ccAddrs)
		}

		fromAddr := []map[string]string{{"email": m.From, "name": m.FromName}}
		toList := make([]map[string]string, len(toAddrs))
		for i, a := range toAddrs {
			toList[i] = map[string]string{"email": a, "name": ""}
		}
		ccList := make([]map[string]string, len(ccAddrs))
		for i, a := range ccAddrs {
			ccList[i] = map[string]string{"email": a, "name": ""}
		}

		e := map[string]any{"id": id}

		set := func(key string, val any) {
			if wantAll || want[key] {
				e[key] = val
			}
		}

		set("threadId", threadID(vf.Thread.ID))
		set("mailboxIds", map[string]bool{mbxID(vf.Inbox): true})
		set("from", fromAddr)
		set("to", toList)
		set("cc", ccList)
		set("subject", m.Meta["subject"])
		set("receivedAt", receivedAt)
		set("preview", truncate(m.Body, 200))
		set("keywords", map[string]bool{"$seen": true})
		if m.MessageID != "" {
			set("messageId", []string{m.MessageID})
		} else {
			set("messageId", []string{})
		}
		if m.ParentID != "" {
			set("inReplyTo", []string{m.ParentID})
		} else {
			set("inReplyTo", []string{})
		}

		if wantAll || want["bodyValues"] || want["textBody"] {
			partId := "1"
			e["textBody"] = []map[string]any{
				{"partId": partId, "type": "text/plain", "charset": "utf-8",
					"size": len(m.Body), "blobId": "blob-" + id},
			}
			e["htmlBody"] = []map[string]any{}
			e["bodyValues"] = map[string]any{
				partId: map[string]any{
					"value":            m.Body,
					"isEncodingProblem": false,
					"isTruncated":      false,
				},
			}
			e["bodyStructure"] = map[string]any{
				"partId": partId, "type": "text/plain", "charset": "utf-8",
				"size": len(m.Body), "blobId": "blob-" + id,
			}
		}

		list = append(list, e)
	}

	if list == nil {
		list = []map[string]any{}
	}
	if notFound == nil {
		notFound = []string{}
	}
	return map[string]any{"accountId": s.cfg.Account, "state": "1", "list": list, "notFound": notFound}
}

// ── Email/set ─────────────────────────────────────────────────────────────────

func (s *server) emailSet(args map[string]json.RawMessage) map[string]any {
	result := map[string]any{
		"accountId":    s.cfg.Account,
		"oldState":     "1",
		"newState":     "2",
		"created":      map[string]any{},
		"notCreated":   map[string]any{},
		"updated":      map[string]any{},
		"notUpdated":   map[string]any{},
		"destroyed":    []any{},
		"notDestroyed": map[string]any{},
	}

	var createMap map[string]map[string]json.RawMessage
	if raw, ok := args["create"]; ok {
		json.Unmarshal(raw, &createMap)
	}

	created := map[string]any{}
	notCreated := map[string]any{}

	for clientId, obj := range createMap {
		var fromList []map[string]string
		var toList []map[string]string
		var bodyVals map[string]map[string]string
		var textBody []map[string]string
		var inReplyTo []string
		var mbxIds map[string]bool

		json.Unmarshal(obj["from"], &fromList)
		json.Unmarshal(obj["to"], &toList)
		json.Unmarshal(obj["bodyValues"], &bodyVals)
		json.Unmarshal(obj["textBody"], &textBody)
		json.Unmarshal(obj["inReplyTo"], &inReplyTo)
		json.Unmarshal(obj["mailboxIds"], &mbxIds)

		// derive account from mailboxIds or from[0]
		account := ""
		for mid := range mbxIds {
			// mbxId format: mbx-{account}
			account = strings.TrimPrefix(mid, "mbx-")
			account = strings.ReplaceAll(account, "~", "/")
		}
		if account == "" && len(fromList) > 0 {
			account = fromList[0]["email"]
		}
		if account == "" {
			account = s.cfg.Account
		}

		contact := ""
		if len(toList) > 0 {
			contact = toList[0]["email"]
		}

		// extract body
		body := ""
		if len(textBody) > 0 {
			partId := textBody[0]["partId"]
			if v, ok := bodyVals[partId]; ok {
				body = v["value"]
			}
		}

		replyTo := ""
		if len(inReplyTo) > 0 {
			replyTo = inReplyTo[0]
		}

		if contact == "" || body == "" {
			notCreated[clientId] = map[string]any{"type": "invalidProperties", "description": "missing to or body"}
			continue
		}

		if err := s.createMD(account, contact, body, replyTo); err != nil {
			notCreated[clientId] = map[string]any{"type": "serverFail", "description": err.Error()}
			continue
		}

		newId := fmt.Sprintf("eml-%s-%d", account, time.Now().UnixMilli())
		created[clientId] = map[string]any{
			"id":         newId,
			"blobId":     "blob-" + newId,
			"threadId":   "thr-" + newId,
			"size":       len(body),
			"receivedAt": time.Now().UTC().Format(time.RFC3339),
		}
	}

	result["created"] = created
	result["notCreated"] = notCreated
	return result
}

func (s *server) createMD(account, contact, body, inReplyTo string) error {
	// find existing MD file for this contact
	inboxDir := filepath.Join(s.cfg.Vault, account)
	entries, _ := os.ReadDir(inboxDir)

	targetMD := ""
	targetIn := inReplyTo

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(inboxDir, e.Name()))
		if err != nil {
			continue
		}
		content := string(b)
		// check if this file is for this contact
		fm := parseFrontmatter(content)
		if strings.EqualFold(fm["contact"], contact) {
			targetMD = filepath.Join(inboxDir, e.Name())
			if targetIn == "" {
				targetIn = fm["in"]
			}
			break
		}
	}

	if targetMD != "" {
		// update existing MD: inject body + status:send
		b, err := os.ReadFile(targetMD)
		if err != nil {
			return err
		}
		content := string(b)
		content = setStatus(content, "send")
		content = injectBody(content, body)
		if targetIn != "" {
			content = setFrontmatterField(content, "in", targetIn)
		}
		return os.WriteFile(targetMD, []byte(content), 0644)
	}

	// create new MD file
	ts := time.Now().Local().Format("200601021504")
	filename := fmt.Sprintf("%s_%s.md", ts, safeName(contact))
	path := filepath.Join(inboxDir, filename)
	os.MkdirAll(inboxDir, 0755)

	in := inReplyTo
	fm := fmt.Sprintf("---\ninbox: %s\ncontact: %s\nsubject: \"\"\nin: %s\nstatus: send\n---\n%s\n",
		account, contact, in, body)
	return os.WriteFile(path, []byte(fm), 0644)
}

// ── Thread/get ────────────────────────────────────────────────────────────────

func (s *server) threadGet(vaultFiles []vaultFile, args map[string]json.RawMessage) map[string]any {
	var ids []string
	if raw, ok := args["ids"]; ok {
		json.Unmarshal(raw, &ids)
	}

	// build lookup: threadId → []emailId
	threadEmails := map[string][]string{}
	for _, vf := range vaultFiles {
		tid := threadID(vf.Thread.ID)
		for _, m := range vf.Thread.Messages {
			eid := emailID(vf.Inbox, m.MessageID)
			threadEmails[tid] = append(threadEmails[tid], eid)
		}
	}

	var list []map[string]any
	var notFound []string
	for _, id := range ids {
		emails, ok := threadEmails[id]
		if !ok {
			notFound = append(notFound, id)
			continue
		}
		list = append(list, map[string]any{"id": id, "emailIds": emails})
	}
	if list == nil {
		list = []map[string]any{}
	}
	if notFound == nil {
		notFound = []string{}
	}
	return map[string]any{"accountId": s.cfg.Account, "state": "1", "list": list, "notFound": notFound}
}

// ── Identity/get ──────────────────────────────────────────────────────────────

func (s *server) identityGet() map[string]any {
	return map[string]any{
		"accountId": s.cfg.Account,
		"state":     "1",
		"list": []map[string]any{{
			"id":           "id-" + s.cfg.Account,
			"name":         "",
			"email":        s.cfg.Account,
			"replyTo":      nil,
			"bcc":          nil,
			"textSignature": "",
			"htmlSignature": "",
			"mayDelete":    false,
		}},
		"notFound": []any{},
	}
}

// ── SSE ───────────────────────────────────────────────────────────────────────

func (s *server) handleSSE(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan string, 4)
	s.mu.Lock()
	s.sseSubs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.sseSubs, ch)
		s.mu.Unlock()
	}()

	fmt.Fprintf(w, "data: connected\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprintf(w, ": ping\n\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case msg := <-ch:
			fmt.Fprintf(w, "event: state\ndata: %s\n\n", msg)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

// ── vault watcher ─────────────────────────────────────────────────────────────

func (s *server) watchVault() {
	var lastMod time.Time
	for {
		time.Sleep(2 * time.Second)
		var latest time.Time
		filepath.Walk(s.cfg.Vault, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".md") {
				if info.ModTime().After(latest) {
					latest = info.ModTime()
				}
			}
			return nil
		})
		if !latest.IsZero() && latest.After(lastMod) {
			lastMod = latest
			s.broadcast(`{"type":"update"}`)
		}
	}
}

// ── HTML serving ──────────────────────────────────────────────────────────────

var cachedHTML string
var cachedHTMLMu sync.Mutex

func (s *server) serveHTML(w http.ResponseWriter) {
	cachedHTMLMu.Lock()
	html := cachedHTML
	cachedHTMLMu.Unlock()

	if html == "" {
		b, err := os.ReadFile(s.cfg.UIHtml)
		if err != nil {
			http.Error(w, "index.html not found", 503)
			return
		}
		inject := fmt.Sprintf(`<script>window.__BISET_SERVE=%s;</script>`,
			jsonStr(s.cfg.Token, "1"))
		html = string(b)
		if strings.Contains(html, "</head>") {
			html = strings.Replace(html, "</head>", inject+"</head>", 1)
		} else {
			html = inject + html
		}
		cachedHTMLMu.Lock()
		cachedHTML = html
		cachedHTMLMu.Unlock()
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func jsonStr(token, fallback string) string {
	if token == "" {
		token = fallback
	}
	b, _ := json.Marshal(token)
	return string(b)
}

// ── HTTP server ───────────────────────────────────────────────────────────────

func (s *server) serve() {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		s.json(w, s.session(), 200)
	})

	mux.HandleFunc("/jmap/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		s.handleJMAP(w, r)
	})

	mux.HandleFunc("/jmap/eventsource/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		s.handleSSE(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.serveHTML(w)
			return
		}
		http.NotFound(w, r)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	log.Printf("[jmap] listening on %s  vault=%s", addr, s.cfg.Vault)
	go s.watchVault()
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

// ── JSON-RPC stdio ────────────────────────────────────────────────────────────

type rpcRequest struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

type rpcResponse struct {
	ID     int `json:"id"`
	Result any `json:"result,omitempty"`
	Error  any `json:"error,omitempty"`
}

func (s *server) runRPC() {
	scanner := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			continue
		}
		var result any
		switch req.Method {
		case "ping":
			result = map[string]string{"status": "ok", "name": "biset-jmap"}
		case "fetch":
			vaultFiles := scanVault(s.cfg.Vault)
			var msgs []map[string]any
			for _, vf := range vaultFiles {
				for _, m := range vf.Thread.Messages {
					msgs = append(msgs, map[string]any{
						"from": m.From, "body": m.Body, "ts": parseTime(m.Time),
						"message_id": m.MessageID, "parent_id": m.ParentID,
						"meta": m.Meta,
					})
				}
			}
			result = msgs
		case "handle":
			result = map[string]bool{"ok": true}
		default:
			enc.Encode(rpcResponse{ID: req.ID, Error: "unknown method"})
			continue
		}
		enc.Encode(rpcResponse{ID: req.ID, Result: result})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseFrontmatter(content string) map[string]string {
	fm := map[string]string{}
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return fm
	}
	for _, line := range strings.Split(parts[1], "\n") {
		kv := strings.SplitN(line, ": ", 2)
		if len(kv) == 2 {
			fm[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
		}
	}
	return fm
}

func setStatus(content, status string) string {
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "status:") {
			lines[i] = "status: " + status
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func setFrontmatterField(content, key, value string) string {
	lines := strings.Split(content, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, key+":") {
			lines[i] = key + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return content
}

func injectBody(content, body string) string {
	parts := strings.SplitN(content, "---", 3)
	if len(parts) < 3 {
		return content
	}
	rest := strings.TrimLeft(parts[2], "\n")
	// if there's already content before first heading, replace it
	idx := strings.Index(rest, "\n# ")
	if strings.HasPrefix(rest, "# ") {
		// no compose area, prepend
		return parts[0] + "---" + parts[1] + "---\n" + body + "\n\n" + rest
	}
	if idx < 0 {
		return parts[0] + "---" + parts[1] + "---\n" + body + "\n"
	}
	return parts[0] + "---" + parts[1] + "---\n" + body + "\n\n" + rest[idx+1:]
}

func safeName(s string) string {
	rep := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "-")
	s = rep.Replace(s)
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func parseTime(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}

// ── main ──────────────────────────────────────────────────────────────────────

func main() {
	serveMode := flag.Bool("serve", false, "run as HTTP server only")
	configPath := flag.String("config", "config.json", "config file path")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	s := newServer(cfg)

	if *serveMode {
		s.serve()
		return
	}
	// default: JSON-RPC + HTTP in background
	go s.serve()
	s.runRPC()
}
