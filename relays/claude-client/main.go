package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	jmap "git.sr.ht/~rockorager/go-jmap"
	jmapserver "github.com/yno9/go-jmapserver"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type Config struct {
	jmapserver.Config
	Bind        string   `json:"bind,omitempty"`
	Port        int      `json:"port,omitempty"`
	ProjectDirs []string `json:"project_dirs"`
	InboxKey    string   `json:"inbox_key"`
	UserName    string   `json:"user_name"`
}

type State struct {
	LastMtimeNs int64 `json:"last_mtime_ns"`
}

var cfg Config

// ── handler ───────────────────────────────────────────────────────────────────

type handler struct {
	store     *jmapserver.Store
	stateMu   sync.Mutex
	state     State
	statePath string
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	return []jmapserver.Account{{ID: jmap.ID(cfg.InboxKey), Name: cfg.InboxKey}}
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/query":
		return h.emailQuery(args)
	case "Email/queryChanges":
		h.scanProjects()
		return h.store.HandleQueryChanges(jmap.ID(cfg.InboxKey), args)
	case "Email/changes":
		return h.store.HandleEmailChanges(jmap.ID(cfg.InboxKey), args)
	case "Email/get":
		return h.store.HandleEmailGet(jmap.ID(cfg.InboxKey), args)
	case "Thread/get":
		return h.store.HandleThreadGet(jmap.ID(cfg.InboxKey), args)
	case "Mailbox/get":
		return h.mailboxGet()
	case "Mailbox/changes":
		return h.store.HandleMailboxChanges(jmap.ID(cfg.InboxKey), args)
	case "Identity/get":
		return h.store.HandleIdentityGet(jmap.ID(cfg.InboxKey))
	case "Identity/changes":
		return h.store.HandleIdentityChanges(jmap.ID(cfg.InboxKey), args)
	case "Thread/changes":
		return h.store.HandleThreadChanges(jmap.ID(cfg.InboxKey), args)
	case "Email/set":
		return h.emailSet(args)
	case "EmailSubmission/set":
		return h.emailSubmissionSet(args)
	default:
		return h.store.Dispatch(jmap.ID(cfg.InboxKey), method, args)
	}
}

// ── Email/query ───────────────────────────────────────────────────────────────

func (h *handler) scanProjects() {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()

	appTitles := loadAppTitles()
	newMtime := h.state.LastMtimeNs

	for _, scanDir := range cfg.ProjectDirs {
		entries, err := os.ReadDir(scanDir)
		if err != nil {
			continue
		}
		projectName := stripProjectPrefix(filepath.Base(scanDir))

		var newEntries []os.DirEntry
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			info, _ := e.Info()
			if info == nil {
				continue
			}
			if info.ModTime().UnixNano() > h.state.LastMtimeNs {
				newEntries = append(newEntries, e)
			}
		}
		if len(newEntries) == 0 {
			continue
		}

		parentMap := buildSessionParentMap(scanDir, entries)

		for _, e := range newEntries {
			info, _ := e.Info()
			mtimeNs := info.ModTime().UnixNano()
			if mtimeNs > newMtime {
				newMtime = mtimeNs
			}
			sid := strings.TrimSuffix(e.Name(), ".jsonl")
			root := rootSession(sid, parentMap)
			title := appTitles[sid]
			if title == "" {
				title = appTitles[root]
			}
			for _, m := range parseJSONL(filepath.Join(scanDir, e.Name()), projectName, root, title) {
				h.store.Put(m) //nolint:errcheck
			}
		}
	}

	h.state.LastMtimeNs = newMtime
	if b, err := json.MarshalIndent(h.state, "", "  "); err == nil {
		os.WriteFile(h.statePath, b, 0644) //nolint:errcheck
	}
}

func (h *handler) emailQuery(args json.RawMessage) (any, error) {
	h.scanProjects()

	all := h.store.All()
	ids := make([]jmap.ID, len(all))
	for i, m := range all {
		ids[i] = m.ID
	}
	return map[string]any{
		"accountId":           jmap.ID(cfg.InboxKey),
		"queryState":          "0",
		"canCalculateChanges": false,
		"position":            0,
		"ids":                 ids,
		"total":               len(ids),
	}, nil
}

// ── Email/get ─────────────────────────────────────────────────────────────────

// ── Mailbox/get ───────────────────────────────────────────────────────────────

func (h *handler) mailboxGet() (any, error) {
	return map[string]any{
		"accountId": jmap.ID(cfg.InboxKey),
		"state":     "0",
		"list":      []vault.Inbox{vault.DefaultInbox(cfg.InboxKey)},
		"notFound":  []string{},
	}, nil
}

// ── Email/set ─────────────────────────────────────────────────────────────────

func (h *handler) emailSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]json.RawMessage `json:"create"`
		Update map[jmap.ID]json.RawMessage `json:"update"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}
	updated := map[jmap.ID]any{}
	notUpdated := map[jmap.ID]any{}

	for key, rawMsg := range req.Create {
		var msg vault.Message
		if err := json.Unmarshal(rawMsg, &msg); err != nil {
			notCreated[key] = errObj("invalidProperties", err.Error())
			continue
		}
		if msg.ID == "" {
			msg.ID = newID()
		}
		receivedAt := time.Now().UTC()
		msg.ReceivedAt = &receivedAt
		h.store.PutPending(msg)
		created[key] = map[string]any{"id": msg.ID, "receivedAt": receivedAt.Format(time.RFC3339Nano)}
	}

	for msgID, rawPatch := range req.Update {
		var patch map[string]any
		if err := json.Unmarshal(rawPatch, &patch); err != nil {
			notUpdated[msgID] = errObj("invalidProperties", err.Error())
			continue
		}
		if err := h.store.PatchKeywords(msgID, patch); err != nil {
			log.Printf("store patch %s: %v", msgID, err)
		}
		updated[msgID] = map[string]any{}
	}

	return map[string]any{
		"accountId":    jmap.ID(cfg.InboxKey),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"updated":      updated,
		"destroyed":    []jmap.ID{},
		"notCreated":   notCreated,
		"notUpdated":   notUpdated,
		"notDestroyed": map[string]any{},
	}, nil
}

// ── EmailSubmission/set ───────────────────────────────────────────────────────

func (h *handler) emailSubmissionSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]struct {
			EmailID jmap.ID `json:"emailId"`
		} `json:"create"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]any{}

	for key, sub := range req.Create {
		msg, ok := h.store.TakePending(sub.EmailID)
		if !ok {
			msg, ok = h.store.Get(sub.EmailID)
		}
		if !ok {
			notCreated[key] = errObj("notFound", fmt.Sprintf("email %q not found", sub.EmailID))
			continue
		}

		body := vault.MessageBody(msg)
		inReplyTo := ""
		if len(msg.InReplyTo) > 0 {
			inReplyTo = msg.InReplyTo[0]
		}

		if err := sendClaude(body, inReplyTo); err != nil {
			notCreated[key] = errObj("serverFail", err.Error())
			continue
		}

		created[key] = map[string]any{
			"id":         newID(),
			"sendAt":     time.Now().UTC().Format(time.RFC3339),
			"undoStatus": "final",
		}
	}

	return map[string]any{
		"accountId":    jmap.ID(cfg.InboxKey),
		"oldState":     "0",
		"newState":     "1",
		"created":      created,
		"notCreated":   notCreated,
		"updated":      map[string]any{},
		"notUpdated":   map[string]any{},
		"destroyed":    []string{},
		"notDestroyed": map[string]any{},
	}, nil
}

// ── send ──────────────────────────────────────────────────────────────────────

func sendClaude(body, inReplyTo string) error {
	sessionID := strings.Trim(inReplyTo, "<>")
	sessionID = strings.TrimSuffix(sessionID, "@claude")
	if sessionID == "" {
		return fmt.Errorf("cannot determine session ID from inReplyTo=%q", inReplyTo)
	}

	var cwd string
	for _, dir := range cfg.ProjectDirs {
		if _, err := os.Stat(filepath.Join(dir, sessionID+".jsonl")); err == nil {
			cwd = decodeCwd(dir)
			break
		}
	}

	cmd := exec.Command("claude", "--resume", sessionID, "--print", body)
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("claude send failed: %w\noutput: %s", err, string(out))
	}
	return nil
}

// ── watch ─────────────────────────────────────────────────────────────────────

func watchProjects(ctx context.Context, h *handler, hub *jmapserver.Hub) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[watch] NewWatcher error: %v", err)
		return
	}
	defer watcher.Close()
	for _, dir := range cfg.ProjectDirs {
		if err := watcher.Add(dir); err != nil {
			log.Printf("[watch] failed to watch %s: %v", dir, err)
		} else {
			log.Printf("[watch] watching %s", dir)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 && strings.HasSuffix(event.Name, ".jsonl") {
				log.Printf("[watch] detected: %s", event.Name)
				h.scanProjects()
				hub.Notify()
			}
		case <-watcher.Errors:
		}
	}
}

// ── parse JSONL ───────────────────────────────────────────────────────────────

type claudeEntry struct {
	Type        string `json:"type"`
	IsSidechain bool   `json:"isSidechain"`
	AITitle     string `json:"aiTitle"`
	Timestamp   string `json:"timestamp"`
	Message     struct {
		Role    string          `json:"role"`
		Model   string          `json:"model"`
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

const maxMsgsPerSession = 50

func loadAppTitles() map[string]string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code-sessions")
	titles := map[string]string{}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var s struct {
			CliSessionID string `json:"cliSessionId"`
			Title        string `json:"title"`
		}
		if json.Unmarshal(b, &s) == nil && s.CliSessionID != "" && s.Title != "" {
			titles[s.CliSessionID] = s.Title
		}
		return nil
	})
	return titles
}

func parseJSONL(path, projectName, rootSessionID, fallbackTitle string) []vault.Message {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sessionRef := fmt.Sprintf("<%s@claude>", rootSessionID)

	mailboxID := vault.MakeMailboxID(cfg.InboxKey)
	userAddr := cfg.UserName
	if userAddr == "" {
		userAddr = cfg.InboxKey
	}

	var emails []vault.Message
	aiTitle := fallbackTitle
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for sc.Scan() {
		var e claudeEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		if e.Type == "ai-title" && e.AITitle != "" {
			aiTitle = e.AITitle
			continue
		}
		if e.IsSidechain || (e.Type != "user" && e.Type != "assistant") {
			continue
		}
		content := string(e.Message.Content)
		if e.Message.Role == "tool" ||
			strings.Contains(content, "No response requested") ||
			strings.Contains(content, "<local-command-caveat>") ||
			strings.Contains(content, "DO NOT respond to these") ||
			strings.Contains(content, "Continue from where you left off") {
			continue
		}

		t, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil || t.IsZero() {
			continue
		}

		body := extractBody(e.Message.Content)
		if body == "" {
			continue
		}

		var from vault.Address
		if e.Type == "assistant" {
			model := e.Message.Model
			if model == "" {
				model = "claude"
			}
			from = vault.Address{Email: projectName, Name: model}
		} else {
			from = vault.Address{Email: cfg.InboxKey, Name: userAddr}
		}

		eID := vault.MakeMessageID("", cfg.InboxKey, t)
		threadID := vault.MakeThreadID(sessionRef)

		email := vault.NewTextMessage(
			eID,
			threadID,
			mailboxID,
			[]*vault.Address{&from},
			[]*vault.Address{{Email: projectName}},
			nil,
			aiTitle,
			body,
			t,
			sessionRef,
		)
		emails = append(emails, email)
	}

	if len(emails) > maxMsgsPerSession {
		emails = emails[len(emails)-maxMsgsPerSession:]
	}
	return emails
}

// ── session graph ─────────────────────────────────────────────────────────────

func buildSessionParentMap(dir string, entries []os.DirEntry) map[string]string {
	type uuidLoc struct {
		sessionID string
		lineNo    int
	}
	uuidToSession := map[string]uuidLoc{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		sid := strings.TrimSuffix(e.Name(), ".jsonl")
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		lineNo := 0
		for sc.Scan() {
			var entry struct {
				UUID string `json:"uuid"`
			}
			if json.Unmarshal(sc.Bytes(), &entry) == nil && entry.UUID != "" {
				if prev, ok := uuidToSession[entry.UUID]; !ok || lineNo > prev.lineNo {
					uuidToSession[entry.UUID] = uuidLoc{sid, lineNo}
				}
			}
			lineNo++
		}
		f.Close()
	}

	parentMap := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		sid := strings.TrimSuffix(e.Name(), ".jsonl")
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
		for sc.Scan() {
			var entry struct {
				Type    string `json:"type"`
				Subtype string `json:"subtype"`
				Parent  string `json:"logicalParentUuid"`
			}
			if json.Unmarshal(sc.Bytes(), &entry) == nil &&
				entry.Type == "system" && entry.Subtype == "compact_boundary" && entry.Parent != "" {
				if loc, ok := uuidToSession[entry.Parent]; ok && loc.sessionID != sid {
					parentMap[sid] = loc.sessionID
				}
				break
			}
		}
		f.Close()
	}
	return parentMap
}

func rootSession(sessionID string, parentMap map[string]string) string {
	visited := map[string]bool{}
	for {
		if visited[sessionID] {
			break
		}
		visited[sessionID] = true
		p := parentMap[sessionID]
		if p == "" {
			break
		}
		sessionID = p
	}
	return sessionID
}

// ── helpers ───────────────────────────────────────────────────────────────────

func previewText(s string) string {
	r := []rune(s)
	if len(r) > 256 {
		return string(r[:256])
	}
	return s
}

func extractBody(content json.RawMessage) string {
	if content == nil {
		return ""
	}
	var s string
	if json.Unmarshal(content, &s) == nil {
		return strings.TrimSpace(s)
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) == nil {
		var parts []string
		for _, b := range blocks {
			if b.Type == "text" && b.Text != "" {
				parts = append(parts, strings.TrimSpace(b.Text))
			}
		}
		return strings.Join(parts, "\n\n")
	}
	return ""
}

func stripProjectPrefix(name string) string {
	re := name
	count := 0
	for i, c := range re {
		if c == '-' {
			count++
			if count == 3 {
				return re[i+1:]
			}
		}
	}
	return name
}

func decodeCwd(projectDir string) string {
	name := filepath.Base(projectDir)
	if !strings.HasPrefix(name, "-") {
		return ""
	}
	tokens := strings.Split(name[1:], "-")
	for i := len(tokens); i >= 1; i-- {
		parts := append(tokens[:i-1:i-1], strings.Join(tokens[i-1:], "-"))
		candidate := "/" + strings.Join(parts, "/")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	return ""
}

func errObj(typ, desc string) map[string]string {
	return map[string]string{"type": typ, "description": desc}
}

func newID() jmap.ID {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return jmap.ID(fmt.Sprintf("srv-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)))
}

// ── entry point ───────────────────────────────────────────────────────────────

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}

	store, err := jmapserver.NewStore(filepath.Join(dir, "data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	h := &handler{
		store:     store,
		statePath: filepath.Join(dir, "data", "fetchstate.json"),
	}
	if b, err := os.ReadFile(h.statePath); err == nil {
		json.Unmarshal(b, &h.state) //nolint:errcheck
	}

	hub := jmapserver.NewHub()
	log.Printf("[watch] starting watcher for %d dirs", len(cfg.ProjectDirs))
	go watchProjects(context.Background(), h, hub)
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port)
	}
	log.Printf("claude: listening on %s", cfg.ListenAddr)
	log.Fatal(jmapserver.Serve(cfg.Config, h, hub))
}
