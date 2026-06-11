package main

import (
	"bufio"
	"context"
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
	"github.com/yd7a/biset/core"
)

type Config struct {
	ProjectDirs []string `json:"project_dirs"`
	InboxKey    string   `json:"inbox_key"`
	UserName    string   `json:"user_name"`
}

type State struct {
	LastMtimeNs int64 `json:"last_mtime_ns"`
}

var (
	cfg       Config
	state     State
	statePath string
	stateMu   sync.Mutex
	outMu     sync.Mutex
	enc       = json.NewEncoder(os.Stdout)
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      *int64    `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
	Method  string    `json:"method,omitempty"`
	Params  any       `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func respond(id *int64, result any, err error) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id}
	if err != nil {
		resp.Error = &rpcError{Code: -32000, Message: err.Error()}
	} else {
		resp.Result = result
	}
	outMu.Lock()
	enc.Encode(resp) //nolint:errcheck
	outMu.Unlock()
}

func notify(event string) {
	outMu.Lock()
	enc.Encode(rpcResponse{JSONRPC: "2.0", Method: "notify", Params: map[string]string{"event": event}}) //nolint:errcheck
	outMu.Unlock()
}

func main() {
	dir, _ := filepath.Abs(filepath.Dir(os.Args[0]))

	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}

	statePath = filepath.Join(dir, "state.json")
	if b, err := os.ReadFile(statePath); err == nil {
		json.Unmarshal(b, &state) //nolint:errcheck
	}

	go watchProjects(context.Background())

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		go handle(req)
	}
}

func handle(req rpcRequest) {
	switch req.Method {
	case "ping":
		respond(req.ID, "pong", nil)

	case "fetch":
		result, err := fetchAll()
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		respond(req.ID, result, nil)

	case "send":
		var p struct {
			Email    core.Email    `json:"email"`
			Envelope core.Envelope `json:"envelope"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			respond(req.ID, nil, err)
			return
		}
		body := core.EmailBody(p.Email)
		inReplyTo := ""
		if len(p.Email.InReplyTo) > 0 {
			inReplyTo = p.Email.InReplyTo[0]
		}
		respond(req.ID, map[string]any{}, sendClaude(body, inReplyTo))

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}

// ── fetch ─────────────────────────────────────────────────────────────────────

// buildSessionParentMap scans all jsonl files in dir and returns a map of
// childSessionID -> parentSessionID using logicalParentUuid linkage.
// When the same entry UUID appears in multiple files (copied context), the parent
// is the file where the UUID appears latest (highest line number = original source).
func buildSessionParentMap(dir string, entries []os.DirEntry) map[string]string {
	type uuidLoc struct {
		sessionID string
		lineNo    int
	}
	// step 1: build entryUUID -> location with highest line number
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

	// step 2: for each session, find its parent session via logicalParentUuid
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

// rootSession walks the parent chain and returns the root session ID.
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

func fetchAll() (core.FetchResult, error) {
	stateMu.Lock()
	defer stateMu.Unlock()

	// Re-read state from disk so external resets (e.g. state.json → 0) take effect
	// without requiring a process restart.
	if b, err := os.ReadFile(statePath); err == nil {
		var s State
		if json.Unmarshal(b, &s) == nil && s.LastMtimeNs < state.LastMtimeNs {
			state = s
		}
	}

	appTitles := loadAppTitles()

	var emails []core.Email
	newMtime := state.LastMtimeNs

	for _, scanDir := range cfg.ProjectDirs {
		entries, err := os.ReadDir(scanDir)
		if err != nil {
			continue
		}
		projectName := stripProjectPrefix(filepath.Base(scanDir))

		// Collect new entries first; skip full parentMap scan if nothing changed.
		var newEntries []os.DirEntry
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			info, _ := e.Info()
			if info == nil {
				continue
			}
			if info.ModTime().UnixNano() > state.LastMtimeNs {
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
			emails = append(emails, parseJSONL(filepath.Join(scanDir, e.Name()), projectName, root, title)...)
		}
	}

	state.LastMtimeNs = newMtime
	if b, err := json.MarshalIndent(state, "", "  "); err == nil {
		os.WriteFile(statePath, b, 0644) //nolint:errcheck
	}

	mailbox := core.DefaultMailbox(cfg.InboxKey)
	return core.FetchResult{
		Emails:    emails,
		Mailboxes: []core.Mailbox{mailbox},
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

func watchProjects(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer watcher.Close()
	for _, dir := range cfg.ProjectDirs {
		watcher.Add(dir) //nolint:errcheck
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
				notify("new_messages")
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

// loadAppTitles scans the Claude desktop app session storage and returns a
// map of cliSessionID → title for sessions that have an auto-generated title.
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

func parseJSONL(path, projectName, rootSessionID, fallbackTitle string) []core.Email {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	sessionRef := fmt.Sprintf("<%s@claude>", rootSessionID)

	mailboxID := core.MakeMailboxID(cfg.InboxKey)
	userAddr := cfg.UserName
	if userAddr == "" {
		userAddr = cfg.InboxKey
	}

	var emails []core.Email
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

		var from core.Address
		if e.Type == "assistant" {
			model := e.Message.Model
			if model == "" {
				model = "claude"
			}
			from = core.Address{Email: projectName, Name: model}
		} else {
			from = core.Address{Email: cfg.InboxKey, Name: userAddr}
		}

		eID := core.MakeEmailID("", cfg.InboxKey, t)
		threadID := core.MakeThreadID(sessionRef)

		partID := "1"
		email := core.Email{
			ID:         eID,
			BlobID:     "blob-" + eID,
			ThreadID:   threadID,
			MailboxIDs: map[string]bool{mailboxID: true},
			Keywords:   map[string]bool{"$seen": true},
			From:       []core.Address{from},
			To:         []core.Address{{Email: projectName}},
			Subject:    aiTitle,
			ReceivedAt: t,
			InReplyTo:  []string{sessionRef},
			References: []string{sessionRef},
			BodyValues: map[string]core.BodyValue{partID: {Value: body}},
			TextBody:   []core.BodyPart{{PartID: partID, BlobID: "blob-" + eID + "-body", Type: "text/plain", Charset: "utf-8", Size: len(body)}},
			HtmlBody:   []core.BodyPart{},
			Preview:    previewText(body),
			Size:       len(body),
		}
		emails = append(emails, email)
	}

	// return only the most recent N emails
	if len(emails) > maxMsgsPerSession {
		emails = emails[len(emails)-maxMsgsPerSession:]
	}
	return emails
}

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

// ── helpers ───────────────────────────────────────────────────────────────────

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
