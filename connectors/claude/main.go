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
		msgs, err := fetchAll()
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		respond(req.ID, map[string]any{"messages": msgs}, nil)

	case "send":
		var p struct {
			Body     string `json:"body"`
			ParentID string `json:"parent_id"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			respond(req.ID, nil, err)
			return
		}
		respond(req.ID, map[string]any{}, sendClaude(p.Body, p.ParentID))

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}

// ── fetch ─────────────────────────────────────────────────────────────────────

func fetchAll() ([]core.Message, error) {
	stateMu.Lock()
	defer stateMu.Unlock()

	var msgs []core.Message
	newMtime := state.LastMtimeNs

	for _, scanDir := range cfg.ProjectDirs {
		entries, err := os.ReadDir(scanDir)
		if err != nil {
			continue
		}
		projectName := stripProjectPrefix(filepath.Base(scanDir))
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
				continue
			}
			info, _ := e.Info()
			if info == nil {
				continue
			}
			mtimeNs := info.ModTime().UnixNano()
			if mtimeNs <= state.LastMtimeNs {
				continue
			}
			if mtimeNs > newMtime {
				newMtime = mtimeNs
			}
			msgs = append(msgs, parseJSONL(filepath.Join(scanDir, e.Name()), projectName)...)
		}
	}

	state.LastMtimeNs = newMtime
	if b, err := json.MarshalIndent(state, "", "  "); err == nil {
		os.WriteFile(statePath, b, 0644) //nolint:errcheck
	}
	return msgs, nil
}

// ── send ──────────────────────────────────────────────────────────────────────

func sendClaude(body, parentID string) error {
	sessionID := strings.Trim(parentID, "<>")
	sessionID = strings.TrimSuffix(sessionID, "@claude")
	if sessionID == "" {
		return fmt.Errorf("cannot determine session ID from parent_id=%q", parentID)
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

func parseJSONL(path, projectName string) []core.Message {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	base := filepath.Base(path)
	sessionID := strings.TrimSuffix(base, ".jsonl")
	sessionRef := fmt.Sprintf("<%s@claude>", sessionID)

	var msgs []core.Message
	aiTitle := ""
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

		from := cfg.UserName
		fromName := cfg.UserName
		if from == "" {
			from = cfg.InboxKey
		}
		if e.Type == "assistant" {
			from = projectName
			fromName = e.Message.Model
			if fromName == "" {
				fromName = "claude"
			}
		}

		msgs = append(msgs, core.Message{
			From:     from,
			Body:     body,
			Ts:       t.UnixMilli(),
			ParentID: sessionRef,
			Seen:     true, // no server-side seen concept for claude
			Meta: map[string]string{
				core.MetaFromName: fromName,
				core.MetaSubject:  aiTitle,
				"inbox_key":       cfg.InboxKey,
				"protocol":        "claude",
			},
		})
	}
	// return only the most recent N messages
	if len(msgs) > maxMsgsPerSession {
		msgs = msgs[len(msgs)-maxMsgsPerSession:]
	}
	return msgs
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
	// "-Users-n-biset-core" → "biset-core"
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
