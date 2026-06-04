package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/yd7a/biset/core"
)

// ── config ────────────────────────────────────────────────────────────────────

type AccountConfig struct {
	InboxKey string     `json:"inbox_key"`
	IMAP     IMAPConfig `json:"imap"`
	SMTP     SMTPConfig `json:"smtp"`
}

type Config struct {
	Accounts []AccountConfig `json:"accounts"`
}

// ── state ─────────────────────────────────────────────────────────────────────

type AccountState struct {
	LastUID     string `json:"last_uid"`
	SentLastUID string `json:"sent_last_uid"`
	SentMailbox string `json:"sent_mailbox"`
}

type State struct {
	Accounts map[string]AccountState `json:"accounts"`
}

var (
	cfg       Config
	state     State
	statePath string
	stateMu   sync.Mutex
)

func loadState() {
	state = State{Accounts: map[string]AccountState{}}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return
	}
	json.Unmarshal(b, &state) //nolint:errcheck
	if state.Accounts == nil {
		state.Accounts = map[string]AccountState{}
	}
}

func saveState() {
	b, _ := json.MarshalIndent(state, "", "  ")
	os.WriteFile(statePath, b, 0644) //nolint:errcheck
}

// ── JSON-RPC server ───────────────────────────────────────────────────────────

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

var (
	outMu sync.Mutex
	enc   = json.NewEncoder(os.Stdout)
)

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
	enc.Encode(rpcResponse{ //nolint:errcheck
		JSONRPC: "2.0",
		Method:  "notify",
		Params:  map[string]string{"event": event},
	})
	outMu.Unlock()
}

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}

	// load config
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}

	// fill SMTP defaults from IMAP
	for i := range cfg.Accounts {
		a := &cfg.Accounts[i]
		if a.SMTP.Host == "" {
			a.SMTP.Host = a.IMAP.Host
		}
		if a.SMTP.Username == "" {
			a.SMTP.Username = a.IMAP.Username
		}
		if a.SMTP.Password == "" {
			a.SMTP.Password = a.IMAP.Password
		}
		if a.SMTP.Port == 0 {
			a.SMTP.Port = 587
		}
		if a.SMTP.TLSMode == "" {
			a.SMTP.TLSMode = "starttls"
		}
	}

	// load state
	statePath = filepath.Join(dir, "state.json")
	loadState()

	// start IDLE watchers
	ctx := context.Background()
	for _, acct := range cfg.Accounts {
		acct := acct
		go watchAccount(ctx, acct)
	}

	// JSON-RPC loop
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		go handleRequest(req)
	}
}

func handleRequest(req rpcRequest) {
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
		var params struct {
			Inbox    string `json:"inbox"`
			To       string `json:"to"`
			CC       string `json:"cc"`
			BCC      string `json:"bcc"`
			Subject  string `json:"subject"`
			Body     string `json:"body"`
			ParentID string `json:"parent_id"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			respond(req.ID, nil, err)
			return
		}
		acct := accountFor(params.Inbox)
		if acct == nil {
			respond(req.ID, nil, fmt.Errorf("no account for inbox %q", params.Inbox))
			return
		}
		raw, err := sendSMTP(acct.SMTP, acct.IMAP.Username, params.To, params.CC, params.BCC, params.Subject, params.Body, params.ParentID)
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		// append to Sent
		go appendToSent(acct.IMAP, raw)
		respond(req.ID, map[string]any{}, nil)

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
		acct := accountFor(params.Inbox)
		if acct == nil {
			respond(req.ID, nil, fmt.Errorf("no account for inbox %q", params.Inbox))
			return
		}
		err := imapHandle(acct.IMAP, params.MessageID, core.Action(params.Action))
		respond(req.ID, map[string]any{}, err)

	default:
		respond(req.ID, nil, fmt.Errorf("unknown method: %s", req.Method))
	}
}

func accountFor(inboxKey string) *AccountConfig {
	for i := range cfg.Accounts {
		if cfg.Accounts[i].InboxKey == inboxKey {
			return &cfg.Accounts[i]
		}
	}
	// fallback: first account
	if len(cfg.Accounts) > 0 {
		return &cfg.Accounts[0]
	}
	return nil
}

// fetchAll fetches new messages from all accounts.
func fetchAll() ([]core.Message, error) {
	var all []core.Message
	stateMu.Lock()
	defer stateMu.Unlock()

	for _, acct := range cfg.Accounts {
		acctState := state.Accounts[acct.InboxKey]
		msgs, newState, err := imapFetch(acct.IMAP, acct.InboxKey, acctState)
		if err != nil {
			log.Printf("[%s] fetch: %v", acct.InboxKey, err)
			continue
		}
		state.Accounts[acct.InboxKey] = newState
		all = append(all, msgs...)
	}
	saveState()
	return all, nil
}

func watchAccount(ctx context.Context, acct AccountConfig) {
	imapWatch(ctx, acct.IMAP, func() {
		notify("new_messages")
	})
}
