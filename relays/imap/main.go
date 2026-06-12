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

	"biset/vault"
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
	LastUID     string            `json:"last_uid"`
	SentLastUID string            `json:"sent_last_uid"`
	SentMailbox string            `json:"sent_mailbox"`
	EmailUIDs   map[string]uint32 `json:"email_uids,omitempty"` // emailId → IMAP UID
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

	statePath = filepath.Join(dir, "state.json")
	loadState()

	ctx := context.Background()
	for _, acct := range cfg.Accounts {
		acct := acct
		go watchAccount(ctx, acct)
	}

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
		result, err := fetchAll()
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		respond(req.ID, result, nil)

	case "send":
		var params struct {
			Email    vault.Message  `json:"email"`
			Envelope vault.Envelope `json:"envelope"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			respond(req.ID, nil, err)
			return
		}
		raw, err := sendFromEmail(params.Email, params.Envelope)
		if err != nil {
			respond(req.ID, nil, err)
			return
		}
		// append to Sent
		acct := accountForEmail(params.Email)
		if acct != nil {
			go appendToSent(acct.IMAP, raw)
		}
		respond(req.ID, map[string]any{}, nil)

	case "handle":
		var params struct {
			EmailID string `json:"emailId"`
			Action  string `json:"action"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			respond(req.ID, nil, err)
			return
		}
		err := handleAction(params.EmailID, params.Action)
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
	if len(cfg.Accounts) > 0 {
		return &cfg.Accounts[0]
	}
	return nil
}

func accountForEmail(email vault.Message) *AccountConfig {
	mbxID := vault.MessageMailboxID(email)
	inboxKey := vault.InboxKeyFromMailboxID(mbxID)
	return accountFor(inboxKey)
}

func fetchAll() (vault.FetchResult, error) {
	var result vault.FetchResult
	stateMu.Lock()
	defer stateMu.Unlock()

	for _, acct := range cfg.Accounts {
		acctState := state.Accounts[acct.InboxKey]
		emails, newState, err := imapFetch(acct.IMAP, acct.InboxKey, acctState)
		if err != nil {
			log.Printf("[%s] fetch: %v", acct.InboxKey, err)
			continue
		}
		state.Accounts[acct.InboxKey] = newState
		result.Messages = append(result.Messages, emails...)
		result.Inboxes = append(result.Inboxes, vault.DefaultInbox(acct.InboxKey))
	}
	saveState()
	return result, nil
}

// sendFromEmail builds SMTP parameters from a JMAP Email and Envelope and sends.
func sendFromEmail(email vault.Message, envelope vault.Envelope) ([]byte, error) {
	inboxKey := vault.InboxKeyFromMailboxID(vault.MessageMailboxID(email))
	acct := accountFor(inboxKey)
	if acct == nil {
		return nil, fmt.Errorf("no account for inbox %q", inboxKey)
	}

	var to, cc, bcc []string
	for _, a := range email.To {
		if a != nil {
			to = append(to, a.Email)
		}
	}
	for _, a := range email.CC {
		if a != nil {
			cc = append(cc, a.Email)
		}
	}
	for _, a := range email.BCC {
		if a != nil {
			bcc = append(bcc, a.Email)
		}
	}

	inReplyTo := ""
	if len(email.InReplyTo) > 0 {
		inReplyTo = email.InReplyTo[0]
	}

	body := vault.MessageBody(email)

	return sendSMTP(
		acct.SMTP,
		acct.IMAP.Username,
		to, cc, bcc,
		email.Subject,
		body,
		inReplyTo,
	)
}

func handleAction(emailID, action string) error {
	stateMu.Lock()
	defer stateMu.Unlock()

	// find account that has this email
	for _, acct := range cfg.Accounts {
		acctState := state.Accounts[acct.InboxKey]
		if err := imapHandle(acct.IMAP, acctState, emailID, action); err != nil {
			log.Printf("[%s] handle %s: %v", acct.InboxKey, emailID, err)
		}
	}
	return nil
}

func watchAccount(ctx context.Context, acct AccountConfig) {
	imapWatch(ctx, acct.IMAP, func() {
		notify("new_messages")
	})
}
