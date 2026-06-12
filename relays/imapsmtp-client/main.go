package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/relays/core"
	"biset/vault"
)

// ── config ────────────────────────────────────────────────────────────────────

type AccountConfig struct {
	InboxKey string     `json:"inbox_key"`
	IMAP     IMAPConfig `json:"imap"`
	SMTP     SMTPConfig `json:"smtp"`
}

// Config embeds core.Config (port, bind, username, password) plus IMAP/SMTP accounts.
type Config struct {
	core.Config
	Accounts []AccountConfig `json:"accounts"`
}

// ── handler ───────────────────────────────────────────────────────────────────

// handler implements core.Handler by delegating to store (JMAP persistence) and
// client functions (IMAP/SMTP protocol).
type handler struct {
	store     *core.Store
	fetchMu   sync.Mutex
	states    map[string]FetchState // inboxKey → incremental IMAP state
	statePath string
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []core.Account {
	out := make([]core.Account, 0, len(cfg.Accounts))
	for _, a := range cfg.Accounts {
		out = append(out, core.Account{ID: jmap.ID(a.InboxKey), Name: a.InboxKey})
	}
	return out
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	switch method {
	case "Email/query":
		return h.emailQuery()
	case "Email/get":
		return h.emailGet(args)
	case "Mailbox/get":
		return h.mailboxGet()
	case "Email/set":
		return h.emailSet(args)
	case "EmailSubmission/set":
		return h.emailSubmissionSet(args)
	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

// ── Email/query ───────────────────────────────────────────────────────────────

func (h *handler) emailQuery() (any, error) {
	h.fetchMu.Lock()
	defer h.fetchMu.Unlock()

	for _, acct := range cfg.Accounts {
		state := h.states[acct.InboxKey]
		msgs, newState, err := FetchNew(acct.IMAP, acct.InboxKey, state)
		if err != nil {
			log.Printf("[%s] fetch: %v", acct.InboxKey, err)
			continue
		}
		h.states[acct.InboxKey] = newState
		for _, m := range msgs {
			if err := h.store.Put(m); err != nil {
				log.Printf("[%s] store put: %v", acct.InboxKey, err)
			}
		}
	}
	h.saveStates()

	all := h.store.All()
	ids := make([]jmap.ID, len(all))
	for i, m := range all {
		ids[i] = m.ID
	}
	return map[string]any{
		"accountId":           h.primaryID(),
		"queryState":          "0",
		"canCalculateChanges": false,
		"position":            0,
		"ids":                 ids,
		"total":               len(ids),
	}, nil
}

// ── Email/get ─────────────────────────────────────────────────────────────────

func (h *handler) emailGet(args json.RawMessage) (any, error) {
	var req struct {
		IDs []jmap.ID `json:"ids"`
	}
	json.Unmarshal(args, &req) //nolint:errcheck

	var list []vault.Message
	var notFound []jmap.ID
	for _, id := range req.IDs {
		if m, ok := h.store.Get(id); ok {
			list = append(list, m)
		} else {
			notFound = append(notFound, id)
		}
	}
	if list == nil {
		list = []vault.Message{}
	}
	if notFound == nil {
		notFound = []jmap.ID{}
	}
	return map[string]any{
		"accountId": h.primaryID(),
		"state":     "0",
		"list":      list,
		"notFound":  notFound,
	}, nil
}

// ── Mailbox/get ───────────────────────────────────────────────────────────────

func (h *handler) mailboxGet() (any, error) {
	mbs := h.store.Mailboxes()
	if mbs == nil {
		mbs = []vault.Inbox{}
		for _, a := range cfg.Accounts {
			mbs = append(mbs, vault.DefaultInbox(a.InboxKey))
		}
	}
	return map[string]any{
		"accountId": h.primaryID(),
		"state":     "0",
		"list":      mbs,
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
		msg.ID = newID()
		h.store.PutPending(msg)
		created[key] = map[string]any{"id": msg.ID}
	}

	for msgID, rawPatch := range req.Update {
		var patch map[string]any
		if err := json.Unmarshal(rawPatch, &patch); err != nil {
			notUpdated[msgID] = errObj("invalidProperties", err.Error())
			continue
		}
		// persist keyword changes to store
		if err := h.store.PatchKeywords(msgID, patch); err != nil {
			log.Printf("store patch %s: %v", msgID, err)
		}
		// apply to IMAP server
		h.applyIMAPAction(string(msgID), patch)
		updated[msgID] = map[string]any{}
	}

	return map[string]any{
		"accountId":    h.primaryID(),
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

// applyIMAPAction translates a JMAP keyword patch to IMAP flag/expunge operations.
func (h *handler) applyIMAPAction(msgID string, patch map[string]any) {
	h.fetchMu.Lock()
	states := h.states
	h.fetchMu.Unlock()

	for _, acct := range cfg.Accounts {
		state := states[acct.InboxKey]
		switch {
		case patch["keywords/$seen"] == true:
			if err := SetFlag(acct.IMAP, state, msgID); err != nil {
				log.Printf("[%s] setflag %s: %v", acct.InboxKey, msgID, err)
			}
		case patch["keywords/$deleted"] == true,
			patch["keywords/$biset_archived"] == true,
			patch["keywords/$spam"] == true:
			if err := Expunge(acct.IMAP, state, msgID); err != nil {
				log.Printf("[%s] expunge %s: %v", acct.InboxKey, msgID, err)
			}
		}
	}
}

// ── EmailSubmission/set ───────────────────────────────────────────────────────

func (h *handler) emailSubmissionSet(args json.RawMessage) (any, error) {
	var req struct {
		Create map[jmap.ID]struct {
			EmailID  jmap.ID         `json:"emailId"`
			Envelope *vault.Envelope `json:"envelope"`
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

		acct := h.accountForMsg(msg, sub.Envelope)
		if acct == nil {
			notCreated[key] = errObj("serverFail", "no matching account")
			continue
		}

		to, cc, bcc := recipientsFrom(msg, sub.Envelope)
		inReplyTo := ""
		if len(msg.InReplyTo) > 0 {
			inReplyTo = msg.InReplyTo[0]
		}

		raw, err := Send(acct.SMTP, acct.IMAP.Username, to, cc, bcc, msg.Subject, vault.MessageBody(msg), inReplyTo)
		if err != nil {
			notCreated[key] = errObj("serverFail", err.Error())
			continue
		}
		go AppendToSent(acct.IMAP, raw)

		created[key] = map[string]any{
			"id":         newID(),
			"sendAt":     time.Now().UTC().Format(time.RFC3339),
			"undoStatus": "final",
		}
	}

	return map[string]any{
		"accountId":    h.primaryID(),
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

func (h *handler) accountForMsg(msg vault.Message, envelope *vault.Envelope) *AccountConfig {
	var fromAddr string
	if envelope != nil && envelope.MailFrom != nil {
		fromAddr = envelope.MailFrom.Email
	} else if len(msg.From) > 0 && msg.From[0] != nil {
		fromAddr = msg.From[0].Email
	}
	for i := range cfg.Accounts {
		if cfg.Accounts[i].IMAP.Username == fromAddr {
			return &cfg.Accounts[i]
		}
	}
	inboxKey := vault.InboxKeyFromMailboxID(vault.MessageMailboxID(msg))
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

func recipientsFrom(msg vault.Message, envelope *vault.Envelope) (to, cc, bcc []string) {
	if envelope != nil {
		for _, a := range envelope.RcptTo {
			if a != nil {
				to = append(to, a.Email)
			}
		}
		if len(to) > 0 {
			return
		}
	}
	for _, a := range msg.To {
		if a != nil {
			to = append(to, a.Email)
		}
	}
	for _, a := range msg.CC {
		if a != nil {
			cc = append(cc, a.Email)
		}
	}
	for _, a := range msg.BCC {
		if a != nil {
			bcc = append(bcc, a.Email)
		}
	}
	return
}

// ── state persistence ─────────────────────────────────────────────────────────

func (h *handler) loadStates() {
	h.states = map[string]FetchState{}
	b, err := os.ReadFile(h.statePath)
	if err != nil {
		return
	}
	json.Unmarshal(b, &h.states) //nolint:errcheck
}

func (h *handler) saveStates() {
	b, _ := json.MarshalIndent(h.states, "", "  ")
	os.WriteFile(h.statePath, b, 0644) //nolint:errcheck
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (h *handler) primaryID() jmap.ID {
	if len(cfg.Accounts) > 0 {
		return jmap.ID(cfg.Accounts[0].InboxKey)
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

var cfg Config

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

	store, err := core.NewStore(filepath.Join(dir, "data"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	h := &handler{
		store:     store,
		statePath: filepath.Join(dir, "data", "fetchstate.json"),
	}
	h.loadStates()

	hub := core.NewHub()
	ctx := context.Background()
	for _, acct := range cfg.Accounts {
		a := acct
		go Watch(ctx, a.IMAP, func() {
			log.Printf("[%s] imap idle: new messages", a.InboxKey)
			hub.Notify()
		})
	}

	log.Printf("imapsmtp: listening on %s:%d", cfg.Bind, cfg.Port)
	log.Fatal(core.Serve(cfg.Config, h, hub))
}
