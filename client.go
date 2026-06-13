package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/emailsubmission"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"biset/vault"
)

const mailURI = jmap.URI("urn:ietf:params:jmap:mail")

// FetchResult is an alias for vault.FetchResult.
type FetchResult = vault.FetchResult

// Manager holds configured Relay connections.
type Manager struct {
	relays  []*Relay
	changed chan struct{}
}

func NewManager(cfg *vault.Config) *Manager {
	m := &Manager{changed: make(chan struct{}, 1)}
	for _, rc := range cfg.Relays {
		m.relays = append(m.relays, newRelay(rc))
	}
	return m
}

func (m *Manager) Relays() []*Relay { return m.relays }

// Changed returns a channel that receives when any relay reports new messages.
func (m *Manager) Changed() <-chan struct{} { return m.changed }

func (m *Manager) notifyChange() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// WatchRelays starts background SSE subscribers for all configured relays.
func (m *Manager) WatchRelays() {
	for _, r := range m.relays {
		go r.watchSSE(m.notifyChange)
	}
}

// RelayForAccount returns the Relay that manages the given inboxKey (account ID).
func (m *Manager) RelayForAccount(inboxKey string) *Relay {
	id := jmap.ID(inboxKey)
	for _, r := range m.relays {
		if err := r.ensureAuth(); err != nil {
			continue
		}
		if _, ok := r.client.Session.Accounts[id]; ok {
			return r
		}
	}
	return nil
}

// ── Relay ─────────────────────────────────────────────────────────────────────

// Relay is a JMAP peer that biset connects to as a client.
type Relay struct {
	cfg       vault.RelayConfig
	client    *jmap.Client
	accountID jmap.ID
	mu        sync.Mutex
	authed    bool
}

func newRelay(cfg vault.RelayConfig) *Relay {
	c := &jmap.Client{SessionEndpoint: cfg.URL}
	switch {
	case cfg.Token != "":
		c.WithAccessToken(cfg.Token)
	case cfg.RelayName != "":
		c.WithBasicAuth(cfg.RelayName, cfg.Password)
	default:
		c.HttpClient = http.DefaultClient
	}
	return &Relay{cfg: cfg, client: c}
}

func setErrMsg(e *jmap.SetError) string {
	if e.Description != nil {
		return e.Type + ": " + *e.Description
	}
	return e.Type
}

func (r *Relay) Name() string { return r.cfg.URL }

// watchSSE subscribes to the relay's JMAP EventSource and calls onChange on state events.
// Loops forever, reconnecting on error.
func (r *Relay) watchSSE(onChange func()) {
	for {
		if err := r.watchSSEOnce(onChange); err != nil {
			log.Printf("[relay] %s: sse: %v — retry in 30s", r.cfg.URL, err)
		}
		time.Sleep(30 * time.Second)
	}
}

func (r *Relay) watchSSEOnce(onChange func()) error {
	if err := r.ensureAuth(); err != nil {
		return err
	}
	eventURL := string(r.client.Session.EventSourceURL)
	if eventURL == "" {
		return fmt.Errorf("no EventSourceURL in session")
	}
	req, err := http.NewRequest("GET", eventURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if r.cfg.RelayName != "" {
		req.SetBasicAuth(r.cfg.RelayName, r.cfg.Password)
	} else if r.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: state") {
			onChange()
		}
	}
	return scanner.Err()
}

func (r *Relay) ensureAuth() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.authed {
		return nil
	}
	if err := r.client.Authenticate(); err != nil {
		return fmt.Errorf("%s: %w", r.cfg.URL, err)
	}
	if id, ok := r.client.Session.PrimaryAccounts[mailURI]; ok {
		r.accountID = id
	}
	r.authed = true
	return nil
}

func (r *Relay) Has(capability string) bool {
	if err := r.ensureAuth(); err != nil {
		log.Printf("[relay] %s: auth: %v", r.cfg.URL, err)
		return false
	}
	switch capability {
	case "fetch":
		_, ok := r.client.Session.RawCapabilities[mailURI]
		return ok
	case "send":
		subURI := jmap.URI("urn:ietf:params:jmap:submission")
		_, ok := r.client.Session.RawCapabilities[subURI]
		return ok
	}
	return false
}

// Fetch retrieves all messages and inboxes from the relay via JMAP.
func (r *Relay) Fetch() (FetchResult, error) {
	if err := r.ensureAuth(); err != nil {
		return FetchResult{}, err
	}

	req := &jmap.Request{}
	queryCallID := req.Invoke(&email.Query{
		Account: r.accountID,
		Sort:    []*email.SortComparator{{Property: "receivedAt", IsAscending: false}},
	})
	req.Invoke(&email.Get{
		Account: r.accountID,
		ReferenceIDs: &jmap.ResultReference{
			ResultOf: queryCallID,
			Name:     "Email/query",
			Path:     "/ids",
		},
		FetchAllBodyValues: true,
	})
	req.Invoke(&mailbox.Get{Account: r.accountID})

	resp, err := r.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch: %w", err)
	}

	var result FetchResult
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *email.GetResponse:
			for _, e := range res.List {
				if e != nil {
					result.Messages = append(result.Messages, *e)
				}
			}
		case *mailbox.GetResponse:
			for _, mb := range res.List {
				if mb != nil {
					result.Inboxes = append(result.Inboxes, *mb)
				}
			}
		}
	}
	return result, nil
}

// Send creates a draft email on the relay and submits it for delivery.
func (r *Relay) Send(msg vault.Message, envelope vault.Envelope) (time.Time, error) {
	if err := r.ensureAuth(); err != nil {
		return time.Time{}, err
	}

	createKey := jmap.ID("draft")
	setReq := &jmap.Request{}
	setReq.Invoke(&email.Set{
		Account: r.accountID,
		Create:  map[jmap.ID]*email.Email{createKey: &msg},
	})
	setResp, err := r.client.Do(setReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("email/set: %w", err)
	}

	var serverEmailID jmap.ID
	var serverReceivedAt time.Time
	for _, inv := range setResp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			if obj, ok2 := res.Created[createKey]; ok2 && obj != nil {
				serverEmailID = obj.ID
				if obj.ReceivedAt != nil {
					serverReceivedAt = *obj.ReceivedAt
				}
			}
			if e, ok2 := res.NotCreated[createKey]; ok2 {
				return time.Time{}, fmt.Errorf("email/set create: %s", setErrMsg(e))
			}
		}
	}
	if serverEmailID == "" {
		return time.Time{}, fmt.Errorf("email/set: no created ID in response")
	}

	subReq := &jmap.Request{}
	subReq.Invoke(&emailsubmission.Set{
		Account: r.accountID,
		Create: map[jmap.ID]*emailsubmission.EmailSubmission{
			"sub": {
				EmailID:  serverEmailID,
				Envelope: &envelope,
			},
		},
	})
	subResp, err := r.client.Do(subReq)
	if err != nil {
		return time.Time{}, fmt.Errorf("submission/set: %w", err)
	}
	for _, inv := range subResp.Responses {
		if res, ok := inv.Args.(*emailsubmission.SetResponse); ok {
			if e, ok2 := res.NotCreated["sub"]; ok2 {
				return time.Time{}, fmt.Errorf("submission/set create: %s", setErrMsg(e))
			}
		}
	}
	return serverReceivedAt, nil
}

// Handle patches email keywords (seen, archived, deleted, spam) on the relay.
func (r *Relay) Handle(msgID, action string) error {
	if err := r.ensureAuth(); err != nil {
		return err
	}

	patch := jmap.Patch{}
	switch action {
	case "seen":
		patch["keywords/$seen"] = true
	case "archived":
		patch["keywords/$biset_archived"] = true
	case "deleted":
		patch["keywords/$deleted"] = true
	case "spam":
		patch["keywords/$spam"] = true
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	req := &jmap.Request{}
	req.Invoke(&email.Set{
		Account: r.accountID,
		Update: map[jmap.ID]jmap.Patch{
			jmap.ID(msgID): patch,
		},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("email/set update: %w", err)
	}
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			if e, ok2 := res.NotUpdated[jmap.ID(msgID)]; ok2 {
				return fmt.Errorf("email/set update: %s", setErrMsg(e))
			}
		}
	}
	return nil
}
