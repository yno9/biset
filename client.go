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
	"git.sr.ht/~rockorager/go-jmap/mail/identity"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"git.sr.ht/~rockorager/go-jmap/mail/thread"
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

// InboxConfigFor returns the InboxConfig for the relay that owns inboxKey.
func (m *Manager) InboxConfigFor(inboxKey string, cfg *vault.Config) vault.InboxConfig {
	r := m.RelayForAccount(inboxKey)
	if r == nil {
		return vault.InboxConfig{}
	}
	return r.InboxConfigFor(inboxKey, cfg)
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

// NotificationEnabled resolves the notification setting for inboxKey on this relay.
func (r *Relay) NotificationEnabled(inboxKey string, cfg *vault.Config) bool {
	if err := r.ensureAuth(); err != nil {
		return true
	}
	return cfg.NotificationEnabled(r.cfg.URL, inboxKey, string(r.accountID))
}

// InboxConfigFor returns the InboxConfig for a specific inboxKey on this relay.
func (r *Relay) InboxConfigFor(inboxKey string, cfg *vault.Config) vault.InboxConfig {
	if err := r.ensureAuth(); err != nil {
		return vault.InboxConfig{}
	}
	for _, rc := range cfg.Relays {
		if rc.URL == r.cfg.URL {
			return rc.InboxConfigFor(inboxKey, string(r.accountID))
		}
	}
	return vault.InboxConfig{}
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

// AccountID returns the primary account ID for this relay.
func (r *Relay) AccountID() jmap.ID {
	r.ensureAuth() //nolint:errcheck
	return r.accountID
}

// Fetch retrieves messages and inboxes from the relay.
// If sinceQueryState is non-empty, attempts a delta fetch via Email/queryChanges + Email/changes.
// Falls back to full fetch on any error.
func (r *Relay) Fetch(sinceQueryState, sinceEmailState, sinceMailboxState string) (FetchResult, error) {
	if sinceQueryState != "" {
		result, err := r.fetchDelta(sinceQueryState, sinceEmailState, sinceMailboxState)
		if err == nil {
			return result, nil
		}
		log.Printf("[relay] %s: delta fetch failed (%v), falling back to full fetch", r.cfg.URL, err)
	}
	return r.fetchFull()
}

func (r *Relay) fetchFull() (FetchResult, error) {
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
	req.Invoke(&identity.Get{Account: r.accountID})
	req.Invoke(&email.Changes{Account: r.accountID, SinceState: ""})

	resp, err := r.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch: %w", err)
	}

	var result FetchResult
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *email.QueryResponse:
			result.QueryState = res.QueryState
		case *email.GetResponse:
			for _, e := range res.List {
				if e != nil {
					result.Messages = append(result.Messages, *e)
				}
			}
		case *mailbox.GetResponse:
			result.MailboxState = res.State
			for _, mb := range res.List {
				if mb != nil {
					result.Inboxes = append(result.Inboxes, *mb)
				}
			}
		case *email.ChangesResponse:
			result.EmailState = res.NewState
		case *identity.GetResponse:
			for _, id := range res.List {
				if id != nil {
					result.Identities = append(result.Identities, *id)
				}
			}
		}
	}

	result.Threads, _ = r.fetchThreads(threadIDsFrom(result.Messages))
	return result, nil
}

func (r *Relay) fetchDelta(sinceQueryState, sinceEmailState, sinceMailboxState string) (FetchResult, error) {
	if err := r.ensureAuth(); err != nil {
		return FetchResult{}, err
	}

	// Step 1: queryChanges + Email/changes + Mailbox/changes (or get) in one request
	req := &jmap.Request{}
	req.Invoke(&email.QueryChanges{
		Account:         r.accountID,
		SinceQueryState: sinceQueryState,
	})
	if sinceEmailState != "" {
		req.Invoke(&email.Changes{
			Account:    r.accountID,
			SinceState: sinceEmailState,
		})
	}
	if sinceMailboxState != "" {
		req.Invoke(&mailbox.Changes{
			Account:    r.accountID,
			SinceState: sinceMailboxState,
		})
	} else {
		req.Invoke(&mailbox.Get{Account: r.accountID})
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("queryChanges: %w", err)
	}

	var qcResp *email.QueryChangesResponse
	var changesResp *email.ChangesResponse
	var result FetchResult
	for _, inv := range resp.Responses {
		switch res := inv.Args.(type) {
		case *email.QueryChangesResponse:
			qcResp = res
		case *email.ChangesResponse:
			changesResp = res
		case *mailbox.GetResponse:
			result.MailboxState = res.State
			for _, mb := range res.List {
				if mb != nil {
					result.Inboxes = append(result.Inboxes, *mb)
				}
			}
		case *mailbox.ChangesResponse:
			result.MailboxState = res.NewState
			// Mailbox/changes only returns IDs; if anything changed, fall back to full Mailbox/get
			if len(res.Created)+len(res.Updated)+len(res.Destroyed) > 0 {
				if mbResp, err := r.fetchMailboxes(); err == nil {
					result.Inboxes = mbResp
				}
			}
		}
	}

	if qcResp == nil {
		return FetchResult{}, fmt.Errorf("no queryChanges response")
	}

	result.QueryState = qcResp.NewQueryState
	result.RemovedIDs = qcResp.Removed
	if changesResp != nil {
		result.EmailState = changesResp.NewState
	}

	// Step 2: fetch new messages + updated messages (keywords/flags)
	addedIDs := make([]jmap.ID, 0, len(qcResp.Added))
	for _, a := range qcResp.Added {
		addedIDs = append(addedIDs, a.ID)
	}

	var updatedIDs []jmap.ID
	if changesResp != nil {
		updatedIDs = changesResp.Updated
	}

	toFetch := deduplicateIDs(append(addedIDs, updatedIDs...))
	if len(toFetch) > 0 {
		getReq := &jmap.Request{}
		getReq.Invoke(&email.Get{
			Account:            r.accountID,
			IDs:                toFetch,
			FetchAllBodyValues: true,
		})
		getResp, err := r.client.Do(getReq)
		if err != nil {
			return FetchResult{}, fmt.Errorf("email/get: %w", err)
		}
		addedSet := make(map[jmap.ID]bool, len(addedIDs))
		for _, id := range addedIDs {
			addedSet[id] = true
		}
		for _, inv := range getResp.Responses {
			if res, ok := inv.Args.(*email.GetResponse); ok {
				for _, e := range res.List {
					if e == nil {
						continue
					}
					if addedSet[e.ID] {
						result.Messages = append(result.Messages, *e)
					} else {
						result.UpdatedMessages = append(result.UpdatedMessages, *e)
					}
				}
			}
		}
	}

	result.Threads, _ = r.fetchThreads(threadIDsFrom(result.Messages))
	return result, nil
}

func deduplicateIDs(ids []jmap.ID) []jmap.ID {
	seen := make(map[jmap.ID]bool, len(ids))
	out := ids[:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func threadIDsFrom(msgs []vault.Message) []jmap.ID {
	seen := map[jmap.ID]bool{}
	var ids []jmap.ID
	for _, m := range msgs {
		if tid := m.ThreadID; tid != "" && !seen[tid] {
			seen[tid] = true
			ids = append(ids, tid)
		}
	}
	return ids
}

func (r *Relay) fetchMailboxes() ([]vault.Inbox, error) {
	req := &jmap.Request{}
	req.Invoke(&mailbox.Get{Account: r.accountID})
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	var out []vault.Inbox
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*mailbox.GetResponse); ok {
			for _, mb := range res.List {
				if mb != nil {
					out = append(out, *mb)
				}
			}
		}
	}
	return out, nil
}

func (r *Relay) fetchThreads(ids []jmap.ID) ([]vault.Thread, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	req := &jmap.Request{}
	req.Invoke(&thread.Get{Account: r.accountID, IDs: ids})
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	var out []vault.Thread
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*thread.GetResponse); ok {
			for _, t := range res.List {
				if t != nil {
					out = append(out, *t)
				}
			}
		}
	}
	return out, nil
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

// Follow sends an Email/set create to the relay signalling a follow/subscribe intent.
// The relay interprets the To address as the follow target (feed URL, AP handle, etc).
func (r *Relay) Follow(contact string) error {
	if err := r.ensureAuth(); err != nil {
		return err
	}
	msg := vault.Message{
		To:       []*vault.Address{{Email: contact}},
		Keywords: map[string]bool{"$follow": true},
	}
	req := &jmap.Request{}
	req.Invoke(&email.Set{
		Account: r.accountID,
		Create:  map[jmap.ID]*email.Email{"follow": &msg},
	})
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("follow: email/set: %w", err)
	}
	for _, inv := range resp.Responses {
		if res, ok := inv.Args.(*email.SetResponse); ok {
			if e, ok2 := res.NotCreated["follow"]; ok2 {
				return fmt.Errorf("follow: %s", setErrMsg(e))
			}
		}
	}
	return nil
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
