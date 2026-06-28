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
	"biset/vault"
)

// Relay is a JMAP peer that biset connects to as a client.
// For multi-account relays, one Relay represents one (URL, email) pair.
type Relay struct {
	cfg            vault.RelayConfig
	client         *jmap.Client
	accountID      jmap.ID
	mu             sync.Mutex
	authed         bool
	accountEmail   string // populated only for per-account relay instances
	accountPlainPW string // plaintext user password; used once for envelope unseal
	kek            []byte // 32B AES-GCM key for PGP privkey enc/dec; populated by envelope login
}

// RelayName returns the relay type identifier from config (e.g. "jmapsmtp", "claude").
// Stable across multi-account expansion (does not get overridden to the account email).
func (r *Relay) RelayName() string { return r.cfg.RelayName }

func newRelay(cfg vault.RelayConfig) *Relay {
	if cfg.AuthUser == "" {
		cfg.AuthUser = cfg.RelayName
	}
	c := &jmap.Client{SessionEndpoint: cfg.URL}
	switch {
	case cfg.Token != "":
		c.WithAccessToken(cfg.Token)
	case cfg.AuthUser != "":
		c.WithBasicAuth(cfg.AuthUser, cfg.Password)
	default:
		c.HttpClient = http.DefaultClient
	}
	return &Relay{cfg: cfg, client: c}
}

// NotificationEnabled resolves the notification setting for mailboxName on this relay.
func (r *Relay) NotificationEnabled(mailboxName string, cfg *vault.Config) bool {
	if err := r.ensureAuth(); err != nil {
		return true
	}
	return cfg.NotificationEnabled(r.cfg.URL, mailboxName, string(r.accountID))
}

// MailboxConfigFor returns the MailboxConfig for a specific mailboxName on this relay.
func (r *Relay) MailboxConfigFor(mailboxName string, cfg *vault.Config) vault.MailboxConfig {
	if err := r.ensureAuth(); err != nil {
		return vault.MailboxConfig{}
	}
	for _, rc := range cfg.Relays {
		if rc.URL == r.cfg.URL {
			return rc.MailboxConfigFor(mailboxName, string(r.accountID))
		}
	}
	return vault.MailboxConfig{}
}

func setErrMsg(e *jmap.SetError) string {
	if e.Description != nil {
		return e.Type + ": " + *e.Description
	}
	return e.Type
}

func (r *Relay) Name() string { return r.cfg.URL }

// AccountEmail returns the account email for per-account relays (empty otherwise).
func (r *Relay) AccountEmail() string { return r.accountEmail }

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
	if r.cfg.AuthUser != "" {
		req.SetBasicAuth(r.cfg.AuthUser, r.cfg.Password)
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
	// For per-account relays (jmapsmtp-style), derive auth_token + KEK from
	// the envelope on first auth. Token relays and admin-level relays skip this.
	if r.accountEmail != "" && r.accountPlainPW != "" && r.cfg.Password == "" {
		authB64, kek, err := loginViaEnvelope(r.cfg.URL, r.accountEmail, r.accountPlainPW)
		if err != nil {
			return fmt.Errorf("%s: envelope login: %w", r.cfg.URL, err)
		}
		r.cfg.Password = authB64
		r.kek = kek
		r.client.WithBasicAuth(r.cfg.AuthUser, r.cfg.Password)
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
