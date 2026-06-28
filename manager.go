package main

import (
	"log"
	"sync"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
)

const mailURI = jmap.URI("urn:ietf:params:jmap:mail")

// FetchResult is an alias for vault.FetchResult.
type FetchResult = vault.FetchResult

// Manager holds configured Relay connections.
type Manager struct {
	relays       []*Relay
	changed      chan struct{}
	mu           sync.RWMutex
	mailboxRelay map[string]*Relay // mailboxName → relay, updated after each sync
}

func NewManager(cfg *vault.Config) *Manager {
	m := &Manager{changed: make(chan struct{}, 1), mailboxRelay: map[string]*Relay{}}
	for _, rc := range cfg.Relays {
		if len(rc.Accounts) == 0 {
			m.relays = append(m.relays, newRelay(rc))
			continue
		}
		// Multi-account relay: one Relay instance per account.
		for email, acc := range rc.Accounts {
			perAccount := rc
			perAccount.AuthUser = email
			perAccount.Password = "" // filled lazily by envelope login in ensureAuth
			perAccount.Accounts = nil // children don't inherit
			r := newRelay(perAccount)
			r.accountEmail = email
			r.accountPlainPW = acc.Password
			m.relays = append(m.relays, r)
		}
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

// EnsureKeys ensures that every per-account relay has a usable PGP keypair
// (recovered from the server or freshly generated and uploaded). Called once
// at startup. Non-account relays are skipped.
func (m *Manager) EnsureKeys() {
	for _, r := range m.relays {
		if r.accountEmail == "" {
			continue
		}
		if err := r.ensureAuth(); err != nil {
			log.Printf("[pgp] auth failed for %s: %v", r.accountEmail, err)
			continue
		}
		if err := EnsureAccountKey(r); err != nil {
			log.Printf("[pgp] %v", err)
		}
	}
}

// MailboxConfigFor returns the MailboxConfig for the relay that owns mailboxName.
func (m *Manager) MailboxConfigFor(mailboxName string, cfg *vault.Config) vault.MailboxConfig {
	r := m.RelayForAccount(mailboxName)
	if r == nil {
		return vault.MailboxConfig{}
	}
	return r.MailboxConfigFor(mailboxName, cfg)
}

// RelayForAccount returns the Relay that manages the given mailboxName (account ID).
func (m *Manager) RelayForAccount(mailboxName string) *Relay {
	id := jmap.ID(mailboxName)
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

// SetMailboxRelay records that mailboxName is served by r. Called after each sync.
func (m *Manager) SetMailboxRelay(mailboxName string, r *Relay) {
	m.mu.Lock()
	m.mailboxRelay[mailboxName] = r
	m.mu.Unlock()
}

// RelayForMailbox returns the relay that last reported serving mailboxName.
// Falls back to RelayForAccount for relays discovered before the first sync.
func (m *Manager) RelayForMailbox(mailboxName string) *Relay {
	m.mu.RLock()
	r := m.mailboxRelay[mailboxName]
	m.mu.RUnlock()
	if r != nil {
		return r
	}
	return m.RelayForAccount(mailboxName)
}
