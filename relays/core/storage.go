package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"biset/vault"
)

// Store is a disk-backed, in-memory-cached store for JMAP objects.
//
// Disk layout:
//   <dir>/messages/<id>.json   — one file per message (persisted)
//   <dir>/mailboxes.json       — mailbox array (persisted)
//
// Pending messages (created by Email/set, awaiting EmailSubmission/set) are
// held in memory only and never written to disk.
type Store struct {
	dir     string
	mu      sync.RWMutex
	msgs    map[jmap.ID]vault.Message // persisted
	pending map[jmap.ID]vault.Message // in-memory only
}

// NewStore opens (or creates) a store at dir, loading existing data into memory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "messages"), 0755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:     dir,
		msgs:    map[jmap.ID]vault.Message{},
		pending: map[jmap.ID]vault.Message{},
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "messages"))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "messages", e.Name()))
		if err != nil {
			continue
		}
		var m vault.Message
		if err := json.Unmarshal(b, &m); err == nil && m.ID != "" {
			s.msgs[m.ID] = m
		}
	}
	return s, nil
}

// ── messages (persisted) ──────────────────────────────────────────────────────

// Put inserts or updates a message on disk and in memory.
func (s *Store) Put(m vault.Message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.msgPath(m.ID), b, 0644); err != nil {
		return err
	}
	s.mu.Lock()
	s.msgs[m.ID] = m
	s.mu.Unlock()
	return nil
}

// Get returns a message by ID, checking both persisted and pending stores.
func (s *Store) Get(id jmap.ID) (vault.Message, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if m, ok := s.msgs[id]; ok {
		return m, true
	}
	m, ok := s.pending[id]
	return m, ok
}

// All returns all persisted messages sorted newest-first.
func (s *Store) All() []vault.Message {
	s.mu.RLock()
	all := make([]vault.Message, 0, len(s.msgs))
	for _, m := range s.msgs {
		all = append(all, m)
	}
	s.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool {
		return vault.TimeVal(all[i].ReceivedAt).After(vault.TimeVal(all[j].ReceivedAt))
	})
	return all
}

// PatchKeywords applies a JMAP keyword patch (keys like "keywords/$seen") to a
// stored message and persists the change.
func (s *Store) PatchKeywords(id jmap.ID, patch map[string]any) error {
	s.mu.Lock()
	m, ok := s.msgs[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if m.Keywords == nil {
		m.Keywords = map[string]bool{}
	}
	for k, v := range patch {
		if kw := strings.TrimPrefix(k, "keywords/"); kw != k {
			if b, isBool := v.(bool); isBool {
				m.Keywords[kw] = b
			}
		}
	}
	s.msgs[id] = m
	s.mu.Unlock()
	return s.Put(m)
}

// ── pending (in-memory only) ──────────────────────────────────────────────────

// PutPending stores a draft in memory (not on disk).
func (s *Store) PutPending(m vault.Message) {
	s.mu.Lock()
	s.pending[m.ID] = m
	s.mu.Unlock()
}

// TakePending removes and returns a pending message (used when submitting).
func (s *Store) TakePending(id jmap.ID) (vault.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	return m, ok
}

// ── mailboxes (persisted) ─────────────────────────────────────────────────────

// PutMailboxes overwrites the persisted mailbox list.
func (s *Store) PutMailboxes(mbs []vault.Inbox) error {
	b, err := json.Marshal(mbs)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "mailboxes.json"), b, 0644)
}

// Mailboxes returns the persisted mailbox list.
func (s *Store) Mailboxes() []vault.Inbox {
	b, err := os.ReadFile(filepath.Join(s.dir, "mailboxes.json"))
	if err != nil {
		return nil
	}
	var mbs []vault.Inbox
	json.Unmarshal(b, &mbs) //nolint:errcheck
	return mbs
}

// ── internal ──────────────────────────────────────────────────────────────────

func (s *Store) msgPath(id jmap.ID) string {
	return filepath.Join(s.dir, "messages", safeFilename(string(id))+".json")
}

func safeFilename(s string) string {
	rep := strings.NewReplacer(
		"/", "-", "\\", "-", ":", "-", "*", "-",
		"?", "-", `"`, "-", "<", "-", ">", "-", "|", "-",
	)
	s = rep.Replace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
