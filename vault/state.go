package vault

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

type RelayState struct {
	LastSeen     time.Time         `json:"lastSeen"`
	MailboxNames    []string          `json:"inboxKeys"`
	QueryState   map[string]string `json:"queryState,omitempty"`   // accountID → Email/queryChanges state
	EmailState   map[string]string `json:"emailState,omitempty"`   // accountID → Email/changes state
	MailboxState map[string]string `json:"mailboxState,omitempty"` // accountID → Mailbox/changes state
}

type State struct {
	Relays map[string]*RelayState `json:"relays"`
}

func NewState() *State {
	return &State{Relays: map[string]*RelayState{}}
}

func (s *State) UpdateRelay(name string, inboxKeys []string) {
	rs := s.ensureRelay(name)
	rs.LastSeen = time.Now().UTC()
	rs.MailboxNames = inboxKeys
}

func (s *State) UpdateQueryState(relayName, accountID, queryState string) {
	rs := s.ensureRelay(relayName)
	if rs.QueryState == nil {
		rs.QueryState = map[string]string{}
	}
	rs.QueryState[accountID] = queryState
}

func (s *State) GetQueryState(relayName, accountID string) string {
	rs := s.Relays[relayName]
	if rs == nil || rs.QueryState == nil {
		return ""
	}
	return rs.QueryState[accountID]
}

func (s *State) UpdateEmailState(relayName, accountID, emailState string) {
	rs := s.ensureRelay(relayName)
	if rs.EmailState == nil {
		rs.EmailState = map[string]string{}
	}
	rs.EmailState[accountID] = emailState
}

func (s *State) GetEmailState(relayName, accountID string) string {
	rs := s.Relays[relayName]
	if rs == nil || rs.EmailState == nil {
		return ""
	}
	return rs.EmailState[accountID]
}

func (s *State) UpdateMailboxState(relayName, accountID, mailboxState string) {
	rs := s.ensureRelay(relayName)
	if rs.MailboxState == nil {
		rs.MailboxState = map[string]string{}
	}
	rs.MailboxState[accountID] = mailboxState
}

func (s *State) GetMailboxState(relayName, accountID string) string {
	rs := s.Relays[relayName]
	if rs == nil || rs.MailboxState == nil {
		return ""
	}
	return rs.MailboxState[accountID]
}

func (s *State) ensureRelay(name string) *RelayState {
	if s.Relays[name] == nil {
		s.Relays[name] = &RelayState{}
	}
	return s.Relays[name]
}

func statePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".data", "state.json")
}

// PurgeState removes state.json so the next sync does a full fetch across all
// relays. Used by `biset sync --full` together with PurgeMessageCache.
func PurgeState(vaultDir string) {
	os.Remove(statePath(vaultDir)) //nolint:errcheck
}

func LoadState(vaultDir string) *State {
	b, err := os.ReadFile(statePath(vaultDir))
	if err != nil {
		return NewState()
	}
	s := NewState()
	if err := json.Unmarshal(b, s); err != nil {
		return NewState()
	}
	return s
}

func SaveState(vaultDir string, s *State) {
	path := statePath(vaultDir)
	os.MkdirAll(filepath.Dir(path), 0755) //nolint:errcheck
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		log.Printf("[vault] save state: %v", err)
	}
}
