package vault

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

type RelayState struct {
	LastSeen  time.Time `json:"lastSeen"`
	InboxKeys []string  `json:"inboxKeys"`
}

type State struct {
	Relays map[string]*RelayState `json:"relays"`
}

func NewState() *State {
	return &State{Relays: map[string]*RelayState{}}
}

func (s *State) UpdateRelay(name string, inboxKeys []string) {
	s.Relays[name] = &RelayState{
		LastSeen:  time.Now().UTC(),
		InboxKeys: inboxKeys,
	}
}

func statePath(vaultDir string) string {
	return filepath.Join(vaultDir, ".data", "state.json")
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
