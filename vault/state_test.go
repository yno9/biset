package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewState(t *testing.T) {
	s := NewState()
	if s == nil {
		t.Fatal("NewState returned nil")
	}
	if s.Relays == nil {
		t.Error("Relays map is nil")
	}
	if len(s.Relays) != 0 {
		t.Error("Relays should be empty")
	}
}

func TestStateUpdateRelay(t *testing.T) {
	s := NewState()
	s.UpdateRelay("relay1", []string{"a@b.com", "c@d.com"})

	rs, ok := s.Relays["relay1"]
	if !ok {
		t.Fatal("relay1 not found")
	}
	if len(rs.MailboxNames) != 2 {
		t.Errorf("MailboxNames len = %d, want 2", len(rs.MailboxNames))
	}
	if rs.LastSeen.IsZero() {
		t.Error("LastSeen should not be zero")
	}
	if time.Since(rs.LastSeen) > time.Second {
		t.Error("LastSeen too old")
	}

	// update again
	s.UpdateRelay("relay1", []string{"e@f.com"})
	if len(s.Relays["relay1"].MailboxNames) != 1 {
		t.Error("expected overwrite")
	}
}

func TestStateUpdateRelayEmpty(t *testing.T) {
	s := NewState()
	s.UpdateRelay("r", nil)
	if s.Relays["r"] == nil {
		t.Error("relay should exist even with nil keys")
	}
}

func TestLoadSaveState(t *testing.T) {
	dir := t.TempDir()
	s := NewState()
	s.UpdateRelay("relay1", []string{"a@b.com"})
	SaveState(dir, s)

	loaded := LoadState(dir)
	if loaded == nil {
		t.Fatal("LoadState returned nil")
	}
	rs, ok := loaded.Relays["relay1"]
	if !ok {
		t.Fatal("relay1 not found after load")
	}
	if len(rs.MailboxNames) != 1 || rs.MailboxNames[0] != "a@b.com" {
		t.Errorf("MailboxNames = %v", rs.MailboxNames)
	}
}

func TestLoadStateNotFound(t *testing.T) {
	dir := t.TempDir()
	s := LoadState(dir)
	if s == nil {
		t.Fatal("LoadState should return empty state, not nil")
	}
	if len(s.Relays) != 0 {
		t.Error("Relays should be empty")
	}
}

func TestLoadStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	p := statePath(dir)
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("not valid json"), 0644)
	s := LoadState(dir)
	if s == nil {
		t.Fatal("should return empty state on parse error")
	}
	if len(s.Relays) != 0 {
		t.Error("Relays should be empty")
	}
}

func TestSaveStateMultipleRelays(t *testing.T) {
	dir := t.TempDir()
	s := NewState()
	s.UpdateRelay("r1", []string{"a@b.com"})
	s.UpdateRelay("r2", []string{"c@d.com", "e@f.com"})
	SaveState(dir, s)

	loaded := LoadState(dir)
	if len(loaded.Relays) != 2 {
		t.Errorf("relay count = %d, want 2", len(loaded.Relays))
	}
	if len(loaded.Relays["r2"].MailboxNames) != 2 {
		t.Errorf("r2 keys = %v", loaded.Relays["r2"].MailboxNames)
	}
}
