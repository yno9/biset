package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestServerConfigEnabled(t *testing.T) {
	tests := []struct {
		s    ServerConfig
		want bool
	}{
		{ServerConfig{Port: 8080, Bind: "0.0.0.0", Serve: true}, true},
		{ServerConfig{Port: 0, Bind: "0.0.0.0", Serve: true}, false},
		{ServerConfig{Port: 8080, Bind: "", Serve: true}, false},
		{ServerConfig{Port: 8080, Bind: "0.0.0.0", Serve: false}, false},
		{ServerConfig{}, false},
	}
	for _, tt := range tests {
		if got := tt.s.Enabled(); got != tt.want {
			t.Errorf("Enabled() = %v, want %v for %+v", got, tt.want, tt.s)
		}
	}
}

func TestNotificationsEnabled(t *testing.T) {
	trueVal, falseVal := true, false
	tests := []struct {
		cfg  *Config
		want bool
	}{
		{&Config{}, true},
		{&Config{Notification: &trueVal}, true},
		{&Config{Notification: &falseVal}, false},
	}
	for _, tt := range tests {
		if got := NotificationsEnabled(tt.cfg); got != tt.want {
			t.Errorf("NotificationsEnabled = %v, want %v", got, tt.want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"vault":  "",
		"relays": []map[string]any{{"relayname": "r1", "url": "http://localhost:8765"}},
	}
	b, _ := json.Marshal(cfg)
	os.WriteFile(path, b, 0644)

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.Vault != dir {
		t.Errorf("Vault = %q, want %q", got.Vault, dir)
	}
	if len(got.Relays) != 1 || got.Relays[0].RelayName != "r1" {
		t.Errorf("Relays = %+v", got.Relays)
	}
}

func TestLoadConfigVaultRelative(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	b, _ := json.Marshal(map[string]any{"vault": "data"})
	os.WriteFile(path, b, 0644)

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := filepath.Join(dir, "data")
	if got.Vault != want {
		t.Errorf("Vault = %q, want %q", got.Vault, want)
	}
}

func TestLoadConfigVaultAbsolute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	absVault := filepath.Join(dir, "mydata")
	b, _ := json.Marshal(map[string]any{"vault": absVault})
	os.WriteFile(path, b, 0644)

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got.Vault != absVault {
		t.Errorf("Vault = %q, want %q", got.Vault, absVault)
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadConfigBadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte("not json"), 0644)
	_, err := LoadConfig(path)
	if err == nil {
		t.Error("expected error for bad JSON")
	}
}
