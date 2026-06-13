package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/emailsubmission"
	"git.sr.ht/~rockorager/go-jmap/mail/identity"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	"git.sr.ht/~rockorager/go-jmap/mail/thread"
)

// ── go-jmap 型エイリアス ──────────────────────────────────────────────────────
// biset ではメッセージを protocol-agnostic に扱う。
// JMAP ワイヤー名（Email/get 等）はプロトコル詳細であり内部名ではない。

type (
	ID         = jmap.ID
	Message    = email.Email      // あらゆるメッセージ（email/AP/claude 共通）
	BodyPart   = email.BodyPart
	BodyValue  = email.BodyValue
	Address    = mail.Address
	Inbox      = mailbox.Mailbox  // biset では "Inbox" と呼ぶ
	Thread     = thread.Thread
	Identity   = identity.Identity
	Submission = emailsubmission.EmailSubmission // 送信キュー
	Envelope   = emailsubmission.Envelope
	EnvelopeAddress = emailsubmission.Address
)

// ── biset 固有型 ──────────────────────────────────────────────────────────────

// RelayConfig describes one JMAP peer node biset connects to.
// Local nodes have a Local field (binary name); remote nodes do not.
type RelayConfig struct {
	RelayName string `json:"relayname"`
	Password  string `json:"password,omitempty"`
	URL       string `json:"url"`
	Local     string `json:"local,omitempty"`
	Token     string `json:"token,omitempty"`
}

type ServerConfig struct {
	Port      int    `json:"port,omitempty"`
	Bind      string `json:"bind,omitempty"`
	RelayName string `json:"relayname,omitempty"`
	Password  string `json:"password,omitempty"`
	Interface string `json:"interface,omitempty"`
	Serve     bool   `json:"serve,omitempty"`
}

func (s ServerConfig) Enabled() bool {
	return s.Port > 0 && s.Bind != "" && s.Serve
}

type Config struct {
	Vault        string        `json:"vault"`
	Relays       []RelayConfig `json:"relays"`
	Notification *bool         `json:"notification,omitempty"`
	Server       ServerConfig  `json:"server,omitempty"`
}

func NotificationsEnabled(cfg *Config) bool {
	return cfg.Notification == nil || *cfg.Notification
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if cfg.Vault == "" {
		cfg.Vault = filepath.Dir(path)
	} else if !filepath.IsAbs(cfg.Vault) {
		cfg.Vault = filepath.Join(filepath.Dir(path), cfg.Vault)
	}
	return &cfg, nil
}

type SyncNotification struct {
	Contact   string
	Body      string
	Ts        int64
	MessageID string
}

// FetchResult holds messages and inboxes returned by a node Fetch call.
type FetchResult struct {
	Messages []Message `json:"messages"`
	Inboxes  []Inbox   `json:"inboxes"`
}

// PendingSubmission is a queued outgoing send written to .data/submissions/.
type PendingSubmission struct {
	ID       string    `json:"id"`
	Message  Message   `json:"message"`
	Envelope Envelope  `json:"envelope"`
	InboxKey string    `json:"inbox_key"`
	Created  time.Time `json:"created"`
}
