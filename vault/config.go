package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	RelayName    string                 `json:"relayname"`
	Password     string                 `json:"password,omitempty"`
	URL          string                 `json:"url"`
	Local        string                 `json:"local,omitempty"`
	Token        string                 `json:"token,omitempty"`
	Notification *bool                  `json:"notification,omitempty"`
	Inboxes      map[string]InboxConfig `json:"inboxes,omitempty"`
}

// InboxConfigFor returns the InboxConfig for inboxKey relative to accountID.
// Looks up "./subdir" keys, falls back to ".", then empty InboxConfig.
func (r RelayConfig) InboxConfigFor(inboxKey, accountID string) InboxConfig {
	rel := relativeInboxKey(inboxKey, accountID)
	if cfg, ok := r.Inboxes[rel]; ok {
		return cfg
	}
	if cfg, ok := r.Inboxes["."]; ok {
		return cfg
	}
	return InboxConfig{}
}

func relativeInboxKey(inboxKey, accountID string) string {
	trimmed := strings.TrimPrefix(inboxKey, accountID)
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "."
	}
	return "./" + trimmed
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
	Server       ServerConfig  `json:"server,omitempty"`
	Notification *bool         `json:"notification,omitempty"` // global default
}

// NotificationEnabled resolves the notification setting for a specific inbox.
// Priority: inbox > relay > global > default (true).
func (cfg *Config) NotificationEnabled(relayURL, inboxKey, accountID string) bool {
	result := true
	if cfg.Notification != nil {
		result = *cfg.Notification
	}
	for _, rc := range cfg.Relays {
		if rc.URL != relayURL {
			continue
		}
		if rc.Notification != nil {
			result = *rc.Notification
		}
		rel := relativeInboxKey(inboxKey, accountID)
		if ic, ok := rc.Inboxes[rel]; ok && ic.Notification != nil {
			return *ic.Notification
		}
		if rel != "." {
			if ic, ok := rc.Inboxes["."]; ok && ic.Notification != nil {
				result = *ic.Notification
			}
		}
		return result
	}
	return result
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

// InboxConfig holds per-inbox display and render settings, set by the human in config.json.
type InboxConfig struct {
	Meta         []string `json:"meta,omitempty"`         // frontmatter fields to include
	FileFormat   string   `json:"fileformat,omitempty"`   // filename template, e.g. "{contact}_{shortId}.md"
	MaxDisplay   int      `json:"maxDisplay,omitempty"`   // max messages shown in MD (0 = unlimited)
	Notification *bool    `json:"notification,omitempty"` // overrides relay/global notification setting
}

func (c InboxConfig) EffectiveMeta() []string {
	if len(c.Meta) > 0 {
		return c.Meta
	}
	return []string{"subject", "contact", "id", "status"}
}

func (c InboxConfig) EffectiveFileFormat() string {
	if c.FileFormat != "" {
		return c.FileFormat
	}
	return "{contact}_{shortId}.md"
}

func (c InboxConfig) IsSimplified() bool {
	return !strings.Contains(c.EffectiveFileFormat(), "{shortId}")
}

// FetchResult holds messages and inboxes returned by a node Fetch call.
type FetchResult struct {
	Messages        []Message  `json:"messages"`
	UpdatedMessages []Message  `json:"updated_messages"` // flag/keyword changes only
	Threads         []Thread   `json:"threads"`
	Inboxes         []Inbox    `json:"inboxes"`
	Identities      []Identity `json:"identities"`
	RemovedIDs      []ID       // IDs no longer on relay (delta fetch only)
	QueryState      string     // queryState for next delta fetch
	EmailState      string     // Email/changes state for next delta fetch
	MailboxState    string     // Mailbox/changes state for next delta fetch
}

// PendingSubmission is a queued outgoing send written to .data/submissions/.
type PendingSubmission struct {
	ID       string    `json:"id"`
	Message  Message   `json:"message"`
	Envelope Envelope  `json:"envelope"`
	InboxKey string    `json:"inbox_key"`
	Created  time.Time `json:"created"`
}
