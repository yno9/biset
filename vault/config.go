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
// biset では JMAP ワイヤー型を直接使う。Email/get などの JMAP メソッド名は
// プロトコル詳細であり、biset 内部の用語ではない。

type (
	ID         = jmap.ID
	Message    = email.Email      // あらゆるメッセージ（email/AP/claude 共通）
	BodyPart   = email.BodyPart
	BodyValue  = email.BodyValue
	Address    = mail.Address
	Mailbox    = mailbox.Mailbox
	Thread     = thread.Thread
	Identity   = identity.Identity
	Submission = emailsubmission.EmailSubmission // 送信キュー
	Envelope   = emailsubmission.Envelope
	EnvelopeAddress = emailsubmission.Address
)

// ── biset 固有型 ──────────────────────────────────────────────────────────────

// RelayConfig describes one JMAP peer node biset connects to.
// Local nodes have a Local field (binary name); remote nodes do not.
// Multi-account relays (e.g. smtp-host) populate Accounts instead of relay-level Password.
type RelayConfig struct {
	RelayName    string                     `json:"relayname"`
	AuthUser     string                     `json:"-"` // runtime auth username (defaults to RelayName; per-account multi-account expansion overrides)
	Password     string                     `json:"password,omitempty"`
	URL          string                     `json:"url"`
	Local        string                     `json:"local,omitempty"`
	Token        string                     `json:"token,omitempty"`
	Notification *bool                      `json:"notification,omitempty"`
	Mailboxes    map[string]MailboxConfig   `json:"mailboxes,omitempty"`
	Accounts     map[string]AccountConfig   `json:"accounts,omitempty"`
}

// AccountConfig holds per-account credentials for multi-account relays.
// Password is the user's plaintext login password; biset derives auth_token
// (for JMAP Basic auth) and enc_password (for PGP private key decryption) from it.
type AccountConfig struct {
	Password string `json:"password"`
}

// MailboxConfigFor returns the MailboxConfig for mailboxName relative to accountID.
// Looks up "./subdir" keys, falls back to ".", then empty MailboxConfig.
func (r RelayConfig) MailboxConfigFor(mailboxName, accountID string) MailboxConfig {
	rel := relativeMailboxName(mailboxName, accountID)
	if cfg, ok := r.Mailboxes[rel]; ok {
		return cfg
	}
	if cfg, ok := r.Mailboxes["."]; ok {
		return cfg
	}
	return MailboxConfig{}
}

func relativeMailboxName(mailboxName, accountID string) string {
	trimmed := strings.TrimPrefix(mailboxName, accountID)
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

// NotificationEnabled resolves the notification setting for a specific mailbox.
// Priority: mailbox > relay > global > default (true).
func (cfg *Config) NotificationEnabled(relayURL, mailboxName, accountID string) bool {
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
		rel := relativeMailboxName(mailboxName, accountID)
		if mc, ok := rc.Mailboxes[rel]; ok && mc.Notification != nil {
			return *mc.Notification
		}
		if rel != "." {
			if mc, ok := rc.Mailboxes["."]; ok && mc.Notification != nil {
				result = *mc.Notification
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

// MailboxConfig holds per-mailbox display and render settings, set by the human in config.json.
type MailboxConfig struct {
	Meta         []string `json:"meta,omitempty"`         // frontmatter fields to include
	FileFormat   string   `json:"fileformat,omitempty"`   // filename template, e.g. "{contact}_{shortId}.md"
	MaxDisplay   int      `json:"maxDisplay,omitempty"`   // max messages shown in MD (0 = unlimited)
	Notification *bool    `json:"notification,omitempty"` // overrides relay/global notification setting
}

func (c MailboxConfig) EffectiveMeta() []string {
	if len(c.Meta) > 0 {
		return c.Meta
	}
	return []string{"subject", "contact", "id", "status"}
}

func (c MailboxConfig) EffectiveFileFormat() string {
	if c.FileFormat != "" {
		return c.FileFormat
	}
	return "{contact}_{shortId}.md"
}

func (c MailboxConfig) IsSimplified() bool {
	return !strings.Contains(c.EffectiveFileFormat(), "{shortId}")
}

// FetchResult holds messages and mailboxes returned by a node Fetch call.
type FetchResult struct {
	Messages        []Message  `json:"messages"`
	UpdatedMessages []Message  `json:"updated_messages"` // flag/keyword changes only
	Threads         []Thread   `json:"threads"`
	Mailboxes       []Mailbox  `json:"mailboxes"`
	Identities      []Identity `json:"identities"`
	RemovedIDs      []ID       // IDs no longer on relay (delta fetch only)
	QueryState      string     // queryState for next delta fetch
	EmailState      string     // Email/changes state for next delta fetch
	MailboxState    string     // Mailbox/changes state for next delta fetch
}

// PendingSubmission is a queued outgoing send written to .data/submissions/.
type PendingSubmission struct {
	ID          string    `json:"id"`
	Message     Message   `json:"message"`
	Envelope    Envelope  `json:"envelope"`
	MailboxName string    `json:"mailbox_name"`
	Created     time.Time `json:"created"`
}
