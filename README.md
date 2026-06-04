# biset

biset ia a protocol translator that handles several forms of messages in md/json files.
Folder of plain text files become your inboxes. Recieve, read, write and send, all locally.
```
IMAP ──→ biset-core ──→ vault/
                          └── you@example.com/
                              ├── {ts}_{contact}.md   ← read & reply here
                              └── .data/
                                  └── {ts}_{contact}.json
```

---

## Features

- **Pull email** via IMAP (incremental, only new messages)
- **IMAP IDLE** — instant new mail detection, no polling
- **Reply / New message** — write in the compose area, biset sends automatically
- **Sent messages** fetched back and merged into threads
- **macOS menu bar** — tray app with per-account connection status
- **Setup wizard** — browser-based first-run setup
- **Multiple accounts** supported
- **Operation log** — `log.md` in vault root with configurable logging
- Works with **biset-ui** (web interface) or any text editor

---

## Requirements

- Go 1.21+
- An IMAP/SMTP mail account
- macOS (for tray mode; `--sync`/`--watch` work on Linux too)

---

## Installation

```bash
git clone https://github.com/yd7a/biset-core
cd biset-core
go build -o biset .
```

Or via Homebrew (once published):

```bash
brew tap yd7a/biset
brew install biset
```

---

## First run

```bash
./biset
```

Opens a browser-based setup wizard. Enter your email and password — IMAP server is auto-detected via MX DNS.

---

## Usage

```bash
./biset                   # tray app (default) — menu bar + auto-sync via IMAP IDLE
./biset --sync            # sync once and exit
./biset --watch           # continuous sync (interval-based)
./biset --render          # re-render all MD files from JSON (no IMAP)
./biset --setup           # force re-run setup wizard
./biset /path/config.json # use specific config
```

---

## Vault structure

```
vault/
└── you@example.com/
    ├── _new.md                     ← compose new messages here
    ├── {ts}_{contact}.md          ← thread files (read & reply)
    └── .data/
        └── {ts}_{contact}.json    ← thread data (don't edit)
```

---

## Replying

Open a thread file. Write in the compose area (between frontmatter and first `#`), then set `status: send`:

```markdown
---
thread_id: ...
inbox: you@example.com
contact: bob@example.com
subject: "Re: hello"
in_reply_to: <message-id>
status: send
---

Thanks, sounds good!

# 2024-01-15 11:00 Bob(bob@example.com)

Hey, are you free tomorrow?
```

biset detects the change and sends automatically.

---

## New message

Edit `_new.md` in your inbox dir:

```markdown
---
contact: bob@example.com
status: send
---

Hi Bob, just wanted to reach out.
```

---

## Actions

Set `status:` in frontmatter:

| status | action |
|---|---|
| `send` | send via SMTP |
| `deleted` | remove from IMAP, delete file |
| `archived` | move to Archive |
| `spam` | move to Spam |

---

## Config (`config.json`)

```json
{
  "accounts": [{
    "adapter": "imap",
    "imap": {
      "host": "imap.example.com",
      "port": 993,
      "tls_mode": "tls",
      "username": "you@example.com",
      "password": "your-password",
      "inbox_key": "you@example.com"
    },
    "smtp": {
      "host": "smtp.example.com",
      "port": 587,
      "tls_mode": "starttls"
    }
  }],
  "renderers": ["md", "json"],
  "output": "/Users/you/vault"
}
```

SMTP `username`, `password`, and `host` default to IMAP values if omitted.

---

## Operation log (`log.md`)

biset writes a log of all sent/received messages and errors to `log.md` in the vault root. Configure logging by editing the frontmatter:

```markdown
---
contact: biset
subject: log
enabled: true
level: all
accounts: 
max: 1000
status: 
---
```

| field | values | description |
|---|---|---|
| `enabled` | `true` / `false` | turn logging on or off |
| `level` | `all` / `sent` / `received` / `errors` | what to log |
| `accounts` | comma-separated list | restrict to specific accounts (empty = all) |
| `max` | integer | maximum number of log lines to keep |

**Log format:**
```
2026-06-02 14:28 mizuki@4r.ma → y@kukubooks.jp
2026-06-02 14:16 nez → mizuki@4r.ma
2026-06-02 09:00 Error: fetch failed — connection refused
```

---

## Web interface (biset-ui)

Open `index.html` from your vault directory in Chrome for a full inbox UI:

```bash
open ~/vault/index.html
```

Or download the latest `index.html` from [biset-ui releases](https://github.com/yd7a/biset-core/releases).

---

## License

MIT
