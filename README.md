# biset

Walks locally. Flies globally. Dwells in [doucot](https://github.com/yno9/doucot), a portable text editor.

Biset keeps two data streams in sync: local changes in vaults and external events bridged by connectors. All data lives locally in JMAP format, while Markdown is the human interface rendered on top. Each connector is an independent external process speaking its own protocol.

```
External events
       ↕ 
Connectors (JSON-RPC 2.0 speakers)
  ├── IMAP/SMTP
  ├── Claude Code
  ├── ActivityPub
  └── ...
       ↕
Biset core (MD/JSON translator)
       ↕
Vault + JMAP API (MD/JSON interfaces)
       ↕
Human/AI agency
```

---

## Features

- **Multiple protocols** — IMAP/SMTP, Claude Code conversations, ActivityPub (Fediverse)
- **JMAP-native** — internal data model speaks RFC 8621 (Email, Mailbox, Thread)
- **IMAP IDLE** — instant new mail detection via connector
- **Reply / Send** — write in the compose area, set `status: send`
- **Actions** — `seen`, `archived`, `deleted`, `spam` via frontmatter
- **Tray app** — menu bar icon on macOS

---

## Requirements

- macOS or Linux
- An IMAP/SMTP account (for biset-imap)
- Go 1.21+ (for building from source)

---

## Installation

```sh
curl -fsSL https://github.com/yno9/biset/releases/latest/download/install.sh | sh
```

### Build from source

```sh
git clone https://github.com/yno9/biset
cd biset
go build -o biset .
cd connectors/imap && go build .
```

---

## Usage

```
biset             show help
biset up          start daemon (tray app on macOS)
biset down        stop daemon
biset status      show running status
biset sync        sync once 
biset serve       start JMAP HTTP server
biset config      open config in $EDITOR
biset version     show version
```

---

## Vault structure

```
vault/
├── .data/
│   ├── emails/{emailId}.json        ← one JMAP Email object per file
│   ├── threads/{threadId}.json      ← thread index (emailIds list)
│   └── mailboxes.json               ← all Mailbox objects
└── you@example.com/
    ├── _new.md                              ← compose new messages here
    ├── _bob@example.com_06101423.md         ← unseen thread (_ prefix)
    └── bob@example.com_06101423.md          ← seen thread
```

Filenames: `{contact}_{mmddHHMM}.md` — the timestamp is from the first message in the thread (immutable). The `_` prefix means the thread has unread messages.

JSON (`.data/`) is the source of truth. Markdown files are rendered from JSON. Only the `status:` frontmatter field is read back to trigger actions.

---

## Thread format

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123.def456@mail.example.com
status: 
---



- - -
2024-01-15 11:30 you@example.com

Sounds good, see you then!

- - -
2024-01-15 11:00 bob@example.com

Hey, are you free tomorrow?
```

**Frontmatter fields:**

| Field | Description |
|---|---|
| `subject` | Thread subject |
| `contact` | The other party's email address |
| `id` | Thread ID (used internally for lookups) |
| `status` | Set to trigger an action (see below) |

---

## Replying

Write in the compose area (between frontmatter and the first `- - -`), then set `status: send` or include `!b` in body :

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123.def456@mail.example.com
status: 
---

Thanks, sounds good.!b

- - -
2024-01-15 11:00 bob@example.com

Hey, are you free tomorrow?
```

biset detects the change and sends automatically.

---

## New message

Edit `_new.md` in your inbox directory:

```markdown
---
contact: bob@example.com
status: send
---

Hi Bob, just wanted to reach out.
```

---

## Actions

Set `status:` in frontmatter to trigger an action on next sync:

| status | action |
|---|---|
| `send` | send the compose area via the connector |
| `seen` | mark thread as read |
| `archived` | archive (IMAP: move to Archive) |
| `deleted` | delete (IMAP: expunge) |
| `spam` | mark as spam |

---

## Connectors

| Connector | Protocols | Description |
|---|---|---|
| `biset-imap` | imap, smtp | IMAP/SMTP email |
| `biset-claude` | claude | Claude Code conversation history |

Each connector is an independent binary communicating with biset over JSON-RPC 2.0 via stdio. It owns its own config and state, and handles its own reconnection and debouncing.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
