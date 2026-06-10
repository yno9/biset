# biset

Walks locally. Flies globally.

A multi-protocol messenger. Your inbox is a folder of plain text files — read, write, and reply in any editor. It pairs well with [doucot](https://github.com/yno9/doucot), a portable text editor.

```
IMAP / Claude / ActivityPub / ...
         ↕ JSON-RPC 2.0 (stdio)
      Connector
         ↕
      biset core   (JMAP-native)
         ↕
      vault/
        └── you@example.com/
            ├── _new.md                        ← compose here
            └── bob@example.com_06101423.md    ← threads as markdown
```

---

## Features

- **Multiple protocols** — IMAP/SMTP, Claude Code conversations, ActivityPub (Fediverse)
- **JMAP-native** — internal data model speaks RFC 8621 (Email, Mailbox, Thread)
- **IMAP IDLE** — instant new mail detection via connector
- **Reply / Send** — write in the compose area, set `status: send`
- **Actions** — `seen`, `archived`, `deleted`, `spam` via frontmatter
- **Setup wizard** — browser-based first-run setup
- **JMAP HTTP server** — expose vault to any JMAP-compatible client (`--serve`)

---

## Requirements

- macOS and linux
- An IMAP/SMTP account (for biset-imap)
- Go 1.21+ (for building from source)

---

## Installation

### End users

```sh
curl -fsSL https://github.com/yno9/biset/releases/latest/download/install.sh | sh
```

### Developers

```sh
git clone https://github.com/yno9/biset
cd biset
go build .
cd connectors/imap && go build .
cd ../claude && go build .
```

---

## First run

```sh
./biset
```

Opens a browser-based setup wizard. Select connectors, enter account credentials — IMAP server is auto-detected via MX DNS.

---

## Usage

```sh
./biset                          # tray app (default) — menu bar
./biset --sync                   # sync once and exit
./biset --watch                  # continuous sync (interval-based)
./biset --serve --port 1080      # JMAP HTTP server
./biset --serve --token <secret> # JMAP server with Bearer token auth
./biset --interval 5m            # set sync interval (default: 1m)
./biset /path/to/biset.json      # use specific config file
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
    ├── bob@example.com_06101423.md          ← seen thread
    └── _bob@example.com_06101423.md         ← unseen thread (_ prefix)
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

Write in the compose area (between frontmatter and the first `- - -`), then set `status: send` or include `!b` in your message :

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123.def456@mail.example.com
status: send
---

Thanks, sounds good!

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

## Serve mode

`biset --serve` exposes the Vault as a JMAP server any compatible client can connect to.

```sh
biset --serve --port 1080 --token <secret> /path/to/biset.json
```

Plain HTTP — put Caddy or nginx in front for TLS. Vault changes are pushed to clients in real-time over Server-Sent Events.

---

## Connectors

| Connector | Protocols | Description |
|---|---|---|
| `biset-imap` | imap, smtp | IMAP/SMTP email |
| `biset-claude` | claude | Claude Code conversation history |

Each connector is an independent binary communicating with biset over JSON-RPC 2.0 via stdio. It owns its own config and state, and handles its own reconnection and debouncing.

See `config.example.json` in each connector directory for configuration reference.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
