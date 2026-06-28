# biset

The ubiquitous pigeon, de facto like HTTP. Biset and its relays together form a JMAP node network. Each relay is a standalone server bridging an external protocol. Biset itself is a node — client to its relays, server to any JMAP client. It aggregates messages into a single local vault and renders them in MD interface.

```
External events
       ↕ 
  Relays (Per-protocol client & JMAP server)
   ├── IMAP-SMTP-Client
   ├── SMTP-Host
   ├── AP-Host
   └── ...
       ↕ Server-Sent Events
  biset core (JMAP client & JMAP server)
   └── Vault (JSON & MD)
       ↕ 
  JMAP client / WebDAV / FSAA
```

---

## Features

- **Relay network** — each relay is an independent JMAP HTTP server bridging an external protocol (IMAP/SMTP, ActivityPub, …)
- **SSE push** — IMAP IDLE → relay notifies biset via SSE → immediate sync
- **Local vault** — all messages stored locally as JSON + Markdown
- **JMAP server** — biset serves its vault to any JMAP client (e.g. doucot)

---

## Requirements

- macOS or Linux
- An IMAP-SMTP account (for imapsmtp-client relay)
- Go 1.21+ (for building from source)

---

## Installation

```sh
curl -fsSL https://github.com/yno9/biset/releases/latest/download/install.sh | sh
```

### Build from source

```sh
git clone https://github.com/yno9/biset
cd biset && make
```

---

## Usage

```
biset                            show help
biset up                         start daemon
biset down                       stop daemon
biset sync                       sync once
biset relays                     list relays
biset relays up [name]           start a local relay
biset relays down [name]         stop a local relay
biset relays config [name]       edit a local relay's config
biset server up                  start JMAP server only
biset server down                stop JMAP server
biset config                     open config in $EDITOR
biset version                    show version
```

---

## Config

`~/.biset/config.json`:

```json
{
  "vault": "/path/to/vault",
  "server": {
    "port": 1080,
    "bind": "127.0.0.1",
    "relayname": "biset",
    "password": "...",
    "interface": "~/doucot/docs/index.html"
  },
  "relays": [
    {
      "relayname": "imapsmtp",
      "password": "changeme",
      "local": "imapsmtp-client",
      "url": "http://127.0.0.1:8765/.well-known/jmap"
    }
  ]
}
```

---

## Vault structure

```
vault/
├── .data/
│   ├── messages/{msgId}.json        ← JMAP Email object
│   ├── threads/{threadId}.json      ← thread index
│   ├── mailboxes.json
│   └── submissions/{id}.json        ← queued outgoing
└── you@example.com/
    ├── _new.md                      ← compose new messages here
    ├── _bob@example.com_06101423.md ← unseen thread (_ prefix)
    └── bob@example.com_06101423.md  ← seen thread
```

Filenames: `{contact}_{mmddHHMM}.md` — timestamp from the first message (immutable). `_` prefix = unread.

JSON (`.data/`) is the source of truth. Markdown files are rendered from JSON. Only the `status:` frontmatter field is read back to trigger actions.

---

## Thread format

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123
status:
---



# 2024-01-15 11:30 you@example.com

Sounds good, see you then!

# 2024-01-15 11:00 bob@example.com

Hey, are you free tomorrow?
```

**Frontmatter fields:**

| Field | Description |
|---|---|
| `subject` | Thread subject |
| `contact` | The other party's address |
| `id` | Short thread ID |
| `status` | Set to trigger an action (see below) |

---

## Replying

Write in the compose area (before the first `#` header), then set `status: send` or include `!b` in the body:

```markdown
---
subject: "Re: hello"
contact: bob@example.com
id: abc123
status:
---

Thanks, sounds good.!b

# 2024-01-15 11:00 bob@example.com

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
| `send` | send the compose area via the relay |
| `seen` | mark thread as read |
| `archive` | archive (IMAP: move to Archive) |
| `delete` | delete (IMAP: expunge) |

---

## Relays

| Relay | Protocols | Description |
|---|---|---|
| [go-jmapsmtp](https://github.com/yno9/go-jmapsmtp) | SMTP | Self-hosted SMTP receive + send |
| imapsmtp-client | IMAP, SMTP | Email via IMAP/SMTP |
| ap-host | ActivityPub | Fediverse (Mastodon-compatible) |
| jmapclaude | Claude CLI | AI assistant as inbox (per-project mailbox) |
| rss-client | RSS/Atom | Feed subscriptions as inbox |

Each relay is an independent JMAP HTTP server. It owns its config and state, handles reconnection, and exposes an SSE endpoint so biset gets push notifications on new data.

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
