# biset

biset is a *protocol translator*: receives Messages from the outside world via Connectors and writes them to a local Vault.

```
Outside world
  ├── IMAP/SMTP
  ├── ActivityPub
  └── ...
       ↕ JSON-RPC (stdio)
  Connector (per protocol)
       ↕
  biset core
       ↕
  Vault (local files)
```

**Three concepts:**

| Term | Meaning |
|---|---|
| `Message` | The minimal unit of communication |
| `Connector` | A bridge between an external protocol and the Vault |
| `Vault` | Local file store (Markdown + JSON) |

---

## Directory structure

```
biset/
├── core/
│   ├── message.go       — Message, Thread, Action types
│   ├── vault.go         — Vault read/write + rendering
│   └── connector.go     — Connector lifecycle + JSON-RPC
├── connectors/
│   └── imap/
│       ├── main.go
│       └── manifest.json
├── sync.go              — sync orchestrator (flushOutgoing, fetch, merge, render)
├── tray.go              — menu bar (cross-platform)
├── dock_darwin.go       — hide Dock icon (macOS only)
└── main.go              — CLI entrypoint
```

---

## Vault structure

```
vault/
└── y@example.com/          ← inbox (one per Connector account)
    ├── _new.md             ← compose new messages
    ├── {ts}_{contact}.md   ← thread (human interface)
    └── .data/
        └── {ts}_{contact}.json  ← source of truth
```

**Role separation:**
- *JSON* (`.data/`): source of truth. Written by sync, read for merge/render.
- *MD*: human interface. Compose area + display. Setting `status: send` triggers outgoing.

---

## Message

```go
type Message struct {
    From      string
    Body      string
    Ts        int64
    MessageID string
    ParentID  string
    Seen      bool
    Meta      map[string]string
}
```

Well-known Meta keys: `from_name`, `subject`, `to_addrs`, `cc_addrs`, `my_role`

---

## Connector

Each Connector is an *independent binary* that communicates with biset core via JSON-RPC 2.0 over stdio.

- One Connector per protocol (e.g. `biset-imap`, `biset-ap`)
- Connector owns its own `config.json` and state
- Core does not know protocol internals — it only calls methods

### Directory layout

```
~/.biset/connectors/
└── biset-imap/
    ├── biset-imap     ← binary
    ├── manifest.json
    └── config.json    ← connector-managed (accounts, credentials, etc.)
```

### Lifecycle

```
core starts
  → scans ~/.biset/connectors/
  → spawns each Connector as subprocess
  → sends ping to verify liveness
  → begins sync loop

crash → auto-restart after 5s
core stops → SIGTERM to all Connectors
```

Config is read once at subprocess startup.

---

## JSON-RPC API

biset core and Connectors communicate over stdin/stdout using JSON-RPC 2.0.

### `fetch`

Returns all new Messages since last sync. Connector tracks state internally.

```json
// request
{ "jsonrpc": "2.0", "id": 1, "method": "fetch" }

// response
{
  "jsonrpc": "2.0", "id": 1,
  "result": { "messages": [...] }
}
```

### `send`

```json
{
  "jsonrpc": "2.0", "id": 2, "method": "send",
  "params": {
    "to": "bob@example.com",
    "cc": "",
    "bcc": "",
    "subject": "Re: hello",
    "body": "...",
    "parent_id": "<msg-id>"
  }
}
```

### `handle`

```json
{
  "jsonrpc": "2.0", "id": 3, "method": "handle",
  "params": { "message_id": "<msg-id>", "action": "archived" }
}
```

Actions: `deleted` / `archived` / `spam`

### `notify` (Connector → core, async)

Sent unsolicited by the Connector when new Messages arrive (e.g. IMAP IDLE). No `id` field — JSON-RPC 2.0 notification.

```json
{
  "jsonrpc": "2.0",
  "method": "notify",
  "params": { "event": "new_messages" }
}
```

Core distinguishes responses (have `id`) from notifications (no `id`) on the same stdio stream.

### `ping`

```json
{ "jsonrpc": "2.0", "id": 0, "method": "ping" }
→ { "jsonrpc": "2.0", "id": 0, "result": "pong" }
```

---

## manifest.json

```json
{
  "name": "biset-imap",
  "version": "1.0.0",
  "description": "IMAP/SMTP connector",
  "capabilities": ["fetch", "send", "handle", "watch"]
}
```

`capabilities` declares which methods the Connector implements. Core checks before calling.

---

## Routing

When core finds `status: send` in a Vault MD file, it reads the `protocol` frontmatter field to determine which Connector to call.

```yaml
---
inbox: y@example.com
protocol: smtp
status: send
---
```

Core maps `protocol` → Connector name → calls `send`. Connectors use `inbox` to resolve which internal account to use.

---

## Sync flow

```
1. flushOutgoing()   scan Vault MD for status:send → Connector.send()
2. flushActions()    scan for status:deleted/archived/spam → Connector.handle()
3. fetch()           call Connector.fetch() for each Connector
4. deduplicateMessages()   remove duplicates by MessageID
5. mergeWithExisting()     merge with .data/*.json
6. render            write .data/*.json + *.md (preserving compose drafts)
```

Connectors manage their own state; core does not persist sync state.

---

## Markdown format

```markdown
---
thread_id: 1780061604266-abc@example.com
inbox: y@example.com
contact: bob@example.com
subject: "Re: hello"
parent_id: <latest-message-id>
protocol: smtp
status:
---

[compose area]

# 2024-01-15 11:00 Bob(bob@example.com)

Hey, how are you?
```

---

## Relationship to biset-core

biset replaces biset-core.

| biset-core | biset |
|---|---|
| `Adapter` interface (in-process) | `Connector` (subprocess, JSON-RPC) |
| `message/` package types | `core/` package types (same types) |
| `adapters/imap.go` | `biset-imap` (separate binary) |
| `state.json` (core-managed) | state managed per Connector |

`Message`, `Thread`, `Action` types carry over as-is.

---

## Future work

- Connector SDK (`biset-sdk-go`) — boilerplate library for Connector authors
- Connector registry and `biset install` command
- Plugin signing and verification
