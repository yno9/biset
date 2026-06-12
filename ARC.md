---
version: v0.3.11
description: Architecture document for contributors. Read before modifying code.
---

# biset

## Concept

The ubiquitous pigeon, de facto like HTTP. Best nested in [doucot](https://github.com/yno9/doucot), a portable text editor.

biset and its relays together form a JMAP node network. Each relay is an independent JMAP HTTP server bridging an external protocol. biset itself is a JMAP node — client to its relays, server to any JMAP client. It aggregates messages into a single local vault and renders them as Mardkdon for human interaction.

```
External events
       ↕ 
  Relays (JMAP server)
   ├── IMAP-SMTP Client
   ├── SMTP Host
   ├── ActivityPub
   └── ...
       ↕ JMAP HTTP + SSE
  biset core (JMAP client + server)
   └── Vault (JSON + Markdown)
       ↕ 
  JMAP clients / WebDav / FSAA
```

**Three concepts:**

| Term | Meaning |
|---|---|
| `Message` | The minimal unit of communication |
| `Relay` | A standalone JMAP HTTP server bridging an external protocol |
| `Vault` | Local file store (JSON + Markdown) |

biset's internal data model speaks **JMAP (RFC 8621)** — `Email`, `Mailbox`, `Thread`. Relays translate their native protocol into JMAP types; biset core never sees protocol internals.

biset core has a small JMAP HTTP server (`server.go`) that serves doucot directly. All external protocol handling lives in relays.

### MD is a human interface, not the source of truth

```
Human → MD (status: seen/send/...) → biset reads intent → updates JSON → re-renders MD from JSON
```

- **JSON** (`.data/`) is the source of truth
- **MD** is the human interface — rendered from JSON, edited by humans to express intent
- biset never patches MD strings directly; it always re-renders from JSON via `WriteThreadMD`

### Relay routing

biset routes sends and actions to relays by **inboxKey** (account ID), not by protocol name.

At startup biset connects to each relay's JMAP session endpoint and reads `accounts`. The account IDs are inboxKeys (e.g. `you@example.com`). `RelayForAccount(inboxKey)` finds the relay that owns a given account.

MD files live under `vault/<inboxKey>/` — the directory name is the inboxKey and is sufficient for routing. No `protocol:` frontmatter field is needed.

### SSE push

Relays expose a `/jmap/eventsource/` SSE endpoint. biset subscribes to each relay's event stream; on a `state` event biset triggers an immediate sync rather than waiting for the next ticker interval.

```
IMAP IDLE → relay hub.Notify() → SSE event → biset watchSSE → runSync()
```

---

## Directory structure

```
biset/
├── vault/
│   ├── config.go      — Config, RelayConfig, ServerConfig; JMAP type aliases
│   ├── message.go     — Email helpers: accessors, ID generation, thread assignment, merge/dedup
│   ├── storage.go     — Vault JSON I/O: ReadMessage/WriteMessage/…, submissions, migration
│   └── render.go      — MD rendering + WriteThreadMD (canonical JSON→MD bridge)
├── relays/
│   ├── core/
│   │   └── server.go  — Shared JMAP HTTP server: Handler interface, Serve(), Hub (SSE), auth
│   │   └── storage.go — Shared disk-backed JMAP store
│   └── imapsmtp-client/
│       ├── main.go    — Handler impl: emailQuery/Get/Set, mailboxGet, emailSubmissionSet
│       ├── imap.go    — IMAP: FetchNew, SetFlag, Expunge, AppendToSent, Watch (IDLE)
│       └── smtp.go    — SMTP: Send, buildRFC5322
├── interfaces/
│   └── cli.go         — RunStatus, PingRelay, RelayAccountInfo
├── actions.go         — Human intent execution: FlushOutgoing, FlushActions
├── auth.go            — Key management: RSA key gen/load, PGP derivation
├── client.go          — JMAP relay client: Manager, Relay, RelayForAccount, WatchRelays
├── log.go             — Log config read/write
├── process.go         — Process management: lock, TTY detection
├── relays.go          — Relay lifecycle: startManagedRelays, relayUp/Down, listRelays
├── server.go          — biset's own JMAP HTTP server (serves doucot)
├── sync.go            — Sync cycle: runSync + dispatchSubmissions + StartWatcher
└── main.go            — CLI entrypoint + watchLoop
```

---

## vault/ — file responsibilities

### `config.go`
Config types and JMAP data type aliases. No logic beyond LoadConfig.
- `Config`: `Vault`, `Relays`, `Notification`, `Server`
- `RelayConfig`: `RelayName`, `URL`, `Local`, `Password`, `Token`
- `ServerConfig`: `Port`, `Bind`, `RelayName`, `Password`, `Interface`
- `FetchResult` — `{Messages, Inboxes}` returned by relay Fetch
- `PendingSubmission` — queued outgoing send: `ID`, `Message`, `Envelope`, `InboxKey`, `Created`
- Type aliases: `Message` (email.Email), `Inbox` (mailbox.Mailbox), `Thread`, `Address`, …

### `message.go`
Pure functions on Message/Thread values. No I/O.
- **ID generation**: `MakeMessageID`, `MakeThreadID`, `MakeMailboxID`, `InboxKeyFromMailboxID`
- **Accessors**: `MessageFromAddr`, `MessageBody`, `MessageIsSeen`, `MessageHeaderID`, `MessageInReplyTo`, `MessageMailboxID`
- **Thread logic**: `AssignThreadIDs`, `GroupByThread`, `DeduplicateMessages`, `MergeMessages`

### `storage.go`
All Vault JSON I/O. Reads and writes `.data/` files only.
- **Message CRUD**: `ReadMessage`, `WriteMessage`, `DeleteMessage`, `ScanMessages`, `ReadMessagesForThread`
- **Thread CRUD**: `ReadThread`, `WriteThread`, `DeleteThread`
- **Inbox CRUD**: `ReadInboxes`, `WriteInboxes`
- **Submissions**: `WriteSubmission`, `ScanSubmissions`, `DeleteSubmission`

### `render.go`
Everything MD: rendering from JSON, string parsing, and the canonical write bridge.
- **Rendering**: `WriteThreadMD`, `RenderMissingMDs`
- **File ops**: `EnsureNewFile(vaultDir, inboxKey)`, `NewFileContent()`
- **Frontmatter/body parsing**: `ParseFrontmatter`, `ExtractBody`, `ClearBody`

---

## relays/core/ — shared relay infrastructure

### `server.go`
Shared JMAP HTTP server all relays use. A relay calls `core.Serve(cfg, handler, hub)`.

```go
type Handler interface {
    Capabilities() []jmap.URI
    Accounts() []Account
    Handle(method string, args json.RawMessage) (any, error)
}

type Hub struct { /* SSE broadcaster */ }
func NewHub() *Hub
func (h *Hub) Notify()   // call from relay on new data

func Serve(cfg Config, h Handler, hub *Hub) error  // hub=nil disables SSE
```

Handles: Basic auth, `/.well-known/jmap`, `/jmap/api/`, `/jmap/eventsource/`, result-reference resolution.

`core.Config`: `port`, `bind`, `relayname`, `password`

### `storage.go`
Disk-backed JMAP object store.

```go
func NewStore(dir string) (*Store, error)
func (s *Store) Put(m vault.Message) error
func (s *Store) Get(id jmap.ID) (vault.Message, bool)
func (s *Store) All() []vault.Message
func (s *Store) PatchKeywords(id jmap.ID, patch map[string]any) error
func (s *Store) PutPending(m vault.Message)       // in-memory draft, not persisted
func (s *Store) TakePending(id jmap.ID) (vault.Message, bool)
```

Disk layout: `<dir>/messages/<id>.json`, `<dir>/mailboxes.json`

---

## relays/imapsmtp-client/

Standalone JMAP HTTP server. Speaks IMAP (fetch, IDLE) and SMTP (send) externally; presents JMAP internally.

**Config** (`config.json` next to binary):
```json
{
  "port": 8765,
  "bind": "127.0.0.1",
  "relayname": "imapsmtp",
  "password": "changeme",
  "accounts": [
    {
      "inbox_key": "you@example.com",
      "imap": { "host": "...", "port": 993, "tls_mode": "tls", "username": "...", "password": "..." },
      "smtp": { "host": "...", "port": 587, "tls_mode": "starttls" }
    }
  ]
}
```

**JMAP methods handled:**

| Method | Action |
|---|---|
| `Email/query` | Calls `FetchNew` on all IMAP accounts, stores results, returns ID list |
| `Email/get` | Returns stored messages by ID |
| `Mailbox/get` | Returns inbox list |
| `Email/set` (create) | Stores draft in pending map for submission |
| `Email/set` (update) | Applies keyword patch + IMAP `SetFlag` / `Expunge` |
| `EmailSubmission/set` | Takes pending draft, calls `Send` via SMTP, appends to IMAP Sent folder |

**SSE**: `Watch()` runs IMAP IDLE per account; on new messages calls `hub.Notify()` which pushes to all SSE subscribers.

**State persistence:** `data/fetchstate.json` — incremental IMAP fetch state (last UID, sent mailbox).

---

## package main — file responsibilities

### `client.go`
JMAP relay client. biset connects to relays as a JMAP client.
- `Manager`: holds configured `Relay` connections; `changed` channel for SSE-triggered sync
- `RelayForAccount(inboxKey)` — finds relay that manages the given account
- `Relay.Fetch()` — `Email/query` + `Email/get` + `Mailbox/get` → `FetchResult`
- `Relay.Send(msg, envelope)` — `Email/set` + `EmailSubmission/set`
- `Relay.Handle(msgID, action)` — `Email/set` keyword update
- `Manager.WatchRelays()` — starts SSE subscriber goroutines; fires `mgr.Changed()` on state events

### `relays.go`
Relay process lifecycle.
- `startManagedRelays` / `stopManagedRelays` — called on biset up/down
- `relayUp` / `relayDown` — start/stop individual relay binary (PID file at `~/.biset/relays/<local>/pid`)
- `listRelays` — prints Local/Remote relay status via `PingRelay`
- `runRelaysCommand` — dispatch for `biset relays up/down/config`

### `actions.go`
Reads human intent from MD `status:` fields and executes it.
- `FlushOutgoing` — scans MD files for `status: send` → writes `PendingSubmission`
- `FlushActions` — scans for `status: seen/archived/deleted/spam` → calls `Relay.Handle` → `WriteThreadMD`

### `sync.go`
The full sync cycle.
- `runSync` — `FlushOutgoing` → `dispatchSubmissions` → `FlushActions` → fetch from all relays → assign thread IDs → deduplicate → write inboxes → `WriteThreadMD` per thread
- `dispatchSubmissions` — reads queued `PendingSubmission` files, calls `Relay.Send`, writes sent message to vault
- `StartWatcher` — macOS tray watcher (uses `mgr.Changed()`)

### `server.go`
biset's own JMAP HTTP server serving doucot.
- `GET /.well-known/jmap` — session document
- `POST /jmap/api/` — `Mailbox/get`, `Email/query`, `Email/get`, `Email/set`, `Thread/get`
- `GET /jmap/eventsource/` — SSE on vault change
- `GET /dav/` — WebDAV
- Auth: Bearer or Basic via `cfg.Server.RelayName` / `cfg.Server.Password`

### `main.go`
CLI entrypoint and watchLoop.
- **Subcommands**: `up` / `down` / `sync` / `relays` / `relays up/down/config` / `server up/down` / `config` / `version`
- `watchLoop` — ticker + `mgr.Changed()` (SSE) + vault fsnotify

---

## biset.json

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

| Field | Description |
|---|---|
| `server.port` / `server.bind` | biset's own JMAP server; both must be set to enable |
| `server.interface` | Path to UI HTML file (doucot) |
| `relays[].url` | Relay JMAP session endpoint |
| `relays[].local` | Binary name under `~/.biset/relays/<local>/` (local relay) |
| `relays[].relayname` / `password` | Basic auth credentials |

---

## Vault structure

```
vault/
├── .data/
│   ├── messages/{msgId}.json       ← JMAP Email object
│   ├── threads/{threadId}.json     ← thread index
│   ├── mailboxes.json
│   └── submissions/{id}.json       ← queued outgoing PendingSubmission
└── you@example.com/
    ├── _new.md                     ← compose new messages
    └── {contact}_{shortId}.md     ← thread (human interface)
```

---

## Markdown format

```markdown
---
subject: "Re: hello"
contact: bob@example.com
mailboxId: mbx-you@example.com
id: abc123
seen: true
status:
---

[compose area — cleared after send]

# 2024-01-15 11:00 bob@example.com

Hey, how are you?
```

| Field | Description |
|---|---|
| `subject` | Thread subject |
| `contact` | The non-self correspondent |
| `mailboxId` | JMAP Mailbox ID (`mbx-{inboxKey}`) — determines which relay handles this thread |
| `id` | Short thread ID |
| `seen` | `false` = thread has unread messages |
| `status` | `send` / `seen` / `archived` / `deleted` / `spam` |

---

## Message flow

### Receive

```
IMAP IDLE (Watch)
  │  relay: hub.Notify()
  │
  /jmap/eventsource/ SSE
  │  biset: watchSSE → mgr.Changed()
  │
  sync.go:runSync
  │
  client.go:Relay.Fetch    (Email/query + Email/get + Mailbox/get)
  │
  sync.go:runSync
    ├─ AssignThreadIDs
    ├─ DeduplicateMessages
    ├─ WriteInboxes
    └─ WriteThreadMD per thread
```

### Send

```
Human edits MD (status: send)
  │
  sync.go:runSync → actions.go:FlushOutgoing
    └─ write PendingSubmission to vault/.data/submissions/
  │
  sync.go:dispatchSubmissions
    ├─ RelayForAccount(inboxKey) → Relay.Send(msg, envelope)
    │    Email/set (create draft) + EmailSubmission/set
    │      └─ smtp.go:Send → smtpDeliver
    │         go AppendToSent → IMAP Sent folder
    └─ WriteMessage + WriteThreadMD
```

---

## Changelog

### v0.3.11

- **`nodes` → `relays`** — renamed throughout: `NodeConfig` → `RelayConfig`, `Node` → `Relay`, `biset nodes` → `biset relays`, `~/.biset/nodes/` → `~/.biset/relays/`
- **JMAP SSE** — `core.Hub` + `/jmap/eventsource/` endpoint in relay server; `imapsmtp-client` IMAP IDLE triggers `hub.Notify()`; biset `watchSSE` subscribes and fires immediate sync via `mgr.Changed()`
- **`biset server up/down`** — new subcommand; `server` config section replaces top-level `http_port`/`password`/`ui`
- **`tray.go` archived** — macOS menu bar UI moved to `interfaces/tray.go.bak`; all platforms now use `watchLoop`

### v0.3.10

- **Relay architecture** — relays are standalone JMAP HTTP servers; biset connects as a JMAP client
- **`relays/core/`** — shared package: Handler interface, Serve, disk-backed Store
- **`relays/imapsmtp-client/`** — first JMAP-native relay
- **`RelayForAccount(inboxKey)`** — routing by JMAP session account ID
- **`protocol:` frontmatter removed** — routing derived from file path (inboxKey)
- **Two-phase send** — `FlushOutgoing` writes `PendingSubmission`; `dispatchSubmissions` delivers atomically

### v0.3.9

- **`auth.go`** — RSA key generation, PGP derivation, WKD helpers
- **WKD endpoint** — `/.well-known/openpgpkey/hu/`
- **Autocrypt** — save peer keys on receive; inject `Autocrypt:` header on send
- **DKIM** — biset-smtp signs outgoing messages

### v0.3.8

- **`vault/` package** — renamed from `core/`
- **`biset-jmap` connector** — JMAP HTTP + WebDAV server
- **`biset-smtp` connector** — SMTP server receive + direct MX send
- **`biset-ap` connector** — ActivityPub HTTP server
