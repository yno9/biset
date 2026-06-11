---
version: v0.3.7
description: Architecture document for contributors. Read before modifying code.
---

# biset

## Concept

Biset keeps two data streams in sync: local changes in vaults and external events bridged by connectors. All data lives locally in JMAP format. Markdown is the human interface rendered on top. Each connector is an independent external process speaking its own protocol.

```
External events
  ├── IMAP/SMTP
  ├── Claude Code
  ├── ActivityPub
  └── ...
       ↕ JSON-RPC 2.0 (stdio)
  Connector (per protocol)
       ↕
  biset core   (JMAP-native data model)
       ↕
  Vault (local JSON + Markdown files)
       ↕
  Human (reads/writes Markdown)
```

**Three concepts:**

| Term | Meaning |
|---|---|
| `Message` | The minimal unit of communication |
| `Connector` | A bridge between an external protocol and the Vault |
| `Vault` | Local file store (JSON + Markdown) |

biset's internal data model speaks **JMAP (RFC 8621)** — `Email`, `Mailbox`, `Thread`. Connectors translate their native protocol into JMAP types; biset core never sees protocol internals.

### MD is a human interface, not the source of truth

```
Human → MD (status: seen/send/...) → biset reads intent → updates JSON → re-renders MD from JSON
```

- **JSON** (`.data/`) is the source of truth
- **MD** is the human interface — rendered from JSON, edited by humans to express intent
- biset never patches MD strings directly; it always re-renders from JSON via `WriteThreadMD`

---

## Directory structure

```
biset-dev/
├── core/
│   ├── types.go       — JMAP type definitions (Email, Mailbox, Thread, Address, …)
│   ├── email.go       — Email helpers: accessors, ID generation, thread assignment, merge/dedup
│   ├── json.go        — Vault JSON I/O: ReadEmail/WriteEmail/ReadThread/WriteThread/…, migration
│   ├── md.go          — MD rendering + string ops + WriteThreadMD (canonical JSON→MD bridge)
│   ├── actions.go     — Human intent execution: FlushOutgoing, FlushActions
│   └── connector.go   — Connector subprocess lifecycle + JSON-RPC client
├── connectors/
│   ├── imap/          — IMAP/SMTP connector source
│   └── claude/        — Claude Code connector source
├── assets/
│   ├── setup.html     — first-run setup wizard
│   ├── setup.js       — connector definitions + release URLs
│   └── icon.png       — tray icon
├── sync.go            — sync cycle: runSync (fetch → merge → write) + group/merge helpers
├── watch.go           — sync triggers: StartWatcher (vault fsnotify + connector notify + ticker)
├── serve.go           — JMAP HTTP server (--serve mode)
├── tray.go            — menu bar UI (macOS / cross-platform)
└── main.go            — CLI entrypoint + setup flow + process management
```

---

## core/ — file responsibilities

### `types.go`
JMAP data types only. No logic, no I/O.
- `Email`, `Thread`, `Mailbox`, `Address`, `BodyPart`, `BodyValue`
- `Envelope`, `EnvelopeAddress`

### `email.go`
Pure functions on Email/Thread values. No I/O, no side effects.
- **ID generation**: `MakeEmailID`, `MakeThreadID`, `MakeMailboxID`, `InboxKeyFromMailboxID`, `MessageIDFromEmailID`
- **Accessors**: `EmailFromAddr`, `EmailFromName`, `EmailBody`, `EmailIsSeen`, `EmailMessageID`, `EmailInReplyTo`, `EmailMailboxID`
- **Constructors**: `NewTextEmail`, `DefaultMailbox`
- **Thread logic**: `AssignThreadIDs`, `GroupByThread`, `DeduplicateEmails`, `MergeEmails`
- **Utilities**: `SafeFilename`, `previewText`

### `json.go`
All Vault JSON I/O. Reads and writes `.data/` files only.
- **Path helpers**: `EmailFilePath`, `ThreadFilePath`, `MailboxesFilePath`
- **Email CRUD**: `ReadEmail`, `WriteEmail`, `DeleteEmail`, `ScanEmails`
- **Thread CRUD**: `ReadThread`, `WriteThread`, `DeleteThread`, `ScanThreads`, `ReadEmailsForThread`
- **Mailbox CRUD**: `ReadMailboxes`, `WriteMailboxes`
- **Utility**: `WriteIfChanged` (write-if-content-changed, used by both json.go and md.go)
- **Migration**: `MigrateVault` (old VaultThread format → per-email format), `ReThreadVault` (re-assign threadIDs globally)

### `md.go`
Everything MD: rendering from JSON, string parsing, and the canonical write bridge.
- **Rendering**: `RenderMD` (Email[] → path + content bytes), `mdContent`, `threadContact`, `isSeen`
- **File naming**: `ShortThreadID`, `FindThreadMD`
- **Frontmatter/body parsing**: `ParseFrontmatter`, `ExtractBody`, `InjectBody`, `ClearBody`
- **File ops**: `SetMDMtime`, `EnsureNewFile`, `RenderMissingMDs`
- **Bridge**: `WriteThreadMD` — canonical JSON→MD writer; always call this instead of patching MD strings

### `actions.go`
Reads human intent from MD `status:` fields and executes it. The only file in `core/` that uses `*Manager`.
- `FlushOutgoing` — scans all inbox MD files for `status: send` or `!b` body → calls `Connector.Send`
- `FlushActions` — scans for `status: seen/archived/deleted/spam` → calls `Connector.Handle` → updates JSON → calls `WriteThreadMD`

### `connector.go`
Connector subprocess management and JSON-RPC communication.
- `Manager`: spawns/restarts connector binaries, routes calls by protocol
- `Connector`: per-connector client — `Fetch`, `Send`, `Handle`, `SetOnChange`
- `Manager.ConnectorFor(protocol)` — returns connector by protocol name
- `Manager.SetOnChange(fn)` — registers callback fired on any connector `notify`

---

## package main — file responsibilities

### `sync.go`
The full sync cycle. Called by `watch.go` on every trigger.
- `runSync` — orchestrates: `FlushOutgoing` → `FlushActions` → fetch from all connectors → assign thread IDs → deduplicate → write mailboxes → merge with existing → `WriteThreadMD` per thread
- `mergeWithExistingThread` — reads existing vault emails, merges with incoming batch
- `groupEmailsByInbox`, `emailsForThread`, `emailsForInbox` — grouping helpers
- `EmailBodyPreview` — truncated body for desktop notifications
- `writeSyncLog` — appends sync log per inbox

### `watch.go`
Wires all sync triggers; returns immediately after setup.
- `StartWatcher` — sets up three trigger sources: connector notify, vault fsnotify, periodic ticker; fires `onSync` on any trigger
- `watchVault` — fsnotify loop over vault MD files; fires only when a file has `status: send`, `status: seen`, or `!b` in body; 500ms debounce; also handles `biset-quit.json` and `biset-open-vault.json`

### `tray.go`
Pure menu bar UI. No sync logic.
- Menu: `~/inbox (HH:MM)` (vault + last sync time), `Full Sync`, `Serve` (toggle), `Vault…` (change vault), `Connectors` (submenu → toggle on/off), `Config` (submenu → open config files in default text editor), `Notify: on/off`, `Restart`, `Quit`
- **Full Sync** — resets all connector state.json files, removes lock, runs sync from scratch
- Desktop notifications on new mail
- Calls `StartWatcher` to wire sync triggers
- `openVault` — opens vault directory in Finder

### `serve.go`
JMAP HTTP server (`biset --serve`).
- `/.well-known/jmap` — session document
- `/jmap/api/` — JMAP API (POST): `Mailbox/get`, `Email/query`, `Email/get`, `Email/set`, `Thread/get`, `Identity/get`
- `/jmap/eventsource/` — Server-Sent Events push on vault change

### `main.go`
CLI entrypoint and process management.
- **Subcommand parsing**: `up` / `down` / `sync` / `serve` / `status` / `config` / `version`; no args → help screen
- `up`: forks daemon (macOS), acquires lock at `vault/.data/.biset.lock`, launches tray
- `down`: writes `biset-quit.json` to vault, polls lock file until daemon exits
- `status`: reads lock file, checks `isBisetProcess`, prints vault stats
- `config`: shows numbered menu of all config files (`biset.json` + connector `config.json`s); opens selected in `$EDITOR`
- `sync --full` / `-full`: resets all connector state.json → removes lock → syncs from scratch
- `acquireLock` / `isBisetProcess`: single-instance enforcement via PID lock file; **5-minute stale timeout** — lock older than 5 min is treated as abandoned (process hung/killed without cleanup)
- `resetConnectorStates(connectorsDir)`: writes `{"last_mtime_ns":0}` to each connector's state.json; shared by `sync --full` and Full Sync tray item
- `runSetup`: first-run setup wizard (only if `biset.json` absent)

---

## Vault structure

```
vault/
├── .data/
│   ├── emails/
│   │   └── {emailId}.json       ← one file per Email (JMAP Email object)
│   ├── threads/
│   │   └── {threadId}.json      ← thread index {id, emailIds:[...]}
│   └── mailboxes.json           ← all Mailbox objects
└── you@example.com/             ← inbox directory (one per account)
    ├── _new.md                  ← compose new messages
    └── {contact}_{shortThreadId}.md   ← thread (human interface)
        or _{contact}_{shortThreadId}.md  (unseen: _ prefix sorts to top)
```

**Role separation:**
- *JSON* (`.data/`): source of truth. JMAP objects written by sync, read for O(1) lookup.
- *MD*: human interface. Compose area + message history. Frontmatter `status:` field triggers actions.

**Filename conventions:**
- `shortThreadId` = `threadId` with `thr-` prefix and `@domain` suffix stripped
- `_` prefix on MD filename = thread has unread messages (`seen: false`)

---

## JMAP data model

Core types (RFC 8621):

```go
type Email struct {
    ID         string
    BlobID     string
    ThreadID   string
    MailboxIDs map[string]bool
    Keywords   map[string]bool   // "$seen", "$draft", "$flagged"
    MessageID  []string
    InReplyTo  []string
    From, To, Cc, Bcc []Address
    Subject    string
    ReceivedAt time.Time
    BodyValues map[string]BodyValue
    TextBody   []BodyPart
    HtmlBody   []BodyPart
    Preview    string
    Size       int
}

type Thread struct {
    ID       string
    EmailIDs []string   // sorted newest-first
}
```

`Email.Keywords["$seen"]` = read/unread status (from IMAP `\Seen`, defaulting to true for sent).

---

## Connector

Each Connector is an *independent binary* communicating with biset via JSON-RPC 2.0 over stdio.

- One Connector per protocol
- Connector owns its own `config.json` and state files
- **Connector is responsible for its own debounce/throttle before sending `notify`**
- Core does not know protocol names or internals — it only calls methods
- Connectors return JMAP `Email` and `Mailbox` objects

### Lifecycle

```
core starts
  → scans connectors directory
  → reads manifest.json for each connector
  → spawns binary as subprocess
  → sends ping to verify liveness
  → registers onChange callback → triggers sync on any notify

crash → auto-restart after 5s
core stops → SIGTERM to all connectors
```

---

## JSON-RPC API

biset and Connectors communicate over stdin/stdout using JSON-RPC 2.0.

### `ping`
```json
{ "jsonrpc": "2.0", "id": 0, "method": "ping" }
→ { "jsonrpc": "2.0", "id": 0, "result": "pong" }
```

### `fetch`
Returns JMAP Emails and Mailboxes since last sync. Connector tracks state internally.
```json
{ "jsonrpc": "2.0", "id": 1, "method": "fetch" }
→ { "result": { "emails": [...], "mailboxes": [...] } }
```

### `send`
```json
{
  "jsonrpc": "2.0", "id": 2, "method": "send",
  "params": {
    "email": { /* JMAP Email object */ },
    "envelope": { "mailFrom": { "email": "..." }, "rcptTo": [...] }
  }
}
```

### `handle`
```json
{
  "jsonrpc": "2.0", "id": 3, "method": "handle",
  "params": { "emailId": "eml-...", "action": "seen" }
}
```
Actions: `seen` / `archived` / `deleted` / `spam`

### `notify` (Connector → core, unsolicited)
Sent by the Connector when new messages arrive or state changes. Connector handles its own debounce before sending.
```json
{ "jsonrpc": "2.0", "method": "notify" }
```

---

## manifest.json

```json
{
  "name": "biset-imap",
  "version": "0.1.0",
  "description": "IMAP/SMTP connector",
  "capabilities": ["fetch", "send", "handle", "watch"],
  "protocols": ["imap", "smtp"]
}
```

`capabilities` declares which methods the Connector implements. Core checks before calling.  
`protocols` maps frontmatter `protocol:` values to this Connector.

---

## Sync triggers (`watch.go`)

Three sources trigger `runSync`:

| Source | Mechanism |
|---|---|
| Connector notify | `mgr.SetOnChange` → immediate |
| Vault MD change | `fsnotify` watching vault dirs → 500ms debounce |
| Periodic fallback | `time.Ticker` (configurable interval) |

Vault watcher fires only when a MD file has `status: send`, `status: seen`, or `!b` in body.

---

## Sync flow (`sync.go` + `core/actions.go`)

```
1. core.FlushOutgoing()   scan Vault MD for status:send or !b  → Connector.Send()
2. core.FlushActions()    scan for status:seen/archived/deleted/spam → Connector.Handle() + update JSON + re-render MD
3. fetch()                Connector.Fetch() → JMAP Emails + Mailboxes
4. assignThreadIDs()      walk InReplyTo chain, assign ThreadID
5. deduplicate()          remove duplicates by Email.ID
6. writeMailboxes()       vault/.data/mailboxes.json
7. mergeWithExisting()    merge incoming with vault/.data/emails/ (preserves $seen from local if server hasn't propagated)
8. WriteThreadMD()        write per-email JSON + thread index + MD (preserves drafts, renames on seen change)
```

### `status: seen` flow

```
Human sets status: seen in MD
  → watchVault detects change → syncNow
  → FlushActions reads MD intent
  → Connector.Handle(emailId, "seen")   ← tells server
  → WriteEmail($seen: true)             ← updates local JSON
  → ReadEmailsForThread                 ← re-reads updated JSON
  → WriteThreadMD                       ← re-renders MD from JSON (seen: true, status: )
```

### `core.WriteThreadMD` — canonical JSON→MD writer

All MD writes go through `core.WriteThreadMD`. Never patch MD strings directly.

```go
func WriteThreadMD(vaultDir, inboxKey string, emails []Email) bool
```

1. Writes each email JSON
2. Writes thread index JSON
3. Calls `RenderMD` to generate content from JSON
4. Preserves draft body from existing MD
5. Renames file if seen status changed (`_` prefix)
6. Writes MD only if content changed

---

## Serve mode (`biset --serve`)

biset can run as a standalone JMAP HTTP server, exposing the Vault over JMAP to any compatible client.

**Endpoints:**

| Path | Description |
|---|---|
| `/.well-known/jmap` | JMAP session document |
| `/jmap/api/` | JMAP API (POST) |
| `/jmap/eventsource/` | Server-Sent Events — push on vault change |

**JMAP methods implemented:**

`Mailbox/get`, `Email/query`, `Email/get`, `Email/set`, `Thread/get`, `Identity/get`

---

## Markdown format

```markdown
---
subject: "Re: hello"
contact: bob@example.com
mailboxId: mbx-you@example.com
threadId: thr-abc123
seen: true
status:
---

[compose area — cleared after send]

# 2024-01-15 11:00 bob@example.com (abc123)

Hey, how are you?
```

**Frontmatter fields:**

| Field | Description |
|---|---|
| `subject` | Thread subject |
| `contact` | The non-self correspondent |
| `mailboxId` | JMAP Mailbox ID (`mbx-{inboxKey}`) |
| `threadId` | JMAP Thread ID |
| `seen` | `false` = thread has unread messages (derived from JSON, not edited by human) |
| `status` | `send` / `seen` / `archived` / `deleted` / `spam` — triggers action on next sync |

`seen: false` → MD filename has `_` prefix (sorts to top in file browser).

---

## Changelog

### v0.3.7

- **`biset sync --full`** — new flag resets all connector state.json + removes stale lock before syncing; equivalent to "sync from scratch"
- **Full Sync tray item** — menu bar button that does the same as `sync --full` without touching the running daemon
- **Lock stale timeout** — `acquireLock` now treats a lock older than 5 minutes as abandoned; prevents permanent lockout when the daemon crashes without cleanup
- **Claude connector: session thread merging** — `buildSessionParentMap` + `rootSession()` walk `logicalParentUuid` chains in `.jsonl` files to merge continuation sessions into one thread; `InReplyTo` and `ThreadID` set on all child emails so core's `AssignThreadIDs` groups them correctly
- **Claude connector: desktop app title lookup** — `loadAppTitles()` scans `~/Library/Application Support/Claude/claude-code-sessions/**/*.json` for `cliSessionId → title` mappings; used as `fallbackTitle` in `parseJSONL` for sessions that have no `ai-title` entry (desktop-app sessions where the title is generated by the app, not the CLI)
- **Claude connector: performance** — `buildSessionParentMap` now only runs when new `.jsonl` files are present; skips the 77MB+ scan on unchanged directories
- **Claude connector: state.json re-read** — `fetchAll()` re-reads `state.json` from disk at each call so a state reset (e.g. `sync --full`) takes effect without restarting the connector process

### v0.3.6

- **Subcommand model** — `biset up/down/sync/serve/status/config/version`; no args shows help
- **Single-instance lock** — `acquireLock` writes PID to `vault/.data/.biset.lock`; duplicate `up` exits with "already running (pid X)"
- **`biset down`** — polls lock file after sending quit signal; prints "stopped" on clean exit
- **`biset config`** — numbered menu listing `biset.json` and all connector `config.json`s
- **Tray menu redesign** — `~/inbox (HH:MM)`, `Serve`, `Vault…`, `Config` (submenu), `Quit`
- **Config submenu** — `open -t` to open in default text editor (not browser)
- **install.sh** — optional connector selection (biset-imap forced, others prompted); IMAP auth test blocks on failure
- **`biset: stopped`** — printed after daemon exits cleanly

### v0.3.0

- **`core/` restructured** — `vault.go` split into `json.go` (JSON I/O) and `md.go` (MD rendering + string ops)
- **`message.go` → `email.go`** — renamed to reflect content (Email accessors, helpers, thread logic)
- **`core/actions.go`** — `FlushOutgoing`/`FlushActions` moved from `package main` into `core`; the only file in `core/` that uses `*Manager`

### v0.2.0

- **`status: seen` support** — marks thread as read via Connector + updates local JSON + re-renders MD
- **MD↔JSON architecture** — MD is always re-rendered from JSON via `core.WriteThreadMD`; no direct MD string patching
- **`actions.go`** — MD action processing separated from fetch cycle
- **`watch.go`** — sync trigger layer separated from tray UI
- **Connector debounce responsibility** — biset no longer embeds protocol-specific debounce; connectors handle their own throttle before sending notify
- **biset-jmap removed** — legacy connector deleted; JMAP HTTP server remains in `serve.go`
- `tray.go` reduced to pure UI (menu, notifications, serve toggle)

### v0.1.0

- Core architecture: Message / Connector / Vault
- JMAP-native data model (RFC 8621)
- Vault format: per-email JSON, thread index, mailboxes.json
- MD filename conventions with `_` prefix for unseen
- `biset --serve`: JMAP HTTP server
- Connectors: biset-imap, biset-claude
- Tray menu bar app (macOS)
