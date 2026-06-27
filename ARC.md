---
version: v0.4.0
description: Architecture document for contributors. Read before modifying code.
---

# biset

## Concept

biset and its relays form a JMAP node network. Each relay is a standalone JMAP HTTP server bridging an external protocol. biset aggregates them into a local vault and renders messages as Markdown.

```
External protocols (IMAP, SMTP, ActivityPub, RSS, Claude API, …)
       ↕
  Relays  (JMAP server — source of truth)
       ↕  JMAP HTTP + SSE
  biset   (JMAP client + JMAP server)
   └── Vault (JSON cache + Markdown rendering)
       ↕
  JMAP clients (doucot, WebDAV, …)
```

### Relay = source of truth

- Each relay runs independently. biset never writes to a relay except via JMAP (`Email/set`, `EmailSubmission/set`).
- Relay stores are authoritative. The vault is a read cache.

### biset = JMAP client + JMAP server

- **Client side**: connects to relays, fetches via `Email/query` + delta sync, caches to vault.
- **Server side**: serves doucot/UI via `go-jmapserver` Store backed by `<vault>/.data`.
- The only thing biset reads back from Markdown is human intent: `status: send/seen/follow/archived/deleted/spam`.

### Relay routing

biset routes sends and actions by **inboxKey** (JMAP account ID). At startup biset reads `accounts` from each relay's session endpoint. `RelayForAccount(inboxKey)` finds the relay that owns a given account. MD files live under `vault/<inboxKey>/`.

### Multi-account relays

Some relays (e.g. `smtp-host`) host multiple JMAP accounts behind one URL. Config for these uses an `accounts` map:

```json
{
  "relayname": "smtp-host",
  "url": "https://mail.example.com/.well-known/jmap",
  "accounts": {
    "you@example.com": { "password": "user-plaintext-password" }
  }
}
```

`NewManager` expands each `accounts` entry into its own internal `Relay` instance authenticated as that account (Basic auth: `email + PBKDF2(password, ":biset-auth-v1")`). Single-tenant relays keep the legacy form with relay-level `password`.

### View conversion (relay → biset)

Relays and biset can have **divergent threading**. jmapsmtp sees outer RFC 822 headers only; biset can additionally decrypt PGP bodies and read inner Protected Headers (RFC 1847 / Memory Hole). Trusting the relay's view would mean some replies end up in new threads.

The fix: `ConvertRelayView` in `relay_view.go` normalizes every batch returned by `Relay.Fetch` before it touches the rest of the pipeline:

1. PGP decrypt + extract inner `In-Reply-To`
2. Clear ThreadID when InReplyTo is set
3. Oldest-first `store.Put` so the parent is present when the reply resolves its thread

After this point all downstream code (sync, render, dispatch) sees biset's authoritative view only. Relay-provided `Thread/get` responses are ignored.

### SSE push

```
Protocol event → relay hub.Notify() → SSE /jmap/eventsource/ → biset watchSSE → runSync()
```

---

## Directory structure

```
biset/
├── vault/
│   ├── config.go      — Config types, JMAP type aliases, FetchResult, PendingSubmission
│   ├── message.go     — Pure helpers: ID generation, accessors, GroupByThread
│   ├── storage.go     — Vault JSON I/O: message/thread/submission read+write
│   └── render.go      — MD rendering: WriteThreadMD, RenderMissingMDs, frontmatter parse
├── relays/
│   ├── imapsmtp-client/   — IMAP fetch + SMTP send
│   ├── smtp-host/         — SMTP receive + SMTP send (direct MX / relay)
│   ├── ap-host/           — ActivityPub server
│   ├── rss-client/        — RSS/Atom feed reader
│   └── claude-client/     — Claude API conversation reader
├── interfaces/
│   └── cli.go         — RunStatus, PingRelay, RelayAccountInfo
├── actions.go         — Human intent: FlushOutgoing, FlushActions
├── auth.go            — PBKDF2 derivations: deriveAuthToken, deriveEncPassword
├── pgp.go             — PGP key recovery/gen, body decrypt+encrypt, MIME parse
├── relay_view.go      — ConvertRelayView: PGP decrypt + ThreadID re-resolve
├── client.go          — JMAP relay client: Manager, Relay, WatchRelays, EnsureKeys
├── log.go             — Log config read/write
├── process.go         — Lock, TTY detection
├── relays.go          — Relay process lifecycle
├── serve.go           — biset JMAP server (serves doucot)
├── sync.go            — Sync cycle: runSync, dispatchSubmissions, StartWatcher
└── main.go            — CLI entrypoint + watchLoop
```

---

## vault/ package

### `config.go`
Config types and JMAP type aliases. No logic beyond `LoadConfig`.
- `Config`: `Vault`, `Relays`, `Notification`, `Server`, `Inboxes`
- `RelayConfig`: `RelayName`, `URL`, `Local`, `Password`, `Accounts` (multi-account relays use `Accounts: map[email]AccountConfig` instead of relay-level `Password`)
- `AccountConfig`: `Password` (user's plaintext login password; biset derives auth_token and enc_password from it)
- `ServerConfig`: `Port`, `Bind`, `RelayName`, `Password`, `Interface`
- `InboxConfig`: `MaxDisplay`, `Format` — per-inbox render config; `cfg.InboxConfigFor(key, cfg)` returns zero value if absent
- `FetchResult`: `Messages`, `Threads`, `Inboxes`, `QueryState`, `EmailState`, `MailboxState`
- `PendingSubmission`: queued outgoing send
- Type aliases: `Message` (email.Email), `Inbox` (mailbox.Mailbox), `Thread`, `Address`, `Envelope`, `Identity`

### `message.go`
Pure functions on Message values. No I/O.
- **ID generation**: `MakeMessageID`, `MakeThreadID`, `MakeMailboxID`, `InboxKeyFromMailboxID`
- **Accessors**: `MessageFromAddr`, `MessageBody`, `MessageIsSeen`, `MessageHeaderID`, `MessageMailboxID`
- **Thread grouping**: `GroupByThread`
- **Helpers**: `DefaultInbox`, `NewTextMessage`, `SafeFilename`

### `storage.go`
All vault JSON I/O. Reads and writes `<vault>/.data/` only.
- **Message**: `ReadMessage`, `WriteMessage`, `DeleteMessage`, `ScanMessages`
- **Thread**: `ReadThread`, `WriteThread`, `DeleteThread`, `ScanThreads`, `ReadMessagesForThread`
- **Mailbox**: `ReadInboxes`, `WriteInboxes`, `GetInboxes`
- **Submissions**: `WriteSubmission`, `ScanSubmissions`, `DeleteSubmission`
- **Identities**: `WriteIdentities`, `GetIdentities`

### `render.go`
Markdown rendering and the canonical JSON→MD bridge.
- `WriteThreadMD(vaultDir, inboxKey, messages, cfg)` — writes thread MD + backing JSON files
- `RenderMissingMDs(vaultDir, inboxKey, cfg)` — renders MD for threads without an MD file (e.g. sent-only)
- `EnsureNewFile`, `NewFileContent` — `_new.md` compose file
- `ParseFrontmatter`, `ExtractBody`, `ClearBody`, `InjectBody` — MD string parsing
- Accepts `InboxConfig`; applies `MaxDisplay` and `Format` without knowing relay identity

---

## go-jmapserver (`github.com/yno9/go-jmapserver`)

Shared JMAP library used by all relays and biset server. Lives at `~/go-jmapserver/`.

### Handler interface

```go
type Handler interface {
    Capabilities() []jmap.URI
    Accounts() []Account
    Handle(method string, args json.RawMessage) (any, error)
}

type Hub struct{}
func NewHub() *Hub
func (h *Hub) Notify()  // call on new data; pushes to SSE subscribers

func Serve(cfg Config, h Handler, hub *Hub) error
```

`Config`: `Port`, `Bind`, `Username`, `Password`. Handles Basic auth, `/.well-known/jmap`, `/jmap/api/`, `/jmap/eventsource/`, result-reference resolution.

### Store

Disk-backed JMAP object store. Each relay (and biset server) has one Store.

```go
func NewStore(dir string) (*Store, error)
func (s *Store) Put(m email.Email) error           // insert/update; auto-resolves ThreadID from InReplyTo chain
func (s *Store) Get(id jmap.ID) (email.Email, bool)
func (s *Store) Delete(id jmap.ID)
func (s *Store) All() []email.Email
func (s *Store) AllForThread(threadID jmap.ID) []email.Email  // sorted by ReceivedAt asc
func (s *Store) PatchKeywords(id jmap.ID, patch map[string]any) error
func (s *Store) PutPending(m email.Email)          // in-memory draft, not persisted
func (s *Store) TakePending(id jmap.ID) (email.Email, bool)
func (s *Store) PutMailboxes(mbs []mailbox.Mailbox) error
func (s *Store) Mailboxes() []mailbox.Mailbox
```

Standard JMAP method handlers (relay delegates instead of reimplementing):
```go
func (s *Store) HandleEmailGet(accountID, args) (any, error)
func (s *Store) HandleEmailQuery(accountID, args) (any, error)
func (s *Store) HandleEmailChanges(accountID, args) (any, error)
func (s *Store) HandleQueryChanges(accountID, args) (any, error)
func (s *Store) HandleThreadGet(accountID, args) (any, error)
func (s *Store) HandleThreadChanges(accountID, args) (any, error)
func (s *Store) HandleMailboxGet(accountID, args) (any, error)
func (s *Store) HandleMailboxChanges(accountID, args) (any, error)
func (s *Store) HandleIdentityGet(accountID) (any, error)
func (s *Store) HandleIdentityChanges(accountID, args) (any, error)
```

**Disk layout** (`<dir>/`):
- `messages/<id>.json` — one file per Email
- `mailboxes.json` — mailbox list
- `delta.json` — monotonic state counter + change history (survives restarts)

**biset server** opens Store at `<vault>/.data` — same path as `vault.WriteMessage`, so vault-written files are visible to the Store immediately.

**Thread ID resolution**: `Put` checks `InReplyTo` / `References` against existing messages; falls back to `"thr-" + MessageID[0]` for new threads. No external thread assignment needed.

---

## Relays

All relays share the same structure:
1. Parse `config.json` next to binary
2. Create `go-jmapserver` Store + Hub
3. Implement `Handler` interface; delegate most methods to Store
4. Protocol-specific goroutine (IMAP IDLE, HTTP server, RSS poller, …)
5. Call `hub.Notify()` on new data

### imapsmtp-client

Bridges IMAP (fetch, IDLE) and SMTP (send). Supports multiple accounts.

| Method | Action |
|---|---|
| `Email/query` | `FetchNew` on all IMAP accounts → store → `HandleEmailQuery` |
| `Email/queryChanges` | `HandleQueryChanges` |
| `Email/changes`, `Email/get` | store delegates |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | accounts list |
| `Identity/get`, `Identity/changes` | store delegates |
| `Email/set` (create) | draft → pending map |
| `Email/set` (update) | `PatchKeywords` + IMAP `SetFlag` / `Expunge` |
| `EmailSubmission/set` | SMTP send + IMAP Sent append |

SSE: IMAP IDLE per account → `hub.Notify()`.  
State: `data/fetchstate.json` — last UID per account.

### smtp-host

Receives email via SMTP (port 25); sends via direct MX or relay host. Supports DKIM signing and Autocrypt encryption.

| Method | Action |
|---|---|
| `Email/query` | drain incoming buffer → store → `HandleEmailQuery` |
| `Email/queryChanges` | `HandleQueryChanges` |
| `Email/changes`, `Email/get` | store delegates |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | store delegates |
| `Identity/get`, `Identity/changes` | store delegates |
| `Email/set` (create) | draft → pending map |
| `EmailSubmission/set` | SMTP send (direct MX or relay host); DKIM sign; Autocrypt encrypt if key known |

### ap-host

ActivityPub HTTP server. Handles follows, notes, DMs.

| Method | Action |
|---|---|
| `Email/query` | store → `HandleEmailQuery` |
| `Email/queryChanges` | `HandleQueryChanges` |
| `Email/get`, `Email/changes` | store delegates |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | AP inbox list |
| `Identity/get`, `Identity/changes` | store delegates |
| `Email/set` | AP post / follow / unfollow |
| `EmailSubmission/set` | AP send |

### rss-client

Polls RSS/Atom feeds via `gofeed`. All items from one feed share a single thread (`MakeThreadID(feedURL)`).

| Method | Action |
|---|---|
| `Email/query` | `pollAll()` → store → `HandleEmailQuery` |
| `Email/queryChanges` | `pollAll()` → `HandleQueryChanges` |
| `Email/get`, `Email/changes` | store delegates |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | store delegates |
| `Identity/get`, `Identity/changes` | store delegates |
| `Email/set` (create) | registers `To[0].Email` as feed URL in `state.json` |
| `EmailSubmission/set` | no-op |

State: `state.json` — `{feedURL → {seen_guids}}`.

### claude-client

Reads Claude Code conversation `.jsonl` files from configured project dirs. Presents sessions as email threads.

| Method | Action |
|---|---|
| `Email/query` | scan new `.jsonl` files → store → return IDs |
| `Email/queryChanges` | `HandleQueryChanges` |
| `Email/get`, `Email/changes` | store delegates |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | store delegates |
| `Identity/get`, `Identity/changes` | store delegates |
| `Email/set` (update) | `PatchKeywords` |
| `EmailSubmission/set` | no-op |

State: `state.json` — last seen mtime per project dir.

---

## biset package files

### `client.go`
JMAP relay client.
- `Manager`: holds configured `Relay` connections; `Changed()` channel for SSE-triggered sync
- `NewManager(cfg)` — expands multi-account `RelayConfig.Accounts` into per-account `Relay` instances (Basic auth: `email + deriveAuthToken(plaintext)`)
- `RelayForAccount(inboxKey)` — finds relay owning the account
- `Relay.Fetch(...)` — returns raw `FetchResult`; conversion to biset's view happens in `sync.go` via `ConvertRelayView`
- `Relay.Send(msg, envelope)` — `Email/set` + `EmailSubmission/set`
- `Relay.Handle(msgID, action)` — `Email/set` keyword update
- `Relay.Follow(contact)` — `Email/set` create with `$follow` keyword
- `Manager.WatchRelays()` — SSE subscriber goroutines; fires `mgr.Changed()` on state events
- `Manager.EnsureKeys()` — for each per-account relay, recovers (or generates+uploads) the user's PGP keypair at startup

### `auth.go`
PBKDF2-derived authentication tokens (match biset-ui formulas).
- `deriveAuthToken(password, email)` — `PBKDF2(password, email+":biset-auth-v1", 200000, SHA-256)` → base64; sent over the wire as Basic-auth password.
- `deriveEncPassword(password, email)` — `PBKDF2(password, email+":biset-enc-v1", ...)` → base64; never transmitted; used as the AES-GCM key for the encrypted PGP private key blob.

### `pgp.go`
PGP key management + body decrypt/encrypt.
- `EnsureAccountKey(relay)` — `GET /pgp/privkey` → AES-GCM decrypt with `enc_password` → save to `~/.biset/keys/<email>.asc`; if absent, generate ed25519/cv25519 keypair, encrypt, `PUT /pgp/privkey`, `PUT /pgp/pubkey`.
- `DecryptMessageBodies(messages, email)` — replaces PGP-armored bodies with plaintext, strips RFC 1847 Protected Headers, decodes Content-Transfer-Encoding.
- `EncryptBodyForPeer(relay, toEmail, body)` — fetches `peers/<addr>.pgp` from relay, encrypts+signs with `peer + sender` keys (used by `Relay.Send`).

### `relay_view.go`
The relay → biset view conversion layer.
- `ConvertRelayView(messages, store, accountEmail)`:
  1. `DecryptMessageBodies` (PGP decrypt + inner-header extraction)
  2. Clear `ThreadID` whenever `InReplyTo` is present so the store re-resolves it locally
  3. Oldest-first `store.Put` (parents before replies)
  4. Refresh in-place so callers see resolved ThreadIDs

Applied once on every `Relay.Fetch` result and every `Relay.Send` submission. Downstream code never touches the raw relay view.

### `relays.go`
Relay process lifecycle: `startManagedRelays`, `relayUp/Down`, `listRelays`.

### `actions.go`
Reads `status:` frontmatter and executes human intent.
- `FlushOutgoing` — `status: send` → write `PendingSubmission`
- `FlushActions` — `status: follow/seen/archived/deleted/spam` → relay call → `WriteThreadMD`

### `sync.go`
Full sync cycle.
- `runSync` — FlushOutgoing → dispatchSubmissions → FlushActions → fetch all relays → `ConvertRelayView` → `WriteThreadMD` per thread → `RenderMissingMDs`
- `dispatchSubmissions` — reads queued submissions, calls `Relay.Send`, runs the sent message through `ConvertRelayView`, then `WriteThreadMD`
- `StartWatcher` — ticker + SSE + fsnotify; `watchVault` adds newly-created inbox dirs to the fsnotify set
- Per-thread rendering uses `store.AllForThread` exclusively (relay `Thread/get` results are ignored — biset's view wins)
- Threads with empty ID and messages whose `MailboxIDs` don't match the inbox are filtered out before rendering

### `serve.go`
biset JMAP HTTP server serving doucot. Backed by `go-jmapserver` Store at `<vault>/.data`.

| Method | Action |
|---|---|
| `Email/query`, `Email/queryChanges`, `Email/changes` | store delegates |
| `Email/get` | store delegates |
| `Email/set` (create) | write draft MD to vault; `store.Put` |
| `Email/set` (update/destroy) | `store.PatchKeywords` / `store.Delete` + `vault.DeleteMessage` |
| `Thread/get`, `Thread/changes` | store delegates |
| `Mailbox/get`, `Mailbox/changes` | store delegates |
| `Identity/get`, `Identity/changes` | `vault.GetIdentities` / store delegate |

### `main.go`
CLI: `up` / `down` / `sync` / `relays` / `server` / `config` / `version`. `watchLoop` runs ticker + SSE + fsnotify.

---

## JMAP method coverage (RFC 8621)

凡例: ✅ 実装済み / — 未実装・対象外

- **biset** 列 = biset が relay に対して呼び出す（`client.go`）
- **go-jmapserver** 列 = `Store.HandleXxx` の実装状態
  - ✅ = 実装済み（実際に動作する）
  - △ = 有効な JMAP レスポンスを返すが実質 no-op（serverFail / 空リスト）
  - — = ハンドラなし（`unknown method` エラー）

| メソッド | biset | go-jmapserver | 概要 |
|---|---|---|---|
| `Mailbox/get` | ✅ | ✅ | メールボックス一覧・詳細取得 |
| `Mailbox/changes` | ✅ | ✅ | 変更差分取得 |
| `Mailbox/query` | — | ✅ | 条件指定でメールボックスID検索 |
| `Mailbox/queryChanges` | — | ✅ | クエリ結果差分取得（常に空） |
| `Mailbox/set` | — | ✅ | メールボックス作成・更新・削除 |
| `Thread/get` | ✅ | ✅ | スレッドのメッセージID一覧取得 |
| `Thread/changes` | — | ✅ | スレッド変更差分取得 |
| `Email/get` | ✅ | ✅ | メール内容・ヘッダー・本文取得 |
| `Email/changes` | ✅ | ✅ | メール変更差分取得 |
| `Email/query` | ✅ | ✅ | フィルター・ソートでメール検索（filter.inMailbox, position, limit 対応） |
| `Email/queryChanges` | ✅ | ✅ | クエリ結果差分取得 |
| `Email/set` | ✅ | ✅ | create → `OnCreateEmail` hook；update → PatchKeywords；destroy → Delete |
| `Email/copy` | — | △ | 別アカウントへコピー（serverFail） |
| `Email/import` | — | △ | RFC822 メッセージインポート（serverFail） |
| `Email/parse` | — | △ | 添付ファイル等をメールとしてパース（serverFail） |
| `SearchSnippet/get` | — | ✅ | 検索マッチ箇所のスニペット取得（本文テキスト検索） |
| `Identity/get` | ✅ | ✅ | 差出人アドレス・署名設定取得 |
| `Identity/changes` | — | ✅ | Identity 変更差分取得 |
| `Identity/set` | — | ✅ | 差出人情報作成・更新・削除（`OnSetIdentity` hook 経由で relay 側検証可） |
| `EmailSubmission/get` | — | ✅ | 送信キューオブジェクト取得（常に空） |
| `EmailSubmission/changes` | — | ✅ | 送信オブジェクト変更差分取得（常に空） |
| `EmailSubmission/query` | — | ✅ | 送信オブジェクト条件検索（常に空） |
| `EmailSubmission/queryChanges` | — | ✅ | 送信クエリ結果差分取得（常に空） |
| `EmailSubmission/set` | ✅ | ✅ | `OnSubmitEmail` hook 経由でプロトコル送信 |
| `VacationResponse/get` | — | ✅ | 不在応答設定取得（デフォルト無効） |
| `VacationResponse/set` | — | ✅ | 不在応答設定更新 |

### relay の個別実装

go-jmapserver が持たない `Email/set` と `EmailSubmission/set` は各 relay が実装する。

| Relay | `Email/set` | `EmailSubmission/set` |
|---|---|---|
| imapsmtp-client | create → pending / update → PatchKeywords + IMAP SetFlag/Expunge | SMTP 送信 + IMAP Sent append |
| smtp-host | create → pending | SMTP 送信（direct MX or relay host）+ DKIM + Autocrypt |
| ap-host | AP 投稿・follow・unfollow | AP 送信 |
| rss-client | create → `To[0].Email` を feed URL として `state.json` に登録 | no-op |
| claude-client | update → PatchKeywords | no-op |
| biset server | create → vault MD 生成 + store.Put / update → PatchKeywords / destroy → store.Delete | — |

---

## Vault structure

```
vault/
├── .data/
│   ├── messages/{msgId}.json       ← JMAP Email (written by store.Put and WriteThreadMD)
│   ├── threads/{threadId}.json     ← thread index (written by WriteThreadMD)
│   ├── mailboxes.json              ← mailbox list
│   ├── submissions/{id}.json       ← queued outgoing (written by FlushOutgoing)
│   ├── delta.json                  ← store state counter
│   └── .biset.lock                 ← daemon lock
├── you@example.com/
│   ├── _new.md                     ← compose / follow
│   └── {contact}_{shortId}.md     ← thread
└── rss/                            ← simplified inbox (trailing slash = simplified format)
    ├── _new.md
    └── {feedDomain}.md
```

---

## Markdown format

**Standard** (email inboxes):

```markdown
---
subject: "Re: hello"
contact: bob@example.com
mailboxId: mbx-you@example.com
id: abc123
seen: true
status:
---

[compose area]

# 2024-01-15 11:00 bob@example.com

message body
```

**Simplified** (inboxKey ends with `/`, e.g. `rss/`):

```markdown
---
contact: example.com
status:
---

- - -
2026-06-14 06:15 example.com
Article title …
```

| Field | Description |
|---|---|
| `status: send` | send compose area as message |
| `status: seen` | mark thread read |
| `status: follow` | follow `contact:` address (relay-interpreted) |
| `status: archived/deleted/spam` | move/delete/spam on relay |

---

## Message flow

### Receive

```
Protocol event (IMAP IDLE / HTTP POST / RSS poll)
  → relay hub.Notify() → SSE event
  → biset watchSSE → mgr.Changed() → runSync()
  → Relay.Fetch() (Email/query + Email/get + Thread/get + Mailbox/get)
  → store.Put(m) for each message
  → WriteThreadMD per thread
```

### Send

```
Human edits _new.md (status: send)
  → FlushOutgoing → PendingSubmission written to submissions/
  → dispatchSubmissions → Relay.Send(msg, envelope)
      → Email/set (draft) + EmailSubmission/set (send)
      → protocol delivery (SMTP / AP / …)
  → store.Put(sentMsg) + WriteThreadMD
```

---

## Config and state files

### biset

| File | Location | Notes |
|---|---|---|
| `config.json` | `~/.biset/config.json` | vault path, relays, server. fsnotify → reload → runSync. **relay add/remove requires daemon restart** |
| `private_key.pem` | `~/.biset/private_key.pem` | RSA master key; auto-generated if absent |
| `biset.log` | `~/.biset/biset.log` | daemon stdout/stderr |
| `.biset.lock` | `<vault>/.data/.biset.lock` | pid lock; stale lock overwritten on startup |

### vault

| File | Written by | Notes |
|---|---|---|
| `messages/{id}.json` | `store.Put`, `WriteThreadMD` | delete → re-fetched from relay on next sync |
| `threads/{id}.json` | `WriteThreadMD` | delete → MD re-rendered on next sync |
| `mailboxes.json` | `store.PutMailboxes` | overwritten each sync |
| `state.json` | `vault.SaveState` | relay → inboxKey map; used by `CleanupOrphanedInboxes` |
| `delta.json` | store internal | state counter; delete → next sync falls back to full fetch |
| `submissions/{id}.json` | `FlushOutgoing` → deleted by `dispatchSubmissions` | leftover = re-send on next sync |

### Per-relay

| Relay | Config location | State file |
|---|---|---|
| imapsmtp-client | `~/.biset/relays/imapsmtp-client/config.json` | `data/fetchstate.json` — last UID per account |
| smtp-host | `~/.biset/relays/smtp-host/config.json` | — |
| ap-host | `~/.biset/relays/ap-host/config.json` | `data/` store files |
| rss-client | `~/.biset/relays/rss-client/config.json` | `state.json` — seen GUIDs per feed |
| claude-client | `~/.biset/relays/claude-client/config.json` | `state.json` — last mtime per project dir |

---

## Changelog

### v0.4.1

- **Multi-account relays** — `RelayConfig.Accounts: map[email]AccountConfig` (`AccountConfig.Password` = user plaintext). `NewManager` expands each entry into a per-account `Relay` authed as `email + deriveAuthToken(password)`.
- **`auth.go`** — PBKDF2 derivations (`deriveAuthToken`, `deriveEncPassword`) matching biset-ui formulas.
- **`pgp.go`** — PGP keypair recovery / generation per account. On `biset up`, `Manager.EnsureKeys` fetches `/pgp/privkey` (or generates+uploads), saves armored private key to `~/.biset/keys/<email>.asc`.
- **Layer 2 send encryption** — `Relay.Send` now fetches the recipient's `peers/<addr>.pgp` and signs+encrypts client-side before submitting via JMAP (so DeltaChat-style peers see a properly signed Autocrypt message).
- **`relay_view.go`** — `ConvertRelayView` consolidates PGP decryption, inner-header extraction, and ThreadID re-resolution. Applied once per `Relay.Fetch` and per `Relay.Send`. All downstream code uses biset's authoritative view; the relay's `Thread/get` response is informational only.
- **fsnotify dir watching** — new inbox directories created at runtime are now added to the watcher (previously only initial scan).
- **MD render** — empty-threadID threads skipped; messages are filtered by `MailboxIDs[inbox]` before render (prevents cross-inbox bleed).
- **`config.example.json`** — adds `smtp-host` multi-account example.

### v0.4.0

- **`go-jmapserver`** (`github.com/yno9/go-jmapserver`) — shared JMAP library extracted; replaces `relays/core/`. All relays and biset server use `Store` + `Hub` + `Serve`.
- **biset server** (`server.go`) — hand-rolled JMAP handlers replaced by `Store` delegation. Store opens at `<vault>/.data` (same path as vault JSON files).
- **All relays** — now implement full method set: `Mailbox/changes`, `Thread/changes`, `Identity/changes`, `Email/queryChanges` (delta sync across restarts via `delta.json`).
- **`HandleEmailQuery`** — supports `filter.inMailbox`, `position`, `limit`.
- **`HandleThreadGet`** — email IDs sorted by `ReceivedAt` ascending.
- **`smtp-host`** relay — new: SMTP receive + direct MX send, DKIM, Autocrypt.
- **`claude-client`** relay — new: Claude Code `.jsonl` session reader.
- **`rss-client`** relay — new: RSS/Atom feed reader with per-feed thread grouping.
- **Deleted**: `relays/core/`, `relays/imap/`, `relays/smtp/`, `relays/claude/`.
- **`AssignThreadIDs`** removed from `sync.go`; Store.Put handles thread ID resolution via `InReplyTo` chain.

### v0.3.12

- **`relays/rss-client/`** — RSS/Atom feed reader relay.
- **`status: follow`** — first-class human intent; `FlushActions` calls `Relay.Follow`.
- **`InboxConfig`** — per-inbox `maxDisplay`/`format` in `config.json`; relay carries no render preferences.
- **Simplified MD format** — inboxKeys ending with `/` use contact-only filename and minimal frontmatter.

### v0.3.11

- **`nodes` → `relays`** — renamed throughout.
- **JMAP SSE** — `Hub` + `/jmap/eventsource/`; biset `watchSSE` triggers immediate sync.
- **`biset server up/down`** — new subcommand; `server` config section.

### v0.3.10

- **Relay architecture** — relays as standalone JMAP HTTP servers.
- **`relays/core/`** — shared Handler interface, Serve, Store.
- **`relays/imapsmtp-client/`** — first JMAP-native relay.
- **`RelayForAccount(inboxKey)`** — routing by JMAP session account ID.
- **Two-phase send** — `FlushOutgoing` + `dispatchSubmissions`.
