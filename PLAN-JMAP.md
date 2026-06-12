# biset JMAP ノードチェーン移行計画

## ゴール

各コネクタを独立した JMAP サーバとし、biset を JMAP クライアント + サーバのノードにする。

```
[外部プロトコル] ←→ [コネクタ: JMAP server] ←JMAP HTTP→ [biset: JMAP server+client] ←→ vault (MD)
```

- コネクタは biset 以外の JMAP クライアントとも話せる
- biset は Stalwart 等の外部 JMAP サーバに直接接続できる
- 各ノードは独立してデプロイ可能

---

## ライブラリ

**`git.sr.ht/~rockorager/go-jmap` v0.5.3**（導入済み）

- RFC 8620 core + RFC 8621 mail 実装
- `Client` (HTTP JMAP クライアント)、`Session` 付き
- サブパッケージ: `mail`, `mail/email`, `mail/mailbox`, `mail/thread`, `mail/emailsubmission`, `mail/identity`

---

## 変わる / 変わらない

### 変わらない
- vault の MD ファイル構造・フロントマター形式
- `auth.go` (鍵管理)
- `submissions/` pathway の概念
- connectors/imap の IMAP/SMTP ロジック本体

### 変わる（全面）
- `vault/config.go` の型定義 → go-jmap 型エイリアスに全置換
- `vault/message.go`, `storage.go`, `render.go` → 新型に対応
- `connector.go` → JMAP HTTP クライアントに書き直し
- `sync.go`, `actions.go` → 新型・新インターフェースに対応
- 各コネクタ → JMAP HTTP サーバ化

---

## 型マッピング

| 旧 vault 型 | 新 go-jmap 型 | パッケージ |
|---|---|---|
| `vault.Email` | `email.Email` | `mail/email` |
| `vault.Address` | `mail.Address` | `mail` |
| `vault.BodyPart` | `email.BodyPart` | `mail/email` |
| `vault.BodyValue` | `email.BodyValue` | `mail/email` |
| `vault.Mailbox` | `mailbox.Mailbox` | `mail/mailbox` |
| `vault.MailboxRights` | `mailbox.Rights` | `mail/mailbox` |
| `vault.Thread` | `thread.Thread` | `mail/thread` |
| `vault.Identity` | `identity.Identity` | `mail/identity` |
| `vault.EmailSubmission` | `emailsubmission.EmailSubmission` | `mail/emailsubmission` |
| `vault.Envelope` | `emailsubmission.Envelope` | `mail/emailsubmission` |
| `vault.EnvelopeAddress` | `emailsubmission.Address` | `mail/emailsubmission` |
| `string` (ID) | `jmap.ID` (= `type ID string`) | `go-jmap` |

**残す biset 固有型**: `Config`, `FetchResult`, `SyncNotification`, `PendingSubmission`

---

## 主な型差分と対処

| 差分 | 対処 |
|---|---|
| `map[string]bool` → `map[jmap.ID]bool` (MailboxIDs) | `jmap.ID(s)` でキャスト |
| `time.Time` → `*time.Time` (ReceivedAt) | `TimePtr(t)` / `TimeVal(t)` ヘルパー追加 |
| `[]Address` → `[]*mail.Address` (From/To/Cc/Bcc) | スライス要素をポインタに |
| `[]string` (EmailIDs in Thread) → `[]jmap.ID` | `jmap.ID(s)` でキャスト |
| `int` → `uint64` (Size) | キャスト |
| `MailboxRights` フィールド名 `MyRights` → `Rights` | 参照箇所を修正 |

---

## JMAP サブセット（実装対象）

| メソッド | 用途 |
|---|---|
| `Email/get` | メール取得 |
| `Email/changes` | 差分取得（増分同期） |
| `Email/set` | archive / delete / spam |
| `Mailbox/get` | メールボックス一覧 |
| `EmailSubmission/set` | 送信 |

エンドポイント:
- `GET /.well-known/jmap` → Session Resource
- `POST /jmap` → JMAP API
- `GET /jmap/eventsource` → SSE push

---

## フェーズ

### Phase 0: vault 型の go-jmap 移行
**対象ファイル**: `vault/config.go`, `vault/message.go`, `vault/storage.go`, `vault/render.go`

**方針**: `vault/config.go` の型定義を go-jmap 型エイリアスに全置換。
`vault.Email` という名前は残すが実体は `email.Email`。
外部コードは `vault.Email` のまま使えるが、フィールド型が変わるため全ファイルのコンパイルエラーを修正する。

```go
// vault/config.go
type (
    ID               = jmap.ID
    Email            = email.Email
    BodyPart         = email.BodyPart
    BodyValue        = email.BodyValue
    Address          = mail.Address
    Mailbox          = mailbox.Mailbox
    Thread           = thread.Thread
    Identity         = identity.Identity
    EmailSubmission  = emailsubmission.EmailSubmission
    Envelope         = emailsubmission.Envelope
    EnvelopeAddress  = emailsubmission.Address
)
```

追加ヘルパー:
```go
func TimePtr(t time.Time) *time.Time { return &t }
func TimeVal(t *time.Time) time.Time { if t == nil { return time.Time{} }; return *t }
```

`PendingSubmission` の `Email`/`Envelope` フィールドも自動的に新型になる。

**完了条件**: `go build ./...` が通る（全コネクタ含む）

---

### Phase 1: connector.go — JMAP HTTP クライアント化
**対象ファイル**: `connector.go` 書き直し、`jmap_client.go` 新規

- `Manifest` に `URL string` フィールド追加
- `manifest.URL` が空 → 従来の JSON-RPC（互換維持・暫定）
- `manifest.URL` がある → go-jmap `Client` で HTTP 接続
- `Connector.Fetch()` → `Email/get` + `Mailbox/get`
- `Connector.Send()` → `EmailSubmission/set`
- `Connector.Handle()` → `Email/set`
- プロセス起動・再起動ロジックはそのまま維持

**完了条件**: URL 指定時に JMAP で通信できる。URL なしは従来通り動く。

---

### Phase 2: biset-imap — JMAP サーバ化
**対象ファイル**: `connectors/imap/jmap_server.go` 新規、`connectors/imap/main.go` 改修

- `net/http` サーバ起動（ポート: manifest の `url` から取得 or env `BISET_JMAP_PORT`）
- `GET /.well-known/jmap` → Session Resource
- `POST /jmap` → `Email/get`, `Email/changes`, `Mailbox/get`, `Email/set`, `EmailSubmission/set`
- JMAP state 文字列管理（`AccountState` に `JMAPState string` 追加）
- `EmailSubmission/set` → 既存 SMTP 送信ロジックを呼び出す
- EventSource: IMAP IDLE 新着 → SSE push
- 旧 JSON-RPC stdin/stdout ハンドラ削除

`manifest.json` 変更:
```json
{ "url": "http://localhost:8801", ... }
```

**完了条件**: biset が JMAP で biset-imap と同期・送信できる。JSON-RPC コードが消える。

---

### Phase 3: biset — JMAP サーバ化
**対象ファイル**: `router.go` 拡張、`jmap_server.go` 新規

- `GET /.well-known/jmap` → biset Session（vault を accountId として公開）
- `POST /jmap` → vault データを JMAP レスポンスとして返す
- Password 認証（`BISET_PASSWORD`）
- 外部 JMAP クライアント（UI、スクリプト、他ノード）が直接接続可能

**完了条件**: `curl` で vault のメールが JMAP 形式で取得できる

---

### Phase 4（後回し）: biset-smtp / biset-ap JMAP サーバ化

biset-imap の実装をテンプレートに同様の手順。

---

### Phase 5（後回し）: 外部 JMAP ノード直接接続

Stalwart 等の `/.well-known/jmap` URL を manifest に指定するだけで動く状態にする。
biset-imap が不要になるケース。

---

## 移行順序と依存関係

```
Phase 0 (型移行)
    ↓
Phase 1 (connector JMAP クライアント化)
    ↓
Phase 2 (biset-imap JMAP サーバ化)  ←→  Phase 3 (biset JMAP サーバ化)
    ↓
Phase 4 (smtp/ap) ← 後回し
    ↓
Phase 5 (外部ノード) ← 後回し
```

Phase 0 が全ての基盤。Phase 1 は Phase 0 完了後すぐに着手できる。
Phase 2 と Phase 3 は独立して進められる。

---

## ファイル変更一覧

```
# Phase 0
vault/config.go         MOD  型定義を go-jmap エイリアスに全置換
vault/message.go        MOD  *time.Time, []*Address, map[ID]bool 対応
vault/storage.go        MOD  関数シグネチャ更新
vault/render.go         MOD  同上
actions.go              MOD  新型対応
sync.go                 MOD  新型対応
connectors/imap/main.go MOD  新型対応
connectors/imap/imap.go MOD  新型対応
connectors/smtp/main.go MOD  新型対応
connectors/ap/main.go   MOD  新型対応
router.go               MOD  新型対応

# Phase 1
connector.go            REW  JMAP HTTP クライアント
jmap_client.go          NEW  go-jmap Client ラッパー

# Phase 2
connectors/imap/jmap_server.go  NEW
connectors/imap/main.go         MOD  JSON-RPC 削除、JMAP サーバ起動

# Phase 3
jmap_server.go          NEW  biset JMAP サーバ
router.go               MOD  /.well-known/jmap + /jmap エンドポイント
```
