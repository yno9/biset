# Concept Inventory (Phase 1 of design review)

Generated 2026-06-28 from Explore agent scan of biset / biset-ui / go-jmapserver / relays/*.

## 主要 drift / 痛みポイント（重要度順）

### 🔴 1. inboxKey の責務漏れ / 概念混在 (HIGH)

`inboxKey` は biset core 内部の routing 識別子だが、relay によって意味が違う：
- imapsmtp: account email (`alice@example.com`)
- rss-client: relay 名 (`rss`)
- jmapclaude: project 名 (`dev`, `biset`)

biset-ui は `inboxKey` を直接使わず 3-part path `${user}/${mailbox}/${contact}` で扱う。同じものを別表現で扱っているが、構造が違う → 変更時に同期取れない。

### 🔴 2. account / inboxKey / email の混同 (HIGH)

3 つの重複する概念：
- JMAP `accountID`: relay 認証ドメイン
- `inboxKey`: biset routing キー
- email address: multi-account relay の per-account 識別子

`vault/state.go` は accountID 単位で queryState 持つので、jmapclaude のように 1 account / N mailbox の場合、N project すべてで同じ state を共有 → 1 つの変更で全 project の delta sync state がリセットされる。

### 🟡 3. mailboxes.json 二重書き込み (MEDIUM)

`<vault>/.data/mailboxes.json` を `vault.WriteInboxes` と `Store.PutMailboxes` の両方が書く。どちらが canonical か不明。crash 中の整合性保証なし。

### 🟡 4. Relay view divergence の不完全な解決 (MEDIUM)

`ConvertRelayView`（PGP 復号 + ThreadID 再解決）は jmapsmtp 限定。他 relay（ap-host, smtp-host 等）が将来 encrypt するようになっても同じ問題が起きる。

### 🟡 5. inbox path の 2 系統 (MEDIUM)

- biset core: `vault/<inboxKey>/{contact}_{shortId}.md`（2-level）
- biset-ui: `${user}/${mailbox}/${contact}`（3-level、`~` エンコード）

UI は vault directory を直接読まないので動くが、概念的に 2 系統存在。

### 🟢 6. ARC.md vs 実装の小ドリフト (LOW)

ARC.md は `thr-msg-draft-` prefix に言及するが実装にない。

### 🟢 7. pending message のライフサイクル不統一 (LOW)

3 箇所に分散：vault `PendingSubmission`（永続）/ go-jmapserver `store.pending`（in-memory）/ biset-ui `state.pending`（UI state）。crash recovery の挙動が不明。

### 🟢 8. from_name の multi-hop 派生 (LOW)

relay → vault JSON → biset server → biset-ui の各層で from_name が伝播。途中で誰かが変えても下流に伝わらない。

### 🟢 9. jmapclaude identity name override が UI に見えない (LOW)

relay 側で identity name 上書きしているが、UI 側にその仕組みの認識なし。

## 観察された用語ゆれ

| 用語 | 場所 | 意味 |
|---|---|---|
| `inboxKey` | biset core | mailbox-derived routing key |
| `mailbox` | biset-ui | inbox path の 2 番目 segment |
| `account` | JMAP | 認証ドメイン |
| `Relay` | code | JMAP HTTP peer |
| `Connector` | ARC.md（旧記述？） | 同上 |
| `from_name` | biset-ui Message | display name（string） |
| `From[0].Name` | JMAP Email | display name（Address.Name） |
| `Inbox` | vault/config.go | `= mailbox.Mailbox` の type alias |

## Phase 2 議論候補（優先度順）

1. **inboxKey と accountID の責務再定義**（#1 + #2 まとめて）
2. **state を inboxKey 単位に変更**（#2 の派生）
3. **mailboxes.json の単一書き込み経路化**（#3）
4. **ConvertRelayView を opt-in にして全 relay 対応**（#4）
5. **inbox path 2 系統の統一**（#5）
6. **ARC.md の刷新と分割**（#6 + 全体）
7. **pending message lifecycle 統一**（#7）
