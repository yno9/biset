# biset client/relay server 分離計画

## 前提

| 役割 | コンポーネント | 正本 |
|------|--------------|------|
| JMAP server (source of truth) | relay (各プロトコル変換) | ✓ |
| JMAP client (cache + render) | biset core | ✗ |
| ローカルキャッシュ | vault/ | ✗ |

relay が正本を持つ。biset は異なる relay の正本を JMAP 経由で aggregate する。vault は relay レスポンスのローカルキャッシュにすぎない。

---

## 4つの関心領域

機能は以下の4区分に分類される。それぞれが独立した責務を持つ。

| 区分 | 担当 | 内容 |
|------|------|------|
| **biset proper** | biset | MD rendering、frontmatter パース、vault キャッシュ読み書き、ユーザー intent（status: send/seen/follow）の処理 |
| **biset JMAP client** | biset | relay に対する JMAP メソッド呼び出し（Email/query、Thread/get 等）、delta sync、state 管理 |
| **relay JMAP server** | relay | RFC 8621 メソッドの実装（go-jmapserver 使用）、delta tracking、SSE push |
| **relay protocol** | relay | 各プロトコル固有の処理（IMAP/SMTP、ActivityPub、RSS/Atom 等）と JMAP オブジェクトへの変換 |

biset proper と biset JMAP client の間、relay JMAP server と relay protocol の間は内部 API。  
**biset JMAP client と relay JMAP server の間は RFC 8621 のみ。独自プロトコルなし。**

---

## 現状の問題

- biset と relay が同一リポジトリ・モジュールに混在
- relay が biset 固有の内部 API（MergeMessages, DeduplicateMessages 等）に依存
- relay が vault/ に直接依存（本来不要）
- JMAP で解決できることを独自プロトコルで実装している箇所がある

---

## 目標

1. **relay は純粋な JMAP server** — RFC 8621 メソッドのみ実装、biset 固有コードゼロ
2. **biset は純粋な JMAP client** — relay の JMAP エンドポイントを叩くだけ
3. 共有ライブラリは `github.com/yno9/go-jmapserver`（biset 非依存）のみ

---

## 使用する JMAP メソッド

biset と relay の間は JMAP HTTP のみ。

### biset → relay（client side）

| メソッド | 現状 | 用途 |
|---------|------|------|
| `Mailbox/get` | ✅ | メールボックス一覧取得 |
| `Mailbox/changes` | — | メールボックス変更差分 |
| `Mailbox/query` | — | メールボックス検索 |
| `Mailbox/queryChanges` | — | メールボックスクエリ差分 |
| `Mailbox/set` | — | メールボックス作成・更新・削除 |
| `Thread/get` | — | スレッドのメッセージID一覧 |
| `Thread/changes` | — | スレッド変更差分 |
| `Mailbox/get` | ✅ | メールボックス一覧取得 |
| `Mailbox/changes` | — | メールボックス変更差分 |
| `Mailbox/query` | — | メールボックス検索 |
| `Mailbox/queryChanges` | — | メールボックスクエリ差分 |
| `Mailbox/set` | — | メールボックス作成・更新・削除 |
| `Thread/get` | ✅ | スレッドのメッセージID一覧 |
| `Thread/changes` | — | スレッド変更差分 |
| `Email/get` | ✅ | メール本文・ヘッダー取得 |
| `Email/changes` | ✅ | メール変更差分（フラグ更新検知） |
| `Email/query` | ✅ | メール一覧取得 |
| `Email/queryChanges` | ✅ | クエリ結果差分（追加/削除） |
| `Email/set` | ✅ | フラグ更新・下書き作成・削除 |
| `Email/copy` | — | 別アカウントへコピー |
| `Email/import` | — | RFC822 メッセージのインポート |
| `Email/parse` | — | 添付ファイルのパース |
| `SearchSnippet/get` | — | 検索スニペット取得 |
| `Identity/get` | ✅ | 差出人設定取得 |
| `Identity/changes` | — | 差出人設定変更差分 |
| `Identity/set` | — | 差出人設定更新 |
| `EmailSubmission/get` | — | 送信キュー取得 |
| `EmailSubmission/changes` | — | 送信オブジェクト変更差分 |
| `EmailSubmission/query` | — | 送信オブジェクト検索 |
| `EmailSubmission/queryChanges` | — | 送信クエリ差分 |
| `EmailSubmission/set` | ✅ | メール送信 |
| `VacationResponse/get` | — | 不在応答取得 |
| `VacationResponse/set` | — | 不在応答設定 |

### relay → biset（server side、doucot 向け）

| メソッド | 現状 | 用途 |
|---------|------|------|
| `Mailbox/get` | ✅ | メールボックス一覧 |
| `Mailbox/changes` | ✅ | メールボックス変更差分 |
| `Email/query` | ✅ | メール検索 |
| `Email/queryChanges` | ✅ | クエリ差分（go-jmapserver Store） |
| `Email/get` | ✅ | メール取得 |
| `Email/changes` | ✅ | フラグ変更差分（go-jmapserver Store） |
| `Email/set` | ✅ | 下書き作成・キーワード更新・削除 |
| `Thread/get` | ✅ | スレッド取得（receivedAt ソート） |
| `Thread/changes` | ✅ | スレッド変更差分 |
| `Identity/get` | ✅ | 差出人情報 |
| `Identity/changes` | ✅ | 差出人変更差分 |

**biset server は go-jmapserver Store を使用**（server.go の手書きハンドラ廃止）

---

## アーキテクチャ原則: 二面性と対称性

| | JMAP server（対外） | JMAP client（対内） |
|--|--|--|
| **biset** | go-jmapserver Store で dovecot/UI に serve | relay の JMAP エンドポイントを fetch |
| **relay** | go-jmapserver Store で biset に serve | IMAP/SMTP/AP 等のプロトコルを fetch |

この対称性をコードベースで明示する。現状はファイル名レベル（server.go / client.go）で示している。

---

## Phase 1: relay の完全 JMAP 化（完了）

- [x] `go-jmapserver` ライブラリ作成（`~/go-jmapserver/`、`github.com/yno9/go-jmapserver`）
- [x] `go-jmapserver` から biset 依存を全削除
- [x] 各 relay を `go-jmapserver` に移行（`relays/core` → `go-jmapserver`）
- [x] delta sync: `Email/queryChanges`、`Email/changes` 全 relay 実装
- [x] state persistence: `delta.json` でリスタート後も差分同期継続
- [x] ビルドエラー修正

---

## Phase 2: vault/ の役割明確化（進行中）

- vault/ = MD レンダリング + biset 固有 UI ロジック のみ
- メッセージ/スレッド/メールボックスの JMAP serve は go-jmapserver Store に移管済み
- sync.go が store.Put/Delete/PutMailboxes を使うよう変更済み

完了：
- [x] `MergeMessages` 削除
- [x] `DeduplicateMessages` 削除
- [x] biset server の手書きハンドラ削除（store.Handle* に置換）
- [x] sync.go: vault.WriteMessage → store.Put
- [x] sync.go: vault.WriteInboxes → store.PutMailboxes
- [x] sync.go: vault.ReadMessagesForThread → store.AllForThread
- [x] `Mailbox/changes`, `Thread/changes`, `Identity/changes` 全 relay + biset server 実装
- [x] relay `HandleThreadGet` の receivedAt ソート

残タスク：
- [x] `AssignThreadIDs` フォールバック削除（sync.go から除去済み）
- [x] `relays/core/` 削除（`go-jmapserver` に移行済み）
- [ ] vault/storage.go の不要関数整理（ReadThread/WriteThread は render.go 経由で使用中）

---

## Phase 3: relay の独立リポジトリ化

各 relay を独立 Go モジュールとして切り出す。

```
github.com/yno9/biset-smtp-host
github.com/yno9/biset-ap-host
github.com/yno9/biset-rss-client
github.com/yno9/biset-imap-client
github.com/yno9/biset-claude-client
```

依存関係（各 relay）：

```
relay
  └── github.com/yno9/go-jmapserver   (JMAP server フレームワーク)
  └── git.sr.ht/~rockorager/go-jmap   (JMAP 型定義)
  └── (プロトコル固有ライブラリのみ)
```

biset core・vault/ は含まない。

完了条件：`go build` が biset リポジトリ外で通る。

