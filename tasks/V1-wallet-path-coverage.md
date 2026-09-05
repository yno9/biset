# V1: wallet 経路にテストを入れる（アプリ唯一の入口が無検査）

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

## なぜこれをやるのか

2026-09-05 に native login（BIP39 seed 由来の identity）を削除し、**did.md Wallet ログインがアプリへの
唯一の入口になった**。ところが `src/wallet/` は 1,083行あるのに、テストがあるのは直近に追加された2件だけである。

| ファイル | 行数 | テスト |
|---|---|---|
| `src/wallet/did-md-oauth.ts` | 508 | **無し** |
| `src/wallet/did-md-store.ts` | 317 | **無し** |
| `src/wallet/relationship.ts` | 175 | `test/wallet-relationship-initiation.test.ts` |
| `src/wallet/didcomm-outbox.ts` | 83 | `test/wallet-didcomm-outbox.test.ts` |

**無検査の2つが、最も大きく、最もセキュリティに関わる。** `did-md-oauth.ts` は
did:webvh log の検証、Data Integrity proof の検証、MLS device credential の検証、OAuth コールバックの
state/issuer 照合、秘密の封印を行う。ここが間違っていても、現状それを教えてくれるものが何も無い。

これは「機能を足す」作業ではなく、**既にある振る舞いを固定する**作業である。

## テストを入れる対象（優先度順）

### 1. `did-md-store.ts` の seal / open（最優先・純粋な暗号処理で最も書きやすい）

- `sealDidMdBisetDeviceMaterial` / `openDidMdBisetDeviceMaterial`
- `sealDidMdBisetDidCommDeviceMaterial` / `openDidMdBisetDidCommDeviceMaterial`

書くべきこと:
- 往復（seal → open）で元の値が復元されること
- **改竄した封印が開かないこと**（ciphertext・nonce・付随するメタデータをそれぞれ1バイト変える）
- 別の鍵／別のコンテキストでは開かないこと
- open 失敗時に**平文や鍵素材が例外メッセージへ漏れないこと**

### 2. OAuth コールバックの検証（`completeDidMdWalletCallback`）

古典的な脆弱性がここに集まる。**それぞれ拒否されることを確認すること:**

- `state` が保存済みの pending authorization と一致しない
- `issuer`（`iss`）が期待値と一致しない
- pending authorization が存在しないのにコールバックが来る
- 同じ `code` の二度目の使用（リプレイ）
- 成功後に pending authorization が**確実に破棄される**こと

`beginDidMdWalletLogin` が `state` と `codeVerifier` をどう生成・保存しているか（`randomBase64url`）と、
`readDidMdPendingAuthorization` / `clearDidMdPendingAuthorization` の使われ方を読んでから書くこと。

### 3. IndexedDB の読み書き（`fake-indexeddb` を使う）

`fake-indexeddb` は既に devDependency にある。既存テストの使い方（`import 'fake-indexeddb/auto'`）に倣うこと。

- registration / pending authorization / device session の read・save・clear が往復すること
- `clear` 後に `read` が `undefined` を返すこと
- 保存済みデータが**平文で入っていないこと**（封印されたものが封印されたまま入っている）

### 4. did:webvh log の検証（余力があれば）

`beginDidMdWalletLogin` は Wallet を開く前に公開 did:webvh log を検証する。
不正な log（proof 不一致、hash chain の破れ、期待と異なる DID）を**拒否すること**を確認できると価値が高い。
既存の `test/protocol/webvh-*.test.ts` 群に log を組み立てるヘルパがあるはずなので、まず読むこと。

これが難しければ**やらなくてよい**。1〜3 の方が優先度が高い。

## ⚠️ このタスク特有の注意: 「テストが実装前に落ちること」の確認方法

このリポジトリの規約では、テストは「修正前のコードに対して落ちること」を確認するまでが1件の作業である。
しかし今回は**既にある正しい振る舞いを固定する**作業なので、そのままでは適用できない。

代わりに **「テストが本当に噛んでいること」を変異させて確認すること**:

1. テストを書く（通る）
2. **テストが守っているガードを一時的に壊す**（例: `state` の照合を `if (false)` にする、
   AES-GCM の AAD を空にする、改竄検知の比較を削る）
3. **そのテストが落ちることを確認する**
4. コードを元に戻し、テストが通ることを再確認する

これをやらないと、何も検査していないテストが増えるだけになる。実際にこのリポジトリでは、
`toThrow(TypeError)` という緩い判定のテストが**壊れたコードでも通ってしまった**事例がある。

**報告には、どのガードをどう壊して、どのテストが落ちたかを具体的に書くこと。**

## 絶対ルール

- **本番コードを変更しない。** これはテストを足す作業である。
  変異による確認は必ず元に戻すこと（`git status` が clean であることで確認）。
  ただし**テストを書く過程で実際のバグを見つけた場合は、直さずに報告すること。** それが最大の成果になる。
- テストのために本番コードへ「テスト用の口」を新設しない。既存の export だけで書けるところを書く。
  書けないものは無理に書かず、「なぜ書けないか」を報告すること（それ自体が設計上の発見である）。
- 既存テストを1本も消さない・弱めない。
- 「ついでの」リファクタは禁止。

## 触ってよいファイル

`test/` 配下の新規テストファイルのみ。

`src/` 配下は**読むだけ**（変異による確認は一時的な変更なので可。必ず元に戻すこと）。
本番コードの恒久的な変更が必要だと判断したら、変更せずに止まって報告すること。

## 他の作業との競合

このタスクは `test/` にしか書かないので、他の作業と競合しにくい。
ただし着手前に `git status --porcelain` を確認し、**`src/wallet/` に未コミットの変更がある場合は着手しないこと**
（誰かが同じ場所を触っている）。

## 検証

```
bun run typecheck
bun run test           # 全通過
```

テストを足すだけなので `build` は不要だが、走らせて損はない。

## git

- 自分が追加したテストファイルだけを `git add`。`git add -A` は使わない。
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）。
- 対象ごとにコミットを分けてよい。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告

1. 追加したテストの一覧と、それぞれ何を固定したか
2. **変異による確認の記録**（どのガードを壊し、どのテストが落ちたか）— 最重要
3. **書けなかったもの**と、その理由（設計上テストしにくい箇所はどこか）
4. テストを書く過程で見つけたバグ・疑わしい挙動（あれば最優先で詳しく）
5. 検証コマンドの結果

## 参考

- `PLAN-simplify.md` §3.6 — native login 廃止の経緯。なぜ wallet が唯一の入口になったか
- `ARC.md` §3.2 — did.md OAuth と DPoP-bound device session
- `test/wallet-relationship-initiation.test.ts` — 直近に書かれた wallet 経路のテスト。書き方の参考に
