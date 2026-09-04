# W3: wallet 経路の機能穴を埋める（native login 削除で落ちた機能の再実装）

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

## 背景

biset は native login（BIP39 seed ベース）を廃止し、did.md Wallet ログインへ一本化した。
ユーザーの判断で「**先に削除、機能は後追い**」の順序をとったため、
**削除された seed 経路にしか無かった機能が、現在アプリから失われている。**

この作業はその穴を埋める。**先に N1（native login 削除）が完了していることが前提。**
`git log --oneline -20` で確認し、まだなら着手しないこと。

削除で実際に何が落ちたかは、N1 の作業報告と `PLAN-simplify.md` §3.6 に記録されている。
**着手前に必ず読むこと。** 以下の一覧は削除前の調査時点のものなので、実際とずれている可能性がある。

## 埋める穴（優先度順）

### 1. 自分から関係を開始する（最優先・これが無いと誰とも通信できない）

**現状**: `sendWalletMessage`（`src/main.ts`）は contact が無ければ相手の公開 kid へ直接 basicmessage を投げるだけで、
`RELATIONSHIP_INIT` を送らない。さらに `RELATIONSHIP_ACCEPT` のハンドラも無い
（wallet の relationship ハンドラは `type !== RELATIONSHIP_INIT` で早期 return していた）。

つまり **wallet アカウント同士は双方が responder** であり、**誰とも関係を確立できない**。
native login があった頃は「相手が seed アカウントなら向こうから INIT が来る」ことで成立していたが、
全員が wallet になった今、その経路は無い。

**やること**: 削除された seed 経路の `ensureDidCommContact` に相当する開始側の実装を wallet 経路に持たせる。
`git show` で削除前の実装（`src/app/send.ts` の `ensureDidCommContact` と `src/main.ts` の
`handleRelationshipMessage`）を読み、**移植ではなく wallet の鍵管理に合わせて再実装する**こと。
wallet アカウントは `IdentityRecord` を持たず、鍵は did.md の認可フローで得た device session から来る。

### 2. DIDComm 送信 outbox と再送ループ

**現状**: wallet 経路は送信に失敗するとその場で失われる。
seed 経路は Vault の delivery outbox に積み、10秒間隔のポーリングで再送していた。

**やること**: 削除前の `flushDidCommTransportOutbox` 相当を wallet 経路に用意する。
Vault 側の outbox 機構（`src/vault/store.ts` の `DidCommTransportOutboxStore` 系）は**残っている**ので、
それを使う。

### 3. MIMI checkpoint（作成・復元）

**現状**: KEK が `masterSeed` 由来（`src/vault/vault-checkpoint.ts`）で、wallet アカウントは seed を持たない。
checkpoint が無いと、新デバイスが join 前の履歴を復元できないだけでなく、
**MIMI hub の delivery ログに圧縮点が作られず無限に伸びる**。

**方針は決定済み（ユーザー判断、2026-09-05）**:
> **wallet の `vaultSecret` を使う。**

`src/wallet/did-md-oauth.ts` が既に32バイトのランダム値を `vaultSecret` として生成・封印しているが、
**現状どこからも使われていない**（checkpoint KEK の置き場として用意された跡に見える）。
まずこの値がどう封印され、どう取り出せるのかを確認するところから始めること。

`vault-checkpoint.ts` の `createPortableCoordinatorCheckpoint` /
`openPortableCoordinatorCheckpoint` が seed を要求する形になっているので、
**KEK を引数で受け取る形に変え**、seed 側の呼び出し元が消えている今なら素直に置き換えられるはず。

> 名前について: これらの関数と `deriveCoordinatorRecoveryKek` の `Coordinator` は、
> 既に撤去されたサブシステムの名残であり、中身は MIMI Self Vault のもの。
> **改名はこの作業ではやらない**（別作業）。

### 4. DIDComm グループチャット

作成・招待・送受信。削除前の実装は `src/didcomm/group-chat.ts` と `group-chat-store.ts` に
**モジュールとしては残っている**（`git log` で確認すること）。呼び出し側だけが消えた状態のはず。

> 現在、未対応のメッセージ type は「ACK して破棄し、警告ログを出す」形でガードされている
> （`isProjectableDidCommIngress`）。グループチャットを復活させるときは、
> `GROUP_INVITE` / `GROUP_MESSAGE` をこのガードの手前で分岐させること。
> **ガードを緩めてはいけない** — それは未対応 type がキューを詰まらせるバグ（`4a5554d` で修正）の再発になる。

### 5. メール送受信

**方針（ユーザー判断、2026-09-05）**:
> 「これは biset の問題というより mediator の問題。did.md が専用の mediator を運用すればいい。
> ユーザーは did.md での wallet ログイン時に did.md の mediator に登録する形をとる。
> ログイン時に特定の mediator の使用許可という capability を付与する必要があるかも。」

したがって:
- `mailFromForIdentity`（`src/identity/webvh/identifier.ts`）の
  「DID のドメインが biset の apex 配下であること」という制約を外す
- メールアドレスの採番と送信署名鍵は **mediator 側の責務**として設計する
- wallet ログイン時に mediator 使用許可の capability を付与する仕組みを検討する

**これは設計を伴うため、実装前に設計案を出して確認を取ること。** 4 までとは性質が違う。

## 絶対ルール

- **1つずつやる。** 1機能ごとに検証してコミットする。まとめてやらない。
- 削除された実装を `git show` で読むのはよいが、**そのまま移植しない**。
  wallet アカウントは `IdentityRecord` も seed も持たないので、鍵の出どころが違う。
- **回帰テストを付ける。** そして **「その機能が無い状態でテストが落ちること」を確認する**までが1つの作業。
  緩い判定（`toThrow(TypeError)` のような）では、実装前でも通ってしまうことがある。
  具体的な条件で判定すること。
- 既存テストを1本も消さない・弱めない。
- 未対応メッセージ type のガードを緩めない（上記）。
- 「ついでの」リファクタは禁止。

## 検証（すべて必須）

```
bun run typecheck
bun run test           # 全通過
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run reachability --quiet
```

`bun run reachability` の `reached only by tests` は、機能を配線するたびに**減るはず**
（部品はあるが呼ばれていない、という状態が解消されるため）。前後の数値を報告すること。

## git

- 自分が変更したファイルだけを `git add`。`dist/` は stage しない。
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）で行う。
- 機能ごとにコミットを分ける。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告してほしいこと

- 実装した機能と、それぞれの回帰テストが「実装前に落ちること」をどう確認したか
- wallet の鍵管理に合わせて**削除前の実装から変えた点**
- `vaultSecret` が実際にどう封印されていて、どう取り出したか（3 をやった場合）
- `reachability` の before / after
- 積み残した機能と理由

## 参考

- `PLAN-simplify.md` §3.6 — seed 経路と wallet 経路の機能対照表、この作業の背景
- `ARC.md` — 現行アーキテクチャ
- N1 の作業報告 — 実際に何が落ちたかの一次情報
