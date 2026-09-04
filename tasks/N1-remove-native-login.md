# N1: クライアントの native login を削除する

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

## 背景と決定事項

biset は自前ログイン（**native login**: BIP39 seed から identity を作る方式）を廃止し、
外部の did IdP（did.md）ログインへ一本化する。

**ユーザーの明示的な決定（2026-09-05）:**
- 既存ユーザーのデータは**すべて消してよい**。移行パスは不要
- **機能が一時的に落ちることを許容する**（「先に削除、機能は後追い」）

つまりこの作業は「機能を保ったまま消す」ものではない。**消した結果として落ちる機能があってよい。**
ただし**何が落ちたかを正確に報告すること**が、この作業の成果物の半分である。

## 前提

この作業の前に、別作業で **Anchor 全体**（`src/anchor/`）と **`src/oid4vp/` / `src/oidc/`** が削除されている。
着手時に `git log --oneline -20` で確認すること。まだなら、そちらが先。

## 削除対象

### `src/main.ts`
- `bootClient()` 内の `storedRecords` を起点とする経路一式（`IndexedDbIdentityRecordStore` から
  `IdentityRecord` を読み、seed から鍵を導出して動く本流。618行目以降のほぼ全体）
- `configureWalletAccountIfPresent()` を**無条件の入口**にする
  （現在は「ローカルに IdentityRecord が無いとき」のフォールバックとして呼ばれている）

> **注意**: `configureWalletAccountIfPresent()` を `bootClient()` 本体にインライン化するのは**この作業ではやらない**。
> 呼び出し構造の整理は別作業（PLAN-simplify の S4）の仕事。ここでは seed 経路を消して
> wallet 経路を唯一の入口にするところまで。

### `src/identity/`
- `bootstrap.ts` の `createNewIdentity` / `restoreIdentity` と、それらからしか呼ばれないヘルパ
- `seed.ts` `slip10.ts` `keys.ts`（BIP39 / SLIP-10 由来の鍵導出）
- `record-store.ts`（seed ベースの `IdentityRecord` の永続化）
- `webvh/create-genesis.ts` `prerotation.ts` `move.ts` `migrate.ts` `adopt-move.ts`
  （自前の did:webvh 発行・鍵ローテーション・ドメイン移転。did.md が発行元になるので不要）

### `src/ui/`
- `mnemonic.ts`（24語フレーズの入力・表示 UI、337行）
- `account-create.ts` の native 部分（username / TOS / recovery phrase / sign phrase のフォームと submit ハンドラ）。
  **同じファイルの did.md Wallet ログイン部分は残す**
- `account/config-page.ts` の Root Key 行、`account/state.ts` の `AccountPageConfig.masterSeed`
- `account/identity-modals.ts` の、seed 由来の鍵を扱うモーダル（表示名変更・identity 編集）で
  wallet アカウントに意味を持たないもの

### 絶対に消してはいけないもの
- **`src/wallet/`**（did.md OAuth）— これが唯一の入口になる
- **`src/identity/webvh/` の解決系**: `resolver.ts` `identifier.ts` `log.ts` `log-io.ts` `proof.ts`
  `document.ts` `multikey.ts` `hash.ts` `jcs.ts` `scid.ts`。**他人の DID を解決する**のに必須
- Vault / DIDComm / MIMI / mail / mediator のすべて

## 消すと落ちる機能（調査済み。**消してよいが、記録すること**）

wallet 経路にはこれらが無い。seed 経路を消せば、そのまま機能が消える:

| 機能 | 補足 |
|---|---|
| **自分から関係を開始（`RELATIONSHIP_INIT` 送信 / `ACCEPT` 処理）** | wallet 同士は双方 responder になり、**誰とも関係を確立できなくなる**。最優先の後追い実装対象 |
| メール送信（SMTP submission） | did.md 側の mediator が担う方針（下記） |
| メール受信（`MailIngressProjector` / mail-bridge 分岐） | 同上 |
| DIDComm グループチャット（作成・招待・送受信） | |
| DIDComm 送信 outbox と再送ループ | 送信失敗が即座に失われる |
| OpenPGP メール鍵の有効化 | |
| MIMI checkpoint の作成・復元 | KEK が `masterSeed` 由来のため。`src/wallet/did-md-oauth.ts` が既に生成している `vaultSecret`（現状未使用）を使う方針が決まっている |
| 表示名変更 / ドメイン移転 / 鍵ローテ | **不要**。did.md 側の責務 |

> **メールについての方針**（ユーザー判断、2026-09-05）:
> 「これは biset の問題というより mediator の問題。did.md が専用の mediator を運用すればいい。
> ユーザーは did.md での wallet ログイン時に did.md の mediator に登録する形をとる。
> ログイン時に特定の mediator の使用許可という capability を付与する必要があるかも。」
>
> したがって `mailFromForIdentity`（`src/identity/webvh/identifier.ts`）の
> **「DID のドメインが biset の apex 配下であること」という制約は将来的に外れる**。
> ただしその設計は別作業。この作業では**メール関連コードを消すところまで**でよい。

## 進め方

1. **削除の前に、消える機能の一覧を作る。** 上の表を出発点に、実際に消したコードと突き合わせて更新すること。
   これが後続の再実装作業の入力になるので、**推測ではなく実際に消したものを列挙する**。
2. UI 層 → `main.ts` → `identity/` の順に消す。UI から消すと、下の層の未使用が見えやすくなる。
3. 1段階ごとに `bun run typecheck` を回す。
4. `bun run knip` と `bun run reachability` を各段階で実行し、**孤立したファイルを拾う**。
   seed 経路だけが使っていたヘルパが取り残されるはず。

## 絶対ルール

- 残す対象（上記）を巻き添えにしない。
- **既存テストのうち、削除対象を検証しているものだけを消す。** 消したテストは報告に列挙すること。
- 「ついでの」リファクタ・バグ修正は禁止。気づいたことは報告に書く。
- **型が通らなくなった箇所を、動かないダミー実装で埋めない。** 消せないなら消さずに報告する。
- 迷ったら勝手に決めず、その項目を飛ばして報告に書く。

## 検証（すべて必須）

```
bun run typecheck      # tsconfig すべて
bun run test           # 全通過。落ちたら隠さず出力ごと報告
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run knip           # exit 1 が正常
bun run reachability --quiet
```

`bun run reachability` はこのリポジトリ独自のチェックで、「テストからしか到達されないモジュール」を検出する
（knip はテストが import したファイルを "used" と見なすため、この層を捕まえられない）。
**この削除で `reached only by tests` は大きく動くはず**なので、前後の数値と、
新たにそこへ落ちたファイルの一覧を報告すること。それが「消し残した部品」のリストになる。

## git

- 自分が変更・削除したファイルだけを `git add` / `git rm`。`git add -A` は使わない。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）で行う。
- UI / main.ts / identity でコミットを分けてよい。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告してほしいこと

1. 削除したファイル数・行数（UI / main.ts / identity / テスト の内訳）
2. **実際に落ちた機能の完全な一覧**（上の表を実測で更新したもの）。後続作業の入力になる
3. **消せなかったもの**とその理由
4. `knip` / `reachability` の before / after と、新たに孤立したファイルの一覧
5. 検証コマンドの結果
6. 気づいたが手を出さなかった問題

## 参考

- 全体計画: `PLAN-simplify.md`（§3.6 に seed 経路と wallet 経路の機能対照表がある）
- アーキテクチャ: `ARC.md`
