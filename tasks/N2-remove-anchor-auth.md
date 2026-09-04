# N2: Anchor の認証サーバー（OIDC provider + OpenID4VP Verifier）を削除する

対象リポジトリ: `~/biset`（TypeScript / Bun）

## 背景

biset は自前ログイン（native login）を廃止し、外部の did IdP（did.md）ログインへ一本化する。

その native login のサーバー側が **Anchor の OIDC provider + OpenID4VP Verifier** である。
Anchor は Biset 発行の holder-bound Login Credential を Wallet から受け取って検証し、
OIDC の authorization code フローを完成させていた。did.md が identity provider になるため、この層は不要になる。

**注意: Anchor 全体を消すのではない。** Anchor は did:webvh の公開文書ホスティング
（`did.jsonl` / `did.json` / `routing.json`）も担っており、そちらは別の判断が要る（この作業の範囲外）。

## 削除対象

### サーバー側
- `src/anchor/oidc.ts`（273行）— OIDC authorization / token エンドポイント
- `src/anchor/oidc-sqlite.ts`（298行）— OIDC の永続化
- `src/anchor/oidc-deployment.ts`（102行）
- `src/anchor/oid4vp.ts`（474行）— OpenID4VP Verifier（direct_post）
- `src/anchor/index.ts` / `app.ts` からこれらをマウントしている箇所

### クライアント側
- `src/oid4vp/` 全4ファイル（`wallet.ts` `wallet-store.ts` `profile.ts` `file-bridge.ts`）
- `src/oidc/client.ts`
- `src/main.ts` からの参照（**これらの呼び出し元は `main.ts` のみであることを確認済み**）
- `src/main.ts` の `ALL_LOCAL_DATABASE_NAMES`（143行目付近）から `'biset-wallet'` を外す
  （`src/oid4vp/wallet-store.ts:25` が使っていた IndexedDB）
- `IndexedDbBisetLoginWalletCredentialStore` とその `rekeyIdentity` 呼び出し（`main.ts:665`, `681-685` 付近）

### 対応するテスト
`test/anchor/` 配下の OIDC / OID4VP 関連、`test/oid4vp/`、`test/oidc-client-popup-race.test.ts`、
`test/anchor-wallet-origin.test.ts` など。**削除対象のコードを検証しているテストだけを消す。**
どのテストが該当するかは自分で確認すること（テストファイル名だけで判断しない）。

## 重要: 混同してはいけない2つの Wallet

このリポジトリには **名前の似た別物が2つ**ある。取り違えると動いている機能を壊す。

| | 何か | 扱い |
|---|---|---|
| `src/oid4vp/wallet.ts` ほか | **Anchor の Login Credential Wallet**（native login 用、OpenID4VP） | **削除対象** |
| `src/wallet/did-md-oauth.ts`, `did-md-store.ts` | **did.md OAuth Wallet**（新方式、これから唯一の入口になる） | **絶対に消さない** |

`src/wallet/` は残す。`src/oid4vp/` と `src/oidc/` を消す。

## 進め方

1. **まず `grep -rn` で削除対象への参照を全部洗う**（`src/` と `test/` の両方）。
   想定外の参照が見つかったら、消さずに報告すること。
2. クライアント側 → サーバー側の順に消す。クライアント側の方が参照が少ない。
3. 1つ消すごとに `bun run typecheck` を回す。
4. `bun run knip` を削除の前後で実行し、**新たに孤立したファイルが出ていないか**確認する。
   OIDC/OID4VP だけが使っていたヘルパが取り残される可能性がある。

## 絶対ルール

- **機能を巻き添えにしない。** 削除対象が「実は別の生きた機能からも使われていた」と分かったら、
  消さずに報告すること。
- `src/wallet/`（did.md OAuth）には一切触らない。
- Anchor の did:webvh 公開文書ホスティング（`src/anchor/webvh/`）には触らない。**これは別判断**。
- 既存テストのうち、**削除対象と無関係なものを消さない**。
- 「ついでの」リファクタは禁止。
- 削除して typecheck が通っても、**`bun run build:anchor` が通ることを必ず確認する**
  （Anchor は別の tsconfig / 別の entry point でビルドされる）。

## 他の作業との競合

`src/main.ts` は他の作業でも触られている可能性が高い。着手前に `git log --oneline -20` と
`git status --porcelain` を確認し、作業ツリーがクリーンであることを確かめること。
未コミットの変更がある場合は着手せずに報告する。

## 検証（すべて必須）

```
bun run typecheck      # tsconfig 5本すべて
bun run test           # 全通過
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run build:anchor   # Anchor が単体でビルドできること（必須）
bun run knip           # exit 1 が正常。unused files が増えていないこと
bun run reachability --quiet
```

`bun run reachability` の実行前後を比較すること。この削除により
**`reached only by tests` が 23 → 20 に減るはず**（`oid4vp/wallet.ts` `oid4vp/file-bridge.ts` `oidc/client.ts` の3件）。
減らない場合は消し漏れ、それ以外が減った場合は消しすぎ。

## git

- 自分が変更・削除したファイルだけを `git add` / `git rm`。`git add -A` は使わない。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）で行う。
- クライアント側とサーバー側でコミットを分けてよい。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告してほしいこと

- 削除したファイル数・行数
- **消さなかったもの**とその理由（他から参照されていた等）
- `knip` と `reachability` の before / after
- `bun run build:anchor` を含む検証コマンドの結果
- 気づいたが手を出さなかった問題

## 参考

- 全体計画: `PLAN-simplify.md`（§3.6 の N2）
- アーキテクチャ: `ARC.md`（§3 に Anchor の二層認証の説明がある。この作業で外側の OIDC と
  内側の OpenID4VP Verifier の両方が消える）
