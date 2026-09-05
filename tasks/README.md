# 外部エージェント向けの作業指示書

`PLAN-simplify.md` から切り出した、**単独で実行できる**作業。各ファイルは自己完結しており、
このリポジトリを知らないエージェントがそれだけを読んで着手できるように書いてある。

## 現在の方針（2026-09-05 のユーザー判断）

biset は自前ログイン（native login: BIP39 seed から identity を作る方式）を廃止し、
外部の did IdP（**did.md**）ログインへ一本化する。

- 既存ユーザーのデータは**すべて消してよい**。移行パスは不要
- **Anchor そのものを削除する**（OIDC 層だけでなく did:webvh 公開文書ホスティングも含めて全部）→ ✅ 完了 `74864ff` `c26db16`
- **機能が一時的に落ちることを許容する**（「先に削除、機能は後追い」）
- MIMI checkpoint の KEK は wallet の `vaultSecret` を使う
- メールアドレスの採番は **mediator 側の責務**（did.md が専用 mediator を運用する）

## 一覧

| ファイル | 内容 | 規模 | 前提 |
|---|---|---|---|
| [N1-remove-native-login.md](N1-remove-native-login.md) | クライアントの native login を削除（seed 由来の identity 生成・復元・鍵導出・UI） | 大 | Anchor 削除（済） |
| [W3-wallet-feature-gaps.md](W3-wallet-feature-gaps.md) | N1 で落ちた機能を wallet 経路に実装（関係確立・送信outbox・checkpoint・グループ・メール） | 大 | **N1 が先** |
| [S5-client-server-split.md](S5-client-server-split.md) | `src/` を client / server / shared に分離 | 大 | **他の全作業と排他** |

## 実行順序

```
（Anchor 削除 ✅）──→ N1 ──→ W3 ──→ S5
```

- **Anchor 削除は完了済み**（`74864ff` `c26db16`）。`src/anchor/` `src/oid4vp/` `src/oidc/`
  `tsconfig.anchor.json`、`deploy.sh` の anchor ターゲットはいずれも存在しない
- **W3 は N1 の後**。何が落ちたかが分からないと埋めようがない
- **S5 は最後**。ほぼ全ファイルを動かすので他と同時に走らせられない。
  N1 でファイルが大幅に減ってから移動する方が作業量が少ない

**N1・W3・S5 はいずれも `src/main.ts` を触るため、同時に実行しないこと。**

## 全作業に共通の約束

- **`bun run build` を使う。`bun build` 単体では不完全**（`scripts/inline.mjs` まで走らせる必要がある）。
- 検証は `bun run typecheck` / `bun run test` / `bun run build` / `node --check dist/app.js` を全部通す。
- **`bun run reachability`** はこのリポジトリ独自のチェックで、
  「本番エントリからは到達できず、テストからしか到達されないモジュール」を検出する。
  knip はテストが import したファイルを "used" と見なすため、この層を捕まえられない。
  作業の前後で数値を比較すること。**新たにそこへ落ちたファイルは「配線が切れた部品」**である。
- `dist/` は stage しない。ビルドで変わるが、まとめて別途コミットする。
- `git add -A` / `git commit -a` は使わない。`git commit <paths> -F <messagefile>` の形で、
  自分が触ったファイルだけをコミットする（他プロセスの stage を巻き込まないため）。
- **既存テストを消さない・弱めない。** 削除作業で消す場合は、消したテストを報告に列挙する。
- **コメントを捨てない。** このコードベースのコメントは「なぜこうなっているか」「どの障害を受けて入ったか」を
  記録しており、最も価値のある資産である。コードを移動するときはコメントも一緒に運ぶ。
- 「ついでの」バグ修正・リファクタ・改名はしない。気づいたことは報告に書く。
- **迷ったら勝手に決めず、その項目を飛ばして報告する。**

## バグ修正・機能追加を伴う場合の約束

回帰テストを付けること。そして **「修正前 / 実装前のコードに対してそのテストが落ちる」ことを実際に確認する**まで
が1つの作業である。

この約束は失敗から来ている: 一度、`toThrow(TypeError)` という緩い判定のテストを書いたところ、
検証を通過した入力も後段の別処理で TypeError を投げるため、**修正前のコードでも通ってしまった**。
具体的な条件（エラーメッセージなど）で判定する形に直して、初めて回帰テストとして機能した。

## 名前が紛らわしいもの（取り違え注意）

| | 何か | 扱い |
|---|---|---|
| ~~`src/oid4vp/`, `src/oidc/`~~ | Anchor の Login Credential Wallet（旧 native login 用） | 削除済 `74864ff` |
| `src/wallet/` | **did.md OAuth Wallet**（新方式、唯一の入口） | **絶対に消さない** |
| ~~`src/anchor/webvh/`~~ | Anchor 側の did:webvh **ホスティング** | 削除済 `c26db16` |
| `src/identity/webvh/` | クライアント側の did:webvh **解決** | **残す**（他人の DID 解決に必須） |

`createPortableCoordinatorCheckpoint` などに残る `Coordinator` は、既に撤去されたサブシステムの名残で、
中身は MIMI Self Vault のもの。改名は別作業。

## 背景資料

- `PLAN-simplify.md` — 簡素化計画の全体像、これまでに分かったこと、未解決issue
- `ARC.md` — **Anchor 削除で記述が古い**（§3 の全体像、§4.2、§13.1、§17.2 が実在しない
  コンポーネントを説明している）。N1 着地後にまとめて更新予定。読むときは注意
- `src/vault/README.md` — Vault 層の構成と不変条件
