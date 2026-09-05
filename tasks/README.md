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
| [R1-src-restructure-design.md](R1-src-restructure-design.md) | **設計文書**（指示書ではない）。`src/` 構成変更の設計・実測・決定事項 | — | 先に読む |
| [R2-phase1-delete-unreachable.md](R2-phase1-delete-unreachable.md) | 本番から到達不能なコードの削除（約2,700行） | 中 | R1 を読むこと |
| [R3-phase2-restructure.md](R3-phase2-restructure.md) | `src/` を client / server / shared へ再構成 | **大** | **R2 完了後**。他の全作業と排他 |
| [W3-wallet-mail-design-proposal.md](W3-wallet-mail-design-proposal.md) | **設計案**。メールを did.md mediator の capability として実装する案 | — | 実装は did.md 側が必要 |

### 完了済み

`N1`（native login 削除）`W3`（wallet 経路の機能穴）`W5`（checkpoint の KEK を MLS へ）
`V1`（wallet 経路のテスト）は完了。参照用に残してある。

`S5-client-server-split.md` は **R3 が置き換えた**ため削除した（Anchor 削除と
`protocol/` → `shared/` 移動で前提が変わり、記述が古くなっていた）。

## 実行順序

```
R2（削除）──→ R3（再構成）──→ ARC.md にプログラム構成を書く（Phase 3）
```

- **R2 が先**。2,700行を移動してから消すのは二度手間で、移動の diff に消し忘れが埋もれる
- **ARC.md は最後**。構成が固まる前に書くと、移動のたびに書き直しになる

## ⚠️ 同一作業ツリーでの並行実行は禁止

これらの作業は**どれも `src/main.ts` を触る**。複数のエージェント（Codex、Claude Code、人間の手作業を含む）が
同じ作業ツリーで同時に書き込むと、どちらの成果も壊れる。

**着手前に必ず確認すること:**

```
git status --porcelain     # 空でなければ着手しない
git log --oneline -5       # 他の作業が進行中でないか
```

作業ツリーに未コミットの変更がある、または直近のコミットが別の作業のものである場合は、
**着手せずに報告すること。** 消えたはずの関数や、削除済みのはずのファイルが実行時に現れるといった
不可解な現象は、ほぼ確実に並行編集が原因である。そのときは自分の判断で辻褄を合わせようとせず、止まること。

（2026-09-05 に実際に発生: N1 が進行中の作業ツリーで別エージェントが Anchor 削除の後始末を始め、
`bootstrap.ts` から `enableDidComm` が消えていく途中経過を「取り残し」と誤認した。
そのエージェントが自分で気づいて停止したのは正しい判断だった。）

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
