# W2: seed 経路と wallet 経路の二重配線を統合する

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA、ビルドは `bun run build`）

## この作業の位置づけ

biset は自前ログイン（native login: BIP39 seed から identity を作る方式）を廃止し、
外部 did IdP（did.md）ログインへ一本化する方針が決まっている。

`src/main.ts` には現在アカウントの経路が2つ並存している:

1. **seed 経路** — `bootClient()` 内の `storedRecords` を起点とする本流（618行目以降のほぼ全体）
2. **wallet 経路** — `configureWalletAccountIfPresent()`（157行目から約460行）

将来 seed 経路を削除するが、**削除の前に「両経路が同じ関数を呼ぶ」状態にしておく必要がある**。
先に片方を消すと、wallet 側に残った実装が正しいかを検証する手段が無くなるため。

**この作業は削除ではない。統合だけを行う。** 振る舞いは1ビットも変えない。

## 統合対象（調査済み。行番号は 2026-09-05 時点なので自分で確認し直すこと）

優先度順。上の3件は「完全同一またはほぼ同一」で、最も安全。

| # | 機能 | seed 側 | wallet 側 | 差分 |
|---|---|---|---|---|
| 1 | DIDComm sender key 解決 | `resolveAnyDidCommSenderKey`（`main.ts:1218-1224`） | `resolveWalletSenderKey`（`main.ts:414-420`） | **完全同一** |
| 2 | contact key の起動時復元ループ | `main.ts:1509-1524` | `main.ts:526-536` | 実質同一 |
| 3 | DIDComm ingress envelope 生成 | `main.ts:1327-1344` | `main.ts:490-511` | `ingressId` の label 文字列のみ（`biset/didcomm-mediator-ingress/v1` vs `biset/didcomm-wallet-mediator-ingress/v1`） |
| 4 | relationship watch 登録 | `startRelationshipPoll`（`main.ts:1473-1485`） | `startWalletRelationshipWatch`（`main.ts:434-450`） | 実質同一 |
| 5 | relationship INIT への応答 | `handleRelationshipMessage`（`main.ts:1414-1471`） | `handleWalletRelationshipMessage`（`main.ts:452-489`） | mediator URL 比較の方法（下記） |
| 6 | Vault カード status 更新 | `setVaultCard`（`main.ts:735-740`） | `setWalletVaultStatus`（`main.ts:255-260`） | 差分抑止の有無 |

### #3 の label について
`ingressId` の label 文字列が違う。**これは ingress の重複排除キーに影響する可能性があるため、
安易に片方へ寄せてはいけない。** まず `ingressId` がどう使われるか（`src/vault/ingress-ingest.ts` や
`didcomm/ingress-projector.ts`）を読み、label を統一して安全かを判断すること。
安全でない、または判断がつかない場合は **label をパラメータとして受け取る共通関数**にして、
呼び出し側が現在の文字列を渡し続ける形にする。

### #5 の URL 比較（重要）
- wallet 側は `new URL(...).toString()` 同士で正規化して比較（`main.ts:457-460`）
- seed 側は `route.url !== mediatorUrl` の生文字列比較（`main.ts:1421`）

config の綴り（末尾スラッシュの有無）次第で **seed 側だけが誤って弾く**。
**wallet 側の実装が正しい。** 統合時は wallet 側に寄せること。

> 注: この URL 比較の修正は別作業（W1）で既に seed 側へ適用されている可能性がある。
> 作業開始時に `git log --oneline -20` と該当箇所を確認し、既に直っていれば #5 は「統合のみ」になる。

## 進め方

1. **1件ずつやる。** 1件統合するたびに `bun run typecheck` と `bun run test` を回す。
   まとめて全部やってから検証すると、どこで壊れたか分からなくなる。
2. 共通化した関数の置き場所は `src/app/` 配下が自然（既に `src/app/send.ts` がある）。
   ただし1〜2件しか無い小さなものを無理にファイル分割しなくてよい。
3. 共通関数には、**両側のコメントのうち情報量の多い方を残す**。このコードベースのコメントは
   「なぜこうなっているか」「どの障害を受けて入ったか」を記録した最も価値ある資産なので、捨てない。

## 絶対ルール

- **振る舞いを変えない。** 唯一の例外は #5 の URL 比較（seed 側を wallet 側の正しい実装に合わせる）で、
  これは意図的な修正なのでコミットメッセージに明記すること。
- 既存テストを1本も消さない・弱めない。
- 統合の過程でコードを「コピーして両方に置く」ことは絶対にしない。必ず移動させる。
- 「ついでの」バグ修正・リファクタ・改名は禁止。気づいたことは報告に書く。
- **統合してみて「実は振る舞いが違った」と分かったら、それが最重要の発見**なので、
  揃えてしまわずに差異を正確に報告すること。バグの可能性がある。
- 迷ったら勝手に決めず、その項目を飛ばして報告に書く。

## 触ってよいファイル

`src/main.ts`、`src/app/` 配下（新規作成含む）、`test/` 配下の新規テスト。
これら以外の変更が必要になったら、変更せずに止まって報告すること。

## 検証（すべて必須）

```
bun run typecheck      # tsconfig 5本すべて
bun run test           # 全通過。落ちたら隠さず出力ごと報告
bun run build          # `bun build` 単体は不可。必ず `bun run build`（scripts/inline.mjs まで走る）
node --check dist/app.js
bun run reachability --quiet   # 新設ファイルが本番から到達可能になっていること
```

`bun run reachability` は「テストからしか到達されないモジュール」を検出する自作チェック。
統合で新しいファイルを作った場合、`reached only by tests` や `reached by nothing` が
**増えていたら配線ミス**なので必ず確認すること。

## git

- 自分が変更したファイルだけを `git add`。`git add -A` / `git commit -a` は使わない。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）で行う。
  他プロセスが同じリポジトリで作業している場合に index を巻き込まないため。
- 統合1件ごとにコミットを分けてよい。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告してほしいこと

- 統合できた件数とできなかった件数、それぞれの理由
- **統合の過程で見つかった「両者の振る舞いの差異」**（あれば最優先で詳しく）
- `ingressId` の label を統一したか、パラメータ化したか、その判断根拠
- before/after の行数
- 検証コマンドと結果

## 参考

- 全体計画と背景: `PLAN-simplify.md`（特に §3.6）
- アーキテクチャ: `ARC.md`
