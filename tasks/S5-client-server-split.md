# S5: client / server のディレクトリ分離

対象リポジトリ: `~/biset`（TypeScript / Bun、ビルドは `bun run build`）

## 課題

`src/` の直下に、ブラウザで動くコードと Bun サーバーで動くコードと、両者が共有する wire schema が
**区別なく同居している**。型検査は `tsconfig` 5本で分けているが、**ディレクトリ構造がそれを反映していない**。

結果として起きていること:

- ブラウザバンドル（`src/main.ts` 起点）が `src/mimi/`（MIMI **サーバー**実装のディレクトリ）から
  直接 import している（`src/mls/mimi-client-transport.ts`、`src/mls/mimi-vault-*.ts`、`src/vault/mimi-vault-sync.ts` 経由）
- あるファイルを開いても「これはブラウザで動くのか、Bun で動くのか」がファイルの位置から判断できない
- ブラウザ向けに書いたつもりのコードが Node API を使っていても、対応する tsconfig に含まれていなければ気づけない

## やること

`src/` を役割で3分割する:

| 移動先 | 内容 |
|---|---|
| `src/client/` | ブラウザで動くもの: `main.ts` `sw.ts` `app/` `ui/` `local-jmap/` `vault/` `mail/` `identity/` `wallet/` `oid4vp/` `oidc/` と、`didcomm/` `mls/` のクライアント側 |
| `src/server/` | Bun で動くもの: `anchor/` `mediator/` `mimi/` |
| `src/shared/` | 双方が使うもの: `protocol/`（wire schema、canonical encoding、ID、署名対象バイト列） |

そのうえで:

1. **クライアントがサーバー実装ディレクトリを直接 import している箇所を洗い出す。**
   起点は `src/mls/mimi-client-transport.ts` / `src/mls/mimi-vault-{room,session,watch}.ts` / `src/vault/mimi-vault-sync.ts`。
   共有すべき型・エンコーダだけを `src/shared/` に切り出し、**クライアントが `src/server/` を import しない状態**にする。
2. `tsconfig.json` / `tsconfig.{anchor,mediator,mail-plugin,mimi}.json` の `include` を新しい構造に合わせる。
   **「型検査の分離」と「ディレクトリの分離」を一致させる**のがこの作業の本質。
3. `package.json` の `scripts`（`build` / `build:*` / 各 entry）と `knip.json`、`scripts/reachability.mjs` の
   `ENTRIES` 配列も新しいパスに追従させる。

## 進め方（重要）

**大量の import 書き換えを伴うので、一気にやらない。** 推奨する順序:

1. まず `src/shared/`（= `protocol/` の移動）だけをやる。参照元が最も多いが、機械的で判断が要らない。
2. 次に `src/server/`（`anchor/` `mediator/` `mimi/`）。ここは相互参照が少ない。
3. **クライアント→サーバーの import を断ち切る**（上記 1.）。ここだけが設計判断を含む。
4. 最後に `src/client/`。

各段階で `bun run typecheck` / `bun run test` / `bun run build` を通し、**段階ごとにコミットする**。

`git mv` を使うこと（履歴が追える）。import パスの一括書き換えはスクリプトで機械的に行い、
**手で1つずつ直さない**（漏れが出る）。

## 絶対ルール

- **振る舞いを変えない。** ファイルの移動と import パスの書き換えだけ。中身のロジックには触らない。
- **`src/mls/vendor/` の中身は書き換えない。** RFC 9420 の vendored fork であり、
  upstream との diff を保つ必要がある。ディレクトリごと移動するのは可だが、ファイルの中身は触らない。
- 既存テストを1本も消さない・弱めない。`test/` 側の import パスは当然書き換えが必要。
- 「ついでの」リファクタ・改名・バグ修正は禁止。気づいたことは報告に書く。
- クライアント→サーバーの import を断つ段階で「共有すべきものが思ったより多い」と判明した場合、
  **無理に切らずに報告すること。** 何が共有されているかの一覧そのものが価値ある成果物になる。

## 他の作業との競合（重要）

このリポジトリでは並行して別の作業が走っている可能性がある。**S5 は `src/` のほぼ全ファイルを動かすため、
他のどの作業とも同時に実行できない。** 着手前に:

```
git log --oneline -20
git status --porcelain
```

を確認し、**作業ツリーがクリーンで、他のエージェントが動いていないことを確かめてから始めること。**
作業ツリーに未コミットの変更がある場合は、着手せずに報告すること。

## 検証（すべて必須）

```
bun run typecheck      # tsconfig 5本すべて
bun run test           # 全通過
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run knip           # exit code 1 で終わるのが正常。unused files が増えていないこと
bun run reachability --quiet
```

`bun run reachability` は本番エントリからの到達可能性を見る自作チェック。
移動前後で **`reachable` の分子・分母が同じ値のまま**（ファイル数は変わらないので）、
かつ `reached only by tests` / `reached by nothing` が**増えていない**ことを確認すること。
増えていたら import の書き換え漏れか、entry パスの更新漏れ。

サーバー3種のビルドも通ること:
```
bun run build:anchor
bun run build:didcomm-mediator
bun run build:mail-plugin
bun run build:mimi
```

## git

- `git mv` を使う。
- 段階ごとにコミットを分ける（`shared` / `server` / import 断ち切り / `client`）。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）で行う。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告してほしいこと

- 各段階の before/after（ファイル数、変更した import 数）
- **クライアントがサーバーから何を import していたか**の完全な一覧と、それぞれをどう解決したか
  （`shared` へ移動 / 型だけ複製 / 切れなかった）
- tsconfig の include がディレクトリ構造と一致したか
- 検証コマンドと結果（サーバー4種のビルドを含む）
- 気づいたが手を出さなかった問題

## 参考

- 全体計画: `PLAN-simplify.md`（S5 の節、および §1.4「client / server の境界が物理的にない」）
- アーキテクチャ: `ARC.md`（§3 にコンポーネント構成図がある）
