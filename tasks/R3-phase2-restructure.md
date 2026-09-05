# R3 (Phase 2): `src/` を client / server / shared に再構成する

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

**先に `tasks/R1-src-restructure-design.md` を読むこと。** 構成の設計と決定理由はそこにある。
**Phase 1（`tasks/R2-phase1-delete-unreachable.md`）が完了していることが前提。**
`git log --oneline -10` で確認し、未完了なら着手しないこと。

## 目的

現在の `src/` 直下11ディレクトリは、**デプロイ先・レイヤ・プロトコルという3つの軸が1階層に潰れている**。
そのため新しいファイルをどこに置くべきかが構造から決まらず、置きやすい場所に置かれ続けてきた。

実測された破綻は3つ（詳細は R1 §2）:

- **循環依存**: `vault ↔ local-jmap`（12/8）、`vault ↔ didcomm`（15/2）、`mls ↔ mimi`（11/2）
- **client/server 境界の違反**: `src/mls/` の4ファイルが MIMI **サーバー**ディレクトリを import
- 型検査（tsconfig）だけが境界を持ち、ディレクトリが持っていない

## 目標の構成

```
src/
  shared/
    protocol/          wire schema、canonical encoding、ID、署名対象バイト列
    mimi/              MIMI の protocol-types / wire / authorizer / app-data
  vendor/
    mls/               RFC 9420 fork。client と server の両方が使う。中身は一切触らない
  client/
    app/               起動と配線、および UI（main.ts、sw.ts、net-fetch.ts、app/send.ts、現 ui/）
    store/             Vault と projection（現 vault + local-jmap を統合）
    identity/          did:webvh 解決 + did.md Wallet セッション（現 identity + wallet）
    didcomm/           DIDComm クライアント
    mimi/              Self Vault クライアント（現 mls/ の client 部分 + mls/mimi-*.ts）
  server/
    didcomm-mediator/  mediator 本体（現 mediator/ の mail-plugin 以外）
    mail-plugin/       SMTP listener + submission HTTP（現 mediator/mail-plugin/）
    mimi/              self / normal / anon の3モード（現 mimi/）
```

## 設計上の要点（実測に基づく。推測で変えないこと）

### 1. `vault` と `local-jmap` は統合する

循環依存（vault→local-jmap 12、local-jmap→vault 8）は、**この2つが1つの関心事である証拠**として読む。
`vault/commit.ts` は projection を組むために `local-jmap/reducer.ts` を呼び、
`local-jmap/vault-mutation-sink.ts` は Vault へ書くために `vault/events.ts` を呼ぶ。
**分けたから循環したのであって、循環したから設計が悪いのではない。** `client/store/` にまとめる。

統合後、内部でどう並べるか（`store/vault/` と `store/projection/` に分ける等）は任せる。
ただし**新たな循環を作らないこと**。

### 2. `vendor/mls` は最上位に置く（mimi 配下に入れない）

`src/mimi/`（サーバー）が `mls/vendor/*` を大量に import している——`codec/{number,tlsDecoder,tlsEncoder,variableLength}`、
`credential`、`groupInfo`、`ratchetTree`、`publicGroupState`、`welcome`、`authenticationService`、
`groupContext`、`crypto/hpke`、そして `mls/suite.ts`。client 側も同じ vendor を使う。
**両方が使うので、両方から届く高さに置く必要がある。**

`mls/suite.ts`（ciphersuite の選択）も同じ理由で共有側に置くこと。置き場所は
`src/vendor/mls/suite.ts` でも `src/shared/` でもよいが、**client からも server からも import できること**。

### 3. client → server 違反は「移せば消える」

`src/mls/mimi-{client-transport,vault-session,vault-room,vault-watch}.ts` が
`src/mimi/` から import しているのは次の4つだけである。

| import 元 | 中身 |
|---|---|
| `mimi/protocol-types.ts` | wire の型定義 |
| `mimi/wire.ts` | エンコード／デコード |
| `mimi/authorizer.ts` | provider-internal credential signature |
| `mimi/app-data.ts` | MLS app data のエンコード |

**どれもサーバー実装ではなくプロトコル定義である。** これらを `shared/mimi/` へ移せば、
client と server が両方そこから import する形になり、**違反そのものが成立しなくなる**。

ただし、これらのファイルがサーバー専用の依存（SQLite、`Bun.serve`、node API など）を
引きずっていないか**必ず確認すること**。引きずっている場合は、client が必要とする部分だけを
切り出して `shared/mimi/` に置き、残りは server 側に残す。**その切り分け方を報告すること。**

## 進め方（この順序を守ること）

**一気にやらない。段階ごとにコミットし、段階ごとに全検証を通す。**

1. **`shared/` と `vendor/mls/`** — 参照元が最も多いが機械的で判断が要らない
2. **`server/`**（`mediator/` → `server/didcomm-mediator/` + `server/mail-plugin/`、`mimi/` → `server/mimi/`）
   — 相互参照が少ない
3. **client → server の import を断つ**（§3。ここだけが設計判断を含む）
4. **`client/` 内のレイヤ分け**。`vault` + `local-jmap` の統合はここ
5. **設定の追従** — `tsconfig*.json` の `include`/`exclude`、`package.json` の各 script、
   `knip.json` の entry、`scripts/reachability.mjs` の `ENTRIES` 配列

`git mv` を使うこと（履歴が追える）。
**import パスの書き換えはスクリプトで機械的に行うこと。手で1つずつ直すと必ず漏れる。**

## 絶対ルール

- **振る舞いを変えない。** ファイルの移動と import パスの書き換えだけ。中身のロジックには触らない。
- **`src/mls/vendor/` の中身は書き換えない。** RFC 9420 の vendored fork であり、
  upstream との diff を保つ必要がある。ディレクトリごと移動するのは可、ファイルの中身は不可。
- 既存テストを1本も消さない・弱めない。`test/` 側の import パス書き換えは当然必要。
- **コメント内のファイルパス参照も追従させること。** このコードベースのコメントは
  「なぜこうなっているか」「どの障害を受けて入ったか」を記録した最大の資産であり、
  そこに書かれたパスが古くなると価値が落ちる。機械的な置換に含めること。
- **ただし `src.bak/` を移植元として引用しているコメントのパスは変えないこと。**
  あれは実在する別ディレクトリへの参照である。
- 「ついでの」リファクタ・改名・バグ修正は禁止。気づいたことは報告に書く。
- 段階3で「共有すべきものが思ったより多い」と判明した場合、**無理に切らずに報告すること。**
  何が共有されているかの一覧そのものが価値ある成果物になる。

## 他の作業との競合

**この作業は `src/` のほぼ全ファイルを動かすため、他のどの作業とも同時に実行できない。**
着手前に必ず:

```
git status --porcelain     # 空でなければ着手しない
git log --oneline -10      # 他の作業が進行中でないか
```

作業ツリーに未コミットの変更がある場合は、着手せずに報告すること。

## 検証（各段階で必須）

```
bun run typecheck
bun run test           # 全通過
bun run build          # `bun build` 単体は不可。必ず `bun run build`
node --check dist/app.js
bun run knip           # exit 1 が正常。unused files が増えていないこと
bun run reachability --quiet
bun run build:didcomm-mediator && bun run build:mail-plugin && bun run build:mimi
bash -n deploy.sh
```

`bun run reachability` について: 移動はファイル数を変えないので、
**`reachable` の分子・分母が移動前と同じ値のまま**であること、
かつ **`reached only by tests` と `reached by nothing` が増えていない**ことを確認すること。
増えていたら import 書き換えの漏れか、`ENTRIES` の更新漏れである。

## git

- `git mv` を使う。
- **段階ごとにコミットを分ける**（shared+vendor / server / 境界断ち / client / 設定）。
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告

1. 各段階の before / after（ファイル数、書き換えた import 数）
2. **client が server から何を import していたか**の完全な一覧と、それぞれをどう解決したか
   （`shared/` へ移動 / 一部だけ切り出し / 切れなかった）
3. `vault` + `local-jmap` 統合後の内部構成と、新たな循環が無いことの確認方法
4. tsconfig の include が新しいディレクトリ構造と一致したか
5. 検証コマンドの結果（サーバー3種のビルドと `bash -n deploy.sh` を含む）
6. 気づいたが手を出さなかった問題

## この後の作業（着手しないこと）

Phase 3 で `ARC.md` にプログラム構成を書く。**構成が固まってから書く**ので、この作業では触らない。
