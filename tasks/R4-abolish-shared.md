# R4: `shared/` を廃止し、`protocol/` を主軸に再構成する

対象リポジトリ: `~/biset`（TypeScript / Bun / ブラウザSPA）

**先に `tasks/R1-src-restructure-design.md` の末尾「追記: `shared` の廃止」を読むこと。**
実測データと決定の経緯はそこにある。

## 目的（ユーザー決定、2026-09-06）

> 「shared という概念はやめよう。didcomm も mimi サーバも独立して client と無関係に存在すべき」

R3 で作った `src/shared/` は、**使用者（誰が使うか）で命名されたバケツ**であって、
中身の実態を表していない。実測すると:

- 38ファイル中、**client からのみ到達が10、server からのみ到達が4**——共有物ですらない
- 本当に両側が使う23ファイルは、**プロトコル線できれいに割れている**
  （didcomm 13 = client+mediator、mimi 4 = client+MIMI鯖、vault/mail schema 5、canonical 1 = 全部）

したがって**内容で命名し直せば、重複ゼロで `shared` を廃止できる**。
そして `server/` は `client/` を一切参照しなくなる——これが「サーバーが client と無関係に存在する」の実体である。

## 目標の構成

```
src/
  client/            クライアント本体（app / store / identity / mimi など現状の構造を維持）
  server/
    mediator/        DIDComm mediator 本体（現 server/didcomm-mediator/）
      mail-plugin/   SMTP listener + submission HTTP（現 server/mail-plugin/）
    mimi/            MIMI サーバー（self / normal / anon）
  protocol/          wire 定義。使用者ではなく内容で命名する
    canonical.ts     正準 JSON とバイト列化（client・mediator・MIMI鯖のすべてが使う唯一の物）
    ids.ts vault.ts signing.ts ingress.ts mail-submission.ts
    didcomm/         DIDComm プロトコル定義（13ファイル）
    mimi/            MIMI プロトコル定義（4ファイル）
    webvh/           did:webvh の解決・routing.json（下記 §3）
    mls/             RFC 9420 fork（現 vendor/mls/）。**中身は一切触らない**（下記 §5）
```

`vendor/` ディレクトリは**廃止する**。中身は `mls` だけであり、MLS は文字通りプロトコル（RFC 9420）で、
利用者も client 8ファイル・server 6ファイルと `protocol/didcomm/` `protocol/mimi/` と同じプロファイルである。

**依存の向きは一方向**: `client/` → `protocol/`、`server/` → `protocol/`。
**`protocol/` と `server/` は `client/` を参照しない。**

## 実測に基づく移動先（推測しないこと）

### 1. `shared/` の解体

| 現在 | 移動先 | 根拠 |
|---|---|---|
| `shared/didcomm/` の13ファイル<br>（`crypto` `devicekid` `forward-wrap` `message` `multikey` `peer` `problems` `mediator-protocol` `mediator-coordinate` `mediator-pickup` `mediator-transport` `webvh-resolve` `webvh-routing`） | `protocol/didcomm/` | client と mediator の**両方**から到達。MIMI サーバーからは到達しない |
| `shared/mimi/` の4ファイル<br>（`protocol-types` `wire` `authorizer` `app-data`） | `protocol/mimi/` | client と MIMI サーバーの**両方**から到達。mediator からは到達しない |
| `shared/protocol/` の `canonical.ts` | `protocol/canonical.ts` | **3者すべて**から到達する唯一のファイル |
| `shared/protocol/` の `ids` `vault` `signing` `ingress` `mail-submission` | `protocol/` 直下 | client と mediator から到達 |
| **`shared/didcomm/` の10ファイル**<br>（`basicmessage` `front-door-send` `group-chat` `group-chat-store` `ingress-projector` `mediator-sync` `mediator-watch` `relationship` `send-message` `trust-ping`） | **`client/` 配下** | **どのサーバーからも到達しない＝client 専用**。<br>`group-chat.ts` と `ingress-projector.ts` は `client/store/` を7〜9個 import しており、これが逆流の主因 |
| `shared/didcomm/mail-bridge.ts`、`shared/protocol/mail-submission-wire.ts` | `server/mediator/mail-plugin/` | **server からのみ**到達 |
| `shared/didcomm/route-deliver.ts`、`shared/protocol/validate.ts` | `server/` 配下 | **server からのみ**到達。適切な位置は自分で判断し、報告すること |
| `shared/protocol/test-vectors.ts` | `protocol/` に残す | どこからも到達しないがテストベクタ定義として正当 |

client 専用10ファイルの `client/` 内での配置は任せる（`client/didcomm/` を新設するのが素直）。
**判断した配置と理由を報告すること。**

### 2. `net-fetch.ts` の移動

`client/app/net-fetch.ts` は **client と mediator の両方から到達**し、
現在9ファイルが import している（`shared/didcomm/*` と `server/*` を含む）。これが逆流の最大の発生源である。

→ **`protocol/net-fetch.ts` へ移す。** プロトコルクライアントが持つべき土台であり、
client アプリ固有のものではない。

### 3. `client/identity/webvh/` の扱い（実測結果に注意）

`webvh/` の13ファイルのうち **10ファイルが client と mediator の両方から到達する**
（`document` `hash` `identifier` `jcs` `log` `multihash` `multikey` `proof` `resolver` `scid`）。
`server/mediator/mail-plugin/` が署名検証とアドレス判定に使っているためである。

→ **その10ファイルを `protocol/webvh/` へ移す。** did:webvh は wire 上の identity 表現であり、
client 固有ではない。

残りは移動しない:

| ファイル | 扱い |
|---|---|
| `webvh/log-io.ts` | client からのみ到達。`client/` に残す |
| `webvh/create-genesis.ts` `webvh/migrate.ts` `web/identifier.ts` `web/mirror.ts` | **本番からは到達しない**が、**残す側のコードのテスト3件が実物の did:webvh log を組み立てる唯一の手段**として使っている。消さない・動かす場合もテストが通ることを必ず確認する |

### 4. `vendor/mls/` → `protocol/mls/`（`vendor` の廃止）

`vendor/` を無くす。中身は `mls` だけである。

**移動そのものは最も安全な部類である**——実測の結果、`vendor/mls/` は
**外部を一切 import しない完全な葉**であり、書き換えが必要なのは参照側だけである。

> **ただし「これは vendored fork であり中身を編集しない」という情報が、パス名から失われる。**
> これを補うため、次を必ず守ること:
> - `VENDOR.md` は移動先（`protocol/mls/VENDOR.md`）にそのまま置く
> - **ファイルの中身は1バイトも変更しない。** import パスの書き換えも不要（自己完結しているため）
> - upstream との差分を示す `// biset:` marker には触れない
>
> 中身を触らないことが upstream diff の可視性を保つ唯一の手段なので、
> 「ついでに整形する」「未使用 export を消す」といった誘惑に乗らないこと。
> knip がこのディレクトリの unused export を報告し続けるのは**正常**である。

### 5. 残る逆流の解消

上記を終えた時点で、`protocol/` と `server/` から `client/` への import は**ゼロになるはず**である。
残っていたら、それは分類の誤りか見落としなので**報告すること**。

既知の個別項目:
- `shared/mimi/authorizer.ts` → `server/mimi/store.ts`（**型のみ**の import）。
  `protocol/mimi/authorizer.ts` へ移ると `protocol → server` の逆流になる。
  型を `protocol/mimi/` 側へ移すか、依存を反転させること。**やり方を報告すること**
- `shared/didcomm/send-message.ts` → `client/store/vault/contact-key.ts`（型のみ）。
  `send-message.ts` は client 専用なので `client/` へ移れば解消する

## 進め方（この順序を守ること）

**一気にやらない。段階ごとにコミットし、段階ごとに全検証を通す。**

1. **client 専用10ファイルを `shared/didcomm/` から `client/` へ**
   （最も逆流を減らし、以降の分類を単純にする）
2. **server 専用4ファイルを `server/` へ**
3. **`protocol/` の新設と、残る `shared/` の移動**（didcomm 13 / mimi 4 / canonical + schema 5）
4. **`net-fetch.ts` と `webvh/` 10ファイルを `protocol/` へ**
5. **`vendor/mls/` → `protocol/mls/`**（葉なので単独で安全。参照側の書き換えのみ）
6. **`server/didcomm-mediator/` → `server/mediator/`、`server/mail-plugin/` → `server/mediator/mail-plugin/`**
7. **設定の追従** — `tsconfig*.json` の include/exclude、`package.json` の各 script、
   `knip.json` の entry、`scripts/reachability.mjs` の `ENTRIES`

`git mv` を使うこと。**import パスの書き換えはスクリプトで機械的に行うこと。手作業は必ず漏れる。**

## 絶対ルール

- **振る舞いを変えない。** 移動と import パスの書き換えだけ。ロジックには触らない。
- **`protocol/mls/`（現 `vendor/mls/`）の中身は書き換えない。** RFC 9420 の vendored fork であり、
  中身を触らないことだけが upstream との差分を追える状態を保つ。
- 既存テストを1本も消さない・弱めない。`test/` 側の import 書き換えは当然必要。
- **コメント内のファイルパス参照も追従させること。** このコードベースのコメントは
  「なぜこうなっているか」を記録した最大の資産であり、パスが古くなると価値が落ちる。
  **ただし `src.bak/` への参照は実在する別ディレクトリなので変えない。**
- 「ついでの」リファクタ・改名・バグ修正は禁止。気づいたことは報告に書く。
- 分類が実測と食い違ったら、**自分の判断で押し通さず報告すること。**

## 他の作業との競合

**`src/` のほぼ全ファイルが動くため、他のどの作業とも同時に実行できない。** 着手前に:

```
git status --porcelain     # 空でなければ着手しない
git log --oneline -10
```

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

着手前の値: **reachable 168/266、tests-only 15、reached by nothing 0**。
移動はファイル数を変えないので、**分子・分母が同じまま**であること、
**tests-only と nothing が増えていない**ことを確認すること。増えていたら書き換え漏れか `ENTRIES` の更新漏れ。

### この作業に固有の検証

最後に、**層の逆流がゼロになったこと**を機械的に確認すること:

```bash
# protocol/ と server/ から client/ への import が無いこと（出力が空であるべき）
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*client/" src/protocol src/server --include='*.ts'

# protocol/ から server/ への import が無いこと（出力が空であるべき）
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*server/" src/protocol --include='*.ts'
```

**この2つが空になることが、この作業の成功条件である。**

あわせて `vendor/` が消えたことも確認する:

```bash
test ! -d src/vendor && echo "vendor 廃止 OK"
test -f src/protocol/mls/VENDOR.md && echo "VENDOR.md 保持 OK"
# vendored fork の中身が変わっていないこと（移動のみでdiffが出ないこと）
git log --follow --oneline -1 -- src/protocol/mls/VENDOR.md
```

## git

- `git mv` を使う。**段階ごとにコミットを分ける。**
- **`dist/` は stage しない。**
- コミットは `git commit <paths> -F <messagefile>` の形（pathspec 付き）。
- コミットメッセージ末尾に `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` を付ける。

## 報告

1. 各段階の before / after（ファイル数、書き換えた import 数）
2. **上記2つの grep が空になったことの確認**
3. client 専用10ファイルを `client/` のどこに置いたか、その理由
3b. `vendor/` が消え、`protocol/mls/` の**中身が1バイトも変わっていない**ことの確認方法
4. `authorizer.ts` の型依存をどう反転させたか
5. 実測と食い違った分類（あれば最優先で詳しく）
6. 検証コマンドの結果（サーバー3種のビルドと `bash -n deploy.sh` を含む）
7. 気づいたが手を出さなかった問題

## この後（着手しないこと）

`ARC.md` §21 は現在の構成を前提に書かれているため、この作業で全面的に古くなる。
**更新は別作業**なので触らないこと。
