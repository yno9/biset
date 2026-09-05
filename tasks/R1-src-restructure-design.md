# R1: `src/` の構成を作り直す（設計案）

Status: **設計案。実装の承認は未取得。**
作成: 2026-09-05

## 1. なぜやるのか

現在の `src/` 直下は次の11ディレクトリである。

```
didcomm  identity  local-jmap  mail  mediator  mimi  mls  shared  ui  vault  wallet
```

**3種類の異なる軸が1階層に潰れている**のが問題である。

| 軸 | 該当 |
|---|---|
| デプロイ先（ブラウザ / Bun サーバー） | `mediator` `mimi` はサーバー、他はブラウザ |
| レイヤ（UI / 保存 / 転送 / 配線） | `ui` `vault` `local-jmap` |
| プロトコル | `didcomm` `mail` `mls` `identity/webvh` |

軸が混ざっているため、**新しいファイルをどこに置くべきかが構造から決まらない**。
決まらないので「置きやすい場所」に置かれ続け、今の形になった。

## 2. 実測された破綻（2026-09-05 時点）

推測ではなく、import グラフを実際に走査した結果である。

### 2.1 循環依存が3つ

| 循環 | 回数 |
|---|---|
| `vault` ↔ `local-jmap` | vault→local-jmap 12 / local-jmap→vault 8 |
| `vault` ↔ `didcomm` | didcomm→vault 15 / vault→didcomm 2 |
| `mls` ↔ `mimi` | mls→mimi 11 / mimi→mls 2 |

**`vault` ↔ `local-jmap` の循環は「この2つが実は1つの関心事である」という証拠**として読むべきである。
`vault/commit.ts` は projection を組み立てるために `local-jmap/reducer.ts` を呼び、
`local-jmap/vault-mutation-sink.ts` は Vault へ書くために `vault/events.ts` を呼ぶ。
分けたから循環したのであって、循環したから設計が悪いのではない。**統合が正しい。**

### 2.2 client / server 境界の違反

`src/mls/` の4ファイルが、MIMI **サーバー**の実装ディレクトリ `src/mimi/` を直接 import している。

```
src/mls/mimi-client-transport.ts
src/mls/mimi-vault-session.ts
src/mls/mimi-vault-room.ts
src/mls/mimi-vault-watch.ts
```

型検査は tsconfig 4本で分かれているが、**ディレクトリ構造がそれを反映していない**ため、
あるファイルを開いても「ブラウザで動くのか Bun で動くのか」が位置から判断できない。

### 2.3 本番から到達不能なコードが 2,720行 / 38ファイル

`bun run reachability` による実測。内訳（ディレクトリ別のファイル数）:

```
vault 13 / mail 7 / mls 3 / mimi 3 / shared 2 / local-jmap 2 /
identity-webvh 2 / identity-web 2 / ui 1 / didcomm 1 / mls-vendor 2
```

## 3. 提案する構成

**主軸をデプロイ先に取り、その中をレイヤで分け、プロトコルは葉に置く。**
デプロイ先を主軸にする理由は、それが唯一 tsconfig とビルドで**強制されている境界**だからである。

```
src/
  shared/            両方が使う: wire schema、canonical encoding、ID、署名対象バイト列
  vendor/mls/        RFC 9420 の vendored fork。upstream diff を保つため一切触らない
  client/            ブラウザ
    app/             起動と配線（main.ts、send.ts、sw.ts）
    ui/
    store/           Vault と projection（現 vault + local-jmap。§2.1 により統合）
    identity/        did:webvh の解決 + did.md Wallet セッション（現 identity + wallet）
    messaging/       DIDComm（将来 mail が戻ればここ）
    selfvault/       MLS self-group と MIMI クライアント（現 mls の client 部分）
  server/            Bun
    mediator/        + mail-plugin
    mimi/
```

### 主な移動

| 現在 | 移動先 | 理由 |
|---|---|---|
| `vault/` + `local-jmap/` | `client/store/` | 循環依存が示すとおり1つの関心事 |
| `mls/mimi-*.ts`（4ファイル） | `client/selfvault/` | client/server 違反の解消。共有すべき wire 型は `shared/` へ切り出す |
| `mls/` の残り + `mls/vendor/` | `client/selfvault/` と `vendor/mls/` | fork を独立させ、upstream diff を見やすくする |
| `identity/` + `wallet/` | `client/identity/` | どちらも「この端末が誰であるか」を扱う |
| `didcomm/` + `mail/` | `client/messaging/` | 同じ「相手に届ける」レイヤ |
| `main.ts` `sw.ts` `net-fetch.ts` | `client/app/` | root 直下にファイルを置かない |
| `mediator/` `mimi/` | `server/` 配下 | デプロイ先が違うことを構造で示す |

### この構成が答えること

- **新しいファイルをどこに置くか** — まずブラウザかサーバーか、次にどのレイヤか、で一意に決まる
- **これはブラウザで動くのか** — パスを見れば分かる
- **循環していないか** — レイヤが上下関係を持つので、逆流が目に見える

## 4. 実施順序（重要）

**削除を先にやる。** 2,720行を移動してから消すのは無駄であり、
移動の diff に紛れて「消すべきだったもの」が見えなくなる。

### Phase 1: 到達不能コードの棚卸しと削除

38ファイルを次の3つに分類し、**分類結果を先に報告してから**削除に入ること。

- **(a) 完全に死んでいる** — 撤去済みサブシステムの残骸。削除する
- **(b) 未完成の機能の部品** — 例: mail 一式（実装は did.md 側の mediator 待ち）、
  peer restore（実装も呼び出し元も無い）。**削除は機能の判断なので、勝手に消さず報告する**
- **(c) テスト専用で正常** — ベクタ定義、vendored fork。残す

> 判断の前例: `identity/webvh/create-genesis.ts` と `migrate.ts` は削除候補に見えるが、
> **残す側のコードのテスト3件が、実物の did:webvh log を組み立てる唯一の手段**として使っている。
> 消すと resolver のカバレッジごと消える。到達可能性の数字だけで判断してはいけない。

### Phase 2: 構成の移動

Phase 1 完了後。**1段階ずつコミットする。**

1. `shared/` と `vendor/mls/`（参照元が最も多いが機械的で判断が要らない）
2. `server/`（相互参照が少ない）
3. **client → server の import を断つ**（§2.2。ここだけが設計判断を含む）
4. `client/` 内のレイヤ分け。`vault` + `local-jmap` の統合はここ
5. tsconfig / `package.json` / `knip.json` / `scripts/reachability.mjs` の `ENTRIES` を追従

`git mv` を使い、import の書き換えはスクリプトで機械的に行うこと（手作業は漏れる）。

### Phase 3: ARC.md にプログラム構成を書く

**構成が固まってから書く。** 先に書くと、移動のたびに書き直すことになる。

## 5. 未解決の論点（実装前に決めること）

1. **`mail/` を削除するか残すか。** 現在 7ファイル全部が到達不能。
   実装は did.md 側の mediator が必要で、設計案は `tasks/W3-wallet-mail-design-proposal.md` にある。
   残すなら「未完成」と分かる場所（例: `client/messaging/mail/`）に置き、
   消すなら設計案が復元の出発点になる
2. **peer restore と archive import を残すか。** `ARC.md` §2.1 が復旧経路として挙げているが、
   実装も本番呼び出し元も無い。checkpoint だけが動いている
3. **`mimi` の `normal`/`anon` モードを残すか。** サーバーとしては動いているが client からの呼び出し経路が無い
4. **`client/` と `server/` を同じリポジトリに置き続けるか。** 別リポジトリに分ける選択肢もある

## 6. リスク

- ほぼ全ファイルが動くため、**他のどの作業とも同時に実行できない**
- 移動中はコメント内のファイルパス参照が古くなる。このコードベースのコメントは
  「なぜこうなっているか」を記録した最大の資産なので、**パスの機械的な置換も含めて追従させること**
- `src.bak/` を移植元として引用しているコメントが多数ある。そちらのパスは変えないこと
