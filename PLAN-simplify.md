# biset コードベース簡素化計画（全体版）

> 作成: 2026-09-04。既存 `PLAN-SIMPIFY.md`（2026-09-03、MIMI Vault sync 局所計画。A・B完了、C・D未着手）の上位版。
> 対象: `~/biset` commit `51e0cfc` 時点の `src/`（315 tracked .ts / 44,751行）、`test/`（12,799行）、リポジトリ運用。
> 方針: 「バグを塞ぐ if を足す」前に、if を足したくなる構造そのものを減らす。各パッケージは独立にmerge可能・独立に検証可能。

## 0. 現状の数値（診断の根拠）

| 指標 | 値 | 意味 |
|---|---|---|
| `src/**/*.ts` | 325ファイル / 44,751行 | うち `src/mls/vendor/` = RFC9420 fork（対象外） |
| `main.ts` | 2,022行、import 73本、`bootClient()` 1本が1,400行 | アプリ配線が単一関数に集中 |
| knip unused files | 9 | `state.ts`/`route.ts`/`types.ts`/`context.ts` など旧UI骨組みの残骸 |
| knip unused exports | 433 | 内部実装が全部 public、依存グラフが読めない |
| knip unused deps | 5（`jmap-jam`, `cborg`, `hash-wasm`, `@scure/bip32`, `bittorrent-dht`） | 廃止済み設計の残り物 |
| git 管理外のテスト | **25ファイル** | `.gitignore` の `test/*` + allow-list 方式。新規テストは明示追加しない限り消える |
| `src/vault/` | 47ファイル / 5,646行 | うち credential 4系統 × (record/reader/sink) = 12ファイルがほぼ同型 |
| `src/ui/account-page.ts` | 1,041行 | modal・menu・card・config画面が1ファイル |

## 1. 診断：複雑さの4つの源

### 1.1 死んだ設計が物理的に残る（Coordinator パターンの再発）
`src/core/` は撤去済みだが、`coreBaseUrl` を読む分岐、`CoreIngressTransport` / `CoreVaultDeliveryTransport` / `core-restore-control-transport.ts`、`syncMailIngress` の core 経路は `main.ts` と `restore-workflow.ts` に生きたまま残り、「本番configが指さないので falsy」という理由だけで無害化されている。同じ形の残骸が `state.ts`/`route.ts`/`types.ts`/`context.ts`（旧UI）、`protocol/mls-ds-wire.ts`（撤去済みMLS DS）、未使用依存5つにも存在する。**読む人（と次のバグ調査）はこれらを「生きているかもしれない経路」として毎回検討させられる。**

### 1.2 アプリ配線が `bootClient()` 1関数に集中
`bootClient()` は識別子復元・DB掃除・did:webvh move追従・MLS/Vault 修復・DIDComm有効化・mediator poll登録・MIMI Vault同期・UIハンドラ（`sendReply`/`sendDidCommChat`/`sendDidCommGroupMessage`/`createAndSendDidCommGroup`/`logout`/`moveIdentity`/`removeVaultDevice`…）を全部この1スコープのクロージャとして定義する。結果:
- 依存はクロージャ変数（`identity` は `let`）で暗黙に共有され、初期化順が正しさの一部になっている（コメントで「ここより前でないと壊れる」を守っている箇所が複数）
- 単体テストできる単位がない。回帰テストは常に下位モジュール側にしか書けず、**「配線ミス」由来のバグは実機でしか見つからない**（今日までの障害の多くがこの型）
- Wallet アカウント経路（`configureWalletAccountIfPresent`、152–600行）が同じ配線をもう一組、別実装で持っている＝二重配線

### 1.3 同型コードの手コピー（memory: unify common logic 違反）
`vault/` の credential 4系統（contact-key / didcomm-credential / didcomm-device-key / openpgp-credential）は、それぞれ `*-reader.ts`（イベント走査→署名検証→segment key解決→復号）と `*-sink.ts`（active segment確認→record生成→署名→commit）を持ち、差分はイベント種別名と record 型だけ。片方だけ直したバグが他3つに残る構造。

### 1.4 client / server の境界が物理的にない
ブラウザバンドル（`main.ts`）が `src/mimi/`（MIMI **サーバー**実装のディレクトリ）から直接 import している（`src/mls/mimi-*.ts`、`src/vault/mimi-vault-sync.ts` 経由）。tsconfig 5本で型検査は分けているが、ディレクトリ構造上は client・server・shared wire が同居しており、「これはブラウザで動くのか、Bunで動くのか」がファイル位置から判断できない。

### 1.5 （運用）テストがgitに入らない
`.gitignore` の `test/*` + 個別 allow-list により、**25個のテストがローカルにしか存在しない**。`bun run test` は179ファイル通ると報告するが、他マシン・CI・エージェントworktreeでは同じ保証が得られない。回帰テストを書く運用（PLAN-SIMPIFY §3のガードレール）が、リポジトリ側で無効化されている。

---

## 2. 作業パッケージ

各パッケージは **独立ブランチ・独立merge**。完了条件は共通で:
`bun run typecheck` / `bun run test` / `bun run build`（`bun build` 単体は不可、inline.mjs まで走らせる）が全通過し、`dist/index.html` を **file:// で開いて** 起動・アカウント表示・受信箱表示を目視確認（localhost dev サーバー厳禁）。

### S1. ✅ 完了（2026-09-04, commit `6843551`）死んだ経路の物理削除
**実績**: 11ファイル / 約1,050行削除、依存6本除去（knip unused deps 5+1 → **0**、unresolved imports 4 → **0**）。
作業中に、死んでいたのではなく**壊れていた**コードが2件見つかり修正済み:
- `main.ts` の `flushReplicationOutbox` が `new URL(path, '')` で**呼ばれるたび例外を投げていた**（非MIMI環境）
- `bootstrap.ts` が routing.json に `'' + '/v1/didcomm/ingress'` という**相対＝配送不能なURI**をfallback service entryとして公開していた

**残した判断**: `src/protocol/{ingress,restore-control,vault-delivery}-wire.ts` は core transport 消滅で無参照になったが、
ingress/restore/vault-delivery という**現存機能の wire 定義**なので削除は機能判断とみなし保留。
`src/mls/vendor/` の2ファイルは fork の upstream diff 可視性を優先して保持。

**別途記録すべき発見**: `restore-workflow.ts` は core に依存していなかった（型のみの構造的参照）。
ただし **restore 機能には transport 実装も本番呼び出し元も存在せず、テストだけが動かしている**。
これは S1 が壊したものではなく元からの状態。→ §6 の未解決issueへ。

<details><summary>当初の作業項目</summary>
- `coreBaseUrl` 経路の全廃: `ui/config.ts` の項目、`main.ts` の `syncMailIngress` core分岐（1455–1480付近）と `flushReplicationOutbox` の `CoreVaultDeliveryTransport`、`identity/bootstrap.ts:871` の `didCommEndpoint` 生成、`vault/core-{ingress,delivery,restore-control}-transport.ts`、`test/core-ingress-transport.test.ts`
  - **注意**: `restore-workflow.ts` が core transport を参照している。単純削除ではなく「core 抜きで restore が成立するか」を先に確認し、成立しないなら S1 から外して別issue化する（勝手に機能を消さない）
- knip unused files 9本の削除（`src/context.ts` `src/route.ts` `src/state.ts` `src/types.ts` `src/mediator/identity.ts` `src/protocol/mls-ds-wire.ts` `src/protocol/transport.ts` `src/mls/vendor/codec/json.ts` `src/mls/vendor/customCredential.ts`）。vendor 配下2本は fork 由来なので、upstream diff の見通しを優先して**残す判断も可**（判断理由をコミットメッセージに書く）
- 未使用依存の削除: `jmap-jam` `cborg` `hash-wasm` `@scure/bip32` `bittorrent-dht` `@types/wicg-file-system-access`
  - `bittorrent-dht` は廃止済み Pkarr/did:dht 時代の残り。`scripts/pkarr-smoke.mjs`（unresolved import 4本、`src/did/` は存在しない）も同時に削除
- ~~`src.bak/**/*.ts` の削除~~ → **撤回（2026-09-04）**。`src/` 内に **53件のコメントが33個の `src.bak/*.ts` を移植元として引用**しており、`src.bak` は gitignore 対象＝削除は復元不能。参照価値が実在するため残す。

</details>

### S2. ✅ 完了（2026-09-04, commit `a09e589`）テストをgit管理に戻す
**実績**: `.gitignore` の `test/*` + 30行 allow-list ブロックを撤廃、**37ファイルを新規 tracked 化**
（36テスト + `test/vectors/rfc9420-crypto-basics.json`）。`PLAN*` と `docs/` の ignore は未変更。

<details><summary>当初の作業項目</summary>
`.gitignore` の `test/*` allow-list 方式を撤廃し、`test/**` を素直に tracked にする。除外は `test/**/*.bak` `.DS_Store` のみ。現在ignoreされている25ファイルを `git add` する。
- `PLAN*` と `docs/` の ignore も見直す（本計画・ARC.md 系は共有価値がある。判断はユーザーに確認する）
- これが無いと以降のパッケージの「回帰テストを残す」が機能しない。**S3以降より先に入れる**

</details>

### S3. Vault commit の一本化（中リスク・S1後・効果最大）
**S9の調査結果（§2末尾）により当初案から範囲を拡大。** 「Vault mutation を commit 可能な record に組み立てる」処理が **9箇所** に手コピーされている:
`mail/ingress-projector.ts:85` / `didcomm/ingress-projector.ts:198` / `didcomm/group-chat.ts:187` /
`local-jmap/vault-mutation-sink.ts:119,196` / `vault/{contact-key,didcomm-credential,didcomm-device-key,openpgp-credential}-sink.ts`

どれも同じ手順を踏む: `activeSegment()` → `assertActiveVaultSegment` → record build → `currentSnapshot()` →
projection（reduce する系としない系がある）→ `encodeVaultDeliveryPack` → `sha256Bytes` → `deliveryOutbox` 組み立て → commit。
**片方だけ直したバグが他8箇所に残る構造。** 段階的に統合する:

- **段階1 ✅完了（2026-09-04, commit `8cfd5a3`）**: credential 4系統の reader/sink を generic 化
  - `VaultCredentialKind<T>` 記述子: `{ eventKind, label, assert, build, createdAtOf, copy, eventSource }`
  - `VaultCredentialReader<T>` / `VaultCredentialSink<T>` の2クラス + `selectUnsuperseded()` ヘルパ
  - 差分は eventKind 文字列・assert/build 関数・エラー語のみ（調査済み。`didcomm-device-key` だけ events source が
    `VaultRecordReader.readVaultEvents`、他3つは `VaultCredentialEventReader.readCredentialEvents`）
  - supersede 選択は `contact-key.currentFor` と `didcomm-credential.readCurrent` が同一ロジック → 1本に
  - 秘密のディープコピー（`slice()`）はフィールドが系統ごとに違うので記述子の `copy(record)` に持たせる
  - 既存クラス名・シグネチャは薄いラッパで維持 → `main.ts` 無改変。既存テストは1本も消さない
  - **実績**: `src/vault/credential-store.ts`（202行）新設、reader/sink 8ファイルが 548行 → 262行。
    純減は26行にとどまった（クラス名・シグネチャ維持のためラッパ8本が残るため）が、**目的は達成**:
    走査/署名検証/segmentKey解決ループ ×4 → 1、active-segment→build→delivery pack→commit ×4 → 1、supersede選択 **×3** → 1
    （調査時に見落としていた `OpenPgpCredentialReader.readCurrent` も同一ロジックだった）。呼び出し側は1行も変更なし。
  - 記述子は型引数 `E` で events source の差（`VaultCredentialEventReader` ×3 / `VaultRecordReader` ×1）を吸収。
    `label`（エラー文言用）と `segmentLabel`（`assertActiveVaultSegment` 用）を分けているのは、device-key だけ
    既存の文言が "DIDComm device-key" / "DIDComm device key" で食い違っていたため（文言は1文字も変えていない）
- **段階2 ✅完了（2026-09-05, commit `09c98bf`）**: `buildVaultCommit()` を1本用意し、残る5箇所（2つの ingress-projector、group-chat、vault-mutation-sink ×2）を寄せる。
  projection の reduce/passthrough 差は `reduce?: DecryptedMutationRecord[]` の1パラメータで吸収できた。
  - **実績**: `src/vault/commit.ts`（86行）新設。6箇所すべて（指示の5箇所＋段階1の `VaultCredentialSink`）を集約し、
    **`encodeVaultDeliveryPack` を呼ぶ本番コードはリポジトリ内で1箇所だけ**になった。呼び出し箇所は -146/+61。
  - `activeSegment()` / segment検証 / record build は意図的に呼び出し側に残した（入力が全く別物で、
    取り込むと純粋な構造変更でなくなるため）
  - **この統合で実バグが1件見つかった → 別コミット `8df862c` で修正済み**（下記 S11）

### S11. ✅ 完了（2026-09-05, commit `8df862c`）JMAP書き込み経路の segment 検証漏れ
S3段階2 の統合中に発見。**簡素化そのものではなくバグ修正**だが、本計画の目的（バグを根本から潰す）に直結するため実施した。

`assertActiveVaultSegment()` は4条件を検査する（`segmentId` が空でない / `segmentKey` が32バイト /
keyWrap が1つ以上ある / wrap の identity・segment が一致）。他の全 commit 経路はこれを呼んでいたが、
**`local-jmap/vault-mutation-sink.ts` だけが後ろ2条件を手書きコピーしており**（同一ファイル内に2回）、
**空の `segmentId` と32バイトでない `SegmentKey` を素通しして、その鍵で暗号化していた**。
アプリで最も使われる書き込み経路（ローカルJMAP write）である。

修正: 2箇所を `assertActiveVaultSegment(identityId, segment, 'mutation')` に置換（手書きコピーも同時に消滅）。
回帰テスト `test/vault-mutation-sink-segment.test.ts`（4件）を追加し、**修正前のコードに対して 4/4 fail、
修正後に 4/4 pass することを実際に確認した**。
> 教訓: 最初に書いたテストは `toThrow(TypeError)` だったが、検証を通過した segment も後段の別処理で
> TypeError を投げるため、**修正前のコードでも通ってしまった**。検証メッセージで判定する形に直して初めて
> 回帰テストとして機能した。「テストが通った」ではなく「**修正前に落ちること**を確認する」まで含めて1つの作業。

### S4. `bootClient()` の分解（高リスク・S1/S2後・単独で進める）
1,400行の単一スコープを、明示的な依存を持つ配線関数へ分割する。**振る舞いは変えない、純粋な構造変更**。
- 段階1: クロージャ群を `AppWiring` 相当の1オブジェクト（`identity` の可変性を含む状態を明示的に保持）へ移し、`sendReply` などのハンドラを `src/app/handlers/*.ts` としてトップレベル関数化（引数で依存を受ける）
- 段階2: boot の各フェーズ（`restoreIdentities` → `adoptMoves` → `repairVaultCrypto` → `ensureMimiVault` → `enableDidComm` → `registerPolls` → `mountUi`）を、**順序が型または戻り値の受け渡しで強制される**形に分ける。現在コメントで守っている順序制約を、コンパイラが守る形に移すのがこのパッケージの本質
- 段階3: Wallet 経路（`configureWalletAccountIfPresent`）が同じフェーズ関数を再利用できるかを評価し、二重配線を減らす。できない部分は「なぜ別なのか」をコード内に1箇所だけ記述する
- 各段階で個別にmerge可能。**段階を跨いで一気にやらない**

### S5. client / server のディレクトリ分離（中リスク・S1後）
`src/` 直下を役割で分ける:
- `src/client/`（ブラウザ）… `main.ts` `ui/` `local-jmap/` `vault/` `mail/` `didcomm/`(client部) `mls/`(client部) `identity/` `oid4vp/` `oidc/` `wallet/`
- `src/server/`（Bun）… `anchor/` `mediator/` `mimi/`
- `src/shared/` … `protocol/`（wire schema・canonical・ids・署名対象）
そのうえで **client が `src/server/mimi/` を import している箇所**（`mls/mimi-client-transport.ts` `mls/mimi-vault-*.ts` `vault/mimi-vault-sync.ts`）を洗い出し、共有すべき型・エンコーダだけを `shared/mimi-wire.ts` に切り出す。tsconfig 5本の include も同時に整理し、**「型検査の分離」と「ディレクトリの分離」を一致させる**。
- 大量のimport書き換えを伴う。S3/S4 と同時に走らせない（コンフリクト地獄）

### S6. `ui/account-page.ts`（1,041行）の分割（低リスク・独立）
modal基盤（`openModal`/`openDropdownMenu`）・identity menu・vault card・wallet card・config画面 の5つに分ける。HTML/CSSは `src.bak` verbatim 方針を維持し、**構造だけ**動かす。

### S7. ✅ 完了（2026-09-05, commit `56f2f3e`）未使用 export の内部化
公開の必要がない export を落とし、モジュール境界を実際の依存に一致させる。`src/mls/vendor/` は対象外（upstream fork）。

**実績**: 対象範囲の unused export **130 → 10**（全体は 644 → 522。差分の大半は触っていない vendor の486件）。
内部化114件 / 削除14件 / 「実は使われていたので戻した」8件。51ファイル、+106/−413。
削除したのは `protocol/mls-ds.ts` 全体（156行、退役 MLS DS の wire 型）と `protocol/signing.ts` の
`mls*SigningBytes` 12関数（279→131行）——いずれも `src/` `test/` `scripts/` から呼び出し0。

**戻した8件が示したこと**: `protocol/{ingress,restore-control,vault-delivery}-wire.ts` の3ファイルは
**どこからも import されていないのに**、`validate.ts` の assert 7本と `vault.ts` の型を「使われている」状態に
保っていた。**デッドファイルによる偽の生存**。S1 でこの3ファイルを「現存機能の wire 定義だから」と残した判断は、
この事実を踏まえて見直す余地がある（§5-8）。

### S12. ✅ 完了（2026-09-05, commits `d7761fe` `d9ddf8b`）テストが守っていないコードの発見
S7 の残りを片付ける途中で、**より深刻な問題**が見つかった。

`src/utils.ts`（137行）は `ui/format.ts` と**同じ7関数のコピー**を持ち、本番は `ui/format.ts` だけを使う
（`left-pane.ts` / `thread.ts` が import）。ところが `test/preview-normalisation.test.ts` は
**死んでいる方（utils.ts）をテストしていた**。しかもそのテストが防ごうとしていたバグは
「一覧とスレッドでプレビューの読み方が食い違う」——**まさにこの重複そのものが原因**の障害である。
本番の `ui/format.ts` が同じ形で壊れても、このテストは通り続ける状態だった。
加えて `bun:test` の API を使わず自前の `console.log` ハーネスで書かれていたため、
`bun run test` には「Ran 0 tests」と報告されており、失敗しても集計に出なかった。

**対応**: テストを `ui/format.ts` に向け直し bun:test API へ移植（0件 → 7件が集計対象に）、
本番から到達不能な `src/utils.ts` を削除。

**そして同種の問題を全数チェックする仕組みを入れた**（`scripts/reachability.mjs`、`bun run reachability`、
`bun run check` にも組み込み済み）。knip はテストが import したファイルを「used」と見なすため、この層を検出できない。

| 指標 | 値 |
|---|---|
| 本番6エントリから到達可能な src モジュール | **206 / 315** |
| **テストからしか到達されないモジュール** | **23** |
| 何からも到達されない（vendor除く） | 3（上記の wire 3ファイル） |

**23件の内訳**（すべてが欠陥ではない。多くは配線前の「部品」で、ARC.md も「部品実装済み」と分類している）:
- Wallet ログイン系（`oid4vp/wallet.ts` `oidc/client.ts` `oid4vp/file-bridge.ts`）— **今まさに WIP で配線中**
- OpenPGP メール（`mail/openpgp-message.ts` `rfc3156.ts`）— ARC.md がスコープ外と明記
- core撤去で経路が消えた層（`vault/restore-workflow.ts` `delivery-sync.ts` `ingress-sync.ts` `delivery-outbox.ts`）
- biset-mimi の anon モード（`mimi/anon/*` `room-policy.ts`）— client からの呼び出し経路なし
- その他（`local-jmap/accounts.ts` `remote.ts` `mls/mimi-room-migration.ts` ほか）

**23件の分類**（`bun run reachability` で再取得できる。「テストが通る」は「本番で動く」を意味しない）:

| 分類 | ファイル | 判断 |
|---|---|---|
| **未完成機能（部品はあるが配線が無い）** | `vault/restore-workflow.ts` `restore-transfer*.ts`<br>`vault/recovery-archive-{file,import}.ts` | §5-1。**復旧経路2本が動いていない** |
| | `mail/openpgp-message.ts` `mail/rfc3156.ts` `mail/ingress-workflow.ts` | ARC.md §2.2 がスコープ外と明記 |
| | `local-jmap/accounts.ts` `local-jmap/remote.ts` | リモートJMAPアカウント |
| | `oid4vp/wallet.ts` `oid4vp/file-bridge.ts` `oidc/client.ts` | Anchor OIDC ログイン。<br>did.md Wallet（`src/wallet/`）とは**別実装**で、そちらは配線済み |
| **旧アーキ由来（core撤去で経路が消滅）** | `vault/delivery-outbox.ts` `delivery-sync.ts` `ingress-sync.ts` | §5-8 の wire 3ファイルと同根 |
| **サーバ側の未使用モード** | `mimi/anon/{identity-link,pseudonym}.ts` `mimi/room-policy.ts` | client からの呼び出し経路が無い（ARC.md §3 記載） |
| **将来機能の下ごしらえ** | `mls/keypackage-store.ts` | 現行 Self Vault は external join を使い KeyPackage を要さない |
| | `mls/mimi-client-routing.ts` `mls/mimi-room-migration.ts` | anon room への移行機構 |
| **テスト専用で正常** | `protocol/test-vectors.ts`<br>`mls/vendor/crypto/{kdf,signature}.ts` | ベクタ定義と vendored fork。問題なし |

→ **コードベースが複雑に見える理由の一つがこれ**: 動いているコードと、まだ動いていない部品が、
同じディレクトリに区別なく同居している。読む人は毎回「これは生きているのか」を自分で判定させられる。

### S8. 端末/鍵管理の統合（調査完了・実装は保留）
旧 PLAN-SIMPIFY の C。**2026-09-05 の調査で、前提が一部誤っていたことが判明した。**

現状の正確な地図:
| 操作 | 実装 | 状態 |
|---|---|---|
| 端末の追加 | `createMimiVaultRoom` / `joinMimiVaultRoom`（`mls/mimi-vault-room.ts`） | ✅稼働 |
| 端末の削除 | `removeMimiVaultDevice` → `main.ts` の `removeVaultDevice` | ✅稼働（MIMI版は実装済み） |
| did:webvh の Sign/Spare 鍵ローテーション | `identity/webvh/prerotation.ts` + config画面 | ✅稼働 |
| **MLS group generation rotation** | 旧 `rotateSelfGroupGeneration`（Coordinator専用） | ❌ **MIMI版が無い** |

つまり「Spare Key rotation が消えた」は不正確で、**消えたのは MLS self-group の世代ローテーション**（デバイス鍵の世代交代）である。
did:webvh 側の鍵ローテーション（pre-rotation による Spare→Sign 昇格）は生きている。

→ **残る欠落は1つだけ**であり、しかもそれは「簡素化」ではなく**機能の再実装**。
本計画のスコープからは外し、独立した設計課題として §5 に記録する。統合APIの新設は、その機能が戻ってから考えればよい。

### S10. ✅ 完了（2026-09-05, commit `654bffc`）撤退済みサブシステム向けの「罠」の除去
S8 調査中に発見した、S1（死んだ**ファイル**の削除）では取り切れない残骸のクラス。
**削除済みサブシステムのためだけに存在する引数・分岐・デフォルト値**が、生きたコードの中に残っている。

実例（発見済み）:
```ts
// src/mls/group.ts:229
export async function removeMembers(state, kids, wireAsPublicMessage = false)
```
デフォルトの `false` は「他の呼び出し元（self-group.ts / conversation-group.ts）」向けだが、**その2つは削除済み**。
唯一残った呼び出し元 `mimi-vault-room.ts:216` は常に `true` を渡す。しかも `false` のまま呼ぶと
MIMIハブが「room-state update must be a complete MLS PublicMessage」で 400 を返す——
**間違った値がデフォルトとして残っている**。次に誰かがこの関数を素直に呼べば踏む罠。

作業内容:
1. 削除済みサブシステム（Coordinator / self-group / conversation-group / mls-ds / mimi-content / core）に言及する
   **103箇所**を機械的に走査し、次の3つに分類する:
   - (a) **コード上の罠** — 死んだ呼び出し元のために残る引数・デフォルト値・分岐 → **修正する**
   - (b) **価値ある設計記録** — 「なぜこうなっているか」の履歴を説明するコメント → **残す**
   - (c) **単なる幽霊参照** — 存在しないファイルを指すだけのコメント → **書き換える**
2. (a) は「唯一の実呼び出し元に合わせて固定する」のが原則。オプションを消せるなら消す。
3. **分類結果を先に報告し、(a) の修正だけを行う。** (b)(c) の大量書き換えは別作業。

これは S1 の続きだが、S1 より慎重さが要る（ファイル削除と違い、生きたコードの振る舞いに触れるため）。

**分類結果（106箇所）**: (a) コード上の罠 **1件** / (b) 価値ある設計記録 74件 / (c) 幽霊参照・命名の残骸 31件。
→ **恐れていたほど罠は無かった**。撤去作業自体は概ね丁寧に行われており、残っていたのは主にコメントだった。

**修正した唯一の (a)**: `removeMembers` のデフォルト引数を**削除して必須引数化**した。
デフォルトを `true` に変える案は退けた——既存テスト5本が引数なしで呼び、private-wire framing を意図的に検証しているため、
`true` にすると**テストが黙って別のものを検証し始める＝別の罠を作るだけ**になる。
必須化なら振る舞いは1ビットも変わらず、罠だけが構造的に消える。
回帰テスト2本（`true` → `mls_public_message` / `false` → `mls_private_message` を wire バイト列で固定）を追加。

**(a) から外し、引き継いだもの**:
- `vault/vault-checkpoint.ts` の v1 envelope 復号分岐と `deriveCoordinatorRecoveryKek` —
  退役 Coordinator が書いた**既存の永続データ**を読む互換パス。消すのは機能判断なのでスコープ外
- `protocol/mls-ds.ts` + `signing.ts` の signing-bytes 関数群 — 呼び出し元0の完全な dead export → **S7へ**
- `identity/record-store.ts` の `deviceSignaturePrivateKey?` optional —
  今日の MIMI-only デバイスでは常に必要。required 化は筋が通るが参照が WIP の `bootstrap.ts` に集中 → **WIP解消後**
- (c) の大半は **`coordinatorUrl` という名前の残骸**（中身は MIMI Self Vault の URL で振る舞いは正しい）。
  改名は `main.ts` / `account-page.ts` を跨ぐため WIP解消後

### S9. ✅ 調査完了（2026-09-04）— 結論は S3 に合流済み
旧 PLAN-SIMPIFY §D の「DIDComm group chat と MIMI Vault が別々の chunk 機構・別々の retry 設計で同じ問題を解いている」という推測は **誤りだった**。

- **DIDComm group chat に chunk 機構は存在しない**。`group-chat.ts` は pairwise fan-out で、1メッセージ = N個の独立した DIDComm 送信。分割も再組立もしない（サイズ上限は mediator 側の関心事）
- **MIMI Vault の chunk**（`vault/mimi-vault-chunks.ts`）は checkpoint payload 専用。500KiB分割 + manifest + payloadHash 検証で、group chat とは問題そのものが違う
- 統合すべき共通部分は chunk/retry ではなく **Vault commit record の組み立て**だった。`group-chat.ts:187` の
  `buildDidCommGroupMessageVaultRecord` は、credential sink 4本・2つの ingress-projector・vault-mutation-sink と
  同じ9箇所コピーの一員である

→ **S9 として独立した作業は不要。S3 段階2 に吸収した。**

---

## 3. 実行順序

```
S9 (調査) ✅完了 → S3 に合流

S1 (死んだ経路削除) ─┐
S2 (テストをgitへ)  ─┴→ S3段階1 (credential generic化) → S3段階2 (buildVaultCommit) ─┐
                       S6 (account-page分割) ─────────────────────────────────────┼→ S4 (bootClient分解) → S8 (端末/鍵統合)
                       S7 (export内部化)   ─────────────────────────────────────┘
                                                                                  S5 (client/server分離) ※S3/S4と排他
```
- 並列可: S1・S2（別ファイル群）、S6・S7（S1後、互いに別ファイル）
- 排他: S4 と S5 は同時に走らせない。S3 と S5 も同時不可
- **同一worktree・同一ブランチで作業するため、複数エージェントの同時実行はファイル集合が完全に分離している場合に限る**

## 3.5 今日（2026-09-04）の実行可能範囲 — WIPによる制約

未コミットの wallet WIP が以下のファイルに乗っている:
`src/main.ts` `src/identity/bootstrap.ts` `src/ui/{account-page,account-create,shell}.ts` `src/index.html`
`src/mls/mimi-vault-room.ts` `src/wallet/`（未追跡）`deploy.sh` `PLAN.md` `dist/*`

これらに触るパッケージは**他人の進行中作業を壊すため実行しない**:

| | 状態 | 理由 |
|---|---|---|
| S1 / S2 | ✅完了 | — |
| **S3段階1**（credential generic化） | ✅完了 | 対象 `src/vault/**` は全て clean |
| **S3段階2**（buildVaultCommit） | ✅完了 | 対象4ファイル（mail/ingress-projector, didcomm/ingress-projector, didcomm/group-chat, local-jmap/vault-mutation-sink）は全て clean |

| S4（bootClient分解） | 🔴保留 | `main.ts` に WIP |
| S6（account-page分割） | 🔴保留 | `account-page.ts` に WIP |
| S5（client/server分離） | 🔴保留 | 全ファイル移動、WIPと全面衝突 |
| S8（端末/鍵統合） | ✅調査完了 | 欠落は1つだけと判明。実装は機能追加のためスコープ外 |
| **S11**（segment検証漏れ修正） | ✅完了 | S3段階2 が掘り当てた実バグ |
| **S10**（撤退済みサブシステムの罠除去） | ✅完了 | 罠は1件のみだった |
| **S7**（unused export内部化） | ✅完了 | 対象範囲 130 → 10 |
| **S12**（到達可能性チェック） | ✅完了 | テストが守っていないコードを発見・仕組み化 |

→ **WIP がコミットまたは stash されるまで、S4 / S5 / S6 は着手できない。**

## 3.6 方針変更: native login 廃止（2026-09-05、ユーザー指示）

**biset 自前のログイン（BIP39 seed から identity を作り、Anchor が OIDC provider として認証する方式）を廃止し、
外部の did IdP（現状 did.md）ログインに一本化する。native login 関連コードは全削除。**

これは簡素化計画にとって**追い風**である——§1.2 で指摘した「Wallet 経路が同じ配線をもう一組、別実装で持っている＝二重配線」が、
片方を消すことで根本的に解消する。S4（bootClient 分解）はこの削除の**後**にやる方が、対象が半分になる。

### ⚠️ 調査結果: 今すぐ削除すると**アプリが機能しなくなる**（2026-09-05）

削除前提で seed 経路と wallet 経路の機能を1つずつ突き合わせた結果、**wallet 経路は seed 経路と同等ではない**。
最も重大なのは:

> **wallet アカウント同士では関係（relationship）を一度も確立できない。**
> `sendWalletMessage`（`main.ts:552-559`）は contact が無ければ相手の公開 kid へ直接 basicmessage を投げるだけで
> `RELATIONSHIP_INIT` を送らず、`RELATIONSHIP_ACCEPT` のハンドラも無い（`main.ts:454` で早期 return）。
> **双方が responder** であり、今は「相手が seed アカウントなら向こうから INIT が来る」ことで成立している。
> native を消せば全員が wallet になり、**誰とも関係を確立できなくなる**。

#### wallet 経路に無い機能

| 機能 | 状態 | 分類 |
|---|---|---|
| **自分から関係を開始（`RELATIONSHIP_INIT` 送信 / `ACCEPT` 処理）** | ❌ | **再実装必須・最優先** |
| **メール送信（SMTP submission）** | ❌ | **再実装必須・設計課題あり**（下記） |
| **メール受信（`MailIngressProjector` / mail-bridge 分岐）** | ❌ | 再実装必須 |
| **DIDComm グループチャット（作成・招待・送受信）** | ❌ | 再実装必須 |
| **DIDComm 送信 outbox と再送ループ** | ❌ | 再実装必須（送信失敗が即座に失われる） |
| **OpenPGP メール鍵の有効化** | ❌ | 再実装必須 |
| **MIMI checkpoint の作成・復元** | ❌ | 再設計必須（下記） |
| **local JMAP gateway 経由の送信** | ❌ sink 直叩きで迂回 | 統合対象 |
| 表示名変更 / ドメイン移転 / 鍵ローテ / Root Key phrase 表示 | ❌ | **不要**（did.md 側の責務。N3 の想定通り） |

**メールの設計課題**: `buildMailSubmitter` は `record.signPrivateKey` で署名し、`mailFromForIdentity`
（`identity/webvh/identifier.ts:88-93`）は identity の DID ドメインが biset の apexDomain のサブドメインであることを
要求する。**did.md がホストする DID は apex 配下ではないため、wallet アカウントは現状メールアドレスを持ちようがない。**
送信署名鍵とアドレス採番の両方を設計しなおす必要がある。

**checkpoint の設計課題**: 現状 `masterSeed` 派生 KEK が前提（`vault/vault-checkpoint.ts:20-23`）。
checkpoint が無いと「新デバイスが join 前の履歴を復元できない」（これは MLS forward secrecy 上の意図的な仕様）
だけでなく、**MIMI provider 側の delivery ログに圧縮点が作られず無限に伸びる**。
`did-md-oauth.ts:382-385` が `vaultSecret` として32バイトを生成・封印しているが**どこからも使われておらず**、
checkpoint KEK の置き場として用意された跡に見える（要確認）。

#### `masterSeed` 依存の実態
調査の結果、**本当に困るのは checkpoint の作成・復元だけ**だった。
`buildLocalJmapReadModel` / `buildVaultDeliveryProjector` の `masterSeed` は optional 引数で、
wallet は MLS epoch wrap のみで動作する。それ以外は削除対象か、wallet 側に等価物がある。

### wallet 経路で見つかった実バグ（native 削除後に残る側）→ ✅ 修正済み（`4a5554d` `0371a48`）

3件とも「修正前のコードに対して回帰テストが落ちること」を実際に確認したうえで修正した。
さらに調査で**seed 経路も同じ poison message の罠を1 type 分だけ抱えている**ことが判明——
既知の4 type は分岐するが、それ以外は同じ projector に落ちる。今日の既知 type はすべて処理されるので
現時点では到達不能だが、**新しいメッセージ type が1つ増えた瞬間に再現する**。同じガードを入れた。
両経路と projector が1つの allow-list（`isProjectableDidCommIngress`）を共有する形にしたので、
ガードと projector の実際の挙動がずれることはなくなった。

25秒タイムアウトも `withVaultSyncTimeout` に一本化した。**どちらの経路もタイマーを clear していなかった**——
1秒で終わったラウンドも25秒間タイマーを保持し、ポーリング間隔の方が短いため蓄積する。

以下は修正前の記録:

1. **グループ招待が poison message になる**。`handleWalletDidCommMessage`（`main.ts:490`）は type 分岐なしで
   すべて `DidCommIngressProjector` に渡すが、同 projector は ping/basicmessage/relationship 以外を throw する。
   `mediator-watch.ts:111-114` は throw 時に **ACK せずキューに残す**。
   → 1通届くと再接続のたびに同じメッセージで失敗し続ける
2. **wallet の MIMI sync にタイムアウトが無い**。seed 側は `main.ts:1739-1747` で25秒レースを張り、
   コメントが「無いと `mimiPollBusy` が永久に true で固まる」と**実障害として**記録している。
   wallet 側の `syncBusy` に同じ保護が無い。**seed を消すとこの既知の障害モードだけが残る**
3. **relationship の mediator URL 比較が seed 側だけ生文字列**。wallet 側は `new URL().toString()` で正規化。
   統合時は **wallet 側の実装を残すのが正しい**

### 二重配線（同じ機能を両経路が別実装で持つ）
削除の**前に**統合すべきもの。両経路が同じコードを呼ぶ状態にしてから片方を消せば、削除時の diff は
「呼び出し元が1つ減る」だけになる。逆順だと wallet 側に残った実装の正しさを検証できない。

| 機能 | seed 側 | wallet 側 | 差分 |
|---|---|---|---|
| sender key 解決 | `resolveAnyDidCommSenderKey` | `resolveWalletSenderKey` | **完全同一** |
| DIDComm ingress envelope 生成 | `main.ts:1327-1344` | `main.ts:490-511` | `ingressId` の label 文字列だけ |
| contact key 起動時復元ループ | `main.ts:1509-1524` | `main.ts:526-536` | 実質同一 |
| relationship watch 登録 | `startRelationshipPoll` | `startWalletRelationshipWatch` | 実質同一 |
| relationship INIT 応答 | `handleRelationshipMessage` | `handleWalletRelationshipMessage` | URL比較のみ（wallet が正） |
| Vault カード status 更新 | `setVaultCard` | `setWalletVaultStatus` | 差分抑止の有無 |
| Vault crypto boundary | `buildVaultCryptoBoundary` | `buildWalletVaultCryptoBoundary` | `storageKek` の有無 |
| MIMI room bootstrap | `ensureMimiVaultRoom` | `ensureWalletMimiVaultRoom` | routing publish の有無 |
| MIMI sync ループ | `synchronizeMimi` | `synchronizeWalletVault` | checkpoint とタイムアウトの有無 |

### 実行順序（2026-09-05 のユーザー判断で改訂）

ユーザーの決定により順序が変わった: **「先に削除、機能は後追い」**。
機能が一時的に落ちることを許容し、既存ユーザーのデータはすべて破棄してよい。Anchor も丸ごと削除する。

| | 内容 | 状態 |
|---|---|---|
| **W1** | wallet 経路の実バグ3件を直す（残る側なので最優先） | ✅完了 `4a5554d` `0371a48` |
| **W2** | 二重配線の統合 | ✅完了 `d8ba82b` `a263d7b`（**seed 経路ごと消えるため以後は不要**） |
| **N2** | Anchor の OIDC / OpenID4VP とクライアント側の対 | ✅完了 `74864ff` |
| **N4** | **Anchor の残り全部**（did:webvh 公開文書ホスティング、build/deploy 配線） | ✅完了 `c26db16` |
| **N1** | クライアントの native login 削除（seed 由来の identity 生成・復元・鍵導出・UI） | ✅完了 `dd5a0cd` `71336b9` `7357830` |
| **W3** | wallet 経路の機能穴を埋める（①関係確立 INIT/ACCEPT ②送信 outbox ③checkpoint ④グループ ⑤mail） | **着手可** → `tasks/W3-wallet-feature-gaps.md` |

#### N1 の実績（2026-09-05）
**合計 −4,174行**、削除13ファイル。`src/main.ts` **1,876 → 742行**。
`dist/index.html` **1,219kb → 711kb（42%減）**。依存 `@scure/bip39` も除去。

実際に失われた機能（削除後のツリーに対する grep で確認済み。W3 の入力）:
- **自分から関係を開始できない** — `initiateRelationship` の本番呼び出し元がゼロ。
  `sendRelationshipAccept` は生きているので応答はできるが、**wallet 同士は永久に関係を確立できない**。最優先
- **メール一式** — 送信（`buildMailSubmitter`）、受信（`MailIngressProjector`、mail-bridge 分岐）、OpenPGP
- **DIDComm グループチャット** — 作成・招待・送受信
- **DIDComm 送信 outbox と再送** — 送信失敗が即座に失われる
- **`enableDidComm`** — identity 全体の X25519 provisioning、`#routing` 公開、mediator 登録。
  （wallet は Wallet 経由の独自 device enrollment を持つので DIDComm 通信自体は動く。消えたのは biset 側の provisioning）
- **MIMI checkpoint 作成・復元** — KEK が `masterSeed` 由来だったため
- **Local JMAP gateway / transport 層** — wallet は sink 直叩きで、JMAP を話す層が無い（`local-jmap/accounts.ts` `remote.ts` が到達不能）
- **masterSeed 由来の Vault storage KEK** — 全 segment wrap が MLS epoch 束縛のみになった

**削除しなかったもの（判断）**: `identity/webvh/create-genesis.ts` と `migrate.ts` は削除リストにあったが、
**残す側のコードのテスト3件が、実物の did:webvh log を組み立てる唯一の手段**として使っている。
消すと resolver のカバレッジごと消える。`identity/web/`（did:web mirror）も同じ理由で連鎖的に残った。

**「何からも到達されない」7件は全部残した**——`vault-checkpoint.ts` `didcomm-credential-{reader,sink}.ts`
`mail-submission-transport.ts` `webvh-routing-pointer.ts` `ui/account/modal.ts` `restore-control-wire.ts`。
どれも W3 が配線し直す部品か、別途判断が要るもの。**今消すと W3 が必要とするコードを失う**。
| **S5** | client / server / shared の分離 | 一部完了 `4f889a6`（protocol → shared）→ `tasks/S5-client-server-split.md` |

**削除そのものは簡単で、diff も大きい。難しいのは削除ではなく、消える機能を wallet 側に持たせることである。**
W3 の①（関係確立）が入るまで、**wallet アカウント同士は誰とも通信できない**——これが後追い実装の最優先事項。

#### 決定済みの設計方針（2026-09-05）
- **メール**: biset ではなく **mediator の問題**として扱う。did.md が専用 mediator を運用し、
  wallet ログイン時にユーザーがそこへ登録する。特定 mediator の使用許可を capability として付与する形を検討。
  → `mailFromForIdentity` の「DID ドメインが biset apex 配下」制約は将来外れる
- **checkpoint**: wallet の `vaultSecret`（`did-md-oauth.ts` が既に生成・封印しているが未使用）を KEK に使う
- **既存ユーザー**: 移行パス不要。すべて破棄してよい

## 4. やらないこと（明示）
- 機能の削除・仕様変更。S1 で「消えている機能」を見つけたら、消すのではなく**issueとして記録して残す**（core経由restoreが該当する可能性あり）
- HTML/CSS の書き換え・簡略化（`src.bak` verbatim 方針）
- `src/mls/vendor/`（RFC9420 fork）への手入れ
- 新しいメッセージング機構の追加
- 「ついでに直す」バグ修正。構造変更PRに混ぜない（混ぜると回帰の原因切り分けが不可能になる）

## 5. 未解決issue（簡素化の対象外・記録のみ）

8. **`shared/protocol/{ingress,restore-control,vault-delivery}-wire.ts` は何からも到達されない**（S7/S12で判明、2026-09-05に内訳確定）。
   `bun run knip` の "Unused files" と `reachability` の "reached by nothing" に出続けている3ファイル。
   **この6つの assert 関数（`assertIngressPull` `assertIngressAck` `assertRestoreCancel`
   `assertRestoreControlPull` `assertVaultDeliveryAck` `assertVaultDeliveryPull`）を呼んでいるのは
   この3ファイルだけ**であることを確認済み——他にゼロ。死んだファイルが `validate.ts` の export を
   生かして見せているだけの構図。
   内訳は同じではない:
   - `ingress-wire.ts` — 削除済み core の ingress pull API。後継は mediator queue。**掃除して差し支えない**
   - `vault-delivery-wire.ts` — 自身のコメントが「the bounded **core** HTTP API」と言っている。
     後継は MIMI Self Vault。**掃除して差し支えない**
   - `restore-control-wire.ts` — restore 機能のもの。**これは別件**。§5-1 の通り実装も呼び出し元も無いが、
     native login 廃止とは無関係の未完成機能であり、削除は独立した判断が要る
9. **未配線の部品23個を、動いているコードと物理的に分けるべきか**（S12で判明）。
   `src/staged/` のようなディレクトリへ移す、あるいは各ファイル先頭に統一マーカーを置くなど。
   移動は import 書き換えを伴い WIP と衝突するため、本計画では提案のみ。

1. **復旧経路が2つとも未配線**（S1で判明、S12の到達可能性チェックで全容確定）。
   ARC.md §2.1 は「復旧に必要な履歴を、biset-mimi Self Vault の checkpoint、信頼済み peer、または
   **利用者管理の暗号化 archive** から取得する」を設計原則に挙げているが、後ろ2つが動いていない:

   | 経路 | 状態 |
   |---|---|
   | biset-mimi Self Vault の checkpoint | ✅稼働（`main.ts` から実配線） |
   | 信頼済み peer からの restore | ❌ `restore-workflow.ts` / `restore-transfer*.ts` は存在するが、
     `RestoreControlTransport` の**実装クラスが `src/` `test/` のどこにも無く**、本番の呼び出し経路も無い |
   | 利用者管理の暗号化 archive | ❌ `recovery-archive-file.ts`（Blob 書き出し / File 読み込み）も
     `recovery-archive-import.ts` も**どこからも呼ばれていない**。
     `recovery-archive-export.ts` だけは到達可能だが、それは**MIMI checkpoint を作るため**に
     `createRecoveryArchiveSnapshot` が使われているだけで、ユーザー向けのバックアップ機能ではない |

   つまり **端末が1台になった時の復旧手段が、実質 Self Vault checkpoint 一本**である。
   部品はすべて実装され、テストも通っている——**配線だけが無い**。
   これは「死コードだから消す」案件ではなく「**未完成の機能**」であり、消すか完成させるかの判断が要る。
2. `CoreMailSubmissionTransport`（`vault/mail-submission-transport.ts`）は**生きている**（mediator の mail plugin に POST する）。
   `Core` prefix だけが legacy。改名候補。
3. `test/preview-normalisation.test.ts` は 0 テストしか実行していない。
4. `test/mimi/http.test.ts` と `test/mls/mimi-vault-room.test.ts` が `Cannot use a closed database` 等を
   ログしながら pass している（teardown race の疑い）。
6. 4つの `*BuildContext` 型（`ContactKeyBuildContext` 等）は構造が完全一致で `VaultCredentialBuildContext` と同型。
   record モジュールの公開 API なので段階1では統合を見送った。
7. `ContactKeyReader.currentFor` に元からある二重コピー（`forCounterparty` のコピー済み結果をさらにコピー）。無害。
5. **MLS self-group の世代ローテーション（旧 `rotateSelfGroupGeneration`）の MIMI 版が存在しない。**
   Coordinator 撤去の巻き添えで消えたまま。did:webvh の Sign/Spare 鍵ローテーション（`webvh/prerotation.ts`）は
   別物であり生きている（S8調査で確認）。これは簡素化ではなく**機能の再実装**なので本計画のスコープ外。
   独立した設計課題として要判断。

## 6. エージェント運用ルール
1. 1エージェント = 1パッケージ。範囲外のファイルに触れたら中断して報告する
2. 完了条件（§2冒頭の typecheck / test / build / file:// 目視）を満たさない限り「完了」と報告しない。落ちたテストは隠さず出力ごと報告する
3. 削除の前に必ず `grep` で参照を確認し、参照が残っているものは削除せず報告する
4. コミットは分割し、各コミットメッセージに「何を消したか」「なぜ安全と判断したか」を書く
5. 判断に迷ったら止まって聞く。勝手に設計判断をしない
