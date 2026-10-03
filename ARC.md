# Biset アーキテクチャ

> 調査基準日: 2026-10-03（Asia/Tokyo）
> 調査対象: `~/biset` の作業ツリー（2026-10-03 のコミット。HEAD `9e997fd` の次）。
>
> 2026-10-02 版を、DIDComm／Vault Sync の仕様準拠作業（P0・P1、P2 の一部）に合わせて書き直した。
> 変わった点は §1.4 にまとめた。方針は「現行コードを正とする」。将来案・廃止予定は、現行の事実と混ぜずに明示する。

## 0. 要約

- **Biset は、メールと DIDComm のデータを利用者の端末側（ブラウザの IndexedDB）に暗号化して保管する通信クライアント**である。
  サーバーに恒久的なメールボックスやメッセージ履歴は無い。
- **identity は外部（did.md）が発行・ホストする。** biset は did:webvh を解決するクライアントに徹し、公開文書を自分では書かない。
  利用者は did.md Wallet（SIOPv2／OID4VP）で biset の端末を承認し、biset は DPoP に束縛された端末セッションを持つ（§5）。
- **端末集合の唯一の権威は DID Document の `keyAgreement`** である。送信者は全端末の鍵に 1 通で暗号化し（multiplexed encryption）、
  mediator は端末ごとの受信箱に配る。端末を外すことは、DID Document から鍵を消すことと同じ意味になる（§5.6、§9）。
- **長期の正本は端末の暗号化 Vault（event ＋ 暗号文 object ＋ SegmentKey）**で、UI が読む JMAP 形の projection は
  そこから再計算できる派生物である（§7）。Vault の event は署名を持たない（§7.1）。
- **複数端末の同期は DIDComm 上の「Vault Sync」**で、自分の DID 宛ての通常の DIDComm メッセージとして送る。専用サーバーも専用の鍵も無い（§8）。
- **mediator は DIDComm v2.1 の標準手順で話す**: HTTPS POST と WebSocket、`return_route`、Pickup 3.0 の live mode、
  `application/didcomm-encrypted+json`、Trust Ping（§11.1）。
- biset が自分で運用するサーバーは **mediator** と **rp-signer**（did.md への認可要求に署名）。
  メール用の **did-md-mail-relay**（SMTP ⇄ DIDComm bridge）が同じホスト（v2）で動く（§11）。
- **世代（VCK）・routing alias・関係秘密・ML-KEM・Vault event の署名・MLS 端末証明書は、すべて撤去済み**（§1.4）。

## 1. この文書の読み方

### 1.1 判定語彙

| 語 | 意味 |
|---|---|
| ✅ 実装済み | 起動経路・呼び出し経路まで接続されている |
| 🔧 部品 | コードとテストはあるが、本番の経路から呼ばれない |
| ⛔ 廃止／撤去対象 | 設計上は消えたが、コードや記述が残っている |
| ❓ 未検証 | コードを読んだだけで、実機・テストでは確かめていない |

### 1.2 関連文書

| 文書 | 内容 |
|---|---|
| [`PLAN.md`](PLAN.md) | did.md Wallet login の設計 |
| [`PLAN-tor.md`](PLAN-tor.md) | mediator の Tor 対応（設計判断・進捗・実機検証の記録） |
| [`PLAN-mail.md`](PLAN-mail.md) | 汎用 DIDComm mail bridge |
| [`PLAN_vault-sync-redesign.md`](PLAN_vault-sync-redesign.md) | 複数端末同期の再設計（ログ層／projection 層） |
| [`PLAN_biset-mimi-server.md`](PLAN_biset-mimi-server.md) | MIMI delivery service（稼働するが、現行クライアントは呼ばない） |
| [`docs/protocols/biset-messenger-capability.md`](docs/protocols/biset-messenger-capability.md) | capability 文書型 `biset.md/MessengerCapability` |
| `src/protocol/mls/VENDOR.md` | vendored MLS fork の差分 |

> `PLAN*`・`docs/`・`tasks/`・`ops/`・`scripts/`・`deploy.sh`・`home/`・`config.json` は **`.gitignore` で git の追跡外**である（§17-6）。

### 1.3 本番との関係

本書が記述するコードは、**全利用者が再ログインすることを前提に**デプロイされる（§15.4）。
mediator の登録の形（受信箱が DID × 端末になった）、Vault の IndexedDB（v15）、wallet セッションの形（VCK・関係秘密・MLS 証明書が消えた）が、いずれも互換性を持たない。
後方互換は持たない方針である（本番のデータはすべてテスト用）。

### 1.4 2026-10-02 版から変わったこと

| 領域 | 2026-10-02 版 | 現行コード |
|---|---|---|
| 端末集合 | DID Document の verificationMethod ＋ Vault 鍵の世代（`#biset-vault`） | **`keyAgreement` だけ**。世代の概念は撤去（§5.6） |
| 送信の暗号化 | 受信者の 1 鍵（「先頭の keyAgreement」） | **全 keyAgreement 鍵への multiplexed encryption**。`apv` は仕様どおり（§9.6） |
| mediator の受信箱 | recipient kid ごと。所有の証明なし | **(DID, 端末ラベル) ごと**。登録は DID 自身の鍵からの authcrypt に限る。1 DID 最大 3 端末（§11.1） |
| 関係（relationship）の鍵 | wallet が導出する「関係秘密」から決定論的に導出 | **Vault に置く relationship seed**から導出。最初の端末が作り、他は Vault Sync で受け取る（§9.2） |
| 端末を外す | DIDComm 鍵の削除 ＋ 世代 +1（本番では機能せず） | **DID Document の編集 → seed の作り直し → 全 relationship を `from_prior` で新しい did:peer へ移す**（§5.6） |
| Vault Sync | sibling ごとに送る。全体を VCK で暗号化 | **自分の DID 宛ての 1 通**。DIDComm authcrypt だけで守る。pack は SegmentKey をそのまま運ぶ（§8.1） |
| Vault event | 端末の Ed25519 で署名、MLS 端末証明書で認可 | **署名なし**。event id は内容の hash（§7.1） |
| SegmentKey | VCK で wrap して同期 | **wrap なし**。Vault Sync の pack に入れて運ぶ |
| JMAP export | 既定は VCK 暗号化の `.biset` | **平文 JSON**。取り込み時に確認し、取り込んだものに `$imported` を付ける（§8.2） |
| ML-KEM ハイブリッド | public-DID 経路にあった | **撤去**（§9.6） |
| live 受信 | 独自の `WATCH_REQUEST` ＋ SSE（`GET /stream`） | **WebSocket ＋ Pickup 3.0 `live-delivery-change`**（§9.7、§11.1） |
| mediator の応答 | 常に HTTP の応答本文 | **`return_route: "all"` のときだけ**。無ければ 202（§11.1） |
| Content-Type | 多くが `application/json` | **`application/didcomm-encrypted+json`**。mediator と mail relay は他を 415 で拒否 |
| Trust Ping | 応答の義務を記録するだけ | **応答する**（client も mediator も）（§9.5） |
| メール受信の宛先解決 | did.md の authority API（鍵 1 つ） | **公開 did:webvh の解決**（全端末の鍵）（§10.2） |
| 撤去したもの | — | recovery archive、delivery outbox／ingest／projector、`vault-content-key.ts`、`crypto.ts`（VCK）、`didcomm-credential.ts`、routing alias、mediator の connection／keycache／replay／watch-token、旧 vault delivery の wire 型 |
| 検査 | `bun run check` は失敗（typecheck 1、knip 5） | **`bun run check` が成功**（§16） |

## 2. 設計原則と非目標

### 2.1 原則

- **長期正本は各端末の暗号化 Vault である。** IndexedDB 上の「暗号文 object ＋ event ＋ SegmentKey」。
  mediator も MIMI サーバーも正本ではない。複数端末同期は、その同じ record を DIDComm で運ぶだけである。
- **ログ層と projection 層を分ける。** immutable event が唯一の正本で、UI が読む projection はそこから決定論的に再計算される。
  壊れたら捨てて作り直せる。
- **マージは join-semilattice** — 冪等・可換・結合的。`compareEvents`（`createdAt → actorDeviceId → actorSeq → id`）が全順序を与え、
  同一 entity への競合は per-entity の last-writer-wins で解決する。CRDT ライブラリは使わない。
- **端末集合の権威は DID Document だけ。** mediator は信頼の根拠にしない（ただの仲介役）。最初の端末かどうかも DID ログで決める（§9.2）。
- **mediator は blind queue。** 内側の DIDComm JWE を復号しない。Vault plaintext・SegmentKey を知る必要が無い。
- **identity の発行とホスティングは biset の責務ではない。** biset は解決するクライアントに徹し、公開文書を書かない。
  wallet は SIOPv2 の serverless な形で、サーバー側の失効の仕組みは持たない。
- **復旧に必要な履歴本体を biset のサーバーに置かない。** 履歴の移送経路は二本だけ（起動中の兄弟端末との Vault Sync、利用者が持つ JMAP export ファイル）。
- **DID と到達手段（URL）は別物。** relationship の did:peer には canonical（clearnet）の URL だけを埋め、onion は到達手段として別に扱う（§9.8）。
- **同じ意味の処理は共通関数に 1 つだけ置く。** endpoint の選択（`service-endpoint.ts`）、keyAgreement の読み取り（`keyAgreementRecipients`）、
  DIDComm の HTTP 送信（`didCommPost`）などは、この方針で統合された。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけにする。

### 2.2 非目標・未完成

- **オフライン起動**。起動時に did.md（device-refresh）と DID ログへのネットワークアクセスが要る（§12）。
- サーバー側の mailbox、全文検索、履歴 API、添付 archive。
- 完全な JMAP server。ローカル gateway は UI が使う最小メソッドだけを実装する。
- ActivityPub の実動 adapter。ただし External Feed の受信口はある（§9.4）。
- Web Push / background sync。Service Worker は install/activate のみ。
- メールの受信者側の拡張（did.md 以外のドメイン、添付、`send-result` による送信状態の確定）（§10）。

## 3. システム全体像

```text
┌──────────────────────── Biset Client（ブラウザ） ───────────────────────┐
│ UI ─ JMAP projection（派生）                                            │
│        ▲ VaultProjector（唯一の writer）                                │
│  IndexedDB Vault（ログ層）  ／ did.md Wallet セッション ／ DIDComm      │
└──┬───────────────┬─────────────────────────┬────────────────────────────┘
   │SIOPv2/OID4VP  │DIDComm v2.1             │File System Access API
   │(DPoP, JAR)    │HTTPS POST ＋ WebSocket  │ローカルの Markdown フォルダ
   │DID 解決(読む) │・1:1 / group chat       │JMAP export/import ファイル
   │               │・Vault Sync（自分の DID 宛て）
   │               │・mail bridge の送受信
   ▼               ▼
┌─ did.md（外部）─┐  ┌─ Mediator（"A"）──────────────┐  ┌─ did-md-mail-relay ─┐
│identity 発行    │  │mediator.biset.md              │  │smtp.did.md          │
│did:webvh ホスト │  │did:peer identity、SQLite      │  │SMTP :25 ⇄ DIDComm   │
│wallet の承認    │  │受信箱 = (DID, 端末)、最大 3   │  │did:web の bridge    │
│                 │  │Pickup 3.0、live mode(WS)      │  │DKIM(未設定)         │
│                 │  │Tor Hidden Service(onion)      │  │                     │
└─────────────────┘  └───────────────────────────────┘  └─────────────────────┘
        ▲ JAR に署名
┌─ biset-rp-signer ─┐   biset-mimi（稼働可能だが、現行クライアントは呼ばない）
│t.biset.md の RP DID│
└────────────────────┘
```

### 3.1 運用コンポーネント

| コンポーネント | 入口 | 状態 |
|---|---|---|
| **Mediator** | `src/server/mediator/index.ts`（"A"） | ✅ 本番稼働（v2、`127.0.0.1:8791`、Caddy 経由で `mediator.biset.md`） |
| Mediator + mail-plugin | `src/server/mediator/mail-plugin/index.ts`（"B"） | 🔧 ビルド可。本番では使っていない（同じ unit・DB を奪い合う排他関係） |
| **did-md-mail-relay** | `src/server/mail-relay/index.ts` | ✅ 本番稼働（v2、SMTP `:25`、HTTP `127.0.0.1:8792`）。mail-plugin のコードを共有 |
| **biset-rp-signer** | `src/server/rp-signer/index.ts` | ✅ 本番稼働（v2、`:8794`、`t.biset.md/api/rp-signer/*` として公開） |
| biset-mimi | `src/server/mimi/index.ts` | 🔧 サーバーとしては動くが、クライアントからの呼び出し経路が無い（将来の MIMI クライアントのために残す） |
| **クライアント** | `src/client/app/main.ts` | ✅ `t.biset.md`（v2 の Caddy が `/opt/biset/app` を配信）。`file://` の `dist/index.html` でも動く |
| tor | v2 の `tor@default`（did.md と共有） | ✅ Hidden Service が 2 つ（did.md の `didmd-app`、biset の mediator） |

did.md は biset が運用するものではなく、依存する外部サービスである（identity の発行とホスト、wallet の承認、旧メール HTTP 経路の authority API）。
本番の biset と did.md は**同じホスト v2 に同居**している（Caddy、tor、did.md の各サービス）。

## 4. 信頼境界

### 4.1 クライアントが保持するもの
- did.md Wallet の端末セッション（DPoP 鍵、封印された device material、Vault 用の端末 ID）
- 端末固有の DIDComm 鍵（X25519、公開鍵が DID Document の `keyAgreement`）と、mediator の端末ラベルを作る秘密（`mediatorDeviceSecret`）
- Vault の暗号文 object、event、SegmentKey、JMAP projection
- Vault 内の **relationship seed** と、relationship ごとの非公開 DIDComm credential（`contact-key.set`、1:1・group chat 共通）
- Markdown ミラーのディレクトリハンドル

クライアントは plaintext の最終処理点であり、侵害されたクライアントから取得済みの秘密を取り戻すことはできない。

### 4.2 did.md を信頼する範囲
did.md は identity の発行元かつホスト、wallet の承認者である。知り得るのは公開文書と、承認・capability に伴う metadata。
Vault plaintext・SegmentKey・relationship seed を知る必要は無く、**wallet から biset へ渡る秘密は無い**（derived secret の要求は撤去済み）。
biset は did.md の controller 鍵を保持しない。

### 4.3 Mediator を信頼する範囲
blind queue。内側の JWE は読めない。観測できるのは、登録された DID と端末ラベル、受信箱ごとの queue 数・時刻、接続元 IP、外側 Forward の `next`（宛先 DID）。
- 端末ラベルは `HMAC(mediatorDeviceSecret, DID)` で、**DID ごとに異なる**。別々の DID の受信箱が同じ端末のものかは、ラベルからは分からない。
- 継続的な会話は公開 did:webvh ではなく relationship 固有の `did:peer:2` を使い、公開 identity との直接の相関を避ける（group chat も同様）。
- **Vault Sync は自分の DID 宛て**なので、「この identity が自分の端末同士で同期している」ことは観測できる。
- **mediator は信頼の根拠にしない**。受信箱の登録は、DID 自身の鍵による authcrypt でしかできない（所有の証明、§11.1）。

### 4.4 mail relay が見るもの
SMTP のメールは、通常の SMTP と同様に平文で relay を通る（relay は raw RFC 5322 を見られる）。DIDComm 区間は authcrypt で、mediator には見えない。
DKIM は未設定で、送信メールは署名されない（起動時に警告、§10）。

### 4.5 利用者が持ち出すファイル
JMAP export は**平文の JSON**（`.json`）。dashboard を開ける時点で全情報が見えているため、暗号化はしない。
import は確認ダイアログを経て、別の identity の export は拒否する。取り込んだメッセージには `$imported` キーワードが付く。

## 5. Identity と did.md Wallet

### 5.1 biset は identity を作らない
発行とホスティングは did.md が行う。biset は did:webvh を**解決**し、wallet の承認を経て端末を登録する。

### 5.2 認証経路（SIOPv2 / OID4VP）

`src/client/identity/wallet/did-md-oauth.ts` が唯一の入口である。リクエストは、DID 編集（端末の鍵と `#didcomm` service）と、メール relay の capability を
`authorization_details` に載せる。

| ビルド | client の識別 | 認可要求 |
|---|---|---|
| **https**（`t.biset.md`） | **RP DID**（固定の did:webvh、`t.biset.md` に束縛）。登録の往復は無い | **JAR（RFC 9101）**。`biset-rp-signer` が RP DID の鍵で署名する |
| **file://** | DCR で得るランダムな `client_xxx`（`registrationAccessToken` を保持） | 通常のクエリ形式（`redirect_uri`、`capability_type`、`alias` など） |

- 応答は **直接配送**（PLAN7）で、`vp_token`（VC-DM の capability）と `id_token` が fragment（https）、または popup の postMessage／クエリ（file://）で戻る。コード交換の往復は無い。
- `redirect_uri` は、https では signer が固定値（`https://t.biset.md/wallet/callback`）を埋め、呼び出し側からは受け取らない。
- **file:// 版は、https 版と別のアプリとして wallet に登録される**（client_id と redirect_uri が別）（§17-5）。
- 端末セッションは、DPoP 用の ECDSA P-256 鍵（**非抽出**の `CryptoKey`）に束縛される。
- ログイン時に、Vault 上の端末 ID（`vaultDeviceId`、`urn:uuid:…`）を作ってセッションに保存する。

### 5.3 capability と端末セッション

- capability は **Biset 所有の VC-DM 2.0**（`type: biset.md/MessengerCapability`）。形は
  `src/client/identity/wallet/schemas/biset-messenger-capability.schema.json`（JSON Schema 2020-12）が唯一の正本で、
  `json-schema.ts`（`eval` を使わない最小の解釈器）が検証する。`authorizationDetails` の要素は DID 編集とメール relay の 2 種類。
- 検証の順序: スキーマ → `issuer`・`audience`・`deviceJkt`・期限・必須 scope（`biset:device`、`biset:vault`）→ Data Integrity Proof（Root 鍵）→
  `authorizationDetails` の照合（DID 編集のエコー）。
- 要求する scope: `openid profile biset:login biset:device biset:routing biset:messaging biset:vault`。
- セッションは `biset-did-md-wallet` IndexedDB に保存される。DIDComm の秘密鍵と `mediatorDeviceSecret` は、非抽出の AES 鍵で封印した「device material」に入る。
- 起動のたびに `device-refresh`（DPoP 付き POST）で capability を取り直し、同じ検証を通す（§12）。
  **ネットワークエラーでは session は保たれるが、非 2xx 応答や検証の失敗は一律に session を破棄する**（§17-4）。

### 5.4 DID Document の編集契約（`urn:did-core:document-edit:v1`）

biset は DID Document を直接書かず、**編集の要求を wallet に渡し、承認後に wallet が署名付きログへ書く**。契約は did.md 側にある。

| 項目 | 意味 |
|---|---|
| `services` | 追加・置換する service（id が同じなら置換） |
| `services[].endpointMode: "merge"` | **置換せず、`serviceEndpoint` の要素を既存の service に足す**。要素は `uri`（string ならその値）で同一視する。結果が 1 要素なら単体の形に戻す。省略または `"replace"` は従来の置換 |
| `verificationMethods` | 追加・置換する鍵（`controller` は wallet が自分の DID に強制する） |
| `serviceKeyBindings` | service と鍵の対応 |
| `remove` | 削除する id（鍵・service） |
| `removeEndpoints: [{serviceId, match}]` | `match` の全プロパティが一致する endpoint を、その service から削除する。全部消えたら service ごと消える |

- **適用は承認の瞬間に、wallet が持つ現在の状態に対して行う**（`did.md/packages/wallet/src/did-document-edit.ts` の `withDidDocumentEdit`）。
- biset の使い方（`buildDocumentEdit`）: `#didcomm` は常に `merge`。ログインは clearnet の要素だけを足す。「Enable Tor」は clearnet と onion の 2 要素を足す。
  「Edit server」は mediator が**変わるときだけ**、古い `routingKid` に一致する要素を `removeEndpoints` で消す。
- **承認後の検証**（`did-document-edit-check.ts`）: replace なら「公開された service が要求と一致」、merge なら「要求した要素をすべて含む」、
  `removeEndpoints` なら「一致する要素が残っていない」。公開結果は、CDN を避けた読み取り（`freshFetch`）で確かめる。

### 5.5 公開される DID Document

| 項目 | 内容 |
|---|---|
| `verificationMethod`／`keyAgreement` | 端末ごとの X25519 鍵。fragment は公開鍵から導出した自己検証的な値（`#k_<hash>`）。**この一覧が端末集合そのもの** |
| `service #didcomm`（`DIDCommMessaging`） | `{uri, accept, routingKeys}`。**単一の map、または clearnet＋onion の配列**。`routingKeys` は mediator の did:peer の kid |
| `service #udi-wallet-issuer` | did.md が付ける |

**`#didcomm` の優先順位**: 配列の順序が所有者の希望順（DIDComm 2.1）。biset は clearnet を先に置く。

### 5.6 端末集合・端末の外し方

- **端末集合は、DID Document の `keyAgreement` が参照する X25519 鍵**（`keyAgreementRecipients`、`resolveOwnDeviceKids`）。
  アカウント画面の device list はこの解決結果をそのまま表示する。自端末が一覧に無ければ、起動時に再接続を求める。
- 送信者は、この全鍵に 1 通で暗号化する。mediator は、その DID の全受信箱にコピーを置く。
- **「Remove other devices」**（account の device list の削除アイコン、`beginDidMdRemoveOtherDevices`）:
  1. 自端末以外の鍵を DID Document から消す編集を wallet に承認してもらう。セッションに `deviceRemoval` の印を残す。
  2. 次の起動で、`registerWithMediator` が新しい DID ログを mediator に渡す。**mediator は、消えた鍵で登録された受信箱を失効させる**。
     送信者も次の解決から、外された端末に暗号化しなくなる。Vault Sync も同じ理由で届かなくなる。
  3. `finishDeviceRemoval` が **relationship seed を作り直す**（外された端末は新しい seed を持たない）。
  4. `rotateOwnRelationships` が、全 relationship を新しい seed から導出した did:peer へ移し、`from_prior`（旧 did:peer の鍵で署名した JWT）を付けて相手に知らせる（§9.3）。
  5. すべて移せたら印を消す。途中で失敗した分は、次の起動で再試行する（冪等）。
- 外された端末がすでに持っている情報（過去の Vault、過去の relationship 鍵）は取り戻せない。外した後の新しい通信だけが守られる。

### 5.7 wallet directory
`wallet-directory.ts` の静的な配列（現状は dito＝did.md の 1 件）。`resolveWalletFromSuffix` は、ログインボタン横の入力欄（did:web の suffix）から wallet を解決する。
did-md-oauth.ts は特定の wallet を前提にせず、選択された entry の issuer に対して動く。メール relay の origin（`https://api.did.md`）だけは固定である。

## 6. 鍵と秘密

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 |
|---|---|---|---|
| DPoP 鍵（P-256、非抽出） | 端末 | `biset-did-md-wallet` | しない |
| 端末の DIDComm X25519 | 端末 | 同上。**非抽出の AES 鍵で封印** | 公開鍵が DID Document の `keyAgreement` |
| `mediatorDeviceSecret` | 端末 | 同上 | しない。mediator の端末ラベル `HMAC(secret, DID)` を作る |
| **relationship seed** | identity | Vault（`credential.relationship-seed.set`） | Vault Sync で全端末へ。端末を外すと作り直す |
| relationship の X25519／Ed25519 | 相手ごと | `contact-key.set`（暗号化 Vault object） | service を含む `did:peer:2`、Vault Sync で全端末へ |
| SegmentKey | Vault segment | `vault_segments.segmentKey` に**平文** | Vault Sync の pack に入れて運ぶ（DIDComm authcrypt の中） |

- relationship の did:peer は `deriveRelationshipPeerIdentity(seed, 相手の DID, mediatorRoutingKid)` で**決定論的**に導出する。
  同一 identity の複数端末が同じ相手へ同時に初回接触しても、同じ peer に収束する。**service の URL は mediator の did:peer 自身が持つ canonical の値から取る**（onion の URL は入らない）。
- **seed を作ってよいのは identity の最初の端末だけ**（`isFirstDidCommDevice`）。判定は DID ログで行う: 自分の鍵を初めて載せたエントリに、他の keyAgreement 鍵が無ければ最初の端末。
  ログは追記のみで wallet が 1 エントリずつ署名するため、2 台がともに「最初」と判断することは無い。他の端末は、Vault Sync で seed が届くまで relationship の操作を保留する（`RelationshipSeedPendingError`）。

### 6.1 at rest
wallet の device material は封印される。一方 **SegmentKey は IndexedDB に平文**で、browser profile を読める攻撃者に対する at-rest の保護は Vault 側で未完成。
Markdown ミラーを有効にすると、ローカルディスクに平文の `.md` が置かれる（利用者が選んだディレクトリのみ）。

### 6.2 撤去した鍵
VCK（Vault Content Key、世代つき）、wallet から導出する関係秘密、routing alias、端末の Ed25519 署名鍵と MLS 端末証明書（key authorization credential）、ML-KEM-768、
master seed／24 語 phrase、Root/Sign/Spare 鍵、recovery archive の鍵。いずれも現行コードに存在しない。
MLS そのもの（`src/protocol/mls/`、`client/mls/`、`client/mimi/`、`server/mimi/`）は、将来の MIMI クライアントのために残している（§11.4）。

## 7. Vault

### 7.1 データモデル
長期正本は immutable な二種類の record である。

- **VaultObjectV1** — 32 byte の SegmentKey と AES-256-GCM で暗号化した content-addressed object。
- **VaultEventV1** — actor device、actor sequence、kind、target、object 参照、parents、時刻。**署名は持たない**。
  event ID は内容の正準形の hash（`domainHash('biset/vault/event-id/v2', …)`）で、`verifyVaultEvent` は「ID が内容と一致するか」を確かめる。
  Vault の内容が端末の外に出るのは DIDComm authcrypt の中（Vault Sync）だけで、送り手の認証はそちらが担う。

event の種別の正本は `src/protocol/vault.ts` の `VAULT_EVENT_KINDS`（`message.add/edit/tombstone`、`mailbox.set`、`keyword.set`、`transport.result`、
`didcomm.control`、`contact-key.set`、`credential.relationship-seed.set`、`credential.openpgp.set` など）。

### 7.2 IndexedDB
`biset-vault-core`、**schema version 15**。object・event・segment（SegmentKey つき）・manifest・projection・JMAP state・各種 outbox／cursor を持つ。
v15 の upgrade で、key wrap と旧 vault delivery の store を削除した。

| 要素 | 内容 |
|---|---|
| `vault_actor_sequences` | `[identityId, deviceId]` ごとの actorSeq 採番カウンタ。カウンタと既存 event の最大値の**両方**を上限に取る |
| `vault_projection_meta` | projection の永続 tombstone 集合と pending 集合 |
| `vault_events` の index | `by_target_id`（multiEntry）、`by_actor_sequence` |

local mutation・ingress commit・Vault Sync の受信適用は、record・projection・JMAP state を**同一 transaction** に書く。

### 7.3 projection
`VaultProjector` が**唯一の writer**で、対象の email に触れた event だけを `by_target_id` で引いて畳み直す（per-entity LWW）。
永続 tombstone（`message.tombstone`）は、後から届いた古い `message.add` が削除済みを復活させない。材料が揃わない email は `pending` に入り、次の再計算で再試行される。
対象が 200 件を超える、または projection が無いときは `rebuildAll`。

## 8. 端末間同期・履歴移送・Markdown

### 8.1 Vault Sync（層 1: ログの同期）
`src/client/didcomm/vault-sync.ts` の `VaultSyncClient`。メッセージ型は 3 つ（`protocol/didcomm/vault-sync-protocol.ts`）。

| 型 | 向き | 意味 |
|---|---|---|
| `https://biset.md/vault-sync/1.0/update` | PUSH | 「今これを確定した」。**ヒントであって保証ではない** |
| `…/state-request` | PULL 要求 | 手元の summary を添えて「不足分をくれ」 |
| `…/state-response` | PULL 応答 | 不足分。`hasMore` で続きを示す |

- **宛先は自分の DID**。front door と同じ送信経路（`sendFrontDoorMessage`）で、DID Document の全端末の鍵に 1 通で暗号化し、mediator が各端末の受信箱へ配る。
  送った端末にも自分のコピーが届くが、無視する。DID Document から外された端末は、新しい同期を読めず、送ることもできない（鍵が解決されないため）。
- **中身は delivery pack**（`delivery-pack.ts`）: event、その object、object が要る SegmentKey。暗号は DIDComm authcrypt だけ。
- **summary は version vector**: `Record<actorDeviceId, {max, gaps[]}>`。採番の重複がある actor は `max=0` に落とし、全件を「不足」にする。
- **PUSH は content-carrying**。PUSH を受けた側は必ず `state-request` を返して突き合わせる。
- **応答は有界**: 1 通 128 KB（`VAULT_SYNC_CHUNK_BYTES`）。mediator の既定の上限 1 MB から、封入で約 3.2 倍に膨らむことを考慮して逆算した値。
- **適用は record 単位で skip**: object の完全性、event ID の一致、SegmentKey の形式を個別に検証し、落ちた分を数えるだけで batch 全体は落とさない。
- **送信は 6 回・250 ms から倍々のバックオフ**。宛先は毎回 DID Document から解決し直す。
- **取りこぼしの回収**: mediator は、休眠中（14 日）や満杯の受信箱へのコピーを捨て、その受信箱に `missed` の印を付ける。
  status でこの印を受け取った端末は、`state-request` を送って兄弟から追いつく（`onMissed`）。

### 8.2 履歴の移送
移送経路は二本だけ。

1. **起動中の兄弟端末からの Vault Sync**。新端末は boot 時に `state-request` を送る。兄弟が一台も起きていなければ、**空の Vault で始まる**（仕様）。
2. **JMAP export / import**（`jmap-export.ts`）。汎用の JMAP（`mailboxes`／`emails`／`blobs`）に、順位情報を拡張プロパティ `https://biset.md/jmap/ns:stateRank` 1 つで載せる。
   順位は `keywords`／`mailboxIds`／`content` の 3 つの独立したキー（`createdAt|actorDeviceId|actorSeq|eventId`）。import は現在の projection と順位を比べ、**新しい側だけ**を合成イベントとして書く。
   複数の不完全な export を順不同で何度 import しても、同じ集合に収束する。export は平文の `.json`、import は確認ダイアログを経て、取り込んだものに `$imported` を付ける。

### 8.3 Markdown ミラー
File System Access API で利用者が選んだディレクトリに、スレッドを Markdown として書き出す（`markdown-mirror.ts`／`markdown-directory.ts`、設定画面のトグル）。
- ディレクトリは正本ではない。書き出しは projection から作り直す方向で、ファイルから取り込むのは frontmatter の `status` と、メッセージブロックより前の下書き本文だけ。
- レイアウトは `{mailbox 名}/{相手}_{MMDDhhmm}.md`（未読は先頭に `_`）、`Drafts/_new.md` が雛形。
- `status` は JMAP の変更に翻訳される（`seen`／`follow` は keyword、`archived`／`spam` は mailbox の移動、`deleted` は destroy）。本文に `!b` だけの行を入れると、そのスレッドへの返信として送信する。
- `MarkdownSelfWriteGuard` が自己書き込みのループを防ぐ。`FileSystemObserver` があれば 500 ms のデバウンスで監視し、無ければ手動の再走査になる。

## 9. DIDComm

### 9.1 front door
端末ごとの X25519 鍵（`#k_<hash>`）が公開の front door。起動時に mediator へ登録する（`registerWithMediator`: DID ログを `POST /webvh-log` で渡し、mediate-request、keylist-update）。
wallet が認可した mediator が、このデプロイの `mediatorUrls` に含まれていなければ fail closed。
front door は、新規の relationship の発見と `RELATIONSHIP_INIT`、Vault Sync、メールの送受信に使う。
送信は、宛先の DID Document の**全** keyAgreement 鍵に 1 通で暗号化し、`#didcomm` の `routingKeys` があれば Forward で包む（`next` は宛先の DID）。

### 9.2 private relationship
初回の送信者は、専用の X25519／Ed25519 と service を含む `did:peer:2` を **relationship seed から決定論的に**導出し、その受信箱を mediator に **INIT より先に**登録する。
受信者も専用の peer を導出・登録して `RELATIONSHIP_ACCEPT` を返す。双方の公開情報と自分の秘密鍵は、`contact-key.set` として Vault に保存される。
確立後の Basic Message 2.0 と group chat は、同じ relationship kid 間の authcrypt だけを使う（公開 front-door kid を含めない）。
did:peer の鍵は identity の全端末で同じだが、mediator の受信箱は端末ごと（端末ラベルが別）なので、全端末がそれぞれ受け取る。
- 同じ相手への並行する `ensureContact` は直列化される（`WalletRelationshipManager` の `ensuring`）。呼び出し側の 60 秒タイムアウトは「待つのをやめる」だけで、登録済みの receiver と pending は残る。
- **crash 耐性は無い**: pending の状態はメモリ上の Map だけで、INIT 後・ACCEPT 前の reload で private pending key を失う。ただし決定論的導出により、やり直せば同じ peer が再構成される。

### 9.3 relationship の乗り換え（DID Rotation、`from_prior`）
端末を外すと（§5.6）、seed が作り直され、各 relationship の自分側の did:peer が変わる。
- 新しい `ContactKeyV1` は `supersedes`（旧レコードへの参照）と `fromPrior`（旧 did:peer の Ed25519 鍵で署名した EdDSA JWT、`from-prior.ts`）を持つ。
- 乗り換えた側は、以後の全メッセージに `from_prior` を付ける。直後に Trust Ping（応答不要）を送って相手にすぐ知らせる。
- 受信側は `acceptCounterpartyRotation` で `from_prior` を検証し、相手の新しい did:peer を記録する。
- 自分の旧 kid の受信箱は、乗り換え後 30 日間は watch を続ける（相手がまだ旧 kid へ送ってくる間の取りこぼしを防ぐ）。
- 限界: 相手が 2 回の乗り換えをまたいでオフラインだと追従できない。不正な `from_prior` のメッセージは ACK されずに残る（P3 の課題）。

### 9.4 group chat と External Feed
- **group chat**: MLS を使わない、**full-mesh の pairwise fan-out**。アドレスは `didcomm-group:<groupId>`。作成時に各招待者へ `GROUP_INVITE`、続けて `GROUP_MESSAGE`。
  v1 の範囲は意図的に狭い（作成後のメンバー変更、端末間の roster 同期、改名、退出、編集・削除・リアクションは未実装）。roster は端末ローカル（`group-chat-store.ts`）。
- **External Feed**（`https://didcomm.org/external-feed/1.0/post`）: **anoncrypt のみ**で、送信者を認証しない。ActivityPub／AT Protocol／RSS のフィード投稿を bridge が運ぶことを想定している。
  スレッドは `(identityId, source, actorId)` で作り、本文の URL は `X-Source-Url` ヘッダに退避して CR/LF を除く。anoncrypt を許すのはこの型だけ。

### 9.5 Trust Ping 2.0
`response_requested` が `false` でない ping には、`ping-response`（`thid` は ping の id）を返す（`answerTrustPing`）。
relationship の did:peer 宛てに来た ping はその relationship で、それ以外は front door で返す。mediator も自分宛ての ping に応答する。
受け取った `ping-response` は何もせず ACK する。

### 9.6 暗号形式
- Authcrypt `ECDH-1PU+A256KW` + `A256CBC-HS512`。Anoncrypt は `ECDH-ES+A256KW` + `A256CBC-HS512`（受信は `XC20P` も許容）。
- **multi-recipient**: 1 つの JWE に受信者ごとの `recipients[]`。`apv` は受信者の kid を並べ替えて `.` で連結した文字列の SHA-256（DIDComm v2.1）で、受信時にも照合する。
- DIF の DIDComm v2.1 の X25519 のテストベクタで相互運用を確認している（`test/protocol/didcomm-spec-vectors.test.ts`）。
- HTTP の Content-Type は `application/didcomm-encrypted+json`（`DIDCOMM_ENCRYPTED_MEDIA_TYPE`、送信は `didCommPost` に統一）。

### 9.7 受信（live mode）と振り分け
受信は **mediator ごとに WebSocket 1 本**（`mediator-live.ts` の `watchMediatorLive`）。front door と全 relationship の受信箱がその 1 本を共有する。
接続のたびに、受信箱ごとに:
1. HTTPS で登録する（自己修復。冪等）。
2. `live-delivery-change {live_delivery: true}`（`return_route: "all"`）を送る。以後の新着は `delivery` メッセージとして流れてくる。
3. mediator の status に溜まっている分があれば、`delivery-request` で 10 件ずつ取り出す（live mode は既存の queue に触れない、Pickup 3.0）。
4. 処理が終わった分だけ `messages-received` で ACK する（同じ socket で）。ACK するまで mediator の queue に残る。処理に失敗した分は ACK せず、同じ分を取り直し続けることもしない。

接続が切れると live は解除され、再接続で上をやり直す。受け取ったメッセージは型で振り分けられる。

1. relationship の乗り換え（`from_prior`）を先に記録する
2. Vault Sync の 3 型 → `VaultSyncClient.receive`
3. group chat（`GROUP_INVITE`／`GROUP_MESSAGE`）
4. `ping-response` → 何もしない
5. それ以外 → `DidCommIngressProjector`（Basic Message、Trust Ping、relationship、`MAIL_BRIDGE_INBOUND`、`MAIL_BRIDGE_SEND_RESULT`、External Feed）→ `ingestTransportIngress` → Vault。
   relationship の `INIT`／`ACCEPT` は `WalletRelationshipManager` が続きを処理し、ping には応答する。

`isProjectableDidCommIngress` に無い型は、**明示的に捨てて ACK する**。throw したままだと、mediator が同じメッセージを再配送し続ける。
dedupe の `alreadyProcessed()` は常に false を返す（未接続、§17-7）。

### 9.8 mediator の入口の選択と Tor
mediator は clearnet（`https://mediator.biset.md`）と onion（v3 Hidden Service）の 2 つの入口を持ち、**同じプロセス・同じ queue** に届く。

- **DID Document**: 既定では clearnet の単一 map。利用者が Account の Mediator カードで **「Enable Tor」**（⋮ メニュー）を選ぶと、
  `prompt` に config の `mediatorOnionUrls` が初期値として入り、OK で wallet 承認を経て `#didcomm` が `[clearnet, onion]` になる。**自動では公開しない**。
- **選択の規則**（`protocol/didcomm/service-endpoint.ts` の `selectDidCommEndpoint`）: 単一 map はそのまま。集合は clearnet を返し、Tor 環境（`preferOnion`）で、`routingKeys` が同一の onion があれば onion を返す。
  onion のみ・空・不正な要素の集合は route なし。読み取りの経路（通常の送信、`did:web`、mail bridge、mail relay、Vault Sync）がこの規則に揃っている。
- **Tor 環境の判定**（`isTorEnvironment`）は、**ページ自身が onion のホストから配信されているときだけ**真になる。
  biset の app は onion からは配信されていないため、現状では常に偽。WebSocket の URL は入口の URL から作る（https → wss、onion の http → ws）。
- **canonical URL を DID に埋める**: relationship の did:peer には canonical の URL だけを入れる。`sameMediatorUrl`（`mediator-endpoints.ts`）は、clearnet と onion を同じ mediator の別名として扱う。
- **実機**: onion での登録・Forward の POST・配信は 2026-10-01 に SSE 時代の実装で確認した。**WebSocket 化後の onion 経由は未確認**（❓）。
- **rate limit の注意**: mediator は `x-forwarded-for` の先頭、無ければ接続元 IP を単位に 1 分あたり 3000 件を数える（WebSocket はフレームごと）。
  onion は tor が 127.0.0.1 から直接つなぐため、**onion の利用者全員が 1 つの枠を共有し、送信者が XFF を自由に付けられる**。

## 10. メール

did.md ホストの利用者に限り、**DIDComm を土台にした汎用の mail bridge** が動く（`PLAN-mail.md`）。

### 10.1 送信
1. 宛先にメールアドレスが含まれると、`sendWalletMessage`（`main.ts`）が `buildOutboundRfc5322`（Message-ID は `…@did.md`）で RFC 5322 を作る。
   **差出人は `{handle の最初のラベル}@did.md` に固定**で、他のドメインは扱えない。
2. その email を outbox として Vault にコミットしてから、`submitDidCommMail` が `did:web:did.md` を解決して `MailBridge` service を見つけ、
   そのホストの `did:web:smtp.did.md` へ、**`MAIL_BRIDGE_SEND`（`https://didcomm.org/mail-bridge/1.0/send`）を authcrypt で送る**。RFC 5322 は attachment。
3. relay（`createMailBridgeAgent`、`POST /v1/mail`）は Content-Type を確かめ、authcrypt の sender kid を解決し、`mailFrom` が sender の DID から導出したアドレスと一致することを確かめて、
   外部へ SMTP 配送する（STARTTLS、DKIM は設定されていれば署名）。結果は `MAIL_BRIDGE_SEND_RESULT` として、sender の DID Document の経路へ返す。
4. クライアントは **POST の成功をもって `transport.result: accepted` と `mailbox.set sent` を記録する**。`SEND_RESULT` は `didcomm.control` として残すだけで、送信状態を確定させない（❓ 未完）。

### 10.2 受信
外部の SMTP → relay の `:25`（`createMailPluginListener`）。RCPT TO で、`{label}@did.md` を `{label}.did.md` の **公開 did:webvh ログ**から解決する（`resolveMailRecipientRoute`）。
宛先の全 keyAgreement 鍵が受信者になり、DATA の受理時に `MAIL_BRIDGE_INBOUND` を authcrypt（relay 専用の did:web の鍵）して、宛先の mediator へ Forward する。
クライアントは通常の DIDComm と同じく live 受信で受け、`DidCommIngressProjector` が RFC 5322 のヘッダ（Message-ID、References など）からスレッドを組み、本文を暗号化 object として保存する。

### 10.3 現状の限界
- 差出人・宛先は did.md のドメインのみ（relay 側は `apexDomain = did.md` を強制）。
- DKIM は **未設定**（`ops/mail-relay-dkim.md`）。SPF／DMARC は DNS に公開済みだが、本番での pass は未確認。
- bounce、rate limit、永続的な retry queue、送信の冪等性は未実装。**outbox の永続 retry は無く**、temporary failure は利用者操作なしには再送されない。
- 旧 HTTP 経路（`POST /v1/mail/submit`、capability＋DPoP、did.md の authority API）が relay に残る（`submission-http.ts`）。クライアントからは呼ばれない。
  一方、wallet への認可要求には `urn:biset:mail-relay:v1` の capability が今も毎回含まれる（⛔、§17-2）。

## 11. サーバー

### 11.1 Mediator（"A"／"B" 共通、`deployment.ts` ＋ `server.ts`）
- 自分の `did:peer:2` を SQLite に持つ。**公開 URL（https）が DID の service に埋まる**ため、`MEDIATOR_PUBLIC_URL` を変えると DID が変わり、起動時に fail closed する。
- プロトコル: Coordinate Mediation 2.0（登録）、Routing 2.0（Forward）、Pickup 3.0（status／delivery-request／messages-received／live-delivery-change）、Trust Ping 2.0、Report Problem 2.0。
- **トランスポート**: `POST /`（HTTPS）と、同じ `/` の **WebSocket upgrade**。どちらも 1 メッセージ＝1 JWE で、信頼は各メッセージの暗号化に置く（接続そのものは信頼しない）。
  - `POST /` は Content-Type `application/didcomm-encrypted+json` 以外を **415** で拒否する。
  - 応答は、要求に **`return_route: "all"`** があるときだけ、同じ接続（HTTP の応答、または socket）に返す。無ければ HTTP は本文なしの 202、socket は何も返さない。
  - **live mode** は WebSocket かつ `return_route: "all"` のときだけ有効にできる（それ以外は problem-report `e.m.live-mode-not-supported`）。
    新着は、live を有効にした鍵宛てに authcrypt した `delivery` メッセージとして push する。**push したコピーも ACK まで queue に残る**。接続が切れると live は解除される。
- **受信箱 = (DID, 端末ラベル)**。登録（keylist-update）は、その DID 自身の keyAgreement 鍵から authcrypt されたものだけを受け付ける（所有の証明。Coordinate Mediation 3.0 が「将来の課題」とする部分を biset が補う）。
  - did:peer の鍵は DID そのものから読む。did:webvh の鍵は、client が `POST /webvh-log` で渡した**検証済みの最新ログ**から読む（mediator はネットワークに出ない）。
    新しいログで消えた鍵で登録された受信箱は失効する。
  - **1 DID あたり最大 3 端末**。4 台目は problem-report `e.p.req.max-devices` で拒否し、client は登録済み端末の最終利用日つきのエラーを利用者に見せる（`MediatorDeviceLimitError`）。
- **配送**: Forward の `next`（宛先 DID）の全受信箱にコピーを置く（本文は 1 回だけ保存し、受信箱ごとの配送行で管理）。
  14 日使われていない受信箱（休眠）と満杯の受信箱は飛ばして `missed` の印を付ける。全受信箱が休眠なら、最後に使われた 1 つには置く。
  どこにも置けなければ HTTP 503。未登録の DID 宛の Forward は、署名付きの problem-report（`e.p.req.not_enroll`）を HTTP 401 で返して拒否する（open relay にしない）。
- 上限（既定）: 受信箱 30,000、受信箱あたり 256 件・16 MB、メッセージ 1 MB、保持 30 日、休眠 14 日、replay guard 10 分／50,000 ID。
- HTTP の入口: `POST /`、`GET /`（WebSocket upgrade）、`POST /webvh-log`、`GET /.well-known/did.json`、`/healthz`、`/readyz`、`/metrics`。
  WebSocket は Bun が idle の socket に ping を送る（`idleTimeout` 120 秒）。CORS と WebSocket の Origin は `MEDIATOR_ALLOWED_ORIGINS`（`null` は `file://` 用）。
- `relay-poller.ts`: 別の upstream mediator へ自分を client として登録し、自分宛の Forward を unwrap して再 Forward する、任意の多段中継（`MEDIATOR_RELAY_UPSTREAM_URL`）。
- 永続化は `sqlite-store.ts`（テーブル: `did_states`、`inboxes`、`messages`、`deliveries`、`replay_ids`、`identities`）。Vault Sync も同じ queue を使うだけで、専用のテーブルや権限は無い。

### 11.2 mail-plugin と mail-relay
`mail-plugin/`（"B"）は、mediator に **SMTP `:25` の listener** と **`POST /v1/mail/submit` の HTTP（`:8792`）** を同居させた deployment variant。
`mail-relay/` は、そのコード（listener、`smtp-client`、DKIM、bridge）を共有しつつ、**mediator とは独立したプロセス・独立した SQLite** として動く。

| 経路（relay） | 役割 |
|---|---|
| SMTP `:25` | 外部からの受信 → 公開 DID の解決 → `MAIL_BRIDGE_INBOUND`（§10.2） |
| `POST /v1/mail`（`:8792`） | DIDComm の送信 agent（§10.1） |
| `POST /v1/mail/submit` | 旧 HTTP 経路（capability＋DPoP、did.md の authority API）。⛔ |
| `GET /.well-known/did.json` | `Host: smtp.did.md` なら bridge の did:web（`#key-1` の X25519）、`Host: did.md` なら discovery（`MailBridge` service） |

### 11.3 biset-rp-signer
状態を持たない。RP DID の鍵（`RP_DID_KEY_FILE`）で JAR を署名するだけ。受け付ける claim は許可リスト（`state`、`dpop_jkt`、`login_hint`、`authorization_details`、`dcql_query`、`scope` など）で、
`iss`・`client_id`・`response_type`・`redirect_uri` は**サーバー側で固定**し、呼び出し側からは受け取らない。

### 11.4 biset-mimi（🔧）
IETF `draft-ietf-mimi-protocol` に沿った MLS delivery service（`normal`／`anon`／`self`）。サーバーとしては動き、テストも通るが、**現行クライアントからの呼び出し経路は無い**。
biset は将来 MIMI クライアントにもなる予定で、そのために MLS／MIMI のコードを残している。設計の正本は `PLAN_biset-mimi-server.md`。

### 11.5 環境変数（要点）
- Mediator: `MEDIATOR_PUBLIC_URL`（必須）、`MEDIATOR_DATABASE_PATH`（または `MEDIATOR_DATA_DIR`）、`PORT`（既定 8791）、`MEDIATOR_HOST`（既定 127.0.0.1）、
  `MEDIATOR_ALLOWED_ORIGINS`、`MEDIATOR_RATE_LIMIT_PER_MINUTE`、`MEDIATOR_MAX_REQUEST_BYTES`、`MEDIATOR_MAX_INBOXES`、`MEDIATOR_MAX_DEVICES_PER_DID`、
  `MEDIATOR_MAX_QUEUE_ITEMS`、`MEDIATOR_MAX_QUEUE_BYTES`、`MEDIATOR_MAX_MESSAGE_BYTES`、`MEDIATOR_QUEUE_TTL_MS`、`MEDIATOR_DORMANT_AFTER_MS`、
  `MEDIATOR_REPLAY_TTL_MS`、`MEDIATOR_MAX_REPLAY_IDS`、`MEDIATOR_RELAY_UPSTREAM_URL`。
- mail-plugin（"B"）: `MAIL_PLUGIN_APEX_DOMAIN`（必須）ほか `MAIL_PLUGIN_SMTP_*`、`MAIL_PLUGIN_SUBMIT_*`、`MAIL_PLUGIN_TLS_*`。
- mail-relay: `DID_MD_AUTHORITY_URL`、`DID_MD_MAIL_RELAY_SECRET`（旧 HTTP 経路だけが使う）、`MAIL_RELAY_DATABASE_PATH`（必須）、`MAIL_RELAY_SMTP_*`、`MAIL_RELAY_SUBMIT_*`、`MAIL_RELAY_TLS_*`、`MAIL_RELAY_ALLOWED_ORIGINS`、DKIM 関連。
- rp-signer: `RP_DID_KEY_FILE`、`RP_REDIRECT_URI`、`RP_SIGNER_ALLOWED_ORIGIN`、`PORT`（既定 8794）。
- biset-mimi: `MIMI_DATABASE_PATH`、`MIMI_MODE`、`MIMI_PUBLIC_BASE_URL`、`MIMI_ALLOW_EXTERNAL_JOIN`、`PORT`。

## 12. クライアントの起動

`bootClient`（`main.ts`）。**wallet セッションが唯一のアカウント経路**である。

0. 前回のセッションの mediator watch を**無条件に**止める。
1. wallet の callback を先に消費する（DID の編集で古い capability の snapshot が古くなるため、通常の refresh より先）。失敗はコンソールの警告にとどめ、画面は壊さない。
2. `restoreDidMdWalletSession`（`device-refresh` ＋ §5.3 の検証。**ネットワークが要る**）。復元できなければ、ログイン画面、または「capability の期限切れ。再接続を」の画面。
3. Vault IndexedDB を開く（v15）。actorSeq の採番器、暗号境界、read model、`VaultProjector`、mutation sink を組む。export／import、Markdown ミラーを配線する。
4. **既存のローカル projection で先に inbox を描画する**（ネットワークを待たない）。
5. DIDComm の device material を開き、自分の DID Document を解決する。**自端末の鍵が `keyAgreement` に無ければ**、再接続を求めて止まる。
6. mediator へ登録する（DID ログを渡す → mediate-request → keylist-update）。入口は `preferredMediatorUrl`（通常は clearnet）。onion で失敗したら canonical へ戻る。
7. relationship seed を用意する（`provisionRelationshipSeed`）。最初の端末なら作り、そうでなければ Vault Sync で届くのを待つ。
8. `VaultSyncClient` を作り、`state-request` を送る（`void`）。
9. `DidCommIngressProjector`、`WalletRelationshipManager`、outbox を作り、`watchMediatorLive` で front door の live 受信を始める。
10. 保存済みの relationship の受信箱の watch を再開する（**1 つの相手の恒久的な失敗で boot 全体を落とさない**。乗り換え後 30 日の旧 kid も含む）。
11. 「Remove other devices」の途中なら、seed の作り直しと relationship の乗り換えを済ませる（§5.6）。
12. outbox を flush し、10 秒ごとの再試行タイマーを張る。

どこかで例外が起きても、Vault カードを `error` にして、アカウント画面は出す。

## 13. 可用性・失敗・冪等性

- クライアントは、local transaction を network の ACK より先に行う。response が失われても、再送で回復できる。
- Vault Sync の PUSH は到達保証を持たず、取りこぼしは PUSH 適用後の `state-request` と、mediator の `missed` による `state-request` で回収される。送信は 6 回・指数バックオフ。
- 一件の不正な record が batch 全体を落とさない（record 単位の skip）。materialize できない email は `pending` になる。
- 承認直後に古い DID ログが返ることがある（did.md の公開読み取りは CDN が `s-maxage=30` で保持し、更新時に purge しない）。
  biset は CDN を避けた読み取り（`freshFetch`、`fetchLogContaining`）で、承認した内容がログに現れるのを確かめる。
- relationship の handshake は reload を跨げない（§9.2）。outbox の mail 送信は自動再送されない（§10.3）。
- **`main.ts` の boot wiring は、ブラウザ E2E で覆われていない。** 部品のテスト成功と、製品経路への接続を機械的に区別できない。

## 14. セキュリティ性質と未解消リスク

### 14.1 実装されている性質
- Vault object は認証付き暗号、content-derived ID、ciphertext hash で改ざんを検出する。event ID は内容の hash。
- Vault Sync は DIDComm authcrypt（端末の鍵、DID Document で検証）の中だけを通る。適用は fail-closed かつ record 単位。
- merge は join-semilattice。削除は永続 tombstone。actorSeq の採番は transaction 内で単調。import は順位を比べ、新しい状態を巻き戻さない。
- mediator は、受信箱の登録に DID 自身の鍵による所有の証明を要求し、未登録の DID への open forwarding を拒否する。端末数を 1 DID 3 台に制限する。
- 端末の失効は DID Document が唯一の権威。外された端末は、新しいメッセージ・新しい Vault Sync・新しい relationship seed を受け取れない。
- 承認後は、capability の Data Integrity Proof と、公開された DID Document を**独立に検証**する。
- `biset-rp-signer` は redirect_uri を固定し、claim を許可リストに限る。

### 14.2 未解消リスク
1. **SegmentKey が IndexedDB に平文（高）**。wallet の material は封印されるが、Vault 側は未完成。
2. **全端末を失うと履歴は戻らない（高）**。移送は「起動中の兄弟」か「利用者が持つ export」だけ。利用者への警告 UI は無い。
3. **端末を外しても過去は取り戻せない（中）**。外された端末が持つ過去の Vault と relationship 鍵は有効なまま。外した後の通信だけが守られる。
4. **セッションの破棄が厳しすぎる（中）**。device-refresh の非 2xx 応答や、検証の失敗は、一律に session を破棄する。§5.3。
5. **relationship handshake が非永続（中）**、**dedupe の lookup が未接続（中）**、**group chat の roster が端末ローカル（中）**。
6. **`from_prior` の追従の限界（中）**。相手が 2 回の乗り換えをまたいでオフラインだと追従できない。不正な `from_prior` のメッセージは ACK されずに残る（§9.3）。
7. **onion の rate limit 共有（中、Tor 実運用まで）**（§9.8）。
8. **メール**: DKIM 未設定、送信状態の確定が未完、outbox の自動再送が無い（§10.3）。
9. **No background／push（運用）**。ページが閉じている間は同期しない。
10. **mediator の DB 書き込み失敗時の挙動は未検証（運用）**。

## 15. Build・設定・運用

### 15.1 クライアント
- `bun run build` — `src/client/app/main.ts` と `sw.ts` を browser の IIFE に bundle し、`scripts/inline.mjs` で `dist/index.html` に inline 化する。
  **`bun build` 単体では不十分**で、必ず `bun run build` を使う。検証は `file://` の `dist/index.html` で行う（localhost の dev サーバーは使わない）。
- 実行時設定は `window.__BISET_CONFIG__`（`ui/config.ts` が読む唯一の場所。`config.json` を `inline.mjs` が埋め込む）。

| キー | 用途 |
|---|---|
| `apexDomain` | このデプロイの apex ドメイン |
| `mediatorUrls` | 登録先の mediator |
| `mediatorOnionUrls` | 同じ index の mediator の onion。**「Enable Tor」の初期値にだけ使う**（自動では公開しない） |
| `walletDeviceName` | wallet に見せる端末名 |
| `didDocumentServices` | wallet 承認時に提案する DID Document の service テンプレート（`#didcomm` のみ）。`$mediatorUrl`／`$routingKid` を展開する |
| `mimiSelfBaseUrl` | **未使用**（型と既定値だけ残る） |

本番の `config.json` には、他に `anchorBaseUrl`、`anchorOidcClientId`（Anchor 削除後の**残骸**）がある。

### 15.2 本番の構成（v2、Debian 12、x86_64）
- Caddy（`/etc/caddy/Caddyfile`、did.md の deploy と共有。**biset の `deploy.sh` は Caddyfile を触らない**）:
  `mediator.biset.md` → `127.0.0.1:8791`（WebSocket の upgrade も Caddy の `reverse_proxy` がそのまま通す）、
  `t.biset.md` → `/opt/biset/app`（`/wallet/callback` は `index.html` に書き換え、`/api/rp-signer/*` は `127.0.0.1:8794`）、`biset.md` → `/opt/biset/home`。
- systemd: `biset-didcomm-mediator.service`（`DynamicUser`、`/opt/biset/didcomm-mediator/`）、`biset-rp-signer.service`、`did-md-mail-relay.service`（`/opt/did-md-mail-relay/`）。
- tor: `/etc/tor/torrc` の Hidden Service は 2 つ。`/var/lib/tor/biset-mediator/` → `127.0.0.1:8791`。**秘密鍵を失うと `.onion` が変わり、公開済みの DID Document がすべて古くなる**。
- mediator の DB は `/var/lib/biset-didcomm-mediator/mediator.sqlite`。mail-relay の DB は `/var/lib/did-md-mail-relay/relay.sqlite`。`deploy.sh` は mediator の入れ替え前に `sqlite3 .backup` で `/var/backups/biset-didcomm-mediator/` へ退避する。

### 15.3 デプロイ（`deploy.sh`、git 追跡外）
`./deploy.sh [app|landing|didcomm-mediator|mail-plugin|smtp|ap|relay|tor-backup|all]`。
- `app`: build → `v2:/opt/biset/app/` へ `index.html` と `sw.js` → sha256 と公開 URL で検証。
- `tor-backup`: v2 の `/var/lib/tor`（キャッシュを除く）と torrc を、ローカルの `~/.biset-backups/tor/` に 0600 で退避する（暗号化は無い）。
- `didcomm-mediator` と `mail-plugin` は排他。**mail-relay には専用のターゲットが無く**、`bun run build:mail-relay` のバイナリを手動で入れ替えている。
- `smtp`／`ap` は biset repo の外の relay（Rust／Go）を配る。

### 15.4 2026-10-03 のデプロイの前提
mediator・app・mail-relay を**同時に**入れ替える。
- mediator の SQLite は**消さない**。自分の did:peer（`mediator_identity`）のテーブルは新旧で同じ形なので、そのまま引き継がれ、`routingKeys` は変わらない。
  新しい queue のテーブル（`did_states`、`inboxes`、`messages`、`deliveries`）は空で作られ、旧テーブル（`connections`、`connection_keys`、`queued_messages`、`received_acks`）は使われずに残る。
  旧 queue に残っていたメッセージは届かなくなる。各端末は起動時に登録し直す。
- 利用者は全員、did.md Wallet で再ログインが要る（wallet セッションの形が変わったため。古いセッションは読めずにログイン画面になる）。
- ブラウザの Vault（IndexedDB v15）は upgrade で旧 store を消す。

## 16. 検証状況

2026-10-03、作業ツリーで実測した。

| コマンド | 結果 |
|---|---|
| `bun run typecheck`（root ＋ mediator／mail-plugin／mail-relay／mimi／rp-signer） | ✅ すべて成功 |
| `bun run knip` | ✅ 成功 |
| `bun run reachability` | 本番の入口から 164／266 を到達、**テストのみ 23**（MLS／MIMI のクライアント側、`manifest.ts`、identity の fixture 用モジュールなど）、**どこからも到達しない 0** |
| `bun run test` | ✅ **104 ファイル、536 件成功、失敗 0** |
| `bun run check`（上の 4 つ） | ✅ 成功 |
| `bun run build` | ✅ `app.js` 567 KB、`sw.js` 183 B、`index.html` 705 KB |

テストは、canonical protocol、Vault の store、Vault Sync、VaultProjector、JMAP export／import、Markdown ミラー、
DIDComm の crypto（DIF のテストベクタを含む）／multi-device 配送／mediator（HTTP と WebSocket、本物の Bun サーバーでの upgrade を含む）／relationship／seed／乗り換え／group、
mail-plugin／mail-relay（DKIM を含む）、SQLite、SMTP、wallet の callback、JSON Schema、RP signer、MIMI を覆う。
**テストで store を偽装しない**方針を採る（モックが本物の検証を再現していなかったことで障害を取り逃がした反省による）。

## 17. 負債・不整合・整理対象

優先度の高い順ではなく、**事実として確認できたもの**を挙げる。

1. **DIDComm の仕様準拠の残り**: Coordinate Mediation 3.0 の名前（`recipient-update` など。現状は 2.0）、Discover Features（mediator の `max_receive_bytes` を問い合わせられないため、Vault Sync は 128 KB を決め打ち）、
   恒久的なエラーを再試行しない・恒久的に不正なメッセージを ACK して捨てる（P3）。`mail-bridge`／`external-feed` が didcomm.org の名前空間を使っている点は、対応しないと決めた。
2. **旧メール HTTP 経路**: relay の `/v1/mail/submit`（`submission-http.ts`）、did.md の authority API への依存、wallet 認可要求の `urn:biset:mail-relay:v1`。クライアントからは呼ばれない。
3. **`client/` が `server/` を import**（`client/mail/didcomm-submit.ts`、`client/didcomm/ingress-projector.ts` が `server/mediator/mail-plugin/mail-bridge.ts` を参照）。
   メールの wire 型が `server/` に置かれているため。`protocol/` へ移すのが筋。
4. **セッション復元の失敗が一律にセッション破棄になる**（§14.2-4）。
5. **file:// 版と https 版が別のアプリとして wallet に登録される**（§5.2）。**RP DID は `t.biset.md` に束縛**されており、ドメインを後から自由に変えられるという方針と衝突しうる。
6. **git の追跡**: `.gitignore` が `scripts/`・`ops/`・`tasks/`・`docs/`・`deploy.sh`・`home/`・`PLAN*`・`config.json` を除外している。**`bun run build` が使う `scripts/inline.mjs` が、clone から再現できない。**
7. **dedupe の `alreadyProcessed()` が常に false**（`main.ts`）。
8. **結線の無い UI と config の残骸**: `config-page.ts` の「New Relay」フォームと「Notifications」のトグル（`src.bak` の HTML を改変せずに移植する方針の結果で、意図した「空の UI」）。
   `mimiSelfBaseUrl` と config の `anchor*` も残骸。
9. **失敗した承認の残骸**: DID Document に、mediator に登録されていない端末鍵が残ると、その鍵にも暗号化される（受け取る受信箱が無いだけで害は無い）。biset 側で自動的に除く処理は無い。
10. **旧データの救出コード**: `legacy-crdt-migration.ts` と `store.ts` の旧 outbox の移行。後方互換を持たない方針なので、消してよい。
11. **`manifest.ts`**: テストだけが使う（🔧）。
12. **`PLAN-tor.md` と本書の差**: Tor の V-3（Tor Browser）、WebSocket の onion 経由の長時間維持、onion の rate limit の実測は未実施。

## 18. 実装状態の総括

| 領域 | 状態 |
|---|---|
| did:webvh の解決（`protocol/webvh/`） | ✅ |
| did.md Wallet login（RP DID／JAR、DCR、直接配送、DPoP 端末セッション、VC capability） | ✅ |
| DID Document の編集（merge、removeEndpoints）と、承認後の独立な検証 | ✅ |
| 端末集合＝`keyAgreement`、multiplexed encryption、端末ごとの受信箱 | ✅ ❓ 本番での複数端末の通し確認は未実施 |
| 端末を外す（DID 編集 → seed の作り直し → `from_prior` による乗り換え） | ✅ ❓ 本番での通し確認は未実施 |
| ローカルの暗号化 Vault（ログ層、schema v15） | ✅ |
| Vault Sync（自分の DID 宛て、PUSH／REQUEST／RESPONSE、有界応答、`missed` での追いつき） | ✅ |
| VaultProjector（per-entity LWW、tombstone、pending） | ✅ |
| JMAP export／import（平文、差分収束、`$imported`） | ✅ |
| Markdown ミラー | ✅ |
| DIDComm の front door／1:1／group chat／relationship／Trust Ping | ✅ |
| mediator（"A"、SQLite、所有の証明、端末上限、WebSocket の live mode、relay-poller） | ✅（本番は 2026-10-03 のデプロイで入れ替え） |
| メールの送信（DIDComm mail bridge）と受信 | ✅（did.md アドレスに限る。DKIM 未設定、送信状態の確定が未完） |
| Tor（onion の入口、opt-in の公開、入口の選択） | ✅ 公開と読み取り。❓ Tor Browser・WebSocket での実運用 |
| External Feed の受信 | ✅ 受信口のみ（送る bridge は未実装） |
| biset-mimi、`client/mls/`・`client/mimi/` | 🔧 将来の MIMI クライアントのために残す |
| 旧メール HTTP 経路 | ⛔ |
| ActivityPub の adapter、Web Push、オフライン起動 | 未実装 |

## 19. 次の作業

1. **2026-10-03 のデプロイ後の実機確認**: 2 台での登録・配送・Vault Sync、4 台目の拒否、「Remove other devices」と乗り換え、WebSocket（clearnet と onion）、メールの受信。
2. **DIDComm の仕様準拠の残り**（§17-1）: Coordinate Mediation 3.0、Discover Features と `max_receive_bytes`、P3（恒久的なエラーの扱い）。
   `didcomm` の参照実装（npm）を dev 依存にした相互運用テスト。
3. **旧メール HTTP 経路の撤去**（§17-2）。wallet への認可要求から `urn:biset:mail-relay:v1` を外すかを決める。
4. **セッション復元の失敗の分類**（§17-4）。transient な失敗でセッションを破棄しない。
5. **残骸の整理**: 旧データの救出コード、空の UI、`anchor*` の config、`client/`→`server/` の import（§17-3、8、10）。
6. **メールの完成**: 送信状態を `SEND_RESULT` で確定させる、outbox の永続 retry、DKIM、did.md 以外のドメイン。
7. **repo の追跡の整理**（§17-6）。`scripts/` と `ops/` を追跡に戻す。
8. **`main.ts` の boot wiring への統合テスト**。

## 20. `src/` の構成

トップレベルは **client／server／protocol** の三つ。**依存は一方向**で、`protocol/` と `server/` は `client/` を参照しない（機械的に検証できる。現状は成立）:

```bash
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*client/" src/protocol src/server --include='*.ts'
grep -rnE "^\s*import .*from '[^']*\.\./(\.\./)*server/" src/protocol --include='*.ts'
```

ただし `client/` → `server/` の import が 2 件ある（§17-3）。

### 20.1 `protocol/` — client と server が共有する wire 定義

| パス | 責務 |
|---|---|
| `canonical.ts`、`ids.ts`、`signing.ts`、`vault.ts`、`ingress.ts`、`mail-submission.ts`、`net-fetch.ts` | 正準 JSON、ID 型、署名対象、Vault の event 種別、外部 payload、`fetch` の束縛 |
| `didcomm/` | `crypto.ts`（JWE、multi-recipient、`didCommPost`）、`message.ts`（`return_route` を含む）、`peer.ts`（did:peer:2、relationship の決定論的導出）、`from-prior.ts`、`devicekid.ts`、`multikey.ts`、`problems.ts`、`forward-wrap.ts`、`trust-ping.ts`、`mediator-{protocol,coordinate,pickup,transport,device}.ts`、`webvh-route.ts`・`did-web.ts`（route と受信者の選択）、`webvh-resolve.ts`（sender 鍵の解決）、**`service-endpoint.ts`（endpoint 選択の唯一の所有者）**、`vault-sync-protocol.ts` |
| `webvh/` | `resolver.ts`、`log.ts`、`proof.ts`、`document.ts`、`identifier.ts`、`scid.ts`、`hash.ts`、`multihash.ts`、`multikey.ts`、`jcs.ts` |
| `mimi/` | MIMI の型・wire・authorizer・app-data（MIMI サーバーが使う） |
| `mls/` | RFC 9420 の vendored fork。**中身は変更しない**。現在の利用者は biset-mimi のサーバーだけ |

### 20.2 `client/app/` — 起動、配線、UI
`main.ts`（唯一の入口、全配線）、`sw.ts`、`ui/`（`shell`、`left-pane`、`thread`、`compose-page`、`account-page`、`account-create`、`account/{state,menu,config-page}`、`config`、`format`、`did-display`、`message/{message-view,body-text,rfc5322-headers}`）。
`ui/message/` は、DIDComm もメール形の read model に projection されるため、その**表示**に使う。

### 20.3 `client/store/` — Vault と projection
**`store/vault/`（ログ層）**: `store.ts`（IndexedDB）、`objects.ts`、`events.ts`、`active-segment.ts`、`segment-key-resolver.ts`、
`commit.ts`（共有 Vault 状態を書く全経路が通る組み立て地点）、`mutations.ts`／`mutation-records.ts`、`mail-message.ts`、`credential-store.ts`、`contact-key{,-reader,-sink}.ts`、`relationship-seed.ts`、
`delivery-pack.ts`、`ingress-ingest.ts`、`projector.ts`、`jmap-export.ts`、`markdown-{mirror,directory}.ts`、`legacy-crdt-migration.ts`、`projection-rebuild.ts`、`blob-reader.ts`、
`openpgp-credential.ts`、🔧 `manifest.ts`。詳細は `store/vault/README.md`。
**`store/projection/`（read model）**: `gateway.ts`（`LocalJmapGateway`）、`reducer.ts`、`indexeddb.ts`、`mutations.ts`、`vault-mutation-sink.ts`、`transport.ts`（型のみ）。

### 20.4 `client/didcomm/`
`send-message.ts`（relationship 経由の送信、`answerTrustPing`）、`front-door-send.ts`、`relationship.ts`（wire）、`relationship-seed-bootstrap.ts`、`basicmessage.ts`、`ingress-projector.ts`、
`group-chat{,-store}.ts`、`external-feed.ts`、**`vault-sync.ts`**、`mediator-sync.ts`（登録）、**`mediator-live.ts`**（WebSocket の live 受信）、
**`mediator-endpoints.ts`**（入口の別名、`sameMediatorUrl`、Tor 環境の判定）。

### 20.5 `client/identity/`・`client/mail/`・本番から外れた部分
- `identity/bootstrap.ts`（Vault 側の identity 境界）、`idkey.ts`。
- `identity/wallet/`: `did-md-oauth.ts`（wallet の承認、capability、DID 編集、端末の削除）、`did-md-store.ts`（セッションの封印）、`relationship.ts`、`relationship-rotation.ts`、
  `didcomm-outbox.ts`、`wallet-directory.ts`、`json-schema.ts`＋`schemas/biset-messenger-capability.schema.json`、`did-document-edit-check.ts`。
- `identity/webvh/`（`log-io.ts` は現役。`freshFetch`／`fetchLogContaining`）、`identity/web/`・`create-genesis.ts`・`migrate.ts`（テストの fixture 用）。
- `mail/`: `rfc5322-builder.ts`、`didcomm-submit.ts`。
- `mls/*`、`mimi/*` は 🔧（将来の MIMI クライアント用）。

### 20.6 `server/`
- `mediator/`: `index.ts`（"A"）、`deployment.ts`（HTTP と WebSocket）、`server.ts`、`sqlite-store.ts`、`relay-poller.ts`、`signature.ts`、`rate-limit.ts`、`route-deliver.ts`、`validate.ts`。
- `mediator/mail-plugin/`: `index.ts`（"B"）、`listener.ts`、`smtp-socket-server.ts`、`mail-smtp-protocol.ts`、`bridge.ts`、`smtp-client.ts`、`dkim.ts`、`mail-submission-http.ts`、`mail-bridge.ts`／`mail-submission-wire.ts`。
- `mail-relay/`: `index.ts`、`agent-http.ts`、`did-document.ts`、`sqlite-store.ts`、`submission-http.ts`、`dkim-config.ts`。
- `rp-signer/index.ts`。
- `mimi/`: `index.ts`、`deployment.ts`、`http.ts`、`store.ts`、`mls-appsync.ts` ほか（§11.4）。

### 20.7 リポジトリ直下の補足
`dist/`（ビルド生成物。追跡されている）、`home/`（`biset.md` のランディング）、`src.bak/`（旧実装。参照用）、`pds/`（Bluesky PDS の配布物。biset のコードではない）、
`biset-*`（コンパイル済みバイナリ。`.gitignore` 対象）、`test/`（104 ファイル）。
