# Biset アーキテクチャ

> Coordinatorについては2026-08-29のv2再設計後、[ARC-coordinator.md](ARC-coordinator.md)を現行実装の正本とする。MLSについては[ARC-MLS.md](ARC-MLS.md)を現行実装の正本とする。本書に残る「Coordinator固有MLS」「VEK/current epoch wrapによるVault at-rest鍵管理」「per-device ACK」の記述は調査時点の旧設計であり、Coordinator v2には適用しない。

> 調査基準日: 2026-08-26（Asia/Tokyo）
> 調査対象: `~/biset` の commit `3237c8bb659b92c9a8333a63ad29ef651b9af1d3`
> 状態: 現行コードを正とした実装アーキテクチャ。将来案は明示的に区別する。

## 1. この文書の目的

Biset は、メールと DIDComm のデータを利用者の端末側で長期保管し、サーバーを恒久的なメールボックスやメッセージ履歴にしない通信クライアントである。本書は、現行コードの構成、信頼境界、暗号鍵、状態遷移、配送・復旧経路、運用方法、および未完成部分を一つの資料にまとめる。

リポジトリ直下の `PLAN.md` と `PLANIMPLEMENTATION.md` には実装経緯や将来計画も含まれる。本書ではそれらを参考にしつつ、実際に `src/` と `test/` に存在し、呼び出し経路へ接続されているものを「実装済み」と判定する。クラスやテストだけが存在し、ブラウザの起動経路へ未接続のものは「部品実装済み」とする。

## 2. 設計原則と非目標

### 2.1 原則

- 長期正本は各 endpoint の暗号化 Vault であり、core や DIDComm mediator ではない。
- core が保持するのは、公開 identity 情報、端末 roster、MLS 配送状態、および TTL・quota 付き暗号文バッファに限る。
- UI と保存層の間には JMAP 形のローカル API を置き、暗号方式を UI へ漏らさない。
- MLS は会話の暗号化には使わず、同じ identity の信頼済み端末集合と Vault Epoch Key（VEK）の導出境界に使う。
- 外部 ingress を ACK するのは、端末で検証・暗号化・永続化が完了した後だけとする。
- 復旧に必要な履歴本体を core に置かず、信頼済み peer または利用者管理の暗号化 archive から取得する。
- did:webvh の SCID を identity の安定した識別子として扱い、ドメイン移転で self-group や配送列を分断しない。

### 2.2 現行スコープ外または未完成

- MLS による複数人チャット。MLS application message は通常メッセージ配送に使用しない。
- ActivityPub の実動 adapter。protocol enum に値は残るが、adapter、UI、配送経路はない。
- サーバー側の mailbox、全文検索、履歴 API、添付 archive。
- 完全な JMAP server。ローカル gateway は UI が必要とする最小メソッドだけを実装する。
- OpenPGP を用いた実際のメール送信時暗号化と UI での受信復号。
- Web Push。Service Worker は install/activate のみで、通知・バックグラウンド同期を行わない。

## 3. システム全体像

```text
┌──────────────────────── Biset Client（ブラウザ） ────────────────────────┐
│ UI ─ Local JMAP Gateway ─ Projection                                    │
│                  │                                                       │
│        IndexedDB Vault（暗号文 object + 署名 event + key wrap）          │
│                  │                                                       │
│   did:webvh / MLS self-group / Mail / DIDComm / Restore endpoint logic  │
└───────────────┬──────────────────────────────┬────────────────────────────┘
                │ signed narrow HTTP           │ DIDComm v2 encrypted HTTP
                ▼                              ▼
┌──────────────── Biset Core ─────────────┐  ┌── Standalone Mediator ─────┐
│ did.jsonl / did.json / routing.json     │  │ did:peer identity          │
│ trusted-device roster / MLS DS          │  │ Coordinate Mediation 2.0   │
│ bounded ingress / vault delivery        │  │ Routing 2.0 Forward        │
│ restore control only / SMTP in & out    │  │ Message Pickup 3.0         │
│ SQLite: bounded/public state only       │  │ bounded blind JWE queue    │
└───────────────┬─────────────────────────┘  └────────────────────────────┘
                │ SMTP / DNS MX
                ▼
          外部メールシステム
```

Bisetの目標構成は四つの主要コンポーネントである。

1. **Anchor** — `src/anchor/index.ts` を入口とするidentity provider。公開DID/domain/addressとOIDCを担当する。
2. **Mediator** — transport protocolsの一時配送。現状のDIDComm実装は`src/mediator/index.ts`を入口とし、Mailは別adapter/storeとして分離する。
3. **Vault** — `src/main.ts`内で動くClient local storage。暗号化長期正本、projection、秘密、server間bindingを保持する。
4. **Coordinator** — `src/coordinator/index.ts`を入口とし、opaque Vault deliveryと複数端末間の永続性・収束を担当する。

`src/core/index.ts`は移行中のcompatibility compositionであり、最終構成の主要コンポーネントではない。`src/protocol/`は各境界が共有するwire schema、canonical encoding、ID、署名対象byte列を定義する。browser、anchor、mediator、coordinator、legacy coreは別々のTypeScript設定で型検査する。

Anchorの認証は二層である。third party、Coordinatorから見える外側は通常のOpenID Connect Authorization Code + PKCEである。そのOIDC authorization endpointが必要とするinteractive authenticationだけをOpenID4VP 1.0 Verifierが担当する。WalletはAnchor発行のholder-bound Login Credentialを提示し、Anchorは検証結果を内部principalへ変換してOIDC処理を再開する。

```text
Nextcloud / Forgejo / Coordinator / Biset Client
                     │ OIDC Code + PKCE
                     ▼
               Biset Anchor
          OIDC Authorization Endpoint
                     │ login required
                     ▼
          OpenID4VP Verifier (direct_post)
                     ▲
                     │ holder-signed vp_token
              Biset Login Wallet
```

Login CredentialのsubjectはrandomなAnchor account referenceで、DID、SCID、domain、mail address、`vaultId`、MLS memberを含まない。初回発行だけはcurrent did:webvh documentの`authentication` keyによるData Integrity proofでbootstrapする。このenrollment APIはBiset profileであり、OpenID4VPのpresentation flowと、将来必要になり得る完全なOpenID4VCI issuer実装を区別する。

## 4. 信頼境界

### 4.1 Client が信頼して保持するもの

- identity の master seed、Root Key、端末 MLS private state
- Vault の暗号文、署名 event、SegmentKey と wrap、JMAP projection
- identity 共有の DIDComm / OpenPGP 秘密 credential
- relationship ごとの非公開 DIDComm credential
- 復号済み本文と鍵を扱う実行時メモリ

Client は plaintext の最終処理点であり、侵害された client から既取得の秘密を取り戻すことはできない。MLS revoke は将来 epoch へのアクセスを止めるが、過去にコピー済みの DIDComm/OpenPGP 共有秘密や平文を消去する機能ではない。

### 4.2 Core を信頼する範囲

Core は可用性、順序付け、quota、SMTP 転送、公開文書の hosting を担う。Vault plaintext、SegmentKey、MLS exporter secret、OpenPGP private key を知る必要はない。

ただし、次の metadata は観測できる。

- identity、device kid、roster、MLS group/epoch と操作時刻
- SMTP envelope、接続元、宛先、メッセージ byte 数
- ingress と Vault delivery の頻度、サイズ、TTL、ACK 状態
- did:webvh、did:web mirror、routing.json の公開内容

SMTP ingress の `protectedPayload` は「core に対する E2EE」を意味しない。通常メールなら core は受信した raw RFC 5322 byte を見ることができる。core が保存する期間を短く限定する設計である。

### 4.3 Standalone mediator を信頼する範囲

Mediator は inner DIDComm JWE を復号しない blind queue である。一方、登録された recipient kid、接続、queue 数、時刻、送受信元 IP、外側 Forward の routing metadata は観測できる。継続会話では公開 did:webvh ではなく relationship 固有の `did:peer:2` を使い、公開 identity との直接相関を mediator の保存状態から外す。

### 4.4 外部 peer と archive

Peer restore は現在の MLS member による署名と current-epoch grant を要求する。Recovery archive は独立した 32-byte Recovery Key で AES-GCM 暗号化され、利用者自身が archive と鍵を別途管理する。Core は archive 本体も Recovery Key も保持しない。

## 5. Identity と did:webvh

### 5.1 Identity の生成

`createNewIdentity` は以下を一続きで実行する。

1. 32-byte master seed を生成する。
2. seed を 24-word BIP39 mnemonic として利用者に提示する。
3. SLIP-0010 の `m/0'` から Ed25519 Root Key を導出する。
4. subdomain ごとの did:webvh genesis を `/.well-known/did.jsonl` に作成する。
5. 端末固有の MLS KeyPackage / leaf signature key を生成し、`#device-{random}` verification method として追加する。
6. SCID 由来の MLS self-group を作成または external join し、core roster を反映する。
7. identity record と MLS state を IndexedDB に保存する。

メール address は独立して発行せず、`did:webvh:{scid}:{username}.{apexDomain}` の domain から `{username}@mail.{apexDomain}` を導出する。`routing.json.alsoKnownAs` にも best-effort で掲載する。

### 5.2 mnemonic によるログイン

Onboarding UI は入力 domain が既に resolve できる場合、signup から login へ切り替える。`restoreIdentity` は mnemonic から Root Key を再導出し、resolved document の最初の verification method と公開鍵が一致することを確認してから新しい端末 leaf を登録する。

現行 UI は `deliveryFloorForNewDevice = 0` を渡し、「唯一の端末を失った後の全面復旧」として扱う。しかし、Vault delivery の pull と archive/peer restore は boot path に接続されていないため、mnemonic login だけで過去の Vault 本体が復元されるわけではない。さらに複数端末が生きている identity に floor 0 で参加させると、コード内コメントが掲げる forward-secrecy 方針と衝突する。製品 UI 上の前提と protocol capability を明確に分ける必要がある。

### 5.3 公開文書

| 文書 | 内容 | 更新認可 |
|---|---|---|
| `did.jsonl` | hash chain、updateKeys、verificationMethod、move | did:webvh proof / current update key |
| `did.json` | 任意の did:web mirror | current did:webvh state による検証 |
| `routing.json` | DIDComm service/keyAgreement、mediator、alsoKnownAs、name、OpenPGP 公開鍵 | Root/current update key の Data Integrity proof |

`routing.json` は operational data を署名付き PUT で管理するが、did:webvh hash chain 自体には含まれない。DIDComm を有効化すると、signed log には `#routing` pointer が追加される。

### 5.4 Domain move

Identity は SCID を維持したまま新しい domain へ移転できる。`moveWebvhIdentity` は次を行う。

- 新 location に moved did:webvh log を作り、最後に old location に move を記録する。
- network self-group ID は SCID 由来のため変更しない。
- 新旧 location が同時に resolve できる狭い区間で、移転を実行する端末の MLS credential を新 DID prefix へ更新する。
- `routing.json` を新 location へ移し、埋め込まれた DID prefix を置換する。
- identity record、18 個の Vault object store、local MLS state row を新 DID key へ re-key する。
- DID を埋め込んだ既存 KeyPackage pool を clear し、次回補充させる。

Core roster、Vault delivery、self-group ID は raw DID ではなく SCID から得る stable identity key で管理し、移転で列を分割しない。

移転に関係しなかった sibling device は、boot 時の `adoptPendingMove` で old DID を resolve し、document の現在の `id` が異なれば local record を追従させる。追従は一回の boot につき一 hop である。複数回の移転中に中間 domain が廃止されると、自動追従できない。

### 5.5 署名鍵解決の三つの場所

同一の「この kid の鍵は正当か」という検査が三層に存在する。

- core HTTP/DS 認証: `core/identity/webvh-signing-key-resolver.ts`
- MLS Authentication Service: `mls/webvh-authentication-service.ts`
- DIDComm sender 解決: `didcomm/webvh-resolve.ts`

Domain move は document 内の DID prefix を一括変更するため、三者とも caller の古い完全 kid ではなく `#fragment` を current document の `doc.id` に結合して照合する。Core resolver は解決済み `(kid, key)` も process lifetime 中 cache する。DIDComm routing は old domain ではなく、verified log が示す current `doc.id` から取得する。

## 6. MLS self-group

### 6.1 用途

一つの identity に一つの MLS group が対応する。用途は次の二つだけである。

- 現在信頼されている device leaf の roster
- MLS exporter secret から current VEK を導出する暗号境界

メール本文や DIDComm Basic Message は MLS application message として送られない。端末間の内容同期には §9 の shared Vault delivery を使う。

Self-group ID は `SHA-256("biset-self-group/1 " + SCID)` で決定論的に導出する。復旧端末が lookup service なしで group を特定でき、domain move 後も同じ group を参照できる。

### 6.2 Lifecycle

- 最初の端末は group を作成し、external join 用 GroupInfo を直ちに公開する。
- 後続端末は RFC 9420 §11 external commit で参加する。
- boot 時に pending commit を反映し、accepted roster を core へ install し、KeyPackage pool を補充する。
- 他端末の revoke は Remove + 必須 UpdatePath の commit で行う。削除された端末は新 epoch の exporter secret を導出できない。
- epoch 更新時、旧 active segment を seal して新 segment を作り、旧 segment の同じ SegmentKey を current VEK で re-wrap する self-grant sweep を行う。

`maintainSelfGroup` は `main.ts` の末尾で identity ごとに呼ばれる。ただし UI の read/write setup より後であるため、boot 直後に古い epoch の segment を読む操作と競合し得る。コードは current-epoch wrap がなければ fail closed する。

### 6.3 Vendored ts-mls

`src/mls/vendor/` は ts-mls v1.6.2 の fork で、利用する ciphersuite を `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` に限定し、noble ベース HPKE を使う。主な差分は以下である。

1. 1 member Remove にも UpdatePath を必須化する security fix。
2. self-remove 後の無限走査回避と application sender leaf attribution。
3. Domain move のため、committer 自身の UpdatePath で credential を置換できる additive hook。

差分には `// biset:` marker があり、`src/mls/vendor/VENDOR.md` に記録される。同ファイルが言及する `test/mls-vectors.test.ts` は現行 tree に存在しないため、「RFC 9420 vector suite がある」という記述は現状と一致しない。`test/mls-core.test.ts` と `test/mls-crypto.test.ts` は存在し、fork の主要操作を検査している。

## 7. 鍵と秘密の一覧

| 鍵・秘密 | 単位 | 保存 | 公開・伝播 | 更新状況 |
|---|---|---|---|---|
| Master seed / 24-word Root Key phrase | identity | Client local `IdentityRecord` に hex 平文 | mnemonic を利用者が外部保管 | 自動 rotation なし |
| Root Ed25519 key | identity | Client local `IdentityRecord` に private key 平文 | did:webvh updateKeys、routing.json 署名 | pre-rotation で権限移行可能 |
| Spare/Sign Ed25519 key | rotation 世代 | アプリは永続保存せず phrase を一度表示 | hash のみ `nextKeyHashes` | 一回使用後に次世代へ |
| MLS leaf signature/private group state | device | MLS IndexedDB | public verification method、KeyPackage | MLS UpdatePath / credential migration |
| MLS HPKE leaf material | device/epoch | MLS state | MLS tree / KeyPackage | commit により更新 |
| VEK | identity + epoch | 永続保存しない | 同 epoch member が exporter から導出 | epoch ごとに変更 |
| SegmentKey | Vault segment | `vault_segments.segmentKey` に平文保存 | VEK で暗号化した signed wrap を同期 | key は固定、wrap を epoch ごとに更新 |
| Identity front-door DIDComm X25519 | identity | encrypted Vault credential **と** identity record の hex 平文 cache | routing.json、信頼済み端末へ Vault 同期 | rotation schema/UI なし |
| Relationship X25519 + Ed25519 | counterparty/世代 | encrypted `contact-key.set` Vault object | service-bearing `did:peer:2`、Vault 同期 | `supersedesKid` chain、UI rotation なし |
| OpenPGP private credential | identity | encrypted Vault object | 公開 certificate を routing.json、private を Vault 同期 | supersedes chain のみ、trigger なし |
| Recovery Key | archive | アプリ内に保存しない | 利用者が archive と別管理 | archive ごとに新規 |

重要な現状上の注意は二点ある。

第一に、`IdentityRecord` の master seed、Root private key、DIDComm private key は IndexedDB に平文で保存される。過去設計にあった WebAuthn PRF 由来鍵による at-rest sealing は未移植である。

第二に、`VaultSegmentRecord.segmentKey` も local IndexedDB に平文で保持される。Vault object と delivery payload は暗号化されるが、端末 local storage 全体が別鍵で封印されているわけではない。したがって、この構成は server compromise と配送経路上の漏洩を主に抑えるもので、browser profile / local IndexedDB を読み取れる攻撃者に対する at-rest protection は未完成である。

## 8. Vault

### 8.1 データモデル

Vault の長期正本は immutable な二種類の record からなる。

- **VaultObjectV1** — 32-byte SegmentKey と AES-256-GCM で暗号化した content-addressed object。nonce、AAD、ciphertext hash、plaintext length を ID に含める。
- **VaultEventV1** — actor device、actor sequence、kind、target、object reference、parents、timestamp を MLS leaf Ed25519 key で署名した event。event ID は canonical body と署名から導出する。

代表的 event kind は `message.add/edit/tombstone`、`mailbox.set`、`keyword.set`、`transport.result`、`didcomm.control`、`contact-key.set`、OpenPGP/DIDComm credential である。Raw RFC 5322 と JMAP metadata は別々の encrypted object として一つの `message.add` から参照される。

### 8.2 Segment と epoch

同一 segment の object は同じ random SegmentKey を使う。SegmentKey は current epoch の VEK で AES-GCM wrap され、grantor device の署名を付ける。Self-group epoch が変わると active segment を seal し、新 segment を作る。過去 segment は鍵自体を変えず、current VEK 向け wrap を追加する。

復号時は必ず current self-group state を読み、current epoch の有効な member が署名した wrap だけを受け入れる。古い epoch の wrap へ自動 fallback しない。

### 8.3 IndexedDB transaction

`biset-vault-core` database version 9 は、object、event、chunk、segment、key wrap、manifest、projection、JMAP state、各種 durable outbox/receipt/cursor、restore session、transport statusに加え、Clientだけが知るAnchor↔Vault↔Coordinator binding、private Vault MLS state、期限付きpending join KeyPackage秘密鍵を持つ。

Ingress commit、local mutation、Vault delivery ingest は、record、projection、JMAP state、次の network ACK/outbox を同一 transaction に書く。Network 送信に失敗しても、次回 retry すべき ACK または delivery intent が local に残る。重複 event/ingress は unique key と content hash で idempotent に扱う。

### 8.4 Projection

Local JMAP projection は cache/read model であり正本ではない。Reducer は event を決定論的順序で適用し、offline の競合を収束させる。壊れた projection は全 event/object を検証・復号して再構築できる。必要な current-epoch wrap が一つでもなければ部分結果を返さず失敗する。

Local garbage collection は実装されていない。Tombstone や completed outbox は一部削除されるが、長期 Vault record の compact/retention policy はない。

## 9. 配送モデル

### 9.1 外部 ingress

Mail または legacy DIDComm adapter は、宛先 identity、offer 時点の device snapshot、expiry、metadata/source evidence、payload hash、opaque payload を core ingress store へ積む。公開 HTTP は adapter offer を公開せず、認証済み device の `/v1/ingress/pull` と `/v1/ingress/ack` だけを提供する。

Pull は一端末に短い exclusive lease（既定 60 秒）を与える。端末は payload hash と protocol を検証し、Vault record、projection、ACK outbox を atomic commit してから署名 ACK を送る。ACK 後、core は payload を消去して tombstone だけを残す。

既定 quota は一 payload 25 MiB、identity あたり pending 100 MiB / 128 件。Mail ingress TTL は 30 日、legacy core DIDComm ingress TTL は 24 時間である。

### 9.2 Shared Vault delivery

一端末で確定した Vault mutation は、object/event/current key wrap を canonical `VaultDeliveryPackV1` にして Coordinator へ append する。Coordinator は append 時の Vault member snapshot を固定し、payload を一コピーだけ保存する。各 recipient の状態は ACK set と cursor だけである。

- 同じ `appendId` と hash の retry は同じ item を返す。
- 全 snapshot recipient が ACK しても、それだけでは payload body を消去しない。
- Client は全 event/object/SegmentKey を含む完全な暗号化 checkpoint を最新 cursor まで定期的に保存する。checkpoint が durable commit された後にだけ、covered sequence の delivery body を compact する。
- checkpoint 未作成の正本を TTL/quota だけで削除しない。quota 超過時は append を拒否し、Client の durable outbox に残す。
- 後から参加した device は OIDC owner 権限で opaque checkpoint を取得し、root phrase 由来の domain-separated KEK で復号してから delivery floor 以後の差分を pull する。

### 9.3 現行 Client の接続状態

Protocol、SQLite store、HTTP transport、projector、ACK/outbox、boot/poll loop はブラウザ製品経路へ接続済みであり、二端末への同一メッセージ配送を実機で確認した。`message.add` が直接transportとCoordinatorの二経路から届く場合は、base projectionに同一immutable metadataがあれば冪等化し、同一batch内の重複または異なるmetadataは競合として拒否する。

### 9.4 Restore

完全復元の正規経路は Coordinator checkpoint である。

1. Client は event/object と全 SegmentKey を canonical Recovery Archive snapshot にする。MLS exporter secret と device signing key は含めない。
2. root phrase と random `vaultId`、Coordinator origin から HKDF-SHA256 で recovery KEK を導出する。
3. fresh random data key で snapshot を AES-GCM 暗号化し、その data key を recovery KEK で wrapする。外側 envelope に DID/SCID/domain/mail address を含めない。
4. Coordinator は Vault ごとの最新 checkpoint を永続保持し、member署名・payload hash・covered sequence の単調性を検証する。
5. 新端末は Anchor OIDC の pairwise owner subject で Vault を発見・取得し、root phrase で復号、current epochへkey wrapを更新し、projection/cursorを再構築する。

既存memberがonlineでfresh OIDC sessionを持つ場合、pending KeyPackageはpollで自動承認される。全既存member不在でもdata復元は可能だが、MLS routing membershipのrecovery join/resetは未実装である。

これらの store、検証、import、projection rebuild は実装・テスト済みだが、`main.ts` と UI には export/import、peer approval、transfer、`restoreRequired` 処理が接続されていない。現行 UI で実行できる「restore」は mnemonic による identity/device 再参加までであり、Vault history restore ではない。

## 10. Local JMAP と UI

### 10.1 Local gateway

`LocalJmapGateway` は IndexedDB projection を JMAP 形で公開する。実装済みメソッドは以下である。

- `Mailbox/get`
- `Email/get`
- `Email/query`（mailbox filter、position、limit）
- `Email/set`（mailboxIds / keywords の限定更新）
- `EmailSubmission/set`（一回に一 create の同期的最小実装）
- local blob download と byte range

Session は `biset://local/...` URL を使い、account を read-only と宣言しているが、mutation sink が構成された場合は限定 write を受け付ける。JMAP changes、search、copy、identity、vacation response、完全な submission lifecycle は未実装である。

### 10.2 Remote JMAP

`RemoteJmapTransport` と `AccountRouter` は標準 `/.well-known/jmap` discovery、method call、blob range download、および `local-vault` / `remote-jmap` account type を実装する。ただし `main.ts` の実 UI は local records の先頭一件だけを選び、account switcher や remote account provisioning を構成しない。現時点では library capability であり製品機能ではない。

### 10.3 Boot sequence

Identity がある場合の主要順序は次のとおりである。

1. 以前の interval / mediator poll を停止する。
2. identity、MLS、Vault IndexedDB を開く。
3. domain move を passive adoption する。
4. 最初の identity で read model と account UI を構成する。
5. core 設定と device kid があれば Vault mutation boundary を作る。
6. DIDComm と OpenPGP credential を best-effort で provision する。
7. compose/reply、mail ingress、mediator poll を構成する。
8. inbox を描画し、ingress を直ちに同期する。
9. ingress を 10 秒間隔で poll する。
10. 最後に全 local identity の MLS maintenance を行う。

Core 設定がなければ UI は local projection の read-only viewer として起動する。

## 11. Mail transport

### 11.1 受信

Core は Bun TCP listener 上に byte-oriented SMTP state machine を構成する。EHLO/HELO、MAIL、RCPT、DATA、RSET、NOOP、QUIT、STARTTLS を扱い、25 MiB 制限を広告・強制する。SMTPUTF8 と AUTH は提供しない。宛先 `{user}@mail.{apexDomain}` を `{user}.{apexDomain}` の did:webvh identity と roster へ解決し、raw RFC 5322 byte を変更せず ingress へ積む。

TLS certificate/key が設定されれば STARTTLS を提供する。未設定でも server は起動し、plaintext SMTP となる。接続元、HELO、envelope sender、TLS 使用有無を source evidence として保存する。

Client は ingress を pull し、raw message と表示 metadata を Vault に確定する。MIME 全体を構造化するのではなく、bounded header summary と本文表示のための最小処理を行う。

### 11.2 送信

Client はまず local Vault に outbox message を commit する。`EmailSubmission/set` は device leaf key で raw RFC 5322、MAIL FROM、recipient、時刻を署名し、`/v1/mail/submit` へ送る。Core は current roster と did:webvh 公開鍵で認証してから MX lookup と SMTP delivery を行う。

成功時は `transport.result` と `mailbox.set(sent)` を Vault に記録する。失敗時は temporary-failure として outbox に残すが、自動 retry scheduler と DSN はない。複数 domain の一部失敗も全体を temporary-failure に畳むため、recipient 単位の再送制御は未実装である。

### 11.3 OpenPGP

実装済みの endpoint primitive は、OpenPGP credential 生成、Vault への private key 保存、routing.json への public certificate 公開、RFC 3156 encrypted packet 抽出、packet 復号と署名検証である。

一方、`main.ts` の compose/send は常に plaintext RFC 5322 を構築し、recipient public key 解決や encrypt/sign を呼ばない。受信 UI も OpenPGP decrypt primitive を呼ばない。よって現在の OpenPGP は **鍵 provision と検証済み部品まで** であり、実際の mail E2EE は製品経路に未接続である。Autocrypt header の生成・peer state もない。

## 12. DIDComm

### 12.1 Public front door

Boot 時、最初の端末が identity-shared X25519 credential を Vault に作り、routing.json の一つの `keyAgreementVerificationMethod` として公開する。Sibling は同じ encrypted credential を shared Vault delivery から読む設計である。Mediator URL が設定されていれば各 mediator へ Coordinate Mediation 2.0 で登録し、成功した endpoint だけを DIDCommMessaging service として公開する。全 mediator が失敗した場合は legacy core `/v1/didcomm/ingress` を fallback とする。

Identity front-door key は新規関係の発見と `RELATIONSHIP_INIT` だけに使う。

### 12.2 Private relationship

初回送信者は relationship 専用 X25519/Ed25519 pair と service-bearing `did:peer:2` を生成し、その peer kid を mediator に **INIT より先に** 登録する。受信者も専用 peer identity を生成・登録し、双方の公開情報と自分の秘密鍵を encrypted `contact-key.set` として保存し、登録済み initiator peer へ `RELATIONSHIP_ACCEPT` を返す。

確立後の Basic Message 2.0 は relationship kid 間の authcrypt だけを使う。継続 JWE と mediator connection owner に公開 did:webvh front-door kid を含めない。Current relationship credential は boot 時に Vault から読み、peer kid ごとに mediator poll を再開する。

Handshake pending state は `main.ts` の二つの `Map` にのみ存在し、60 秒 timeout がある。INIT 後 ACCEPT 前に reload/crash すると private pending key と promise を失い、queue に届いた ACCEPT を復号できない。この状態の durable 化または再開始 protocol が必要である。

### 12.3 暗号形式

- Authcrypt: `ECDH-1PU+A256KW` + `A256CBC-HS512`
- Anoncrypt Forward: `ECDH-ES+A256KW` + `A256CBC-HS512` を生成し、受信は `XC20P` も許容
- 任意の hybrid authcrypt: X25519 + ML-KEM-768 を独自 alg identifier で KDF に混ぜる

Hybrid は recipient routing に ML-KEM key がある public-DID path の primitive として存在する。Relationship credential schema は X25519/Ed25519 だけで、継続 private relationship は ML-KEM hybrid を使わない。

### 12.4 Mediator

Standalone mediator は自身の did:peer identity、connection keylist、queue を file に保存する。Coordinate/Pickup request は DIDComm authcrypt の sender X25519 keyで認証する。did:webvh sender は公開 routing を resolve し、did:peer sender は self-certifying DID から鍵を得る。Relationship peer の Ed25519 key は DID に含まれるが、Coordinate/Pickup に別 Ed25519 signature は付けない。

Queue は recipient kid あたり最大 256 件、保持 30 日で、満杯時は古い正当 message を捨てず sender を拒否する。Pickup は non-destructive delivery の後、`messages-received` ACK で削除する。Connection は最大 10,000、connection ごとに最大 32 kid。Replay guard は既定 10 分 / 50,000 ID、resolved key cache TTL は 10 分で stale-while-refresh 動作をする。

Queue と connection JSON の書き込み失敗は warning のみで、memory 上の成功を caller に返す。したがって disk full 時は process restart で message/registration を失う可能性がある。File 全体の同期書き換えであり、複数 process 共有や強い crash consistency は想定しない。

### 12.5 Legacy core DIDComm path

Core の `/v1/didcomm/ingress` と client の core ingress projector は残っており、mediator 未設定時の fallback になる。新しい独立 mediator path と二重に存在するため、運用時は routing.json がどちらを広告しているかを明示する必要がある。

## 13. Core API と保存状態

### 13.1 HTTP surface

| Prefix / path | 役割 |
|---|---|
| `/healthz` | 常時利用可能な health |
| `/.well-known/did.jsonl` | did:webvh log GET/PUT/POST |
| `/.well-known/did.json` | did:web mirror GET/PUT |
| `/.well-known/routing.json` | operational routing GET/PUT |
| `/v1/roster/*` | signed roster install/read |
| `/v1/mls/*` | group create、commit、external commit、GroupInfo、KeyPackage、delivery |
| `/v1/ingress/pull`, `/ack` | endpoint claim と durable ACK |
| `/v1/vault-delivery/append`, `/pull`, `/ack` | shared encrypted delivery |
| `/v1/restore/*` | request/offer/pull/cancel の control のみ |
| `/v1/mail/submit` | signed outbound SMTP submission |
| `/v1/didcomm/ingress` | legacy DIDComm ingress |

全 route に CORS `*`、許可 header `Authorization, Content-Type`、method `GET, POST, PUT, OPTIONS` を付ける。認証は CORS ではなく payload signature と current roster で行う。

### 13.2 Fail-closed composition

`DATABASE_PATH` がなければ core は health endpoint だけを公開する。Full deployment には `DATABASE_PATH` と `APEX_DOMAIN` が必須である。`WEBVH_DATA_DIR` を省けば public document route を公開せず、mail hello name がなければ library composition 上は mail submit route を公開しない。Optional component 欠落時に open relay へ fallback しない。

一つの SQLite database に roster、bounded ingress、Vault delivery、restore control、MLS DS を置く。Webvh/routing files は `WEBVH_DATA_DIR` に置く。Plaintext mailbox projection、private identity key、SegmentKey、MLS exporter secret は SQLite に置かない。

### 13.3 Hosting limits

- did.jsonl: request 1 MiB、identity ごと最大 10,000 entry / 16 MiB
- did.json と roster/restore/ingress control: 小さい bounded body
- routing.json: 1 MiB
- mail submit: 25 MiB

Core の expiry sweep は多くの場合 request 時に実行される。常時 timer/job による vacuum はなく、tombstone と SQLite file の物理縮小も運用者責任である。

## 14. 可用性、失敗、冪等性

- Client の local transaction を network ACK より先に行うため、response loss は再送で回復できる。
- Core append は append ID + payload hash、Vault store は event/object ID、mediator message ACK は message ID で冪等にする。
- Ingress lease により複数端末が同じ外部 body を同時処理しない。Lease expiry 後は別端末が retry できる。
- Core の TTL/quota gap は `restoreRequired` として明示し、空の catch-up と区別する。
- DIDComm mediator poll と core ingress poll は network error を log して次周期に retry する。
- Outbound mail temporary failure は durable outbox に残るが scheduler がないため、利用者操作なしには retry されない。
- OpenPGP / DIDComm provision、domain move adoption、MLS maintenance の一部は boot を止めない best-effort であり、警告が console にしか出ない。
- `routing.json` 更新は fetch-merge-put だが version/ETag compare-and-swap がなく、複数端末の同時更新で last-write-wins となり得る。

## 15. Security properties と限界

### 15.1 実装されている主な性質

- Vault object は authenticated encryption、content-derived ID、ciphertext hash で改ざんを検出する。
- Vault event と SegmentKeyWrap は current MLS member device の Ed25519 signature を要求する。
- Device revoke 後の新 epoch は UpdatePath により rekey され、removed member は将来 VEK を導出できない。
- Core は append caller に recipient snapshot を選ばせず、current roster から固定する。
- 新規端末は過去 delivery recipient へ遡及追加されない。
- External ingress ACK は durable Vault commit 後だけ送る。
- DIDComm mediator は未登録 recipient への open forwarding を拒否する。
- Relationship ごとの pairwise DID により、継続会話を公開 identity front door から分離する。
- Canonical encoding と domain-separated signing/hash labels を protocol 全体で使う。

### 15.2 未解消リスク

1. **Local secret at rest（高）** — master seed、Root private key、DIDComm private cache、SegmentKey が IndexedDB 平文。Passkey/WebAuthn PRF sealing が必要。
2. **Shared Vault pull 未接続（高）** — 製品 client で multi-device 同期と credential/relationship key 伝播が完結しない。
3. **DIDComm credential delivery decoder 不整合（高）** — protocol の `VaultEventKind` は `credential.didcomm.set` を含むが、`vault/delivery-pack.ts` の decode allow-list `eventKind()` はこれを含まない。Sibling が当該 pack を decode すると拒否するため、pull 接続前に修正と回帰 test が必要。
4. **Restore UI/boot 未接続（高）** — TTL gap や端末全損時に、実装済み peer/archive primitive を利用者が起動できない。
5. **Credential revoke gap（高）** — device revoke だけでは既取得の identity-shared DIDComm/OpenPGP private key を無効化できない。Rotation/republication/re-encryption policy がない。
6. **OpenPGP mail E2EE 未接続（中）** — 鍵を公開するため相手は暗号化可能だが、通常 UI が復号しない。公開 capability と製品挙動が一致しない。
7. **Relationship handshake 非永続（中）** — reload で ACCEPT を復号不能にする。
8. **DIDComm dedupe lookup 未接続（中）** — projector の `alreadyProcessed()` は常に false。同一 message ID は reducer conflict で拒否されるが、静かな idempotent skip ではない。
9. **Routing update race（中）** — ETag/CAS なし。複数端末同時更新で field loss の可能性。
10. **Domain multi-hop adoption（中）** — 一 boot 一 hop、中間 domain 廃止で停止。
11. **No background/push（運用）** — page が閉じている間は pull せず、30 日を越えると restore が必要。
12. **Mediator file persistence（運用）** — 単一 process/file 前提で、disk write failure を request failure にしない。

## 16. Protocol versioning

Wire record は原則 `version: 1` を持ち、decoder は shape、canonical serialization、hash、署名、identity/epoch binding を検証して fail closed する。Opaque ID は domain-separated hash または UUID として扱う。

互換性を保つ際は、TypeScript union に event kind を追加するだけでは不十分である。Wire decoder の allow-list、Vault reducer の explicit no-op/application rule、archive decoder、delivery projector、テスト fixture を同時更新する必要がある。`credential.didcomm.set` の不整合は、この cross-layer checklist が必要な実例である。

Legacy core DIDComm ingress と standalone mediator は並存している。廃止時には routing publication、client polling、core route、adapter test を一括で移行し、中途半端な二重 delivery を避ける。

## 17. Build、設定、運用

### 17.1 Client

- `bun run build` — `src/main.ts` と `src/sw.ts` を browser IIFE に bundle し、`scripts/inline.mjs` で `dist/index.html` に inline 化する。
- Runtime config — `window.__BISET_CONFIG__` の `apexDomain`、`coreBaseUrl`、`mediatorUrls`。
- `mediatorUrls` は未設定時空配列でlegacy core DIDComm pathへfallbackする。production configは`https://mediator.biset.md`を設定済みで、standalone mediatorへauthcrypt registration/pollする。

### 17.2 Core environment

| 変数 | 必須性 / 既定 |
|---|---|
| `PORT` | 既定 8787 |
| `DATABASE_PATH` | full deployment に必須。未設定は health only |
| `APEX_DOMAIN` | DATABASE_PATH と同時に必須 |
| `WEBVH_DATA_DIR` | public document hosting に必要 |
| `SMTP_PORT` | 既定 25 |
| `SMTP_HOSTNAME` | 既定 `0.0.0.0` |
| `SMTP_HELLO_NAME` | 既定 `mail.{APEX_DOMAIN}` |
| `SMTP_MAIL_DOMAIN` | 任意の受信 mail domain override |
| `SMTP_TLS_CERT_PATH`, `SMTP_TLS_KEY_PATH` | 両方あれば STARTTLS |

`bun run build:core` は Linux x64 向け standalone Bun binary を生成する。

### 17.3 Mediator environment

| 変数 | 必須性 / 既定 |
|---|---|
| `MEDIATOR_PUBLIC_URL` | 必須 |
| `PORT` | 既定 8791（8790のlegacy coreと衝突させない） |
| `MEDIATOR_DATA_DIR` | 既定 `./mediator-data` |

Data directory と JSON/private identity file は単一 instance だけが所有し、filesystem permission、backup、容量監視を運用で担保する。`bun run build:mediator` で Linux x64 binary を生成する。

## 18. 検証状況とコード品質

対象 commit で以下を実行し、成功を確認した。

- `bun run typecheck` — browser、core、mediator の三設定すべて成功
- `bun run build` — 成功。`app.js` 約 0.97 MB、inline HTML 約 1.07 MB
- `bun run test` — 133 個の `*.test.ts` file を serial 実行し、すべて成功

テストは canonical protocol、Vault crypto/store、ingress/delivery/restore、SQLite、MLS self-group、domain move、SMTP、OpenPGP primitive、DIDComm crypto/mediator/private relationship を広く覆う。一方、`main.ts` の boot wiring を browser E2E として網羅しておらず、「部品のテスト成功」と「製品経路への接続」を検出できていない箇所がある。

`bun run knip` は失敗する。現状の主な debt は unused file 6、unused dependency 4、unused devDependency 1、旧 `scripts/pkarr-smoke.mjs` の unresolved import 4、大量の unused export である。特に `@scure/bip32`、`bittorrent-dht`、`hash-wasm`、`jmap-jam` は dependency として宣言されるが knip 上未使用で、legacy migration の残骸を整理する必要がある。したがって `bun run check` は typecheck/test が正常でも knip で非 zero になる。

## 19. 実装状態の総括

| 領域 | 状態 | 判定 |
|---|---|---|
| did:webvh create/resolve/update/pre-rotation/domain move | UI まで接続 | 実装済み |
| MLS self-group、roster、revoke、VEK | UI/boot と core に接続 | 実装済み |
| Local encrypted Vault + JMAP projection | UI read/write に接続 | 実装済み |
| SMTP ingress/outbound | Core と UI に接続 | 実装済み（retry/DSN は未完成） |
| Core bounded ingress | 10 秒 poll に接続 | 実装済み |
| Shared Vault delivery | protocol/store/test/append あり、client pull なし | 部分実装 |
| Mnemonic login | identity/device join まで UI 接続 | 部分実装 |
| Anchor OpenID4VP login | Verifier、credential、session、Wallet enrollment/presentation、file bridge、OIDC PKCE callback/token検証 | 実装済み（consent UIは未実装） |
| Coordinator Vault provision / MLS DS | random vault/member ID、Vault専用MLS genesis、KeyPackage、atomic Commit/View/Welcome、OIDC主体束縛one-time invitation、Account参加UI、pending join再開 | 実装済み（QRは未実装） |
| Peer/archive restore | primitive と test あり、UI/boot なし | 部品実装済み |
| OpenPGP | key provision/publication/crypto primitive あり、mail path 未接続 | 部分実装 |
| DIDComm public front door + legacy core ingress | UI/boot に接続 | 実装済み |
| Standalone mediator | binary、protocol、poll、file persistence あり | 実装済み、deployment 設定なし |
| Private relationship DIDComm | UI send/receive と mediator E2E あり | 実装済み、pending durability なし |
| Multi-device product experience | pull/restore/account switching 不足 | 未完成 |
| Remote JMAP account | transport/router のみ | 部品実装済み |
| ActivityPub | adapter なし | 未実装 |
| Web Push / background sync | Service Worker shell のみ | 未実装 |

## 20. 推奨する次の作業順

1. OpenID4VPのconsent/account chooser UIとcredential管理/revoke UIを追加する。Verifier、session、永続provider compositionは実装済み。
2. 実装済みの二台目参加UIとcrash-safeなpending join再開を実機で通し、招待codeのQR表示を追加する。招待codeは`vaultId`を含まず、同じOIDC pairwise subjectだけがredeemできる。`file:` redirect URIは許可しない。
3. `restoreRequired`を専用UIへ接続し、Peer/Archive restoreを開始できるようにする。現在はsystem messageまでで止まる。
4. 二台目のVaultGroupView Add/Remove、opaque delivery、ACK、TTL gapからのrestoreを実機で通す。
5. Coordinator MLS DSのretention/GCとRemove workflowを完成させ、DID/SCID/domain/addressがCoordinator DBへ混入しないrelease gateをproduction DB/logでも通す。
6. Peer restoreとRecovery archive export/importをUIへ接続し、identity復旧と履歴復旧を分けて表示する。
7. Device revoke後のidentity/DIDComm/OpenPGP credential rotationをcrash-safeにする。
8. knip debtとlegacy dependency/scriptを整理し、`bun run check`をrelease gateとして通す。

## 21. 主要ソース案内

| 関心 | 主なファイル |
|---|---|
| Client composition | `src/main.ts`, `src/ui/*`, `src/ui/config.ts` |
| Identity lifecycle | `src/identity/bootstrap.ts`, `src/identity/record-store.ts` |
| did:webvh / Anchor | `src/identity/webvh/*`, `src/anchor/webvh/*`, `src/anchor/oidc*.ts`, `src/anchor/oid4vp.ts`, `src/oid4vp/*` |
| MLS | `src/mls/self-group.ts`, `src/mls/group.ts`, `src/mls/vendor/VENDOR.md` |
| Vault | `src/vault/store.ts`, `objects.ts`, `events.ts`, `crypto.ts`, `delivery-*`, `restore-*` |
| Local JMAP | `src/local-jmap/gateway.ts`, `reducer.ts`, `vault-mutation-sink.ts`, `indexeddb.ts` |
| Coordinator composition | `src/coordinator/index.ts`, `src/coordinator/deployment.ts`, `src/coordinator/app.ts` |
| Legacy Core compatibility | `src/core/index.ts`, `src/core/deployment.ts`, `src/core/app.ts` |
| SMTP | `src/core/adapters/mail-smtp-*`, `src/mail/*` |
| DIDComm | `src/didcomm/*`, `src/vault/contact-key*`, `src/vault/didcomm-*` |
| Standalone mediator | `src/mediator/index.ts`, `server.ts`, `queue.ts`, `connections.ts` |
| Wire schemas | `src/protocol/*` |
| Tests | `test/`, 特に `test/protocol/*`, `test/mediator-relationship-handshake.test.ts` |

---

この文書は「意図」ではなく上記 commit の現状を記録する。将来の変更でコードと本書が食い違った場合は、まず実行経路と wire compatibility をコード・テストで確認し、その後この調査基準 commit と実装状態表を更新する。
