# Biset Coordinator 現行アーキテクチャ

> 調査・更新日: 2026-08-29（Asia/Tokyo）  
> 対象: `~/biset` の現行worktreeおよびproduction `https://coordinator.biset.md`  
> 状態: Coordinator v2がproduction稼働中。v1は移行互換として残存。  
> この文書は将来計画ではなく、現時点の実装を正として記述する。

## 1. 結論

`biset-coordinator`は、同じ利用者が所有する複数のlocal Vaultを収束させ、端末喪失後にも暗号化Vaultを復元できるようにするサービスである。

現行v2の責務は、OIDC principalごとに次の三つを保持することだけである。

1. 一つのrandom `vaultId`
2. 一つの単調増加するopaque ordered log
3. 最新の完全暗号化checkpoint

Coordinatorは端末membershipを管理しない。端末集合、追加、削除、revokeはcore上のRFC 9420 Self Groupだけが管理する。Coordinator固有のMLS group、member、KeyPackage、Welcome、Invite、Approve、per-device fan-out、ACKはv2から除去された。

```text
                    Anchor
       OIDC Code + PKCE / refresh_token
                       │
                       ▼
┌──────────────── Biset Client / Device A ────────────────┐
│ DIDComm/Mail ingress → Local Vault → durable outbox     │
│ Self Group member                                      │
└───────────────────────┬─────────────────────────────────┘
                        │ append opaque mutation pack
                        ▼
              ┌── biset-coordinator v2 ──┐
              │ owner-scoped stream       │
              │ seq 1, 2, 3, ...          │
              │ latest checkpoint         │
              └──────────┬────────────────┘
                         │ pull after local cursor
             ┌───────────┴───────────┐
             ▼                       ▼
┌──── Device B ────┐       ┌──── Device C ────┐
│ Local Vault      │       │ Local Vault      │
│ projection       │       │ projection       │
│ local cursor     │       │ local cursor     │
└──────────────────┘       └──────────────────┘
```

## 2. コンポーネント境界

### 2.1 Coordinatorが行うこと

- OIDC bearer access tokenを検証し、pairwise subjectをowner keyとして使う。
- ownerに対応するdefault Vaultを作成または発見する。
- client-generated `appendId`を冪等性keyとして暗号化payloadを順序付ける。
- `after` cursorより後の保持中entryを返す。
- 完全checkpointを保存する。
- checkpointが覆った古いentry bodyを破棄可能にする。
- ownerの異なるVaultを404として隠す。
- payload byte数、checkpoint byte数、hash、sequence単調性を検査する。

### 2.2 Coordinatorが行わないこと

- DID、SCID、domain、mail addressの解決または保存
- device ID、MLS member、MLS epochの管理
- Self Groupへの端末追加・削除
- Vault eventの意味解釈、JMAP projection、message conflict解決
- plaintext、master seed、Root Key、SegmentKeyの保持
- device別recipient snapshot、fan-out、ACK追跡
- push通知
- 複数Coordinator間のconsensus

### 2.3 他コンポーネントとの関係

| コンポーネント | Coordinatorから見た役割 | 共有するもの |
|---|---|---|
| Anchor | OIDC issuer / authorization server | issuer、JWKS、pairwise subject、scope |
| Self Group / core MLS DS | 端末membershipの唯一の正本 | Coordinatorとは直接接続しない |
| DIDComm mediator | 外部messageの一時transport | Coordinatorとは直接接続しない |
| Mail mediator | SMTP互換transport | Coordinatorとは直接接続しない |
| Local Vault | 暗号化長期正本とprojection | opaque delivery pack、checkpoint |

Self GroupとCoordinatorは互いの内部状態を知らない。Root Keyで復元した新端末はSelf GroupへExternal Joinし、その後OIDC ownerとしてCoordinatorからVaultを復元する。Coordinator側のInvite/Approveは不要である。

## 3. 識別子と所有権

### 3.1 `vaultId`

`vaultId`は`vlt_`と256-bit random base64urlからなる。

```text
vlt_<43 base64url characters>
```

DID、SCID、domain、mail address、OIDC subjectから導出しない。Clientが変更されても、identityがdomain moveしても、同じVaultを参照できる。

### 3.2 owner subject

Coordinator SQLiteの`owner_subject`はAnchorがCoordinator client/sector向けに発行するpairwise OIDC subjectである。Anchor内部account IDやDIDそのものではない。

v2 schemaでは`owner_subject`にUNIQUE制約があり、一つのOIDC ownerにつき一つのdefault streamとなる。

### 3.3 device identity

v2 requestにはdevice IDを含めない。各端末のcursorはClient IndexedDBだけに保存する。サーバーから見ると、同じownerのどの端末がappend/pullしたかはapplication fieldとして区別されない。ただし通常のHTTP接続metadataやIP addressまでは秘匿されない。

## 4. 認証とsession

### 4.1 初回ログイン

ClientはAnchorに対してOpenID Connect Authorization Code + PKCEを実行する。Anchorのinteractive authenticationにはOpenID4VP presentationを使う。

Coordinator用access tokenは以下の性質を持つ。

- ES256 signed JWT
- `typ = at+jwt`
- `aud = Coordinator origin`
- `client_id`を拘束
- pairwise `sub`
- operation scopeを含む
- production既定TTLは5分

### 4.2 scope

| scope | v2での用途 |
|---|---|
| `vault.create` | default streamの作成・発見 |
| `vault.append` | entry append、checkpoint put |
| `vault.pull` | entry pull、checkpoint pull |
| `vault.group.install` | v1移行互換のみ |
| `vault.ack` | v1移行互換のみ |

### 4.3 refresh session

短命access tokenの失効でbackground pullが停止しないよう、標準OAuth 2.0 `refresh_token` grantを実装している。

- refresh tokenは端末localの`biset-wallet` IndexedDBにだけ保存する。
- access tokenはmemoryだけに保持する。
- refresh tokenは一回使用ごとにserverでconsumeし、新しいtokenへrotateする。
- refresh token既定TTLは30日。
- 通常boot時はlocal refresh sessionを発見し、popupなしでCoordinator streamを再開する。
- refreshが拒否された場合はlocal refresh sessionを消し、次回`Connect coordinator`でinteractive loginをやり直す。

このrefresh sessionはVault同期されない。各端末が一度ずつ明示ログインして取得する。

## 5. v2 HTTP API

すべてPOST、JSON、bearer認証付きである。CORSは`Access-Control-Allow-Origin: *`で、`file://` UIからも利用できる。

### 5.1 Default Vault

```http
POST /v2/vaults/default
Authorization: Bearer <token with vault.create>
Content-Type: application/json

{"version":2}
```

応答:

```json
{
  "version": 2,
  "vaultId": "vlt_...",
  "latestSeq": "20",
  "checkpointSeq": "17"
}
```

初回呼び出しではrandom Vaultを作る。既存v1 Vaultが同じownerにある場合は、新規作成せず既存`vaultId`と`latestSeq`をlazy adoptionする。

### 5.2 Append

```http
POST /v2/entries/append
Authorization: Bearer <token with vault.append>

{
  "version": 2,
  "vaultId": "vlt_...",
  "appendId": "sha256:...",
  "payload": "<base64url>",
  "payloadHash": "<SHA-256, base64url>"
}
```

Coordinatorはownerを確認し、`payloadHash`を再計算してから次のglobal sequenceを割り当てる。同じ`appendId`と同じhashの再送は同じseqを返す。異なるhashを同じ`appendId`へ結び付けると409になる。

### 5.3 Pull

```http
POST /v2/entries/pull
Authorization: Bearer <token with vault.pull>

{"version":2,"vaultId":"vlt_...","after":"17"}
```

応答は`after`より大きい保持中entry、`nextCursor`、stream headの`latestSeq`である。v2にはrecipientやACKがないため、同じownerの全端末が同じglobal streamを読む。

### 5.4 Checkpoint

```http
POST /v2/checkpoints/put
Authorization: Bearer <token with vault.append>

{
  "version": 2,
  "vaultId": "vlt_...",
  "coveredSeq": "20",
  "payload": "<base64url encrypted snapshot>",
  "payloadHash": "<SHA-256, base64url>"
}
```

```http
POST /v2/checkpoints/pull
Authorization: Bearer <token with vault.pull>

{"version":2,"vaultId":"vlt_..."}
```

`coveredSeq`はstream headを越えられず、既存checkpointより後退できない。同じseqへの複数uploadは、v2 checkpointが既に存在すれば最初のものを採用する。

### 5.5 Health

```http
GET /healthz
```

```json
{"ok":true,"service":"biset-coordinator"}
```

## 6. Client同期アルゴリズム

### 6.1 Local mutationからappendまで

Mail、DIDComm、UI操作でlocal Vault mutationがcommitされると、同じlocal transactionでdelivery outbox rowを作る。

```text
external ingress / local UI action
  → verify/decrypt transport message
  → create encrypted Vault object + signed event
  → update local projection
  → create durable delivery outbox entry
  → append to Coordinator v2
  → append accepted後にlocal outbox entryを削除
```

network failureやtoken refresh失敗時はoutboxを残す。次のpollまたは新しいmutation時に再送する。`appendId`が冪等性を保証するため、response消失後の再送でも重複sequenceを作らない。

### 6.2 Pullとingest

各端末は自分のIndexedDBに`(identityId, deviceId) → cursor`を保持する。

```text
read local cursor
  → pull(vaultId, after=cursor)
  → payload hashを再検査
  → VaultDeliveryPackを検証
  → encrypted objects/events/key wrapsをatomic commit
  → projectionを更新
  → local cursorを進める
```

現行ingest transactionはv1由来のlocal ACK outbox rowも作るため、v2 bridgeはcommit直後にその互換artifactを削除する。CoordinatorへACKは送らない。

### 6.3 Poll周期

Coordinator pollは10秒周期である。pushではないため、通常は最大10秒程度にnetwork/processing時間を加えた遅延がある。tabが完全に終了している間は同期せず、次回boot時にcheckpointとstream deltaからcatch upする。

### 6.4 第三者messageの複数端末配送

DIDComm mediatorまたはMail mediatorは、最初に一つのonline端末へmessageを渡すことがある。その端末がlocal Vaultへ保存したmutationをCoordinator streamへappendし、残りの全端末がglobal streamからpullすることで最終的に同じmessageを持つ。

したがって「transportが全端末へ直接fan-outする」設計ではない。Coordinatorがlocal Vault mutationを全端末へ収束させる。

## 7. Checkpointと復旧

### 7.1 内容

checkpoint plaintextは完全なRecovery Archive snapshotである。

- Vault manifest
- signed Vault events
- encrypted Vault objects
- 復号に必要なrandom SegmentKey集合
- snapshot作成時刻

plaintextはClient内でcanonical encodeされ、Coordinatorへ送る前に暗号化される。

### 7.2 checkpoint v2暗号

```text
recoveryKek = HKDF-SHA256(
  masterSeed,
  salt = SHA-256("biset/vault-recovery-kek/salt/v2", vaultId),
  info = "biset/vault-recovery-kek/info/v2"
)
```

実際のsnapshotはfresh random 32-byte data keyでAES-256-GCM暗号化し、そのdata keyを`recoveryKek`でAES-256-GCM wrapする。

AAD:

```text
{"label":"biset/vault-checkpoint/aad/v2","vaultId":...,"coveredSeq":...}
```

Coordinator URLはv2の鍵導出にもAADにも含めない。このため、同じ`vaultId`とRoot Keyを保ったままCoordinator operatorを変更できる。

### 7.3 新端末の復旧

```text
Root phrase login
  → did:webvh controlを確認
  → Self Group External Join
  → Anchor OIDC login
  → default vault discovery
  → latest checkpoint pull
  → Root-derived recoveryKekでdecrypt
  → objects/events/SegmentKeysをlocal Vaultへcommit
  → stable storage wrapsを生成
  → projectionを全再構築
  → local cursorをcoveredSeqへ進める
  → stream deltaをpull
```

既存端末のonline approvalは不要である。

### 7.4 compaction

checkpointが安全に保存された後、Coordinatorは`seq <= coveredSeq`のentry payloadをzero-length blobへ置換する。rowとsequenceは残るがbodyはcheckpointにsupersedeされる。

ACKでは削除しない。完全checkpointだけがretention/compaction境界である。

## 8. Vault at-rest暗号との関係

### 8.1 MLS epochからの分離

Vault objectはrandom SegmentKeyで暗号化する。SegmentKeyを保存・同期するwrapは、現在のSelf Group exporterではなくRoot phraseから決定論的に得る安定KEKを使用する。

```text
storageKek = HKDF-SHA256(
  masterSeed,
  salt = SHA-256("biset/vault-storage/salt/v2"),
  info = "biset/vault-storage/kek/v2"
)
```

stable wrap metadata:

```text
selfGroupId    = urn:biset:vault-storage:v2
sourceEpoch    = 0
recipientEpoch = 0
```

これにより次の操作は保存済みVault objectの可読性を変えない。

- Self Groupへの端末追加
- Self Groupからの端末revoke
- MLS epoch更新
- DID/domain move
- Coordinator URL変更

MLSは端末membershipと将来のConversation Group暗号に残るが、Vault at-rest key lifecycleを担わない。

### 8.2 Local保存

現行IndexedDBのsegment recordはrandom SegmentKey自体もlocalに保持する。stable wrapは複数端末同期およびcheckpoint復旧用である。passkeyによるlocal secret保護はUI項目があるものの、Vault全体のat-rest device encryptionとしては未完成である。

## 9. SQLite schema

v2が使用するtableは次の三つである。

```sql
CREATE TABLE vault_streams (
  vault_id TEXT PRIMARY KEY,
  owner_subject TEXT NOT NULL UNIQUE,
  latest_seq TEXT NOT NULL
);

CREATE TABLE vault_stream_entries (
  vault_id TEXT NOT NULL,
  seq TEXT NOT NULL,
  append_id TEXT NOT NULL,
  payload BLOB NOT NULL,
  payload_hash BLOB NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(vault_id, seq),
  UNIQUE(vault_id, append_id)
);

CREATE TABLE vault_stream_checkpoints (
  vault_id TEXT PRIMARY KEY,
  covered_seq TEXT NOT NULL,
  payload BLOB NOT NULL,
  payload_hash BLOB NOT NULL,
  created_at TEXT NOT NULL
);
```

sequenceはJSON安全性とuint64精度維持のためdecimal stringで保存する。SQLでの順序付けは`length(seq), seq`を使う。

## 10. v1からv2への移行

### 10.1 v1に存在したもの

- Vault固有MLS group
- `vault_members`
- member signature key
- MLS KeyPackage / transition / Welcome
- invitation / redeem
- recipient snapshot
- per-device ACK
- group epochに拘束されたappend/pull

この設計はSelf Groupと同じ端末集合を二重管理し、retryで孤児memberが生じ、Vault保存鍵をMLS epochへ結合していた。

### 10.2 現行migration

- v1 tableとAPIは削除していない。
- v1 `vaults.latest_seq`をv2 streamの初期headとして採用する。
- v1 checkpointはv2 checkpointがまだなければpull可能。
- v1 checkpoint envelopeは旧Coordinator origin拘束keyで復号できる。
- 次の完全同期時にportable checkpoint v2を同じseqへ書ける。
- UIはInvite、Approve、Join、Resumeを表示しない。
- Clientのactive経路はv2で上書きされる。

v1 APIはserverから物理的に削除されておらず、正しい旧scope/tokenを持つlegacy clientからはまだ呼び出せる。完全廃止は全Client migrationとbackup確認後の別作業である。

## 11. セキュリティ特性

### 11.1 Coordinatorが知る情報

- pairwise owner subject
- random `vaultId`
- stream sequence、entry数、size、時刻
- checkpoint sequence、size、時刻
- HTTP接続metadata

### 11.2 Coordinatorが知らない秘密

- master seed / Root Key
- recovery KEK / storage KEK
- SegmentKey
- object plaintext
- checkpoint plaintext
- MLS private state
- DIDComm private key

### 11.3 「opaque payload」の現在の限界

Checkpoint v2は暗号学的にopaqueであり、Coordinator operatorは中身を読めない。

一方、stream entryの外側payloadは現在`VaultDeliveryPackV1`のcanonical JSON byte列そのものである。Vault object bodyは暗号化されているが、pack内のidentity partition field、event envelope、object reference、key-wrap metadataなどは、Coordinator実装が意味解釈しないだけで、operatorがbyte列を解析すれば観測できる。

したがって現行streamの「opaque」はAPI責務上のopaqueであり、全metadataの暗号学的秘匿を意味しない。将来、Self Group MLS application messageまたは専用root-derived transport envelopeでpack全体を外側暗号化する余地がある。

### 11.4 bearer token

access tokenとrefresh tokenはbearer credentialである。端末local malwareや同一origin scriptに奪取されると、有効期間中はCoordinator ownerとして操作され得る。refresh tokenはrotateされるが、sender-constrained DPoP/mTLSではない。

## 12. 故障時の挙動

| 故障 | 現行挙動 |
|---|---|
| append network failure | local durable outboxを保持し再送 |
| append responseだけ消失 | 同じ`appendId`で冪等再送 |
| access token失効 | refresh tokenで自動更新 |
| refresh token失効/revoke | sessionを消し、明示Connectが必要 |
| Client crash中 | Coordinatorがentry/checkpointを保持、次回bootでcatch up |
| 一台だけがDIDCommを受信 | その端末がappendし、他端末はstream pull |
| checkpoint以前のentry body消去 | checkpointから復元後、後続deltaをpull |
| checkpointがない状態で履歴欠損 | 完全復元不能。現行v2は`restoreRequired`を返さない |
| Coordinator database喪失 | Client local Vaultは残るが、offline端末向け永続copyを喪失 |
| owner token漏洩 | opaque bytesのread/append/checkpoint上書きが可能。plaintext keyは得られない |

## 13. 現行の制約と技術的負債

1. v2 `pullStream`は現状server-side件数limit/paginationを持たず、保持entryを一括返す。
2. v2 entry retention quotaは未接続。checkpointが進まないとpayloadが蓄積する。
3. Caddy production設定のrequest body上限は2 MiBであり、application内の25 MiB entry / 100 MiB checkpoint上限より先に効く。
4. checkpoint upload条件はClient同期状態に依存する。常時online端末がない期間はcheckpoint headが遅れる。
5. Web Push/background Service Worker同期はなく、開いているtabの10秒pollまたは次回bootが必要。
6. 同一deviceで複数tabが同じrotating refresh tokenを同時使用する場合のcross-tab lockは未実装。
7. v1 runtime code、API、tableが残り、コード量と監査面を増やしている。
8. stream pack全体の外側暗号化は未実装で、一部metadataがCoordinator operatorから見える。
9. server-side checkpointのrollback防止は同じSQLite正本内の単調性に依存し、外部transparency logはない。
10. Coordinatorはavailabilityを保証する単一operatorで、replication/consensusはない。

## 14. Production構成

| 項目 | 現行値 |
|---|---|
| Public URL | `https://coordinator.biset.md` |
| Process | `/opt/biset/bin/biset-coordinator` |
| systemd | `biset-coordinator.service` |
| listen | `127.0.0.1:8792`相当、Caddy reverse proxy |
| SQLite | `/var/lib/biset-coordinator/coordinator.sqlite` |
| OIDC issuer | `https://biset.md` |
| UI | `https://t.biset.md`およびlocal `file://` build |

2026-08-29時点の移行直後production snapshot:

```text
v2 streams:          1
stream latestSeq:   20
v2 entries:          3  (seq 18..20)
checkpoint covered: 17
```

この値は運用中に変化するため、障害調査時にはSQLiteを再確認する。

## 15. 主要実装ファイル

| ファイル | 責務 |
|---|---|
| `src/coordinator/index.ts` | standalone process entrypoint |
| `src/coordinator/deployment.ts` | store、OIDC verifier、HTTP composition |
| `src/coordinator/app.ts` | HTTP routes、scope、CORS、error mapping |
| `src/coordinator/store.ts` | SQLite v1/v2 state machine |
| `src/coordinator/auth.ts` | OIDC JWT access-token verification |
| `src/protocol/coordinator-stream.ts` | strict v2 wire schema |
| `src/vault/coordinator-transport.ts` | browser-side HTTP client |
| `src/vault/coordinator-sync.ts` | outbox flush、pull、local cursor bridge |
| `src/vault/coordinator-checkpoint.ts` | v1/v2 checkpoint encryption |
| `src/vault/storage-root.ts` | stable Vault storage KEK derivation |
| `src/oidc/client.ts` | PKCE、JWT verification、refresh flow |
| `src/oid4vp/wallet-store.ts` | login credential、refresh session local store |
| `src/main.ts` | UI/Local Vault/Coordinator production wiring |

## 16. テストと検証

主な自動テスト:

- `test/coordinator/coordinator-stream-v2.test.ts`
- `test/coordinator/coordinator-checkpoint.test.ts`
- `test/coordinator/coordinator-http.test.ts`
- `test/coordinator/coordinator-auth.test.ts`
- `test/anchor/oidc.test.ts`
- `test/anchor/oidc-client.test.ts`
- `test/anchor/oidc-sqlite.test.ts`
- `test/vault-storage-root.test.ts`
- `test/protocol/identity-end-to-end-mail-sync.test.ts`

2026-08-29時点でfull test suite、全TypeScript targetのtypecheck、browser/Anchor/Coordinator buildが成功している。productionではAnchorとCoordinatorの`/healthz`、OIDC discoveryの`refresh_token` grant、binary/UI hash一致を確認済みである。

## 17. 現在の正本となる設計判断

1. MLSは削除しない。
2. Self Groupは同一identityの端末membershipを管理する。
3. 将来の第三者group chatは別Conversation Groupとして同じMLS基盤を使う。
4. CoordinatorはMLS membershipを持たない。
5. Vault at-rest keyはMLS epochから独立させる。
6. Coordinatorはowner-scoped logと完全checkpointだけを永続化する。
7. 新端末はRoot login → Self Group External Join → OIDC → checkpoint restoreで自動参加する。
8. compactionはACKではなく完全checkpointを境界にする。
9. v1は移行完了まで削除しないが、新機能を追加しない。

