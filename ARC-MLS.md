# Biset MLS 現行アーキテクチャ

> 調査・更新日: 2026-08-29（Asia/Tokyo）
> 対象: `~/biset` の現行worktree
> 状態: Self Groupは稼働中。Conversation Groupは基盤のみ。Self Group DSのCoordinator抽出とClient配線はworktreeで実装済み、production releaseは未実施。roster projectionだけは廃止済み`biset-core`境界に残存。
> この文書は将来計画ではなく、現時点の実装を正として記述する。

> 2026-08-29設計決定: MLSでClient処理できるものはすべてClientへ置き、Client単独では成立しないDelivery Service機能はCoordinatorへ移す。以下では現行実装と確定済み移行先を明示的に区別する。

## 1. 結論

「MLSはbiset-uiに完全に組み込まれているか」という質問には、次のように答えるのが正確である。

- **Biset Clientというブラウザアプリ全体を指すなら、ほぼYes。** MLS engine、private group state、leaf private key、KeyPackage private half、commit処理、暗号処理はClient bundle内で動く。
- **画面表示を担当するUI層を指すなら、No。** MLSは画面componentではなく、`main.ts`、identity bootstrap、Vault crypto boundaryから利用されるClient内部のsecurity subsystemである。
- **システム全体がClientだけで完結するわけではない。** Server側にはMLS Delivery Service、KeyPackage Store、公開roster projectionが必要である。DSとKeyPackage StoreはCoordinatorへ抽出済みで、公開roster projectionは廃止済み`biset-core`境界に互換実装が残る。ServerはMLS private stateやepoch secretを持たず、MLS payloadを復号しない。

現行production pathでMLSが実際に管理しているgroupは、同じdid:webvh identityに属する端末群の**Self Group**である。第三者とのgroup chatを暗号化する**Conversation Group**はまだ製品経路に接続されていない。

```text
┌──────────────────── Biset Client / browser bundle ────────────────────┐
│                                                                       │
│  UI ── main.ts ── identity/bootstrap ── Self Group orchestration      │
│                                      │                                │
│                                src/mls/group.ts                       │
│                                      │                                │
│                         vendored ts-mls / RFC 9420 engine              │
│                                      │                                │
│           IndexedDB: ClientState / KeyPackage private halves          │
│                                                                       │
│  Local Vault ── event/wrap signing and membership verification ───────┘
└──────────────────────────────┬────────────────────────────────────────┘
                               │ signed control request / opaque MLS wire
                               ▼
┌──────── Coordinator MLS DS (`coordinatorUrl`, `mls_ds_*`) ────────────┐
│ MLS Delivery Service: group epoch, claimed roster, commit log,        │
│ GroupInfo, Welcome, KeyPackage                                        │
│ MLS objectを復号しない / ClientState・leaf private keyを持たない       │
└───────────────────────────────────────────────────────────────────────┘

┌──── Legacy roster compatibility (`src/core`, `coreBaseUrl`) ──────────┐
│ Trusted Device Roster: ClientがSelf Groupから作った公開projection     │
└───────────────────────────────────────────────────────────────────────┘

┌──────────── Coordinator owner-scoped Vault stream v2 ────────────────┐
│ OIDC owner-scoped opaque stream + checkpoint                         │
│ Self Group/MLS membershipを知らない                                   │
└───────────────────────────────────────────────────────────────────────┘
```

## 2. 現在存在する三種類のMLS group

| 種類 | 状態 | member | 現在の用途 |
|---|---|---|---|
| Self Group | 稼働中 | 一つのidentityの各device leaf | 端末追加・revoke、公開rosterの正本、Vault event/wrap署名者の判定 |
| Conversation Group | 未接続 | 複数identityのdevice/memberを想定 | 将来の第三者group chat。暗号primitiveだけ存在する |
| Vault/Coordinator MLS Group v1 | 移行互換 | Coordinator固有random member | v2では不使用。旧API・DB・test・Client内部codeが残る |

Self Groupと将来のConversation Groupは同じRFC 9420 engineを共有できるが、**同じgroupではない**。Self Groupへ端末を追加したことが、第三者とのConversation Groupへ自動的に端末を追加することを意味してはならない。

## 3. MLSの現在の責務

### 3.1 担う責務

1. 一つのidentityに属する現在のdevice集合を、RFC 9420 group stateとして管理する。
2. device追加時にExternal Commitを行い、group epochを進める。
3. device revoke時にRemove CommitとUpdatePathを生成し、残存memberだけが次epochへ進めるようにする。
4. 各leafのBasicCredentialをdid:webvh verification methodへ結び付ける。
5. ClientがVault eventとSegmentKeyWrapへ署名するとき、現在のSelf Group memberのleaf署名鍵を使う。
6. Clientが受け取ったVault event/wrapを検証するとき、actor/grantorが現在のSelf Group memberか確認する。
7. Self Group stateから公開device rosterを生成し、現在はlegacy roster APIへ反映する。
8. 将来のConversation Groupに必要なMLS application message、Welcome、Add/Remove、exporterのprimitiveを提供する。

### 3.2 担わない責務

- DID documentそのもののhostingと更新
- Root phraseまたはRoot Keyの管理
- DIDComm envelopeの暗号化と配送
- SMTP/OpenPGP mailの暗号化と配送
- JMAP projection、message conflict解決、Local Vault永続化
- Coordinator v2の認証、stream、checkpoint、retention
- Vault contentのserver-side復号
- 現行の一対一DIDComm/message本文のMLS application message化

特に、**MLSは現在、普通のmessage配送channelではない**。Self GroupのDelivery Serviceが配送するのはSelf Groupのcommit/proposal/Welcomeであり、DIDCommやmailの本文ではない。

## 4. Client内部のレイヤー

### 4.1 MLS engine

`src/mls/vendor/`には`ts-mls v1.6.2`のforkを同梱している。npm packageをruntimeで呼ぶのではなく、Biset Clientのbundleへ直接含める。

使用ciphersuiteは一つに固定されている。

```text
MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
```

これはX25519、HKDF-SHA256、AES-128-GCM、Ed25519の組合せである。DIDComm側のPQ-hybrid transport cryptoとは別レイヤーであり、現行MLSはPQ suiteではない。

forkには少なくとも次のBiset固有変更がある。

- Removeが一人だけでも必ずUpdatePathを生成する修正
- self-remove処理の停止条件修正
- application message sender leaf indexの取得
- noble-based HPKE
- domain move時のown credential更新hook
- 未使用ciphersuiteとWebCrypto providerの削除

RFC 9420 vectorとremove security propertyはtestで検証している。

### 4.2 Biset向けMLS facade

`src/mls/group.ts`がvendored engineを直接触る唯一の主要境界である。

- group作成
- KeyPackage生成、encode/decode
- Welcome join、External Join
- Add/Remove/Update commit
- GroupInfo生成
- application message encrypt/process
- state encode/decode
- epoch exporter secret導出
- leaf credential/member列挙

MLS stateはimmutableとして扱い、各操作後に返された新しい`ClientState`へ置き換える。commitがDelivery Serviceに受理された後にのみ、retireされたkey materialをzeroizeする。

### 4.3 Self Group orchestration

`src/mls/self-group.ts`が一つのdid:webvh identityとMLS groupを対応付ける。

Self Group IDは次で決定論的に導出する。

```text
SHA-256("biset-self-group/1 " + SCID)
```

SCIDを使う理由は次の通りである。

- Root phraseからidentityを復元した端末が、別のgroup lookupなしで対象groupを特定できる。
- did:webvhのdomain move後もSCIDは変わらない。
- これはVault IDやmail addressの代用ではなく、「このidentity自身の端末group」を名付ける用途に限定される。

つまり、以前議論した「VaultをSCIDから導出しない」という決定と矛盾しない。Coordinatorの`vaultId`はrandomであり、Self Group IDだけがSCID由来である。

### 4.4 Identity bootstrapとの接続

`src/identity/bootstrap.ts`が、Root authorityとSelf Groupを接続する。

新規identityでは次が起こる。

```text
master seed
  → Root Key
  → did:webvh genesis
  → random device leaf key / KeyPackage
  → leaf public keyをDID verificationMethodへ追加
  → Self Group作成
  → GroupInfo公開
  → legacy roster APIへgenesis projection
```

Root phraseによる新端末loginでは次が起こる。

```text
root phrase
  → Root Keyを再導出
  → 対象domainのDID documentのRoot公開鍵と照合
  → 新device leaf keyを生成
  → Root KeyでDID verificationMethodへ追加
  → GroupInfoをpull
  → RFC 9420 External Join
  → 新ClientStateをIndexedDBへ保存
```

このため、現行設計では**有効なRoot phraseを持つ端末は既存端末の手動approveなしでSelf Groupへ参加できる**。Root phraseによるDID control証明がadmissionである。

### 4.5 Boot maintenance

`main.ts`の`bootClient()`は各local identityについて`maintainSelfGroup()`を実行する。

- Coordinator Self Group DS endpointからpending commitをpullする。
- 自分の`ClientState`へ順番に適用する。
- epochが進んだ場合はIndexedDBへ保存する。
- Self Groupのmember listをlegacy trusted rosterへ反映する。
- 自分のKeyPackage poolを5個まで補充する。
- 古いVault wrapの修復・安定保存鍵へのmigrationを行う。

現時点ではこのmaintenanceは主にboot時であり、Self Group commitの常時poll loopではない。

## 5. Clientに保存するMLS情報

### 5.1 Self Group state

IndexedDB database:

```text
biset-mls-self-group
  self-group-state
```

identity IDをkeyに、次を保存する。

- `selfGroupId`
- encodeされたMLS `ClientState`
- 更新時刻

`ClientState`には公開treeだけでなく、この端末が次epochへ進み、message/commitを処理するためのprivate stateが含まれる。これはcacheではなく秘密の永続状態である。

### 5.2 KeyPackage private halves

別IndexedDB databaseを使う。

```text
biset-mls-keypackages
  own-key-packages
```

各recordはKeyPackage reference、device kid、public wire、private package、作成時刻を持つ。KeyPackageは一回使用であり、Welcomeを開くと対応するprivate halfをconsumeして削除する。

Self Group state、KeyPackage store、Local Vaultを別databaseにしているため、それぞれのmigration boundaryは独立している。

## 6. CredentialとAuthentication Service

Self Group leafのBasicCredentialはdeviceのDID URLである。

```text
did:webvh:<SCID>:<domain>#device-<random>
```

`src/mls/webvh-authentication-service.ts`はcredentialを次のように検証する。

1. credentialからDIDとfragmentを読む。
2. did:webvh logをresolveし、hash chainと署名を検証する。
3. current DID documentの同じfragmentを持つ`verificationMethod`を探す。
4. そのEd25519公開鍵とMLS leaf signature public keyが一致するか比較する。

単に「DID documentに同じkid文字列がある」だけではなく、leafが実際に持つ公開鍵との一致まで確認する。

domain moveではDID prefixが変わるため、fragmentを安定部分としてcurrent documentへ対応させる。移転を実行するdevice自身のleaf credentialはUpdatePathで新DID prefixへ更新し、他deviceの旧prefix leafもSCID同一性の範囲で検証可能にしている。

## 7. Server側のMLS Delivery Service

Server側の`SqliteMlsDeliveryService`はRFC 9750におけるDelivery Service相当の役割を持つ。現在の実装はSelf Group専用profileであり、roster entryはidentityではなくdevice kidである。

これは**独立した`MLS server`でも、現行の正式な`biset-core`サービスでもない**。正式な所有者はCoordinatorであり、実装は次へ移動した。

- `src/coordinator/mls-delivery-store.ts`
- `src/coordinator/mls-delivery-authorizer.ts`
- `src/coordinator/mls-delivery-http.ts`
- `src/mls/coordinator-mls-delivery-transport.ts`

新規作成、restore、boot maintenance、revoke、domain moveは`coordinatorUrl`をMLS DS originとして使用する。`mlsDeliveryBaseUrl`は必須であり、`coreBaseUrl`へのfallbackはない。旧coreのMLS route、store、transport aliasは削除した。roster APIだけは引き続き`coreBaseUrl`を使う。

旧coreのSelf Group履歴は移行しない。Coordinatorは空の`mls_ds_*` tableを正本として開始し、旧DBを参照しない。具体的な稼働確認手順は`ops/RUNBOOK_biset-coordinator-mls.md`を正本とする。

保持するもの:

- group IDとidentity ID
- current epoch number
- current rosterとever-member集合
- bounded commit/proposal/Welcome log
- latest GroupInfo
- pending self-removal
- public KeyPackage

保持しないもの:

- `ClientState`
- leaf signature private key
- HPKE private key
- epoch secret、exporter secret
- application plaintext
- Vault SegmentKey、Root Key、master seed

主要HTTP APIは次である。

```text
POST /v1/mls/group/create
POST /v1/mls/commit/submit
POST /v1/mls/commit/external
POST /v1/mls/group-info/pull
POST /v1/mls/deliveries/pull
POST /v1/mls/keypackage/publish
POST /v1/mls/keypackage/take
POST /v1/mls/keypackage/drop
POST /v1/mls/keypackage/count
POST /v1/mls/self-remove/submit
POST /v1/mls/pending-removals/clear
POST /v1/mls/groups-for
```

control requestはdevice leafのEd25519 private keyで署名し、serverはDID documentから公開鍵をresolveして検証する。

Delivery ServiceはMLS wire objectを復号・parseしない。通常commitについては、現在のDS rosterにいる署名済みsenderとepoch一致を確認し、最初に届いたcommitを受理する。外部joinは`senderKid`がrequestの`identityId`に属し、そのDID keyで署名できることを確認する。

Server上のDS rosterは、最後のsenderが申告したrouting用bookkeepingであり、MLS暗号stateそのものではない。MLS commitの暗号学的検証は各Clientが`processIncoming()`するときに行う。

## 8. Self Groupからlegacy rosterへのprojection

廃止済みCoreの互換実装には、MLS DS内部rosterとは別に`TrustedDeviceRoster`が残っている。

Clientは、自分が暗号学的に処理したSelf Group stateから次の公開projectionを作る。

```text
AcceptedSelfGroupProjectionV1
  identityId
  selfGroupId
  epoch
  devices[]
    deviceId
    signingKeyId
    deliveryFloor
```

このprojectionはlegacy互換経路の次の処理で使われる。

- DIDComm ingressのrecipient device snapshot
- mail ingressのrecipient device snapshot
- 旧Vault delivery pull/ackのdevice authorization
- peer restore request/offerのdevice authorization
- live deviceだけを対象にしたKeyPackage取得

genesis以外のprojection更新は、**一つ前のlegacy rosterですでにtrustedだったdevice**の署名を要求する。External Joinした新deviceは自分自身を直ちにtrusted rosterへ追加できない。既存deviceがcommitをcatch-upし、次のboot maintenanceでprojectionをinstallする必要がある。

このprojectionは公開control-plane stateであり、Coordinator v2のowner-scoped streamとは接続していない。

## 9. MLSとLocal Vaultの現在の関係

### 9.1 MLSがまだ担う部分

Vault eventはactor deviceのMLS leaf Ed25519 keyで署名する。SegmentKeyWrapもgrantor deviceの同じkeyで署名する。受信側はcurrent Self Group stateから該当deviceの公開鍵を得て検証する。

したがってSelf Groupは現在、Vaultに対して次の問いに答えるauthorization boundaryでもある。

```text
「このmutation/wrapを作ったdeviceは、現在このidentityのmemberか」
```

Local Vaultのreader/writerを構築するにもSelf Group stateが必要である。MLSは単にAccount画面のdevice listを作る補助ではない。

### 9.2 MLS epochから分離済みの部分

Coordinator v2への再設計に伴い、Vaultの長期at-rest復号能力はMLS exporter epochへ依存しない形へ移行した。

- Vault objectはrandom SegmentKeyで暗号化する。
- SegmentKeyの安定wrap用KEKはmaster seedからdomain-separated HKDFで導出する。
- 安定storage group IDは`urn:biset:vault-storage:v2`、epoch labelは`0`である。
- DID、SCID、domain、server、device、MLS epochには依存しない。
- Coordinator checkpointはRoot phraseを持つ新端末が復号・復元できる。

旧current-epoch VEK wrapとre-wrap処理はmigration・peer restore互換としてまだ残っており、readerも安定wrapがない場合に旧MLS epoch wrapへfallbackする。したがってcodeは完全に整理済みではないが、**保存鍵の正本をMLS epochにする設計は現行v2 pathでは廃止済み**である。

### 9.3 Revokeの意味

Self Group Remove Commitは、removed leafが将来のSelf Group epoch secretを得ることを防ぐ。またCore rosterが追随すれば、mediatorの新しいfan-outや旧device API authorizationからも外れる。

ただし次は別問題である。

- 端末がすでに保存・復号した過去plaintext
- 端末に残るRoot phrase/master seed
- Anchor/CoordinatorのOIDC refresh session
- master seedから得る安定Vault storage KEK

MLS revokeだけではこれらを消せない。特にCoordinator v2はSelf Groupを参照せずOIDC ownerで認可するため、**MLS device revokeとCoordinator session revokeは現在別のauthority domain**である。完全な端末喪失対応には、DID key削除、mediator routing更新、Self Group Removeに加え、Anchor session/token revoke policyを明確にする必要がある。

## 10. Coordinatorとの境界

Coordinatorのowner-scoped Vault stream v2自身はMLSを使わない。一方、同じCoordinator processは別namespaceでSelf Group MLS DSを提供する。

- Self Group membershipを保存しない。
- MLS epochを知らない。
- Vault streamはKeyPackage、Welcome、Add/Removeを扱わない。MLS DSはopaque payloadとしてKeyPackage、Welcome、commit/proposalを保管・配送する。
- OIDC pairwise subjectごとに一つのordered opaque streamとcheckpointを持つ。
- 新端末はRoot loginでSelf GroupへExternal Joinし、別途OIDC loginでcheckpointを復元する。

`src/main.ts`、`src/coordinator/`、`src/mls/vault-group.ts`にはCoordinator v1のVault専用MLS codeがまだ残っている。v2 cut-over後はUI callbackが`undefined`に上書きされ、Invite/Approve/Join操作は露出しない。Coordinator serverのv1 endpointとtableもmigration compatibilityとして残存する。

この残存codeをSelf Groupの現行責務と混同してはならない。

これはCoordinator自身がMLS Clientまたはmembership authorityになるという意味ではない。

### Clientが必ず担うもの

- MLS private `ClientState`と全秘密鍵
- KeyPackage生成とprivate halfの保管
- credential検証
- group policyとAdd/Remove判断
- proposal/commit生成
- 受信commitのRFC 9420完全検証
- application message暗号化・復号
- sender attribution
- epoch secret/exporter secret
- group transcript/fork検出

### Coordinatorだけが担うもの

- public KeyPackageの公開・取得
- GroupInfo、Ratchet Tree、Welcomeの保管・配送
- opaque proposal/commit/application wireのstore-and-forward
- groupごとの単調sequence
- same-epoch first-winsまたは明示的conflict応答
- offline member向けbounded retention
- 冪等appendとpull cursor
- quota、TTL、GC、可用性

### Coordinatorが担ってはならないもの

- MLS private stateまたはgroup secret
- commit/application payloadの復号
- Add/Remove policyの決定
- Clientに代わるcredentialの暗号学的承認
- plaintextまたはVault SegmentKey
- Self GroupとConversation Groupの意味解釈

Coordinatorが知ってよいのは、DS routingに不可欠なopaque group handle、epoch/sequence、opaque recipient handle、payload size、時刻である。DID、SCID、domain、mail addressをDS protocolへ直接入れない。現行Self Group APIの`identityId`、DID device kid、SCID-derived group ID、legacy roster projectionは移行対象である。

MLS DSはCoordinatorのVault streamとは別namespaceにする。Vault streamは一つのOIDC ownerに閉じるが、Conversation Groupは複数のOIDC ownerを跨ぐためである。MLS DSの認可はgroup-scoped capabilityまたはMLS leaf署名を使う抽象境界とし、`owner_subject = group owner`とは仮定しない。具体的な認証profileは別設計とするが、この分離はAPI/DB schemaの前提にする。

## 11. Conversation Groupの現在地

将来の第三者group chatに必要なcryptographic primitiveはすでにある。

- 複数member group作成
- Add/Remove commit
- KeyPackageとWelcome
- MLS application messageのencrypt/decrypt
- authenticated sender leaf attribution
- epoch exporter

しかし、製品としてのConversation Groupはまだ存在しない。少なくとも次が未実装である。

- conversationとMLS group IDの対応metadata
- conversationごとの`ClientState`永続store
- 異なるidentity間のKeyPackage discovery
- multi-identity用Delivery Service authorization profile
- commit競合、catch-up、Welcome再送、offline member処理
- MLS application messageとVault/JMAP message modelの対応
- one-to-oneからgroupへのUI lifecycle
- member device追加・revokeを各Conversation Groupへ反映する方針

現行Self Group DSは一つのidentity配下のdevice kidを前提にしているため、そのまま第三者Conversation GroupのDSとして使うことはできない。engineとfacadeは再利用できるが、server profileとorchestrationは別途必要である。

## 12. 現在の不整合とリスク

### 12.1 Self Groupとlegacy rosterは原子的ではない

External Commitが受理された時点でMLS Self Groupは進むが、legacy trusted rosterの更新は既存memberによる後続projection installである。既存memberがbootしなければ、次が起こり得る。

- 新端末はSelf Groupにjoinedしている。
- legacy rosterにはまだ新端末がいない。
- mediatorのrecipient snapshotに新端末が含まれない。
- UI上のDID documentには新deviceが見えるが、routing authorizationは古い。

これは「一台目だけ／二台目だけに届く」現象を生み得る現在のeventual-consistency gapである。

### 12.2 MLS maintenanceがboot中心である

`maintainSelfGroup()`は通常boot時に走り、常時pollではない。別端末がjoin/revokeした後、開きっぱなしの既存Clientが即座にcommitを反映する保証はない。

### 12.3 Delivery log pullにpaging cursorがない

Self Group catch-upは毎回`afterSeq: 0`でpullし、local epochに一致するcommitだけを適用する。Serverは一回のpullを32件に制限し、group logを256件に制限する。長期間・多数のmembership change後には、先頭pageだけを再取得して先へ進めない可能性がある。

### 12.4 Concurrent External Join retryが弱い

External Joinでepoch conflictが起きた場合、現行`ensureSelfGroup()`は十分な再pull/backoff loopを持たない。同時に複数端末をrestoreする場合のrobustnessは不足している。

### 12.5 ServerはMLS commitとprojectionの対応を証明しない

Serverはopaque MLS commitをparseせず、Clientが提出するDS rosterとCore projectionを公開device署名に基づいて受け入れる。つまりserverは「このprojectionがこのcommitから厳密に導出された」というcryptographic proofを検証しない。現在のtrust modelでは既存trusted deviceをmembership administratorとして信頼している。

### 12.6 Vault migration codeが二世代混在する

安定root-derived storage wrapが優先される一方、current MLS epoch wrap、self-grant、peer restore grant、Coordinator v1 rewrap codeが残る。責務の理解と障害解析を難しくしている。

### 12.7 UI文言と実際のrevoke境界

Account UIはdevice revokeを「Vault accessを直ちに失う」と表現しているが、既取得plaintext、master seed、安定storage KEK、独立したOIDC sessionまではMLS Removeで消えない。UIとsession revoke policyを現行architectureに合わせる必要がある。

## 13. 現行の正本となる責務分割

| 問い | 正本 |
|---|---|
| このDIDのRoot controllerは誰か | Anchor上のdid:webvh log |
| このidentityの現在のdevice memberは誰か | Clientが保持するMLS Self Group state |
| 旧配送・互換API認可に使う公開device集合は何か | Self Groupから反映したlegacy Trusted Device Roster |
| messageの一時transportは誰か | DIDComm/Mail Mediator |
| messageとcredentialの長期local正本は何か | Local Vault |
| 複数端末へVault mutationを永続配送するのは誰か | Coordinator v2 stream |
| MLS wireをoffline memberへ保存・順序配送するのは誰か | Coordinator MLS Delivery Service（実装済み、production release待ち） |
| Vault長期保存鍵を復元できるauthorityは何か | Root phrase/master seed |
| 将来の第三者group chatをE2EEするのは何か | Conversation Group MLS（未実装） |

要点は、**Vault/ClientがMLSの暗号とpolicyを所有し、CoordinatorがMLS DSの可用性・順序・配送だけを所有する**という分割である。MediatorはDIDCommとMailの外部transportを担い、MLS DSはCoordinatorに置く。

## 14. 主要code map

| 領域 | file |
|---|---|
| MLS facade | `src/mls/group.ts` |
| Self Group orchestration | `src/mls/self-group.ts` |
| ciphersuite | `src/mls/suite.ts` |
| did:webvh Authentication Service | `src/mls/webvh-authentication-service.ts` |
| Self Group IndexedDB | `src/mls/store.ts` |
| KeyPackage IndexedDB | `src/mls/keypackage-store.ts` |
| KeyPackage pool | `src/mls/key-package-pool.ts` |
| Coordinator MLS transport | `src/mls/coordinator-mls-delivery-transport.ts` |
| legacy roster transport | `src/mls/core-roster-install-transport.ts` |
| roster projection producer | `src/mls/roster-projection.ts` |
| Vault membership signer/verifier | `src/mls/segment-key-membership.ts` |
| identity create/restore/maintenance | `src/identity/bootstrap.ts` |
| browser composition root | `src/main.ts` |
| vendored engineと差分 | `src/mls/vendor/`, `src/mls/vendor/VENDOR.md` |
| Self Group DS実装 | `src/coordinator/mls-delivery-store.ts` |
| request authorization | `src/coordinator/mls-delivery-authorizer.ts` |
| HTTP API | `src/coordinator/mls-delivery-http.ts` |
| legacy trusted roster | `src/core/identity/device-roster.ts`, `src/core/identity/sqlite-device-roster.ts` |
| Coordinator v1 legacy MLS | `src/mls/vault-group.ts`, `src/protocol/vault-mls-ds.ts`, `src/coordinator/` |
| stable Vault storage KEK | `src/vault/storage-root.ts` |

## 15. 設計判断の要約

1. MLS engine、private state、暗号処理、group policyはClientに置く。
2. Client単独で成立しないMLS DS機能はCoordinatorへ置く。
3. Self Groupは一identityのdevice membershipに限定する。
4. Self Group IDはSCIDから決定論的に導出し、domain moveに耐える。ただしCoordinator向けrouting handleは公開識別子から分離する。
5. Root phraseによるDID controlを新deviceの自動External Join admissionとする。
6. DIDComm/mail本文はSelf Group MLSで同期しない。
7. CoordinatorはMLS membershipを所有しないが、汎用MLS DSを所有する。
8. Vault at-rest key lifecycleはMLS epochから分離する。
9. MLSは削除せず、将来の第三者group chatには別Conversation Groupとして再利用する。
10. 現在の最大の構造的課題は、Self Group commitとlegacy roster projectionが非原子的で、projection/catch-upが廃止済みCoreとboot maintenanceへ残ることである。
