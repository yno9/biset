# Biset Vault Core — 実装作業工程

*最終更新: 2026-08-23 / 現在の基準 commit: 作業中*

この文書は、実装を順番に進めるためのチェックリストである。設計の根拠、wire schema、状態機械、security invariant の詳細は [`PLANIMPLEMENTATION.md`](PLANIMPLEMENTATION.md) を正とする。本書は「次に何を作るか」「どこまで終わったか」「何を満たせば次へ進めるか」を示す。

## 0. 現在地

- [x] 旧 client を `src.bak/` に、旧 `jmapsmtp` を `jmapsmtp.bak/` にローカル退避した。
- [x] 新しい `src/` の client / anchor / protocol の最小骨格を作った。
- [x] 新設計の統合文書 `PLANIMPLEMENTATION.md` を作った。
- [x] 新しい ARC/README の骨格を作った。
- [x] canonical JSON、domain-separated hash、ingress schema validation を実装した。first-party adapter の offer から recipient snapshot を排除し、core が accepted self-group roster から凍結する。
- [x] memory-only の bounded `IngressStore` を実装し、TTL、quota、recipient snapshot、一台の authorised ACK、payload 削除をテストした。
- [x] core を `identity`（anchor）、`mediation`、`adapters` に概念分離し、初期 deployment は一つの `biset-core` binary に統合した。
- [-] IndexedDB の local vault schema、atomic ingress commit、object crypto、flat manifest は存在するが、ingest workflow と durable recovery は未実装。
- [-] SQLite roster + SQLite delivery / restore-control / ingress、roster authorizer、Ed25519 verifier、narrow HTTP の deployment composition を実装した。ingress の endpoint API は signed pull / durable ACK のみで、external offer は adapter 内部に限定する。actual MLS accepted-commit source / DID resolver cache policy は未実装。
- [ ] Local JMAP Gateway、MLS VEK 導出、DIDComm/Mail adapter は未実装である。SegmentKey の object encryption と、VEK を入力に取る wrap primitive は実装済みである。

**次に着手する工程:** §4.1 は DID resolver・MLS 暗号処理系の移植・roster install 認可・roster producer・`MlsSelfGroupProvider`・AS・self-group DS 通信（12 操作、core + client transport）・self-group bootstrap（`ensureSelfGroup`）・roster 取得 API と roster install の接続（`ensureSelfGroupWithRosterInstall`/`installCurrentRosterProjection`）・既存メンバーによる新 epoch 検知/反映（`reflectPendingSelfGroupCommits`）・did:web mirror（`src/identity/web/`）・key-package pool（`keypackage-store.ts`/`key-package-pool.ts`）・新規 identity 作成 / 追加 device 復元の end-to-end bootstrap（`identity/bootstrap.ts` の `createNewIdentity`/`restoreIdentity`）・boot 時の self-group 定期メンテナンス（`maintainSelfGroup`、`main.ts` の `bootClient` からの結線、実 vault-delivery `latestSeq` 配線込み）と最小限の new-user/login UI（`src/ui/`）まで実装した。残るのは (1) `restoreIdentity` 自身の `deliveryFloorForNewDevice`（新規参加 device 自身はまだ roster に信頼されておらず vault-delivery pull を呼べないため、`0` 固定のまま — 通常は roster install 自体が rejected になり実害はない）、(2) `src.bak/ui/` の残り（left-pane・account 管理・relay 接続等、9000 行超）の本格移植 — これと `submitApplication` を移植するかどうかの判断は、Vault Core 全体のブートストラップに関わる別の大きな作業として後続に残す。§3.3 の ingress/vault 接続とは独立して進められる。ingress は generic public HTTP API にせず、first-party adapter の内部 boundary に限定する方針は維持する。

## 1. 作業上の不変条件

以下に反する実装は追加しない。各 PR / commit で確認する。

- [ ] core/anchor に `Email/get`、`Email/query`、server-side search、恒久 blob URL、mailbox history API を追加しない。
- [ ] external ingress の payload は trusted device 一台が durable ACK したら削除できる。
- [ ] vault delivery の payload は一コピーだけ保持し、端末ごとに payload を複製しない。
- [ ] TTL / quota による不足を成功扱いにせず、`restoreRequired` として明示する。
- [ ] TLS / DIDComm / PGP / MLS の秘密鍵を core に送らない。
- [ ] client が ACK を送る前に、object、event、projection、再送 outbox を durable に保存する。
- [ ] MLS Remove 後には旧 SegmentKey で新 object を復号できない。

> 上の項目は全体完了まで未チェックのまま残す。各 milestone の test で部分的に検証する。

## 2. Protocol foundation と mediator model

### 2.1 Canonical encoding と基本 schema

- [x] `src/protocol/canonical.ts` に canonical JSON、SHA-256、domain-separated hash、constant-time byte comparison を実装する。
- [x] `src/protocol/ingress.ts` に `IngressEnvelopeV1`、`IngressAckV1`、adapter 入力専用の `AdapterIngressOfferV1` を定義する。
- [x] `src/protocol/validate.ts` に ingress / ACK の shape validation を実装する。
- [x] canonical order、hash domain、byte equality、invalid ingress の unit test を追加する。
- [ ] canonical JSON V1 の値域・Unicode・number の cross-language test vector を `src/protocol/test-vectors.ts` に固定する。
- [ ] opaque ID の grammar、最大長、生成規則を `ids.ts` と validator に固定する。
- [ ] protocol version negotiation と未知 field / version の互換性 policy を決める。

**完了条件:** client/core が同一 bytes を署名・hash でき、異なる実装言語でも再現可能な vector がある。

### 2.2 IngressStore

- [x] `src/core/mediation/ingress-store.ts` に in-memory reference implementation を作る。
- [x] payload size、identity 合計 bytes、pending item 数の quota を実装する。
- [x] recipient snapshot 外の device への pull を拒否する。
- [x] recipient snapshot に入っていても、pull 時点で trusted roster から Remove 済みなら ingress を渡さない。
- [x] ACK hash、snapshot、authorizer を確認後に payload を削除し、tombstone だけを残す。
- [x] expiry で payload を削除する。
- [x] adapter 入力は recipient device snapshot を持てず、`CoreIngressAdapter` が offer 時点の accepted self-group roster から snapshot を凍結する。
- [x] endpoint への ingress pull は current trusted device の Ed25519 署名を必須にし、public HTTP は signed pull / durable ACK だけを公開する。external adapter offer は内部 boundary のままにする。
- [x] ingress pull は最初に取得した正規端末へ短命の exclusive claim lease を付与する。claim 中は他端末へ同じ body を出さず、claim 端末だけが ACK できる。lease 失効後は別端末が引き継げ、SQLite restart 後も本文一コピーと claim state を維持する。
- [x] trusted-device roster を mediation authorizer adapter に接続し、DID/webvh public-key resolver を入力に取る Ed25519 verifier を実装した。`src/identity/webvh/`（読み取り専用の resolver、`src.bak/did/webvh/` から移植）を使う `WebvhSigningKeyResolver` が real DID resolution を行う。fail-closed（未解決 DID/fragment は署名検証失敗になる）。key rotation cache は未実装のまま残す。
- [x] crash-safe な SQLite `VaultDeliveryStore` / `IngressStore` と core deployment への authorizer/persistence wiring を実装した。ingress は first-party adapter の内部 boundary だけで、公開 HTTP には出していない。restart coverage に加え、同時操作の coverage を実装した——`test/protocol/sqlite-vault-delivery-store.test.ts` に同時 ACK（別 device 二台の同時 ACK、同一 device の自己競合リトライ）を追加。**その過程で実バグを発見・修正**: `SqliteVaultDeliveryStore.acknowledge` が `row.state` を `authorizer.verifyAck` の `await` より前に読んでいたため、その await 中に別の呼び出し（`expire()` 等）が同じ row の state を書き換えると、stale な 'pending' 判定のまま completed に書き込んでしまう（expired な delivery を completed として蘇らせ、`gap_reason` を破壊する）レースが存在した。state の再読み取りと書き込みを一つの同期 SQLite transaction 内に収めて修正し、修正前は実際に失敗する regression test で確認した。
- [ ] tombstone retention / dedup retention / quota eviction の数値を policy として決める。
- [-] signed shared vault delivery の `append` / `pull` / `ack` を narrow HTTP adapter と browser transport に結び付けた。SQLite を使う production core composition / persistence は実装済み。actual DID resolution / MLS commit の runtime injection は未実装。`status` は core internal のみ。
- [x] SQLite restart、all-ACK 後の body 消去、ACK 再送、TTL/ quota gap の integration test を追加した。同時 ACK（`sqlite-vault-delivery-store.test.ts`、実バグ修正込み——上記参照）、duplicate offer（`restore-control-store.test.ts`/`sqlite-restore-control-store.test.ts` に同一 offer の再送=no-op と衝突する offer の再送=拒否を追加）、authorizer rejection（`roster-authorizers.test.ts` に `rosterBackedRestoreControlAuthorizer` の `verifyOffer`/`verifyCancel` の未信頼 device 拒否を追加、従来 `verifyRequest`/`verifyPull` のみだった）を実装した。

**完了条件:** core restart 後も body を誤って復活させず、未 authorised device の ACK で body を消せない。

### 2.3 Shared VaultDeliveryStore

- [x] `VaultDeliveryItemV1`、`VaultDeliveryAppendV1`、`VaultDeliveryAckV1`、`DeliveryPullResult` を `src/protocol/vault.ts` に定義する。
- [x] append 時の `recipientsAtAppend` は、client input でなく core の trusted-device roster から immutable に取得する。
- [x] payload body を一コピー、端末ごとには ACK/cursor だけを持つ in-memory store を実装する。recipient snapshot と TTL は core policy が決定する。
- [x] all-ACK 時の body 削除を実装する。
- [x] local delivery outbox の再送を重複配送にしないため、core append を client-generated `appendId` で idempotent にする。
- [x] TTL / quota expiry 時に `retainedFrom` と gap record を更新し、SQLite 再起動後にも正しい restore reason になることを検証する。
- [x] 古い cursor の pull が必ず `restoreRequired` を返すよう実装する。
- [x] new device を過去 item の recipient set に遡及追加しない test を書く。
- [ ] N devices でも payload copy が一つだけである storage test を書く。

**完了条件:** per-device DIDComm queue を使わず、共有 body + cursor/ACK だけで sibling devices を TTL 内 catch-up できる。

### 2.4 Restore control

- [x] `RestoreRequestV1`、`RestoreOfferV1`、cancel / expiry schema と canonical signing bytes を定義する。
- [-] short-lived restore control store を memory / SQLite で実装した。current roster の署名 verifier と bounded persistence に接続済み。actual MLS commit source と peer availability は未実装。
- [x] restore store の API は request / offer / cancel / signed poll の control 型だけを受け付け、history/blob/chunk を受け付けない。64 KiB HTTP boundary と production storage の restart / expiry / quota test を追加した。
- [-] `restoreRequired` を受けた client が、署名済み `RestoreRequestV1` を local durable state に先に保存し、同一 request ID で core へ再送する contract を実装した。peer の signed poll と、承認後の `RestoreOfferV1` durable outbox も実装済み。実 UI / transfer approval は未実装。
- [ ] peer への opaque push / control notification を定義する。

**完了条件:** TTL 外端末は不足を明確に検出でき、peer が不在なら曖昧に同期成功したように見えない。

## 3. Endpoint vault

### 3.1 Local persistence abstraction

- [-] `IndexedDbVaultStore` から projection だけを読む `VaultProjectionReader` boundary を抽出し、Local JMAP adapter に接続した。event/object write と migration の testable abstraction は未抽出。
- [x] IndexedDB version 3 schema と store 作成を実装する。
- [x] store: `vault_events`、`vault_objects`、`vault_chunks`、`vault_segments`、`vault_key_wraps` を作る。
- [x] store: `vault_manifests`、`vault_projection`、`vault_jmap_state`、`vault_outbox`、`vault_delivery_state`、`vault_restore_state` を作る。
- [x] ingress receipt / object / event / projection / JMAP state / ACK outbox を単一 transaction にする。
- [x] local JMAP mutation の object / event / projection / JMAP state / shared vault-delivery outbox を単一 transaction にした。browser fault injection は未実装。
- [-] outbox の causal-order flush / append idempotency boundary を実装した。IndexedDB outbox の index、retry backoff、actual core HTTP transport は未実装。
- [x] browser restart、partial write、migration failure の test harness を実装した（`test/protocol/vault-store-durability.test.ts`）。他のテストが全て memory fake で済ませていた `IndexedDbVaultStore` を、`fake-indexeddb`（新規 devDependency）で spec 準拠の実 `indexedDB` に対して初めて動かした——memory fake では unique key constraint も version upgrade も実際には検証できないため。(1) browser restart: `commitIngress` 後に store を close し、新しい `IndexedDbVaultStore.open()`（`main.ts` の `bootClient` が毎回たどる経路と同じ）で object/event/projection が生存していることを確認。(2) partial write: 同じ ingressId を二回 `commitIngress` しても `vault_ingress_receipts` の実 keyPath unique constraint により重複コミットされないことを確認（`already-committed` が実際の ConstraintError 経由で返ることの検証）。(3) migration failure: `vault_restore_transfer_state`（v5 で追加された store）を持たない v4 相当の DB を手動構築し既存データを書き込んだ上で `IndexedDbVaultStore.open()`（v5 を要求）を呼び、既存データが生き残ること・新 store が使えるようになること・DB の実 version が 5 に上がることを確認した。

**完了条件:** network がなくても、再起動後に vault root と Local JMAP state を同じ状態へ復元できる。

### 3.2 Event / object / manifest

- [-] immutable `VaultEventV1` の ID、署名対象、actor sequence を実装する。signer interface と canonical event ID は実装済み、MLS/device signer 接続は未実装。
- [-] AES-GCM による encrypted `VaultObjectV1` と SegmentKey/VEK wrap primitive を実装した。chunked attachment object と MLS exporter 接続は未実装。
- [-] event signature、parent reference、duplicate event、replay の validation を実装する。署名 verify の interface は実装済み、store-level validation は未実装。
- [ ] edit / tombstone / read / mailbox / reaction の競合規則を kind ごとに固定する。
- [x] manifest root と event/object set の diff を実装する。階層 Merkle proof と durable checkpoint は未実装。
- [-] mailbox / keyword / tombstone mutation event の deterministic JMAP projection reducer を実装した。`message.add` は、署名 event の第1 object reference に encrypted JMAP metadata、第2 reference に加工しない raw RFC 5322 blob を束縛する。projection は metadata と blob ID の一致を検証して再構築し、mailbox 件数も再計算する。attachment / decrypted MIME projector / full vault scan checkpoint persistence は未実装。
- [ ] duplicate、offline concurrent write、interrupted transfer の convergence test を書く。

**完了条件:** 二端末が同じ検証済み event/object 集合から同じ manifest root と JMAP projection を作る。

### 3.3 Ingress-to-vault transaction

- [-] `src/vault/delivery-ingest.ts` と `delivery-projector.ts` に shared vault delivery の hash/pack verify → current MLS wrap / event / object verify → deterministic projection → durable commit → delivery ACK outbox を実装した。`ingress-ingest.ts` に external ingress の verify/project → atomic commit → ACK outbox 境界を実装し、Mail の concrete projector は存在する。`VaultDeliveryProjector`（`delivery-projector.ts`）が要求する `VaultEpochKeyResolver`/`VaultEventVerifier & SegmentKeyWrapVerifier` を実 self-group に接続する `identity/bootstrap.ts` の `buildVaultDeliveryProjector` を追加し、実 MLS self group を通した end-to-end test（`test/protocol/identity-vault-delivery-projector.test.ts`）で、`buildVaultCryptoBoundary` が作った segment で書いた mutation record が pack 化・decode・検証・復号・projection まで正しく通ること、self group に存在しない device が署名した event の拒否を確認した。DIDComm decoder と MIME/OpenPGP mail projector（ingress 側のプロトコル固有デコード）は未実装。
- [x] TTL 内の shared vault delivery は cursor-based pull → ordered ingest → durable ACK outbox flush として同期し、TTL 外は `restoreRequired` を UI 層へ返す。
- [x] append / pull / ACK はすべて current trusted device の署名を必要とする。HTTP binding はこの型をそのまま使う。
- [x] ACK outbox の retry / idempotence を実装する。
- [x] signed ingress pull → endpoint ingest → durable ingress ACK outbox flush の client 同期ループを実装した。既存 ACK を pull 前に再送し、今回の ACK は atomic commit 後にだけ送る。
- [x] mail の endpoint workflow は claimed ingress を project/commit/ACK した後、その transaction が積んだ shared vault-delivery outbox を append する。`commit` より前の sibling append は許さない。
- [ ] crash が ACK 前なら payload を再 pull でき、ACK 後なら local state が必ず存在することを test する。
- [ ] duplicate ingress ID / payload hash を安全に処理する。

**完了条件:** `IngressAckV1` が「端末が受信した」ではなく「vault へ durable commit した」を正しく意味する。

## 4. MLS self group と vault cryptography

### 4.1 MLS integration boundary

- [x] `PLANMLSARCH.md` に RFC 9420/9750 の原則整理と、core（DS）が roster install 時に検証してよい範囲を確定した。
- [-] new core 用の最小 `MlsSelfGroupProvider` / fixed VEK exporter boundary を抽出した。`ClientState` から作る具象実装は未実装。
- [-] accepted MLS epoch だけで更新する public trusted-device roster projection と、それを使う delivery / restore authorizer adapter を実装した。SQLite persistence も追加。DID publishing との接続は未実装（DID signature verifier は実装済み — 上の §2.2 参照）。
- [x] `installAcceptedProjection` の認可モデル（core=DSが検証してよい範囲）を RFC 9420/9750 に基づき確定した。`PLANMLSARCH.md` を参照。epoch 単調性 + 同一 epoch tie-break は実装済み。
- [x] `RosterInstallV1` 署名型（`src/core/identity/roster-install.ts`）と `verifyRosterInstall` を追加し、`installRosterProjection`（`src/core/identity/authorizers.ts`）が roster が現に信頼する device 以外（genesis を除く）の install を拒否する。
- [x] `src.bak/mls/vendor/`（vendored ts-mls、RFC 9420 実装 + biset の Remove/UpdatePath セキュリティ修正）と `group.ts`/`identity.ts`/`suite.ts` を `src/mls/` へ移植した。DIDComm transport-key extension（`mlsCapabilities`/`memberTransportKeys`）は削り、DIDComm adapter 実装時に必要なら作り直す。
- [x] accepted MLS commit から `AcceptedSelfGroupProjectionV1` を組み立て、`RosterInstallV1` として署名する producer（`src/mls/roster-projection.ts`、endpoint 側・core 非依存）を実装した。既存 device は `deliveryFloor` を保持し、新規 device だけ呼び出し元が渡す `deliveryFloorForNewDevice()` から取得する。MLS credential kid → roster `signingKeyId` の対応は呼び出し元が注入する未確定の写像のまま残す（`PLANMLSDIDCRED.md` §4 の未決事項に依存するため）。実 MLS group（vendored ts-mls）を使った genesis / rekey の end-to-end test で検証済み（`test/protocol/mls-roster-projection.test.ts`）。
- [x] `RosterInstallV1` の narrow HTTP エンドポイント `/v1/roster/install`（`src/core/identity/roster-http.ts`）を追加し、`core/app.ts` と `core/deployment.ts` に配線した。wire encode/decode は `protocol/ingress-wire.ts` 等の既存パターンに倣う（`src/core/identity/roster-install.ts` に同居）。
- [x] fixed label/context/32-byte output の `deriveVaultEpochKey(group)` boundary を実装した。`ClientState` から `MlsEpochExporter` を作る具象 `MlsSelfGroupProvider`（`StoredMlsSelfGroupProvider`、`src/mls/store.ts`）を実装し、`MlsVaultEpochKeyResolver`（`vault-epoch.ts`）まで通しての VEK 導出を実 MLS group（genesis / rekey）で検証した（`test/protocol/mls-self-group-store.test.ts`）。永続化は `vault/store.ts` とは別の IndexedDB database（`biset-mls-self-group`）とし、双方のマイグレーションを分離した。`IndexedDbMlsSelfGroupStore` 自体（実 IndexedDB 読み書き）は Bun test 環境で検証できないため未検証、契約は `MlsSelfGroupStateStore` インターフェースの in-memory fake でのみ確認済み。
- [x] DS 通信寄りの key-package pool を実装した（`src/mls/keypackage-store.ts` の `IndexedDbMlsKeyPackageStore`、`mint`/`takeForWelcome` として `src.bak/mls/store.ts` の `mintKeyPackages`/`takeKeyPackageForWelcome` を移植。`vault/store.ts`・`mls/store.ts` の self-group state ともマイグレーションが分離した第三の IndexedDB database）。`src/mls/key-package-pool.ts` の `ensureKeyPackagePool` は `src.bak/did/didcomm-devices.ts` の補充アルゴリズム（DS の実際の残数を問い合わせ、不足分だけ mint/publish する — ローカルの数を信用しない）を移植した。実 DS・実 HTTP ハンドラを通した end-to-end test（`test/protocol/mls-key-package-pool.test.ts`）で、空プールからの補充・target 到達後の no-op（publish 未呼び出しまで確認）・一部消費後の差分補充を検証した。`IndexedDbMlsKeyPackageStore` 自体は `IndexedDbMlsSelfGroupStore` と同様 Bun test 環境で未検証、契約は in-memory fake でのみ確認済み。
- [ ] VEK を永続化しないことを code review / test で保証する。
- [x] AS（leaf credential の正当性検証）を `src/mls/webvh-authentication-service.ts` として実装した。credential の wire 形式（`did#fragment` basic credential）は無変更 — `did` と `verification_method_id`（= fragment）へ分解できる既存表現がそのまま `PLANMLSDIDCRED.md` の `did_webvh_credential` に相当するため、`vendor/customCredential.ts` の custom credential type（デコード側が未実装であることが判明した）は使わない。検証は「resolve した DID の `verificationMethod[id===kid]` が、MLS leaf の実際の signature key と bytes 一致するか」まで確認する、旧実装（`doc.keyAgreement` に kid が列挙されているかだけを見る緩い検証）より厳密なもの。fail-closed（未解決 DID / 不一致鍵はすべて拒否）。実 MLS `KeyPackage` の leaf signature key を使う test で検証済み（`test/protocol/mls-webvh-authentication-service.test.ts`）。`setMlsAuthService` を呼ぶ endpoint 起動時の配線はまだ無い（endpoint 初期化コード自体が未実装）。

### 4.1.1 self-group の DS 通信（RFC 9750 §5、`src.bak/anchor/mediator/mls-ds.ts` からの移植）

新規に設計せず、biset がすでに実装していた `MlsDeliveryService`（commit ordering / tie-break / GroupInfo / KeyPackage directory、コメント自体が RFC 9750 の DS 原則をなぞっている）を移植した。スコープの変更点は一つ — 旧実装は複数 identity 間の会話 group を想定し `roster`/`everMembers` が identity 単位だったが、Vault Core の MLS group は self-group 専用（`PLANIMPLEMENTATION.md` §4.1）なので device kid 単位に変えた。tie-break/pull の意味論は無変更。

- [x] `SqliteMlsDeliveryService`（`src/core/mediation/mls-delivery-store.ts`）: `createGroup`、`submitCommit`（epoch 一致 + tie-break + Welcome 同梱）、`groupInfoFor`、`submitExternalCommit`（外部 join、GroupInfo 必須）、`submitSelfRemove`/`clearPendingRemovals`、`since`/`deliveriesSince`（ever-member 認可、bounded pull）、KeyPackage directory（`publishKeyPackages`/`takeKeyPackages`/`dropKeyPackages`/`keyPackageCount`、single-use 消費）を SQLite 永続化で実装。`test/protocol/mls-delivery-store.test.ts` で旧実装の意味論（tie-break、ever-member pull、single-use consumption、restart 後の永続化）を検証。
- [x] `SqliteMlsDeliveryService` 自身の `roster`/`everMembers` は `TrustedDeviceRoster` とは意図的に別管理（DS 内部の未検証な作業 roster、commit の sender 自己申告に基づく — commit を受理した時点ではまだ producer が `RosterInstallV1` を作っていないため、検証済み roster を先に参照できない）。
- [x] 署名検証（`src/core/mediation/mls-delivery-authorizer.ts`、`Ed25519MlsDsSignatureVerifier`）: 各 control message を **送信者自身の device key**（`DeviceSigningPublicKeyResolver` で DID 解決、`TrustedDeviceRoster` は経由しない）で検証する。AS（`webvh-authentication-service.ts`）と同じ「credential kid を解決して署名確認」という形を、MLS credential 自体ではなく transport 層の control message に適用したもの。12 操作すべてに実装済み。
- [x] protocol 型（`src/protocol/mls-ds.ts`）と signing bytes（`protocol/signing.ts`）、narrow HTTP エンドポイント（`src/core/mediation/mls-delivery-http.ts`）を実装し `core/app.ts`・`core/deployment.ts` に配線した。wire encode/decode（`protocol/mls-ds-wire.ts`）は client/core 両方から中立に使えるよう protocol 層に置いた（`MlsGroupInfoAnswer`/`MlsLogEntry` も `mls-delivery-store.ts` から `protocol/mls-ds.ts` へ移設）。`test/protocol/mls-delivery-authorizer.test.ts`・`test/protocol/mls-delivery-http.test.ts` で偽造署名の拒否と wire round-trip を検証。12 操作すべて（`/v1/mls/group/create` `/v1/mls/commit/submit` `/v1/mls/commit/external` `/v1/mls/group-info/pull` `/v1/mls/keypackage/publish` `/v1/mls/keypackage/take` `/v1/mls/self-remove/submit` `/v1/mls/pending-removals/clear` `/v1/mls/deliveries/pull` `/v1/mls/keypackage/drop` `/v1/mls/keypackage/count` `/v1/mls/groups-for`）に署名認可を実装済み。
- [x] client（endpoint）側 transport（`src/mls/core-mls-delivery-transport.ts`、`CoreMlsDeliveryTransport`）を実装した。commit 系操作（submit/external/self-remove）は tie-break 敗北（`epoch-conflict`）や `unauthorized` を例外にせず `{ ok: false, reason, epoch }` として返す — MLS の標準的な回復（新 epoch で retry）を呼び出し側が書けるようにするため。`test/protocol/mls-delivery-client-transport.test.ts` で実際の HTTP ハンドラと繋いだ end-to-end（wire の client/server 側が食い違っていないこと）を検証。
- [x] `groupInfoFor`/`pullMlsGroupInfo` のバグを修正した。「group がまだ存在しない（新規 device の最初の join 試行、正常系）」と「認可失敗」を同じ `undefined`/403 で返しており、`joinSelfGroupExternally` の一番最初の呼び出しが必ず 403 になっていた。`MlsGroupInfoPullResult = {ok:true, answer} | {ok:false}` に分離し、group 不在は `{ok:true, answer:{pendingRemovals:[]}}`（空の正常応答）に変更した。
- [x] self-group bootstrap（`src/mls/self-group.ts`）を実装した。`src.bak/mls/self-group.ts` から state machine の核（`selfGroupIdHex`/`createSelfGroup`/`publishGroupInfo`/`joinSelfGroupExternally`/`ensureSelfGroup`）を移植し、DIDComm device-sync・transport-key extension・stale-leaf recovery・pendingRemovals 追従・add/remove device 操作は意図的に含めない（モジュール冒頭のコメントに理由を明記、それぞれ別途レビューすべき変更として後続に残す）。署名は呼び出し元が注入する `SelfGroupSigner`（実体は device の MLS leaf signature key、`PLANMLSDIDCRED.md` §2.3 の「新しい鍵種を増やさない」方針通り）。実 MLS group・実 SQLite DS・実 HTTP ハンドラを通した end-to-end test（`test/protocol/mls-self-group-bootstrap.test.ts`）で、1 台目の genesis 作成と 2 台目の外部 join（1 台目が online である必要なし）を検証した。
- [x] `src/mls/core-roster-install-transport.ts`（`CoreRosterInstallTransport`）を実装した。`RosterInstallV1` を `/v1/roster/install` へ送る client 側 transport。`fetchProjection(identityId)`（`GET /v1/roster/:identityId`、`roster-http.ts` に追加、未認証 — projection は public device id/signing key id のみを含むため）で既存 roster の `AcceptedSelfGroupProjectionV1` を取得できる。
- [x] `ensureSelfGroup` から roster install まで接続した（`ensureSelfGroupWithRosterInstall`、`installCurrentRosterProjection` として分離実装）。**重要な設計制約が判明**: `installRosterProjection`（`authorizers.ts`）の genesis 以外は「直前 epoch の trusted device のみが installer になれる」ルールにより、新規参加した device 自身は自分をロースターに載せる install を行えない（genesis install を行えるのは初回のみ）。2 台目以降の参加は、その install が `'rejected'` を返しても例外にせず MLS join 自体は成功として扱い、**既存メンバー側が新 epoch を検知した際に `installCurrentRosterProjection` を呼んで反映する**、という運用を前提とする設計にした。実 MLS group・実 SQLite DS・実 SQLite roster・実 HTTP ハンドラを通した end-to-end test（`test/protocol/mls-self-group-roster-install.test.ts`）で、genesis install と、新規参加者の自己 install 拒否 → 既存メンバーによる `processIncoming` 経由の commit 取り込み → 反映、の両方を検証した。
- [x] 「既存メンバーが新 epoch を検知して roster を反映する」フローを `reflectPendingSelfGroupCommits`（`src/mls/self-group.ts`）として実装した。この device が既に持つ self-group state に対し `pullDeliveries`（`afterSeq: 0` 固定、DS の log は `MAX_LOG_PER_GROUP` で上限があるため全量再取得で十分と判断）→ 自分の現在 epoch に一致する commit だけ `processIncoming` で適用（一致しないものはこの device 自身が過去に出した commit の再送であり、適用済みの鍵で復号しようとすると失敗する）→ epoch が進んでいれば `installCurrentRosterProjection` で roster に反映、という流れ。呼び出しタイミング（いつポーリングするか）自体はまだ決めていない — endpoint 初期化コード（起動時 / 定期実行のどちらにするか）と合わせて後続タスクとする。`test/protocol/mls-self-group-roster-install.test.ts` で、新規参加者の commit を既存メンバーが取り込んで roster 反映するケースと、変化が無ければ roster に一切触れない（no-op）ことを検証した。
- [ ] `submitApplication`（アプリケーションメッセージのルーティング）は移植していない。self-group では vault delivery（`VaultDeliveryStore`）が同等の役割を担うため、MLS application message 経由のルーティングが実際に必要か要検討。
- [x] identity bootstrap（`src/identity/bootstrap.ts`）を実装した。新規作成の `createNewIdentity` と、既存 identity への追加 device 復元 `restoreIdentity` の両方が、共通の `registerDeviceAndJoinSelfGroup`（この device の MLS leaf key を verificationMethod として登録 → `ensureSelfGroupWithRosterInstall` で self-group 参加 + roster 反映 → `ensureKeyPackagePool` で補充）を共有する。root key 導出は `identity/keys.ts`/`identity/seed.ts`（`src.bak/did/keys.ts`/`seed.ts` の SLIP-10/BIP39 をそのまま移植）。`restoreIdentity` は 24 語の recovery phrase → root key を再導出し、DID 文字列は `resolveByDomain`（`identity/webvh/resolver.ts`、`identifier.ts` の `domainDidJsonlUrl` とセット — did:webvh の SCID は genesis 時刻依存でオフライン再計算できないため、`{username}.{apex}` のサブドメインから直接 `did.jsonl` を取得して `state.id` を読む）で読み、resolve した document の `verificationMethod[0]`（`add-device-verification-method.ts` は追記のみなのでこれが常に genesis の root key）と phrase から導出した鍵が一致するかを fail-closed で検証してから device 登録に進む。identity のローカル永続化は `src/identity/record-store.ts`（`IndexedDbIdentityRecordStore`、旧 `DidRecord` から mail/AP/pre-rotation/JMAP デバイス鍵を落とした最小形、**平文保存** — passkey 封印は未移植、後で `sealed` フィールドに差し替えられる形だけ用意）。`setMlsAuthService` はこの呼び出し内で一度だけ配線する（グローバル状態、group.ts 自身の注記通り）。`selfGroupStore`/`keyStore` は呼び出し元が注入するため、実 DID anchor + 実 core（`createBisetCoreFetchHandler`）+ 実 DID 解決（`WebvhSigningKeyResolver`）を通した end-to-end test（`test/protocol/identity-bootstrap.test.ts`）がブラウザ外でも走り、2 台目 device の外部 join・誤った phrase の拒否・存在しない identity への login 拒否まで検証済み。`restoreIdentity` の `deliveryFloorForNewDevice` は vault delivery の実際の `latestSeq` を渡すべきだが、vault delivery の pull API がまだ UI に配線されていないため呼び出し元（`src/ui/account-create.ts`）は暫定的に `0` を渡している — 既存の vault content があるアイデンティティで実際に使うと過去分を誤って再配布し得る、既知の未解決事項。
- [x] `maintainSelfGroup`（`src/identity/bootstrap.ts`）を実装し、`main.ts` の `bootClient` から boot 時に一度だけ呼ぶ形で結線した。`reflectPendingSelfGroupCommits`（他 device の commit 取り込み + epoch 進行時の roster 反映）と `ensureKeyPackagePool`（補充）をこの device が持つ全 identity に対して実行する。元の `OwnKeyPackage` をメモリに保持し続けなくても再起動後に呼べるよう、`ClientState` から直接この device の MLS leaf signature private key を取り出す `ownSignaturePrivateKey`（`src/mls/group.ts`）を新設した。保存済み self-group state が無い identity（`registerDeviceAndJoinSelfGroup` がまだ一度も成功していない）には no-op で `undefined` を返す。実 DS/実 roster を通した end-to-end test で、genesis device の `maintainSelfGroup` が後から `restoreIdentity` した 2 台目 device を roster に反映することを検証（`test/protocol/identity-bootstrap.test.ts`）。
- [x] `maintainSelfGroup` の `deliveryFloorForNewDevice` を実際の vault-delivery `latestSeq` に配線した（`currentVaultDeliveryLatestSeq`、`CoreVaultDeliveryTransport.pull` を `after: 0` で呼び `latestSeq` だけ取り出す — `items` 自体は捨てる）。この API は呼び出し元 device が roster に信頼されていることを要求する（`rosterBackedVaultDeliveryAuthorizer`）ため、まだ信頼されていない新規参加 device 自身（`restoreIdentity`）ではなく、既に信頼されている既存 device（`maintainSelfGroup`）からしか呼べない — `restoreIdentity` 側の `deliveryFloorForNewDevice` は今も呼び出し元が渡す値のまま（通常は install 自体が rejected になり実害はないが、正確性としては未解決のまま）。実 vault-delivery append を挟んだ end-to-end test で、2 台目 device の `deliveryFloor` が `0` ではなく append 後の実際の `latestSeq` になることを検証（`test/protocol/identity-bootstrap.test.ts`）。
- [x] `src.bak/ui/account-create.ts`（署名フォーム）・`mnemonic.ts`（recovery phrase 表示）の TS ロジックを流用し、`src/ui/account-create.ts`/`src/ui/mnemonic.ts` として新設計向けに書き直した。DNS anchor lookup によるログイン分岐・mail/AP relay provisioning・DIDComm mediator 登録・TOS 同意・passkey enrollment はすべて未移植（対応する新実装がまだ無いか、スコープ外）。`src/main.ts` の `bootClient()` から、ローカルに identity が 0 件なら `setupNewUserPage()` を呼ぶ形で結線した（1 件以上ある場合の vault UI はまだ無いので found-identity の簡易表示のみ）。
- [x] **ビルド設定の既存バグを発見・修正**: `bun build` のデフォルト出力（ESM、`export{...}` を含む）を `<script>`（`type="module"` 無し）にそのまま埋め込んでいたため、`scripts/inline.mjs` が生成する `dist/index.html` はブラウザ上で常に構文エラーとなり `bootClient()` が一度も実行されていなかった（file:// で実際に開いて発覚）。`package.json` の `build`/`dev` スクリプトに `--format=iife` を追加して解消。
- [ ] endpoint 初期化コード自体（`ensureSelfGroup`/`reflectPendingSelfGroupCommits`/`ensureKeyPackagePool` の実際の呼び出し元とポーリングタイミング、`createNewIdentity` 完了後のログインセッション確立）は Vault Core 全体のブートストラップに関わる別の大きな作業として後続に残す。

### 4.2 SegmentKey lifecycle

- [x] random SegmentKey で payload を一度だけ AEAD encrypt する。
- [x] VEK を入力に取る署名付き `SegmentKeyWrapV1` の AEAD wrap/unwrap と、current epoch の stored wrap だけを使う SegmentKey resolver を実装した。actual MLS VEK 導出・membership signer を接続した: `src/mls/segment-key-membership.ts` の `MlsMembershipSegmentKeyWrapVerifier`/`MlsMembershipSegmentKeyWrapSigner` は grantor の署名を（resolve した DID document ではなく）**現在の self-group member list** に対して検証する（`group.ts` に新設した `memberSignaturePublicKey`。Remove 済み device は DID document がまだ追従していなくても検証に失敗すべき、という理由）。`src/identity/bootstrap.ts` の `buildVaultCryptoBoundary(wraps, selfGroupStore, record)` が `MlsVaultEpochKeyResolver` + `StoredMlsSelfGroupProvider`（既存）とこの signer/verifier を束ねて `SegmentKeyResolver` + signer の一組を返す。ClientState は commit ごとに丸ごと置き換わるため、resolver/signer は構築時ではなく呼び出しごとに `selfGroupStore.load` で最新 state を読む。実 MLS self group（`createMlsGroup`）を通した end-to-end test（`test/protocol/identity-vault-crypto.test.ts`）で、`createSegmentKeyWrap`/`resolveSegmentKey` の実ラウンドトリップと、group に存在しない grantor の検証拒否を確認した。
- [x] MLS commit durable acceptance 後に active segment を seal する。`vault/store.ts` に `VaultSegmentRecord`/`ActiveVaultSegmentStore`（`vault_segments` object store は schema 上は既に存在したが読み書きするコードが無かった）を追加し、`vault/active-segment.ts` の `ActiveVaultSegmentManager.activeSegment()` を実装した：self-group の現在 epoch と保存済み segment の epoch を比較し、一致すればその segment を（wrap が無ければ同一 segment に対して追加で mint して）そのまま返す、不一致なら新しい random segmentId/segmentKey で `sealAndActivateSegment`（旧 segment を sealed にする書き込みと新 segment の activate を同一操作にする——これが「後から新規 object が古い SegmentKey に追記されない」ことの保証そのもの）。`identity/bootstrap.ts` の `buildVaultCryptoBoundary` が組み立てて返す `activeSegment()` がそのまま `vault-mutation-sink.ts` の `activeSegment` オプションに渡せる。実 MLS self group（`rekey` で epoch を進める）を通した end-to-end test（`test/protocol/identity-vault-crypto.test.ts`）で、同一 epoch 内での再利用・epoch 変化後の seal + 新規 mint を検証した。
- [x] Add/Remove/Update/rekey 後に旧 SegmentKey へ新 object を追記しない。上記 `ActiveVaultSegmentManager` の設計そのもの（`sealAndActivateSegment` が唯一の segment 切り替え経路であるため、seal されていない segment は常に「現在 epoch に対応する最新の」ものだけになる）。
- [x] old ciphertext を mutation せず、新 epoch 向け wrap を作る restore grant を実装した。`identity/bootstrap.ts` の `buildRestoreTransferSource`（`vault/restore-transfer.ts` の `RestoreTransferSource`、peer restore transfer の送信側）の `readCurrentEpochWraps` が該当：既存の `resolver.resolveSegmentKey` で自分の現在 epoch 向け wrap から SegmentKey を平文に戻し、それを要求元の epoch（送信側自身の現在 epoch と一致する場合のみ許可——一致しなければ `Error` で拒否）向けに `createSegmentKeyWrap` で再 wrap するだけで、ciphertext 自体には一切触れない。実 MLS self group を通した end-to-end test（`test/protocol/identity-restore-transfer-source.test.ts`）で、`createRestoreTransferChunk`/`verifyRestoreTransferChunk` の実ラウンドトリップ、再 wrap が元の wrap のコピーでないこと、要求側が同じ SegmentKey で実際に object を復号できること、他 epoch への grant 拒否を検証した。
- [x] Remove 前 device が Remove 後 object を復号できない security test を書いた（`test/protocol/identity-vault-crypto.test.ts`）。実 MLS self group で device B を external join させ、device A が `removeMembers` で B を Remove（B はその commit を一切受信しない、素の「もう何も知らされない removed device」の状態）。Remove 後に mint された segment の wrap を、B の Remove 前のまま凍結された state から導出した VEK で `unwrapSegmentKey` しようとすると、MLS の forward secrecy により B の state はもう正しい epoch の exporter secret を持たず、AEAD タグ検証が失敗して reject されることを確認した。
- [x] epoch 遷移時に自分自身の旧 segment を自己 re-wrap する処理を実装した（`maintainSelfGroup`（`identity/bootstrap.ts`）拡張、新設の `selfGrantSegmentRewraps`）。**発見した制約**: `MlsVaultEpochKeyResolver.deriveVaultEpochKey` は self-group provider が持つ「現在の」state からしか VEK を導出できず、過去 epoch の VEK は MLS の forward secrecy により事後的に取得不可能（exporter secret は commit の度に丸ごと入れ替わる key schedule の産物であり、過去 epoch の分を保持する場所が無い——vendor の `historicalReceiverData`/`retainKeysForEpochs` も調査したが、これは `resumptionPsk`/`secretTree` 等の会話メッセージ用データであり `exporterSecret` は含まれない）。そのため「boot 時に遅れて再 wrap」ではなく「`reflectPendingSelfGroupCommits` が実際に epoch を進めたその場」で、まだメモリにある旧 `ClientState`（`oldState`）から VEK を導出し、`segments.allSegments` で旧 epoch のままの自分の segment を全て洗い出して新 epoch 向けに再 wrap する設計にした。`MaintainSelfGroupOptions` に `wraps`/`segments` を追加（省略可——vault content が無い device はこれまで通り no-op）。実 MLS self group（2 台目 device の外部 join → 1 台目の `maintainSelfGroup` が epoch 進行を検知）を通した end-to-end test（`test/protocol/identity-bootstrap.test.ts`）で、旧 epoch で mint した segment が新 epoch の wrap を持つよう更新され、同じ SegmentKey バイト列が引き続き復号できることを確認した。`main.ts` の `bootClient` から `IndexedDbVaultStore`（`wraps`/`segments` 両方を実装済み）を渡すよう結線した。

**完了条件:** Forward Secrecy を保ったまま、正規 peer の明示 grant による過去 vault restore ができる。

### 4.3 Peer restore transfer

- [ ] peer membership verification と restore approval UI contract を実装する。
- [-] manifest first、chunk hash、resume cursor を使う peer transfer frame の作成・検証と、verified records/session cursor の IndexedDB atomic import を実装した。実際の direct/relayed channel、projection rebuild、browser fault test は未実装。
- [x] frame 内の event signature、ciphertext hash/object ID、current-epoch SegmentKeyWrap を別々に検証する。actual MLS grant verification を接続した：`identity/bootstrap.ts` の `buildRestoreTransferVerifier(selfGroupStore, identityId)` が `RestoreTransferVerifier` を組み立てる。`VaultEventVerifier.verify`/`SegmentKeyWrapVerifier.verify` は両方とも同じ `verify(deviceId, bytes, signature)` 形なので、`MlsMembershipSegmentKeyWrapVerifier`（§4.2 で実装済み）を両方の検証にそのまま流用する——「event の actor」も「wrap の grantor」も、結局「この device kid は現在の self-group member か」という同じ問いだったため。実 MLS self group を通した end-to-end test（`test/protocol/identity-restore-transfer-verifier.test.ts`）で、実 member の event/wrap の受理と、self group に存在しない device の event の拒否を確認した。
- [x] interrupted cursor / tampered frame / stale grant / removed requester / replay の channel-level test を実装した。実 MLS self group を通した end-to-end test（`test/protocol/identity-restore-transfer-channel.test.ts`）で、(1) rekey で epoch が進んだ後に旧 epoch の wrap を含む frame が拒否されること（`recipientEpoch` パラメータと wrap 自体の epoch の不一致を `assertWrapCoverage` が検出）、(2) Remove された device が自分の（凍結された）epoch 向けの新規 grant を要求しても `buildRestoreTransferSource` が「grantor 自身の現在 epoch と一致しない」として拒否すること、(3) Remove 前に正当に署名された wrap が、署名自体は有効なままでも Remove 後の現在 member list に対する検証では失敗すること、を確認した。replay（session 完了後に FINAL でない過去 chunk を再送）は `test/protocol/restore-transfer-receiver.test.ts` に追加し、`'duplicate'` ではなく `'already complete'` エラーになることを確認した。
- [-] user-owned archive の endpoint-only AES-GCM envelope と、IndexedDB record reader から全 event/object と必要な SegmentKey を集める export snapshot builder を実装した。復元後の current MLS epoch だけへ SegmentKey を再 wrap し、raw record/wrap を atomic import する endpoint workflow を実装した。encrypted-only canonical file / Blob boundary も実装した。browser file picker/download UI と projection rebuild は未実装。

**完了条件:** mediator history storage なしで、新端末または TTL 外端末が foreground peer から全 vault を検証付きで復元できる。

## 5. Local JMAP client backend

### 5.1 Account transport abstraction

- [x] `AccountTransport`、`LocalVaultSession`、`RemoteJmapSession` の型を作った。
- [-] standard session discovery / API call / blob download を行う `RemoteJmapTransport` を実装した。既存 UI の account settings / authentication flow 移植は未実装。
- [ ] UI/feature call site を direct `JamClient` 依存から `AccountTransport` へ移す。
- [x] account routing を `biset:<did>` / `remote:<provider>:<id>` に固定する。
- [x] `AccountRouter` は一回の action を一つの account transport にしか解決せず、cross-backend JMAP batch を提供しない。

### 5.2 Local JMAP Gateway

- [x] `Session` と read-only local account capability を実装する。
- [-] memory read model と IndexedDB vault projection adapter 上の `Mailbox/get`、`Email/get`、`Email/query` read path を実装した。state mutation reducer はあるが、full projection rebuild は未実装。
- [x] full projection rebuild を実装した。`vault/projection-rebuild.ts` の `rebuildLocalJmapProjection` が、この identity が持つ全 `VaultEventV1`/`VaultObjectV1`（`VaultRecordReader.readVaultEvents`/`readVaultObjects`、増分の pack 一件ずつではなく全件）を対象に、`VaultDeliveryProjector` と同じ検証・復号ロジック（重複を避けるため `vault/mutation-records.ts` の `decryptVaultMutationRecords` へ共通化し、両者から呼ぶ形にリファクタした）を空の `base`（`{mailboxes: [], emails: []}`）に対して流し込む。SegmentKey は通常の read と同じ current-epoch `StoredSegmentKeyResolver` で解決するため、正しく動くのは §4.2 の self-grant（`maintainSelfGroup` の `selfGrantSegmentRewraps`）がこの identity の全 segment を現在 epoch まで運び続けている前提あってこそ、という設計依存を明記した。`vault/store.ts` に `VaultProjectionWriter`（`writeProjection`、event を伴わない projection 単体の書き込み——**新規 identity の最初の `vault_projection` row は他に何も seed しないため、これが唯一の書き込み経路**）を追加し `IndexedDbVaultStore` に実装、`identity/bootstrap.ts` の `buildLocalJmapProjectionRebuild(records, wraps, projections, selfGroupStore, identityId)` で実 self group に接続した。実 MLS self group を通した end-to-end test（`test/protocol/identity-local-jmap-projection-rebuild.test.ts`）で、新規 identity の空 projection 生成・永続化、実際の `message.add`（`buildMailMessageAdd`）からの再構築、self group に存在しない device の event 拒否（かつ拒否時に projection を書き込まないこと）を確認した。
- [ ] `Email/changes`、`Mailbox/changes`、query state を実装する。
- [-] `Email/set` の mailbox / keyword / tombstone 更新を immutable vault mutation intent → encrypted object → signed event → local transaction → shared vault-delivery outbox に接続した。mediator append retry、`Mailbox/set`、`Email/import` は未実装。
- [ ] `EmailSubmission/set` を outbound intent に変換する。
- [-] encrypted `VaultObjectV1` を SegmentKey resolver で検証・復号する local blob reader と range read を実装した（`vault/blob-reader.ts` の `VaultObjectBlobReader`、当初は fixture の `SegmentKeyResolver` を受け取るだけで実 self group には未接続だった）。`identity/bootstrap.ts` の `buildVaultBlobReader(objects, wraps, selfGroupStore, identityId)` で、他の boundary 関数と同じ current-epoch `StoredSegmentKeyResolver`/`MlsMembershipSegmentKeyWrapVerifier` を実 self group に接続した——これが「stored key wrap からの SegmentKey resolver」の残タスクだった。実 MLS self group を通した end-to-end test（`test/protocol/identity-vault-blob-reader.test.ts`）で、実 VEK での復号・range read・存在しない blob の拒否・範囲外 read の拒否を確認した。attachment chunk reader（一つの blob が複数 `VaultObjectV1` に分割される場合、PLAN.md §3.2 の chunked attachment object 自体が未実装）は依然未実装。
- [ ] same UI test を Local/Remote account の両方で実行する。

**完了条件:** Biset account は offline でも JMAP UI で過去 vault を一覧・検索・閲覧できる。

## 6. Transport adapters

### 6.1 DIDComm adapter

- [ ] DID resolution、service endpoint、capability discovery を新 protocol boundary に移す。
- [ ] DIDComm を external ingress、OOB、bootstrap、短い control に限定する。
- [ ] self-device history payload の outer per-device packed JWE fanout を停止する。
- [ ] external ingress の protected body + device capability/wrap の wire format を決める。
- [ ] replay、sender authentication、push wake-up、multidevice ingress の test を追加する。

### 6.2 Mail adapter

- [ ] SMTP / upstream JMAP input を raw RFC 5322 ingress に変換する。
- [ ] RCPT TO と address-to-identity resolution を実装する。
- [ ] raw mail、envelope、DKIM/ARC evidence を server-side decrypt せずに渡す。
- [-] endpoint の `MailIngressProjector` は opaque mail ingress を raw RFC 5322 object + encrypted JMAP metadata の `message.add` に変換し、ingress receipt / ACK outbox / sibling vault-delivery outbox を一 transaction に確定する。SMTP listener、address resolution、RFC 5322/MIME metadata parser、OpenPGP/Autocrypt projector は未実装。
- [-] endpoint-only の RFC 5322 header summary は Subject / Date / Message-ID / References を conservative に取り出して最初の JMAP metadata に使う。RFC 2047、address parser、MIME、OpenPGP protected headers は未実装。
- [-] endpoint-only OpenPGP packet decrypt/optional signature verification と strict RFC 3156 `multipart/encrypted` packet extraction を実装した。Autocrypt、DeltaChat protected headers、SecureJoin、decrypted MIME projector は未実装。
- [ ] outbound intent から client-side PGP/MIME を作り、SMTP/JMAP Submission する。
- [ ] `250` 後の TTL expiry policy を **DSN 型**または**4xx 型**のどちらかに決定・実装する。
- [-] PGP private-key credential は vault / peer restore の対象、全端末喪失への備えはユーザー管理の暗号化 recovery archive、core の恒久 key blob は置かない、と policy を決定した。OpenPGP.js による mail 専用鍵生成/packet 検証、暗号化 credential object/event schema、local atomic commit/outbox、shared delivery の検証・保存、署名/current epoch wrap/object を再検証して現行 credential を fail-closed に選ぶ endpoint-only reader は実装済み。restore approval、rotation / revocation、archive export/import は未実装。

### 6.3 ActivityPub adapter

- [ ] ActivityPub ingress / egress の canonical envelope を定義する。
- [ ] adapter object cache が vault archive にならない quota / TTL を実装する。
- [ ] first-party adapter boundary test を追加する。

## 7. Client UX と PWA

- [ ] Local vault account の初回作成 / unlock UX を実装する。
- [ ] ingress available / delivery available / restore requested の opaque push を実装する。
- [ ] iOS PWA では大容量 restore に foreground が必要であることを UI に明示する。
- [ ] restore request を送る UI と peer 側 approve/deny UI を実装する。
- [ ] resumable transfer progress、pause、failure、no-peer/no-archive の状態を表示する。
- [ ] device removal の「未来のデータを止めるが過去は回収できない」意味を UI に明示する。

## 8. Migration と relay retirement

- [ ] current relay data を read-only local vault へ import する tool を作る。
- [ ] import 後の message/thread/mailbox count と root/hash を照合する。
- [ ] new ingress の dual-write / hash comparison を導入する。
- [ ] new Biset identity を Local JMAP + vault primary にする。
- [ ] old relay を read-only migration source / grace-period fallback にする。
- [ ] user export/archive confirmation を作る。
- [ ] `jmapsmtp` を mailbox service から bounded Mail adapter / submission spool へ置換する。
- [ ] old relay data の deletion / retention date を product policy として決める。

## 9. Release gate

- [ ] `bun run typecheck` が通る。
- [ ] 新しい protocol test suite が通る。
- [ ] client build と anchor build が通る。
- [ ] core API review で history query / mailbox API がないことを確認する。
- [ ] mediator storage inspection で、expiry/ACK 後の payload が残らないことを確認する。
- [ ] one-copy delivery の容量測定が旧 per-device fanout より改善している。
- [ ] TTL 外端末、new device、removed device、all-device-loss の UX を受け入れテストする。
- [ ] iOS PWA foreground restore を実機で検証する。
- [ ] migration/export/recovery limitation を README/ARC に反映する。

## 10. 進捗ログ

| 日付 | Commit | 内容 |
| --- | --- | --- |
| 2026-08-21 | `c4ee298` | 旧 `src` を退避し、Vault Core の最小骨格と統合設計を追加 |
| 2026-08-21 | `f56188b` | 新 ARC/README の骨格を追加 |
| 2026-08-21 | `efc863c` | canonical/hash/schema validation と bounded in-memory IngressStore を追加 |
| 2026-08-21 | `2254ed9` | protocol source の整形 |
| 2026-08-21 | 作業中 | `biset-core` 内の identity / mediation / adapters 境界へ再編 |
| 2026-08-21 | `39008f4` | Local JMAP mutation と共有 vault-delivery outbox を原子的に保存。canonical delivery pack と MLS key-wrap 同梱を追加 |
| 2026-08-21 | `409a6dd` | delivery recipient snapshot / TTL を core policy に移し、idempotent append と causal-order outbox flush を追加 |
| 2026-08-21 | `ccc2aa9` | shared vault delivery append を current roster の device signature で認可 |
| 2026-08-21 | `25042c0` | pull した shared vault delivery を検証・projection・receipt/ACK outbox と一括 commit してから ACK |
| 2026-08-21 | `bb0a845` | current MLS epoch wrap、event signature、AEAD object を検証して Local JMAP projection を再計算 |
| 2026-08-21 | `6d96cd5` | cursor-based delivery sync と durable ACK retry、idempotent core ACK を追加 |
| 2026-08-21 | `faef01d` | signed vault-delivery pull を追加し、device ID のみでは payload を取得できないようにした |
| 2026-08-21 | `d944cbd` | bounded vault delivery の append / pull / ACK HTTP adapter と browser transport を追加 |
| 2026-08-21 | `8fb0bfa` | authorizer 注入なしでは relay を公開しない安全な core application composition を追加 |
| 2026-08-21 | `27af8c3` | bounded shared vault delivery を crash-safe SQLite へ永続化し、再起動後 pull を検証 |
| 2026-08-21 | `7866f95` | accepted MLS device roster の public projection を SQLite 永続化 |
| 2026-08-21 | `ff483d0` | roster-selected DID public key を使う Ed25519 device-control verifier を追加 |
| 2026-08-21 | `b068b22` | SQLite roster / delivery / authorizer / DID key verifier / HTTP を一体化した core deployment を追加 |
| 2026-08-21 | `cfe56a4` | SQLite restart 後の all-ACK body 消去、ACK 再送、TTL restore gap を検証 |
| 2026-08-21 | `3a8b3cc` | SQLite の quota eviction が再起動後も明示的な restore gap になることを検証 |
| 2026-08-21 | `d4a2002` | 署名付き restore poll、SQLite の短命 control store、bounded HTTP / browser transport を追加 |
| 2026-08-21 | `c0957b6` | client が restore gap を durable request state に保存し、同じ request ID で再送する workflow を追加 |
| 2026-08-21 | `b86d96f` | peer の signed restore poll と、承認後 offer の durable outbox / 再送を追加 |
| 2026-08-21 | `57b0d34` | manifest-first / resume cursor / frame hash を使う peer-only restore transfer frame を追加 |
| 2026-08-21 | `8cdcff8` | verified restore frame の records と resume session を IndexedDB で atomic commit |
| 2026-08-21 | `1457a73` | first-party adapter 向け SQLite ingress と offer 時の payload hash 検証を追加 |
| 2026-08-21 | `709ffe5` | adapter から recipient snapshot を受け取らず、core が accepted self-group roster から ingress 宛先を凍結 |
| 2026-08-21 | `647c54f` | signed ingress pull / durable ACK の narrow HTTP API と browser transport を追加。external offer は adapter 内部に維持 |
| 2026-08-21 | `d454d9d` | external ingress の verify/project → atomic local vault commit → ACK outbox 共通境界を追加 |
| 2026-08-21 | `27ed1a5` | OpenPGP 秘密鍵を vault credential とし、peer restore・ユーザー管理 recovery archive・Remove 時 rotation の policy を固定 |
| 2026-08-21 | `9d46dc5` | canonical OpenPGP private credential、encrypted vault object、signed credential event を追加 |
| 2026-08-21 | `4cff26d` | shared vault delivery で OpenPGP credential を検証・保存し、JMAP projection から分離 |
| 2026-08-21 | `e67981c` | OpenPGP credential の local atomic commit と shared delivery outbox sink を追加 |
| 2026-08-21 | `a135e8f` | endpoint-only OpenPGP 鍵生成と vault credential fingerprint / packet 検証を追加 |
| 2026-08-22 | `411c521` | verified OpenPGP credential から public certificate のみを DID / WKD / Autocrypt 向けに取り出す境界を追加 |
| 2026-08-22 | `3044a09` | endpoint-only OpenPGP credential reader を追加し、current epoch の再検証と fail-closed な現行鍵選択を実装 |
| 2026-08-22 | `d4b2297` | core 非依存の独立 recovery key で vault ciphertext/SegmentKey snapshot を保護する user-owned archive primitive を追加 |
| 2026-08-22 | `ad05cfb` | local vault 全 record と current SegmentKey から archive snapshot を組み立て、resolver key buffer を消去する export 境界を追加 |
| 2026-08-22 | `4510a2c` | archive 復元で旧 MLS secret を持ち込まず、新しい current self-group epoch 向け SegmentKey wrap を発行する preparation を追加 |
| 2026-08-22 | `80639c3` | archive の復号・current epoch rewrap・raw vault record の atomic local import を endpoint-only workflow として追加 |
| 2026-08-22 | `dffbc5a` | recovery archive の outer ciphertext だけを canonical file として encode/decode する browser export/import 基盤を追加 |
| 2026-08-22 | `199be4f` | encrypted-only recovery archive を browser Blob/File として扱う境界と identity 非露出 filename を追加 |
| 2026-08-22 | `079380f` | endpoint-only OpenPGP packet decrypt / optional signature verification を追加し、署名必須時の unsigned 受理を拒否 |
| 2026-08-22 | `af96b84` | strict RFC 3156 multipart/encrypted extractor を追加し、実暗号文で endpoint-only packet decrypt まで結合検証 |
| 2026-08-22 | `ffed586` | `message.add` の二 object 正本（encrypted JMAP metadata + unchanged raw RFC 5322）と projection / delivery 検証を追加 |
| 2026-08-22 | `721dfac` | endpoint mail ingress を raw mail vault record とし、ingress ACK と sibling delivery outbox を一 transaction に接続 |
| 2026-08-22 | `b5e71c6` | external ingress を最初の正規 endpoint に短期 lease し、同時 pull による二重 vault 正本化を防止 |
| 2026-08-22 | `8401919` | durable ingress ACK outbox を pull 前後に flush する endpoint 同期ループを追加 |
| 2026-08-23 | `ea66269` | mail の endpoint workflow を sibling vault-delivery outbox append に接続 |
| 2026-08-23 | `14f41dd` | `PLANMLSARCH.md` を追加し、core（DS）の roster install 認可モデルを RFC 9420/9750 に基づき確定 |
| 2026-08-23 | `1e888ae` | 読み取り専用 webvh resolver、vendored ts-mls + group/identity/suite 移植、`RosterInstallV1` installer 認可を追加 |
| 2026-08-23 | 作業中 | accepted MLS commit → `RosterInstallV1` producer と narrow HTTP エンドポイント `/v1/roster/install` を追加し、実 MLS group を使う end-to-end test で検証 |
| 2026-08-23 | 作業中 | did:webvh ベースの MLS Authentication Service を追加。leaf の実際の signature key と verificationMethod の一致を検証（fail-closed）。custom credential type は vendor 側デコード未実装のため使わず、既存 basic credential の wire 形式のまま |
| 2026-08-23 | 作業中 | `ClientState` を保持する `MlsSelfGroupStateStore`（`vault/store.ts` とは別 IndexedDB）と、それを使う具象 `MlsSelfGroupProvider` を追加。実 MLS group の genesis/rekey を通した VEK 導出まで検証 |
| 2026-08-23 | `c535a3e` | `src.bak/anchor/mediator/mls-ds.ts`（RFC 9750 準拠の既存 DS 実装）を self-group 専用（device kid 単位）に調整して SQLite へ移植。署名認可・narrow HTTP エンドポイントを 6 操作分追加 |
| 2026-08-23 | `2504b78` | MLS DS の残り 6 操作（self-remove、pending-removals クリア、deliveries pull、KeyPackage drop/count、groupsFor）に署名認可と HTTP エンドポイントを追加。12 操作すべてが揃った |
| 2026-08-23 | `fe8919f` | MLS DS の wire encode/decode を `protocol/mls-ds-wire.ts` へ移設し client/core で共有できるようにした |
| 2026-08-23 | `562b7bb` | `CoreMlsDeliveryTransport`（client 側 transport）を追加し、実際の HTTP ハンドラと繋いだ end-to-end test で wire の client/server 側の整合を検証 |
| 2026-08-23 | `7cea395` | `groupInfoFor`/`submitExternalCommit` の認可を device membership から identity 一致に修正（外部 join が構造的に不可能だったバグ） |
| 2026-08-23 | 作業中 | self-group bootstrap（`src/mls/self-group.ts`、`ensureSelfGroup`）を追加。`pullMlsGroupInfo` の「group 不在」と「認可失敗」混同バグも修正し、実 MLS/実 SQLite DS/実 HTTP を通した genesis + 外部 join の end-to-end test で検証 |
| 2026-08-23 | 作業中 | roster 取得 API（`GET /v1/roster/:identityId`）を追加し `ensureSelfGroupWithRosterInstall`/`installCurrentRosterProjection` で roster install まで接続。installer 認可ルール（直前 epoch の trusted device のみ）により新規参加者は自己 install できないという設計制約を発見し、既存メンバーが後で反映する前提の設計に修正。`test/protocol/mls-self-group-roster-install.test.ts` で genesis install と `processIncoming` 経由の commit 取り込み→反映を検証 |
| 2026-08-23 | 作業中 | `reflectPendingSelfGroupCommits`（`src/mls/self-group.ts`）を追加。既存メンバーが `pullDeliveries` + `processIncoming` で他 device の commit を取り込み、epoch が進んでいれば `installCurrentRosterProjection` で roster に反映する。呼び出しタイミング（起動時/定期実行）は endpoint 初期化と合わせて後続。`test/protocol/mls-self-group-roster-install.test.ts` に no-op ケースも追加 |
| 2026-08-23 | 作業中 | did:web mirror（`src/identity/web/`）を追加。`createGenesis`/`addDeviceVerificationMethod` に `didWebMirror: true` を渡すと、同じサブドメインの `/.well-known/did.json` に did:webvh の現在 state を did:web 形式（proof なし、SCID を含まない別 DID）で常時上書き同期する。Bluesky の atproto did:web 運用（ハンドルのドメインそのものが did:web domain、path segment なし）との互換のため、did:webvh・did:web とも今後は `biset.md:y` ではなく `y.biset.md` のサブドメイン形式に統一する方針（既存の path 形式 API 自体は後方互換のため残す）。`test/protocol/webvh-did-web-mirror.test.ts` で genesis 時の mirror 発行・device 追加時の再同期・`didWebMirror` 未指定時に何も書かないことを検証 |
| 2026-08-23 | 作業中 | key-package pool（`src/mls/keypackage-store.ts` の `IndexedDbMlsKeyPackageStore`、`src/mls/key-package-pool.ts` の `ensureKeyPackagePool`）を追加。`src.bak/mls/store.ts`/`src.bak/did/didcomm-devices.ts` の既存アルゴリズム（DS の実際の残数を問い合わせ不足分だけ mint/publish）を移植。実 DS/実 HTTP を通した end-to-end test（`test/protocol/mls-key-package-pool.test.ts`）で空プールからの補充・target 到達後の no-op・部分消費後の差分補充を検証 |
| 2026-08-23 | 作業中 | identity bootstrap（`src/identity/bootstrap.ts` の `createNewIdentity`）と最小限の new-user UI（`src/ui/account-create.ts`/`mnemonic.ts`、`src/main.ts` からの結線）を追加。root key 導出（`identity/keys.ts`/`seed.ts`）から self-group 参加・roster 反映・KeyPackage 補充までを一気通貫で行う。実 anchor + 実 core + 実 DID 解決を通した end-to-end test（`test/protocol/identity-bootstrap.test.ts`）で検証。副産物として、`bun build` の ESM 出力を `type="module"` 無しの `<script>` に埋め込んでいたビルド設定の既存バグ（`bootClient()` が一度もブラウザで実行されていなかった）を file:// 実機確認で発見・修正（`--format=iife`） |
| 2026-08-23 | 作業中 | `restoreIdentity`（`src/identity/bootstrap.ts`）を追加し recovery phrase による追加 device のログインに対応。`resolveByDomain`/`domainDidJsonlUrl`（`resolver.ts`/`identifier.ts`）で SCID 不明のまま `did.jsonl` から DID を読み、root key 一致を fail-closed 検証してから `registerDeviceAndJoinSelfGroup`（`createNewIdentity` と共有）へ。UI にログイン切替（`src/ui/account-create.ts`、`src/index.html` の `#nu-phrase`）を追加。`test/protocol/identity-bootstrap.test.ts` に 2 台目 device の外部 join・誤 phrase 拒否・存在しない identity 拒否を追加。`deliveryFloorForNewDevice` は vault delivery pull API 未配線のため暫定的に `0` 固定 — 既知の未解決事項として明記 |
| 2026-08-23 | 作業中 | `maintainSelfGroup`（`src/identity/bootstrap.ts`）を追加し `main.ts` の `bootClient` から boot 時に結線。`ownSignaturePrivateKey`（`src/mls/group.ts`）を新設し、`OwnKeyPackage` をメモリに保持し続けなくても保存済み `ClientState` から device の署名鍵を再構成できるようにした。実 DS/実 roster を通した end-to-end test で、genesis device の boot 時メンテナンスが後から復元された 2 台目 device を roster に反映することを検証 |
| 2026-08-23 | 作業中 | `maintainSelfGroup` の `deliveryFloorForNewDevice` を `currentVaultDeliveryLatestSeq`（`CoreVaultDeliveryTransport.pull` 経由）に配線した。roster に信頼済みの device しか vault-delivery pull を呼べないため、新規参加 device 自身（`restoreIdentity`）ではなく既存 device（`maintainSelfGroup`）側だけがこれを呼べる、という非対称性を確認。実 vault-delivery append を挟んだ end-to-end test で、2 台目 device の `deliveryFloor` が `0` ではなく実際の `latestSeq` になることを検証（`test/protocol/identity-bootstrap.test.ts`） |
| 2026-08-23 | 作業中 | PLAN.md §4.2「actual MLS VEK 導出・membership signer」を接続。`src/mls/segment-key-membership.ts`（`MlsMembershipSegmentKeyWrapVerifier`/`Signer`、grantor 署名を現在の self-group member list に対して検証）、`group.ts` の `memberSignaturePublicKey`、`identity/bootstrap.ts` の `buildVaultCryptoBoundary` を追加。実 MLS self group を通した end-to-end test（`test/protocol/identity-vault-crypto.test.ts`）で `createSegmentKeyWrap`/`resolveSegmentKey` の実ラウンドトリップと、group に存在しない grantor の検証拒否を確認 |
| 2026-08-23 | 作業中 | `vault/store.ts` に `ActiveVaultSegmentStore`（`vault_segments` の読み書き）、`vault/active-segment.ts` に `ActiveVaultSegmentManager` を追加し、`buildVaultCryptoBoundary` の `activeSegment()` として配線した。self-group epoch が進むたびに旧 segment を seal し新 segment を mint する（PLAN.md §4.2 の segment seal / 旧 SegmentKey 追記禁止）。実 MLS self group で `rekey` を挟んだ end-to-end test で、同一 epoch 内の再利用と epoch 変化後の seal + 新規 mint を検証 |
| 2026-08-23 | 作業中 | PLAN.md §4.2 の security test（Remove 前 device が Remove 後 object を復号できない）を `test/protocol/identity-vault-crypto.test.ts` に追加。実 MLS self group で device B を external join → device A が `removeMembers` で Remove（B は commit 未受信のまま）→ Remove 後に mint された segment の wrap を B の凍結 state から unwrap しようとすると forward secrecy により AEAD 検証が失敗することを確認 |
| 2026-08-23 | 作業中 | PLAN.md §4.3「actual MLS grant verification」を接続。`identity/bootstrap.ts` の `buildRestoreTransferVerifier` が、event verifier と SegmentKeyWrap verifier を同じ `MlsMembershipSegmentKeyWrapVerifier` インスタンスで賄う（両方とも `verify(deviceId, bytes, signature)` という同じ形なため）。実 MLS self group を通した end-to-end test（`test/protocol/identity-restore-transfer-verifier.test.ts`）で検証 |
| 2026-08-23 | 作業中 | PLAN.md §4.2 の restore grant を実装。`identity/bootstrap.ts` の `buildRestoreTransferSource`（peer restore transfer 送信側、`RestoreTransferSource`）が `readCurrentEpochWraps` で既存 SegmentKey を要求元の epoch 向けに再 wrap する（ciphertext 非改変、他 epoch への grant は拒否）。`createRestoreTransferChunk`/`verifyRestoreTransferChunk`/`buildRestoreTransferVerifier` を繋いだ実 end-to-end test（`test/protocol/identity-restore-transfer-source.test.ts`）で、要求側が実際に転送された object を復号できるところまで検証 |
| 2026-08-23 | 作業中 | PLAN.md §3.3 の shared vault delivery を MLS self group に接続。`identity/bootstrap.ts` の `buildVaultDeliveryProjector` が既存の `VaultDeliveryProjector` に実 `MlsVaultEpochKeyResolver`/`MlsMembershipSegmentKeyWrapVerifier` を渡す。実 MLS self group + `buildVaultCryptoBoundary` の segment を通した end-to-end test（`test/protocol/identity-vault-delivery-projector.test.ts`）で、mutation record の pack 化から検証・復号・projection まで、および self group に存在しない device の event 拒否を確認 |
| 2026-08-24 | 作業中 | PLAN.md §4.2「epoch 遷移時の自己 re-wrap」を実装。`maintainSelfGroup`（`identity/bootstrap.ts`）が `reflectPendingSelfGroupCommits` で epoch が実際に進んだ瞬間、まだメモリにある旧 `ClientState` から VEK を導出して自分の旧 epoch segment を全て新 epoch 向けに再 wrap する（新設 `selfGrantSegmentRewraps`、`MaintainSelfGroupOptions` に任意の `wraps`/`segments` を追加）。vendor の `historicalReceiverData`（`retainKeysForEpochs`）を調査したが `exporterSecret` を保持しないため使えないと判明——「事後的な救済」ではなく「遷移の瞬間の処理」が必須という結論に至った。`main.ts` の `bootClient` から `IndexedDbVaultStore` を渡すよう配線。実 MLS self group（2 台目 device の外部 join で 1 台目の epoch が進む）を通した end-to-end test（`test/protocol/identity-bootstrap.test.ts`）で、旧 epoch の segment が新 epoch の wrap を得て同じ SegmentKey バイト列を引き続き復号できることを確認 |
| 2026-08-24 | 作業中 | PLAN.md §5.2「full projection rebuild」を実装。`vault/mutation-records.ts` に `VaultDeliveryProjector` と共通の検証・復号ループ（`decryptVaultMutationRecords`）を抽出し、`vault/projection-rebuild.ts` の `rebuildLocalJmapProjection`（全 event/object から空 base への再構築）と両方から呼ぶ形にリファクタ。`vault/store.ts` に `VaultProjectionWriter`（event 無しの projection 単体書き込み、新規 identity の最初の projection row を seed する唯一の経路）を追加。`identity/bootstrap.ts` の `buildLocalJmapProjectionRebuild` で実 self group に接続。実 MLS self group を通した end-to-end test（`test/protocol/identity-local-jmap-projection-rebuild.test.ts`）で、空 identity の seed、実 `message.add` からの再構築、不正 device の event 拒否時に projection を書き込まないことを確認 |

| 2026-08-24 | 作業中 | PLAN.md §5.2「stored key wrap からの SegmentKey resolver」を接続。`identity/bootstrap.ts` の `buildVaultBlobReader` が既存の `VaultObjectBlobReader`（`vault/blob-reader.ts`、以前は fixture の `SegmentKeyResolver` しか受け取っていなかった）に実 `StoredSegmentKeyResolver`/`MlsMembershipSegmentKeyWrapVerifier` を渡す。実 MLS self group を通した end-to-end test（`test/protocol/identity-vault-blob-reader.test.ts`）で、実 VEK での復号・range read・存在しない blob/範囲外 read の拒否を確認した |

| 2026-08-24 | 作業中 | PLAN.md §4.3「stale grant / removed requester / replay の channel-level test」を実装。実 MLS self group を通した end-to-end test（`test/protocol/identity-restore-transfer-channel.test.ts`）で、rekey 後の旧 epoch wrap 拒否、Remove された device が自分の凍結 epoch 向け grant を要求しても拒否されること、Remove 前に有効だった wrap の署名が Remove 後は現在 member list に対する検証で失敗することを確認。replay（session 完了後の非-final chunk 再送）は `test/protocol/restore-transfer-receiver.test.ts` に追加し、`'duplicate'` ではなく `'already complete'` になることを確認 |

| 2026-08-24 | 作業中 | PLAN.md §3.1「browser restart / partial write / migration failure の test harness」を実装。`fake-indexeddb` を devDependency に追加し、`IndexedDbVaultStore` を初めて実 IndexedDB に対して動かすテスト（`test/protocol/vault-store-durability.test.ts`）を作成。close→再 open での生存確認、実 unique key constraint による ingress 重複防止確認、v4 相当（`vault_restore_transfer_state` 無し）から v5 への実 schema upgrade で既存データが残り新 store が使えることを確認 |

| 2026-08-24 | 作業中 | PLAN.md §2.3/§3.1「同時 ACK / duplicate offer / authorizer rejection の coverage」を実装。同時 ACK のテストを書く過程で `SqliteVaultDeliveryStore.acknowledge` の実レース bug（`authorizer.verifyAck` の await 前に読んだ stale な `row.state` を使っていたため、expire() と競合すると expired な delivery が completed に蘇り得た）を発見し修正——state の再読み取り+書き込みを一つの同期 transaction に収めた。修正前に実際に失敗する regression test で確認。duplicate offer（同一 offer 再送=no-op、衝突 offer 再送=拒否）と `rosterBackedRestoreControlAuthorizer` の `verifyOffer`/`verifyCancel` 拒否も追加 |

新しい作業を始める際は、該当する checkbox を `[-]` にし、完了時に `[x]`、進捗ログに commit と検証結果を記録する。
