# Biset Vault Core — 実装作業工程

*最終更新: 2026-08-21 / 現在の基準 commit: 作業中*

この文書は、実装を順番に進めるためのチェックリストである。設計の根拠、wire schema、状態機械、security invariant の詳細は [`PLANIMPLEMENTATION.md`](PLANIMPLEMENTATION.md) を正とする。本書は「次に何を作るか」「どこまで終わったか」「何を満たせば次へ進めるか」を示す。

## 0. 現在地

- [x] 旧 client を `src.bak/` に、旧 `jmapsmtp` を `jmapsmtp.bak/` にローカル退避した。
- [x] 新しい `src/` の client / anchor / protocol の最小骨格を作った。
- [x] 新設計の統合文書 `PLANIMPLEMENTATION.md` を作った。
- [x] 新しい ARC/README の骨格を作った。
- [x] canonical JSON、domain-separated hash、ingress schema validation を実装した。
- [x] memory-only の bounded `IngressStore` を実装し、TTL、quota、recipient snapshot、一台の authorised ACK、payload 削除をテストした。
- [x] core を `identity`（anchor）、`mediation`、`adapters` に概念分離し、初期 deployment は一つの `biset-core` binary に統合した。
- [-] IndexedDB の local vault schema、atomic ingress commit、object crypto、flat manifest は存在するが、ingest workflow と durable recovery は未実装。
- [ ] production 用の mediator persistence / MLS device authorizer / HTTP binding はまだ存在しない。
- [ ] Local JMAP Gateway、MLS VEK 導出、DIDComm/Mail adapter は未実装である。SegmentKey の object encryption と、VEK を入力に取る wrap primitive は実装済みである。

**次に着手する工程:** §2.3 の vault delivery protocol と、§3 の durable local vault の基盤。`MemoryIngressStore` を HTTP に公開する前に、device authorization と永続化の境界を設計・実装する。

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
- [x] `src/protocol/ingress.ts` に `IngressEnvelopeV1` と `IngressAckV1` を定義する。
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
- [-] trusted-device roster を mediation authorizer adapter に接続した。Ingress ACK / delivery ACK の実際の DID signature verifier は未実装。
- [ ] in-memory Map を crash-safe bounded persistence adapter に置換する。
- [ ] tombstone retention / dedup retention / quota eviction の数値を policy として決める。
- [ ] `offer` / `pull` / `ack` / `status` を authentication 付き core API に結び付ける。
- [ ] restart、同時 ACK、duplicate offer、quota eviction、authorizer rejection の integration test を追加する。

**完了条件:** core restart 後も body を誤って復活させず、未 authorised device の ACK で body を消せない。

### 2.3 Shared VaultDeliveryStore

- [x] `VaultDeliveryItemV1`、`VaultDeliveryAppendV1`、`VaultDeliveryAckV1`、`DeliveryPullResult` を `src/protocol/vault.ts` に定義する。
- [x] append 時の `recipientsAtAppend` は、client input でなく core の trusted-device roster から immutable に取得する。
- [x] payload body を一コピー、端末ごとには ACK/cursor だけを持つ in-memory store を実装する。recipient snapshot と TTL は core policy が決定する。
- [x] all-ACK 時の body 削除を実装する。
- [x] local delivery outbox の再送を重複配送にしないため、core append を client-generated `appendId` で idempotent にする。
- [-] TTL / quota expiry 時に `retainedFrom` と gap record を更新する。in-memory reference は実装済み、quota の境界 test と durable persistence は未実装。
- [x] 古い cursor の pull が必ず `restoreRequired` を返すよう実装する。
- [x] new device を過去 item の recipient set に遡及追加しない test を書く。
- [ ] N devices でも payload copy が一つだけである storage test を書く。

**完了条件:** per-device DIDComm queue を使わず、共有 body + cursor/ACK だけで sibling devices を TTL 内 catch-up できる。

### 2.4 Restore control

- [x] `RestoreRequestV1`、`RestoreOfferV1`、cancel / expiry schema と canonical signing bytes を定義する。
- [-] in-memory の short-lived restore control store を実装した。MLS authorizer、durable bounded persistence、peer availability は未実装。
- [-] restore store の API は request / offer / cancel の control 型だけを受け付け、history/blob/chunk を受け付けない。production storage boundary の test は未実装。
- [ ] requester が `restoreRequired` から restore UI/state へ遷移する client contract を定義する。
- [ ] peer への opaque push / control notification を定義する。

**完了条件:** TTL 外端末は不足を明確に検出でき、peer が不在なら曖昧に同期成功したように見えない。

## 3. Endpoint vault

### 3.1 Local persistence abstraction

- [-] `IndexedDbVaultStore` から projection だけを読む `VaultProjectionReader` boundary を抽出し、Local JMAP adapter に接続した。event/object write と migration の testable abstraction は未抽出。
- [x] IndexedDB version 2 schema と store 作成を実装する。
- [x] store: `vault_events`、`vault_objects`、`vault_chunks`、`vault_segments`、`vault_key_wraps` を作る。
- [x] store: `vault_manifests`、`vault_projection`、`vault_jmap_state`、`vault_outbox`、`vault_delivery_state`、`vault_restore_state` を作る。
- [x] ingress receipt / object / event / projection / JMAP state / ACK outbox を単一 transaction にする。
- [x] local JMAP mutation の object / event / projection / JMAP state / shared vault-delivery outbox を単一 transaction にした。browser fault injection は未実装。
- [-] outbox の causal-order flush / append idempotency boundary を実装した。IndexedDB outbox の index、retry backoff、actual core HTTP transport は未実装。
- [ ] browser restart、partial write、migration failure の test harness を作る。

**完了条件:** network がなくても、再起動後に vault root と Local JMAP state を同じ状態へ復元できる。

### 3.2 Event / object / manifest

- [-] immutable `VaultEventV1` の ID、署名対象、actor sequence を実装する。signer interface と canonical event ID は実装済み、MLS/device signer 接続は未実装。
- [-] AES-GCM による encrypted `VaultObjectV1` と SegmentKey/VEK wrap primitive を実装した。chunked attachment object と MLS exporter 接続は未実装。
- [-] event signature、parent reference、duplicate event、replay の validation を実装する。署名 verify の interface は実装済み、store-level validation は未実装。
- [ ] edit / tombstone / read / mailbox / reaction の競合規則を kind ごとに固定する。
- [x] manifest root と event/object set の diff を実装する。階層 Merkle proof と durable checkpoint は未実装。
- [-] mailbox / keyword / tombstone mutation event の deterministic JMAP projection reducer を実装した。message.add、attachment、full vault scan/checkpoint persistence は未実装。
- [ ] duplicate、offline concurrent write、interrupted transfer の convergence test を書く。

**完了条件:** 二端末が同じ検証済み event/object 集合から同じ manifest root と JMAP projection を作る。

### 3.3 Ingress-to-vault transaction

- [ ] `src/vault/ingest.ts` に raw ingress の validate → object/event → projection → ACK outbox transaction を実装する。
- [ ] ACK outbox の retry / idempotence を実装する。
- [ ] crash が ACK 前なら payload を再 pull でき、ACK 後なら local state が必ず存在することを test する。
- [ ] duplicate ingress ID / payload hash を安全に処理する。

**完了条件:** `IngressAckV1` が「端末が受信した」ではなく「vault へ durable commit した」を正しく意味する。

## 4. MLS self group と vault cryptography

### 4.1 MLS integration boundary

- [-] new core 用の最小 `MlsSelfGroupProvider` / fixed VEK exporter boundary を抽出した。現行 MLS group implementation の移植は未実装。
- [-] accepted MLS epoch だけで更新する public trusted-device roster projection と、それを使う delivery / restore authorizer adapter を実装した。actual MLS commit / DID publishing / DID signature verifier との接続は未実装。
- [-] fixed label/context/32-byte output の `deriveVaultEpochKey(group)` boundary を実装した。実際の MLS group adapter への接続は未実装。
- [ ] VEK を永続化しないことを code review / test で保証する。

### 4.2 SegmentKey lifecycle

- [x] random SegmentKey で payload を一度だけ AEAD encrypt する。
- [-] VEK を入力に取る署名付き `SegmentKeyWrapV1` の AEAD wrap/unwrap と、current epoch の stored wrap だけを使う SegmentKey resolver を実装した。actual MLS VEK 導出・membership signer は integration 待ちである。
- [ ] MLS commit durable acceptance 後に active segment を seal する。
- [ ] Add/Remove/Update/rekey 後に旧 SegmentKey へ新 object を追記しない。
- [ ] old ciphertext を mutation せず、新 epoch 向け wrap を作る restore grant を実装する。
- [ ] Remove 前 device が Remove 後 object を復号できない security test を書く。

**完了条件:** Forward Secrecy を保ったまま、正規 peer の明示 grant による過去 vault restore ができる。

### 4.3 Peer restore transfer

- [ ] peer membership verification と restore approval UI contract を実装する。
- [ ] manifest first、chunk hash、resume token を使う chunked transfer を実装する。
- [ ] ciphertext と current-epoch SegmentKeyWrap を別々に検証する。
- [ ] interrupted transfer / stale grant / removed requester / replay の test を書く。
- [ ] user-owned archive を peer と同じ restore source interface に追加する。

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
- [ ] `Email/changes`、`Mailbox/changes`、query state を実装する。
- [-] `Email/set` の mailbox / keyword / tombstone 更新を immutable vault mutation intent → encrypted object → signed event → local transaction → shared vault-delivery outbox に接続した。mediator append retry、`Mailbox/set`、`Email/import` は未実装。
- [ ] `EmailSubmission/set` を outbound intent に変換する。
- [-] encrypted `VaultObjectV1` を SegmentKey resolver で検証・復号する local blob reader と range read を実装した。stored key wrap からの SegmentKey resolver / attachment chunk reader は未実装。
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
- [ ] client で OpenPGP、Autocrypt、DeltaChat protected headers、SecureJoin を処理する。
- [ ] outbound intent から client-side PGP/MIME を作り、SMTP/JMAP Submission する。
- [ ] `250` 後の TTL expiry policy を **DSN 型**または**4xx 型**のどちらかに決定・実装する。
- [ ] PGP private-key credential の self-device restore / revoke / export policy を実装する。

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

新しい作業を始める際は、該当する checkbox を `[-]` にし、完了時に `[x]`、進捗ログに commit と検証結果を記録する。
