# PLANIMPLEMENTATION.md — Biset Vault Core 実装計画

*Status: 提案・実装計画。2026-08-21。端末保有 vault、MLS self group、短期 mediator 配送、Local JMAP、ならびに DIDComm / Mail / ActivityPub transport adapter の設計と移行を、この文書に統合する。旧 `PLANVAULT.md` と `PLANTRANSPORT.md` は本書へ統合済みである。*

## 0. この計画が決めること

Biset の正本を JMAP/SMTP relay のメールボックスから、各ユーザー端末が保持する暗号化 vault へ移す。

この計画における役割は次のとおりである。

| 層 | 正本・責務 | 保持しないもの |
| --- | --- | --- |
| Biset client | vault、検索用 projection、JMAP UI、端末鍵 | 他端末の代理としての永続配送責務 |
| Vault | メッセージ、会話状態、添付、設定、監査イベントの完全複製 | サーバー上のメールボックス |
| MLS self group | 同一 identity の端末集合、端末追加・削除、vault 鍵世代 | メール履歴そのものの配送ログ |
| mediator / anchor | DID・端末 endpoint の発見、短期 buffer、配送状態、push | 全履歴、JMAP `Email/get` / `Email/query`、長期 blob archive |
| transport adapter | 外部 protocol の ingress / egress | vault の正本、独自の mailbox DB |
| Local JMAP Gateway | vault を既存 client が読むための JMAP 表現 | remote JMAP server の代替 |

従って「storage をなくす」は、データを消す意味ではない。**Biset 運営サーバーがユーザー履歴を恒久保存する責務を捨て、正本を端末群へ移す**という意味である。

### 0.1 設計上の主要決定

1. `biset client` は JMAP client のまま維持する。Biset identity では Local JMAP Gateway を通じて local vault を読み、通常の外部アカウントでは既存の remote JMAP server を読む。
2. `biset core` は `biset-anchor` と現行 `jmapsmtp` を再編した、protocol / mediator / adapter host である。Biset vault の永続メールストアにはならない。
3. self-device の履歴同期は MLS self group を認可・鍵世代の基盤とする。ただし MLS epoch ciphertext を履歴 archive にしない。
4. vault payload は一度だけ暗号化し、端末ごとに payload を複製しない。端末ごとの差は小さい ACK・cursor・鍵 wrap に限定する。
5. mediator が保持できる payload は、未確認の ingress または未 ACK の vault delivery だけであり、どちらも TTL と quota を持つ。
6. TTL を超えた端末は信頼を失わない。`restore-required` として、新端末と同じ復元フローを行う。TTL による MLS Remove や「repair」状態は導入しない。
7. v1 の adapter は core と同一 release の first-party module とする。実行時 plugin loader は作らない。
8. core の初期実装は TypeScript とする。Rust 化は protocol が固定され、性能・隔離・公開 daemon の要件が明確になった時点で再評価する。

### 0.2 成功条件

- Biset identity の `Email/get`、`Email/query`、`Mailbox/get` は、ネットワーク上の JMAP mailbox ではなく local vault から返る。
- 端末がオンラインであれば、同一 identity の vault object は一コピーの短期 object と ACK/cursor により他端末へ追随する。
- 全端末が ACK した object は mediator から削除される。いずれかが長期不在でも TTL を越えれば削除される。
- TTL 外端末は、mediator が返す明示的な `restoreRequired` により、既存端末またはユーザー所有 archive から復元を開始できる。
- anchor / core の永続 DB だけから、ユーザーのメール・会話・添付・検索結果を復元できない。
- 端末を MLS Remove した後に作られた vault object を、その removed device が復号できない。

### 0.3 非目標

- 「全端末がオフラインでも、無期限に外部メールを受信できる」こと。これは誰かが無期限 store-and-forward storage を持たない限り実現できない。
- 端末 Remove 後、当該端末がすでに受け取った過去データを暗号的に回収すること。
- v1 で任意の第三者 adapter を安全にロードする runtime plugin marketplace。
- v1 で local vault と remote JMAP account を双方向同期すること。
- オフライン端末をリアルタイムに完全一致させること。正しい定義は、接続機会があれば同じ signed event 集合へ収束することである。

## 1. 用語と端末状態

### 1.1 用語

- **identity**: webvh DID を中心とする Biset の一人の利用者。
- **device**: identity の MLS self group に属する端末。device ID は MLS leaf identity と DID key を束ねる安定 ID である。
- **vault**: 端末ローカルにある、イベント、暗号化 object、添付、manifest、JMAP projection の集合。
- **object**: vault に保存される不変の暗号化 payload。一度作った body の内容・hash は変更しない。
- **event**: object の生成、編集、削除、既読、ラベル、設定変更等を表す署名付き不変イベント。
- **manifest**: 端末が保有する object/event hash 集合と checkpoint を表す検証可能な索引。
- **ingress**: DIDComm、mail、ActivityPub 等から、最初に Biset identity へ入るデータ。
- **vault delivery**: ある端末で durable に vault 化された object を sibling devices へ知らせ、必要時に渡す経路。
- **restore**: 新端末または TTL 外端末が、正規 peer から過去 vault を再配布してもらう操作。

### 1.2 端末状態は二系統に分ける

端末の信頼状態と配送状態を混同しない。

| 種別 | 状態 | 意味 | 変更者 |
| --- | --- | --- | --- |
| trust | `trusted` | self group の有効端末。今後の鍵・配送を受けられる | 明示的 MLS Add / Remove |
| trust | `revoked` | 紛失・侵害等で明示的に除外された端末 | 明示的 MLS Remove |
| delivery | `delivery-active` | mediator の保持範囲から通常 catch-up できる | durable ACK により進行 |
| delivery | `restore-required` | 保持開始位置より cursor が古く、peer/archive 復元が必要 | TTL / retention により自動 |

`restore-required` は `revoked` ではない。TTL は storage の有界化の規則であり、端末がデータを読む資格を奪うセキュリティ操作ではない。

### 1.3 「repair」を置かない理由

当初は、短い欠落だけを mediator 経由で埋める `repair` 状態を考えた。しかし v1 では採用しない。

- mediator が保持していない payload を、保持端末から pull して一時保存する仕組みを作ると、restore と別の payload relay・認可・失敗回復・quota を二重実装する。
- TTL を越えた欠落は量を事前に限定できず、数 KB と数 GB を同じ状態遷移で扱えない。
- 「TTL 内なら mediator の短期 delivery、外なら peer/archive restore」という二分の方が、利用者にも実装にも明確である。

将来、十分な利用実績の後に小容量・上限固定の repair を追加する余地は残すが、v1 の状態機械は `delivery-active` と `restore-required` の二つだけにする。

## 2. 全体アーキテクチャ

```text
外部送信者 / 外部ネットワーク
  DIDComm / Mail / ActivityPub
             │
             ▼
     Transport adapter ──┐
                         ▼
                  Biset core / mediator
        endpoint discovery, short ingress buffer,
        vault-delivery buffer, ACK/cursor, push
                         │
              小さい control / 一時暗号文
                         │
             ┌───────────┴───────────┐
             ▼                       ▼
      Biset client A           Biset client B
       Local vault              Local vault
       Local JMAP Gateway       Local JMAP Gateway
             │                       │
             └──── MLS self group ───┘
                membership / epoch keys
```

mediator は二種類の短期 storage を持てる。両者を「mailbox」と呼ばないことが重要である。

| buffer | 入る時点 | 削除条件 | 恒久正本か |
| --- | --- | --- | --- |
| ingress buffer | 外部 payload がまだどの端末にも durable save されていない | 現在 trusted な端末一台の署名付き `IngressAck`、または TTL | いいえ |
| vault delivery buffer | すでに一端末で vault object 化された | append 時の全宛先の durable ACK、または TTL | いいえ |

通常の vault delivery は「暗号文本体一コピー + 宛先 device ごとの小さい ACK 状態」である。N 台に N 個の payload を複製する per-device fanout を正本配送には使わない。

## 3. Vault データモデル

### 3.1 event log と object

vault は literal Git repository ではない。Git 的な利点、すなわち content address、immutable object、signed append-only event、manifest 差分を採用する。

| 種類 | 内容 | 役割 |
| --- | --- | --- |
| `VaultEventV1` | message、edit、tombstone、mailbox change、reaction、read state、setting 等 | 競合解決と監査の正本 |
| `VaultObjectV1` | 暗号化された RFC 5322 / JMAP message / 添付 chunk 等 | 大きい payload |
| `ManifestV1` | event/object hash、segment、checkpoint、Merkle root | 差分発見と検証 |
| `ProjectionCheckpointV1` | JMAP query 用の reducer/index の世代 | 高速なローカル読み出し |

イベントを不変にし、編集・削除を後続 event として表す。削除は payload の物理消去を約束しない tombstone とする。競合規則（LWW、actor sequence、または型ごとの merge 規則）は event kind ごとに明示する。

### 3.2 必須の識別子

```ts
type IdentityId = string;      // DID から canonical に導出
type DeviceId = string;        // self group leaf と endpoint key に対応
type VaultEventId = string;    // actor + actorSeq + hash
type VaultObjectId = string;   // multihash(ciphertext / canonical header)
type SegmentId = string;       // random, immutable
type IngressId = string;       // random, adapter namespace を含む
type DeliverySeq = bigint;     // identity ごとの単調増加値
type CheckpointId = string;    // manifest root / projection state
```

すべての署名対象は canonical JSON/CBOR を固定する。hash algorithm、encoding、時刻の精度、署名 domain separation を `src/protocol/canonical.ts` に固定し、test vector を置く。

### 3.3 `VaultEventV1`

```ts
interface VaultEventV1 {
  version: 1;
  id: VaultEventId;
  identityId: IdentityId;
  actorDeviceId: DeviceId;
  actorSeq: number;
  kind: 'message.add' | 'message.edit' | 'message.tombstone'
      | 'mailbox.set' | 'keyword.set' | 'thread.set'
      | 'reaction.set' | 'read.set' | 'settings.set';
  targetIds: string[];
  objectRefs: VaultObjectId[];
  parents: VaultEventId[];
  createdAt: string;
  signature: Uint8Array;
}
```

受信時には、identity、trusted device、actor sequence、署名、parent、object hash、event ID を検証する。検証済み event だけが projection に反映される。

### 3.4 blob と添付

- 添付は固定上限の暗号化 chunk に分割し、chunk hash を content address とする。
- message object は添付 manifest を参照するだけで、添付を event に inline しない。
- download は range/resume を許す。object hash を検証するまで利用可能扱いにしない。
- core は添付の全文検索・サムネイル生成・恒久 CDN 化をしない。

### 3.5 garbage collection

端末 local vault の GC は、参照を失った object を直ちに消さない。最低限、checkpoint/snapshot の保持、復元能力、ユーザー export の完了を考慮する。

- append-only history を全端末が無期限に持つことは v1 の必須条件ではないが、勝手な compaction は禁止する。
- compaction は signed snapshot を新 event として作り、必要な端末が snapshot を durable に確認した後だけ行う。
- mediator の TTL 削除は local vault の GC を意味しない。

## 4. MLS self group と vault 鍵

### 4.1 MLS の担当範囲

MLS self group は、同一 identity の端末を認可し、鍵世代を進める。会話相手との MLS group とは別である。

MLS が直接担当しないものは、過去 vault の自動復号・履歴 archive・端末の物理消去である。新端末が全履歴を得るのは、正規の既存端末が明示的に vault を再配布するからであり、MLS 加入の副作用ではない。

### 4.2 Vault Epoch Key (VEK)

各 self group epoch `e` から exporter で次を導出する。

```text
VEK_e = MLS-Exporter(
  label   = "biset/vault/epoch-key/v1",
  context = canonical(selfGroupId, e),
  length  = 32
)
```

- label と context は protocol 定数であり、他目的の exporter secret と混用しない。
- `VEK_e` は永続保存しない。利用時に MLS state から導出し、使用後に破棄する。
- exporter API が `src/mls/group.ts` の `exportSecret` として利用可能か、label/context/epoch を明示して検証する。

### 4.3 SegmentKey と一度だけの payload 暗号化

VEK で各 object を直接暗号化しない。epoch ごとに random `SegmentKey` を作り、payload は SegmentKey で一度だけ暗号化する。

```text
ciphertext = AEAD_Encrypt(SegmentKey, object plaintext, object AAD)
wrap       = AEAD_Encrypt(VEK_e, SegmentKey, segment AAD)
```

```ts
interface VaultObjectV1 {
  version: 1;
  objectId: VaultObjectId;
  segmentId: SegmentId;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  ciphertextHash: Uint8Array;
  plaintextLength: number;
  aad: Uint8Array;
}

interface SegmentKeyWrapV1 {
  version: 1;
  identityId: IdentityId;
  selfGroupId: string;
  segmentId: SegmentId;
  sourceEpoch: MlsEpoch; // decimal uint64 string
  recipientEpoch: MlsEpoch; // decimal uint64 string
  nonce: Uint8Array;
  aad: Uint8Array;
  wrappedSegmentKey: Uint8Array;
  grantorDeviceId: DeviceId;
  grantedAt: string;
  signature: Uint8Array;
}
```

この方式により、過去 object を新端末へ与えるときに payload を再暗号化・再 upload せず、current VEK で包み直した小さい `SegmentKeyWrapV1` だけを渡せる。

現在 `src/vault/crypto.ts` には、この下位プリミティブを実装している。caller が 32-byte VEK を渡すと、`identityId` / self group / segment / source epoch / recipient epoch / grantor device を canonical AAD に束縛して AES-GCM wrap し、その全体に grantor の署名を付ける。unwrap は metadata と AAD の一致、署名、AEAD tag のすべてを確認する。**ここで渡す VEK が MLS exporter 由来であり、grantor が current member であることの確認はまだ未接続**で、§12 M0/M2 の責務である。

`src/vault/segment-key-resolver.ts` は current self-group epoch を得て、その `(identityId, segmentId, recipientEpoch)` の stored wrap だけを読み、current epoch VEK で unwrap する。旧 epoch の wrap へ fallback しないため、新端末 / TTL 外端末には trusted peer の current-epoch grant が必要になる。VEK は resolver 内で使用後に zeroize し、IndexedDB には key wrap だけを保存する。

### 4.4 membership 変更時の必須規則

MLS commit（Add / Remove / Update / rekey）が durable に受理されたら、現在の vault segment を seal する。

1. commit 前 epoch で作った SegmentKey に新 object を追記しない。
2. commit 後の最初の object は新しい SegmentKey を使う。
3. Remove 後の object と新しい wrap は新 epoch の VEK だけで作る。

この規則を守らないと、removed device がすでに持つ旧 SegmentKey で Remove 後の object を復号できる。これは最重要の security invariant である。

### 4.5 新端末・TTL 外端末の restore

新端末または `restore-required` 端末は次の順で復元する。

1. self group へ Add され、current epoch の正規端末になる。
2. peer に `RestoreRequestV1`（identity、device、manifest root、必要 object/segment 範囲）を送る。
3. peer は requester の current membership を検証する。
4. peer は manifest 差分、暗号化 object、添付 chunk、current VEK 向け `SegmentKeyWrapV1` を渡す。
5. requester は hash・署名・event DAG を検証し、manifest root に到達したときだけ restore 完了にする。

peer は payload を復号して送る必要がない。既存 ciphertext と、current epoch に向けた key wrap を再配布すればよい。

既存端末もユーザー所有 archive も存在しなければ、過去 history は復元できない。この限界は UI と recovery flow に明記する。

### 4.6 Forward Secrecy との関係

Forward Secrecy を捨てない。新 leaf は過去 epoch の exporter secret を得ないため、self group 加入だけでは昔の vault を開けない。過去データは trusted peer が `SegmentKeyWrapV1` を明示的に grant した場合だけ読める。

ただし Remove 前に端末へ渡った payload や SegmentKey を回収することはできない。MLS Remove が保証するのは **Remove 後に新しく作られるデータ** を受け取れず復号できないことである。

## 5. mediator の短期 storage と配送状態

### 5.1 ingress buffer

外部 transport から届いた payload が、どの端末にもまだ vault 化されていない間だけ使う。

```ts
interface IngressEnvelopeV1 {
  version: 1;
  ingressId: IngressId;
  protocol: 'didcomm' | 'mail' | 'activitypub';
  recipientIdentityId: IdentityId;
  recipientDeviceSnapshot: DeviceId[];
  createdAt: string;
  expiresAt: string;
  transportMetadata: Record<string, string>;
  sourceEvidence: Uint8Array;
  protectedPayload: Uint8Array;
  protectedPayloadHash: Uint8Array;
}

interface IngressAckV1 {
  version: 1;
  ingressId: IngressId;
  protectedPayloadHash: Uint8Array;
  recipientDeviceId: DeviceId;
  vaultEventId: VaultEventId;
  checkpointId: CheckpointId;
  ackedAt: string;
  signature: Uint8Array;
}
```

状態は `pending`、`vault-ingested`、`expired`、`rejected` とする。

- 端末は payload を decrypt・validate し、local vault と projection への durable transaction を完了した後だけ ACK する。
- mediator は ACK signer が ACK 時点でも trusted であり、hash と recipient snapshot が一致することを検証する。
- mediator は pull 時にも recipient snapshot と current trusted roster の両方を確認する。snapshot は offer 時点の配送候補を凍結するためのものであり、MLS Remove 後の端末に未処理 ingress を渡す権利ではない。
- **trusted な一台** の ACK で ingress body を削除できる。以後の sibling 同期は vault delivery の仕事である。
- 新規 device は過去 ingress の snapshot に遡って追加しない。
- TTL、identity あたりの payload bytes / object count、global quota、重複 ingress ID の処理を必ず持つ。

### 5.2 vault delivery buffer

端末が vault object を durable save した後、同時 online でない sibling devices を短期間 catch-up させるための buffer である。

```ts
interface VaultDeliveryItemV1 {
  version: 1;
  identityId: IdentityId;
  seq: DeliverySeq;
  payload: Uint8Array;       // encrypted object/event pack; one body only
  payloadHash: Uint8Array;
  createdAt: string;
  expiresAt: string;
}

interface VaultDeliveryAppendV1 {
  version: 1;
  identityId: IdentityId;
  payload: Uint8Array;
  payloadHash: Uint8Array;
  recipientsAtAppend: DeviceId[]; // core-only immutable snapshot
  createdAt: string;
  expiresAt: string;
}
```

- `VaultDeliveryItemV1` は recipient に渡す visible item であり、body と hash だけを含む。`recipientsAtAppend`、pending ACK set、gap reason は core 内部の metadata であり、payload ごとに複製しない。
- payload は一コピーだけ保存する。device ごとに保存するのは ACK/cursor 等の小さい metadata である。
- `recipientsAtAppend` は append 時点の trusted set で固定する。新端末を過去 delivery の pending recipient にしない。
- device が object を durable save・hash verify した後、署名付き ACK を送る。
- 全 `recipientsAtAppend` が ACK したら body を削除する。
- expiry で body を削除し、`latestSeq` と `retainedFrom`（または gap range）だけを残す。

これは「未確認差分の総和」を実現する最小量に近い。ただし長期不在端末があれば無限に増えるため、TTL / quota は不可欠である。

### 5.3 gap 通知と restore 判定

device が `cursor` を提示して pull したとき、`cursor < retainedFrom - 1` なら mediator は空の成功を返してはならない。

```ts
type DeliveryPullResult =
  | {
      kind: 'items';
      items: VaultDeliveryItemV1[];
      nextCursor: DeliverySeq; // durable cursor は ACK 後だけ client が進める
      retainedFrom: DeliverySeq;
      latestSeq: DeliverySeq;
    }
  | {
      kind: 'restoreRequired';
      requestedCursor: DeliverySeq;
      retainedFrom: DeliverySeq;
      latestSeq: DeliverySeq;
      reason: 'ttl-expired' | 'retention-quota' | 'delivery-confirmed' | 'new-device';
    };
```

これにより C は、mediator 接続時に「自分の差分が TTL で失効し、通常 pull では追いつけない」ことを機械可読に理解できる。client はこの応答を受けて restore request を作り、push / control message を通じて peer を起こせる。`restoreRequestId` は delivery pull の副作用にせず、次段階の Restore control API が発行する。

### 5.4 mediator が restore でしてよいこと・してはいけないこと

restore control の wire schema は、content transfer を意図的に表現できない小さい control 型に限定する。

```ts
interface RestoreRequestV1 {
  version: 1;
  requestId: string;
  identityId: IdentityId;
  requesterDeviceId: DeviceId;
  reason: RestoreRequiredReason;
  knownManifestRoot?: string;
  requestedAt: string;
  expiresAt: string;
  signature: Uint8Array;
}

interface RestoreOfferV1 {
  version: 1;
  requestId: string;
  identityId: IdentityId;
  requesterDeviceId: DeviceId;
  responderDeviceId: DeviceId;
  manifestRoot: string;
  offeredAt: string;
  expiresAt: string;
  signature: Uint8Array;
}
```

`src/core/mediation/restore-control-store.ts` の reference implementation は、同じ identity の current trusted device にだけ request を見せ、requester にだけ offer を返す。request / offer / cancel は expiry 後に消える。型と store API に object、chunk、添付、manifest 本体を置かないため、この層を vault data storage に拡張する余地を API 上から閉じている。実際の MLS membership / signature validation と durable bounded persistence は後続実装で差し込む。

**してよいこと**:

- `RestoreRequestV1` の小さい signed control message を保存・配信する。
- どの trusted device が online / restore offer 可能と宣言したかの短期 metadata を扱う。
- visible push で「この端末を開いて復元を許可してください」と通知する。
- peer 同士が foreground で data transfer するための endpoint discovery、短命 capability、接続中継をする。

**してはいけないこと（v1）**:

- peer から history payload を pull して、復元者が後で取りに来るまで保持する。
- 未期限の vault archive、添付 archive、検索 index になる。
- peer が不在でも永続的に復元を保証する。

この境界により、restore は「端末間の再配布」であって core に新しい mailbox storage を戻すものではない。

### 5.5 iOS PWA の現実的な動作

iOS の Web Push は PWA を GB 級の同期に使うための常時実行基盤ではない。service worker は短時間の通知処理を前提とする。

- core は peer に visible push を送り、「別端末の復元要求があります。Biset を開いてください」と促す。
- peer と requester が前景で接続したとき、resumable / chunked transfer を行う。
- silent push の到達や背景実行に、history restore の完遂を依存させない。

電話が通常 online であることは、短期 catch-up の成功率を高める。しかし、バックグラウンドで必ず大容量 transfer できるという保証にはならない。

## 6. Transport adapter と ingress / egress

### 6.1 Core の narrow API

adapter は protocol の翻訳器であり、mailbox の所有者ではない。v1 の core API は次だけに限定する。

```ts
interface TransportAdapterHost {
  resolveRecipient(input: RecipientReference): Promise<RecipientResolution>;
  offerIngress(input: IngressEnvelopeV1): Promise<IngressOfferResult>;
  recordTransportResult(input: TransportResult): Promise<void>;
  publishPush(input: PushRequest): Promise<void>;
}
```

adapter ができないこと:

- `Email/query`、`Email/get`、全文検索、mailbox state の提供。
- local vault object / projection DB の直接書込み。
- TTL、trusted set、ACK 正当性の変更。
- core 外に恒久的な受信 payload DB を作ること。

### 6.2 DIDComm adapter

- DID resolution と existing DIDComm authcrypt を利用し、相手との interoperability、bootstrap、OOB、短い control を担う。
- self-device vault history の通常同期で、全 object を端末ごとの packed DIDComm JWE に fanout しない。
- 外部 sender が self MLS の VEK を持たない ingress では、一つの大きい protected body と、宛先 device 用の小さい capability / key wrap を使う設計を検討できる。
- この envelope は標準 packed DIDComm の単純な一通ごとの authcrypt ではないため、Biset protocol version と互換性条件を明示する。

### 6.3 Mail adapter

Mail adapter は `jmapsmtp` の relay mailbox を廃止し、mail ingress / egress の翻訳をする。

**ingress**:

1. SMTP/JMAP mail source から受信する。
2. 宛先アドレス・webvh・署名鍵の対応を検証する。
3. MIME/RFC 5322 を**加工前の raw mail**として、SMTP envelope、DKIM/ARC 等の source evidence とともに canonical ingress payload にする。core は OpenPGP 秘密鍵を持たず、復号・Autocrypt 解釈をしない。
4. `offerIngress` を呼ぶ。
5. 一端末の `IngressAck` 後に短期 body を消す。

**egress**:

1. client の `EmailSubmission/set` を local vault の immutable outbound intent event にする。
2. client が recipient の Autocrypt / OpenPGP state に従って RFC 5322 / MIME を組み立て、署名・暗号化する。秘密鍵を core に渡さない。
3. Mail adapter が完成済み raw mail を改変せず、SMTP/JMAP submission を実行する。
4. delivery result を signed transport result event として vault へ戻す。

adapter は外部メールの再送 queue を持ち得るが、それは RFC mail delivery の bounded spool であり、Biset account のメール履歴・JMAP mailbox ではない。TTL、状態、失敗時の user-visible semantics を別途明示する。特に SMTP の `250` は adapter が配送責任を引き受けたことを意味するため、ingress TTL の失効を黙って削除してはならない。v1 実装前に、次のいずれかを protocol / 運用 policy として固定する。

| 方針 | SMTP での振る舞い | TTL 切れ時 |
| --- | --- | --- |
| 短期受理型 | `offerIngress` が成功した時点で `250` を返す | DSN / permanent failure を発行し、失敗を vault / audit に記録する |
| 非受理型 | 宛先端末が利用不能なら `4xx` を返し、送信側 MTA の再送に委ねる | Biset は本文を保持しない |

どちらを選んでも、Biset が恒久 mailbox にならないという境界は維持する。

### 6.4 ActivityPub adapter

- ActivityPub activity を canonical ingress payload と source evidence に変換する。
- outbound event を actor/outbox へ配送し、配送結果を transport result として戻す。
- AP object cache を Biset vault の正本や無期限 inbox にしない。

### 6.5 adapter の配置

v1 は static first-party module とする。

```text
biset core
  protocol / policy / mediator stores
  adapters/didcomm
  adapters/mail
  adapters/activitypub
```

理由は、identity・ingress schema・認可・監査・versioning が密結合だからである。将来、sandbox、権限 manifest、resource limit、IPC schema が整った後は、同じ narrow API を使う別 process adapter を許せる。

## 7. Local JMAP Gateway と二つの account mode

### 7.1 client は JMAP client のままでよい

client が JMAP を話すことは、今回の設計と矛盾しない。JMAP は UI とデータ backend の契約として使い、Biset identity の場合だけ server の代わりに local vault を JMAP に投影する。

```text
UI / feature code
       │ JMAP methods
       ▼
  AccountTransport
    ├─ LocalJmapTransport  → Local JMAP Gateway → local vault
    └─ RemoteJmapTransport → third-party JMAP server
```

Local gateway は HTTP server である必要がない。TypeScript の direct transport、virtual endpoint、または PWA 内の request dispatcher として実装してよい。JMAP response shape と state semantics を守ることが必要条件である。

### 7.2 account routing

| account | transport | 正本 |
| --- | --- | --- |
| `biset:<did>` | `LocalJmapTransport` | local encrypted vault |
| `remote:<provider>:<id>` | `RemoteJmapTransport` | 第三者 JMAP server |

同じ account の正本は一つだけにする。remote account をそのまま Biset vault と双方向同期しない。将来の read-only import は別 adapter として設計する。

異なる backend をまたぐ JMAP method batch は原子的に実行できない。v1 は reject するか、UI が明示的に分割実行する。

### 7.3 Local JMAP の最小 method 対応

| JMAP method | local vault での実装 |
| --- | --- |
| `Session` | local account capabilities と accountId を返す |
| `Mailbox/get` | vault event reducer の mailbox projection |
| `Mailbox/changes` | local mailbox projection checkpoint 差分 |
| `Email/get` | event/object index から組み立てる |
| `Email/query` | local immutable index + query state |
| `Email/changes` | local checkpoint 差分 |
| `Email/set` | immutable vault event を transactionally append |
| `Mailbox/set` | mailbox event を append |
| `Email/import` | validated ingress を message.add event と object に変換 |
| `EmailSubmission/set` | outbound intent event を append し adapter に引き渡す |
| blob download | local object/chunk reader |

`Email.id` は最初の received/sent vault event ID を基礎に安定に導出する。`threadId`、`mailboxIds`、`keywords`、`hasAttachment` は reducer/projection から返す。JMAP の state token は `ProjectionCheckpointV1` を基に作る。

### 7.4 AccountSession の再定義

現行の synthetic DIDComm account が「JMAP session だが `jmapClient` は null」という形であるなら、廃止する。型は明示的に分ける。

```ts
type AccountSession = LocalVaultSession | RemoteJmapSession;

interface LocalVaultSession {
  kind: 'local-vault';
  accountId: string;
  identityId: IdentityId;
  jmap: LocalJmapTransport;
}

interface RemoteJmapSession {
  kind: 'remote-jmap';
  accountId: string;
  jmap: RemoteJmapTransport;
}
```

UI と email/mailbox/submission helper は `AccountTransport` だけを見る。backend の判定を UI 各所へ漏らさない。

現在 `src/local-jmap/remote.ts` は第三者 JMAP account 向けに standard `/.well-known/jmap` discovery、`apiUrl` への JMAP method call、`downloadUrl` template による blob download を実装している。この transport は Biset identity / MLS / vault に依存しないため、client は local vault gateway の完成前でも pure remote-JMAP mode を維持できる。provider 固有の credential acquisition と既存 UI settings の移植は別工程である。

`src/local-jmap/gateway.ts` は同じ `AccountTransport` の local 実装である。read model が返す local vault projection から、read-only `Session`、`Mailbox/get`、`Email/get`、`Email/query`、local blob range download を返す。現段階の `MemoryLocalJmapReadModel` は protocol test 用であり、次に IndexedDB の vault projection / encrypted object reader を `LocalJmapReadModel` として実装する。したがって UI は transport の違いを意識せず、remote account と local-vault account の双方へ同じ JMAP call を送れる。

`src/local-jmap/indexeddb.ts` は `VaultProjectionReader` と `LocalVaultBlobReader` を受ける `IndexedDbLocalJmapReadModel` を実装した。IndexedDB store は versioned `LocalJmapProjectionV1` を返し、JMAP layer は identity/version/state を検証して snapshot に変換する。blob reader は別注入なので、JMAP gateway も IndexedDB projection reader も SegmentKey / VEK に依存しない。

`src/vault/blob-reader.ts` の `VaultObjectBlobReader` は object record を読み、外部注入の `SegmentKeyResolver` で key を得てから `VaultObjectV1` の object ID / ciphertext hash / AEAD を検証・復号する。検証失敗時には JMAP UI へ一切の byte を返さない。resolver は MLS exporter から導く VEK と stored `SegmentKeyWrapV1` を使う予定であり、VEK を IndexedDB に保存しない。添付用 chunk manifest は別工程である。

## 8. 実装モジュールと現状コードの対応

### 8.1 新しい論理モジュール

```text
src/
  protocol/
    ids.ts                 # ID、canonical encoding、domain separation
    canonical.ts
    ingress.ts             # IngressEnvelope/Ack と protocol validation
    vault.ts               # event/object/manifest schema
    transport.ts           # control messages と adapter host contract
    jmap-local.ts          # Local JMAP public types
    test-vectors.ts
  vault/
    store.ts               # IndexedDB schema and atomic ingress commit
    objects.ts             # encrypted object/chunk I/O
    events.ts              # append、verify、conflict rules
    manifest.ts            # Merkle manifest、checkpoint、diff
    crypto.ts              # SegmentKey、VEK wrap、AEAD
    ingest.ts              # ingress -> vault transaction
    delivery.ts            # ACK/cursor/control
    restore.ts             # peer restore protocol
    projection.ts          # JMAP query/index reducer
  local-jmap/
    transport.ts
    gateway.ts
    mail.ts
    mailbox.ts
    submission.ts
    state.ts
  transport/
    core-client.ts
    didcomm-adapter.ts
    mail-adapter.ts
    activitypub-adapter.ts
  core/
    index.ts               # unified process composition root
    identity/              # anchor: DID/webvh and public device projection
    mediation/             # bounded ingress/delivery buffers, cursor, push
    adapters/              # DIDComm / Mail / ActivityPub adapters
```

物理ディレクトリ名は既存 layout に合わせて調整してよいが、上の責務境界を崩さない。

### 8.2 現行実装で変える箇所

| 現在の箇所 | 現在の問題 | 移行後 |
| --- | --- | --- |
| `src/did/didcomm/send.ts` | `toDoc.keyAgreement` ごとに authcrypt・forward し payload が O(devices) | external ingress / control に限定。vault object は一コピー + ACK に移す |
| `src.bak/anchor/mediator/queue.ts` | `kid` ごとの packed JWE queue、Pickup ACK で削除 | `src/core/mediation/` の ingress store と vault delivery store に責務分離 |
| `src/did/didcomm/channel.ts` | self sync が best effort、synthetic JMAP session に依存 | vault ingest / delivery / restore control へ移行 |
| `src.bak/anchor/mediator/server.ts` | MLS message の outer per-device fanout | group log は短期順序通知、object delivery は共有 body + cursor |
| `src.bak/anchor/mediator/mls-ds.ts` | bounded group log はあるが history vault ではない | 短期 DS のまま維持し、vault 正本化しない |
| `src/jmap/client.ts` | `.well-known/jmap` 前提の `JamClient` | `AccountTransport` factory を導入 |
| `src/jmap/email.ts` / `mailbox.ts` / `submission.ts` | remote `JamClient` を直接前提 | Local/Remote 共通 JMAP transport へ抽象化 |
| `src/store/idb.ts` | messages/threads/mailboxes は cache 寄り | vault object/event/manifest/projection を durable に追加 |
| `src/types.ts` | `AccountSession` が remote JMAP 前提 | discriminated local/remote session |
| `src/context.ts` | `didcomm:` synthetic relay route | local-vault account route |
| `src/mls/group.ts` | exporter を vault protocol に結びつけていない | VEK 導出の固定 API を追加 |

### 8.3 なぜ現状より経済的か

現行 DIDComm の authcrypt は受信端末鍵ごとに暗号文が異なるため、そのままでは一つの object に集約できない。端末 N 台なら、同じ大きい本文・添付が概ね N 回暗号化・N queue に保存される。

新設計では、self-device vault replication の payload を SegmentKey で一回だけ暗号化する。mediator の違いは per-device の ACK/cursor と key wrap に縮められる。通常 online の端末群では未 ACK window だけが残るため、長期全履歴を持つ JMAP relay より storage が小さい。

ただしこれは「サーバーが payload を一時的に持つ性質」を完全には消さない。非同期 delivery を保証する限り、送信者と受信者の時間差を埋める短期 store-and-forward は必要である。本計画はそれを TTL、quota、削除条件、API 境界で明示的に限定する。

## 9. Protocol と state machine

### 9.1 control message

v1 の control type URI は次を候補にする。

```text
https://biset.dev/transport/1.0/ingress-offer
https://biset.dev/transport/1.0/ingress-pull
https://biset.dev/transport/1.0/ingress-ack
https://biset.dev/vault/1.0/delivery-offer
https://biset.dev/vault/1.0/delivery-pull
https://biset.dev/vault/1.0/delivery-ack
https://biset.dev/vault/1.0/delivery-status
https://biset.dev/vault/1.0/restore-request
https://biset.dev/vault/1.0/restore-offer
https://biset.dev/vault/1.0/restore-cancel
```

既存 DIDComm `sendAndUnpack` は、移行中これらの小さい control transport として再利用できる。payload transfer 自体は hash-addressed、chunked、resumable な vault transfer protocol に分ける。

### 9.2 ingress 状態機械

```text
adapter offer
  → mediator pending
  → trusted device pulls
  → validates + durable local vault transaction
  → signed IngressAck
  → mediator verifies and deletes body
  → sibling vault delivery begins

pending → expired  (TTL/quota)
pending → rejected (invalid evidence/policy)
```

ACK より前に client が crash しても、再起動後に local transaction と ACK outbox を照合できる必要がある。ACK を先に送って local save が失敗する順序は禁止する。

### 9.3 vault delivery 状態機械

```text
local event/object durable
  → append shared delivery item (seq, recipient snapshot)
  → device pulls item
  → verifies + durable save
  → signed ACK / cursor advance
  → all snapshot devices ACK: delete body

item expires → body deleted, retainedFrom advanced
old cursor pull → restoreRequired
```

ACK は単なる network receipt ではなく、object/event/manifest が local durable state に入ったことを意味する。

### 9.4 restore 状態機械

```text
new device or restoreRequired
  → joins/verifies current self MLS group
  → asks mediator for peer discovery + sends RestoreRequest
  → peer receives visible push and opens app
  → peer validates membership and offers manifest
  → manifest diff / chunks / SegmentKeyWrap transfer
  → requester verifies roots and installs projection checkpoint
  → normal delivery cursor is initialized
```

transfer は途中停止を許す。chunk hash と manifest root により、何度再開しても同じ結果になるようにする。

### 9.5 cursor の原則

- cursor は identity + device + delivery stream に束縛する。
- cursor advance と local durable write は同一 transaction または再送可能な outbox で扱う。
- cursor が消えた端末は `new-device` 相当の restore を行う。推測で最新 cursor に飛ばしてはならない。
- mediator は `retainedFrom` を署名または server-authenticated response で返す。

### 9.6 外部通信ワークフロー

この節は、adapter、mediator、client、vault の責務境界を実装順に固定する。外部 protocol の配送完了と、同一 identity の端末同期完了は別の操作である。

#### 9.6.1 DIDComm 受信

```text
送信者 client
  → recipient DID / service / endpoint を解決
  → DIDComm ingress を mediator に offer
  → recipient device A が pull / push 通知で起動
  → decrypt・検証・vault へ durable save
  → IngressAck
  → mediator が ingress body を削除
  → vault delivery で B/C 端末へ同期
```

1. **宛先発見**: 送信者は webvh DID Document を解決し、DIDComm service endpoint、key agreement key、protocol capability を得る。送信者は受信者の self MLS group や Vault Epoch Key を知る必要がない。
2. **外部暗号化**: 送信者は DIDComm `authcrypt` 等で ingress を作る。互換フェーズでは端末鍵ごとの DIDComm message を許す。目標形では、本文を一つの protected body とし、recipient device snapshot 用の小さい復号 capability / key wrap を別に持つ。後者は標準 packed DIDComm そのものではないため、Biset transport version として明示する。
3. **短期受理**: DIDComm adapter は `IngressEnvelopeV1` を作り、recipient identity、device snapshot、payload hash、TTL とともに `IngressStore.offer` する。ここで保存するのは、まだどの端末にも vault 化されていない payload だけである。
4. **端末への到達**: mediator は online endpoint への control message、または opaque な Web Push で端末 A に知らせる。push に本文・添付名・会話 metadata を入れない。
5. **端末での ingest**: A は ingress を pull し、DIDComm の復号、送信者認証、宛先、replay、payload hash、形式を検証する。成功時は message/blob、`message.add` 等の event、manifest、JMAP projection、ACK outbox を一つの durable transaction として保存する。
6. **ingress の確定**: A は `IngressAckV1` に ingress ID、payload hash、vault event ID、checkpoint、device signature を入れて送る。mediator は current trusted device であることと hash を検証し、body を削除する。ACK は network receipt ではなく local vault への確定保存を意味する。
7. **自端末への複製**: A が作った vault object/event は、共有 body 一コピーの vault delivery stream に append される。B/C は durable save 後に ACK する。TTL 内に戻らない端末には `restoreRequired` を返し、peer/archive restore に切り替える。
8. **返信**: A はまず local vault に outbound intent と送信 message を記録し、その後 DIDComm adapter が宛先 DID を解決して送信する。外部配送結果は `transport result` event として vault に戻す。

#### 9.6.2 DeltaChat 互換 Mail / Autocrypt / OpenPGP の受信

```text
送信側 MTA / JMAP source
  → SMTP envelope の RCPT TO で Mail adapter が宛先 identity を解決
  → raw RFC 5322 / PGP-MIME を短期 ingress に保存
  → device A が取得
  → local OpenPGP 秘密鍵で復号
  → Autocrypt・Chat-*・SecureJoin を解釈
  → raw mail と正規化結果を vault へ durable save
  → IngressAck と短期 body 削除
  → vault delivery で B/C 端末へ同期
```

1. **メール配送の受理**: SMTP listener または upstream JMAP fetcher は、SMTP envelope の `RCPT TO` から Biset identity を解決する。`To:` header は DeltaChat 互換メールでは hidden であり得るため、宛先判定の根拠にしない。
2. **raw mail の保存**: Mail adapter は完成した RFC 5322 / MIME を変更せず、envelope、受信時刻、DKIM/ARC 等の source evidence とともに ingress に置く。OpenPGP encrypted body、署名、添付、Autocrypt header を server 側で復号・書換え・連絡先学習しない。
3. **端末での PGP 処理**: device A は raw mail を pull し、local OpenPGP 秘密鍵で PGP/MIME を復号・検証する。DeltaChat 互換メールでは `To: hidden-recipients:;`、`Autocrypt`、`Chat-Version`、`Chat-Group-ID`、member 情報、SecureJoin 情報などが暗号文内にあるため、復号後に初めて読み取る。
4. **Autocrypt / DeltaChat state**: A は送信者 address と Autocrypt public key の対応、key fingerprint の変更、PGP signature/encryption status、group state、SecureJoin、reaction を検証し、vault event として保存する。Autocrypt は鍵発見であって人間としての本人確認ではない。より強い確認は SecureJoin、fingerprint 照合、DID binding 等で別途扱う。
5. **vault への確定**: A は raw `.eml` object、復号後の message / attachment object、検証結果、contact-key / group / reaction event、Local JMAP projection を durable に保存する。raw mail は export、再解析、再検証、相互運用のために端末 vault に残す。
6. **ACK と sibling 同期**: A は `IngressAckV1` を送る。mediator は有効性を確認後に raw mail の短期 body を削除する。B/C へは SMTP で再配送せず、vault delivery と MLS による端末認可で同期する。
7. **OpenPGP 秘密鍵の端末間扱い**: B/C が raw PGP mail を独立に復号・再検証するには、identity の OpenPGP 秘密鍵も正規端末だけが読める credential として vault / restore 設計に含める必要がある。これを実装するまでは、復号済み正規化結果を同期するだけでは完全な独立再検証を保証できない。この credential の Add/Remove と export/recovery policy は MLS self group の端末認可に接続して設計する。
8. **SMTP 失効**: adapter が SMTP `250` を返した ingress が端末 ACK 前に TTL を超えた場合、silent loss は禁止する。§6.3 の短期受理型なら DSN/permanent failure、非受理型なら SMTP `4xx` により送信側再送、という選択を実装前に固定する。

#### 9.6.3 DeltaChat 互換 Mail / Autocrypt / OpenPGP の送信

```text
client UI の EmailSubmission/set
  → vault に outbound intent と sent object を保存
  → local Autocrypt state から recipient key を選ぶ
  → client が PGP/MIME / protected Chat-* headers を生成
  → Mail adapter が raw mail を SMTP/JMAP submission
  → 結果を transport result event として vault へ保存
  → sibling devices は vault delivery で追随
```

1. **先に正本化**: client は `EmailSubmission/set` を、outbound intent、sent message object、attachment、宛先、選択した recipient key fingerprint、暗号化 policy の immutable vault event として確定する。
2. **鍵と policy の決定**: client は local vault の Autocrypt contact-key state を参照する。有効鍵があれば OpenPGP encryption、group chat なら参加者鍵への暗号化と DeltaChat group headers、SecureJoin 中なら必要な handshake mail を作る。鍵なし・鍵変更未承認時の plaintext / 保留 / user confirmation は明示的な policy に従う。
3. **client 側で暗号化**: client は `multipart/mixed` の添付を含む RFC 5322 を構成し、OpenPGP sign/encrypt する。DeltaChat 互換の protected headers、hidden recipients、Autocrypt / `Chat-*` headers はこの時点で組み立てる。秘密鍵は client 外へ出さない。
4. **外部 submission**: Mail adapter は署名済み・暗号化済み raw mail を変更せず SMTP または JMAP Submission で送る。必要な短期 retry spool は outbound delivery 専用であり、Sent mailbox の正本ではない。
5. **結果の記録**: SMTP accept、temporary/permanent failure、DSN 等は `transport result` event として local vault に戻す。送信済み履歴は server の Sent mailbox でなく vault にあるため、B/C は vault delivery だけで同じ状態に収束する。

## 10. client 実装計画

### C0. backend 抽象化を先に導入する

`src/jmap/email.ts`、`mailbox.ts`、`submission.ts` が `JamClient` を直接使う箇所を調べ、次の最小 interface に寄せる。

```ts
interface AccountTransport {
  session(): Promise<JmapSession>;
  call<T>(methodCalls: JmapMethodCall[]): Promise<T>;
  download(blobId: string, range?: ByteRange): Promise<Uint8Array>;
}
```

完了条件:

- remote account の振る舞いを変えず、すべて `RemoteJmapTransport` 経由になる。
- UI 層に `if (local)` が散らばらない。
- typecheck と既存 JMAP client test が通る。

### C1. local vault の IndexedDB schema

`src/store/idb.ts` に versioned migration を追加する。少なくとも次の store を持つ。

```text
vault_events
vault_objects
vault_chunks
vault_segments
vault_key_wraps
vault_manifests
vault_projection
vault_jmap_state
vault_outbox
vault_delivery_state
vault_restore_state
transport_status
```

object body と event、projection、outbox の durability boundary を明文化する。ingress ACK は、object/event/projection/outbox が commit された後にだけ enqueue する。

完了条件:

- browser restart 後も manifest root と JMAP state が再現する。
- partial write/crash を fault injection で検証する。
- DB migration の downgrade/rollback 方針がある。

### C2. vault crypto / event / manifest

`vault/crypto.ts`、`events.ts`、`manifest.ts` を実装する。

- canonical encoding、hash、signature、AEAD AAD を protocol test vector に固定する。
- SegmentKey の生成、VEK wrap/unwrap、segment seal を実装する。
- event signature、actor sequence、tombstone/編集の競合規則を実装する。
- Merkle root から object/event の不足集合を求める。

完了条件:

- 同じ input が異なる端末で同じ ID/root を生成する。
- 改竄 ciphertext、署名、parent、wrap を拒否する。
- Remove 後の新 object が旧 SegmentKey で読めない test がある。

### C3. Local JMAP Gateway

`local-jmap/gateway.ts` を実装し、まず read path を移す。

1. `Session`、`Mailbox/get`、`Email/get`、`Email/query`。
2. `Email/changes`、`Mailbox/changes`、query state。
3. `Email/set`、`Mailbox/set`、`Email/import`、`EmailSubmission/set`。

既存 UI が期待する JMAP capabilities、sort、filter、pagination、notFound、state mismatch を list 化し、対応範囲を test で固定する。

完了条件:

- Biset identity を offline で開き、過去 local vault を一覧・検索・閲覧できる。
- remote account の JMAP UI regression がない。
- local JMAP は network access を要求しない。

### C4. ingress と vault delivery client

- ingress offer/pull を受け、validate → vault transaction → `IngressAck` outbox の順に実装する。
- vault delivery pull、ACK、cursor を実装する。
- `restoreRequired` を受けたら通常 sync を止め、restore UI/state に遷移する。
- duplicate ingress、duplicate delivery、順序逆転、ACK 再送を idempotent にする。

### C5. restore UI と PWA 行動

- 新端末/TTL 外端末に、何が失われたのではなく「peer または backup から復元が必要」と明示する。
- restore request を送る UI、QR/OOB 等の device approval UI、peer 側の approve/deny UI を作る。
- iOS push は visible prompt とし、foreground で transfer を再開できる progress UI を作る。
- peer/archive がない場合の不可逆な failure を、曖昧な loading のままにしない。

## 11. core / mediator 実装計画

### S0. protocol package

client/core 共通 schema を `src/protocol/` または共有 package に置く。

- JSON/CBOR canonicalization、type URI、version negotiation。
- ingress/vault/restore payload validator。
- golden test vectors と backward compatibility test。
- protocol field を勝手に optional 化しない version policy。

### S1. IngressStore

`anchor/mediator/ingress-store.ts` を実装する。

```ts
interface IngressStore {
  offer(envelope: IngressEnvelopeV1): Promise<IngressOfferResult>;
  pull(identityId: IdentityId, deviceId: DeviceId, cursor?: string): Promise<IngressEnvelopeV1[]>;
  acknowledge(ack: IngressAckV1): Promise<void>;
  expire(now: Date): Promise<ExpiryResult>;
  status(ingressId: IngressId): Promise<IngressStatus>;
}
```

要件:

- crash/restart 後にも TTL、ACK、dedupe が壊れない bounded persistence。
- `acknowledge` は trusted membership、snapshot、payload hash、signature を検証する。
- 削除後は重複 ACK を安全に処理する最小 tombstone だけを保持し、payload は残さない。
- metrics は bytes/count/age/expiry/ack latency のみ。payload plaintext と全文 metadata をログに出さない。

### S2. VaultDeliveryStore

`anchor/mediator/vault-delivery-store.ts` を実装する。

```ts
interface VaultDeliveryStore {
  append(item: VaultDeliveryItemV1): Promise<void>;
  pull(identityId: IdentityId, deviceId: DeviceId, after: DeliverySeq): Promise<DeliveryPullResult>;
  acknowledge(input: VaultDeliveryAckV1): Promise<void>;
  expire(now: Date): Promise<ExpiryResult>;
  deliveryStatus(identityId: IdentityId, deviceId: DeviceId): Promise<DeliveryStatusV1>;
}
```

要件:

- 同じ body を device ごとに複製しないことを storage test で確認する。
- `recipientsAtAppend` を immutable にする。
- ACK/expiry により body を削除し、`retainedFrom/latestSeq` を正確に進める。
- quota eviction も `restoreRequired` を返せる gap record として扱う。

### S3. endpoint と push

- DID / webvh から current endpoint と device ID を解決する。
- `IngressOffer`、delivery hint、restore request/offer を short control message として配信する。
- push payload に本文、添付名、詳細な差出人情報を入れない。必要最小限の opaque notification ID にする。
- push が使えない端末でも pull で同じ状態に到達する。

### S4. 現行 queue / fanout からの二重運用

現行 `queue.ts` を直ちに削除しない。migration flag ごとに以下を行う。

1. 新 protocol を shadow で記録し、payload hash と delivery 結果を比較する。
2. 新 client は new ingress / delivery を read できるが、旧 path を fallback として残す。
3. identity 単位で new path を primary にする。
4. 新 path の ACK/restore telemetry が十分なら、payload の旧 per-device fanout を停止する。
5. legacy queue は期限後に read-only drain し、削除する。

rollback は「新規 payload を旧 queue に再複製」ではなく、flag を戻して新規 delivery のみ旧 path に戻す。既存 new object は client が読め続けなければならない。

### S5. core の API 境界

core が外部に公開する API には、vault history query を追加しない。

許可する API:

- discovery、ingress offer/pull/ack、delivery pull/ack/status、restore control、push registration、adapter health。

禁止する API:

- `/jmap`、`Email/get`、`Email/query`、`Mailbox/get`、全履歴 export、恒久 blob URL、server-side search。

この API レビューを release gate にする。

## 12. MLS 実装計画

既存 MLS group / delivery service の詳細計画は別に保ってよいが、本書は vault との結合要件を正とする。

### M0. VEK 導出 API

- `src/mls/vault-epoch.ts` に fixed label/context/32-byte output の `deriveVaultEpochKey(group)` boundary を実装済み。`group` は current self-group ID、decimal uint64 epoch、MLS `exportSecret` だけを渡す。
- 次に `src/mls/group.ts` の actual exporter をこの boundary に接続する。vault 側には MLS state / exporter secret を渡さない。
- label/context/length を caller が任意指定できないようにする。
- MLS state 変更と vault segment seal の transaction/outbox 境界を定義する。

### M0.5 trusted-device projection

`src/core/identity/device-roster.ts` には `AcceptedSelfGroupProjectionV1` を置く。これは accepted MLS epoch、public device ID、public signing key ID、normal vault delivery の開始 cursor (`deliveryFloor`) だけからなる。identity control plane はこの projection を保存・提供できるが、MLS state、exporter secret、vault payload を受け取らない。

- 同じ identity の roster は epoch が単調増加する accepted projection によってのみ変わる。
- stale epoch と同 epoch の異なる roster を拒否する。
- Remove は後続 epoch から device を落とすことで表し、TTL / push 不達 / 非活動で roster を自動変更しない。
- 実際の MLS commit validation と DID 公開への反映は次段階の adapter が担う。memory reference はその結果を受け取るだけである。

`src/core/identity/authorizers.ts` はこの roster を mediation の `VaultDeliveryAuthorizer` / `RestoreControlAuthorizer` に接続する。authorizer は毎回 current roster を参照し、caller supplied device list では認可しない。署名 bytes の canonical 化と実際の public-key verification は identity / MLS adapter から注入するため、mediation に秘密鍵・MLS state を持ち込まない。

`src/protocol/signing.ts` が Ingress ACK、vault-delivery ACK、restore request / offer / cancel の canonical signing bytes を固定する。すべての routing identity、payload hash、cursor、expiry、request ID を含め、メッセージ種別ごとに domain label を分ける。したがって、ある種類の control message の署名を別種類の ACK / restore message に流用できない。実際の DID public key verification は、これらの bytes を `DeviceControlSignatureVerifier` に渡して行う。

### M1. segment lifecycle

- identity ごとの active segment を管理する。
- accepted commit 後は active segment を seal し、新 SegmentKey を作る。
- old object の ciphertext を mutate しない。
- duplicate/late commit と app message の順序をテストする。

### M2. restore grant

- peer は requester が current self group member であることを検証する。
- peer は requested segment の ciphertext と、新 epoch VEK 向け wrap を生成する。
- grant は device、group、epoch、segment、expiry、request nonce に束縛して署名する。
- grant reuse/replay、removed device、異なる identity への転用を拒否する。

### M3. current MLS delivery service との境界

`mls-ds.ts` の bounded group log は、commit/application message の順序付き短期配送に使い続けてよい。しかし vault payload の恒久正本・復元元・全文 archive に転用しない。

## 13. mail relay の段階的廃止

### R0. 現状を固定して計測する

- JMAP relay に保存される account あたりの message/blob/history bytes。
- DIDComm per-device fanout の payload bytes、queue count、ACK latency。
- 端末数、offline 日数、TTL expiry、restore 要求の頻度。
- client の local indexedDB size と JMAP query latency。

### R1. local read-only vault

- current JMAP account を読み取り、local vault へ one-way import する migration tool を作る。
- Local JMAP Gateway で同じ message/thread/mailbox を read-only 表示する。
- root/hash と message count の照合 UI を作る。

### R2. dual-write

- 新着 ingress を旧 relay と新 vault path の双方へ書き、hash/metadata を比較する。
- ただしこの段階の relay は移行のための temporary copy であり、新設計の正本ではない。
- mismatch は user data を破棄せず調査できるようにする。

### R3. vault primary

- 新規 Biset identity は Local JMAP + vault を primary にする。
- old relay は read-only migration source / grace-period fallback に制限する。
- transport adapter は ingress ACK を受けて relay mailbox へ保存しない。

### R4. relay retirement

- user が local vault/export/archive を確認した後に old mailbox を削除できる migration flow を作る。
- retention deadline、export 形式、復旧不能条件を利用者へ明示する。
- `jmapsmtp` は mailbox service から Mail adapter / bounded submission spool へ縮小または置換する。

## 14. テスト計画

### 14.1 protocol / crypto

- canonical bytes、ID、hash、signature、AEAD AAD の golden vectors。
- VEK の group/epoch/label domain separation。
- SegmentKey wrap の改竄、replay、epoch 取り違え。
- Remove 後、新 object を removed device が decrypt できないこと。
- old history が removed device から自動回収されないことを仕様テストに明記する。

### 14.2 vault consistency

- duplicate event/object/ACK の idempotence。
- offline concurrent writes、edit/tombstone/read state の競合規則。
- manifest diff と interrupted chunk transfer の収束。
- projection rebuild が vault event/object と同じ JMAP 表示を作る。
- local DB crash の任意地点から再開する fault injection。

### 14.3 mediator retention

- one ingress body + one trusted ACK で body が消える。
- shared vault body + N ACK metadata で、N payload copy を作らない。
- all ACK、TTL expiry、quota expiry、restart、重複 ACK。
- cursor が `retainedFrom` より古いと必ず `restoreRequired` になる。
- new device が append 前の pending recipient に遡及しない。

### 14.4 restore

- TTL 外 C が mediator から `restoreRequired` を受ける。
- mediator が C の復元要求を peer に push/control で通知できる。
- A と C が同時前景で transfer し、中断再開後同一 manifest root になる。
- peer 不在、全端末喪失、拒否、removed device、古い backup をそれぞれ正しく表示する。
- mediator に restore payload が残らないことを storage inspection で確認する。

### 14.5 JMAP / client regression

- 同じ UI test を local account と remote account の双方で実行する。
- local `Email/query` pagination、filter、sort、changes、state mismatch。
- cross-backend batch を明確に reject/split する。
- offline Biset vault 表示と remote account error 表示を混同しない。

### 14.6 iOS PWA

- push を受けた closed PWA が、前景を要求する通知として見える。
- background execution が途中で止まっても restore が壊れない。
- Wi-Fi/cellular 切替、長時間 suspension、大きい添付、中断再開。

## 15. 運用指標・privacy・容量 policy

収集するのは aggregate / opaque metadata に限る。

| 指標 | 目的 |
| --- | --- |
| ingress bytes/count/age | short buffer の容量監視 |
| vault delivery bytes/count/age | 未 ACK 差分の健全性 |
| ACK latency と TTL expiry rate | offline 実態と TTL 調整 |
| `restoreRequired` rate | 端末運用 UX の評価 |
| restore 完了率・中断率 | PWA/transfer の改善 |
| per-device fanout 削減率 | 新設計の経済性検証 |

記録しないもの:

- message plaintext、添付 plaintext、全文検索 index。
- JMAP `Email/get` / `Email/query` 相当の履歴。
- 長期的な peer の object 所有一覧。

TTL、object size、identity quota、global quota は定数に埋め込まず policy として versioned configuration にする。ただし quota eviction は data loss を隠さず、必ず `restoreRequired` の原因として client に返す。

## 16. release gate と未決定事項

### 16.1 release gate

- [ ] core の API に history query / mailbox API がない。
- [ ] payload storage に TTL / quota / delete path / restart recovery がある。
- [ ] local vault を持たない core backup だけから history を復元できない。
- [ ] Biset local account の JMAP read/write が network relay なしで動く。
- [ ] remote JMAP account の既存挙動を回帰させない。
- [ ] Remove 後 segment seal の security test が通る。
- [ ] TTL 外端末が `restoreRequired` を確実に認識できる。
- [ ] restore transfer は peer/archive からのみ行い mediator history storage を増やさない。
- [ ] iOS では foreground restore が必要なことを product UX に明記する。
- [ ] migration/export/全端末喪失時の回復不能条件を利用者に明示する。

### 16.2 実装開始前に数値を決める事項

1. ingress TTL、vault delivery TTL、identity/global quota、最大 object/chunk size。
2. transport ごとの retry / DSN / spam / abuse policy。
3. event conflict rules と projection rebuild の version policy。
4. restore approval の UX、QR/OOB の要否、ユーザー所有 archive の最初の形式。
5. Local JMAP の最初の method coverage と、未対応 method の error semantics。
6. migration 期間と old JMAP relay の read-only/export deadline。

## 17. 実装順序

次の順序で進める。各段階は前段の test と gate を満たしてから進める。

1. **Protocol foundations**: canonical schema、IDs、test vectors、AccountTransport。
2. **Local vault read path**: IndexedDB vault、event/object/manifest、read-only Local JMAP。
3. **MLS vault crypto**: VEK、SegmentKey、segment seal、Remove security test。
4. **Short ingress**: IngressStore、client ingest/ACK、DIDComm adapter の最小接続。
5. **Shared vault delivery**: one-copy delivery store、cursor/ACK/gap response。
6. **Restore**: peer discovery、foreground resumable transfer、SegmentKeyWrap grant、UX。
7. **Mail/ActivityPub adapters**: mailbox storage なしの ingress/egress へ移す。
8. **JMAP relay retirement**: dual-write、migration、primary cutover、drain、削除。

各段階で、旧 per-device queue と新 delivery の payload hash、削除時刻、端末到達性を比較する。新設計の安全性は「暗号化している」ことだけではなく、正本の所在、削除条件、失敗時の明示的な restore 要求を検証して初めて成立する。
