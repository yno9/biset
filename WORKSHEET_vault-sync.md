# 作業指示書: self-mimi → CRDT + mediator 移行

> 設計の根拠は [PLAN_biset-mimi-transition.md](./PLAN_biset-mimi-transition.md) (rev.3) にある。**着手前に必ず読むこと。**
> このワークシートは、その設計を実行可能なタスクに分解したもの。

---

## 0. 前提（作業者が最初に理解すべきこと）

### やること

bisetの「自分の複数端末間でのVault同期」から MIMI/MLS を撤退させ、以下に置き換える:

| 層 | 現在 | 移行後 |
|---|---|---|
| 状態収束 | イベントログの順次適用（同時編集で恒久的にingest失敗する） | **Yjs**（`Y.Array`にイベントを並べる） |
| 内容鍵 | VEK = MLS self-group exporter由来 | **VCK** = Wallet派生秘密（世代カウンタ付き） |
| 失効 | MLS Remove commit（個別デバイス） | **世代更新のみ**（個別removeは実装しない） |
| 配送 | `biset-mimi` / `biset-vault-relay`（MIMI固有プロトコル） | 既存の `biset-didcomm-mediator`（DIF標準のみ） |

### やらないこと（重要）

- [ ] **MIMIモジュールは削除しない。** `src/protocol/mimi/*`・`src/server/mimi/*`・`src/mls/conversation-group-*.ts` は第三者MIMI providerとのinteropのために維持する。廃止するのは `MimiClientMode` の `'self'` とその周辺クライアントコードのみ
- [ ] **個別デバイスのremoveは実装しない。** 締め出したくなったら世代を上げる。デバイス選択UIも作らない
- [ ] **移行コードは書かない（クリーンブレーク）。** 既存Vaultは作り直し。デュアルリード・移行マーカー・ロールバック経路のいずれも不要
- [ ] **`route-deliver.ts` の multi-recipient 化はしない。** mediatorのキューが受信者kid単位である以上、転送量は減らない（PLAN §7-3）

### 押さえるべき前提

**bisetはRoot/Sign/Spare私鍵を一切持たない。** Wallet（dispo, `app.did.md`）がそれらを保持し、OAuth往復のレスポンスで以下を返すだけ:

- `urn:did.md:derived-secret:v1` — bisetが指定した `purpose`/`context` に対し、Walletが `HKDF(Root私鍵, purpose:context)` を自分のブラウザ内で計算し、**結果の32バイトだけ**返す。`authorization_details` は配列なので **1往復で複数の派生秘密を要求できる**（世代更新で必須）
- `urn:did-core:document-edit:v1` — DID Documentの `services` / `verificationMethods` / `remove` を公開してもらう
- `urn:did.md:key-authorization:v1` — bisetがローカル生成したEd25519公開鍵に対する Root+Sign 署名credential（31日失効）

既存の実例は `src/client/identity/wallet/did-md-oauth.ts` の `MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE`（:55）とその処理経路（`redirectToWallet` :659 → `capabilityDetails` :502 → `tokenFrom` :584）。**VCKもまったく同じ経路に乗せる。**

### 検証コマンド

```
bun run typecheck     # tsc（4つのtsconfig全部）
bun run test          # test/ 配下を1ファイルずつ
bun run knip          # 未使用export検出（撤去作業で必ず使う）
bun run check         # 上記全部 + reachability
```

各フェーズの完了時に最低 `bun run typecheck && bun run test` を通すこと。撤去フェーズでは `bun run knip` も必須。

---

## Phase 1: 鍵層（VCK）

MLSを残したまま並行して成立する。まずここだけで一度 green にすること。

### 1-1. VCKモジュールの新設

- [x] `src/client/store/vault/vault-content-key.ts` を新規作成
  - [x] `export const VAULT_CONTENT_KEY_GROUP_ID = 'urn:biset:vault-content-key:v1'`
  - [x] `export const VAULT_CONTENT_KEY_PURPOSE = 'biset:vault-content-key:v1'`
  - [x] `vaultGenerationUrn(generation: MlsEpoch): string` → `` `${VAULT_CONTENT_KEY_GROUP_ID}:${generation}` ``
  - [x] `parseVaultGenerationUrn(value: string): MlsEpoch` — 厳格にパース。プレフィックス不一致・`assertMlsEpoch` 不合格は throw
  - [x] `export class WalletDerivedVaultKeyResolver implements VaultEpochKeyResolver`
    - `currentVaultEpoch(identityId)` → `{ selfGroupId: VAULT_CONTENT_KEY_GROUP_ID, epoch: <現在の世代> }`
    - `deriveVaultEpochKey(identityId, selfGroupId, epoch)` → セッションに保持しているVCKを返す。`selfGroupId` 不一致、または要求世代のVCKを持っていない場合は throw（「did.md Walletに再接続してください」系のメッセージ）
  - [x] 世代とVCKの供給元はコンストラクタ注入にする（セッションストアを直接importしない。`MlsVaultEpochKeyResolver` が `MlsSelfGroupProvider` を注入されているのと同じ構造にする）

> **背景**: `VaultEpochKeyResolver`（`src/client/store/vault/segment-key-resolver.ts:12`）は `{selfGroupId, epoch}` という抽象で、MLS固有の概念に依存していない。`selfGroupId`→固定URN、`epoch`→世代カウンタと読み替えるだけで、`SegmentKeyWrap`・`vault-checkpoint.ts`・`recovery-archive-rewrap.ts`・`projection-rebuild.ts` は**すべて無改変で動く**。`MlsEpoch` は `assertMlsEpoch`（`src/protocol/ids.ts:94`）が検証する符号なし64bit10進文字列なので、世代カウンタがそのまま入る。

- [x] `test/` に単体テストを追加（URNの往復、不正入力の拒否、世代不一致時のthrow）

### 1-2. DID Document への世代公開

- [x] `src/client/identity/wallet/did-md-oauth.ts`
  - [x] `defaultDidDocumentServices`（:80）に `#biset-vault` テンプレートを追加
    ```ts
    { id: '#biset-vault', type: 'BisetVault', serviceEndpoint: '$vaultGeneration' }
    ```
  - [x] `buildDocumentEdit`（:336）に現在の世代を渡せるようにし、`materializeServiceEndpoint`（:109）の置換表に `'$vaultGeneration': vaultGenerationUrn(generation)` を追加
  - [x] `#biset-vault` は `purpose: 'didcomm'` を持たないため、`.filter(service => service.purpose !== 'didcomm' || device)`（:339）の対象外になる＝**mediator未設定でも常に公開される**。この性質を壊さないこと（PLAN §5 ギャップ4の理由）
  - [x] `walletConfiguration`（:84）のバリデーションが新テンプレートを通すことを確認

> **なぜ独立サービスか**（`#didcomm` に畳まない理由）: ①`removeMediator` で `#didcomm` ごと消えると世代も消える ②署名済みDIDログ上にないと世代ロールバック攻撃（古いチェックポイントを注入して旧VCKを使わせる）を防げない ③`#didcomm` は mediator 変更のたびに作り直されるので、世代の引き継ぎ忘れという静かなバグを生む

- [x] DID Document から現在の世代を読むリーダーを実装
  - [x] 解決済みドキュメントの `service` から `id` が `#biset-vault`（または `<did>#biset-vault`）のものを探し、`serviceEndpoint` を `parseVaultGenerationUrn` に通す
  - [x] 見つからない場合の扱いを決めて明記する（クリーンブレーク前提なので「未初期化」として扱い、初回ログイン時に世代0で作成する経路にする）

### 1-3. 派生秘密の要求と保存

- [x] `did-md-oauth.ts` の pending / authorization_details に VCK 要求を追加
  - [x] `redirectToWallet`（:659）の `authorization_details` 配列に `{ type: DERIVED_SECRET_DETAIL, purpose: VAULT_CONTENT_KEY_PURPOSE, context: '<generation>' }` を載せる
  - [x] **複数世代を同時に要求できる形にする**（世代更新で n と n+1 を1往復で取るため。`app.ts` 側は `authorizationDetails.map` で全DERIVED_SECRET_DETAILを処理するので、複数入れて問題ない）
  - [x] `capabilityDetails`（:502）で、返ってきた derived-secret のうち VCK 分を `purpose`/`context` の一致を確認しつつ取り出す（既存のMIMI room分の検証ロジックが手本）
  - [x] `tokenFrom`（:584）でセッションに保存

- [x] `src/client/identity/wallet/did-md-store.ts`
  - [x] `DidMdDeviceSession`（:122）に VCK 保持フィールドを追加。**世代→鍵のマップにすること**（更新中は n と n+1 を併せ持つ必要がある）
  - [x] VCKは秘密なので、`bisetDevice` の `sealed` と同じ封印パターン（`sealDidMdBisetDeviceMaterial` 相当）に乗せる。平文でIndexedDBに置かない
  - [x] `mimiVaultRoom` のようにセッション復元時に引き継ぐ経路（`tokenFrom` :601-602 の `previousSession` 参照が手本）を用意する

### 1-4. 配線の差し替え

- [x] `src/client/identity/bootstrap.ts` の4箇所（:182, :239, :267, :296）の `new MlsVaultEpochKeyResolver(...)` を `WalletDerivedVaultKeyResolver` に差し替え
- [x] `src/client/app/main.ts` の `deriveVaultEpochKey` 呼び出し（:482, :540）が新resolverで動くことを確認
- [x] `bun run typecheck && bun run test` が green

---

## Phase 2: CRDT層（Yjs）

### 2-1. 依存追加

- [x] `yjs` を `dependencies` に追加

> **なぜ Yjs か**: biset の依存方針は「wasm実行時読み込みは避けるが、それ以外は車輪の再発明をしない」（`PLAN-mimi.md` §3）。Automerge も Loro も Rust コアの wasm なので不適合。Yjs は pure JS で唯一適合する。**この判断を覆さないこと。**

### 2-2. CRDTログモジュール

- [x] `src/client/store/vault/crdt-log.ts` を新規作成
  - [x] Vaultイベントを `Y.Array` の要素として保持するドキュメントのラッパ
  - [x] `appendEvent(doc, event)` — ローカル変更の追加
  - [x] `encodeStateVector(doc)` — 「自分が持っているもの」
  - [x] `encodeDelta(doc, remoteStateVector)` — `Y.encodeStateAsUpdate(doc, sv)`、「相手に足りないぶん」
  - [x] `encodeSnapshot(doc)` — `Y.encodeStateAsUpdate(doc)`、全体
  - [x] `applyUpdate(doc, update)` — マージ
  - [x] イベントは**不透明な要素として並べる**（フィールド単位のCRDT型には分解しない。PLAN §7-1の決定）

> **この方式で何が直るか**: 現在 `ingestDeliveries`（`mimi-vault-sync.ts`）は同時編集で "vault message.add conflicts with an existing email" を起こし、該当エントリを**恒久的にスキップ**する（端末ごとにVaultの中身がずれる）。Y.Arrayならログの順序が全端末で同一に収束するため、reducerの投影結果も決定的になる。既存の reducer / projection はほぼそのまま使える。

- [x] 既存の `VaultEventV1` / イベントログ読み書き経路（`src/client/store/vault/events.ts`, `store.ts`, `store/projection/reducer.ts`）との接続部を設計・実装
- [x] 単体テスト: 2つのdocに別々の変更を入れて相互applyし、**両者が同一の順序に収束すること**を確認

---

## Phase 3: 配送層

### 3-1. メッセージ型

- [x] `src/protocol/didcomm/vault-sync-protocol.ts` を新規作成（`mediator-protocol.ts` と同じスタイルで定数を1箇所に）
  ```
  https://biset.md/vault-sync/1.0/update           差分push
  https://biset.md/vault-sync/1.0/state-request    pull要求（state vector同梱）
  https://biset.md/vault-sync/1.0/state-response   pull応答（差分/スナップショット、チャンク分割）
  ```
- [x] biset独自拡張である旨を、`mediator-protocol.ts:21-31` の `WATCH_REQUEST` と同じようにコメントで明記する

### 3-2. チャンク分割の移設

- [x] `src/client/store/vault/mimi-vault-chunks.ts` → `vault-sync-chunks.ts` にリネームし、MIMI固有の命名を外す
  - [x] 分割・再構成・ハッシュ検証のロジックはそのまま流用可（500KiB/チャンク、最大256チャンク、canonical JSON）
  - [x] `sendMimiVaultCheckpoint` はSelf MIMI撤去に伴い削除し、pull応答は `VaultSyncClient` のstate-responseへ置換

### 3-3. 同期クライアント

- [x] `src/client/didcomm/vault-sync.ts` を新規作成

**push（小さな差分を全兄弟デバイスへ）**
- [x] ローカル変更発生時に `encodeDelta` を計算
- [x] VCKで暗号化（内容機密性はここで確定する）
- [x] 各兄弟デバイス宛にDIDComm packし、Forward経由でmediatorへ（既存の `src/client/didcomm/send-message.ts` の経路を使う）

**pull（大きな状態を要求元1台へ）**
- [x] `state-request` に自分のstate vectorを同梱
- [x] 受け取った側は **要求元にだけ** `state-response` を返す（チャンク分割）
- [x] 新端末のブートストラップと、長期離脱後のcatch-upの両方をこの経路で賄う

> **チェックポイント／スナップショットを push 経路に流さないこと。** mediatorのキューは受信者kid単位で、Forward wrapが添付を各kidぶん複製するため、大きなペイロードをfan-outすると転送量がデバイス数倍になる。push=小さい差分、pull=大きい状態、の分離がこの設計の要（PLAN §3）。

**宛先の解決**
- [x] 兄弟デバイスの一覧は **DID Document から読む**（Vault内の `DidCommDeviceKeyV1` レコードは使わない）
  - [x] 理由: Vaultを開く前でも解決できる必要がある（新端末のブートストラップで循環依存になる）
  - [x] 自分（biset）が登録した分の識別は `deviceKidFragment(x25519PublicKey)` 規約で再計算して照合する。DID Documentは他のRPとも共有される資産なので、他RPのエントリを拾わないこと
- [x] 送信直前にDID Documentを再解決してから宛先リストを組む（キャッシュ由来の取りこぼし防止）

### 3-4. 受信ループ

- [x] `mediator-pickup.ts` の既存クライアント（`pickupStatus` / `pickupDeliver` / `acknowledgeMessages`）で受信する
- [x] biset-mediator に対しては SSE（`requestWatch` / `mediatorStreamUrl`）で即時起動、第三者mediatorではポーリングにフォールバックする
- [x] 受信した `update` を復号 → `applyUpdate` → ack（`messages-received`）の順。**durableに適用してからackすること**

---

## Phase 4: 失効フロー（世代更新）

### 4-1. 世代更新の実装

Wallet承認は1往復。1つの authorization request で世代 n/n+1 のVCK取得と公開世代の更新を行い、Bisetへ戻った直後にローカルSegmentKeyを再ラップする。

- [x] `derived-secret` で generation n と n+1 のVCKを同時に要求
- [x] 同じ承認の `documentEdit` で:
  - [x] `#biset-vault` の `serviceEndpoint` を generation n+1 に更新
  - [x] biset自身が過去に登録した `#didcomm` デバイス鍵を、**操作元デバイス以外すべて** `remove`
- [x] callbackで新旧VCKを端末内に保存した後、現行VCK(n)で全SegmentKeyをアンラップし、VCK(n+1)で再ラップして保存
- [x] 再ラップ完了までは `phase: rewrap` を永続化し、reload後もauthorizeなしで冪等に再開する
- [x] `SegmentKeyWrap` は generation 単位で保管されるため n と n+1 は併存できる
- [x] 一掃の対象は `deviceKidFragment` 規約で自分の登録分と確認できたものだけに限定する

> 名簿の一掃は個別選択を伴わない一律の掃き出しであり、「個別removeを実装しない」方針と矛盾しない。生きている端末は次回ログイン時に `buildDocumentEdit` が自分のエントリを含めるため自動的に復帰する。新VCKを得るためにどのみちログインが必要なので追加負担にはならない。名簿から外れていた間の差分は Phase 3-3 の pull 経路で取り戻す。

- [x] ガード: 操作元デバイス自身は掃き出しの対象外にする

### 4-2. UI

- [x] `src/client/app/main.ts:626` の `onRemoveVaultDevice` を削除し、「世代更新」アクションに置き換える（`main.ts:1005` の config 配線も更新）
- [x] `src/client/app/ui/account-page.ts:277-304` のデバイス一覧を**情報表示のみ**にする（個別removeボタンを撤去）
  - [x] 一覧は全履歴の actor ではなく、現在のDID Documentに残る自己検証可能なBiset DIDComm leafだけを表示する。世代更新で掃き出された旧世代端末は表示せず、現世代VCKで再ログインしてleafを再公開した端末だけを復帰させる
- [x] 失効操作は「**Vaultの鍵を更新する（他のすべての端末で再ログインが必要になります）**」という単一のアクションとして提示する
- [x] 確認ダイアログに限界を明記する: 更新は「これから先」だけを守り、**対象デバイスが更新前に受信済みの内容は取り消せない**。乗っ取りを疑う場合の追加対応は別の説明面へ誘導する

---

## Phase 5: 撤去

`bun run knip` を回しながら進めること。

- [x] `src/client/mimi/vault-room.ts` 削除
- [x] `src/client/mimi/vault-session.ts` 削除
- [x] `src/client/mimi/vault-watch.ts` 削除
- [x] `src/client/mimi/room-migration.ts` 削除
- [x] `src/client/store/vault/mimi-vault-sync.ts` 削除
- [x] `src/client/store/vault/didcomm-device-key.ts` / `-reader.ts` / `-sink.ts` 削除（唯一の読み手が MLS revoke だった）
- [x] `src/client/mls/vault-epoch.ts` 削除（`MlsVaultEpochKeyResolver`）
- [x] `src/client/mimi/client-transport.ts` から `MimiClientMode: 'self'` と `selfBaseUrl` を撤去
- [x] `did-md-oauth.ts` の `vaultSecret`（:727）と、`did-md-store.ts` の対応フィールドを削除（未使用のデッドコード）
- [x] `did-md-oauth.ts` の `MIMI_VAULT_ROOM_DERIVED_SECRET_PURPOSE` / `mimiVaultRoom` 関連を撤去
- [x] `src/client/store/vault/storage-root.ts` のデッドパス（`deriveVaultStorageKek` / `VAULT_STORAGE_GROUP_ID` / `VAULT_STORAGE_EPOCH` と、それを受ける `storageKek` 引数）を VCK 方式に吸収するか削除する
- [x] 対応するテストの削除・更新（`test/vault-mimi-sync.test.ts`, `test/vault-mimi-chunks.test.ts` ほか）
- [x] `biset-vault-relay` のビルド/デプロイ定義を撤去（`biset-mimi` の normal/anon モードは interop 用に稼働継続するので**残す**）

**撤去してはいけないもの（再掲）**
- [ ] `src/protocol/mimi/*`
- [ ] `src/server/mimi/*`
- [ ] `src/mls/conversation-group-*.ts`
- [ ] `MimiClientMode` の `'normal'` / `'anon'`

---

## Phase 6: 検証

- [x] `bun run check` が green（typecheck + knip + reachability + test、2026-09-15実行）
- [x] 2台のクライアントで、一方の変更が他方に反映されること
- [x] 新端末が、**既存端末が1台もオンラインでない状態から**、mediatorに残るチェックポイント経由でVaultを復元できること（VCK方式の主要な利点。MLS方式では不可能だった。`test/didcomm-vault-sync.test.ts` は別の新規mediator-control接続で同じVCK派生受信鍵を登録し、既存の通常デバイスを起動せずに暗号化state-responseを復元する。`test/protocol/vault-recovery-checkpoint.test.ts` は同じcheckpointがCRDTだけでなく暗号化object・署名event・VCK wrapも原子的に復元することを検証する）
- [x] 世代更新後、更新前のVCKしか持たない端末が新しい内容を復号できないこと
- [x] 世代更新後、生きている端末が再ログインで復帰できること（`test/didcomm-vault-sync.test.ts` は世代1のVCK派生回復受信鍵に対し、旧control接続が保存したcheckpointを、新しいcontrol接続＝再ログイン済み端末として登録・復元する）
- [x] **mediatorが「DID Documentから消えたxKid宛のforward」をどう扱うかを実測する**（登録済みkidにはDID再解決なしでキューへ受理する。BisetはDID Documentの再解決で宛先から外すため、新規送信は行わない）

---

## 付録: 設計判断の早見表（迷ったら）

| 論点 | 決定 | 根拠 |
|---|---|---|
| CRDTライブラリ | Yjs | wasm不使用の既存方針（PLAN §7-1） |
| Yjs写像の深さ | イベントログを Y.Array | reducer/projection を温存できる（PLAN §7-1） |
| VCK世代の置き場 | 独立した `#biset-vault` サービス | ライフサイクル分離・ロールバック防止・誤クロバー防止 |
| 個別デバイスremove | 実装しない | 世代更新で足りる |
| 移行 | クリーンブレーク | 既存Vaultは作り直し |
| multi-recipient暗号化 | しない | 転送量が減らない（PLAN §7-3） |
| 大きなペイロード | pushせずpullで1:1 | fan-outの転送量問題（PLAN §3） |
| 宛先名簿 | DID Document | Vaultを開く前に必要（循環依存の回避） |
