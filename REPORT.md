# Vault Sync 移行作業報告

作成日: 2026-09-15

## 結果

`WORKSHEET_vault-sync.md` の実装・検証項目を完了し、検証済みの項目を `[x]` に更新した。
残る `[ ]` はタスクではなく、MIMIモジュールを消さない・個別removeを作らない・移行コードを作らない・multi-recipient化しない、という不変条件である。

## 実施内容

- Wallet派生の Vault Content Key (VCK) を導入した。
  - 世代は DID Document の `#biset-vault` サービスで公開する。
  - VCKはセッション内で世代ごとに封印保存し、既存の `VaultEpochKeyResolver` 境界へ接続した。
  - 世代更新は、次世代VCK取得・SegmentKey再ラップ・DID Document公開の二段階にした。
- Vaultイベントログを Yjs `Y.Array` に移した。
  - 差分同期、state vector、snapshot、同時更新の収束を実装した。
- DIDComm mediator 経由の Vault同期を実装した。
  - 通常更新は兄弟端末へ小さなYjs差分だけをfan-outする。
  - 新端末・長期離脱端末は state-request / state-response による1対1のpullで追随する。
  - 宛先はVault内の名簿ではなく、毎回DID Documentから自己検証して解決する。
- Self MIMI専用のVault同期・監視・room移行・MLS self-group/Vault epoch経路を撤去した。
  - `MimiClientMode` は `normal` / `anon` のみ残した。
  - `src/protocol/mimi/*` と `src/server/mimi/*` の第三者provider互換部分は維持した。
- 未使用コードをknipで整理した。
  - 未参照のMLS補助コードと未使用exportを削除した。
  - 第三者MIMI provider向けの `submitVaultCheckpointSigningBytes` と `decodeDeliveryEntry` は `@public` として明示し、公開互換APIとして残した。

## 独自判断と根拠

### 1. mediator上の回復チェックポイントの保存方法

設計書は「mediatorに残るチェックポイント」を要求していたが、既存mediatorには任意blobを保存・取得する独自APIはなかった。
そこで新たなサーバーAPIやSelf MIMIを追加せず、現在世代のVCKからHKDFで決定論的にX25519回復受信鍵を導出する方式にした。

- 各ログイン端末は、その回復kidを既存の Coordinate Mediation keylist に登録する。
- 完全Vaultチェックポイントは、そのkidだけへ通常のDIDComm Forwardとして送る。
- 新端末は同じWalletから同じVCKを得るため、既存の通常端末が全台オフラインでも回復kidの秘密鍵を再導出してPickupできる。
- mediatorには暗号文しか保存されず、独自の保存API・復号権限・Vault索引は追加していない。

これは「pushで大きなpayloadを兄弟全員へfan-outしない」という設計制約も維持する。チェックポイントは回復受信鍵1件だけへの送信であり、通常差分のfan-out経路とは分離されている。

### 2. チェックポイントをCRDTだけでなく完全Vaultにした

最初のCRDT snapshotだけでは、イベントが参照する暗号化objectとSegmentKey wrapが新端末に存在せず、実際のVault復元として不完全だった。
このため、既存の recovery archive 形式をVCK暗号化されたcheckpoint payloadに含めるようにした。

- CRDT snapshot
- 暗号化Vault object
- 署名済みVault event
- 各SegmentKey

をまとめ、受信側では現在世代VCKでSegmentKey wrapを再作成してからIndexedDBへコミットする。これにより、復元後にobjectを読み出せる。

### 3. 世代更新時のcheckpoint順序

Round 2でDID Documentの世代を公開する前に、Round 1で得た次世代VCKによる回復checkpointをmediatorへ保存するようにした。
この順序により、公開直後に再ログインする生存端末は次世代VCKだけで復元できる。公開前に失敗した場合は旧世代が依然として有効であり、公開後に新世代のcheckpointが存在しない状態を避けられる。

### 4. knip修正の扱い

knipの検出結果に対し、未参照の非公開exportは機械的に削除した。その後に型検査・全テスト・reachabilityを実行した。
ただしMIMIの第三者interop境界はワークシートの保持条件を優先し、外部利用があり得る2関数を公開APIとして明示して削除対象から外した。

## 主な追加・変更ファイル

- `src/client/store/vault/vault-content-key.ts`
- `src/client/store/vault/crdt-log.ts`
- `src/client/store/vault/vault-sync-chunks.ts`
- `src/client/store/vault/vault-key-rotation.ts`
- `src/client/store/vault/vault-recovery-checkpoint.ts`
- `src/client/didcomm/vault-sync.ts`
- `src/protocol/didcomm/vault-sync-protocol.ts`
- `src/client/identity/wallet/did-md-oauth.ts`
- `src/client/identity/wallet/did-md-store.ts`
- `src/client/app/main.ts`

## 検証

以下を実行し、成功した。

```sh
bun run typecheck
bun run knip
bun run reachability --quiet
bun run test
bun run check
git diff --check
```

追加した主な検証:

- `test/didcomm-vault-sync.test.ts`
  - 2端末のCRDT収束
  - mediatorを経由した、通常端末全台オフライン時の回復
  - 次世代VCKで再ログインした端末の回復
- `test/protocol/vault-recovery-checkpoint.test.ts`
  - checkpointによるCRDT、Vault object、event、VCK wrapの一括復元

