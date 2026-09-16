# Vault モジュール

このディレクトリは Biset の唯一の長期正本を実装する場所である。

## 保存の中核

- `store.ts`: IndexedDB の永続化層。object / event / key wrap / outbox を一つのトランザクション境界で扱う
- `objects.ts`: 暗号化 object の封入と復号、hash 検証
- `events.ts`: immutable event の署名・検証
- `manifest.ts`: Merkle manifest と差分検出
- `crypto.ts`: Vault Content Key (VCK) で保護する SegmentKey と key wrap
- `active-segment.ts`: 書き込み可能な現行 segment の決定と検証（`assertActiveVaultSegment`）
- `segment-key-resolver.ts`: VCKでラップされたSegmentKeyの解決経路

## 書き込み

- **`commit.ts`: 共有 vault 状態を書く全経路が通る唯一の組み立て地点**（`buildVaultCommit`）。
  objects/events への identity スタンプ → projection → delivery pack → payload hash → delivery outbox。
  ここを迂回して `encodeVaultDeliveryPack` を直接呼ぶ本番コードがあってはならない
- `mutations.ts` / `mutation-records.ts` / `mail-message.ts`: 各 record 種別の build
- `credential-store.ts`: private credential の汎用 reader / sink。
  contact-key・DIDComm credential・DIDComm device key・OpenPGP credential の4系統は
  すべてこの1実装に記述子を渡す薄いラッパである（`*-reader.ts` / `*-sink.ts`）

## 配送と同期

- `delivery-pack.ts` / `delivery-outbox.ts` / `delivery-ingest.ts` / `delivery-projector.ts`: shared delivery、ACK、cursor
- `crdt-log.ts` / `vault-sync-chunks.ts`: YjsイベントログとDIDComm Vault同期のペイロード分割
- `ingress-ingest.ts` / `ingress-sync.ts`: 外部 ingress の確定

## 復旧

- `recovery-archive.ts` / `recovery-archive-export.ts`:
  利用者管理の暗号化 archive

## 規則

- protocol と wire schema の正本は `src/protocol/`、システム全体の現行アーキテクチャは
  リポジトリ直下の `ARC.md`。
  かつてここが指していた `PLANIMPLEMENTATION.md` は 2026-09-05 に削除された
- 長期正本はこの暗号化 Vault であり、mediator や第三者MIMI providerではない。
  サーバー側に history query や mailbox DB を持たせてはならない
