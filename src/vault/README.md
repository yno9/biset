# Vault モジュール

このディレクトリは Biset の唯一の長期正本を実装する場所である。

## 保存の中核

- `store.ts`: IndexedDB の永続化層。object / event / key wrap / outbox を一つのトランザクション境界で扱う
- `objects.ts`: 暗号化 object の封入と復号、hash 検証
- `events.ts`: immutable event の署名・検証
- `manifest.ts`: Merkle manifest と差分検出
- `crypto.ts`: MLS exporter から導出した VEK、SegmentKey、key wrap
- `active-segment.ts`: 書き込み可能な現行 segment の決定と検証（`assertActiveVaultSegment`）
- `storage-root.ts` / `segment-key-resolver.ts`: SegmentKey の解決経路

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
- `mimi-vault-sync.ts` / `mimi-vault-chunks.ts`: biset-mimi Self Vault との同期（現行の複数端末同期の本番経路）
- `vault-checkpoint.ts`: checkpoint の封入と復元
- `ingress-ingest.ts` / `ingress-sync.ts`: 外部 ingress の確定

## 復旧

- `recovery-archive*.ts`: 利用者管理の暗号化 archive への export / import / rewrap
- `restore-workflow.ts` / `restore-transfer*.ts`: peer からの resumable restore
  （**現在 transport 実装も本番呼び出し元も存在しない。テストのみが動かしている**——
  `bun run reachability` の「reached only by tests」に出る。PLAN-simplify.md §5 参照）

## 規則

- protocol と wire schema の正本は `src/protocol/`、システム全体の現行アーキテクチャは
  リポジトリ直下の `ARC.md`（§6・§9 が Vault と Self Vault 同期を扱う）。
  かつてここが指していた `PLANIMPLEMENTATION.md` は 2026-09-05 に削除された
- 長期正本はこの暗号化 Vault であり、mediator や biset-mimi ではない。
  サーバー側に history query や mailbox DB を持たせてはならない
