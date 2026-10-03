# Vault モジュール

このディレクトリは Biset の唯一の長期正本を実装する場所である。

## 保存の中核

- `store.ts`: IndexedDB の永続化層。object / event / segment key を一つのトランザクション境界で扱う
- `objects.ts`: 暗号化 object の封入と復号、hash 検証
- `events.ts`: immutable event の組み立てと検証。event id は内容の hash で、署名は持たない
  （Vault の内容が端末間を動くのは DIDComm authcrypt の中だけなので、送り手の認証はそちらが担う）
- `manifest.ts`: Merkle manifest と差分検出
- `active-segment.ts`: 書き込み可能な現行 segment の決定と検証（`assertActiveVaultSegment`）
- `segment-key-resolver.ts`: SegmentKey の解決経路（端末ローカルの segment key を読むだけ）

## 書き込み

- **`commit.ts`: 共有 vault 状態を書く全経路が通る唯一の組み立て地点**（`buildVaultCommit`）。
  objects/events への identity スタンプ → JMAP projection。
  他端末への反映は Vault Sync が、コミット済みの record を読んで行う
- `mutations.ts` / `mutation-records.ts` / `mail-message.ts`: 各 record 種別の build
- `credential-store.ts`: private credential の汎用 reader / sink。
  contact-key・relationship-seed・OpenPGP credential は、
  すべてこの1実装に記述子を渡す薄いラッパである

## 同期

- `delivery-pack.ts`: Vault Sync で送る event / object / segment key の束
- `ingress-ingest.ts`: 外部 ingress の確定
- 端末間の同期そのものは `client/didcomm/vault-sync.ts`（自分の DID 宛ての DIDComm メッセージ）

## エクスポート

- `jmap-export.ts`: 平文 JSON の JMAP エクスポートと取り込み。
  取り込んだものには `$imported` キーワードが付く

## 規則

- protocol と wire schema の正本は `src/protocol/`、システム全体の現行アーキテクチャは
  リポジトリ直下の `ARC.md`
- 長期正本はこの暗号化 Vault であり、mediator や第三者MIMI providerではない。
  サーバー側に history query や mailbox DB を持たせてはならない
