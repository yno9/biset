# Vault モジュール

このディレクトリは Biset の唯一の長期正本を実装する場所である。

- `objects.ts`: 暗号化 object/chunk の永続化と hash 検証
- `events.ts`: immutable event の署名・追加・競合規則
- `manifest.ts`: Merkle manifest と差分検出
- `crypto.ts`: MLS exporter からの VEK、SegmentKey、key wrap
- `ingest.ts`: ingress を local vault transaction に確定する処理
- `delivery.ts`: shared delivery、ACK、cursor
- `restore.ts`: peer/archive からの resumable restore
- `projection.ts`: Local JMAP の read model

実装時の protocol と状態機械はリポジトリ直下の `PLANIMPLEMENTATION.md` を正とする。core に history query や mailbox DB を追加してはならない。

