# Coordinator MLS Delivery Service の稼働手順

## 前提

Self Group MLS Delivery Serviceは`biset-coordinator`だけが提供する。旧Coreの
MLS API、DB、クライアントtransportとの後方互換は提供せず、既存MLS履歴も
移行しない。MLS private state、秘密鍵、group policy、commitの暗号学的検証は
Clientが担う。

## 手順

1. `bun run typecheck`、`bun run test`、`bun run build:coordinator`、
   `bun run build`を完走させる。
2. Coordinator DBをバックアップする。
3. 新しい`biset-coordinator` binaryと、`coordinatorUrl`がCoordinator originを
   指す新UIを同じreleaseとして配置する。
4. `ops/coordinator.env.example`と`ops/coordinator.service.example`を基に
   serviceを起動する。
5. `GET /healthz`が200を返すことを確認する。
6. 新規identityを作成し、Coordinator DBへ`mls_ds_groups`と
   `mls_ds_key_packages`が作られることを確認する。
7. Root loginで二台目を追加し、External Commit、Welcome、両端末のcatch-up、
   新しいmessageのVault同期を実機確認する。

旧UIはCoordinator DSへ接続できないため公開しない。旧Coreの`mls_groups`、
`mls_log`、`mls_key_packages`は参照もimportもしない。不要になった旧データの
削除は、rollback不要と確認した後に別の明示的な運用として行う。
