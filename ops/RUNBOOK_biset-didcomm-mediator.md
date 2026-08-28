# biset-didcomm-mediator 運用手順

## 前提

- 公開URLはHTTPSで終端し、process自体は`127.0.0.1:8791`だけで待ち受ける。
- `/var/lib/biset-didcomm-mediator`だけを書き込み可能にする。
- SQLite DBにはmediator秘密鍵、connection keylist、opaque JWE、ACK/replay tombstoneが入る。本文をlogへ出さない。
- single active writerで運用する。同じDBを複数processからactive-active利用しない。

## 初回設置

1. `bun run build:didcomm-mediator`でLinux x86_64 binaryを作る。
2. binaryを`/opt/biset/didcomm-mediator/biset-didcomm-mediator`へ設置する。
3. `didcomm-mediator.env.example`を`/etc/biset/didcomm-mediator.env`へコピーし、公開URLを確定する。
4. `biset-didcomm-mediator.service`をsystemdへ設置して起動する。
5. reverse proxyへ`Caddyfile.didcomm-mediator.example`相当のrouteを追加する。

初回起動時にmediator did:peer鍵がDBへ生成される。以後`MEDIATOR_PUBLIC_URL`を変更するとDIDも変わるため、processは意図的に起動失敗する。

## 確認

```sh
curl -fsS http://127.0.0.1:8791/healthz
curl -fsS http://127.0.0.1:8791/readyz
curl -fsS https://mediator.example.com/.well-known/did.json
curl -fsS http://127.0.0.1:8791/metrics
```

`readyz`が503ならDB破損・I/O error・shutdown中を疑う。壊れたDBを別名で退避せず空DBを作って起動してはいけない。既存clientのregistrationと待機messageが孤立する。

## Backup

DB本体だけでなくWAL整合性が必要なので、稼働中の単純な`cp`は使わない。

```sh
sqlite3 /var/lib/biset-didcomm-mediator/mediator.sqlite \
  ".backup '/var/backups/biset-didcomm-mediator/mediator-$(date +%Y%m%d-%H%M%S).sqlite'"
```

backupにはmediator秘密鍵が含まれる。permissionを`0600`相当にし、別系統へ暗号化保管する。

## Restore rehearsal

1. serviceを停止する。
2. 現DB、`-wal`、`-shm`を同じincident directoryへ退避する。
3. backupを`mediator.sqlite`へrestoreする。
4. `sqlite3 mediator.sqlite 'PRAGMA integrity_check'`が`ok`であることを確認する。
5. serviceを起動し、`readyz`と公開DIDがbackup前と同じことを確認する。
6. test clientでregister→Forward→restart→pickup→ACKを確認する。

## Upgrade / rollback

- binaryを`.new`でuploadし、architectureを確認してからatomic renameする。
- DB backupを取ってからrestartする。
- schema migration後の古いbinary rollbackは自動で安全とは限らない。release noteのschema versionを確認する。
- binaryだけを戻す場合も、公開DIDが変化していないことを確認する。

## Alert候補

- `readyz != 200`
- process restart loop
- queued bytes/itemsの継続増加
- oldest message ageのTTL接近
- filesystem使用率80%以上
- Forward 503、SQLite I/O error、replay拒否の急増

metrics labelへrecipient kidやconnection DIDを入れない。
