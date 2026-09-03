#!/usr/bin/env bash
# biset 本番デプロイ。別成果物を扱う（混同厳禁）:
#   app     : チャットアプリ  dist/index.html      → v1:/root/biset/app/     (t.biset.md が Caddy 配信)
#   landing : ランディング     home/*               → v1:/root/biset/home/    (biset.md が Caddy 配信)
#   anchor  : Identity Provider + did:webvh host src/anchor/*
#             → v1:/opt/biset/bin/biset-anchor (systemd biset-anchor.service,
#             listen 127.0.0.1:8788)。旧anchor.service:8770は2026-08-30に廃止・削除済み。
#   smtp    : メールrelay      ~/biset/jmapsmtp     → v1:/root/jmapsmtp/      (systemd jmapsmtp, mail.biset.md)
#   ap      : ActivityPub relay ~/go-jmapap         → v1:/root/jmapap/        (systemd jmapap,   ap.biset.md)
#   relay   : smtp + ap をまとめて
# 配信は Caddy（jmapap ではない）。relay 資産とは /root/biset/ に分離済み。
# anchorはv1と別ホスト(v2)、macローカルはarm64だがv2はx86_64なので
# クロスビルド必須（bun build --compile --target=bun-linux-x64、package.json
# のbuild:anchorに埋め込み済み）。ここを忘れてネイティブ(arm64)バイナリを
# そのまま送ると、実行中プロセスを再起動した瞬間 systemd が
# status=203/EXEC で起動失敗する（2026-07-28 本番で発生、原因はまさにこれ）。
# ap（go-jmapap）も同じ罠（v1もx86_64）なので GOOS/GOARCH を明示し、
# ローカルとリモート両方で file(1) によるアーキ確認を通してからでないと
# swap しない。smtp（jmapsmtp、Rust）はクロスコンパイルが実質不可能
# （web-push→isahc→curl、ring がCコンパイラ・muslクロスツールチェーンを
# 要求する）ため、s2（Linux/x86_64ビルドホスト）上でビルドしてv1に送る
# ~/biset/jmapsmtp/scripts/deploy.sh に丸投げする（deploy_smtp参照）。
#
# smtp は2026-08-16、go-jmapsmtpからjmapsmtp（Rust、~/biset/jmapsmtp）へ
# 移行済み — go-jmapserverとはもう無関係（この移行を忘れて古いdeploy_smtp
# で上書きし、biset本体が新しく送るsession statementのrelayHostセグメント
# をサーバー側が知らずに全ログイン401で落ちた実例が2026-08-16にある）。
# go-jmapserver を単体のデプロイ対象として意識する必要があるのは、もう
# ap（go-jmapap）だけ: その go.mod が
#   replace github.com/yno9/go-jmapserver => /Users/n/go-jmapserver
# を持つので、core を直したら ap のバイナリを作り直す必要がある。
#
# 使い方: ./deploy.sh [app|landing|anchor|didcomm-mediator|mail-plugin|smtp|ap|relay|all]   (引数なし = all)
#   mail-plugin は didcomm-mediator と同じ biset-didcomm-mediator.service/DB
#   を奪い合う排他ターゲット（同じsqliteを2プロセスで開けない）。どちらか
#   一方だけが本番で動く。core retirement後の現行方針（2026-09-03時点）で
#   はmail-pluginが本番稼働中。didcomm-mediatorへ戻す時は同じ手順で
#   deploy_didcomm_mediatorを流す。
set -euo pipefail

HOST=v1
APP_DST=/root/biset/app
LANDING_DST=/root/biset/home
ANCHOR_HOST=v1
ANCHOR_DST=/opt/biset/bin
DIDCOMM_MEDIATOR_HOST=v1
DIDCOMM_MEDIATOR_DST=/opt/biset/didcomm-mediator
DIDCOMM_MEDIATOR_PUBLIC_HOST="${DIDCOMM_MEDIATOR_PUBLIC_HOST:-mediator.biset.md}"
ROOT="$(cd "$(dirname "$0")" && pwd)"

# relay repos（biset repo の外にある — このスクリプトが唯一の集約点）
CORE_REPO="${CORE_REPO:-$HOME/go-jmapserver}"    # ap のみが依存
JMAPSMTP_REPO="${JMAPSMTP_REPO:-$HOME/biset/jmapsmtp}"
AP_REPO="${AP_REPO:-$HOME/go-jmapap}"
# 旧バイナリを何世代残すか（ap・go-jmapap側のみ。smtpの世代管理は
# jmapsmtp/scripts/deploy.sh 側の /root/jmapsmtp-bin-bak-* が別途持つ）。
RELAY_BACKUPS=3

target="${1:-all}"

fail() { echo "✗ $1" >&2; exit 1; }

deploy_app() {
  echo "== app: build =="
  ( cd "$ROOT" && bun run build )
  [ -f "$ROOT/dist/index.html" ] || fail "dist/index.html がない"
  [ -f "$ROOT/dist/sw.js" ] || fail "dist/sw.js がない"

  echo "== app: upload → $HOST:$APP_DST =="
  scp "$ROOT/dist/index.html" "$HOST:$APP_DST/index.html"
  # Service Worker は index.html と違ってインライン不可（別ファイルとして
  # 同一オリジンから配信必須） — ルート直下でapp全体をscope対象にする。
  scp "$ROOT/dist/sw.js" "$HOST:$APP_DST/sw.js"

  echo "== app: verify (t.biset.md) =="
  local local_sha remote_sha
  local_sha=$(shasum -a 256 "$ROOT/dist/index.html" | awk '{print $1}')
  remote_sha=$(ssh "$HOST" "sha256sum $APP_DST/index.html" | awk '{print $1}')
  [ "$local_sha" = "$remote_sha" ] || fail "app: サーバーのsha不一致 (local=$local_sha remote=$remote_sha)"
  local sw_local_sha sw_remote_sha
  sw_local_sha=$(shasum -a 256 "$ROOT/dist/sw.js" | awk '{print $1}')
  sw_remote_sha=$(ssh "$HOST" "sha256sum $APP_DST/sw.js" | awk '{print $1}')
  [ "$sw_local_sha" = "$sw_remote_sha" ] || fail "app: sw.jsのsha不一致 (local=$sw_local_sha remote=$sw_remote_sha)"
  local body
  body=$(curl -fsS https://t.biset.md/)
  case "$body" in *BISET_CONFIG*) ;; *) fail "app: t.biset.md が __BISET_CONFIG__ を返さない" ;; esac
  echo "✓ app OK ($local_sha, sw.js $sw_local_sha)"
}

deploy_landing() {
  echo "== landing: upload → $HOST:$LANDING_DST =="
  [ -f "$ROOT/home/index.html" ] || fail "home/index.html がない"
  # home/ 内の全アセットを配る（ドットファイルは対象外）
  for f in "$ROOT"/home/*; do
    scp "$f" "$HOST:$LANDING_DST/$(basename "$f")"
  done

  echo "== landing: verify (biset.md) =="
  local local_sha remote_sha
  local_sha=$(shasum -a 256 "$ROOT/home/index.html" | awk '{print $1}')
  remote_sha=$(ssh "$HOST" "sha256sum $LANDING_DST/index.html" | awk '{print $1}')
  [ "$local_sha" = "$remote_sha" ] || fail "landing: サーバーのsha不一致 (local=$local_sha remote=$remote_sha)"
  local body
  body=$(curl -fsS https://biset.md/index.html)
  case "$body" in *"<!DOCTYPE html>"*|*"<!doctype html>"*) ;; *) fail "landing: biset.md/index.html がHTMLを返さない" ;; esac
  echo "✓ landing OK ($local_sha)"
}

deploy_anchor() {
  echo "== anchor: build (linux-x64 cross-compile) =="
  ( cd "$ROOT" && bun run build:anchor )
  [ -f "$ROOT/biset-anchor" ] || fail "biset-anchor がない"
  file "$ROOT/biset-anchor" | grep -q "x86-64" || fail "biset-anchor がx86_64バイナリでない（クロスビルド失敗）"

  ssh "$ANCHOR_HOST" "test -f /etc/biset/anchor.env; systemctl cat biset-anchor.service >/dev/null" \
    || fail "anchor: env/systemd unitが未準備"

  echo "== anchor: compressed upload → $ANCHOR_HOST:$ANCHOR_DST =="
  local transfer_dir binary_sha
  transfer_dir="$(mktemp -d)"
  binary_sha="$(shasum -a 256 "$ROOT/biset-anchor" | awk '{print $1}')"
  gzip -9 -c "$ROOT/biset-anchor" > "$transfer_dir/biset-anchor.gz"
  scp "$transfer_dir/biset-anchor.gz" "$ANCHOR_HOST:$ANCHOR_DST/biset-anchor.new.gz" \
    || { rm -rf "$transfer_dir"; fail "anchor: upload失敗"; }
  rm -rf "$transfer_dir"
  ssh "$ANCHOR_HOST" "
    set -e
    gzip -dc $ANCHOR_DST/biset-anchor.new.gz > $ANCHOR_DST/biset-anchor.new
    test \"\$(sha256sum $ANCHOR_DST/biset-anchor.new | awk '{print \$1}')\" = $binary_sha
    file $ANCHOR_DST/biset-anchor.new | grep -q x86-64
    rm -f $ANCHOR_DST/biset-anchor.new.gz
  " || fail "anchor: remote checksum/architecture検証失敗"

  echo "== anchor: swap + restart (systemd) =="
  ssh "$ANCHOR_HOST" "
    set -e
    chmod 0755 $ANCHOR_DST/biset-anchor.new
    backup=$ANCHOR_DST/biset-anchor.bak-\$(date +%Y%m%d-%H%M%S)
    cp -p $ANCHOR_DST/biset-anchor \$backup
    mv $ANCHOR_DST/biset-anchor.new $ANCHOR_DST/biset-anchor
    if ! systemctl restart biset-anchor.service || ! sleep 2 || ! systemctl is-active --quiet biset-anchor.service || ! curl -fsS http://127.0.0.1:8788/.well-known/openid-configuration >/dev/null; then
      cp -p \$backup $ANCHOR_DST/biset-anchor
      systemctl restart biset-anchor.service
      exit 1
    fi
  " || fail "anchor: restart/readiness失敗（直前binaryへ自動rollback済み）"

  echo "== anchor: verify (health) =="
  curl -fsS https://biset.md/.well-known/openid-configuration >/dev/null \
    || fail "anchor: 公開OIDC discovery失敗"
  echo "✓ anchor OK"
}

deploy_didcomm_mediator() {
  echo "== didcomm-mediator: protocol + durability tests =="
  ( cd "$ROOT" && bun test \
      test/mediator-server.test.ts \
      test/mediator-client.test.ts \
      test/mediator-relationship-handshake.test.ts \
      test/mediator-sqlite-store.test.ts ) \
    || fail "didcomm-mediator: test失敗（本番に出さない）"

  echo "== didcomm-mediator: build (linux-x64 cross-compile) =="
  ( cd "$ROOT" && bun run build:didcomm-mediator )
  [ -f "$ROOT/biset-didcomm-mediator" ] || fail "biset-didcomm-mediator がない"
  file "$ROOT/biset-didcomm-mediator" | grep -q "x86-64" \
    || fail "biset-didcomm-mediator がx86_64バイナリでない"

  ssh "$DIDCOMM_MEDIATOR_HOST" "
    set -e
    test -d $DIDCOMM_MEDIATOR_DST
    test -f /etc/biset/didcomm-mediator.env
    systemctl cat biset-didcomm-mediator.service >/dev/null
  " || fail "didcomm-mediator: remote directory/env/systemd unitが未準備（ops/を参照）"

  echo "== didcomm-mediator: upload =="
  local transfer_dir binary_sha
  transfer_dir="$(mktemp -d)"
  binary_sha="$(shasum -a 256 "$ROOT/biset-didcomm-mediator" | awk '{print $1}')"
  gzip -9 -c "$ROOT/biset-didcomm-mediator" > "$transfer_dir/biset-didcomm-mediator.gz"
  rsync -a "$transfer_dir/biset-didcomm-mediator.gz" \
    "$DIDCOMM_MEDIATOR_HOST:$DIDCOMM_MEDIATOR_DST/biset-didcomm-mediator.new.gz" \
    || { rm -rf "$transfer_dir"; fail "didcomm-mediator: compressed upload失敗"; }
  rm -rf "$transfer_dir"
  ssh "$DIDCOMM_MEDIATOR_HOST" "
    set -e
    cd $DIDCOMM_MEDIATOR_DST
    gzip -dc biset-didcomm-mediator.new.gz > biset-didcomm-mediator.candidate
    test \"\$(sha256sum biset-didcomm-mediator.candidate | awk '{print \$1}')\" = $binary_sha
    mv biset-didcomm-mediator.candidate biset-didcomm-mediator.new
  " || fail "didcomm-mediator: remote展開/checksum検証失敗"
  ssh "$DIDCOMM_MEDIATOR_HOST" "file $DIDCOMM_MEDIATOR_DST/biset-didcomm-mediator.new" | grep -q "x86-64" \
    || fail "didcomm-mediator: remote binaryがx86_64でない"

  echo "== didcomm-mediator: swap + restart =="
  ssh "$DIDCOMM_MEDIATOR_HOST" "
    set -e
    if [ -f /var/lib/biset-didcomm-mediator/mediator.sqlite ]; then
      install -d -m 0700 /var/backups/biset-didcomm-mediator
      sqlite3 /var/lib/biset-didcomm-mediator/mediator.sqlite \
        \".backup '/var/backups/biset-didcomm-mediator/mediator-\$(date +%Y%m%d-%H%M%S).sqlite'\"
    fi
    cd $DIDCOMM_MEDIATOR_DST
    chmod 0755 biset-didcomm-mediator.new
    if [ -f biset-didcomm-mediator ]; then
      mv biset-didcomm-mediator biset-didcomm-mediator.bak-\$(date +%Y%m%d-%H%M%S)
    fi
    mv biset-didcomm-mediator.new biset-didcomm-mediator
    systemctl restart biset-didcomm-mediator.service
    sleep 1
    systemctl is-active --quiet biset-didcomm-mediator.service
    curl -fsS http://127.0.0.1:8791/readyz >/dev/null
  " || fail "didcomm-mediator: restart/readiness失敗（直前binaryへ手動rollback）"

  curl -fsS "https://$DIDCOMM_MEDIATOR_PUBLIC_HOST/.well-known/did.json" \
    | grep -q '"id"' \
    || fail "didcomm-mediator: 公開HTTPS endpoint検証失敗"
  ( cd "$ROOT" && bun run smoke:didcomm-mediator "https://$DIDCOMM_MEDIATOR_PUBLIC_HOST" ) \
    || fail "didcomm-mediator: production protocol smoke失敗"
  echo "✓ didcomm-mediator OK (https://$DIDCOMM_MEDIATOR_PUBLIC_HOST)"
}

# mediator + mail-plugin (src/mediator/mail-plugin/index.ts) -- the SAME
# biset-didcomm-mediator.service/binary path/database as deploy_didcomm_mediator
# above, not a second process: mail-plugin's own createMediatorDeployment call
# would otherwise fight the plain mediator over the same sqlite file. This
# swaps that one binary for the superset build (mediator core + an inbound
# SMTP listener on :25) and assumes the unit already carries the one-time
# setup a fresh binary swap alone can't provide: AmbientCapabilities=
# CAP_NET_BIND_SERVICE (DynamicUser can't bind :25 otherwise) and
# LoadCredential= entries copying mail.biset.md's Caddy-managed TLS cert/key
# into the service's own credentials dir for STARTTLS (that cert directory
# is root-only 0700, unreadable by the dynamic unprivileged UID directly) --
# see /etc/systemd/system/biset-didcomm-mediator.service on v1 (2026-09-03
# setup) for the exact directives. Retire this target the same way
# deploy_core was retired if the plan direction changes and mail-plugin is
# dropped instead of kept -- swap the binary back with deploy_didcomm_mediator.
deploy_mail_plugin() {
  echo "== mail-plugin: protocol + durability tests =="
  ( cd "$ROOT" && bun test \
      test/mediator-server.test.ts \
      test/mediator-client.test.ts \
      test/mediator-relationship-handshake.test.ts \
      test/mediator-sqlite-store.test.ts \
      test/mediator/mail-plugin/bridge.test.ts \
      test/mediator/mail-plugin/listener.test.ts \
      test/mediator/mail-plugin/mail-smtp-protocol.test.ts ) \
    || fail "mail-plugin: test失敗（本番に出さない）"

  echo "== mail-plugin: build (linux-x64 cross-compile) =="
  ( cd "$ROOT" && bun run build:mail-plugin )
  [ -f "$ROOT/biset-mediator-mail-plugin" ] || fail "biset-mediator-mail-plugin がない"
  file "$ROOT/biset-mediator-mail-plugin" | grep -q "x86-64" \
    || fail "biset-mediator-mail-plugin がx86_64バイナリでない"

  ssh "$DIDCOMM_MEDIATOR_HOST" "
    systemctl cat biset-didcomm-mediator.service | grep -q AmbientCapabilities
  " || fail "mail-plugin: remote unitにAmbientCapabilities未設定（:25 bindできない。手動セットアップが要る、ops/を参照）"

  echo "== mail-plugin: upload =="
  local transfer_dir binary_sha
  transfer_dir="$(mktemp -d)"
  binary_sha="$(shasum -a 256 "$ROOT/biset-mediator-mail-plugin" | awk '{print $1}')"
  gzip -9 -c "$ROOT/biset-mediator-mail-plugin" > "$transfer_dir/biset-mediator-mail-plugin.gz"
  rsync -a "$transfer_dir/biset-mediator-mail-plugin.gz" \
    "$DIDCOMM_MEDIATOR_HOST:$DIDCOMM_MEDIATOR_DST/biset-mediator-mail-plugin.new.gz" \
    || { rm -rf "$transfer_dir"; fail "mail-plugin: compressed upload失敗"; }
  rm -rf "$transfer_dir"
  ssh "$DIDCOMM_MEDIATOR_HOST" "
    set -e
    cd $DIDCOMM_MEDIATOR_DST
    gzip -dc biset-mediator-mail-plugin.new.gz > /root/biset-mediator-mail-plugin.candidate
    test \"\$(sha256sum /root/biset-mediator-mail-plugin.candidate | awk '{print \$1}')\" = $binary_sha
    mv /root/biset-mediator-mail-plugin.candidate biset-didcomm-mediator.new
    rm -f biset-mediator-mail-plugin.new.gz
  " || fail "mail-plugin: remote展開/checksum検証失敗"
  ssh "$DIDCOMM_MEDIATOR_HOST" "file $DIDCOMM_MEDIATOR_DST/biset-didcomm-mediator.new" | grep -q "x86-64" \
    || fail "mail-plugin: remote binaryがx86_64でない"

  echo "== mail-plugin: swap + restart =="
  ssh "$DIDCOMM_MEDIATOR_HOST" "
    set -e
    if [ -f /var/lib/biset-didcomm-mediator/mediator.sqlite ]; then
      install -d -m 0700 /var/backups/biset-didcomm-mediator
      sqlite3 /var/lib/biset-didcomm-mediator/mediator.sqlite \
        \".backup '/var/backups/biset-didcomm-mediator/mediator-\$(date +%Y%m%d-%H%M%S).sqlite'\"
    fi
    cd $DIDCOMM_MEDIATOR_DST
    chmod 0755 biset-didcomm-mediator.new
    systemctl stop biset-didcomm-mediator.service
    if [ -f biset-didcomm-mediator ]; then
      mv biset-didcomm-mediator biset-didcomm-mediator.bak-\$(date +%Y%m%d-%H%M%S)
    fi
    mv biset-didcomm-mediator.new biset-didcomm-mediator
    systemctl start biset-didcomm-mediator.service
    sleep 1
    systemctl is-active --quiet biset-didcomm-mediator.service
    curl -fsS http://127.0.0.1:8791/readyz >/dev/null
    ss -tln | grep -q ':25 ' || exit 1
  " || fail "mail-plugin: restart/readiness失敗（直前binaryへ手動rollback: biset-didcomm-mediator.bak-* を戻してsystemctl restart）"

  curl -fsS "https://$DIDCOMM_MEDIATOR_PUBLIC_HOST/.well-known/did.json" \
    | grep -q '"id"' \
    || fail "mail-plugin: 公開HTTPS endpoint検証失敗"
  echo "✓ mail-plugin OK (https://$DIDCOMM_MEDIATOR_PUBLIC_HOST + SMTP :25)"
}

# ── relay (Go) ────────────────────────────────────────────────────────────────
# smtp と ap は systemd unit 名・設置先・公開ホストが違うだけで手順は同一なので
# 1つの関数に集約する。config.json と data/ はサーバー側の資産 — バイナリ
# 以外は絶対に送らない（データディレクトリを上書きしたら全アカウントが飛ぶ）。
#
#   $1 unit/バイナリ名 (= 設置先ディレクトリ名)  $2 repo  $3 公開ホスト
deploy_relay_unit() {
  local name="$1" repo="$2" public_host="$3"
  local dst="/root/$name"

  [ -d "$repo" ] || fail "$name: repo がない ($repo)"
  # 参照している go-jmapserver がこのマシンのものだと確認してから作る。
  # replace が外れていれば、直したはずの core が入っていない物が出来上がる。
  grep -q "replace github.com/yno9/go-jmapserver => $CORE_REPO\$" "$repo/go.mod" \
    || fail "$name: go.mod の go-jmapserver replace が $CORE_REPO を指していない（core の修正が入らない）"

  echo "== $name: test =="
  ( cd "$repo" && go test ./... >/dev/null ) || fail "$name: go test 失敗（本番に出さない）"

  echo "== $name: build (linux/amd64 cross-compile) =="
  local build_dir
  build_dir="$(mktemp -d)"
  # repo直下ではなく tmp に吐く。過去に手で作った jmapsmtp-linux /
  # jmapap-linux-amd64.new 等が repo に散らかっており、どれが今のものか
  # 分からなくなる状態を再生産しない。
  ( cd "$repo" && GOOS=linux GOARCH=amd64 go build -o "$build_dir/$name" . ) \
    || { rm -rf "$build_dir"; fail "$name: build 失敗"; }
  file "$build_dir/$name" | grep -q "x86-64" \
    || { rm -rf "$build_dir"; fail "$name: x86_64バイナリでない（クロスビルド失敗）"; }

  echo "== $name: upload → $HOST:$dst =="
  scp "$build_dir/$name" "$HOST:$dst/$name.new" || { rm -rf "$build_dir"; fail "$name: scp 失敗"; }
  rm -rf "$build_dir"

  echo "== $name: verify arch on remote =="
  ssh "$HOST" "file $dst/$name.new" | grep -q "x86-64" || fail "$name: リモートの $name.new がx86_64でない"

  echo "== $name: swap + restart (systemd) =="
  ssh "$HOST" "
    set -e
    cd $dst
    chmod +x $name.new
    mv $name $name.bak-\$(date +%Y%m%d-%H%M%S)
    mv $name.new $name
    systemctl restart $name.service
    sleep 1
    systemctl is-active --quiet $name.service
  " || fail "$name: restart失敗（手動ロールバック: ssh $HOST 'cd $dst && mv \$(ls -t $name.bak* | head -1) $name && systemctl restart $name.service'）"

  # ヘルスチェックは公開URL越し。プロセスが上がっただけでなく Caddy 経由で
  # 実際に応答することまで見る。VAPID公開鍵はJMAPの中で唯一無認証で叩ける
  # エンドポイントで、しかも空でない本文を返すこと自体が「このrelayでWeb Push
  # が有効」の証明になる（設定漏れなら200のまま本文0バイトになる）。
  echo "== $name: verify (https://$public_host) =="
  local key
  key=$(curl -fsS "https://$public_host/jmap/push/vapid-public-key") \
    || fail "$name: ヘルスチェック失敗（https://$public_host が応答しない）"
  [ -n "$key" ] || fail "$name: VAPID公開鍵が空（Web Push未設定 — config.json の vapid_* を確認）"

  # 世代整理。古い方から消し、直近 $RELAY_BACKUPS 個だけ残す。命名規則が
  # 2種類（.bak.YYYYmmddHHMMSS / .bak-YYYYmmdd-HHMMSS）混在していたので
  # 両方拾う。
  ssh "$HOST" "cd $dst && ls -t $name.bak* 2>/dev/null | tail -n +$((RELAY_BACKUPS + 1)) | xargs -r rm -f" \
    || echo "  (警告: 旧バックアップの整理に失敗 — デプロイ自体は成功)"
  echo "✓ $name OK"
}

# ── smtp (jmapsmtp, Rust) ────────────────────────────────────────────────────
# 独自のビルド/配備パイプラインを持つ（s2でLinux/x86_64ビルド→v1へ設置、
# 世代バックアップ、systemd再起動、起動ログ確認まで一式）ので、ここでは
# それを呼ぶだけ。deploy_relay_unit（Go向け、ローカルクロスビルド）とは
# 別経路 — 二重管理を避けるため車輪の再発明はしない。
deploy_smtp() {
  [ -d "$JMAPSMTP_REPO" ] || fail "smtp: repo がない ($JMAPSMTP_REPO)"
  [ -x "$JMAPSMTP_REPO/scripts/deploy.sh" ] || fail "smtp: $JMAPSMTP_REPO/scripts/deploy.sh がない"
  echo "== smtp: jmapsmtp (Rust) 経由でデプロイ =="
  ( cd "$JMAPSMTP_REPO" && ./scripts/deploy.sh ) || fail "smtp: jmapsmtp/scripts/deploy.sh 失敗（作業ツリーが汚れていないか確認）"
  echo "✓ smtp OK"
}

deploy_ap() { deploy_relay_unit jmapap "$AP_REPO" ap.biset.md; }

case "$target" in
  app)     deploy_app ;;
  landing) deploy_landing ;;
  anchor)  deploy_anchor ;;
  didcomm-mediator) deploy_didcomm_mediator ;;
  mail-plugin) deploy_mail_plugin ;;
  smtp)    deploy_smtp ;;
  ap)      deploy_ap ;;
  relay)   deploy_smtp; deploy_ap ;;
  all)     deploy_app; deploy_landing; deploy_anchor; deploy_smtp; deploy_ap ;;
  *)       fail "unknown target: $target (app|landing|anchor|didcomm-mediator|mail-plugin|smtp|ap|relay|all)" ;;
esac

echo "== done: $target =="
