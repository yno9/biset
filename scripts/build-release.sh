#!/bin/bash
# Build biset + all connectors for release.
# Output goes to ./dist/
# Usage: ./build-release.sh

set -e

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_DIR="$(dirname "$SCRIPTS_DIR")"  # biset-dev root
DIST="$SCRIPT_DIR/dist"
mkdir -p "$DIST"

# biset本体はdaemon/trayがsystrayに依存するためdarwinのみ
BISET_TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
)

# コネクタはCGO不要なのでlinuxも対象
CONNECTOR_TARGETS=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/amd64"
  "linux/arm64"
)

CONNECTORS=(imap claude jmap)

echo "=== Building biset ==="
for target in "${BISET_TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  echo "  biset-$os-$arch"
  CGO_ENABLED=1 GOOS=$os GOARCH=$arch go build -C "$SCRIPT_DIR" -o "$DIST/biset-$os-$arch" .
done

echo "=== Building connectors ==="
for name in "${CONNECTORS[@]}"; do
  dir="$SCRIPT_DIR/connectors/$name"
  if [ ! -f "$dir/main.go" ]; then
    echo "  skip $name (no main.go)"
    continue
  fi
  for target in "${CONNECTOR_TARGETS[@]}"; do
    os="${target%/*}"
    arch="${target#*/}"
    echo "  biset-$name-$os-$arch"
    GOOS=$os GOARCH=$arch go build -C "$dir" -o "$DIST/biset-$name-$os-$arch" .
  done
  # manifest + config
  cp "$dir/manifest.json"       "$DIST/biset-$name-manifest.json"
  cp "$dir/config.example.json" "$DIST/biset-$name-config.example.json"
done

# install.sh → dist/ と docs/
cp "$SCRIPTS_DIR/install.sh" "$DIST/install.sh"
cp "$SCRIPTS_DIR/install.sh" "$HOME/biset/docs/install.sh"

echo ""
echo "Done. Files in $DIST:"
ls -lh "$DIST"
