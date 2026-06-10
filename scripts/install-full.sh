#!/bin/bash
# Download biset + all connectors from GitHub Releases.
# Usage: curl -fsSL https://github.com/yno9/biset/releases/latest/download/install-full.sh | sh

set -e

REPO="yno9/biset"
BASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="${BISET_DIR:-$HOME/.biset}"
CONNECTORS=(imap claude)

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)       ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH"; exit 1 ;;
esac
case "$OS" in
  darwin|linux) ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo "=== Installing biset + connectors ($OS/$ARCH) to $INSTALL_DIR ==="
mkdir -p "$INSTALL_DIR/assets"
mkdir -p "$INSTALL_DIR/connectors"

echo "Downloading biset..."
curl -fsSL "$BASE_URL/biset-$OS-$ARCH" -o "$INSTALL_DIR/biset"
chmod +x "$INSTALL_DIR/biset"

echo "Downloading assets..."
curl -fsSL "$BASE_URL/setup.html" -o "$INSTALL_DIR/assets/setup.html"
curl -fsSL "$BASE_URL/setup.js"   -o "$INSTALL_DIR/assets/setup.js"

for name in "${CONNECTORS[@]}"; do
  dir="$INSTALL_DIR/connectors/biset-$name"
  mkdir -p "$dir"
  echo "Downloading biset-$name..."
  curl -fsSL "$BASE_URL/biset-$name-$OS-$ARCH"            -o "$dir/biset-$name"
  curl -fsSL "$BASE_URL/biset-$name-manifest.json"         -o "$dir/manifest.json"
  if [ ! -f "$dir/config.json" ]; then
    curl -fsSL "$BASE_URL/biset-$name-config.example.json" -o "$dir/config.json" 2>/dev/null || true
  fi
  chmod +x "$dir/biset-$name"
done

echo ""
echo "Done. Run: $INSTALL_DIR/biset"
