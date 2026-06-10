#!/bin/bash
# Download biset + all connectors from GitHub Releases, then run setup wizard.
# Usage: curl -fsSL https://github.com/yno9/biset/releases/latest/download/install.sh | sh
# Uninstall: sh install.sh uninstall

set -e

REPO="yno9/biset"
BASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="${BISET_DIR:-$HOME/.biset}"
CONNECTORS=(imap claude)

# ── Action selection ───────────────────────────────────────────────────────────

echo "What would you like to do?"
echo "  1) Install biset"
echo "  2) Uninstall biset (if installed)"
read -rp "Choice [1]: " choice </dev/tty
choice="${choice:-1}"

if [ "$choice" = "2" ]; then
  echo "=== Uninstalling biset ==="
  rm -f /usr/local/bin/biset 2>/dev/null || sudo rm -f /usr/local/bin/biset
  rm -rf "$INSTALL_DIR"
  echo "✓ Removed $INSTALL_DIR and /usr/local/bin/biset"
  echo "  (vault was not removed)"
  exit 0
fi

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

echo "=== Installing biset ($OS/$ARCH) to $INSTALL_DIR ==="
mkdir -p "$INSTALL_DIR/connectors"

echo "Downloading biset..."
curl -fsSL "$BASE_URL/biset-$OS-$ARCH" -o "$INSTALL_DIR/biset"
chmod +x "$INSTALL_DIR/biset"

for name in "${CONNECTORS[@]}"; do
  dir="$INSTALL_DIR/connectors/biset-$name"
  mkdir -p "$dir"
  echo "Downloading biset-$name..."
  curl -fsSL "$BASE_URL/biset-$name-$OS-$ARCH"            -o "$dir/biset-$name"
  curl -fsSL "$BASE_URL/biset-$name-manifest.json"         -o "$dir/manifest.json"
  curl -fsSL "$BASE_URL/biset-$name-config.example.json"   -o "$dir/config.example.json" 2>/dev/null || true
  chmod +x "$dir/biset-$name"
done

# ── Add to PATH ────────────────────────────────────────────────────────────────

mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/biset" "$HOME/.local/bin/biset"

SHELL_RC="$HOME/.zshrc"
[ -n "$BASH_VERSION" ] && SHELL_RC="$HOME/.bashrc"

if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
  ADDED_TO_PATH=1
fi

# ── Setup wizard ───────────────────────────────────────────────────────────────

BISET_JSON="$INSTALL_DIR/biset.json"
IMAP_CFG="$INSTALL_DIR/connectors/biset-imap/config.json"

if [ -f "$BISET_JSON" ]; then
  echo ""
  echo "✓ Updated to latest version. Run: biset"
  exit 0
fi

echo ""
echo "=== Setup ==="
echo ""

read -rp "Vault directory [$HOME/inbox]: " vault </dev/tty
vault="${vault:-$HOME/inbox}"
mkdir -p "$vault"

echo ""
read -rp "Email address: " email </dev/tty
read -rsp "Password: " password </dev/tty
echo ""

domain="${email#*@}"
imap_host=""
smtp_host=""
if command -v dig &>/dev/null; then
  mx=$(dig +short MX "$domain" 2>/dev/null | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
  [ -n "$mx" ] && imap_host="$mx" && smtp_host="$mx"
fi

read -rp "IMAP host [${imap_host:-imap.$domain}]: " input </dev/tty
imap_host="${input:-${imap_host:-imap.$domain}}"

read -rp "SMTP host [${smtp_host:-smtp.$domain}]: " input </dev/tty
smtp_host="${input:-${smtp_host:-smtp.$domain}}"

# ── Write biset.json ───────────────────────────────────────────────────────────

cat > "$BISET_JSON" << EOF
{
  "vault": "$vault",
  "connectors_dir": "connectors",
  "connectors": ["biset-imap", "biset-claude"]
}
EOF

# ── Write connector config ─────────────────────────────────────────────────────

cat > "$IMAP_CFG" << EOF
{
  "accounts": [
    {
      "inbox_key": "$email",
      "imap": {
        "host": "$imap_host",
        "port": 993,
        "tls_mode": "tls",
        "username": "$email",
        "password": "$password"
      },
      "smtp": {
        "host": "$smtp_host",
        "port": 587,
        "tls_mode": "starttls",
        "username": "$email",
        "password": "$password"
      }
    }
  ]
}
EOF
chmod 600 "$IMAP_CFG"

echo ""
if [ "${ADDED_TO_PATH:-0}" = "1" ]; then
  echo "✓ Done. Restart your terminal, then run: biset"
else
  echo "✓ Done. Run: biset"
fi
