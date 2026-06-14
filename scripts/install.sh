#!/bin/bash
# Download biset + all connectors from GitHub Releases, then run setup wizard.
# Usage: curl -fsSL https://github.com/yno9/biset/releases/latest/download/install.sh | sh
# Uninstall: sh install.sh uninstall

set -e

REPO="yno9/biset"
BASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="${BISET_DIR:-$HOME/.biset}"
ALL_CONNECTORS=(imap claude)
OPTIONAL_CONNECTORS=(claude)

# ── Action selection ───────────────────────────────────────────────────────────

TAG=$(curl -fsI "https://github.com/$REPO/releases/latest" 2>/dev/null \
  | grep -i '^location:' | sed 's|.*/tag/||' | tr -d '\r\n')
[ -n "$TAG" ] && echo "biset $TAG is available."
echo ""
echo " 1. Install or update biset"
echo " 2. Uninstall biset"
echo ""
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

echo "Downloading biset${TAG:+ $TAG}..."
rm -f "$INSTALL_DIR/biset"
curl -fsSL "$BASE_URL/biset-$OS-$ARCH" -o "$INSTALL_DIR/biset"
chmod +x "$INSTALL_DIR/biset"

install_connector() {
  local name=$1
  local dir="$INSTALL_DIR/connectors/biset-$name"
  mkdir -p "$dir"
  echo "Downloading biset-$name..."
  rm -f "$dir/biset-$name"
  curl -fsSL "$BASE_URL/biset-$name-$OS-$ARCH"           -o "$dir/biset-$name"
  curl -fsSL "$BASE_URL/biset-$name-manifest.json"        -o "$dir/manifest.json"
  curl -fsSL "$BASE_URL/biset-$name-config.example.json"  -o "$dir/config.example.json" 2>/dev/null || true
  chmod +x "$dir/biset-$name"
}

for name in "${ALL_CONNECTORS[@]}"; do
  install_connector "$name"
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

CONFIG_JSON="$INSTALL_DIR/config.json"
IMAP_CFG="$INSTALL_DIR/connectors/biset-imap/config.json"

if [ -f "$CONFIG_JSON" ]; then
  echo ""
  echo "✓ Updated. Run: biset connectors  to enable/disable connectors."
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

# Auto-detect IMAP/SMTP host via MX
imap_host=""
smtp_host=""
if command -v dig &>/dev/null; then
  mx=$(dig +short MX "$domain" 2>/dev/null | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
  [ -n "$mx" ] && imap_host="$mx" && smtp_host="$mx"
fi
imap_host="${imap_host:-imap.$domain}"
smtp_host="${smtp_host:-smtp.$domain}"
imap_port=993
imap_tls="tls"
smtp_port=587
smtp_tls="starttls"

# Test IMAP connection (TLS or STARTTLS)
test_imap() {
  local host=$1 port=$2 tls=$3 user=$4 pass=$5
  if ! command -v openssl &>/dev/null; then return 1; fi
  if [ "$tls" = "tls" ]; then
    printf 'a001 LOGIN "%s" "%s"\r\na002 LOGOUT\r\n' "$user" "$pass" | \
      openssl s_client -connect "$host:$port" -quiet 2>/dev/null | grep -q "a001 OK"
  else
    printf 'a001 LOGIN "%s" "%s"\r\na002 LOGOUT\r\n' "$user" "$pass" | \
      openssl s_client -connect "$host:$port" -starttls imap -quiet 2>/dev/null | grep -q "a001 OK"
  fi
}

echo ""
echo "Connecting to $imap_host..."
if test_imap "$imap_host" "$imap_port" "$imap_tls" "$email" "$password"; then
  echo "✓ Connected"
  IMAP_OK=1
else
  echo "✗ Failed. Configure manually:"
  echo ""
  read -rp "IMAP host [$imap_host]: " input </dev/tty
  imap_host="${input:-$imap_host}"
  read -rp "IMAP port [$imap_port]: " input </dev/tty
  imap_port="${input:-$imap_port}"
  read -rp "IMAP TLS mode (tls/starttls) [$imap_tls]: " input </dev/tty
  imap_tls="${input:-$imap_tls}"
  read -rp "SMTP host [$smtp_host]: " input </dev/tty
  smtp_host="${input:-$smtp_host}"
  read -rp "SMTP port [$smtp_port]: " input </dev/tty
  smtp_port="${input:-$smtp_port}"
  read -rp "SMTP TLS mode (tls/starttls) [$smtp_tls]: " input </dev/tty
  smtp_tls="${input:-$smtp_tls}"
  read -rsp "Password: " password </dev/tty
  echo ""
  echo ""
  echo "Retrying..."
  if test_imap "$imap_host" "$imap_port" "$imap_tls" "$email" "$password"; then
    echo "✓ Connected"
    IMAP_OK=1
  else
    IMAP_OK=0
    echo "✗ Still failed."
  fi
fi

if [ "${IMAP_OK:-0}" != "1" ]; then
  echo ""
  read -rp "Authentication failed. Continue anyway? [y/N]: " yn </dev/tty
  case "$yn" in [yY]*) ;; *) echo "Aborted."; exit 1 ;; esac
fi

# ── Connector opt-in/out ───────────────────────────────────────────────────────

echo ""
echo "Connectors:"
ENABLED_CONNECTORS=(imap)
for name in "${OPTIONAL_CONNECTORS[@]}"; do
  echo ""
  echo "  biset-$name:"
  echo "    1) on"
  echo "    2) off"
  read -rp "  Choice [1]: " yn </dev/tty
  yn="${yn:-1}"
  if [ "$yn" = "1" ]; then
    ENABLED_CONNECTORS+=("$name")
  fi
done

# ── Write config.json ───────────────────────────────────────────────────────────

connectors_json=""
for name in "${ENABLED_CONNECTORS[@]}"; do
  [ -n "$connectors_json" ] && connectors_json="$connectors_json, "
  connectors_json="$connectors_json\"biset-$name\""
done

cat > "$CONFIG_JSON" << EOF
{
  "vault": "$vault",
  "connectors_dir": "connectors",
  "connectors": [$connectors_json]
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
        "port": $imap_port,
        "tls_mode": "$imap_tls",
        "username": "$email",
        "password": "$password"
      },
      "smtp": {
        "host": "$smtp_host",
        "port": $smtp_port,
        "tls_mode": "$smtp_tls",
        "username": "$email",
        "password": "$password"
      }
    }
  ]
}
EOF
chmod 600 "$IMAP_CFG"

echo ""
if [ "${IMAP_OK:-0}" = "1" ]; then
  if [ "${ADDED_TO_PATH:-0}" = "1" ]; then
    echo "✓ Done. Restart your terminal, then run: biset"
  else
    echo "✓ Done. Run: biset"
  fi
else
  echo "✗ Could not connect. Edit config and retry:"
  echo "  $IMAP_CFG"
  echo "  Then run: biset"
fi
