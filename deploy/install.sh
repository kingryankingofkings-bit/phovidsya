#!/usr/bin/env bash
# Aegis Shield installer (Linux, requires root)
# Usage: sudo bash deploy/install.sh
set -euo pipefail

INSTALL_USER="aegis"
NAMESPACE_DIR="/var/lib/aegis-shield/namespace"
NAMESPACE_BLOCKS="${AEGIS_NAMESPACE_BLOCKS:-65536}"  # 256 MB at 4096 B/block
KEY_DIR="/etc/aegis-shield"
SERVICE_FILE="deploy/systemd/aegis-shield.service"
SYSTEMD_DIR="/etc/systemd/system"

# ── Colours ──────────────────────────────────────────────────────────────────
green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
info()  { printf '  → %s\n' "$*"; }

# ── Pre-checks ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  red "This script must be run as root (sudo bash deploy/install.sh)."
  exit 1
fi

command -v python3 &>/dev/null || { red "python3 not found"; exit 1; }
python3 -c "import sys; assert sys.version_info >= (3,11)" 2>/dev/null \
  || { red "Python 3.11+ required"; exit 1; }
command -v pip3 &>/dev/null || { red "pip3 not found"; exit 1; }

green "=== Aegis Shield installer ==="

# ── Create service account ────────────────────────────────────────────────────
if ! id "$INSTALL_USER" &>/dev/null; then
  info "Creating system user: $INSTALL_USER"
  useradd -r -s /bin/false -d /var/lib/aegis-shield "$INSTALL_USER"
fi

# ── Create directories ────────────────────────────────────────────────────────
info "Creating directories"
mkdir -p "/var/lib/aegis-shield" "$KEY_DIR" "/run/aegis-shield"
chown -R "$INSTALL_USER:" "/var/lib/aegis-shield" "$KEY_DIR" "/run/aegis-shield"
chmod 750 "$KEY_DIR"

# ── Install Python package ────────────────────────────────────────────────────
info "Installing aegis-shield Python package"
pip3 install --quiet -e "$(pwd)"

# ── Generate admin keypair if not present ─────────────────────────────────────
if [[ ! -f "$KEY_DIR/admin.pem" ]]; then
  info "Generating Ed25519 admin keypair → $KEY_DIR/admin.{pem,pub}"
  aegis-shield keygen "$KEY_DIR/admin.pem" "$KEY_DIR/admin.pub"
  chmod 600 "$KEY_DIR/admin.pem"
  chmod 644 "$KEY_DIR/admin.pub"
  chown "$INSTALL_USER:" "$KEY_DIR/admin.pem" "$KEY_DIR/admin.pub"
  echo ""
  red "  ⚠  Store admin.pem offline and remove it from this machine"
  red "     before the device enters production."
  echo ""
fi

# ── Provision namespace if not present ───────────────────────────────────────
if [[ ! -d "$NAMESPACE_DIR" ]]; then
  info "Provisioning namespace at $NAMESPACE_DIR ($NAMESPACE_BLOCKS blocks)"
  sudo -u "$INSTALL_USER" aegis-shield provision "$NAMESPACE_DIR" \
    --blocks "$NAMESPACE_BLOCKS"
fi

# ── Install systemd service ───────────────────────────────────────────────────
if [[ -f "$SERVICE_FILE" ]]; then
  info "Installing systemd unit → $SYSTEMD_DIR/aegis-shield.service"
  cp "$SERVICE_FILE" "$SYSTEMD_DIR/aegis-shield.service"
  systemctl daemon-reload
  systemctl enable aegis-shield.service
  green "Service installed. Start with: systemctl start aegis-shield"
else
  red "Service file not found at $SERVICE_FILE — skipping systemd install"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
green ""
green "=== Installation complete ==="
echo "  Namespace : $NAMESPACE_DIR"
echo "  Keys      : $KEY_DIR"
echo "  API port  : 8443 (set AEGIS_API_KEY environment variable)"
echo ""
echo "  Next steps:"
echo "    1. Set AEGIS_API_KEY in /etc/systemd/system/aegis-shield.service.d/env.conf"
echo "    2. systemctl start aegis-shield"
echo "    3. Open http://localhost:8443 for the web dashboard"
