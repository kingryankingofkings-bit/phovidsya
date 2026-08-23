#!/usr/bin/env bash
# Aegis Shield installer (Linux, requires root)
# Usage: sudo bash deploy/install.sh
#
# This installer deliberately does NOT generate the recovery signing key.
# The private key must never exist on the machine it protects: an attacker who
# compromises this host would otherwise be able to sign their own recovery and
# maintenance tokens and release containment. Generate it on a separate,
# offline machine and copy only the PUBLIC half here.
set -euo pipefail

INSTALL_USER="aegis"
NAMESPACE_DIR="/var/lib/aegis-shield/namespace"
NAMESPACE_BLOCKS="${AEGIS_NAMESPACE_BLOCKS:-65536}"  # 256 MB at 4096 B/block
KEY_DIR="/etc/aegis-shield"
PUBLIC_KEY="$KEY_DIR/admin.pub"
ENV_FILE="$KEY_DIR/env"
SERVICE_FILE="deploy/systemd/aegis-shield.service"
SYSTEMD_DIR="/etc/systemd/system"

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

# ── Create service account ───────────────────────────────────────────────────
if ! id "$INSTALL_USER" &>/dev/null; then
  info "Creating system user: $INSTALL_USER"
  useradd -r -s /bin/false -d /var/lib/aegis-shield "$INSTALL_USER"
fi

# ── Create directories ───────────────────────────────────────────────────────
info "Creating directories"
mkdir -p "/var/lib/aegis-shield" "$KEY_DIR" "/run/aegis-shield"
chown -R "$INSTALL_USER:" "/var/lib/aegis-shield" "/run/aegis-shield"
# Key material stays root-owned; the daemon only needs to read the public key.
chown root:"$INSTALL_USER" "$KEY_DIR"
chmod 750 "$KEY_DIR"

# ── Install Python package ───────────────────────────────────────────────────
info "Installing aegis-shield Python package"
pip3 install --quiet "$(pwd)"

# ── Refuse to run alongside a private key ────────────────────────────────────
shopt -s nullglob
private_keys=("$KEY_DIR"/*.pem)
shopt -u nullglob
if (( ${#private_keys[@]} )); then
  red "  ⚠  Private key material found in $KEY_DIR:"
  for k in "${private_keys[@]}"; do red "       $k"; done
  red ""
  red "     The recovery signing key must not live on the host it protects."
  red "     Move it to offline storage and re-run this installer."
  exit 1
fi

# ── Require an externally generated public key ───────────────────────────────
if [[ ! -f "$PUBLIC_KEY" ]]; then
  red "  ⚠  No admin public key at $PUBLIC_KEY"
  red ""
  red "     Generate the keypair on a SEPARATE, OFFLINE machine:"
  red "         aegis-shield keygen admin.pem admin.pub"
  red ""
  red "     Then copy ONLY the public half to this host:"
  red "         scp admin.pub root@<this-host>:$PUBLIC_KEY"
  red ""
  red "     Keep admin.pem offline. It is the only thing that can authorize"
  red "     recovery, and anything that can read it can release containment."
  exit 1
fi
chown root:"$INSTALL_USER" "$PUBLIC_KEY"
chmod 640 "$PUBLIC_KEY"
info "Using admin public key: $PUBLIC_KEY"

# ── Generate a stable API key ────────────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
  info "Generating API key → $ENV_FILE"
  umask 077
  printf 'AEGIS_API_KEY=%s\n' \
    "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > "$ENV_FILE"
  chown root:"$INSTALL_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
  green "  API key written to $ENV_FILE (readable by root and $INSTALL_USER only)."
  green "  Read it with: sudo grep AEGIS_API_KEY $ENV_FILE"
else
  info "Keeping existing API key at $ENV_FILE"
fi

# ── Provision namespace if not present ───────────────────────────────────────
if [[ ! -d "$NAMESPACE_DIR" ]]; then
  info "Provisioning namespace at $NAMESPACE_DIR ($NAMESPACE_BLOCKS blocks)"
  sudo -u "$INSTALL_USER" aegis-shield provision "$NAMESPACE_DIR" \
    --blocks "$NAMESPACE_BLOCKS"
fi

# ── Install systemd service ──────────────────────────────────────────────────
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
echo "  Namespace  : $NAMESPACE_DIR"
echo "  Public key : $PUBLIC_KEY"
echo "  API key    : $ENV_FILE"
echo "  API        : http://127.0.0.1:8443 (dashboard at /ui)"
echo ""
echo "  Next steps:"
echo "    1. systemctl start aegis-shield"
echo "    2. Open http://127.0.0.1:8443/ui and paste the API key"
echo ""
echo "  Reminder: keep admin.pem offline. Recovery is impossible without it,"
echo "  and containment is bypassable by anything that can read it."
