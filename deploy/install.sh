#!/usr/bin/env bash
# NetSentry one-shot installer for Raspberry Pi / Debian / Ubuntu.
#
# Usage (as the target user, NOT root — uses sudo only where needed):
#   curl -fsSL .../install.sh | bash
#   or: ./install.sh

set -euo pipefail

REPO_DIR="${REPO_DIR:-$HOME/netsentry-src}"
USER_NAME="$(id -un)"

echo "▶ NetSentry installer (user: $USER_NAME)"
echo

# 1. System packages
echo "▶ Installing system packages…"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-venv \
    python3-cryptography python3-yaml \
    sqlite3 qrencode speedtest-cli vnstat \
    openssh-client

# 2. Pi-hole group membership (so we can read FTL DB)
if getent group pihole >/dev/null; then
    echo "▶ Adding $USER_NAME to pihole group…"
    sudo usermod -aG pihole "$USER_NAME"
fi

# 3. Install NetSentry (if a repo is checked out at REPO_DIR)
if [ -d "$REPO_DIR" ]; then
    echo "▶ Installing NetSentry from $REPO_DIR…"
    sudo pip install --break-system-packages -e "$REPO_DIR"
else
    echo "⚠ No source at $REPO_DIR — install with: pip install netsentry"
fi

# 4. Initial setup
echo
echo "▶ Initialising vault + config…"
netsentry init || true

# 5. systemd unit
UNIT="/etc/systemd/system/netsentry.service"
if [ ! -f "$UNIT" ]; then
    SRC="$REPO_DIR/deploy/netsentry.service"
    if [ -f "$SRC" ]; then
        echo "▶ Installing systemd unit at $UNIT…"
        sudo sed "s/__USER__/$USER_NAME/g" "$SRC" | sudo tee "$UNIT" >/dev/null
        sudo systemctl daemon-reload
    fi
fi

echo
echo "✅ Install complete."
echo
echo "Next:"
echo "  netsentry secret set TELEGRAM_TOKEN ..."
echo "  netsentry secret set TELEGRAM_CHAT_ID ..."
echo "  netsentry secret set ROUTER_HOST ..."
echo "  netsentry secret set ROUTER_USER ..."
echo "  netsentry secret set SSH_KEY  ~/.ssh/netsentry-router-key"
echo "  netsentry secret set ALLOWED_CHAT_ID ..."
echo
echo "  edit ~/.config/netsentry/config.yaml"
echo "  sudo systemctl enable --now netsentry"
echo "  sudo journalctl -u netsentry -f"
