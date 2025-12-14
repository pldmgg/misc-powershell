#!/usr/bin/env bash
set -euo pipefail

ZT_NET="1d7193940464cb98"
RDP_IP="10.147.17.179"
RDP_USER="saintchristophe\\shawnaminnucci"
RDP_NAME="parishsec1.rdp"

echo "Starting setup..."

# -----------------------------
# Get console user + Desktop
# -----------------------------
CONSOLE_USER="$(/usr/bin/stat -f "%Su" /dev/console)"
USER_HOME="$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory | /usr/bin/awk '{print $2}')"
DESKTOP="${USER_HOME}/Desktop"

# -----------------------------
# Sudo helpers
# -----------------------------
require_sudo() {
  if ! /usr/bin/sudo -n true 2>/dev/null; then
    echo "Admin password required for system-level steps (ZeroTier join)."
    /usr/bin/sudo -v
  fi
}

keep_sudo_alive() {
  ( while true; do /usr/bin/sudo -n true; /bin/sleep 60; done ) 2>/dev/null &
  SUDO_KEEPALIVE_PID=$!
  trap 'kill $SUDO_KEEPALIVE_PID 2>/dev/null || true' EXIT
}

# -----------------------------
# Homebrew
# -----------------------------
if ! command -v brew >/dev/null 2>&1; then
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

if [[ -x /opt/homebrew/bin/brew ]]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
elif [[ -x /usr/local/bin/brew ]]; then
  eval "$(/usr/local/bin/brew shellenv)"
fi

# -----------------------------
# ZeroTier
# -----------------------------
brew list zerotier-one >/dev/null 2>&1 || brew install zerotier-one
brew services start zerotier-one >/dev/null || true
sleep 2

require_sudo
keep_sudo_alive
/usr/bin/sudo zerotier-cli join "${ZT_NET}" || true

# -----------------------------
# Microsoft Remote Desktop
# -----------------------------
brew list --cask microsoft-remote-desktop >/dev/null 2>&1 || brew install --cask microsoft-remote-desktop

# -----------------------------
# .rdp association
# -----------------------------
brew list duti >/dev/null 2>&1 || brew install duti
duti -s com.microsoft.rdc.mac rdp all

# -----------------------------
# Create .rdp file
# -----------------------------
/bin/mkdir -p "${DESKTOP}"
RDP_PATH="${DESKTOP}/${RDP_NAME}"

cat > "${RDP_PATH}" <<EOF
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
full address:s:${RDP_IP}
username:s:${RDP_USER}
prompt for credentials:i:1
administrative session:i:0
audiomode:i:0
redirectclipboard:i:1
redirectprinters:i:0
redirectcomports:i:0
redirectsmartcards:i:0
redirectposdevices:i:0
redirectdrives:i:0
autoreconnection enabled:i:1
authentication level:i:2
EOF

/usr/sbin/chown "${CONSOLE_USER}":staff "${RDP_PATH}" 2>/dev/null || true
touch "${RDP_PATH}"

# -----------------------------
# NEW: Refresh Finder
# -----------------------------
/usr/bin/killall Finder || true

echo "Done. Finder refreshed and RDP shortcut ready."
