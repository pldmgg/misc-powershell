#!/usr/bin/env bash
set -euo pipefail

ZT_NET="1d7193940464cb98"
RDP_IP="10.147.17.179"
RDP_USER="saintchristophe\\shawnaminnucci"
RDP_NAME="parishsec1.rdp"

# Get the active console user + their Desktop (works even if script is run with sudo)
CONSOLE_USER="$(/usr/bin/stat -f "%Su" /dev/console)"
USER_HOME="$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory | awk '{print $2}')"
DESKTOP="${USER_HOME}/Desktop"

echo "Console user: ${CONSOLE_USER}"
echo "Desktop: ${DESKTOP}"

# ---- Install Homebrew (if missing) ----
if ! command -v brew >/dev/null 2>&1; then
  echo "Installing Homebrew..."
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Ensure brew is on PATH for this script (Apple Silicon + Intel)
if [[ -x /opt/homebrew/bin/brew ]]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
elif [[ -x /usr/local/bin/brew ]]; then
  eval "$(/usr/local/bin/brew shellenv)"
fi

echo "Using brew: $(command -v brew)"

# ---- Install + start ZeroTier ----
echo "Installing ZeroTier..."
brew update >/dev/null
brew list zerotier-one >/dev/null 2>&1 || brew install zerotier-one

echo "Starting ZeroTier service..."
brew services start zerotier-one >/dev/null || true

# Give the daemon a moment to come up
sleep 2

echo "Joining ZeroTier network: ${ZT_NET}"
sudo /usr/local/bin/true 2>/dev/null || true  # no-op to encourage sudo caching if needed
sudo zerotier-cli join "${ZT_NET}" || true

echo "NOTE: Your controller may still need to authorize this device in ZeroTier Central."

# ---- Install Microsoft Remote Desktop ----
echo "Installing Microsoft Remote Desktop..."
brew list --cask microsoft-remote-desktop >/dev/null 2>&1 || brew install --cask microsoft-remote-desktop

# ---- Create .rdp file on Desktop ----
mkdir -p "${DESKTOP}"

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

# Make sure the console user owns the file (in case script ran as root)
chown "${CONSOLE_USER}":staff "${RDP_PATH}" 2>/dev/null || true

echo "Created RDP shortcut: ${RDP_PATH}"
echo "Done."
