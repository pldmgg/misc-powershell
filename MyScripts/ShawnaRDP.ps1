# =============================
# Install Chocolatey + ZeroTier, join network, create RDP on logged-in user's Desktop
# =============================

$ErrorActionPreference = "Stop"

# --- Helper: get interactive (logged-in) user's desktop path (works even if script runs elevated)
function Get-LoggedInUserDesktopPath {
    $cs = Get-CimInstance Win32_ComputerSystem
    $loggedOn = $cs.UserName  # e.g. DOMAIN\User
    if ([string]::IsNullOrWhiteSpace($loggedOn)) {
        # fallback
        return [Environment]::GetFolderPath("Desktop")
    }

    $user = ($loggedOn -split "\\")[-1]

    # Try to get profile path from registry ProfileList
    $profilePath = $null
    $profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue
    foreach ($p in $profiles) {
        if ($p.ProfileImagePath -and ($p.ProfileImagePath -match "\\$([regex]::Escape($user))$")) {
            $profilePath = $p.ProfileImagePath
            break
        }
    }

    if (-not $profilePath) {
        $profilePath = "C:\Users\$user"
    }

    return Join-Path $profilePath "Desktop"
}

# -----------------------------
# Install Chocolatey
# -----------------------------
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Ensure choco is on path for this session
$env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"

# -----------------------------
# Install ZeroTier
# -----------------------------
if (-not (Get-Command zerotier-cli -ErrorAction SilentlyContinue)) {
    Write-Host "Installing ZeroTier..."
    choco install zerotier-one -y
}

Start-Sleep -Seconds 10

# -----------------------------
# Join ZeroTier Network
# -----------------------------
$NetworkId = "1d7193940464cb98"
$ZtCliBat  = "C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat"

if (-not (Test-Path $ZtCliBat)) {
    throw "ZeroTier CLI not found at: $ZtCliBat"
}

Write-Host "Joining ZeroTier network $NetworkId..."
& $ZtCliBat join $NetworkId | Out-Null

Write-Host "ZeroTier status:"
& $ZtCliBat status

Write-Host "ZeroTier networks:"
& $ZtCliBat listnetworks

# -----------------------------
# Create .RDP file on logged-in user's Desktop (format similar to your attached)
# -----------------------------
$DesktopPath = Get-LoggedInUserDesktopPath
if (-not (Test-Path $DesktopPath)) {
    New-Item -ItemType Directory -Path $DesktopPath -Force | Out-Null
}

$RdpFileName = "parishsec1.rdp"
$RdpPath = Join-Path $DesktopPath $RdpFileName

$RdpTarget = "10.147.17.179"
$RdpUser   = "saintchristophe\shawnaminnucci"

# Template based on your attached .rdp file style
$RdpContent = @"
screen mode id:i:2
session bpp:i:16
compression:i:1
keyboardhook:i:2
displayconnectionbar:i:1
disable wallpaper:i:1
disable full window drag:i:1
allow desktop composition:i:0
allow font smoothing:i:0
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:$RdpTarget
audiomode:i:0
redirectprinters:i:0
redirectcomports:i:0
redirectsmartcards:i:0
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:0
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:1
drivestoredirect:s:0
desktopwidth:i:1440
desktopheight:i:900
winposstr:s:0,3,0,0,800,600
redirectdrives:i:0
devicestoredirect:s:*
username:s:$RdpUser
domain:s:
drivestoredirect:s:*
"@

# Write as ASCII (typical for .rdp)
Set-Content -Path $RdpPath -Value $RdpContent -Encoding ASCII -Force

Write-Host "Created RDP file: $RdpPath"
