#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs signal-cli on a fresh Windows 11 machine.
.DESCRIPTION
    - Installs Eclipse Temurin JRE 21 via winget (ships with Windows 11)
    - Installs Python 3 and the qrcode pip package (for QR code generation)
    - Downloads the latest signal-cli release from GitHub
    - Extracts it to ~/.local/lib/signal-cli
    - Creates a signal-cli.cmd wrapper in ~/.local/bin
    - Adds ~/.local/bin to the user PATH if not already present
    - Requires an elevated (Administrator) PowerShell session
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LocalBase  = Join-Path $env:USERPROFILE '.local'
$BinDir     = Join-Path $LocalBase 'bin'
$LibDir     = Join-Path $LocalBase 'lib'
$InstallDir = Join-Path $LibDir 'signal-cli'

# ── 1. Install Java 21 JRE via winget ──────────────────────────────────────────

Write-Host "`n[1/6] Installing Eclipse Temurin JRE 21..." -ForegroundColor Cyan

$javaCheck = Get-Command java -ErrorAction SilentlyContinue
if ($javaCheck) {
    $ver = & java -version 2>&1 | Select-Object -First 1
    if ($ver -match '"21\.') {
        Write-Host "  Java 21 already installed, skipping." -ForegroundColor Green
    } else {
        Write-Host "  Existing Java found ($ver) but not 21. Installing Temurin 21..."
        winget install EclipseAdoptium.Temurin.21.JRE --accept-source-agreements --accept-package-agreements --silent
    }
} else {
    winget install EclipseAdoptium.Temurin.21.JRE --accept-source-agreements --accept-package-agreements --silent
}

# Refresh PATH for current session so java is available immediately
$machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$userPath    = [Environment]::GetEnvironmentVariable('PATH', 'User')
$env:PATH    = "$machinePath;$userPath"

# Verify java works
$javaCheck = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaCheck) {
    Write-Error "Java installation failed. 'java' not found on PATH after install."
}
Write-Host "  $(& java -version 2>&1 | Select-Object -First 1)" -ForegroundColor Green

# ── 2. Install Python 3 and qrcode package ─────────────────────────────────────

Write-Host "`n[2/6] Installing Python 3 and qrcode package..." -ForegroundColor Cyan

# Remove Windows Store python stubs that shadow real Python installs
$stubDir = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps'
foreach ($stub in @('python.exe', 'python3.exe')) {
    $stubPath = Join-Path $stubDir $stub
    if (Test-Path $stubPath) {
        Remove-Item $stubPath -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed Windows Store stub: $stub"
    }
}

$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if ($pythonCheck -and (& python --version 2>&1) -match 'Python 3') {
    Write-Host "  Python 3 already installed, skipping." -ForegroundColor Green
} else {
    winget install Python.Python.3.13 --accept-source-agreements --accept-package-agreements --silent
    # Refresh PATH
    $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $env:PATH    = "$machinePath;$userPath"
}

$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCheck) {
    Write-Error "Python installation failed. 'python' not found on PATH after install."
}
Write-Host "  $(& python --version 2>&1)" -ForegroundColor Green

Write-Host "  Installing qrcode pip package..."
& python -m pip install --quiet qrcode
Write-Host "  qrcode package installed." -ForegroundColor Green

# ── 3. Determine latest signal-cli version ─────────────────────────────────────

Write-Host "`n[3/6] Fetching latest signal-cli release info..." -ForegroundColor Cyan

$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/AsamK/signal-cli/releases/latest'
$version = $release.tag_name -replace '^v', ''
$downloadUrl = $release.assets |
    Where-Object { $_.name -eq "signal-cli-${version}.tar.gz" } |
    Select-Object -ExpandProperty browser_download_url

Write-Host "  Latest version: $version" -ForegroundColor Green
Write-Host "  Download URL:   $downloadUrl"

# ── 4. Download and extract ────────────────────────────────────────────────────

Write-Host "`n[4/6] Downloading and extracting signal-cli $version..." -ForegroundColor Cyan

$tempTar = Join-Path $env:TEMP "signal-cli-${version}.tar.gz"
$tempExtract = Join-Path $env:TEMP "signal-cli-extract"

# Download
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempTar -UseBasicParsing
Write-Host "  Downloaded to $tempTar"

# Clean previous extraction if any
if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }
New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null

# Extract using tar (built into Windows 10+)
tar -xzf $tempTar -C $tempExtract
Write-Host "  Extracted."

# ── 5. Install to ~/.local/lib/signal-cli ──────────────────────────────────────

Write-Host "`n[5/6] Installing to $InstallDir..." -ForegroundColor Cyan

# Remove old install if present
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "  Removed previous installation."
}

New-Item -ItemType Directory -Path $LibDir -Force | Out-Null
Move-Item -Path (Join-Path $tempExtract "signal-cli-${version}") -Destination $InstallDir
Write-Host "  Installed signal-cli to $InstallDir"

# Create wrapper in ~/.local/bin
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

$wrapperPath = Join-Path $BinDir 'signal-cli.cmd'
Set-Content -Path $wrapperPath -Value @'
@echo off
"%~dp0..\lib\signal-cli\bin\signal-cli.bat" %*
'@
Write-Host "  Created wrapper at $wrapperPath"

# Create QR helper Python script
$qrPyPath = Join-Path $LibDir 'signal-cli-qr.py'
Set-Content -Path $qrPyPath -Value @'
import subprocess
import sys
import io
import qrcode

device_name = sys.argv[1] if len(sys.argv) > 1 else "signal-cli"

proc = subprocess.Popen(
    ["signal-cli", "link", "-n", device_name],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

# signal-cli prints the sgnl:// URI as the first line of stdout, then blocks
uri = proc.stdout.readline().strip()

if not uri:
    # Some versions write to stderr instead
    uri = proc.stderr.readline().strip()

if not uri.startswith("sgnl://"):
    print(f"Unexpected output from signal-cli link: {uri}", file=sys.stderr)
    proc.terminate()
    sys.exit(1)

# Force UTF-8 for the block characters
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

print()
print("Scan this QR code with Signal on your phone:")
print("  Settings > Linked Devices > Link New Device")
print()

q = qrcode.QRCode()
q.add_data(uri)
q.make()
q.print_ascii()

print()
print("Waiting for you to scan...")

# Wait for signal-cli to finish (completes once the phone confirms the link)
proc.wait()

if proc.returncode == 0:
    print("Linked successfully!")
else:
    err = proc.stderr.read()
    print(f"Linking failed (exit code {proc.returncode}): {err}", file=sys.stderr)
    sys.exit(proc.returncode)
'@
Write-Host "  Created QR helper at $qrPyPath"

# Create wrapper cmd for the QR helper
$qrCmdPath = Join-Path $BinDir 'signal-cli-qr.cmd'
Set-Content -Path $qrCmdPath -Value @"
@echo off
python "%~dp0..\lib\signal-cli-qr.py" %*
"@
Write-Host "  Created wrapper at $qrCmdPath"

# Clean up temp files
Remove-Item $tempTar -Force -ErrorAction SilentlyContinue
Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue

# ── 6. Ensure ~/.local/bin is on user PATH ─────────────────────────────────────

Write-Host "`n[6/6] Checking user PATH..." -ForegroundColor Cyan

$currentUserPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($currentUserPath -split ';' -notcontains $BinDir) {
    $newPath = if ($currentUserPath) { "$currentUserPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
    $env:PATH = "$env:PATH;$BinDir"
    Write-Host "  Added $BinDir to user PATH." -ForegroundColor Green
} else {
    Write-Host "  $BinDir is already on user PATH." -ForegroundColor Green
}

# ── Done ───────────────────────────────────────────────────────────────────────

Write-Host "`n── Verification ──" -ForegroundColor Cyan
$result = & (Join-Path $BinDir 'signal-cli.cmd') --version 2>&1
Write-Host "  $result" -ForegroundColor Green

Write-Host "`nInstallation complete! Open a new terminal, then:" -ForegroundColor Green
Write-Host "  signal-cli --version        # verify install" -ForegroundColor White
Write-Host "  signal-cli-qr MyDevice      # link to your Signal account via QR code" -ForegroundColor White
