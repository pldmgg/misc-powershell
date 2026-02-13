#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs signal-cli on a fresh Windows 11 machine.
.DESCRIPTION
    1. Installs Eclipse Temurin JRE 21 via winget
    2. Installs Python 3 via winget (+ qrcode/pillow pip packages)
    3. Downloads the latest signal-cli release from GitHub
    4. Extracts to ~/.local/lib/signal-cli
    5. Creates signal-cli.cmd wrapper in ~/.local/bin
    6. Compiles signal-cli.exe native wrapper (for Node.js/programmatic use)
    7. Creates signal-cli-qr helper for QR-based account linking
    8. Registers a "Signal CLI Daemon" scheduled task for auto-start
    9. Adds ~/.local/bin to user PATH
    Requires an elevated (Administrator) PowerShell session.
#>

param(
    [string]$Account  # E.164 phone number, e.g. +15551234567 (for daemon task)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$LocalBase   = Join-Path $env:USERPROFILE '.local'
$BinDir      = Join-Path $LocalBase 'bin'
$LibDir      = Join-Path $LocalBase 'lib'
$InstallDir  = Join-Path $LibDir 'signal-cli'
$CscPath     = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$TaskName    = 'Signal CLI Daemon'

# ── 1. Install Java 21 JRE ──────────────────────────────────────────────────────

Write-Host "`n[1/8] Installing Eclipse Temurin JRE 21..." -ForegroundColor Cyan

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

# Refresh PATH for current session
$machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
$userPath    = [Environment]::GetEnvironmentVariable('PATH', 'User')
$env:PATH    = "$machinePath;$userPath"

$javaCheck = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaCheck) {
    Write-Error "Java installation failed. 'java' not found on PATH after install."
}
Write-Host "  $(& java -version 2>&1 | Select-Object -First 1)" -ForegroundColor Green

# ── 2. Install Python 3 ─────────────────────────────────────────────────────────

Write-Host "`n[2/8] Installing Python 3..." -ForegroundColor Cyan

# Remove Windows Store python stubs that shadow real Python installs ("Access is denied")
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
    $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $env:PATH    = "$machinePath;$userPath"
}

$pythonCheck = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCheck) {
    Write-Error "Python installation failed. 'python' not found on PATH after install."
}
Write-Host "  $(& python --version 2>&1)" -ForegroundColor Green

Write-Host "  Installing qrcode and pillow pip packages..."
& python -m pip install --quiet qrcode pillow
Write-Host "  pip packages installed." -ForegroundColor Green

# ── 3. Determine latest signal-cli version ───────────────────────────────────────

Write-Host "`n[3/8] Fetching latest signal-cli release..." -ForegroundColor Cyan

$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/AsamK/signal-cli/releases/latest'
$version = $release.tag_name -replace '^v', ''
$downloadUrl = $release.assets |
    Where-Object { $_.name -eq "signal-cli-${version}.tar.gz" } |
    Select-Object -ExpandProperty browser_download_url

Write-Host "  Latest version: $version" -ForegroundColor Green

# ── 4. Download and extract ──────────────────────────────────────────────────────

Write-Host "`n[4/8] Downloading and extracting..." -ForegroundColor Cyan

$tempTar     = Join-Path $env:TEMP "signal-cli-${version}.tar.gz"
$tempExtract = Join-Path $env:TEMP "signal-cli-extract"

Invoke-WebRequest -Uri $downloadUrl -OutFile $tempTar -UseBasicParsing
Write-Host "  Downloaded."

if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }
New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
tar -xzf $tempTar -C $tempExtract
Write-Host "  Extracted."

# ── 5. Install to ~/.local/lib/signal-cli ────────────────────────────────────────

Write-Host "`n[5/8] Installing to $InstallDir..." -ForegroundColor Cyan

# Stop daemon if running (so we can overwrite files)
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask -and $existingTask.State -eq 'Running') {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
# Kill any lingering signal-cli/java processes from a previous daemon
Get-Process -Name 'signal-cli' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
# Give file handles a moment to release
Start-Sleep -Seconds 1

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "  Removed previous installation."
}

New-Item -ItemType Directory -Path $LibDir -Force | Out-Null
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
Move-Item -Path (Join-Path $tempExtract "signal-cli-${version}") -Destination $InstallDir
Write-Host "  Installed signal-cli to $InstallDir"

# ── signal-cli.cmd (shell wrapper) ──
$cmdPath = Join-Path $BinDir 'signal-cli.cmd'
Set-Content -Path $cmdPath -Value @'
@echo off
"%~dp0..\lib\signal-cli\bin\signal-cli.bat" %*
'@
Write-Host "  Created $cmdPath"

# ── signal-cli.exe (native wrapper for Node.js / programmatic spawning) ──
# Node.js spawn() on Windows cannot execute .cmd/.bat without shell:true.
# This .exe wrapper delegates to the .bat via cmd.exe with stdio forwarding,
# allowing tools like OpenClaw to spawn signal-cli as a child process.
$csPath = Join-Path $LibDir 'signal-cli-wrapper.cs'
Set-Content -Path $csPath -Value @'
using System;
using System.Diagnostics;
using System.Threading;

class SignalCliWrapper
{
    static int Main(string[] args)
    {
        var exeDir = System.IO.Path.GetDirectoryName(
            System.Reflection.Assembly.GetExecutingAssembly().Location);
        var batPath = System.IO.Path.GetFullPath(
            System.IO.Path.Combine(exeDir, "..", "lib", "signal-cli", "bin", "signal-cli.bat")
        );
        var psi = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = "/c \"" + batPath + "\" " + string.Join(" ", args),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true
        };
        var proc = Process.Start(psi);

        proc.OutputDataReceived += (s, e) => {
            if (e.Data != null) Console.WriteLine(e.Data);
        };
        proc.ErrorDataReceived += (s, e) => {
            if (e.Data != null) Console.Error.WriteLine(e.Data);
        };
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        Console.CancelKeyPress += (s, e) => {
            e.Cancel = true;
            try { proc.Kill(); } catch {}
        };

        proc.WaitForExit();
        return proc.ExitCode;
    }
}
'@

$exePath = Join-Path $BinDir 'signal-cli.exe'
if (Test-Path $CscPath) {
    & $CscPath -nologo "-out:$exePath" $csPath 2>&1 | Out-Null
    Write-Host "  Compiled $exePath"
} else {
    Write-Host "  WARNING: .NET Framework csc.exe not found; skipped signal-cli.exe build." -ForegroundColor Yellow
    Write-Host "  (Only affects programmatic spawning from Node.js; signal-cli.cmd still works.)" -ForegroundColor Yellow
}

# ── signal-cli-qr (QR code helper for account linking) ──
$qrPyPath = Join-Path $LibDir 'signal-cli-qr.py'
Set-Content -Path $qrPyPath -Value @'
import subprocess
import sys
import io
import os
import tempfile
import qrcode
import shutil

device_name = sys.argv[1] if len(sys.argv) > 1 else "signal-cli"

signal_cli = shutil.which("signal-cli")
if not signal_cli:
    print("Error: signal-cli not found on PATH", file=sys.stderr)
    sys.exit(1)

proc = subprocess.Popen(
    [signal_cli, "link", "-n", device_name],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    shell=True,
)

# signal-cli prints the sgnl:// URI as the first line of stdout, then blocks
uri = proc.stdout.readline().strip()

if not uri:
    uri = proc.stderr.readline().strip()

if not uri.startswith("sgnl://"):
    print(f"Unexpected output from signal-cli link: {uri}", file=sys.stderr)
    proc.terminate()
    sys.exit(1)

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

print()
print(f"URI: {uri}")
print()
print("Scan this QR code with Signal on your phone:")
print("  Settings > Linked Devices > Link New Device")
print()

q = qrcode.QRCode(border=4)
q.add_data(uri)
q.make()
q.print_ascii(invert=True)

try:
    img = qrcode.make(uri)
    qr_path = os.path.join(tempfile.gettempdir(), "signal-cli-qr.png")
    img.save(qr_path)
    print()
    print(f"QR code also saved to: {qr_path}")
    os.startfile(qr_path)
except Exception:
    pass

print()
print("Waiting for you to scan...")

proc.wait()

if proc.returncode == 0:
    print("Linked successfully!")
else:
    err = proc.stderr.read()
    print(f"Linking failed (exit code {proc.returncode}): {err}", file=sys.stderr)
    sys.exit(proc.returncode)
'@
Write-Host "  Created $qrPyPath"

$qrCmdPath = Join-Path $BinDir 'signal-cli-qr.cmd'
Set-Content -Path $qrCmdPath -Value @'
@echo off
python "%~dp0..\lib\signal-cli-qr.py" %*
'@
Write-Host "  Created $qrCmdPath"

# Clean up temp files
Remove-Item $tempTar -Force -ErrorAction SilentlyContinue
Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue

# ── 6. Ensure ~/.local/bin is on user PATH ───────────────────────────────────────

Write-Host "`n[6/8] Checking user PATH..." -ForegroundColor Cyan

$currentUserPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($currentUserPath -split ';' -notcontains $BinDir) {
    $newPath = if ($currentUserPath) { "$currentUserPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
    $env:PATH = "$env:PATH;$BinDir"
    Write-Host "  Added $BinDir to user PATH." -ForegroundColor Green
} else {
    Write-Host "  $BinDir already on user PATH." -ForegroundColor Green
}

# ── 7. Register signal-cli daemon as a scheduled task ────────────────────────────

Write-Host "`n[7/8] Registering signal-cli daemon scheduled task..." -ForegroundColor Cyan

# Build the daemon launch script
$daemonCmd = Join-Path $LocalBase 'signal-cli-daemon.cmd'

if ($Account) {
    $accountArg = $Account
} else {
    # Try to detect account from existing signal-cli data
    $dataDir = Join-Path $env:USERPROFILE '.local\share\signal-cli\data'
    $accountFile = Get-ChildItem -Path $dataDir -Filter '*.d' -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($accountFile) {
        $accountArg = $accountFile.Name -replace '\.d$', ''
        Write-Host "  Auto-detected account: $accountArg"
    } else {
        $accountArg = $null
    }
}

if ($accountArg) {
    # Snapshot current PATH (with Java) into the daemon script
    $daemonPath = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' +
                  [Environment]::GetEnvironmentVariable('PATH', 'User')

    Set-Content -Path $daemonCmd -Value @"
@echo off
rem Signal CLI Daemon — auto-generated by install-signal-cli.ps1
set PATH=$daemonPath
"$BinDir\signal-cli.cmd" -a $accountArg daemon --http 127.0.0.1:8080 --no-receive-stdout
"@
    Write-Host "  Created daemon script: $daemonCmd"

    # Register scheduled task (runs at logon, restarts on failure)
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    $action  = New-ScheduledTaskAction -Execute $daemonCmd
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 3 `
        -RestartInterval ([TimeSpan]::FromMinutes(1))
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Settings $settings -User $env:USERNAME -RunLevel Limited | Out-Null

    Write-Host "  Registered scheduled task: '$TaskName'" -ForegroundColor Green
    Write-Host "  Runs at logon, auto-restarts on failure, listens on 127.0.0.1:8080"

    # Start it now
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 5

    # Verify daemon is responding
    try {
        $check = Invoke-WebRequest -Uri 'http://127.0.0.1:8080/api/v1/check' -UseBasicParsing -TimeoutSec 5
        if ($check.StatusCode -eq 200) {
            Write-Host "  Daemon is running and healthy." -ForegroundColor Green
        }
    } catch {
        Write-Host "  WARNING: Daemon started but health check failed. It may need a few more seconds." -ForegroundColor Yellow
    }
} else {
    Write-Host "  Skipped — no account linked yet. Re-run after linking:" -ForegroundColor Yellow
    Write-Host "    .\install-signal-cli.ps1 -Account +1YOURNUMBER" -ForegroundColor White
}

# ── 8. Verification ─────────────────────────────────────────────────────────────

Write-Host "`n[8/8] Verification..." -ForegroundColor Cyan
$result = & (Join-Path $BinDir 'signal-cli.cmd') --version 2>&1
Write-Host "  signal-cli $result" -ForegroundColor Green

# ── Summary ──────────────────────────────────────────────────────────────────────

Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

Write-Host "`n  Installed files:" -ForegroundColor White
Write-Host "    $InstallDir\                     signal-cli distribution"
Write-Host "    $BinDir\signal-cli.cmd           shell wrapper"
Write-Host "    $BinDir\signal-cli.exe           native wrapper (for Node.js)"
Write-Host "    $BinDir\signal-cli-qr.cmd        QR code linking helper"
Write-Host "    $daemonCmd      daemon auto-start script"

Write-Host "`n  Next steps (open a new terminal):" -ForegroundColor White
Write-Host "    signal-cli --version             # verify install"

if (-not $accountArg) {
    Write-Host "    signal-cli-qr MyDevice           # link to your Signal account" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  After linking, re-run to register the daemon:" -ForegroundColor Yellow
    Write-Host "    .\install-signal-cli.ps1 -Account +1YOURNUMBER" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "  OpenClaw integration notes" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  The signal-cli daemon runs externally on http://127.0.0.1:8080"
Write-Host "  as a scheduled task. OpenClaw must be configured to connect to"
Write-Host "  it (rather than trying to auto-spawn signal-cli itself)."
Write-Host ""
Write-Host "  In ~/.openclaw/openclaw.json, set the signal channel to:" -ForegroundColor White
Write-Host ""
Write-Host '    "channels": {' -ForegroundColor DarkYellow
Write-Host '      "signal": {' -ForegroundColor DarkYellow
Write-Host '        "enabled": true,' -ForegroundColor DarkYellow
if ($accountArg) {
    Write-Host "        `"account`": `"$accountArg`"," -ForegroundColor DarkYellow
} else {
    Write-Host '        "account": "+1YOURNUMBER",' -ForegroundColor DarkYellow
}
Write-Host '        "httpUrl": "http://127.0.0.1:8080"' -ForegroundColor DarkYellow
Write-Host '      }' -ForegroundColor DarkYellow
Write-Host '    }' -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  Key points:" -ForegroundColor White
Write-Host "    - httpUrl tells OpenClaw to use the external daemon (no auto-spawn)"
Write-Host "    - Do NOT set cliPath when using httpUrl"
Write-Host "    - Node.js spawn() cannot execute .bat/.cmd files on Windows,"
Write-Host "      so OpenClaw's auto-spawn of signal-cli does not work"
Write-Host "    - The scheduled task '$TaskName' handles daemon lifecycle"
Write-Host ""
Write-Host "  Daemon management:" -ForegroundColor White
Write-Host "    schtasks /Run /TN `"$TaskName`"      # start daemon"
Write-Host "    schtasks /End /TN `"$TaskName`"      # stop daemon"
Write-Host "    schtasks /Query /TN `"$TaskName`"    # check status"
Write-Host ""
