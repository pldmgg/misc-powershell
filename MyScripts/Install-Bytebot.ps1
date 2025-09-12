<#
InstallByteBotDockerDesktop.ps1 — Full Installer (with fixes & your original helper functions)

Flow:
1) Assert-Admin, Check-SystemResources, Ensure-WSL2, Ensure-Choco, Ensure-Package (git, docker-desktop), Wait-ForDocker
2) Optional wipe/clone with a 10s timeout defaulting to Yes
3) Ensure docker\.env: prompt for ANTHROPIC_API_KEY; keep OPENAI/GEMINI placeholders; generate BYTEBOT_ENCRYPTION_KEY if missing
4) docker compose down; up -d --build using **--env-file docker\.env** and the override file
5) Verify envs inside the container
#>

param(
  [switch]$Fresh = $true
)

$ErrorActionPreference = 'Stop'

# -------------------- Helper functions (original and new) --------------------

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching this script as Administrator..." -ForegroundColor Yellow
    $psi = @{
      FilePath    = "powershell.exe"
      ArgumentList= "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
      Verb        = "RunAs"
    }
    Start-Process @psi
    exit
  }
}

function Check-SystemResources {
  $ramGB  = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
  $diskGB = [math]::Round((Get-PSDrive -Name C).Free/1GB, 2)
  Write-Host "Detected RAM: $ramGB GB; Free on C:: $diskGB GB"
  $ok = $true
  if ($ramGB -lt 15)  { Write-Warning "This machine has < 15 GB RAM. ($ramGB)"; $ok = $false }
  if ($diskGB -lt 30) { Write-Warning "Less than 50 GB free on C: drive. ($diskGB)"; $ok = $false }
  if (-not $ok) { throw "Minimum requirements not met." }
}

function Ensure-WSL2 {
  Write-Host "Ensuring WSL + VirtualMachinePlatform are enabled..." -ForegroundColor Cyan

  # Query current state
  Write-Host "Querying current state 1" -ForegroundColor Cyan
  $featWSL = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
  $featVMP = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform

  # Enable features if needed (no restart yet)
  if ($featWSL.State -ne 'Enabled') {
    Write-Host "Enabling Microsoft-Windows-Subsystem-Linux..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart | Out-Null
  }
  if ($featVMP.State -ne 'Enabled') {
    Write-Host "Enabling VirtualMachinePlatform..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart | Out-Null
  }

  # Re-query to see if anything changed
  Write-Host "Querying current state 2" -ForegroundColor Cyan
  $featWSL = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
  $featVMP = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform

  # Best-effort WSL configuration; ignore benign failures on older builds
  try {
    # Set WSL2 as default backend when supported
    wsl --set-default-version 2 | Out-Null
  } catch { }

  try {
    # Update WSL kernel if supported (newer Windows only)
    wsl --update | Out-Null
  } catch { }

  # Check pending reboot using common markers
  $pending = $false
  if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
  #if (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { $pending = $true }

  # If features were just enabled or a reboot is pending, offer reboot with 10s default = Yes
  if ($pending -or $featWSL.State -ne 'Enabled' -or $featVMP.State -ne 'Enabled') {
    Write-Warning "Windows features were just enabled or a reboot is pending. A reboot is recommended before continuing."
    Write-Host "Reboot now? (Y/N) [Default=Y in 10s]" -ForegroundColor Yellow
    choice /C YN /N /T 10 /D Y | Out-Null
    switch ($LASTEXITCODE) {
      1 { Restart-Computer -Force }  # Y or timeout → reboot
      2 { Write-Host "Continuing without reboot (may require manual reboot later)..." -ForegroundColor Yellow }
      default { Restart-Computer -Force }
    }
  }
}

function Ensure-Choco {
  if (Get-Command choco -ErrorAction SilentlyContinue) { return }
  Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'Machine')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'Machine')
  [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'User')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'User')
}

function Ensure-Package {
  param([Parameter(Mandatory=$true)][string]$Name)
  if (choco list --local-only | Select-String -SimpleMatch "^$Name ") {
    Write-Host "$Name is already installed."
  } else {
    Write-Host "Installing $Name via Chocolatey..." -ForegroundColor Cyan
    choco install $Name -y --no-progress
  }
}

function Wait-ForDocker {
  Write-Host "Starting Docker Desktop..." -ForegroundColor Cyan
  $dockerExe = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
  if (Test-Path $dockerExe) { Start-Process -FilePath $dockerExe }
  $deadline = (Get-Date).AddMinutes(5)
  do {
    Start-Sleep -Seconds 3
    try {
      $ver = docker version --format '{{.Server.Version}}' 2>$null
      if ($LASTEXITCODE -eq 0 -and $ver) {
        Write-Host "Docker engine is up (Server $ver)."
        break
      }
    } catch { }
  } while ((Get-Date) -lt $deadline)
  if (-not $ver) { throw "Docker engine did not become ready in time." }
  try { docker compose version | Out-Null } catch { throw "Docker Compose v2 not available." }
}

function Remove-DirForce {
  param([Parameter(Mandatory=$true)][string]$Path, [int]$Retries = 6, [int]$DelayMs = 500)
  if (-not (Test-Path $Path)) { return }
  for ($i=1; $i -le $Retries; $i++) {
    try {
      Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        try { attrib -r -s -h $_.FullName 2>$null } catch {}
      }
      attrib -r -s -h $Path 2>$null
      Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
      break
    } catch {
      if ($i -ge $Retries) { throw "Failed to remove $Path : $($_.Exception.Message)" }
      Start-Sleep -Milliseconds $DelayMs
    }
  }
  if (Test-Path $Path) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    robocopy $tmp $Path /MIR | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Nuke-Bytebot {
  param(
    [string]$RepoPath,
    [string]$EnvPath
  )
  Write-Host "Cleaning any previous Bytebot containers/images/volumes/networks..." -ForegroundColor Cyan
  if ($RepoPath -and (Test-Path $RepoPath)) {
    $composeFile = Join-Path $RepoPath "docker\docker-compose.yml"
    if (Test-Path $composeFile) {
      try { docker compose --env-file $EnvPath -f $composeFile down -v } catch { }
    }
  }
  $ctr = $(docker ps -a --filter "name=bytebot" -q) 2>$null
  if ($ctr) { try { docker rm -f $ctr | Out-Null } catch { } }
  $img = $(docker images --filter "reference=*bytebot*" -q) 2>$null
  if ($img) { try { docker rmi -f $img | Out-Null } catch { } }
  $vol = $(docker volume ls --filter "name=bytebot" -q) 2>$null
  if ($vol) { try { docker volume rm $vol | Out-Null } catch { } }
  $net = $(docker network ls --filter "name=bytebot" -q) 2>$null
  if ($net) { try { docker network rm $net | Out-Null } catch { } }
  if ($RepoPath -and (Test-Path $RepoPath)) {
    Write-Host "Removing previous repo at $RepoPath ..." -ForegroundColor Yellow
    Remove-DirForce -Path $RepoPath
  }
}

function Clone-Fresh-Bytebot {
  $basePath = "C:\Scripts\gitrepos"
  if (-not (Test-Path $basePath)) { New-Item -ItemType Directory -Path $basePath | Out-Null }
  $target = Join-Path $basePath "bytebot"
  if (Test-Path $target) { Remove-DirForce -Path $target }
  Write-Host "Cloning Bytebot to $target..." -ForegroundColor Cyan
  git clone https://github.com/bytebot-ai/bytebot.git $target
  return (Resolve-Path $target).Path
}

# UTF-8 no BOM writer (works on PS5 & PS7)
function Write-Utf8NoBom {
  param([Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content)
  $enc = New-Object System.Text.UTF8Encoding($false)
  $sw  = New-Object System.IO.StreamWriter($Path, $false, $enc)
  $sw.Write($Content)
  $sw.Close()
}

# -------------------- Script starts here --------------------

Assert-Admin
Check-SystemResources
Ensure-WSL2
Ensure-Choco
Ensure-Package git
Ensure-Package docker-desktop
Wait-ForDocker

$repoPath = "C:\Scripts\gitrepos\bytebot"
$DockerDir       = Join-Path $repoPath 'docker'
$ComposeYml      = Join-Path $DockerDir 'docker-compose.yml'
$EnvPath         = Join-Path $DockerDir '.env'
$AgentPkgJson    = Join-Path $repoPath 'packages\bytebot-agent\package.json'

# Fresh clone prompt with 10s timeout (default = Y)
Write-Host "Do you want to wipe any previous ByteBot setup and clone fresh? (Y/N) [Default=Y in 10s]" -ForegroundColor Yellow

choice /C YN /N /T 10 /D Y
$exitCode = $LASTEXITCODE

switch ($exitCode) {
    1 {
        # User pressed Y or timeout defaulted to Y
        Nuke-Bytebot -RepoPath $repoPath -EnvPath $EnvPath
        $repoPath = Clone-Fresh-Bytebot
    }
    2 {
        # User pressed N
        if (-not (Test-Path $repoPath)) { $repoPath = Clone-Fresh-Bytebot }
    }
    default {
        # Just in case, default to Y
        Nuke-Bytebot -RepoPath $repoPath -EnvPath $EnvPath
        $repoPath = Clone-Fresh-Bytebot
    }
}

# Refresh paths (repo may have been re-cloned)
$DockerDir       = Join-Path $repoPath 'docker'
$ComposeYml      = Join-Path $DockerDir 'docker-compose.yml'
$EnvPath         = Join-Path $DockerDir '.env'
$AgentPkgJson    = Join-Path $repoPath 'packages\bytebot-agent\package.json'

# Ensure docker\.env exists and prompt for Anthropic key
New-Item -ItemType Directory -Force -Path $DockerDir | Out-Null
if (-not (Test-Path $EnvPath)) { New-Item -ItemType File -Path $EnvPath | Out-Null }

function Ensure-LineInFile {
  param([string]$Path,[string]$Key,[string]$Value)
  $raw = Get-Content -Raw -Path $Path
  if ($raw -notmatch "^\s*$([regex]::Escape($Key))=") {
    Add-Content -Path $Path -Value "$Key=$Value"
  }
}

# OPENAI/GEMINI placeholders unless user replaces later
Ensure-LineInFile -Path $EnvPath -Key "OPENAI_API_KEY" -Value "placeholder"
Ensure-LineInFile -Path $EnvPath -Key "GEMINI_API_KEY" -Value "placeholder"

# Prompt for ANTHROPIC_API_KEY (optional)
$existingEnv = Get-Content -Raw $EnvPath
$existingAnth = $null
if ($existingEnv -match 'ANTHROPIC_API_KEY=(.+)') { $existingAnth = $Matches[1] }
$anthInput = Read-Host "Enter your ANTHROPIC_API_KEY (press Enter to keep existing or set later)"
if ([string]::IsNullOrWhiteSpace($anthInput)) {
  if (-not $existingAnth) {
    Ensure-LineInFile -Path $EnvPath -Key "ANTHROPIC_API_KEY" -Value "placeholder"
  }
} else {
  $lines = Get-Content $EnvPath
  $updated = $false
  for ($i=0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^\s*ANTHROPIC_API_KEY=') { $lines[$i] = "ANTHROPIC_API_KEY=$anthInput"; $updated = $true }
  }
  if (-not $updated) { $lines += "ANTHROPIC_API_KEY=$anthInput" }
  Set-Content -Path $EnvPath -Value ($lines -join "`r`n")
}

# Generate BYTEBOT_ENCRYPTION_KEY if missing
$envRaw = Get-Content -Raw $EnvPath
if ($envRaw -notmatch '^\s*BYTEBOT_ENCRYPTION_KEY=') {
  $b = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  $hex = ($b | ForEach-Object { $_.ToString("x2") }) -join ""
  Add-Content -Path $EnvPath -Value "BYTEBOT_ENCRYPTION_KEY=$hex"
  Write-Host "Generated BYTEBOT_ENCRYPTION_KEY" -ForegroundColor Green
}

# Bring the stack down/up with --env-file and override
Push-Location $repoPath
Write-Host "docker compose down" -ForegroundColor Cyan
docker compose --env-file $EnvPath -f $ComposeYml down

Write-Host "docker compose up -d --build (with --env-file docker\.env + override)" -ForegroundColor Cyan
docker compose --env-file $EnvPath -f $ComposeYml up -d --build
# Patch VS Code desktop launcher to suppress WSL nag
docker compose --env-file $EnvPath -f $ComposeYml exec -T bytebot-desktop sh -lc "sed -i 's|^Exec=.*|Exec=env DONT_PROMPT_WSL_INSTALL=1 /usr/bin/code --password-store=basic %F|' /home/user/Desktop/code.desktop"
Pop-Location

# --- Verifying envs inside bytebot-agent (paste directly below your Write-Host line) ---
Write-Host "Verifying envs inside bytebot-agent..." -ForegroundColor Cyan
$tmpDir = Join-Path $env:TEMP "bytebot-setup"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$envCheckFile = Join-Path $tmpDir "env_check.sh"

$envCheckScript = @'
for k in OPENAI_API_KEY GEMINI_API_KEY ANTHROPIC_API_KEY BYTEBOT_ENCRYPTION_KEY PRISMA_CLI_QUERY_ENGINE_TYPE PRISMA_CLIENT_ENGINE_TYPE
do
  if [ -n "$(printenv "$k")" ]; then
    echo "$k=set"
  else
    echo "$k=MISSING"
  fi
done
'@ -replace "`r`n","`n"

Write-Utf8NoBom -Path $envCheckFile -Content $envCheckScript
docker cp $envCheckFile bytebot-agent:/tmp/env_check.sh
docker compose --env-file $EnvPath -f $ComposeYml exec -T bytebot-agent sh -lc 'sh /tmp/env_check.sh'

# Launch browser UI
Write-Host "Waiting 20 seconds to launch Bytebot UI in your default browser..." -ForegroundColor Cyan
Start-Sleep -Seconds 20
$ui = "http://localhost:9992"
Start-Process $ui

#Write-Host "`nBytebot is starting. Follow logs with:" -ForegroundColor Yellow
#Write-Host ("  docker compose -f `"{0}\docker\docker-compose.yml`" logs -f" -f $repo) -ForegroundColor Yellow

Write-Host "`nNow navigate to http://localhost:9992 and try the prompt: 'Open Firefox and get me the weather forecast'" -ForegroundColor Yellow

Write-Host @'
If you ever need to do a clean rebuild of the Bytebot agent (for example, after modifying the Dockerfile), run these commands in an elevated PowerShell:

cd C:\Scripts\gitrepos\bytebot
docker compose -f docker\docker-compose.yml down -v

# Rebuild and relaunch
docker compose -f docker\docker-compose.yml up -d --build
docker compose -f docker\docker-compose.yml logs -f bytebot-agent
'@

