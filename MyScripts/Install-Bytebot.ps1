<# 
InstallByteBotDockerDesktop.ps1 — Full Installer (with your original functions + fixes)

Flow:
1) Assert-Admin, Check-SystemResources, Ensure-WSL2, Ensure-Choco, Ensure-Package (git, docker-desktop), Wait-ForDocker
2) (Optional) Nuke-Bytebot previous setup; Clone-Fresh-Bytebot to C:\Scripts\gitrepos\bytebot
3) Ensure docker\.env: prompt for ANTHROPIC_API_KEY, keep OPENAI/GEMINI as placeholders unless you set them; generate BYTEBOT_ENCRYPTION_KEY if missing
4) Write docker\docker-compose.override.yml to force Prisma native library engines + pass encryption key
5) Pin Prisma CLI in packages\bytebot-agent\package.json to match @prisma/client
6) docker compose down; up -d --build using --env-file docker\.env and override
7) Inside bytebot-agent: pin prisma CLI, add WASM stub, prisma generate + migrate
#>

param(
  [switch]$Fresh = $true  # set -Fresh:$false to skip nuking the previous repo
)

$ErrorActionPreference = 'Stop'

# -------------------- Your original helper functions --------------------

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
  if ($ramGB -lt 15)  { Write-Warning "This machine has < 16 GB RAM."; $ok = $false }
  if ($diskGB -lt 30) { Write-Warning "Less than 50 GB free on C: drive."; $ok = $false }
  if (-not $ok) { throw "Minimum requirements not met." }
}

function Ensure-WSL2 {
  Write-Host "Ensuring WSL + VirtualMachinePlatform are enabled..." -ForegroundColor Cyan
  $feat1 = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
  $feat2 = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform
  if ($feat1.State -ne "Enabled") { Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart | Out-Null }
  if ($feat2.State -ne "Enabled") { Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart | Out-Null }
  try { wsl --set-default-version 2 | Out-Null } catch { }
  if (($feat1.State -ne "Enabled") -or ($feat2.State -ne "Enabled")) {
    Write-Warning "Windows features were just enabled. A reboot is recommended before continuing."
    $resp = Read-Host "Reboot now? (Y/N)"
    if ($resp -match '^[Yy]') { Restart-Computer -Force }
  }
}

function Ensure-Choco {
  if (Get-Command choco -ErrorAction SilentlyContinue) { return }
  Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
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

# Robust directory removal w/ retries (handles file locks/RO attrs)
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
  param([string]$RepoPath)
  Write-Host "Cleaning any previous Bytebot containers/images/volumes/networks..." -ForegroundColor Cyan
  if ($RepoPath -and (Test-Path $RepoPath)) {
    $composeFile = Join-Path $RepoPath "docker\docker-compose.yml"
    if (Test-Path $composeFile) {
      try { docker compose -f $composeFile down -v } catch { }
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
if ($Fresh) {
  Write-Host "Do you want to wipe any previous ByteBot setup and clone fresh? (Y/N) [Default=Y in 10s]" -ForegroundColor Yellow
  $resp = $null
  try {
    # PowerShell 7+ supports -Timeout
    $resp = Read-Host -Timeout 10
  } catch {
    # Fallback for Windows PowerShell: manual timeout loop
    $end = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $end -and -not $host.UI.RawUI.KeyAvailable) {
      Start-Sleep -Milliseconds 200
    }
    if ($host.UI.RawUI.KeyAvailable) {
      $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
      $resp = $key.Character
    }
  }

  if ([string]::IsNullOrWhiteSpace($resp)) { $resp = "Y" }

  if ($resp -match '^[Yy]') {
    Nuke-Bytebot -RepoPath $repoPath
    $repoPath = Clone-Fresh-Bytebot
  } else {
    if (-not (Test-Path $repoPath)) { $repoPath = Clone-Fresh-Bytebot }
  }
} else {
  if (-not (Test-Path $repoPath)) { $repoPath = Clone-Fresh-Bytebot }
}


# Paths
$DockerDir       = Join-Path $repoPath 'docker'
$ComposeYml      = Join-Path $DockerDir 'docker-compose.yml'
$ComposeOverride = Join-Path $DockerDir 'docker-compose.override.yml'
$EnvPath         = Join-Path $DockerDir '.env'
$AgentPkgJson    = Join-Path $repoPath 'packages\bytebot-agent\package.json'


# --- Patch bytebot-desktop Dockerfile to use Code OSS instead of Microsoft VS Code ---
$desktopDockerfile = Join-Path $repoPath 'docker\bytebot-desktop\Dockerfile'
if (Test-Path $desktopDockerfile) {
    $dockerfileText = Get-Content -Raw $desktopDockerfile

    # Replace the block that installs Microsoft VS Code with Code OSS
    $pattern = '(?ms)^# Install VS Code.*?rm -f microsoft\.gpg\s*'
    $replacement = @"
# Install Code OSS (pure Linux build, no WSL hooks)
RUN apt-get update && \
    apt-get remove -y code || true && \
    apt-get install -y code-oss
"@

    if ($dockerfileText -match $pattern) {
        $dockerfileText = [regex]::Replace($dockerfileText, $pattern, $replacement)
        Write-Host "Patched bytebot-desktop Dockerfile to use Code OSS." -ForegroundColor Green
    } elseif ($dockerfileText -notmatch 'code-oss') {
        # If the expected block isn’t found, just append Code OSS install
        $dockerfileText += "`n$replacement`n"
        Write-Host "Appended Code OSS install to bytebot-desktop Dockerfile." -ForegroundColor Yellow
    }

    Write-Utf8NoBom -Path $desktopDockerfile -Content $dockerfileText
} else {
    Write-Warning "Could not find docker/bytebot-desktop/Dockerfile; skipping Code OSS patch."
}


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

# OPENAI/GEMINI placeholder unless you provide real ones later
Ensure-LineInFile -Path $EnvPath -Key "OPENAI_API_KEY"    -Value "placeholder"
Ensure-LineInFile -Path $EnvPath -Key "GEMINI_API_KEY"    -Value "placeholder"

# Prompt for ANTHROPIC_API_KEY (masked). If blank, keep existing line or write placeholder.
$existingEnv = Get-Content -Raw $EnvPath
$existingAnth = $null
if ($existingEnv -match 'ANTHROPIC_API_KEY=(.+)') { $existingAnth = $Matches[1] }

Write-Host "You need an ANTHROPIC_API_KEY from https://console.anthropic.com/settings/keys in order to use Anthropic AI models." -ForegroundColor Yellow
$anthInput = Read-Host "Enter your ANTHROPIC_API_KEY (press Enter to keep existing or set later)"
if ([string]::IsNullOrWhiteSpace($anthInput)) {
  if (-not $existingAnth) {
    Ensure-LineInFile -Path $EnvPath -Key "ANTHROPIC_API_KEY" -Value "placeholder"
  }
} else {
  # Update or append the line
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

# Compose override: force native library engine and pass encryption key
$overrideYml = @"
services:
  bytebot-agent:
    environment:
      - PRISMA_CLI_QUERY_ENGINE_TYPE=library
      - PRISMA_CLIENT_ENGINE_TYPE=library
      - BYTEBOT_ENCRYPTION_KEY=\${BYTEBOT_ENCRYPTION_KEY}
"@
Set-Content -Path $ComposeOverride -Value $overrideYml -Encoding UTF8
Write-Host "Wrote docker/docker-compose.override.yml" -ForegroundColor Green

# Pin prisma CLI in package.json to match @prisma/client
if (Test-Path $AgentPkgJson) {
  $pkg = Get-Content -Raw -Path $AgentPkgJson | ConvertFrom-Json
  $clientVer = $null
  if ($pkg.PSObject.Properties.Name -contains 'dependencies')   { $clientVer = $pkg.dependencies.'@prisma/client' }
  if (-not $clientVer -and $pkg.PSObject.Properties.Name -contains 'devDependencies') { $clientVer = $pkg.devDependencies.'@prisma/client' }
  if (-not $clientVer) { $clientVer = '6.6.0' }  # safe fallback if not declared
  if (-not ($pkg.PSObject.Properties.Name -contains 'devDependencies')) {
    $pkg | Add-Member -NotePropertyName devDependencies -NotePropertyValue (@{}) -Force
  }
  $pkg.devDependencies.prisma = $clientVer
  Write-Utf8NoBom -Path $AgentPkgJson -Content ($pkg | ConvertTo-Json -Depth 100)
  Write-Host "Pinned prisma devDependency to version $clientVer" -ForegroundColor Green
} else {
  Write-Warning "Could not find packages\bytebot-agent\package.json; continuing without pin."
}

# Bring the stack down/up with env-file + override
Push-Location $repoPath
Write-Host "docker compose down" -ForegroundColor Cyan
docker compose -f $ComposeYml down

Write-Host "docker compose up -d --build (with --env-file docker\.env + override)" -ForegroundColor Cyan
docker compose --env-file $EnvPath -f $ComposeYml -f $ComposeOverride up -d --build
Pop-Location

# Finalize inside the agent container (pin CLI, stub wasm, generate/migrate)
Write-Host "Finalizing Prisma inside bytebot-agent..." -ForegroundColor Cyan
docker compose -f $ComposeYml exec bytebot-agent sh -lc '
  set -e
  PRISMA_VER="$(node -p "require(\"@prisma/client/package.json\").version")"
  npm i -D --silent prisma@"$PRISMA_VER"
  export PRISMA_CLI_QUERY_ENGINE_TYPE=library
  export PRISMA_CLIENT_ENGINE_TYPE=library
  mkdir -p node_modules/@prisma/client/runtime
  printf "module.exports = \"\";\n" > node_modules/@prisma/client/runtime/query_engine_bg.postgresql.wasm-base64.js
  rm -rf node_modules/.prisma
  npx prisma -v
  npx prisma generate
  npx prisma migrate deploy
  node -e "require(\"@prisma/client\"); console.log(\"Prisma client OK (library engine)\")"
'

# Sanity: print key envs inside container
Write-Host "Verifying envs inside bytebot-agent..." -ForegroundColor Cyan
docker compose -f $ComposeYml exec bytebot-agent sh -lc '
  for k in OPENAI_API_KEY GEMINI_API_KEY ANTHROPIC_API_KEY BYTEBOT_ENCRYPTION_KEY PRISMA_CLI_QUERY_ENGINE_TYPE PRISMA_CLIENT_ENGINE_TYPE; do
    v="$(printenv "$k")"; [ -n "$v" ] && echo "$k=set (len=${#v})" || echo "$k=MISSING";
  done
'

Write-Host "`nDone. ByteBot should now come up clean with native Prisma engine and proper envs." -ForegroundColor Green
