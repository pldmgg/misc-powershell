# Ensures Docker Desktop is running and Docker engine (Linux by default) is ready

param(
  [ValidateSet('linux','windows')]
  [string]$Engine = 'linux'  # set to 'windows' if you use Windows containers
)

function Get-DockerDesktopPath {
    $cands = @()
    foreach ($rk in 'HKCU:\Software\Docker Inc.\Docker Desktop','HKLM:\Software\Docker Inc.\Docker Desktop') {
        try {
            $ip = (Get-ItemProperty -Path $rk -ErrorAction Stop).InstallPath
            if ($ip) { $cands += (Join-Path $ip 'Docker Desktop.exe') }
        } catch {}
    }
    $cands += @(
        "C:\Program Files\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    )
    $cands | Where-Object { Test-Path $_ } | Select-Object -First 1
}

# 1) Start Docker Desktop if not running
$dockerExe = Get-DockerDesktopPath
if (-not $dockerExe) { Write-Error "Docker Desktop.exe not found"; exit 1 }

if (-not (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue)) {
    Write-Host "Starting Docker Desktop..."
    Start-Process -FilePath $dockerExe
}

# 2) Wait for the engine named pipe to appear
$pipe = if ($Engine -eq 'linux') { "\\.\pipe\dockerDesktopLinuxEngine" } else { "\\.\pipe\docker_engine" }
$timeoutSec = 180
$intervalSec = 2
$elapsed = 0

Write-Host "Waiting for Docker engine pipe: $pipe"
while (-not (Test-Path $pipe)) {
    if ($elapsed -ge $timeoutSec) {
        Write-Error "Timed out waiting for Docker engine pipe ($pipe) after $timeoutSec seconds."
        exit 2
    }
    Start-Sleep -Seconds $intervalSec
    $elapsed += $intervalSec
}

# 3) Wait until docker CLI responds successfully (check exit code)
$elapsed = 0
while ($true) {
    docker info 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Docker is ready."
        break
    }
    if ($elapsed -ge $timeoutSec) {
        Write-Error "Timed out waiting for 'docker info' to succeed after $timeoutSec seconds."
        exit 3
    }
    Start-Sleep -Seconds $intervalSec
    $elapsed += $intervalSec
}

# Optional: ensure expected context (uncomment if you want to force)
# if ($Engine -eq 'linux') { docker context use desktop-linux | Out-Null } else { docker context use desktop-windows | Out-Null }
