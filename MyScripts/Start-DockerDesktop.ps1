# Ensure Docker Desktop is running and Docker engine is ready

function Get-DockerDesktopPath {
    $candidates = @()

    # 1) Registry (per-user)
    try {
        $regPath = 'HKCU:\Software\Docker Inc.\Docker Desktop'
        $installPath = (Get-ItemProperty -Path $regPath -ErrorAction Stop).InstallPath
        if ($installPath) { $candidates += (Join-Path $installPath 'Docker Desktop.exe') }
    } catch {}

    # 2) Registry (machine-wide)
    try {
        $regPath = 'HKLM:\Software\Docker Inc.\Docker Desktop'
        $installPath = (Get-ItemProperty -Path $regPath -ErrorAction Stop).InstallPath
        if ($installPath) { $candidates += (Join-Path $installPath 'Docker Desktop.exe') }
    } catch {}

    # 3) Common default paths
    $candidates += @(
        "C:\Program Files\Docker\Docker\Docker Desktop.exe",
        "$env:LOCALAPPDATA\Programs\Docker\Docker\Docker Desktop.exe"
    )

    return ($candidates | Where-Object { Test-Path $_ } | Select-Object -First 1)
}

# Start Docker Desktop if needed
$dockerExe = Get-DockerDesktopPath
if (-not $dockerExe) {
    Write-Error "Docker Desktop.exe not found. Is Docker Desktop installed?"
    exit 1
}

if (-not (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue)) {
    Write-Host "Starting Docker Desktop..."
    Start-Process -FilePath $dockerExe
}

# Wait for engine readiness
$timeoutSec = 120
$intervalSec = 2
$elapsed = 0
while ($true) {
    try {
        docker info | Out-Null
        Write-Host "Docker is ready."
        break
    } catch {
        if ($elapsed -ge $timeoutSec) {
            Write-Error "Timed out waiting for Docker engine to become ready after $timeoutSec seconds."
            exit 2
        }
        Start-Sleep -Seconds $intervalSec
        $elapsed += $intervalSec
    }
}
