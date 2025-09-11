<#
Set-AnthropicKey.ps1

Usage:
  .\Set-AnthropicKey.ps1

Prompts for a new ANTHROPIC_API_KEY, updates docker\.env in your ByteBot repo,
and restarts the docker compose stack.
#>

$repoRoot = "C:\Scripts\gitrepos\bytebot"
$dockerDir = Join-Path $repoRoot "docker"
$envPath   = Join-Path $dockerDir ".env"
$composeYml = Join-Path $dockerDir "docker-compose.yml"
$composeOverride = Join-Path $dockerDir "docker-compose.override.yml"

# --- Sanity checks ---
if (-not (Test-Path $repoRoot)) {
  Write-Error "ByteBot repo not found at $repoRoot. Please clone it first."
  exit 1
}
if (-not (Test-Path $composeYml)) {
  Write-Error "docker-compose.yml not found under $dockerDir."
  exit 1
}
if (-not (Test-Path $envPath)) {
  New-Item -ItemType File -Path $envPath | Out-Null
}

# --- Prompt for key ---
$newKey = Read-Host "Enter your ANTHROPIC_API_KEY"
if ([string]::IsNullOrWhiteSpace($newKey)) {
  Write-Warning "No key entered. Exiting without changes."
  exit 0
}

# --- Update .env ---
$lines = Get-Content $envPath
$updated = $false
for ($i=0; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match '^\s*ANTHROPIC_API_KEY=') {
    $lines[$i] = "ANTHROPIC_API_KEY=$newKey"
    $updated = $true
  }
}
if (-not $updated) { $lines += "ANTHROPIC_API_KEY=$newKey" }
Set-Content -Path $envPath -Value ($lines -join "`r`n") -Encoding UTF8
Write-Host "Updated ANTHROPIC_API_KEY in $envPath" -ForegroundColor Green

# --- Restart stack ---
Push-Location $repoRoot
Write-Host "Restarting ByteBot containers..." -ForegroundColor Cyan
docker compose --env-file $envPath -f $composeYml -f $composeOverride up -d
Pop-Location

Write-Host "`nAll done. New ANTHROPIC_API_KEY applied." -ForegroundColor Green
