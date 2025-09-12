# Kill running VS Code so installs aren't ignored
Get-Process code, code-insiders -ErrorAction SilentlyContinue | Stop-Process -Force

# Pick the first code CLI found (Stable, User install, or Insiders)
$cliCandidates = @(
  "C:\Program Files\Microsoft VS Code\bin\code.cmd",
  "$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin\code.cmd",
  "C:\Program Files\Microsoft VS Code Insiders\bin\code-insiders.cmd"
)
$codeCli = $cliCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $codeCli) { throw "VS Code CLI (code.cmd) not found. Install VS Code or add 'code' to PATH." }

# Install extensions (force re-install in case of partials)
& $codeCli --install-extension ms-vscode-remote.remote-containers --force --verbose
& $codeCli --install-extension ms-vscode-docker --force --verbose

# Verify
& $codeCli --list-extensions | Select-String -SimpleMatch ms-vscode-remote.remote-containers, ms-vscode-docker

& $codeCli