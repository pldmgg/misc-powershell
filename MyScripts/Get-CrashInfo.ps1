# Analyze Windows crash dumps and summarize root cause
# Run in an elevated PowerShell

# 0) Ensure Debugging Tools (cdb.exe) exist; install WinDbg if missing
$Cdb = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"
if (-not (Test-Path $Cdb)) {
  Write-Host "Installing WinDbg..." -ForegroundColor Yellow
  winget install --id Microsoft.WinDbg -e --accept-source-agreements --accept-package-agreements | Out-Null
  $Cdb = "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe"
  if (-not (Test-Path $Cdb)) {
    throw "Could not find cdb.exe after installation. Install Windows 10/11 Debugging Tools and retry."
  }
}

# 1) Symbol cache (fast & reliable)
$SymCache = Join-Path $env:LOCALAPPDATA "SymCache"
$env:_NT_SYMBOL_PATH = "srv*$SymCache*https://msdl.microsoft.com/download/symbols"

# 2) Pick dumps to analyze
$miniDumpDir = "C:\Windows\Minidump"
$miniDumps = @(Get-ChildItem -Path $miniDumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
$fullDump   = Get-Item -Path "C:\Windows\MEMORY.DMP" -ErrorAction SilentlyContinue
$dumps = @()
if ($miniDumps) { $dumps += $miniDumps.FullName }
if ($fullDump)  { $dumps += $fullDump.FullName }

if (-not $dumps) { throw "No dump files found in $miniDumpDir or C:\Windows\MEMORY.DMP" }

# 3) Analyze each dump with cdb (!analyze -v) and parse key fields
$results = foreach ($dump in $dumps) {
  $log = Join-Path $env:TEMP ("cdb_{0}.log" -f [IO.Path]::GetFileNameWithoutExtension($dump))

  # Run debugger headlessly, fix symbols, analyze, quit
  & $Cdb -z $dump -c ".symfix; .sympath srv*$SymCache*https://msdl.microsoft.com/download/symbols; .reload; !analyze -v; q" `
    2>&1 | Tee-Object -FilePath $log | Out-Null

  $text = Get-Content $log -Raw

  # Extract common fields
  $bugCheck      = ([regex]::Match($text, 'BugCheck\s+([0-9A-Fa-fx]+)')).Groups[1].Value
  if (-not $bugCheck) { $bugCheck = ([regex]::Match($text, 'KERNEL_MODE_EXCEPTION_NOT_HANDLED|WATCHDOG_TIMEOUT|DPC_WATCHDOG_VIOLATION|[\w_]+')).Value }

  $probCause     = ([regex]::Match($text, 'Probably caused by\s*:\s*([^\r\n]+)')).Groups[1].Value.Trim()
  $process       = ([regex]::Match($text, 'PROCESS_NAME:\s*([^\r\n]+)')).Groups[1].Value.Trim()
  $imageName     = ([regex]::Match($text, 'IMAGE_NAME:\s*([^\r\n]+)')).Groups[1].Value.Trim()
  $failureBucket = ([regex]::Match($text, 'FAILURE_BUCKET_ID:\s*([^\r\n]+)')).Groups[1].Value.Trim()
  $module        = ([regex]::Match($text, 'MODULE_NAME:\s*([^\r\n]+)')).Groups[1].Value.Trim()

  # A quick taste of the top of the call stack (first non-empty frame line)
  $stackLine = ($text -split "`r?`n" | Where-Object { $_ -match '^[0-9a-fA-F` ]{0,16}[\!\+a-zA-Z_].*\b' } | Select-Object -First 1)

  [pscustomobject]@{
    DumpFile        = $dump
    BugCheck        = $bugCheck
    ProbablyCausedBy= $probCause
    Process         = $process
    ImageName       = $imageName
    Module          = $module
    FailureBucketID = $failureBucket
    TopStackLine    = $stackLine
    LogFile         = $log
  }
}

# 4) Show a concise table. Use $results | Format-List for full detail.
$results | Select-Object DumpFile, BugCheck, ProbablyCausedBy, Process, ImageName, Module, FailureBucketID | Format-Table -Auto
