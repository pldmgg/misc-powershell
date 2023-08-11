# Clean up the PATH environment variable
$env:Path = ($env:Path -split ';' | Sort-Object | Get-Unique) -join ';'
$FinalPath = $env:Path.TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine).TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User).TrimEnd(';')
$env:Path = ($FinalPath -split ';' | Sort-Object | Get-Unique) -join ';'

# Clean up environment variables loading (or not) from various sources
$userEnvironmentVariables = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::User)
$machineEnvironmentVariables = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Machine)
$pwshEnvironmentVariables = [System.Environment]::GetEnvironmentVariables([System.EnvironmentVariableTarget]::Process)

$finalHashtable = @{}

foreach ($key in $userEnvironmentVariables.Keys) {
    $value = $userEnvironmentVariables[$key]
    if ($value -ne $machineEnvironmentVariables[$key] -and $value -ne $pwshEnvironmentVariables[$key]) {
        $finalHashtable[$key] = $value
    }
}

foreach ($key in $machineEnvironmentVariables.Keys) {
    $value = $machineEnvironmentVariables[$key]
    if ($value -ne $userEnvironmentVariables[$key] -and $value -ne $pwshEnvironmentVariables[$key]) {
        $finalHashtable[$key] = $value
    }
}

foreach ($key in $pwshEnvironmentVariables.Keys) {
    $value = $pwshEnvironmentVariables[$key]
    if ($value -ne $userEnvironmentVariables[$key] -and $value -ne $machineEnvironmentVariables[$key]) {
        $finalHashtable[$key] = $value
    }
}

# Set the cleaned up environment variables
foreach ($key in $finalHashtable.Keys) {
    $value = $finalHashtable[$key]
    [System.Environment]::SetEnvironmentVariable($key,$value)
}

# Set Aliases
function hist {(Get-Content (Get-PSReadLineOption).HistorySavePath)}

function grep {
  [CmdletBinding()]
  Param(
    [Parameter(ValueFromPipeline)]
    $item,

    [Parameter(Position = 0)]
    [string]$Pattern
  )

  process {
    $item | Select-String -Pattern $Pattern
  }
}