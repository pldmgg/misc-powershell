# Clean up the PATH environment variable
$env:Path = ($env:Path -split ';' | Sort-Object | Get-Unique) -join ';'
$FinalPath = $env:Path.TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine).TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User).TrimEnd(';')
$env:Path = ($FinalPath -split ';' | Sort-Object | Get-Unique) -join ';'

$machinePath = ([System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine).TrimEnd(';') -split ';' | Sort-Object | Get-Unique) -join ';'
$userPath = ([System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User).TrimEnd(';') -split ';' | Sort-Object | Get-Unique) -join ';'
$processPath = ($env:Path.TrimEnd(';') -split ';' | Sort-Object | Get-Unique) -join ';'


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

# Set Helper Functions
function Update-Path {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$PathString,
    
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet('User', 'Machine', 'Process')]
        [string]$Type
    )

    $PathString = $PathString.Trim(';')
    $originalPath = Invoke-Expression "([System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::$Type).TrimEnd(';') -split ';' | Sort-Object | Get-Unique) -join ';'"
    $newPath = (($originalPath + ';' + $PathString).TrimEnd(';') -split ';' | Sort-Object | Get-Unique) -join ';'
    [System.Environment]::SetEnvironmentVariable('PATH', $newPath, $Type)
}


# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

# Install/Import PowerShellAI module
if (!$(Get-Module -ListAvailable 'PowerShellAI' -ErrorAction SilentlyContinue)) {
    try {
        $InstallModuleResult = Install-Module 'PowerShellAI' -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module $ModuleName -ErrorAction Stop
        Set-ChatSessionOption -model 'gpt-4' -ErrorAction Stop
        Write-Host "PowerShellAI loaded with GPT-4 model."
    } catch {
        Write-Warning $_.Exception.Message
    }
}