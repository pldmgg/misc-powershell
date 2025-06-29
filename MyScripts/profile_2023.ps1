# Clean up the PATH environment variable
#$env:Path = ($env:Path -split ';' | Sort-Object | Get-Unique) -join ';'
#$FinalPath = $env:Path.TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine).TrimEnd(';') + ';' + [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User).TrimEnd(';')
#$env:Path = ($FinalPath -split ';' | Sort-Object | Get-Unique) -join ';'

$env:Path = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User).TrimEnd(';') + ';' +
            [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine).TrimEnd(';') | Get-Unique

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
    if (!(Test-Path $PathString -ErrorAction SilentlyContinue)) {
        Write-Error "Path '$PathString' does not exist! Halting!"
        return
    }
    if (!(Get-Item $PathString -ErrorAction SilentlyContinue).PSIsContainer) {
        Write-Error "Path must be a directory! Halting!"
        return
    }
    
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


# For dealing with using "sudo" in PSSessions on Remote Linux machines
function Cache-SudoPwd {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [securestring]$SudoPass,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession
    )

    if ($PSSession) {
        if ($PSVersionTable.PSVersion -ge [version]'7.1') {
            Invoke-Command $PSSession -ScriptBlock {
                param([securestring]$SudoPassSS)
                $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPassSS))) | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @($SudoPass)
        } else {
            Invoke-Command $PSSession -ScriptBlock {
                param([String]$SudoPassPT)
                $null = $SudoPassPT | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass)))
        }
    } else {
        if (!$PSSenderInfo) {
            Write-Error -Message "You must be running this function from within a PSSession or provide a PSSession object via the -PSSession parameter! Halting!"
            return
        }
        $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass))) | sudo -S whoami 2>&1
        if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
    }
}
Set-Alias -Name "presudo" -Value Cache-SudoPwd
function secureprompt {Read-Host 'Enter sudo password' -AsSecureString}
function presudo {Cache-SudoPwd -SudoPass $(Read-Host 'Enter sudo password' -AsSecureString)}


function Process-ICM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$True)]
        [string]$Command,

        [Parameter(Mandatory=$False)]
        [ValidateSet('String','Other')]
        [string]$OutputType = 'Other'
    )

    if ($OutputType -eq 'String') {
        # Validate [string]$Command has a line in it that indicates $OutputThatICareAbout is below here...
        $OutputIndicatorLine = ($Command -split "`n") -match 'SuccessOutput'
        if (!$OutputIndicatorLine) {
            Write-Error "The Command you provided does not have a line with the string 'SuccessOutput' (including single quotes)`
            that indicates where the output you care about is. Halting!"
            return
        }

        Invoke-Command -Session $PSSession {Invoke-Expression -Command $using:Command} -ErrorVariable icmErrs 2>&1 | Tee-Object -Variable icmAllOutput *>$null

        $ErrsThatICareAbout = $icmErrs.Exception.Message -notmatch '^NotSpecified'
        #if ($ErrsThatICareAbout.Count -gt 0) {$ErrsThatICareAbout | foreach {Write-Error $_}}
        $OutputThatICareAbout = $icmAllOutput[($icmAllOutput.IndexOf('SuccessOutput') + 1)..$icmAllOutput.Count]
        #if ($OutputThatICareAbout.Count -gt 0) {$OutputThatICareAbout | foreach {$_}}

        [pscustomobject]@{
            Errors = $icmErrs
            Output = $icmAllOutput
            RealErrors = $ErrsThatICareAbout
            RealOutput = $OutputThatICareAbout
        }

        Write-Host '$_.RealOutput is [string[]]'
    } else {
        Invoke-Command -Session $PSSession {Invoke-Expression -Command $using:Command} -ErrorVariable icmErrs 2>&1 | Tee-Object -Variable icmAllOutput *>$null

        $ErrsThatICareAbout = $icmErrs.Exception.Message -notmatch '^NotSpecified'
        #if ($ErrsThatICareAbout.Count -gt 0) {$ErrsThatICareAbout | foreach {Write-Error $_}}
        $OutputThatICareAbout = @($icmAllOutput) | Where-Object {$_ -isnot [System.Management.Automation.ErrorRecord]}
        #if ($OutputThatICareAbout.Count -gt 0) {$OutputThatICareAbout | foreach {$_}}
        if ($OutputThatICareAbout -match 'SuccessOutput') {
            $LineContent = $OutputThatICareAbout | Where-Object {$_ -match 'SuccessOutput'}
            $OutputThatICareAbout = $OutputThatICareAbout[($OutputThatICareAbout.IndexOf($LineContent) + 1)..$OutputThatICareAbout.Count]
        }

        [pscustomobject]@{
            Errors = $icmErrs
            Output = $icmAllOutput
            RealErrors = $ErrsThatICareAbout
            RealOutput = $OutputThatICareAbout
        }

        if ($OutputThatICareAbout.Count -gt 0) {
            $objectTypes = $OutputThatICareAbout | foreach {$_.GetType().FullName}
            Write-Host "`$_.RealOutput.Count is $($OutputThatICareAbout.Count) and it contains these types of objects (in order): $($objectTypes -join ', ')`n"
        } elseif (!$icmAllOutput) {
            Write-Host "You received *no* output at all...including no errors. This might be okay."
        } else {
            Write-Host "You received *no* relevant output. Check the contents of `$_.RealErrors and `$_.Output to see what happened."
        }
    }
}


function Get-Elevation {
    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )
  
        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
  
        if($currentPrincipal.IsInRole($administratorsRole)) {
            return $true
        }
        else {
            return $false
        }
    }
    
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -eq "root") {
            return $true
        }
        else {
            return $false
        }
    }
}