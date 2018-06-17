#region >> Helper Functions

function Get-FilePath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$FileNameWExtension,

        [Parameter(Mandatory=$True)]
        [string[]]$DirectoriesToSearch
    )

    [System.Collections.ArrayList]$FoundFileItems = @()
    foreach ($Dir in $DirectoriesToSearch) {
        if (Test-Path $Dir) {
            Get-ChildItem -Path $Dir -File -Recurse -Filter $FileNameWExtension | Where-Object {
                ![bool]$($_.FullName -match "\\pkgs\\")
            } | foreach {
                $null = $FoundFileItems.Add($_)
            }
        }
        else {
            Write-Warning "The directory '$Dir' does not exist!"
        }
    }

    if ($FoundFileItems.Count -eq 0) {
        Write-Error "Unable to find '$FileNameWExtension' under the following directories:`n$($DirectoriesToSearch -join "`n")`nHalting!"
        $global:FunctionResult = "1"
        return
    }
    if ($FoundFileItems.Count -eq 1) {
        $FinalFilePath = $FoundFileItems[0].FullName
    }
    if ($FoundFileItems.Count -gt 1) {
        Write-Warning "Multiple '$FileNameWExtension' files were found! Available '$FileNameWExtension' files are as follows:"
        for ($i=0; $i -lt $FoundFileItems.Count; $i++) {
            Write-Host "$i) '$($FoundFileItems[$i].FullName)'"
        }
        $ValidChoiceNumbers = 0..$($FoundFileItems.Count-1)
        $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the '$FileNameWExtension' file that you would like to use"
        while ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
            Write-Host "'$ChoiceNumber' is not a valid choice! Valid choices are $($ValidChoiceNumbers -join ",")"
            $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the '$FileNameWExtension' file that you would like to use"
        }

        $FinalFilePath = $FoundFileItems[$ChoiceNumber].FullName
    }

    $FinalFilePath
}

function Add-ToPath {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$PathToAdd,

        [Parameter(Mandatory=$False)]
        [switch]$SystemPathOnly,

        [Parameter(Mandatory=$False)]
        [switch]$PSEnvPathOnly
    )

    if (!$PSEnvPathOnly) {
        $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $CurrentSystemPathArray = $CurrentSystemPath -split ";"
        if ($CurrentSystemPathArray -notcontains $PathToAdd) {
            $UpdatedSystemPath = "$PathToAdd;$CurrentSystemPath"
            Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value $UpdatedSystemPath
        }
    }

    if (!$SystemPathOnly) {
        $CurrentEnvPathArray = $env:Path -split ";"
        if ($CurrentEnvPathArray -notcontains $PathToAdd) {
            $env:Path = "$PathToAdd;$env:Path"
        }
    }
}

#endregion >> Helper Functions

function Set-AnacondaEnv {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$AnacondaDirectoryPath,

        [Parameter(Mandatory=$False)]
        [Alias("env")]
        [string]$Environment,

        [Parameter(Mandatory=$False)]
        [switch]$HideOutput,

        [Parameter(Mandatory=$False)]
        [switch]$ChangeMachineEnv
    )

    #region >> Prep

    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalPSEnvPath = $env:Path
    $OriginalPYTHONIOENCODING = $env:PYTHONIOENCODING
    $OriginalCONDA_EXE = $env:CONDA_EXE
    $OriginalCONDA_NEW_ENV = $env:CONDA_NEW_ENV
    $OriginalCONDA_PS1_BACKUP = $env:CONDA_PS1_BACKUP


    if ($AnacondaDirectoryPath) {
        $RegexTestA = $($AnacondaDirectoryPath | Select-String -Pattern "\\Anaconda[a-zA-Z0-9]+\\").Matches.Value
        $RegexTestB = $($AnacondaDirectoryPath | Select-String -Pattern "\\Anaconda[a-zA-Z0-9]+$").Matches.Value

        if ($RegexTestA) {
            $AnacondaDirectoryName = $($RegexTestA -replace '\\','').Trim()
        }
        elseif ($RegexTestB) {
            $AnacondaDirectoryName = $($RegexTestB -replace '\\','').Trim()
        }
    }
    else {
        $AnacondaDirectoryName = "Anaconda3"
    }

    # Make sure we can find the Anaconda3 directory
    if (!$PSBoundParameters['AnacondaDirectoryPath']) {
        $PotentialDirectoriesToSearch = @(
            "C:\tools\$AnacondaDirectoryName"
            "C:\ProgramData\$AnacondaDirectoryName"
            "$HOME\$AnacondaDirectoryName"
        )

        [array]$DirectoriesToSearch = $PotentialDirectoriesToSearch | foreach {
            if (Test-Path $_) {
                $_
            }
        }
    }
    else {
        if (!$(Test-Path $AnacondaDirectoryPath)) {
            Write-Error "The path '$AnacondaDirectoryPath' does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }

        [array]$DirectoriesToSearch = @($AnacondaDirectoryPath)
    }

    if ($Environment) {
        [array]$DirectoriesToSearch = foreach ($Dir in $DirectoriesToSearch) {
            $(Get-ChildItem -Path $Dir -Directory -Recurse -Filter $Environment).FullName
        }

        if ($DirectoriesToSearch.Count -eq 0) {
            Write-Error "Unable to find Anaconda Environment '$Environment'! Try again without the -Environment parameter. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Find python.exe
    try {
        $PythonExePath = Get-FilePath -FileNameWExtension "python.exe" -DirectoriesToSearch $DirectoriesToSearch -ErrorAction Stop
        if (!$PythonExePath) {throw "The Get-FilePath function failed! Halting!"}
        $PythonParentDir = $PythonExePath | Split-Path -Parent
        $PythonCmd = $PythonExePath | Split-Path -Leaf

        $FinalAnacondaDirectoryPath = $($PythonExePath -split "\\$AnacondaDirectoryName\\")[0] + "\$AnacondaDirectoryName"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Add python.exe to System PATH and $env:Path
    try {
        if ($ChangeMachineEnv) {
            $null = Add-ToPath -PathToAdd $PythonParentDir -ErrorAction Stop
        }
        else {
            $null = Add-ToPath -PathToAdd $PythonParentDir -PSEnvPathOnly -ErrorAction Stop
        }

        if (![bool]$(Get-Command $PythonCmd -ErrorAction SilentlyContinue)) {
            throw "Did not successfully add '$PythonCmd' to System and PowerShell environment paths! Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Set PYTHONIOENCODING PowerShell-Specific Environment Variable
    $env:PYTHONIOENCODING = python.exe -c 'import ctypes; print(ctypes.cdll.kernel32.GetACP())'
    if (!$env:PYTHONIOENCODING) {
        Write-Error "Unable to determine `$env:PYTHONIOENCODING! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ChangeMachineEnv) {
        # Set PYTHONIOENCODING System Environment Variable
        [Environment]::SetEnvironmentVariable("PYTHONIOENCODING", $env:PYTHONIOENCODING, "Machine")
    }

    # Set CONDA_NEW_ENV PowerShell-Specific Environment Variable
    $env:CONDA_NEW_ENV = $PythonParentDir
    if ($ChangeMachineEnv) {
        # Set CONDA_NEW_ENV System Environment Variable
        [Environment]::SetEnvironmentVariable("CONDA_NEW_ENV", $env:CONDA_NEW_ENV, "Machine")
    }

    # Find conda.exe
    try {
        # Ensure -DirectoriesToSearch is NOT environment specific, because conda.exe isn't environment specific
        # So use -DirectoriesToSearch $FinalAnacondaDirectoryPath...
        $CondaExePath = Get-FilePath -FileNameWExtension "conda.exe" -DirectoriesToSearch $FinalAnacondaDirectoryPath -ErrorAction Stop
        if (!$CondaExePath) {throw "The Get-FilePath function failed! Halting!"}
        $CondaParentDir = $CondaExePath | Split-Path -Parent
        $CondaCmd = $CondaExePath | Split-Path -Leaf
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Add conda.exe to System PATH and $env:Path
    try {
        if ($ChangeMachineEnv) {
            $null = Add-ToPath -PathToAdd $CondaParentDir -ErrorAction Stop
        }
        else {
            $null = Add-ToPath -PathToAdd $CondaParentDir -PSEnvPathOnly -ErrorAction Stop
        }

        if (![bool]$(Get-Command $CondaCmd -ErrorAction SilentlyContinue)) {
            throw "Did not successfully add '$CondaCmd' to System and PowerShell environment paths! Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Set CONDA_EXE PowerShell-Specific Environment Variable
    $env:CONDA_EXE = $CondaExePath
    if ($ChangeMachineEnv) {
        # Set CONDA_EXE System Environment Variable
        [Environment]::SetEnvironmentVariable("CONDA_EXE", $env:CONDA_EXE, "Machine")
    }

    # Set CONDA_PS1_BACKUP PowerShell-Specific Environment Variable
    $env:CONDA_PS1_BACKUP = $(Get-Location).Path
    if ($ChangeMachineEnv) {
        # Set CONDA_PS1_BACKUP System Environment Variable
        [Environment]::SetEnvironmentVariable("CONDA_PS1_BACKUP", $env:CONDA_PS1_BACKUP, "Machine")
    }

    $NewSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $NewPSEnvPath = $env:Path
    $NewPYTHONIOENCODING = $env:PYTHONIOENCODING
    $NewCONDA_EXE = $env:CONDA_EXE
    $NewCONDA_NEW_ENV = $env:CONDA_NEW_ENV
    $NewCONDA_PS1_BACKUP = $env:CONDA_PS1_BACKUP

    $FinalNewSystemPath = if ($OriginalSystemPath -ne $NewSystemPath) {$NewSystemPath} else {"NoChange"}
    $FinalPSEnvPath = if ($OriginalPSEnvPath -ne $NewPSEnvPath) {$NewPSEnvPath} else {"NoChange"}
    $FinalPyEn = if ($OriginalPYTHONIOENCODING -ne $NewPYTHONIOENCODING) {$NewPYTHONIOENCODING} else {"NoChange"}
    $FinalCondaExe = if ($OriginalCONDA_EXE -ne $NewCONDA_EXE) {$NewCONDA_EXE} else {"NoChange"}
    $FinalCondaNewEnv = if ($OriginalCONDA_NEW_ENV -ne $NewCONDA_NEW_ENV) {$NewCONDA_NEW_ENV} else {"NoChange"}
    $FInalCondaPS1 = if ($OriginalCONDA_PS1_BACKUP -ne $NewCONDA_PS1_BACKUP) {$NewCONDA_PS1_BACKUP} else {"NoChange"}

    if (!$HideOutput) {
        [pscustomobject]@{
            SystemPathChanges       = @{Original = $OriginalSystemPath; New = $FinalNewSystemPath}
            PSEnvPathChanges        = @{Original = $OriginalPSEnvPath; New = $FinalPSEnvPath}
            PYTHONIOENCODING        = @{Original = $OriginalPYTHONIOENCODING; New = $FinalPyEn}
            CONDA_EXE               = @{Original = $OriginalCONDA_EXE; New = $FinalCondaExe}
            CONDA_NEW_ENV           = @{Original = $OriginalCONDA_NEW_ENV; New = $FinalCondaNewEnv}
            CONDA_PS1_BACKUP        = @{Original = $OriginalCONDA_NEW_ENV; New = $FInalCondaPS1}
        }

        Write-Host "Environment set successfully!" -ForegroundColor Green
    }
}

function Revert-AnacondaEnv {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [pscustomobject]$SetAnacondaEnvOutput
    )

    # Validate $SetAnacondaEnvOutput object
    $NotePropertiesOutputShouldHave = @(
        "SystemPathChanges"
        "PSEnvPathChanges"
        "PYTHONIOENCODING"
        "CONDA_EXE"
        "CONDA_NEW_ENV"
        "CONDA_PS1_BACKUP"
    )

    foreach ($ValidProperty in $NotePropertiesOutputShouldHave) {
        if ($($SetAnacondaEnvOutput | Get-Member).Name -notcontains $ValidProperty) {
            Write-Error "The pscustomobject provided to the -SetAnacondaEnvOutput parameter is invalid! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # We're not going to halt on any errors, because we want to report all errors at the end, so
    # we need to collect success/failure as we go...
    [System.Collections.ArrayList]$SuccessfulReversions = @()
    [System.Collections.ArrayList]$FailedReversions = @()

    # Revert System Path and $env:Path
    try {
        if ($SetAnacondaEnvOutput.SystemPathChanges.New -ne "NoChange") {
            $SetItemPropertySplatParams = @{
                Path        = "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment"
                Name        = "PATH"
                Value       = $SetAnacondaEnvResult.SystemPathChanges.Original
            }
            Set-ItemProperty @SetItemPropertySplatParams

            $SystemPathState = [pscustomobject]@{
                EnvironmentCharacteristic   = "SystemPath"
                AttemptedValue              = $SetAnacondaEnvResult.SystemPathChanges.Original
                CurrentValue                = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            }
            $null = $SuccessfulReversions.Add($SystemPathState)
        }
    }
    catch {
        Write-Warning $($_ | Out-String)
        Write-Warning "Unable to revert System Path!"

        $SystemPathState = [pscustomobject]@{
            EnvironmentCharacteristic   = "SystemPath"
            AttemptedValue              = $SetAnacondaEnvResult.SystemPathChanges.Original
            CurrentValue                = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        }
        $null = $FailedReversions.Add($SystemPathState)
    }

    if ($SetAnacondaEnvOutput.PSEnvPathChanges.New -ne "NoChange") {
        $env:Path = $SetAnacondaEnvOutput.PSEnvPathChanges.Original

        $PSEnvPathState = [pscustomobject]@{
            EnvironmentCharacteristic   = "PSEnvPath"
            AttemptedValue              = $SetAnacondaEnvOutput.PSEnvPathChanges.Original
            CurrentValue                = $env:Path
        }
        $null = $SuccessfulReversions.Add($PSEnvPathState)
    }

    # Revert $env:PYTHONIOENCODING...
    if ($SetAnacondaEnvOutput.PYTHONIOENCODING.New -ne "NoChange") {
        try {
            $env:PYTHONIOENCODING = $SetAnacondaEnvOutput.PYTHONIOENCODING.Original
            [Environment]::SetEnvironmentVariable("PYTHONIOENCODING", $SetAnacondaEnvOutput.PYTHONIOENCODING.Original, "Machine")

            $PyIOEnState = [pscustomobject]@{
                EnvironmentCharacteristic   = "PYTHONIOENCODING"
                AttemptedValue              = $SetAnacondaEnvOutput.PYTHONIOENCODING.Original
                CurrentValue                = $SetAnacondaEnvOutput.PYTHONIOENCODING.Original
            }
            $null = $SuccessfulReversions.Add($PyIOEnState)
        }
        catch {
            Write-Warning $($_ | Out-String)
            Write-Warning "Unable to revert the System Environment Variable 'PYTHONIOENCODING'!"

            $PyIOEnState = [pscustomobject]@{
                EnvironmentCharacteristic   = "PYTHONIOENCODING"
                AttemptedValue              = $SetAnacondaEnvOutput.PYTHONIOENCODING.Original
                CurrentValue                = $SetAnacondaEnvOutput.PYTHONIOENCODING.New
            }
            $null = $FailedReversions.Add($PyIOEnState)
        }
    }

    if ($SetAnacondaEnvOutput.CONDA_EXE.New -ne "NoChange") {
        try {
            $env:CONDA_EXE = $SetAnacondaEnvOutput.CONDA_EXE.Original
            [Environment]::SetEnvironmentVariable("CONDA_EXE", $SetAnacondaEnvOutput.CONDA_EXE.Original, "Machine")

            $CondaExeState = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_EXE"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_EXE.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_EXE.Original
            }
            $null = $SuccessfulReversions.Add($CondaExeState)
        }
        catch {
            Write-Warning $($_ | Out-String)
            Write-Warning "Unable to revert the System Environment Variable 'CONDA_EXE'!"

            $CondaExeState = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_EXE"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_EXE.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_EXE.New
            }
            $null = $FailedReversions.Add($CondaExeState)
        }
    }

    if ($SetAnacondaEnvOutput.CONDA_NEW_ENV.New -ne "NoChange") {
        try {
            $env:CONDA_NEW_ENV = $SetAnacondaEnvOutput.CONDA_NEW_ENV.Original
            [Environment]::SetEnvironmentVariable("CONDA_NEW_ENV", $SetAnacondaEnvOutput.CONDA_NEW_ENV.Original, "Machine")

            $CondaNewEnvState = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_NEW_ENV"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_NEW_ENV.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_NEW_ENV.Original
            }
            $null = $SuccessfulReversions.Add($CondaNewEnvState)
        }
        catch {
            Write-Warning $($_ | Out-String)
            Write-Warning "Unable to revert the System Environment Variable 'CONDA_NEW_ENV'!"

            $CondaNewEnvState = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_NEW_ENV"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_NEW_ENV.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_NEW_ENV.New
            }
            $null = $FailedReversions.Add($CondaNewEnvState)
        }
    }

    if ($SetAnacondaEnvOutput.CONDA_PS1_BACKUP.New -ne "NoChange") {
        try {
            $env:CONDA_PS1_BACKUP = $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.Original
            [Environment]::SetEnvironmentVariable("CONDA_PS1_BACKUP", $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.Original, "Machine")

            $CondaPS1State = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_PS1_BACKUP"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.Original
            }
            $null = $SuccessfulReversions.Add($CondaPS1State)
        }
        catch {
            Write-Warning $($_ | Out-String)
            Write-Warning "Unable to revert the System Environment Variable 'CONDA_PS1_BACKUP'!"

            $CondaPS1State = [pscustomobject]@{
                EnvironmentCharacteristic   = "CONDA_PS1_BACKUP"
                AttemptedValue              = $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.Original
                CurrentValue                = $SetAnacondaEnvOutput.CONDA_PS1_BACKUP.New
            }
            $null = $FailedReversions.Add($CondaPS1State)
        }
    }

    # Prep Output
    $Output = @{}

    if ($SuccessfulReversions.Count -gt 0) {
        $Output.Add("SuccessfulReversions",$SuccessfulReversions)
    }
    if ($FailedReversions.Count -gt 0) {
        $Output.Add("FailedReversions",$FailedReversions)
    }

    if ($SuccessfulReversions.Count -eq 0 -and $FailedReversions.Count -eq 0) {
        Write-Host "Nothing was reverted because nothing was changed by the Set-AnacondaEnv function in the first place!" -ForegroundColor Green
    }
    if ($SuccessfulReversions.Count -gt 0 -and $FailedReversions.Count -eq 0) {
        Write-Host "Reverted environment successfully!" -ForegroundColor Green
    }
    
    $Output
}


# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUqjpijaQ75lOH/N2pbwS31m1n
# CbGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFESmXFzSnf6NqYYU
# p7kvJV8aKGi4MA0GCSqGSIb3DQEBAQUABIIBAEuqiFkyCc4RYqG5Qge++TqXyGaP
# IoynAE5R5Ks3jHuaiFfytQjeNeGMBpCJT/39qk4U9Nx2qDv/gw89g0eW0Rmy4Lcw
# yVrNDb3SeLugGgBxP1tYIS6gB7I6j0p/SasiJVLPsk2JKNlgY2vm5MeQsQ300sfS
# pLMW1i+YhzyrsK+tfj22aibaqYfZJy6XpTCAtRigss1UPShkiWjqODLgj4WwMsPF
# EMVjUJknnwDozy+Q9cHaxPgOmBCsr0ByBF7G351n9dTmEFWjQcyFoCj+e3SDYYVQ
# LAvpoltGXniZA+IRnIrAx9t5c1E7gN3nYmbudCenVno4FDP+Q5+BYR29qCE=
# SIG # End signature block
