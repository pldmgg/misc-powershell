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

function Install-TTYD {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NetworkInterfaceAlias
    )

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\TTYDInstall"
    $LogFilePath = $LogFileDir + '\' + 'ttyd_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'ttyd.exe'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    if (!$(Get-Elevation)) {
        $ErrMsg = "You need to run this script as an administrator."
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    $Owner = "tsl0922"
    $Repo = "ttyd"
    $ReleaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $Asset = $ReleaseInfo.assets | Where-Object {$_.Name -match "win32\.exe"}
    $AssetUrl = $Asset.browser_download_url
    $AssetName = $Asset.Name
    $AssetVersion = [version]$AssetUrl.Split("/")[-2]
    $HostIPPrep = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -match [regex]::Escape($NetworkInterfaceAlias)}
    if (!$HostIPPrep) {
        $ErrMsg = "Unable to find Network Interface that matches '$NetworkInterfaceAlias'. Halting!"
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
    $HostIP = $HostIPPrep.IPAddress

    # Get local binary file version
    $InstallDir = "C:\Scripts\bin"
    $LocalBinPath = $InstallDir + "\" + $AssetName
    $LocalBinVersion = $(Get-Item -Path $LocalBinPath -ErrorAction SilentlyContinue).VersionInfo.FileVersion
    $FinalBinPath = $InstallDir + "\" + "ttyd.exe"

    # Download the latest release if it's newer than the local binary
    try {
        if ($AssetVersion -gt $LocalBinVersion) {
            Invoke-WebRequest -Uri $AssetUrl -OutFile $LocalBinPath -ErrorAction Stop
            Write-Host "Downloaded the latest release of ttyd to: $LocalBinPath"

            if (!$(Test-Path $InstallDir)) {
                $null = New-Item -Path $InstallDir -ItemType Directory -Force
            }
            $null = Copy-Item -Path $LocalBinPath -Destination $FinalBinPath -Force
        }

        # Output
        Get-Item $FinalBinPath -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Configure Firewall Rules
    $Protocols = @("TCP", "UDP")
    foreach ($Protocol in $Protocols) {
        $AllowRuleName = "Allow_ttyd_" + $Protocol + "_traffic"
        $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
        if (!$AllowRule) {
            $null = New-NetFirewallRule -DisplayName $AllowRuleName -Direction Inbound -Program $FinalBinPath -Protocol $Protocol -LocalPort 7681 -LocalAddress $HostIP -Action Allow -Profile Domain,Public,Private
        }

        $BlockRuleName = "Block_ttyd"
        $BlockRule = Get-NetFirewallRule -DisplayName $BlockRuleName -ErrorAction SilentlyContinue
        if (!$BlockRule) {
            $null = New-NetFirewallRule -DisplayName $BlockRuleName -Direction Inbound -Program $FinalBinPath -Action Block -Profile Domain,Public,Private
        }
    }

    try {
        Enable-TTYD -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}

function Enable-TTYD {
    [CmdletBinding()]
    Param()

    $LogFileDir = "C:\Scripts\logs\TTYDEnable"
    $LogFilePath = $LogFileDir + '\' + 'ttyd_enable_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    if (!$(Get-Elevation)) {
        $ErrMsg = "You need to run this script as an administrator."
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Disable the Block rule and make sure the Allow rule is enabled
    $Protocols = @("TCP", "UDP")
    try {
        foreach ($Protocol in $Protocols) {
            $AllowRuleName = "Allow_ttyd_" + $Protocol + "_traffic"
            $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
            if (!$AllowRule) {
                throw "Unable to find the Windows Firewall Rule called '$AllowRuleName'! Halting!"
            } else {
                $AllowRule | Enable-NetFirewallRule -ErrorAction Stop
            }

            $BlockRuleName = "Block_ttyd"
            $BlockRule = Get-NetFirewallRule -DisplayName $BlockRuleName -ErrorAction SilentlyContinue
            if (!$BlockRule) {
                throw "Unable to find the Windows Firewall Rule called '$BlockRuleName'! Halting!"
            } else {
                $BlockRule | Disable-NetFirewallRule -ErrorAction Stop
            }
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}

function Disable-TTYD {
    [CmdletBinding()]
    Param()

    $LogFileDir = "C:\Scripts\logs\TTYDDisable"
    $LogFilePath = $LogFileDir + '\' + 'ttyd_disable_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    if (!$(Get-Elevation)) {
        $ErrMsg = "You need to run this script as an administrator."
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Enable the Block rule and make sure the Allow rule is disabled
    $Protocols = @("TCP", "UDP")
    try {
        foreach ($Protocol in $Protocols) {
            $AllowRuleName = "Allow_ttyd_" + $Protocol + "_traffic"
            $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
            if (!$AllowRule) {
                throw "Unable to find the Windows Firewall Rule called '$AllowRuleName'! Halting!"
            } else {
                $AllowRule | Disable-NetFirewallRule -ErrorAction Stop
            }

            $BlockRuleName = "Block_ttyd"
            $BlockRule = Get-NetFirewallRule -DisplayName $BlockRuleName -ErrorAction SilentlyContinue
            if (!$BlockRule) {
                throw "Unable to find the Windows Firewall Rule called '$BlockRuleName'! Halting!"
            } else {
                $BlockRule | Enable-NetFirewallRule -ErrorAction Stop
            }
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}


function Create-TTYDScheduledTask {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NetworkInterfaceAlias, # Example: "ZeroTier One [8bkp1rxn07zvy5tfh]"
        
        [Parameter(Mandatory=$True)]
        [pscredential]$TaskUserCreds,

        [Parameter(Mandatory=$False)]
        [string]$TTYDPort = "7681",

        [Parameter(Mandatory=$False)]
        [string]$TTYDWebUser = "ttydadmin",
        
        [Parameter(Mandatory=$False)]
        [string]$TTYDWebPassword = "MyPassword123!"
    )

    # NOTE: To view the resulting task in Task Scheduler GUI, navigate:
    # Task Scheduler Library -> Microsoft -> Windows -> PowerShell -> Scheduled Jobs -> Network Disconnect Log
    $LogFileDir = "C:\Scripts\logs\CreateTTYDScheduledTask_$env:COMPUTERNAME"
    $LogFilePath = $LogFileDir + '\' + 'create_ttyd_schdtask_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'ttyd.exe'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    if (!$(Get-Elevation)) {
        $ErrMsg = "You need to run this script as an administrator."
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    [System.Collections.Generic.List[String]]$Modules = @('TTYDModule')
    [System.Collections.Generic.List[String]]$FunctionsForRemoteUse = @()
    foreach ($ModuleName in $Modules) {
        $ModulePath = "C:\Scripts\powershell\$ModuleName.psm1"
        if (!$(Test-Path $ModulePath)) {
            $ErrMsg = "Unable to find the $ModuleName.psm1 file! Halting!"
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }

        try {
            Import-Module $ModulePath -ErrorAction Stop

            # Prepare the Functions for Remote Use
            $Module = Get-Module -Name $ModuleName
            [System.Collections.Generic.List[String]]$ModuleFunctions = $Module.ExportedFunctions.Keys.GetEnumerator() | foreach {$_}
            foreach ($Func in $ModuleFunctions) {
                $CmdString = "`${Function:$Func}.Ast.Extent.Text"
                $null = $FunctionsForRemoteUse.Add($(Invoke-Expression $CmdString) + "`n")
            }
        } catch {
            $ErrMsg = $_.Exception.Message
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }
    }

    # This function MUST run in Windows PowerShell (not PowerShell Core)
    if ($PSVersionTable.PSEdition -ne "Desktop") {
        $ErrMsg = "This function must run in Windows PowerShell (not PowerShell Core)."
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Create the TTYD Scheduled Task as the Active User
    $ModulePath = $(Get-Module "TTYDModule").Path
    $TaskUser = $TaskUserCreds.UserName
    $TaskName = "Run TTYD as $TaskUser"

    $ScriptBlockAsStringPart1 = @"
`$LogFileDir = '$LogFileDir'
`$LogFilePath = '$LogFilePath'
`$BinFileDir = '$BinFileDir'
`$BinFilePath = '$BinFilePath'
`$NetworkInterfaceAlias = '$NetworkInterfaceAlias'
`$TaskUser = '$TaskUser'
`$ModulePath = '$ModulePath'
`$AltModulePath = 'C:\Scripts\bin\DynamicallyCreatedTTYDModule.psm1'
`$TTYDPort = '$TTYDPort'
`$TTYDWebUser = '$TTYDWebUser'
`$TTYDWebPassword = '$TTYDWebPassword'
"@
    $ScriptBlockAsStringPart2 = @'
try {
    if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
    if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
} catch {
    $ErrMsg = $_.Exception.Message
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $ErrMsg
    return
}

try {
    if (!$(Test-Path $ModulePath)) {
        $null = Import-Module $AltModulePath -ErrorAction Stop
    } else {
        $null = Import-Module $ModulePath -ErrorAction Stop
    }
    
} catch {
    $ErrMsg = $_.Exception.Message
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $ErrMsg
    return
}

if (!$(Test-Path $BinFilePath)) {
    try {
        Install-TTYD -NetworkInterfaceAlias $NetworkInterfaceAlias -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}

# Start the ttyd. Specify port, basic credentials for logging into website, interface
$RunLogFile = $LogFileDir + '\' + 'ttyd_schdtask_run_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
$null = Add-Content -Path $RunLogFile -Value "Running ttyd as $TaskUser on port 7681..."
$TTYDCredString = $TTYDWebUser + ':' + $TTYDWebPassword
& $BinFilePath --port $TTYDPort --writable --max-clients 1 --credential $TTYDCredString --once --reconnect powershell
'@
    $ScriptBlockAsString = $ScriptBlockAsStringPart1 + "`n" + $ScriptBlockAsStringPart2

    try {
        $ExistingTaskCheck = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($ExistingTaskCheck) {
            $ExistingTaskCheck | Unregister-ScheduledTask -Confirm:$False -ErrorAction Stop
        }

        <#
        $ScriptBlock = [ScriptBlock]::Create($ScriptBlockAsString)
        $TenSecondsFromNow = $(Get-Date).Add($(New-TimeSpan -Seconds 10))
        $TaskTrigger = New-JobTrigger -Once -At $TenSecondsFromNow
        $Options = New-ScheduledJobOption -MultipleInstancePolicy IgnoreNew -WakeToRun -RunElevated -StartIfOnBattery -ContinueIfGoingOnBattery
        Register-ScheduledJob -Name $TaskName -Trigger $TaskTrigger -ScheduledJobOption $Options -Credential $TaskUserCreds -ScriptBlock $ScriptBlock
        #>
        
        $ScriptOutputPath = "$BinFileDir\RunTTYD" + "_as_$TaskUser" + ".ps1"
        $ScriptBlockAsString | Out-File -FilePath $ScriptOutputPath -Encoding ascii -Force
        $TenSecondsFromNow = $(Get-Date).Add($(New-TimeSpan -Seconds 10))
        $TaskTrigger = New-ScheduledTaskTrigger -Once -At $TenSecondsFromNow
        $Options = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit $(New-TimeSpan -Hours 1)
        $Passwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($TaskUserCreds.Password))
        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& $ScriptOutputPath`""
        Register-ScheduledTask -TaskName $TaskName -Trigger $TaskTrigger -Settings $Options -User $TaskUserCreds.UserName -Password $Passwd -Action $Action -ErrorAction Stop

        Write-Host "Please wait 20 seconds..."        
        Start-Sleep -Seconds 20
        $TTYDProcess = Get-Process ttyd -ErrorAction SilentlyContinue
        if ($TTYDProcess) {
            $TTYDProcess | Stop-Process -Force
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}