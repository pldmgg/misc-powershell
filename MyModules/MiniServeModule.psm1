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

function Enable-MiniServe {
    [CmdletBinding()]
    Param()

    $LogFileDir = "C:\Scripts\logs\MiniServeEnable"
    $LogFilePath = $LogFileDir + '\' + 'miniserve_enable_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
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
            $AllowRuleName = "Allow_miniserve_" + $Protocol + "_traffic"
            $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
            if (!$AllowRule) {
                throw "Unable to find the Windows Firewall Rule called '$AllowRuleName'! Halting!"
            } else {
                $AllowRule | Enable-NetFirewallRule -ErrorAction Stop
            }

            $BlockRuleName = "Block_miniserve"
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

function Disable-MiniServe {
    [CmdletBinding()]
    Param()

    $LogFileDir = "C:\Scripts\logs\MiniServeDisable"
    $LogFilePath = $LogFileDir + '\' + 'miniserve_disable_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
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
            $AllowRuleName = "Allow_miniserve_" + $Protocol + "_traffic"
            $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
            if (!$AllowRule) {
                throw "Unable to find the Windows Firewall Rule called '$AllowRuleName'! Halting!"
            } else {
                $AllowRule | Disable-NetFirewallRule -ErrorAction Stop
            }

            $BlockRuleName = "Block_miniserve"
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


function Install-MiniServe {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NetworkInterfaceAlias
    )

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\MiniServeInstall"
    $LogFilePath = $LogFileDir + '\' + 'miniserve_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'miniserve.exe'
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

    $Owner = "svenstaro"
    $Repo = "miniserve"
    $ReleaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $Asset = $ReleaseInfo.assets | Where-Object {$_.Name -match "windows"}
    $AssetUrl = $Asset.browser_download_url
    $AssetName = $Asset.Name
    $AssetVersion = [version]$($AssetUrl.Split("/")[-2] -replace 'v','')
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
    $LocalBinPath = $InstallDir + "\" + "miniserve.exe"
    $LocalBinInfo = Get-Item -Path $LocalBinPath -ErrorAction SilentlyContinue
    $LocalBinVersion = $LocalBinInfo.VersionInfo.FileVersion

    # Download the latest release if it's newer than the local binary
    try {
        if ($Asset.created_at -lt $LocalBinInfo.CreationTime -and $Asset.size -ne $LocalBinInfo.Length) {
            $DownloadPath = "$env:USERPROFILE\Downloads\$AssetName"
            Invoke-WebRequest -Uri $AssetUrl -OutFile $DownloadPath -ErrorAction Stop
            Write-Host "Downloaded the latest release of ttyd to: $DownloadPath"

            if (!$(Test-Path $InstallDir)) {
                $null = New-Item -Path $InstallDir -ItemType Directory -Force
            }
            $null = Move-Item -Path $DownloadPath -Destination $LocalBinPath -Force
        }

        # Output
        Get-Item $BinFilePath -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Configure Firewall Rules
    $Protocols = @("TCP", "UDP")
    foreach ($Protocol in $Protocols) {
        $AllowRuleName = "Allow_miniserve_" + $Protocol + "_traffic"
        $AllowRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
        if (!$AllowRule) {
            $null = New-NetFirewallRule -DisplayName $AllowRuleName -Direction Inbound -Program $LocalBinPath -Protocol $Protocol -LocalPort 8080 -LocalAddress $HostIP -Action Allow -Profile Domain,Public,Private
        }

        $BlockRuleName = "Block_miniserve"
        $BlockRule = Get-NetFirewallRule -DisplayName $AllowRuleName -ErrorAction SilentlyContinue
        if (!$BlockRule) {
            $null = New-NetFirewallRule -DisplayName $BlockRuleName -Direction Inbound -Program $LocalBinPath -Action Block -Profile Domain,Public,Private
        }
    }

    try {
        Enable-MiniServe -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}


function Install-PSExec {
    [CmdletBinding()]
    Param()

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\PSExecInstall"
    $LogFilePath = $LogFileDir + '\' + 'psexec_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Windows\System32"
    $BinFilePath = $BinFileDir + '\' + 'psexec.exe'
    $DownloadDir = "C:\Scripts\temp"
    $DownloadPath = $DownloadDir + '\' + 'PSTools.zip'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $DownloadDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
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

    $AssetVersion = $(Get-Item -Path $BinFilePath -ErrorAction SilentlyContinue).VersionInfo.FileVersion

    # Set the download URL and destination path
    $AssetUrl = "https://download.sysinternals.com/files/PSTools.zip"
    $ExtractionFolder = "$DownloadDir\PSTools"

    try {
        # Download the PsTools zip file
        $null = Invoke-WebRequest -Uri $AssetUrl -OutFile $DownloadPath -ErrorAction Stop

        # Extract the PsTools zip file
        Expand-Archive -Path $DownloadPath -DestinationPath $ExtractionFolder -Force -ErrorAction Stop

        $NewAssetVersion = $(Get-Item -Path "$ExtractionFolder\psexec.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion

        if ($AssetVersion -lt $NewAssetVersion) {
            # Move PsExec.exe to C:\Windows\System32
            $null = Copy-Item -Path "$ExtractionFolder\psexec.exe" -Destination $BinFilePath -Force -ErrorAction Stop
        }

        # Clean up the temporary files
        $null = Remove-Item -Path $DownloadPath -Force -ErrorAction Stop
        $null = Remove-Item -Path $ExtractionFolder -Recurse -Force -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
}

function Prompt-ActiveUserForSecureString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.2.250"

        #[Parameter(Mandatory=$False)]
        #[string]$ReturnSSHUserName, # Example: "adminuser"

        #[Parameter(Mandatory=$True)]
        #[string]$ReturnIPAddress, # Example: "192.168.2.81"

        [Parameter(Mandatory=$True)]
        [string]$MiniServeNetworkInterfaceAlias, # Example: "ZeroTier One [8bkp1rxn07zvy5tfh]"

        [Parameter(Mandatory=$False)]
        [switch]$RemovePwdFile,

        [Parameter(Mandatory=$False)]
        [string]$SSHPrivateKeyPath
    )

    #region >> Cross Check

    # Make sure we have all of the necessary binaries on the local machine
    try {
        $null = Get-Command scp -ErrorAction Stop
        $null = Get-Command ssh -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    # Get miniserve.exe if it doesn't already exist
    $MiniServeBinPath = "C:\Scripts\bin\miniserve.exe"
    if (!$(Test-Path $MiniServeBinPath)) {
        try {
            $null = Install-MiniServe -NetworkInterfaceAlias $MiniServeNetworkInterfaceAlias -ErrorAction Stop
        } catch {
            $ErrMsg = $_.Exception.Message
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $_
            return
        }
    }

    if ($SSHPrivateKeyPath) {
        if (!$(Test-Path $SSHPrivateKeyPath)) {
            Write-Error "The path $SSHPrivateKeyPath was not found! Halting!"
            return
        }
    }

    #endregion >> Cross Check

    #region >> Main

    # Set all necessary variables
    #$GetElevationFunctionAsString = 'function Get-Elevation {' + $(Get-Command Get-Elevation).ScriptBlock.ToString() + '}'
    #$InstallPSExecFunctionAsString = 'function Install-PSExec {' + $(Get-Command Install-PSExec).ScriptBlock.ToString() + '}'
    $GetElevationFunctionAsString = ${Function:Get-Elevation}.Ast.Extent.Text
    $InstallPSExecFunctionAsString = ${Function:Install-PSExec}.Ast.Extent.Text
    $TempFileDir = "C:/Scripts/temp" # NOTE: This is a directory on the local AND remote machine
    $TempFileName = [IO.Path]::GetRandomFileName()
    $ReturnIPAddressPrep = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -match [regex]::Escape($MiniServeNetworkInterfaceAlias)}
    if (!$ReturnIPAddressPrep) {
        $ErrMsg = "Unable to find Network Interface that matches '$MiniServeNetworkInterfaceAlias'. Halting!"
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
    $ReturnIPAddress = $ReturnIPAddressPrep.IPAddress

    # Create a string containing the script to be executed on the remote machine
    $GetSecureStringScriptPart1 = @"
$GetElevationFunctionAsString

$InstallPSExecFunctionAsString

`$SSHUserName = '$ReturnSSHUserName'
`$ReturnIPAddress = '$ReturnIPAddress'
`$TempFileName = '$TempFileName'
`$TempFileDir = '$TempFileDir'
`$TempFilePath = '$TempFileDir' + '\' + `$TempFileName
`$LogFilePath = `$TempFileDir + '\' + 'Prompt_ActiveUserForSecureString_' + `$(Get-Date -Format MMddyy_hhmmss) + '.log'
"@
    $GetSecureStringScriptPart2 = @'
if (!$(Get-Command psexec.exe -ErrorAction SilentlyContinue)) {
    try {
        $null = Install-PSExec -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
}

$ActiveSessionIDPrep = $(qwinsta.exe | Select-String "Active") -split "[\s]" | foreach {if (![String]::IsNullOrWhiteSpace($_)) {$_}}
$ActiveSessionID = $ActiveSessionIDPrep[-2]
if (!$(Test-Path $TempFileDir)) {$null = New-Item -Path $TempFileDir -ItemType Directory -Force -ErrorAction Stop}
$CommandString = @"
psexec.exe -accepteula -i $ActiveSessionID -s -d powershell.exe -Command "[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt 'Please enter secure string' -AsSecureString))) | Out-File $TempFilePath"
"@
$null = Invoke-Expression -Command $CommandString
while (!$(Test-Path $TempFilePath)) {Start-Sleep -Seconds 2}

#$Result = Get-Content -Path $TempFilePath
#$SCPRemoteLocationString = $SSHUserName + '@' + $ReturnIPAddress + ':' + $TempFilePath
#scp.exe $TempFilePath $SCPRemoteLocationString

$url = 'http://' + $ReturnIPAddress + ':8080/upload?path=/'
$webClient = New-Object System.Net.WebClient
$null = $webClient.UploadFile($url, $TempFilePath)

$null = Remove-Item -Path $TempFilePath -Force -ErrorAction Stop
'@
    $GetSecureStringScript = $GetSecureStringScriptPart1 + "`n" + $GetSecureStringScriptPart2

    # Send the script to the remote machine
    $ScriptTempPath = "$TempFileDir/GetSecureString.ps1"
    $GetSecureStringScript | Out-File -FilePath $ScriptTempPath -Force -ErrorAction Stop
    $SSHRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress
    $SCPRemoteLocationString = $SSHRemoteLocationString + ':' + $ScriptTempPath
    if ($SSHPrivateKeyPath) {
        $SCPResult = scp.exe -i $SSHPrivateKeyPath $ScriptTempPath $SCPRemoteLocationString
    } else {
        scp.exe $ScriptTempPath $SCPRemoteLocationString
    }
    if ($SCPResult -match 'No such file or directory') {
        $ErrMsg = "Path $ScriptTempPath does not exist on remote machine! Halting!"
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Start miniserve http server on localhost to that the remote host can upload the result back to the local host
    #& "C:\Scripts\bin\miniserve.exe" -u -i $ReturnIPAddress $TempFileDir
    $Arguments = "-u -i $ReturnIPAddress $TempFileDir"
    Start-Process -FilePath $MiniServeBinPath -ArgumentList $Arguments -WindowStyle Hidden
    Start-Sleep -Seconds 2
    if ($SSHPrivateKeyPath) {
        ssh.exe -i $SSHPrivateKeyPath $SSHRemoteLocationString "powershell.exe -ExecutionPolicy Bypass -File $ScriptTempPath"
    } else {
        ssh.exe $SSHRemoteLocationString "powershell.exe -ExecutionPolicy Bypass -File $ScriptTempPath"
    }

    # Wait for the remote host to upload the result
    #$UploadedFilePath = Get-ChildItem -Path $TempFileDir)[-1].FullName
    while (!(Test-Path "$TempFileDir/$TempFileName")) {Start-Sleep -Seconds 2}
    Get-Content "$TempFileDir/$TempFileName"
    if ($RemovePwdFile) {$null = Remove-Item -Path "$TempFileDir/$TempFileName" -Force -ErrorAction Stop}

    # Finally, kill miniserve
    Get-Process -Name "miniserve" | Stop-Process -Force
}