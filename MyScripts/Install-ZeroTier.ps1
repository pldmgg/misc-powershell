##### BEGIN Helper Functions #####
function Install-Pwsh {
    [CmdletBinding()]
    Param()

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\TacticalPwshInstall"
    $LogFilePath = $LogFileDir + '\' + 'pwsh_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'pwsh.exe'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
	    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    # Check for where we expect pwsh 7 to be and if it is available in terminal
    $Pwsh7BinCheck = Test-Path "$env:SystemDrive\Program Files\PowerShell\7\pwsh.exe"
    $PwshCommandCheck = Get-Command pwsh -ErrorAction SilentlyContinue

    if (!$Pwsh7BinCheck -or !$PwshCommandCheck -or $PwshCommandCheck.Version.Major -lt 7) {
        try {
            # Set PowerShell to TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Install pwsh
            $null = Invoke-Expression "& {$(Invoke-RestMethod https://aka.ms/install-powershell.ps1)} -UseMSI -Quiet" -ErrorAction Stop
            
            # Refresh PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path', 'User')

            $LogMsg = "Pwsh has been installed."
            $null = Add-Content -Path $LogFilePath -Value $LogMsg
            # Output
            Get-Command pwsh
            return
        } catch {
            $ErrMsg = $_.Exception.Message
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }
    } else {
        $LogMsg = "Pwsh version $($PwshCommandCheck.Version.ToString()) is already installed. No action taken."
        $null = Add-Content -Path $LogFilePath -Value $LogMsg
        # Output
        Get-Command pwsh
        return
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
##### END Helper Functions #####

<#
  .SYNOPSIS
    Installs ZeroTier
  .DESCRIPTION
    Install ZeroTier and join/configure ZeroTier network
  .EXAMPLE
    Install-ZeroTier -NetworkID [Network ID]
    Install-ZeroTier -NetworkID [Network ID] -Token [API Token] -Headless
    Install-ZeroTier -NetworkID [Network ID] -Token [API Token] -BackupExistingConfig
  .NOTES
    Requires PowerShell 7 or higher (installed if missing) when using the $Token parameter.
    A UAC prompt will appear during install if -Headless is not used.
#>
function Install-ZeroTier {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NetworkID,

        [Parameter(Mandatory=$False)]
        [string]$Token,

        [Parameter(Mandatory=$False)]
        [switch]$Headless,

        [Parameter(Mandatory=$False)]
        [switch]$ManageDNS, # Allows ZeroTier to manage DNS

        [Parameter(Mandatory=$False)]
        [switch]$GlobalRoutes, # Allows ZeroTier managed routes to overlap public IP space

        [Parameter(Mandatory=$False)]
        [switch]$DefaultRoute, # Allows ZeroTier to override system default route (full tunnel)

        [Parameter(Mandatory=$False)]
        [switch]$BackupExistingConfig # Backup existing ZeroTier config
    )

    if (!$(Get-Elevation)) {
        Write-Error "You need to run this script as an administrator."
        return
    }

    # Setup bin, log, and conf paths
    $LogFileDir = "C:\Scripts\logs\TacticalZeroTierInstall"
    $LogFilePath = $LogFileDir + '\' + 'zerotier_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'ZeroTierOne.msi'
    $ConfFileDir = "C:\Scripts\conf"
    $ConfFilePath = $ConfFileDir + '\' + 'C_ProgramData_ZeroTier_One.zip'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $ConfFileDir)) {$null = New-Item -Path $ConfFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    $DownloadURL = 'https://download.zerotier.com/dist/ZeroTier%20One.msi'
    $Installer = "$BinFileDir\ZeroTierOne.msi"
    $ZTCLI = 'C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat'
    $ZTDesktopUI = "C:\Program Files (x86)\ZeroTier\One\zerotier_desktop_ui.exe"
    $ZTConfigDir = "C:\ProgramData\ZeroTier\One"

    # Backup existing ZeroTier config if it exists
    if ($BackupExistingConfig) {
        try {
            if (Test-Path $ZTConfigDir) {
                $ZipParams = @{
                    Path                = $ZTConfigDir
                    CompressionLevel    = "Fastest"
                    DestinationPath     = $ConfFilePath
                    Force               = $True
                    ErrorAction         = "Stop"
                }
                $null = Compress-Archive @ZipParams
            }

            if (Test-Path $ZTCLI) {
                $DumpResult = cmd /c $ZTCLI dump
                if ($DumpResult -match "Error") {
                    throw "Error dumping ZeroTier config."
                }
                if ($DumpResult) {
                    $DumpOutputFilePath = $($DumpResult -split '[\s]')[-1]
                    $null = Move-Item -Path $DumpOutputFilePath -Destination "$ZTConfigDir\zerotier_dump.txt" -Force -ErrorAction Stop
                }
            }
        } catch {
            $ErrMsg = $_.Exception.Message
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $_
            return
        }
    }

    # Set PowerShell to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    if ($Token) {
        # Check for required PowerShell version (7+)
        if (!($PSVersionTable.PSVersion.Major -ge 7)) {
            try {
                Write-Host "Installing PowerShell 7..."
                # Install pwsh
                $InstallPwshResult = Install-Pwsh -ErrorAction Stop
                
                # Restart Install-ZeroTier.ps1 script in PowerShell 7
                $null = Add-Content -Path $LogFilePath -Value "Restarting Install-ZeroTier.ps1 in Pwsh..." -ErrorAction Stop
                Write-Host "Restarting Install-ZeroTier.ps1 in Pwsh..."
                pwsh -File "`"$PSCommandPath`"" @PSBoundParameters
                return
            } catch {
                $ErrMsg = $_.Exception.Message
                $null = Add-Content -Path $LogFilePath -Value $ErrMsg
                Write-Error $_
                return
            }
        }
    }

    # Download ZeroTier
    try {
        $IWRResult = Invoke-WebRequest -Uri $DownloadURL -OutFile $Installer -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    # Kill any existing ZeroTier processes
    $null = Get-Process -Name zerotier* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    
    # Install ZeroTier
    try {
        if ($Headless) {
            # Install & unhide from installed programs list
            Write-Host "Installing Headless..."
            cmd /c msiexec /i $Installer /qn /norestart 'ZTHEADLESS=Yes' | Out-Null
            $Paths = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
            $RegKey = Get-ChildItem -Path $Paths | Get-ItemProperty | Where-Object { $_.DisplayName -like 'ZeroTier One' } | Select-Object
            $null = Remove-ItemProperty -Path $RegKey.PSPath -Name 'SystemComponent' -ErrorAction Ignore
        } else {
            # Install & close ui
            cmd /c msiexec /i $Installer /qn /norestart | Out-Null
            #$null = Stop-Process -Name 'zerotier_desktop_ui' -Force -ErrorAction SilentlyContinue

            # Ensure the ZeroTier Desktop UI runs on startup for all users
            # Create .lnk file from C:\Program Files (x86)\ZeroTier\One\zerotier_desktop_ui.exe to C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\zerotier_desktop_ui.lnk
            $LnkFile = $(New-Object -ComObject WScript.Shell).CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\zerotier_desktop_ui.lnk")
            $LnkFile.TargetPath = $ZTDesktopUI
            $LnkFile.Save()
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    # Wait for the ZeroTier Service to start
    try {
        if ($(Get-Service -Name ZeroTierOneService).Status -ne "Running") {
            $null = Restart-Service -Name ZeroTierOneService -ErrorAction SilentlyContinue
        }
        
        $counter = 0
        while ($(cmd /c $ZTCLI status) -match "connection failed" -and $counter -lt 3) {
            Write-Host "Waiting for ZeroTier Service to start..."
            Start-Sleep -Seconds 5
            $counter++
        }

        if (!$(Get-Process zerotier_desktop_ui -ErrorAction SilentlyContinue) -and !$Headless) {
            & $ZTDesktopUI
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
    

    # Ensure permissions on C:\ProgramData\ZeroTier\One\authtoken.secret and C:\ProgramData\ZeroTier\One\identity.secret are correct
    # Set file permissions to Everyone Read
    $AuthToken = "C:\ProgramData\ZeroTier\One\authtoken.secret"
    $IdentitySecret = "C:\ProgramData\ZeroTier\One\identity.secret"
    try {
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","Read","Allow")
        if (Test-Path $AuthToken) {
            $AuthTokenACL = Get-Acl -Path $AuthToken -ErrorAction Stop
            $AuthTokenACL.SetAccessRule($AccessRule)
            $AuthTokenACL | Set-Acl -ErrorAction Stop
        }

        if (Test-Path $IdentitySecret) {
            $IdentitySecretACL = Get-Acl -Path $IdentitySecret -ErrorAction Stop
            $IdentitySecretACL.SetAccessRule($AccessRule)
            $IdentitySecretACL | Set-Acl -ErrorAction Stop
        }
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    try {        
        if ($Token) {
            # Get Node ID
            $NodeID = (cmd /c $ZTCLI info).split(' ')[2]

            # API Member object properties
            $Member = @{
                name = $env:COMPUTERNAME
                description = ''
                config = @{ authorized = $True }
            } | ConvertTo-Json

            # Prepare API request
            $Params = @{
                Method = 'Post'
                Uri = "https://my.zerotier.com/api/network/$NetworkID/member/$NodeID"
                Body = $Member
                Authentication = 'Bearer'
                Token = ConvertTo-SecureString $Token -AsPlainText -Force
                MaximumRetryCount = 3
                RetryIntervalSec = 5
            }
            
            $null = Invoke-RestMethod @Params
        }
        
        # Join the network if not already
        $AlreadyJoinedCheck = $(cmd /c $ZTCLI listnetworks) -match $NetworkID
        if (!$AlreadyJoinedCheck) {
            cmd /c $ZTCLI join $NetworkID | Out-Null
        }

        # Configure ZeroTier client
        if ($ManageDNS) { cmd /c $ZTCLI set $NetworkID allowDNS=1 | Out-Null }
        if ($GlobalRoutes) { cmd /c $ZTCLI set $NetworkID allowGlobal=1 | Out-Null }
        if ($DefaultRoute) { cmd /c $ZTCLI set $NetworkID allowDefault=1 | Out-Null }

        # Output
        cmd /c $ZTCLI status
        cmd /c $ZTCLI listnetworks
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    } finally {
        #$null = Remove-Item $Installer -Force -ErrorAction SilentlyContinue
    }
}