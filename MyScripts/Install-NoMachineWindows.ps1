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

function Install-NoMachineWindows {
    [CmdletBinding()]
    Param()

    if (!$(Get-Elevation)) {
        Write-Error "You need to run this script as an administrator."
        return
    }

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\TacticalNoMachineInstall"
    $LogFilePath = $LogFileDir + '\' + 'nomachine_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'nomachine.exe'
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    # Set PowerShell to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Check for required PowerShell version (7+)
    if (!($PSVersionTable.PSVersion.Major -ge 7)) {
        try {
            Write-Host "Installing PowerShell 7..."
            # Install pwsh
            $InstallPwshResult = Install-Pwsh -ErrorAction Stop
            
            # Restart Install-NoMachineWindows.ps1 script in PowerShell 7
            $null = Add-Content -Path $LogFilePath -Value "Restarting Install-NoMachineWindows.ps1 in Pwsh..." -ErrorAction Stop
            Write-Output "Restarting Install-NoMachineWindows.ps1 in Pwsh. Check $LogFilePath for details."
            pwsh -File "`"$PSCommandPath`"" @PSBoundParameters
            return
        } catch {
            $ErrMsg = $_.Exception.Message
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $_
            return
        }
    }

    # Install NoMachine
    try {
        $UriPrep = "https://downloads.nomachine.com/download/?id=9"
        $LatestUriCheck = Invoke-WebRequest -Uri $UriPrep -ErrorAction Stop
        $NoMachineForWindowsUri = $($LatestUriCheck.Links.href | Select-String -Pattern 'x64\.exe$').Line
        Invoke-WebRequest -Uri $NoMachineForWindowsUri -OutFile $BinFilePath -ErrorAction Stop
        & $BinFilePath /VERYSILENT /NORESTART

        $NxPlayerPath = "C:\Program Files\NoMachine\bin\nxplayer.exe"
        $counter = 0
        while (!$(Test-Path $NxPlayerPath) -and $counter -lt 5) {
            Start-Sleep -Seconds 5
            $counter++
        }
        if (!$(Test-Path $NxPlayerPath)) {
            $ErrMsg = "Unable to find '$NxPlayerPath'...NoMachine installation failed."
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }

        # Output
        $Output = Get-Item $NxPlayerPath -ErrorAction Stop
        $Output >> $LogFilePath
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }
}

Install-NoMachineWindows
