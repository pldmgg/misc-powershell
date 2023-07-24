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

$LogFileDir = "C:\Scripts\logs\SSHDInstall"
$LogFilePath = $LogFileDir + '\' + 'sshd_install_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
try {
    if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
} catch {
    $ErrMsg = $_.Exception.Message
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $_
    return
}

if (!$(Get-Elevation)) {
    $ErrMsg = "You need to run this script as an administrator."
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $ErrMsg
    return
}

if ($PSVersionTable.PSEdition -ne "Desktop") {
    $ErrMsg = "This script is only supported on Windows Desktop Edition."
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $ErrMsg
    return
}

try {
    $SSHDCheck = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object {$_.Name -match 'OpenSSH\.Server'}
} catch {
    $ErrMsg = $_.Exception.Message
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $_
    return
}

if ($SSHDCheck.State -ne "Installed") {
    try {
        Write-Host "Installing SSHD service..."
        $InstallSSHDResult = Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }

    try {
        Write-Host "Setting SSHD default shell to powershell.exe"
        $PowerShellBinPath = $(Get-Command "powershell.exe").Source
        Set-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value $PowerShellBinPath -ErrorAction Stop
        $SSHDService = Get-Service sshd -ErrorAction Stop
        $SSHDService | Set-Service -StartupType Automatic -ErrorAction Stop
        $SSHDService | Start-Service -ErrorAction Stop
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $_
        return
    }
}