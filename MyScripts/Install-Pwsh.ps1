function Install-Pwsh {
    [CmdletBinding()]
    Param()

    # Setup bin and log paths
    $LogFileDir = "C:\Scripts\logs\PwshInstall"
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

Install-Pwsh