<#
.SYNOPSIS
    Creates the following directories on the RemoteHost
        C:\Scripts\bin
        C:\Scripts\logs
        C:\Scripts\powershell
        C:\Scripts\configs
        C:\Scripts\temp

.DESCRIPTION
    Created directories

.NOTES
    DEPENDENCEIES
        ssh.exe
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Invoke-ScaffoldingOnRemoteHost -RemoteUserName "adminuser" -RemoteIPAddress "192.168.2.250" -SSHPrivateKeyPath "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Invoke-ScaffoldingOnRemoteHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.2.250"

        [Parameter(Mandatory=$False)]
        [string]$SSHPrivateKeyPath # Example: "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"
    )

    if ($SSHPrivateKeyPath) {
        if (!$(Test-Path $SSHPrivateKeyPath)) {
            Write-Error "The path $SSHPrivateKeyPath was not found! Halting!"
            return
        }
    }

    # Make sure we have all of the necessary binaries on the local machine
    try {
        $null = Get-Command ssh -ErrorAction Stop
    } catch {
        Write-Error $_
        return
    }

    $SSHRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress

    # Setup the directory paths
    $ScriptsPath = "C:\Scripts"
    $RemotePaths = @(
        "$ScriptsPath\bin"
        "$ScriptsPath\logs"
        "$ScriptsPath\powershell"
        "$ScriptsPath\configs"
        "$ScriptsPath\temp"
        "$ScriptsPath\certs"
        "C:\Users\$RemoteUserName\Documents\WindowsPowerShell"
        "C:\Users\$RemoteUserName\Documents\PowerShell"
    )
    $RemotePathsArrayString = "@('" + $($RemotePaths -join "','") + "') | "
    $CreateDirsCommandString = 'foreach {if (!(Test-Path ```$_)) {New-Item -Path ```$_ -ItemType Directory -Force}}'
    $SSHCommandStringPrep = '`"' + $RemotePathsArrayString + $CreateDirsCommandString + '`"'
    $SSHCommandString = 'powershell.exe -ExecutionPolicy Bypass -Command ' + $SSHCommandStringPrep
    $FinalCmdStringPrep = $SSHRemoteLocationString + ' ' + '"' + $SSHCommandString + '"'
    if ($SSHPrivateKeyPath) {
        $FinalCmdString = 'ssh.exe -i ' + $SSHPrivateKeyPath + ' ' + $FinalCmdStringPrep
    } else {
        $FinalCmdString = 'ssh.exe ' + $FinalCmdStringPrep
    }
    Write-Host "FinalCmdString for Invoke-Expression is: $FinalCmdString"

    Invoke-Expression $FinalCmdString

    <#
    if ($SSHPrivateKeyPath) {
        # Run the script on the remote machine
        ssh.exe -i $SSHPrivateKeyPath $FinalCmdString
    } else {
        # Run the script on the remote machine
        ssh.exe $FinalCmdString
    }
    #>
}


<#
.SYNOPSIS
    Adds ssh public key to remote host C:\ProgramData\ssh\administrators_authorized_keys and C:\Users\$RemoteUserName\.ssh\authorized_keys

.DESCRIPTION
    See Synopsis

.NOTES
    DEPENDENCEIES
        ssh.exe
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Send-SSHKeyToRemoteHost -RemoteUserName "adminuser" -RemoteIPAddress "192.168.2.250" -SSHPrivateKeyPath "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands" -SSHPublicKeyPath "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands.pub"
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Send-SSHKeyToRemoteHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.2.250"

        [Parameter(Mandatory=$True)]
        [string]$SSHPrivateKeyPath, # Example: "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"

        [Parameter(Mandatory=$True)]
        [string]$SSHPublicKeyPath # Example: "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands.pub"
    )

    # Make sure we have all of the necessary binaries on the local machine
    try {
        $null = Get-Command ssh -ErrorAction Stop
    } catch {
        Write-Error $_
        return
    }

    if (!$(Test-Path $SSHPrivateKeyPath)) {
        Write-Error "The path $SSHPrivateKeyPath was not found! Halting!"
        return
    }

    # NOTE: This function is INTERACTIVE and requires user input

    $RemoteHostDotSSHDir = "C:\Users\$RemoteUserName\.ssh"
    $SSHAuthorizedKeysPath = "$RemoteHostDotSSHDir\authorized_keys"
    $SSHAuthorizedKeysPath2 = "C:\ProgramData\ssh\administrators_authorized_keys"
    $SSHRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress

    $SSHPublicKey = Get-Content -Raw $SSHPublicKeyPath
    #[System.IO.File]::AppendAllLines($SSHAuthorizedKeysPath, $SSHPublicKey, [System.Text.UTF8Encoding]::new())
    $SSHCommandString = @"
powershell.exe -ExecutionPolicy Bypass -Command "if (!(Test-Path '$RemoteHostDotSSHDir')) {New-Item -Path '$RemoteHostDotSSHDir' -ItemType Directory -Force}; [System.IO.File]::AppendAllLines([string]'$SSHAuthorizedKeysPath', [string[]]'$SSHPublicKey', [System.Text.UTF8Encoding]::new()); [System.IO.File]::AppendAllLines([string]'$SSHAuthorizedKeysPath2', [string[]]'$SSHPublicKey', [System.Text.UTF8Encoding]::new())"
"@
    
    # Send the public key to the remote host
    $null = ssh.exe $SSHRemoteLocationString $SSHCommandString

    # Test Key Authentication - This should return the name of the remote host
    ssh.exe -i $SSHPrivateKeyPath $SSHRemoteLocationString "powershell.exe -ExecutionPolicy Bypass -Command `"'`$env:ComputerName'`""
}


<#
.SYNOPSIS
    Adds the following to .ssh/config on the local machine

        Host $RemoteIPAddress
            HostName $RemoteIPAddress
            User $RemoteUserName
            IdentityFile $SSHPrivateKeyPath

.DESCRIPTION
    See Synopsis

.NOTES
    DEPENDENCEIES
        ssh.exe
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Add-ToSSHConfigFile -RemoteUserName "adminuser" -RemoteIPAddress "192.168.2.250" -SSHPrivateKeyPath "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Add-ToSSHConfigFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.2.250"

        [Parameter(Mandatory=$True)]
        [string]$SSHPrivateKeyPath # Example: "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"
    )

    # Make sure we have all of the necessary binaries on the local machine
    try {
        $null = Get-Command ssh -ErrorAction Stop
    } catch {
        Write-Error $_
        return
    }

    if (!$(Test-Path $SSHPrivateKeyPath)) {
        Write-Error "The path $SSHPrivateKeyPath was not found! Halting!"
        return
    }

    # Check to make sure there isn't already an entry for this host
    $SSHConfigPath = "$env:USERPROFILE\.ssh\config"
    if (Test-Path $SSHConfigPath) {
        if ($(Get-Content -Raw $SSHConfigPath) -match "^Host $RemoteIPAddress") {
            Write-Error "There is already an entry for $RemoteIPAddress in $SSHConfigPath! Halting!"
            return
        }
    }

@"
Host $RemoteIPAddress
  HostName $RemoteIPAddress
  User $RemoteUserName
  IdentityFile $SSHPrivateKeyPath
"@ | Out-File -Append -FilePath $SSHConfigPath

}


<#
.SYNOPSIS
    Creates a webserver on a remote host that runs a powershell terminal as the specified user ($TaskUser).
    Site can be accessed via http://$RemoteIPAddress:7681 and can be password protected (Basic Auth).

.DESCRIPTION
    In order 

.NOTES
    DEPENDENCEIES
        ssh.exe
        scp.exe
        ttyd.exe - https://github.com/tsl0922/ttyd
        miniserve.exe - https://github.com/svenstaro/miniserve
        TTYDModule.psm1 - PowerShell module should come packaged with this Module
        MiniServeModule.psm1 - PowerShell module should come packaged with this Module
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Create-RemoteTTYDScheduledTask {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.2.250"

        [Parameter(Mandatory=$True)]
        [string]$ModuleDir, # Example: "C:\Scripts\powershell"

        [Parameter(Mandatory=$False)]
        [string]$SSHPrivateKeyPath, # Example: "$HOME\.ssh\id_rsa_for_remote_commands"

        [Parameter(Mandatory=$True)]
        [string]$NetworkInterfaceAlias, # Example: "ZeroTier One [8bkp1rxn07zvy5tfh]"

        [Parameter(Mandatory=$True)]
        [string]$TaskUser, # Example: "adminuserbackup"

        [Parameter(Mandatory=$False)]
        [string]$TaskUserPasswd, # Example: "P@assWord321!_For_adminuserbackup"

        [Parameter(Mandatory=$False)]
        [string]$TTYDWebUser, # Example: "ttydadmin"

        [Parameter(Mandatory=$False)]
        [string]$TTYDWebPassword # Example: "TheP@wd_For_ttyd_website!"
    )

    # NOTE: This script is INTERACTIVE and requires user input
    # NOTE: The remote host must have SSHD running
    # NOTE: The remote host must have the directory created already: C:\Scripts\temp
    # This script outputs an object of type Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject

    $TempFileDir = "C:/Scripts/temp"
    $ScriptTempPath = "$TempFileDir/CreateTTYDSchdTask.ps1"
    $SSHRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress
    $SCPRemoteLocationString = $SSHRemoteLocationString + ':' + $ScriptTempPath

    $LogFileDir = "C:\Scripts\logs"
    $LogFilePath = $LogFileDir + '\' + 'create_remote_ttyd_schdtask_' + $(Get-Date -Format MMddyy_hhmmss) + '.log'
    $BinFileDir = "C:\Scripts\bin"
    $BinFilePath = $BinFileDir + '\' + 'ttyd.exe'
    $ModuleDir = $ModuleDir.TrimEnd('\')
    try {
        if (!$(Test-Path $LogFileDir)) {$null = New-Item -Path $LogFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $BinFileDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
        if (!$(Test-Path $ModuleDir)) {$null = New-Item -Path $BinFileDir -ItemType Directory -Force -ErrorAction Stop}
    } catch {
        $ErrMsg = $_.Exception.Message
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

    if ($SSHPrivateKeyPath) {
        if (!$(Test-Path $SSHPrivateKeyPath)) {
            Write-Error "The path $SSHPrivateKeyPath was not found! Halting!"
            return
        }
    }

    [System.Collections.Generic.List[String]]$Modules = @('TTYDModule','MiniServeModule')
    [System.Collections.Generic.List[String]]$FunctionsForRemoteUse = @()
    foreach ($ModuleName in $Modules) {
        $ModulePath = $ModuleDir + '\' + $ModuleName + '.psm1'
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
    $FunctionsForRemoteUse = $FunctionsForRemoteUse | Sort-Object | Get-Unique

    if (!$TaskUserPasswd) {
        $Params = @{
            RemoteUserName                  = $RemoteUserName
            RemoteIPAddress                 = $RemoteIPAddress
            MiniServeNetworkInterfaceAlias  = $NetworkInterfaceAlias
            RemovePwdFile                   = $False
        }
        if ($SSHPrivateKeyPath) {$Params.Add('SSHPrivateKeyPath', $SSHPrivateKeyPath)}
        Write-Host "Running Prompt-ActiveUserForSecureString with the following parameters:"
        $Params.GetEnumerator() | foreach {Write-Host "`t$($_.Key) = $($_.Value)"}
        $TaskUserPasswd = Prompt-ActiveUserForSecureString @Params
    }

    if (!$TaskUserPasswd) {
        $ErrMsg = "Unable to get the password for the $TaskUser user! Halting!"
        $null = Add-Content -Path $LogFilePath -Value $ErrMsg
        Write-Error $ErrMsg
        return
    }

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


    [System.Collections.Generic.List[String]]$CreateTTYDSchdTaskScriptPrep = @(
        $FunctionsForRemoteUse
@'
# Get the AST for the current script
$ast = [System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$null, [ref]$null)

# Get all function definitions from the AST
$FunctionDefinitions = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)

$FunctionDefinitions | foreach {
    if (!$(Test-Path 'C:\Scripts\bin')) {$null = New-Item -Path 'C:\Scripts\bin' -ItemType Directory -Force -ErrorAction Stop}
    $null = Add-Content -Path "C:\Scripts\bin\DynamicallyCreatedTTYDModule.psm1" -Value $_.Extent.text
    if (!$(Test-Path 'C:\Scripts\powershell')) {$null = New-Item -Path 'C:\Scripts\powershell' -ItemType Directory -Force -ErrorAction Stop}
    $null = Add-Content -Path "C:\Scripts\powershell\TTYDModule.psm1" -Value $_.Extent.text
}

'@
@"
`$UserName = '$TaskUser'
`$PwdSS = ConvertTo-SecureString '$TaskUserPasswd' -AsPlainText -Force
`$NetworkInterfaceAlias = '$NetworkInterfaceAlias'
`$LogFileDir = '$LogFileDir'
`$LogFilePath = '$LogFilePath'
`$TTYDWebUser = '$TTYDWebUser'
`$TTYDWebPassword = '$TTYDWebPassword'

"@
@'
$Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $PwdSS
$CreateTTYDParams = @{
    NetworkInterfaceAlias   = $NetworkInterfaceAlias
    TaskUserCreds           = $Credentials
    ErrorAction             = 'Stop'
}
if ($TTYDWebUser) {$CreateTTYDParams.Add('TTYDWebUser', $TTYDWebUser)}
if ($TTYDWebPassword) {$CreateTTYDParams.Add('TTYDWebPassword', $TTYDWebPassword)}

try {
    $null = Create-TTYDScheduledTask @CreateTTYDParams
} catch {
    $ErrMsg = $_.Exception.Message
    $null = Add-Content -Path $LogFilePath -Value $ErrMsg
    Write-Error $ErrMsg
    return
}

#Start-Sleep -Seconds 20
#Get-Process ttyd | Stop-Process -Force

# Self Destruct This Script
$null = Remove-Item -Path $MyInvocation.MyCommand.Path -Force
'@
        )
    $CreateTTYDSchdTaskScript = $CreateTTYDSchdTaskScriptPrep -join "`n"
    $CreateTTYDSchdTaskScript | Out-File -FilePath $ScriptTempPath -Force -ErrorAction Stop

    if ($SSHPrivateKeyPath) {
        # Send the script to the remote machine
        $SCPResult = scp.exe -i $SSHPrivateKeyPath $ScriptTempPath $SCPRemoteLocationString
        if ($SCPResult -match 'No such file or directory') {
            $ErrMsg = "Path $ScriptTempPath does not exist on remote machine! Halting!"
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }

        # Run the script on the remote machine
        ssh.exe -i $SSHPrivateKeyPath $SSHRemoteLocationString "powershell.exe -ExecutionPolicy Bypass -File $ScriptTempPath"
    } else {
        # Send the script to the remote machine
        $SCPResult = scp.exe $ScriptTempPath $SCPRemoteLocationString
        if ($SCPResult -match 'No such file or directory') {
            $ErrMsg = "Path $ScriptTempPath does not exist on remote machine! Halting!"
            $null = Add-Content -Path $LogFilePath -Value $ErrMsg
            Write-Error $ErrMsg
            return
        }

        # Run the script on the remote machine
        ssh.exe $SSHRemoteLocationString "powershell.exe -ExecutionPolicy Bypass -File $ScriptTempPath"
    }

    $MsgOutput = @"

To access TTYD as $TaskUser, start the Scheduled Task remotely over ssh via:
ssh $RemoteUserName@$RemoteIPAddress "powershell.exe -ExecutionPolicy Bypass -Command ``"Start-ScheduledTask -TaskName 'Run TTYD as $TaskUser'``""
...and then navigate to http://{ZeroTierIPAddress}`:7681

Stop the Scheduled Task remotely over ssh via:
ssh $RemoteUserName@$RemoteIPAddress "powershell.exe -ExecutionPolicy Bypass -Command ``"Stop-ScheduledTask -TaskName 'Run TTYD as $TaskUser'; Stop-Process -Name ttyd -Force -ErrorAction SilentlyContinue``""

"@
    Write-Host $MsgOutput -ForegroundColor Cyan

    Write-Host "Sleeping for 10 more seconds to wait for ttyd webserver to start..." -ForegroundColor Green
    Start-Sleep -Seconds 10

    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    Invoke-WebRequest -UseBasicParsing -Uri "http://$RemoteIPAddress`:7681/" -WebSession $session `
    -Headers @{
        "Accept"                    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        "Accept-Encoding"           = "gzip, deflate"
        "Accept-Language"           = "en-US,en;q=0.9"
        "Authorization"             = "Basic dHR5ZGFkbWluOk15UGFzc3dvcmQxMjMh"
        "Cache-Control"             = "max-age=0"
        "Upgrade-Insecure-Requests" = "1"
        "dnt"                       = "1"
        "sec-gpc"                   = "1"
    }
}