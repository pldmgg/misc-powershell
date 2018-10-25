<#
    .SYNOPSIS
        This function creates a new SSH Public/Private Key Pair. Optionally, add it to the ssh-agent.
        Optionally add the public key to a Remote Host's ~/.ssh/authorized_keys file.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER NewSSHKeyName
        This parameter is MANDATORY.

        This parameter takes a string that represents the file name that you would like to give to the new
        SSH User/Client Keys.

    .PARAMETER NewSSHKeyPurpose
        This parameter is OPTIONAL.

        This parameter takes a string that represents a very brief description of what the new SSH Keys
        will be used for. This description will be added to the Comment section when the new keys are
        created.

    .PARAMETER NewSSHKeyPwd
        This parameter is OPTIONAL.

        This parameter takes a SecureString that represents the password used to protect the new
        Private Key file that is created.

    .PARAMETER BlankSSHPrivateKeyPwd
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to ensure that the newly created Private Key is NOT password
        protected.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL, but recommended.

        This parameter is a switch. If used, the new SSH Key Pair will be added to the ssh-agent service.

    .PARAMETER RemovePrivateKey
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter is a switch. If used, the newly created Private Key will be added to the ssh-agent
        and deleted from the filesystem.

    .PARAMETER RemoteHost
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys switch.

        This parameter takes a string that represents the IP Address of DNS-Resolvable name of a Remote Host.
        The newly created public key will be added to the Remote Host's ~/.ssh/authorized_keys file. The
        Remote Host can be either Windows or Linux (as long as you can ssh to it from the local host).

    .PARAMETER AddToRemoteHostAuthKeys
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the newly created Public Key will be added to the Remote Host's
        ~/.ssh/authorized_keys file. (Specify the Remote Host using the -RemoteHost parameter)

    .PARAMETER RemoteHostUserName
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys parameter.

        This parameter takes a string that represents the name of the user with ssh access to
        the Remote Host (specified by the -RemoteHost parameter).

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            NewSSHKeyName           = "ToRHServ01"
            NewSSHKeyPurpose        = "ForSSHToRHServ01"
            AddToSSHAgent           = $True
        }
        PS C:\Users\zeroadmin> New-SSHKey @SplatParams
        
#>
function New-SSHKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [securestring]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        #[Parameter(Mandatory=$False)]
        #[switch]$ShowNextSteps,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$False)]
        [switch]$AddToRemoteHostAuthKeys,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUserName
    )

    #region >> Helper Functions

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

    function Install-LinuxPackage {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string[]]$PossiblePackageNames,
    
            [Parameter(Mandatory=$True)]
            [string]$CommandName
        )
    
        if (!$(command -v $CommandName)) {
            foreach ($PackageName in $PossiblePackageNames) {
                if ($(command -v pacman)) {
                    $null = sudo pacman -S $PackageName --noconfirm *> $null
                }
                elseif ($(command -v yum)) {
                    $null = sudo yum -y install $PackageName *> $null
                }
                elseif ($(command -v dnf)) {
                    $null = sudo dnf -y install $PackageName *> $null
                }
                elseif ($(command -v apt)) {
                    $null = sudo apt-get -y install $PackageName *> $null
                }
                elseif ($(command -v zypper)) {
                    $null = sudo zypper install $PackageName --non-interactive *> $null
                }
    
                if ($(command -v $CommandName)) {
                    break
                }
            }
    
            if (!$(command -v $CommandName)) {
                Write-Error "Unable to find the command $CommandName! Install unsuccessful! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Write-Host "$PackageName was successfully installed!" -ForegroundColor Green
            }
        }
        else {
            Write-Warning "The command $CommandName is already available!"
            return
        }
    }

    #endregion >> Helper Functions


    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if (Get-Elevation) {
            Write-Error "You cannot run the $($PSCmdlet.MyInvocation.MyCommand) function as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        try {
            if ($(Get-Module -ListAvailable).Name -notcontains 'WinSSH') {$null = Install-Module WinSSH -ErrorAction Stop}
            if ($(Get-Module).Name -notcontains 'WinSSH') {$null = Import-Module WinSSH -ErrorAction Stop}
            Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Stop-AwaitSession
        }
        catch {
            Write-Verbose $_.Exception.Message
        }
    }

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        # Determine if we have required Linux commands
        [System.Collections.ArrayList]$LinuxCommands = @(
            "echo"
            "expect"
        )
        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }

        if ($CommandsNotPresent.Count -gt 0) {
            [System.Collections.ArrayList]$FailedInstalls = @()
            if ($CommandsNotPresent -contains "echo") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames "coreutils" -CommandName "echo"
                }
                catch {
                    $null = $FailedInstalls.Add("coreutils")
                }
            }
            if ($CommandsNotPresent -contains "expect") {
                try {
                    $null = Install-LinuxPackage -PossiblePackageNames "expect" -CommandName "expect"
                }
                catch {
                    $null = $FailedInstalls.Add("expect")
                }
            }
    
            if ($FailedInstalls.Count -gt 0) {
                Write-Error "The following Linux packages are required, but were not able to be installed:`n$($FailedInstalls -join "`n")`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$CommandsNotPresent = @()
        foreach ($CommandName in $LinuxCommands) {
            $CommandCheckResult = command -v $CommandName
            if (!$CommandCheckResult) {
                $null = $CommandsNotPresent.Add($CommandName)
            }
        }
    
        if ($CommandsNotPresent.Count -gt 0) {
            Write-Error "The following Linux commands are required, but not present on $env:ComputerName:`n$($CommandsNotPresent -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find ssh-keygen! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($AddToSSHAgent) {
        if (!$(Get-Command ssh-add -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find ssh-add! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            if ($(Get-Service ssh-agent).Status -ne "Running") {
                $SSHDErrMsg = "The ssh-agent service is NOT curently running! No ssh key pair has been created. Please ensure that the " +
                "ssh-agent and sshd services are running and try again. Halting!'"
                Write-Error $SSHDErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($AddToRemoteHostAuthKeys -and !$RemoteHost) {
        $RemoteHost = Read-Host -Prompt "Please enter an IP, FQDN, or DNS-resolvable Host Name that represents the Remote Host you would like to share your new public key with."
    }
    if ($RemoteHost -and !$AddToRemoteHostAuthKeys) {
        $AddToRemoteHostAuthKeys = $True
    }

    if ($RemoteHost) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHost -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($RemoteHost -or $AddToRemoteHostAuthKeys -and !$RemoteHostUserName) {
        $RemoteHostUserName = Read-Host -Prompt "Please enter a UserName that has access to $RemoteHost"
    }

    $UserSSHDir = Join-Path $HOME ".ssh"
    if (!$(Test-Path $UserSSHDir)) {
        $null = New-Item -Type Directory -Path $UserSSHDir
    }

    $SSHKeyOutFile = Join-Path $UserSSHDir $NewSSHKeyName

    if ($NewSSHKeyPwd) {
        $NewSSHKeyPwdPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSSHKeyPwd))
    }

    if ($NewSSHKeyPurpose) {
        #$SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwdPT`" -C `"$NewSSHKeyPurpose`""
        $NewSSHKeyPurpose = $NewSSHKeyPurpose -replace "[\s]",""
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -C `"$NewSSHKeyPurpose`""
        $SSHKeyGenArgumentsStringForExpect = "-t rsa -b 2048 -f \`"$SSHKeyOutFile\`" -q -C \`"$NewSSHKeyPurpose\`""
    }
    else {
        #$SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`""
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q"
        $SSHKeyGenArgumentsStringForExpect = "-t rsa -b 2048 -f \`"$SSHKeyOutFile\`" -q"
    }
    
    #endregion >> Prep


    #region >> Main

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        $sshkeygenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent

        #region >> Await Attempt 1 of 2

        # Create new public/private keypair
        $null = Start-AwaitSession
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$sshkeygenParentDir'"
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand -Command $([scriptblock]::Create("ssh-keygen $SSHKeyGenArgumentsString; Test-Path $SSHKeyOutFile"))
        Start-Sleep -Seconds 2

        $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
        $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
        $Counter = 0
        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and
        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Overwrite (y/n)?")) -and $Counter -le 30
        ) {
            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
            $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                break
            }
            Start-Sleep -Seconds 1
            $Counter++
        }
        if ($Counter -eq 31) {
            Write-Verbose "sshkeygen attempt timed out!"

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
                $PSAwaitProcess = $null
            }
        }

        #endregion >> Await Attempt 1 of 2

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            
        #region >> Await Attempt 2 of 2
        
        # If $CheckResponsesOutput contains the string "must be greater than zero", then something broke with the Await Module.
        # Most of the time, just trying again resolves any issues
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            # Create new public/private keypair
            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$sshkeygenParentDir'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create("ssh-keygen $SSHKeyGenArgumentsString"))
            Start-Sleep -Seconds 2

            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and
            ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Overwrite (y/n)?")) -and $Counter -le 30
            ) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "sshkeygen attempt timed out!"
                $global:FunctionResult = "1"

                #$CheckForExpectedResponses

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }
        }

        #endregion >> Await Attempt 2 of 2

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}

        # At this point, if we don't have the expected output, we need to fail
        if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]" -or
        $CheckResponsesOutput -match "background process reported an error") {
            if ($CheckResponsesOutput -match "must be greater than zero" -or @($CheckResponsesOutput)[-1] -notmatch "[a-zA-Z]") {
                Write-Error "Something went wrong with the PowerShell Await Module! Halting!"
            }
            if ($CheckResponsesOutput -match "background process reported an error") {
                Write-Error "Please check your credentials! Halting!"
            }
            $global:FunctionResult = "1"

            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }

            return
        }

        # Now we should either have a prompt to accept the host key, a prompt for a password, or it already worked...

        if ($CheckResponsesOutput -match [regex]::Escape("Overwrite (y/n)?")) {
            $null = Send-AwaitCommand "y"
            Start-Sleep -Seconds 3
            
            # This will either not prompt at all or prompt for a password
            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
            $null = $CheckExpectedSendYesOutput.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("Enter passphrase (empty for no passphrase):")) -and $Counter -le 30) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckExpectedSendYesOutput.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "Sending 'y' to overwrite the existing ssh key timed out!"
                $global:FunctionResult = "1"
                
                $CheckForExpectedResponses

                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
        }

        if ($CheckSendYesOutput -match [regex]::Escape("Enter passphrase (empty for no passphrase):") -or
        $CheckResponsesOutput -match [regex]::Escape("Enter passphrase (empty for no passphrase):")
        ) {
            if ($NewSSHKeyPwd) {
                $null = Send-AwaitCommand $NewSSHKeyPwdPT
            }
            else {
                $null = Send-AwaitCommand ""
            }
            Start-Sleep -Seconds 3

            $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendPwdOutput = @()
            $null = $CheckExpectedSendPwdOutput.Add($PassphraseOrOverwriteExistingKey)
            $Counter = 0
            while (![bool]$($CheckExpectedSendPwdOutput -match [regex]::Escape("Enter same passphrase again:")) -and $Counter -le 30) {
                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                $null = $CheckExpectedSendPwdOutput.Add($PassphraseOrOverwriteExistingKey)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 31) {
                Write-Error "Sending the initial password for the private key timed out!"
                $global:FunctionResult = "1"

                $CheckExpectedSendPwdOutput
                
                if ($PSAwaitProcess.Id) {
                    try {
                        $null = Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                            }
                            $Counter = 0
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                                $Counter++
                            }
                        }
                    }
                }

                return
            }

            $CheckSendPwdOutput = $CheckExpectedSendPwdOutput | foreach {$_ -split "`n"}

            if ($CheckSendPwdOutput -match [regex]::Escape("Enter same passphrase again:")) {
                if ($NewSSHKeyPwd) {
                    $null = Send-AwaitCommand $NewSSHKeyPwdPT
                }
                else {
                    $null = Send-AwaitCommand ""
                }
                Start-Sleep -Seconds 3

                $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse

                if (!$OutputPrep) {
                    [System.Collections.ArrayList]$OutputPrep = @()
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $OutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                }
                $Counter = 0
                while (![bool]$($($OutputPrep -split "`n") -match "True") -and $Counter -le $CounterLimit) {
                    $PassphraseOrOverwriteExistingKey = Receive-AwaitResponse
                    $null = $OutputPrep.Add($PassphraseOrOverwriteExistingKey)
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 31) {
                    Write-Error "Sending the password again timed out!"
                    $global:FunctionResult = "1"

                    $OutputPrep
                    
                    if ($PSAwaitProcess.Id) {
                        try {
                            $null = Stop-AwaitSession
                        }
                        catch {
                            if ($PSAwaitProcess.Id -eq $PID) {
                                Write-Error "The PSAwaitSession never spawned! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                    Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                                }
                                $Counter = 0
                                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                    Start-Sleep -Seconds 1
                                    $Counter++
                                }
                            }
                        }
                    }

                    return
                }
            }
        }
    
        $SSHKeyGenOutput = $OutputPrep
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if ($AddToSSHAgent) {
            # Check to see if the ssh-agent is running
            #[scriptblock]::Create('ssh-add -L').InvokeReturnAsIs()
            $SSHAgentProcesses = Get-Process -Name ssh-agent -IncludeUserName -ErrorAction SilentlyContinue | Where-Object {$_.UserName -eq $env:USER}
            if ($SSHAgentProcesses.Count -gt 0) {
                $LatestSSHAgentProcess = $(@($SSHAgentProcesses) | Sort-Object StartTime)[-1]
                $env:SSH_AUTH_SOCK = $(Get-ChildItem /tmp -Recurse -File | Where-Object {$_.FullName -match "\.$($LatestSSHAgentProcess.Id-1)"}).FullName
                $env:SSH_AGENT_PID = $LatestSSHAgentProcess.Id
            }
            else {                
                $SSHAgentInfo = ssh-agent
                $env:SSH_AUTH_SOCK = $($($($SSHAgentInfo -match "AUTH_SOCK") -replace 'SSH_AUTH_SOCK=','') -split ';')[0]
                $env:SSH_AGENT_PID = $($($($SSHAgentInfo -match "SSH_AGENT_PID") -replace 'SSH_AGENT_PID=','') -split ';')[0]
            }
        }

        [System.Collections.ArrayList]$ExpectScriptPrep = @(
            'expect - << EOF'
            'set timeout 20'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep.Add("set password $NewSSHKeyPwdPT")
        }

        [System.Collections.ArrayList]$ExpectScriptPrep2 = @(
            'set prompt \"(>|:|#|\\\\\\$)\\\\s+\\$\"'
            "spawn ssh-keygen $SSHKeyGenArgumentsStringForExpect"
            'match_max 100000'
            'expect {'
            '    \"*Overwrite (y*\" {'
            '        send -- \"y\r\"'
            '        exp_continue'
            '    }'
            '    \"*(empty for no passphrase)*\" {'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep2.Add('        send -- \"\$password\r\"')
        }
        else {
            $null = $ExpectScriptPrep2.Add('        send -- \"\r\"')
        }

        [System.Collections.ArrayList]$ExpectScriptPrep3 = @(
            '        expect \"*Enter same passphrase again*\"'
            '    }'
            '}'
        )
        if ($NewSSHKeyPwdPT) {
            $null = $ExpectScriptPrep3.Add('send -- \"\$password\r\"')
        }
        else {
            $null = $ExpectScriptPrep3.Add('send -- \"\r\"')
        }

        foreach ($Line in $ExpectScriptPrep2) {
            $null = $ExpectScriptPrep.Add($Line)
        }
        foreach ($Line in $ExpectScriptPrep3) {
            $null = $ExpectScriptPrep.Add($Line)
        }

        $null = $ExpectScriptPrep.Add('expect eof')
        $null = $ExpectScriptPrep.Add('EOF')
        
        $ExpectScript = $ExpectScriptPrep -join "`n"

        #Write-Host "`$ExpectScript is:`n$ExpectScript"
        #$ExpectScript | Export-CliXml "$HOME/ExpectScriptA.xml"
        
        # The below $ExpectOutput is an array of strings
        $ExpectOutput = bash -c "$ExpectScript"

        $SSHKeyGenOutput = $ExpectOutput
    }

    $PubPrivKeyPairFiles = Get-ChildItem -Path $UserSSHDir -File | Where-Object {$_.Name -match "$NewSSHKeyName"}
    $PubKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

    if (!$PubKey -or !$PrivKey) {
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            $Counter = 0
            if ($PSAwaitProcess.Id) {
                try {
                    $null = Stop-AwaitSession
                }
                catch {
                    if ($PSAwaitProcess.Id -eq $PID) {
                        Write-Error "The PSAwaitSession never spawned! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        if ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                            Stop-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue
                        }
                        $Counter = 0
                        while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue) -and $Counter -le 15) {
                            Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                            Start-Sleep -Seconds 1
                            $Counter++
                        }
                    }
                }
            }
        }

        Write-Error "The New SSH Key Pair was NOT created! Please review the output of ssh-keygen below. Halting!"
        $global:FunctionResult = "1"
        $SSHKeyGenOutput
        return
    }

    if ($AddToSSHAgent) {
        # Add the New Private Key to the ssh-agent
        $null = [scriptblock]::Create("ssh-add $($PrivKey.FullName)").InvokeReturnAsIs()
        if ($LASTEXITCODE -ne 0) {
            Write-Warning $Error[0].Exception.Message
            Write-Warning "There was a problem adding $($PrivKey.FullName) to the ssh-agent PID $env:SSH_AGENT_PID!"
        }

        [System.Collections.ArrayList]$PublicKeysAccordingToSSHAgent = @()
        $(ssh-add -L) | foreach {
            $null = $PublicKeysAccordingToSSHAgent.Add($_)
        }
        $ThisPublicKeyAccordingToSSHAgent = $PublicKeysAccordingToSSHAgent | Where-Object {$_ -match "$NewSSHKeyName$"}
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToSSHAgent -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromSSHAgent = $($ThisPublicKeyAccordingToSSHAgent -split " ")[0..$ArrayPositionBeforeComment] -join " "

        $ThisPublicKeyAccordingToFile = Get-Content $PubKey.FullName
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToFile -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromFile = $($ThisPublicKeyAccordingToFile -split " ")[0..$ArrayPositionBeforeComment] -join " "

        if ($PublicKeySansCommentFromSSHAgent -ne $PublicKeySansCommentFromFile) {
            Write-Warning "The public key according to the ssh-agent does NOT match the public key content in $($PubKey.FullName)! It appears the private key was never added to the ssh-agent!"
        }

        Write-Host "The Private Key $PublicKeyLocationFinal has been added to the ssh-agent service." -ForegroundColor Green
        
        if (!$RemovePrivateKey) {
            Write-Host "It is now safe to delete the private key (i.e. $($PrivKey.FullName)) since it has been added to the ssh-agent." -ForegroundColor Green
        }
    }

    if ($AddToRemoteHostAuthKeys) {
        if ($RemoteHostNetworkInfo.FQDN) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.FQDN
        }
        elseif ($RemoteHostNetworkInfo.HostName) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.HostName
        }
        elseif ($RemoteHostNetworkInfo.IPAddressList[0]) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.IPAddressList[0]
        }
        
        try {
            Add-PublicKeyToRemoteHost -PublicKeyPath $PubKey.FullName -RemoteHost $RemoteHostLocation -RemoteHostUserName $RemoteHostUserName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to add the public key to the authorized_keys file on $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if (!$AddToSSHAgent) {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh -i $PubKey.FullName $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
        else {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
    }

    [pscustomobject]@{
        PublicKeyFilePath       = $PubKey.FullName
        PrivateKeyFilePath      = if (!$RemovePrivateKey) {$PrivKey.FullName} else {"PrivateKey was deleted after being added to the ssh-agent"}
        PublicKeyContent        = Get-Content $(Join-Path $UserSSHDir "$NewSSHKeyName.pub")
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaMr0H+D0yzNKBN4q3CEv+l6Z
# 2t+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOlDIU5PuQt/K4an
# I4FKVJcTOfr0MA0GCSqGSIb3DQEBAQUABIIBAJsesWhJwKFwfAX+LR5uRGfLxApk
# 6DMD6P7ds4CU5OwjieWZZ5zs08rvedVwsMRVXGrZ8lxmyxQhVzwf7EvJgOnUWQah
# RX+Z34mrI2/AJm1bp/OPH1t0nTGoN2mRsG+v04gCVdqLFf/Eqc2i0r9ty2zoVVq5
# Zx+4ReW0H/6BW0AVXtIpebGgTKg7Hj4YNDm7lGlo6VSaQEfpwqFbrxeOECZwy6at
# tb5cw3HaszFQblWeyASTtN5ig4VGTQSRbFzscK5ZYXpBxek42CQFQy8RG10TIuxQ
# ocW7jmowg9VSb0ueiDlSOufZzBN4ua83gnqcWCXqrEaNJjiGg5QB/y/NjJY=
# SIG # End signature block
