<#
.SYNOPSIS
    Start a new encrypted or unencrypted VNC session with a remote host
.DESCRIPTION
    The free version of the Windows VNC Client provided by RealVNC called VNC Connect does not allow for encrypted connections
    to remote VNC servers. This function uses Putty to create an SSH tunnel in order to encrypt VNC traffic when the 
    switch "encrypted" is used.

    The function also has logic to validate ports being used on local and remote hosts. This prevents unintentional closing
    of existing Putty or VNC sessions.
.NOTES
    DEPENDENCEIES
        1) VNC Connect - https://www.realvnc.com/download/vnc/windows/
        2) Putty - http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html

.PARAMETER VNCViewerDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that contains vncviewer.exe

.PARAMETER RemoteHost
    This parameter is MANDATORY.

    This parameter takes a string that represents either a DNS-resolvable address or IP Address running a VNC server.

.PARAMETER RemoteVNCPort
    This parameter is MANDATORY.

    This parameter takes an interger that represents the port number listening on the remote VNC server.

.PARAMETER encrypted
    This parameter is OPTIONAL.

    This parameter is a switch.

    If it is not used, the VNC connection will not be encrypted, and only mandatory parameters
    are needed.

    If it is used, the following additional parameters become mandatory:
    1) LocalPortForSSHTunnel
    2) PuttyDir
    3) SSHUsername
    4) SSHKeyPath

.PARAMETER KillExistingPuttyPortForwarding
    This parameter is OPTIONAL. It should ONLY BE USED iF the "encrypted" switch is used.

    This parameter is a switch.

    If it is used, existing Putty sessions performing port forwarding using $LocalPortForSSHTunnel
    to $RemoteHost`:$RemoteVNCPort will be closed (i.e. the putty.exe PID will be killed). After existing Putty sessions are
    killed, a fesh Putty sessions performing port forwarding using $LocalPortForSSHTunnel to $RemoteHost`:$RemoteVNCPort will be
    created.

    If it is not used, if there is an existing Putty session performing port forwarding using $LocalPortForSSHTunnel
    to $RemoteHost`:$RemoteVNCPort, it will be used. If there is not an existing Putty session performing port forwarding
    using $LocalPortForSSHTunnel to $RemoteHost`:$RemoteVNCPort, one will be created.

.PARAMETER LocalPortForSSHTunnel
    This parameter is OPTIONAL.

    This parameter becomes MANDATORY IF the "encrypted" switch is used.

    This parameter takes an interger that represents the local port to be used for SSH tunnelling.

.PARAMETER PuttyDir
    This parameter is OPTIONAL.

    This parameter becomes MANDATORY IF the "encrypted" switch is used.

    This parameter takes a string the represents the full path to the directory that contains putty.exe

.PARAMETER SSHUsername
    This parameter is OPTIONAL.

    This parameter becomes MANDATORY IF the "encrypted" switch is used.

    This parameter takes a string that represents the SSH username to be used to access the remote host.

.PARAMETER SSHKeyPath
    This parameter is OPTIONAL.

    This parameter becomes MANDATORY IF the "encrypted" switch is used.

    This parameter takes a string that represents the file path to $SSHUsername's SSH Key.

    WARNING. The SSH Key must be in Putty's .ppk format!

.EXAMPLE
    $params1 = @{
        VNCViewerDir = "C:\Program Files\RealVNC\VNC Viewer"
        RemoteHost = "centos7-ws.test2.lab"
        RemoteVNCPort = "5904"
        LocalPortForSSHTunnel = "5999"
        PuttyDir = "C:\Program Files (x86)\PuTTY"
        SSHKeypath = "$HOME\.ssh\centos7-ws_keypair.ppk"
        SSHUserName = "pdadmin"
    }

    New-VNCConnection @params1 -encrypted

.EXAMPLE
    $params2 = @{
        VNCViewerDir = "C:\Program Files\RealVNC\VNC Viewer"
        RemoteHost = "192.168.2.101"
        RemoteVNCPort = "5900"
        LocalPortForSSHTunnel = "5998"
        PuttyDir = "C:\Program Files (x86)\PuTTY"
        SSHKeypath = "$HOME\.ssh\pdadminmacz-pc_keypair.ppk"
        SSHUserName = "pdadmin"
    }

    New-VNCConnection @params2 -encrypted

.EXAMPLE
    New-VNCConnection -VNCViewerDir "C:\Program Files\RealVNC\VNC Viewer"` -RemoteHost "centos7-ws.test2.lab"` -RemoteVNCPort "5904"

#>

function New-VNCConnection {

    [CmdletBinding(
        DefaultParameterSetName='Parameter Set 1', 
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    [Alias('vnc')]
    Param(
        [Parameter(
            Mandatory=$False,
        )]
        [Alias("vncdir")]
        [string]$VNCViewerDir = $(Read-Host -Prompt "Please enter the full path to the directory that contains vncviewer.exe"),

        [Parameter(
            Mandatory=$False,
        )]
        $RemoteHost = $(Read-Host -Prompt "Please enter the IP Address or DNS-resolvable name of the remote host."),

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("remoteport")]
        [int]$RemoteVNCPort = $(Read-Host -Prompt "Please enter the port number listening on the remote VNC Server."),

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("enc")]
        [switch]$encrypted,

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("killputty")]
        [switch]$KillExistingPuttyPortForwarding,

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("localport")]
        [int]$LocalPortForSSHTunnel,

        [Parameter(
            Mandatory=$False,
        )]
        [string]$PuttyDir,

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("sshuname")]
        [string]$SSHUserName,

        [Parameter(
            Mandatory=$False,
        )]
        [Alias("sshkey")]
        [string]$SSHKeyPath
    )

    ##### REGION Helper Functions and Libraries #####

    ## BEGIN Native Helper Functions ##
    function Test-Port
    {
        [CmdletBinding()]
        [Alias('testport')]
        Param(
            [Parameter(Mandatory=$False)]
            $RemoteMachine = $(Read-Host -Prompt "Please enter the IP Address of the remote host."),

            [Parameter(Mandatory=$False)]
            [int]$RemotePort = $(Read-Host -Prompt "Please enter the port number listening on the remote host.")
        )

        Begin {
            ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
            $tcp = New-Object Net.Sockets.TcpClient
            ##### END Variable/Parameter Transforms and PreRun Prep #####
        }

        ##### BEGIN Main Body #####
        Process {
            if ($pscmdlet.ShouldProcess("$RemoteMachine","Test Connection on $RemoteMachine`:$RemotePort")) {
                try {
                    $tcp.Connect($RemoteMachine, $RemotePort)
                }
                catch {}

                if ($tcp.Connected) {
                    $tcp.Close()
                    $open = $true
                }
                else {
                    $open = $false
                }

                $PortTestResult = [pscustomobject]@{
                    Address      = $RemoteMachine
                    Port    = $RemotePort
                    Open    = $open
                }
                $PortTestResult
            }
            ##### END Main Body #####
        }
    }

    function Get-NetworkState {
        [CmdletBinding()]
        [Alias('netstate')]
        Param(
            [Parameter(Mandatory=$False)]
            [int]$LocalPort,

            [Parameter(Mandatory=$False)]
            $RemoteIP
        )

        $ECULPS1 = Get-NetTCPConnection | Where-Object {
            $_.LocalAddress -eq "127.0.0.1" -and
            $_.RemoteAddress -eq "127.0.0.1" -and
            $_.LocalPort -eq "$LocalPort" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario1" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario1"
                Value   = $ECULPS1
            }
        )
        
        $ECULPS2 = Get-NetTCPConnection | Where-Object {
            $_.LocalAddress -eq "127.0.0.1" -and
            $_.RemoteAddress -eq "0.0.0.0" -and
            $_.LocalPort -eq "$LocalPort" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario2" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario2"
                Value   = $ECULPS2
            }
        )

        $ECULPS3 = Get-NetTCPConnection | Where-Object {
            $_.LocalAddress -eq "127.0.0.1" -and
            $_.RemoteAddress -eq "127.0.0.1" -and
            $_.RemotePort -eq "$LocalPort" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario3" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario3"
                Value   = $ECULPS3
            }
        )

        $ECULPS4 = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -ne "$RemoteIP" -and
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -ne "::" -and
            $_.RemotePort -eq "$LocalPort" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario4" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario4"
                Value   = $ECULPS4
            }
        )

        $ECULPS5 = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -ne "$RemoteIP" -and
            $_.RemoteAddress -ne "0.0.0.0" -and
            $_.RemoteAddress -ne "::" -and
            $_.LocalPort -eq "$LocalPort" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario5" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario5"
                Value   = $ECULPS5
            }
        )

        $ECULPS6 = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -eq "$RemoteIP" -and
            $_.OwningProcess -eq $($ExistingConnectionUsingLocalPortScenario2.OwningProcess)
        }
        New-Variable -Name "ExistingConnectionUsingLocalPortScenario6" -Scope Private -Value $(
            New-Object PSObject -Property @{
                Name   = "ExistingConnectionUsingLocalPortScenario6"
                Value   = $ECULPS6
            }
        )

        $NetworkScenarioArray = @()
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario1
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario2
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario3
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario4
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario5
        $NetworkScenarioArray += $ExistingConnectionUsingLocalPortScenario6

        $OwningProcessArray = @()
        $RemoteAddressArray = @()
        foreach ($ECULPS in $NetworkScenarioArray) {
            $OwningProcessArray += $ECULPS.Value.OwningProcess
            $RemoteAddressArray += $ECULPS.Value.RemoteAddress
        }

        New-Variable -Name "NetworkState" -Scope Global -Value $(
            New-Object PSObject -Property @{
                Scenarios           = $NetworkScenarioArray
                OwningProcesses     = $OwningProcessArray
                RemoteAddresses     = $RemoteAddressArray
            }
        )

        Write-Verbose "The PSObject `$NetworkState is now available in the current scope."

        $global:FunctionResult = "0"
    }
    ## END Native Helper Functions ##

    ##### REGION END Helper Functions and Libraries #####


    ##### BEGIN Parameter Validation #####
    # Validate $VNCViewerDir
    if (! $(Test-Path $VNCViewerDir)) {
        Write-Verbose "The path $VNCViewerDir was not found! Halting!"
        Write-Error "The path $VNCViewerDir was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Validate $RemoteHost
    if (! $(Test-Connection $RemoteHost -Count 1 -Quiet)) {
        Write-Verbose "Unable to connect to $RemoteHost. Please ensure $RemoteHost can be resolved and try again. Halting!"
        Write-Error "Unable to connect to $RemoteHost. Please ensure $RemoteHost can be resolved and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $RemoteHostIPObject = [ipaddress]$RemoteHost
    }
    catch [System.Management.Automation.RuntimeException] {
        Write-Verbose "The parameter `$RemoteHost is NOT an IP Address. Attempting to determine IP..."
        [string]$RemoteHostIP = $(Resolve-DnsName -Name $RemoteHost).IPAddress
    }
    finally {
        if ($RemoteHostIPObject) {
            [string]$RemoteHostIP = $RemoteHostIPObject.IPAddressToString
        }
    }

    # Validate $RemoteVNCPort
    #if (! $(Test-NetConnection -ComputerName $RemoteHostIP -Port $RemoteVNCPort).TcpTestSucceeded)
    if (! $(Test-Port -RemoteMachine $RemoteHostIP -RemotePort $RemoteVNCPort).Open) {
        Write-Verbose "The port $RemoteVNCPort on remote host $RemoteHost is not open. Halting!"
        Write-Error "The port $RemoteVNCPort on remote host $RemoteHost is not open. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($encrypted) {
        # Validate $LocalPortForSSHTunnel
        if (! $LocalPortForSSHTunnel) {
            [int]$LocalPortForSSHTunnel = Read-Host -Prompt "Please enter the local port number that will be used for the ssh tunnel."
        }

        if (! $PuttyDir) {
            $PuttyDir = Read-Host -Prompt "Please enter the full path to the directory that contains putty.exe."
        }
        if (! $(Test-Path $PuttyDir)) {
            Write-Verbose "The path $PuttyDir was not found! Halting!"
            Write-Error "The path $PuttyDir was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Validate $SSHUsername
        if (! $SSHUsername) {
            Read-Host -Prompt "Please enter the username for SSH access on the remote host."
        }

        # Validate $SSHKeyPath
        if (! $SSHKeyPath) {
            $SSHKeyPath = Read-Host -Prompt "Please enter the file path to the Putty .ppk key used to access $RemoteHost"
        }
        if (! $(Test-Path $SSHKeyPath)) {
            Write-Verbose "The path $SSHKeyPath was not found! Halting!"
            Write-Error "The path $SSHKeyPath was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $pos1 = $SSHKeyFile.LastIndexOf("\")
        $SSHKeyFile = $SSHKeyFile.Substring($pos+1)
        $pos2 = $SSHKeyFile.LastIndexOf(".")
        $SSHKeyFileExtension = $SSHKeyFile.Substring($pos+1)
        if ($SSHKeyFileExtension -ne "ppk") {
            Write-Verbose "The SSH Key File must be in Putty's .ppk format! Halting!"
            Write-Error "The SSH Key File must be in Putty's .ppk format! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    ##### END Parameter Validation #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    Get-NetworkState -LocalPort $LocalPortForSSHTunnel -RemoteIP $RemoteHostIP
    if ($global:FunctionResult -eq "0") {
        $OldNetworkState = $global:NetworkState
        Remove-Variable -Name "NetworkState" -Scope Global
    }
    
    $ExistingConnectionUsingLocalPortPIDs = $OldNetworkState.OwningProcesses | Sort-Object | Get-Unique
    Write-Host "Writing PIDs related to existing tunnel connection:"
    $ExistingConnectionUsingLocalPortPIDs
    $ExistingConnectionUsingLocalPortRemoteHost = foreach ($PIDobj in $ExistingConnectionUsingLocalPortPIDs) {
        $PotentialRemoteAddress = $(Get-NetTCPConnection | Where-Object {
            $_.OwningProcess -eq "$PIDobj" -and
            $_.RemoteAddress -ne "::" -and
            $_.RemoteAddress -ne "0.0.0.0" -and
            $_.RemoteAddress -ne "127.0.0.1"
        }).RemoteAddress
        if ($PotentialRemoteAddress -ne $null)
        {
            $PotentialRemoteAddress
        }
    }
    Write-Host "Writing `$ExistingConnectionUsingLocalPortRemoteHost IP Address:"
    $ExistingConnectionUsingLocalPortRemoteHost

    # Re-Used Error Messages
    $LocalPortInUseErrorMsg = "There is already a tunnel using local port $LocalPortForSSHTunnel! (It's connected to remote host $ExistingConnectionUsingLocalPortRemoteHost). Halting!"
    $LocalPortInUseLiveVNCSessionError = "There is already an active VNC session using an SSH tunnel using local port $LocalPortForSSHTunnel! (It's connected to remote host $ExistingConnectionUsingLocalPortRemoteHost). Halting!"

    $VNCViewerPIDs = $(Get-Process -Name vncviewer -ErrorAction SilentlyContinue).Id

    if ($encrypted) {
        if ($VNCViewerPIDs) {
            $VNCSessionsUsingPortForwarding = foreach ($VNCPID in $VNCViewerPIDs) {
                $(Get-NetTCPConnection | Where-Object {
                    $_.OwningProcess -eq "$VNCPID" -and
                    $_.RemotePort -eq "$LocalPortForSSHTunnel" -and
                    $_.State -ne "TimeWait" -and
                    $_.State -ne "CloseWait"
                }).OwningProcess
            }

            $VNCProcessesToKill = $VNCSessionsUsingPortForwarding | Sort-Object | Get-Unique

            <#
            foreach ($VNCProcessID in $VNCProcessesToKill) {
                if ($(Get-Process -id $VNCProcessID).ProcessName -eq "vncviewer")
                {
                    Stop-Process -id $VNCProcessID
                    Start-Sleep -Seconds 1
                }
            }
            #>
        }

        # Determine if there is already an active VNC Session over an SSH Tunnel to $RemoteHost
        # If so, kill the corresponding VNC PID and Putty PID
        $PuttySessionsUsingVNCPortForwardingPrep = Get-NetTCPConnection | Where-Object {
            $_.RemoteAddress -eq "$RemoteHostIP" -or
            $_.LocalPort -eq "$LocalPortForSSHTunnel" -and
            $_.State -ne "TimeWait" -and
            $_.State -ne "CloseWait"
        }
        if ($PuttySessionsUsingVNCPortForwardingPrep) {
            $PuttySessionsUsingVNCPortForwardingPrep2 = $($PuttySessionsUsingVNCPortForwardingPrep | Group-Object -Property OwningProcess | Where-Object {$_.Count -gt 2})
            $PuttySessionsUsingVNCPortForwarding = $($PuttySessionsUsingVNCPortForwardingPrep2.Name) | Sort-Object | Get-Unique
            Write-Host "Writing PID(s) for `$PuttySessionsUsingVNCPortForwarding"
            $PuttySessionsUsingVNCPortForwarding

            if ($KillExistingPuttyPortForwarding) {
                $PuttyProcessesToKill = foreach ($PuttyPID in $PuttySessionsUsingVNCPortForwarding) {
                    $NumberOfConnections = $($PuttySessionsUsingVNCPortForwardingPrep2.Group | Where-Object {
                        $_.OwningProcess -eq $PuttyPID -and
                        $_.LocalPort -eq "$LocalPortForSSHTunnel"
                    }).Count
                    if ($NumberofConnections -gt 1) {
                        $PuttyPID
                    }
                }
                Write-Host "Writing PID(s) `$PuttyProcessesToKill"
                $PuttyProcessesToKill

                foreach ($PuttyPIDObj in $PuttyProcessesToKill) {
                    if ($(Get-Process -id $PuttyPIDObj).ProcessName -eq "putty") {
                        Stop-Process -id $PuttyPIDObj
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }
    }

    if (! $encrypted) {
        if ($VNCViewerPIDs) {
            $VNCProcessesToKill = $(Get-NetTCPConnection | Where-Object {
                $_.RemotePort -eq "$RemoteVNCPort" -and
                $_.State -ne "TimeWait" -and
                $_.State -ne "CloseWait"
            }).OwningProcess
        }

        <#
        foreach ($VNCProcessID in $VNCProcessesToKill) {
            if ($(Get-Process -id $VNCProcessID).ProcessName -eq "vncviewer")
            {
                Stop-Process -id $VNCProcessID
                Start-Sleep -Seconds 1
            }
        }
        #>
    }
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    if ($encrypted) {
        if ($RemoteAddressArray -contains $RemoteHostIP) {
            Write-Warning "There is already a tunnel using local port $LocalPortForSSHTunnel! (It's connected to remote host $ExistingConnectionUsingLocalPortRemoteHost)."
        }
        if ($RemoteAddressArray -notcontains $RemoteHostIP -and
        $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario6"}).Value -ne $null) {
            Write-Verbose "Msg 1"
            Write-Verbose "$LocalPortInUseErrorMsg"
            Write-Error "$LocalPortInUseErrorMsg"
            $global:FunctionResult = "1"
            return
        }
        if ($pscmdlet.ShouldProcess("$env:ComputerName","Set Up SSH Tunnel on Local Port $LocalPortForSSHTunnel")) {
            if (! $($($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario1"}).Value -ne $null -or
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value -ne $null -or
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario3"}).Value -ne $null -or
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario4"}).Value -ne $null -or
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario5"}).Value -ne $null)) {
                & "$PuttyDir\putty.exe" -ssh $RemoteHost -l $SSHUserName -i $SSHKeyPath -L $LocalPortForSSHTunnel`:$RemoteHost`:$RemoteVNCPort
                Start-Sleep -Seconds 2
            }
        }

        Get-NetworkState -LocalPort $LocalPortForSSHTunnel -RemoteIP $RemoteHostIP
        if ($global:FunctionResult -eq "0") {
            $NewNetworkState = $global:NetworkState
            Remove-Variable -Name "NetworkState" -Scope Global
        }
        
        if ($($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario1"}).Value -ne $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value -ne $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario3"}).Value -ne $null) {
            Write-Verbose "Msg 2"
            Write-Verbose "$LocalPortInUseLiveVNCSessionError"
            Write-Error "$LocalPortInUseLiveVNCSessionError"
            $global:FunctionResult = "1"
            return
        }

        if ($NewNetworkState.RemoteAddressArray -notcontains $RemoteHostIP -and
        ! $($($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario1"}).Value -eq $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value -ne $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario3"}).Value -eq $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario4"}).Value -eq $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario5"}).Value -eq $null -and
        $($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario6"}).Value -eq $null)) {
            Write-Verbose "Msg 3"
            Write-Host "$LocalPortInUseErrorMsg"
            Write-Error "$LocalPortInUseErrorMsg"
            $global:FunctionResult = "1"
            return
        }
        if ($ExistingConnectionUsingLocalPortRemoteHost -ne $RemoteHostIP -and
        $($($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value).LocalPort -eq $LocalPortForSSHTunnel -and
        $ExistingConnectionUsingLocalPortRemoteHost -ne $null) {
            Write-Verbose "Msg 4"
            Write-Host "$LocalPortInUseErrorMsg"
            Write-Error "$LocalPortInUseErrorMsg"
            $global:FunctionResult = "1"
            return
        }
        if ($pscmdlet.ShouldProcess("$env:ComputerName","Start VNC Connection via SSH Tunnel on $LocalPortForSSHTunnel")) {
            if ($($NewNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value -ne $null -or
            $($($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario1"}).Value -eq $null -and
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario2"}).Value -eq $null -and
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario3"}).Value -eq $null -and
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario4"}).Value -eq $null -and
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario5"}).Value -eq $null -and
            $($OldNetworkState.Scenarios | Where-Object {$_.Name -eq "ExistingConnectionUsingLocalPortScenario6"}).Value -eq $null)) {
                & "$VNCViewerDir\vncviewer.exe" -useaddressbook 127.0.0.1:$LocalPortForSSHTunnel
            }
        }
    }
    if (! $encrypted)
    {
        & "$VNCViewerDir\vncviewer.exe" -useaddressbook $RemoteHostIP`:$RemoteVNCPort
    }

    ##### END Main Body #####

    $global:FunctionResult = "0"

}










# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMykIfR43THMkbsQWPDQskOXy
# hlagggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE1MDkwOTA5NTAyNFoXDTE3MDkwOTEwMDAyNFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmRIzy6nwK
# uqvhoz297kYdDXs2Wom5QCxzN9KiqAW0VaVTo1eW1ZbwZo13Qxe+6qsIJV2uUuu/
# 3jNG1YRGrZSHuwheau17K9C/RZsuzKu93O02d7zv2mfBfGMJaJx8EM4EQ8rfn9E+
# yzLsh65bWmLlbH5OVA0943qNAAJKwrgY9cpfDhOWiYLirAnMgzhQd3+DGl7X79aJ
# h7GdVJQ/qEZ6j0/9bTc7ubvLMcJhJCnBZaFyXmoGfoOO6HW1GcuEUwIq67hT1rI3
# oPx6GtFfhCqyevYtFJ0Typ40Ng7U73F2hQfsW+VPnbRJI4wSgigCHFaaw38bG4MH
# Nr0yJDM0G8XhAgMBAAGjggECMIH/MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQW
# BBQ4uUFq5iV2t7PneWtOJALUX3gTcTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBR2
# lbqmEvZFA0XsBkGBBXi2Cvs4TTAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vcGtp
# L2NlcnRkYXRhL1plcm9EQzAxLmNybDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUH
# MAKGIGh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb0RDMDEuY3J0MA0GCSqGSIb3DQEB
# CwUAA4IBAQAUFYmOmjvbp3goa3y95eKMDVxA6xdwhf6GrIZoAg0LM+9f8zQOhEK9
# I7n1WbUocOVAoP7OnZZKB+Cx6y6Ek5Q8PeezoWm5oPg9XUniy5bFPyl0CqSaNWUZ
# /zC1BE4HBFF55YM0724nBtNYUMJ93oW/UxsWL701c3ZuyxBhrxtlk9TYIttyuGJI
# JtbuFlco7veXEPfHibzE+JYc1MoGF/whz6l7bC8XbgyDprU1JS538gbgPBir4RPw
# dFydubWuhaVzRlU3wedYMsZ4iejV2xsf8MHF/EHyc/Ft0UnvcxBqD0sQQVkOS82X
# +IByWP0uDQ2zOA1L032uFHHA65Bt32w8MIIFmzCCBIOgAwIBAgITWAAAADw2o858
# ZSLnRQAAAAAAPDANBgkqhkiG9w0BAQsFADA9MRMwEQYKCZImiZPyLGQBGRYDTEFC
# MRQwEgYKCZImiZPyLGQBGRYEWkVSTzEQMA4GA1UEAxMHWmVyb1NDQTAeFw0xNTEw
# MjcxMzM1MDFaFw0xNzA5MDkxMDAwMjRaMD4xCzAJBgNVBAYTAlVTMQswCQYDVQQI
# EwJWQTEPMA0GA1UEBxMGTWNMZWFuMREwDwYDVQQDEwhaZXJvQ29kZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8LM3f3308MLwBHi99dvOQqGsLeC11p
# usrqMgmEgv9FHsYv+IIrW/2/QyBXVbAaQAt96Tod/CtHsz77L3F0SLuQjIFNb522
# sSPAfDoDpsrUnZYVB/PTGNDsAs1SZhI1kTKIjf5xShrWxo0EbDG5+pnu5QHu+EY6
# irn6C1FHhOilCcwInmNt78Wbm3UcXtoxjeUl+HlrAOxG130MmZYWNvJ71jfsb6lS
# FFE6VXqJ6/V78LIoEg5lWkuNc+XpbYk47Zog+pYvJf7zOric5VpnKMK8EdJj6Dze
# 4tJ51tDoo7pYDEUJMfFMwNOO1Ij4nL7WAz6bO59suqf5cxQGd5KDJ1ECAwEAAaOC
# ApEwggKNMA4GA1UdDwEB/wQEAwIHgDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3
# FQiDuPQ/hJvyeYPxjziDsLcyhtHNeIEnofPMH4/ZVQIBZAIBBTAdBgNVHQ4EFgQU
# a5b4DOy+EUyy2ILzpUFMmuyew40wHwYDVR0jBBgwFoAUOLlBauYldrez53lrTiQC
# 1F94E3EwgeMGA1UdHwSB2zCB2DCB1aCB0qCBz4aBq2xkYXA6Ly8vQ049WmVyb1ND
# QSxDTj1aZXJvU0NBLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NlcnRp
# ZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmli
# dXRpb25Qb2ludIYfaHR0cDovL3BraS9jZXJ0ZGF0YS9aZXJvU0NBLmNybDCB4wYI
# KwYBBQUHAQEEgdYwgdMwgaMGCCsGAQUFBzAChoGWbGRhcDovLy9DTj1aZXJvU0NB
# LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
# Tj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NBQ2VydGlmaWNhdGU/YmFz
# ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCsGCCsGAQUFBzAC
# hh9odHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EuY3J0MBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQEL
# BQADggEBACbc1NDl3NTMuqFwTFd8NHHCsSudkVhuroySobzUaFJN2XHbdDkzquFF
# 6f7KFWjqR3VN7RAi8arW8zESCKovPolltpp3Qu58v59qZLhbXnQmgelpA620bP75
# zv8xVxB9/xmmpOHNkM6qsye4IJur/JwhoHLGqCRwU2hxP1pu62NUK2vd/Ibm8c6w
# PZoB0BcC7SETNB8x2uKzJ2MyAIuyN0Uy/mGDeLyz9cSboKoG6aQibnjCnGAVOVn6
# J7bvYWJsGu7HukMoTAIqC6oMGerNakhOCgrhU7m+cERPkTcADVH/PWhy+FJWd2px
# ViKcyzWQSyX93PcOj2SsHvi7vEAfCGcxggH1MIIB8QIBATBUMD0xEzARBgoJkiaJ
# k/IsZAEZFgNMQUIxFDASBgoJkiaJk/IsZAEZFgRaRVJPMRAwDgYDVQQDEwdaZXJv
# U0NBAhNYAAAAPDajznxlIudFAAAAAAA8MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQI6KaPQwFP
# S4PN+QO8vtknlCVHlTANBgkqhkiG9w0BAQEFAASCAQCGD2e+2uX93HaLLDshdhG0
# 4Ws7lC7iK3cV/iT4LK4EAjNBpuqBBuCOwkRlJ4BWUauKhJ1nIKWwmqSfFjCRGlSw
# F0YO2fpNtwDmwIXCg8/V4oxKTNCx8f0duzMVkLGQ8p7XuyEf6D63MUT57pAA47b0
# qqNy74uqqaqoaEkMdgePw19LWjL/oC2nqpIldFum5SWmyVvnKZEimNuuHdtYfFab
# wKD3FuUC8lR6PK5ndWegCKKIrnbwB1wOb0EtYUadoOpK0hoLbDlpt8PwEB6zjPeO
# 2ShRb8T6sGfD/MWsb0zMGuVfW02KkC8LG9DRJStvYxnZLL43VgnLPtLA3oJEq8/r
# SIG # End signature block
