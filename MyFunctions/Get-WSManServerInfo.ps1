<#
NOTES About WinRM:

The "System" Process on the WSManServer ConnectionStartTime property indicates that actual activity takes place 
over an open WinRM connection.

The "wsmprovhost" Process on the WSManServer ConnectionStartTime property at best indicates when a new
WSMan connection was originally created.

#>
function Get-WsManServerInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$RemoteComputer = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserAccount = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1]),
        
        [Parameter(Mandatory=$False)]
        $Psswd,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$RemoteCreds,

        [Parameter(Mandatory=$False)]
        [switch]$UseSSL,

        [Parameter(Mandatory=$False)]
        [switch]$DoNotProbeWSManClients

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($UserAccount -and $Psswd -and $RemoteCreds) {
        Write-Verbose "Please use EITHER the RemoteCreds parameter OR the UserAccount and Psswd parameters! Halting!"
        Write-Error "Please use EITHER the RemoteCreds parameter OR the UserAccount and Psswd parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserAccount) {
        $UserNameFormatOne = $UserAccount | Select-String -Pattern "\\"
        $UserNameFormatTwo = $UserAccount | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $UserAccount = $UserAccount.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $UserAccount = $UserAccount.Split("@")[0]
        }
    }

    if ($Psswd) {
        if ($Psswd.GetType().FullName -eq "System.String") {
            $Psswd = ConvertTo-SecureString $Psswd -AsPlainText -Force
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    $WSManServerMapping = @()
    if ($UserAccount -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($RemoteComputer -ne $env:COMPUTERNAME -and $RemoteComputer -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $RemoteComputer.Count -gt 1) {
        for ($i=0; $i -lt $RemoteComputer.Count; $i++) {
            $RemoteHostNetworkInfoArray = @()
            if (! $(Test-IsValidIPAddress -IPAddress $RemoteComputer[$i])) {
                try {
                    $RemoteHostIP = $(Resolve-DNSName $RemoteComputer[$i]).IPAddress
                }
                catch {
                    Write-Verbose "Unable to resolve $($RemoteComputer[$i])!"
                }
                if ($RemoteHostIP) {
                    # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
                    $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                    # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
                    if ($RemoteHostIP.Count -gt 1) {
                        $RemoteHostIP = $RemoteHostIP[0]
                    }
                    $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                    $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostName).Name
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                    $RemoteHostUserName = "$UserAccount@$RemoteHostNameFQDNPost"

                    $RemoteHostNetworkInfoArray += $RemoteHostIP
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                }
                if (!$RemoteHostIP) {
                    Write-Error "Unable to resolve $($RemoteComputer[$i])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            if (Test-IsValidIPAddress -IPAddress $RemoteComputer[$i]) {
                try {
                    $RemoteHostIP = $RemoteComputer[$i]
                    $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                    $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostName).Name
                }
                catch {
                    Write-Warning "Unable to resolve $RemoteComputer to HostName using rDNS lookup. Please ensure there is a PTR record available for $RemoteComputer on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteHostNameFQDN) {
                    if ($($RemoteHostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteHostNameFQDN.IndexOf(".")
                        $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                        $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                        $RemoteHostNameFQDNPost = $RemoteHostNameFQDN
                    }
                    $RemoteHostUserName = "$UserAccount@$RemoteHostNameFQDNPost"

                    $RemoteHostNetworkInfoArray += $RemoteHostIP
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                }
                if (!$RemoteHostNameFQDN) {
                    Write-Error "Unable to resolve $RemoteComputer! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            if ($RemoteCreds) {
                $FinalCreds = $RemoteCreds
            }
            else {
                if (!$Psswd) {
                    $Psswd = Read-Host -Prompt "Please enter the password for $UserAccount" -AsSecureString
                }
                # If $ComputerName[0] is on a different Domain, change $UserAccount to $RemoteHostUserName
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                    $UserAccount = $RemoteHostUserName
                }
                $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccount, $Psswd
            }

            # Collect Information About WSManServer
            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                # Test $FinalCreds against WSManServer. If they don't work, move on to the next hostname in $RemoteComputer
                try {
                    $RemoteWSmanServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[$i] -ConnectionURI "http://$($RemoteComputer[$i]):5985/wsman" -ResourceURI "shell" -Enumerate -Credential $FinalCreds

                    if (!$RemoteWSmanServerWSManInstances) {
                        throw
                    }
                }
                catch {
                    Write-Warning "The credentials used for $($RemoteComputer[$i]) did not work. Skipping $($RemoteComputer[$i])"
                    continue
                }
                
                $RemoteServerProcesses = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    try {
                        Get-Process -IncludeUserName
                    }
                    catch {
                        Get-Process
                    }
                } -Credential $FinalCreds

                $RemoteServerWSMANTCPConnections = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
                } -Credential $FinalCreds
            }
            else {
                $RemoteWSmanServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[$i] -ConnectionURI "http://$($RemoteComputer[$i]):5985/wsman" -ResourceURI "shell" -Enumerate
                $RemoteServerProcesses = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    try {
                        Get-Process -IncludeUserName
                    }
                    catch {
                        Get-Process
                    }
                }

                $RemoteServerWSMANTCPConnections = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
                }
            }
            
            $RemoteWSManServerClientIPs = $RemoteWSmanServerWSManInstances.ClientIP
            $RemoteServerWSManProcesses = foreach ($WSManInstance in $RemoteWSmanServerWSManInstances) {
                $RemoteServerProcesses | Where-Object {$_.Id -eq $WSManInstance.ProcessId}
            }
            $RemoteServerWSManProcesses = foreach ($Process in $RemoteServerWSManProcesses) {
                # Add a UtcCreationTime NoteProperty
                $UtcTimePrep1 = $Process.StartTime
                $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
                $Process | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
                $Process
            }

            # Determine WSMAN Server TCP Connections
            # IMPORTANT NOTE: The Get-NetTCPConnection CreationTime property is accurate for the WSMANServer, but not
            # WSMan Clients. Since it's accurate for the WSManServer, we can feel comfortable doing the below
            $RemoteServerWSMANTCPConnections = foreach ($tcpobj in $RemoteServerWSMANTCPConnections) {
                # Add a UtcCreationTime NoteProperty
                $UtcTimePrep1 = $tcpobj.CreationTime
                $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
                $tcpobj | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
                $tcpobj
            }

            $WSManClientMapping = @()
            if (!$DoNotProbeWSManClients) {
                foreach ($ClientIP in $RemoteWSManServerClientIPs) {
                    try {
                        $NameHost = $(Resolve-DNSName $ClientIP).NameHost
                    }
                    catch {
                        Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                        continue
                    }

                    $InvCmdCollection = @()
                    # Determine if the Credentials that worked on WSManServer will work on WSManClient
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            
                        } -Credential $FinalCreds
                        $InvCmd1DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                        $InvCmdCollection +=, $InvCmd1DateTime

                        if (!$RemoteClientProcesses) {
                            throw
                        }

                        $ClientCreds = $FinalCreds
                    }
                    catch {
                        Write-Warning "Credentials provided for WSManClient $NameHost are not valid."
                        $InputNewCredsAsk = Read-Host -Prompt "Would you like to supply different credentials for $NameHost? [Yes/No]"
                        if ($InputNewCredsAsk -match "Yes|yes|Y|y") {
                            $tempuname = Read-Host -Prompt "Please enter the name of a User Account that has access to $NameHost"
                            $temppwd = Read-Host -Prompt "Please enter the password for $tempuname" -AsSecureString
                            $ClientCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $tempuname,$temppwd
                        }
                        else {
                            Write-Warning "Skipping gathering data for WSManClient $NameHost"
                            continue
                        }
                    }
                    if (!$RemoteClientProcesses) {
                        Write-Host "RemoteClientProcesses still not defined. Trying newly entered ClientCreds..."
                        try {
                            $RemoteClientProcesses = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                                try {
                                    Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                catch {
                                    Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                
                            } -Credential $ClientCreds
                            $InvCmd2DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                            $InvCmdCollection +=, $InvCmd2DateTime

                            if (!$RemoteClientProcesses) {
                                throw
                            }
                        }
                        catch {
                            Write-Warning "Credentials provided for WSManClient $NameHost are not valid. Skipping gathering data for WSManClient $NameHost"
                            continue
                        }
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    } -Credential $ClientCreds
                    $InvCmd3DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                    $InvCmdCollection +=, $InvCmd3DateTime

                    foreach ($ClientTCPIPConnection in $RemoteWSManClientTCPIPConnections) {
                        # Since the Get-NetTCPConnection CreationTime property is only reliable on Windows 10 and
                        # Windows Server 2016 and higher, we need to probe each client to determine if their OS
                        # is Windows 10 or Windows Server 2016 or higher. If not, then make sure the
                        # WSManClientTCPConnection and ConnectionStartTime properties are null and the
                        # PossibleWSManClientTCPConnections and PossibleConnectionStartTime properties are
                        # filled in.
                        #$ClientOSCheck = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                        #    [version]$($(Get-CimInstance -ClassName Win32_OperatingSystem).Version)
                        #} -Credential $FinalCreds

                        # Add a UtcCreationTime NoteProperty
                        $UtcTimePrepA = $ClientTCPIPConnection.CreationTime
                        $UtcTimePrepB = [System.DateTimeOffset]$UtcTimePrepA
                        $ClientTCPIPConnection | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrepB -Force

                        # Map TCP Connections to Processes where possible
                        $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $RemoteServerWSMANTCPConnections) {
                            if ($ClientTCPIPConnection.LocalPort -eq $WSManServerTCPConnection.RemotePort -and
                            $WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                                $WSManServerTCPConnection
                            }
                        }
                        $MappedWSManServerProcess = foreach ($Process in $RemoteServerProcesses) {
                            $WSManServProcId = $($RemoteWSmanServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                            if ($Process.Id -eq $WSManServProcId) {
                                $Process
                            }
                        }
                        $MappedWSManClientTCPConnection = $ClientTCPIPConnection
                        $MappedWSManClientProcess = $RemoteClientProcesses | Where-Object {
                            $_.Id -eq $ClientTCPIPConnection.OwningProcess
                        }
                        if ($MappedWSManServerProcess) {
                            $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                        }
                        else {
                            $MappedConnectionStartTime = ""
                        }
                        if ($MappedWSManServerTCPConnection.CreationTime) {
                            [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $MappedWSManServerTCPConnection.CreationTime
                            $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                        }
                        else {
                            $MappedWSManServerActivityUTCDateTime = ""
                        }

                        New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                            [pscustomobject][ordered]@{
                                WSManServerName                     = $RemoteComputer[$i]
                                WSManServerProcess                  = $MappedWSManServerProcess
                                WSManServerTCPConnection            = $MappedWSManServerTCPConnection
                                WSManClientName                     = $NameHost
                                WSManClientProcess                  = $MappedWSManClientProcess
                                WSManClientTCPConnection            = $MappedWSManClientTCPConnection
                                ConnectionStartTime                 = $MappedConnectionStartTime
                                MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                            }
                        ) -Force

                        if ($MappedWSManServerActivityUTCDateTime) {
                            # Filter out TCP Connections made by this function via Invoke-Command
                            New-Variable -Name "TimeCheck$($MappedWSManServerTCPConnection.RemotePort)" -Value $(
                                $($([System.DateTimeOffset]$(Get-Date)).UtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds
                            ) -Force

                            $InvCmdTimeCheck = @()
                            foreach ($InvCmdUtcDateTime in $InvCmdCollection) {
                                $InvCmdTimeCheck +=, $($($InvCmdUtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds -gt 3)
                            }
                            if ($InvCmdTimeCheck -contains $false) {
                                $AddMatch = $false
                            }
                            else {
                                $AddMatch = $true
                            }

                            if ($MappedWSManServerTCPConnection -and $AddMatch -and
                            $(Get-Variable -Name "TimeCheck$($MappedWSManServerTCPConnection.RemotePort)" -ValueOnly) -gt 3 -and
                            $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -or
                            $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress)) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        else {
                            if ($MappedWSManServerTCPConnection -and
                            $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -or
                            $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress)) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                    }
                }
            }
            else {
                foreach ($ClientIP in $RemoteWSManServerClientIPs) {
                    try {
                        $NameHost = $(Resolve-DNSName $ClientIP).NameHost
                    }
                    catch {
                        Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                        continue
                    }

                    # Map TCP Connections to Processes where possible
                    $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $RemoteServerWSMANTCPConnections) {
                        if ($WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                            $WSManServerTCPConnection
                        }
                    }

                    foreach ($WSManServTCPObj in $MappedWSManServerTCPConnection) {
                        $MappedWSManServerProcess = foreach ($Process in $RemoteServerProcesses) {
                            $WSManServProcId = $($RemoteWSmanServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                            if ($Process.Id -eq $WSManServProcId) {
                                $Process
                            }
                        }
                        if ($MappedWSManServerProcess) {
                            $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                        }
                        else {
                            $MappedConnectionStartTime = ""
                        }
                        if ($WSManServTCPObj.CreationTime) {
                            [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $WSManServTCPObj.CreationTime
                            $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                        }
                        else {
                            $MappedWSManServerActivityUTCDateTime = ""
                        }

                        New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                            [pscustomobject][ordered]@{
                                WSManServerName                     = $RemoteComputer[$i]
                                WSManServerProcess                  = $MappedWSManServerProcess
                                WSManServerTCPConnection            = $WSManServTCPObj
                                WSManClientName                     = $NameHost
                                ConnectionStartTime                 = $MappedConnectionStartTime
                                MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                            }
                        ) -Force

                        # Filter out TCP Connections made by this function via Invoke-Command
                        if ($MappedWSManServerActivityUTCDateTime) {
                            New-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -Value $(
                                $($([System.DateTimeOffset]$(Get-Date)).UtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds
                            ) -Force

                            if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -and
                            $(Get-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -ValueOnly) -gt 3) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        else {
                            if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        <#
                        if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -and
                        $($WSManServTCPObj.UtcCreationTime.UtcDateTime).TimeOfDay -ne "00:00:00" -and 
                        $(Get-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -ValueOnly) -gt 3) {
                            $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                        }
                        #>
                    }
                }
            }

            # Attempt to Identify the initial connection versus the connection that actually handle WinRM Activity
            $UpdatedWSManClientMappingPrep = $WSManClientMapping | Group-Object -Property MostRecentConnectionActivity
            $Connections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -gt 1}).Group
            $InitialConnections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -eq 1}).Group
            $ActiveConnections = foreach ($connection in $Connections) {
                if ($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess") {
                    if ($connection.MostRecentConnectionActivity -and
                    $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00" -and
                    $connection.WSManClientProcess -ne $null) {
                        $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                        $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                        $connection
                    }
                }
                else {
                    if ($connection.MostRecentConnectionActivity -and
                    $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00") {
                        $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                        $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                        $connection
                    }
                }
            }

            $InactiveConnections = foreach ($connection in $Connections) {
            if (!$($connection.MostRecentConnectionActivity) -or
                $($connection.MostRecentConnectionActivity).TimeOfDay -eq "00:00:00" -or
                $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientTCPConnection" -and $connection.WSManClientTCPConnection -eq $null) -or
                $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess" -and $connection.WSManClientProcess -eq $null)) {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false -Force
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false -Force
                    $connection
                }
            }

            $InitialConnections = foreach ($connection in $InitialConnections) {
                $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false
                $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $true
                $connection
            }
            $UpdatedWSManClientMapping = $InactiveConnections + $ActiveConnections + $InitialConnections

            New-Variable -Name "PSRemotingInfoFor$($RemoteComputer[$i])" -Value $(
                [pscustomobject][ordered]@{
                    WSManServer         = $RemoteComputer[$i]
                    WSManClientMapping  = $UpdatedWSManClientMapping
                }
            )

            $WSManServerMapping +=, $(Get-Variable -Name "PSRemotingInfoFor$($RemoteComputer[$i])" -ValueOnly)

            Remove-Variable -Name "ClientCreds" -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        # NOTE: In this else clause, all references to $RemoteComputer[$i] actually refer to the localhost
        $LocalServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[0] -ConnectionURI "http://$($RemoteComputer[0]):5985/wsman" -ResourceURI "shell" -Enumerate
        $LocalWSManServerClientIPs = $LocalServerWSManInstances.ClientIP
        $LocalServerProcesses = try {Get-Process -IncludeUserName} catch {Get-Process}
        $LocalWSManServerProcesses = foreach ($WSManInstance in $LocalServerWSManInstances) {
            $LocalServerProcesses | Where-Object {$_.Id -eq $WSManInstance.ProcessId}
        }
        $LocalWSManServerProcesses = foreach ($Process in $LocalWSManServerProcesses) {
            # Add a UtcCreationTime NoteProperty
            $UtcTimePrep1 = $Process.StartTime
            $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
            $Process | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
            $Process
        }

        $LocalServerWSMANTCPConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
        $LocalServerWSMANTCPConnections = foreach ($tcpobj in $LocalServerWSMANTCPConnections) {
            # Add a UtcCreationTime NoteProperty
            $UtcTimePrep1 = $tcpobj.CreationTime
            $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
            $tcpobj | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
            $tcpobj
        }

        $WSManClientMapping = @()
        if (!$DoNotProbeWSManClients) {
            foreach ($ClientIP in $LocalWSManServerClientIPs) {
                $RemoteClientNetworkInfoArray = @()
                try {
                    $RemoteClientName = $(Resolve-DNSName $ClientIP).NameHost
                    $RemoteClientNameFQDN = $(Resolve-DNSName $RemoteClientName).Name
                }
                catch {
                    Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteClientNameFQDN) {
                    if ($($RemoteClientNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteClientNameFQDN.IndexOf(".")
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN.Substring(0, $pos)
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN
                    }
                    $RemoteClientUserName = "$UserAccount@$RemoteClientNameFQDNPost"

                    $RemoteClientNetworkInfoArray += $ClientIP
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDN
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDNPre
                }
                if (!$RemoteClientNameFQDN) {
                    Write-Error "Unable to resolve $ClientIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # If $ClientIP is on a different Domain, determine Credentials
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteClientNameFQDNPost) {
                    $UserAccount = $RemoteClientUserName

                    if (!$Psswd -and !$RemoteCreds) {
                        $Psswd = Read-Host -Prompt "Please enter the password for $UserAccount" -AsSecureString
                        $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccount, $Psswd
                    }
                    if ($RemoteCreds) {
                        $FinalCreds = $RemoteCreds
                    }

                    # Determine if the Credentials for $ClientIP work
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            
                        } -Credential $FinalCreds

                        if (!$RemoteClientProcesses) {
                            throw
                        }

                        $ClientCreds = $FinalCreds
                    }
                    catch {
                        Write-Warning "Credentials provided for WSManClient $RemoteClientNameFQDN are not valid."
                        $InputNewCredsAsk = Read-Host -Prompt "Would you like to supply different credentials for $RemoteClientNameFQDN? [Yes/No]"
                        if ($InputNewCredsAsk -match "Yes|yes|Y|y") {
                            $tempuname = Read-Host -Prompt "Please enter the name of a User Account that has access to $RemoteClientNameFQDN"
                            $temppwd = Read-Host -Prompt "Please enter the password for $tempuname" -AsSecureString
                            $ClientCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $tempuname,$temppwd
                        }
                        else {
                            Write-Warning "Skipping gathering data for WSManClient $RemoteClientNameFQDN"
                            continue
                        }
                    }
                    if (!$RemoteClientProcesses) {
                        Write-Host "RemoteClientProcesses still not defined. Trying newly entered ClientCreds..."
                        try {
                            $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                                try {
                                    Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                catch {
                                    Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                
                            } -Credential $ClientCreds

                            if (!$RemoteClientProcesses) {
                                throw
                            }
                        }
                        catch {
                            Write-Warning "Credentials provided for WSManClient $RemoteClientNameFQDN are not valid. Skipping gathering data for WSManClient $RemoteClientNameFQDN"
                            continue
                        }
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    } -Credential $ClientCreds
                }
                else {
                    # Determine if the Credentials for $ClientIP work
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                        }

                        if (!$RemoteClientProcesses) {
                            throw
                        }
                    }
                    catch {
                        Write-Warning "Unable to run remote command on $RemoteClientNameFQDN! Please ensure you are using a Domain Admin account on the $RemoteClientNameFQDNPost Domain. Skipping gathering data for WSManClient $RemoteClientNameFQDN..."
                        continue
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    }
                }

                foreach ($ClientTCPIPConnection in $RemoteWSManClientTCPIPConnections) {
                    # Since the Get-NetTCPConnection CreationTime property is only reliable on Windows 10 and
                    # Windows Server 2016 and higher, we need to probe each client to determine if their OS
                    # is Windows 10 or Windows Server 2016 or higher. If not, then make sure the
                    # WSManClientTCPConnection and ConnectionStartTime properties are null and the
                    # PossibleWSManClientTCPConnections and PossibleConnectionStartTime properties are
                    # filled in.
                    #$ClientOSCheck = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                    #    [version]$($(Get-CimInstance -ClassName Win32_OperatingSystem).Version)
                    #} -Credential $FinalCreds

                    # Add a UtcCreationTime NoteProperty
                    $UtcTimePrepA = $ClientTCPIPConnection.CreationTime
                    $UtcTimePrepB = [System.DateTimeOffset]$UtcTimePrepA
                    $ClientTCPIPConnection | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrepB -Force

                    # Map TCP Connections to Processes where possible
                    $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $LocalServerWSMANTCPConnections) {
                        if ($ClientTCPIPConnection.LocalPort -eq $WSManServerTCPConnection.RemotePort -and
                        $WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                            $WSManServerTCPConnection
                        }
                    }
                    $MappedWSManServerProcess = foreach ($Process in $LocalServerProcesses) {
                        $WSManServProcId = $($LocalServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                        if ($Process.Id -eq $WSManServProcId) {
                            $Process
                        }
                    }
                    $MappedWSManClientTCPConnection = $ClientTCPIPConnection
                    $MappedWSManClientProcess = $RemoteClientProcesses | Where-Object {
                        $_.Id -eq $ClientTCPIPConnection.OwningProcess
                    }
                    if ($MappedWSManServerProcess) {
                        $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                    }
                    else {
                        $MappedConnectionStartTime = ""
                    }
                    if ($MappedWSManServerTCPConnection.CreationTime) {
                        [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $MappedWSManServerTCPConnection.CreationTime
                        $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                    }
                    else {
                        $MappedWSManServerActivityUTCDateTime = ""
                    }

                    New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                        [pscustomobject][ordered]@{
                            WSManServerName                     = $RemoteComputer[0]
                            WSManServerProcess                  = $MappedWSManServerProcess
                            WSManServerTCPConnection            = $MappedWSManServerTCPConnection
                            WSManClientName                     = $RemoteClientNameFQDN
                            WSManClientProcess                  = $MappedWSManClientProcess
                            WSManClientTCPConnection            = $MappedWSManClientTCPConnection
                            ConnectionStartTime                 = $MappedConnectionStartTime
                            MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                        }
                    ) -Force

                    if ($MappedWSManServerTCPConnection -and
                    $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress -or
                    $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress)) {
                        $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                    }
                }
            }
        }
        else {
            foreach ($ClientIP in $LocalWSManServerClientIPs) {
                $RemoteClientNetworkInfoArray = @()
                try {
                    $RemoteClientName = $(Resolve-DNSName $ClientIP).NameHost
                    $RemoteClientNameFQDN = $(Resolve-DNSName $RemoteClientName).Name
                }
                catch {
                    Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteClientNameFQDN) {
                    if ($($RemoteClientNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteClientNameFQDN.IndexOf(".")
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN.Substring(0, $pos)
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN
                    }
                    $RemoteClientUserName = "$UserAccount@$RemoteClientNameFQDNPost"

                    $RemoteClientNetworkInfoArray += $ClientIP
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDN
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDNPre
                }
                if (!$RemoteClientNameFQDN) {
                    Write-Error "Unable to resolve $ClientIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # Map TCP Connections to Processes where possible
                $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $LocalServerWSMANTCPConnections) {
                    if ($WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                        $WSManServerTCPConnection
                    }
                }

                foreach ($WSManServTCPObj in $MappedWSManServerTCPConnection) {
                    $MappedWSManServerProcess = foreach ($Process in $LocalServerProcesses) {
                        $WSManServProcId = $($LocalServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                        if ($Process.Id -eq $WSManServProcId) {
                            $Process
                        }
                    }
                    if ($MappedWSManServerProcess) {
                        $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                    }
                    else {
                        $MappedConnectionStartTime = ""
                    }
                    if ($WSManServTCPObj.CreationTime) {
                        [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $WSManServTCPObj.CreationTime
                        $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                    }
                    else {
                        $MappedWSManServerActivityUTCDateTime = ""
                    }

                    New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                        [pscustomobject][ordered]@{
                            WSManServerName                     = $RemoteComputer[0]
                            WSManServerProcess                  = $MappedWSManServerProcess
                            WSManServerTCPConnection            = $WSManServTCPObj
                            WSManClientName                     = $RemoteClientNameFQDN
                            ConnectionStartTime                 = $MappedConnectionStartTime
                            MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                        }
                    ) -Force

                    if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) {
                        $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                    }
                }
            }
        }

        # Attempt to Identify the initial connection versus the connection that actually handle WinRM Activity
        $UpdatedWSManClientMappingPrep = $WSManClientMapping | Group-Object -Property MostRecentConnectionActivity
        $Connections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -gt 1}).Group
        $InitialConnections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -eq 1}).Group
        $ActiveConnections = foreach ($connection in $Connections) {
            if ($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess") {
                if ($connection.MostRecentConnectionActivity -and
                $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00" -and
                $connection.WSManClientProcess -ne $null) {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                    $connection
                }
            }
            else {
                if ($connection.MostRecentConnectionActivity -and
                $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00") {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                    $connection
                }
            }
        }

        $InactiveConnections = foreach ($connection in $Connections) {
        if (!$($connection.MostRecentConnectionActivity) -or
            $($connection.MostRecentConnectionActivity).TimeOfDay -eq "00:00:00" -or
            $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientTCPConnection" -and $connection.WSManClientTCPConnection -eq $null) -or
            $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess" -and $connection.WSManClientProcess -eq $null)) {
                $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false -Force
                $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false -Force
                $connection
            }
        }

        $InitialConnections = foreach ($connection in $InitialConnections) {
            $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false
            $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $true
            $connection
        }
        $UpdatedWSManClientMapping = $InactiveConnections + $ActiveConnections + $InitialConnections

        New-Variable -Name "PSRemotingInfoFor$($RemoteComputer[0])" -Value $(
            [pscustomobject][ordered]@{
                WSManServer         = $RemoteComputer
                WSManClientMapping  = $UpdatedWSManClientMapping
            }
        )

        $WSManServerMapping +=, $(Get-Variable -Name "PSRemotingInfoFor$($RemoteComputer[0])" -ValueOnly)

        Remove-Variable -Name "ClientCreds" -Force -ErrorAction SilentlyContinue
    }

    if ($($WSManServerMapping.WSManClientMapping) -eq $null) {
        Write-Verbose @"
Unable to determine PSRemoting Info for any Computer Names provided to the -RemoteComputer parameter!
This is either because access to the information was denied, or because no PSRemoting Sessions exist for those Computers! Halting!
"@
        Write-Error @"
Unable to determine PSRemoting Info for any Computer Names provided to the -RemoteComputer parameter!
This is either because access to the information was denied, or because no PSRemoting Sessions exist for those Computers! Halting!
"@
        $global:FunctionResult = "1"
        return
    }

    foreach ($result in $WSManServerMapping) {
        $result
    }

    ##### END Main Body #####

}

















# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjO2F+G89UIeRFlldnkQTedec
# 5NSgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQnHjnL2Wwk
# zQF9tUEsuwu18mGgqzANBgkqhkiG9w0BAQEFAASCAQBbwldx2MV0g1KrP7INoynS
# 1NR3+fD7lsq6g0TjQrMDhDvXIf6CghCalEkyDN1aZKQENnDP7LKI/i6qtHaOB69V
# Cel0aXGl9E8nUi4eRP0BwtN1fZDhdWiSRUktBLELaltdB/1LDiYgNF0iGPFpqR8f
# DyHPsXKE/I9fcDX1eMFLOJXgGe3sXjfvNadxnSGhM8IKqNmo5+fmM5clyPd949/8
# U2O196GBWHK/CSt26fPE3GRPGvIoTXoFg94F9sdcTc5UjKw8Vxb7bEjDbh41O7t7
# m1UuaMYAiFEaoTbkRRE5zO8zCjoKEuL22WbAdFSfqlc+umS8vOdybpZk9YQjMgfW
# SIG # End signature block
