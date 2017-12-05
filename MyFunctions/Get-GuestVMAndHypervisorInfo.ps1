function Get-GuestVMAndHypervisorInfo {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(
            Mandatory = $True,
            ParameterSetName = 'Default'
        )]
        [string]$TargetHostNameOrIP,

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'RanFromHypervisor'
        )]
        [string]$TargetVMName,

        [Parameter(Mandatory=$False)]
        [string]$HypervisorFQDNOrIP,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$TargetHostNameCreds,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$HypervisorCreds
    )

    ##### BEGIN Helper Functions #####

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                $ResolutionInfo.AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        # At this point, we have $RemoteHostArrayOfIPAddresses...
        [System.Collections.ArrayList]$RemoteHostFQDNs = @()
        foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
            try {
                $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
                continue
            }
            if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                $null = $RemoteHostFQDNs.Add($FQDNPrep)
            }
        }
    
        if ($RemoteHostFQDNs.Count -eq 0) {
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
    
        [System.Collections.ArrayList]$HostNameList = @()
        [System.Collections.ArrayList]$DomainList = @()
        foreach ($fqdn in $RemoteHostFQDNs) {
            $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
            if ($PeriodCheck) {
                $HostName = $($fqdn -split "\.")[0]
                $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
            }
            else {
                $HostName = $fqdn
                $Domain = "Unknown"
            }
    
            $null = $HostNameList.Add($HostName)
            $null = $DomainList.Add($Domain)
        }
    
        [pscustomobject]@{
            IPAddressList   = $RemoteHostArrayOfIPAddresses
            FQDN            = $RemoteHostFQDNs[0]
            HostName        = $HostNameList[0].ToLowerInvariant()
            Domain          = $DomainList[0]
        }
    
        ##### END Main Body #####
    
    }

    ##### END Helper Functions #####

    ## BEGIN $TargetVMName adjudication ##

    if ($TargetVMName) {
        if (!$HypervisorFQDNOrIP) {
            # Assume that $env:ComputerName is the hypervisor
            $HypervisorFQDNOrIP = $env:ComputerName
            if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V") {
                Write-Warning "The localhost $env:ComputerName does not appear to be a hypervisor!"
                $HypervisorFQDNOrIP = Read-Host -Prompt "Please enter the FQDN or IP of the hypervisor that manages $TargetVMName"
            }
        }
    }

    if ($HypervisorFQDNOrIP) {
        try {
            $HypervisorNetworkInfo = Resolve-Host -HostNameOrIP $HypervisorFQDNOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HypervisorFQDNOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($TargetVMName) {
        # Make sure the $TargetVMName exists on the hypervisor and get some info about it from the Hypervisor's perspective
        if ($HypervisorNetworkInfo.HostName -ne $env:ComputerName) {
            $InvokeCommandSB = {
                try {
                    $TargetVMInfoFromHyperV  = Get-VM -Name $using:TargetVMName -ErrorAction Stop
                }
                catch {
                    Write-Error "Unable to find $using:TargetVMName on $($using:HypervisorNetworkInfo.HostName)!"
                    return
                }

                # Need to Get $HostNameNetworkInfo via Network Adapter IP
                $GuestVMIPAddresses = $TargetVMInfoFromHyperV.NetworkAdapters.IPAddresses

                [pscustomobject]@{
                    HypervisorComputerInfo  = Get-CimInstance Win32_ComputerSystem
                    HypervisorOSInfo        = Get-CimInstance Win32_OperatingSystem
                    TargetVMInfoFromHyperV  = $TargetVMInfoFromHyperV
                    GuestVMIPAddresses      = $GuestVMIPAddresses
                }
            }

            try {
                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
            }
            catch {
                if ($_ -match "Cannot find the computer") {
                    try {
                        if (!$HypervisorCreds) {
                            Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                            $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                            $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
    
                            $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                        }
                        $Creds = $HypervisorCreds

                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                        $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
                    }
                    catch {
                        if ($_ -match "no logon servers") {
                            try {
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                elseif ($_ -match "no logon servers") {
                    try {
                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                        $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
                    }
                    catch {
                        if ($_ -match "Cannot find the computer") {
                            try {
                                if (!$HypervisorCreds) {
                                    Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                                    $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            
                                    $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                }
                                $Creds = $HypervisorCreds
        
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                else {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            # Guest VM Info from Hypervisor Perspective
            try {
                $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # Guest VM OS Info
            $HypervisorComputerInfo = Get-CimInstance Win32_ComputerSystem
            $HypervisorOSInfo = Get-CimInstance Win32_OperatingSystem
            $GuestVMIPAddresses = $TargetVMInfoFromHyperV.NetworkAdapters.IPAddresses
        }

        # Now, we need to get $HostNameOSInfo and $HostNameComputerInfo
        [System.Collections.ArrayList]$ResolvedIPs = @()
        foreach ($IPAddr in $GuestVMIPAddresses) {
            try {
                $HostNameNetworkInfoPrep = Resolve-Host -HostNameOrIP $IPAddr -ErrorAction Stop

                $null = $ResolvedIPs.Add($HostNameNetworkInfoPrep)
            }
            catch {
                Write-Verbose "Unable to resolve $IPAddr"
            }
        }
        foreach ($ResolvedIP in $ResolvedIPs) {
            $NTDomainInfo = Get-CimInstance Win32_NTDomain
            if ($ResolvedIP.Domain -eq $NTDomainInfo.DnsForestName) {
                $HostNameNetworkInfo = $ResolvedIP
            }
        }
        if (!$HostNameNetworkInfo) {
            $HostNameNetworkInfo = $ResolvedIPs[0]
        }

        $InvokeCommandSB = {
            [pscustomobject]@{
                HostNameComputerInfo  = Get-CimInstance Win32_ComputerSystem
                HostNameOSInfo        = Get-CimInstance Win32_OperatingSystem
                HostNameProcessorInfo = Get-CimInstance Win32_Processor
                HostNameBIOSInfo      = Get-CimInstance Win32_BIOS
            }
        }

        try {
            $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.FQDN -ScriptBlock $InvokeCommandSB -ErrorAction Stop

            #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
            $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
            $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
            $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
            $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
        }
        catch {
            if ($_ -match "Cannot find the computer") {
                try {
                    if (!$TargetHostNameCreds) {
                        Write-Warning "Connecting to remote server $($HostNameNetworkInfo.FQDN) failed using credentials of the current user."
                        $UserName = Read-Host -Prompt "Please enter a user name with access to $($HostNameNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                        $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString

                        $TargetHostNameCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                    }
                    $Creds = $TargetHostNameCreds

                    $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                    #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -WarningAction SilentlyContinue -ErrorAction Stop
                    $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                    $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                    $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                    $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                }
                catch {
                    if ($_ -match "no logon servers") {
                        try {
                            $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                            
                            #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                            $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                            $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                            $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                            $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    else {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            elseif ($_ -match "no logon servers") {
                try {
                    $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                    
                    #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                    $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                    $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                    $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                    $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                }
                catch {
                    if ($_ -match "Cannot find the computer") {
                        try {
                            if (!$TargetHostNameCreds) {
                                Write-Warning "Connecting to remote server $($HostNameNetworkInfo.FQDN) failed using credentials of the current user."
                                $UserName = Read-Host -Prompt "Please enter a user name with access to $($HostNameNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
        
                                $TargetHostNameCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                            }
                            $Creds = $TargetHostNameCreds
        
                            $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                            #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -WarningAction SilentlyContinue -ErrorAction Stop
                            $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                            $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                            $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                            $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    else {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        # Now we have $HypervisorNetworkInfo, $HypervisorComputerInfo, $HypervisorOSInfo, $TargetVMInfoFromHyperV, 
        # $HostNameNetworkInfo, $HostNameComputerInfo, $HostNameOSInfo, and $HostNameBIOSInfo
    }

    ## END $TargetVMName adjudication ##

    ## BEGIN $TargetHostNameOrIP adjudication ##

    if ($TargetHostNameOrIP) {
        try {
            $HostNameNetworkInfo = Resolve-Host -HostNameOrIP $TargetHostNameOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $TargetHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # BEGIN Get Guest VM Info # 
        
        if ($HostNameNetworkInfo.HostName -ne $env:ComputerName) {
            $InvokeCommandSB = {
                try {
                    $HostNameGuestVMInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction Stop
                }
                catch {
                    $HostNameGuestVMInfo = "IntegrationServices_Not_Installed"
                }

                [pscustomobject]@{
                    HostNameComputerInfo  = Get-CimInstance Win32_ComputerSystem
                    HostNameOSInfo        = Get-CimInstance Win32_OperatingSystem
                    HostNameProcessorInfo = Get-CimInstance Win32_Processor
                    HostNameBIOSInfo      = Get-CimInstance Win32_BIOS
                    HostNameGuestVMInfo   = $HostNameGuestVMInfo 
                }
            }

            try {
                $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.FQDN -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
            }
            catch {
                if ($_ -match "Cannot find the computer") {
                    try {
                        if (!$TargetHostNameCreds) {
                            Write-Warning "Connecting to remote server $($HostNameNetworkInfo.FQDN) failed using credentials of the current user."
                            $UserName = Read-Host -Prompt "Please enter a user name with access to $($HostNameNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                            $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString

                            $TargetHostNameCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                        }
                        $Creds = $TargetHostNameCreds

                        $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop

                        #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -WarningAction SilentlyContinue -ErrorAction Stop
                        $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                        $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                        $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                        $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                        $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
                    }
                    catch {
                        if ($_ -match "no logon servers") {
                            try {
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                
                                #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                                $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                                $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                                $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                                $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                                $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                elseif ($_ -match "no logon servers") {
                    try {
                        $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                        #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                        $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                        $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                        $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                        $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                        $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
                    }
                    catch {
                        if ($_ -match "Cannot find the computer") {
                            try {
                                if (!$TargetHostNameCreds) {
                                    Write-Warning "Connecting to remote server $($HostNameNetworkInfo.FQDN) failed using credentials of the current user."
                                    $UserName = Read-Host -Prompt "Please enter a user name with access to $($HostNameNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
        
                                    $TargetHostNameCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                }
                                $Creds = $TargetHostNameCreds
        
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HostNameNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                                #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -Credential $Creds -WarningAction SilentlyContinue -ErrorAction Stop
                                $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                                $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                                $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                                $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                                $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                else {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            try {
                $HostNameGuestVMInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -ErrorAction Stop
            }
            catch {
                $HostNameGuestVMInfo = "IntegrationServices_Not_Installed"
            }

            $HostNameComputerInfo = Get-CimInstance Win32_ComputerSystem
            $HostNameOSInfo = Get-CimInstance Win32_OperatingSystem
            $HostNameProcessorInfo = Get-CimInstance Win32_Processor
            $HostNameBIOSInfo = Get-CimInstance Win32_BIOS
            $HostNameGuestVMInfo = $HostNameGuestVMInfo
        }

        if ($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V|VirtualBox|VMWare" -or
        $HostNameBIOSInfo.Manufacturer -match "Hyper-V|VirtualBox|VMWare" -or
        $HostNameBIOSInfo.Name -match "Hyper-V|VirtualBox|VMWare" -or
        $HostNameBIOSInfo.SerialNumber -match "Hyper-V|VirtualBox|VMWare" -or
        $HostNameBIOSInfo.Version -match "Hyper-V|VirtualBox|VMWare") {
            Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $True
        }
        else {
            Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $False
        }

        if (!$HostNameBIOSInfo.IsVirtual) {
            Write-Error "This function is meant to determine if a Guest VM is capable of Nested Virtualization, but $TargetHostNameOrIP is a physical machine! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V" -or $HostNameBIOSInfo.Name -match "Hyper-V")) {
            Write-Warning "The hypervisor for $($HostNameNetworkInfo.FQDN) is NOT Microsoft's Hyper-V. Unable to get additional information about the hypervisor!"
            $HypervisorIsHyperV = $False
        }
        else {
            $HypervisorIsHyperV = $True
        }


        # END Get Guest VM Info #

        # BEGIN Get Hypervisor Info #

        if ($HypervisorIsHyperV) {
            # Now we need to try and get some info about the hypervisor
            if ($HostNameGuestVMInfo -eq "IntegrationServices_Not_Installed") {
                # Still need the FQDN/Location of the hypervisor
                if (!$HypervisorFQDNOrIP) {
                    $HypervisorFQDNOrIP = $env:ComputerName
                    if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V") {
                        Write-Warning "The localhost $env:ComputerName does not appear to be a hypervisor!"
                        $HypervisorFQDNOrIP = Read-Host -Prompt "Please enter the FQDN or IP of the hypervisor that manages $TargetVMName"
                    }
                }

                try {
                    $HypervisorNetworkInfo = Resolve-Host -HostNameOrIP $HypervisorFQDNOrIP -ErrorAction Stop
                }
                catch {
                    Write-Error "Unable to resolve $HypervisorFQDNOrIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # Still need the name of the Guest VM according the the hypervisor
                if ($HypervisorNetworkInfo.HostName -ne $env:ComputerName) {
                    $InvokeCommandSB = {
                        # We an determine the $TargetVMName by finding the Guest VM Network Adapter with an IP that matches
                        # $HostNameNetworkInfo.IPAddressList
                        $TargetVMName = $(Get-VM | Where-Object {$_.NetworkAdapters.IPAddresses -contains $using:HostNameNetworkInfo.IPAddressList[0]}).Name

                        try {
                            $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
                        }
                        catch {
                            $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                        }

                        [pscustomobject]@{
                            HypervisorComputerInfo  = Get-CimInstance Win32_ComputerSystem
                            HypervisorOSInfo        = Get-CimInstance Win32_OperatingSystem
                            TargetVMInfoFromHyperV  = $TargetVMInfoFromHyperV
                        }
                    }
        
                    try {
                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                        
                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                    }
                    catch {
                        if ($_ -match "Cannot find the computer") {
                            try {
                                if (!$HypervisorCreds) {
                                    Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                                    $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            
                                    $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                }
                                $Creds = $HypervisorCreds
        
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                            }
                            catch {
                                if ($_ -match "no logon servers") {
                                    try {
                                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                                        
                                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                    }
                                    catch {
                                        Write-Error $_
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                }
                                else {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }
                        elseif ($_ -match "no logon servers") {
                            try {
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                                
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                            }
                            catch {
                                if ($_ -match "Cannot find the computer") {
                                    try {
                                        if (!$HypervisorCreds) {
                                            Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                                            $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                            $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
                    
                                            $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                        }
                                        $Creds = $HypervisorCreds
                
                                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo..HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                
                                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                    }
                                    catch {
                                        Write-Error $_
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                }
                                else {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                else {
                    # We an determine the $TargetVMName by finding the Guest VM Network Adapter with an IP that matches
                    # $HostNameNetworkInfo.IPAddressList
                    $TargetVMName = $(Get-VM | Where-Object {$_.NetworkAdapters.IPAddresses -contains $HostNameNetworkInfo.IPAddressList[0]}).Name

                    try {
                        $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
                    }
                    catch {
                        $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                    }

                    $HypervisorComputerInfo = Get-CimInstance Win32_ComputerSystem
                    $HypervisorOSInfo = Get-CimInstance Win32_OperatingSystem
                }
            }
            else {
                # Already have the FQDN of the hypervisor...
                try {
                    $HypervisorNetworkInfo = Resolve-Host -HostNameOrIP $HostNameGuestVMInfo.PhysicalHostNameFullyQualified -ErrorAction Stop
                }
                catch {
                    Write-Error "Unable to resolve $($HostNameGuestVMInfo.PhysicalHostNameFullyQualified))! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                if ($HypervisorNetworkInfo.HostName -ne $env:ComputerName) {
                    $InvokeCommandSB = {
                        try {
                            $TargetVMInfoFromHyperV = Get-VM -Name $using:HostNameGuestVMInfo.VirtualMachineName -ErrorAction Stop
                        }
                        catch {
                            $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                        }

                        [pscustomobject]@{
                            HypervisorComputerInfo  = Get-CimInstance Win32_ComputerSystem
                            HypervisorOSInfo        = Get-CimInstance Win32_OperatingSystem
                            TargetVMInfoFromHyperV  = $TargetVMInfoFromHyperV
                        }
                    }
        
                    try {
                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                    }
                    catch {
                        if ($_ -match "Cannot find the computer") {
                            try {
                                if (!$HypervisorCreds) {
                                    Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                                    $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            
                                    $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                }
                                $Creds = $HypervisorCreds
        
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                            }
                            catch {
                                if ($_ -match "no logon servers") {
                                    try {
                                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                        
                                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                    }
                                    catch {
                                        Write-Error $_
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                }
                                else {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }
                        elseif ($_ -match "no logon servers") {
                            try {
                                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                
                                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                            }
                            catch {
                                if ($_ -match "Cannot find the computer") {
                                    try {
                                        if (!$HypervisorCreds) {
                                            Write-Warning "Connecting to remote server $($HypervisorNetworkInfo.FQDN) failed using credentials of the current user."
                                            $UserName = Read-Host -Prompt "Please enter a user name with access to $($HypervisorNetworkInfo.FQDN) using format <DomainPrefix>\<User>"
                                            $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
                    
                                            $HypervisorCreds = [System.Management.Automation.PSCredential]::new($UserName,$Password)
                                        }
                                        $Creds = $HypervisorCreds
                
                                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
                
                                        $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                                        $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                                        $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                                    }
                                    catch {
                                        Write-Error $_
                                        $global:FunctionResult = "1"
                                        return
                                    }
                                }
                                else {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }
                        else {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                }
                else {
                    try {
                        $TargetVMInfoFromHyperV = Get-VM -Name $HostNameGuestVMInfo.VirtualMachineName -ErrorAction Stop
                    }
                    catch {
                        $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                    }

                    $HypervisorComputerInfo = Get-CimInstance Win32_ComputerSystem
                    $HypervisorOSInfo = Get-CimInstance Win32_OperatingSystem
                }            
            }

            if ($TargetVMInfoFromHyperV -eq "Unable_to_find_VM") {
                Write-Error "Unable to find VM $TargetVMName on the specified hypervisor $($HypervisorNetworkInfo.FQDN)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $HypervisorNetworkInfo = $null
            $HypervisorComputerInfo = $null
            $HypervisorOSInfo = $null
        }

        # Now we have $HypervisorNetworkInfo, $HypervisorComputerInfo, $HypervisorOSInfo, $TargetVMInfoFromHyperV, 
        # $HostNameGuestVMInfo, $HostNameNetworkInfo, $HostNameComputerInfo, and $HostNameOSInfo, $HostNameBIOSInfo,
        # and $HostNameProcessorInfo

            
        # End Get Hypervisor Info #

    }

    ## END $TargetHostNameOrIP adjudication ##

    [pscustomobject]@{
        HypervisorNetworkInfo       = $HypervisorNetworkInfo
        HypervisorComputerInfo      = $HypervisorComputerInfo
        HypervisorOSInfo            = $HypervisorOSInfo
        TargetVMInfoFromHyperV      = $TargetVMInfoFromHyperV
        HostNameNetworkInfo         = $HostNameNetworkInfo
        HostNameComputerInfo        = $HostNameComputerInfo
        HostNameOSInfo              = $HostNameOSInfo
        HostNameProcessorInfo       = $HostNameProcessorInfo
        HostNameBIOSInfo            = $HostNameBIOSInfo
    }
}





























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcNVVlkjIKd0FD7qy6wBWCltg
# Raegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFQZMe8dxYV0Hcrm
# 8pBaKWtdoMCUMA0GCSqGSIb3DQEBAQUABIIBAGSFv7rbP1r8CiSdwJb/NKEkwumj
# 1uQxtmL1IpuxzOccPKIQcN2Uz+oOvZnKLRJvAcmVPS0XjKJa4AI6i5B6HYqQiIbs
# 0ccioAB0hwM6wOp9Ow1ZLNPiw6lrg94eAMfYvt8zwMygLj/PaA17fXm6ATV6rZU3
# ffIjq7ucBPQVHP5fTWc+Ptxb92PuHrUxvOXWTLvdiUZIFgxI7kmuiO3VqbHHZb3J
# 0NjBowEJwtKH3uwpJpATJCjR8lDwKfaRjr7dHGpTo6xJ5BwnKDY9A9VyaMOcKU2d
# 18pmh6hIzsWVaBABtDVzqDem7fKYzbQoUeJqsc6rm8e2I8t89SSimLVRTdo=
# SIG # End signature block
