#region >> Helper Functions

function TestPort {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        try {
            $HostNameNetworkInfo = ResolveHost -HostNameOrIP $HostName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HostName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $tcp = New-Object Net.Sockets.TcpClient
        $RemoteHostFQDN = $HostNameNetworkInfo.FQDN
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$RemoteHostFQDN","Test Connection on $RemoteHostFQDN`:$Port")) {
            try {
                $tcp.Connect($RemoteHostFQDN, $Port)
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
                Address = $RemoteHostFQDN
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}

Function TestLDAP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$ADServerHostNameOrIP
    )

    # Make sure you CAN resolve $ADServerHostNameOrIP AND that we can get FQDN
    try {
        $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($ADServerHostNameOrIP)
        if ($ADServerNetworkInfo.HostName -notmatch "\.") {
            $IP = $ADServerNetworkInfo.AddressList[0].IPAddressToString
            $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($IP)
            if ($ADServerNetworkInfo.HostName -notmatch "\.") {
                throw "Can't resolve $ADServerHostNameOrIP FQDN! Halting!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $ADServerFQDN = $ADServerNetworkInfo.HostName

    $LDAPPrep = "LDAP://" + $ADServerFQDN

    # Try Global Catalog First - It's faster and you can execute from a different domain and
    # potentially still get results
    try {
        $LDAP = $LDAPPrep + ":3269"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $GlobalCatalogConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or SSL on Global Catalog (3269) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":3268"
        $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
        $Connection.Close()
        $GlobalCatalogConfigured = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or Global Catalog (3268) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }
  
    # Try the normal ports
    try {
        $LDAP = $LDAPPrep + ":636"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $ConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server or SSL (636) is NOT configured! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access! Halting!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":389"
        $Connection = [System.DirectoryServices.DirectoryEntry]($LDAP)
        $Connection.Close()
        $Configured = $True
    }
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server (389)! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    if (!$GlobalCatalogConfiguredForSSL -and !$GlobalCatalogConfigured -and !$ConfiguredForSSL -and !$Configured) {
        Write-Error "Unable to connect to $LDAPPrep! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$PortsThatWork = @()
    if ($GlobalCatalogConfigured) {$null = $PortsThatWork.Add("3268")}
    if ($GlobalCatalogConfiguredForSSL) {$null = $PortsThatWork.Add("3269")}
    if ($Configured) {$null = $PortsThatWork.Add("389")}
    if ($ConfiguredForSSL) {$null = $PortsThatWork.Add("636")}

    [pscustomobject]@{
        DirectoryEntryInfo                  = $Connection
        LDAPBaseUri                         = $LDAPPrep
        GlobalCatalogConfigured3268         = if ($GlobalCatalogConfigured) {$True} else {$False}
        GlobalCatalogConfiguredForSSL3269   = if ($GlobalCatalogConfiguredForSSL) {$True} else {$False}
        Configured389                       = if ($Configured) {$True} else {$False}
        ConfiguredForSSL636                 = if ($ConfiguredForSSL) {$True} else {$False}
        PortsThatWork                       = $PortsThatWork
    }
}

function TestIsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

function ResolveHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$HostNameOrIP
    )

    ##### BEGIN Main Body #####

    $RemoteHostNetworkInfoArray = @()
    if (!$(TestIsValidIPAddress -IPAddress $HostNameOrIP)) {
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
    if (TestIsValidIPAddress -IPAddress $HostNameOrIP) {
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

    if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
        [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
        # Test to see if we can reach the IP Addresses
        foreach ($ip in $RemoteHostArrayOfIPAddresses) {
            if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                $null = $SuccessfullyPingedIPs.Add($ip)
            }
        }

        if ($SuccessfullyPingedIPs.Count -eq 0) {
            Write-Error "Unable to resolve $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
    if ($FQDNPrep -match ',') {
        $FQDN = $($FQDNPrep -split ',')[0]
    }
    else {
        $FQDN = $FQDNPrep
    }

    $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
    if ($DomainPrep -match ',') {
        $Domain = $($DomainPrep -split ',')[0]
    }
    else {
        $Domain = $DomainPrep
    }

    [pscustomobject]@{
        IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
        FQDN            = $FQDN
        HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
        Domain          = $Domain
    }

    ##### END Main Body #####

}

function GetDomainController {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [String]$Domain,

        [Parameter(Mandatory=$False)]
        [switch]$UseLogonServer
    )

    ##### BEGIN Helper Functions #####

    function Parse-NLTest {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$Domain
        )

        while ($Domain -notmatch "\.") {
            Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
            $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
        }

        if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find nltest.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $DomainPrefix = $($Domain -split '\.')[0]
        $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
        if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
            Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
            return
        }
        $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
        if ($PrimaryDomainControllerPrep -match '\\\\') {
            $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
        }
        else {
            $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
        }

        $PrimaryDomainController
    }

    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
    $PartOfDomain = $ComputerSystemCim.PartOfDomain

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (!$PartOfDomain -and !$Domain) {
        Write-Error "$env:ComputerName is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $ThisMachinesDomain = $ComputerSystemCim.Domain

    # If we're in a PSSession, [system.directoryservices.activedirectory] won't work due to Double-Hop issue
    # So just get the LogonServer if possible
    if ($Host.Name -eq "ServerRemoteHost" -or $UseLogonServer) {
        if (!$Domain -or $Domain -eq $ThisMachinesDomain) {
            $Counter = 0
            while ([string]::IsNullOrWhitespace($DomainControllerName) -or $Counter -le 20) {
                $DomainControllerName = $(Get-CimInstance win32_ntdomain).DomainControllerName
                if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                    Write-Warning "The win32_ntdomain CimInstance has a null value for the 'DomainControllerName' property! Trying again in 15 seconds (will try for 5 minutes total)..."
                    Start-Sleep -Seconds 15
                }
                $Counter++
            }

            if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                $IPOfDNSServerWhichIsProbablyDC = $(Resolve-DNSName $ThisMachinesDomain).IPAddress
                $DomainControllerFQDN = $(ResolveHost -HostNameOrIP $IPOfDNSServerWhichIsProbablyDC).FQDN
            }
            else {
                $LogonServer = $($DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
                $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
            }

            [pscustomobject]@{
                FoundDomainControllers      = [array]$DomainControllerFQDN
                PrimaryDomainController     = $DomainControllerFQDN
            }

            return
        }
        else {
            Write-Error "Unable to determine Domain Controller(s) network location due to the Double-Hop Authentication issue! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Domain) {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
        }
        catch {
            Write-Verbose "Cannot connect to current forest."
        }

        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                try {
                    Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                    Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                $PrimaryDomainController = Parse-NLTest -Domain $Domain
                [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        catch {
            Write-Verbose "Cannot connect to current forest."

            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                $Domain = $ThisMachinesDomain

                try {
                    $CurrentUser = "$(whoami)"
                    Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                    Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                    if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                        Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                    }
                    Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                    Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    [pscustomobject]@{
        FoundDomainControllers      = $FoundDomainControllers
        PrimaryDomainController     = $PrimaryDomainController
    }

    ##### END Main Body #####
}

function GetComputerObjectsInLDAP {
    [CmdletBinding()]
    Param()

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        $DomainControllerInfo = GetDomainController -ErrorAction Stop
        $LDAPInfo = TestLDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with TestLDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $($DomainControllerInfo.PrimaryDomainController)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":389"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3268"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":636"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3269"
    }

    <#
    $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri)
    $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPSearchRoot)
    $LDAPSearcher.Filter = "(&(objectCategory=Group))"
    $LDAPSearcher.SizeLimit = 0
    $LDAPSearcher.PageSize = 250
    $GroupObjectsInLDAP = $LDAPSearcher.FindAll() | foreach {$_.GetDirectoryEntry()}
    #>

    $LDAPSearchRoot = [System.DirectoryServices.DirectoryEntry]::new($LDAPUri)
    $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPSearchRoot)
    $LDAPSearcher.Filter = "(objectClass=computer)"
    $LDAPSearcher.SizeLimit = 0
    $LDAPSearcher.PageSize = 250
    $ComputerObjectsInLDAP = $LDAPSearcher.FindAll() | foreach {$_.GetDirectoryEntry()}
    <#
    $null = $LDAPSearcher.PropertiesToLoad.Add("name")
    [System.Collections.ArrayList]$ServerList = $($LDAPSearcher.FindAll().Properties.GetEnumerator()).name
    $null = $ServerList.Insert(0,"Please Select a Server")
    #>

    $ComputerObjectsInLDAP
}

#endregion >> Helper Functions


#region >> Main

<#
    .SYNOPSIS
        This function starts a PowerShell Universal Dashboard (Web-based GUI) instance on the specified port on the
        localhost. The Dashboard features a Network Monitor tool that pings the specified Remote Hosts in your Domain
        every 5 seconds and reports the results to the site.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER Port
        This parameter is OPTIONAL, however, it has a default value of 80.

        This parameter takes an integer between 1 and 32768 that represents the port on the localhost that the site
        will run on.

    .PARAMETER RemoveExistingPUD
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, all running PowerShell Universal Dashboard instances will be removed
        prior to starting the Network Monitor Dashboard.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PUDNetMon
        
#>
function Get-PUDNetMon {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True
    )

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = $(Get-CimInstance Win32_ComputerSystem).Domain
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Get all Computers in Active Directory without the ActiveDirectory Module
    [System.Collections.ArrayList]$RemoteHostList = $(GetComputerObjectsInLDAP).Name
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$RemoteHostList = $RemoteHostList | foreach {$_ -replace "CN=",""}
    }
    $null = $RemoteHostList.Insert(0,"Please Select a Server")


    [System.Collections.ArrayList]$Pages = @()

    # Create Home Page
    $HomePageContent = {
        New-UDLayout -Columns 1 -Content {
            New-UDCard -Title "Network Monitor" -Id "NMCard" -Text "Monitor Network" -Links @(
                New-UDLink -Text "Network Monitor" -Url "/NetworkMonitor" -Icon dashboard
            )
        }
    }
    $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
    $null = $Pages.Add($HomePage)

    # Create Network Monitor Page
    [scriptblock]$NMContentSB = {
        for ($i=1; $i -lt $RemoteHostList.Count; $i++) {
            New-UDInputField -Type 'radioButtons' -Name "Server$i" -Values $RemoteHostList[$i]
        }
    }
    [System.Collections.ArrayList]$paramStringPrep = @()
    for ($i=1; $i -lt $RemoteHostList.Count; $i++) {
        $StringToAdd = '$' + "Server$i"
        $null = $paramStringPrep.Add($StringToAdd)
    }
    $paramString = 'param(' + $($paramStringPrep -join ', ') + ')'
    $NMEndPointSBAsStringPrep = @(
        $paramString
        '[System.Collections.ArrayList]$SubmitButtonActions = @()'
        ''
        '$AddNewRowA = New-UDRow -Endpoint {'
        '    New-UDColumn -Size 4 {}'
        '    New-UDColumn -Size 4 {'
        '        New-UDInput -Title "Enter a Toast Message" -Id "ToastMsgForm" -Content {'
        '            $DefValue = "Please enter a Toast Message"'
        '            New-UDInputField -Type textbox -Name "ToastMessage" -DefaultValue $DefValue'
        '        } -Endpoint {'
        '            param($ToastMessage)'
        '            $FinalToastMessage = $ToastMessage'
        '            New-UDInputAction -Toast $FinalToastMessage -Duration 5000'
        '            Remove-Variable -Name "ToastMessage" -Force -ErrorAction SilentlyContinue'
        '        }'
        '    }'
        '    New-UDColumn -Size 4 {}'
        '}'
        '$null = $SubmitButtonActions.Add($AddNewRowA)'
        ''
        'foreach ($kvpair in $PSBoundParameters.GetEnumerator()) {'
        '    if ($kvpair.Value -ne $null) {'
        '        $AddNewRowB = New-UDRow -Columns {'
        '            New-UDColumn -Size 1 {}'
        '            New-UDColumn -Size 5 {'
        '                # Create New Grid'
        '                [System.Collections.ArrayList]$LastFivePings = @()'
        '                $PingResultProperties = @("Status","IPAddress","RoundtripTime","DateTime")'
        '                $PingGrid = New-UdGrid -Title $kvpair.Value -Headers $PingResultProperties -AutoRefresh -Properties $PingResultProperties -Endpoint {'
        '                    try {'
        '                        $ResultPrep =  [System.Net.NetworkInformation.Ping]::new().Send('
        '                            $($kvpair.Value),1000'
        '                        )| Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId'
        '                        $GridData = [PSCustomObject]@{'
        '                             IPAddress       = $ResultPrep.Address.IPAddressToString'
        '                             Status          = $ResultPrep.Status.ToString()'
        '                             RoundtripTime   = $ResultPrep.RoundtripTime'
        '                             DateTime        = Get-Date -Format MM-dd-yy_hh:mm:sstt'
        '                        }'
        '                    }'
        '                    catch {'
        '                        $GridData = [PSCustomObject]@{'
        '                            IPAddress       = "Unknown"'
        '                            Status          = "Unknown"'
        '                            RoundtripTime   = "Unknown"'
        '                            DateTime        = Get-Date -Format MM-dd-yy_hh:mm:sstt'
        '                        }'
        '                    }'
        '                    if ($LastFivePings.Count -eq 5) {'
        '                        $LastFivePings.RemoveAt($LastFivePings.Count-1)'
        '                    }'
        '                    $LastFivePings.Insert(0,$GridData)'
        '                    $LastFivePings | Out-UDGridData'
        '                }'
        '                $PingGrid'
        '                #$null = $SubmitButtonActions.Add($PingGrid)'
        '             }'
        '            New-UDColumn -Size 5 {'
        '                # Create New Monitor'
        '                $PingMonitor = New-UdMonitor -Title $kvpair.Value -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor "#80FF6B63" -ChartBorderColor "#FFFF6B63"  -Endpoint {'
        '                    try {'
        '                        [bool]$([System.Net.NetworkInformation.Ping]::new().Send($($kvpair.Value),1000)) | Out-UDMonitorData'
        '                    }'
        '                    catch {'
        '                        $False | Out-UDMonitorData'
        '                    }'
        '                }'
        '                $PingMonitor'
        '                #$null = $SubmitButtonActions.Add($PingMonitor)'
        '            }'
        '            New-UDColumn -Size 1 {}'
        '        }'
        '        $null = $SubmitButtonActions.Add($AddNewRowB)'
        '    }'
        '}'
        'New-UDInputAction -Content $SubmitButtonActions'
    )
    $NMEndPointSBAsString = $NMEndPointSBAsStringPrep -join "`n"
    $NMEndPointSB = [scriptblock]::Create($NMEndPointSBAsString)
    $NetworkMonitorPageContent = {
        New-UDInput -Title "Select Servers To Monitor" -Id "Form" -Content $NMContentSB -Endpoint $NMEndPointSB
    }
    $NetworkMonitorPage = New-UDPage -Name "NetworkMonitor" -Icon dashboard -Content $NetworkMonitorPageContent
    $null = $Pages.Add($NetworkMonitorPage)
    
    # Finalize the Site
    $MyDashboard = New-UDDashboard -Pages $Pages

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}

#endregion >> Main

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXWe7SUXwAZtZNgFGfq/lHKUt
# Fu6gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLCs1cflMfBbcYKY
# iOJsqzSszFw9MA0GCSqGSIb3DQEBAQUABIIBAHmwQ3RLQ3+P8csqAuGw6019N/Wt
# mlgUkSX+bXOOZl6hchLY3QIG6oYpxv97o5FivY5t0l5YlpuCEKMGlVci9ysfIJf7
# qHXNdg+SwE8W5AskUmSERBN+B2+sbt8CvTqHO1LWgD5K8x2CFb3tZtBA7CUw9d3A
# e8bKQckfPAVFfyxprx386eUhAIy2zIITHhF1ZGAti3v1S+B+aSdSDSUpR8nr8yOH
# 05K9LjlbKhDVC+BwMmQBSKQ0dSaf6OTjfmPqMrUSNjG/LefJrgRuXnxHfksovixL
# sm4956mro82WsoBvv31QREZfZ59HCnkGp4GOMuDjdjjlC69VTA+Dbylbun0=
# SIG # End signature block
