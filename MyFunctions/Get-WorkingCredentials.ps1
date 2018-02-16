<#
.SYNOPSIS
    This function checks to see if the provided credentials are valid for the specified domain/logon server
    and if those credentials can actually grant you access to the specified remote host.

.DESCRIPTION
    See SYNOPSIS

.PARAMETER RemoteHostNameOrIP
    This parameter is MANDATORY.

    This parameter takes a string that represents an IP, FQDN, or DNS-Resolvable HostName of a remote host.

.PARAMETER AltCredentials
    This parameter is OPTIONAL.

    This parameter takes a System.Management.Automation.PSCredential object. Use this parameter to specify
    credentials other than the current user that you would like to test.

.PARAMETER UserName
    This parameter is OPTIONAL.

    This parameter takes a string in format <DomainPrefix>\<UserAcct> or (if using a Local Account on
    the Remote Host) <RemoteHostName>\<UserAcct>.

.PARAMETER Password
    This parameter is OPTIONAL.

    This parameter takes a System.Security.SecureString.

.EXAMPLE
    PS C:\Users\testadmin> Get-WorkingCredentials -RemoteHostNameOrIP ZeroTesting.zero.lab -UserName "zero\zeroadmin"
    Please enter the password for zero\zeroadmin: 

    LogonType                             : DomainAccount
    DeterminedCredsThatWorkedOnRemoteHost : True
    WorkingCredsAreValidOnDomain          : True
    WorkingCredentials                    : System.Management.Automation.PSCredential
    RemoteHostWorkingLocation             : ZeroTesting.zero.lab
    CurrentLoggedInUserCredsWorked        : NotTested
    ProvidedCredsAreValidOnDomain         : True

.EXAMPLE
    PS C:\Users\testadmin> Get-WorkingCredentials -RemoteHostNameOrIP Win12Chef.test2.lab

    LogonType                             : DomainAccount
    DeterminedCredsThatWorkedOnRemoteHost : True
    WorkingCredsAreValidOnDomain          : True
    WorkingCredentials                    : test2\testadmin
    RemoteHostWorkingLocation             : Win12Chef.test2.lab
    CurrentLoggedInUserCredsWorked        : True
    

.EXAMPLE
    PS C:\Users\testadmin> $Creds = Get-Credential

    cmdlet Get-Credential at command pipeline position 1
    Supply values for the following parameters:
    Credential
    PS C:\Users\testadmin> Get-WorkingCredentials -RemoteHostNameOrIP 192.168.2.46 -AltCredentials $Creds

    LogonType                             : DomainAccount
    DeterminedCredsThatWorkedOnRemoteHost : True
    WorkingCredsAreValidOnDomain          : True
    WorkingCredentials                    : System.Management.Automation.PSCredential
    RemoteHostWorkingLocation             : win16zerows.zero.lab
    CurrentLoggedInUserCredsWorked        : NotTested
    ProvidedCredsAreValidOnDomain         : True

.EXAMPLE
    PS C:\Users\testadmin> Get-WorkingCredentials -RemoteHostNameOrIP win12chef -UserName "win12chef\pdadminbackup"
    Please enter the password for win12chef\pdadminbackup: 


    LogonType                             : LocalAccount
    DeterminedCredsThatWorkedOnRemoteHost : True
    WorkingCredsAreValidOnDomain          : False
    WorkingCredentials                    : System.Management.Automation.PSCredential
    RemoteHostWorkingLocation             : Win12Chef.test2.lab
    CurrentLoggedInUserCredsWorked        : NotTested
    ProvidedCredsAreValidOnDomain         : False


.NOTES
    About the behavior of Invoke-Command:

    If credentials are supplied, and if the username for those credentials is in format '<DomainPrefix>\<UserAcct>',
    then the first thing that Invoke-Command does is check for logon servers on DomainPrefix. If it can't find
    a logon server, then it yields an error message similar to:

        Get-WorkingCredentials : [zerotesting] Connecting to remote server zerotesting failed with the following error message : WinRM cannot process the request. The
        following error with errorcode 0x80090311 occurred while using Kerberos authentication: There are currently no logon servers available to service the logon
        request.
        Possible causes are:
        -The user name or password specified are invalid.
        -Kerberos is used when no authentication method and no user name are specified.
        -Kerberos accepts domain user names, but not local user names.
        -The Service Principal Name (SPN) for the remote computer name and port does not exist.
        -The client and remote computers are in different domains and there is no trust between the two domains.
        After checking for the above issues, try the following:
        -Check the Event Viewer for events related to authentication.
        -Change the authentication method; add the destination computer to the WinRM TrustedHosts configuration setting or use HTTPS transport.
        Note that computers in the TrustedHosts list might not be authenticated.
        -For more information about WinRM configuration, run the following command: winrm help config. For more information, see the about_Remote_Troubleshooting
        Help topic.
        At line:1 char:1
        + Get-WorkingCredentials -RemoteHostNameOrIP ZeroTesting -AltCredential ...
        + ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
            + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,Get-WorkingCredentials

    Under the same circumstances (i.e. credentials provded in format '<DomainPrefix>\<UserAcct>'), if the
    logon server IS FOUND, but -ComputerName CANNOT BE FOUND on the network, OR if the credentials supplied to
    -Credential are legitimately bad, then Invoke-Command yields an error similar to the following:

        [blep] Connecting to remote server blep failed with the following error message : The user name or password is incorrect. For more information, see the
        about_Remote_Troubleshooting Help topic.
            + CategoryInfo          : OpenError: (blep:String) [], PSRemotingTransportException
            + FullyQualifiedErrorId : LogonFailure,PSSessionStateBroken
         
        
    If credentials are supplied, and if the username for those credentials is in format '<UserAcct>', then
    then the first thing that Invoke-Command does is try and find -ComputerName on the network. 
    If Invoke-Command CANNOT find -ComputerName, OR if the credentials supplied to -Credential are
    legitimately bad, then it yields an error similar to the following:

        [blep] Connecting to remote server blep failed with the following error message : The user name or password is incorrect. For more information, see the
        about_Remote_Troubleshooting Help topic.
            + CategoryInfo          : OpenError: (blep:String) [], PSRemotingTransportException
            + FullyQualifiedErrorId : LogonFailure,PSSessionStateBroken

    This is a problem, because this error message could mean that either -ComputerName can't be found on the network
    or that -ComputerName WAS found but the credentials were actually bad.

    This function checks all of these things in advance so that we can easily determine why Invoke-Command failed.

.OUTPUTS
    PSCustomObject
#>

function Get-WorkingCredentials {
    [CmdletBinding(DefaultParameterSetName='PSCredential')]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteHostNameOrIP,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PSCredential'
        )]
        [System.Management.Automation.PSCredential]$AltCredentials,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='NoCredentialObject'
        )]
        [string]$UserName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='NoCredentialObject'
        )]
        [System.Security.SecureString]$Password
    )

    #region >> Helper Functions

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".")).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        #region >> Helper Function Main Body
    
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
    
        [pscustomobject]@{
            IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
            FQDN            = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
            HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
            Domain          = if ($DomainList) {$DomainList[0]} else {$null}
        }
    
        #endregion >> Helper Function Main Body
    
    }

    function Check-CredsAndLockStatus {
        if (![bool]$($CurrentlyLoadedAssemblies -match "System.DirectoryServices.AccountManagement")) {
            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        }
        $SimpleDomain = $RemoteHostNetworkInfo.Domain
        $SimpleDomainWLDAPPort = $SimpleDomain + ":3268"
        $DomainLDAPContainers = "DC=" + $($SimpleDomain -split "\.")[0] + "," + "DC=" + $($SimpleDomain -split "\.")[1]

        try {
            $SimpleUserName = $($AltCredentials.UserName -split "\\")[1]
            $PrincipleContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain,
                "$SimpleDomainWLDAPPort",
                "$DomainLDAPContainers",
                [System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind,
                "$($AltCredentials.UserName)",
                "$([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AltCredentials.Password)))"
            )

            try {
                $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipleContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, "$SimpleUserName")
                $AltCredentialsAreValid = $True
            }
            catch {
                $AltCredentialsAreValid = $False
            }

            if ($AltCredentialsAreValid) {
                # Determine if the User Account is locked
                $AccountLocked = $UserPrincipal.IsAccountLockedOut()

                if ($AccountLocked -eq $True) {
                    Write-Error "The provided UserName $($AltCredentials.Username) is locked! Please unlock it before additional attempts at getting working credentials!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        $Output = [ordered]@{
            AltCredentialsAreValid = $AltCredentialsAreValid
        }
        if ($AccountLocked) {
            $Output.Add("AccountLocked",$AccountLocked)
        }

        [pscustomobject]$Output
    }

    #endregion >> Helper Functions


    #region >> Variable/Parameter Transforms and PreRun Prep

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if ($RemoteHostNameOrIP) {
        try {
            $RemoteHostNetworkInfo = Resolve-Host -HostNameOrIP $RemoteHostNameOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $RemoteHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $EnvironmentInfo = Get-ItemProperty 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Volatile Environment\'
    $CurrentUserLogonServer = $EnvironmentInfo.LogonServer -replace '\\\\',''
    if ($CurrentUserLogonServer -eq $env:ComputerName) {
        $LogonServerIsDomainController = $False
        $LoggedInAsLocalUser = $True
    }
    else {
        $LogonServerIsDomainController = $True
        $LoggedInAsLocalUser = $False
    }

    if ($UserName) {
        while ($UserName -notmatch "\\") {
            $UserName = Read-Host -Prompt "The provided UserName is NOT in the correct format! Please enter a UserName with access to $($RemoteHostNetworkInfo.FQDN) using format <DomainPrefix_Or_$($RemoteHostNetworkInfo.HostName)>\<UserName>"
        }
        if (!$Password) {
            $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
        }
        $AltCredentials = [System.Management.Automation.PSCredential]::new($UserName,$Password)
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep

    #region >> Main Body

    if ($AltCredentials) {
        while ($AltCredentials.UserName -notmatch "\\") {
            $AltUserName = Read-Host -Prompt "The provided UserName is NOT in the correct format! Please enter a UserName with access to $($RemoteHostNetworkInfo.FQDN) using format <DomainPrefix_Or_$($RemoteHostNetworkInfo.HostName)>\<UserName>"
            $AltPassword = Read-Host -Prompt "Please enter the password for $AltUserName" -AsSecureString
            $AltCredentials = [System.Management.Automation.PSCredential]::new($AltUserName,$AltPassword)
        }

        if ($($AltCredentials.UserName -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName -and 
        $($AltCredentials.UserName -split "\\")[0] -ne $($RemoteHostNetworkInfo.Domain -split "\.")[0]
        ) {
            $ErrMsg = "Using the credentials provided we will not be able to find a Logon Server. The credentials do not " +
            "indicate a Local Logon (i.e. $($RemoteHostNetworkInfo.HostName)\$($($AltCredentials.UserName -split "\\")[1]) " +
            "or a Domain Logon (i.e. $($($($RemoteHostNetworkInfo.Domain) -split "\.")[0])\$($($AltCredentials.UserName -split "\\")[1])! " +
            "Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }

        if ($LoggedInAsLocalUser) {
            # If we ARE trying a Local Account on the Remote Host
            if ($($AltCredentials.Username -split "\\")[0] -eq $RemoteHostNetworkInfo.HostName) {
                $LogonType = "LocalAccount"
                $AltCredentialsUncertain = $True
                $CurrentUserCredentialsMightWork = $False
            }
            # If we ARE NOT trying a Local Account on the Remote Host, we are necessarily trying Domain Credentials
            if ($($AltCredentials.Username -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName) {
                $LogonType = "DomainAccount"
                $CurrentUserCredentialsMightWork = $False

                $CredsAndLockStatus = Check-CredsAndLockStatus

                $AltCredentialsAreValid = $CredsAndLockStatus.AltCredentialsAreValid
                if ($AltCredentialsAreValid) {
                    $AccountLocked = $CredsAndLockStatus.AccountLocked
                }
            }
        }

        if (!$LoggedInAsLocalUser) {
            if ($AltCredentials.Username -eq $(whoami)) {
                # If we ARE trying a Local Account on the Remote Host
                if ($($AltCredentials.Username -split "\\")[0] -eq $RemoteHostNetworkInfo.HostName) {
                    $LogonType = "LocalAccount"
                    $AltCredentialsUncertain = $True
                    $CurrentUserCredentialsMightWork = $False
                }

                # If we ARE NOT trying a Local Account on the Remote Host, we are necessarily trying Domain Credentials
                if ($($AltCredentials.Username -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName) {
                    $LogonType = "DomainAccount"

                    # We know we're staying within the same Domain...
                    $CurrentUserCredentialsMightWork = $True
                }
            }

            if ($AltCredentials.Username -ne $(whoami)) {
                # If we ARE trying a Local Account on the Remote Host
                if ($($AltCredentials.Username -split "\\")[0] -eq $RemoteHostNetworkInfo.HostName) {
                    $LogonType = "LocalAccount"
                    $AltCredentialsUncertain = $True
                    $CurrentUserCredentialsMightWork = $False
                }

                # If we ARE NOT trying a Local Account on the Remote Host, we are necessarily trying Domain Credentials
                if ($($AltCredentials.Username -split "\\")[0] -ne $RemoteHostNetworkInfo.HostName) {
                    $LogonType = "DomainAccount"

                    # If we're staying in the same Domain...
                    if ($EnvironmentInfo.UserDNSDomain -eq $RemoteHostNetworkInfo.Domain) {
                        $CurrentUserCredentialsMightWork = $True
                    }

                    # If we're trying a machine on a different Domain...
                    if ($EnvironmentInfo.UserDNSDomain -ne $RemoteHostNetworkInfo.Domain) {
                        $CredsAndLockStatus = Check-CredsAndLockStatus

                        $AltCredentialsAreValid = $CredsAndLockStatus.AltCredentialsAreValid
                        if ($AltCredentialsAreValid) {
                            $AccountLocked = $CredsAndLockStatus.AccountLocked
                        }
                    } # end Different Domain 'if' block
                } # end Domain Creds 'if' block
            } # end $AltCredentials.Username -ne $(whoami) 'if block'
        } # end !$LoggedInAsLocalUser 'if' block
    } # end $AltCredentials 'if' block
    if (!$AltCredentials) {
        # $AltCredentialsAreValid -eq $False because they are not provided...
        $AltCredentialsAreValid = $False
        
        if ($LoggedInAsLocalUser) {
            $CurrentUserCredentialsMightWork = $False
        }
        else {
            if ($RemoteHostNetworkInfo.Domain -eq $EnvironmentInfo.UserDNSDomain) {
                $LogonType = "DomainAccount"
                $CurrentUserCredentialsMightWork = $True
            }
            else {
                $CurrentUserCredentialsMightWork = $False
            }
        }
    }

    if ($AltCredentialsAreValid -or $AltCredentialsUncertain) {
        # NOTE: For some reason, there are situations where FQDN works over HostName or visa versa. So we use
        # logic to try FQDN, and if that fails, try HostName
        try {
            $InvokeCommandOutput = Invoke-Command -ComputerName $RemoteHostNetworkInfo.FQDN -Credential $AltCredentials -ScriptBlock {"Success"} -ErrorAction Stop
            $TargetHostLocation = $RemoteHostNetworkInfo.FQDN
            $CredentialsWorked = $True
            $ProvidedCredsWorked = $True
        }
        catch {
            try {
                $InvokeCommandOutput = Invoke-Command -ComputerName $RemoteHostNetworkInfo.HostName -Credential $AltCredentials -ScriptBlock {"Success"} -ErrorAction Stop
                $TargetHostLocation = $RemoteHostNetworkInfo.HostName
                $CredentialsWorked = $True
                $ProvidedCredsWorked = $True
            }
            catch {
                if ($CurrentUserCredentialsMightWork) {
                    $TryCurrentUserCreds = $True
                }
                else {
                    Write-Warning "Unable to determine working credentials for $RemoteHostNameOrIP! Try providing different credentials."
                }
            }
        }
    }

    if ($($AltCredentialsAreValid -and $TryCurrentUserCreds) -or
    $(!$AltCredentials -and $CurrentUserCredentialsMightWork) -or
    $(!$LoggedInAsLocalUser -and $AltCredentials.Username -eq $(whoami))
    ) {
        try {
            $InvokeCommandOutput = Invoke-Command -ComputerName $RemoteHostNetworkInfo.FQDN -ScriptBlock {"Success"} -ErrorAction Stop
            $TargetHostLocation = $RemoteHostNetworkInfo.FQDN
            $CredentialsWorked = $True
            $TriedCurrentlyLoggedInUser = $True
        }
        catch {
            try {
                $InvokeCommandOutput = Invoke-Command -ComputerName $RemoteHostNetworkInfo.HostName -ScriptBlock {"Success"} -ErrorAction Stop
                $TargetHostLocation = $RemoteHostNetworkInfo.HostName
                $CredentialsWorked = $True
                $TriedCurrentlyLoggedInUser = $True
            }
            catch {
                Write-Warning "Unable to determine working credentials for $RemoteHostNameOrIP! Try providing different credentials."
            }
        }
    }

    # Create Output
    $Output = [ordered]@{
        LogonType       = $LogonType
    }

    $CredentialsWorked = if ($CredentialsWorked) {$True} else {$False}
    $Output.Add("DeterminedCredsThatWorkedOnRemoteHost",$CredentialsWorked)

    if ($CredentialsWorked) {
        if ($LogonType -eq "LocalAccount") {
            $Output.Add("WorkingCredsAreValidOnDomain",$False)
        }
        else {
            $Output.Add("WorkingCredsAreValidOnDomain",$True)
        }

        if ($AltCredentials -and $ProvidedCredsWorked) {
            $WorkingCredentials = $AltCredentials
        }
        else {
            $WorkingCredentials = "$(whoami)"
        }

        $Output.Add("WorkingCredentials",$WorkingCredentials)
        $Output.Add("RemoteHostWorkingLocation",$TargetHostLocation)
    }
    
    if ($WorkingCredentials.UserName -eq "$(whoami)" -or $WorkingCredentials -eq "$(whoami)") {
        $Output.Add("CurrentLoggedInUserCredsWorked",$True)
    }
    else {
        if (!$TriedCurrentlyLoggedInUser) {
            $Output.Add("CurrentLoggedInUserCredsWorked","NotTested")
        }
        elseif ($TriedCurrentlyLoggedInUser -and $CredentialsWorked) {
            $Output.Add("CurrentLoggedInUserCredsWorked",$True)
        }
        elseif ($TriedCurrentlyLoggedInUser -and !$CredentialsWorked) {
            $Output.Add("CurrentLoggedInUserCredsWorked",$False)
        }
    }

    if ($AltCredentials) {
        if ($LogonType -eq "LocalAccount" -or $AltCredentialsAreValid -eq $False) {
            $Output.Add("ProvidedCredsAreValidOnDomain",$False)
        }
        elseif ($ProvidedCredsWorked) {
            $Output.Add("ProvidedCredsAreValidOnDomain",$True)
        }
        elseif ($ProvidedCredsWorked -eq $null) {
            $Output.Add("ProvidedCredsAreValidOnDomain","NotTested")
        }
        elseif ($ProvidedCredsWorked -eq $False) {
            $Output.Add("ProvidedCredsAreValidOnDomain",$False)
        }
        else {
            $Output.Add("ProvidedCredsAreValidOnDomain",$AltCredentialsAreValid)
        }
    }

    [pscustomobject]$Output

    #endregion >> Main Body
}



























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwauzGVFtIImyB3iuG5uU9O3I
# NFWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMSajhjWlJoIub0v
# 3oTirK/TAvBNMA0GCSqGSIb3DQEBAQUABIIBADSlOql9KHjXR4gAzXvkR39ZTfIK
# PVMUjJGTHfba1OxyDH1+dO5LTD8/IQoI+AVXy1BrpeC7bEZKL1/QnD/h/iiZuQIN
# bmT14mb3N9TYwNRjp7VEnnz28thCB/WazG/qJK/bkhaEJFU8aGUpOjaAyyCVwnJ6
# JWQapvp/rCmWUf4xqEiF8mIuIvjfEliXkLR6uSHQ86PxCy/QvJofLFob/ijzNEUq
# ni98ISdV+9AhCJ36Mg+HjD3eVMQ7UYZCRbipGfiiHjYz/82zTSeS3lzYAP0eJ+3/
# jBjqRd5YDRpFeaSOPoM9lRRXX2M97MlX26w2ex4vSXzaTfVXQHTSNe5K7ec=
# SIG # End signature block
