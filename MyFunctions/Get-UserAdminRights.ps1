function Get-UserAdminRights {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+\\[\w]+")]
        [string]$UserAcct = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    )

    #region >> Helper Functions

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

    function Get-DomainController {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$False)]
            [String]$Domain
        )
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
        $PartOfDomain = $ComputerSystemCim.PartOfDomain
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        ##### BEGIN Main Body #####
    
        if (!$PartOfDomain -and !$Domain) {
            Write-Error "$env:Computer is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $ThisMachinesDomain = $ComputerSystemCim.Domain
    
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

    Function Test-LDAP {
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
            $Connection = [ADSI]($LDAP)
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
            $Connection = [ADSI]($LDAP)
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
            $Connection = [ADSI]($LDAP)
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
            $Connection = [ADSI]($LDAP)
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

    function Get-UserObjectsInLDAP {
        [CmdletBinding()]
        Param()
    
        # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
        # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
        # PortsThatWork
        try {
            $DomainControllerInfo = Get-DomainController -ErrorAction Stop
            $LDAPInfo = Test-LDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
            if (!$DomainControllerInfo) {throw "Problem with Get-DomainController function! Halting!"}
            if (!$LDAPInfo) {throw "Problem with Test-LDAP function! Halting!"}
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
    
        $Connection = [ADSI]($LDAPUri)
        #$UsersLDAPContainer = $Connection.Children | Where-Object {$_.distinguishedName -match "Users"}
        #$UserObjectsInLDAP = $UsersLDAPContainer.Children | Where-Object {$_.objectClass -contains "user" -and $_.objectClass -notcontains "group"}
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Connection
        $Searcher.Filter = "(&(objectCategory=User))"
        $UserObjectsInLDAP = $Searcher.FindAll() | foreach {$_.GetDirectoryEntry()}
    
        $UserObjectsInLDAP
    }
    
    function Get-GroupObjectsInLDAP {
        [CmdletBinding()]
        Param()
    
        # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
        # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
        # PortsThatWork
        try {
            $DomainControllerInfo = Get-DomainController -ErrorAction Stop
            $LDAPInfo = Test-LDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
            if (!$DomainControllerInfo) {throw "Problem with Get-DomainController function! Halting!"}
            if (!$LDAPInfo) {throw "Problem with Test-LDAP function! Halting!"}
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
    
        $Connection = [ADSI]($LDAPUri)
        #$UsersLDAPContainer = $Connection.Children | Where-Object {$_.distinguishedName -match "Users"}
        #$UserObjectsInLDAP = $UsersLDAPContainer.Children | Where-Object {$_.objectClass -contains "user" -and $_.objectClass -notcontains "group"}
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Connection
        $Searcher.Filter = "(&(objectCategory=Group))"
        $GroupObjectsInLDAP = $Searcher.FindAll() | foreach {$_.GetDirectoryEntry()}
    
        $GroupObjectsInLDAP
    }
    
    #endregion >> Helper Functions
    


    ##### BEGIN Helper Functions #####

    ##### BEGIN PreRun Prep #####
    
    $UserShortName = $($UserAcct -split "\\")[-1]
    try {
        $LocalUserObject = Get-LocalUser -Name $UserShortName -ErrorAction Stop
        $UserIsLocalAccount = $True
    }
    catch {
        $UserIsDomainAccount = $True
    }

    $LocalAdministratorsGroupMembers = $(Get-LocalGroupMember -Group Administrators).Name
    if ($LocalAdministratorsGroupMembers -notcontains $UserAcct) {
        $GroupObjectsInLocalAdministratorsGroup = Get-LocalGroupMember -Group Administrators | Where-Object {$_.ObjectClass -eq "Group"}

        [System.Collections.ArrayList]$UserAcctMembershipCheck = @()
        foreach ($GroupObject in $GroupObjectsInLocalAdministratorsGroup) {
            if ($GroupObject.PrincipalSource -eq "Local") {
                if ($(Get-LocalGroupMember -Group $GroupObject.Name).Name -contains $UserAcct) {
                    $null = $UserAcctMembershipCheck.Add($True)
                }
            }
            if ($GroupObject.PrincipalSource -eq "ActiveDirectory" -and $UserIsDomainAccount) {
                $GroupShortName = $($GroupObject.Name -split "\\")[-1]
                [array]$RelevantLDAPGroupObject = Get-GroupObjectsInLDAP | Where-Object {$_.CN -match $GroupShortName}

                if ($RelevantLDAPGroupObject.Count -eq 1) {
                    if ($RelevantLDAPGroupObject.member -match "CN=$UserShortName,") {
                        $null = $UserAcctMembershipCheck.Add($True)
                    }
                }
                else {
                    Write-Warning "Unable to find exact match for the Group '$GroupShortName' in LDAP!"
                }
            }
        }
    }


    if ($LocalAdministratorsGroupMembers -contains $UserAcct -or $UserAcctMembershipCheck -contains $True) {
        $True
    }
    else {
        $False
    }
}








# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUd4iZGxy22IuD7Bz/QMLaJemm
# wnqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFgaKhtMZXaVInHs
# T7NKV+Ce1v2lMA0GCSqGSIb3DQEBAQUABIIBAHB0u5x/fSgZIYum3bCtN7JNzjSX
# a95CgXIFZ/mi9U+yf4nY1p5cVYaC4Ej/9mV/MTaIXZ+r1fIidc4bfqnhivkykiBr
# Ao1uYyS1oTa9EAaNYGB2ig/j983omsH5JMTWlH9LhE7NrQh0I5lpaIs4q2+fFOdK
# 3Mnddi4/kZpvbxQP7KYQzNQcwDQLxVbg4r/8R3abFNiTAhDj9KaYKO0y/5Cxr2WB
# fHb4bgujM3yBSUAg7rsBuC0isMMcQnQWx/q/ptRCoQGsBy6M5qibmii2+QqjHnn9
# cespxLNFsy/TflA6vZ/pgCRfjumaMoFJJWuSZQTi213ZFkH6ONgxgBRHCc8=
# SIG # End signature block
