<#
Segments of the below Get-LocalGroup function are from:
https://mcpmag.com/articles/2015/06/18/reporting-on-local-groups.aspx
#>
Function Get-LocalGroup {
    [Cmdletbinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string[]]$Group,

        [Parameter(Mandatory=$False)]
        [switch]$IncludeADGroupsAppliedLocally
    )

    ## BEGIN Native Helper Functions ##

    Function  ConvertTo-SID {
        Param([byte[]]$BinarySID)

        (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    Function Get-LocalGroupMember {
        Param (
            $GroupObject,
            $ADSIConnection,
            $Credentials,
            $Domain,
            $DomainPre,
            $RemoteHostNameFQDN,
            $UserNameWithAccess,
            $PasswordForUserNameWithAccess
        )

        $GroupMemberObjectArray = @()
        $Members = $GroupObject.Invoke('members') | ForEach {
            $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
        }

        $LocalUserAccounts = @()
        $LocalSystemAccounts = @()
        $LocalGroupAccounts = @()
        $ADUserAccountsAppliedLocally = @()
        $ADGroupAccountsAppliedLocally = @()

        if ($Members) {
            foreach ($Member in $Members) {
                # Check to See if $Member is a Local User Account
                try {
                    $MemberUserObject = $ADSIConnection.Children.Find("$Member", "User")
                }
                catch {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is either NOT a User Account or IS a User Account from Active Directory applied to the Local Group $($GroupObject.Name) ."
                }
                if ($MemberUserObject) {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is a Local User Account applied to the Local Group $($GroupObject.Name)"
                    $LocalUserAccounts +=, $MemberUserObject
                    Remove-Variable -Name "MemberUserObject"
                    continue
                }
                # Check To See if $Member is a Local System Account
                if ($Domain -and $Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | Where-Object {$_.Name -eq "$Member"}
                }
                if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | Where-Object {$_.Name -eq "$Member"}
                }
                if (!$Domain) {
                    $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | Where-Object {$_.Name -eq "$Member"}
                }
                if ($LocalSystemAccountCheck) {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is a Local System Account applied to the Local Group $($GroupObject.Name)"
                    $LocalSystemAccounts +=, $LocalSystemAccountCheck
                }

                # Check to See if $Member is a Local Group
                try {
                    $MemberGroupObject = $ADSIConnection.Children.Find("$Member", "Group")
                }
                catch {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is either NOT a Group or IS a Group from Active Directory applied to the Local Group $($GroupObject.Name)"
                }
                if ($MemberGroupObject) {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is a Local Group"
                    $LocalGroupAccounts +=, $MemberGroupObject
                    Remove-Variable -Name "MemberGroupObject"
                    continue
                }

                # Start checking Active Directory
                $ADSIForAD = [ADSI]"WinNT://$DomainPre"

                # Check to see if $Member is an AD User
                try {
                    $MemberADUserObject = $ADSIForAD.Children.Find("$Member", "User")
                }
                catch {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is NOT an AD User Account, which means it MUST be an AD Group."
                }
                if ($MemberADUserObject) {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is an AD User Account"
                    $ADUserAccountsAppliedLocally +=, $MemberADUserObject
                    Remove-Variable -Name "MemberADUserObject"
                    continue
                }

                # Check to see if $Member is an AD Group
                try {
                    $MemberADGroupObject = $ADSIForAD.Children.Find("$Member", "Group")
                }
                catch {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is NOT an AD Group. Either $Member is a database account (i.e. NT Service\$Member), or $Member is an AD Group or AD User that previously existed on the Domain and has since been deleted from Active Directory."
                }
                if ($MemberADGroupObject) {
                    Write-Verbose "The $($GroupObject.Name) Group Member $Member is an AD Group"
                    $ADGroupAccountsAppliedLocally +=, $MemberADGroupObject
                    Remove-Variable -Name "MemberADGroupObject"
                    continue
                }

                if (!$MemberUserObject -and !$LocalSystemAccountCheck -and !$MemberGroupObject -and !$MemberADUserObject -and !$MemberADGroupObject) {
                    Write-Verbose "Unable to find the Account $Member on the Local Host or in AD eventhough it is part of the Group $($GroupObject.Name). Either $Member is a database account (i.e. NT Service\$Member), or $Member is an AD Group or AD User that previously existed on the Domain and has since been deleted from Active Directory."
                    continue
                }
            }
        }

        $GetLocalGroupMemberFunctionOutput = @()
        for ($i=0; $i -lt $LocalUserAccounts.Count; $i++) {
            New-Variable -Name "LocalUserMemberInfo$i" -Value $(
                New-Object PSObject -Property @{
                    Name                = "$RemoteHostNameFQDNPre\$($LocalUserAccounts[$i].Name)"
                    ObjectClass         = "User"
                    PrincipalSource     = "Local"
                    SID                 = ConvertTo-SID -BinarySID $($LocalUserAccounts[$i].objectSid[0])
                    Object              = $LocalUserAccounts[$i]
                }
            ) -Force

            $GetLocalGroupMemberFunctionOutput +=, $(Get-Variable -Name "LocalUserMemberInfo$i" -ValueOnly)
        }
        for ($i=0; $i -lt $LocalSystemAccounts.Count; $i++) {
            New-Variable -Name "LocalSystemAccountMemberInfo$i" -Value $(
                New-Object PSObject -Property @{
                    Name                = "$RemoteHostNameFQDNPre\$($LocalSystemAccounts[$i].Name)"
                    ObjectClass         = "System"
                    PrincipalSource     = "Local"
                    SID                 = $LocalSystemAccounts[$i].SID
                    Object              = $LocalSystemAccounts[$i]
                }
            ) -Force

            $GetLocalGroupMemberFunctionOutput +=, $(Get-Variable -Name "LocalSystemAccountMemberInfo$i" -ValueOnly)
        }
        for ($i=0; $i -lt $LocalGroupAccounts.Count; $i++) {
            New-Variable -Name "LocalGroupMemberInfo$i" -Value $(
                New-Object PSObject -Property @{
                    Name                = "$RemoteHostNameFQDNPre\$($LocalGroupAccounts[$i].Name)"
                    ObjectClass         = "Group"
                    PrincipalSource     = "Local"
                    SID                 = ConvertTo-SID -BinarySID $($LocalGroupAccounts[$i].objectSid[0])
                    Object              = $LocalGroupAccounts[$i]
                }
            ) -Force

            $GetLocalGroupMemberFunctionOutput +=, $(Get-Variable -Name "LocalGroupMemberInfo$i" -ValueOnly)
        }
        for ($i=0; $i -lt $ADUserAccountsAppliedLocally.Count; $i++) {
            New-Variable -Name "ADUserMemberInfo$i" -Value $(
                New-Object PSObject -Property @{
                    Name                = "$DomainPre\$($ADUserAccountsAppliedLocally[$i].Name)"
                    ObjectClass         = "User"
                    PrincipalSource     = "ActiveDirectory"
                    SID                 = ConvertTo-SID -BinarySID $($ADUserAccountsAppliedLocally[$i].objectSid[0])
                    Object              = $ADUserAccountsAppliedLocally[$i]
                }
            ) -Force

            $GetLocalGroupMemberFunctionOutput +=, $(Get-Variable -Name "ADUserMemberInfo$i" -ValueOnly)
        }
        for ($i=0; $i -lt $ADGroupAccountsAppliedLocally.Count; $i++) {
            New-Variable -Name "ADGroupMemberInfo$i" -Value $(
                New-Object PSObject -Property @{
                    Name                = "$DomainPre\$($ADGroupAccountsAppliedLocally[$i].Name)"
                    ObjectClass         = "Group"
                    PrincipalSource     = "ActiveDirectory"
                    SID                 = ConvertTo-SID -BinarySID $($ADGroupAccountsAppliedLocally[$i].objectSid[0])
                    Object              = $ADGroupAccountsAppliedLocally[$i]
                }
            ) -Force

            $GetLocalGroupMemberFunctionOutput +=, $(Get-Variable -Name "ADGroupMemberInfo$i" -ValueOnly)
        }

        $GetLocalGroupMemberFunctionOutput
    }

    ## END Native Helper Functions ##

    $FoundGroupSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","MemberUserObject","GroupObject","MemberGroupObject",
        "UserNameWithAccess","PasswordForUserNameWithAccess","Credentials","RemoteHostIP","RemoteHostNameFQDN",
        "RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    ForEach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        $Domain = $RemoteHostNameFQDNPost
        if ($($Domain | Select-String -Pattern "\.").Matches.Success) {
            $DomainPre = $($RemoteHostNameFQDNPost.Split(".")[0])
        }
        else {
            $DomainPre = $RemoteHostNameFQDNPre
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####
        Write-Verbose  "Connecting to $($Computer)"

        If ($PSBoundParameters.ContainsKey('Group')) {
            Write-Verbose "Scanning for groups: $($Group -join ',')"
            $GroupObjects = ForEach ($Item in $Group) {
                $ADSI.Children.Find($Item, "Group")
            }
        } 
        Else {
            Write-Verbose "Scanning all Groups"
            $GroupObjects = $ADSI.Children | where {$_.SchemaClassName -eq "Group"}
        }

        $GetLocalGroupMemberParams = @{
            ADSIConnection                  = $ADSI
            Credentials                     = $Credentials
            Domain                          = $Domain
            DomainPre                       = $DomainPre
            RemoteHostNameFQDN              = $RemoteHostNameFQDN
            UserNameWithAccess              = $UserNameWithAccess
            PasswordForUserNameWithAccess   = $PasswordForUserNameWithAccess 
        }
        if ($GroupObjects) {
            $GroupObjects | ForEach {
                New-Variable -Name "FoundGroup$($_.Name[0])On$Computer" -Value $(
                    New-Object PSObject -Property @{
                        ComputerName = $Computer
                        Name = $_.Name[0]
                        Members = $(Get-LocalGroupMember -GroupObject $_ @GetLocalGroupMemberParams)
                        SID = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
                        GroupObject = $_
                    }
                ) -Force
                
                $FoundGroupSuccessArray +=, $(Get-Variable -Name "FoundGroup$($_.Name[0])On$Computer" -ValueOnly)
            }
        }
        Else {
            Throw  "No groups found!"
        }

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }

        ##### END Main Body #####
    }

    if ($FoundGroupSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to find any Groups on any Computers! Halting!"
        Write-Error "Unable to find any Groups on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($FoundGroupSuccessArray.Count -ge 1) {
        $FoundGroupSuccessArray
    }
}


Function Get-LocalUser {
    [Cmdletbinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string[]]$UserName
    )

    ## BEGIN Native Helper Functions ##

    Function  ConvertTo-SID {
        Param([byte[]]$BinarySID)

        (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    ## END Native Helper Functions ##

    [array]$FoundUserSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","GroupObject","UserNameWithAccess","PasswordForUserNameWithAccess",
        "Credentials","RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    ForEach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        if ($UserNameWithAccess) {
            $GetLocalGroupParams = @{
                ComputerName                    = $RemoteHostNameFQDN
                UserNameWithAccess              = $UserNameWithAccess
                PasswordForUserNameWithAccess   = $PasswordForUserNameWithAccess
            }
        }
        if (!$UserNameWithAccess) {
            $GetLocalGroupParams = @{
                ComputerName                    = $RemoteHostNameFQDN
            }
        }
        $ListOfGroupObjects = Get-LocalGroup @GetLocalGroupParams

        $GroupObjectsThatUserBelongsTo = foreach ($GroupObject in $ListOfGroupObjects) {
            if ($UserName) {
                $Present = $($GroupObject.Members | Where-Object {$_.ObjectClass -eq "User" -and $_.Name -eq "$Computer\$UserName"})
            }
            if (!$UserName) {
                $Present = $($GroupObject.Members | Where-Object {$_.ObjectClass -eq "User" -and $_.Name -like "$Computer\*"})
            }
            if ($Present) {
                $GroupObject
            }
        }

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####        

        Write-Verbose  "Connecting to $($Computer)"
        $adsi = [ADSI]"WinNT://$Computer"

        If ($PSBoundParameters.ContainsKey('UserName')) {
            Write-Verbose  "Scanning for UserName: $($UserName -join ',')"
            $UserObjects = ForEach ($Item in $UserName) {
                $adsi.Children.Find($Item, "User")
            }
        } 
        Else {
            Write-Verbose "Scanning all UserNames"
            $UserObjects = $adsi.Children | where {$_.SchemaClassName -eq "User"}
        }

        If ($UserObjects) {
            $UserObjects | ForEach {
                New-Variable -Name "FoundUser$($_.Name[0])On$Computer" -Value $(
                    New-Object PSObject -Property @{
                        ComputerName = $Computer
                        Name = $_.Name[0]
                        Enabled = !$_.InvokeGet('AccountDisabled')
                        GroupsThatTheUserBelongsTo = $GroupObjectsThatUserBelongsTo
                        SID = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
                        UserObject = $_
                    }
                ) -Force
                
                $FoundUserSuccessArray +=, $(Get-Variable -Name "FoundUser$($_.Name[0])On$Computer" -ValueOnly)
            }
        }
        Else {
            Throw  "No UserName(s) found!"
        }

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }

        ##### BEGIN Main Body #####
    }

    if ($FoundUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to find any Users on any Computers! Halting!"
        Write-Error "Unable to find any Users on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($FoundUserSuccessArray.Count -ge 1) {
        $FoundUserSuccessArray
    }
}


function Add-LocalGroupMember {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Member = $(Read-Host -Prompt "Please enter the name of the User or Group you would like to add to a Local Group"),

        [Parameter(Mandatory=$False)]
        [string]$Group = $(Read-Host -Prompt "Please enter the name of the Local Group you would like to add $Member to")
    )

    if ($($Member | Select-String -Pattern "\\").Matches.Success) {
        $DomainSearch = $Member.Split("\\")[0]
        $NameSearch = $Member.Split("\\")[-1]
    }
    else {
        $NameSearch = $Member
    }

    [array]$MemberAdditionSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","ADSIMember","UserObject","MemberUserObject","GroupObject","MemberGroupObject",
        "UserNameWithAccess","PasswordForUserNameWithAccess","DirectoryEntryPath","Credentials","RemoteHostIP","RemoteHostNameFQDN",
        "RemoteHostNameFQDNPre","RemoteHostNameFQDNPost","LocalAndDomainGroupMatches","LocalAndDomainAccountMatches",
        "MemberUserAccountObjectCheck","MemberSystemAccountObjectCheck","AdditionalMemberCheck"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        $Domain = $RemoteHostNameFQDNPost
        if ($($Domain | Select-String -Pattern "\.").Matches.Success) {
            $DomainPre = $($RemoteHostNameFQDNPost.Split(".")[0])
        }
        else {
            $DomainPre = $RemoteHostNameFQDNPre
        }

        # Check to see if $Member is a Local or Domain Group
        if ($Domain -and $Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $LocalAndDomainGroups = Get-WmiObject -Class "Win32_Group" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN,$Domain

            $ADSIMember = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
            $LocalAndDomainGroupsPrep = Get-WmiObject -Class "Win32_Group" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN,$Domain
            $LocalAndDomainGroups = $LocalAndDomainGroupsPrep | Where-Object {$_.Domain -eq "$RemoteHostNameFQDNPre" -or $Domain -eq "$DomainPre"}
        
            $ADSIMember = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$DomainPre/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if (!$Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
            $LocalAndDomainGroups = Get-WmiObject -Class "Win32_Group" -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN

            $ADSIMember = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($DomainSearch) {
            [array]$LocalAndDomainGroupMatches = $LocalAndDomainGroups | Where-Object {$_.Name -eq "$NameSearch" -or $_.Caption -eq "$DomainSearch\$NameSearch"}
        }
        if (!$DomainSearch) {
            [array]$LocalAndDomainGroupMatches = $LocalAndDomainGroups | Where-Object {$_.Name -eq "$NameSearch" -or $_.Caption -eq "$NameSearch"}
        }

        if ($LocalAndDomainGroupMatches) {
            if ($LocalAndDomainGroupMatches.Count -gt 1) {
                Write-Host "There is a Local Group on $Computer called $Member as well as a Domain Group called $Member on $Domain"
                $AddLocalOrDomainGroup = Read-Host -Prompt "Would you like to add the Local Group or the Domain Group to the Local Group $Group ? [Local/Domain]"
                while ($AddLocalOrDomainGroup -notmatch "Local|Domain") {
                    Write-Host "`"$AddLocalOrDomainGroup`" is not a valid option. Valid options are either `"Local`" or `"Domain`""
                    $AddLocalOrDomainGroup = Read-Host -Prompt "Would you like to add the Local Group or the Domain Group to the Local Group $Group ? [Local/Domain]"
                }
                if ($AddLocalOrDomainGroup -eq "Local") {
                    $ADSIMember = [ADSI]("WinNT://$Computer")
                }
                if ($AddLocalOrDomainGroup -eq "Domain") {
                    $ADSIMember = [ADSI]("WinNT://$DomainPre")
                }
            }
            if ($LocalAndDomainGroupMatches.Count -eq 1) {
                if ($LocalAndDomainGroupMatches.Domain -eq $DomainPre) {
                    $ADSIMember = [ADSI]("WinNT://$DomainPre")
                }
                else {
                    $ADSIMember = [ADSI]("WinNT://$Computer")
                }
            }
        }

        # If $ADSI still doesn't exist, then $Member is not a Group, so check to see if it is a Local or Domain User/System Account
        # This could take awhile if the Domain has thousands of users
        if (!$ADSIMember) {
            # Get All Accounts matching $Member in case $Member is a User Account or a System Account
            if ($Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
                $LocalAndDomainUserAccounts = Get-WmiObject -Class "Win32_UserAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN,$Domain
                $LocalSystemAccounts = Get-WmiObject -Class "Win32_SystemAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN
            }
            if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
                $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                $LocalAndDomainUserAccountsPrep = Get-WmiObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN,$Domain
                $LocalAndDomainUserAccounts = $LocalAndDomainUserAccountsPrep | Where-Object {$_.Domain -eq "$RemoteHostNameFQDNPre" -or $Domain -eq "$DomainPre"}
                $LocalSystemAccounts = Get-WmiObject -Class "Win32_SystemAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN
            }
            if (!$Domain) {
                $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                $LocalAndDomainUserAccounts = Get-WmiObject -Class "Win32_UserAccount" -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN
                $LocalSystemAccounts = Get-WmiObject -Class "Win32_SystemAccount" -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN
            }

            $LocalAndDomainAccounts = $LocalAndDomainUserAccounts + $LocalSystemAccounts
            if ($DomainSearch) {
                $MemberUserAccountObjectCheck = $LocalAndDomainUserAccounts | Where-Object {$_.Caption -eq "$DomainSearch\$NameSearch"}
                $MemberSystemAccountObjectCheck = $LocalSystemAccounts | Where-Object {$_.Caption -eq "$DomainSearch\$NameSearch"}
                [array]$LocalAndDomainAccountMatches = $LocalAndDomainAccounts | Where-Object {$_.Caption -eq "$DomainSearch\$NameSearch"}
            }
            if (!$DomainSearch) {
                $MemberUserAccountObjectCheck = $LocalAndDomainUserAccounts | Where-Object {$_.Name -eq "$NameSearch"}
                $MemberSystemAccountObjectCheck = $LocalSystemAccounts | Where-Object {$_.Name -eq "$NameSearch"}
                [array]$LocalAndDomainAccountMatches = $LocalAndDomainAccounts | Where-Object {$_.Name -eq "$NameSearch"}   
            }

            if ($LocalAndDomainAccountMatches) {
                if ($LocalAndDomainAccountMatches.Count -gt 1) {
                    Write-Warning "There is a Local User Account on $Computer called $Member as well as a Domain User Account called $Member on $Domain"
                    $AddLocalOrDomainAccount = Read-Host -Prompt "Would you like to add the Local User Account or the Domain User Account to the Local Group $Group ? [Local/Domain]"
                    while ($AddLocalOrDomainAccount -notmatch "Local|Domain") {
                        Write-Host "`"$AddLocalOrDomainAccount`" is not a valid option. Valid options are either `"Local`" or `"Domain`""
                        $AddLocalOrDomainAccount = Read-Host -Prompt "Would you like to add the Local User Account or the Domain User Account to the Local Group $Group ? [Local/Domain]"
                    }
                    if ($AddLocalOrDomainAccount -eq "Local") {
                        $ADSIMember = [ADSI]("WinNT://$Computer")
                    }
                    if ($AddLocalOrDomainAccount -eq "Domain") {
                        $ADSIMember = [ADSI]("WinNT://$DomainPre")
                    }
                }
                if ($LocalAndDomainAccountMatches.Count -eq 1) {
                    if ($LocalAndDomainAccountMatches.Domain -eq $DomainPre) {
                        $ADSIMember = [ADSI]("WinNT://$DomainPre")
                    }
                    else {
                        $ADSIMember = [ADSI]("WinNT://$Computer")
                    }
                }
            }
        }

        # Create ADSI $GroupObject so that we can add $Member to it later
        try {
            $GroupObject = $ADSI.Children.Find($Group, "Group")
        }
        catch {
            Write-Verbose "The Group $Group was NOT found on $Computer!"
        }
        if (!$GroupObject) {
            Write-Warning "The Group $Group was NOT found on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        $CurrentGroupMembers = $GroupObject.psbase.invoke("Members") | ForEach {
            $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
        }

        # If $Member is a Normal User Account, Create the $UserObject and get the $DirectoryEntryPath
        if ($MemberUserAccountObjectCheck) {
            try {
                $MemberUserObject = $ADSIMember.Children.Find($NameSearch, "User")
            }
            catch {
                Write-Verbose "User $Member NOT found on $($($ADSI.Path).Split("/")[-1])"
            }
            if (!$MemberUserObject) {
                Write-Warning "User $Member NOT found on $($($ADSI.Path).Split("/")[-1])!"

                # Cleanup
                foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                    Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                }
                continue
            }
            $DirectoryEntryPath = $MemberUserObject.Path
        }
        # If $Member is a Local System Account, the Find() Method will not help, so create the $DirectoryEntryPath manually
        if ($MemberSystemAccountObjectCheck) {
            $DirectoryEntryPath = "WinNT://NT AUTHORITY/$Member"
        }
        # If $Member is a Group, Create the $MemberGroupObject and get the $DirectoryEntryPath
        if (!$MemberUserAccountObjectCheck -and !$MemberSystemAccountObjectCheck) {
            try {
                $MemberGroupObject = $ADSIMember.Children.Find($NameSearch, "Group")
            }
            catch {
                if ($Domain) {
                    Write-Verbose "$Member was NOT found on $Computer or $Domain!"
                }
                if (!$Domain) {
                    Write-Verbose "$Member was NOT found on $Computer!"
                }
            }
            if (!$MemberGroupObject) {
                if ($Domain) {
                    Write-Warning "$Member was NOT found on $Computer or $Domain!"
                }
                if (!$Domain) {
                    Write-Warning "$Member was NOT found on $Computer!"
                }

                # Cleanup
                foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                    Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                }
                continue
            }
            if ($MemberGroupObject -eq $GroupObject) {
                Write-Warning "You cannot add the Local Group $Group to itself!"

                # Cleanup
                foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                    Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                }
                continue
            }
            $DirectoryEntryPath = $MemberGroupObject.Path
        }

        # Make sure the Member isn't already part of the Group
        if ($CurrentGroupMembers -contains $NameSearch) {
            if ($AddLocalOrDomainAccount -eq "Local") {
                if ($Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }
                if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }
                if (!$Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }

                if ($AdditionalMemberCheck) {
                    Write-Warning "The User $Member is already a member of the Group $Group on $Computer!"

                    # Cleanup
                    foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                        Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                    }
                    continue
                }
            }
            if ($AddLocalOrDomainAccount -eq "Domain") {
                if ($Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }
                if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }
                if (!$Domain) {
                    $AdditionalMemberCheck = Get-WmiObject Win32_GroupUser -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN | `
                    Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.PartComponent -like "*Domain=`"$DomainPre`"*"}
                }

                if ($AdditionalMemberCheck) {
                    Write-Warning "The User $Member is already a member of the Group $Group on $Computer!"

                    # Cleanup
                    foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                        Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                    }
                    continue
                }
            }
            if (!$AddLocalOrDomainAccount) {
                Write-Warning "The User $Member is already a member of the Group $Group on $Computer!"

                # Cleanup
                foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                    Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
                }
                continue
            }
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####
        try {
            # Add the User to the Group
            $GroupObject.Add(("$DirectoryEntryPath"))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $CredentialFailure = $True
            Write-Warning "Error creating $Name on $Computer`. This is most likely a problem with the provided Credentials."
        }
        if ($CredentialFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        # Record Success in $MemberAdditionSuccessArray
        if ($LocalAndDomainGroupMatches) {
            $MemberAdded = $LocalAndDomainGroupMatches.Caption
        }
        if ($LocalAndDomainAccountMatches) {
            $MemberAdded = $LocalAndDomainAccountMatches.Caption
        }

        New-Variable -Name "MemberAddedOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName    = $Computer
                Group           = $Group
                MemberAdded     = $MemberAdded
            }
        ) -Force
        
        $MemberAdditionSuccessArray +=, $(Get-Variable -Name "MemberAddedOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($MemberAdditionSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to add Local Member $Member to Local Group $Group on any Computers! Halting!"
        Write-Error "Unable to add Local Member $Member to Local Group $Group on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($MemberAdditionSuccessArray.Count -ge 1) {
        $MemberAdditionSuccessArray
    }
}



function Remove-LocalGroupMember {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Member = $(Read-Host -Prompt "Please enter the name of the User or Group you would like to remove from a Local Group"),

        [Parameter(Mandatory=$False)]
        [string]$Group = $(Read-Host -Prompt "Please enter the name of the Local Group you would like to remove $Member from")
    )

    if ($($Member | Select-String -Pattern "\\").Matches.Success) {
        $DomainSearch = $Member.Split("\\")[0]
        $NameSearch = $Member.Split("\\")[-1]
    }
    else {
        $NameSearch = $Member
    }

    [array]$MemberRemovalSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4)
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","ADSIMember","GroupObject","UserNameWithAccess","PasswordForUserNameWithAccess",
        "DirectoryEntryPath","Credentials","RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost",
        "LocalSystemAccountCheck","MemberToRemove","MemberToRemoveSystemAccountCheck"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        $Domain = $RemoteHostNameFQDNPost
        if ($($Domain | Select-String -Pattern "\.").Matches.Success) {
            $DomainPre = $($RemoteHostNameFQDNPost.Split(".")[0])
        }
        else {
            $DomainPre = $RemoteHostNameFQDNPre
        }

        if ($Domain -and $Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $MemberToRemove = Get-WmiObject "Win32_GroupUser" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
            Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*"}
            # Need $LocalSystemAccounts for later if Member is a System Account
            $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | Where-Object {$_.Name -eq $NameSearch}

            $ADSIMember = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
            
            $MemberToRemove = Get-WmiObject "Win32_GroupUser" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
            Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*"}
            # Need $LocalSystemAccounts for later if Member is a System Account
            $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
            Where-Object {$_.Name -eq $NameSearch}

            $ADSIMember = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$DomainPre/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")

        }
        if (!$Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
            
            $MemberToRemove = Get-WmiObject "Win32_GroupUser" -Credential $AltCredentials -ComputerName $RemoteHostNameFQDN | `
            Where-Object {$_.PartComponent -like "*Name=`"$NameSearch`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*"}
            # Need $LocalSystemAccounts for later if Member is a System Account
            $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN | `
            Where-Object {$_.Name -eq $NameSearch}

            $ADSIMember = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        if ($MemberToRemove.Count -gt 1) {
            if ($DomainSearch) {
                $MemberToRemove = $MemberToRemove | Where-Object {$_.PartComponent -like "*Domain=`"$DomainSearch`"*"}
            }
            else {
                Write-Host "There are $($MemberToRemove.Count) Members that are part of the Local Group $Group that match the Member Name $Member"
                Write-Host "Choices are as follows:"
                for ($i=0; $i -lt $MemberToRemove.Count; $i++) {
                    Write-Host "$($i+1))"$($MemberToRemove[$i].PartComponent | Select-String -Pattern "Domain=\`"(.*?)\`",Name=\`"$Member\`"").Matches.Value
                }
                $Choice = Read-Host -Prompt "Please select option $($(1..$MemberToRemove.Count) -join ", ")"
                while ($(1..$MemberToRemove.Count) -notcontains $Choice) {
                    Write-Warning "`"$Choice`" is not a valid option number!"
                    $Choice = Read-Host -Prompt "Please select option $($(1..$MemberToRemove.Count) -join ", ")" 
                }
                $ChoiceIndex = $Choice-1

                $MemberToRemove = $MemberToRemove[$ChoiceIndex]
            }
        }

        $MemberToRemoveSystemAccountCheck = $MemberToRemove.PartComponent -like "*SystemAccount*"

        # Get the ADSI $GroupObject we are going to remove $Member from so we can use it laser
        try {
            $GroupObject = $ADSI.Children.Find($Group, "Group")
        }
        catch {
            Write-Verbose "The Group $Group was NOT found on $Computer! Halting!"
        }
        if (!$GroupObject) {
            Write-Warning "The Group $Group was NOT found on $Computer! Halting!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        $CurrentGroupMembers = $GroupObject.psbase.invoke("Members") | ForEach {
            $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
        }

        if ($MemberToRemoveSystemAccountCheck) {
            $DirectoryEntryPath = "WinNT://NT AUTHORITY/$NameSearch"
        }
        if (!$MemberToRemoveSystemAccountCheck -and $Domain -and $($MemberToRemove.PartComponent -like "*Domain=`"$RemoteHostNameFQDNPre`"*")) {
            $DirectoryEntryPath = "WinNT://$DomainPre/$RemoteHostNameFQDNPre/$NameSearch"
        }
        if (!$MemberToRemoveSystemAccountCheck -and $Domain -and $($MemberToRemove.PartComponent -like "*Domain=`"$DomainPre`"*")) {
            $DirectoryEntryPath = "WinNT://$DomainPre/$NameSearch"
        }
        if (!$MemberToRemoveSystemAccountCheck -and !$Domain) {
            $DirectoryEntryPath = "WinNT://$RemoteHostNameFQDNPre/$NameSearch"
        }

        # Make sure the Member is part of the Group
        if ($CurrentGroupMembers -notcontains $NameSearch) {
            Write-Warning "The Member $Member is NOT a member of the Group $Group!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Remove the Local User from the Local Group
            $GroupObject.Remove(("$DirectoryEntryPath"))
        }
        catch [System.Management.Automation.MethodInvocationException] {
            $CredentialFailure = $True
            Write-Warning "Error removing $Member from $Group on $Computer`. This is most likely a problem with the provided Credentials."
        }
        if ($CredentialFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        # Record Success in $MemberRemovalSuccessArray
        $MemberRemoved = "$($DirectoryEntryPath.Split("/")[-2])\$($DirectoryEntryPath.Split("/")[-1])"

        New-Variable -Name "MemberRemovedOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName    = $Computer
                Group           = $Group
                MemberRemoved   = $MemberRemoved
            }
        ) -Force
        
        $MemberRemovalSuccessArray +=, $(Get-Variable -Name "MemberRemovedOn$Computer" -ValueOnly)

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }

        ##### END Main Body #####
    }

    if ($MemberRemovalSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to remove Local Member $Member to Local Group $Group on any Computers! Halting!"
        Write-Error "Unable to remove Local Member $Member to Local Group $Group on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($MemberRemovalSuccessArray.Count -ge 1) {
        $MemberRemovalSuccessArray
    }

}


function New-LocalGroup {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the new group you would like to create on the Computer(s) $ComputerName."),

        [Parameter(Mandatory=$False)]
        [string]$Description = $(Read-Host -Prompt "Please enter a description for the the group $Name")
    )

    [array]$NewGroupSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","GroupObject","GroupObjectTest","UserNameWithAccess","PasswordForUserNameWithAccess",
        "Credentials","RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Make sure a Group with the Name $Name doesn't already exist
        try {
            $GroupObjectTest = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "A Local Group with the name $Name does NOT already exist on $Computer. Continuing..."
        }
        if ($GroupObjectTest) {
            Write-Warning "A Group with the name $Name already exists on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Prep the GroupObject
            $GroupObject = $ADSI.Create("Group", $Name)
            # Actually Create the New Group
            $GroupObject.SetInfo()

            $GroupObject.Description = $Description
            $GroupObject.SetInfo()
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to create the Group $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $GroupObjectRemote = $using:GroupObject
                        # Prep the GroupObject
                        $GroupObjectRemote = $ADSIRemote.Create("Group", $using:Name)
                        # Actually Create the New Group
                        $GroupObjectRemote.SetInfo()

                        $GroupObjectRemote.Description = $using:Description
                        $GroupObjectRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error creating $Name on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }


        New-Variable -Name "NewLocalGroupCreatedOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName    = $Computer
                GroupCreated    = $Name
            }
        ) -Force

        $NewGroupSuccessArray +=, $(Get-Variable -Name "NewLocalGroupCreatedOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($NewGroupSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to create New Local Group $Name on any Computers! Halting!"
        Write-Error "Unable to create New Local Group $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($NewGroupSuccessArray.Count -ge 1) {
        $NewGroupSuccessArray
    }

}


function Remove-LocalGroup {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the group you would like to delete from the Computer(s) $ComputerName")
    )

    [array]$GroupRemovalSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","GroupObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Make sure the Local Group we want to Delete exists
        try {
            $GroupObject = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "The Group $Name was NOT found on $Computer!"
        }
        if (!$GroupObject) {
            Write-Warning "The Group $Name was NOT found on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Remove the Group
            $ADSI.Children.Remove($GroupObject)
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to remove the Group $Name from $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $ADSIRemote.Children.Remove($using:GroupObject)
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error Removing $Name from $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalGroupRemovedFrom$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName    = $Computer
                GroupRemoved    = $Name
            }
        ) -Force

        $GroupRemovalSuccessArray +=, $(Get-Variable -Name "LocalGroupRemovedFrom$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($GroupRemovalSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to remove Local Group $Name on any Computers! Halting!"
        Write-Error "Unable to remove Local Group $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($GroupRemovalSuccessArray.Count -ge 1) {
        $GroupRemovalSuccessArray
    }
}


function New-LocalUser {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the new user account would like to create on the Computer(s) $ComputerName."),

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$Password = $(Read-Host -Prompt "Please enter a new password for the new user account $Name." -AsSecureString),

        [Parameter(Mandatory=$False)]
        [string]$Description,

        [Parameter(Mandatory=$False)]
        [switch]$ChangePasswordOnFirstLogon
    )

    [array]$NewLocalUserSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        
        # Make sure the user does NOT already exist on the $Computer
        try {
            $UserObject = $ADSI.Children.Find("$Name", "User")
        }
        catch {
            Write-Verbose "User $Name NOT already on $Computer. Continuing..."
        }
        if ($UserObject) {
            Write-Warning "The User $Name already exists on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        $LocalUserAccounts = $ADSI.Children  | where {$_.SchemaClassName  -eq 'User'}

        # Get current password minimum length requirement
        $PwdMinLength = $LocalUserAccounts[2].MinPasswordLength

        # NOTE: To change the password length requirement, change the numbers at end of the below regex {$PwdMinLength,25}
        $PasswordComplexityRegex = @"
^((?=.*[a-z])(?=.*[A-Z])(?=.*\d)|(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])|(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]))([A-Za-z\d@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]|\.(?!@)){$PwdMinLength,30}$
"@
        $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
        $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        
        # Below -cmatch comparison operator is for case-sensitive matching
        while (!$($PTPwd -cmatch $PasswordComplexityRegex)) {
            Write-Warning "The password provided does not meet minimum password complexity requirements."
            Write-Host "Passwords must be $PwdMinLength-30 characters, and meet three out of four of the following conditions:"
            Write-Host "    - Lowercase characters"
            Write-Host "    - Uppercase characters"
            Write-Host "    - digits (0-9)"
            Write-Host '    - One or more of the following symbols: @ # $ % ^ & * – _ + = [ ] { } | \ : , ? / ` ~ " ( ) ; . £'
            $Password = Read-Host -Prompt "Please enter a new password for the new user account $Name." -AsSecureString
            $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
            $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Create New User
        try {
            $NewUser = $ADSI.Create('User',$Name)
            $NewUser.SetPassword(($PTPwd))
            if ($ChangePasswordOnFirstLogon) {
                $NewUser.PasswordExpired = 1
            }
            $NewUser.SetInfo()

            if ($Description) {
                $NewUser.Description = $Description
            }
            $NewUser.SetInfo()
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to create new user $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = [ADSI]("WinNT://$($(Get-WMIObject Win32_ComputerSystem).Name)")
                        $NewUserRemote = $ADSIRemote.Create('User',$Name)
                        $NewUserRemote.SetPassword(($using:PTPwd))
                        if ($using:ChangePasswordOnFirstLogon) {
                            $NewUserRemote.PasswordExpired = 1
                        }
                        $NewUserRemote.SetInfo()

                        if ($using:Description) {
                            $NewUserRemote.Description = $using:Description
                        }
                        $NewUserRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error creating $Name on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "NewLocalUserFor$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName    = $Computer
                NewLocalUser    = $Name
            }
        ) -Force

        $NewLocalUserSuccessArray +=, $(Get-Variable -Name "NewLocalUserFor$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }

    }

    if ($NewLocalUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to create New Local User $Name on any Computers! Halting!"
        Write-Error "Unable to create New Local User $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($NewLocalUserSuccessArray.Count -ge 1) {
        $NewLocalUserSuccessArray
    }

    # Wipe all traces of the Password from Memory
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    Remove-Variable Password,BSTR,PTPwd

}


function Remove-LocalUser {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the user account would like to remove from the Computer(s) $ComputerName.")
    )

    [array]$RemoveLocalUserSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer!"
        }
        if (!$UserObject) {
            Write-Warning "User $Name NOT found on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try{
            # Delete the User
            $ADSI.Delete("User", $Name)
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to remove the User $Name from $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        # Delete the User
                        $ADSIRemote.Delete("User", $using:Name)
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error Removing $Name from $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalUserRemovedFrom$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName        = $Computer
                RemovedLocalUser    = $Name
            }
        ) -Force

        $RemoveLocalUserSuccessArray +=, $(Get-Variable -Name "LocalUserRemovedFrom$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }

    }

    if ($RemoveLocalUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to remove Local User $Name on any Computers! Halting!"
        Write-Error "Unable to remove Local User $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($RemoveLocalUserSuccessArray.Count -ge 1) {
        $RemoveLocalUserSuccessArray
    }

}


function Disable-LocalUser {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the user account you would like disable on the Computer(s) $ComputerName.")
    )

    [array]$DisabledLocalUserSuccessArray = @()    

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }
    
    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer!"
        }
        if (!$UserObject) {
            Write-Warning "User $Name NOT found on $Computer!"
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        # Check to see if the user account is already disabled
        $Disabled = 0x0002
        if ([boolean]$($UserObject.UserFlags.value -BAND $Disabled)) {
            Write-Warning "Account $Name is already disabled on $Computer!"
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Disable the User Account
            $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BOR $Disabled
            $UserObject.SetInfo()
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to disable the User $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $UserObjectRemote = $using:UserObject

                        # Disable the User Account
                        $UserObjectRemote.UserFlags.Value = $UserObjectRemote.UserFlags.Value -BOR $using:Disabled
                        $UserObjectRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error disabling $Name on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalUserDisabledOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName        = $Computer
                DisabledLocalUser   = $Name
            }
        ) -Force

        $DisabledLocalUserSuccessArray +=, $(Get-Variable -Name "LocalUserDisabledOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($DisabledLocalUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to disable Local User $Name on any Computers! Halting!"
        Write-Error "Unable to disable Local User $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($DisabledLocalUserSuccessArray.Count -ge 1) {
        $DisabledLocalUserSuccessArray
    }

}


function Enable-LocalUser {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the name of the user account you would like enable on Computer(s) $ComputerName.")
    )

    [array]$EnabledLocalUserSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }
    
    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer!"
        }
        if (!$UserObject) {
            Write-Warning "User $Name NOT found on $Computer!"
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        # Check to see if the user account is already enabled.
        $Disabled = 0x0002
        if (-not [boolean]$($UserObject.UserFlags.value -BAND $Disabled)) {
            Write-Warning "Account $Name is already enabled on $Computer! Halting!"
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Enable the User Account
            $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BXOR $Disabled
            $UserObject.SetInfo()
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to enable the User $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $UserObjectRemote = $using:UserObject

                        # Enable the User Account
                        $UserObjectRemote.UserFlags.Value = $UserObjectRemote.UserFlags.Value -BXOR $using:Disabled
                        $UserObjectRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error enabling $Name on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalUserEnabledOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName        = $Computer
                EnabledLocalUser    = $Name
            }
        ) -Force

        $EnabledLocalUserSuccessArray +=, $(Get-Variable -Name "LocalUserEnabledOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($EnabledLocalUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to enable Local User $Name on any Computers! Halting!"
        Write-Error "Unable to enable Local User $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($EnabledLocalUserSuccessArray.Count -ge 1) {
        $EnabledLocalUserSuccessArray
    }

}


function Reset-LocalUserPassword {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$UserName = $(Read-Host -Prompt "Please enter the UserName of the account that you would like reset the password on the Computer(s) $ComputerName."),

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$Password = $(Read-Host -Prompt "Please enter the new password for the user account $UserName." -AsSecureString),

        [Parameter(Mandatory=$False)]
        [switch]$ChangePasswordOnFirstLogon,

        [Parameter(Mandatory=$False)]
        [switch]$PasswordNeverExpires
    )

    $ResetPwdSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }
    
    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($UserName, "User")
        }
        catch {
            Write-Verbose "User $UserName NOT found on $Computer!"
        }
        if (!$UserObject) {
            Write-Warning "User $UserName NOT found on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        $PasswordComplexityRegex = @"
^((?=.*[a-z])(?=.*[A-Z])(?=.*\d)|(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])|(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]))([A-Za-z\d@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]|\.(?!@)){$($UserObject.MinPasswordLength),30}$
"@
        $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
        $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        
        # Below -cmatch comparison operator is for case-sensitive matching
        while (!$($PTPwd -cmatch $PasswordComplexityRegex)) {
            Write-Warning "The password provided does not meet minimum password complexity requirements."
            Write-Host "Passwords must be $($UserObject.MinPasswordLength)-30 characters, and meet three out of four of the following conditions:"
            Write-Host "    - Lowercase characters"
            Write-Host "    - Uppercase characters"
            Write-Host "    - digits (0-9)"
            Write-Host '    - One or more of the following symbols: @ # $ % ^ & * – _ + = [ ] { } | \ : , ? / ` ~ " ( ) ; . £'
            $Password = Read-Host -Prompt "Please enter a new password for the new user account $UserName." -AsSecureString
            $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
            $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        try {
            # Change User Password
            $UserObject.SetPassword(($PTPwd))
            if ($ChangePasswordOnFirstLogon) {
                $UserObject.PasswordExpired = 1
            }
            if ($PasswordNeverExpires) {
                $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -bor 0x10000
            }
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to reset password for the User $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $UserObjectRemote = $using:UserObject

                        # Change User Password
                        $UserObjectRemote.SetPassword(($using:PTPwd))
                        if ($ChangePasswordOnFirstLogon) {
                            $UserObjectRemote.PasswordExpired = 1
                        }
                        if ($using:PasswordNeverExpires) {
                            $UserObjectRemote.UserFlags.Value = $UserObjectRemote.UserFlags.Value -bor 0x10000
                        }
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error changing password for $UserName on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalUserPwdResetOn$Computer" -Value $(
            New-Object PSObject -Property @{
                ComputerName             = $Computer
                LocalUserThatWasReset    = $UserName
            }
        ) -Force

        $ResetPwdSuccessArray +=, $(Get-Variable -Name "LocalUserPwdResetOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($ResetPwdSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to reset password for Local User $UserName on any Computers! Halting!"
        Write-Error "Unable to reset password for Local User $UserName on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ResetPwdSuccessArray.Count -ge 1) {
        $ResetPwdSuccessArray
    }

    # Wipe all traces of the Password from Memory
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    Remove-Variable Password,BSTR,PTPwd

}


function Set-LocalUser {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the UserName of the account that you would like change properties for on the Computer(s) $ComputerName."),

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$Password,

        [Parameter(Mandatory=$False)]
        [switch]$ChangePasswordOnFirstLogon,

        [Parameter(Mandatory=$False)]
        [switch]$PasswordNeverExpires,

        [Parameter(Mandatory=$False)]
        [switch]$PasswordExpires,

        [Parameter(Mandatory=$False)]
        [System.DateTime]$AccountExpiresDateTime,

        [Parameter(Mandatory=$False)]
        [switch]$AccountNeverExpires,

        [Parameter(Mandatory=$False)]
        [switch]$EnableUserAccount,

        [Parameter(Mandatory=$False)]
        [switch]$DisableUserAccount,

        [Parameter(Mandatory=$False)]
        [switch]$LockUserAccount,

        [Parameter(Mandatory=$False)]
        [switch]$UnlockUserAccount,

        [Parameter(Mandatory=$False)]
        [string]$Description
    )

    if ($AccountExpiresDateTime -and $AccountNeverExpires) {
        Write-Verbose "Please use *either* the parameter `$AccountExpiresDateTime *or* the parameter `$AccountNeverExpires! Halting!"
        Write-Error "Please use *either* the parameter `$AccountExpiresDateTime *or* the parameter `$AccountNeverExpires! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($($ChangePasswordOnFirstLogon -and $PasswordNeverExpires) -or
    $($ChangePasswordOnFirstLogon -and $PasswordExpires) -or
    $($PasswordNeverExpires -and $PasswordExpires)) {
        Write-Verbose "Please use *either* the parameter `$ChangePasswordOnFirstLogon *or* the parameter `$PasswordNeverExpires *or* the parameter `$PasswordExpires! Halting!"
        Write-Error "Please use *either* the parameter `$ChangePasswordOnFirstLogon *or* the parameter `$PasswordNeverExpires *or* the parameter `$PasswordExpires! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$Password -and !$ChangePasswordOnFirstLogon -and !$PasswordNeverExpires -and !$PasswordExpires -and !$AccountExpiresDateTime -and !$Description) {
        Write-Verbose "No properties to modify were specified. Please use additional parameters to specify which properties you would like to modify. Halting!"
        Write-Error "No properties to modify were specified. Please use additional parameters to specify which properties you would like to modify. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($Name | Select-String -Pattern "\\").Matches.Success) {
        $DomainSearch = $Member.Split("\\")[0]
        $NameSearch = $Member.Split("\\")[-1]
    }
    else {
        $NameSearch = $Name
    }

    [array]$SetLocalUserSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }
    
    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","UserObject","UserNameWithAccess","PasswordForUserNameWithAccess","Credentials",
        "RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost","UserAccountPropertiesThatWereChanged",
        "WMIUserObject"
    )

    foreach ($Computer in $ComputerName) {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        $UserAccountPropertiesThatWereChanged = New-Object System.Collections.Specialized.OrderedDictionary
        
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        $Domain = $RemoteHostNameFQDNPost
        if ($($Domain | Select-String -Pattern "\.").Matches.Success) {
            $DomainPre = $($RemoteHostNameFQDNPost.Split(".")[0])
        }
        else {
            $DomainPre = $RemoteHostNameFQDNPre
        }

        if ($Domain -and $Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
            if ($DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }
        if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess

            if ($DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }
        if (!$Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess

            if ($DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIUserObject = Get-WMIObject -Class "Win32_UserAccount" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer!"
        }
        if (!$UserObject) {
            Write-Warning "User $Name NOT found on $Computer!"

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

        try {
            # These aren't properties, but will be a part of the output PSCustomObject, which is why they're being added
            $UserAccountPropertiesThatWereChanged.Add("ComputerName","$Computer")
            $UserAccountPropertiesThatWereChanged.Add("LocalUser","$Name")

            if ($Password) {
                $PasswordComplexityRegex = @"
^((?=.*[a-z])(?=.*[A-Z])(?=.*\d)|(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])|(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]))([A-Za-z\d@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]|\.(?!@)){$($UserObject.MinPasswordLength),30}$
"@
                $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
                $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
                
                # Below -cmatch comparison operator is for case-sensitive matching
                while (!$($PTPwd -cmatch $PasswordComplexityRegex)) {
                    Write-Warning "The password provided does not meet minimum password complexity requirements."
                    Write-Host "Passwords must be $($UserObject.MinPasswordLength)-30 characters, and meet three out of four of the following conditions:"
                    Write-Host "    - Lowercase characters"
                    Write-Host "    - Uppercase characters"
                    Write-Host "    - digits (0-9)"
                    Write-Host '    - One or more of the following symbols: @ # $ % ^ & * – _ + = [ ] { } | \ : , ? / ` ~ " ( ) ; . £'
                    $Password = Read-Host -Prompt "Please enter a new password for the new user account $Name." -AsSecureString
                    $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
                    $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
                }

                # Change User Password
                $UserObject.SetPassword(($PTPwd))
                $UserAccountPropertiesThatWereChanged.Add("ChangedPassword","Password Was Changed")
                #$UserAccountPropertiesThatWereChanged +=, @{"Password"="Password Was Changed"}
            }
            if ($ChangePasswordOnFirstLogon) {
                if ($UserObject.PasswordExpired -eq 1) {
                    Write-Warning "The User Account $Name on $Computer is already configured to force a password change upon next logon! No changes made!"
                }
                else {
                    $UserObject.PasswordExpired = 1
                    $UserAccountPropertiesThatWereChanged.Add("ChangedPasswordExpiration","Password Set To Expire Immediately")
                    #$UserAccountPropertiesThatWereChanged +=, @{"PasswordExpiration"="Password Set To Expire Immediately"}
                }
            }
            if ($PasswordNeverExpires) {
                if (!$WMIUserObject.PasswordExpires) {
                    Write-Warning "The password for $Name on $Computer is already configured to NEVER expire! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{PasswordExpires=$false} | Out-Null
                    #$UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BOR 0x10000
                    $UserAccountPropertiesThatWereChanged.Add("ChangedPasswordExpiration","Password Never Expires")
                    #$UserAccountPropertiesThatWereChanged +=, @{"PasswordExpiration"="Password Never Expires"}
                }
            }
            if ($PasswordExpires) {
                if ($WMIUserObject.PasswordExpires) {
                    Write-Warning "The password for $Name on $Computer is already configured to expire at some point in the future! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{PasswordExpires=$true} | Out-Null
                    $UserAccountPropertiesThatWereChanged.Add("ChangedPasswordExpiration","Password Expires")
                }
            }

            if ($AccountExpiresDateTime) {
                $UserObject.Put("AccountExpirationDate", $AccountExpiresDateTime)
                $UserAccountPropertiesThatWereChanged.Add("ChangedAccountExpirationDate","Account Expiration Date Set To $AccountExpiresDateTime")
                #$UserAccountPropertiesThatWereChanged +=, @{"AccountExpirationDate"="Account Expiration Date Set To $AccountExpiresDateTime"}
            }
            if ($AccountNeverExpires) {
                $UserObject.Put("AccountExpirationDate", [System.DateTime]::MaxValue)
                $UserAccountPropertiesThatWereChanged.Add("ChangedAccountExpirationDate","Account Never Expires")
                #$UserAccountPropertiesThatWereChanged +=, @{"AccountExpirationDate"="Account Never Expires"}
            }

            if ($EnableUserAccount) {
                if (!$WMIUserObject.Disabled) {
                    Write-Warning "The User Account $Name on $Computer is already Enabled! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{Disabled=$false} | Out-Null
                    $UserAccountPropertiesThatWereChanged.Add("AccountStatus","Account Has Been Enabled")
                }
            }
            if ($DisableUserAccount) {
                if ($WMIUserObject.Disabled) {
                    Write-Warning "The User Account $Name on $Computer is already Disabled! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{Disabled=$true} | Out-Null
                    $UserAccountPropertiesThatWereChanged.Add("AccountStatus","Account Has Been Disabled")
                }
            }
            if ($LockUserAccount) {
                if ($WMIUserObject.Lockout) {
                    Write-Warning "The User Account $Name on $Computer is already LockedOut! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{Lockout=$true} | Out-Null
                    $UserAccountPropertiesThatWereChanged.Add("AccountLockStatus","Account Is Locked")
                }
            }
            if ($UnlockUserAccount) {
                if (!$WMIUserObject.Lockout) {
                    Write-Warning "The User Account $Name on $Computer is already Unlocked! No changes made!"
                }
                else {
                    $WMIUserObject | Set-WMIInstance -Argument @{Lockout=$false} | Out-Null
                    $UserAccountPropertiesThatWereChanged.Add("AccountLockStatus","Account Is Unlocked")
                }
            }

            $UserObject.SetInfo()

            if ($Description) {
                $UserObject.Description = $Description
                $UserAccountPropertiesThatWereChanged.Add("ChangedDescription","$Description")
                #$UserAccountPropertiesThatWereChanged +=, @{"Description"="$Description"}
            }

            $UserObject.SetInfo()
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to reset password for the User $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $UserObjectRemote = $using:UserObject
                        $UserAccountPropertiesThatWereChangedRemote = $using:UserAccountPropertiesThatWereChanged

                        # These aren't properties, but will be a part of the output PSCustomObject, which is why they're being added
                        $UserAccountPropertiesThatWereChangedRemote.Add("ComputerName","$using:Computer")
                        $UserAccountPropertiesThatWereChangedRemote.Add("LocalUser","$using:Name")

                        if ($using:Password) {
                            # Change User Password
                            $UserObjectRemote.SetPassword(($using:PTPwd))
                            $UserAccountPropertiesThatWereChangedRemote.Add("ChangedPassword","Password Was Changed")
                            #$UserAccountPropertiesThatWereChanged +=, @{"Password"="Password Was Changed"}
                        }
                        if ($using:ChangePasswordOnFirstLogon) {
                            if ($UserObjectRemote.PasswordExpired -eq 1) {
                                Write-Warning "The User Account $Name on $Computer is already configured to force a password change upon next logon! No changes made!"
                            }
                            else {
                                $UserObjectRemote.PasswordExpired = 1
                                $UserAccountPropertiesThatWereChangedRemote.Add("ChangedPasswordExpiration","Password Set To Expire Immediately")
                                #$UserAccountPropertiesThatWereChanged +=, @{"PasswordExpiration"="Password Set To Expire Immediately"}
                            }
                        }
                        if ($using:PasswordNeverExpires) {
                            if (!$using:WMIUserObject.PasswordExpires) {
                                Write-Warning "The password for $using:Name on $using:Computer is already configured to NEVER expire! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{PasswordExpires=$false}
                                #$UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BOR 0x10000
                                $UserAccountPropertiesThatWereChangedRemote.Add("ChangedPasswordExpiration","Password Never Expires")
                                #$UserAccountPropertiesThatWereChanged +=, @{"PasswordExpiration"="Password Never Expires"}
                            }
                        }
                        if ($using:PasswordExpires) {
                            if ($using:WMIUserObject.PasswordExpires) {
                                Write-Warning "The password for $using:Name on $using:Computer is already configured to expire at some point in the future! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{PasswordExpires=$true}
                                $UserAccountPropertiesThatWereChangedRemote.Add("ChangedPasswordExpiration","Password Expires")
                            }
                        }

                        if ($using:AccountExpiresDateTime) {
                            $UserObjectRemote.Put("AccountExpirationDate", $using:AccountExpiresDateTime)
                            $UserAccountPropertiesThatWereChangedRemote.Add("ChangedAccountExpirationDate","Account Expiration Date Set To $AccountExpiresDateTime")
                            #$UserAccountPropertiesThatWereChanged +=, @{"AccountExpirationDate"="Account Expiration Date Set To $AccountExpiresDateTime"}
                        }
                        if ($using:AccountNeverExpires) {
                            $UserObjectRemote.Put("AccountExpirationDate", [System.DateTime]::MaxValue)
                            $UserAccountPropertiesThatWereChangedRemote.Add("ChangedAccountExpirationDate","Account Never Expires")
                            #$UserAccountPropertiesThatWereChanged +=, @{"AccountExpirationDate"="Account Never Expires"}
                        }

                        if ($using:EnableUserAccount) {
                            if (!$using:WMIUserObject.Disabled) {
                                Write-Warning "The User Account $using:Name on $using:Computer is already Enabled! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{Disabled=$false}
                                $UserAccountPropertiesThatWereChangedRemote.Add("AccountStatus","Account Has Been Enabled")
                            }
                        }
                        if ($using:DisableUserAccount) {
                            if ($using:WMIUserObject.Disabled) {
                                Write-Warning "The User Account $using:Name on $using:Computer is already Disabled! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{Disabled=$true}
                                $UserAccountPropertiesThatWereChangedRemote.Add("AccountStatus","Account Has Been Disabled")
                            }
                        }
                        if ($using:LockUserAccount) {
                            if ($using:WMIUserObject.Lockout) {
                                Write-Warning "The User Account $using:Name on $using:Computer is already LockedOut! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{Lockout=$true}
                                $UserAccountPropertiesThatWereChangedRemote.Add("AccountLockStatus","Account Is Locked")
                            }
                        }
                        if ($using:UnlockUserAccount) {
                            if (!$using:WMIUserObject.Lockout) {
                                Write-Warning "The User Account $using:Name on $using:Computer is already Unlocked! No changes made!"
                            }
                            else {
                                $using:WMIUserObject | Set-WMIInstance -Argument @{Lockout=$false}
                                $UserAccountPropertiesThatWereChangedRemote.Add("AccountLockStatus","Account Is Unlocked")
                            }
                        }

                        $UserObjectRemote.SetInfo()

                        if ($using:Description) {
                            $UserObjectRemote.Description = $using:Description
                            $UserAccountPropertiesThatWereChangedRemote.Add("ChangedDescription","$using:Description")
                            #$UserAccountPropertiesThatWereChanged +=, @{"Description"="$Description"}
                        }

                        $UserObjectRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error changing propert(ies) for $Name on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        if ($($UserAccountPropertiesThatWereChanged.Keys).Count -eq 2 -and
        $UserAccountPropertiesThatWereChanged.Keys -contains "ComputerName" -and
        $UserAccountPropertiesThatWereChanged.Keys -contains "LocalUser") {
            Write-Verbose "No changes were made. Moving on..."

            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue   
        }


        New-Variable -Name "LocalUserPropertiesOn$Computer" -Value $(
            New-Object PSObject -Property $UserAccountPropertiesThatWereChanged
        ) -Force

        $SetLocalUserSuccessArray +=, $(Get-Variable -Name "LocalUserPropertiesOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
    }

    if ($Password) {
        # Wipe all traces of the Password from Memory
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        Remove-Variable Password,BSTR,PTPwd
    }

    if ($SetLocalUserSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to change properties for Local User $Name on any Computers! Halting!"
        Write-Error "Unable to change properties for Local User $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SetLocalUserSuccessArray.Count -ge 1) {
        $SetLocalUserSuccessArray
    }
}


function Set-LocalGroup {
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True
        )]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$PasswordForUserNameWithAccess,

        [Parameter(Mandatory=$False)]
        [string]$Name = $(Read-Host -Prompt "Please enter the Name of the Local Group that you would like change properties for on $env:COMPUTERNAME."),

        [Parameter(Mandatory=$False)]
        [string]$Description
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if (!$Description) {
        Write-Host "Currently, this function is only capable of modifying the Description of a Local Group. Since the parameter `$Description was not used, no action will be taken."
        Write-Host "No changes to Group $Name have been made."
        return
    }

    [array]$SetLocalGroupSuccessArray = @()

    if ($UserNameWithAccess) {
        if (!$PasswordForUserNameWithAccess) {
            $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
        }
    }
    
    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    $VariablesToRemoveAtEndOfEachLoop = @("ADSI","GroupObject", "UserNameWithAccess","PasswordForUserNameWithAccess",
        "Credentials","RemoteHostIP","RemoteHostNameFQDN","RemoteHostNameFQDNPre","RemoteHostNameFQDNPost",
        "GroupAccountPropertiesThatWereChanged"
    )

    foreach ($Computer in $ComputerName) {
        $GroupAccountPropertiesThatWereChanged = New-Object System.Collections.Specialized.OrderedDictionary
        
        if (! $(Test-IsValidIPAddress -IPAddress $Computer)) {
            try {
                $RemoteHostIP = $([System.Net.DNS]::Resolve("$Computer")).AddressList.IPAddressToString
            }
            catch {
                Write-Verbose "Unable to resolve $Computer !"
            }
            if ($RemoteHostIP) {
                # To ensure [System.Net.DNS]::Resolve() returns an FQDN every time (as opposed to just a hostname), you MUST use an IP
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostIP) {
                Write-Warning "Unable to resolve $RemoteHost!"
                continue
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Computer) {
            try {
                $RemoteHostIP = $RemoteHost
                $RemoteHostNameFQDN = $([System.Net.DNS]::Resolve("$RemoteHostIP")).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.") -ne $null) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                }
            }
            if (!$RemoteHostNameFQDN) {
                Write-Warning "Unable to resolve $RemoteHost! Halting!"
                continue
            }
        }
        if (!$RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPre -ne $env:ComputerName)) {
            Write-Verbose "$Computer is NOT part of a Domain"
            if (!$UserNameWithAccess) {
                Write-Warning "The Remote Host $Computer is not part of a Domain."
                $UserNameWithAccess = Read-Host -Prompt "Please enter the UserName for a local admin account on $RemoteHostNameFQDNPre"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$RemoteHostNameFQDNPre\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $RemoteHostNameFQDNPre) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$RemoteHostNameFQDNPre"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -eq $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer is part of the same Domain that $env:ComputerName is on. No Credentials needed (assuming PowerShell is being run under a Domain Admin account)."
            $ADSI = [ADSI]("WinNT://$RemoteHostNameFQDNPre")
        }
        if ($RemoteHostNameFQDNPost -and $($RemoteHostNameFQDNPost -ne $(Get-WMIObject -Class Win32_ComputerSystem).Domain)) {
            Write-Verbose "$Computer.$RemoteHostNameFQDNPost is NOT part of the same Domain as $env:ComputerName.$($(Get-WMIObject -Class Win32_ComputerSystem).Domain)"
            if (!$UserNameWithAccess) {
                $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                    $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                }
                if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                    $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                }
            }
            if (!$PasswordForUserNameWithAccess) {
                $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
            }
            $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
            
            while (!$CredentialCheck) {
                try {
                    $CredCheckAltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
                    $CredCheckAltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $CredCheckAltFormatUserNameWithAccess, $PasswordForUserNameWithAccess
                    $CredentialCheck = Get-WMIObject -Class "Win32_UserAccount" -Authority "ntlmdomain:$RemoteHostNameFQDNPost" -Credential $CredCheckAltCredentials -ComputerName $RemoteHostNameFQDN
                }
                catch {
                    Write-Warning "Bad credentials"
                }
                if (!$CredentialCheck) {
                    $UserNameWithAccess = Read-Host -Prompt "Please enter a UserName for a Domain Admin account on $RemoteHostNameFQDNPost"
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -eq $null) {
                        $UserNameWithAccess = "$($RemoteHostNameFQDNPost.Split(".")[0])\$UserNameWithAccess"
                    }
                    if ($($UserNameWithAccess | Select-String -Pattern "\\") -ne $null -and $UserNameWithAccess.Split("\\")[0] -ne $($RemoteHostNameFQDNPost.Split(".")[0])) {
                        $UserNameWithAccess = $UserNameWithAccess -replace "$($UserNameWithAccess.Split("\\")[0])","$($RemoteHostNameFQDNPost.Split(".")[0])"
                    }
                    $PasswordForUserNameWithAccess = Read-Host -Prompt "Please enter the password for $UserNameWithAccess" -AsSecureString
                    $Credentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $UserNameWithAccess, $PasswordForUserNameWithAccess
                }
            }

            $ADSI = New-Object -TypeName System.DirectoryServices.DirectoryEntry("WinNT://$($RemoteHostNameFQDNPost.Split(".")[0])/$RemoteHostNameFQDNPre", $($Credentials.UserName), $($Credentials.GetNetworkCredential().password), "Secure")
        }

        $Domain = $RemoteHostNameFQDNPost
        if ($($Domain | Select-String -Pattern "\.").Matches.Success) {
            $DomainPre = $($RemoteHostNameFQDNPost.Split(".")[0])
        }
        else {
            $DomainPre = $RemoteHostNameFQDNPre
        }

        if ($Domain -and $Domain -eq $(Get-WMIObject Win32_ComputerSystem).Domain) {
            if ($DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }
        if ($Domain -and $Domain -ne $(Get-WMIObject Win32_ComputerSystem).Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess

            if ($DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -Authority "ntlmdomain:$Domain" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }
        if (!$Domain) {
            $AltFormatUserNameWithAccess = $UserNameWithAccess.Split("\\")[-1]
            $AltCredentials = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $AltFormatUserNameWithAccess, $PasswordForUserNameWithAccess

            if ($DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$DomainSearch`""
            }
            if (!$DomainSearch) {
                $WMIGroupObject = Get-WMIObject -Class "Win32_Group" -Credential $AltCredentials -NameSpace "root\cimv2" -ComputerName $RemoteHostNameFQDN -filter "Name=`"$NameSearch`" and Domain=`"$RemoteHostNameFQDNPre`""
            }
        }

        # Verify Existence of Group
        try {
            $GroupObject = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "Group $Name NOT found on $Computer!"
        }
        if (!$GroupObject) {
            Write-Warning "Group $Name NOT found on $Computer!"
            
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####
        # These aren't properties, but will be a part of the output PSCustomObject, which is why they're being added
        $GroupAccountPropertiesThatWereChanged.Add("ComputerName","$Computer")
        $GroupAccountPropertiesThatWereChanged.Add("LocalGroup","$Name")

        try {
            $GroupObject.SetInfo()

            if ($Description) {
                $GroupObject.Description = $Description
            }

            $GroupObject.SetInfo()

            $GroupAccountPropertiesThatWereChanged.Add("ChangedDescription","$Description")
        }
        catch {
            if ($RemoteHostNameFQDNPre -ne $env:ComputerName) {
                if ($Error[0].Exception.GetType().fullname -eq "System.Management.Automation.MethodInvocationException") {
                    Write-Warning "Unable to reset password for the User $Name on $RemoteHostNameFQDNPre using ADSI from $env:ComputerName. Trying WinRM via Invoke-Command..."
                    # Try Invoke Command over WinRM
                    Invoke-Command -ComputerName $RemoteHostNameFQDN -Credential $Credentials -ScriptBlock {
                        $ADSIRemote = $using:ADSI
                        $GroupObjectRemote = $using:GroupObject

                        $GroupObjectRemote.SetInfo()

                        if ($using:Description) {
                            $GroupObjectRemote.Description = $using:Description
                        }

                        $GroupObjectRemote.SetInfo()
                    }
                    if (!$?) {
                        $WinRMFailure = $True
                        Write-Warning "WinRM connection to $RemoteHostNameFQDNPre was unsuccessful!"
                    }
                }
            }
            else {
                $OtherFailure = $True
                Write-Warning "Error changing propert(ies) for $Group on $Computer. Moving on..."
                Write-Error $Error[0]
            }
        }
        if ($OtherFailure -or $WinRMFailure) {
            # Cleanup
            foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
                Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
            }
            continue
        }

        New-Variable -Name "LocalGroupPropertiesOn$Computer" -Value $(
            New-Object PSObject -Property $GroupAccountPropertiesThatWereChanged
        ) -Force

        $SetLocalGroupSuccessArray +=, $(Get-Variable -Name "LocalGroupPropertiesOn$Computer" -ValueOnly)

        ##### END Main Body #####

        # Cleanup
        foreach ($VarName in $VariablesToRemoveAtEndOfEachLoop) {
            Remove-Variable -Name $VarName -Force -ErrorAction SilentlyContinue
        }
        continue
    }

    if ($SetLocalGroupSuccessArray.Count -lt 1) {
        Write-Verbose "Unable to change properties for Local Group $Name on any Computers! Halting!"
        Write-Error "Unable to change properties for Local Group $Name on any Computers! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SetLocalGroupSuccessArray.Count -ge 1) {
        $SetLocalGroupSuccessArray
    }

}








# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQnCJ5UCoVqCtIZUv1ee7tPr2
# YOqgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTin1TSNsTM
# g4YNULNkKtwVpc5xYTANBgkqhkiG9w0BAQEFAASCAQB8HoExDFvN+a0UHTj4mma1
# DcySCO3xRf53AeKDPAfXRX6XdtvPyQHImOudMdQO0TdX4jA5p8IBIwsa2BuEehMn
# Turtg/SVs7INBqDB4lVyKt7GGUOZbRfzXog1SD6mZ4/55UP4jiHPqNz9YKrRSg52
# obxt/6eaC1kNdnQ0Lu6NPnOrpz5bz7zcAaPm/btuZU7I+AhycDKdVJSl7sDdafm4
# MVGG1riB1uJwyy7SQbSrG85VQ35ZSTWss23JLbuZssq/+rhCjil+yJtna9Uf+c8p
# lMoZDorU/qciy1ntOFMEdAturEj56oVijhfyShUC7nk31MJNBFS8hHU82/E2FhXB
# SIG # End signature block
