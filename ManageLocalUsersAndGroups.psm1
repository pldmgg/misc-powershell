<#
Segments of the below Get-LocalGroup function are from:
https://mcpmag.com/articles/2015/06/18/reporting-on-local-groups.aspx

Eventhough the cmdlet Get-LocalGroup exists in PowerShell Versions 5.1 and higher, this function (in my 
opinion) goes the extra mile by returning the 5.1 cmdlet info as well as additional useful information
(such as Group Members that are themselves objects that can be further explored)
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
        [string[]]$Group,

        [Parameter(Mandatory=$False)]
        [switch]$IncludeADGroupsAppliedLocally
    )

    Begin {
        $Domain = $(Get-WmiObject Win32_ComputerSystem).Domain
        $DomainPre = $(Get-WmiObject Win32_ComputerSystem).Domain.Split(".")[0]

        Function  ConvertTo-SID {
            Param([byte[]]$BinarySID)

            (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
        }

        Function  Get-LocalGroupMember {
            Param ($GroupObject,$HostName)

            $ADSI = [ADSI]"WinNT://$HostName"

            $GroupMemberObjectArray = @()
            $Members = $GroupObject.Invoke('members') | ForEach {
                $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
            }

            $LocalUserAccounts = @()
            $LocalSystemAccounts = @()
            $LocalGroupAccounts = @()
            $ADUserAccountsAppliedLocally = @()
            $ADGroupAccountsAppliedLocally = @()

            $DomainPre = $(Get-WmiObject Win32_ComputerSystem).Domain.Split(".")[0]

            if ($Members) {
                foreach ($Member in $Members) {
                    # Check to See if $Member is a Local User Account
                    try {
                        $MemberUserObject = $ADSI.Children.Find("$Member", "User")
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
                    $LocalSystemAccountCheck = Get-WmiObject -Class "Win32_SystemAccount" -NameSpace "root\cimv2" | Where-Object {$_.Name -eq "$Member"}
                    if ($LocalSystemAccountCheck) {
                        Write-Verbose "The $($GroupObject.Name) Group Member $Member is a Local System Account applied to the Local Group $($GroupObject.Name)"
                        $LocalSystemAccounts +=, $LocalSystemAccountCheck
                    }

                    # Check to See if $Member is a Local Group
                    try {
                        $MemberGroupObject = $ADSI.Children.Find("$Member", "Group")
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
                        Write-Verbose "The $($GroupObject.Name) Group Member $Member is NOT an AD Group. At this point, this could only mean that it is an AD Group or AD User that previously existed and has since been deleted from Active Directory."
                    }
                    if ($MemberADGroupObject) {
                        Write-Verbose "The $($GroupObject.Name) Group Member $Member is an AD Group"
                        $ADGroupAccountsAppliedLocally +=, $MemberADGroupObject
                        Remove-Variable -Name "MemberADGroupObject"
                        continue
                    }

                    if (!$MemberUserObject -and !$LocalSystemAccountCheck -and !$MemberGroupObject -and !$MemberADUserObject -and !$MemberADGroupObject) {
                        Write-Warning "Unable to find the Account $Member on the Local Host or in AD. It is possible that $Member is an AD Group or AD User that previously existed on the Domain and has since been deleted from Active Directory."
                        continue
                    }
                }
            }

            $GetLocalGroupMemberFunctionOutput = @()
            for ($i=0; $i -lt $LocalUserAccounts.Count; $i++) {
                New-Variable -Name "LocalUserMemberInfo$i" -Value $(
                    New-Object PSObject -Property @{
                        Name                = "$HostName\$($LocalUserAccounts[$i].Name)"
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
                        Name                = "$HostName\$($LocalSystemAccounts[$i].Name)"
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
                        Name                = "$HostName\$($LocalGroupAccounts[$i].Name)"
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
    }
    Process {
        ForEach ($Computer in $ComputerName) {
            Try {
                Write-Verbose  "Connecting to $($Computer)"
                $adsi = [ADSI]"WinNT://$Computer"

                If ($PSBoundParameters.ContainsKey('Group')) {
                    Write-Verbose  "Scanning for groups: $($Group -join ',')"
                    $GroupObjects = ForEach ($Item in $group) {
                        $adsi.Children.Find($Item, "Group")
                    }
                } 
                Else {
                    Write-Verbose "Scanning all Groups"
                    $GroupObjects = $adsi.Children | where {$_.SchemaClassName -eq "Group"}
                }

                If ($GroupObjects) {
                    $GroupObjects | ForEach {
                        [pscustomobject]@{
                            Computername = $Computer
                            Name = $_.Name[0]
                            Members = $(Get-LocalGroupMember -GroupObject $_ -HostName $Computer)
                            SID = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
                            GroupObject = $_
                        }
                    }
                }
                Else {
                    Throw  "No groups found!"
                }
            } Catch  {
                Write-Warning "$($Computer): $_"
            }
        }
    }
}


<#
Eventhough the cmdlet Get-LocalUser exists in PowerShell Versions 5.1 and higher, this function (in my 
opinion) goes the extra mile by returning the 5.1 cmdlet info as well as additional useful information
(such as GroupsThatTheUserBelongsTo as objects that can be further explored)
#>
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
        [string[]]$UserName
    )

    Begin {
        Function  ConvertTo-SID {
            Param([byte[]]$BinarySID)

            (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
        }
    }
    Process {
        ForEach ($Computer in $ComputerName) {
            $ListOfGroupObjects = Get-LocalGroup -ComputerName $Computer
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
            Try {
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
                        [pscustomobject]@{
                            Computername = $Computer
                            Name = $_.Name[0]
                            Enabled = !$_.InvokeGet('AccountDisabled')
                            GroupsThatTheUserBelongsTo = $GroupObjectsThatUserBelongsTo
                            SID = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
                            UserObject = $_
                        }
                    }
                }
                Else {
                    Throw  "No UserName(s) found!"
                }
            } Catch  {
                Write-Warning "$($Computer): $_"
            }
        }
    }
}

if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Add-LocalGroupMember {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Member = $(Read-Host -Prompt "Please enter the name of the User or Group you would like to add to a Local Group"),

            [Parameter(Mandatory=$False)]
            [string]$Group = $(Read-Host -Prompt "Please enter the name of the Local Group you would like to add $Member to")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $Domain = $(Get-WmiObject Win32_ComputerSystem).Domain
        $DomainPre = $(Get-WmiObject Win32_ComputerSystem).Domain.Split(".")[0]

        # Check to see if $Member is a Local or Domain Group
        $LocalAndDomainGroups = Get-WmiObject -Class "Win32_Group" -NameSpace "root\cimv2"
        [array]$LocalAndDomainGroupMatches = $LocalAndDomainGroups | Where-Object {$_.Name -eq "$Member"}

        if ($LocalAndDomainGroupMatches) {
            if ($LocalAndDomainGroupMatches.Count -gt 1) {
                Write-Host "There is a Local Group on $env:ComputerName called $Member as well as a Domain Group called $Member on $Domain"
                $AddLocalOrDomainGroup = Read-Host -Prompt "Would you like to add the Local Group or the Domain Group to the Local Group $Group ? [Local/Domain]"
                while ($AddLocalOrDomainGroup -notmatch "Local|Domain") {
                    Write-Host "`"$AddLocalOrDomainGroup`" is not a valid option. Valid options are either `"Local`" or `"Domain`""
                    $AddLocalOrDomainGroup = Read-Host -Prompt "Would you like to add the Local Group or the Domain Group to the Local Group $Group ? [Local/Domain]"
                }
                if ($AddLocalOrDomainGroup -eq "Local") {
                    $ADSI = [ADSI]("WinNT://$Computer")
                }
                if ($AddLocalOrDomainGroup -eq "Domain") {
                    $ADSI = [ADSI]("WinNT://$DomainPre")
                }
            }
            if ($LocalAndDomainGroupMatches.Count -eq 1) {
                if ($LocalAndDomainGroupMatches.Domain -eq $DomainPre) {
                    $ADSI = [ADSI]("WinNT://$DomainPre")
                }
                else {
                    $ADSI = [ADSI]("WinNT://$Computer")
                }
            }
        }

        # If $ADSI still doesn't exist, then $Member is not a Group, so check to see if it is a Local or Domain User/System Account
        # This could take awhile if the Domain has thousands of users
        if (!$ADSI) {
            # Get All Accounts matching $Member in case $Member is a User Account or a System Account
            $LocalAndDomainUserAccounts = Get-WmiObject -Class "Win32_UserAccount" -NameSpace "root\cimv2"
            $MemberUserAccountObjectCheck = $LocalAndDomainUserAccounts | Where-Object {$_.Name -eq "$Member"}
            $LocalSystemAccounts = Get-WmiObject -Class "Win32_SystemAccount" -NameSpace "root\cimv2"
            $MemberSystemAccountObjectCheck = $LocalSystemAccounts | Where-Object {$_.Name -eq "$Member"}
            $LocalAndDomainAccounts = $LocalAndDomainUserAccounts + $LocalSystemAccounts
            [array]$LocalAndDomainAccountMatches = $LocalAndDomainAccounts | Where-Object {$_.Name -eq "$Member"}

            if ($LocalAndDomainAccountMatches) {
                if ($LocalAndDomainAccountMatches.Count -gt 1) {
                    Write-Host "There is a Local User Account on $env:ComputerName called $Member as well as a Domain User Account called $Member on $Domain"
                    $AddLocalOrDomainAccount = Read-Host -Prompt "Would you like to add the Local User Account or the Domain User Account to the Local Group $Group ? [Local/Domain]"
                    while ($AddLocalOrDomainAccount -notmatch "Local|Domain") {
                        Write-Host "`"$AddLocalOrDomainAccount`" is not a valid option. Valid options are either `"Local`" or `"Domain`""
                        $AddLocalOrDomainAccount = Read-Host -Prompt "Would you like to add the Local User Account or the Domain User Account to the Local Group $Group ? [Local/Domain]"
                    }
                    if ($AddLocalOrDomainAccount -eq "Local") {
                        $ADSI = [ADSI]("WinNT://$Computer")
                    }
                    if ($AddLocalOrDomainAccount -eq "Domain") {
                        $ADSI = [ADSI]("WinNT://$DomainPre")
                    }
                }
                if ($LocalAndDomainAccountMatches.Count -eq 1) {
                    if ($LocalAndDomainAccountMatches.Domain -eq $DomainPre) {
                        $ADSI = [ADSI]("WinNT://$DomainPre")
                    }
                    else {
                        $ADSI = [ADSI]("WinNT://$Computer")
                    }
                }
            }
        }

        # Create ADSI $GroupObject so that we can add $Member to it later
        try {
            $GroupObject = $ADSI.Children.Find($Group, "Group")
        }
        catch {
            Write-Verbose "The Group $Group was NOT found! Halting!"
        }
        if (!$GroupObject) {
            Write-Error "The Group $Group was NOT found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $CurrentGroupMembers = $GroupObject.psbase.invoke("Members") | ForEach {
            $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
        }

        # If $Member is a Normal User Account, Create the $UserObject and get the $DirectoryEntryPath
        if ($MemberUserAccountObjectCheck) {
            try {
                $MemberUserObject = $ADSI.Children.Find($Member, "User")
            }
            catch {
                Write-Verbose "User $Member NOT found on $Computer! Halting!"
            }
            if (!$MemberUserObject) {
                Write-Error "User $Member NOT found on $Computer! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $DirectoryEntryPath = $MemberUserObject.Path
        }
        # If $Member is a System Account, the Find() Method will not help, so create the $DirectoryEntryPath manually
        if ($MemberSystemAccountObjectCheck) {
            $DirectoryEntryPath = "WinNT://NT AUTHORITY/$Member"
        }
        # If $Member is a Group, Create the $MemberGroupObject and get the $DirectoryEntryPath
        if (!$MemberUserAccountObjectCheck -and !$MemberSystemAccountObjectCheck) {
            try {
                $MemberGroupObject = $ADSI.Children.Find($Member, "Group")
            }
            catch {
                Write-Verbose "The Group $Member was NOT found! Halting!"
            }
            if (!$MemberGroupObject) {
                Write-Error "The Group $Member was NOT found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($MemberGroupObject -eq $GroupObject) {
                Write-Verbose "You cannot add the Local Group $Group to itself! Halting!"
                Write-Error "You cannot add the Local Group $Group to itself! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $DirectoryEntryPath = $MemberGroupObject.Path
        }

        # Make sure the Member isn't already part of the Group
        if ($CurrentGroupMembers -contains $Member) {
            Write-Verbose "The User $Member is already a member of the Group $Group! Halting!"
            Write-Error "The User $Member is already a member of the Group $Group! Halting!"
            $global:FunctionResult = "1"
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Add the User to the Group
        $GroupObject.Add(("$DirectoryEntryPath"))

        ##### END Main Body #####

    }
}

if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Remove-LocalGroupMember {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Member = $(Read-Host -Prompt "Please enter the name of the User or Group you would like to remove from a Local Group"),

            [Parameter(Mandatory=$False)]
            [string]$Group = $(Read-Host -Prompt "Please enter the name of the Local Group you would like to remove $Member from")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $Domain = $(Get-WmiObject Win32_ComputerSystem).Domain
        $DomainPre = $(Get-WmiObject Win32_ComputerSystem).Domain.Split(".")[0]

        [array]$MemberToRemove = Get-WmiObject Win32_GroupUser | Where-Object {$_.PartComponent -like "*Name=`"$Member`"*" -and $_.GroupComponent -like "*Name=`"$Group`"*" -and $_.GroupComponenet -like "*Domain=`"$Computer`"*"}
        if ($MemberToRemove.Count -eq 1) {
            $MemberFromDomainBool = $($MemberToRemove.PartComponent | Select-String -Pattern "Domain=`"$DomainPre`"").Matches.Success
        }
        if ($MemberToRemove.Count -gt 1) {
            Write-Host "There are $($MemberToRemove.Count) Members that are part of the Local Group $Group that match the Member Name $Member"
            Write-Host "Choices are as follows:"
            for ($i=0; $i -lt $MemberToRemove.Count; $i++) {
                Write-Host "$($i+1))"$($MemberToRemove[$i].PartComponent | Select-String -Pattern "Domain=\`"(.*?)\`",Name=\`"$Member\`"").Matches.Value
            }
            $Choice = Read-Host -Prompt "Please select option $($(1..$MemberToRemove.Count) -join ", ")"
            $ChoiceIndex = $Choice-1

            $MemberFromDomainBool = $($MemberToRemove[$ChoiceIndex].PartComponent | Select-String -Pattern "Domain=`"$DomainPre`"").Matches.Success
        }

        if ($MemberFromDomainBool) {
            $ADSI = [ADSI]("WinNT://$DomainPre")
        }
        else {
            $ADSI = [ADSI]("WinNT://$Computer")
        }

        # Get the ADSI $GroupObject we are going to remove $Member from so we can use it laser
        try {
            $GroupObject = $ADSI.Children.Find($Group, "Group")
        }
        catch {
            Write-Verbose "The Group $Group was NOT found! Halting!"
        }
        if (!$GroupObject) {
            Write-Error "The Group $Group was NOT found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $CurrentGroupMembers = $GroupObject.psbase.invoke("Members") | ForEach {
            $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
        }

        # If $Member is a Normal User Account, Create the $UserObject and get the $DirectoryEntryPath
        try {
            $MemberUserObject = $ADSI.Children.Find($Member, "User")
        }
        catch {
            Write-Verbose "User $Member NOT found on $Computer! Halting!"
        }
        if ($MemberUserObject) {
            $DirectoryEntryPath = $MemberUserObject.Path
        }
        # If $Member is a Group, Create the $MemberGroupObject and get the $DirectoryEntryPath
        try {
            $MemberGroupObject = $ADSI.Children.Find($Member, "Group")
        }
        catch {
            Write-Verbose "The Group $Member was NOT found! Halting!"
        }
        if ($MemberGroupObject) {
            $DirectoryEntryPath = $MemberGroupObject.Path
        }
        # If $Member is a System Account, the Find() Method will not help, so create the $DirectoryEntryPath manually
        if (!$MemberUserObject -and !$MemberGroupObject) {
            $DirectoryEntryPath = "WinNT://NT AUTHORITY/$Member"
        }

        # Make sure the User is part of the Group
        if ($CurrentGroupMembers -notcontains $Member) {
            Write-Verbose "The User $Member is NOT a member of the Group $Group! Halting!"
            Write-Error "The User $Member is NOT a member of the Group $Group! Halting!"
            $global:FunctionResult = "1"
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Remove the Local User from the Local Group
        $GroupObject.Remove(("$DirectoryEntryPath"))

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function New-LocalGroup {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the new group you would like to create on $env:COMPUTERNAME."),

            [Parameter(Mandatory=$False)]
            [string]$Description = $(Read-Host -Prompt "Please enter a description for the the group $Name")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Make sure a Group with the Name $Name doesn't already exist
        try {
            $GroupObjectTest = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "A Local Group with the name $Name does NOT already exist. Continuing..."
        }
        if ($GroupObjectTest) {
            Write-Verbose "A Group with the name $Name already exists on the Local Host! Halting!"
            Write-Error "A Group with the name $Name already exists on the Local Host! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Prep the GroupObject
        $GroupObject = $ADSI.Create("Group", $Name)
        # Actually Create the New Group
        $GroupObject.SetInfo()

        $GroupObject.Description  = $Description
        $GroupObject.SetInfo()

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Remove-LocalGroup {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the group you would like to delete from $env:COMPUTERNAME")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Make sure the Local Group we want to Delete exists
        try {
            $GroupObject = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "The Group $Name was NOT found! Halting!"
        }
        if (!$GroupObject) {
            Write-Error "The Group $Name was NOT found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Remove the Group
        $ADSI.Children.Remove($GroupObject)

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function New-LocalUser {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the new user account would like to create on $env:COMPUTERNAME."),

            [Parameter(Mandatory=$False)]
            [System.Security.SecureString]$Password = $(Read-Host -Prompt "Please enter a new password for the new user account $Name." -AsSecureString),

            [Parameter(Mandatory=$False)]
            [string]$Description,

            [Parameter(Mandatory=$False)]
            [switch]$ChangePasswordOnFirstLogon
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        $PasswordComplexityRegex = @'
^((?=.*[a-z])(?=.*[A-Z])(?=.*\d)|(?=.*[a-z])(?=.*[A-Z])(?=.*[^A-Za-z0-9])|(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])|(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]))([A-Za-z\d@#$%^&£*\-_+=[\]{}|\\:',?/`~"();!]|\.(?!@)){8,16}$
'@
        $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
        $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        
        # Below -cmatch comparison operator is for case-sensitive matching
        while (!$($PTPwd -cmatch $PasswordComplexityRegex)) {
            Write-Warning "The password provided does not meet minimum password complexity requirements."
            Write-Host "Passwords must be 8-16 characters, and meet three out of four of the following conditions:"
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

        # Wipe all traces of the Password from Memory
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        Remove-Variable Password,BSTR,PTPwd

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Remove-LocalUser {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the new user account would like to create on $env:COMPUTERNAME.")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer! Halting!"
        }
        if (!$UserObject) {
            Write-Error "User $Name NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $UserDirectoryEntryPath = $UserObject.Path

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Delete the User
        $ADSI.Delete("User", $Name)

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Disable-LocalUser {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the user account you would like disable on $env:COMPUTERNAME.")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer! Halting!"
        }
        if (!$UserObject) {
            Write-Error "User $Name NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $UserDirectoryEntryPath = $UserObject.Path

        # Check to see if the user account is already disabled
        $Disabled = 0x0002
        if ([boolean]$($UserObject.UserFlags.value -BAND $Disabled)) {
            Write-Verbose "Account $Name is already disabled! Halting!"
            Write-Error "Account $Name is already disabled! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Disable the User Account
        $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BOR $Disabled
        $UserObject.SetInfo()

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Enable-LocalUser {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the name of the user account you would like enable on $env:COMPUTERNAME.")
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer! Halting!"
        }
        if (!$UserObject) {
            Write-Error "User $Name NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $UserDirectoryEntryPath = $UserObject.Path

        # Check to see if the user account is already enabled.
        $Disabled = 0x0002
        if (-not [boolean]$($UserObject.UserFlags.value -BAND $Disabled)) {
            Write-Verbose "Account $Name is already enabled! Halting!"
            Write-Error "Account $Name is already enabled! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Enable the User Account
        $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -BXOR $Disabled
        $UserObject.SetInfo()

        ##### END Main Body #####

    }
}


# For PowerShell Version 5.1 and higher, use: Set-LocalUser -Password <SecureString>
if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Reset-LocalUserPassword {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$UserName = $(Read-Host -Prompt "Please enter the UserName of the account that you would like reset the password for on $env:COMPUTERNAME."),

            [Parameter(Mandatory=$False)]
            [System.Security.SecureString]$Password = $(Read-Host -Prompt "Please enter the new password for the user account $UserName." -AsSecureString),

            [Parameter(Mandatory=$False)]
            [switch]$ChangePasswordOnFirstLogon,

            [Parameter(Mandatory=$False)]
            [switch]$PasswordNeverExpires
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($UserName, "User")
        }
        catch {
            Write-Verbose "User $UserName NOT found on $Computer! Halting!"
        }
        if (!$UserObject) {
            Write-Error "User $UserName NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
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
            $Password = Read-Host -Prompt "Please enter a new password for the new user account $Name." -AsSecureString
            $BSTR = [System.Runtime.Interopservices.Marshal]::SecureStringToBSTR($Password)
            $PTPwd = [System.Runtime.Interopservices.Marshal]::PtrToStringAuto($BSTR)
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        # Change User Password
        $UserObject.SetPassword(($PTPwd))
        if ($ChangePasswordOnFirstLogon) {
            $UserObject.PasswordExpired = 1
        }
        if ($PasswordNeverExpires) {
            $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -bor 0x10000
        }

        # Wipe all traces of the Password from Memory
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        Remove-Variable Password,BSTR,PTPwd

        ##### END Main Body #####

    }
}


if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Set-LocalUser {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$Name = $(Read-Host -Prompt "Please enter the UserName of the account that you would like change properties for on $env:COMPUTERNAME."),

            [Parameter(Mandatory=$False)]
            [System.Security.SecureString]$Password,

            [Parameter(Mandatory=$False)]
            [switch]$ChangePasswordOnFirstLogon,

            [Parameter(Mandatory=$False)]
            [switch]$PasswordNeverExpires,

            [Parameter(Mandatory=$False)]
            [System.DateTime]$AccountExpiresDateTime,

            [Parameter(Mandatory=$False)]
            [switch]$AccountNeverExpires,

            [Parameter(Mandatory=$False)]
            [string]$Description
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        if ($AccountExpiresDateTime -and $AccountNeverExpires) {
            Write-Verbose "Please use *either* the parameter `$AccountExpiresDateTime *or* the parameter `$AccountNeverExpires! Halting!"
            Write-Error "Please use *either* the parameter `$AccountExpiresDateTime *or* the parameter `$AccountNeverExpires! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Verify Existence of User
        try {
            $UserObject = $ADSI.Children.Find($Name, "User")
        }
        catch {
            Write-Verbose "User $Name NOT found on $Computer! Halting!"
        }
        if (!$UserObject) {
            Write-Error "User $Name NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

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
            if ($ChangePasswordOnFirstLogon) {
                $UserObject.PasswordExpired = 1
            }
            if ($PasswordNeverExpires) {
                $UserObject.UserFlags.Value = $UserObject.UserFlags.Value -bor 0x10000
            }
        }

        if ($AccountExpiresDateTime) {
            $UserObject.Put("AccountExpirationDate", $AccountExpiresDateTime)
        }
        if ($AccountNeverExpires) {
            $UserObject.Put("AccountExpirationDate", [System.DateTime]::MaxValue)
        }

        $UserObject.SetInfo()

        if ($Description) {
            $UserObject.Description = $Description
        }

        $UserObject.SetInfo()        

        if ($Password) {
            # Wipe all traces of the Password from Memory
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            Remove-Variable Password,BSTR,PTPwd
        }

        ##### END Main Body #####

    }
}

if ($PSVersionTable.PSVersion -lt [version]"5.1") {
    function Set-LocalGroup {
        [CmdletBinding()]
        Param(
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

        $Computer = $env:COMPUTERNAME
        $ADSI = [ADSI]("WinNT://$Computer")

        # Verify Existence of Group
        try {
            $GroupObject = $ADSI.Children.Find($Name, "Group")
        }
        catch {
            Write-Verbose "Group $Name NOT found on $Computer! Halting!"
        }
        if (!$GroupObject) {
            Write-Error "Group $Name NOT found on $Computer! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

        $GroupObject.SetInfo()

        if ($Description) {
            $GroupObject.Description = $Description
        }

        $GroupObject.SetInfo()

        ##### END Main Body #####

    }
}










# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURdbPRq66lKiIqd29kivqBJWX
# h2mgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTLJL5UG1oo
# 3xuDGFOM+/KWYrfUdDANBgkqhkiG9w0BAQEFAASCAQA7mXJOgbfbQp/CJ940/Lkb
# 2ccg+ivjQPCGugOQedSb4PH2Znje75bEjdE9su2TVJ9hRiYNdHtcmOSEP0SWxfFj
# VVzaj/a48aVRY+Jz0E0mY0/sGkq1U3AhZNp3e2fAwWRd9/cAr9mtZ1295LoxVRc8
# CwwFoREUAzyWIJnwbN1imB/97SWAyYLdzATKiJc1QAk/qModPNlawC7CWbxuWwjs
# SNHK9HnY79v28evAhxFCac3yoxoQwD1OAT56zpWa0GuWFOPnqeMqFMLSCAb6Yl6V
# yuFcw2cmf5ZRxy4NOWv1tn2WvcWnMNGlte+X5FgipSwQLRxeH2P4C0hbKasHm3jt
# SIG # End signature block
