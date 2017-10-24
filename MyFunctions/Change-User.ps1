function Change-User {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$UserName = $(Read-Host -Prompt "Please enter the UserName you would like to switch to."),

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$Password = $(Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString),

        [Parameter(Mandatory=$False)]
        $WorkingDirectory = $(Get-Location).Path,

        [Parameter(Mandatory=$False)]
        [string]$PathToProfile,

        [Parameter(Mandatory=$False)]
        [string[]]$ForwardCurrentSessionVars, # Must be an array of strings of variable names (without $).

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ## BEGIN Native Helper Functions ##

    function Write-WelcomeMessage {
        [CmdletBinding(PositionalBinding=$True)]
        Param(
            [Parameter(Mandatory=$True)]
            [System.Management.Automation.Runspaces.PSSession]$PSSession
        )

        $SetupScriptBlock = @"
            function Check-Elevation {
                if (`$PSVersionTable.PSEdition -eq "Desktop" -or `$PSVersionTable.Platform -eq "Win32NT" -or `$PSVersionTable.PSVersion.Major -le 5) {
                    [System.Security.Principal.WindowsPrincipal]`$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                        [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    )
            
                    [System.Security.Principal.WindowsBuiltInRole]`$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
            
                    if(`$currentPrincipal.IsInRole(`$administratorsRole)) {
                        return `$true
                    }
                    else {
                        return `$false
                    }
                }
                
                if (`$PSVersionTable.Platform -eq "Unix") {
                    if (`$(whoami) -eq "root") {
                        return `$true
                    }
                    else {
                        return `$false
                    }
                }
            }

            if (Check-Elevation) {
                `$PowerShellUserAccount = "ELEVATED `$(whoami)"
            }
            else {
                `$PowerShellUserAccount = `$(whoami)
            }

            Write-Host "``n``nYou are `$PowerShellUserAccount``n"
"@

        [System.Collections.ArrayList]$ScriptBlockPrepArrayOfLines = $SetupScriptBlock -split "`n"

        $ScriptBlockFinalString = $ScriptBlockPrepArrayOfLines | Out-String
        New-Variable -Name "ScriptBlock$($PSSession.Name)" -Scope Local -Value $([scriptblock]::Create($ScriptBlockFinalString))

        $InvokeCommandString = 'Invoke-Command -Session $PSSession -ScriptBlock $(Get-Variable -Name "ScriptBlock$($PSSession.Name)" -ValueOnly)'
        Invoke-Expression $InvokeCommandString
    }

    function Initialize-PSProfileInRemoteSession {
        [CmdletBinding(PositionalBinding=$True)]
        Param(
            [Parameter(Mandatory=$True)]
            [System.Management.Automation.Runspaces.PSSession]$PSSession,

            [Parameter(Mandatory=$True)]
            [string]$ProfileToLoadOnRemoteHost = $(Read-Host -Prompt "Please enter the full file path to the profile.ps1 on the Local Host that you would like to load in the Remote PSSession on the Remote Host.") # Must be a full file path to an existing file on the Remote Host
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        if (! $(Test-Path $ProfileToLoadOnRemoteHost)) {
            Write-Verbose "The path $ProfileToLoadOnRemoteHost was not found! Halting!"
            Write-Error "The path $ProfileToLoadOnRemoteHost was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ProfileToLoadOnRemoteHost = $(Resolve-Path -Path $ProfileToLoadOnRemoteHost).Path
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

        $SetupScriptBlock = ". $ProfileToLoadOnRemoteHost"

        [System.Collections.ArrayList]$ScriptBlockPrepArrayOfLines = $SetupScriptBlock -split "`n"

        $ScriptBlockFinalString = $ScriptBlockPrepArrayOfLines | Out-String
        New-Variable -Name "ScriptBlock$($PSSession.Name)" -Scope Local -Value $([scriptblock]::Create($ScriptBlockFinalString))

        $InvokeCommandString = 'Invoke-Command -Session $PSSession -ScriptBlock $(Get-Variable -Name "ScriptBlock$($PSSession.Name)" -ValueOnly)'
        Invoke-Expression $InvokeCommandString

        ##### END Main Body #####
    }

    function Send-LocalObjects {
        [CmdletBinding(PositionalBinding=$True)]
        Param(
            [Parameter(Mandatory=$True)]
            [System.Management.Automation.Runspaces.PSSession]$PSSession,

            [Parameter(Mandatory=$False)]
            [string[]]$LocalVarsToForward, # Must be an array of strings of variable names (without $). If null, then only the default $AlwaysForwardVars will be forwarded

            [Parameter(Mandatory=$False)]
            [switch]$Silent
        )

        # Begin Initial Setup #
        
        $LocalHostName = $env:COMPUTERNAME

        $SetupScriptBlock = @"
    [CmdletBinding(PositionalBinding=`$True)]
    Param(
        [Parameter(Mandatory=`$False)]
        `$LocalHostName = "$LocalHostName"
    )
"@

        [System.Collections.ArrayList]$ScriptBlockPrepArrayOfLines = $SetupScriptBlock -split "`n"

        # End Initial Setup #

        # Define Variables that should ALWAYS be forwarded to Remote Host
        $LocalHostUserNameFullAcct = whoami
        $LocalHostUserName = $LocalHostUserNameFullAcct.Split("\") | Select-Object -Index 1
        $LocalHostComputerName = $env:COMPUTERNAME
        $LocalHostPowerShellSessionInfo = Get-Process -PID $pid
        $LocalHostUserSession = Get-UserSession -ComputerName $env:COMPUTERNAME
        if (!$?) {
            Write-Verbose "The function Get-UserSession failed. Determining user session info by alternate means."

        }

        $AlwaysForwardVars = @(
            "LocalHostUserNameFullAcct",
            "LocalHostUserName",
            "LocalHostComputerName",
            "LocalHostPowerShellSessionInfo",
            "LocalHostUserSession"
        )
        $LocalVarsToForward = $AlwaysForwardVars+$LocalVarsToForward
        $LocalVarsToForward = $LocalVarsToForward | ? {$_}
        
        $EnvironmentVariables = @()
        $NonEnvironmentVariables = @()
        foreach ($PotentialVar in $LocalVarsToForward) {
            if ($(Get-Variable | Where-Object {$_.Name -eq "$PotentialVar"}).Value) {
                Write-Verbose "$PotentialVar is NOT an environment variable"
                $NonEnvironmentVariables += $PotentialVar
            }
            if ($(Get-ChildItem Env: | Where-Object {$_.Name -eq "$PotentialVar"}).Value) {
                Write-Verbose "$PotentialVar IS an environment variable"
                $EnvironmentVariables += $PotentialVar
            }
            if (!$($(Get-Variable | Where-Object {$_.Name -eq "$PotentialVar"}).Value) -and !$($(Get-ChildItem Env: | Where-Object {$_.Name -eq "$PotentialVar"}).Value)) {
                Write-Warning "The variable $PotentialVar was not found. Skipping..."
            }
        }

        if ($EnvironmentVariables.Count -gt 0) {
            if (!$Silent) {
                Write-Warning "The specified Environment Variables from the Local Host will be forwarded to the Remote Host $($PSSession.ComputerName), but they will NOT be set as Environment Variables on the Remote Host. Instead, you will be able to call them by simply using `$VariableName (as opposed to `$env:VariableName) while in the Remote Session."
            }
        }

        # Extend the scriptblock-string by adding params that match LocalVarsToForward so that they are available on the Remote Host
        foreach ($AdditionalParam in $NonEnvironmentVariables) {
            New-Variable -Name "ScriptBlock$AdditionalParam" -Value @"
        [Parameter(Mandatory=`$False)]
        `$$AdditionalParam
    )
"@
            $ScriptBlockPrepArrayOfLines = Add-ParamToScriptBlockString -ArrayOfLinesInput $ScriptBlockPrepArrayOfLines -ScriptBlockAsString $(Get-Variable -Name "ScriptBlock$AdditionalParam" -ValueOnly)
        }
        foreach ($AdditionalParam in $EnvironmentVariables) {
            New-Variable -Name "ScriptBlock$AdditionalParam" -Value @"
        [Parameter(Mandatory=`$False)]
        `$$AdditionalParam
    )
"@
            $ScriptBlockPrepArrayOfLines = Add-ParamToScriptBlockString -ArrayOfLinesInput $ScriptBlockPrepArrayOfLines -ScriptBlockAsString $(Get-Variable -Name "ScriptBlock$AdditionalParam" -ValueOnly)
        }

        $ParamBlockFinalString = $ScriptBlockPrepArrayOfLines | Out-String
        New-Variable -Name "ParamScriptBlock$($PSSession.Name)" -Scope Local -Value $([scriptblock]::Create($ParamBlockFinalString))

        $InvokeCommandString = 'Invoke-Command -Session $PSSession -ScriptBlock $(Get-Variable -Name "ParamScriptBlock$($PSSession.Name)" -ValueOnly) -ArgumentList $LocalHostName'
        foreach ($AdditionalParam in $NonEnvironmentVariables) {
            $InvokeCommandString = "$InvokeCommandString"+","+"`$(Get-Variable -Name `"$AdditionalParam`" -ValueOnly)"
        }
        foreach ($AdditionalParam in $EnvironmentVariables) {
            $InvokeCommandString = "$InvokeCommandString"+","+"`$(Get-ChildItem Env: | Where-Object {`$_.Name -eq `"$AdditionalParam`"}).Value"
        }

        # Inject the LocalVars into the $PSSession with Remote Host, i.e. make them available in the $PSSession when using: Enter-PSsession -Session $PSSession
        Invoke-Expression $InvokeCommandString
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($PathToProfile) {
        if (! $(Test-Path $PathToProfile)) {
            Write-Verbose "The path $PathToProfile was not found! Halting!"
            Write-Error "The path $PathToProfile was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $PotentialUserNameFormatOne = $UserName | Select-String -Pattern "\\"
    $PotentialUserNameFormatTwo = $UserName | Select-String -Pattern "@"

    if ($PotentialUserNameFormatOne) {
        $UserNamePrefix = $PotentialUserNameFormatOne.Split("\")[0]
        $UserName = $PotentialUserNameFormatOne.Split("\")[-1]
    }
    if ($PotentialUserNameFormatTwo) {
        $UserNamePrefixPrep = $PotentialUserNameFormatTwo.Split("@")[-1]
        $UserNamePrefix = $UserNamePrefixPrep.Split(".")[0]
        $UserName = $PotentialUserNameFormatTwo.Split("@")[0]
    }

    $JoinedToDomain = $(Get-WmiObject Win32_ComputerSystem).PartOfDomain

    if ($JoinedToDomain) {
        $FQDNPost = $(Get-WmiObject Win32_ComputerSystem).Domain
        $DomainPre = $FQDNPost.Split(".")[0]
        $HostFQDN = "$env:COMPUTERNAME"+"."+"$FQDNPost"
        $MatchingUserAccounts = Get-WMIObject -Class "Win32_UserAccount" -ComputerName $env:ComputerName,$FQDNPost -Filter "Name='$UserName'" | Where-Object {$_.PSComputerName -eq $env:ComputerName}
    }
    if (!$JoinedToDomain) {
        $MatchingUserAccounts = Get-WMIObject -Class "Win32_UserAccount" -ComputerName $env:ComputerName -Filter "Name='$UserName'" | Where-Object {$_.PSComputerName -eq $env:ComputerName}
    }

    if ($MatchingUserAccounts.Count -gt 1 -and !$PotentialUserNameFormatOne -and !$PotentialUserNameFormatTwo) {
        Write-Host "The UserName $UserName matches accounts on the Local Host $env:COMPUTERNAME and the Domain $FQDNPost"
        $AccountChoice = Read-Host -Prompt "Would you like to switch to the LOCAL account $UserName or the DOMAIN account $DomainPre\$UserName [Local\Domain]"
        if ($AccountChoice -notmatch "Local|Domain") {
            Write-Host "$AccountChoice is not a valid option. Please enter either `"Local`" or `"Domain`""
            $AccountChoice = Read-Host -Prompt "Would you like to switch to the LOCAL account $UserName or the DOMAIN account $DomainPre\$UserName [Local\Domain]"
            if ($AccountChoice -notmatch "Local|Domain") {
                Write-Verbose "The AccountChoice $AccountChoice is not valid! Halting!"
                Write-Error "The AccountChoice $AccountChoice is not valid! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($AccountChoice -eq "Local") {
            $FinalUserName = $($MatchingUserAccounts | Where-Object {$_.Domain -eq $env:COMPUTERNAME}).Caption
        }
        if ($AccountChoice -eq "Domain") {
            $FinalUserName = $($MatchingUserAccounts | Where-Object {$_.Domain -eq $DomainPre}).Caption
        }
    }
    if ($MatchingUserAccounts.Count -gt 1 -and $($PotentialUserNameFormatOne -or $PotentialUserNameFormatTwo)) {
        $FinalUserName = $($MatchingUserAccounts | Where-Object {$_.Domain -eq $DomainPre}).Caption
    }
    if ($MatchingUserAccounts.Count -eq 1) {
        $FinalUserName = $MatchingUserAccounts.Caption
    }
    if ($MatchingUserAccounts.Count -lt 1) {
        Write-Verbose "The UserName $UserName was NOT found! Halting!"
        Write-Error "The UserName $UserName was NOT found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $UserNamePrefix = $($FinalUserName -split "\\")[0]
    $UserName = $($FinalUserName -split "\\")[-1]

    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $FinalUserName, $Password

    # Make sure WinRM Service is Running and Configured to Allow Local Host
    $NeededTrustedHostStrings = @()
    $LocalHostIPv4AddressesPrep = Get-WMIObject Win32_NetworkAdapterConfiguration | foreach {
        if ($_.IPAddress -ne $null) {
            $_.IPAddress
        }
    }
    $LocalHostIPv4Addresses = $LocalHostIPv4AddressesPrep | foreach {
        try {
            [ipaddress]$_ | Where-Object {$_.AddressFamily -notlike "*v6"}
        }
        catch {
            Write-Verbose "$($_) is NOT an IP Address"
        }
    } | foreach {$_.IPAddressToString}
    foreach ($IPAddr in $LocalHostIPv4Addresses) {
        $NeededTrustedHostStrings += $IPAddr
    }
    $NeededTrustedHostStrings += $env:ComputerName
    if ($JoinedToDomain) {
        $NeededTrustedHostStrings += $HostFQDN
    }

    try {
        $WinRMStatusCheck = Test-WSMan
    }
    catch {
        Write-Verbose "WinRM is NOT running."
    }
    if (!$WinRMStatusCheck) {
        Set-WSManQuickConfig -Force
        $TrustedHostsString = $NeededTrustedHostStrings -join ", "
        Set-Item -Path "WSMAN:\localhost\Client\TrustedHosts" -Value $TrustedHostsString -Force
    }
    if ($WinRMStatusCheck) {
        $TrustedHostsToAdd = @()
        $CurrentTrustedHostsArray = $(Get-ChildItem "WSMan:\localhost\Client\TrustedHosts").Value -split ", "
        foreach ($TrustedHost in $NeededTrustedHostStrings) {
            if ($CurrentTrustedHostsArray -notcontains $TrustedHost) {
                $TrustedHostsToAdd += $TrustedHost
            }
        }
        $FullUpdatedTrustedHostList = $($CurrentTrustedHostsArray+$TrustedHostsToAdd) -join ", "
        Set-Item -Path "WSMAN:\localhost\Client\TrustedHosts" -Value $FullUpdatedTrustedHostList -Force
    }

    # Make sure the user you are changing to is in the appropriate Security Group Locally and in AD
    if ($JoinedToDomain) {
        Write-Host "1"
        $ComputerNameArgs = "$env:ComputerName,$FQDNPost"
        $AddUserToGroupScriptBlock = {
            if ($FinalGroupObj.Domain -eq $DomainPre) {
                $script:ADSI = [ADSI]"WinNT://$DomainPre"
            }
            if ($FinalGroupObj.Domain -eq $env:ComputerName) {
                $script:ADSI = [ADSI]"WinNT://$DomainPre/$env:ComputerName"
            }
            $script:GroupObject = $script:ADSI.Children.Find($FinalGroupObj.Name, "Group")
            if ($UserNamePrefix -eq $DomainPre) {
                $script:UserDirectoryEntryPath = "WinNT://$DomainPre/$UserName"
            }
            if ($UserNamePrefix -eq $env:Computername) {
                $script:UserDirectoryEntryPath = "WinNT://$DomainPre/$env:ComputerName/$UserName"
            }
            $script:GroupObject.Add(("$script:UserDirectoryEntryPath"))
        }
    }
    if (!$JoinedToDomain) {
        $ComputerNameArgs = "$env:ComputerName"
        $AddUserToGroupScriptBlock = {
            $script:ADSI = [ADSI]"WinNT://$env:ComputerName"
            $script:GroupObject = $script:ADSI.Children.Find($FinalGroupObj.Name, "Group")
            $script:UserDirectoryEntryPath = "WinNT://$env:ComputerName/$UserName"
            $script:GroupObject.Add(("$script:UserDirectoryEntryPath"))
        }
    }

    $SecurityGroupsScriptBlockString = @"
        Get-WMIObject -Class "Win32_Group" -ComputerName $ComputerNameArgs | `
        Where-Object {
            `$_.Name -match "Remote Management Users|WinRMRemoteWMIUsers_" -and 
            `$_.Domain -match "`$env:ComputerName|`$DomainPre" -and
            `$_.PSComputerName -eq "`$env:ComputerName"
        }
"@
    $SecurityGroupsScriptBlock = [scriptblock]::Create($SecurityGroupsScriptBlockString)
    $SecurityGroupsThatUserNameShouldBePartOf = Invoke-Command $SecurityGroupsScriptBlock

    # Check if $UserName is a Member
    foreach ($SecurityGroupObject in $SecurityGroupsThatUserNameShouldBePartOf) {
        if ($SecurityGroupObject.Domain -ne $env:ComputerName) {
            if ($UsernamePrefix -eq $DomainPre) {
                $DomainADSICheck = [ADSI]"WinNT://$DomainPre"
                $DomainGroupObjectCheck = $DomainADSICheck.Children.Find($SecurityGroup.Name, "Group")
                $CurrentGroupMembers = $DomainGroupObjectCheck.psbase.invoke("Members") | ForEach {
                    $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
                }
                # CurrentGroupMembers can only possibly contain Domain Accounts
            }
        }
        if ($SecurityGroupObject.Domain -eq $env:ComputerName) {
            if ($UsernamePrefix -eq $DomainPre) {
                $LocalADSICheck = [ADSI]"WinNT://$env:ComputerName"
                $LocalGroupObjectCheck = $LocalADSICheck.Children.Find($SecurityGroup.Name, "Group")
                $CurrentGroupMembers = $DomainGroupObjectCheck.psbase.invoke("Members") | ForEach {
                    $_.GetType().InvokeMember("Name","GetProperty",$Null,$_,$Null)
                }
                # CurrentGroupMembers could contain Local Accounts OR Domain Accounts
                if ($CurrentGroupMembers -notcontains $UserName) {
                    $UserDirectoryEntryPath = "WinNT://$DomainPre/$UserName"
                    $LocalGroupObjectCheck.Add(("$UserDirectoryEntryPath"))
                }
                if ($CurrentGroupMembers -contains $UserName) {
                    # Need to determine if the Member of the Local Group is a Local or Domain account
                }
            }
        }
    }
    $SecurityGroupsUserNameCheckScriptBlockString = @"
        foreach (`$SecurityGroupObject in `$SecurityGroupsThatUserNameShouldBePartOf) {
            `$query="GroupComponent = ``"Win32_Group.Domain='" + `$UserNamePrefix + "',Name='" + `$SecurityGroupObject.Name + "'``""
            `$IsUserNameAMember = Get-WMIObject -Class "Win32_GroupUser" -ComputerName $ComputerNameArgs | Where-Object {
                `$_.GroupComponent -like "*Domain=``"`$UserNamePrefix``",Name=``"`$(`$SecurityGroupObject.Name)``"*" -and
                `$_.PartComponent -like "*Domain=``"`$UserNamePrefix``",Name=``"`$UserName``"*"}
            if (!`$IsUserNameAMember) {
                `$SecurityGroupObject
            }
            Remove-Variable -Name "IsUserNameAMember"
        }
"@
    $SecurityGroupsUserNameCheckScriptBlock = [scriptblock]::Create($SecurityGroupsUserNameCheckScriptBlockString)
    $GroupsThatNeedUserName = Invoke-Command $SecurityGroupsUserNameCheckScriptBlock

    # Add the User to the Security Groups if it's not Already A Member
    Write-Host "Writing GroupsThatNeedUserName"
    $GroupsThatNeedUserName
    $GroupsThatNeedUserName.Count
    foreach ($FinalGroupObj in $GroupsThatNeedUserName) {
        Write-Host "2"
        Invoke-Command $AddUserToGroupScriptBlock
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    # Create New PSSession
    New-Variable -Name "$UserName`SwitchUserSession" -Value $(
        New-PSSession -ComputerName $env:ComputerName -Credential $Creds -Name "$UserName`SwitchUserSession"
    )
    Write-WelcomeMessage -PSSession $(Get-Variable -Name "$UserName`SwitchUserSession" -ValueOnly)
    if ($PathToProfile) {
        Initialize-PSProfileInRemoteSession -PSSession $(Get-Variable -Name "$UserName`SwitchUserSession" -ValueOnly) -ProfileToLoadOnRemoteHost $PathToProfile
    }
    if ($ForwardCurrentSessionVars) {
        if ($Silent) {
            Send-LocalObjects -PSSession $(Get-Variable -Name "$UserName`SwitchUserSession" -ValueOnly) -LocalVarsToForward $ForwardCurrentSessionVars -Silent
        }
        if (!$Silent) {
            Send-LocalObjects -PSSession $(Get-Variable -Name "$UserName`SwitchUserSession" -ValueOnly) -LocalVarsToForward $ForwardCurrentSessionVars
        }
    }

    ##### END Main Body #####
}










# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4pozHE72T5BlHIzPeuV+aE1/
# mUOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFL4n8tJKtbCKfgdH
# UgUIMBsPEZgrMA0GCSqGSIb3DQEBAQUABIIBAEKLhrzUJ/Qu03EsLBQyklILQ+ge
# d5GoJEX4gQOSiK6FQTZlIetvXEuBj4CLaliY3+CquOakBWvXqeMGtlp39TmwvgiY
# EJeNB+goYoyz6R62gKm4hHb89CSltMdl8v9IxJJUrD8o5nZOkjo20p2DkXo1kzUF
# wm4YvRBDJ01/iOsQCM6zZqfmARcB3BAxDV1oH/Gr4PDjtMD1Z3XiKhlUEcgCw5gB
# nmJ8jxWQs5EWFGQNZg5wjQcvVGSahC+vAVPeDegaraJuNmJM1HN6wfqVm95tafT4
# /Q1sGGDevPIrvumvMEhCur0WmDYvkU+SCpPqoAQC8c/Z8zEKGPTRlovYvKw=
# SIG # End signature block
