function Get-UserSessionViaCim {
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$CompName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserName = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1]),
 
        [Parameter(Mandatory=$False)]
        $Password,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$False)]
        [switch]$UseSSL
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($UserName -and $Password -and $Credential) {
        Write-Verbose "Please use EITHER the Credential parameter OR the UserName and Password parameters! Halting!"
        Write-Error "Please use EITHER the Credential parameter OR the UserName and Password parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserName) {
        $UserNameFormatOne = $RemoteHostUser | Select-String -Pattern "\\"
        $UserNameFormatTwo = $RemoteHostUser | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $UserName = $UserName.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $UserName = $UserName.Split("@")[0]
        }
    }

    if ($Password) {
        if ($Password.GetType().FullName -eq "System.String") {
            $Password = ConvertTo-SecureString $Passwd -AsPlainText -Force
        }
    }

    $LogonTypeTranslated = @{
        "0" = "Local System"
        "2" = "Local Console Logon" #(Interactive)
        "3" = "Network (PSRemoting or RDP)" # (MSDN says 3 explicitly does NOT cover RDP, but testing proves otherwise)
        "4" = "Scheduled Task" # (Batch)
        "5" = "Service Account" # (Service)
        "7" = "ScreenSaver Unlock" #(Unlock)
        "8" = "Cleartext Network Logon" # (NetworkCleartext)
        "9" = "RunAs Using Alt Creds" #(NewCredentials)
        "10" = "RDP\TS\RemoteAssistance" #(RemoteInteractive)
        "11" = "Local Console w/Cached Creds" #(CachedInteractive)
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Native Helper Functions #####

    Function Get-LHSCimSession {
        <#
        .SYNOPSIS
            Create CIMSessions to retrieve WMI data.

        .DESCRIPTION
            The Get-CimInstance cmdlet in PowerShell V3 can be used to retrieve WMI information
            from a remote computer using the WSMAN protocol instead of the legacy WMI service
            that uses DCOM and RPC. However, the remote computers must be running PowerShell
            3 and WSMAN protocol version 3. When querying a remote computer,
            Get-CIMInstance setups a temporary CIMSession. However, if the remote computer is
            running PowerShell 2.0 this will fail. You have to manually create a CIMSession
            with a CIMSessionOption to use the DCOM protocol. This Script does it for you
            and creates a CimSession depending on the remote Computer capabilities.

        .PARAMETER ComputerName
            The computer name(s) to connect to. 
            Default to local Computer

        .PARAMETER Credential
            [Optional] alternate Credential to connect to remote computer.

        .EXAMPLE
            $CimSession = Get-LHSCimSession -ComputerName PC1
            $BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession
            Remove-CimSession -CimSession $CimSession    

        .EXAMPLE
            $cred = Get-Credential Domain01\User02 
            $CimSession = Get-LHSCimSession -ComputerName PC1 -Credential $cred
            $Volume = Get-CimInstance -ClassName Win32_Volume -Filter "Name = 'C:\\'" -CimSession $CimSession
            Remove-CimSession -CimSession $CimSession 

        .INPUTS
            System.String, you can pipe ComputerNames to this Function

        .OUTPUTS
            An array of Microsoft.Management.Infrastructure.CimSession objects

        .NOTES
            to get rid of CimSession because of testing use the following to remove all CimSessions
            Get-CimSession | Remove-CimSession -whatif

            Most of the CIM Cmdlets do not have a -Credential parameter. The only way to specify 
            alternate credentials is to manually build a new CIM session object, and pass that 
            into the -CimSession parameter on the other cmdlets.

            AUTHOR: Pasquale Lantella 
            LASTEDIT: 
            KEYWORDS: CIMSession

        .LINK
            The Lonely Administrator: Get CIMInstance from PowerShell 2.0 
            http://jdhitsolutions.com/blog/2013/04/get-ciminstance-from-powershell-2-0/

        #Requires -Version 3.0
        #>
        [cmdletbinding()]
        [OutputType('Microsoft.Management.Infrastructure.CimSession')]
        Param(
            [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,
                HelpMessage='An array of computer names. The default is the local computer.')]
            [alias("CN")]
            [string[]]$ComputerName = $Env:COMPUTERNAME,

            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$Creds,

            [Parameter(Mandatory=$False)]
            [switch]$UseSSL
        )

        BEGIN {
            Set-StrictMode -Version Latest
            ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name

            # Test if Local Host is running WSMan 3 or higher
            Function Test-IsWsman3 {
            # Test if WSMan is greater or eqaul Version 3.0
            # Tested against Powershell 4.0
                [cmdletbinding()]
                Param(
                    [Parameter(Position=0,ValueFromPipeline)]
                    [string]$LocalComputerName=$env:computername
                )

                Begin {
                    #a regular expression pattern to match the ending
                    [regex]$rx="\d\.\d$"
                }
                Process {
                    $result = $Null
                    Try {
                        $result = Test-WSMan -ComputerName $LocalComputerName -ErrorAction Stop
                    }
                    Catch {
                        # Write-Error $_
                        $False
                    }
                    if ($result) {
                        $m = $rx.match($result.productversion).value
                        if ($m -ge '3.0') {
                            $True
                        }
                        else {
                            $False
                        }
                    }
                } #process
                End {}
            } #end Test-IsWSMan
        } # end BEGIN

        PROCESS {
            Write-Verbose "${CmdletName}: Starting Process Block"
            Write-Debug ("PROCESS:`n{0}" -f ($PSBoundParameters | Out-String))
            
            $CimSessionObjectArray = @()
            ForEach ($Computer in $ComputerName)
            {
                # Test if Remote Host has WSMan available 
                IF (Test-WSMan -ComputerName $Computer) {
                    $SessionParams = @{
                          ComputerName = $Computer
                          ErrorAction = 'Stop'
                    }
                    if ($PSBoundParameters['Creds'])
                    {
                        Write-Verbose "Adding alternate credential for CIMSession"
                        $SessionParams.Add("Credential",$Creds)
                    }

                    If (Test-IsWsman3 -LocalComputerName $Computer)
                    {
                        $option = New-CimSessionOption -Protocol WSMan 
                        $SessionParams.SessionOption = $Option
                    }
                    Else
                    {
                        $option = New-CimSessionOption -Protocol DCOM
                        $SessionParams.SessionOption = $Option
                    }

                    try {
                        $CimSession = New-CimSession @SessionParams
                    }
                    catch {
                        if ($PSBoundParameters['Creds']) {
                            Write-Warning "Failed to establish CimSession with $Computer! Please check your Credentials."
                        }
                        if (!$($PSBoundParameters['Creds'])) {
                            Write-Warning @"
Failed to establish CimSession with $Computer! If $Computer is NOT on the same domain as $env:ComputerName
(i.e.  $($(Get-WMIObject Win32_ComputerSystem).Domain)), please use the -Credential parameter.
"@
                        }

                        # Move on to the next Computer in foreach loop
                        continue
                    }
                    
                    New-Variable -Name "$Computer`CimSession" -Value $(
                        [pscustomobject][ordered]@{
                            ComputerName   = $Computer
                            CimSession   = $CimSession
                            CimSessionObjName = "$Computer`CimSession"
                        }
                    ) -Force

                    $CimSessionObjectArray +=, $(Get-Variable -Name "$Computer`CimSession" -ValueOnly)
                }
                Else {
                    Write-Warning "WSMan (i.e. WinRM service) not available on $Computer...Continuing..."
                } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)  
            } # end ForEach ($Computer in $ComputerName)

            if ($CimSessionObjectArray.Count -lt 1) {
                Write-Verbose "Unable to create CimSessions for any of the ComputerNames provided! Halting!"
                Write-Error "Unable to create CimSessions for any of the ComputerNames provided! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($CimSessionObjectArray.Count -ge 1) {
                foreach ($CimSesObj in $CimSessionObjectArray) {
                    Write-Verbose "Created CimSession for $($CimSesObj.ComputerName)"
                }
            }

            $CimSessionObjectArray
        } # end PROCESS

        END { Write-Verbose "Function ${CmdletName} finished." }

    } # end Function Get-LHSCimSession
    
    ##### END Native Helper Functions #####

    ##### BEGIN Main Body #####

    # NOTE: $defaultDisplaySet, $defaultDisplayPropertySet, and $PSStandardMembers below will be used towards
    # the end of the below foreeach ($Comp in $CompName) loop...
    # Configure a default display set for CustomObject TypeName Logon.Info
    $defaultDisplaySet = "LogonId","SessionId","SessionName","UpdatedName","Status","IdleTime","LogonTypeTranslated","UpdatedStartTime","AuthenticationPackage","RelevantWSManInfo","UpdatedDomain"
    # Create the default property display set
    #$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
    Update-TypeData -TypeName Logon.Info -DefaultDisplayPropertySet $defaultDisplaySet -ErrorAction SilentlyContinue
    #$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

    $UserSessionInfoObjArray = @()
    foreach ($Comp in $CompName) {
        $RemoteHostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $Comp)) {
            try {
                $RemoteHostIP = $(Resolve-DNSName $Comp).IPAddress
            }
            catch {
                Write-Verbose "Unable to resolve $Comp!"
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
                $RemoteHostUserName = "$UserName@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostIP) {
                Write-Error "Unable to resolve $Comp! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Comp) {
            try {
                $RemoteHostIP = $CompName[0]
                $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostName).Name
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
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
                $RemoteHostUserName = "$UserName@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostNameFQDN) {
                Write-Error "Unable to resolve $Comp! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($UserName -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
        $($CompName -ne $env:COMPUTERNAME -and $CompName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
        $CompName.Count -gt 1) {
            if ($Credential) {
                $FinalCreds = $Credential
            }
            else {
                if (!$Password) {
                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
                }
                # If $CompName[0] is on a different Domain, change $UserName to $RemoteHostUserName
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                    $UserName = $RemoteHostUserName
                }
                $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
            }
        }

        if ($UserName -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
        $($CompName -ne $env:COMPUTERNAME -and $CompName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
        $CompName.Count -gt 1) {
            try {
                $CimSessionObj = Get-LHSCimSession -ComputerName $Comp -Creds $FinalCreds
                
                if (!$CimSessionObj) {
                    throw
                }
            }
            catch {
                Write-Warning "The credentials used for $Comp did not work. Skipping $Comp"
                continue
            }
        }
        else {
            $CimSessionObj = Get-LHSCimSession -ComputerName $Comp
        }

        New-Variable -Name "$Comp`LoggedOnUserCimInfo" -Value $(Get-CimInstance -ClassName Win32_LoggedOnUser -CimSession $CimSessionObj.CimSession) -Force
        New-Variable -Name "$Comp`LogOnSessionCimInfo" -Value $(Get-CimInstance -ClassName Win32_LogOnSession -CimSession $CimSessionObj.CimSession) -Force
        New-Variable -Name "$Comp`LogonsReconciled" -Value $(
            $(Get-Variable -Name "$Comp`LogOnSessionCimInfo" -ValueOnly) | foreach {
                if ($($(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly).Dependent.LogonId) -contains $_.LogonId) {
                    $_
                }
            }
        ) -Force

        # Convert $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly) to a PSCustomObject in order
        # to change the default Properties/NoteProperties that are displayed without losing the rest of
        # the Properties under the hood (which is what would happen with Select-Object). For more info:
        # https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
        New-Variable -Name "$Comp`FinalLogons" -Value $(New-Object -TypeName System.Collections.ArrayList)
        for ($li=0; $li -lt $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly).Count; $li++) {
            $LTT = $LogonTypeTranslated[$($($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonType.ToString())]
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "LogonTypeTranslated" -Value $LTT
            
            $UpdatedName = foreach ($obj2 in $(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly)) {
                if ($obj2.Dependent.LogonId -eq $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonId) {
                    $obj2.Antecedent.Name
                }
            }
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value $UpdatedName

            $UpdatedDomain = foreach ($obj3 in $(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly)) {
                if ($obj3.Dependent.LogonId -eq $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonId) {
                    $obj3.Antecedent.Domain
                }
            }
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedDomain" -Value $UpdatedDomain

            [System.DateTimeOffset]$UpdatedStartTimePrep = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).StartTime
            $UpdatedStartTime = $UpdatedStartTimePrep.UtcDateTime
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedStartTime" -Value $UpdatedStartTime

            # SessionID for a Particular Account
            <#
            $SessionIdPrep = $(Get-Process -IncludeUserName | Where-Object {$_.UserName -like "*$UpdatedName"}) | Group-Object -Property SessionId | Sort-Object -Property Count -Descending
            if ($SessionIdPrep -ne $null) {
                $SessionId = $SessionIdPrep[0].Name
            }
            else {
                $SessionId = ""
            }
            #>
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "SessionId" -Value ""

            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "SessionName" -Value ""
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "IdleTime" -Value ""
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "RelevantWSManInfo" -Value ""

            $ArrayOfProperties = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Get-Member | Where-Object {$_.MemberType -match "Property|NoteProperty"}).Name
            $CustomObjectHashTable = @{}
            for ($pi=0; $pi -lt $ArrayOfProperties.Count; $pi++) {
                $Key = $ArrayOfProperties[$pi]
                $Value = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).$($ArrayOfProperties[$pi])
                $CustomObjectHashTable.Add($Key,$Value)
            }
            New-Variable -Name "$Comp`CustomLogonObj$li" -Value $(
                New-Object PSObject -Property $CustomObjectHashTable
            )
            # Change the TypeName to Logon.Info
            $(Get-Variable -Name "$Comp`CustomLogonObj$li" -ValueOnly).PSObject.TypeNames.Insert(0,'Logon.Info')
            # $(Get-Variable -Name "$Comp`LogonsCustom" -ValueOnly) | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            
            # Finally, add it to $Comp`FinalLogons object array
            $(Get-Variable -Name "$Comp`FinalLogons" -ValueOnly).Add($(Get-Variable -Name "$Comp`CustomLogonObj$li" -ValueOnly)) | Out-Null
        }

        New-Variable -Name "$Comp`LogonSessions" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                ComputerName   = $Comp
                LogonSessions   = $(Get-Variable -Name "$Comp`FinalLogons" -ValueOnly)
            }
        ) -Force

        $UserSessionInfoObjArray +=, $(Get-Variable -Name "$Comp`LogonSessions" -ValueOnly)

        Remove-CimSession -CimSession $CimSessionObj.CimSession
    }

    Write-Warning "Results may contain stale entries (i.e. accounts may have since logged off or otherwise disconnected) unless `"Status`" explicitly has a value"
    $UserSessionInfoObjArray

    ##### END Main Body #####

}
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnbLgxlB7q4fYZCkhl2CzpKiq
# uimgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTM7reyOIGe
# rkbqb54Cgmq38KEAUDANBgkqhkiG9w0BAQEFAASCAQAdjlTnNJIYzlNIe4yMq2Zm
# q9CmDAetKx1FpqeEq4umNQhsw8SNKgBLU7ka20hr49Qy/x6FzDLC7EajLrfABEUh
# P/n+zQZo1mxdOU49yVIgBApT5EilmTOHiat+ffSOU69J0OR/mmUpBIxWuTOcoihX
# e9+T+muPS2O/sd0nQxhJTyqBQvQqaV6azEt8tLKcZdzwIGDY05CpSI1QJfQfe080
# YrzCCsErJvyKbzfF3qBb8Q5/SRAEK16Hjh+E5txFb5mog9mGpIF+K8fGgMtHJndl
# geeH6Nn9PL61rIPzrp8SQixo38sYw6Szd39jOvIKKZrbhAi2SzQgRLyZ61Oi2p/9
# SIG # End signature block
