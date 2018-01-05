<#
    .SYNOPSIS
        Get errors and warnings from Hyper-V Operational logs.

    .DESCRIPTION
        This command will search a specified server for all Hyper-V related Windows 
        Operational logs and get all errors that have been recorded in the specified
        number of days. By default, the command will search for errors and warnings 
        that have been recently recorded within the last 30 days. The command also uses
        Get-WSManInstance to resolve the SID to an actual accountname.

    .PARAMETER HypervisorNameOrIP
        This parameter is MANDATORY.

        This parameter takes a string that represents the IP, FQDN, or DNS-Resolvable hostname of the Hyper-V host.

    .PARAMETER NumberOfDays
        This parameter is MANDATORY.

        This parameter takes an integer that specifies the number of past days to include when collecting event logs.

    .PARAMETER HypervisorCreds
        This parameter is OPTIONAL.

        This parameter takes a System.Management.Automation.PSCredential object.

    .PARAMETER LogLevels
        This parameter is OPTIONAL.

        This parameter takes an integer or array of integers from 0 to 5 that represent the different types
        of logs that can be collected. For reference, log levels are as follows:

        Verbose=5, Informational=4, Warning=3, Error=2, Critical=1, LogAlways=0

        The default value for this parameter is 4 (i.e. Informational).

    .EXAMPLE
        Get-HVEventLog -HypervisorNameOrIP hyper216.test2.lab -NumberOfDays 1 -LogLevels 4

    .EXAMPLE
        Get-HVEventLog -HypervisorNameOrIP hyper216.test2.lab -NumberOfDays 1 -LogLevels 4 | Out-Gridview -Title "Events"
        
    .NOTES
        
        Last Update : January 5, 2018
        Version     : 2.0
        Updated By  : Paul DiMaggio
        u/fourierswager (Reddit) / pldmgg (GitHub)


        Previous Update: October 21, 2013
        Version     : 1.0

        Learn more:
            PowerShell in Depth: An Administrator's Guide (http://www.manning.com/jones2/)
            PowerShell Deep Dives (http://manning.com/hicks/)
            Learn PowerShell 3 in a Month of Lunches (http://manning.com/jones3/)
            Learn PowerShell Toolmaking in a Month of Lunches (http://manning.com/jones4/)
            PowerShell and WMI (http://www.manning.com/siddaway2/)
        
        From: https://www.altaro.com/hyper-v/monitoring-hyper-v-operational-and-admin-event-logs/

    .LINK
        Get-WinEvent
        Get-Eventlog
    
    .INPUTS
        [String]
    
    .Outputs
        [System.Diagnostics.Eventing.Reader.EventLogRecord]
    
#>
Function Get-HVEventLog {
    [cmdletbinding()]
    Param(
        [Parameter(
            Mandatory=$True,
            HelpMessage="Enter the IP, FQDN, or DNS-Resolvable HostName of a Hyper-V host"
        )]
        [ValidateNotNullorEmpty()]
        [string]$HypervisorNameOrIP,
        
        [Parameter(
            Mandatory=$True
        )]
        [ValidateScript({$_ -ge 1})]
        [int]$NumberOfDays,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$HypervisorCreds,

        [Parameter(Mandatory=$False)]
        [ValidateSet(0,1,2,3,4,5)]
        [int[]]$LogLevels
    )

    ##### BEGIN Helper Functions #####

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ## BEGIN Native Helper Functions ##
    
        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }
    
        ## END Native Helper Functions ##
        
    
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


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($HypervisorNameOrIP) {
        try {
            $HypervisorNetworkInfo = Resolve-Host -HostNameOrIP $HypervisorNameOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HypervisorNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Test to see if we need to explicitly provide Credentials to get into the Hypervisor host
    try {
        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -ScriptBlock {"Success"} -ErrorAction Stop
        $CredsNeeded = $False
        $HypervisorLocation = $HypervisorNetworkInfo.FQDN
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

                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.FQDN -Credential $Creds -ScriptBlock {"Success"} -ErrorAction Stop
                $CredsNeeded = $True
                $HypervisorLocation = $HypervisorNetworkInfo.FQDN
            }
            catch {
                if ($_ -match "no logon servers") {
                    try {
                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock {"Success"} -ErrorAction Stop
                        $CredsNeeded = $True
                        $HypervisorLocation = $HypervisorNetworkInfo.HostName
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
                $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -ScriptBlock {"Success"} -ErrorAction Stop
                $CredsNeeded = $False
                $HypervisorLocation = $HypervisorNetworkInfo.HostName
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

                        $InvokeCommandOutput = Invoke-Command -ComputerName $HypervisorNetworkInfo.HostName -Credential $Creds -ScriptBlock {"Success"} -ErrorAction Stop
                        $CredsNeeded = $True
                        $HypervisorLocation = $HypervisorNetworkInfo.HostName
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

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    #define a hash table of parameters to splat to Get-WinEvent
    $GetWinEventSplatParams = @{
        ErrorAction     = "Stop"
        ErrorVariable   = "MyErr"
        Computername    = $HypervisorLocation
    }
    if ($CredsNeeded) {
        $GetWinEventSplatParams.Add("Credential",$HypervisorCreds)
    }

    #calculate the cutoff date
    $start = (Get-Date).AddDays(-$NumberOfDays)

    #construct a hash table for the -FilterHashTable parameter in Get-WinEvent
    $filter = @{
        Logname     = "Microsoft-Windows-Hyper-V*"
        Level       = $LogLevels
        StartTime   = $start
    } 

    #add it to the parameter hash table
    $GetWinEventSplatParams.Add("FilterHashTable", $filter)

    #search logs for errors and warnings 
    try {
        $InvokeCommandSB = {
            #add a property for each entry that translates the SID into the account name
            #hash table of parameters for Get-WSManInstance
            $script:NewHash = @{
                ResourceURI     = "wmicimv2/win32_SID"
                SelectorSet     = $null
                Computername    = $using:HypervisorLocation
                ErrorAction     = "Stop"
                ErrorVariable   = "myErr"
            }
            if ($using:CredsNeeded) {
                $script:NewHash.Add("Credential",$using:HypervisorCreds)
            }

            # Using the $this special variable: http://mctexpert.blogspot.com/2015/09/this-psitem-whatever.html
            Get-WinEvent @using:GetWinEventSplatParams | Add-Member -MemberType ScriptProperty -Name Username -Value {
                try {
                    #resolve the SID 
                    $script:NewHash.SelectorSet=@{SID="$($this.userID)"}
                    $Resolved = Get-WSManInstance @using:NewHash
                }
                catch {
                    Write-Verbose $myerr.ErrorRecord
                }

                if ($Resolved.accountname) {
                    #write the resolved name to the pipeline
                    "$($Resolved.ReferencedDomainName)\$($Resolved.Accountname)"
                }
                else {
                    #re-use the SID
                    $this.userID
                }
            } -PassThru
        }

        if ($CredsNeeded) {
            Invoke-Command -ComputerName $HypervisorLocation -Credential $HypervisorCreds -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        }
        else {
            Invoke-Command -ComputerName $HypervisorLocation -ScriptBlock $InvokeCommandSB -ErrorAction Stop
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    ##### END Main Body #####
}




























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5vCtEfZ45jeLTLQo4SUGiq/2
# RsOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMT6GnxkRqVuAycn
# NHaQ7KD0dnj8MA0GCSqGSIb3DQEBAQUABIIBAB+wKAitxmDftWOAKKi1Latji8lA
# 8exmFoS8TymZFq4Jd5UdaTWOantRC20O75PthJ9nnWkBHYp578LbPWYilEWGsnsk
# O1LeaMurVgkdrvebHi3lZMWUnhL5bF8TVL+biTt81BteSP/rckCVJILwPmduuxJq
# A7UR3bKZzsBkVphXr7DqoBmVNTMjNH8qJaUZyEK2qRPf1JFbKfmbwFBKcwe6FLiF
# Pg8p9KhTZ6tQyL021kPA5u1meD/tXoQTEdB2uFbCyxQ/G9jUKDNCz3rCUBlNZl97
# Q5fWDfE6sX0t1GIxcEAXElk7OLmmmp2FPSJ49etjizKQXRb52eYx/6fM78Y=
# SIG # End signature block
