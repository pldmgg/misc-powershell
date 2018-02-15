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
    [CmdletBinding(DefaultParameterSetName = 'Days')]
    Param(
        [Parameter(
            Mandatory = $True,
            HelpMessage = "Enter the IP, FQDN, or DNS-Resolvable HostName of a Hyper-V host"
        )]
        [ValidateNotNullorEmpty()]
        [string]$HypervisorNameOrIP,
        
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Days'
        )]
        [ValidateScript({$_ -ge 1})]
        [int]$NumberOfDays,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'Hours'
        )]
        [ValidateScript({$_ -ge 1})]
        [int]$NumberOfHours,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'Minutes'
        )]
        [ValidateScript({$_ -ge 1})]
        [int]$NumberOfMinutes,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'Seconds'
        )]
        [ValidateScript({$_ -ge 1})]
        [int]$NumberOfSeconds,
        
        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$HypervisorCreds,

        [Parameter(Mandatory=$False)]
        [ValidateSet(0,1,2,3,4,5)]
        [int[]]$LogLevels = 4
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$NumberOfDays -and !$NumberOfHours -and !$NumberOfMinutes -and !$NumberOfSeconds) {
        $TimeSpanErr = "You must use one of the following parameters to specify how far back in time " +
        "you would like to collect Hyper-V logs:`n-NumberofDays`n-NumberOfHours`n-NumberOfMinutes`n-NumberOfSeconds"
        Write-Error $TimeSpanErr
    }

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

    if ($HypervisorCreds) {
        $GetWorkingCredsSplatParams = @{
            RemoteHostNameOrIP          = $HypervisorNetworkInfo.FQDN
            AltCredentials              = $HypervisorCreds
            ErrorAction                 = "Stop"
        }
    }
    else {
        $GetWorkingCredsSplatParams = @{
            RemoteHostNameOrIP          = $HypervisorNetworkInfo.FQDN
            ErrorAction                 = "Stop"
        }
    }

    try {
        $GetHypervisorCredsInfo = Get-WorkingCredentials @GetWorkingCredsSplatParams
        if (!$GetHypervisorCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {throw "Can't determine working credentials for $($HypervisorNetworkInfo.FQDN)!"}
        
        if ($GetHypervisorCredsInfo.CurrentLoggedInUserCredsWorked -eq $True) {
            $HypervisorCreds = $null
        }

        $HypervisorLocation = $GetHypervisorCredsInfo.RemoteHostWorkingLocation
    }
    catch {
        Write-Error $_
        if ($PSBoundParameters['HypervisorCreds']) {
            Write-Error "The Get-WorkingCredentials function failed! Check the credentials provided to the -HypervisorCreds parameter! Halting!"
        }
        else {
            Write-Error "The Get-WorkingCredentials function failed! Try using the -HypervisorCreds parameter! Halting!"
        }
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    #define a hash table of parameters to splat to Get-WinEvent
    $GetWinEventSplatParams = @{
        ErrorAction     = "Stop"
        ErrorVariable   = "MyErr"
        Computername    = $HypervisorNetworkInfo.HostName
    }
    if ($HypervisorCreds) {
        $GetWinEventSplatParams.Add("Credential",$HypervisorCreds)
    }

    #calculate the cutoff date
    if ($NumberOfDays) {
        $start = $(Get-Date).AddDays(-$NumberOfDays)
    }
    elseif ($NumberOfHours) {
        $start = $(Get-Date).AddHours(-$NumberOfHours)
    }
    elseif ($NumberOfMinutes) {
        $start = $(Get-Date).AddMinutes(-$NumberOfMinutes)
    }
    elseif ($NumberOfSeconds) {
        $start = $(Get-Date).AddSeconds(-$NumberOfSeconds)
    }

    #construct a hash table for the -FilterHashTable parameter in Get-WinEvent
    $filter = @{
        Logname     = "Microsoft-Windows-Hyper-V*"
        Level       = $LogLevels
        StartTime   = $start
    } 

    #add it to the parameter hash table
    $GetWinEventSplatParams.Add("FilterHashTable", $filter)

    #add a property for each entry that translates the SID into the account name
    #hash table of parameters for Get-WSManInstance
    $GetWSManInstanceSplatParams = @{
        ResourceURI     = "wmicimv2/win32_SID"
        SelectorSet     = $null
        Computername    = $HypervisorNetworkInfo.HostName
        ErrorAction     = "Stop"
        ErrorVariable   = "myErr"
    }
    if ($HypervisorCreds) {
        $GetWSManInstanceSplatParams.Add("Credential",$HypervisorCreds)
    }

    #search logs for errors and warnings 
    try {
        $InvokeCommandSB = {
            $GWESplatParams = $args[0]
            $GWSMANSplatParams = $args[1]
            # IMPORTANT NOTE: The -FilterHashTable "Level" key ONLY accepts System.Object[] arrays.
            # It specifically does NOT accept System.Collections.ArrayList or [int[]] or [string[]]
            # Eventhough we may pass $GWESplatParams.FilterHashTable.Level to the script block as
            # an [array], at some point, it is converted to System.Collections.ArrayList automatically,
            # so we have to reset the object type specifically here
            $GWESplatParams.FilterHashTable.Level = [array]$args[2]
            
            # Using the $this special variable: http://mctexpert.blogspot.com/2015/09/this-psitem-whatever.html
            Get-WinEvent @GWESplatParams | Add-Member -MemberType ScriptProperty -Name Username -Value {
                try {
                    #resolve the SID 
                    $GWSMANSplatParams.SelectorSet=@{SID="$($this.userID)"}
                    $Resolved = Get-WSManInstance @GWSMANSplatParams
                }
                catch {
                    Write-Verbose $myerr.ErrorRecord
                }

                if ($Resolved.Accountname) {
                    #write the resolved name to the pipeline
                    "$($Resolved.ReferencedDomainName)\$($Resolved.Accountname)"
                }
                else {
                    #re-use the SID
                    $this.userID
                }
            } -PassThru
        }

        if ($HypervisorCreds) {
            $InvCmdSplatParams = @{
                ComputerName        = $HypervisorLocation
                Credential          = $HypervisorCreds
                ScriptBlock         = $InvokeCommandSB
                ErrorAction         = "Stop"
            }
        }
        else {
            $InvCmdSplatParams = @{
                ComputerName        = $HypervisorLocation
                ScriptBlock         = $InvokeCommandSB
                ErrorAction         = "Stop"
            }
        }
        
        try {
            Invoke-Command @InvCmdSplatParams -ArgumentList $GetWinEventSplatParams,$GetWSManInstanceSplatParams,$LogLevels 
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUptB6Gk7Y1lMNbOF20oAm2+nK
# wkagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKxeEXW4OFM2hhMW
# t0EUcAGjP5IJMA0GCSqGSIb3DQEBAQUABIIBAC2AXA9MFtMOEEKngPXUiQEspUWE
# CALoAIDH62/nRed68DMN3Kt2o+seUbesW+mTyiKM07H9gl34SRQkcbpuV+ExAU23
# zb+MihJr//oJAqddB2YD2eNGxLsR+kxULnFfJK/qhXA7M4ZQLQmUlZc9iW6NfnBq
# AlYdebyk+jqgvSiGHER/RdeJF2+dp3h4KAS6eBIO3WtB2mvIvDqQ0wk2dhxznyBx
# oKzzQC16FY9TDk79Pk9R69z4wN+PP15RDG05O3MDCe4W/ZQ4TihUwDKw8CRnR0kF
# NM2+zTrNohcBezmR9ngbwS01MMa/CwRASyKrs7AdQ5e4SgdhRplABNuIFFU=
# SIG # End signature block
