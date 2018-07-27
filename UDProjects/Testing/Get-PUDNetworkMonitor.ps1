function Get-PUDNetworkMonitor {
    Param (
        [Parameter(Mandatory=$True)]
        [string]$DomainName,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True
    )

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Make sure we can resolve the $DomainName
    try {
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Get all Computers in Active Directory without the ActiveDirectory Module
    $LDAPRootEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DomainName")
    $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPRootEntry)
    $LDAPSearcher.Filter = "(objectClass=computer)"
    $LDAPSearcher.SizeLimit = 0
    $LDAPSearcher.PageSize = 250
    $null = $LDAPSearcher.PropertiesToLoad.Add("name")
    [System.Collections.ArrayList]$ServerList = $($LDAPSearcher.FindAll().Properties.GetEnumerator()).name
    $null = $ServerList.Insert(0,"Please Select a Server")


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
        for ($i=1; $i -lt $ServerList.Count; $i++) {
            New-UDInputField -Type 'radioButtons' -Name "Server$i" -Values $ServerList[$i]
        }
    }
    [System.Collections.ArrayList]$paramStringPrep = @()
    for ($i=1; $i -lt $ServerList.Count; $i++) {
        $StringToAdd = '$' + "Server$i"
        $null = $paramStringPrep.Add($StringToAdd)
    }
    $paramString = 'param(' + $($paramStringPrep -join ', ') + ')'
    $NMEndPointSBAsStringPrep = @(
        $paramString
        '[System.Collections.ArrayList]$SubmitButtonActions = @()'
        ''
        '    foreach ($kvpair in $PSBoundParameters.GetEnumerator()) {'
        '        if ($kvpair.Value -ne $null) {'
        '            $AddNewRow = New-UDRow -Columns {'
        '                New-UDColumn -Size 6 {'
        '                    # Create New Grid'
        '                    [System.Collections.ArrayList]$LastFivePings = @()'
        '                    $PingResultProperties = @("Status","IPAddress","RoundtripTime","DateTime")'
        '                    $PingGrid = New-UdGrid -Title $kvpair.Value -Headers $PingResultProperties -AutoRefresh -Properties $PingResultProperties -Endpoint {'
        '                        try {'
        '                            $ResultPrep =  [System.Net.NetworkInformation.Ping]::new().Send('
        '                                $($kvpair.Value),1000'
        '                            )| Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId'
        '                            $GridData = [PSCustomObject]@{'
        '                                 IPAddress       = $ResultPrep.Address.IPAddressToString'
        '                                 Status          = $ResultPrep.Status.ToString()'
        '                                 RoundtripTime   = $ResultPrep.RoundtripTime'
        '                                 DateTime        = Get-Date -Format MM-dd-yy_hh:mm:sstt'
        '                            }'
        '                        }'
        '                        catch {'
        '                            $GridData = [PSCustomObject]@{'
        '                                IPAddress       = "Unknown"'
        '                                Status          = "Unknown"'
        '                                RoundtripTime   = "Unknown"'
        '                                DateTime        = Get-Date -Format MM-dd-yy_hh:mm:sstt'
        '                            }'
        '                        }'
        '                        if ($LastFivePings.Count -eq 5) {'
        '                            $LastFivePings.RemoveAt($LastFivePings.Count-1)'
        '                        }'
        '                        $LastFivePings.Insert(0,$GridData)'
        '                        $LastFivePings | Out-UDGridData'
        '                    }'
        '                    $PingGrid'
        '                    #$null = $SubmitButtonActions.Add($PingGrid)'
        '                }'
        ''
        '                New-UDColumn -Size 6 {'
        '                    # Create New Monitor'
        '                    $PingMonitor = New-UdMonitor -Title $kvpair.Value -Type Line -DataPointHistory 20 -RefreshInterval 5 -ChartBackgroundColor "#80FF6B63" -ChartBorderColor "#FFFF6B63"  -Endpoint {'
        '                        try {'
        '                            [bool]$([System.Net.NetworkInformation.Ping]::new().Send($($kvpair.Value),1000)) | Out-UDMonitorData'
        '                        }'
        '                        catch {'
        '                            $False | Out-UDMonitorData'
        '                        }'
        '                    }'
        '                    $PingMonitor'
        '                    #$null = $SubmitButtonActions.Add($PingMonitor)'
        '                }'
        '            }'
        '            $null = $SubmitButtonActions.Add($AddNewRow)'
        '        }'
        '    }'
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
    Start-UDDashboard -Dashboard $MyDashboard
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUw7syvTRdmPDhpAQg94f1AIwa
# /Qygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLdOQ2wUCbZKvGco
# 9IwiQJ/+LrJrMA0GCSqGSIb3DQEBAQUABIIBABtOOhbcvpacTSiyJ1hQSDKh68/Z
# YXot2FKUb53SaFcUb1o0r6BpE3bRpybQe8Dt2PpamMpjoRw+kwm3DgRyXfDTnVy1
# BOo6Bp24Ak4yub4QICa6aNw5CsvWUfzifTDl23q+eGosqbF/ess6fnsIZrOnFbMQ
# OWQ0/EjEsHIcIMitPjXFvHcI47qmTG9ysllwsK2F0oIqtpSPLXOjm+Enu7nauz2K
# Xvc3V2oDn79nQfGVhjSvwfKPNmRwa+mo+DgsXNcxYrbpx51M0h/8afLsULx4cWmf
# ukVuzTvwB/Js7geJXOChyo7P7fbLXfrdfk26vh1PGxnPNYr8Ua7s8aGglz0=
# SIG # End signature block
