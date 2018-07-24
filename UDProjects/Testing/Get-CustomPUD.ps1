function Get-CustomPUD {
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

    # Create some Pages
    $HomePageContent = New-UDLayout -Columns 3 -Content {
        New-UDCard -Title "Server Reports" -Id "SRCard" -Text "Get Basic Info About Servers" -Links @(
            New-UDLink -Text "Server Reports" -Url "/ServerReports" -Icon book
        )

        New-UDCard -Title "Employee Contacts" -Id "ECCard" -Text "Get Contact Info" -Links @(
            New-UDLink -Text "Employee Contacts" -Url "/ContactInfo" -Icon address_book
        )

        New-UDCard -Title "Metrics" -Id "MCard" -Text "Metrics" -Links @(
            New-UDLink -Text "Metrics" -Url "/Metrics" -Icon bullseye
        )
    }
    $HomePage = New-UDPage -Name "Home" -Icon home -Content {$HomePageContent}

    $ServerReportingPage = New-UDPage -Name "ServerReports" -Icon book -Content {
        New-UDInput -Title "Server Report Form" -Id "Form" -Content {
            $ServerList.Insert(0,"Please Select a Server")
            New-UDInputField -Type 'select' -Name 'Server' -Placeholder 'Select Server For Report' -Values $ServerList
        } -Endpoint {
            param($Server)

            [System.Collections.ArrayList]$SubmitButtonActions = @()

            # Output a Grid with the data from Resolve-DNSName
            $DNSInfoProperties = $([Microsoft.DnsClient.Commands.DnsRecord_A]::new() | Get-Member -Type AliasProperty,Property,NoteProperty).Name
            $ResolveDNSGrid = New-UdGrid -Title "DNSInfo" -Headers $DNSInfoProperties -Properties $DNSInfoProperties -Endpoint {
                Resolve-DNSName $Server | Out-UDGridData
            }
            $SubmitButtonActions.Add($ResolveDNSGrid)

            # Output a Grid with data from Get-Process
            $ProcessInfoProperties = @("Name","Id","UserName","SessionId","StartTime","CPU","PagedMemorySize")
            $GetProcessGrid = New-UdGrid -Title "ProcessInfo" -Headers $ProcessInfoProperties -Properties $ProcessInfoProperties -Endpoint {
                Invoke-Command -ComputerName $Server -ScriptBlock {
                    Get-Process -IncludeUserName | Select-Object -Property $using:ProcessInfoProperties
                } -HideComputerName | Out-UDGridData
            }
            $SubmitButtonActions.Add($GetProcessGrid)

            # Output a Chart Displaying Drive Space Info
            $DiskSpaceChart = New-UdChart -Title "DiskInfo" -Type Bar -Endpoint {
                Get-CimInstance -ComputerName $Server -ClassName Win32_LogicalDisk | foreach {
                    $Size = [Math]::Round($_.Size / 1GB, 2)
                    $FreeSpace = [Math]::Round($_.FreeSpace / 1GB, 2)
                    $UsedSpace = $Size - $FreeSpace

                    [PSCustomObject]@{
                        DeviceId = $_.DeviceID
                        Size = $Size
                        FreeSpace = $FreeSpace
                        UsedSpace = $UsedSpace
                    }
                } | Out-UDChartData -LabelProperty "DeviceID" -Dataset @(
                    New-UdChartDataset -DataProperty "Size" -Label "Size" -BackgroundColor "#80962F23" -HoverBackgroundColor "#80962F23"
                    New-UdChartDataset -DataProperty "FreeSpace" -Label "Free Space" -BackgroundColor "#8014558C" -HoverBackgroundColor "#8014558C"
                    New-UdChartDataset -DataProperty "UsedSpace" -Label "Used Space" -BackgroundColor "#85f29c" -HoverBackgroundColor "#35f45e"
                )             
            }
            $SubmitButtonActions.Add($DiskSpaceChart)

            New-UDInputAction -Content $SubmitButtonActions
        }
    }

    $ContactsPage = New-UDPage -Name "ContactInfo" -Icon home -Content {
        New-UDCard -Title "Employee Contacts" -Id "ECCard" -Text "Get Contact Info"
    }

    $MetricsPage = New-UDPage -Name "Metrics" -Icon home -Content {
        New-UDCard -Title "Metrics" -Id "MCard" -Text "Metrics"
    }
    
    # Finalize the Site
    $MyDashboard = New-UDDashboard -Pages @($HomePage,$ServerReportingPage,$ContactsPage,$MetricsPage)

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUt3O6wzkpKVI4RsfTjytXJbGh
# fM6gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHPMrU4IJ0U1ToZM
# FE9hr2+ctQirMA0GCSqGSIb3DQEBAQUABIIBAGiLaJNNopWux47eJcA7gGPXtTeJ
# Tqk0YKqAWshBECCx5FijboMwsWfQAZ5nFknM9JKsrwgUVSh7t2Dg96JssPYB0vkI
# REf3+M8b3xFHO6+NEHxbatNd9tIF/NvtX2/fvjmpEyBqX9h/6Azt+iJ5l2S3/hrW
# zKTcJrhI30gbEPlHCoIVTfdM7jMJPhNXhE0vB/DJY3V6mNYr7SYnH0UNkZ51L4FG
# hdtn+yG8Br9GYIXMKrtUZIMLVeU/4HSSlv7NZ7k9fLruT4tFtelPwdLeNtOaYtRk
# wovwfateBdTnGY1Dn08VbGJ4ChA4YvLM94MNo2UZxl11ffP3gJUDMVPI9/o=
# SIG # End signature block
