<#
.SYNOPSIS
    Get all information about interfaces on your local machine

.DESCRIPTION
    See .SYNOPSIS

.PARAMETER InterfaceStatus
    This parameter is OPTIONAL.
    
    This parameter takes a string that has a value of either "Up" or "Down".

.PARAMETER AddressFamily
    This parameter is OPTIONAL.

    This parameter takes a string that has a value of either "IPv4" or "IPv6"

.EXAMPLE
    # On Windows
    PS C:\Users\testadmin> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"

.EXAMPLE
    # On Linux
    PS /home/pdadmin/Downloads> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"
#>
function Get-NetworkInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateSet("Up","Down")]
        [string]$InterfaceStatus,

        [Parameter(Mandatory=$False)]
        [ValidateSet("IPv4","IPv6")]
        [string]$AddressFamily
    )

    ##### BEGIN Native Helper Functions #####

    function Update-PSCustomObject {
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$True)]
            $ip,

            [Parameter(Mandatory=$True)]
            $ipprops,

            [Parameter(Mandatory=$True)]
            $ippropsPropertyNames,

            [Parameter(Mandatory=$True)]
            $ipUnicastPropertyNames
        )

        $FinalPSObjectPrep = [pscustomobject]@{}

        foreach ($ippropsPropName in $ippropsPropertyNames) {
            $FinalPSObjectMemberCheck = $($FinalPSObjectPrep | Get-Member -MemberType NoteProperty).Name
            if ($FinalPSObjectMemberCheck -notcontains $ippropsPropName -and
            $ippropsPropName -ne "UnicastAddresses" -and $ippropsPropName -ne "MulticastAddresses") {
                $FinalPSObjectPrep | Add-Member -MemberType NoteProperty -Name $ippropsPropName -Value $($ipprops.$ippropsPropName)
            }
        }
        
        foreach ($UnicastPropName in $ipUnicastPropertyNames) {
            $FinalPSObjectMemberCheck = $($FinalPSObjectPrep | Get-Member -MemberType NoteProperty).Name
            if ($FinalPSObjectMemberCheck -notcontains $UnicastPropName) {
                $FinalPSObjectPrep | Add-Member -MemberType NoteProperty -Name $UnicastPropName -Value $($ip.$UnicastPropName)
            }
        }

        $FinalPSObjectPrep
    }

    ##### END Native Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($AddressFamily) {
        if ($AddressFamily -eq "IPv4") {
            $AddrFam = "InterNetwork"
        }
        if ($AddressFamily -eq "IPv6") {
            $AddrFam = "InterNetworkV6"
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    [System.Collections.Arraylist]$PSObjectCollection = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    foreach ($adapter in $interfaces) {
        $ipprops = $adapter.GetIPProperties()
        $ippropsPropertyNames = $($ipprops | Get-Member -MemberType Property).Name

        if ($AddressFamily) {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq $AddrFam}
        }
        else {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses
        }

        foreach ($ip in $UnicastAddressesToExplore) {
            $ipUnicastPropertyNames = $($ip | Get-Member -MemberType Property).Name

            $Params = @{
                ip                      = $ip
                ipprops                 = $ipprops
                ippropsPropertyNames    = $ippropsPropertyNames
                ipUnicastPropertyNames  = $ipUnicastPropertyNames
            }

            if (!$InterfaceStatus -and !$AddressFamily) {
                $FinalPSObject = Update-PSCustomObject @Params
            }

            if ($InterfaceStatus -and $AddressFamily) {
                if ($adapter.OperationalStatus -eq $InterfaceStatus -and $ip.Address.AddressFamily -eq $AddrFam) {
                    $FinalPSObject = Update-PSCustomObject @Params
                }
            }

            if ($InterfaceStatus -and !$AddressFamily) {
                if ($adapter.OperationalStatus -eq $InterfaceStatus) {
                    $FinalPSObject = Update-PSCustomObject @Params
                }
            }

            if (!$InterfaceStatus -and $AddressFamily) {
                if ($ip.Address.AddressFamily -eq $AddrFam) {
                    $FinalPSObject = Update-PSCustomObject @Params
                }
            }
        }

        if ($UnicastAddressesToExplore.Count -ne 0 -and $FinalPSObject) {
            $adapterPropertyNames = $($adapter | Get-Member -MemberType Property).Name
            foreach ($adapterPropName in $adapterPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $adapterPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $adapterPropName -Value $($adapter.$adapterPropName)
                }
            }
        
            $null = $PSObjectCollection.Add($FinalPSObject)
        }
    }

    $PSObjectCollection

    ##### END Main Body #####
        
}






















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaS3ek4IIJfb34BkuwKeejcWS
# LA+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCBkDzmSveNr9uFa
# Z7t5MhIFgA/7MA0GCSqGSIb3DQEBAQUABIIBADrfh/hKU4hw3VLs/eg1+rJDIkHv
# h5vuV8Y4HF2W3wQzyrvmwLXye64GAn+lZ9cnXkQYqzM/o6F+J6/3gV+fb6r1c92s
# t6pqeO3DfuVGyyaCxDOvzO/nav84WWedmM7WGnhW9VzS6jJKWI91YyQILiOkjHsS
# kpf0LrdCFY9Cl1gfSIbPPJqhn68+7GudT9b9e5vXQLHl3xERfd2K3XXEODzqpdRQ
# DL/Q35Ts/nUtLo988t1OOIyReMYhseu3aBVduZQpVxHdw5oHpz/JvJqRKtk2VlKU
# 8yVG9fNv4XjrLmEOSd74V7TF67YWTF/M5RCv5Xby491bnyElYSSt4Q5gZaA=
# SIG # End signature block
