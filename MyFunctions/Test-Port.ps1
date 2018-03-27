function Test-Port {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {
        
        ##### BEGIN Parameter Validation #####

        # Begin Helper Functions #

        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }

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
        
            if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
                [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
                # Test to see if we can reach the IP Addresses
                foreach ($ip in $RemoteHostArrayOfIPAddresses) {
                    if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                        $null = $SuccessfullyPingedIPs.Add($ip)
                    }
                }
        
                if ($SuccessfullyPingedIPs.Count -eq 0) {
                    Write-Error "Unable to resolve $HostNameOrIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        
            $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
            if ($FQDNPrep -match ',') {
                $FQDN = $($FQDNPrep -split ',')[0]
            }
            else {
                $FQDN = $FQDNPrep
            }
        
            $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
            if ($DomainPrep -match ',') {
                $Domain = $($DomainPrep -split ',')[0]
            }
            else {
                $Domain = $DomainPrep
            }
        
            [pscustomobject]@{
                IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
                FQDN            = $FQDN
                HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
                Domain          = $Domain
            }
        
            ##### END Main Body #####
        
        }

        try {
            $HostNameNetworkInfo = Resolve-Host -HostNameOrIP $HostName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HostName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # End Helper Functions #

        ##### END Parameter Validation #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        $tcp = New-Object Net.Sockets.TcpClient
        $RemoteHostFQDN = $HostNameNetworkInfo.FQDN
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$RemoteHostFQDN","Test Connection on $RemoteHostFQDN`:$Port")) {
            try {
                $tcp.Connect($RemoteHostFQDN, $Port)
            }
            catch {}

            if ($tcp.Connected) {
                $tcp.Close()
                $open = $true
            }
            else {
                $open = $false
            }

            $PortTestResult = [pscustomobject]@{
                Address = $RemoteHostFQDN
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}





# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUhCPHqHRyGJdAejVQ8bMR5FSz
# hDagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFAjHQhWlcl7a1vT
# vP2d4+FtfF5rMA0GCSqGSIb3DQEBAQUABIIBAGcNDn/hWqsAhB7dn7cFwvgpeb8+
# X3IjRiDpfaFy5xrjU0KdExpATSxtVp6He/2PM8ps1Ic4DYpUINOacd0Div/xX/RL
# H6uyT6i+UjzWDGObdY4jOD6LrZgXyLwIKSF3O9Hj4uWrKHUjDxxV3odR7k3UK2CP
# b5jUgpxEzE9ZzGFDvC8WQuZkmb+byd6L+TOVmDXaLpsKTdGOUoKM0VU1DEuEnUjl
# ZxlwwheZcp45dfv+eB2U/CJ31pHbwjSMUxmWXbX7hwIq0DGoy5LsJKu4lTraTQiW
# BJcyrWiemzp6C0OJo3YEGPwDdOVVA4+7fgtWmXOyohvuQAe8RUGBLiZ3y4k=
# SIG # End signature block
