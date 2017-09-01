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

        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }

        $HostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $HostName)) {
            try {
                $HostIP = $(Resolve-DNSName $HostName).IP4Address
                if ($HostIP.Count -gt 1) {
                    if ($HostName -eq $env:COMPUTERNAME) {
                        $PrimaryLocalIPv4AddressPrep = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch "^127"}
                        if ($PrimaryLocalIPv4AddressPrep.Count -gt 1) {
                            $HostIP = $($PrimaryLocalIPv4AddressPrep | Where-Object {$_.PrefixOrigin -eq "Dhcp"})[0].IPAddress
                        }
                        else {
                            $HostIP = $PrimaryLocalIPv4AddressPrep.IPAddress
                        }
                    }
                    else {
                        Write-Warning "Potential IPv4 addresses for $HostName are as follows"
                        Write-Host $($HostIP -join "; ")
                        $HostIPChoice = Read-Host -Prompt "Please enter the primary IPv4 address for $HostName"
                        if ($HostIP -notcontains $HostIPChoice) {
                            Write-Error "The specified IPv4 selection does nto match one of the available options! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            $HostIP = $HostIPChoice
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostIP) {
                # Filter out any non IPV4 IP Addresses that are in $HostIP
                $HostIP = $HostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $HostIP, just select the first one
                if ($HostIP.Count -gt 1) {
                    $IP = $HostIP[0]
                }
                if ($HostIP -eq "127.0.0.1") {
                    $LocalHostInfo = Get-CimInstance Win32_ComputerSystem
                    $DNSHostName = "$($LocalHostInfo.Name)`.$($LocalHostInfo.Domain)"
                    $HostNameFQDN = $DNSHostName
                }
                else {
                    $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                    $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
                }

                $pos = $HostNameFQDN.IndexOf(".")
                $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostIP) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostName) {
            try {
                $HostIP = $HostName
                $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostNameFQDN) {
                if ($($HostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                    $pos = $HostNameFQDN.IndexOf(".")
                    $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                    $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)
                }
                else {
                    $HostNameFQDNPre = $HostNameFQDN
                    $HostNameFQDNPost = $HostNameFQDN
                }

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostNameFQDN) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        ##### END Parameter Validation #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        $tcp = New-Object Net.Sockets.TcpClient
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$HostName","Test Connection on $HostName`:$Port")) {
            try {
                $tcp.Connect($HostName, $Port)
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
                Address      = $HostName
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKEqaT8FGcyxA8VG9a0qBt30F
# LYmgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSuERVSTIoL
# G0m1XXgXvOx1mez+QjANBgkqhkiG9w0BAQEFAASCAQAa88OFsELGodGUMocqVHGf
# yv4N7Qk1VFQYHJl6O/B8a87V0jfllOHo+2/3kBjXbYrJUgo+YsKMNY+7M+/Ks7l+
# upZ5r90HjElAvVF8WAx89jKYwBECoFzo9BQsajjINI4J2pgMJ+1+30zHXQzOJMSD
# EIwoWl3dVsIwau6rff9akiihb9KX1mRojdCt623enFS8Jez3FUuMPs/YOW9qORBE
# thGdKFvMIX7IVDyOy/k/r3nEkQyRhC1oGXM/DJjO/QDmqp+GFNDuX+Tqz7teXis6
# JHqw+Oqa7kvLUm0ekeVJvq+EoojiiO8gJYtTFRycLMMM1pM5RoQaSSs+xryNyq8n
# SIG # End signature block
