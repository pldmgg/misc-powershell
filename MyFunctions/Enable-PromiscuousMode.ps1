[CmdletBinding()]
Param (
    [Parameter(Mandatory = $False)]
    [string]$InterfaceName,

    [Parameter(Mandatory = $False)]
    [string]$InterfaceIPAddress,

    [Parameter(Mandatory = $False)]
    [switch]$UseBurntToast
)

function Enable-PromiscuousMode {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$InterfaceName,

        [Parameter(Mandatory = $True)]
        [string]$InterfaceIPAddress,

        [Parameter(Mandatory = $False)]
        [switch]$UseBurntToast
    )

    # Validate parameters
    if ($(Get-NetAdapter).Name -notcontains $InterfaceName) {
        Write-Error "'$InterfaceName' is not a valid Network Adapter Interface Name/InterfaceAlias! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($(Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4).IPAddress -notcontains $InterfaceIPAddress) {
        Write-Error "The interface '$Interface' does not have an IP Address of '$InterfaceIPAddress'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure Promiscuous Mode isn't already enabled
    if ($(Get-NetAdapter -Name $InterfaceName).PromiscuousMode) {
        Write-Error "Promiscuous Mode is already enabled for the interface '$InterfaceName'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UseBurntToast -and [Environment]::OSVersion.Version.Major -ge 10) {
        try {
            if (!$(Get-Module -ListAvailable BurntToast)) {Install-Module BurntToast}
            if (!$(Get-Module BurntToast)) {Import-Module BurntToast}
        }
        catch {
            Write-Verbose "Problem with installing the BurntToast Module! Skipping..."
        }
    }

    # Do some funky stuff with byte arrays
    $byteIn = New-Object Byte[] 4
    $byteOut = New-Object Byte[] 4
    $byteData = New-Object Byte[] 4096
    $byteIn[0] = 1
    $byteIn[1-3] = 0
    $byteOut[0-3] = 0

    # Open an IP Socket
    $Socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP)

    # Include the ip header
    $Socket.SetSocketOption("IP", "HeaderIncluded", $true)

    # Big packet buffer in bytes
    # NOTE: You might need to play with this value if things don't work. Try factors of 1024 (for example, 1024, 8192, 24576, 1024000, etc)
    $Socket.ReceiveBufferSize = 512000

    # Create ip endpoint
    $Endpoint = New-Object System.Net.IPEndpoint([Net.IPAddress]$InterfaceIPAddress, 0)
    $Socket.Bind($Endpoint)

    # Enable promiscuous mode
    [void]$Socket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll, $byteIn, $byteOut)

    # Make sure Promiscuous Mode is on
    if ($(Get-NetAdapter -Name $InterfaceName).PromiscuousMode) {
        if ($UseBurntToast -and [Environment]::OSVersion.Version.Major -ge 10) {
            $NewBTMsgSplatParams = @{
                Text            = @("Promiscuous Mode has been enabled for $InterfaceName $InterfaceIPAddress.","It will remain enabled as long as PowerShell process $PID is running.")
                Button          = New-BTButton -Dismiss
            }
            New-BurntToastNotification @NewBTMsgSplatParams
        }
        $SuccessMsg = "Promiscuous Mode has been enabled for $InterfaceName $InterfaceIPAddress. " +
        "Promiscuous Mode will remain enabled for as long as this PowerShell process (i.e. PID $PID) is running."
        Write-Host $SuccessMsg -ForegroundColor Green
    }
    else {
        Write-Error "Unable to enable Promiscuous Mode for $InterfaceName $InterfaceIPAddress! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $Counter = 0
    while ($True) {
        if ($Counter -eq 0) {
            Write-Host "To turn off Promiscuous Mode for '$InterfaceName', close this PowerShell window, or kill process $PID"
        }
        $Counter++
    }
}


if (!$InterfaceName) {
    $InterfaceName = Read-Host -Prompt "Please enter the name of the Network Interface that you would like to enable Promiscuous Mode for"
}

# Validate parameters
if ($(Get-NetAdapter).Name -notcontains $InterfaceName) {
    Write-Error "'$InterfaceName' is not a valid Network Adapter Interface Name/InterfaceAlias! Halting!"
    $global:FunctionResult = "1"
    return
}

if (!$InterfaceIPAddress) {
    [array]$IPAddressInfo = @($(Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4).IPAddress)
    if ($IPAddressInfo.Count -gt 1) {
        $InterfaceIPAddress = Read-Host -Prompt "Please enter the IP Address for $InterfaceName that you would like to use. Valid options are $($IPAddressInfo -join ', ')"
    }
    else {
        $InterfaceIPAddress = $IPAddressInfo[0]
    }
}

if ($IPAddressInfo -notcontains $InterfaceIPAddress) {
    Write-Error "The interface '$InterfaceName' does not have an IP Address of '$InterfaceIPAddress'! Halting!"
    $global:FunctionResult = "1"
    return
}

$EnablePromiscuousModeSplatParams = @{
    InterfaceName       = $InterfaceName
    InterfaceIPAddress  = $InterfaceIPAddress
}
if ($UseBurntToast) {
    $EnablePromiscuousModeSplatParams.Add("UseBurntToast",$True)
}
Enable-PromiscuousMode @EnablePromiscuousModeSplatParams
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGZ/Cly7xFI17/V8pedyxMkOl
# yqOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKlYcIiipGQ/Aylu
# 67T+V3aO/hSlMA0GCSqGSIb3DQEBAQUABIIBAH7ALc8HUaI8OOyjooDXr1XVsqEk
# InfUzHOvNlmlwgxzWAneE9109YWU+lcl/KyyUgulI3YjJlM12jIk+ngD0SlbYGYk
# MVTwkBg1nDTjqx6rm36woHQUQ2SnwL25PQi21/PC34+87VwXVLjtmGYsf3JnPbtQ
# PB3VcAo/01o3pnTBZTzRnf+9MYYXsJnbpmNONIM7W4dOBQvGTU7IqjmAx8q3V8Nh
# ZwTUlJVrCRPFP0xmMx2AGCNr7ktHg/KdSqOmHyRvHyXZBhGmWgxG8m5mgbMnpkS/
# v+vH7gtpq2FEwkSqgg2Xd8ePOPNqP+MNI42xfS2PgCn/gh33nitDtaSkihE=
# SIG # End signature block
