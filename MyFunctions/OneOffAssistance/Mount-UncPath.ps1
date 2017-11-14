function Mount-UncPath {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$UNCPathToMount,

        [Parameter(Mandatory=$True)]
        [ValidateScript({
            $Alphabet = $(65..90) | foreach {[string][char]$_}
            if ($Alphabet -contains $_) {$true} else {$false}
        })]
        [string]$DriveLetterToUse,

        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $Alphabet = $(65..90) | foreach {[string][char]$_}
            [System.Collections.ArrayList]$Failures = @()
            foreach ($letter in $_) {
                if ($Alphabet -notcontains $_) {
                    $null = $Failures.Add($false)
                }
            }
            if ($Failures -contains $false) {$false} else {$true}
        })]
        [string[]]$DriveLettersToExclude

    )

    ##### BEGIN Native Helper Functions #####

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
    
                [System.Net.Dns]::GetHostEntry($HostNamePrep).AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
                
                [System.Collections.ArrayList]$RemoteHostFQDNs = @()
                foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
                    try {
                        $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
                    }
                    catch {
                        Write-Verbose "Unable to resolve $HostIP. Please check your DNS config."
                        continue
                    }
                    if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                        $null = $RemoteHostFQDNs.Add($FQDNPrep)
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
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add([System.Net.Dns]::GetHostEntry($HostIPPrep).HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
        }
        if ($RemoteHostFQDNs.Count -eq 0) {
            Write-Error "Unable to determine FQDN of $HostNameOrIP! Halting!"
        }
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0 -or $RemoteHostFQDNs.Count -eq 0) {
            $global:FunctionResult = "1"
            return
        }
    
        [pscustomobject]@{
            IPAddressList   = $RemoteHostArrayOfIPAddresses
            FQDNList        = $RemoteHostFQDNs
        }
    
        ##### END Main Body #####
    
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $Alphabet = $(90..65) | foreach {[string][char]$_}

    $CurrentPSDrives = Get-PSDrive

    if ($CurrentPSDrives.DisplayRoot -contains $UNCPathToMount) {
        $PSDriveOutput = $CurrentPSDrives | Where-Object {$_.DisplayRoot -eq $UNCPathToMount}
        $DriveLetterFinal = $PSDriveOutput.Name
        Write-Warning "$UNCPathToMount is already mounted at PSDrive named $DriveLetterFinal! No action taken."
        return $PSDriveOutput
    }

    if ($CurrentPSDrives.Name -contains $DriveLetterToUse) {
        Write-Warning "The specified DriveLetterToUse $DriveLetterToUse is already in use. Automatically selecting an available drive letter..."
    }

    $FileServerHostName = $($UNCPathToMount -split "\\") | Where-Object {$_} | Select-Object -Index 0

    try {
        [bool]$FileServerResolution = Resolve-Host -HostNameOrIP $FileServerHostName -ErrorAction SilentlyContinue

        if (!$FileServerResolution) {
            throw
        }
    }
    catch {
        Write-Error "Unable to resolve host $FileServerHostName"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    try{
        if ($CurrentPSDrives.Name -contains $DriveLetterToUse) {
            $AvailableDriveLettersPrep = $Alphabet | Where-Object {$CurrentPSDrives.Name -notcontains $_}
            $AvailableDriveLetters = foreach ($letter in $AvailableDriveLettersPrep) {
                if ($DriveLettersToExclude -notcontains $letter) {
                    $letter
                }
            }
            
            $DriveLetterFinal = $AvailableDriveLetters[0]
        }
        else {
            $DriveLetterFinal = $DriveLetterToUse
        }

        try {
            $PSDriveOutput = New-PSDrive -Name $DriveLetterFinal -PSProvider FileSystem -Root $UNCPathToMount -Persist -Scope Global -Description "Mount of $UNCPathToMount" -ErrorAction SilentlyContinue
            if (!$?) {throw}
            Write-Host "Successfully mounted $UNCPathToMount to PSDrive $DriveLetterFinal"
        }
        catch {
            $PSDriveOutput = New-PSDrive -Name $DriveLetterFinal -PSProvider FileSystem -Root $UNCPathToMount -Persist -Scope Global -Credential $(Get-Credential) -Description "Mount of $UNCPathToMount" -ErrorAction SilentlyContinue
            if (!$?) {throw}
            Write-Host "Successfully mounted $UNCPathToMount to PSDrive $DriveLetterFinal"
        }
    }
    catch {
        Write-Error "Unable to mount $UNCPathToMount! Please check your credentials. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PSDriveOutput

    ##### END Main Body #####

}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvPuErmu7QmQn9woZjKAyF+I+
# UPegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJwHTj0k1n2AP4KH
# bDsA38tC+OyrMA0GCSqGSIb3DQEBAQUABIIBAFM8B/9rwp1GFOyK0xwbfL/xOFEk
# +J2aiGET+Q/FuXCx/LXvV/gtXKPP1UngQ5ieOk+B+Ct51QncakCDo/1iGgsU+pmu
# mktYPEWo3ueyCgg362j/y0ShrhprDODdylCHmx+7bwQTWdcl36POSrhAFVohAiMt
# s0yuaPkLjdf49YxvDKrULaV4JIVXb8NfrRjkryvUspYCYYfqQaXAhN0jDID0KvJk
# ELlCm2FZGs8GS9QiGNytz4c/vUpYNGPI8O49d+nTCWqs4FiVDsM/8U+xGmblgoBr
# wLowgIPOVt5hxuUKQSuOdWpQE4MWW0bPnENZH9G8CuvhpEEtyYH0fYCbgvc=
# SIG # End signature block
