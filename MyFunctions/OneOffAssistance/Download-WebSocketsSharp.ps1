<#
.SYNOPSIS
    Downloads appropriate WebSocket-Sharp NuGet Package that can run in your version of PowerShell

.DESCRIPTION
    See .SYNOPSIS

.PARAMETER NuGetPkgDownloadPath
    This parameter is MANDATORY

    This parameter takes a string that represents a full path to a directory that will contain the NuGet Package
    or a full path to the file .nupkg file.
    
    NOTE: If you use a full path to a file, any file extension other than .zip (like .nupkg) will be replaced with .zip

.EXAMPLE
    Download-WebSocketsSharp -NuGetPkgDownloadPath "$HOME\Downloads"

#>

function Download-WebSocketsSharp {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NuGetPkgDownloadPath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
    $($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        $WebSocketSharpUri = "https://www.nuget.org/api/v2/package/WebSocketSharp/1.0.3-rc11"
    }
    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        $WebSocketSharpUri = "https://www.nuget.org/api/v2/package/WebSocketSharp-netstandard"
    }

    try {
        $OutFileBaseNamePrep = Invoke-WebRequest $WebSocketSharpUri -DisableKeepAlive -UseBasicParsing
        $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
        $DllFileName = $OutFileBaseName -replace "zip","dll"
        
        if (!$OutFileBaseName) {
            throw
        }
    }
    catch {
        $OutFileBaseName = "WebSocketSharp_LatestAsOf_$(Get-Date -Format MMddyy).zip"
    }

    $TestPath = $NuGetPkgDownloadPath
    $BrokenDir = while (-not (Test-Path $TestPath)) {
        $CurrentPath = $TestPath
        $TestPath = Split-Path $TestPath
        if (Test-Path $TestPath) {$CurrentPath}
    }

    if ([String]::IsNullOrWhitespace([System.IO.Path]::GetExtension($NuGetPkgDownloadPath))) {
        # Assume it's a directory
        if ($BrokenDir) {
            if ($BrokenDir -eq $NuGetPkgDownloadPath) {
                $null = New-Item -ItemType Directory -Path $BrokenDir -Force
            }
            else {
                Write-Error "The path $TestPath was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
        }
        else {
            if ($(Get-ChildItem $NuGetPkgDownloadPath).Count -ne 0) {
                $NewDir = "$NuGetPkgDownloadPath\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                $null = New-Item -ItemType Directory -Path $NewDir -Force
            }
            $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
        }
    }
    else {
        # Assume it's a file
        $OutFileBaseName = $NuGetPkgDownloadPath | Split-Path -Leaf
        $extension = [System.IO.Path]::GetExtension($OutFileBaseName)
        if ($extension -ne ".zip") {
            $OutFileBaseName = $OutFileBaseName -replace "$extension",".zip"
        }

        if ($BrokenDir) {
            Write-Host "BrokenDir is $BrokenDir"
            if ($BrokenDir -eq $($NuGetPkgDownloadPath | Split-Path -Parent)) {
                $null = New-Item -ItemType Directory -Path $BrokenDir -Force
            }
            else {
                Write-Error "The path $TestPath was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
        }
        else {
            if ($(Get-ChildItem $($NuGetPkgDownloadPath | Split-Path -Parent)).Count -ne 0) {
                $NewDir = "$($NuGetPkgDownloadPath | Split-Path -Parent)\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                $null = New-Item -ItemType Directory -Path $NewDir -Force
            }
            
            $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
        }
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $subdir = "lib\netstandard2.0"
    }
    else {
        $subdir = "lib"
    }

    $NuGetPkgDownloadPathParentDir = $FinalNuGetPkgPath | Split-Path -Parent

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    
    ##### BEGIN Main Body #####

    # Download the NuGet Package
    Write-Host "Downloading HTMLAgilityPack NuGet Package to $FinalNuGetPkgPath..."
    Invoke-WebRequest -Uri $WebSocketSharpUri -OutFile $FinalNuGetPkgPath

    Write-Host "Extracting WebSocketSharp NuGet Package ..."
    Expand-Archive -Path $FinalNuGetPkgPath -DestinationPath $NuGetPkgDownloadPathParentDir

    $AssemblyPath = "$NuGetPkgDownloadPathParentDir\$subdir\websocket-sharp.dll"

    [pscustomobject]@{
        NuGetPackageDirectory   = $NuGetPkgDownloadPathParentDir
        AssemblyToLoad          = $AssemblyPath
    }
    
    ##### END Main Body #####

}















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2q1CwCEIDSkR9gcxmiQU168e
# /m2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAbiXYsa94RHMcO8
# xHkbuWCTeONGMA0GCSqGSIb3DQEBAQUABIIBAGj+b98svdZ0FPIlqAulzawdDHik
# l2LszLnSQ91OHqd4focPTEl4qooVw5yt2H6mBum2uo21/nM5StD8qRsWQ5nG4v9C
# J78gV+8sejNPo9x1cBTHR5vAHgWjHM3JHy0gUIgpUd6+tHtmdyuwcFUVWDXK4Stt
# r1S6ex4ZdABsbyXI7MOlXPY1lDniz9z5gi+iFS1Y0/9IIV8KiBOZn2ELuEeHKCoW
# bmhPvpfg9ufBVhjn9nKfLO53d65ocAND3nkKa62GhkSlw5h9sGbJ2VyK8y/yrBiM
# SB+stxurs5T0vP/RODzxE4JvjrGEcmAqNjgLtXaxH5VZBN0vlUySGBpyRIQ=
# SIG # End signature block
