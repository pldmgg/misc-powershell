function Get-NewtonsoftJsonNuget {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ExpectedLocation
    )

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        if (!$ExpectedLocation) {
            $ExpectedLocation = "$HOME\.nuget\packages\Newtonsoft.Json"
        }
    }
    elseif ($PSVersionTable.PSEdition -eq "Core") {
        $ExpectedLocation = $(Get-Command pwsh).Source | Split-Path -Parent

        try {
            $DLLToLoad = $(Resolve-Path "$ExpectedLocation\Newtonsoft.Json.dll" -ErrorAction Stop).Path
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            Add-Type -Path $DLLToLoad -ErrorAction Stop
        }
        catch {
            if ($_.Exception -match "already exists") {
                Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session. Continuing..."
            }
            else {
                Write-Error $_
                Write-Error "Unable to load Newtonsoft.Json! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    # If Newtonsoft.Json is already loaded, don't do anything
    if (![bool]$($CurrentlyLoadedAssemblies.FullName -match "Newtonsoft\.Json")) {
        try {
            $NewtonsoftJsonDir = $(Resolve-Path $ExpectedLocation -ErrorAction Stop).Path
            $LatestVersionPath = $(Get-ChildItem -Path $ExpectedLocation -Directory | Sort-Object -Property LastWriteTime)[-1].FullName
            $DLLToLoad = $(Resolve-Path "$LatestVersionPath\lib\netstandard2.0\Newtonsoft.Json.dll" -ErrorAction Stop).Path
        }
        catch {
            # Get NuGet.CommandLine so we can install Newtonsoft.Json
            if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                try {
                    if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                        $null = Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
                        $null = Set-PackageSource -Name Chocolatey -Trusted
                    }
                    $null = Install-Package -Name Nuget.CommandLine -Confirm:$False -Force
                }
                catch {
                    Write-Error "Problem with 'Install-Package -Name Nuget.CommandLine'! Halting!"
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                # Make sure nuget.bat or nuget.exe is part of $envPath
                if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                    # Since NuGet.CommandLine is from the chocolatey repository, nuget.bat/nuget.exe should be
                    # under either C:\Chocolatey or C:\ProgramData\chocolatey
                    if (Test-Path "C:\Chocolatey") {
                        $RootDriveSearch = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "nuget.exe"
                    }
                    if (Test-Path "$env:ProgramData\chocolatey") {
                        $ProgramDataSearch = Get-ChildItem -Path "$env:ProgramData\chocolatey" -Recurse -File -Filter "nuget.exe"
                    }
                    
                    if (!$RootDriveSearch -and !$ProgramDataSearch) {
                        Write-Error "Unable to find nuget.exe from newly installed package Nuget.CommandLine!"
                        $global:FunctionResult = "1"
                        return
                    }
                    
                    if ($RootDriveSearch) {
                        $NugetExeParentDir = $RootDriveSearch.Directory.FullName
                    }
                    elseif ($ProgramDataSearch) {
                        $NugetExeParentDir = $ProgramDataSearch.Directory.FullName
                    }

                    # Add $NugetExeParentDir to $env:Path
                    $CurrentEnvPathArray = $env:Path -split ";"
                    if ($CurrentEnvPathArray -notcontains $NugetExeParentDir) {
                        # Place $NugetExeParentDir at start so latest openssl.exe get priority
                        $env:Path = "$NugetExeParentDir;$env:Path"
                    }
                }
            }
            
            if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                Write-Error "There was a problem adding nuget.exe to `$env:Path"
                $global:FunctionResult = "1"
                return
            }
            else {
                # Now we have nuget.exe, so install Newtonsoft.Json
                $null = & $(Get-Command nuget).Source install Newtonsoft.Json

                try {
                    $NewtonsoftJsonDir = $(Resolve-Path $ExpectedLocation -ErrorAction Stop).Path
                    $LatestVersionPath = $(Get-ChildItem -Path $ExpectedLocation -Directory | Sort-Object -Property LastWriteTime)[-1].FullName
                    $DLLToLoad = $(Resolve-Path "$LatestVersionPath\lib\netstandard2.0\Newtonsoft.Json.dll" -ErrorAction Stop).Path
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        try {
            Add-Type -Path $DLLToLoad -ErrorAction Stop
        }
        catch {
            if ($_.Exception -match "already exists") {
                Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session."
            }
            else {
                Write-Error $_
                Write-Error "Unable to load Newtonsoft.Json! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session."
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyAU86YU496C7p5pyn0FloRtt
# YEegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP8JMQsfTIQobdHc
# 8p6IdNYRt2pvMA0GCSqGSIb3DQEBAQUABIIBAERcvF+J2BnC2VCj2hk2PWL+oGtX
# VZj7+KwM4Ulov887Tc/FgIpeg5yr5uKoQ54QZ3ez2XlPvPra0ldYI1Q0xV/suQ3q
# +T0UTdKZzSFANT2KUzvdTR5I4SnqH9QNzRPDrUbJZ2psY2yvUMNy2jy3Y+yblpU/
# Ev2Jsj5+uY16+XJiecsw45CpbIqNjd07oL8CYDED5j89/Sbiwu5vqKdLYcQmMFi9
# wPgehlWdkd7jzqvoVS4Gki1Nz6VycYx8HtUudPl229oiaGRoQG7UMs42nQKh59CF
# Jxf62pM8YXxpjiwxFohiNWmO1jpyklpeTg/cEwaLH6J3xvo3RlhYlLCTBHg=
# SIG # End signature block
