function Install-ChocolateyCmdLine {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $UPMResult = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($global:FunctionResult -eq "1" -or $UPMResult -eq $null) {throw "The Update-PackageManagement function failed!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        # The below Install-Package Chocolatey screws up $env:Path, so restore it afterwards
        $OriginalEnvPath = $env:Path

        # Installing Package Providers is spotty sometimes...Using while loop 3 times before failing
        $Counter = 0
        while ($(Get-PackageProvider).Name -notcontains "Chocolatey" -and $Counter -lt 3) {
            Install-PackageProvider -Name Chocolatey -Force -Confirm:$false -WarningAction SilentlyContinue
            $Counter++
            Start-Sleep -Seconds 5
        }
        if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
            Write-Error "Unable to install the Chocolatey Package Provider / Repo for PackageManagement/PowerShellGet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Package -Name Chocolatey -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
            # NOTE: The PackageManagement install of choco is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package Chocolatey -Provider Chocolatey -Force -Confirm:$false -ErrorVariable ChocoInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($ChocoInstallError.Count -gt 0) {
                Write-Warning "There was a problem installing the Chocolatey CmdLine via PackageManagement/PowerShellGet!"
                $InstallViaOfficialScript = $True
                Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
            }

            if ($ChocoInstallError.Count -eq 0) {
                $PMPGetInstall = $True
            }
        }

        # Try and find choco.exe
        try {
            Write-Host "Refreshing `$env:Path..."
            $global:FunctionResult = "0"
            $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
            
            if ($RCEErr.Count -gt 0 -and
            $global:FunctionResult -eq "1" -and
            ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                throw "The Refresh-ChocolateyEnv function failed! Halting!"
            }
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
            Write-Error $($RCEErr | Out-String)
            $global:FunctionResult = "1"
            return
        }

        if ($PMPGetInstall) {
            # It's possible that PowerShellGet didn't run the chocolateyInstall.ps1 script to actually install the
            # Chocolatey CmdLine. So do it manually.
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Warning "Unable to find Chocolatey directory! Halting!"
                Write-Host "Installing via official script at https://chocolatey.org/install.ps1"
                $InstallViaOfficialScript = $True
            }
            
            if ($ChocolateyPath) {
                $ChocolateyInstallScript = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyinstall.ps1").FullName | Where-Object {
                    $_ -match ".*?chocolatey\.[0-9].*?chocolateyinstall.ps1$"
                }

                if (!$ChocolateyInstallScript) {
                    Write-Warning "Unable to find chocolateyinstall.ps1!"
                    $InstallViaOfficialScript = $True
                }
            }

            if ($ChocolateyInstallScript) {
                try {
                    Write-Host "Trying PowerShellGet Chocolatey CmdLine install script from $ChocolateyInstallScript ..." -ForegroundColor Yellow
                    & $ChocolateyInstallScript
                }
                catch {
                    Write-Error $_
                    Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                    if ([bool]$(Get-Package $ProgramName)) {
                        Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # If we still can't find choco.exe, then use the Chocolatey install script from chocolatey.org
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue) -or $InstallViaOfficialScript) {
            $ChocolateyInstallScriptUrl = "https://chocolatey.org/install.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($ChocolateyInstallScriptUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to install Chocolatey via the official chocolatey.org script! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PMPGetInstall = $False
        }
        
        # If we STILL can't find choco.exe, then Refresh-ChocolateyEnv a third time...
        #if (![bool]$($env:Path -split ";" -match "chocolatey\\bin")) {
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            # ...and then find it again and add it to $env:Path via Refresh-ChocolateyEnv function
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    
                    if ($RCEErr.Count -gt 0 -and
                    $global:FunctionResult -eq "1" -and
                    ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                        throw "The Refresh-ChocolateyEnv function failed! Halting!"
                    }
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        # If we STILL can't find choco.exe, then give up...
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find choco.exe after install! Check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Finished installing Chocolatey CmdLine." -ForegroundColor Green

            try {
                cup chocolatey-core.extension -y
            }
            catch {
                Write-Error "Installation of chocolatey-core.extension via the Chocolatey CmdLine failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            $ChocoModulesThatRefreshEnvShouldHaveLoaded = @(
                "chocolatey-core"
                "chocolateyInstaller"
                "chocolateyProfile"
                "chocolateysetup"
            )

            foreach ($ModName in $ChocoModulesThatRefreshEnvShouldHaveLoaded) {
                if ($(Get-Module).Name -contains $ModName) {
                    Write-Host "The $ModName Module has been loaded from $($(Get-Module -Name $ModName).Path)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Warning "The Chocolatey CmdLine is already installed!"
    }

    ##### END Main Body #####
}









































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOznrEl6bp3G9C1dtIKtriuxk
# JtKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFldD6W3qYs94nKz
# Lz75lhUcCVwoMA0GCSqGSIb3DQEBAQUABIIBAFZun1zf/KqSJIKz3CuWsomktATT
# mFLNqSkctCvBtABLg+a7Twx9VRYeYss2+WWl9xA9o1xFyx3cdpeftZ8oURevzHk7
# K8UTxT22L0TXxesVkg8H4C9Yka0CnLhL9LR0vB2t3DRlH1kSccBVtBhCuzA4Oe1j
# dhfaWx9rKv8rJhFB+7dN3PZm6yzUeuJMNTcFbi3Koa6Avq7Do+fNYR8czQCDm1PC
# uesACVv+WGumsioSTCvbFWM4cBW2Is9g8wg+n3Z7OX8OZWVYi+KxD74uPWOBRPhk
# u5wxVJwCvuFsOghLD/hfbC8PIjBkio7dkLldA1Iv/g7MhCPbRcMuQw2dSCM=
# SIG # End signature block
