function Install-Vim {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine
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
            $null = Update-PackageManagement -UseChocolatey -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($UPMErr -and $global:FunctionResult-eq "1") {throw}
        }
        catch {
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            foreach ($error in $UPMErr) {Write-Error $($error | Out-String)}
            Write-Error "The Update-PackageManagement function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UseChocolateyCmdLine -or $(!$UsePackageManagement -and !$UseChocolateyCmdLine)) {
        if (![bool]$(Get-Command Install-ChocolateyCmdLine -ErrorAction SilentlyContinue)) {
            $InstallCCFunctionUrl = "$MyFunctionsUrl/Install-ChocolateyCmdLine.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallCCFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Install-ChocolateyCmdLine function! Halting!"
                $global:FunctionResult = "1"
                return
            }
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

    # If the Chocolatey CmdLine is installed, get a list of programs installed via Chocolatey
    if ([bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        $ChocolateyInstalledProgramsPrep = clist --local-only
        $ChocolateyInstalledProgramsPrep = $ChocolateyInstalledProgramsPrep[1..$($ChocolateyInstalledProgramsPrep.Count-2)]

        [System.Collections.ArrayList]$ChocolateyInstalledProgramsPSObjects = @()

        foreach ($program in $ChocolateyInstalledProgramsPrep) {
            $programParsed = $program -split " "
            $PSCustomObject = [pscustomobject]@{
                ProgramName     = $programParsed[0]
                Version         = $programParsed[1]
            }

            $null = $ChocolateyInstalledProgramsPSObjects.Add($PSCustomObject)
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install Vim if it's not already...
    if (![bool]$(Get-Package vim -ErrorAction SilentlyContinue) -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains "vim") {
        # Alternate Download/Install method...
        <#
        $LatestVimForWin32 = $($(Invoke-WebRequest -Uri "http://www.vim.org/download.php").Links | Where-Object {$_.href -like "*w32*.zip"}).href
        $LatestVimForWin32ZipFileName = $LatestVimForWin32 | Split-Path -Leaf
        Invoke-WebRequest -Uri "$LatestVimForWin32" -OutFile "$HOME\Downloads\$LatestVimForWin32ZipFileName"
        Unzip-File -PathToZip "$HOME\Downloads\$LatestVimForWin32ZipFileName" -TargetDir "$HOME\Downloads"
        $FullPathToVimExe = $(Get-ChildItem "$HOME\Downloads\vim" -Recurse | Where-Object {$_.Name -like "*vim*.exe"}).FullName
        Copy-Item -Path "$FullPathToVimExe" -Destination "C:\Windows\System32\vim.exe"
        #>

        if ($UsePackageManagement -or $(!$UsePackageManagement -and !$UseChocolateyCmdLine)) {
            # NOTE: The PackageManagement install of vim is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            Install-Package vim -Force -ErrorVariable VimInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($VimInstallError) {
                Uninstall-Package vim -Force -ErrorAction SilentlyContinue
            }

            if ($UsePackageManagement) {
                Write-Error "Installing Vim via the the PackageManagement and PowerShellGet Modules failed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($(!$UsePackageManagement -and !$UseChocolateyCmdLine -and $VimInstallError) -or $UseChocolateyCmdLine) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr -and $global:FunctionResult -eq "1") {throw}
            }
            catch {
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                foreach ($error in $RCEErr) {Write-Error $($error | Out-String)}
                Write-Error "The Refresh-ChocolateyEnv function failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            # Make sure Chocolatey CmdLine is installed...if not, install it
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $global:FunctionResult = "0"
                    $null = Install-ChocolateyCmdLine -NoUpdatePackageManagement -ErrorAction SilentlyContinue -ErrorVariable ICCErr
                    if ($ICCErr -and $global:FunctionResult -eq "1") {throw}
                }
                catch {
                    Write-Host "Errors from the Install-ChocolateyCmdline function are as follows:"
                    foreach ($error in $ICCErr) {Write-Error $($error | Out-String)}
                    Write-Error "The Install-ChocolateyCmdLine function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            try {
                cup vim -y
            }
            catch {
                Write-Error "There was a problem installing Vim using the Chocolatey cmdline! Halting!"
                $global:FunctionResult = "1"
                return
            }

            # Now "C:\Program Files (x86)\vim" should be part of the SYSTEM Path (and therefore part of $env:Path)
            if (![bool]$(Get-Command vim -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    if ($RCEErr -and $global:FunctionResult -eq "1") {throw}
                }
                catch {
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    foreach ($error in $RCEErr) {Write-Error $($error | Out-String)}
                    Write-Error "The Refresh-ChocolateyEnv function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            if (![bool]$(Get-Command vim -ErrorAction SilentlyContinue)) {
                $VimDir = "C:\Program Files (x86)\vim"

                $VimPath = $(Get-ChildItem -Path $VimDir -File -Recurse -Filter "vim.exe").FullName

                if (!$(Test-Path $VimPath)) {
                    Write-Error "Unable to find the path to vim.exe! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $VimParentDir = [System.IO.Path]::GetDirectoryName($VimPath)

                if ($($env:Path -split ";") -notcontains $VimParentDir) {
                    if ($env:Path[-1] -eq ";") {
                        $env:Path = "$env:Path$VimParentDir"
                    }
                    else {
                        $env:Path = "$env:Path;$VimParentDir"
                    }
                }
                else {
                    Write-Error "$VimParentDir is already part of `$env:Path, but we are still unable to call vim.exe! Please check your Vim install! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

        #Set-Content -Path "$HOME\.vimrc" -Value "set viminfo+=n$HOME\_viminfo`nset backspace=2`nset backspace=indent,eol,start`nset shortmess=at`nset cmdheight=2`nsilent!"
        $HomeDoubleSlashes = $HOME -replace "\\","\\"
        $HomeVimrc = @'
let $HOME = '{0}'
let $MYVIMRC = '$HOME\\_vimrc'
set viminfo+=n$HOME\\_viminfo
set backspace=2
set backspace=indent,eol,start
set shortmess=at
set cmdheight=2
silent!
'@ -f $HomeDoubleSlashes

        $ProgramFiles86Vimrc = @'
let $HOME = '{0}'
let $MYVIMRC = '$HOME\\_vimrc'        
'@ -f $HomeDoubleSlashes

        if (Test-Path "${env:ProgramFiles(x86)}\vim\_vimrc") {
            Move-Item "${env:ProgramFiles(x86)}\vim\_vimrc" "${env:ProgramFiles(x86)}\vim\_vimrc_original"
        }
        if (Test-Path "$HOME\_vimrc") {
            Move-Item "$HOME\_vimrc" "$HOME\_vimrc_original"
        }

        Set-Content -Path "${env:ProgramFiles(x86)}\vim\_vimrc" -Value $ProgramFiles86Vimrc
        Set-Content -Path "$HOME\_vimrc" -Value $HomeVimrc

    ##### END Main Body #####
}
















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKm+Wpngm9SrU7wOsZKxguNnq
# 3UGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIuuv4ylMT4WmC5x
# +NDfHXZgtyepMA0GCSqGSIb3DQEBAQUABIIBAH0FJEHyfiPww3ArqK5gSQH7m78D
# EhtmIsreoowJue4QeLumhp1AJ84GGf1DlBiT9K6i1mCcWjOMPjfjG6WikLCs1Jv+
# 4KePqhinEwUV+9G3seKMmA/He8k4CuEDF/z7dbByk57Fk1qmQgvjppmcP9Q0Dv7e
# iYFePwJS/63picSPE5aRz1dmL8tJU22xTG1P6SDwDerUz7VyLlBAwZYu8nCI8++b
# catLpNgJD0xNax97KmZYr+6LqmbSsIYxtyKuzqBZjyDib1OuX43dXQSqZYyqq5Jj
# khc8GaE1SqqzkWWcUrBMx3FEnQ1FT3OA+CNwIw3c6/24Xo4eZFv8clVG6i0=
# SIG # End signature block
