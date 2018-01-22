<#
    .SYNOPSIS
        Install a Program using PackageManagement/PowerShellGet OR the Chocolatey Cmdline.

    .DESCRIPTION
        This function was written to make program installation on Windows as easy and generic
        as possible by leveraging existing solutions such as PackageManagement/PowerShellGet
        and the Chocolatey CmdLine.

        The function defaults to using PackageManagement/PowerShellGet. If that fails for
        whatever reason, then the Chocolatey CmdLine is used. You can also use appropriate
        parameters to specifically use EITHER PackageManagement/PowerShellGet OR the
        Chocolatey CmdLine

    .PARAMETER ProgramName
        This parameter is MANDATORY.

        This paramter takes a string that represents the name of the program that you'd like to install.

    .PARAMETER UsePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch that makes the function attempt program installation using ONLY
        PackageManagement/PowerShellGet Modules. Install using those modules fails for whatever
        reason, the function halts and returns the relevant error message(s).

        Installation via the Chocolatey CmdLine will NOT be attempted.

    .PARAMETER UseChocolateyCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch that makes the function attemt program installation using ONLY
        the Chocolatey CmdLine. If installation via the Chocolatey CmdLine fails for whatever reason,
        the function halts and returns the relevant error message(s)

    .PARAMETER ExpectedInstallLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a directory that contains the
        main executable for the installed program. This directory does NOT have to be the immediate
        parent directory of the .exe.

        If you are absolutely certain you know where on the filesystem the program will be installed,
        then use this parameter to speed things up.

    .PARAMETER CommandName
        This parameter is OPTIONAL.

        This parameter takes a string that represents the name of the main executable for the installed
        program. For example, if you are installing 7zip, the value of this parameter should be (under
        most circumstances) '7z'.

    .PARAMETER NoUpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch that suppresses this function's default behavior, which is to try
        and update PackageManagement/PowerShellGet Modules before attempting to use them to install
        the desired program. Updating these modules can take up to a minute, so use this switch
        if you want to skip the attempt to update.

    .EXAMPLE
        Install-Program -ProgramName kubernetes-cli -CommandName kubectl.exe

    .EXAMPLE
        Install-Program -ProgramName awscli -CommandName aws.exe -UsePackageManagement

    .EXAMPLE
        Install-Program -ProgramName VisualStudioCode -CommandName Code.exe -UseChocolateyCmdLine

    .EXAMPLE
        # If the Program Name and Main Executable are the same, then this is all you need...
        Install-Program -ProgramName vagrant

#>
function Install-Program {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$ProgramName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [string]$CommandName,

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

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install $ProgramName if it's not already...
    if (![bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue) -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) {
        if ($UsePackageManagement -or $(!$UsePackageManagement -and !$UseChocolateyCmdLine)) {
            # NOTE: The PackageManagement install of $ProgramName is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package $ProgramName -Force -ErrorVariable InstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($InstallError.Count -gt 0) {
                Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                
                if ($UsePackageManagement) {
                    Write-Error "One or more errors occurred during the installation of $ProgramName via the the PackageManagement/PowerShellGet Modules failed! Installation has been rolled back! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                $pminstall = $true
            }
        }

        if ($(!$UsePackageManagement -and !$UseChocolateyCmdLine -and $InstallError.Count -gt 0) -or $UseChocolateyCmdLine) {
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
                cup $ProgramName -y
                $chocoinstall = $true
            }
            catch {
                Write-Error "There was a problem installing $ProgramName using the Chocolatey cmdline! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        
        # Now $ExpectedInstallPath should be part of the SYSTEM Path (and therefore part of $env:Path)
        $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}
        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
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
        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
            if ($ExpectedInstallLocation) {
                $GeneralLocation = $ExpectedInstallLocation
                $ExePath = $(Get-ChildItem -Path $ExpectedInstallLocation -File -Recurse -Filter "*$FinalCommandName.exe").FullName
            }
            else {
                Write-Host "Searching for the newly installed $FinalCommandName.exe...Please wait..."
                $DirectoriesToSearchRecursively = $(Get-ChildItem -Path "C:\" -Directory | Where-Object {$_.Name -notmatch "Windows|PerfLogs|Microsoft"}).FullName
                foreach ($dir in $DirectoriesToSearchRecursively) {
                    $ExePath = $(Get-ChildItem -Path $dir -Recurse -File -Filter "*$FinalCommandName.exe").FullName
                    if ($ExePath) {
                        break
                    }
                }
            }

            if (!$(Test-Path $ExePath)) {
                Write-Error "Unable to find the path to $FinalCommandName.exe! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $ExeParentDir = [System.IO.Path]::GetDirectoryName($ExePath)

            if ($($env:Path -split ";") -notcontains $ExeParentDir) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$ExeParentDir"
                }
                else {
                    $env:Path = "$env:Path;$ExeParentDir"
                }
            }
            else {
                Write-Error "$ExeParentDir is already part of `$env:Path, but we are still unable to call $FinalCommandName.exe! Please check your $ProgramName install! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($chocoinstall) {
        clist --local-only $ProgramName
    }
    if ($pminstall) {
        Get-Package $ProgramName
    }

    ##### END Main Body #####
}
















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGi03wF0rsBRp9Uop+6scTnl3
# UzSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFI52/MrMmFmQFarH
# nz34tTB0xZgkMA0GCSqGSIb3DQEBAQUABIIBAH+hWMFQc0rivs/vF20Gpx61hy2m
# /oeHnibqWsIE80F+0j8F1wW2ZwC4N0YBLD3Cn1BfuA2LN3o6mWMhCkpSQhpfdK6h
# N7zXGBSrPJIYVwRN0r6iitlNACLO1jkAfIrI46HyvpCN+FypNDjkrj5WSm4nVBBL
# d8lERqanzIh0+9bgfN1PcQRWj+53OGS/5hyz/jpWP2XbLAXnho27Pnvn66IGxkkU
# yOBoWv51p5D/cTD+WjM7sZi/dsHvwKXjlQXKOwdIme29K9Pht4mAvbiZEbOjenCV
# QEFRcU1OJIC3J9NwCeBjZvGwF5wLcQe8HalIp7vVUgExSUTipXHbE3u9zyw=
# SIG # End signature block
