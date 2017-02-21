<#
.SYNOPSIS
    Install and/or Update the PackageManagement PowerShell Module and/or the PowerShellGet PowerShell Module.

    IMPORTANT: This script can be used on systems with PowerShell Version 3 and higher

.DESCRIPTION
    PowerShell versions 3 and 4 do NOT have the PackageManagement and PowerShellGet Modules installed by default.
    If you are running PowerShell 3 or 4 and these modules are NOT installed, it will download PackageMangement_x64.msi
    from Microsoft and install it (thereby installing the Modules) and upgrade the Modules the latest version available
    in the PSGallery PackageProvider Source repo (NOTE: The PackageManagement module is not able to be upgraded beyond
    version 1.0.0.1 on PowerShell 3 or 4, unless you upgrade PowerShell itself to version 5 or higher).

    PowerShell version 5 and higher DOES come with PackageManagement and PowerShellGet Modules (both version
    1.0.0.1) by default. This script will install the latest versions of these Modules ALONGSIDE
    (i.e. SIDE-BY-SIDE MODE) the older versions...because that's apparently how Microsoft wants to
    handle this for the time being.

    At the conclusion of this script, the PowerShell Sessionw will have the latest versions of the PackageManagement and 
    PowerShellGet Modules loaded via Import-Module. (Verify with Get-Module).

.NOTES
    ##### Regarding PowerShell Versions Lower than 5 #####

    Installation of the PackageManagement_x64.msi is necessary. Installing this .msi gives us version 1.0.0.1 of the 
    PackageManagement Module and version 1.0.0.1 of PowerShellGet Module (as well as the PowerShellGet PackageProvider 
    and the PowerShellGet PackageProvider Source called PSGallery).

    However, these are NOT the latest versions of these Modules. You can update the PowerShellGet Module from 1.0.0.1 to
    the latest version by using Install-Module -Force. Unfortunately, it is not possible to update the PackageManagement
    Module itself using this method, because it will complain about it being in use (which it is, since the Install-Module
    cmdlet belongs to the PackageManagement Module).

    It is important to note that updating PowerShellGet using Install-Module -Force in PowerShell versions lower than 5
    actually REMOVES 1.0.0.1 and REPLACES it with the latest version. (In PowerShell version 5 and higher, it installs
    the new version of the Module ALONGSIDE the old version.)

    There is currently no way to update the PackageManagement Module to a version newer than 1.0.0.1 without actually updating
    PowerShell itself to version 5 or higher.


    ##### Regarding PowerShell Versions 5 And Higher #####

    The PackageManagement Module version 1.0.0.1 and PowerShellGet Module version 1.0.0.1 are already installed.

    It is possible to update both Modules using Install-Module -Force, HOWEVER, the newer versions will be installed
    ALONGSIDE (aka SIDE-BY-SIDE mode) the older versions. In future PowerShell Sessions, you need to specify which version
    you want to use when you import the module(s) using Import-Module -RequiredVersion

.EXAMPLE
    Update-PackageManagement

#>

function Update-PackageManagement {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi"` -OutFile "$HOME\Downloads\PackageManagement_x64.msi"
            msiexec /i "$HOME\Downloads\PackageManagement_x64.msi" /quiet /norestart ACCEPTEULA=1
            Start-Sleep -Seconds 3
        }
        while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
            Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
            Start-Sleep -Seconds 1
        }
        Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
    }

    $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PackageManagement"}).Version | Measure-Object -Maximum).Maximum
    $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
    }
    # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
    # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
    # do it beforehand.
    if ($(Get-PackageProvider).Name -notcontains "NuGet") {
        Install-PackageProvider "NuGet" -Force
        # The above Install-PackageProvider "NuGet" -Force does NOT register a PackageSource Repository
        # We could do it manually with th below...
        #    Register-PackageSource -Name 'NuGet' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap
        # ...but ultimately this is useless because Find-Package does NOT successfully search the NuGet Repo for NuGet packages
        # Instead, we'll install the NuGet CLI from the Chocolatey repo...
        Install-PackageProvider "Chocolatey" -Force
        # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
        Set-PackageSource -Name Chocolatey -Trusted
        # Next, install the NuGet CLI using the Chocolatey Repo
        Install-Package Nuget.CommandLine
        # Ensure $env:Path includes C:\Chocolatey\bin
        if ($($env:Path -split ";") -notcontains "C:\Chocolatey\bin") {
            $env:Path = "$env:Path;C:\Chocolatey\bin"
        }
        # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
        $NuGetSymlinkTest = Get-ChildItem "$env:ChocolateyPath" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
        $RealNuGetPath = $(Resolve-Path "$(Get-Location | Split-Path -Parent)\lib\*\*\NuGet.exe").Path
        $TestRealNuGetPath = Test-Path $RealNuGetPath
        if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
            cmd.exe /c mklink C:\Chocolatey\bin\NuGet.exe $RealNuGetPath
        }
    }
    # Next, set the PSGallery PowerShellGet PackageProvider Source to Trusted
    if ($(Get-PackageSource | Where-Object {$_.Name -eq "PSGallery"}).IsTrusted -eq $False) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    # Next, update PackageManagement and PowerShellGet where possible
    [version]$MinimumVer = "1.0.0.1"
    $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
    $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version

    # Take care of updating PowerShellGet before PackageManagement since PackageManagement won't be able to update with PowerShellGet
    # still loaded in the current PowerShell Session
    if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            # Before Updating the PowerShellGet Module, we must unload it from the current PowerShell Session
            Remove-Module -Name "PowerShellGet"
            # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
            # and it will not update it.
            Install-Module -Name "PowerShellGet" -Force -WarningAction "SilentlyContinue"
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Install-Module -Name "PowerShellGet" -Force
        }
    }
    if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Install-Module -Name "PackageManagement" -Force
        }
    }

    # Reset the LatestLocallyAvailableVersion variables to reflect latest available, and then load them into the current session
    $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PackageManagement"}).Version | Measure-Object -Maximum).Maximum
    $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

    Remove-Module -Name "PowerShellGet"
    Remove-Module -Name "PackageManagement"

    Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
    Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion

}












# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9tx+FHgxfGr2wOrY8ilVGj8q
# QXGgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSZBFW/8iDZ
# yHbptDMlZuP2VrRT3TANBgkqhkiG9w0BAQEFAASCAQBLkWujUuDxe8qhKNiBOvyi
# M/eJpyOOaY6SzRH2ktKfybb9hC9CLp3mEMBjHbdSaB+S4e2urxZVwfdyD2ZA+tiJ
# zDXZdpu7Oh4KzbnRPnom84xHweuJUEmjRz6diXxNusMl/jnkRbe78o5Z08EOXi7A
# OpePLG06MiprZ9GoFGnVaglT0DthaEF4Gq/T5oKcsxS4w1id9cWGI9n0ErauQAI2
# n8xxWrrGm/XIb6r315zjlDp3HMkW33QaZIGrY803Wb7fgZtMNZTbb5RzCq5w1C3M
# gfXQ+UMsoRLnNwOBoQJY5TciepiNrK+RF+Q+E+6SurvJuj29QE5HviSz8J3MRvNQ
# SIG # End signature block
