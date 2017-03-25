# Install git on windows:
# After installation, see: https://help.github.com/articles/set-up-git/

##### BEGIN Helper Functions #####

function Check-Elevation {
   [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
      New-Object System.Security.Principal.WindowsPrincipal(
         [System.Security.Principal.WindowsIdentity]::GetCurrent());

   [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
      [System.Security.Principal.WindowsBuiltInRole]::Administrator;

   if($currentPrincipal.IsInRole($administratorsRole))
   {
      return $true;
   }
   else
   {
      return $false;
   }
}

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
        $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
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

function Initialize-GitEnvironment {
    [CmdletBinding()]
    Param(
        [switch]$SkipSSHSetup = $false
    )

    # Set the Git PowerShell Environment
    if ($env:github_shell -eq $null) {
        $env:github_posh_git = Resolve-Path "$env:LocalAppData\GitHub\PoshGit_*" -ErrorAction Continue
        $env:github_git = Resolve-Path "$env:LocalAppData\GitHub\PortableGit_*" -ErrorAction Continue
        $env:PLINK_PROTOCOL = "ssh"
        $env:TERM = "msys"
        $env:HOME = $HOME
        $env:TMP = $env:TEMP = [system.io.path]::gettemppath()
        if ($env:EDITOR -eq $null) {
          $env:EDITOR = "GitPad"
        }

        # Setup PATH
        $pGitPath = $env:github_git
        #$appPath = Resolve-Path "$env:LocalAppData\Apps\2.0\XE9KPQJJ.N9E\GALTN70J.73D\gith..tion_317444273a93ac29_0003.0003_5794af8169eeff14"
        $appPath = $(Get-ChildItem -Recurse -Path "$env:LocalAppData\Apps" | Where-Object {$_.Name -match "^gith..tion*" -and $_.FullName -notlike "*manifests*" -and $_.FullName -notlike "*\Data\*"}).FullName
        $HighestNetVer = $($(Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework" | Where-Object {$_.Name -match "^v[0-9]"}).Name -replace "v","" | Measure-Object -Maximum).Maximum
        $msBuildPath = "$env:SystemRoot\Microsoft.NET\Framework\v$HighestNetVer"
        $lfsamd64Path = Resolve-Path "$env:LocalAppData\GitHub\lfs-*"

        $env:Path = "$env:Path;$pGitPath\cmd;$pGitPath\usr\bin;$pGitPath\usr\share\git-tfs;$lfsamd64Path;$appPath;$msBuildPath"

        $env:github_shell = $true
        $env:git_install_root = $pGitPath
        if ($env:github_posh_git) {
            $env:posh_git = "$env:github_posh_git\profile.example.ps1"
        }

        # Setup SSH
        if (!$SkipSSHSetup) {
            & "$appPath\GitHub.exe" --set-up-ssh
        }
    } 
    else {
        Write-Verbose "GitHub shell environment already setup"
    }
}

##### END Helper Functions #####


##### BEGIN Main Body #####

if (Check-Elevation) {
    Write-Verbose "The GitDesktop install will NOT work from an Elevated PowerShell Session (i.e. PS Session ran as Administrator)! Halting!"
    Write-Error "The GitDesktop install will NOT work from an Elevated PowerShell Session (i.e. PS Session ran as Administrator)! Halting!"
    $global:FunctionResult = "1"
    return
}

# For more info on SendKeys method, see: https://msdn.microsoft.com/en-us/library/office/aa202943(v=office.10).aspx
Invoke-WebRequest -Uri "https://github-windows.s3.amazonaws.com/GitHubSetup.exe" -OutFile "$HOME\Downloads\GitHubSetup.exe"
if (!$?) {
    Write-Verbose "Unable to download file! Halting!"
    Write-Error "Unable to download file! Halting!"
    $global:FunctionResult = "1"
    return
}
& "$HOME\Downloads\GitHubSetup.exe"

$AppInstallSecWarnWindow = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*Install - Security Warning*"}).MainWindowTitle
while (!$AppInstallSecWarnWindow) {
    Write-Host "Waiting For Download to finish..."
    Start-Sleep -Seconds 2
    $AppInstallSecWarnWindow = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*Install - Security Warning*"}).MainWindowTitle
}
if ($AppInstallSecWarnWindow) {
    Write-Host "Download finished. Installing..."
}

$AppInstallSecWarnWindow = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*Install - Security Warning*"}).MainWindowTitle
if ($AppInstallSecWarnWindow) {
    $wshell = New-Object -ComObject wscript.shell
    $wshell.AppActivate("$AppInstallSecWarnWindow") | Out-Null
    #1..4 | foreach {$wshell.SendKeys('{TAB}')}
    $wshell.SendKeys('{i}')
}

$OpenFileWarning = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*File - Security Warning*"}).MainWindowTitle
$GitHubDesktop = Get-Process | Where-Object {$_.MainWindowTitle -eq "GitHub" -and $_.ProcessName -eq "GitHub"}
while (!$OpenFileWarning) {
    Write-Host "Waiting For Install to finish..."
    $GitHubDesktop = Get-Process | Where-Object {$_.MainWindowTitle -eq "GitHub" -and $_.ProcessName -eq "GitHub"}
    if ($GitDesktop) {
        break
    }
    $OpenFileWarning = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*File - Security Warning*"}).MainWindowTitle
    Start-Sleep -Seconds 2
}
if ($OpenFileWarning -or $GitDesktop) {
    Write-Host "Install finished."
}

if (!$GitDesktop) {
    $OpenFileWarning = $(Get-Process | Where-Object {$_.MainWindowTitle -like "*File - Security Warning*"}).MainWindowTitle
    if ($OpenFileWarning) {
        $wshell = New-Object -ComObject wscript.shell
        $wshell.AppActivate("$OpenFileWarning") | Out-Null
        #1..4 | foreach {$wshell.SendKeys('{TAB}')}
        $wshell.SendKeys('{r}')
    }
}

$GitHubDesktop = Get-Process | Where-Object {$_.MainWindowTitle -eq "GitHub" -and $_.ProcessName -eq "GitHub"}
while (!$GitHubDesktop) {
    Write-Host "Waiting For GitDesktop to launch..."
    Start-Sleep -Seconds 2
    $GitHubDesktop = Get-Process | Where-Object {$_.MainWindowTitle -eq "GitHub" -and $_.ProcessName -eq "GitHub"}
}
if ($GitHubDesktop) {
    Write-Host "GitDesktop launched."
    Start-Sleep -Seconds 3
}

while (!$(Test-Path "$env:LocalAppData\GitHub\shell.ps1")) {
    Write-Host "Waiting for Current User Local App Data GitHub Directory to be ready..."
    Start-Sleep -Seconds 2
}
if (Test-Path "$env:LocalAppData\GitHub\shell.ps1") {
    Write-Host "Local App Data GitHub Directory is ready."
    Write-Host "Closing GitDesktop..."
}

Start-Sleep -Seconds 2

$GitHubDesktopPID = $(Get-Process | Where-Object {$_.MainWindowTitle -eq "GitHub" -and $_.ProcessName -eq "GitHub"}).Id
Stop-Process -Id $GitHubDesktopPID

if (!$(Test-Path "$env:LocalAppData\GitHub\PoshGit*")) {
    if (!$(Get-Module -List -Name posh-git)) {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Install-Module posh-git -Scope CurrentUser
            Import-Module posh-git -Verbose
        }
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Update-PackageManagement
            Install-Module posh-git -Scope CurrentUser
            Import-Module posh-git -Verbose
        }
    }
}

# Set the Git PowerShell Environment
Initialize-GitEnvironment

# Write-Host "See the following site for next steps:"
# Write-Host "https://help.github.com/articles/set-up-git/"

##### END Main Body #####
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUa0yaCgoF8fBU2lOulwekEjBM
# SH2gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSfjLnw3xiw
# QsdLohofo5+nGMNPETANBgkqhkiG9w0BAQEFAASCAQBjamvEl8H58oZPh5ycbFbw
# n9VbA66EqH1I1mzFNeX16cmpx8pVfL+lbL4tsCFmFODJb/Y5zMg49QYIhtvuTIt/
# kCIQl+3Oj3I5bD308kKwVv6ij75dCEoR8QXKm/0Y25dbfEycN1xdC+zGTep74WMA
# RImQILQcNciwSVPNI6KyaD5yCZdnm0x3fPdtBbzxA7F+FlGMlpH0G1DbAwmlNwtI
# +nUI+7AAGj124GNYcGxTvdII6tuRdaRV1iE+fW5o2vNobL1EDPZxy0PmmQ7ovpVx
# E8Juxrd0VXZAIei08Hr2aGzle7gCxdAvkNxQd8GZlrnYiFUPbrJ3SOry4gy25KHK
# SIG # End signature block
