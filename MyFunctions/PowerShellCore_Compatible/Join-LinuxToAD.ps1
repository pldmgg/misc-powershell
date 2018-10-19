<#
    .SYNOPSIS
        This function joins a Linux machine to a Windows Active Directory Domain.

        Currently, this function only supports RedHat/CentOS.

        Most of this function is from:

        https://winsysblog.com/2018/01/join-linux-active-directory-powershell-core.html

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER DomainName
        This parameter is MANDATORY.

        This parameter takes a string that represents Active Directory Domain that you would like to join.

    .PARAMETER DomainCreds
        This parameter is MANDATORY.

        This parameter takes a pscredential object that represents a UserName and Password that can join
        a host to teh Active Directory Domain.

    .EXAMPLE
        # Open an elevated PowerShell Core (pwsh) session on a Linux, import the module, and -

        [CentOS7Host] # sudo pwsh

        PS /home/testadmin> $DomainCreds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Enter Password" -AsSecureString))
        PS /home/testadmin> Join-LinuxToAD -DomainName "zero.lab" -DomainCreds $DomainCreds
#>
function Join-LinuxToAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$DomainName,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCreds
    )

    #region >> Helper Functions
    
    function GetElevation {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
            [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )
    
            [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
            if($currentPrincipal.IsInRole($administratorsRole)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        if ($PSVersionTable.Platform -eq "Unix") {
            if ($(whoami) -eq "root") {
                return $true
            }
            else {
                return $false
            }
        }
    }

    #endregion >> Helper Functions
    

    if (!$(GetElevation)) {
        Write-Error "You must run the $($MyInvocation.MyCommand.Name) function with elevated permissions! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$IsLinux) {
        Write-Error "This host is not Linux. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($PSVersionTable.OS -match 'RedHat|CentOS|\.el[0-9]\.')) {
        Write-Error "Currently, the $(MyInvocation.MyCommand.Name) function only works on RedHat/CentOS Linux Distros! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure nslookup is installed
    $NSLookupCheck = command -v nslookup
    if (!$NSLookupCheck) {
        $null = yum install bind-utils -y
    }

    # Ensure you can lookup AD DNS
    $null = nslookup $DomainName
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Could not find domain in DNS. Checking settings'
        $global:FunctionResult = "1"
        return
    }

    #Ensure Samba and dependencies installed
    $DependenciesToInstall = @(
        "sssd"
        "realmd"
        "oddjob"
        "oddjob-mkhomedir"
        "adcli"
        "samba-common"
        "samba-common-tools"
        "krb5-workstation"
        "openldap-clients"
        "policycoreutils-python"
    )

    [System.Collections.ArrayList]$SuccessfullyInstalledDependencies = @()
    [System.Collections.ArrayList]$FailedInstalledDependencies = @()
    foreach ($Dependency in $DependenciesToInstall) {
        $null = yum install $Dependency -y

        if ($LASTEXITCODE -ne 0) {
            $null = $FailedInstalledDependencies.Add($Dependency)
        }
        else {
            $null = $SuccessfullyInstalledDependencies.Add($Dependency)
        }
    }

    if ($FailedInstalledDependencies.Count -gt 0) {
        Write-Error "Failed to install the following dependencies:`n$($FailedInstalledDependencies -join "`n")`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    # Join domain with realm
    $DomainUserName = $DomainCreds.UserName
    if ($DomainUserName -match "\\") {$DomainUserName = $($DomainUserName -split "\\")[-1]}
    $PTPasswd = $DomainCreds.GetNetworkCredential().Password
    printf "$PTPasswd" | realm join $DomainName --user=$DomainUserName *> $null

    if ($LASTEXITCODE -ne 0) {
        Write-Error -Message "Could not join domain $DomainName."
        return
    }

    # Add the Domain Admins Group to /etc/sudoers
    $DomainNameShort = @($($DomainUserName -split "\\"))[0]
    echo "%$DomainNameShort\\Domain\ Admins    ALL=(ALL)    ALL" | sudo EDITOR='tee -a' visudo

    if ($LASTEXITCODE -eq 0) {
        Write-Output 'Success'
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgpTGG75iNe5ywl+S2oWATbtY
# +kKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEELnfQdDaitT4OE
# KD8uEB44qYIbMA0GCSqGSIb3DQEBAQUABIIBAK69Q+RDMY+bI7bytxK1cuicU1tW
# pPPnIxw+uVN380gPAE4oif+QRPm+/g/ykRmySKAPRFkO2NX5UL3/9GMsa2gGkvoN
# aETF4QzeGMhEoOig34y04X7AnUDHcN0Fv+rOPgl3ZJoAJj0JIDpHG9XZfr1jNzc3
# rn6hCqygtB+AAnsJtidfIsuAAQRlenG+KdbPzrl9pceqee+00m+IU4dezIxCq9aw
# 7aT2uAaOv3uViLrBiT7OykLKA+N1MizFbKOuSZSZPspTiJtujLY4451r8iqUbMW2
# BYXX0/tnRwUay3PsZ9XTRkYN7+Vh64MLdOhXAViP5bm7aZeKpUCZ+2BaVx0=
# SIG # End signature block
