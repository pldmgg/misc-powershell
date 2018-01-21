<#
    .SYNOPSIS
        Get Windows Special Folders. (Not as easy as it sounds)

        This function leverages work from:

        Ray Koopa - https://www.codeproject.com/articles/878605/getting-all-special-folders-in-net
        Lee Dailey - https://www.reddit.com/r/PowerShell/comments/7rnt31/looking_for_a_critique_on_function/

    .DESCRIPTION
        Give the function the name (or part of a name) of a Special Folder and this function will tell you
        where the actual path is on the given Windows OS.

    .PARAMETER SpecialFolderName
        This parameter is MANDATORY.
        
        This parameter takes a string that represents the name of the Special Folder you are searching for.

    .EXAMPLE
        Get-SpecialFolder -SpecialFolderName MyDocuments    

    .EXAMPLE
        Get-SpecialFolder Documents

    .OUTPUTS
        One or more Syroot.Windows.IO.KnownFolder objects that look like:

            Type         : Documents
            Identity     : System.Security.Principal.WindowsIdentity
            DefaultPath  : C:\Users\zeroadmin\Documents
            Path         : C:\Users\zeroadmin\Documents
            ExpandedPath : C:\Users\zeroadmin\Documents
#>

function Get-SpecialFolder {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$SpecialFolderName
    )

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    if (![bool]$($CurrentlyLoadedAssemblies.FullName -match "Syroot")) {
        $PathHelper = "$HOME\Downloads\Syroot.Windows.IO.KnownFolders.1.0.2" 
        Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/Syroot.Windows.IO.KnownFolders/1.0.2" -OutFile "$PathHelper.zip"
        Expand-Archive -Path "$PathHelper.zip" -DestinationPath $PathHelper -Force
        $Syroot = Add-Type -Path "$PathHelper\lib\net40\Syroot.Windows.IO.KnownFolders.dll" -Passthru
    }
    else {
        $Syroot = $($CurrentlyLoadedAssemblies -match "Syroot").ExportedTypes
    }
    $SyrootKnownFolders = $Syroot | Where-Object {$_.Name -eq "KnownFolders"}
    $AllSpecialFolders = $($SyrootKnownFolders.GetMembers() | Where-Object {$_.MemberType -eq "Property"}).Name
    [System.Collections.ArrayList]$AllSpecialFolderObjects = foreach ($FolderName in $AllSpecialFolders) {
        [Syroot.Windows.IO.KnownFolders]::$FolderName
    }

    $Full_SFN_List = [enum]::GetNames('System.Environment+SpecialFolder')
    # The ACTUAL paths ARE accounted for in $RealSpecialFolderObjects.Path, but SOME of the Special Names used in $Full_SFN_List
    # are not mapped to the 'Type' property of $RealSpecialFolderObjects
    $SpecialNamesNotAccountedFor = $(Compare-Object $AllSpecialFolders $Full_SFN_List | Where-Object {$_.SideIndicator -eq "=>"}).InputObject

    if ([bool]$($AllSpecialFolderObjects.Type -match $SpecialFolderName)) {
        $AllSpecialFolderObjects | Where-Object {$_.Type -match $SpecialFolderName}
    }
    elseif ([bool]$($SpecialNamesNotAccountedFor -match $SpecialFolderName)) {
        $AllPossibleMatches = $SpecialNamesNotAccountedFor -match $SpecialFolderName

        foreach ($PossibleMatch in $AllPossibleMatches) {
            $AllSpecialFolderObjects | Where-Object {$_.ExpandedPath -eq [environment]::GetFolderPath($PossibleMatch)}
        }
    }
    else {
        Write-Error "Unable to find a Special Folder with the name $SpecialFolderName! Halting!"
        $global:FunctionResult = "1"
        return
    }
}









# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdpZ7ZFUr3WQ1xfy3GDY4pk3S
# xtmgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPnCTJbf091WmfF4
# 8dnUl290ekhiMA0GCSqGSIb3DQEBAQUABIIBAGu87u+b7ywOUa86UtYJTU7GwvjM
# 9gSKWIW4ZDtjqi1hhCzI5co7zImA29e68wtefA/Dpn4v3Dv6/qIE5VfGn1OQKKGG
# VooatJVUHJ4z2TmZETLCsEYw1RFBb0Q0rBuxpI0dZKvaSWzRqo0kjup6zLkt92Kr
# xbNioCCgY2ZOc+S+AN4fZbYsOuH50Yjb/252YiR491SZ3pldN1c2Y29xtlO/NIgd
# 0x5afVU5M5YjHjA0DZqMGJDuqmVU3GipLKu+KpHZns/sJlVmHN0vfu5tFv22DAiu
# slBMfJUaflxU4hnQlwtkiDDYMJOlrSdNymJfvRVUfLdN0EpqAvRDgHYh8/c=
# SIG # End signature block
