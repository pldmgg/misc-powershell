function Get-WebSiteText {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SiteUrl
    )
    
    # Make sure $SiteUrl is a valid Url
    try {
        $SiteUrlAsUriObj = [uri]$SiteUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($SiteUrlAsUriObj.Scheme -match "http")) {
        Write-Error "'$SiteUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $pldmggFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if (![bool]$(Get-Command Install-Program -ErrorAction SilentlyContinue)) {
        $InstallProgramFunctionUrl = "$pldmggFunctionsUrl/Install-Program.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallProgramFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Install-Program function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    try {
        $InstallProgramSplatParams = @{
            ProgramName             = "Nuget.CommandLine"
            CommandName             = "nuget"
            UseChocolateyCmdLine    = $True
            ErrorAction             = "SilentlyContinue"
            ErrorVariable           = "IPErr"
        }

        $InstallNuGetCmdLineResult = Install-Program @InstallProgramSplatParams
        if (!$InstallNuGetCmdLineResult) {throw "The Install-Program function failed!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors for the Install-Program function are as follows:"
        Write-Error $($IPErr | Out-String)
        $global:FunctionResult = "1"
        return
    }

    if (!$(Get-Command nuget -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'nuget.exe' after Nuget.CommandLine install! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $null = nuget install htmlagilitypack

    if (!$(Test-Path "$HOME\.nuget\packages\htmlagilitypack")) {
        Write-Error "The Nuget CommandLine did not install HTML Agility Pack to '$HOME\.nuget\packages\htmlagilitypack'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if (![bool]$($CurrentlyLoadedAssemblies.FullName -match "HtmlAgilityPack")) {
        $PathToHtmlAgilityPackDLL = $(Resolve-Path "$HOME\.nuget\packages\htmlagilitypack\*\lib\net40\HtmlAgilityPack.dll").Path
        [Reflection.Assembly]::LoadFile($PathToHtmlAgilityPackDLL)
    }
    else {
        Write-Warning "HtmlAgilityPack is already loaded!"
    }
    
    $Web = [HtmlAgilityPack.HtmlWeb]::new()
    $HtmlDoc = [HtmlAgilityPack.HtmlDocument]$Web.Load($SiteUrl)
    $TextNodes = $HtmlDoc.DocumentNode.SelectNodes("//*[not(self::script or self::style)]/text()")

    $FinalTextBlob = foreach ($node in $TextNodes) {
        if ($node.InnerText -match "[\w]") {
            $node.InnerText
        }
    }

    $FinalTextBlob
}














# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURcrrd2Y64r7htPMg2lfccQ/p
# nGOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKS03U/z39sXq4qx
# cP8+drCqeSlOMA0GCSqGSIb3DQEBAQUABIIBABW1iV+DK9zrBpDCUQbregkuY1P1
# X/2yoU1pTrPoj4qVs7lA+tzeM4aQrmUnEATpxgZB/PFhbtU8k6R7TWXgAD0PRjI7
# LfMEnn/e7lBBXBr9dou7JAsTW9pUWWL2iU85YliQGSUlFFHxMH29R2vdltldGkSI
# zFZ8e7WrvrlJKlS502Qd0ZCu3HCErhHwPaanJUqQSP8401WSxomibbKnuGGxdTFx
# Mq7frRyXIkfzmDtUu4Jq3vCAz1CNX109vQKmLCvxlw8oBw/q03pamJTvjKc+u+S4
# 8w77KxOLedtMEOpg3OGs50r5c6ncUNF2hrdMjnFcD8li2yMe+69bWMwaG8o=
# SIG # End signature block
