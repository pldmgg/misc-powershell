# Depends on Python
# Wrapper for: https://github.com/miso-belica/sumy
function Summarize-Text {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$SiteUrl,

        [Parameter(Mandatory=$False)]
        [string]$FilePath,

        [Parameter(Mandatory=$False)]
        [string]$Text,

        [Parameter(Mandatory=$False)]
        [ValidateSet("luhn","edmundson","lsa","text-rank","lex-rank","sum-basic","kl")]
        [string]$SummaryAlgorithm = "sum-basic",

        [Parameter(Mandatory=$False)]
        [string]$NumberOfSentencesOrPercentage = 10,

        [Parameter(Mandatory=$False)]
        [ValidateSet("english","czech","french","german","japanese","portuguese","slovak","spanish")]
        [string]$Language = "english",

        [Parameter(Mandatory=$False)]
        [ValidateSet("html","plaintext")]
        [string]$FormatOfFile
    )

    if ($(!$SiteUrl -and !$FilePath -and !$Text) -or $($SiteUrl -and $FilePath) -or $($SiteUrl -and $Text) -or $($Text -and $FilePath)  ) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requies *either* the -SiteUrl *or* -FilePath *or* -Text parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($FormatOfFile -and !$FilePath) {
        Write-Error "You must use the -FilePath parameter with the -FormatOfFile parameter! Halting!"
        $global:FunctionResult = "1"
        return
    } 
    
    if ($SiteUrl) {
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
    }

    if (![bool]$(Get-Command sumy -ErrorAction SilentlyContinue)) {
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
            $InstallPython3result = Install-Program -ProgramName python3 -UseChocolateyCmdLine -WarningAction SilentlyContinue

            if (!$(Get-Command python -ErrorAction SilentlyContinue)) {
                throw "Unable to find 'python.exe'! Halting!"
            }

            $null = python -m pip install --upgrade pip
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        $null = pip install sumy
        $null = pip install numpy

        if (!$(Test-Path "$env:APPDATA\nltk_data")) {
            python -c "import nltk; nltk.download('punkt')"
        }
    }


    ##### BEGIN Main Body #####

    [System.Collections.ArrayList]$sumyParams = @(
        "$SummaryAlgorithm"
        "--length=$NumberOfSentencesOrPercentage"
        "--language=$Language"
    )
    if ($FormatOfFile) {
        $null = $sumyParams.Add("--format=$FormatOfFile")
    }
    if ($SiteUrl) {
        $null = $sumyParams.Add("--url=$SiteUrl")
    }
    if ($FilePath) {
        $null = $sumyParams.Add("--file=$FilePath")
    }
    if ($Text) {
        $null = $sumyParams.Add("--text=$Text")
    }

    if (![bool]$(Get-Command sumy -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find the path to 'sumy.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Run the sumy command...
    #"& `"$($(Get-Command sumy).Source)`" $($sumyParams -join `" `")"
    $FinalParams = $($sumyParams -join " ")
    Invoke-Expression "& $($(Get-Command sumy).Source) $FinalParams"
}














# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYJpCEUlrbT9mVFnzfjsbFjQP
# VWigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLo6+CHrd45/BXGa
# n7zweRZMTZ7bMA0GCSqGSIb3DQEBAQUABIIBAG6WhNKy+Ci8l2s1FeDT2gg4Z4G7
# r/hlVTscEIJ2R84CeGSA75C24PSBx73iakJ9cYb4WQPTdCmozuEsrvhVv4WOg7Xy
# qVIGrNUz0UjFVEUMasZ0jAOjLkHWcme/a0yg5F2QV9bsZDN/XRgd42fp3xra0w4t
# 4XsVRhUMIXy/PVacBwfbqpXWET2yJTuIFsLTQiA6UmOl6M39hSt2nl26o/e6c9nP
# o3ecYcsCuhbXExktfPyN0PevDwF+HtEk66bPVSYyenNCLY4zPoUByWeghD5r/2s5
# 8W++WTevqMzLvrAI2/lLdm+HCcmLz5IOZcbdIGlGbciZljMQQe9wFf3jNMw=
# SIG # End signature block
