Function Generate-RandomString() {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$length = $(Read-Host -Prompt "Please enter the number of characters you would like the string to be"),

        [Parameter(Mandatory=$False)]
        $NumbersAndLettersOnly,

        [Parameter(Mandatory=$False)]
        $LimitSpecialCharsToNumberRowOnKeyBoard
    )

    # Make sure only ONE of the parameters $NumbersAndLettersOnly OR $LimitSpecialCharsToNumberRowOnKeyBoard is used...
    if ($NumbersAndLettersOnly -ne $null -and $LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
        Write-Host "Please only use EITHER the NumbersAndLettersOnly paramter OR the LimitSpecialCharsToNumberRowOnKeyBoard parameter. Halting!"
        return
    }

    # Validate $NumbersAndLettersOnly if it is used...
    if ($NumbersAndLettersOnly -ne $null) {
        if (! ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y" -or $NumbersAndLettersOnly -eq "No" -or $NumbersAndLettersOnly -eq "n") ) {
            Write-Host "The value $NumbersAndLettersOnly is not valid for the parameter NumbersAndLettersOnly. Please enter either 'Yes' or 'No'"
            $NumbersAndLettersOnly = Read-Host -Prompt "Would you like to limit the string to ONLY numbers and letters? [Yes/No]"
            if (! ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y" -or $NumbersAndLettersOnly -eq "No" -or $NumbersAndLettersOnly -eq "n") ) {
                Write-Host "The value $NumbersAndLettersOnly is not valid for the parameter NumbersAndLettersOnly. Please enter either 'Yes' or 'No'. Halting!"
                return
            }
        }
    }

    # Validate $LimitSpecialCharsToNumberRowOnKeyBoard if it is used...
    if ($LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
        if (! ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y" `
        -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "No" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "n") ) {
            Write-Host "The value $LimitSpecialCharsToNumberRowOnKeyBoard is not valid for the parameter LimitSpecialCharsToNumberRowOnKeyBoard. Please enter either 'Yes' or 'No'"
            $LimitSpecialCharsToNumberRowOnKeyBoard = Read-Host -Prompt "Would you like to limit special characters those available on the number row of keys on your keyboard? [Yes/No]"
            if (! ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y" `
            -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "No" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "n") ) {
                Write-Host "The value $LimitSpecialCharsToNumberRowOnKeyBoard is not valid for the parameter LimitSpecialCharsToNumberRowOnKeyBoard. Halting!"
                return
            }
        }
    }


    $ascii = $NULL;For ($a=33;$a –le 126;$a++) {$ascii+=,[char][byte]$a }

    if ($NumbersAndLettersOnly -ne $null) {
        if ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y") {
            $ascii = $($ascii | Select-String -Pattern '[\w]').Matches.Value
        }
    }

    if ($LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
        if ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y") {
            $ascii = $($ascii | Select-String -Pattern '([\w])|(!)|(@)|(#)|(%)|(\^)|(&)|(\*)|(\()|(\))|(-)|(=)|(\+)').Matches.Value
        }
    }

    For ($loop=1; $loop –le $length; $loop++) {
        $TempString+=($ascii | Get-Random)
    }

    Write-Output $TempString
}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsd0Gf+zBssUu28+MY5YIihSD
# 4y+gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRpPNqoFH8L
# IadRTPu1w2SFrQRnHDANBgkqhkiG9w0BAQEFAASCAQBDeH5naSfyC8TGPyfc8nnD
# bS7L1hmPi/GYWPDjqcBR1Uh/hTJnagUTdMDktbRKNmV/I5v+pVBeO73C8wpnPaWE
# hzBONjf/FlGPPjo4gbMVNYmJUhqer3n9BDrjZzEWFQQsrTPQ+8b7gQg/VOlMBptF
# ouQ5Q5d9RCQ5Cw8webABm1+K5nUz36VxZVr4qtA6HWPZYGEf2jopm08FVxxzZwkk
# OW6FVbSMhd5BiQfXwyRK81Ea0uRNg+jFGPXzrkaW16xiNPkHtE8Uf+iT3+QPdvb7
# CuyTpV1iWa+Gf/WL4obAM7ureb/9EfajTO6qbDcCU7LOHqcwPBWb2sKka4/AGhL/
# SIG # End signature block
