Function Send-EmailOnPublicIPChange {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $CurrentPublicIPOutFile,

        [Parameter(Mandatory=$False)]
        $cnForBasisTemplate,

        [Parameter(Mandatory=$False)]
        $CertGenWorking = $(Read-Host -Prompt "Please enter a full path to a temporary working directory for this script"),

        [Parameter(Mandatory=$False)]
        $NewTemplName = $(Read-Host -Prompt "Please enter a name for your New Certificate Template"),

        [Parameter(Mandatory=$False)]
        $IssuingCertAuth = $(Read-Host -Prompt "Please enter the name of the server that acts as your Issuing Certificate Authority.
        This name must be able to be resolved via DNS"),

        [Parameter(Mandatory=$False)]
        $AttributesFile = "BasisTemplate_Attributes.txt",

        [Parameter(Mandatory=$False)]
        $CustomExpirationPeriodInYears = $(Read-Host -Prompt "Please enter the Expiration Period for certificates generated from your New Certificate Template.
        Valid options (in years) are '1' and '2' [1,2]"),

        [Parameter(Mandatory=$False)]
        $AllowPrivateKeyExport = $(Read-Host -Prompt "Would you like to allow private keys to be exported from certificates
        generated from your New Certificate Template? [Yes,No]"),

        [Parameter(Mandatory=$False)]
        $IntendedPurposeValuesPrep,

        [Parameter(Mandatory=$False)]
        $KeyUsageValuesPrep
    )

    ##### BEGIN Variable Validation #####


    ##### END Variable Validation #####

    # Get Old Public IP
    $CurrentPublicIPOutFile = "$HOME\currentpublicip.txt"
    $OldPublicIP = Get-Content -Path $CurrentPublicIPOutFile
    Write-Host "Old Public IP is $OldPublicIP"

    # Get the Public IP string
    # IMPORTANT NOTE: http://checkip.dyndns.com only lets you check your public IP address every 3 minutes max. Otherwise they consider it abuse.
    $PublicIPPrep = Invoke-WebRequest -Uri http://checkip.dyndns.com | Select-Object -ExpandProperty Content
    $IPRegex = '\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b'
    $NewPublicIP = $PublicIPPrep | Select-String -Pattern $IPRegex | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    Write-Host "New Public IP is $NewPublicIP"

    # Write Public IP to file which will be overwritten evertime this script runs
    Set-Content -Path $CurrentPublicIPOutFile -Value $PublicIP

    #If the IP hasnt changed...
    if ($OldPublicIP -eq $NewPublicIP) {
        Write-Host "Public IP Address has NOT changed...No action taken"
        exit
    }

    # Determine if there is a drive mounted that contains a filepath that matches where EncryptedPwdFiles are kept
    $PSDrives = Get-PSDrive | Select-Object -ExpandProperty Name
    foreach ($obj1 in $PSDrives) {
        $obj2 = $obj1+':\EncryptedPwdFiles'
        if (Test-Path $obj2) {
            Write-Host "Found appropriate encrypted pwd directory under $obj1`:\"
            $EncryptedPwdFilesDirectory = $obj2
            $EncryptedPwdFileNeededForThisScript = "XXXXXXXX.txt"
        }
        else {
            Write-Host "Appropriate encrypted pwd directory was not found. Please mount the appropriate network drive"
            Write-Host "or copy the necessary encrypted pwd file to a directory with the following format:"
            Write-Host "[DriveLetter]:\EncryptedPwdFiles\"
            exit
        }
    }

    #If the IP has changed...
    if($OldPublicIP -ne $NewPublicIP){
        $Username = "[gmail username]"
        $PasswordPrep = Decrypt-EncryptedPwdFile -EncryptedPwdFileInput $EncryptedPwdFilesDirectory\$EncryptedPwdFileNeededForThisScript
        $Password = ConvertTo-SecureString $PasswordPrep -AsPlainText -Force
        # Overwrite the plaintext password in memory
        $PasswordPrep = "null"
        $Cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $Username, $Password
        $target = "[cellphone-number-only-digits]@vtext.com"
        $from = "[gmail email address]"
        $smtp = "smtp.gmail.com"
        Send-MailMessage -from $from -Subject "Public IP has changed to $NewPublicIP" -SmtpServer $smtp -Credential $cred -UseSsl -to $target -Port 587
        exit
    }
}
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUY8Wm4yGpJQXa/PgwpOQv4upI
# sJ2gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSEur9KF/At
# K3LIvwyV0Ci7ZRwhKjANBgkqhkiG9w0BAQEFAASCAQAH73eBboOlF3CBPwrE3tnB
# m44BDAFNCxhLCQHJRNp4nBsH5cwCUfLyd5McIgyxfgDfOtJ7j5wt/Vu9nLLV3aP0
# LSeM71xFH/KyYycWPELIFsgbfjELuoxQgpslrzsKX9GWaTYgKJ4ItGNiKtTj3BNv
# g8j7zjzAglNAs9oCRWzkFG7iaKQZqq2LvmPkMUrveBKano19D+6I59MOIbo0wiH1
# QW13KjB1kWxMn4liUHQPF0gfgMQ0tdbhL8AHFWSHdmvC0OrbFQd1JOE2Dz5lxyFb
# BboRzJT2Kzty4Ajxk3YcHaqNBebIL6clHeRWmQdcuCnbZJC8CXZJvdxYk/y05EDJ
# SIG # End signature block
