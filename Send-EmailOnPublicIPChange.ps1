<#
.SYNOPSIS
    This function/script sends an email notification via Gmail to the Verizon SMS Forwarding service in order to provide a text message alert
    when your Public IP Address changes. 

.DESCRIPTION
    
.DEPENDENCIES
    This function/script requires that there be an existing file that contains your encrypted gmail password. This file should be generated
    using the Generate-EncryptedPwdFile.ps1 script/function located here:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1

.PARAMETERS
    1) $OutputDirectory - The full path to the directory where all output files will be written

    2) $AWSIAMProfile - The AWS PowerShell Tools IAM Profile that you would like to use in order to interact with AWS.

    3) $DefaultAWSRegion - The AWS Region that your EC2 instances currently/will reside

    4) $NewEC2KeyName - The name of your new EC2 Key

    5) $PathToWin32OpenSSH - The full path to the directory that contains Win32-OpenSSH

    6) $PathToWinSCP - The full path to the directory that contains WinSCP (must be version 5.9 or higher)

    7) $PathToPageant - The full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY)

.EXAMPLE
    Send-EmailOnPublicIPChange `
    -HelperFunctionSourceDirectory "C:\powershell\HelperFunctions" `
    -OutputDirectory "C:\powershell\RecurringTasks\Outputs" `
    -URLThatReturnsPublicIP "http://checkip.dyndns.com" `
    -GmailUserName "gmailusername" `
    -SMTPConnection "smtp.gmail.com" `
    -EncryptedPwdFile "C:\EncryptedPwdFiles\gmailpwd.txt" `
    -PhoneNumberToReceiveText "1234567890" `
    -CellProvider "Verizon"

.OUTPUTS
    1) $CurrentPublicIPFile - If the file does not exist, this script will create it. If it exists already, this script will overwrite it.
    2) An SMS Text Message to $PhoneNumberToReceiveText 

#>

function Send-EmailOnPublicIPChange {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $HelperFunctionSourceDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that contains the Decrypt-EncryptedPwd.ps1 script/function"),

        [Parameter(Mandatory=$False)]
        $OutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        $CurrentPublicIPFile = "currentpublicip.txt",

        [Parameter(Mandatory=$False)]
        $URLThatReturnsPublicIP = "http://checkip.dyndns.com",

        [Parameter(Mandatory=$False)]
        $GmailUserName = $(Read-Host -Prompt "Please enter the gmail username that will be used to send an email to the CellProvider SMS Forwarding service"),

        [Parameter(Mandatory=$False)]
        $SMTPConnection = "smtp.gmail.com",

        [Parameter(Mandatory=$False)]
        $EncryptedPwdFile = $(Read-Host -Prompt "Please enter the full path to the file that contains your encrypted gmail password"),

        [Parameter(Mandatory=$False)]
        $PhoneNumberToReceiveText = $(Read-Host -Prompt "Please enter the Phone Number (without dashes) that will receive the SMS text message"),

        [Parameter(Mandatory=$True)]
        [ValidateSet('Verizon','T-Mobile','ATT','Sprint')]
        $CellProvider

    )

    ##### BEGIN Helper Functions #####

    # See: https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1
    . "$HelperFunctionSourceDirectory\Decrypt-EncryptedPwdFile.ps1"

    ##### END Helper Functions #####

    ##### BEGIN Variable Transforms #####

    $GmailSenderAddress = "$GmailUserName@gmail.com"

    if ($CellProvider -eq "Verizon") {
        $CellProviderEmailAddress = "$PhoneNumberToReceiveText@vtext.com"
    }
    if ($CellProvider -eq "T-Mobile") {
        $CellProviderEmailAddress = "$PhoneNumberToReceiveText@tmomail.net"
    }
    if ($CellProvider -eq "ATT") {
        $CellProviderEmailAddress = "$PhoneNumberToReceiveText@txt.att.net"
    }
    if ($CellProvider -eq "Sprint") {
        $CellProviderEmailAddress = "$PhoneNumberToReceiveText@messaging.sprintpcs.com"
    }

    ##### END variable Transforms #####

    ##### BEGIN Main Body #####

    # Get Old Public IP
    $OutputPath = "$HOME\$CurrentPublicIPFile"
    $OldPublicIP = Get-Content -Path $OutputPath
    Write-Host "Old Public IP is $OldPublicIP"

    # Get the Public IP string
    $PublicIPPrep = Invoke-WebRequest -Uri "$URLThatReturnsPublicIP" | Select-Object -ExpandProperty Content
    $IPRegex = '\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b'
    $NewPublicIP = $($PublicIPPrep | Select-String -Pattern $IPRegex).Matches.Value
    Write-Host "New Public IP is $NewPublicIP"

    # Write Public IP to file which will be overwritten evertime this script runs
    Set-Content -Path $OutputPath -Value $NewPublicIP

    #If the IP hasnt changed...
    if ($OldPublicIP -eq $NewPublicIP) {
        Write-Host "Public IP Address has NOT changed...No action taken"
        exit
    }

    #If the IP has changed...
    if($OldPublicIP -ne $NewPublicIP){
        $PasswordPrep = Decrypt-EncryptedPwdFile -EncryptedPwdFileInput $EncryptedPwdFile
        $Password = ConvertTo-SecureString $PasswordPrep -AsPlainText -Force
        # Overwrite the plaintext password in memory
        $PasswordPrep = "null"
        $Cred = New-Object -TypeName System.Management.Automation.PSCredential -Argumentlist $Username, $Password
        Send-MailMessage -from $GmailSenderAddress -Subject "Public IP has changed to $NewPublicIP" -SmtpServer $SMTPConnection `
        -Credential $cred -UseSsl -to $CellProviderEmailAddress -Port 587
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdnRzsYpln3EfY6LsVmqKCOOB
# d6GgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTNB0kQ/cuz
# FierqNdPmwImLAmKWTANBgkqhkiG9w0BAQEFAASCAQBy81u1QJg0WIUQfiCvFKv9
# 65yKytXkxDFUFIsMknX+AcAj6iNxgbQV1fqvxmNAxY2OdEWx1sRgXa3qbDdkgfcE
# a+PP006s6t7Kq/sSrkadgFde5+29uGCQ9NDDCgjL3qvWxmwMgiyrdrhlbJ2Zp0i9
# olRsGLEMD4HvyWXavncoKHZXnDXfsg3G7cHuPbqerExwW9rQsHGEY9r+CsiqOTXm
# gcpuCRTz+zugg8mQnUz1AwORXilwRpQzw/HXJSPjMI2Uop0IJ2fGX1Xp4eqDZZwg
# +pEToyVDeySVffExKUyx0FJnCQgsMor/gQSf8JZcP7maQTiPkynjqoaW9VPJ5U/O
# SIG # End signature block
