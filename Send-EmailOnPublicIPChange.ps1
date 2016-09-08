<#
.SYNOPSIS
    This function/script sends an email notification via Gmail to the Verizon SMS Forwarding service in order to provide a text message alert
    when your Public IP Address changes. 

.DESCRIPTION
    
.DEPENDENCIES
    This function/script requires that there be an existing file that contains your encrypted gmail password. This file should be generated
    using the Generate-EncryptedPwdFile.ps1 script/function located here...
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1

    ...and it needs to be decrypted by the Decrypt-EncryptedPwdFile.ps1 script/function which must be placed in the $HelperFunctionSourceDirectory.
    Get the Decrypt-EncryptedPwdFile.ps1 script/function here: 
    https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1

.PARAMETERS
    1) [MANDATORY] $HelperFunctionSourceDirectory - The full path to the directory that contains the Decrypt-EncryptedPwdFile.ps1 script/function

    2) [MANDATORY] $OutputDirectory - The full path to the directory where $CurrentPublicIPFile will be written

    3) [MANDATORY] $CurrentPublicIPFile - The name of the file that contains your current/old/new Public IP Address (Default: currentpublicip.txt)

    4) [MANDATORY] $URLThatReturnsPublicIP - The URL that returns your Public IP (Default: http://checkip.dyndns.com)

    5) [MANDATORY] $GmailUserName - The username for the Gmail Account you are using to send an email to the Cell Provider SMS forwarding service email address.

    6) [MANDATORY] $SMTPConnection - The smtp connection to gmail. (Default: smtp.gmail.com)

    7) [MANDATORY] $EncryptedPwdFile - The file that contains your encrypted Gmail App Password. Should be generated initially by using the
    Generate-EncryptedPwdFile.ps1 script/funtion located here: https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1

    8) $CNofCertInStoreToDecryptPwdFile and $PathToCertFileToDecryptPwdFile - One of these two parameters is MANDATORY. 
    
    If the certificate used to create your $EncryptedPwdFile is available in your local Certificate Store under Cert:\CurrentUser\My, 
    then set the $CNofCertInStoreToDecryptPwdFile parameter to the CN of the certificate. For example, given the following content of your
    local Certificate Store...
    PS Cert:\CurrentUser\My\> Get-ChildItem

        Directory: Microsoft.PowerShell.Security\Certificate::CurrentUser\My

    Thumbprint                                Subject
    ----------                                -------
    03AF099180F1F37DE3C498476784CDEB60128659  CN=PowerShell_Scripting, L=Portland, S=OR, C=US
    
    ...you would set the $CNofCertInStoreToDecryptPwdFile parameter to "PowerShell_Scripting"

    If the certificate used to create your $EncryptedPwdFile is available as a .pfx file on your Windows filesystem, then set the 
    $PathToCertFileToDecryptPwdFile parameter to the full file path. For example: C:\EncryptedPwdFiles\PowerShell_Scripting.pfx

    9) [MANDATORY] $PhoneNumberToReceiveText - The phone number you would like the text message sent to

    10) [MANDATORY] $CellProvider - The Cell Provider for your phone. Choose either Verizon, ATT, T-Mobile, or Sprint

.EXAMPLE
    Send-EmailOnPublicIPChange `
    -HelperFunctionSourceDirectory "C:\powershell\HelperFunctions" `
    -OutputDirectory "C:\powershell\RecurringTasks\Outputs" `
    -URLThatReturnsPublicIP "http://checkip.dyndns.com" `
    -GmailUserName "gmailusername" `
    -CNofCertInStoreToDecryptPwdFile "PowerShell_Scripting" `
    -SMTPConnection "smtp.gmail.com" `
    -EncryptedPwdFile "C:\powershell\EncryptedPwdFiles\gmailpwd.txt" `
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
        $HelperFunctionSourceDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that contains the Decrypt-EncryptedPwdFile.ps1 script/function"),

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
        $CNofCertInStoreToDecryptPwdFile,

        [Parameter(Mandatory=$False)]
        $PathToCertFileToDecryptPwdFile,

        [Parameter(Mandatory=$False)]
        $PhoneNumberToReceiveText = $(Read-Host -Prompt "Please enter the Phone Number (without dashes) that will receive the SMS text message"),

        [Parameter(Mandatory=$True)]
        [ValidateSet('Verizon','T-Mobile','ATT','Sprint')]
        $CellProvider

    )

    ##### BEGIN Variable Validation #####

    # Validate Directories...
    $DirectoryValidationArray = @("$OutputDirectory","$HelperFunctionSourceDirectory")
    foreach ($obj1 in $DirectoryValidationArray) {
        if (Test-Path $obj1) {
            Write-Host "$obj1 is a valid directory. Continuing..."
        }
        else {
            Write-Host "$obj1 cannot be found."
            $obj1 = Read-Host -Prompt "Please enter a valid path to a directory."
            if (Test-Path $obj1) {
                Write-Host "$obj1 is a valid directory. Continuing..."
            }
            else {
                Write-Host "$obj1 cannot be found. Halting!"
                return
            }
        }
    }

    ##### END Variable Validation #####

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
    if (Test-Path "$OutputDirectory\$CurrentPublicIPFile") {
        $OutputPath = "$OutputDirectory\$CurrentPublicIPFile"
        $OldPublicIP = Get-Content -Path $OutputPath
        Write-Host "Old Public IP is $OldPublicIP"
    }
    else {
        $OutputPath = "$OutputDirectory\$CurrentPublicIPFile"
        Set-Content -Path $OutputPath -Value "First Run"
    }

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
        if ($CNofCertInStoreToDecryptPwdFile -ne $null -and $PathToCertFileToDecryptPwdFile -eq $null) {
            $PasswordPrep = Decrypt-EncryptedPwdFile -EncryptedPwdFileInput $EncryptedPwdFile -CNofCertInStore $CNofCertInStoreToDecryptPwdFile
        }
        if ($CNofCertInStoreToDecryptPwdFile -eq $null -and $PathToCertFileToDecryptPwdFile -ne $null) {
            $PasswordPrep = Decrypt-EncryptedPwdFile -EncryptedPwdFileInput $EncryptedPwdFile -PathToCertFile $PathToCertFileToDecryptPwdFile
        }
        if ($CNofCertInStoreToDecryptPwdFile -eq $null -and $PathToCertFileToDecryptPwdFile -eq $null) {
            $PasswordPrep = Decrypt-EncryptedPwdFile -EncryptedPwdFileInput $EncryptedPwdFile
        }
        $Password = ConvertTo-SecureString $PasswordPrep -AsPlainText -Force
        # Overwrite the plaintext password in memory
        $PasswordPrep = "null"
        $Cred = New-Object -TypeName System.Management.Automation.PSCredential -Argumentlist $GmailUsername, $Password
        Send-MailMessage -from $GmailSenderAddress -Subject "Public IP has changed to $NewPublicIP" -SmtpServer $SMTPConnection `
        -Credential $cred -UseSsl -to $CellProviderEmailAddress -Port 587
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+IHk4JKwQCMVt0Y5sy+w9Y/T
# dTugggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSI4tG1Qxfj
# HJrPBVfZ/wBMyFyV7TANBgkqhkiG9w0BAQEFAASCAQBW/GMJnRWvVhJDIVZu+BPR
# pANBq8TMwikb35ttoP9YcPsLW/EDL2nFZJkinZqczbMWriWsdD3TJs5/4fyHC5ta
# Hxc7PTQQrZYjGDuCYSy8pSQINeDd9GxunCuz/aa1e5LJXD31q1kle+oZJoHzOoVH
# PsvQOFpU+RJu+itzaICOs4Q2Ep84ruLdU0KSv1IgqllBDg0nhgiqHdUhd+WR+32T
# Ae4vSJxo0/Mp9rbBEaMl9+eGa7ebtwGVWjF88LX+B51Ey4cQGDQ4VSq0WzVp/fgm
# +FjarqV1+enNTJ1DMiC9VZ+WHbcvH5xEUSEAMDwxbo3T7IKVIts4vRvsLrr51mrh
# SIG # End signature block
