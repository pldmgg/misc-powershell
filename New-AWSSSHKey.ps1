<#
.SYNOPSIS
    This function/script creates a new AWS EC2 Key to be used for SSH access from a Windows workstation to your EC2 instance(s) on AWS.
    It augments the "New-EC2KeyPair" cmdlet from the AWSPowerShell module by using the private key output to create the following:
        1) An OpenSSH formatted public key to be used in ~/.ssh/authorized_keys
        2) A .ppk key (contains both public and private keys) to be used with PuTTY / Pageant 

.DESCRIPTION

.DEPENDENCIES
    1) AWS PowerShell Tools - https://aws.amazon.com/powershell/
    2) Win32 OpenSSL - https://indy.fulgan.com/SSL/
    3) Win32-OpenSSH - https://github.com/PowerShell/Win32-OpenSSH/releases
    4) WinSCP Version 5.9 or Higher - https://winscp.net/eng/download.php

.PARAMETERS
    1) $OutputDirectory - The full path to the directory where all output files will be written

    2) $AWSIAMProfile - The AWS PowerShell Tools IAM Profile that you would like to use in order to interact with AWS.

    3) $DefaultAWSRegion - The AWS Region that your EC2 instances currently/will reside

    4) $NewEC2KeyName - The name of your new EC2 Key

    5) $PathToWin32OpenSSH - The full path to the directory that contains Win32-OpenSSH

    6) $PathToWinSCP - The full path to the directory that contains WinSCP (must be version 5.9 or higher)

    7) $PathToPageant - The full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY)

.EXAMPLE
    New-AWSSSHKey `
    -OutputDirectory "$HOME\.aws" `
    -AWSIAMProfile "testadminprofile" `
    -DefaultAWSRegion "us-east-1" `
    -NewEC2KeyName "testing-primary-ssh" `
    -PathToWin32OpenSSH "C:\openssh-win32-build-5-30-16" `
    -PathToWinSCP "C:\Program Files (x86)\WinSCP" `
    -PathToPageant "C:\Program Files (x86)\PuTTY"

.OUTPUTS
    1) PrivateKey - $OutputDirectory\$NewEC2KeyName-key.pem

    2) OpenSSHPubKey - $OutputDirectory\$NewEC2KeyName-openssh-authorized-keys-format.pub

    3) PageantKey - $OutputDirectory\$NewEC2KeyName-key.ppk

    4) $global:NewEC2SSHKeysPSObject - A Global PSObject with properties that describe where the output files are.

#>

function New-AWSSSHKey {
    [CmdletBinding()]
    Param(
        # TODO: May want to move global:Set-AWSEnvHelper function to $HelperFunctionSourceDirectory... 
        #[Parameter(Mandatory=$False)]
        #$HelperFunctionSourceDirectory,

        [Parameter(Mandatory=$False)]
        $OutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        $AWSIAMProfile = $(Read-Host -Prompt "Please enter the AWS PowerShell Tools IAM Profile that you would like to use for this session"),

        [Parameter(Mandatory=$False)]
        $DefaultAWSRegion = $(Read-Host -Prompt "Please enter the AWS Region that your EC2 instances currently/will reside"),

        [Parameter(Mandatory=$False)]
        $NewEC2KeyName = $(Read-Host -Prompt "Please enter the name of your new EC2 Key"),

        [Parameter(Mandatory=$False)]
        $PathToWin32OpenSSH = $(Read-Host -Prompt "Please enter the full path to the directory that contains Win32-OpenSSH"),

        [Parameter(Mandatory=$False)]
        $PathToWinSCP = $(Read-Host -Prompt "Please enter the full path to the directory that contains WinSCP (must be version 5.9 or higher)"),

        [Parameter(Mandatory=$False)]
        $PathToPageant = $(Read-Host -Prompt "Please enter the full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY)")

    )

    ##### BEGIN Helper Functions #####
    function global:Set-AWSEnvHelper {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            $AWSProfile,

            [Parameter(Mandatory=$False)]
            $AWSRegion
        )

        if ($($(Get-Module -ListAvailable -Name AWSPowerShell).Name | Select-String -Pattern "AWSPowerShell").Matches.Success) {
            Write-Host "The AWSPowerShell Module is already loaded. Continuing..."
        }
        else {
            Import-Module AWSPowerShell
        }

        # Validate $AWSIAMProfile parameter...
        $ValidAWSIAMProfiles = Get-AWSCredentials -ListProfiles
        if ($AWSProfile -eq $null) {
            Write-Host "Available AWS IAM Profiles under this Windows account are as follows:"
            $ValidAWSIAMProfiles
            $AWSProfile = Read-Host -Prompt "Please enter the AWS IAM Profile you would like to use in this PowerShell session."
        }
        if ($AWSProfile -ne $null) {
            if ($ValidAWSIAMProfiles -notcontains $AWSProfile) {
                Write-Host "$AWSProfile is NOT a valid AWS IAM Profile available to PowerShell under the current Windows user account. Available AWS IAM Profiles are as follows:"
                $ValidAWSIAMProfiles
                $CreateNewAWSIAMProfileSwtich = Read-Host -Prompt "Would you like to create a new AWS IAM Profile under this Windows account? [Yes/No]"
                if ($CreateNewAWSIAMProfileSwtich -eq "Yes") {
                    $AWSAccessKey = Read-Host -Prompt "Please enter the AccessKey for AWS IAM user $AWSProfile"
                    $AWSSecretKey = Read-Host -Prompt "Please enter the SecretKey for AWS IAM user $AWSProfile"
                    Set-AWSCredentials -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey -StoreAs $AWSProfile
                }
                if ($CreateNewAWSIAMProfileSwtich -eq "No") {
                    $AWSProfile = Read-Host -Prompt "Please enter the AWS IAM Profile you would like to use in this PowerShell session."
                    if ($ValidAWSIAMProfiles -notcontains $AWSProfile) {
                        Write-Host "$AWSIAMProfile is NOT a valid AWS IAM Profile available to PowerShell under the current Windows user account. Halting!"
                        return
                    }
                }
            }
        }
        
        # Validate $AWSRegion parameter...
        $ValidAWSRegions = @("eu-central-1","ap-northeast-1","ap-northeast-2","ap-south-1","sa-east-1","ap-southeast-2",`
        "ap-southeast-1","us-east-1","us-west-2","us-west-1","eu-west-1")
        if ($AWSRegion -eq $null) {
            Write-Host "You must set a default AWS Region for this PowerShell session. Valid AWS Regions are as follows:"
            $ValidAWSRegions
            $AWSRegion = Read-Host -Prompt "Please enter the default AWS Region for this PowerShell session"
        }
        if ($AWSRegion -ne $null) {
            if ($ValidAWSRegions -notcontains $AWSRegion) {
                Write-Host "$AWSRegion is not a valid AWS Region. Valid AWS Regions are as follows:"
                $ValidAWSRegions
                $AWSRegion = Read-Host -Prompt "Please enter the default AWS Region for this PowerShell session"
                if ($ValidAWSRegions -notcontains $AWSRegion) {
                    Write-Host "$AWSRegion is not a valid AWS Region. Halting!"
                    return
                }
            }
        }

        # Set the AWS IAM Profile and Default AWS Region
        $global:SetAWSCredentials = "Set-AWSCredentials -ProfileName $AWSProfile"
        $global:StoredAWSRegion = $AWSRegion

        Write-Host "Use the following command to complete setting the AWS Environment in your current scope:
        Invoke-Expression `$global:SetAWSCredentials"
    }
    # Set AWS Profile
    Set-AWSEnvHelper -AWSProfile $AWSIAMProfile -AWSRegion $DefaultAWSRegion
    Invoke-Expression $global:SetAWSCredentials

    ##### END Helper Functions #####

    ##### BEGIN Validation ######

    # Validate Directories...
    $DirectoryValidationArray = @("$OutputDirectory","$HelperFunctionSourceDirectory","$PathToWin32OpenSSH","$PathToWinSCP","$PathToPageant")
    foreach ($obj1 in $DirectoryValidationArray) {
        if (Test-Path $OutputDirectory) {
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

    ##### END Validation #####

    ##### BEGIN Main Body #####

    # Create New EC2 KeyPair and Write PRIVATE KEY to $OutputDirectory
    (New-EC2KeyPair -KeyName $NewEC2KeyName).KeyMaterial | Out-File "$OutputDirectory\$NewEC2KeyName-key.pem" -Append ascii
    # Using the above private key, generate a public key in OpenSSH Format to be used in ~/.ssh/authorized_keys using Win32-OpenSSH
    & "$PathToWin32OpenSSH\ssh-keygen" -y -f "$OutputDirectory\$NewEC2KeyName-key.pem" > "$OutputDirectory\$NewEC2KeyName-openssh-authorized-keys-format.pub"
    # Add a comment at the end of the aove OpenSSH public key to help keep track of it in the future
    $PubKeyInOpenSSHFormatFinal = $(Get-Content "$OutputDirectory\$NewEC2KeyName-openssh-authorized-keys-format.pub" -Encoding Ascii)+" $NewEC2KeyName"
    Set-Content -Path "$OutputDirectory\$NewEC2KeyName-openssh-authorized-keys-format.pub" -Value $PubKeyInOpenSSHFormatFinal
    # Convert $NewEC2KeyName-key.pem to $NewEC2KeyName-key.ppk for use with puttygen
    & "$PathToWinSCP\WinSCP.com" /keygen "$OutputDirectory\$NewEC2KeyName-key.pem" /output="$OutputDirectory\$NewEC2KeyName-key.ppk" /comment="$NewEC2KeyName"
    # Start Pageant and Add the new .ppk key to the list of available keys
    & "$PathToPageant\pageant.exe" "$OutputDirectory\$NewEC2KeyName-key.ppk"

    # Output Global PSObject with Properties representing the location of the .pem, .pub, and .ppk files
    New-Variable -Name "NewEC2SSHKeysPSObject" -Scope Global -Value $(
        New-Object PSObject -Property @{
            PrivateKey      = "$OutputDirectory\$NewEC2KeyName-key.pem"
            OpenSSHPubKey   = "$OutputDirectory\$NewEC2KeyName-openssh-authorized-keys-format.pub"
            PageantKey      = "$OutputDirectory\$NewEC2KeyName-key.ppk"
        }
    )

    Write-Host "The Global PSObject `$global:NewEC2SSHKeysPSObject is now available in the current scope"
    Write-Host "If any info in STDOUT is cutoff when calling just `$global:NewEC2SSHKeysPSObject, use '`$global:NewEC2SSHKeysPSObject | Format-List'"

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOUbCSx+G3Fvx6Bg1jC5FZeL1
# TYugggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRy1js+H/oe
# aXP/KMZOsZJNygYjbjANBgkqhkiG9w0BAQEFAASCAQAKI99fqOuFOV5HFFMex1t5
# /Z2NvLUlLRlTMAcGLP6poL4e00mYl2dgVsZb9/aV7kleC+yKfoy50l9Kft/DivlX
# cGd3rWwSEW/yzSaSX8aWkIfCVGw0DQWgpHCmO7fk8Y0BGtELNmDNWCV7c3lDdiao
# QqMXRVWZ6zsygKhYgH3+ufzV5vJ5Kmbs/VW0ObjiNhpeSLMkq1PgdZXJr+o9W+8y
# FGKInDCE3xD1U2eK52zqzttkbWQShQ7yLq/+VmMUv4nC6irh1AXUlag7ejQtUbV7
# PbgRsE2BsxV9trqQ4YXQrAvwMyuzr6nPL0wZcMiVkV8nsoxjduEZviKzmNUubtF7
# SIG # End signature block
