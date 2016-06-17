# Generate-EncryptedPwdFile Function requires Get-PfxCertificateBetter function in order to pass the certificate's password in
# Other Prerequisites: 
# 1) Must have a .pfx Certificate (tested with a .pfx that contains both public and private keys...but just public key/cert should work - but this has not been tested)
# 2) Aforementioned .pfx must be password protected at the time it was created (although this should work even if it wasn't password protected - but this has not been tested)

function Get-PfxCertificateBetter {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Position=0, Mandatory=$true, ParameterSetName='ByPath')] [string[]] $filePath,
        [Parameter(Mandatory=$true, ParameterSetName='ByLiteralPath')] [string[]] $literalPath,

        [Parameter(Position=1, ParameterSetName='ByPath')] 
        [Parameter(Position=1, ParameterSetName='ByLiteralPath')] [string] $password,

        [Parameter(Position=2, ParameterSetName='ByPath')]
        [Parameter(Position=2, ParameterSetName='ByLiteralPath')] [string] 
        [ValidateSet('DefaultKeySet','Exportable','MachineKeySet','PersistKeySet','UserKeySet','UserProtected')] $x509KeyStorageFlag = 'DefaultKeySet'
    )

    if($PsCmdlet.ParameterSetName -eq 'ByPath'){
        $literalPath = Resolve-Path $filePath 
    }

    if(!$password){
        # if the password parameter isn't present, just use the original cmdlet
        $cert = Get-PfxCertificate -literalPath $literalPath
    } else {
        # otherwise use the .NET implementation
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($literalPath, $password, $X509KeyStorageFlag)
    }

    return $cert
}

function Generate-EncryptedPwdFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $PathToCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*Scripting*"}),

        [Parameter(Mandatory=$False)]
        $FileToOutput
    )

    Process {

        $PasswordToEncryptPrep = Read-Host -Prompt 'Password to Encrypt' -AsSecureString
        $PasswordToEncrypt = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordToEncryptPrep))
        
        if ($FileToOutput -eq $null) {
            $FileToOutput = Read-Host -Prompt 'Please enter a full path and filename to output [Example: C:\encryptedpwd.txt]'
        }

        if ($PathToCertFile -ne $null) {
            if (! (Test-Path $PathToCertFile)) {
                Write-Host "The .pfx certificate file was not found at the path specified. Please check to make sure the file exists."
                $PathToCertFile = Read-Host -Prompt 'Please enter the full path to the .pfx certificate file. [Example: C:\ps_scripting.pfx]'
                if (! (Test-Path $PathToCertFile)) {
                    Write-Host "The .pfx certificate file was not found at the path specified. Halting."
                    exit
                }
            }
            if (Test-Path $PathToCertFile) {
                $PasswordPrep1 = Read-Host -Prompt 'Please enter the password for the certificate being used to encrypt the above password' -AsSecureString
                $CertFilePwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordPrep1))
                $Cert1 = Get-PfxCertificateBetter $PathToCertFile $CertFilePwd1
                $EncodedPwd1 = [system.text.encoding]::UTF8.GetBytes($PasswordToEncrypt)
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedPwd1, $true)
                $EncryptedPwd1 = [System.Convert]::ToBase64String($EncryptedBytes1)
                $EncryptedPwd1 | Out-File $FileToOutput
            }
        }

        if ($PathToCertFile -eq $null -and $PathToCertInStore -eq $null) {
            $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been `
            `n loaded in the certificate Store? [Type either File or Store]"
            if ($FileOrStoreSwitch -ne "File" -or $FileOrStoreSwitch -ne "Store") {
                Write-Host "The string entered did not match either 'File' or 'Store'. Please type either File or Store"
                $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been loaded in the certificate Store? [File,Store]"
                if ($FileOrStoreSwitch -ne "File" -or $FileOrStoreSwitch -ne "Store") {
                    Write-Host "The string entered did not match either 'File' or 'Store'. Halting."
                    exit
                }
            }
            if ($FileOrStoreSwitch -eq "File") {
                if ($PathToCertFile -eq $null) {
                    $PathToCertFile = Read-Host -Prompt 'Please enter the full path to the .pfx certificate file. [Example: C:\ps_scripting.pfx]'
                }
                if (! (Test-Path $PathToCertFile)) {
                    Write-Host "The .pfx certificate file was not found at the path specified. Please check to make sure the file exists."
                    $PathToCertFile = Read-Host -Prompt 'Please enter the full path to the .pfx certificate file. [Example: C:\ps_scripting.pfx]'
                    if (! (Test-Path $PathToCertFile)) {
                        Write-Host "The .pfx certificate file was not found at the path specified. Halting."
                        exit
                    }
                }
                if ($PathToCertFile -ne $null -and (Test-Path $PathToCertFile)) {
                    $PasswordPrep1 = Read-Host -Prompt 'Please enter the password for the certificate being used to encrypt the above password' -AsSecureString
                    $CertFilePwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordPrep1))
                    $Cert1 = Get-PfxCertificateBetter $PathToCertFile $CertFilePwd1
                    $EncodedPwd1 = [system.text.encoding]::UTF8.GetBytes($PasswordToEncrypt)
                    $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedPwd1, $true)
                    $EncryptedPwd1 = [System.Convert]::ToBase64String($EncryptedBytes1)
                    $EncryptedPwd1 | Out-File $FileToOutput
                }
            }
            if ($FileOrStoreSwitch -eq "Store") {
                if ($PathToCertInStore -eq $null) {
                    Write-Host "Please ensure that a certificate with the word 'Scripting' somewhere in the Subject exists in the Certificate Store under Cert:\CurrentUser\My and try again."
                    Write-Host "...or please select 'File' and use a certificate file in .pfx format"
                    exit
                }
                if ($PathToCertInStore -ne $null) {
                    $Cert = $PathToCertInStore
                    $EncodedPwd = [system.text.encoding]::UTF8.GetBytes($PasswordToEncrypt)
                    $EncryptedBytes = $Cert.PublicKey.Key.Encrypt($EncodedPwd, $true)
                    $EncryptedPwd = [System.Convert]::ToBase64String($EncryptedBytes)
                    $EncryptedPwd | Out-File $FileToOutput
                }
            }  
        }

        if ($PathToCertFile -eq $null -and $PathToCertInStore -ne $null) {
            $Cert = $PathToCertInStore
            $EncodedPwd = [system.text.encoding]::UTF8.GetBytes($PasswordToEncrypt)
            $EncryptedBytes = $Cert.PublicKey.Key.Encrypt($EncodedPwd, $true)
            $EncryptedPwd = [System.Convert]::ToBase64String($EncryptedBytes)
            $EncryptedPwd | Out-File $FileToOutput
        }
    }
}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUz02UGexU6BB2Qw8p/Nuz+u5Z
# SQCgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSPproefOIV
# GyKpRtPRH0SLlc8kMzANBgkqhkiG9w0BAQEFAASCAQAnM3qBvEG3hRDx9E+m2ZV5
# 25s4q1zm90n6kBHM625jRyBDMPT8QkfUZmjNwmcSiOsmSGESDAsxKlQiQM4WeKqz
# Jg7pR3SlHx/XnGTIh/2oqPtsQfI+dmb7m1TGD211ycTO2Cy1zC4g+3UBuLIEbXA3
# rwjbx87gK4pNEEsqkm7e+hxSFqveCmtgwd5LkZeffP+elXENBzhOP7A63kk1EBlY
# hXzNZMJXX+nWzVjlRTQiEk2RZ1ikC0KvIIBTBhL6lMIW3YNLx4A2eIfOhxb3pwQ2
# K0lAnm0q6dFxDlbx6Mta/X/IKYRTbKAuZBIVVRqFJbp5nzHbqOOHoKRG/26bbQWF
# SIG # End signature block
