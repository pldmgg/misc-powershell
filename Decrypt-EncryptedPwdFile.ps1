# Decrypt-EncryptedPwdFile Function requires Get-PfxCertificateBetter function in order to pass the certificate's password in

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

function Decrypt-EncryptedPwdFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $PathToCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*Scripting*"}),

        [Parameter(Mandatory=$False)]
        $EncryptedPwdFileInput
    )

    Process {
        # $PathToCertFile = R:\zero\ZeroCode.pfx

        if ($EncryptedPwdFileInput -eq $null) {
            $EncryptedPwdFileInput = Read-Host -Prompt 'Please enter the full path to the encrypted password file [Example: C:\encryptedpwd.txt]'
        }
        if (! (Test-Path $EncryptedPwdFileInput)) {
            Write-Host "Cannot find EncryptedPwdFile at the path specified. Please ensure it is present and try again"
            exit
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
                $PasswordPrep2 = Read-Host -Prompt 'Please enter the password for the certificate being used to decrypt the encrypted file' -AsSecureString
                $CertFilePwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordPrep2))
                $Cert2 = Get-PfxCertificateBetter $PathToCertFile $CertFilePwd2
                $EncryptedPwd2 = Get-Content $EncryptedPwdFileInput
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedPwd2)
                $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                $DecryptedPwd2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                $DecryptedPwd2
            }
        }

        if ($PathToCertFile -eq $null -and $PathToCertInStore -eq $null) {
            $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been `
            `nloaded in the certificate Store in order to decrypt the password? [Type either File or Store]"
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
                    $PasswordPrep2 = Read-Host -Prompt 'Please enter the password for the certificate being used to decrypt the encrypted file' -AsSecureString
                    $CertFilePwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordPrep2))
                    $Cert2 = Get-PfxCertificateBetter $PathToCertFile $CertFilePwd2
                    $EncryptedPwd2 = Get-Content $EncryptedPwdFileInput
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedPwd2)
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    $DecryptedPwd2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedPwd2
                }
            }
            if ($FileOrStoreSwitch -eq "Store") {
                if ($PathToCertInStore -eq $null) {
                    Write-Host "Please ensure that a certificate with the word 'Scripting' somewhere in the Subject exists in the Certificate Store under Cert:\CurrentUser\My and try again."
                    Write-Host "...or please select 'File' and use a certificate file in .pfx format"
                    exit
                }
                if ($PathToCertInStore -ne $null) {
                    $Cert2 = $PathToCertInStore
                    $EncryptedPwd2 = Get-Content $EncryptedPwdFileInput
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedPwd2)
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    $DecryptedPwd2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedPwd2
                }
            }  
        }

        if ($PathToCertFile -eq $null -and $PathToCertInStore -ne $null) {
            $Cert2 = $PathToCertInStore
            $EncryptedPwd2 = Get-Content $EncryptedPwdFileInput
            $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedPwd2)
            $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
            $DecryptedPwd2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
            $DecryptedPwd2
        }
    }
}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6L+qcfNrhstNQ2TrX6AEpo/g
# X06gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQVhOSSetua
# sRVdfA+thixufd7mvzANBgkqhkiG9w0BAQEFAASCAQBbjlHYrDipXvsjp0rFJH72
# YIbBPQseFw+Ak3AYpTjpEoZ5SY0oJCnUNGdNQZ+IvNuLC7DOOvOAOgNphF62hRW8
# tQl9AybSGvDBz4t6zyFXkxzPtlbFUJ9DDFxohCYpMb1Kttvce/1ygA6+cdmfLV6t
# uNTbyem0RnTPEHGYk3X+FFfkHIkYBCuolWKhGDIanPqBMrxz7/M935OSBI9hbyge
# rqlU7u1b+0XE39XgSSFvXGL+45aOuSV2J2rwfvFBMH9yxAe5gJvgW5m0qALr+gdD
# mt/S8kVCJgfIWr4Dinc+z2ipMdqU0+TjhrcDD+wQZL5C+ko71lXu4l4TbLh9rJhn
# SIG # End signature block
