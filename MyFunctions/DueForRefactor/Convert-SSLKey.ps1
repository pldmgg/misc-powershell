<#
.SYNOPSIS
    This function/script is a Swiss-Army Knife for SSL key conversion/creation.
     
    Using an existing unencrypted RSA private key, it can generate the following outputs:
        1) A PPK file (contains both public and private key information) for use with PuTTY/Pageant
            - file extension = .ppk
            - file format = UTF-8
        2) A Public Key in OpenSSH Format to be used in ~/.ssh/authorized_keys on Linux hosts
            - file extention: .pub
            - file format: UTF-8
        3) A Public Key in RFC4716 (also known as SSH2) format
            - file extention: .pub
            - file format: UTF-16 LE with BOM
        4) A Public Key in PKCS8 format
            - file extention: .pub
            - file format: UTF-16 LE with BOM
        5) A Public Key in PEM format
            - file extention: .pub
            - file format: UTF-16 LE with BOM
        6) A Self-Signed Certificate (public certificate)
            - file extension: .crt
            - file format: UTF-8

.DESCRIPTION

.DEPENDENCIES
    Depending on the value that you choose for $KeyOutputFormat (i.e. Putty,AuthKeys,SSH2,PKCS8,PEM, or SelfSignedCert), you will need one or more
    of the following binaries:

    1) Win32-OpenSSH - https://github.com/PowerShell/Win32-OpenSSH/releases
    2) WinSCP ***Version 5.9 or Higher*** - https://winscp.net/eng/download.php
    3) Pageant - http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html
    4) Win32 OpenSSL - https://indy.fulgan.com/SSL/

.PARAMETERS
    1) [MANDATORY] $OutputDirectory - The full path to the directory where all output files will be written

    2) [MANDATORY] $KeyOutputFormat - The desired format for the output. Options are: Putty, AuthKeys, SSH2, PKCS8, PEM, SelfSignedCert

    3) $PathToWin32OpenSSH - The full path to the directory that contains Win32-OpenSSH. If $KeyOutputFormat is set to AuthKeys, SSH2, PKCS8, or PEM,
    then, this parameter is MANDATORY.

    4) $PathToWinSCP - The full path to the directory that contains WinSCP (must be version 5.9 or higher). If $KeyOutputFormat is set to Putty,
    then, this parameter is MANDATORY.

    5) $PathToPageant - The full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY). If $KeyOutputFormat is set to Putty,
    then, this parameter is MANDATORY.

    6) $PathToWin32OpenSSL - The full path to the directory that contains Win32 OpenSSL. If $KeyOutputFormat is set to SelfSignedCert,
    then, this parameter is MANDATORY.

    7) $PathToPrivateKey - The full path to the existing unencrypted private key file

    ##### The following parameters are only mandatory if $KeyOutputFormat is set to SelfSignedCert #####

    8) $Company - Name of the Organization to be written to the new self-signed certificate

    9) $Department - Name of the Organization Unit to be written to the new self-signed certificate

    10) $EmailAddress - Email Address to be written to the new self-signed certificate

    11) $City - City in which your Organization is located to be written to the new self-signed certificate 

    12) $State - State in which your Organization is located to be written to the new self-signed certificate

    13) $Country - Country in which your Organization is located to be written to the new self-signed certificate

    14) $CommonName - The Common Name for your new self-signed certificate

    15) $OpenSSLCertConfFile - The configuration file used to generate your new self-signed certificate

.EXAMPLE
    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "Putty" `
    -PathToWinSCP "C:\Program Files (x86)\WinSCP" `
    -PathToPageant "C:\Program Files (x86)\PuTTY"

    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "AuthKeys" `
    -PathToWin32OpenSSH "C:\openssh-win32-build-5-30-16"

    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "SSH2" `
    -PathToWin32OpenSSH "C:\openssh-win32-build-5-30-16"

    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "PKCS8" `
    -PathToWin32OpenSSH "C:\openssh-win32-build-5-30-16"

    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "PEM" `
    -PathToWin32OpenSSH "C:\openssh-win32-build-5-30-16"

    Convert-SSLKey `
    -OutputDirectory "C:\Users\testadmin\.aws" `
    -PathToPrivateKey "C:\Users\testadmin\.aws\testing-primary-ssh-key.pem" `
    -KeyOutputFormat "SelfSignedCert" `
    -PathToWin32OpenSSL "C:\openssl-1.0.2h-i386-win32"
    -Company "Fictional Company" `
    -Department "DevOps" `
    -EmailAddress "null@null.null" `
    -City "Portland" `
    -State "Oregon" `
    -Country "US" `
    -CommonName "MySelfSignedCert" `
    -OpenSSLCertConfFile "openssl.conf"

.INPUTS
    1) Private Key file (usual file extension is .pem) with content in format that resembles the following:
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----

.OUTPUTS
    *One* of the following outputs is provided depending on parameters provided:

    1) A PPK file that contains both public and private key information for for use with PuTTY/Pageant
            - file extension = .ppk
            - file format = UTF-8
    2) A Public Key in OpenSSH Format to be used in ~/.ssh/authorized_keys on Linux hosts
        - file extention: .pub
        - file format: UTF-8
    3) A Public Key in RFC4716 (also known as SSH2) format
        - file extention: .pub
        - file format: UTF-16 LE with BOM
    4) A Public Key in PKCS8 format
        - file extention: .pub
        - file format: UTF-16 LE with BOM
    5) A Public Key in PEM format
        - file extention: .pub
        - file format: UTF-16 LE with BOM
    6) A Self-Signed Certificate (public certificate)
        - file extension: .crt
        - file format: UTF-8

#>

function Convert-SSLKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $OutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        $PathToWin32OpenSSH,

        [Parameter(Mandatory=$False)]
        $PathToWinSCP,

        [Parameter(Mandatory=$False)]
        $PathToPageant,

        [Parameter(Mandatory=$False)]
        $PathToPrivateKey = $(Read-Host -Prompt "Please enter the full path to the Private Key that will be used for the conversion(s)"),

        [Parameter(Mandatory=$True)]
        [ValidateSet('Putty','AuthKeys','SSH2','PKCS8','PEM','SelfSignedCert')]
        $KeyOutputFormat,

        [Parameter(Mandatory=$False)]
        $PathToWin32OpenSSL,

        [Parameter(Mandatory=$False)]
        $Company,

        [Parameter(Mandatory=$False)]
        $Department,

        [Parameter(Mandatory=$False)]
        $EmailAddress,

        [Parameter(Mandatory=$False)]
        $City,

        [Parameter(Mandatory=$False)]
        $State,

        [Parameter(Mandatory=$False)]
        $Country,

        [Parameter(Mandatory=$False)]
        $CommonName,

        [Parameter(Mandatory=$False)]
        $OpenSSLCertConfFile = "openssl.conf"

    )

    ##### BEGIN Validation #####

    # Validate $OutputDirectory...
    if (Test-Path $OutputDirectory) {
        Write-Host "$OutputDirectory is a valid directory. Continuing..."
    }
    else {
        Write-Host "$OutputDirectory cannot be found."
        $OutputDirectory = Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"
        if (Test-Path $OutputDirectory) {
            Write-Host "$OutputDirectory is a valid directory. Continuing..."
        }
        else {
            Write-Host "$OutputDirectory cannot be found. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Validate WinSCP and Putty Directories...
    if ($KeyOutputFormat -eq "Putty") {
        if ($PathToPageant -eq $null) {
            $PathToPageant = Read-Host -Prompt "Please enter the full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY)"
        }
        if ($PathToPageant -ne $null) {
            if (Test-Path $PathToPageant) {
                Write-Host "$PathToPageant is a valid directory. Continuing..."
            }
            else {
                Write-Host "$PathToPageant cannot be found."
                $PathToPageant = Read-Host -Prompt "Please enter the full path to the directory that contains Pageant (most likely in C:\Program Files (x86)\PuTTY)"
                if (Test-Path $PathToPageant) {
                    Write-Host "$PathToPageant is a valid directory. Continuing..."
                }
                else {
                    Write-Host "$PathToPageant cannot be found. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($PathToWinSCP -eq $null) {
            $PathToWinSCP = Read-Host -Prompt "Please enter the full path to the directory that contains WinSCP (must be version 5.9 or higher)"
        }
        if ($PathToWinSCP -ne $null) {
            if (Test-Path $PathToWinSCP) {
                Write-Host "$PathToWinSCP is a valid directory. Continuing..."
            }
            else {
                Write-Host "$PathToWinSCP cannot be found."
                $PathToWinSCP = Read-Host -Prompt "Please enter the full path to the directory that contains WinSCP (must be version 5.9 or higher)"
                if (Test-Path $PathToWinSCP) {
                    Write-Host "$PathToWinSCP is a valid directory. Continuing..."
                }
                else {
                    Write-Host "$PathToWinSCP cannot be found. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    # Validate Win32 OpenSSH Directory...
    if ($KeyOutputFormat -eq "AuthKeys" -or $KeyOutputFormat -eq "SSH2" -or $KeyOutputFormat -eq "PKCS8" -or $KeyOutputFormat -eq "PEM") {
        if ($PathToWin32OpenSSH -eq $null) {
            $PathToWin32OpenSSH = Read-Host -Prompt "Please enter the full path to the directory that contains Win32-OpenSSH"
        }
        if ($PathToWin32OpenSSH -ne $null) {
            if (Test-Path $PathToWin32OpenSSH) {
                Write-Host "$PathToWin32OpenSSH is a valid directory. Continuing..."
            }
            else {
                Write-Host "$PathToWin32OpenSSH cannot be found."
                $PathToWin32OpenSSH = Read-Host -Prompt "Please enter the full path to the directory that contains Win32-OpenSSH"
                if (Test-Path $PathToWin32OpenSSH) {
                    Write-Host "$PathToWin32OpenSSH is a valid directory. Continuing..."
                }
                else {
                    Write-Host "$PathToWin32OpenSSH cannot be found. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
    
    # Validate additional parameters for SelfSignedCert...
    if ($KeyOutputFormat -eq "SelfSignedCert") {
        # Validate $PathToWin32OpenSSL
        if (Test-Path $PathToWin32OpenSSL) {
            Write-Host "$PathToWin32OpenSSL is a valid directory. Continuing..."
        }
        else {
            Write-Host "$PathToWin32OpenSSL cannot be found."
            $PathToWin32OpenSSL = Read-Host -Prompt "Please enter a valid path to a directory."
            if (Test-Path $PathToWin32OpenSSL) {
                Write-Host "$PathToWin32OpenSSL is a valid directory. Continuing..."
            }
            else {
                Write-Host "$PathToWin32OpenSSL cannot be found. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # Validate Company, Department, EmailAddress, City, State, Country, and CommonName...
        if ($Company -eq $null) {
            $Company = Read-Host -Prompt "Please enter the name of the Organization to be written to the self-signed certificate"
        } 
        if ($Department -eq $null) {
            $Department = Read-Host -Prompt "Please enter the name of the Department to be written to the self-signed certificate"
        }
        if ($EmailAddress -eq $null) {
            $EmailAddress = Read-Host -Prompt "Please enter the Email Address to be written to the self-signed certificate"
        }
        if ($City -eq $null) {
            $City = Read-Host -Prompt "Please enter the City in which your organization is located"
        }
        if ($State -eq $null) {
            $State = Read-Host -Prompt "Please enter the State in which your organization is located"
        }
        if ($Country -eq $null) {
            $Country = Read-Host -Prompt "Please enter the Country in which your organization is located"
        }
        if ($CommonName -eq $null) {
            $CommonName = Read-Host -Prompt "Please enter a Common Name for your new self-signed certificate"
        }
    }

    # Validate $PathToPrivateKey...
    if (Test-Path $PathToPrivateKey) {
            Write-Host "The path to $PathToPrivateKey is valid. Continuing..."
    }
    else {
        Write-Host "$PathToPrivateKey cannot be found."
        $PathToPrivateKey = Read-Host -Prompt "Please enter a valid path to a file."
        if (Test-Path $PathToPrivateKey) {
            Write-Host "The path to $PathToPrivateKey is valid directory. Continuing..."
        }
        else {
            Write-Host "$PathToPrivateKey cannot be found. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Validation #####

    ##### BEGIN Variable Transforms #####

    $position = $PathToPrivateKey.LastIndexOf("\")
    $PathToPrivateKeyDirectory = $PathToPrivateKey.Substring(0, $position)
    $PathToPrivateKeyFile = $PathToPrivateKey.Substring($position+1)
    if ($($($PathToPrivateKeyFile | Select-String -Pattern "-key\.[\w]{1,5}").Matches.Success)) {
        $PrivateKeyName = $PathToPrivateKeyFile -replace "-key\.[\w]{1,5}", ""
    }
    elseif ($($($PathToPrivateKeyFile | Select-String -Pattern "\.[\w]{1,5}").Matches.Success)) {
        $PrivateKeyName = $PathToPrivateKeyFile -replace "\.[\w]{1,5}", ""
    }
    elseif ($($($PathToPrivateKeyFile | Select-String -Pattern "\.").Matches.Success) -ne "True") {
        $PrivateKeyName = $PathToPrivateKeyFile
    }

    ##### END Variable Transforms #####

    ##### BEGIN Main Body #####

    if ($KeyOutputFormat -eq "Putty") {
        # Generate private-key.ppk for use with PuTTY/Pageant
        # This is the same as launching the PuttyGen GUI, clicking "Load", selecting private-key.pem, and clicking "Save private key" button
        & "$PathToWinSCP\WinSCP.com" /keygen "$PathToPrivateKey" /output="$OutputDirectory\$PrivateKeyName-key.ppk" /comment="$PrivateKeyName"
        # Start Pageant and Add the new .ppk key to the list of available keys. If Pageant is already running, it will simply add the key.
        & "$PathToPageant\pageant.exe" "$OutputDirectory\$PrivateKeyName-key.ppk"
    }

    if ($KeyOutputFormat -eq "AuthKeys") {
        # Generate a public key in OpenSSH Format to be used in ~/.ssh/authorized_keys on Linux
        & "$PathToWin32OpenSSH\ssh-keygen" -y -f "$PathToPrivateKey" > "$OutputDirectory\$PrivateKeyName-openssh-authorized-keys-format.pub"
        # Add a comment at the end of the above OpenSSH public key to help keep track of it in the future
        $PubKeyInOpenSSHFormatFinal = $(Get-Content "$OutputDirectory\$PrivateKeyName-openssh-authorized-keys-format.pub" -Encoding Ascii)+" $PrivateKeyName"
        Set-Content -Path "$OutputDirectory\$PrivateKeyName-openssh-authorized-keys-format.pub" -Value $PubKeyInOpenSSHFormatFinal
    }

    if ($KeyOutputFormat -eq "SSH2") {
        # Generate a public key in RFC4716 aka SSH2 format
        # This is the same as using the PuttyGen GUI to generate a public key by clicking "Load", selecting the private key file, and 
        # clicking the "Save public key" button
        & "$PathToWin32OpenSSH\ssh-keygen" -e -m RFC4716 -f "$PathToPrivateKey" > "$OutputDirectory\$PrivateKeyName-openssh-RFC4716-SSH2-format.pub"
    }

    if ($KeyOutputFormat -eq "PKCS8") {
        # Generate a public key in PKCS8 format
        & "$PathToWin32OpenSSH\ssh-keygen" -e -m PKCS8 -f "$PathToPrivateKey" > "$OutputDirectory\$PrivateKeyName-openssh-PKCS8-format.pub"
        # NOTE: The above is the same as the below command from Win32 OpenSSL, which can be downloaded from - https://indy.fulgan.com/SSL/:
        #& "$PathToWin32OpenSSL\openssl" rsa -in "$PathToPrivateKey" -pubout > "$OutputDirectory\$PrivateKeyName-openssl-PKCS8-format.pub"
    }

    if ($KeyOutputFormat -eq "PEM") {
        # Generate a public key in PEM format
        & "$PathToWin32OpenSSH\ssh-keygen" -e -m PEM -f "$PathToPrivateKey" > "$OutputDirectory\$PrivateKeyName-openssh-PEM-format.pub"
    }

    if ($KeyOutputFormat -eq "SelfSignedCert") {
        # Generate a self-signed Public Certificate
        $OpenSSLCertConfContent = 
@"
[CA_default]
copy_extensions = copy

[req]
default_bits                            = 4096
default_keyfile                         = generic.key
default_md                              = sha256
x509_extensions                         = v3_ca
req_extensions                          = v3_req
distinguished_name                      = req_distinguished_name

[req_distinguished_name]
0.organizationName                      = Organization Name (company)
organizationalUnitName                  = Organizational Unit Name (department, division)
emailAddress                            = Email Address
emailAddress_max                        = 40
localityName                            = Locality Name (city, district)
stateOrProvinceName                     = State or Province Name (full name)
countryName                             = Country Name (2 letter code)
countryName_min                         = 2
countryName_max                         = 2
commonName                              = Common Name (hostname, IP, or your name)
commonName_max                          = 64

0.organizationName_default              = $Company
organizationalUnitName_default          = $Department
emailAddress_default                    = $EmailAddress
localityName_default                    = $City
stateOrProvinceName_default             = $State
countryName_default                     = $Country
commonName_default                      = $CommonName

[v3_req]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth

[v3_ca]
basicConstraints = CA:TRUE
extendedKeyUsage = serverAuth
"@

        Set-Content -Value $OpenSSLCertConfContent -Path "$OutputDirectory\$OpenSSLCertConfFile"
        & "$PathToWin32OpenSSL\openssl" req -x509 -days 365 -new -key "$PathToPrivateKey" -out "$OutputDirectory\$PrivateKeyName-key.crt" -config "$OutputDirectory\$OpenSSLCertConfFile"
    }

    ##### END Main Body #####

    $global:FunctionResult = "0"
}
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpy7puIj2mKEh37KTcnINa+GZ
# pG6gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSWGWt9eefx
# sU8n9P40TJa1UT7T0TANBgkqhkiG9w0BAQEFAASCAQAfxFTau2BBgXjazgyuvUUu
# 9sAeIZcgY3dUDyWhifYP//6e0v5m0aOjh48KWzIVZ9IW3KZJ01Pcui9RsoLRMUJz
# Mp5Q0SpBxLDBjZlw0BZftNmyeOrlRhRTwV+t0uMSeCXaKZpVmbsR5A/RieDs48Qa
# eES0UcFD9uMBFyz8nuiOwB3zg8eCx+sl28uWVSRCj8pfGjXspa+m6jjsDz2u9sPe
# xxCa1z+Yty1gu5HzmwMFqeQpQeOFRIr5KqSovzESwrfco8Jxhqr89160LXuuY3us
# 3yRaQSfViy4mQklvzySKn2m1qXEqn55SJKtmd3nb8x5BW7uTm3BOb1jGx6I6wP9o
# SIG # End signature block
