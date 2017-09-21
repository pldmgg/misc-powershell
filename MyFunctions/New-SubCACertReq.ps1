# IMPORTANT NOTE: Run this from the Subordinate CA Server hosting the ADCS Website
$CertGenWorkingDir = "$HOME\Downloads\CertGenWorking"
if (!$(Test-Path $CertGenWorkingDir)) {
    New-Item -ItemType Directory -Name CertGenWorking -Path $($CertGenWorkingDir | Split-Path -Parent)
}
$RootCALoc = "ZeroDC01.zero.lab\ZeroDC01"
$SubCALoc = "ZeroSCA.zero.lab\ZeroSCA"
$infFile = "$CertGenWorkingDir\NewSubCAReq_Config_ZeroSCA.ZERO.LAB.inf"
$requestFile = "$CertGenWorkingDir\NewSubCAReq_ZeroSCA.ZERO.LAB.csr"
$CertFileOut = "$CertGenWorkingDir\ZeroSCA.ZERO.LAB_base64.cer"
$CertificateChain = "$CertGenWorkingDir\ZeroSCA.ZERO.LAB.p7b"

$inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=ZeroSCA.zero.lab"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
FriendlyName = "ZeroSCA"
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = "CERT_KEY_CERT_SIGN_KEY_USAGE | CERT_DIGITAL_SIGNATURE_KEY_USAGE | CERT_CRL_SIGN_KEY_USAGE"
KeyUsageProperty = "NCRYPT_ALLOW_SIGNING_FLAG"

[RequestAttributes]
CertificateTemplate = "SubCA"

[BasicConstraintsExtension]
Critical = Yes
"@

$inf | Out-File $infFile
certreq.exe -new "$infFile" "$requestFile"
Sleep -Seconds 5
$RequestID = (certreq.exe -config "$RootCALoc" -submit "$requestFile" "$CertFileOut").split('"')[2]
Sleep -Seconds 5
certreq.exe -retrieve -config $RootCALoc $RequestID $CertificateChain
Sleep -Seconds 5
certutil -config $SubCALoc -installCert $CertificateChain

Write-Host @"
# IMPORTANT NOTE: You will most likely need an updated .crl from your RootCA and/or your SubCA.
# On the RootCA and/or the SubCA, use...
#     certutil -crl
# ...which will publish a new .crl to C:\Windows\System32\CertSrv\CertEnroll. Copy the .crl file(s)
# the the following locations on your SubCA:
# C:\Windows\System32\CertSrv\CertEnroll
# C:\inetpub\wwwroot\certdata (if your Subordinate CA is running ADCS Website)
"@