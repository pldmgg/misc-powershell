<#

.SYNOPSIS
    This script/function requests and receives a New Certificate from your Windows-based Issuing Certificate Authority.

    When used in conjunction with the Generate-CertTemplate.ps1 script/function, all needs can be satisfied.
    (See: https://github.com/pldmgg/misc-powershell/blob/master/Generate-CertTemplate.ps1)

    This can be run as a script by uncommenting the very last line calling the Generate-Certificate function, or by 
    simply loading the entire function into your current PowerShell shell and then calling it.

    IMPORTANT NOTE 1: By running the function without any parameters, the user will be walked through several prompts. 
    This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.

.DESCRIPTION
    This function/script is split into the following sections (ctl-f to jump to each of these sections)
    - Libraries and Helper Functions (~Lines 298-1395)
    - Initial Variable Definition and Validation (~Lines 1397-1760)
    - Writing the Certificate Request Config File (~Lines 1762-2169)
    - Generate Certificate Request and Submit to Issuing Certificate Authority (~Lines 2172-2284)

    .DEPENDENCIES
        OPTIONAL DEPENDENCIES
        1) RSAT (Windows Server Feature) - If you're not using the ADCS Website, then the Get-ADObject cmdlet is used for various purposes. This cmdlet
        is available only if RSAT is installed on the Windows Server.

        2) Win32 OpenSSL - If $UseOpenSSL = "Yes", the script/function depends on the latest Win32 OpenSSL binary that can be found here:
        https://indy.fulgan.com/SSL/
        Simply extract the (32-bit) zip and place the directory on your filesystem in a location to be referenced by the parameter $PathToWin32OpenSSL.

        IMPORTANT NOTE 2: The above third-party Win32 OpenSSL binary is referenced by OpenSSL.org here:
        https://wiki.openssl.org/index.php/Binaries

.PARAMETER CertGenWorking
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents a valid file path. All output files will be written to this location.

.PARAMETER BasisTemplate
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents either the CN or the displayName of the Certificate Template that you are 
    basing this New Certificate on. IMPORTANT NOTE: If you are requesting the new certificate via the ADCS Web Enrollment 
    Website the Certificate Template will ONLY appear in the Certificate Template 
    drop-down on the ADCS Web Enrollment website (which makes it a valid option for this parameter) if 
    msPKITemplateSchemaVersion is "2" or "1" AND pKIExpirationPeriod is 1 year or LESS.  See the Generate-CertTemplate.ps1
    script/function for more details here:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-CertTemplate.ps1

.PARAMETER CertificateCN
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents the name that you would like to give the New Certificate. This name will
    appear in the following locations:
        - "FriendlyName" field of the Certificate Request
        - "Friendly name" field the New Certificate itself
        - "Friendly Name" field when viewing the New Certificate in the Local Certificate Store
        - "Subject" field of the Certificate Request
        - "Subject" field on the New Certificate itself
        - "Issued To" field when viewing the New Certificate in the Local Certificate Store

.PARAMETER CertificateRequestConfigFile
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a file name to be used for the Certificate Request Configuration file 
    to be submitted to the Issuing Certificate Authority. File extension should be .inf.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER CertificateRequestFile
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a file name to be used for the Certificate Request file to be submitted
    to the Issuing Certificate Authority. File extension should be .csr.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER CertFileOut
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a file name to be used for the New Public Certificate received from the
    Issuing Certificate Authority. The file extension should be .cer.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER CertificateChainOut
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a file name to be used for the Chain of Public Certificates from 
    the New Public Certificate up to the Root Certificate Authority. File extension should be .p7b.

    IMPORTANT NOTE: File extension will be .p7b even if format is actually PKCS10 (which should have extension .p10).
    This is to ensure that Microsoft Crypto Shell Extensions recognizes the file. (Some systems do not have .p10 associated
    with Crypto Shell Extensions by default, leading to confusion).

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER PFXFileOut
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a file name to be used for the file containing both Public AND 
    Private Keys for the New Certificate. File extension should be .pfx.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER PFXPwdAsSecureString
    This parameter is OPTIONAL.

    This parameter takes one of two inputs:
    1) A string that represents a Plaintext Password; OR 
    2) A PowerShell Secure String object 
    
    Plaintext will be converted to a Secure String by the script and purged from memory.

    In order to export a .pfx file from the Local Certificate Store, a password must be supplied (or permissions based on user accounts 
    must be configured beforehand, but this is outside the scope of this script). 

    ***IMPORTANT*** This same password is applied to $ProtectedPrivateKeyOut if $UseOpenSSL = "Yes"

    ***IMPORTANT*** To avoid providing this password in plaintext on the command line, recommend using Generate-EncryptedPwdFile.ps1 and 
    Decrypt-EncryptedPwdFile.ps1 to pass this parameter. See:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1
    https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1

.PARAMETER RequestViaWebEnrollment
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. The default value is "No". If the user does not explicitly provide a value from 
    the command line, then the default value will be used.

    This parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    If this parameter is set to "No", then PowerShell cmdlets will be used that assume that the workstation 
    running this script is also joined to the same domain as the Issuing Certificate Authority. If this parameter is
    set to "Yes", then the Invoke-WebRequest cmdlet will be used to POST data to the ADCS Web Enrollment website specified
    by $ADCSWebEnrollmentUrl.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER ADCSWebEnrollmentURL
    This parameter is OPTIONAL.

    This parameter takes a string that represents a valid URL for the ADCS Web Enrollment website.
    Example: https://pki.test.lab/certsrv

.PARAMETER ADCSWebAuthType
    This parameter is OPTIONAL.

    This parameter takes one of two inputs:
    1) The string "Windows"; OR
    2) The string "Basic"

    The IIS Web Server hosting the ADCS Web Enrollment site can be configured to use Windows Authentication, Basic
    Authentication, or both. Use this parameter to specify either "Windows" or "Basic" authentication.

.PARAMETER ADCSWebAuthUserName
    This parameter is OPTIONAL.

    This parameter takes a string that represents a username with permission to access the ADCS Web Enrollment site.
    If $ADCSWebAuthType = "Basic", then INCLUDE the domain prefix as part of the username. 
    Example: test2\testadmin .

    If $ADCSWebAuthType = "Windows", then DO NOT INCLUDE the domain prefix as part of the username.
    Example: testadmin

    (NOTE: If you mix up the above username formatting, then the script will figure it out. This is more of an FYI.)

.PARAMETER ADCSWebAuthPass
    This parameter is OPTIONAL.

    This parameter takes one of two inputs:
    1) A string that represents a Plaintext Password; OR 
    2) A PowerShell Secure String object 
    
    Plaintext will be converted to a Secure String by the script and purged from memory.

    If $ADCSWebEnrollmentUrl is used, then this parameter becomes MANDATORY. Under this circumstance, if 
    this parameter is left blank, the user will be prompted for secure input. If using this script as part of a larger
    automated process, use a wrapper function to pass this parameter securely (this is outside the scope of this script).

    ***IMPORTANT*** To avoid providing this password in plaintext on the command line, recommend using 
    Generate-EncryptedPwdFile.ps1 and Decrypt-EncryptedPwdFile.ps1 to pass this parameter. See:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1
    https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1

.PARAMETER CertADCSWebResponse
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the default value will be used.

    This parameter takes a string that represents a valid file path that contains the HTTP response after submitting 
    the Certificate Request via the ADCS Web Enrollment site.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER Organization
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents an Organization name. This will be added to "Subject" field in the
    Certificate.

.PARAMETER OriginationalUnit
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents an Organization's Department. This will be added to the "Subject" field
    in the Certificate.

.PARAMETER Locality
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents a City. This will be added to the "Subject" field in the Certificate.

.PARAMETER State
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents a State. This will be added to the "Subject" field in the Certificate.

.PARAMETER Country
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes a string that represents a Country. This will be added to the "Subject" field in the Certificate.

.PARAMETER KeyLength
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "2048"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string representing a valid key length. See:
    https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER HashAlgorithmValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "sha256"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string.  For a list of possible values, see:
    https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER EncryptionAlgorithmValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "AES"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string representing an available encryption algorithm. Valid values are:
    AES, DES, RC2, and RC4

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER PrivateKeyExportableValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "TRUE"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "TRUE"; OR
    2) The string "FALSE"

    Setting the value to TRUE means that the Private Key will be exportable.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER KeySpecValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "1"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "1"; OR
    2) The string "2"

    For details about Key Spec Values, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER KeyUsageValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "0x80"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string that represents a hexadecimal value. For a list of valid hexadecimal values,
    see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER MachineKeySet
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes one of two inputs:
    1) The string "TRUE"; OR
    2) The string "FALSE"

    If you would like the private key exported, use "FALSE". 
    If you are creating this certificate to be used in the User's security context (like for a developer to sign their code),
    enter "FALSE". If you are using this certificate for a service that runs in the Computer's security context (such as
    a Web Server, Domain Controller, etc) and DO NOT need the Private Key exported use "TRUE".
    See: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

.PARAMETER SecureEmail
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    If the New Certificate is going to be used to digitally sign and/or encrypt emails, this parameter should be set to "Yes"

.PARAMETER UserProtected
    This parameter is MANDATORY.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    If $MachineKeySet is set to "TRUE", then $UserProtected MUST be set to "No". If $MachineKeySet is set to "FALSE",
    then $UserProtected can be set to "Yes" or "No". 

    If set to "Yes", a CryptoAPI password window is displayed when the key is generated during the certificate request 
    build process. You can optionally protect the key with a password in the window or choose to display only a window when the 
    key is used within an application. Once the key is protected with a password, you must enter this password every time the key 
    is accessed.

    IMPORTANT NOTE: Do not set this parameter to "Yes" if you want this script/function to run unattended.

.PARAMETER ProviderNameOverride
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    Setting this parameter to "Yes", "Y", "yes", or "y" will trigger an interactive walkthrough that explains Cryptographic
    Provider values and asks the user for input.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER ProviderNameValuePrep
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "Microsoft RSA SChannel Cryptographic Provider"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string that represents the name of the Cryptographic Provider you would like to use for the 
    New Certificate. For more details and a list of valid values, see:
    https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    WARNING: The Certificate Template that this New Certificate is based on (i.e. the value provided for the parameter 
    $BasisTemplate) COULD POTENTIALLY limit the availble Crypographic Provders for the Certificate Request. Make sure 
    the Cryptographic Provider you use is allowed by the Basis Certificate Template.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER RequestTypeOverride
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    Setting this parameter to "Yes", "Y", "yes", or "y" will trigger an interactive walkthrough that explains RequestType
    values and asks the user for input.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER RequestTypeValue
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "PKCS10"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    This parameter takes a string that indicates the format of the Certificate Request. Valid values are 
    CMC, PKCS10, PKCS10-, and PKCS7.
    For more details, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER IntendedPurposeOverride
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    Setting this parameter to "Yes", "Y", "yes", or "y" will trigger an interactive walkthrough that explains
    IntendedPurpose values and asks the user for input.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER IntendedPurposeValuesPrep
    This parameter is OPTIONAL.

    There is NO DEFAULT VALUE supplied. If the user does not explicitly provide a value from the command line, then
    the user will receive a prompt asking for a value to be provided.

    This parameter takes 

    This parameter takes a string of values separated by commas, or an array. Valid values are as follows:

    "Code Signing","Document Signing","Client Authentication","Server Authentication",
    "Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",
    "OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",
    "File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",
    "Windows Third Party Application Component","Windows TCB Component","Windows Store",
    "Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",
    "No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",
    "Protected Process Verification","Protected Process Light Verification","Platform Certificate",
    "Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",
    "Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",
    "Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",
    "IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",
    "Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",
    "OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",
    "Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification"

    ***IMPORTANT NOTE:*** If this parameter is not set by user, the Intended Purpose Value(s) of the Basis Certificate Template
    (i.e. $BasisTemplate) will be used.

.PARAMETER UseOpenSSL
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line, 
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    This parameter indicates whether the Win32 OpenSSL binary should be used to extract
    certificates/keys in a format readily used in Linux environments.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER PathToWin32OpenSSL
    This parameter is OPTIONAL.

    There IS A DEFAULT VALUE supplied (i.e. "C:\openssl-0.9.8r-i386-win32-rev2"). If the user does not explicitly provide
    a value from the command line, then the default value will be used.

    This parameter takes a string that represents a file path to the Win32 OpenSSL binaries on your filesystem.
    (Recommend using latest version from https://indy.fulgan.com/SSL/)

    This parameter becomes MANDATORY if the parameter $UseOpenSSL = "Yes"

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER AllPublicKeysInChainOut
    This parameter is OPTIONAL.

    There IS A DEFAULT VALUE supplied (i.e. "NewCertificate_$CertificateCN"+"_all_public_keys_in_chain_"+".pem"). If the
    user does not explicitly provide a value from the command line, then the default value will be used.

    This parameter takes a string that represents a file name. This file will contain all public certificates in the chain, 
    rom the New Certificate up to the Root Certificate Authority. File extension should be .pem

    This parameter becomes MANDATORY if the parameter $UseOpenSSL = "Yes"

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER ProtectedPrivateKeyOut
    This parameter is OPTIONAL.

    There IS A DEFAULT VALUE supplied (i.e. "NewCertificate_$CertificateCN"+"_protected_private_key_"+".pem"). If the
    user does not explicitly provide a value from the command line, then the default value will be used.

    This parameter takes a string that represents a file name. This file will contain the password-protected private key
    for the New Certificate. File extension should be .pem

    This parameter becomes MANDATORY if the parameter $UseOpenSSL = "Yes"

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER UnProtectedPrivateKeyOut
    This parameter is OPTIONAL.

    There IS A DEFAULT VALUE supplied (i.e. "NewCertificate_$CertificateCN"+"_unprotected_private_key_"+".key"). If the
    user does not explicitly provide a value from the command line, then the default value will be used.

    This parameter takes a string that represents a file name. This file will contain the raw private key for the New
    Certificate. File extension should be .key

    This parameter becomes MANDATORY if the parameter $UseOpenSSL = "Yes"

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER StripPrivateKeyOfPassword
    This parameter is OPTIONAL.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line,
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    This parameter removes the password from $ProtectedPrivateKeyOut.

    This parameter becomes MANDATORY if the parameter $UseOpenSSL = "Yes"

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER AddSAN
    This parameter is MANDATORY.

    There IS A DEFAULT VALUE supplied (i.e. "No"). If the user does not explicitly provide a value from the command line,
    then the default value will be used.

    The parameter takes one of two inputs:
    1) The string "No"; OR
    2) The string "Yes"

    Set this parameter to "Yes" if you intend to include Subject Alternate Names (SANs) on the New Certificate.

    IMPORTANT NOTE: Default values for some parameters are already provided, and running the Generate-Certificate script/
    function will generate a New Certificate using these default values, however, the resulting Certificate
    may not satisfy all of your needs depending on your circumstances. Please review the explanation for each of the
    variables/parameters that can/should be changed.

.PARAMETER TypesofSANObjectsToAdd
    This parameter is OPTIONAL.

    This parameter takes a comma separated list of SAN Object Types. All possible values are: 
    DNS, Distinguished Name, URL, IP Address, Email, UPN, or GUID. 
    Example: DNS, IP Address, Email

    This parameter becomes MANDATORY if $AddSAN = "Yes"

.PARAMETER DNSSANObjects
    This parameter is OPTIONAL.
    
    This parameter takes a comma separated list of DNS addresses.
    Example: www.fabrikam.com, www.contoso.com

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "DNS"

.PARAMETER DistinguishedNameSANObjects
    This parameter is OPTIONAL.

    This parameter takes a SEMI-COLON separated list of Distinguished Name objects.
    Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "Distinguished Name"

.PARAMETER URLSANObjects
    This parameter is OPTIONAL.

    This parameter takes a comma separated list of URLs.
    Example: http://www.fabrikam.com, http://www.contoso.com

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "URL"

.PARAMETER IPAddressSANObjects
    This parameter is OPTIONAL.

    This parameter takes a comma separated list of IP Addresses.
    Example: 172.31.10.13, 192.168.2.125

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "IP Address"

.PARAMETER EmailSANObjects
    This parameter is OPTIONAL.

    This paramter takes a comma separated list of Email Addresses.
    Example: mike@fabrikam.com, hazem@fabrikam.com

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "Email"

.PARAMETER UPNSANObjects
    This parameter is OPTIONAL.

    This parameter takes a comma separated list of Principal Name objects.
    Example: mike@fabrikam.com, hazem@fabrikam.com

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "UPN"

.PARAMETER GUIDSANObjects
    This parameter is OPTIONAL.

    This parameter takes a comma separated list of GUIDs.
    Example: f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39, g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48

    This parameter becomes MANDATORY if $SANObjectsToAdd includes "GUID"

.EXAMPLE
    EXAMPLE 1: No Parameters Provided
    Generate-Certificate

    NOTE: Executing the script/function without any parameters will ask for input on de facto mandatory parameters.
    All other parameters will use default values which should be fine under the vast majority of circumstances.
    De facto mandatory parameters are as follows:
    -CertGenWorking
    -BasisTemplate
    -CertificateCN
    -Organization
    -OrganizationalUnit
    -Locality
    -State
    -Country
    -MachineKeySet
    -SecureEmail
    -UserProtected

.EXAMPLE
    EXAMPLE 2: Minimal Parameters Provided
    Generate-Certificate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking\test8" `
    -BasisTemplate "CertTempl166" `
    -CertificateCN "TigerSigningCert" `
    -Organization "Contoso Inc" `
    -OrganizationalUnit "DevOps Department" `
    -Locality "Portland" `
    -State "OR" `
    -Country "US" `
    -MachineKeySet "TRUE" `
    -SecureEmail "No" `
    -UserProtected "No" `
    
.EXAMPLE
    EXAMPLE 3: Minimal Parameters Provided with Win32 OpenSSL
    Generate-Certificate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking\test8" `
    -BasisTemplate "CertTempl166" `
    -CertificateCN "TigerSigningCert" `
    -PFXFileOut "TigerSigningCert.pfx" `
    -PFXPwdAsSecureString "ThisIsNotSecure987!" `
    -Organization "Contoso Inc" `
    -OrganizationalUnit "DevOps Department" `
    -Locality "Portland" `
    -State "OR" `
    -Country "US" `
    -MachineKeySet "FALSE" `
    -SecureEmail "No" `
    -UserProtected "No" `
    -UseOpenSSL "Yes" `
    -PathToWin32OpenSSL "C:\openssl-0.9.8r-i386-win32-rev2" `
    -AllPublicKeysInChainOut "TigerSigningCert_all_public_keys_in_chain.pem" `
    -PublicKeySansChainOutFile "TigerSigningCert_public_key_sans_chain.pem" `
    -ProtectedPrivateKeyOut "TigerSigningCert_protected_private_key.pem" `
    -UnProtectedPrivateKeyOut "TigerSigningCert_unprotected_private_key.key" `
    -StripPrivateKeyOfPassword "Yes"

.EXAMPLE
    EXAMPLE 4: All Possible Parameters
    Generate-Certificate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking\test8" `
    -BasisTemplate "CertTempl166" `
    -CertificateCN "TigerSigningCert" `
    -CertificateRequestConfigFile "TigerSigningCert.inf" `
    -CertificateRequestFile "TigerSigningCert.csr" `
    -CertFileOut "TigerSigningCert.cer" `
    -CertificateChainOut "TigerSigningCert.p7b" `
    -PFXFileOut "TigerSigningCert.pfx" `
    -PFXPwdAsSecureString "ThisIsNotSecure987!" `
    -RequestViaWebEnrollment "Yes" `
    -ADCSWebEnrollmentURL "https://pki.test2.lab/certsrv" `
    -ADCSWebAuthType "Windows" `
    -ADCSWebAuthUserName "testadmin" `
    -ADCSWebAuthPass "SecurityIsHard321!" `
    -CertADCSWebResponse "C:\Users\zeroadmin\Desktop\CertGenWorking\test8\ADCSWebResponse.txt"
    -Organization "Contoso Inc" `
    -OrganizationalUnit "DevOps Department" `
    -Locality "Portland" `
    -State "OR" `
    -Country "US" `
    -KeyLengthOverride "No" `
    -KeyLength "2048" `
    -HashAlgorithmOverride "No" `
    -HashAlgorithmValue "sha256" `
    -EncryptionAlgorithmOverride "No" `
    -EncryptionAlgorithmValue "AES" `
    -PrivateKeyExportableOverride "No" `
    -PrivateKeyExportableValue "TRUE" `
    -KeySpecOverride "No" `
    -KeySpecValue "1" `
    -KeyUsageOverride "No" `
    -KeyUsageValue "0x80" `
    -MachineKeySet "FALSE" `
    -SecureEmail "No" `
    -UserProtected "No" `
    -ProviderNameOverride "No" `
    -ProviderNameValuePrep "Microsoft Enhanced Cryptographic Provider v1.0" `
    -RequestTypeOverride "No" `
    -RequestTypeValue "PKCS10" `
    -IntendedPurposeOverride "No" `
    -IntendedPurposeValuesPrep "Code Signing, Document Signing" `
    -UseOpenSSL "Yes" `
    -PathToWin32OpenSSL "C:\openssl-0.9.8r-i386-win32-rev2" `
    -AllPublicKeysInChainOut "TigerSigningCert_all_public_keys_in_chain.pem" `
    -PublicKeySansChainOutFile "TigerSigningCert_public_key_sans_chain.pem" `
    -ProtectedPrivateKeyOut "TigerSigningCert_protected_private_key.pem" `
    -UnProtectedPrivateKeyOut "TigerSigningCert_unprotected_private_key.key" `
    -StripPrivateKeyOfPassword "Yes" `
    -AddSAN "Yes"
    -TypesofSANObjectsToAdd "DNS, Distinguished Name, URL, IP Address, UPN, GUID"
    -DNSSANObjects "www.fabrikam.com, www.contoso.org"
    -DistinguishedNameSANObjects "CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"
    -URLSANObjects "http://www.fabrikam.com, http://www.contoso.com"
    -IPAddressSANObjects "172.31.10.13, 192.168.2.125"
    -EmailSANObjects "mike@fabrikam.com, hazem@fabrikam.com"
    -UPNSANObjects "mike@fabrikam.com, hazem@fabrikam.com"
    -GUIDSANObjects "f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39, g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48"

.OUTPUTS
    All outputs are written to the $CertGenWorking directory specified by the user.

    ALWAYS GENERATED
    The following outputs are ALWAYS generated by this function/script, regardless of optional parameters: 
        - A Certificate Request Configuration File (with .inf file extension) - 
            RELEVANT PARAMETER: $CertificateRequestConfigFile
        - A Certificate Request File (with .csr file extenstion) - 
            RELEVANT PARAMETER: $CertificateRequestFile
        - A Public Certificate with the New Certificate Name (NewCertificate_$CertificateCN_[Timestamp].cer) - 
            RELEVANT PARAMETER: $CertFileOut
            NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
            the Certificate Request is submitted and accepted by the Issuing Certificate Authority. 
            NOTE: If you choose to use Win32 OpenSSL to extract certs/keys from the .pfx file (see below), this file should have SIMILAR CONTENT
            to the file $PublicKeySansChainOutFile. To clarify, $PublicKeySansChainOutFile does NOT have what appear to be extraneous newlines, 
            but $CertFileOut DOES. Even though $CertFileOut has what appear to be extraneous newlines, Microsoft Crypto Shell Extensions will 
            be able to read both files as if they were the same. However, Linux machines will need to use $PublicKeySansChainOutFile (Also, the 
            file extension for $PublicKeySansChainOutFile can safely be changed from .cer to .pem without issue)
        - A Global HashTable called $GenerateCertificateFileOutputHashGlobal that can help the user quickly and easily reference output 
            files in $CertGenWorking. Example content of $GenerateCertificateFileOutputHashGlobal:

            Key   : CertificateRequestFile
            Value : NewCertRequest_aws-coreos3-client-server-cert04-Sep-2016_2127.csr
            Name  : CertificateRequestFile

            Key   : IntermediateCAPublicCertFile
            Value : ZeroSCA_Public_Cert.pem
            Name  : IntermediateCAPublicCertFile

            Key   : EndPointPublicCertFile
            Value : aws-coreos3-client-server-cert_Public_Cert.pem
            Name  : EndPointPublicCertFile

            Key   : AllPublicKeysInChainOut
            Value : NewCertificate_aws-coreos3-client-server-cert_all_public_keys_in_chain_.pem
            Name  : AllPublicKeysInChainOut

            Key   : CertificateRequestConfigFile
            Value : NewCertRequestConfig_aws-coreos3-client-server-cert04-Sep-2016_2127.inf
            Name  : CertificateRequestConfigFile

            Key   : EndPointUnProtectedPrivateKey
            Value : NewCertificate_aws-coreos3-client-server-cert_unprotected_private_key_.key
            Name  : EndPointUnProtectedPrivateKey

            Key   : RootCAPublicCertFile
            Value : ZeroDC01_Public_Cert.pem
            Name  : RootCAPublicCertFile

            Key   : CertADCSWebResponse
            Value : NewCertificate_aws-coreos3-client-server-cert_ADCSWebResponse04-Sep-2016_2127.txt
            Name  : CertADCSWebResponse

            Key   : CertFileOut
            Value : NewCertificate_aws-coreos3-client-server-cert04-Sep-2016_2127.cer
            Name  : CertFileOut

            Key   : PFXFileOut
            Value : NewCertificate_aws-coreos3-client-server-cert04-Sep-2016_2127.pfx
            Name  : PFXFileOut

            Key   : EndPointProtectedPrivateKey
            Value : NewCertificate_aws-coreos3-client-server-cert_protected_private_key_.pem
            Name  : EndPointProtectedPrivateKey

        - A Global HashTable called $CertNamevsContentsHashGlobal that contains the actual content of certain Certificates. 
            Example content of $CertNamevsContentsHashGlobal is as follows:

            Key   : EndPointUnProtectedPrivateKey
            Value : -----BEGIN RSA PRIVATE KEY-----
                    ...
                    -----END RSA PRIVATE KEY-----
            Name  : EndPointUnProtectedPrivateKey

            Key   : aws-coreos3-client-server-cert
            Value : -----BEGIN CERTIFICATE-----
                    ...
                    -----END CERTIFICATE-----
            Name  : aws-coreos3-client-server-cert

            Key   : ZeroSCA
            Value : -----BEGIN CERTIFICATE-----
                    ...
                    -----END CERTIFICATE-----
            Name  : ZeroSCA

            Key   : ZeroDC01
            Value : -----BEGIN CERTIFICATE-----
                    ...
                    -----END CERTIFICATE-----
            Name  : ZeroDC01

    GENERATED WHEN $MachineKeySet = "FALSE"
    The following outputs are ONLY generated by this function/script when $MachineKeySet = "FALSE" (this is its default setting)
        - A .pfx File Containing the Entire Public Certificate Chain AS WELL AS the Private Key of your New Certificate (with .pfx file extension) - 
            RELEVANT PARAMETER: $PFXFileOut
            NOTE: The Private Key must be marked as exportable in your Certificate Request Configuration File in order for the .pfx file to
            contain the private key. This is controlled by the parameter $PrivateKeyExportableValue = "TRUE". The Private Key is marked as 
            exportable by default.
    
    GENERATED WHEN $ADCSWebEnrollmentUrl is NOT provided
    The following outputs are ONLY generated by this function/script when $ADCSWebEnrollmentUrl is NOT provided (this is its default setting)
    (NOTE: Under this scenario, the workstation running the script must be part of the same domain as the Issuing Certificate Authority):
        - A Certificate Request Response File (with .rsp file extension) 
            NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
            the Certificate Request is submitted
        - A Certificate Chain File (with .p7b file extension) -
            RELEVANT PARAMETER: $CertificateChainOut
            NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
            the Certificate Request is submitted and accepted by the Issuing Certificate Authority
            NOTE: This file contains the entire chain of public certificates, from the requested certificate, up to the Root CA
            WARNING: In order to parse the public certificates for each entity up the chain, you MUST use the Crypto Shell Extensions GUI,
            otherwise, if you look at this content with a text editor, it appears as only one (1) public certificate.  Use the OpenSSL
            Certificate Chain File ($AllPublicKeysInChainOut) optional output in order to view a text file that parses each entity's public certificate.
    
    GENERATED WHEN $ADCSWebEnrollmentUrl IS provided
    The following outputs are ONLY generated by this function/script when $ADCSWebEnrollmentUrl IS provided
    (NOTE: Under this scenario, the workstation running the script is sending a web request to the ADCS Web Enrollment website):
        - An File Containing the HTTP Response From the ADCS Web Enrollment Site (with .txt file extension) - 
            RELEVANT PARAMETER: $CertADCSWebResponse
    
    GENERATED WHEN $UseOpenSSL = "Yes"
    The following outputs are ONLY generated by this function/script when $UseOpenSSL = "Yes"
    (WARNING: This creates a Dependency on a third party Win32 OpenSSL binary that can be found here: https://indy.fulgan.com/SSL/
    For more information, see the DEPENDENCIES Section below)
        - A Certificate Chain File (ending with "all_public_keys_in_chain.pem") -
            RELEVANT PARAMETER: $AllPublicKeysInChainOut
            NOTE: This optional parameter differs from the aforementioned .p7b certificate chain output in that it actually parses
            each entity's public certificate in a way that is viewable in a text editor.
        - EACH Public Certificate in the Certificate Chain File (file name like [Certificate CN]_Public_Cert.cer)
            - A Public Certificate with the New Certificate Name ($CertificateCN_Public_Cert.cer) -
                RELEVANT PARAMETER: $PublicKeySansChainOutFile
                NOTE: This file should have SIMILAR CONTENT to $CertFileOut referenced earlier. To clarify, $PublicKeySansChainOutFile does NOT have
                what appear to be extraneous newlines, but $CertFileOut DOES. Even though $CertFileOut has what appear to be extraneous newlines, Microsoft Crypto Shell Extensions will 
                be able to read both files as if they were the same. However, Linux machines will need to use $PublicKeySansChainOutFile (Also, the 
                file extension for $PublicKeySansChainOutFile can safely be changed from .cer to .pem without issue)
            - Additional Public Certificates in Chain including [Subordinate CA CN]_Public_Cert.cer and [Root CA CN]_Public_Cert.cer
        - A Password Protected Private Key file (ending with "protected_private_key.pem") -
            RELEVANT PARAMETER: $ProtectedPrivateKeyOut
            NOTE: This is the New Certificate's Private Key that is protected by a password defined by the $PFXPwdAsSecureString parameter.

    GENERATED WHEN $UseOpenSSL = "Yes" AND $StripPrivateKeyOfPassword = "Yes"
        - An Unprotected Private Key File (ends with unprotected_private_key.key) -
            RELEVANT PARAMETER: $UnProtectedPrivateKeyOut

#>

Function Generate-Certificate {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False)]
    [string]$CertGenWorking = "$HOME\Downloads\CertGenWorking",

    [Parameter(Mandatory=$False)]
    [string]$BasisTemplate = $(Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificate
    to be based on (Example: 'Web Server'"),

    [Parameter(Mandatory=$False)]
    [string]$CertificateCN = $(Read-Host -Prompt "Please enter the Name that you would like your Certificate to have
    For a Computer/Client/Server Certificate, recommend using host FQDN)"),

    # This function creates the $CertificateRequestConfigFile. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$CertificateRequestConfigFile = "NewCertRequestConfig_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".inf",

    # This function creates the $CertificateRequestFile. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$CertificateRequestFile = "NewCertRequest_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".csr",

    # This function creates $CertFileOut. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$CertFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".cer",

    # This function creates the $CertificateChainOut. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$CertificateChainOut = "NewCertificateChain_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".p7b",

    # This function creates the $PFXFileOut. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$PFXFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".pfx",

    [Parameter(Mandatory=$False)]
    [securestring]$PFXPwdAsSecureString,

    # If the workstation being used to request the certificate is part of the same domain as the Issuing Certificate Authority, we can identify
    # the Issuing Certificate Authority with certutil, so there is no need to set an $IssuingCertificateAuth Parameter
    #[Parameter(Mandatory=$False)]
    #$IssuingCertAuth = $(Read-Host -Prompt "Please enter the FQDN the server responsible for Issuing New Certificates."),

    [Parameter(Mandatory=$False)]
    [string]$ADCSWebEnrollmentUrl, # Example: https://pki.zero.lab/certsrv"

    [Parameter(Mandatory=$False)]
    [ValidateSet("Windows","Basic")]
    [string]$ADCSWebAuthType,

    [Parameter(Mandatory=$False)]
    [string]$ADCSWebAuthUserName,

    [Parameter(Mandatory=$False)]
    [securestring]$ADCSWebAuthPass,

    [Parameter(Mandatory=$False)]
    [System.Management.Automation.PSCredential]$ADCSWebCreds,

    # This function creates the $CertADCSWebResponse file. It should NOT exist prior to running this function
    [Parameter(Mandatory=$False)]
    [string]$CertADCSWebResponse = "NewCertificate_$CertificateCN"+"_ADCSWebResponse"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".txt",

    [Parameter(Mandatory=$False)]
    $Organization = $(Read-Host -Prompt "Please enter the name of the the Company that will appear on the New Certificate"),

    [Parameter(Mandatory=$False)]
    $OrganizationalUnit = $(Read-Host -Prompt "Please enter the name of the Department that you work for within your Company"),

    [Parameter(Mandatory=$False)]
    $Locality = $(Read-Host -Prompt "Please enter the City where your Company is located"),

    [Parameter(Mandatory=$False)]
    $State = $(Read-Host -Prompt "Please enter the State where your Company is located"),

    [Parameter(Mandatory=$False)]
    $Country = $(Read-Host -Prompt "Please enter the Country where your Company is located"),

    <#
    # ValidityPeriod is controlled by the Certificate Template and cannot be modified at the time of certificate request
    # (Unless it is a special circumstance where "RequestType = Cert" resulting in a self-signed cert where no request
    # is actually submitted)
    [Parameter(Mandatory=$False)]
    $ValidityPeriodValue = $(Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
    NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"),
    #>

    [Parameter(Mandatory=$False)]
    [ValidateSet("2048","4096")]
    $KeyLength = "2048",

    [Parameter(Mandatory=$False)]
    [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
    $HashAlgorithmValue = "SHA256",

    <#
    # KeyAlgorithm should be determined by ProviderName. Run "certutil -csplist" to see which Providers use which Key Algorithms
    [Parameter(Mandatory=$False)]
    [ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
    $KeyAlgorithmValue,
    #>

    [Parameter(Mandatory=$False)]
    [ValidateSet("AES","DES","3DES","RC2","RC4")]
    $EncryptionAlgorithmValue = "AES",

    [Parameter(Mandatory=$False)]
    [ValidateSet("True","False")]
    $PrivateKeyExportableValue = "True",

    # Valid values are '1' for AT_KEYEXCHANGE and '2' for AT_SIGNATURE [1,2]"
    [Parameter(Mandatory=$False)]
    [ValidateSet("1","2")]
    $KeySpecValue = "1",

    <#
    The below $KeyUsageValue is the HEXADECIMAL SUM of the KeyUsage hexadecimal values you would like to use.

    A valid value is the hex sum of one or more of following:
        CERT_DIGITAL_SIGNATURE_KEY_USAGE = 80
        CERT_NON_REPUDIATION_KEY_USAGE = 40
        CERT_KEY_ENCIPHERMENT_KEY_USAGE = 20
        CERT_DATA_ENCIPHERMENT_KEY_USAGE = 10
        CERT_KEY_AGREEMENT_KEY_USAGE = 8
        CERT_KEY_CERT_SIGN_KEY_USAGE = 4
        CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 2
        CERT_CRL_SIGN_KEY_USAGE = 2
        CERT_ENCIPHER_ONLY_KEY_USAGE = 1
    
    Commonly Used Values:
        'c0' (i.e. 80+40)
        'a0' (i.e. 80+20)
        'f0' (i.e. 80+40+20+10)
        '30' (i.e. 20+10)
        '80'
    #>
    [Parameter(Mandatory=$False)]
    [ValidateSet("1","10","11","12","13","14","15","16","17","18","2","20","21","22","23","24","25","26","27","28","3","30","38","4","40",
    "41","42","43","44","45","46","47","48","5","50","58","6","60","68","7","70","78","8","80","81","82","83","84","85","86","87","88","9","90",
    "98","a","a0","a8","b","b0","b8","c","c0","c","8","d","d0","d8","e","e0","e8","f","f0","f8")]
    $KeyUsageValue = "80",
    
    [Parameter(Mandatory=$False)]
    [ValidateSet("True","False")]
    $MachineKeySet = "False",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Yes","No")]
    $SecureEmail = "No",

    [Parameter(Mandatory=$False)]
    [ValidateSet("True","False")]
    $UserProtected = "False",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
    "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
    "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
    "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
    "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
    "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
    "Microsoft Passport Key Storage Provider)]
    [string]$ProviderNameValue = "Microsoft RSA SChannel Cryptographic Provider",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Yes","No")]
    $RequestTypeOverride = "No",

    [Parameter(Mandatory=$False)]
    $RequestTypeValue = "PKCS10",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Yes","No")]
    $IntendedPurposeOverride = "No",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Code Signing","Document Signing","Client Authentication","Server Authentication",
    "Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",
    "OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",
    "File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",
    "Windows Third Party Application Component","Windows TCB Component","Windows Store",
    "Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",
    "No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",
    "Protected Process Verification","Protected Process Light Verification","Platform Certificate",
    "Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",
    "Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",
    "Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",
    "IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",
    "Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",
    "OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",
    "Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification")]
    [string[]]$IntendedPurposeValues,

    [Parameter(Mandatory=$False)]
    [ValidateSet("Yes","No")]
    $UseOpenSSL = "Yes",

    [Parameter(Mandatory=$False)]
    [string]$AllPublicKeysInChainOut = "NewCertificate_$CertificateCN"+"_all_public_keys_in_chain_"+".pem",

    [Parameter(Mandatory=$False)]
    [string]$ProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_protected_private_key_"+".pem",
    
    [Parameter(Mandatory=$False)]
    [string]$UnProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_unprotected_private_key_"+".key",

    [Parameter(Mandatory=$False)]
    [ValidateSet("Yes","No")]
    $StripPrivateKeyOfPassword = "Yes",

    [Parameter(Mandatory=$False)]
    [ValidateSet("DNS","Distinguished Name","URL","IP Address","Email","UPN","GUID")]
    [string[]]$SANObjectsToAdd,

    [Parameter(Mandatory=$False)]
    [string[]]$DNSSANObjects, # Example: www.fabrikam.com, www.contoso.org

    [Parameter(Mandatory=$False)]
    [string[]]$DistinguishedNameSANObjects, # Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"

    [Parameter(Mandatory=$False)]
    [string[]]$URLSANObjects, # Example: http://www.fabrikam.com, http://www.contoso.com

    [Parameter(Mandatory=$False)]
    [string[]]$IPAddressSANObjects, # Example: 192.168.2.12, 10.10.1.15

    [Parameter(Mandatory=$False)]
    [string[]]$EmailSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

    [Parameter(Mandatory=$False)]
    [string[]]$UPNSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

    [Parameter(Mandatory=$False)]
    [string[]]$GUIDSANObjects
)

##### BEGIN Helper Functions #####

function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".")).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

function Compare-Arrays {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [array]$LargerArray,

        [Parameter(Mandatory=$False)]
        [array]$SmallerArray
    )

    -not @($SmallerArray | where {$LargerArray -notcontains $_}).Count
}

$OIDHashTable = @{
    # Remote Desktop
    "Remote Desktop" = "1.3.6.1.4.1.311.54.1.2"
    # Windows Update
    "Windows Update" = "1.3.6.1.4.1.311.76.6.1"
    # Windows Third Party Applicaiton Component
    "Windows Third Party Application Component" = "1.3.6.1.4.1.311.10.3.25"
    # Windows TCB Component
    "Windows TCB Component" = "1.3.6.1.4.1.311.10.3.23"
    # Windows Store
    "Windows Store" = "1.3.6.1.4.1.311.76.3.1"
    # Windows Software Extension verification
    " Windows Software Extension Verification" = "1.3.6.1.4.1.311.10.3.26"
    # Windows RT Verification
    "Windows RT Verification" = "1.3.6.1.4.1.311.10.3.21"
    # Windows Kits Component
    "Windows Kits Component" = "1.3.6.1.4.1.311.10.3.20"
    # ROOT_PROGRAM_NO_OCSP_FAILOVER_TO_CRL
    "No OCSP Failover to CRL" = "1.3.6.1.4.1.311.60.3.3"
    # ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION
    "Auto Update End Revocation" = "1.3.6.1.4.1.311.60.3.2"
    # ROOT_PROGRAM_AUTO_UPDATE_CA_REVOCATION
    "Auto Update CA Revocation" = "1.3.6.1.4.1.311.60.3.1"
    # Revoked List Signer
    "Revoked List Signer" = "1.3.6.1.4.1.311.10.3.19"
    # Protected Process Verification
    "Protected Process Verification" = "1.3.6.1.4.1.311.10.3.24"
    # Protected Process Light Verification
    "Protected Process Light Verification" = "1.3.6.1.4.1.311.10.3.22"
    # Platform Certificate
    "Platform Certificate" = "2.23.133.8.2"
    # Microsoft Publisher
    "Microsoft Publisher" = "1.3.6.1.4.1.311.76.8.1"
    # Kernel Mode Code Signing
    "Kernel Mode Code Signing" = "1.3.6.1.4.1.311.6.1.1"
    # HAL Extension
    "HAL Extension" = "1.3.6.1.4.1.311.61.5.1"
    # Endorsement Key Certificate
    "Endorsement Key Certificate" = "2.23.133.8.1"
    # Early Launch Antimalware Driver
    "Early Launch Antimalware Driver" = "1.3.6.1.4.1.311.61.4.1"
    # Dynamic Code Generator
    "Dynamic Code Generator" = "1.3.6.1.4.1.311.76.5.1"
    # Domain Name System (DNS) Server Trust
    "DNS Server Trust" = "1.3.6.1.4.1.311.64.1.1"
    # Document Encryption
    "Document Encryption" = "1.3.6.1.4.1.311.80.1"
    # Disallowed List
    "Disallowed List" = "1.3.6.1.4.1.10.3.30"
    # Attestation Identity Key Certificate
    "Attestation Identity Key Certificate" = "2.23.133.8.3"
	"Generic Conference Contro" = "0.0.20.124.0.1"
	"X509Extensions" = "1.3.6.1.4.1.311.2.1.14"
	"EnrollmentCspProvider" = "1.3.6.1.4.1.311.13.2.2"
    # System Health Authentication
	"System Health Authentication" = "1.3.6.1.4.1.311.47.1.1"
	"OsVersion" = "1.3.6.1.4.1.311.13.2.3"
	"RenewalCertificate" = "1.3.6.1.4.1.311.13.1"
	"Certificate Template" = "1.3.6.1.4.1.311.20.2"
	"RequestClientInfo" = "1.3.6.1.4.1.311.21.20"
	"ArchivedKeyAttr" = "1.3.6.1.4.1.311.21.13"
	"EncryptedKeyHash" = "1.3.6.1.4.1.311.21.21"
	"EnrollmentNameValuePair" = "1.3.6.1.4.1.311.13.2.1"
	"IdAtName" = "2.5.4.41"
	"IdAtCommonName" = "2.5.4.3"
	"IdAtLocalityName" = "2.5.4.7"
	"IdAtStateOrProvinceName" = "2.5.4.8"
	"IdAtOrganizationName" = "2.5.4.10"
	"IdAtOrganizationalUnitName" = "2.5.4.11"
	"IdAtTitle" = "2.5.4.12"
	"IdAtDnQualifier" = "2.5.4.46"
	"IdAtCountryName" = "2.5.4.6"
	"IdAtSerialNumber" = "2.5.4.5"
	"IdAtPseudonym" = "2.5.4.65"
	"IdDomainComponent" = "0.9.2342.19200300.100.1.25"
	"IdEmailAddress" = "1.2.840.113549.1.9.1"
	"IdCeAuthorityKeyIdentifier" = "2.5.29.35"
	"IdCeSubjectKeyIdentifier" = "2.5.29.14"
	"IdCeKeyUsage" = "2.5.29.15"
	"IdCePrivateKeyUsagePeriod" = "2.5.29.16"
	"IdCeCertificatePolicies" = "2.5.29.32"
	"IdCePolicyMappings" = "2.5.29.33"
	"IdCeSubjectAltName" = "2.5.29.17"
	"IdCeIssuerAltName" = "2.5.29.18"
	"IdCeBasicConstraints" = "2.5.29.19"
	"IdCeNameConstraints" = "2.5.29.30"
	"idCdPolicyConstraints" = "2.5.29.36"
	"IdCeExtKeyUsage" = "2.5.29.37"
	"IdCeCRLDistributionPoints" = "2.5.29.31"
	"IdCeInhibitAnyPolicy" = "2.5.29.54"
	"IdPeAuthorityInfoAccess" = "1.3.6.1.5.5.7.1.1"
	"IdPeSubjectInfoAccess" = "1.3.6.1.5.5.7.1.11"
	"IdCeCRLNumber" = "2.5.29.20"
	"IdCeDeltaCRLIndicator" = "2.5.29.27"
	"IdCeIssuingDistributionPoint" = "2.5.29.28"
	"IdCeFreshestCRL" = "2.5.29.46"
	"IdCeCRLReason" = "2.5.29.21"
	"IdCeHoldInstructionCode" = "2.5.29.23"
	"IdCeInvalidityDate" = "2.5.29.24"
	"IdCeCertificateIssuer" = "2.5.29.29"
	"IdModAttributeCert" = "1.3.6.1.5.5.7.0.12"
	"IdPeAcAuditIdentity" = "1.3.6.1.5.5.7.1.4"
	"IdCeTargetInformation" = "2.5.29.55"
	"IdCeNoRevAvail" = "2.5.29.56"
	"IdAcaAuthenticationInfo" = "1.3.6.1.5.5.7.10.1"
	"IdAcaAccessIdentity" = "1.3.6.1.5.5.7.10.2"
	"IdAcaChargingIdentity" = "1.3.6.1.5.5.7.10.3"
	"IdAcaGroup" = "1.3.6.1.5.5.7.10.4"
	"IdAtRole" = "2.5.4.72"
	"IdAtClearance" = "2.5.1.5.55"
	"IdAcaEncAttrs" = "1.3.6.1.5.5.7.10.6"
	"IdPeAcProxying" = "1.3.6.1.5.5.7.1.10"
	"IdPeAaControls" = "1.3.6.1.5.5.7.1.6"
	"IdCtContentInfo" = "1.2.840.113549.1.9.16.1.6"
	"IdDataAuthpack" = "1.2.840.113549.1.7.1"
	"IdSignedData" = "1.2.840.113549.1.7.2"
	"IdEnvelopedData" = "1.2.840.113549.1.7.3"
	"IdDigestedData" = "1.2.840.113549.1.7.5"
	"IdEncryptedData" = "1.2.840.113549.1.7.6"
	"IdCtAuthData" = "1.2.840.113549.1.9.16.1.2"
	"IdContentType" = "1.2.840.113549.1.9.3"
	"IdMessageDigest" = "1.2.840.113549.1.9.4"
	"IdSigningTime" = "1.2.840.113549.1.9.5"
	"IdCounterSignature" = "1.2.840.113549.1.9.6"
	"RsaEncryption" = "1.2.840.113549.1.1.1"
	"IdRsaesOaep" = "1.2.840.113549.1.1.7"
	"IdPSpecified" = "1.2.840.113549.1.1.9"
	"IdRsassaPss" = "1.2.840.113549.1.1.10"
	"Md2WithRSAEncryption" = "1.2.840.113549.1.1.2"
	"Md5WithRSAEncryption" = "1.2.840.113549.1.1.4"
	"Sha1WithRSAEncryption" = "1.2.840.113549.1.1.5"
	"Sha256WithRSAEncryption" = "1.2.840.113549.1.1.11"
	"Sha384WithRSAEncryption" = "1.2.840.113549.1.1.12"
	"Sha512WithRSAEncryption" = "1.2.840.113549.1.1.13"
	"IdMd2" = "1.2.840.113549.2.2"
	"IdMd5" = "1.2.840.113549.2.5"
	"IdSha1" = "1.3.14.3.2.26"
	"IdSha256" = "2.16.840.1.101.3.4.2.1"
	"IdSha384" = "2.16.840.1.101.3.4.2.2"
	"IdSha512" = "2.16.840.1.101.3.4.2.3"
	"IdMgf1" = "1.2.840.113549.1.1.8"
	"IdDsaWithSha1" = "1.2.840.10040.4.3"
	"EcdsaWithSHA1" = "1.2.840.10045.4.1"
	"IdDsa" = "1.2.840.10040.4.1"
	"DhPublicNumber" = "1.2.840.10046.2.1"
	"IdKeyExchangeAlgorithm" = "2.16.840.1.101.2.1.1.22"
	"IdEcPublicKey" = "1.2.840.10045.2.1"
	"PrimeField" = "1.2.840.10045.1.1"
	"CharacteristicTwoField" = "1.2.840.10045.1.2"
	"GnBasis" = "1.2.840.10045.1.2.1.1"
	"TpBasis" = "1.2.840.10045.1.2.1.2"
	"PpBasis" = "1.2.840.10045.1.2.1.3"
	"IdAlgEsdh" = "1.2.840.113549.1.9.16.3.5"
	"IdAlgSsdh" = "1.2.840.113549.1.9.16.3.10"
	"IdAlgCms3DesWrap" = "1.2.840.113549.1.9.16.3.6"
	"IdAlgCmsRc2Wrap" = "1.2.840.113549.1.9.16.3.7"
	"IdPbkDf2" = "1.2.840.113549.1.5.12"
	"DesEde3Cbc" = "1.2.840.113549.3.7"
	"Rc2Cbc" = "1.2.840.113549.3.2"
	"HmacSha1" = "1.3.6.1.5.5.8.1.2"
	"IdAes128Cbc" = "2.16.840.1.101.3.4.1.2"
	"IdAes192Cbc" = "2.16.840.1.101.3.4.1.22"
	"IdAes256Cbc" = "2.16.840.1.101.3.4.1.42"
	"IdAes128Wrap" = "2.16.840.1.101.3.4.1.5"
	"IdAes192Wrap" = "2.16.840.1.101.3.4.1.25"
	"IdAes256Wrap" = "2.16.840.1.101.3.4.1.45"
	"IdCmcIdentification" = "1.3.6.1.5.5.7.7.2"
	"IdCmcIdentityProof" = "1.3.6.1.5.5.7.7.3"
	"IdCmcDataReturn" = "1.3.6.1.5.5.7.7.4"
	"IdCmcTransactionId" = "1.3.6.1.5.5.7.7.5"
	"IdCmcSenderNonce" = "1.3.6.1.5.5.7.7.6"
	"IdCmcRecipientNonce" = "1.3.6.1.5.5.7.7.7"
	"IdCmcRegInfo" = "1.3.6.1.5.5.7.7.18"
	"IdCmcResponseInfo" = "1.3.6.1.5.5.7.7.19"
	"IdCmcQueryPending" = "1.3.6.1.5.5.7.7.21"
	"IdCmcPopLinkRandom" = "1.3.6.1.5.5.7.7.22"
	"IdCmcPopLinkWitness" = "1.3.6.1.5.5.7.7.23"
	"IdCctPKIData" = "1.3.6.1.5.5.7.12.2"
	"IdCctPKIResponse" = "1.3.6.1.5.5.7.12.3"
	"IdCmccMCStatusInfo" = "1.3.6.1.5.5.7.7.1"
	"IdCmcAddExtensions" = "1.3.6.1.5.5.7.7.8"
	"IdCmcEncryptedPop" = "1.3.6.1.5.5.7.7.9"
	"IdCmcDecryptedPop" = "1.3.6.1.5.5.7.7.10"
	"IdCmcLraPopWitness" = "1.3.6.1.5.5.7.7.11"
	"IdCmcGetCert" = "1.3.6.1.5.5.7.7.15"
	"IdCmcGetCRL" = "1.3.6.1.5.5.7.7.16"
	"IdCmcRevokeRequest" = "1.3.6.1.5.5.7.7.17"
	"IdCmcConfirmCertAcceptance" = "1.3.6.1.5.5.7.7.24"
	"IdExtensionReq" = "1.2.840.113549.1.9.14"
	"IdAlgNoSignature" = "1.3.6.1.5.5.7.6.2"
	"PasswordBasedMac" = "1.2.840.113533.7.66.13"
	"IdRegCtrlRegToken" = "1.3.6.1.5.5.7.5.1.1"
	"IdRegCtrlAuthenticator" = "1.3.6.1.5.5.7.5.1.2"
	"IdRegCtrlPkiPublicationInfo" = "1.3.6.1.5.5.7.5.1.3"
	"IdRegCtrlPkiArchiveOptions" = "1.3.6.1.5.5.7.5.1.4"
	"IdRegCtrlOldCertID" = "1.3.6.1.5.5.7.5.1.5"
	"IdRegCtrlProtocolEncrKey" = "1.3.6.1.5.5.7.5.1.6"
	"IdRegInfoUtf8Pairs" = "1.3.6.1.5.5.7.5.2.1"
	"IdRegInfoCertReq" = "1.3.6.1.5.5.7.5.2.2"
	"SpnegoToken" = "1.3.6.1.5.5.2"
	"SpnegoNegTok" = "1.3.6.1.5.5.2.4.2"
	"GSS_KRB5_NT_USER_NAME" = "1.2.840.113554.1.2.1.1"
	"GSS_KRB5_NT_MACHINE_UID_NAME" = "1.2.840.113554.1.2.1.2"
	"GSS_KRB5_NT_STRING_UID_NAME" = "1.2.840.113554.1.2.1.3"
	"GSS_C_NT_HOSTBASED_SERVICE" = "1.2.840.113554.1.2.1.4"
	"KerberosToken" = "1.2.840.113554.1.2.2"
	"Negoex" = "1.3.6.1.4.1.311.2.2.30" 
	"GSS_KRB5_NT_PRINCIPAL_NAME" = "1.2.840.113554.1.2.2.1"
	"GSS_KRB5_NT_PRINCIPAL" = "1.2.840.113554.1.2.2.2"
	"UserToUserMechanism" = "1.2.840.113554.1.2.2.3"
	"MsKerberosToken" = "1.2.840.48018.1.2.2"
	"NLMP" = "1.3.6.1.4.1.311.2.2.10"
	"IdPkixOcspBasic" = "1.3.6.1.5.5.7.48.1.1"
	"IdPkixOcspNonce" = "1.3.6.1.5.5.7.48.1.2"
	"IdPkixOcspCrl" = "1.3.6.1.5.5.7.48.1.3"
	"IdPkixOcspResponse" = "1.3.6.1.5.5.7.48.1.4"
	"IdPkixOcspNocheck" = "1.3.6.1.5.5.7.48.1.5"
	"IdPkixOcspArchiveCutoff" = "1.3.6.1.5.5.7.48.1.6"
	"IdPkixOcspServiceLocator" = "1.3.6.1.5.5.7.48.1.7"
    # Smartcard Logon
	"IdMsKpScLogon" = "1.3.6.1.4.1.311.20.2.2"
	"IdPkinitSan" = "1.3.6.1.5.2.2"
	"IdPkinitAuthData" = "1.3.6.1.5.2.3.1"
	"IdPkinitDHKeyData" = "1.3.6.1.5.2.3.2"
	"IdPkinitRkeyData" = "1.3.6.1.5.2.3.3"
	"IdPkinitKPClientAuth" = "1.3.6.1.5.2.3.4"
	"IdPkinitKPKdc" = "1.3.6.1.5.2.3.5"
	"SHA1 with RSA signature" = "1.3.14.3.2.29"
	"AUTHORITY_KEY_IDENTIFIER" = "2.5.29.1"
	"KEY_ATTRIBUTES" = "2.5.29.2"
	"CERT_POLICIES_95" = "2.5.29.3"
	"KEY_USAGE_RESTRICTION" = "2.5.29.4"
	"SUBJECT_ALT_NAME" = "2.5.29.7"
	"ISSUER_ALT_NAME" = "2.5.29.8"
	"Subject_Directory_Attributes" = "2.5.29.9"
	"BASIC_CONSTRAINTS" = "2.5.29.10"
	"ANY_CERT_POLICY" = "2.5.29.32.0"
	"LEGACY_POLICY_MAPPINGS" = "2.5.29.5"
    # Certificate Request Agent
	"ENROLLMENT_AGENT" = "1.3.6.1.4.1.311.20.2.1"
	"PKIX" = "1.3.6.1.5.5.7"
	"PKIX_PE" = "1.3.6.1.5.5.7.1"
	"NEXT_UPDATE_LOCATION" = "1.3.6.1.4.1.311.10.2"
	"REMOVE_CERTIFICATE" = "1.3.6.1.4.1.311.10.8.1"
	"CROSS_CERT_DIST_POINTS" = "1.3.6.1.4.1.311.10.9.1"
	"CTL" = "1.3.6.1.4.1.311.10.1"
	"SORTED_CTL" = "1.3.6.1.4.1.311.10.1.1"
	"SERIALIZED" = "1.3.6.1.4.1.311.10.3.3.1"
	"NT_PRINCIPAL_NAME" = "1.3.6.1.4.1.311.20.2.3"
	"PRODUCT_UPDATE" = "1.3.6.1.4.1.311.31.1"
	"ANY_APPLICATION_POLICY" = "1.3.6.1.4.1.311.10.12.1"
    # CTL Usage
	"AUTO_ENROLL_CTL_USAGE" = "1.3.6.1.4.1.311.20.1"
	"CERT_MANIFOLD" = "1.3.6.1.4.1.311.20.3"
	"CERTSRV_CA_VERSION" = "1.3.6.1.4.1.311.21.1"
	"CERTSRV_PREVIOUS_CERT_HASH" = "1.3.6.1.4.1.311.21.2"
	"CRL_VIRTUAL_BASE" = "1.3.6.1.4.1.311.21.3"
	"CRL_NEXT_PUBLISH" = "1.3.6.1.4.1.311.21.4"
    # Private Key Archival
	"KP_CA_EXCHANGE" = "1.3.6.1.4.1.311.21.5"
    # Key Recovery Agent
	"KP_KEY_RECOVERY_AGENT" = "1.3.6.1.4.1.311.21.6"
	"CERTIFICATE_TEMPLATE" = "1.3.6.1.4.1.311.21.7"
	"ENTERPRISE_OID_ROOT" = "1.3.6.1.4.1.311.21.8"
	"RDN_DUMMY_SIGNER" = "1.3.6.1.4.1.311.21.9"
	"APPLICATION_CERT_POLICIES" = "1.3.6.1.4.1.311.21.10"
	"APPLICATION_POLICY_MAPPINGS" = "1.3.6.1.4.1.311.21.11"
	"APPLICATION_POLICY_CONSTRAINTS" = "1.3.6.1.4.1.311.21.12"
	"CRL_SELF_CDP" = "1.3.6.1.4.1.311.21.14"
	"REQUIRE_CERT_CHAIN_POLICY" = "1.3.6.1.4.1.311.21.15"
	"ARCHIVED_KEY_CERT_HASH" = "1.3.6.1.4.1.311.21.16"
	"ISSUED_CERT_HASH" = "1.3.6.1.4.1.311.21.17"
	"DS_EMAIL_REPLICATION" = "1.3.6.1.4.1.311.21.19"
	"CERTSRV_CROSSCA_VERSION" = "1.3.6.1.4.1.311.21.22"
	"NTDS_REPLICATION" = "1.3.6.1.4.1.311.25.1"
	"PKIX_KP" = "1.3.6.1.5.5.7.3"
	"PKIX_KP_SERVER_AUTH" = "1.3.6.1.5.5.7.3.1"
	"PKIX_KP_CLIENT_AUTH" = "1.3.6.1.5.5.7.3.2"
	"PKIX_KP_CODE_SIGNING" = "1.3.6.1.5.5.7.3.3"
    # Secure Email
	"PKIX_KP_EMAIL_PROTECTION" = "1.3.6.1.5.5.7.3.4"
    # IP Security End System
	"PKIX_KP_IPSEC_END_SYSTEM" = "1.3.6.1.5.5.7.3.5"
    # IP Security Tunnel Termination
	"PKIX_KP_IPSEC_TUNNEL" = "1.3.6.1.5.5.7.3.6"
    # IP Security User
	"PKIX_KP_IPSEC_USER" = "1.3.6.1.5.5.7.3.7"
    # Time Stamping
	"PKIX_KP_TIMESTAMP_SIGNING" = "1.3.6.1.5.5.7.3.8"
    "KP_OCSP_SIGNING" = "1.3.6.1.5.5.7.3.9"
    # IP security IKE intermediate
	"IPSEC_KP_IKE_INTERMEDIATE" = "1.3.6.1.5.5.8.2.2"
    # Microsoft Trust List Signing
	"KP_CTL_USAGE_SIGNING" = "1.3.6.1.4.1.311.10.3.1"
    # Microsoft Time Stamping
	"KP_TIME_STAMP_SIGNING" = "1.3.6.1.4.1.311.10.3.2"
	"SERVER_GATED_CRYPTO" = "1.3.6.1.4.1.311.10.3.3"
	"SGC_NETSCAPE" = "2.16.840.1.113730.4.1"
	"KP_EFS" = "1.3.6.1.4.1.311.10.3.4"
	"EFS_RECOVERY" = "1.3.6.1.4.1.311.10.3.4.1"
    # Windows Hardware Driver Verification
	"WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.5"
    # Windows System Component Verification
	"NT5_CRYPTO" = "1.3.6.1.4.1.311.10.3.6"
    # OEM Windows System Component Verification
	"OEM_WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.7"
    # Embedded Windows System Component Verification
	"EMBEDDED_NT_CRYPTO" = "1.3.6.1.4.1.311.10.3.8"
    # Root List Signer
	"ROOT_LIST_SIGNER" = "1.3.6.1.4.1.311.10.3.9"
    # Qualified Subordination
	"KP_QUALIFIED_SUBORDINATION" = "1.3.6.1.4.1.311.10.3.10"
    # Key Recovery
	"KP_KEY_RECOVERY" = "1.3.6.1.4.1.311.10.3.11"
	"KP_DOCUMENT_SIGNING" = "1.3.6.1.4.1.311.10.3.12"
    # Lifetime Signing
	"KP_LIFETIME_SIGNING" = "1.3.6.1.4.1.311.10.3.13"
	"KP_MOBILE_DEVICE_SOFTWARE" = "1.3.6.1.4.1.311.10.3.14"
	# Digital Rights
    "DRM" = "1.3.6.1.4.1.311.10.5.1"
	"DRM_INDIVIDUALIZATION" = "1.3.6.1.4.1.311.10.5.2"
    # Key Pack Licenses
	"LICENSES" = "1.3.6.1.4.1.311.10.6.1"
    # License Server Verification
	"LICENSE_SERVER" = "1.3.6.1.4.1.311.10.6.2"
	"YESNO_TRUST_ATTR" = "1.3.6.1.4.1.311.10.4.1"
	"PKIX_POLICY_QUALIFIER_CPS" = "1.3.6.1.5.5.7.2.1"
	"PKIX_POLICY_QUALIFIER_USERNOTICE" = "1.3.6.1.5.5.7.2.2"
	"CERT_POLICIES_95_QUALIFIER1" = "2.16.840.1.113733.1.7.1.1"
	"RSA" = "1.2.840.113549"
	"PKCS" = "1.2.840.113549.1"
	"RSA_HASH" = "1.2.840.113549.2"
	"RSA_ENCRYPT" = "1.2.840.113549.3"
	"PKCS_1" = "1.2.840.113549.1.1"
	"PKCS_2" = "1.2.840.113549.1.2"
	"PKCS_3" = "1.2.840.113549.1.3"
	"PKCS_4" = "1.2.840.113549.1.4"
	"PKCS_5" = "1.2.840.113549.1.5"
	"PKCS_6" = "1.2.840.113549.1.6"
	"PKCS_7" = "1.2.840.113549.1.7"
	"PKCS_8" = "1.2.840.113549.1.8"
	"PKCS_9" = "1.2.840.113549.1.9"
	"PKCS_10" = "1.2.840.113549.1.10"
	"PKCS_12" = "1.2.840.113549.1.12"
	"RSA_MD4RSA" = "1.2.840.113549.1.1.3"
	"RSA_SETOAEP_RSA" = "1.2.840.113549.1.1.6"
	"RSA_DH" = "1.2.840.113549.1.3.1"
	"RSA_signEnvData" = "1.2.840.113549.1.7.4"
	"RSA_unstructName" = "1.2.840.113549.1.9.2"
	"RSA_challengePwd" = "1.2.840.113549.1.9.7"
	"RSA_unstructAddr" = "1.2.840.113549.1.9.8"
	"RSA_extCertAttrs" = "1.2.840.113549.1.9.9"
	"RSA_SMIMECapabilities" = "1.2.840.113549.1.9.15"
	"RSA_preferSignedData" = "1.2.840.113549.1.9.15.1"
	"RSA_SMIMEalg" = "1.2.840.113549.1.9.16.3"
	"RSA_MD4" = "1.2.840.113549.2.4"
	"RSA_RC4" = "1.2.840.113549.3.4"
	"RSA_RC5_CBCPad" = "1.2.840.113549.3.9"
	"ANSI_X942" = "1.2.840.10046"
	"X957" = "1.2.840.10040"
	"DS" = "2.5"
	"DSALG" = "2.5.8"
	"DSALG_CRPT" = "2.5.8.1"
	"DSALG_HASH" = "2.5.8.2"
	"DSALG_SIGN" = "2.5.8.3"
	"DSALG_RSA" = "2.5.8.1.1"
	"OIW" = "1.3.14"
	"OIWSEC" = "1.3.14.3.2"
	"OIWSEC_md4RSA" = "1.3.14.3.2.2"
	"OIWSEC_md5RSA" = "1.3.14.3.2.3"
	"OIWSEC_md4RSA2" = "1.3.14.3.2.4"
	"OIWSEC_desECB" = "1.3.14.3.2.6"
	"OIWSEC_desCBC" = "1.3.14.3.2.7"
	"OIWSEC_desOFB" = "1.3.14.3.2.8"
	"OIWSEC_desCFB" = "1.3.14.3.2.9"
	"OIWSEC_desMAC" = "1.3.14.3.2.10"
	"OIWSEC_rsaSign" = "1.3.14.3.2.11"
	"OIWSEC_dsa" = "1.3.14.3.2.12"
	"OIWSEC_shaDSA" = "1.3.14.3.2.13"
	"OIWSEC_mdc2RSA" = "1.3.14.3.2.14"
	"OIWSEC_shaRSA" = "1.3.14.3.2.15"
	"OIWSEC_dhCommMod" = "1.3.14.3.2.16"
	"OIWSEC_desEDE" = "1.3.14.3.2.17"
	"OIWSEC_sha" = "1.3.14.3.2.18"
	"OIWSEC_mdc2" = "1.3.14.3.2.19"
	"OIWSEC_dsaComm" = "1.3.14.3.2.20"
	"OIWSEC_dsaCommSHA" = "1.3.14.3.2.21"
	"OIWSEC_rsaXchg" = "1.3.14.3.2.22"
	"OIWSEC_keyHashSeal" = "1.3.14.3.2.23"
	"OIWSEC_md2RSASign" = "1.3.14.3.2.24"
	"OIWSEC_md5RSASign" = "1.3.14.3.2.25"
	"OIWSEC_dsaSHA1" = "1.3.14.3.2.27"
	"OIWSEC_dsaCommSHA1" = "1.3.14.3.2.28"
	"OIWDIR" = "1.3.14.7.2"
	"OIWDIR_CRPT" = "1.3.14.7.2.1"
	"OIWDIR_HASH" = "1.3.14.7.2.2"
	"OIWDIR_SIGN" = "1.3.14.7.2.3"
	"OIWDIR_md2" = "1.3.14.7.2.2.1"
	"OIWDIR_md2RSA" = "1.3.14.7.2.3.1"
	"INFOSEC" = "2.16.840.1.101.2.1"
	"INFOSEC_sdnsSignature" = "2.16.840.1.101.2.1.1.1"
	"INFOSEC_mosaicSignature" = "2.16.840.1.101.2.1.1.2"
	"INFOSEC_sdnsConfidentiality" = "2.16.840.1.101.2.1.1.3"
	"INFOSEC_mosaicConfidentiality" = "2.16.840.1.101.2.1.1.4"
	"INFOSEC_sdnsIntegrity" = "2.16.840.1.101.2.1.1.5"
	"INFOSEC_mosaicIntegrity" = "2.16.840.1.101.2.1.1.6"
	"INFOSEC_sdnsTokenProtection" = "2.16.840.1.101.2.1.1.7"
	"INFOSEC_mosaicTokenProtection" = "2.16.840.1.101.2.1.1.8"
	"INFOSEC_sdnsKeyManagement" = "2.16.840.1.101.2.1.1.9"
	"INFOSEC_mosaicKeyManagement" = "2.16.840.1.101.2.1.1.10"
	"INFOSEC_sdnsKMandSig" = "2.16.840.1.101.2.1.1.11"
	"INFOSEC_mosaicKMandSig" = "2.16.840.1.101.2.1.1.12"
	"INFOSEC_SuiteASignature" = "2.16.840.1.101.2.1.1.13"
	"INFOSEC_SuiteAConfidentiality" = "2.16.840.1.101.2.1.1.14"
	"INFOSEC_SuiteAIntegrity" = "2.16.840.1.101.2.1.1.15"
	"INFOSEC_SuiteATokenProtection" = "2.16.840.1.101.2.1.1.16"
	"INFOSEC_SuiteAKeyManagement" = "2.16.840.1.101.2.1.1.17"
	"INFOSEC_SuiteAKMandSig" = "2.16.840.1.101.2.1.1.18"
	"INFOSEC_mosaicUpdatedSig" = "2.16.840.1.101.2.1.1.19"
	"INFOSEC_mosaicKMandUpdSig" = "2.16.840.1.101.2.1.1.20"
	"INFOSEC_mosaicUpdatedInteg" = "2.16.840.1.101.2.1.1.21"
	"SUR_NAME" = "2.5.4.4"
	"STREET_ADDRESS" = "2.5.4.9"
	"DESCRIPTION" = "2.5.4.13"
	"SEARCH_GUIDE" = "2.5.4.14"
	"BUSINESS_CATEGORY" = "2.5.4.15"
	"POSTAL_ADDRESS" = "2.5.4.16"
	"POSTAL_CODE" = "2.5.4.17"
	"POST_OFFICE_BOX" = "2.5.4.18"
	"PHYSICAL_DELIVERY_OFFICE_NAME" = "2.5.4.19"
	"TELEPHONE_NUMBER" = "2.5.4.20"
	"TELEX_NUMBER" = "2.5.4.21"
	"TELETEXT_TERMINAL_IDENTIFIER" = "2.5.4.22"
	"FACSIMILE_TELEPHONE_NUMBER" = "2.5.4.23"
	"X21_ADDRESS" = "2.5.4.24"
	"INTERNATIONAL_ISDN_NUMBER" = "2.5.4.25"
	"REGISTERED_ADDRESS" = "2.5.4.26"
	"DESTINATION_INDICATOR" = "2.5.4.27"
	"PREFERRED_DELIVERY_METHOD" = "2.5.4.28"
	"PRESENTATION_ADDRESS" = "2.5.4.29"
	"SUPPORTED_APPLICATION_CONTEXT" = "2.5.4.30"
	"MEMBER" = "2.5.4.31"
	"OWNER" = "2.5.4.32"
	"ROLE_OCCUPANT" = "2.5.4.33"
	"SEE_ALSO" = "2.5.4.34"
	"USER_PASSWORD" = "2.5.4.35"
	"USER_CERTIFICATE" = "2.5.4.36"
	"CA_CERTIFICATE" = "2.5.4.37"
	"AUTHORITY_REVOCATION_LIST" = "2.5.4.38"
	"CERTIFICATE_REVOCATION_LIST" = "2.5.4.39"
	"CROSS_CERTIFICATE_PAIR" = "2.5.4.40"
	"GIVEN_NAME" = "2.5.4.42"
	"INITIALS" = "2.5.4.43"
	"PKCS_12_FRIENDLY_NAME_ATTR" = "1.2.840.113549.1.9.20"
	"PKCS_12_LOCAL_KEY_ID" = "1.2.840.113549.1.9.21"
	"PKCS_12_KEY_PROVIDER_NAME_ATTR" = "1.3.6.1.4.1.311.17.1"
	"LOCAL_MACHINE_KEYSET" = "1.3.6.1.4.1.311.17.2"
	"KEYID_RDN" = "1.3.6.1.4.1.311.10.7.1"
	"PKIX_ACC_DESCR" = "1.3.6.1.5.5.7.48"
	"PKIX_OCSP" = "1.3.6.1.5.5.7.48.1"
	"PKIX_CA_ISSUERS" = "1.3.6.1.5.5.7.48.2"
	"VERISIGN_PRIVATE_6_9" = "2.16.840.1.113733.1.6.9"
	"VERISIGN_ONSITE_JURISDICTION_HASH" = "2.16.840.1.113733.1.6.11"
	"VERISIGN_BITSTRING_6_13" = "2.16.840.1.113733.1.6.13"
	"VERISIGN_ISS_STRONG_CRYPTO" = "2.16.840.1.113733.1.8.1"
	"NETSCAPE" = "2.16.840.1.113730"
	"NETSCAPE_CERT_EXTENSION" = "2.16.840.1.113730.1"
	"NETSCAPE_CERT_TYPE" = "2.16.840.1.113730.1.1"
	"NETSCAPE_BASE_URL" = "2.16.840.1.113730.1.2"
	"NETSCAPE_REVOCATION_URL" = "2.16.840.1.113730.1.3"
	"NETSCAPE_CA_REVOCATION_URL" = "2.16.840.1.113730.1.4"
	"NETSCAPE_CERT_RENEWAL_URL" = "2.16.840.1.113730.1.7"
	"NETSCAPE_CA_POLICY_URL" = "2.16.840.1.113730.1.8"
	"NETSCAPE_SSL_SERVER_NAME" = "2.16.840.1.113730.1.12"
	"NETSCAPE_COMMENT" = "2.16.840.1.113730.1.13"
	"NETSCAPE_DATA_TYPE" = "2.16.840.1.113730.2"
	"NETSCAPE_CERT_SEQUENCE" = "2.16.840.1.113730.2.5"
	"CMC" = "1.3.6.1.5.5.7.7"
	"CMC_ADD_ATTRIBUTES" = "1.3.6.1.4.1.311.10.10.1"
	"PKCS_7_SIGNEDANDENVELOPED" = "1.2.840.113549.1.7.4"
	"CERT_PROP_ID_PREFIX" = "1.3.6.1.4.1.311.10.11."
	"CERT_KEY_IDENTIFIER_PROP_ID" = "1.3.6.1.4.1.311.10.11.20"
	"CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.28"
	"CERT_SUBJECT_NAME_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.29"
}

function Get-IntendedPurposeAdjudication {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$IntendedPurposeValues,

        [Parameter(Mandatory=$True)]
        [System.Collections.Hashtable]$OIDHashTable
    )

    # This function will be creating several $ variables to be used outside of this function by the rest of the script
    # All variables that are NOT preceded by $ must be set elsewhere BEFORE this funciton is executed
    # Variables that must be set BEFORE running this function are: $IntendedPurposeValues, $ValidIntendedPurposeValues, and $OIDHashTable

    # Using [System.Collections.ArrayList] so that Add and Remove methods work as expected and only operate on a single array 
    # instead of destroying and recreating arrays everytime an item is added/removed
    [System.Collections.ArrayList]$CertRequestConfigFileStringsSectionArray = @()

    [System.Collections.ArrayList]$szOIDArray = @()

    [System.Collections.ArrayList]$ExtKeyUse = @()

    [System.Collections.ArrayList]$AppPol = @()

    # Validation check...
    foreach ($obj1 in $IntendedPurposeValues) {
        if ($ValidIntendedPurposeValues -notcontains $obj1) {
            Write-Host "$($obj1) is not a valid IntendedPurpose. Halting!"
            Write-Host "Valid IntendedPurpose values are as follows:"
            $ValidIntendedPurposeValuesString            
            Write-Error "$($obj1) is not a valid IntendedPurpose. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    foreach ($obj1 in $IntendedPurposeValues) {
        if ($obj1 -eq "Code Signing") {
            $OfficialName = "PKIX_KP_CODE_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Document Signing") {
            $OfficialName = "KP_DOCUMENT_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Client Authentication") {
            $OfficialName = "PKIX_KP_CLIENT_AUTH"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Private Key Archival") {
            $OfficialName = "KP_CA_EXCHANGE"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Directory Service Email Replication") {
            $OfficialName = "DS_EMAIL_REPLICATION"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Key Recovery Agent") {
            $OfficialName = "KP_KEY_RECOVERY_AGENT"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "OCSP Signing") {
            $OfficialName = "KP_OCSP_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Server Authentication") {
            $OfficialName = "PKIX_KP_SERVER_AUTH"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        ##### Below this point, Intended Purposes will be set but WILL NOT show up in the Certificate Templates Console under Intended Purpose column #####
        if ($obj1 -eq "EFS") {
            $OfficialName = "KP_EFS"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Secure E-Mail") {
            $OfficialName = "PKIX_KP_EMAIL_PROTECTION"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Enrollment Agent") {
            $OfficialName = "ENROLLMENT_AGENT"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Microsoft Trust List Signing") {
            $OfficialName = "KP_CTL_USAGE_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Smartcard Logon") {
            $OfficialName = "IdMsKpScLogon"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "File Recovery") {
            $OfficialName = "EFS_RECOVERY"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "IPSec IKE Intermediate") {
            $OfficialName = "IPSEC_KP_IKE_INTERMEDIATE"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "KDC Authentication") {
            $OfficialName = "IdPkinitKPKdc"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        ##### Begin Newly Added #####
        if ($obj1 -eq "Remote Desktop") {
            $OfficialName = "Remote Desktop"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        # Cannot be overridden in Certificate Request
        if ($obj1 -eq "Windows Update") {
            $OfficialName = "Windows Update"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows Third Party Application Component") {
            $OfficialName = "Windows Third Party Application Component"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows TCB Component") {
            $OfficialName = "Windows TCB Component"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows Store") {
            $OfficialName = "Windows Store"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows Software Extension Verification") {
            $OfficialName = "Windows Software Extension Verification"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows RT Verification") {
            $OfficialName = "Windows RT Verification"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows Kits Component") {
            $OfficialName = "Windows Kits Component"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "No OCSP Failover to CRL") {
            $OfficialName = "No OCSP Failover to CRL"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Auto Update End Revocation") {
            $OfficialName = "Auto Update End Revocation"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Auto Update CA Revocation") {
            $OfficialName = "Auto Update CA Revocation"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Revoked List Signer") {
            $OfficialName = "Revoked List Signer"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Protected Process Verification") {
            $OfficialName = "Protected Process Verification"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Protected Process Light Verification") {
            $OfficialName = "Protected Process Light Verification"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Platform Certificate") {
            $OfficialName = "Platform Certificate"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Microsoft Publisher") {
            $OfficialName = "Microsoft Publisher"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Kernel Mode Code Signing") {
            $OfficialName = "Kernel Mode Code Signing"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "HAL Extension") {
            $OfficialName = "HAL Extension"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Endorsement Key Certificate") {
            $OfficialName = "Endorsement Key Certificate"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Early Launch Antimalware Driver") {
            $OfficialName = "Early Launch Antimalware Driver"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Dynamic Code Generator") {
            $OfficialName = "Dynamic Code Generator"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "DNS Server Trust") {
            $OfficialName = "DNS Server Trust"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Document Encryption") {
            $OfficialName = "Document Encryption"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Disallowed List") {
            $OfficialName = "Disallowed List"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Attestation Identity Key Certificate") {
            $OfficialName = "Attestation Identity Key Certificate"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "System Health Authentication") {
            $OfficialName = "System Health Authentication"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "CTL Usage") {
            $OfficialName = "AUTO_ENROLL_CTL_USAGE"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "IP Security End System") {
            $OfficialName = "PKIX_KP_IPSEC_END_SYSTEM"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "IP Security Tunnel Termination") {
            $OfficialName = "PKIX_KP_IPSEC_TUNNEL"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "IP Security User") {
            $OfficialName = "PKIX_KP_IPSEC_USER"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Time Stamping") {
            $OfficialName = "PKIX_KP_TIMESTAMP_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Microsoft Time Stamping") {
            $OfficialName = "KP_TIME_STAMP_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows Hardware Driver Verification") {
            $OfficialName = "WHQL_CRYPTO"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Windows System Component Verification") {
            $OfficialName = "NT5_CRYPTO"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "OEM Windows System Component Verification") {
            $OfficialName = "OEM_WHQL_CRYPTO"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Embedded Windows System Component Verification") {
            $OfficialName = "EMBEDDED_NT_CRYPTO"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Root List Signer") {
            $OfficialName = "ROOT_LIST_SIGNER"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Qualified Subordination") {
            $OfficialName = "KP_QUALIFIED_SUBORDINATION"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Key Recovery") {
            $OfficialName = "KP_KEY_RECOVERY"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Lifetime Signing") {
            $OfficialName = "KP_LIFETIME_SIGNING"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "Key Pack Licenses") {
            $OfficialName = "LICENSES"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
        if ($obj1 -eq "License Server Verification") {
            $OfficialName = "LICENSE_SERVER"
            $OfficialOID = $OIDHashTable.$OfficialName
            $szOIDArray.Add("szOID_$OfficialName")
            $CertRequestConfigFileStringsSectionArray.Add("szOID_$OfficialName = `"$OfficialOID`"")
            $ExtKeyUse.Add("$OfficialOID")
            $AppPol.Add("$OfficialOID")
        }
    }

    [pscustomobject]@{
        szOIDArray                                  = $szOIDArray
        CertRequestConfigFileStringsSectionArray    = $CertRequestConfigFileStringsSectionArray
        ExtKeyUse                                   = $ExtKeyUse
        AppPol                                      = $AppPol
    }
}

function New-UniqueString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ArrayOfStrings,

        [Parameter(Mandatory=$True)]
        [string]$PossibleNewUniqueString
    )

    if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
        $PossibleNewUniqueString
    }
    else {
        $OriginalString = $PossibleNewUniqueString
        $Iteration = 1
        while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
            $AppendedValue = "_$Iteration"
            $PossibleNewUniqueString = $OriginalString + $AppendedValue
            $Iteration++
        }

        $PossibleNewUniqueString
    }
}

function Install-RSAT {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$DownloadDirectory = "$HOME\Downloads",

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestart
    )

    Write-Host "Please wait..."

    if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
        $OSInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $OSCimInfo = Get-CimInstance Win32_OperatingSystem
        $OSArchitecture = $OSCimInfo.OSArchitecture

        if ([version]$OSCimInfo.Version -lt [version]"6.3") {
            Write-Error "This function only handles RSAT Installation for Windows 8.1 and higher! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($OSInfo.ProductName -notlike "*Server*") {
            if (![bool]$(Get-WmiObject -query 'select * from win32_quickfixengineering' | Where-Object {$_.HotFixID -eq 'KB958830' -or $_.HotFixID -eq 'KB2693643'})) {
                if ($([version]$OSCimInfo.Version).Major -lt 10 -and [version]$OSCimInfo.Version -ge [version]"6.3") {
                    if ($OSArchitecture -eq "64-bit") {
                        $OutFileName = "Windows8.1-KB2693643-x64.msu"
                    }
                    if ($OSArchitecture -eq "32-bit") {
                        $OutFileName = "Windows8.1-KB2693643-x86.msu"
                    }

                    $DownloadUrl = "https://download.microsoft.com/download/1/8/E/18EA4843-C596-4542-9236-DE46F780806E/$OutFileName"
                }
                if ($([version]$OSCimInfo.Version).Major -ge 10) {
                    if ([int]$OSInfo.ReleaseId -ge 1709) {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1709-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1709-x86.msu"
                        }
                    }
                    if ([int]$OSInfo.ReleaseId -lt 1709) {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS2016-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS2016-x86.msu"
                        }
                    }

                    $DownloadUrl = "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/$OutFileName"
                }

                try {
                    # Make sure the Url exists...
                    $HTTP_Request = [System.Net.WebRequest]::Create($DownloadUrl)
                    $HTTP_Response = $HTTP_Request.GetResponse()
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                try {
                    # Download via System.Net.WebClient is a lot faster than Invoke-WebRequest...
                    $WebClient = [System.Net.WebClient]::new()
                    $WebClient.Downloadfile($DownloadUrl, "$DownloadDirectory\$OutFileName")
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                Write-Host "Beginning installation..."
                if ($AllowRestart) {
                    $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                }
                else {
                    $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /norestart /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                }
                #Start-Process -FilePath $(Get-Command wusa.exe).Source -ArgumentList "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`"" -NoNewWindow -Wait

                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                $ProcessInfo.FileName = $(Get-Command wusa.exe).Source
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
                #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = $Arguments
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                # Below $FinishedInAlottedTime returns boolean true/false
                # Wait 20 seconds for wusa to finish...
                $FinishedInAlottedTime = $Process.WaitForExit(20000)
                if (!$FinishedInAlottedTime) {
                    $Process.Kill()
                }
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr

                # Check the log to make sure there weren't any errors
                # NOTE: Get-WinEvent cmdlet does NOT work consistently on all Windows Operating Systems...
                Write-Host "Reviewing wusa.exe logs..."
                $EventLogReader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new("$DownloadDirectory\wusaRSATInstall.log", [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
                [System.Collections.ArrayList]$EventsFromLog = @()
                
                $Event = $EventLogReader.ReadEvent()
                $null = $EventsFromLog.Add($Event)
                while ($Event -ne $null) {
                    $Event = $EventLogReader.ReadEvent()
                    $null = $EventsFromLog.Add($Event)
                }

                if ($EventsFromLog.LevelDisplayName -contains "Error") {
                    $ErrorRecord = $EventsFromLog | Where-Object {$_.LevelDisplayName -eq "Error"}
                    $ProblemDetails = $ErrorRecord.Properties.Value | Where-Object {$_ -match "[\w]"}
                    $ProblemDetailsString = $ProblemDetails[0..$($ProblemDetails.Count-2)] -join ": "

                    $ErrMsg = "wusa.exe failed to install '$DownloadDirectory\$OutFileName' due to '$ProblemDetailsString'. " +
                    "This could be because of a pending restart. Please restart $env:ComputerName and try the Install-RSAT function again."
                    Write-Error $ErrMsg
                    $global:FunctionResult = "1"
                    return
                }

                if ($AllowRestart) {
                    Restart-Computer -Confirm:$false -Force
                }
                else{
                    $Output = "RestartNeeded"
                }
            }
        }
        if ($OSInfo.ProductName -like "*Server*") {
            Import-Module ServerManager
            if (!$(Get-WindowsFeature RSAT).Installed) {
                Write-Host "Beginning installation..."
                if ($AllowRestart) {
                    Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools -Restart
                }
                else {
                    Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools
                    $Output = "RestartNeeded"
                }
            }
        }
    }
    else {
        Write-Warning "RSAT is already installed! No action taken."
    }

    if ($Output -eq "RestartNeeded") {
        Write-Warning "You must restart your computer in order to finish RSAT installation."
    }

    $Output
}

##### END Helper Functions #####

##### BEGIN Initial Variable Definition and Validation #####

# Make a working Directory Where Generated Certificates will be Saved
if (Test-Path $CertGenWorking) {
    $NewDirName = New-UniqueString -PossibleNewUniqueString $($CertGenWorking | Split-Path -Leaf) -ArrayOfStrings $(Get-ChildItem -Path $($CertGenWorking | Split-Path -Parent) -Directory).Name
    $CertGenWorking = "$($CertGenWorking | Split-Path -Parent)\$NewDirName"
}
else {
    New-Item -ItemType Directory -Path $CertGenWorking
}

if (!$MachineKeySet) {
    $MachineKeySetPrompt = "If you would like the private key exported, please enter 'False'. If you are " +
    "creating this certificate to be used in the User's security context (like for a developer to sign their code)," +
    "enter 'False'. If you are using this certificate for a service that runs in the Computer's security context " +
    "(such as a Web Server, Domain Controller, etc) enter 'True' [TRUE/FALSE]"
    $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
    while ($MachineKeySet -notmatch "True|False") {
        Write-Host "$MachineKeySet is not a valid option. Please enter either 'True' or 'False'" -ForeGroundColor Yellow
        $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
    }
}
$MachineKeySet = $MachineKeySet.ToUpper()
$PrivateKeyExportableValue = $PrivateKeyExportableValue.ToUpper()
$KeyUsageValue = "0x" + $KeyUsageValue

if (!$SecureEmail) {
    $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
    while ($SecureEmail -notmatch "Yes|No") {
        Write-Host "$SecureEmail is not a vaild option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
        $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
    }
}
if ($SecureEmail -eq "Yes") {
    $KeySpecValue = "2"
    $SMIMEValue = "TRUE"
}
else {
    $KeySpecValue = "1"
    $SMIMEValue = "FALSE"
}

if (!$UserProtected) {
    $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
    while ($UserProtected -notmatch "True|False") {
        Write-Host "$UserProtected is not a valid option. Please enter either 'True' or 'False'"
        $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
    }
}
if ($UserProtected -eq "True") {
    $MachineKeySet = "FALSE"
}
$UserProtected = $UserProtected.ToUpper()

if (!$UseOpenSSL) {
    $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
    while ($UseOpenSSL -notmatch "Yes|No") {
        Write-Host "$UseOpenSSL is not a valid option. Please enter 'Yes' or 'No'"
        $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
    }
}

## TODO: Get rid of *Override parameters ##

if ($RequestTypeOverride -eq "Yes" -or $RequestTypeOverride -eq "y" -or $RequestTypeOverride -eq "No" -or $RequestTypeOverride -eq "n") {
    Write-Host "The value for RequestTypeOverride is valid...continuing"
}
else {
    Write-Host "The value for RequestTypeOverride is not valid. Please enter either 'Yes', 'y', 'No', or 'n'. Halting!"
    $global:FunctionResult = "1"
    return
}

$DomainPrefix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 0
$DomainSuffix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 1
$Hostname = (gwmi Win32_ComputerSystem).Name
$HostFQDN = $Hostname+'.'+$DomainPrefix+'.'+$DomainSuffix

# If using Win32 OpenSSL, check to make sure the path to binary is valid...
if ($UseOpenSSL -eq "Yes") {
    # Check is openssl.exe is already available
    if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
        # Check to make sure the version is at least 1.1.0
        $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
        $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
    }

    # We need at least vertion 1.1.0 of OpenSSL
    if ($OpenSSLExeVersion.Major -lt 1 -or 
    $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1)
    ) {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
        $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl
        $LatestOpenSSLWinBinaryLinkObj = $($IWRResult.Links | Where-Object {$_.innerText -match "OpenSSL Binaries" -and $_.href -match "\.zip"})[0]
        $LatestOpenSSLWinBinaryUrl = $LatestOpenSSLWinBinaryLinkObj.href
        $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
        $OutputFilePath = "$HOME\Downloads\$OutputFileName"
        Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

        if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
            Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $OutputFileItem = Get-Item $OutputFilePath
        $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
        if (!$(Test-Path $ExpansionDirectory)) {
            $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
        }
        else {
            Remove-Item "$ExpansionDirectory\*" -Recurse -Force
        }

        $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

        # Add $ExpansionDirectory to $env:Path
        $CurrentEnvPathArray = $env:Path -split ";"
        if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
            # Place $ExpansionDirectory at start so latest openssl.exe get priority
            $env:Path = "$ExpansionDirectory;$env:Path"
        }
    }

    if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
        Write-Error "Problem setting openssl.exe to `$env:Path! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PathToWin32OpenSSL = $(Get-Command openssl).Source | Split-Path -Parent
}

# Check for contradictions in $MachineKeySet value and $PrivateKeyExportableValue and $UseOpenSSL
if ($MachineKeySet -eq "TRUE" -and $PrivateKeyExportableValue -eq "TRUE") {
    $WrnMsg = "MachineKeySet and PrivateKeyExportableValue have both been set to TRUE, but " +
    "Private Key cannot be exported if MachineKeySet = TRUE!"
    Write-Warning $WrnMsg

    $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
    while ($ShouldPrivKeyBeExportable -notmatch "Yes|yes|Y|y|No|no|N|n") {
        Write-Host "$ShouldPrivKeyBeExportable is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
        $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
    }
    if ($ShouldPrivKeyBeExportable -match "Yes|yes|Y|y") {
        $MachineKeySet = "FALSE"
        $PrivateKeyExportableValue = "TRUE"
    }
    else {
        $MachineKeySet = "TRUE"
        $PrivateKeyExportableValue = "FALSE"
    }
}
if ($MachineKeySet -eq "TRUE" -and $UseOpenSSL -eq "Yes") {
    $WrnMsg = "MachineKeySet and UseOpenSSL have both been set to TRUE. OpenSSL targets a .pfx file exported from the " +
    "local Certificate Store. If MachineKeySet is set to TRUE, no .pfx file will be exported from the " +
    "local Certificate Store!"
    Write-Warning $WrnMsg
    $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
    while ($ShouldUseOpenSSL -notmatch "Yes|yes|Y|y|No|no|N|n") {
        Write-Host "$ShouldUseOpenSSL is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
        $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
    }
    if ($ShouldUseOpenSSL -match "Yes|yes|Y|y") {
        $MachineKeySet = "FALSE"
        $UseOpenSSL = "Yes"
    }
    else {
        $MachineKeySet = "TRUE"
        $UseOpenSSL = "No"
    }
}
if ($MachineKeySet -eq "FALSE" -and $PFXPwdAsSecureString -eq $null) {
    $PFXPwdAsSecureString = Read-Host -Prompt "Please enter a password to use when exporting .pfx bundle certificate/key bundle" -AsSecureString
}

if ($PFXPwdAsSecureString.GetType().Name -eq "String") {
    $PFXPwdAsSecureString = ConvertTo-SecureString -String $PFXPwdAsSecureString -Force -AsPlainText
}

# If the workstation being used to request the Certificate is part of the same Domain as the Issuing Certificate Authority, leverage certutil...
if (!$ADCSWebEnrollmentUrl) {
    #$NeededRSATFeatures = @("RSAT","RSAT-Role-Tools","RSAT-AD-Tools","RSAT-AD-PowerShell","RSAT-ADDS","RSAT-AD-AdminCenter","RSAT-ADDS-Tools","RSAT-ADLDS")

    if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
        try {
            $InstallRSATResult = Install-RSAT -ErrorAction Stop
            if ($InstallRSATResult -eq "RestartNeeded") {
                throw "$env:ComputerName must be restarted post RSAT install! Please restart at your earliest convenience and try the Generate-Certificate funciton again."
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Problem installing the ActiveDirectory PowerShell Module (via RSAT installation). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($(Get-Module).Name -notcontains ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $AvailableCertificateAuthorities = (((certutil | Select-String -Pattern "Config:") -replace "Config:[\s]{1,32}``") -replace "'","").trim()
    $IssuingCertAuth = foreach ($obj1 in $AvailableCertificateAuthorities) {
        $obj2 = certutil -config $obj1 -CAInfo type | Select-String -Pattern "Enterprise Subordinate CA" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -eq "Enterprise Subordinate CA") {
            $obj1
        }
    }
    $IssuingCertAuthFQDN = $IssuingCertAuth.Split("\") | Select-Object -Index 0
    $IssuingCertAuthHostname = $IssuingCertAuth.Split("\") | Select-Object -Index 1
    $null = certutil -config $IssuingCertAuth -ping
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully contacted the Issuing Certificate Authority: $IssuingCertAuth"
    }
    else {
        Write-Host "Cannot contact the Issuing Certificate Authority: $IssuingCertAuth. Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    # $AllAvailableCertificateTemplates Using PSPKI
    # $AllAvailableCertificateTemplates = Get-PSPKICertificateTemplate
    # Using certutil
    $AllAvailableCertificateTemplatesPrep = certutil -ADTemplate
    # Determine valid CN using PSPKI
    # $ValidCertificateTemplatesByCN = $AllAvailableCertificateTemplatesPrep.Name
    # Determine valid displayNames using certutil
    $ValidCertificateTemplatesByCN = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
        $obj2 = $obj1 | Select-String -Pattern "[\w]{1,32}:[\s][\w]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        $obj3 = $obj2 -replace ':[\s][\w]',''
        $obj3
    }
    # Determine valid displayNames using PSPKI
    # $ValidCertificateTemplatesByDisplayName = $AllAvailableCertificateTemplatesPrep.DisplayName
    # Determine valid displayNames using certutil
    $ValidCertificateTemplatesByDisplayName = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
        $obj2 = $obj1 | Select-String -Pattern "\:(.*)\-\-" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        $obj3 = ($obj2 -replace ": ","") -replace " --",""
        $obj3
    }

    if ($ValidCertificateTemplatesByCN -notcontains $BasisTemplate -and $ValidCertificateTemplatesByDisplayName -notcontains $BasisTemplate) {
        $TemplateMsg = "You must base your New Certificate Template on an existing Certificate Template.`n" +
        "To do so, please enter either the displayName or CN of the Certificate Template you would like to use as your base.`n" +
        "Valid displayName values are as follows:`n$($ValidDisplayNamesAsString -join "`n")`n" +
        "Valid CN values are as follows:`n$($ValidCNNamesAsString -join "`n")"

        $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
        while ($($ValidCertificateTemplatesByCN + $ValidCertificateTemplatesByDisplayName) -notcontains $BasisTemplate) {
            Write-Host "$BasisTemplate is not a valid displayName or CN of an existing Certificate Template on Issuing Certificate Authority $IssuingCertAuth!" -ForeGroundColor Yellow
            $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
        }
    }

    # Set displayName and CN Values for user-provided $BasisTemplate
    if ($ValidCertificateTemplatesByCN -contains $BasisTemplate) {
        $cnForBasisTemplate = $BasisTemplate
    }
    if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
        $displayNameForBasisTemplate = $BasisTemplate
    }

    # Get all Certificate Template Properties of the Basis Template
    $LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainPrefix,DC=$DomainSuffix"

    if ($displayNameForBasisTemplate) {
        $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq "$displayNameForBasisTemplate"}
        $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq "$displayNameForBasisTemplate"} -Properties * 
    }
    if ($cnForBasisTemplate) {
        $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq "$cnForBasisTemplate"}
        $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq "$cnForBasisTemplate"} -Properties *
    }

    # Validate $ProviderNameValue
    # All available Cryptographic Providers (CSPs) are as follows:
    $PossibleProvidersPrep = certutil -csplist | Select-String "Provider Name" -Context 0,1
    $PossibleProviders = foreach ($obj1 in $PossibleProvidersPrep) {
        $obj2 = $obj1.Context.PostContext | Select-String 'FAIL' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
        $obj3 = $obj1.Context.PostContext | Select-String 'not ready' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
        if ($obj2 -ne "True" -and $obj3 -ne "True") {
            $obj1.Line -replace "Provider Name: ",""
        }
    }
    # Available Cryptographic Providers (CSPs) based on user choice in Certificate Template (i.e. $BasisTemplate)
    # Does the Basis Certificate Template LDAP Object have an attribute called pKIDefaultCSPs that is set?
    $CertificateTemplateLDAPObjectSetAttributes = $AllCertificateTemplateProperties.PropertyNames
    if ($CertificateTemplateLDAPObjectSetAttributes -notcontains "pKIDefaultCSPs") {
        Write-Host "The Basis Template $BasisTemplate does NOT have the attribute pKIDefaultCSPs set. " +
        "This means that Cryptographic Providers are NOT Limited, and (almost) any ProviderNameValue is valid"
    }
    else {
        $AvailableCSPsBasedOnCertificateTemplate = $AllCertificateTemplateProperties.pkiDefaultCSPs -replace '[0-9],',''
        if ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                while ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                    Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                    Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                    $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                }
            }
        }
    }
}
# If the workstation being used to request the Certificate is NOT part of the same Domain as the Issuing Certificate Authority, use ADCS Web Enrollment Site...
if ($ADCSWebEnrollmentUrl) {
    # Make sure there is no trailing / on $ADCSWebEnrollmentUrl
    if ($ADCSWebEnrollmentUrl.EndsWith('/')) {
        $ADCSWebEnrollmentUrl = $ADCSWebEnrollmentUrl.Substring(0,$ADCSWebEnrollmentUrl.Length-1)
    } 

    # The IIS Web Server hosting ADCS Web Enrollment may be configured for Windows Authentication, Basic Authentication, or both.
    if ($ADCSWebAuthType -eq "Windows") {
        if (!$ADCSWebCreds) {
            if (!$ADCSWebAuthUserName) {
                $ADCSWebAuthUserName = Read-Host -Prompt "Please specify the AD account to be used for ADCS Web Enrollment authentication."
                # IMPORTANT NOTE: $ADCSWebAuthUserName should NOT include the domain prefix. Example: testadmin
            }
            if ($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]") {
                $ADCSWebAuthUserName = $ADCSWebAuthUserName.Split("\")[1]
            }

            if (!$ADCSWebAuthPass) {
                $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
            }

            $ADCSWebCreds = New-Object System.Management.Automation.PSCredential ($ADCSWebAuthUserName, $ADCSWebAuthPass)
        }

        # Test Connection to $ADCSWebEnrollmentUrl
        # Validate $ADCSWebEnrollmentUrl...
        $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Credential $ADCSWebCreds).StatusCode
        if ($StatusCode -eq "200") {
            Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing"
        }
        else {
            Write-Host "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
            $global:FunctionResult = "1"
            return
        }
    }
    if ($ADCSWebAuthType -eq "Basic") {
        if (!$ADCSWebAuthUserName) {
            $PromptMsg = "Please specify the AD account to be used for ADCS Web Enrollment authentication. " +
            "Please *include* the domain prefix. Example: test\testadmin"
            $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
        }
        while (![bool]$($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]")) {
            Write-Host "Please include the domain prefix before the username. Example: test\testadmin"
            $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
        }

        if (!$ADCSWebAuthPass) {
            $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
        }
        # If $ADCSWebAuthPass is a Secure String, convert it back to Plaintext
        if ($ADCSWebAuthPass.GetType().Name -eq "SecureString") {
            $ADCSWebAuthPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ADCSWebAuthPass))
        }

        $pair = "${$ADCSWebAuthUserName}:${$ADCSWebAuthPass}"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
        $base64 = [System.Convert]::ToBase64String($bytes)
        $basicAuthValue = "Basic $base64"
        $headers = @{Authorization = $basicAuthValue}

        # Test Connection to $ADCSWebEnrollmentUrl
        # Validate $ADCSWebEnrollmentUrl...
        $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Headers $headers).StatusCode
        if ($StatusCode -eq "200") {
            Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing" -ForeGroundColor Green
        }
        else {
            Write-Error "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
            $global:FunctionResult = "1"
            return
        }
    }

    # Check available Certificate Templates...
    if ($ADCSWebAuthType -eq "Windows") {
        $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Credential $ADCSWebCreds
    }
    if ($ADCSWebAuthType -eq "Basic") {
        $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Headers $headers
    }

    $ValidADCSWebEnrollCertTemplatesPrep = ($CertTemplCheckInitialResponse.RawContent.Split("`r") | Select-String -Pattern 'Option Value=".*').Matches.Value
    $ValidADCSWEbEnrollCertTemplates = foreach ($obj1 in $ValidADCSWebEnrollCertTemplatesPrep) {
        $obj1.Split(";")[1]
    }
    # Validate specified Certificate Template...
    while ($ValidADCSWebEnrollCertTemplates -notcontains $BasisTemplate) {
        Write-Warning "$BasisTemplate is not on the list of available Certificate Templates on the ADCS Web Enrollment site."
        $DDMsg = "IMPORTANT NOTE: For a Certificate Template to appear in the Certificate Template drop-down on the ADCS " +
        "Web Enrollment site, the msPKITemplateSchemaVersion attribute MUST BE '2' or '1' AND pKIExpirationPeriod MUST " +
        "BE 1 year or LESS"
        Write-Host $DDMsg -ForeGroundColor Yellow
        Write-Host "Certificate Templates available via ADCS Web Enrollment are as follows:`n$($ValidADCSWebEnrollCertTemplates -join "`n")"
        $BasisTemplate = Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificate to be based on"
    }

    $CertTemplvsCSPHT = @{}
    $ValidADCSWebEnrollCertTemplatesPrep | foreach {
        $key = $($_ -split ";")[1]
        $value = [array]$($($_ -split ";")[8] -split "\?")
        $CertTemplvsCSPHT.Add($key,$value)
    }
    
    $ValidADCSWebEnrollCSPs = $CertTemplvsCSPHT.$BasisTemplate

    while ($ValidADCSWebEnrollCSPs -notcontains $ProviderNameValue) {
        $PNMsg = "$ProviderNameVaule is not a valid Provider Name. Valid Provider Names based on your choice in Basis " +
        "Certificate Template are as follows:`n$($ValidADCSWebEnrollCSPs -join "`n")"
        Write-Host $PNMsg
        $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
    }
}
    


##### END Initial Variable Definition and Validation #####

##### BEGIN Writing the Certificate Request Config File #####

# This content is saved to $CertGenWorking\$CertificateRequestConfigFile
# For more information about the contents of the config file, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx 

Set-Content -Value '[Version]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
Add-Content -Value 'Signature="$Windows NT$"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
Add-Content -Value '[NewRequest]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
Add-Content -Value "FriendlyName = $CertificateCN" -Path "$CertGenWorking\$CertificateRequestConfigFile"

# For below Subject, for a wildcard use "CN=*.DOMAIN.COM"
Add-Content -Value "Subject = `"CN=$CertificateCN,OU=$OrganizationalUnit,O=$Organization,L=$Locality,S=$State,C=$Country`"" -Path $CertGenWorking\$CertificateRequestConfigFile

Add-Content -Value "KeyLength = $KeyLength" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "HashAlgorithm = $HashAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "EncryptionAlgorithm = $EncryptionAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "Exportable = $PrivateKeyExportableValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "KeySpec = $KeySpecValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "KeyUsage = $KeyUsageValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "MachineKeySet = $MachineKeySet" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "SMIME = $SMIMEValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value 'PrivateKeyArchive = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value "UserProtected = $UserProtected" -Path "$CertGenWorking\$CertificateRequestConfigFile"

Add-Content -Value 'UseExistingKeySet = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

if ($ProviderNameOverride -eq "Yes" -or $ProviderNameOverride -eq "y") {
    Write-Host ""
    Write-Host "All available Cryptographic Providers (CSPs) are as follows:"
    Write-Host ""
    $PossibleProvidersPrep = certutil -csplist | Select-String "Provider Name" -Context 0,1
    $PossibleProviders = foreach ($obj1 in $PossibleProvidersPrep) {
        $obj2 = $obj1.Context.PostContext | Select-String 'FAIL' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
        $obj3 = $obj1.Context.PostContext | Select-String 'not ready' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
        if ($obj2 -ne "True" -and $obj3 -ne "True") {
            $obj1.Line -replace "Provider Name: ",""
        }
    }
    $PossibleProviders
    Write-Host ""
    Write-Host "Available Cryptographic Providers (CSPs) based on your choice in Certificate Template (i.e. $($BasisTemplate)) are as follows:"
    Write-Host ""
    $AvailableCSPsBasedOnCertificateTemplate = (Get-ADObject $CertificateTemplateLDAPObject -Properties * | Select-Object -ExpandProperty pkiDefaultCSPs) -replace '[0-9],',''
    $AvailableCSPsBasedOnCertificateTemplate
    # NOTE: There can only be one (1) ProviderNameValue. Maybe no need to use array.
    $ProviderNameValuePrep = $(Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use")
    $ProviderNameValue = $ProviderNameValuePrep.Split(",").Trim()
    # Validation check...
    foreach ($obj1 in $ProviderNameValue) {
        if ($AvailableCSPsBasedOnCertificateTemplate -notcontains $obj1) {
            Write-Host "$($obj1) is not a valid ProviderNameValue. Valid Provider Names based on your choice in Basis Certificate Template are as follows:"
            $AvailableCSPsBasedOnCertificateTemplate
            $ProviderNameValuePrep = $(Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use")
            $ProviderNameValue = $ProviderNameValuePrep.Split(",").Trim()
            # Validation check...
            foreach ($obj1 in $ProviderNameValue) {
                if ($AvailableCSPsBasedOnCertificateTemplate -notcontains $obj1) {
                    Write-Host "$($obj1) is not a valid ProviderNameValue. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
    Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    
    # Next, get the $ProviderTypeValue based on $ProviderNameValue
    $ProviderTypeValuePrep = certutil -csplist | Select-String $ProviderNameValue -Context 0,1
    $ProviderTypeValue = $ProviderTypeValuePrep.Context.PostContext | Select-String -Pattern '[0-9]{1,2}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    Add-Content -Value "ProviderType = `"$ProviderTypeValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
}
else {
    Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    $ProviderTypeValuePrep = certutil -csplist | Select-String $ProviderNameValue -Context 0,1
    $ProviderTypeValue = $ProviderTypeValuePrep.Context.PostContext | Select-String -Pattern '[0-9]{1,2}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    Add-Content -Value "ProviderType = `"$ProviderTypeValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
}

if ($RequestTypeOverride -eq "Yes" -or $RequestTypeOverride -eq "y") {
    # TODO: Valid RequestType options are CMC, PKCS10, PKCS10-, PKCS7, and Cert
    # HOWEVER, the "Cert" RequestType indicates a self-signed or self-issued certificate. It does NOT generate a request, but rather a new certificate
    # and then installs the certificate. To create a self-issued certificate that is NOT self-signed, specify a signing cert by using the -cert option 
    # in the certreq.exe command. For this to work, you must 1) add "Cert" to the below $ValidRequestTypes array. 2) Uncomment 
    # the below 'if' statement: if ($RequestTypeValue -eq "Cert"), 3) Uncomment the "certreq -new -cert ..." command, 4) Comment the original 
    # "certreq -new ..." command, and 5) Comment the "certreq submit ..." command
    Write-Host ""
    Write-Host "Available RequestType values are as follows:"
    $ValidRequestTypes = @("CMC", "PKCS10", "PKCS10-", "PKCS7")
    $ValidRequestTypes
    $RequestTypeValue = $(Read-Host -Prompt "Please enter the RequestType value you would like to use")
    # Validation check...
    if ($ValidRequestTypes -notcontains $RequestTypeValue) {
        Write-Host "The RequestType value is not valid. Please choose a RequestType value from the list of available RequestType values. halting!"
        $global:FunctionResult = "1"
        return
    }
    
    # Add RequestType format  
    Add-Content -Value "RequestType = $RequestTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
}
else {
    Add-Content -Value "RequestType = $RequestTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
}
<#
TODO: Logic for self-signed and/or self-issued certificates that DO NOT generate a CSR and DO NOT submit to Certificate Authority
if ($RequestTypeValue -eq "Cert") {
    $ValidityPeriodValue = Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
    #NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"
    $ValidityPeriodPrep = $ValidityPeriodValue.Split(" ") | Select-Object -Index 1
    if ($ValidityPeriodPrep.EndsWith("s")) {
        $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()
    }
    else {
        $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()+'s'
    }
    $ValidityPeriodUnits = $ValidityPeriodValue.Split(" ") | Select-Object -Index 0

    Add-Content -Value "ValidityPeriodUnits = $ValidityPeriodUnits" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value "ValidityPeriod = $ValidityPeriod" -Path "$CertGenWorking\$CertificateRequestConfigFile"
}
#>

if ($IntendedPurposeValues) {
    Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value '[Strings]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"' -Path "$CertGenWorking\$CertificateRequestConfigFile"

    $GetIntendedPurposeResults = Get-IntendedPurposeAdjudication -IntendedPurposeValues $IntendedPurposeValues -OIDHashTable $OIDHashTable
    $szOIDArray = $GetIntendedPurposeResults.szOIDArray
    $CertRequestConfigFileStringsSectionArray = $GetIntendedPurposeResults.CertRequestConfigFileStringsSectionArray
    $ExtKeyUse = $GetIntendedPurposeResults.ExtKeyUse
    $AppPol = $GetIntendedPurposeResults.AppPol

    foreach ($obj1 in $CertRequestConfigFileStringsSectionArray) {
        Add-Content -Value "$obj1" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }

    Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value '[Extensions]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    $szOIDArrayFirstItem = $szOIDArray[0]
    Add-Content -Value "%szOID_ENHANCED_KEY_USAGE%=`"{text}%$szOIDArrayFirstItem%,`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    $szOIDArray.RemoveAt(0)
    foreach ($obj1 in $szOIDArray) {
        Add-Content -Value "_continue_ = `"%$obj1%`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }
}
else {
    $IntendedPurposesFromCertificateTemplate = $($OIDHashTable.GetEnumerator() | Where-Object {$_.Value -eq $AllCertificateTemplateProperties.pKIExtendedKeyUsage}).Name
    Write-Host "Using Intended Purpose Values from the Basis Certificate Template $BasisTemplate, i.e. $($IntendedPurposesFromCertificateTemplate -join ", ") ..."
}

if ($SANObjectsToAdd) {
    Add-Content -Value '2.5.29.17 = "{text}"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    
    if ($SANObjectsToAdd -contains "DNS") {
        if (!$DNSSANObjects) {
            $DNSSANObjects = Read-Host -Prompt "Please enter one or more DNS SAN objects separated by commas`nExample: www.fabrikam.com, www.contoso.org"
            $DNSSANObjects = $DNSSANObjects.Split(",").Trim()
        }

        foreach ($DNSSAN in $DNSSANObjects) {
            Add-Content -Value "_continue_ = `"dns=$DNSSAN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "Distinguished Name") {
        if (!$DistinguishedNameSANObjects) {
            $DNMsg = "Please enter one or more Distinguished Name SAN objects ***separated by semi-colons***`n" +
            "Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"
            $DistinguishedNameSANObjects = Read-Host -Prompt $DNMsg
            $DistinguishedNameSANObjects = $DistinguishedNameSANObjects.Split(";").Trim()
        }

        foreach ($DNObj in $DistinguishedNameSANObjects) {
            Add-Content -Value "_continue_ = `"dn=$DNObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "URL") {
        if (!$URLSANObjects) {
            $URLMsg = "Please enter one or more URL SAN objects separated by commas`nExample: " +
            "http://www.fabrikam.com, http://www.contoso.com"
            $URLSANObjects = Read-Host -Prompt $URLMsg
            $URLSANObjects = $URLSANObjects.Split(",").Trim()
        }
        
        foreach ($UrlObj in $URLSANObjects) {
            Add-Content -Value "_continue_ = `"url=$UrlObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "IP Address") {
        if (!$IPAddressSANObjects) {
            $IPAddressSANObjects = Read-Host -Prompt "Please enter one or more IP Addresses separated by commas`nExample: 172.31.10.13, 192.168.2.125"
            $IPAddressSANObjects = $IPAddressSANObjects.Split(",").Trim()
        }

        foreach ($IPAddr in $IPAddressSANObjects) {
            if (!$(Test-IsValidIPAddress -IPAddress $IPAddr)) {
                Write-Error "$IPAddr is not a valid IP Address! Halting!"

                # Cleanup
                Remove-Item $CertGenWorking -Recurse -Force

                $global:FunctionResult = "1"
                return
            }
        }
        
        foreach ($IPAddr in $IPAddressSANObjects) {
            Add-Content -Value "_continue_ = `"ipaddress=$IPAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "Email") {
        if (!$EmailSANObjects) {
            $EmailSANObjects = Read-Host -Prompt "Please enter one or more Email SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
            $EmailSANObjects = $EmailSANObjects.Split(",").Trim()
        }
        
        foreach ($EmailAddr in $EmailSANObjectsArray) {
            Add-Content -Value "_continue_ = `"email=$EmailAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "UPN") {
        if (!$UPNSANObjects) {
            $UPNSANObjects = Read-Host -Prompt "Please enter one or more UPN SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
            $UPNSANObjects = $UPNSANObjects.Split(",").Trim()
        }
        
        foreach ($UPN in $UPNSANObjects) {
            Add-Content -Value "_continue_ = `"upn=$UPN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
    if ($SANObjectsToAdd -contains "GUID") {
        if (!$GUIDSANObjects) {
            $GUIDMsg = "Please enter one or more GUID SAN objects separated by commas`nExample: " +
            "f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39, g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48"
            $GUIDSANObjects = Read-Host -Prompt $GUIDMsg
            $GUIDSANObjects = $GUIDSANObjects.Split(",").Trim()
        }
        
        foreach ($GUID in $GUIDSANObjectsArray) {
            Add-Content -Value "_continue_ = `"guid=$GUID&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }
}

##### END Writing the Certificate Request Config File #####


##### BEGIN Generate Certificate Request and Submit to Issuing Certificate Authority #####

## Generate new Certificate Request File: ##
# NOTE: The generation of a Certificate Request File using the below "certreq.exe -new" command also adds the CSR to the 
# Client Machine's Certificate Request Store located at PSDrive "Cert:\CurrentUser\REQUEST" which is also known as 
# "Microsoft.PowerShell.Security\Certificate::CurrentUser\Request"
# There doesn't appear to be an equivalent to this using PowerShell cmdlets
$null = certreq.exe -new "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"
# TODO: If the Certificate Request Configuration File referenced in the above command contains "RequestType = Cert", then instead of the above command, 
# the below certreq command should be used:
# certreq.exe -new -cert [CertId] "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"

if ($ADCSWebEnrollmentUrl) {
    # POST Data as a hash table
    $postParams = @{            
        "Mode"             = "newreq"
        "CertRequest"      = $(Get-Content "$CertGenWorking\$CertificateRequestFile" -Encoding Ascii | Out-String)
        "CertAttrib"       = "CertificateTemplate:$BasisTemplate"
        "FriendlyType"     = "Saved-Request+Certificate+($(Get-Date -DisplayHint Date -Format M/dd/yyyy),+$(Get-Date -DisplayHint Date -Format h:mm:ss+tt))"
        "Thumbprint"       = ""
        "TargetStoreFlags" = "0"
        "SaveCert"         = "yes"
    }

    # Submit New Certificate Request and Download New Certificate
    if ($ADCSWebAuthType -eq "Windows") {
        # Send the POST Data
        Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Credential $ADCSWebCreds -OutFile "$CertGenWorking\$CertADCSWebResponse"
    
        # Download New Certificate
        $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponse" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
        if ($ReqId -eq $null) {
            Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
            the Certificate Request Config File and try again."
            $global:FunctionResult = "1"
            return
        }

        $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Credential $ADCSWebCreds).RawContent
        # Replace the line that begins with `r with ;;; then split on ;;; and select the last object in the index
        (($CertWebRawContent.Split("`n") -replace "^`r",";;;") -join "`n").Split(";;;")[-1].Trim() | Out-File "$CertGenWorking\$CertFileOut"
        # Alternate: Skip everything up until `r
        #$CertWebRawContent.Split("`n") | Select-Object -Skip $([array]::indexof($($CertWebRawContent.Split("`n")),"`r")) | Out-File "$CertGenWorking\$CertFileOut"
    }
    if ($ADCSWebAuthType -eq "Basic") {
        # Send the POST Data
        Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Headers $headers -OutFile "$CertGenWorking\$CertADCSWebResponse"

        # Download New Certificate
        $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponse" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
        if ($ReqId -eq $null) {
            Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
            the Certificate Request Config File and try again."
            $global:FunctionResult = "1"
            return
        }

        $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Headers $headers).RawContent
        $CertWebRawContentArray = $CertWebRawContent.Split("`n") 
        $CertWebRawContentArray | Select-Object -Skip $([array]::indexof($CertWebRawContentArray,"`r")) | Out-File "$CertGenWorking\$CertFileOut"
    }
}

if (!$ADCSWebEnrollmentUrl) {
    ## Submit New Certificate Request File to Issuing Certificate Authority and Specify a Certificate to Use as a Base ##
    if (Test-Path "$CertGenWorking\$CertificateRequestFile") {
        certreq.exe -submit -attrib "CertificateTemplate:$cnForBasisTemplate" -config "$IssuingCertAuth" "$CertGenWorking\$CertificateRequestFile" "$CertGenWorking\$CertFileOut" "$CertGenWorking\$CertificateChainOut"
        # Equivalent of above certreq command using "Get-Certificate" cmdlet is below. We decided to use certreq.exe though because it actually outputs
        # files to the filesystem as opposed to just working with the client machine's certificate store.  This is more similar to the same process on Linux.
        #
        # ## Begin "Get-Certificate" equivalent ##
        # $LocationOfCSRInStore = $(Get-ChildItem Cert:\CurrentUser\Request | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty PSPath
        # Get-Certificate -Template $cnForBasisTemplate -Url "https:\\$IssuingCertAuthFQDN\certsrv" -Request $LocationOfCSRInStore -CertStoreLocation Cert:\CurrentUser\My
        # NOTE: The above Get-Certificate command ALSO imports the certificate generated by the above request, making the below "Import-Certificate" command unnecessary
        # ## End "Get-Certificate" equivalent ##
    }
}
    
if (Test-Path "$CertGenWorking\$CertFileOut") {
    ## Generate .pfx file by installing certificate in store and then exporting with private key ##
    # NOTE: I'm not sure why importing a file that only contains the public certificate (i.e, the .cer file) suddenly makes the private key available
    # in the Certificate Store. It just works for some reason...
    # First, install the public certificate in store
    Import-Certificate -FilePath "$CertGenWorking\$CertFileOut" -CertStoreLocation Cert:\CurrentUser\My
    # certreq.exe equivalent of the above Import-Certificate command is below. It is not as reliable as Import-Certifcate.
    # certreq -accept -user "$CertGenWorking\$CertFileOut"     

    # Then, export cert with private key in the form of a .pfx file
    if ($MachineKeySet -eq "FALSE") {
        Sleep 5
        $LocationOfCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*CN=$CertificateCN*"}) | Select-Object -ExpandProperty PSPath
        if ($LocationOfCertInStore.Count -gt 1) {
            Write-Host ""
            Write-Host "Writing LocationofCertInStore"
            Write-Host ""
            $LocationOfCertInStore
            Write-Host ""
            Write-Host "You have more than one certificate in your Certificate Store under Cert:\CurrentUser\My with the same Common Name (CN). Please correct this and try again."
            $global:FunctionResult = "1"
            return
        }
        Sleep 5
        Export-PfxCertificate -Cert $LocationOfCertInStore -FilePath "$CertGenWorking\$PFXFileOut" -Password $PFXPwdAsSecureString
        # Equivalent of above using certutil
        # $ThumbprintOfCertToExport = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty Thumbprint
        # certutil -exportPFX -p "$PFXPwdPlainText" my $ThumbprintOfCertToExport "$CertGenWorking\$PFXFileOut"

        if ($UseOpenSSL -eq "Yes" -or $UseOpenSSL -eq "y") {
            # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
            $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureString))

            # Extract Private Key and Keep It Password Protected
            & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nocerts -out "$CertGenWorking\$ProtectedPrivateKeyOut" -nodes -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

            # The .pfx File Contains ALL Public Certificates in Chain 
            # The below extracts ALL Public Certificates in Chain
            & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nokeys -out "$CertGenWorking\$AllPublicKeysInChainOut" -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

            # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
            # These files should have the EXACT SAME CONTENT as the .cer counterparts
            $PublicKeySansChainPrep1 = Get-Content "$CertGenWorking\$AllPublicKeysInChainOut"
            $LinesToReplace1 = $PublicKeySansChainPrep1 | Select-String -Pattern "issuer" | Sort-Object | Get-Unique
            $LinesToReplace2 = $PublicKeySansChainPrep1 | Select-String -Pattern "Bag Attributes" | Sort-Object | Get-Unique
            $PublicKeySansChainPrep2 = (Get-Content "$CertGenWorking\$AllPublicKeysInChainOut") -join "`n"
            foreach ($obj1 in $LinesToReplace1) {
                $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
            }
            foreach ($obj1 in $LinesToReplace2) {
                $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
            }
            $PublicKeySansChainPrep3 = $PublicKeySansChainPrep2.Split(";;;")
            $PublicKeySansChainPrep4 = foreach ($obj1 in $PublicKeySansChainPrep3) {
                if ($obj1.Trim().StartsWith("-")) {
                    $obj1.Trim()
                }
            }
            # Setup Hash Containing Cert Name vs Content Pairs
            $CertNamevsContentsHash = @{}
            foreach ($obj1 in $PublicKeySansChainPrep4) {
                $obj2 = $obj1.Split("`n")[1]
                if ((($PublicKeySansChainPrep1 | Select-String -SimpleMatch $obj2).Line) -ne $null) {
                    $CertNamePrep = (($PublicKeySansChainPrep1 | Select-String -SimpleMatch $obj2 -Context 4).Context.PreContext | Select-String -Pattern "subject").Line
                    $CertName = $CertNamePrep.Split("=") | Select-Object -Last 1
                    $CertNamevsContentsHash.Add("$CertName", "$obj1")
                }
            }

            # Write each Hash Key Value to Separate Files (i.e. writing all public keys in chain to separate files)
            foreach ($obj1 in $CertNamevsContentsHash.Keys) {
                $CertNamevsContentsHash.$obj1 | Out-File "$CertGenWorking\$obj1`_Public_Cert.pem" -Encoding Ascii
            }

            # Determine if we should remove the password from the private key (i.e. $ProtectedPrivateKeyOut)
            if ($StripPrivateKeyOfPassword -eq $null) {
                $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                    Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                }
                else {
                    Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'."
                    $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                        Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                    }
                    else {
                        Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                    # Strip Private Key of Password
                    & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
                }
            }
            if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                # Strip Private Key of Password
                & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
            }
        }
    }
}

# Create Global HashTable of Outputs for use in scripts that source this script
$GenerateCertificateFileOutputHashGlobal = @{}
$GenerateCertificateFileOutputHashGlobal.Add("CertificateRequestConfigFile", "$CertificateRequestConfigFile")
$GenerateCertificateFileOutputHashGlobal.Add("CertificateRequestFile", "$CertificateRequestFile")
$GenerateCertificateFileOutputHashGlobal.Add("CertFileOut", "$CertFileOut")
if ($MachineKeySet -eq "FALSE") {
    $GenerateCertificateFileOutputHashGlobal.Add("PFXFileOut", "$PFXFileOut")
}
if (!$ADCSWebEnrollmentUrl) {
    $CertUtilResponseFile = (Get-Item "$CertGenWorking\*.rsp").Name
    $GenerateCertificateFileOutputHashGlobal.Add("CertUtilResponseFile", "$CertUtilResponseFile")

    $GenerateCertificateFileOutputHashGlobal.Add("CertificateChainOut", "$CertificateChainOut")
}
if ($ADCSWebEnrollmentUrl) {
    $GenerateCertificateFileOutputHashGlobal.Add("CertADCSWebResponse", "$CertADCSWebResponse")
}
if ($UseOpenSSL -eq "Yes" -or $UseOpenSSL -eq "y") {
    $GenerateCertificateFileOutputHashGlobal.Add("AllPublicKeysInChainOut", "$AllPublicKeysInChainOut")

    # Make CertName vs Contents Key/Value Pair hashtable available to scripts that source this script
    $CertNamevsContentsHashGlobal = $CertNamevsContentsHash

    $AdditionalPublicKeysArray = (Get-Item "$CertGenWorking\*_Public_Cert.pem").Name
    # For each Certificate in the hashtable $CertNamevsContentsHashGlobal, determine it it's a Root, Intermediate, or End Entity
    foreach ($obj1 in $AdditionalPublicKeysArray) {
        $SubjectType = (certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject Type=").Line.Split("=")[-1]
        $RootCertFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject matches issuer"
        $EndPointCNFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "CN=$CertificateCN"
        if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -eq $true) {
            $RootCAPublicCertFile = $obj1
            $GenerateCertificateFileOutputHashGlobal.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
        }
        if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -ne $true) {
            $IntermediateCAPublicCertFile = $obj1
            $GenerateCertificateFileOutputHashGlobal.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
        }
        if ($SubjectType -eq "End Entity" -and $EndPointCNFlag.Matches.Success -eq $true) {
            $EndPointPublicCertFile = $obj1
            $GenerateCertificateFileOutputHashGlobal.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
        }
    }

    # Alternate Logic using .Net to Inspect Certificate files to Determine RootCA, Intermediate CA, and Endpoint
    <#
    foreach ($obj1 in $AdditionalPublicKeysArray) {
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import("$CertGenWorking\$obj1")
        if ($certPrint.Issuer -eq $certPrint.Subject) {
            $RootCAPublicCertFile = $obj1
            $RootCASubject = $certPrint.Subject
            $GenerateCertificateFileOutputHashGlobal.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
        }
    }
    foreach ($obj1 in $AdditionalPublicKeysArray) {
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import("$CertGenWorking\$obj1")
        if ($certPrint.Issuer -eq $RootCASubject -and $certPrint.Subject -ne $RootCASubject) {
            $IntermediateCAPublicCertFile = $obj1
            $IntermediateCASubject = $certPrint.Subject
            $GenerateCertificateFileOutputHashGlobal.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
        }
    }
    foreach ($obj1 in $AdditionalPublicKeysArray) {
        $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certPrint.Import("$CertGenWorking\$obj1")
        if ($certPrint.Issuer -eq $IntermediateCASubject) {
            $EndPointPublicCertFile = $obj1
            $EndPointSubject = $certPrint.Subject
            $GenerateCertificateFileOutputHashGlobal.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
        }
    }
    #>

    $GenerateCertificateFileOutputHashGlobal.Add("EndPointProtectedPrivateKey", "$ProtectedPrivateKeyOut")
}
if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
    $GenerateCertificateFileOutputHashGlobal.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyOut")

    # Add UnProtected Private Key to $CertNamevsContentsHashGlobal
    $UnProtectedPrivateKeyContent = ((Get-Content $CertGenWorking\$UnProtectedPrivateKeyOut) -join "`n").Trim()
    $CertNamevsContentsHashGlobal.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyContent")
}

# Return PSObject that contains $GenerateCertificateFileOutputHashGlobal and $CertNamevsContentsHashGlobal HashTables
New-Variable -Name "GenCertOutput" -Scope Script -Value $(
    [pscustomobject][ordered]@{
        GenerateCertificateFileOutputHashGlobal    = $GenerateCertificateFileOutputHashGlobal
        CertNamevsContentsHashGlobal               = $CertNamevsContentsHashGlobal
    }
)

# Write the two Global Output HashTableses to STDOUT for Awareness
Write-Host "The `$GenCertOutput PSObject containing `$GenCertOutput.GenerateCertificateFileOutputHashGlobal and `$GenCertOutput.CertNamevsContentsHashGlobal `
for $CertificateCN should now be available in the current scope as a result of the Generate-Certificate function"

$global:FunctionResult = "0"

# ***IMPORTANT NOTE: If you want to write the Certificates contained in the $CertNamevsContentsHashGlobal out to files again
# at some point in the future, make sure you use the "Out-File" cmdlet instead of the "Set-Content" cmdlet

##### END Generate Certificate Request and Submit to Issuing Certificate Authority #####

}

# Generate-Certificate

































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXy7taDcpwJiMTsWyj3gzQeTH
# oSCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFZ4qfLM1klFyJwl
# /U5yUNW6M2HQMA0GCSqGSIb3DQEBAQUABIIBABw1BMGSjLauG+WRdQ0I0YfujXzr
# zXlMIV1GL997H5uP5j0I3PFhly1EffZ8rnvoyhk5mf8CyrVkMuRTOsI63j1I9q8L
# sPm5SS6sCDj28JddTTo2W9ncNjP1SAMN5jky2xd/tUZf3Rl+jvVoH4Qgl2OFaHXS
# 2e+mm8GB0DZB36TgPfqki4SXoG+/bhFHsYXC0HvHjLigRqOJwS5xx2z3IXTVlHDh
# p7ep4l/OmwRVp4YWUtmlzzBQ7Va1N3vO4SZVwcvGCZys70khN51Ygxu5GWxmq3V2
# uBMSFPOiVKVl26o09TXIIMV3ZPtd0Gi1t3m5uAb3DlUdmWp+S2bZpev1Gf8=
# SIG # End signature block
