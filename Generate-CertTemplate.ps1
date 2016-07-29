<#
.SYNOPSIS
    IMPORTANT NOTE: If you would like the resulting Certificate Template to appear in the Certificate Template drop-down on the ADCS Web Enrollment site, $msPKITemplateSchemaVersion MUST BE "2" or "1"
    AND $pKIExpirationPeriod must be 1 year or LESS
     
    This script/function generates a New Certificate Template AND Publishes it for use.  It does NOT generate actual certificates.
    This script/function attempts to simplify Certificate Template creation by mapping hashtables/arrays of OID and hexadecimal values to the choices an administrator would see using the Certificate Template Console GUI.

    (Please see https://github.com/pldmgg/misc-powershell/blob/master/Generate-Certificate.ps1 for the script/function that
    that actually generates a Certificate for use based off of a Certificate Template.)

    This can be run as a script by uncommenting the very last line calling the Generate-CertTemplate function, or by simply
    loading the entire function into your current PowerShell shell and then calling it.

    IMPORTANT NOTE 1: By running the function without any parameters, the user will be walked through several prompts. 
    This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.

.DESCRIPTION
    This function/script is split into the following sections (ctl-f to jump to each of these sections)
    - Libraries and Helper Functions  (~Lines 287-1056)
    - Variable Definition and Validation (~Lines 1059-1519)
    - Additional High-Level Variable Prep (~Lines 1522-1545)
    - $IntendedPurposeValues / $ExtKeyUse Adjudication (~Lines 1548-2018)
    - $KeyUsageValues Adjudication (~Lines 2020-2118)
    - Other Good Ideas (~Lines 2120-2143)
    - Creating the New Certificate Template (~Lines 2146-2398)
        - Set Permissions on the new Certificate Template LDAP Object (~Lines 2316-2352)
        - Add New Cert Template to List of Cert Templates to Issue (~Lines 2356-2396)

.PARAMETERS
    IMPORTANT NOTE 2: Default values for ALL parameters are already provided, and running the Generate-CertTemplate script/
    function will generate a New Certificate Template with these default values, however, the resulting New Certificate Template
    may not satisfy all of your needs depending on your circumstances.

    Please review the explanation for each of the variables/parameters that can/should be changed below.

    1) $CertGenWorking - Directory that all output files will be written to (currently, the only output is $AttributesFile). Recommend using this directory to save 
    actual certificates (as opposed to the certificate template that this script generates) in the future when they are generated. Using a network location 
    is perfectly fine. 

    (Note that actual certificate generation is outside scope of this script).

    2) $BasisTemplate - Either the CN or the displayName of the Certificate Template that you are basing this New Certificate Template off of.

    3) $NewTemplName - The name that you would like to give the New Certificate Template. This name will appear
        - In adsiedit under CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
        - In certsrv under "Certificate Templates"
        - In the Certificate Templates Console (launched by right-clicking "Certificate Templates" in certsrv and then clicking "Manage")
        - In adsiedit under the new LDAP Object's "displayName" attribute
        - In adsiedit under the new LDAP Object's "cn" attribute
        NOTE: This script ensures that "displayName" AND "cn" attributes of the new LDAP object match in order to reduce future confusion.

    4) $AttributesFile - All attributes assigned to the New Certificate Template will be written to the file specified in the variable. 

    This is purely for purposes of later manual review if desired.

    ## For #5 through #16 (with the exception of #10) , for more information, see: 
    https://technet.microsoft.com/en-us/library/cc736326(v=ws.10).aspx
    and
    https://technet.microsoft.com/en-us/library/cc736326(v=ws.10).aspx
    and
    https://msdn.microsoft.com/en-us/library/cc226527.aspx

    5) $pKIDefaultKeySpec

    6) $pKIMaxIssuingDepth

    7) $pKICritExt

    8) $msPKIEnrollmentFlag

    9) $msPKIMinimalKeySize

    10) $SetSchemaVersionForOlderOS - If this variable is set to "Yes","yes","Y", or "y", you are asserting that there is an
    Operating System in your environment older than Windows 2012/8.1 and $msPKITemplateSchemaVersion will be set to "2".
    If it is set to anything other than "Yes","yes","Y" or "y", then $msPKITemplateSchemaVersion will be set to "4"

    11) $msPKITemplateSchemaVersion - IMPORTANT: If you would like the resulting Certificate Template to appear in the Certificate Template drop-down on the ADCS Web Enrollment site, $msPKITemplateSchemaVersion MUST BE "2" or "1"
    AND $pKIExpirationPeriod must be 1 year or LESS

    12) $msPKIEnrollmentValues

    13) $msPKIPrivateKeyValues

    14) $msPKICertificateNameValues

    15) $pKIExpirationPeriod - IMPORTANT: If you would like the resulting Certificate Template to appear in the Certificate Template drop-down on the ADCS Web Enrollment site, $msPKITemplateSchemaVersion MUST BE "2" or "1"
    AND $pKIExpirationPeriod must be 1 year or LESS

    16) $pKIOverlapPeriod

    17) $LimitEnhancedKeyUsage - If this variable is set to "Yes","yes","Y", or "y", then Certificates generated from
    this New Certificate Template will ONLY be able to be used for Intended Purposes defined by the New Certificate
    Template. For example, if $IntendedPurposeValuesPrep = "Code Signing, Document Signing", then Certificates generated
    from this New Certificate Template will only be able to be used for Code Signing and Document Signing. 
    *****IMPORTANT Different/Additional purposes defined in the Certificate Request will be ignored.*****

    18) $IntendedPurposeValuesPrep - Either a comma-separated string or array of values such as (but not limited to)
    Client Authentication, Server Authentication, Code Signing, etc

    Full list of choices is defined by $ValidIntendedPurposeValues (jump to it using ctl+f)

    19) $KeyUsageValuesPrep - Either a comma-separated string or array of values such as (but not limited to)
    Digital Signature, Non-Repudiation, etc

    Full list of choices is defined by $ValidKeyUsageValues (jump to it using ctl+f)

    20) $LimitCryptographicProviders - If this variable is set to "Yes","yes","Y", or "y", then Certificates generated from
    this New Certificate Template will ONLY be able to use one of the CSPs (i.e. Cryptographic Providers) defined by $CSPPrep.

    IMPORTANT: If $LimitCryptographicProviders is set to affirmative, then $CSPPrep MUST be provided

    21) $CSPPrep - Set this variable ONLY IF $LimitCryptographicProviders is set to "Yes","yes","Y", or "y". By setting this
    variable, you are asserting that certificates generated from this New Certificate Template can only use one of the CSPs defined in this variable. Set this variable using a comma separated string or array of CSP values such as: 
    "Microsoft Enhanced Cryptographic Provider v1.0, Microsoft RSA SChannel Cryptographic Provider"

    22) $CertTemplLDAPObjectSecurityPrincipalIdentityPrep - A comma separated string or array of Active Directory 
    user/computer/group accounts that will be granted certain permissions with respect to the New Certificate Template
    LDAP object. View these permissions after the creation of the New Certificate Template by launching adsiedit, navigating
    to the New Certificate Template LDAP Object, right-click and select Properties, and click the Security tab.

    23) $CertTemplLDAPObjectSecurityRightsPrep - Sets access rights for EACH ACCOUNT LISTED IN $CertTemplLDAPObjectSecurityPrincipalIdentityPrep. Valid values include (but are not limited to GenericWrite, ExtendedRight,
    etc. See $ValidSecurityRights for a complete list of acceptable values (use ctl+f).

    IMPORTANT NOTE 3: EACH ACCOUNT LISTED IN $CertTemplLDAPObjectSecurityPrincipalIdentityPrep will be assigned the SAME
    permissions! Currently, this script does NOT contain logic to assign different permissions to different accounts.

    24) CertTemplLDAPObjectSecurityType - Either "Allow" or "Deny" AD accounts defined by $CertTemplLDAPObjectSecurityPrincipalIdentityPrep the rights defined by $CertTemplLDAPObjectSecurityRightsPrep

.DEPENDENCIES
    1) PSPKI Module (See: https://pspki.codeplex.com/)
        IMPORTANT NOTE: The main reason that the PSPKI module is needed it to automate the step of publishing the New 
        Certificate Template via the Certificate Templates Console GUI so that is appears in crtsrv.
        
        There is  a cmdlet "Add-CATemplate" available from Microsoft via the ADCSAdministration Module, however, if 
        "Add-CATemplate -Name $NewTemplName -Force" is used immediately after creating the initial LDAP Object for your 
        New Certificate Template, it will FAIL unless you:
        - Wait 15 minutes for some sort of cache to update; or
        - At least "*look at*" the New Certificate Template in the Certificate Templates Console GUI. By "*look at*" I mean 
        navigate Server Manager-->Tools-->Certificate Authority-->right-click the folder "Certificate Templates"--> 
        select "Manage"--> double-click on the New Certificate Template--> click either "OK" or "Cancel" buttons.
        
        If either of these conditions is met, the command "Add-CATemplate -Name $NewTemplName -Force" will be successful.
        However, this effectively destroys one of the main goals of this script/function, which is to be 
        able to be used with automation.


    2) Remote Server Administration Tools (RSAT), specifically:
        - Role Administration Tools
        - AD DS and ADLDS Tools
        - Active Directory Administrative Center
        - AD DS Snap-Ins and Command-Line Tools
        - AD LDS Snap-Ins and Command-Line Tools
    
    3) Your Issuing Certificate Authority server must be:
        - Online; and
        - An "Enterprise Subordinate CA"  
        For details, see: https://technet.microsoft.com/en-us/library/cc732368(v=ws.11).aspx
        - The only Enterprise Subordinate CA in the current domain


    IMPORTANT NOTE ABOUT PSPKI MODULE: Some PSPKI functions, such as Get-CATemplate and Add-CATemplate have the EXACT SAME NAME as CMDLETS found in
    the ADCSAdministration Module. To view conflicts for a particular function/cmdlet, run the following command after both modules are loaded:
    Get-Command [name_of_duplicate_command] -all

    ---- Begin Example ----

    Get-Command Get-CATemplate -all

    CommandType     Name                                               ModuleName
    -----------     ----                                               ----------
    Function        Get-CATemplate                                     PSPKI
    Cmdlet          Get-CATemplate                                     ADCSAdministration

    ---- End Example ----

    To avoid conflicts, when importing the PSPKI Module, use the "-Prefix" parameter to add a prefix to each PSPKI command as seen around line 1151 below:
    Import-Module PSPKI -Prefix PSPKI

    This adds the prefix "PSPKI" to ALL PSPKI functions.  In other words, the PSPKI function:
    Get-CATemplate
    is automatically renamed:
    Get-PSPKICATemplate
    ...for the duration of the script/shell context (they are NOT renamed on the filesystem). All other PSPKI functions are similarly renamed. 

    TODO: Instead of adding the PSPKI prefix, maybe just call the module using full-path, like:
    PSPKI\Get-CATemplate
    or
    ADCSAdministration\Get-CATempate

.SAMPLE USAGE
    EXAMPLE 1: No Parameters Provided
    Generate-CertTemplate

    NOTE: Executing the script/function without any parameters will ask for input on de facto mandatory parameters.
    All other parameters will use default values which should be fine under the vast majority of circumstances.
    De facto mandatory parameters are as follows:
    -CertGenWorking
    -BasisTemplate
    -NewTemplName
    -LimitEnhancedKeyUsage
    -LimitCryptographicProviders
    -IntendedPurposeValuesPrep
    -KeyUsageValuesPrep


    EXAMPLE 2: Minimal Parameters Provided
    Generate-CertTemplate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking" `
    -BasisTemplate "Code Signing" `
    -NewTemplName "CertTempl166" `
    -LimitEnhancedKeyUsage "No" `
    -LimitCryptographicProviders "No" `
    -IntendedPurposeValuesPrep "Code Signing, Document Signing" `
    -KeyUsageValuesPrep "Digital Signature, Non-Repudiation" `


    EXAMPLE 3: All Parameters in Command Line
    Generate-CertTemplate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking" `
    -BasisTemplate "Code Signing" `
    -NewTemplName "CertTempl166" `
    -AttributesFile "CertTempl166_Attributes.txt" `
    -pKIDefaultKeySpec "1" `
    -pKIMaxIssuingDepth "0" `
    -pKICritExt "2.5.29.15" `
    -msPKIEnrollmentFlag "104" `
    -msPKIMinimalKeySize "2048" `
    -SetSchemaVersionForOlderOS "No" `
    -msPKITemplateSchemaVersion "4" `
    -msPKIEnrollmentValues "Get Issuance Policies From Request Instead of Template, Ignore need for enroll permissions on renewals, Include Basic Constraints in Certificate, Enable Enroll-On-Behalf-Of Function, AutoEnroll, Publish certificate in Active Directory, Include symmetric algorithms allowed by the subject" `
    -msPKIPrivateKeyValues "Private Key Exportable, Same Private Key Renewal, Provider Category Legacy Cryptographic Service Provider" `
    -msPKICertificateNameValues "Request Supplies Subject Info, SAN Supplied in Request, FQDN of Requestor Automatically Added to SAN, Use Old Subject and SAN for Renewal" `
    -pKIExpirationPeriod "2 years" `
    -pKIOverlapPeriod "6 weeks" `
    -LimitEnhancedKeyUsage "No" `
    -IntendedPurposeValuesPrep "Code Signing, Document Signing" `
    -KeyUsageValuesPrep "Digital Signature, Non-Repudiation" `
    -LimitCryptographicProviders "Yes" `
    -CSPPrep "Microsoft Enhanced Cryptographic Provider v1.0, Microsoft RSA SChannel Cryptographic Provider" `
    -CertTemplLDAPObjectSecurityPrincipalIdentityPrep "Domain Computers, Domain Controllers, zeroadmin" `
    -CertTemplLDAPObjectSecurityRightsPrep "GenericWrite, ExtendedRight" `
    -CertTemplLDAPObjectSecurityType "Allow"


    EXAMPLE 4: All Parameters with Some Objects Defined Beforehand
    NOTE: The below variables can also be defined as arrays using "$array = @()" syntax as opposed to just strings

    $pKIEnrollmentValuesCmd = "Get Issuance Policies From Request Instead of Template, `
    Ignore need for enroll permissions on renewals, Include Basic Constraints in Certificate, `
    Enable Enroll-On-Behalf-Of Function, AutoEnroll, Publish certificate in Active Directory, `
    Include symmetric algorithms allowed by the subject"

    $msPKIPrivateKeyValuesCmd = "Private Key Exportable, Same Private Key Renewal, `
    Provider Category Legacy Cryptographic Service Provider"

    $msPKICertificateNameValuesCmd = "Request Supplies Subject Info, SAN Supplied in Request, `
    FQDN of Requestor Automatically Added to SAN, Use Old Subject and SAN for Renewal"

    $IntendedPurposeValuesPrepCmd = "Code Signing, Document Signing"

    $KeyUsageValuesPrepCmd = "Digital Signature, Non-Repudiation"

    $CertTemplLDAPObjectSecurityRightsCmd = "GenericWrite, ExtendedRight"

    Generate-CertTemplate `
    -CertGenWorking "C:\Users\zeroadmin\Desktop\CertGenWorking" `
    -BasisTemplate "Code Signing" `
    -NewTemplName CertTempl166 `
    -AttributesFile "CertTempl166_Attributes.txt" `
    -pKIDefaultKeySpec "1" `
    -pKIMaxIssuingDepth "0" `
    -pKICritExt "2.5.29.15" `
    -msPKIEnrollmentFlag "104" `
    -msPKIMinimalKeySize "2048" `
    -SetSchemaVersionForOlderOS "No" `
    -msPKITemplateSchemaVersion "4" `
    -msPKIEnrollmentValues $pKIEnrollmentValuesCmd `
    -msPKIPrivateKeyValues $msPKIPrivateKeyValuesCmd `
    -msPKICertificateNameValues $msPKICertificateNameValuesCmd `
    -pKIExpirationPeriod "2 years" `
    -pKIOverlapPeriod "6 weeks" `
    -LimitEnhancedKeyUsage "No" `
    -IntendedPurposeValuesPrep $IntendedPurposeValuesPrepCmd `
    -KeyUsageValuesPrep $KeyUsageValuesPrepCmd `
    -LimitCryptographicProviders "Yes" `
    -CSPPrep "Microsoft Enhanced Cryptographic Provider v1.0, Microsoft RSA SChannel Cryptographic Provider" `
    -CertTemplLDAPObjectSecurityPrincipalIdentityPrep "Domain Computers, Domain Controllers, zeroadmin" `
    -CertTemplLDAPObjectSecurityRightsPrep $CertTemplLDAPObjectSecurityRightsCmd `
    -CertTemplLDAPObjectSecurityType "Allow"

#>

Function Generate-CertTemplate {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False)]
    $CertGenWorking = $(Read-Host -Prompt "Please enter a full path to a directory that output files will be saved to"),
    
    [Parameter(Mandatory=$False)]
    $BasisTemplate = $(Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificate Template
    to be based on"),

    [Parameter(Mandatory=$False)]
    $NewTemplName = $(Read-Host -Prompt "Please enter a name for your New Certificate Template"),

    # We can determine this automatically using certutil as long as there is only 1 Enterprise Subordinate CA in Domain
    #[Parameter(Mandatory=$False)]
    #$IssuingCertAuth = $(Read-Host -Prompt "Please enter the name of the server that acts as your Issuing Certificate Authority.
    #This name must be able to be resolved via DNS"),

    [Parameter(Mandatory=$False)]
    $AttributesFile = "$NewTemplName_Attributes.txt",

    [Parameter(Mandatory=$False)]
    $pKIDefaultKeySpec = "1",

    [Parameter(Mandatory=$False)]
    $pKIMaxIssuingDepth = "0",

    [Parameter(Mandatory=$False)]
    $pkiCritExt = "2.5.29.15",

    [Parameter(Mandatory=$False)]
    $msPKIEnrollmentFlag = "104",

    [Parameter(Mandatory=$False)]
    $msPKIMinimalKeySize = "2048",
    
    [Parameter(Mandatory=$False)]
    $SetSchemaVersionForOlderOS = "No",

    [Parameter(Mandatory=$False)]
    $msPKITemplateSchemaVersion = "4",
    
    [Parameter(Mandatory=$False)]
    $msPKIEnrollmentValuesPrep = @("Get Issuance Policies From Request Instead of Template","Ignore need for enroll permissions on renewals",`
    "Include Basic Constraints in Certificate","Enable Enroll-On-Behalf-Of Function","AutoEnroll","Publish certificate in Active Directory",`
    "Include symmetric algorithms allowed by the subject"),

    [Parameter(Mandatory=$False)]
    $msPKIPrivateKeyValuesPrep = @("Private Key Exportable","Same Private Key Renewal","Provider Category Legacy Cryptographic Service Provider"),

    [Parameter(Mandatory=$False)]
    $msPKICertificateNameValuesPrep = @("Request Supplies Subject Info","SAN Supplied in Request","FQDN of Requestor Automatically Added to SAN",`
    "Use Old Subject and SAN for Renewal"),

    [Parameter(Mandatory=$False)]
    $pKIExpirationPeriod = "2 years",

    [Parameter(Mandatory=$False)]
    $pKIOverlapPeriod = "6 weeks",

    [Parameter(Mandatory=$False)]
    $LimitEnhancedKeyUsage = $(Read-Host -Prompt "Would you like to limit Certificate Requests using this Certificate Template to Intended Purposes
    explicitly defined by this Certificate Template? [Yes,No]"),

    [Parameter(Mandatory=$False)]
    $IntendedPurposeValuesPrep,  # If this parameter is left as $null, then logic aroud Line 1256 asks for user input

    [Parameter(Mandatory=$False)]
    $KeyUsageValuesPrep,  # If this parameter is left as $null, then logic aroud Line 1308 asks for user input

    [Parameter(Mandatory=$False)]
    $LimitCryptographicProviders = $(Read-Host -Prompt "Would you like to limit the Cryptographic Providers available for a Certificate Request?  [Yes,No]"),

    [Parameter(Mandatory=$False)]
    $CSPPrep,

    [Parameter(Mandatory=$False)]
    $CertTemplLDAPObjectSecurityPrincipalIdentityPrep = "Domain Computers",

    [Parameter(Mandatory=$False)]
    $CertTemplLDAPObjectSecurityRightsPrep = "ExtendedRight",

    [Parameter(Mandatory=$False)]
    $CertTemplLDAPObjectSecurityType = "Allow"
)


##### BEGIN Libraries and Helper Functions #####

#Import-Module PSPKI -Prefix PSPKI

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

function Convert-HexToDec {
    param($hex)

    ForEach ($value in $hex) {
        [Convert]::ToInt32($value,16)
    }
}

function Convert-DecToHex {
    param($dec)

    ForEach ($value in $dec) {
        “{0:x}” -f [Int]$value
    }
}

function Get-PermutationsAll {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $array,

        [Parameter(Mandatory=$False)]
        $cur = "",

        [Parameter(Mandatory=$False)]
        $depth = 0,

        [Parameter(Mandatory=$False)]
        $list = @()
    )

    $depth ++
    for ($i = 0; $i -lt $array.Count; $i++)
    {
        $list += $cur+" "+$array[$i]        

        if ($depth -lt $array.Count)
        {
            $list = Get-PermutationsAll $array ($cur+" "+$array[$i]) $depth $list
        }       
    }

    $list

}

function Get-PermutationsNoRepeats {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $array2,

        [Parameter(Mandatory=$False)]
        $cur2 = "",

        [Parameter(Mandatory=$False)]
        $depth2 = 0,

        [Parameter(Mandatory=$False)]
        $list2 = @()
    )

    $list2 = Get-PermutationsAll -array $array2 -cur $cur2 -depth $depth2 -list $list2

    $list3 = foreach ($obj1 in $list2) {
        [string]$obj2 = $obj1.Split(" ") | Sort-Object | Get-Unique
        $obj2
    }

    $list3 | Sort-Object | Get-Unique
}


function Get-HexArraySumPossibilities {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [array]$hexarray
    )

    # TODO: Validate $hexarray is values are separated by commas

    #$hexarray

    # Temporarily convert Hex to Decimal
    $hexarrayToDec = foreach ($obj1 in $hexarray) {
        Convert-HexToDec $obj1
    }
    #$hexarrayToDec

    $hexarrayToDecCombos = Get-PermutationsNoRepeats $hexarrayToDec
    [array]$hexarrayToDecCombosArray = ($hexarrayToDecCombos | %{$_.trim()}) -replace ' ',','
    #[array]$hexarrayToDecCombosArray
    

    $hexarrayDecCombosSummed = foreach ($obj1 in $hexarrayToDecCombosArray) {
        $obj2 = $obj1.Split(",")
        ($obj2 | Measure-Object -Sum).Sum
    }
    #$hexarrayDecCombosSummed

    $possibleHexSums = foreach ($obj1 in $hexarrayDecCombosSummed) {
        Convert-DecToHex $obj1
    }
    $possibleHexSums
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
    # Document Signing
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

# pKIPeriod Arrays
[array]$3years = @("00","C0","AB","95","8B","A3","FC","FF")
[array]$2years = @("00","80","72","0E","5D","C2","FD","FF")
[array]$1year = @("00","40","39","87","2E","E1","FE","FF")
[array]$12months = @("00","00","4A","5B","1C","E5","FE","FF")
[array]$9months = @("00","80","77","44","D5","2B","FF","FF")
[array]$6months = @("00","00","A5","2D","8E","72","FF","FF")
[array]$3months = @("00","80","D2","16","47","B9","FF","FF")
[array]$2months = @("00","00","37","0F","DA","D0","FF","FF")
[array]$1month = @("00","80","9B","07","6D","E8","FF","FF")
[array]$6weeks = @("00","80","A6","0A","FF","DE","FF","FF")
[array]$4weeks = @("00","00","6F","5C","FF","E9","FF","FF")
[array]$2weeks = @("00","80","37","AE","FF","F4","FF","FF")
[array]$1week = @("00","C0","1B","D7","7F","FA","FF","FF")
[array]$90days = @("00","80","D2","16","47","B9","FF","FF")
[array]$60days = @("00","00","37","0F","DA","D0","FF","FF")
[array]$45days = @("00","40","69","8B","A3","DC","FF","FF")
[array]$30days = @("00","80","9B","07","6D","E8","FF","FF")
[array]$15days = @("00","C0","CD","83","36","F4","FF","FF")
[array]$1day = @("00","40","96","D5","36","FF","FF","FF")

$pKIPeriodHashTable = @{
    "3 years" = $3years
    "2 years" = $2years
    "1 year" = $1year
    "12 months" = $12months
    "9 months" = $9months
    "6 months" = $6months
    "3 months" = $3months
    "2 months" = $2months
    "1 month" = $1month
    "6 weeks" = $6weeks
    "4 weeks" = $4weeks
    "2 weeks" = $2weeks
    "1 week" = $1week
    "90 days" = $90days
    "60 days" = $60days
    "45 days" = $45days
    "30 days" = $30days
    "15 days" = $15days
    "1 day" = $1day
}

# For more details on msPKI-Enrollment-Flag, see: https://msdn.microsoft.com/en-us/library/cc226546.aspx
$msPKIEnrollmentFlagValuesHashTable = @{
    # INCLUDE_SYMMETRIC_ALGORITHMS - Use SMIME
    "Include symmetric algorithms allowed by the subject" = "1"
    # CT_FLAG_PEND_ALL_REQUESTS - The CA will put all requests generated from this template in a pending state
    "All Certificate Requests Pending" = "2"
    # CT_FLAG_PUBLISH_TO_KRA_CONTAINER - The CA will publish the issued certificate to the key recovery agent (KRA) container in AD
    "Publish to KRA" = "4"
    # CT_FLAG_PUBLISH_TO_DS - The CA will append the issued certificate to the userCertificate attribute on the user object in AD
    "Publish certificate in Active Directory" = "8"
    # CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE - Clients will not do autoenrollment for a certificate based on this template
    # if the user's userCertificate attribute in AD has a valid certificate based on the same template
    # (NOTE: Adding this seems to break the math in certain combinations. Not sure why. Leaving commented.)
    # "Check User DS before AutoEnroll" = "10"
    # CT_FLAG_AUTO_ENROLLMENT - Clients will perform autoenrollment for the specified template
    "AutoEnroll" = "20"
    # CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT - Clients will sign the renewal request using the private key of the existing certificate
    # Also instructs the CA to process the renewal requests 
    "Append userCertificate Attribute for User Object" = "40"
    # CT_FLAG_USER_INTERACTION_REQUIRED - Client will prompt for user consent before attempting to enroll for a certificate based on the specified template
    "Prompt the user during enrollment" = "100"
    # CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE - Removes certificates that are no longer needed based on the specific template 
    # from the local certificate storage
    "Remove Other Certificates Based On Template" = "400"
    # CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF - The CA will allow enroll on behalf of (EOBO) functionality.
    "Enable Enroll-On-Behalf-Of Function" = "800"
    # CT_FLAG_ADD_OCSP_NOCHECK - The CA will not include revocation information and add the id-pkix-ocsp-nocheck extension
    "Do Not Include CRL Plus" = "1000"
    # CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL - Client will reuse the private key for a smart card–based certificate renewal if it is 
    # unable to create a new private key on the card.
    "SmartCard reuse keyset if storage full" = "2000"
    # CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS - The CA will not include revocation information and add the id-pkix-ocsp-nocheck extension
    "Do Not Include CRL" = "4000"
    # CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS -  The CA will include Basic Constraints extension in the end entity certificates.
    "Include Basic Constraints in Certificate" = "8000"
    # CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT - The CA will ignore the requirement for Enroll permissions 
    # on the template when processing renewal requests
    "Ignore need for enroll permissions on renewals" = "10000"
    # CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST - This flag indicates that the certificate issuance policies to be included in the issued
    # certificate come from the request rather than from the template. However, the template contains a list of all of the issuance policies 
    # that the request is allowed to specify; if the request contains policies that are not listed in the template, then the request is rejected.
    "Get Issuance Policies From Request Instead of Template" = "20000"
}

# Fore more details, see: https://msdn.microsoft.com/en-us/library/cc226547.aspx
$msPKIPrivateKeyFlagHashTable = @{
    # CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL - This flag instructs the client to create a key archival certificate request
    "Require Private Key Archival" = "1"
    # CT_FLAG_EXPORTABLE_KEY - Client will allow other applications to copy the private key to a .pfx file
    "Private Key Exportable" = "10"
    # CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED - Client will use additional protection for the private key.
    "Strong Private Key Protection" = "20"
    # CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM - Client will use an alternate signature format
    "Alternate Signature Algorithm" = "40"
    # CT_FLAG_REQUIRE_SAME_KEY_RENEWAL - Client will use the same key when renewing the certificate.
    "Same Private Key Renewal" = "80"
    # CT_FLAG_USE_LEGACY_PROVIDER -  Client will process the msPKI-RA-Application-Policies attribute as specified in 
    "Provider Category Legacy Cryptographic Service Provider" = "100"
    # CT_FLAG_ATTEST_PREFERRED -  attestation data is not required when creating the certificate request. It also instructs the server to not`
    # add any attestation OIDs to the issued certificate.
    # "No Attestation Data" = "0"
    # CT_FLAG_ATTEST_REQUIRED - Attestation data is required (by client) when creating the certificate request. Attestation must be completed`
    # (by CA) before any certificates can be issued.
    "Attestation Data Required" = "2000"
    # CT_FLAG_ATTEST_PREFERRED - Informs the client that it SHOULD include attestation data if it is capable of doing so when creating the `
    # certificate request. It also instructs the CA that attestation may or may not be completed before any certificates can be issued.  
    "Attestation Data Preferred" = "1000"
    # CT_FLAG_ATTESTATION_WITHOUT_POLICY - Server will not add any certificate policy OIDs to the issued certificate even though `
    # attestation SHOULD be performed.
    "Attestation Data from Request Only" = "4000"
    # CT_FLAG_EK_TRUST_ON_USE - Attestation based on the user's credentials is to be performed.
    "Attestation via User Creds" = "200"
    # CT_FLAG_EK_VALIDATE_CERT - Attestation based on the hardware certificate of the Trusted Platform Module (TPM) is to be performed. 
    "TPM Certificate Attestation" = "400"
    # CT_FLAG_EK_VALIDATE_KEY - Attestation based on the hardware key of the TPM is to be performed.
    "TPM Key Attestation" = "800"
}

$msPKICertificateNameFlagHashTable = @{
    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT - Client will supply subject information in the certificate request.
    "Request Supplies Subject Info" = "1"
    # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME - Client will supply subject alternate name information in the certificate request.
    "SAN Supplied in Request" = "10000"
    # CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS - The CA will add the value of the requester's FQDN and NetBIOS name to the Subject Alternative Name extension`
    # of the issued certificate.
    "FQDN of Requestor Automatically Added to SAN" = "400000"
    # CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID - The CA will add the value of the objectGUID attribute from the requestor's user object in AD`
    # to the Subject Alternative Name extension of the issued certificate.
    "Add Requestor User objectGUID to SAN" = "1000000"
    # CT_FLAG_SUBJECT_ALT_REQUIRE_UPN - The CA will add the value of the UPN attribute from the requestor's user object in AD`
    # to the Subject Alternative Name extension of the issued certificate.
    "Add Requestor User UPN to SAN" = "2000000"
    # CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL - The CA will add the value of the email attribute from the requestor's user object in AD`
    # to the Subject Alternative Name extension of the issued certificate.
    "Add Requestor User Email to SAN" = "4000000"
    # CT_FLAG_SUBJECT_ALT_REQUIRE_DNS - The CA will add the value obtained from the DNS attribute of the requestor's user object in AD`
    # to the Subject Alternative Name extension of the issued certificate.
    "Add Requestor User DNS to SAN" = "8000000"
    # CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN - The CA will add the value obtained from the DNS attribute of the requestor's user object in AD`
    # as the CN in the subject of the issued certificate.
    "Add Requestor User DNS to Subject" = "10000000"
    # CT_FLAG_SUBJECT_REQUIRE_EMAIL - The CA will add the value of the email attribute from the requestor's user object in AD` 
    # as the subject of the issued certificate.
    "Add Requestor User Email to Subject" = "20000000"
    # CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME - The CA will set the subject name to the requestor's CN from AD.
    "Set Subject to Requestor CN" = "40000000"
    # CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH - The CA will set the subject name to the requestor's distinguished name (DN) from AD.
    "Set Subject to Requestor DN" = "80000000"
    # CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME - The client will reuse values of subject name and alternative subject name extensions 
    # from an existing valid certificate when creating a certificate renewal request
    "Use Old Subject and SAN for Renewal" = "8"
}

##### END Libraries and Helper Functions #####


##### BEGIN Variable Definition and Validation #####
$DomainPrefix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 0
$DomainSuffix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 1
$Hostname = (gwmi Win32_ComputerSystem).Name
$HostFQDN = $Hostname+'.'+$DomainPrefix+'.'+$DomainSuffix

if (Test-Path $CertGenWorking) {
    Write-Host "CertGenWorking directory already exists...No need to create directory"
}
else {
    mkdir $CertGenWorking
}

$ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

$AvailableCertificateAuthorities = (((certutil | Select-String -Pattern "Config:") -replace "Config:[\s]{1,32}``") -replace "'","").trim()
# $AllAvailableCertificateTemplates Using PSPKI
# $AllAvailableCertificateTemplates = Get-PSPKICertificateTemplate
# Using certutil
$AllAvailableCertificateTemplatesPrep = certutil -ADTemplate

# Set and Validate Connection To Issuing Certificate Authority
# IMPORTANT: Assumes only ONE Enterprise Subordinate CA acting as Issuing Certificate Authority
$IssuingCertAuth = foreach ($obj1 in $AvailableCertificateAuthorities) {
    $obj2 = certutil -config $obj1 -CAInfo type | Select-String -Pattern "Enterprise Subordinate CA" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    if ($obj2 -eq "Enterprise Subordinate CA") {
        $obj1
    }
}
$IssuingCertAuthFQDN = $IssuingCertAuth.Split("\") | Select-Object -Index 0
$IssuingCertAuthHostname = $IssuingCertAuth.Split("\") | Select-Object -Index 1
certutil -config $IssuingCertAuth -ping
if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully contacted the server acting as the Issuing Certificate Authority"
}
else {
    Write-Host "Cannot contact the Issuing Certificate Authority. Halting!"
    return
}

## Begin Existing Certificate Template Validation ##

# Determine Valid CNs for Existing Certificate Templates
# Using PSPKI:
# $ValidCertificateTemplatesByCN = $AllAvailableCertificateTemplatesPrep.Name
# Using certutil:
$ValidCertificateTemplatesByCN = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
    $obj2 = $obj1 | Select-String -Pattern "[\w]{1,32}:[\s][\w]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    $obj3 = $obj2 -replace ':[\s][\w]',''
    $obj3
}
$ValidCNNamesAsStringPrep = foreach ($obj1 in $ValidCertificateTemplatesByCN) {
    $obj1.Trim()+','
}
$ValidCNNamesAsString = [string]$ValidCNNamesAsStringPrep

# Determine Valid displayNames for Existing Certificate Templates
# Using PSPKI:
# $ValidCertificateTemplatesByDisplayName = $AllAvailableCertificateTemplatesPrep.DisplayName
# Using certutil:
$ValidCertificateTemplatesByDisplayName = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
    $obj2 = $obj1 | Select-String -Pattern "\:(.*)\-\-" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    $obj3 = ($obj2 -replace ": ","") -replace " --",""
    $obj3
}
$ValidDisplayNamesAsStringPrep = foreach ($obj1 in $ValidCertificateTemplatesByDisplayName) {
    $obj1.Trim()+','
}
$ValidDisplayNamesAsString = [string]$ValidDisplayNamesAsStringPrep

# If $BasisTemplate is not a Valid CN or displayName for and existing Certificate Template, prompt for user input
if ($ValidCertificateTemplatesByCN -notcontains $BasisTemplate -and $ValidCertificateTemplatesByDisplayName -notcontains $BasisTemplate) {
    Write-Host ""
    Write-Host ""
    Write-Host "You must base your New Certificate Template on an existing Certificate Template."
    Write-Host "To do so, please enter either the displayName or CN of the Certificate Template you would like to use as your base."
    Write-Host ""
    Write-Host "Valid displayName values are as follows:"
    Write-Host ""
    $ValidDisplayNamesAsString
    Write-Host ""
    Sleep 2
    Write-Host "Valid CN values are as follows:"
    Write-Host""
    $ValidCNNamesAsString
    Write-Host""

    $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
    # Set displayName and CN Values for user-provided $BasisTemplate
    if ($ValidCertificateTemplatesByCN -contains $BasisTemplate) {
        $cnForBasisTemplate = $BasisTemplate
    }
    if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
        $displayNameForBasisTemplate = $BasisTemplate
    }
    if ($ValidCertificateTemplatesByCN -notcontains $BasisTemplate -and $ValidCertificateTemplatesByDisplayName -notcontains $BasisTemplate) {
        Write-Host ""
        Write-Host ""
        Write-Host "You must base your New Certificate Template on an existing Certificate Template."
        Write-Host "To do so, please enter either the displayName or CN of the Certificate Template you would like to use as your base. Halting!"
        return
    }
}

# If $BasisTemplate is a CN, set the $cnForBasisTemplate variable
if ($ValidCertificateTemplatesByCN -contains $BasisTemplate) {
    $cnForBasisTemplate = $BasisTemplate
}
# If $BasisTemplate is a displayName, set the $displayNameForBasisTemplate variable
if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
    $displayNameForBasisTemplate = $BasisTemplate
}

# Make sure both $cnForBasisTemplate and $displayNameForBasisTemplate are set
if ($cnForBasisTemplate -eq $null -and $displayNameForBasisTemplate -ne $null) {
    $cnForBasisTemplatePrep1 = $AllAvailableCertificateTemplatesPrep | Select-String -Pattern $displayNameForBasisTemplate | Select-Object -ExpandProperty Line
    $cnForBasisTemplatePrep2 = $cnForBasisTemplatePrep1 | Select-String -Pattern "[\w]{1,32}:[\s]$displayNameForBasisTemplate" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    $cnForBasisTemplate = $cnForBasisTemplatePrep2 -replace ":[\s]$displayNameForBasisTemplate",""
}
if ($cnForBasisTemplate -ne $null -and $displayNameForBasisTemplate -eq $null) {
    $displayNameForBasisTemplatePrep1 = $AllAvailableCertificateTemplatesPrep | Select-String -Pattern $cnForBasisTemplate | Select-Object -ExpandProperty Line
    $displayNameForBasisTemplatePrep2 = $displayNameForBasisTemplatePrep1 | Select-String -Pattern "\:(.*)\-\-" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    $displayNameForBasisTemplate = ($displayNameForBasisTemplatePrep2 -replace ": ","") -replace " --",""
}

# Set some variables that need $cnForBasisTemplate or $displayNameForBasisTemplate
#Write-Host "Writing cnForBasisTemplate $cnForBasisTemplate"
$BasisADObject = "CN=$cnForBasisTemplate,$LDAPSearchBase"
$BasisTemplateLDAPObjectDirectoryEntry = $ADSI.psbase.children | where {$_.displayName -contains $displayNameForBasisTemplate}

## End Existing Certificate Template Validation ##

# Validate $IntendedPurposeValuesPrep
$ValidIntendedPurposeValues = @("Code Signing","Client Authentication","Document Signing","Server Authentication",`
"Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",`
"OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",`
"File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",`
"Windows Third Party Application Component","Windows TCB Component","Windows Store",`
"Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",`
"No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",`
"Protected Process Verification","Protected Process Light Verification","Platform Certificate",`
"Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",`
"Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",`
"Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",`
"IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",`
"Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",`
"OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",`
"Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification")
$ValidIntendedPurposeValuesStringPrep = foreach ($obj1 in $ValidIntendedPurposeValues) {
    $obj1+','
}
$ValidIntendedPurposeValuesString = [string]$ValidIntendedPurposeValuesStringPrep
if ($IntendedPurposeValuesPrep -eq $null) {
    Write-Host ""
    Write-Host "Your new Certificate Template must have one or more Intended Purposes"
    Write-Host "Valid Intended Purpose values are as follows:"
    Write-Host ""
    $ValidIntendedPurposeValuesString
    Write-Host ""
    $IntendedPurposeValuesPrep = Read-Host -Prompt "Please enter one (or more) Intended Purpose values separated by commas"
}
if ($IntendedPurposeValuesPrep -ne $null) {
    if (($IntendedPurposeValuesPrep.GetType().Name) -eq "String") {
        $IntendedPurposeValues = $IntendedPurposeValuesPrep.Split(",").Trim()
    }
    if (($IntendedPurposeValuesPrep.GetType().BaseType.Name) -eq "Array") {
        $IntendedPurposeValues = $IntendedPurposeValuesPrep
    }
  
    # Validation check...
    if (Compare-Arrays -LargerArray $ValidIntendedPurposeValues -SmallerArray $IntendedPurposeValues) {
        Write-Host "IntendedPurposeValues are valid...Continuing..."
    }
    else {
        Write-Host "One or more IntendedPurposeValues are NOT valid. Valid Intended Purpose Values are as follows:"
        Write-Host ""
        $ValidIntendedPurposeValuesString
        Write-Host ""
        $IntendedPurposeValuesPrep = Read-Host -Prompt "Please enter one or more Intended Purpose Values separated by commas"
        if (($IntendedPurposeValuesPrep.GetType().Name) -eq "String") {
            $IntendedPurposeValues = $IntendedPurposeValuesPrep.Split(",").Trim()
        }
        if (($IntendedPurposeValuesPrep.GetType().BaseType.Name) -eq "Array") {
            $IntendedPurposeValues = $IntendedPurposeValuesPrep
        }
  
        # Validation check...
        if (Compare-Arrays -LargerArray $ValidIntendedPurposeValues -SmallerArray $IntendedPurposeValues) {
            Write-Host "IntendedPurposeValues are valid...Continuing..."
        }
        else {
            Write-Host "One or more IntendedPurposeValues are NOT valid. Halting!"
            return
        }
    }
}

# Validate $KeyUsageValuesPrep
$ValidKeyUsageValues = @("Digital Signature","Non-Repudiation","Key Encipherment","Data Encipherment","Key Agreement",`
"Certificate Signing","CRL Signing","Encipher Only","Decipher Only")
$ValidKeyUsageValuesStringPrep = foreach ($obj1 in $ValidKeyUsageValues) {
    $obj1+','
}
$ValidKeyUsageValuesString = [string]$ValidKeyUsageValuesStringPrep
if ($KeyUsageValuesPrep -eq $null) {
    Write-Host ""
    Write-Host "Your new Certificate Template must have one or more Key Usage Policies associated with it"
    Write-Host "Valid Key Usage Policies are as follows:"
    Write-Host ""
    $ValidKeyUsageValuesString
    Write-Host ""
    $KeyUsageValuesPrep = Read-Host -Prompt "Please enter one (or more) Key Usage Policy values separated by commas"
}
if ($KeyUsageValuesPrep -ne $null) {
    if (($KeyUsageValuesPrep.GetType().Name) -eq "String") {
        $KeyUsageValues = $KeyUsageValuesPrep.Split(",").Trim()
    }
    if (($KeyUsageValuesPrep.GetType().BaseType.Name) -eq "Array") {
        $KeyUsageValues = $KeyUsageValuesPrep
    }
    
    if (Compare-Arrays -LargerArray $ValidKeyUsageValues -SmallerArray $KeyUsageValues) {
        Write-Host "KeyUsageValues are valid...Continuing..."
    }
    else {
        Write-Host "One or more KeyUsageValues are NOT valid. Valid KeyUsageValues are as follows:"
        Write-Host ""
        $ValidKeyUsageValuesString
        Write-Host ""
        $KeyUsageValuesPrep = Read-Host -Prompt "Please enter one or more KeyUsageValues separated by commas"
        if (($KeyUsageValuesPrep.GetType().Name) -eq "String") {
            $KeyUsageValues = $KeyUsageValuesPrep.Split(",").Trim()
        }
        if (($KeyUsageValuesPrep.GetType().BaseType.Name) -eq "Array") {
            $KeyUsageValues = $KeyUsageValuesPrep
        }
    
        if (Compare-Arrays -LargerArray $ValidKeyUsageValues -SmallerArray $KeyUsageValues) {
            Write-Host "KeyUsageValues are valid...Continuing..."
        }
        else {
            Write-Host "One or more KeyUsageValues are NOT valid. Halting!"
            return
        }
    }
}

# Validate msPKI-Enrollment-Flag
$ValidmsPKIEnrollmentValues = @("Include symmetric algorithms allowed by the subject","All Certificate Requests Pending","Publish to KRA",`
"Publish certificate in Active Directory","AutoEnroll","Append userCertificate Attribute for User Object","Prompt the user during enrollment",`
"Remove Other Certificates Based On Template","Enable Enroll-On-Behalf-Of Function","Do Not Include CRL Plus","Include Basic Constraints in Certificate",`
"Ignore need for enroll permissions on renewals","Get Issuance Policies From Request Instead of Template")
$ValidmsPKIEnrollmentValuesAsString = $ValidmsPKIEnrollmentValues -join ", "
if (($msPKIEnrollmentValuesPrep.GetType().Name) -eq "String") {
    $msPKIEnrollmentValues = $msPKIEnrollmentValuesPrep.Split(",").Trim()
}
if (($msPKIEnrollmentValuesPrep.GetType().BaseType.Name) -eq "Array") {
    $msPKIEnrollmentValues = $msPKIEnrollmentValuesPrep
}

if (Compare-Arrays -LargerArray $ValidmsPKIEnrollmentValues -SmallerArray $msPKIEnrollmentValues) {
    Write-Host "msPKIEnrollmentValues are valid...Continuing..."
}
else {
    Write-Host "The values supplied for msPKIEnrollmentValues are NOT valid. Valid values are as follows:"
    $ValidmsPKIEnrollmentValuesAsString
    $msPKIEnrollmentValuesPrep = Read-Host -Prompt "Please enter one or more msPKIEnrollmentValues separated by commas"
    if (($msPKIEnrollmentValuesPrep.GetType().Name) -eq "String") {
        $msPKIEnrollmentValues = $msPKIEnrollmentValuesPrep.Split(",").Trim()
    }
    if (($msPKIEnrollmentValuesPrep.GetType().BaseType.Name) -eq "Array") {
        $msPKIEnrollmentValues = $msPKIEnrollmentValuesPrep
    }
    if (Compare-Arrays -LargerArray $ValidmsPKIEnrollmentValues -SmallerArray $msPKIEnrollmentValues) {
        Write-Host "msPKIEnrollmentValues are valid...Continuing..."
    }
    else {
        Write-Host "The values supplied for msPKIEnrollmentValues are NOT valid. Halting!"
        return
    }
}

# Validate ms-PKI-Private-Key-Flag
$ValidmsPKIPrivateKeyValues = @("Require Private Key Archival","Private Key Exportable","Strong Private Key Protection","Alternate Signature Algorithm",`
"Same Private Key Renewal","Provider Category Legacy Cryptographic Service Provider","Attestation Data Required","Attestation Data Preferred","Attestation Data from Request Only",`
"Attestation via User Creds","TPM Certificate Attestation","TPM Key Attestation")
$ValidmsPKIPrivateKeyValuesAsString = $ValidmsPKIPrivateKeyValues -join ", "
if (($msPKIPrivateKeyValuesPrep.GetType().Name) -eq "String") {
    $msPKIPrivateKeyValues = $msPKIPrivateKeyValuesPrep.Split(",").Trim()
}
if (($msPKIPrivateKeyValuesPrep.GetType().BaseType.Name) -eq "Array") {
    $msPKIPrivateKeyValues = $msPKIPrivateKeyValuesPrep
}
if (Compare-Arrays -LargerArray $ValidmsPKIPrivateKeyValues -SmallerArray $msPKIPrivateKeyValues) {
    Write-Host "msPKIPrivateKeyValues are valid...Continuing..."
}
else {
    Write-Host "The values supplied for msPKIPrivateKeyValues are NOT valid. Valid values are as follows:"
    $ValidmsPKIPrivateKeyValuesAsString
    $msPKIPrivateKeyValuesPrep = Read-Host -Prompt "Please enter one or more msPKIPrivateKeyValues separated by commas"
    if (($msPKIPrivateKeyValuesPrep.GetType().Name) -eq "String") {
        $msPKIPrivateKeyValues = $msPKIPrivateKeyValuesPrep.Split(",").Trim()
    }
    if (($msPKIPrivateKeyValuesPrep.GetType().BaseType.Name) -eq "Array") {
        $msPKIPrivateKeyValues = $msPKIPrivateKeyValuesPrep
    }
    if (Compare-Arrays -LargerArray $ValidmsPKIPrivateKeyValues -SmallerArray $msPKIPrivateKeyValues) {
        Write-Host "msPKIEnrollmentValues are valid...Continuing..."
    }
    else {
        Write-Host "The values supplied for msPKIPrivateKeyValues are NOT valid. Halting!"
        return
    }
}

# Validate msPKI-Certificate-Name-Flag Attribute
$ValidmsPKICertificateNameValues = @("Request Supplies Subject Info","SAN Supplied in Request","FQDN of Requestor Automatically Added to SAN",`
"Add Requestor User objectGUID to SAN","Add Requestor User UPN to SAN","Add Requestor User Email to SAN","Add Requestor User DNS to SAN",`
"Add Requestor User DNS to Subject","Add Requestor User Email to Subject","Set Subject to Requestor CN","Set Subject to Requestor DN",`
"Use Old Subject and SAN for Renewal")
$ValidmsPKICertificateNameValuesAsString = $ValidmsPKICertificateNameValues -join ", "
if (($msPKICertificateNameValuesPrep.GetType().Name) -eq "String") {
    $msPKICertificateNameValues = $msPKICertificateNameValuesPrep.Split(",").Trim()
}
if (($msPKICertificateNameValuesPrep.GetType().BaseType.Name) -eq "Array") {
    $msPKICertificateNameValues = $msPKICertificateNameValues
}
if (Compare-Arrays -LargerArray $ValidmsPKICertificateNameValues -SmallerArray $msPKICertificateNameValues) {
    Write-Host "msPKICertificateNameValues are valid...Continuing..."
}
else {
    Write-Host "The values supplied for msPKICertificateNameValues are NOT valid. Valid values are as follows:"
    $ValidmsPKICertificateNameValuesAsString
    $msPKICertificateNameValuesPrep = Read-Host -Prompt "Please enter one or more msPKICertificateNameValues separated by commas"
    if (($msPKICertificateNameValuesPrep.GetType().Name) -eq "String") {
        $msPKICertificateNameValues = $msPKICertificateNameValuesPrep.Split(",").Trim()
    }
    if (($msPKICertificateNameValuesPrep.GetType().BaseType.Name) -eq "Array") {
        $msPKICertificateNameValues = $msPKICertificateNameValues
    }
    if (Compare-Arrays -LargerArray $ValidmsPKICertificateNameValues -SmallerArray $msPKICertificateNameValues) {
        Write-Host "msPKICertificateNameValues are valid...Continuing..."
    }
    else {
        Write-Host "The values supplied for msPKICertificateNameValues are NOT valid. Halting!"
        return
    }
}

# ValidpKIPeriodValues
$ValidpKIPeriods = @("3 years","2 years","1 year","12 months","9 months","6 months","3 months","2 months","1 month","6 weeks","4 weeks","2 weeks","1 week",`
"90 days","60 days","45 days","30 days","15 days","1 day")
$ValidpKIPeriodsAsString = $ValidpKIPeriods -join ", "

# Validate pKIExpirationPeriod...
if ($ValidpKIPeriods -notcontains $pKIExpirationPeriod) {
    Write-Host "$pKIExpirationPeriod is not a valid length of time for pKIExpirationPeriod. Valid lengths of time are as follows:"
    Write-Host ""
    Write-Host ""
    $ValidpKIPeriodsAsString
    Write-Host ""
    Write-Host ""
    $pKIExpirationPeriod = Read-Host -Prompt "Please enter a valid length of time"
    if ($ValidpKIPeriods -notcontains $pKIExpirationPeriod) {
        Write-Host "$pKIExpirationPeriod is not a valid length of time for pKIExpirationPeriod. Halting!"
        return
    }
}

# Validate pKIOverlapPeriod...
if ($ValidpKIPeriods -notcontains $pKIOverlapPeriod) {
    Write-Host "$pKIOverlapPeriod is not a valid length of time for pKIOverlapPeriod. Valid lengths of time are as follows:"
    Write-Host "(NOTE: Please note that pKIOverlapPeriod must be less than pKIExpirationPeriod)"
    Write-Host ""
    Write-Host ""
    $ValidpKIPeriodsAsString
    Write-Host ""
    Write-Host ""
    $pKIOverlapPeriod = Read-Host -Prompt "Please enter a valid length of time"
    if ($ValidpKIPeriods -notcontains $pKIOverlapPeriod) {
        Write-Host "$pKIOverlapPeriod is not a valid length of time for pKIExpirationPeriod. Halting!"
        return
    }
}

## Validation Checks on Certificate Template LDAP Object Permissions ##
$ValidUserAccounts = (Get-ADUser -Filter "*").Name
$ValidComputerAccounts = (Get-ADComputer -Filter "*").Name
$ValidGroups = (Get-ADGroup -Filter "*").Name

$ValidSecurityRights = @("CreateChild","DeleteChild","ListChildren","Self","ReadProperty","WriteProperty","DeleteTree","ListObject",`
"ExtendedRight","Delete","ReadControl","GenericExecute","GenericWrite","GenericRead","WriteDacl","WriteOwner","GenericAll","Synchronize","AccessSystemSecurity")
$ValidRightsAsString = $ValidRights -join ", "

$ValidSecurityTypes = @("Allow","Deny")
$ValidSecurityTypesAsString = $ValidSecurityTypes -join ", "

if (($CertTemplLDAPObjectSecurityPrincipalIdentityPrep.GetType().Name) -eq "String") {
        $CertTemplLDAPObjectSecurityPrincipalIdentity = $CertTemplLDAPObjectSecurityPrincipalIdentityPrep.Split(",").Trim()
}
if (($CertTemplLDAPObjectSecurityPrincipalIdentityPrep.GetType().BaseType.Name) -eq "Array") {
    $CertTemplLDAPObjectSecurityPrincipalIdentity = $CertTemplLDAPObjectSecurityPrincipalIdentityPrep
}

if (($CertTemplLDAPObjectSecurityRightsPrep.GetType().Name) -eq "String") {
        $CertTemplLDAPObjectSecurityRights = $CertTemplLDAPObjectSecurityRightsPrep.Split(",").Trim()
}
if (($CertTemplLDAPObjectSecurityRightsPrep.GetType().BaseType.Name) -eq "Array") {
    $CertTemplLDAPObjectSecurityRights = $CertTemplLDAPObjectSecurityRightsPrep
}

$CombinedADUserComputerGroupArray = $ValidUserAccounts + $ValidComputerAccounts + $ValidGroups

# Validation Check on $CertTemplLDAPObjectSecurityPrincipalIdentity...
if (Compare-Arrays -LargerArray $CombinedADUserComputerGroupArray -SmallerArray $CertTemplLDAPObjectSecurityPrincipalIdentity) {
     Write-Host "$CertTemplLDAPObjectSecurityPrincipalIdentity is(are) valid AD user/computer/group account(s). Continuing..."
}
else {
    Write-Host "$CertTemplLDAPObjectSecurityPrincipalIdentity is(are) NOT valid AD user/computer/group account(s)."
    $CertTemplLDAPObjectSecurityPrincipalIdentity = Read-Host -Prompt "Please enter a valid AD user, computer, or group account"
    if (Compare-Arrays -LargerArray $CombinedADUserComputerGroupArray -SmallerArray $CertTemplLDAPObjectSecurityPrincipalIdentity) {
        Write-Host "$CertTemplLDAPObjectSecurityPrincipalIdentity is(are) NOT valid AD user/computer/group account(s). Halting!"
    }
}

# Validation Check on $CertTemplLDAPObjectSecurityRights...
if (! (Compare-Arrays -LargerArray $ValidSecurityRights -SmallerArray $CertTemplLDAPObjectSecurityRights)) {
    Write-Host "Invalid permissions/rights for Certificate Template LDAP object. Valid rights are as follows:"
    Write-Host ""
    Write-Host ""
    $ValidRightsAsString
    Write-Host ""
    Write-Host ""
    $CertTemplLDAPObjectSecurityRightsPrep = Read-Host -Prompt "Please enter a one or more rights separated by commas"
    $CertTemplLDAPObjectSecurityRights = $CertTemplLDAPObjectSecurityRightsPrep.Split(",").Trim()
    if (! (Compare-Arrays -LargerArray $ValidSecurityRights -SmallerArray $CertTemplLDAPObjectSecurityRights)) {
        Write-Host "Invalid permissions/rights for Certificate Template LDAP object. Halting!"
        return
    }
}

# Validation Check on $CertTemplLDAPObjectSecurityType...
if ($ValidSecurityTypes -notcontains $CertTemplLDAPObjectSecurityType) {
    Write-Host "Invalid Security Type for Certificate Template LDAP object. Valid types are as follows:"
    Write-Host ""
    Write-Host ""
    $ValidSecurityTypesAsString
    Write-Host ""
    Write-Host ""
    $CertTemplLDAPObjectSecurityType = Read-Host -Prompt "Please enter a valid Security Type"
    if ($ValidSecurityTypes -notcontains $CertTemplLDAPObjectSecurityType) {
        Write-Host "Invalid Security Type for Certificate Template LDAP object. Halting!"
        return
    }
}

##### END Variable Definition and Validation #####


##### BEGIN Additional High-Level Variable Prep #####
# Using [System.Collections.ArrayList] so that Add and Remove methods work as expected and only operate on a single array 
# instead of destroying and recreating arrays everytime an item is added/removed
[array]$ExtKeyUsePrep = @()
[System.Collections.ArrayList]$ExtKeyUse = $ExtKeyUsePrep

[array]$AppPolPrep = @()
[System.Collections.ArrayList]$AppPol = $AppPolPrep

[array]$KeyUsageHexValuesPrep = @()
[System.Collections.ArrayList]$KeyUsageHexValues = $KeyUsageHexValuesPrep
[array]$KeyUsageHexValuesForByte2Prep = @()
[System.Collections.ArrayList]$KeyUsageHexValuesForByte2Prep = $KeyUsageHexValuesForByte2Prep

[array]$msPKIEnrollmentNumbersPrep = @()
[System.Collections.ArrayList]$msPKIEnrollmentNumbers = $msPKIEnrollmentNumbersPrep

[array]$msPKIPrivateKeyNumbersPrep = @()
[System.Collections.ArrayList]$msPKIPrivateKeyNumbers = $msPKIPrivateKeyNumbersPrep

[array]$msPKICertificateNameNumbersPrep = @()
[System.Collections.ArrayList]$msPKICertificateNameNumbers = $msPKICertificateNameNumbersPrep

Write-Host ""
Write-Host "Adding values to arrays..."
Write-Host ""

##### END Additional High-Level Variable Prep #####


##### BEGIN $IntendedPurposeValues / $ExtKeyUse Adjudication #####

foreach ($obj1 in $IntendedPurposeValues) {
    if ($obj1 -eq "Code Signing") {
        $OfficialName = "PKIX_KP_CODE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Document Signing") {
        $OfficialName = "KP_DOCUMENT_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Client Authentication") {
        $OfficialName = "PKIX_KP_CLIENT_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Private Key Archival") {
        $OfficialName = "KP_CA_EXCHANGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Directory Service Email Replication") {
        $OfficialName = "DS_EMAIL_REPLICATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Key Recovery Agent") {
        $OfficialName = "KP_KEY_RECOVERY_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "OCSP Signing") {
        $OfficialName = "KP_OCSP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Server Authentication") {
        $OfficialName = "PKIX_KP_SERVER_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "EFS") {
        $OfficialName = "KP_EFS"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Secure E-Mail") {
        $OfficialName = "PKIX_KP_EMAIL_PROTECTION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Enrollment Agent") {
        $OfficialName = "ENROLLMENT_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Microsoft Trust List Signing") {
        $OfficialName = "KP_CTL_USAGE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Smartcard Logon") {
        $OfficialName = "IdMsKpScLogon"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "File Recovery") {
        $OfficialName = "EFS_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "IPSec IKE Intermediate") {
        $OfficialName = "IPSEC_KP_IKE_INTERMEDIATE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "KDC Authentication") {
        $OfficialName = "IdPkinitKPKdc"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    ##### Begin Newly Added #####
    if ($obj1 -eq "Remote Desktop") {
        $OfficialName = "Remote Desktop"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Update") {
        $OfficialName = "Windows Update"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Third Party Application Component") {
        $OfficialName = "Windows Third Party Application Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows TCB Component") {
        $OfficialName = "Windows TCB Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Store") {
        $OfficialName = "Windows Store"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Software Extension Verification") {
        $OfficialName = "Windows Software Extension Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows RT Verification") {
        $OfficialName = "Windows RT Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Kits Component") {
        $OfficialName = "Windows Kits Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "No OCSP Failover to CRL") {
        $OfficialName = "No OCSP Failover to CRL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Auto Update End Revocation") {
        $OfficialName = "Auto Update End Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Auto Update CA Revocation") {
        $OfficialName = "Auto Update CA Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Revoked List Signer") {
        $OfficialName = "Revoked List Signer"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Protected Process Verification") {
        $OfficialName = "Protected Process Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Protected Process Light Verification") {
        $OfficialName = "Protected Process Light Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Platform Certificate") {
        $OfficialName = "Platform Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Microsoft Publisher") {
        $OfficialName = "Microsoft Publisher"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Kernel Mode Code Signing") {
        $OfficialName = "Kernel Mode Code Signing"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "HAL Extension") {
        $OfficialName = "HAL Extension"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Endorsement Key Certificate") {
        $OfficialName = "Endorsement Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Early Launch Antimalware Driver") {
        $OfficialName = "Early Launch Antimalware Driver"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Dynamic Code Generator") {
        $OfficialName = "Dynamic Code Generator"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "DNS Server Trust") {
        $OfficialName = "DNS Server Trust"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Document Encryption") {
        $OfficialName = "Document Encryption"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Disallowed List") {
        $OfficialName = "Disallowed List"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Attestation Identity Key Certificate") {
        $OfficialName = "Attestation Identity Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "System Health Authentication") {
        $OfficialName = "System Health Authentication"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "CTL Usage") {
        $OfficialName = "AUTO_ENROLL_CTL_USAGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "IP Security End System") {
        $OfficialName = "PKIX_KP_IPSEC_END_SYSTEM"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "IP Security Tunnel Termination") {
        $OfficialName = "PKIX_KP_IPSEC_TUNNEL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "IP Security User") {
        $OfficialName = "PKIX_KP_IPSEC_USER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Time Stamping") {
        $OfficialName = "PKIX_KP_TIMESTAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Microsoft Time Stamping") {
        $OfficialName = "KP_TIME_STAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows Hardware Driver Verification") {
        $OfficialName = "WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Windows System Component Verification") {
        $OfficialName = "NT5_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "OEM Windows System Component Verification") {
        $OfficialName = "OEM_WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Embedded Windows System Component Verification") {
        $OfficialName = "EMBEDDED_NT_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Root List Signer") {
        $OfficialName = "ROOT_LIST_SIGNER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Qualified Subordination") {
        $OfficialName = "KP_QUALIFIED_SUBORDINATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Key Recovery") {
        $OfficialName = "KP_KEY_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Lifetime Signing") {
        $OfficialName = "KP_LIFETIME_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "Key Pack Licenses") {
        $OfficialName = "LICENSES"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
    if ($obj1 -eq "License Server Verification") {
        $OfficialName = "LICENSE_SERVER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $ExtKeyUse.Add("$OfficialOID")
        if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
            $AppPol.Add("$OfficialOID")
        }
    }
}

##### END $IntendedPurposeValues / $ExtKeyUse Adjudication #####

##### BEGIN $KeyUsageValues Adjudication #####

foreach ($obj1 in $KeyUsageValues) {
    if ($obj1 -eq "Digital Signature") {
        $OfficialName = "CERT_DIGITAL_SIGNATURE_KEY_USAGE"
        $OfficialHexValue = 0x80
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "Non-Repudiation") {
        $OfficialName = "CERT_NON_REPUDIATION_KEY_USAGE"
        $OfficialHexValue = 0x40
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "Key Encipherment") {
        $OfficialName = "CERT_KEY_ENCIPHERMENT_KEY_USAGE"
        $OfficialHexValue = 0x20
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "Data Encipherment") {
        $OfficialName = "CERT_DATA_ENCIPHERMENT_KEY_USAGE"
        $OfficialHexValue = 0x10
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "Key Agreement") {
        $OfficialName = "CERT_KEY_AGREEMENT_KEY_USAGE"
        $OfficialHexValue = 0x08
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "Certificate Signing") {
        $OfficialName = "CERT_KEY_CERT_SIGN_KEY_USAGE"
        $OfficialHexValue = 0x04
        $KeyUsageHexValues.Add("$OfficialHexValue")
    }
    if ($obj1 -eq "CRL Signing") {
        $OfficialName1 = "CERT_OFFLINE_CRL_SIGN_KEY_USAGE"
        $OfficialHexValue1 = 0x02
        $OfficialName2 = "CERT_CRL_SIGN_KEY_USAGE"
        $OfficialHexValue12 = 0x02
        $KeyUsageHexValues.Add("$OfficialHexValue1")
        $KeyUsageHexValues.Add("$OfficialHexValue2")
    }
    # IMPORTANT: "Encipher Only" can only be set if "Key Agreement" is also set.
    if ($obj1 -eq "Encipher Only") {
        if ($KeyUsageValues -contains "Key Agreement") {
            $OfficialName = "CERT_ENCIPHER_ONLY_KEY_USAGE"
            $OfficialHexValue = 0x01
            $KeyUsageHexValues.Add("$OfficialHexValue")
        }
        else {
            Write-Host "'Encipher Only' can only be set if 'Key Agreement' is also set. Not setting Encipher Only."
        }
    }
    # IMPORTANT: "Decipher Only" can only be set if "Key Agreement" is also set.
    # IMPORTANT NOTE: The Decipher Only Hex Value is set in the 2nd byte, as opposed to all above values
    # which are set in the 1st byte.  For example, if you want a combination of "Key Agreement" and 
    # "Decipher Only", then the pKIKeyUsage value in the relevant LDAP object will read:
    # 08 80
    if ($obj1 -eq "Decipher Only") {
        if ($KeyUsageValues -contains "Key Agreement") {
            $OfficialName = "CERT_DECIPHER_ONLY_KEY_USAGE"
            $OfficialHexValue = 0x80
            $KeyUsageHexValuesForByte2.Add("$OfficialHexValue")
        }
        else {
            Write-Host "'Decipher Only' can only be set if 'Key Agreement' is also set. Not setting Encipher Only."
        }
    }

    # Add all values in hex array for FIRST BYTE together.
    # IMPORTANT: Powershell can handle the addition automatically, but output will be in decimal
    $KeyUsageHexValuesSumInDecimal = $KeyUsageHexValues | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $KeyUsageHexValuesSumInHexPrep = Convert-DecToHex $KeyUsageHexValuesSumInDecimal
    if ($KeyUsageHexValuesSumInHexPrep -eq "0") {
        $KeyUsageHexValuesSumInHex = "$KeyUsageHexValuesSumInHexPrep"+"0"
    }
    else {
        $KeyUsageHexValuesSumInHex = $KeyUsageHexValuesSumInHexPrep
    }

    # Add all values in hex array for SECOND BYTE together.
    # IMPORTANT: Powershell can handle the addition automatically, but output will be in decimal
    $KeyUsageHexValuesForByte2SumInDecimal = $KeyUsageHexValuesForByte2 | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    $KeyUsageHexValuesForByte2SumInHexPrep = Convert-DecToHex $KeyUsageHexValuesForByte2SumInDecimal
    if ($KeyUsageHexValuesForByte2SumInHexPrep -eq "0") {
        $KeyUsageHexValuesForByte2SumInHex = "$KeyUsageHexValuesForByte2SumInHexPrep"+"0"
    }
    else {
        $KeyUsageHexValuesForByte2SumInHex = $KeyUsageHexValuesForByte2SumInHexPrep
    }

    # Set Byte Array to be used in Put method below for pKIKeyUsage
    $pKIKeyUsageBytes = New-Object -TypeName Byte[] -ArgumentList 2
    $pKIKeyUsageBytes[0] = Convert-HexToDec $KeyUsageHexValuesSumInHex
    $pKIKeyUsageBytes[1] = Convert-HexToDec $KeyUsageHexValuesForByte2SumInHex
    $pKIKeyUsageBytes

}

##### END $KeyUsageValues Adjudication #####

##### BEGIN Other Good Ideas #####

# If allowing cert to be used for Encrypted File System (EFS), also let it be used for Decrypting files encrypted using EFS
if ($IntendedPurposeValues -contains "EFS" -and $IntendedPurposeValues -contains "File Recovery") {
    Write-Host "Certificate Template allows usage for EFS AND File Recovery. No action necessary."
}
if ($IntendedPurposeValues -contains "EFS" -and $IntendedPurposeValues -notcontains "File Recovery") {
    $OfficialName = "EFS_RECOVERY"
    $OfficialOID = $OIDHashTable.$OfficialName
    $ExtKeyUse.Add("$OfficialOID")
    if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
        $AppPol.Add("$OfficialOID")
    }
}
if ($IntendedPurposeValues -notcontains "EFS" -and $IntendedPurposeValues -contains "File Recovery") {
    $OfficialName = "KP_EFS"
    $OfficialOID = $OIDHashTable.$OfficialName
    $ExtKeyUse.Add("$OfficialOID")
    if ($LimitEnhancedKeyUsage -eq "Yes" -or $LimitEnhancedKeyUsage -eq "y") {
        $AppPol.Add("$OfficialOID")
    }
}

##### END Other Good Ideas #####


##### BEGIN Creating the New Certificate Template #####

# Generate a Unique OID for this new Certificate Template
$OIDRandComp = (Get-Random -Maximum 999999999999999).tostring('d15')
$OIDRandComp = $OIDRandComp.Insert(7,'.')
$CompOIDValuePrep1 = Get-ADObject $BasisADObject -Properties msPKI-Cert-Template-OID | Select-Object -ExpandProperty msPKI-Cert-Template-OID
$CompOIDValuePrep2 = $CompOIDValuePrep1.Split(".") | Select-Object -Last 2
$CompOIDValuePrep3 = foreach ($obj1 in $CompOIDValuePrep2) {
   $obj2 = "."+$obj1
   $obj2
}
$CompOIDValuePrep4 = $CompOIDValuePrep3 -join ''
$CompOIDValuePrep5 = $CompOIDValuePrep1 -replace "$CompOIDValuePrep4",""
$NewCompTemplOID = $CompOIDValuePrep5+"."+$OIDRandComp

$NewTempl = $ADSI.Create("pKICertificateTemplate", "CN=$NewTemplName")
$NewTempl.put("distinguishedName","CN=$NewTemplName,$LDAPSearchBase")

$NewTempl.put("flags","131680")
$NewTempl.put("displayName","$NewTemplName")
$NewTempl.put("revision","100")
# Parameter for pKIDefaultKeySpec above. Default = 1.
# AT_KEYEXCHANGE which is KeySpec = 1 vs AT_SIGNATURE which is KeySpec = 2. 
# Default is AT_KEYEXCHANGE which allows keys to be used for symmetric encryption or signing or both. Change only if you know what you're doing.
$NewTempl.put("pKIDefaultKeySpec","$pKIDefaultKeySpec")

$NewTempl.put("pKIMaxIssuingDepth","$pKIMaxIssuingDepth")
# Parameter for pKICriticalExtensions above. Default value = 2.5.29.15.
# Since OID 2.5.29.15 refers to KeyUsage, by adding this OID to the pKICriticalExtensions, you are making 
# the KeyUsage values Critical (i.e. ticking checkbox "Make this extension critical" under Extensions-->KeyUsage in GUI)
$NewTempl.put("pKICriticalExtensions","$pkiCritExt")

$NewTempl.put("msPKI-RA-Signature","0")

# Determine $msPKIEnrollmentFlag
foreach ($obj1 in $msPKIEnrollmentValues) {
    $obj2 = $msPKIEnrollmentFlagValuesHashTable.$obj1
    $msPKIEnrollmentNumbers.Add("$obj2")
}
$msPKIEnrollmentFlagPrep = $msPKIEnrollmentNumbers | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$msPKIEnrollmentFlag = Convert-HexToDec $msPKIEnrollmentFlagPrep
$NewTempl.put("msPKI-Enrollment-Flag","$msPKIEnrollmentFlag")

# Determine $msPKIPrivateKeyFlag
foreach ($obj1 in $msPKIPrivateKeyValues) {
    $obj2 = $msPKIPrivateKeyFlagHashTable.$obj1
    $msPKIPrivateKeyNumbers.Add("$obj2")
}
$msPKIPrivateKeyFlagPrep = $msPKIPrivateKeyNumbers | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$msPKIPrivateKeyFlag = Convert-HexToDec $msPKIPrivateKeyFlagPrep
$NewTempl.put("msPKI-Private-Key-Flag","$msPKIPrivateKeyFlag")

# Determine msPKI-Certificate-Name-Flag Attribute
foreach ($obj1 in $msPKICertificateNameValues) {
    $obj2 = $msPKICertificateNameFlagHashTable.$obj1
    $msPKICertificateNameNumbers.Add("$obj2")
}
$msPKICertificateNameFlagPrep = $msPKICertificateNameNumbers | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$msPKICertificateNameFlag = Convert-HexToDec $msPKICertificateNameFlagPrep
$NewTempl.put("msPKI-Certificate-Name-Flag","$msPKICertificateNameFlag")

# Parameter for msPKI-Minimal-Key-Size above. Default value = 2048.
$NewTempl.put("msPKI-Minimal-Key-Size","$msPKIMinimalKeySize")

# Parameter for msPKI-Template-Schema-Version. If any OS in environment is older than Windows 2012/8.1, then SchemaVersion = 2.
if ($SetSchemaVersionForOlderOS -eq "Yes" -or $SetSchemaVersionForOlderOS -eq "y") {
    $msPKITemplateSchemaVersion = "2"
}
$NewTempl.put("msPKI-Template-Schema-Version","$msPKITemplateSchemaVersion")

$NewTempl.put("msPKI-Template-Minor-Revision","1")
$NewTempl.put("msPKI-Cert-Template-OID","$NewCompTemplOID")


#------

# Actually create the initial LDAP Object...
$NewTempl.Setinfo()
Sleep 5

#------

# Continue with Additional Modifications to the newly created LDAP Object
# Reference for New LDAP Object
# Need to Refresh $ConfigContext, $ADSI, and $LDAPSearchBase before referencing$NewADObject
$ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$NewADObject = Get-ADObject "CN=$NewTemplName,$LDAPSearchBase"

# Set pKIKeyUsage
$NewTempl.put("pKIKeyUsage",$pKIKeyUsageBytes)
$NewTempl.Setinfo()

# Adding all values from $ExtKeyUse one at a time, using Set-ADObject because we don't have to deal with $NewTempl.Setinfo() 
# weirdness (for explanation of weirdness, see: http://blogs.msmvps.com/richardsiddaway/2008/09/12/adsi-put-and-attributes/)
foreach ($obj1 in $ExtKeyUse) {
    Set-ADObject $NewADObject -Add @{pKIExtendedKeyUsage=$obj1}
}

# Adding all values from $AppPol one at a time, but you can use a hashtable as well
foreach ($obj1 in $AppPol) {
    Set-ADObject $NewADObject -Add @{"msPKI-Certificate-Application-Policy"=$obj1}
}

# Parameter for pKIExpirationPeriod above. Default value = 2 years
$hexarrayexp = $pKIPeriodHashTable.$pKIExpirationPeriod
$pKIExpirationPeriodBytes = New-Object -TypeName Byte[] -ArgumentList 8
For ($loop=1; $loop –lt $pKIExpirationPeriodBytes.Length; $loop++) {
    $conversion2 = Convert-HexToDec $hexarrayexp[$loop]
    $pKIExpirationPeriodBytes[$loop] = $conversion2
    #$interval = [array]::indexof($hexarrayexp,$obj1)
}

#Set-ADObject $NewADObject -Add @{"pKIExpirationPeriod"=$pKIExpirationPeriodBytes}
#$pKIExpirationPeriodBytes
#$pKIExpirationPeriodBytes.GetType()
$NewTempl.put("pKIExpirationPeriod",$pKIExpirationPeriodBytes)
$NewTempl.Setinfo()


# Parameter for pKIOverlapPeriod above. Default value = 6 weeks
$hexarrayover = $pKIPeriodHashTable.$pKIOverlapPeriod
$pKIOverlapPeriodBytes = New-Object -TypeName Byte[] -ArgumentList 8
For ($loop=1; $loop –lt $pKIOverlapPeriodBytes.Length; $loop++) {
    $conversion4 = Convert-HexToDec $hexarrayover[$loop]
    $pKIOverlapPeriodBytes[$loop] = $conversion4
    #$interval = [array]::indexof($hexarrayover,$obj1)
}

#Set-ADObject $NewADObject -Add @{"pKIOverlapPeriod"=$pKIExpirationPeriodBytes}
#$pKIOverlapPeriodBytes
#$pKIOverlapPeriodBytes.GetType()
$NewTempl.put("pKIOverlapPeriod",$pKIOverlapPeriodBytes)
$NewTempl.Setinfo()

# For Microsoft Base Cryptographic Provider v1.0 and Microsoft Enhanced Cryptographic Provider v1.0, Copy from User Template
if ($LimitCryptographicProviders -eq "Yes" -or $LimitCryptographicProviders -eq "y") {
    if ($CSPPrep -eq $null) {
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
        $CSPPrep = Read-Host -Prompt "Please enter one or more CSPs from the above list, separated by commas"
        [array]$CSPPrep2 = $CSPPrep.Split(",").Trim()
        
        # Validation Check...
        if (Compare-Arrays -LargerArray $PossibleProviders -SmallerArray $CSPPrep2) {
            Write-Host ""
            Write-Host "CSPPrep2 value is valid. Continuing..."
            Write-Host ""
        }
        else {
            Write-Host ""
            Write-Host "CSPPrep2 value is NOT valid."
            Write-Host "All available Cryptographic Providers (CSPs) are as follows:"
            Write-Host ""
            $PossibleProviders
            $CSPPrep = Read-Host -Prompt "Please enter one or more CSPs from the above list, separated by commas"
            [array]$CSPPrep2 = $CSPPrep.Split(",").Trim()

            # Validation Check...
            if (Compare-Arrays -LargerArray $PossibleProviders -SmallerArray $CSPPrep2) {
                Write-Host ""
                Write-Host "CSPPrep2 value is valid. Continuing..."
                Write-Host ""
            }
            else {
                Write-Host ""
                Write-Host "CSPPrep2 value is NOT valid. Halting!"
                return
            }
        }

        $CSPs = foreach ($obj1 in $CSPPrep2) {
            $obj2 = [array]::indexof($CSPPrep2,$obj1)
            $obj3 = "$($obj2+1)"+","+"$obj1"
            $obj3
        }
        $NewTempl.pKIDefaultCSPs = $CSPs
        $NewTempl.Setinfo()
    }

    if ($CSPPrep -ne $null) {
        if (($CSPPrep.GetType().Name) -eq "String") {
            [array]$CSPPrep2 = $CSPPrep.Split(",").Trim()
        }
        if (($CSPPrep.GetType().BaseType.Name) -eq "Array") {
            $CSPPrep2 = $CSPPrep
        }
        
        $PossibleProvidersPrep = certutil -csplist | Select-String "Provider Name" -Context 0,1
        $PossibleProviders = foreach ($obj1 in $PossibleProvidersPrep) {
            $obj2 = $obj1.Context.PostContext | Select-String 'FAIL' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
            $obj3 = $obj1.Context.PostContext | Select-String 'not ready' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
            if ($obj2 -ne "True" -and $obj3 -ne "True") {
                $obj1.Line -replace "Provider Name: ",""
            }
        }

        # Validation Check...
        if (Compare-Arrays -LargerArray $PossibleProviders -SmallerArray $CSPPrep2) {
            Write-Host "CSPPrep2 value is valid. Continuing..."
        }
        else {
            Write-Host "CSPPrep2 value is NOT valid."
            Write-Host "All available Cryptographic Providers (CSPs) are as follows:"
            $PossibleProviders
            $CSPPrep = Read-Host -Prompt "Please enter one or more CSPs from the above list, separated by commas"
            [array]$CSPPrep2 = $CSPPrep.Split(",").Trim()

            # Validation Check...
            if (Compare-Arrays -LargerArray $PossibleProviders -SmallerArray $CSPPrep2) {
                Write-Host "CSPPrep2 value is valid. Continuing..."
            }
            else {
                Write-Host "CSPPrep2 value is NOT valid. Halting!"
                return
            }
        }

        $CSPs = foreach ($obj1 in $CSPPrep2) {
            $obj2 = [array]::indexof($CSPPrep2,$obj1)
            $obj3 = "$($obj2+1)"+","+"$obj1"
            $obj3
        }
        $NewTempl.pKIDefaultCSPs = $CSPs
        $NewTempl.Setinfo()
    }
}
else {
    # Not setting pkiDefaultCSPs attribute means that ALL CSPs are available for Certificate Requests using this New Certificate Template
    Write-Host "No need to limit CSPs...Continuing..."
}


##### BEGIN Set Permissions on the new Certificate Template LDAP Object #####
# IMPORTANT NOTE: The way this is written, EACH AD Account/Group will be granted the SAME
# permissions specified by $CertTemplLDAPObjectSecurityRights and $CertTemplLDAPObjectSecurityType
# TODO: Write logic for having different SecurityRights and SecurityTypes for different SecurityPrincipalIdentites

[array]$NewSecurityPrincipalVariableNameArrayPrep = @()
[System.Collections.Arraylist]$NewSecurityPrincipalVariableNameArray = $NewSecurityPrincipalVariableNameArrayPrep

For ($loop=0; $loop –lt $CertTemplLDAPObjectSecurityPrincipalIdentity.Count; $loop++) {
    #$NewVariableName = $CertTemplLDAPObjectSecurityPrincipalIdentity[$loop] -replace " ","_"
    New-Variable -Name $($CertTemplLDAPObjectSecurityPrincipalIdentity[$loop] -replace " ","_") -Value `
    (New-Object PSObject -Property @{
        "SecurityPrincipalIdentity"     = $CertTemplLDAPObjectSecurityPrincipalIdentity[$loop]
        "SecurityRights"                = $CertTemplLDAPObjectSecurityRights
        "SecurityType"                  = $CertTemplLDAPObjectSecurityType
    })

    $VariableName = (Get-Variable $($CertTemplLDAPObjectSecurityPrincipalIdentity[$loop] -replace " ","_")).Name
    $NewSecurityPrincipalVariableNameArray.Add($VariableName)
}

For ($loop=0; $loop –lt $NewSecurityPrincipalVariableNameArray.Count; $loop++) {
    $SecurityPrincipalIdentity = (Get-Variable $NewSecurityPrincipalVariableNameArray[$loop]).Value.SecurityPrincipalIdentity
    $SecurityRights = (Get-Variable $NewSecurityPrincipalVariableNameArray[$loop]).Value.SecurityRights
    $SecurityType = (Get-Variable $NewSecurityPrincipalVariableNameArray[$loop]).Value.SecurityType

    $AccountAdObj = New-Object System.Security.Principal.NTAccount($SecurityPrincipalIdentity)
    $identity = $AccountAdObj.Translate([System.Security.Principal.SecurityIdentifier])
    [array]$adRights = $SecurityRights
    $type = $SecurityType

    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
    $NewTempl.psbase.ObjectSecurity.SetAccessRule($ACE)
    $NewTempl.psbase.commitchanges()
}

##### END Set Permissions on the new Certificate Template LDAP Object #####


##### BEGIN Add New Cert Template to List of Cert Templates to Issue #####
# Need to Refresh $ConfigContext, $ADSI, and $LDAPSearchBase before referencing$NewADObject
$ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$NewADObject = Get-ADObject "CN=$NewTemplName,$LDAPSearchBase"

# If you are using the PSPKI Module #
Import-Module PSPKI -Prefix PSPKI
$GetNewTemplate = Get-PSPKICertificateTemplate -DisplayName $NewTemplName
Get-PSPKICertificationAuthority -ComputerName $IssuingCertAuthFQDN | Get-PSPKICATemplate | Add-PSPKICATemplate -Template $GetNewTemplate | Set-PSPKICATemplate

Write-Host ""
Write-Host "Checking to see if Certificate Template cache has been refreshed and showing new Certificate Template..."
ADCSAdministration\Get-CATemplate | Where-Object {$_.Name -like $NewTemplName}

Write-Host "Restarting certsvc service to force Certificate Template cache update just in case..."
Restart-Service certsvc
Sleep 10

Write-Host ""
Write-Host "Checking to see if Certificate Template cache has been refreshed and showing new Certificate Template..."
ADCSAdministration\Get-CATemplate | Where-Object {$_.Name -like $NewTemplName}

# NOTE: If you prefer NOT using the PSPKI Module, and the ADCSAdministration PowerShell Module is available, you can use
# ADCSAdministration\Add-CATemplate... 
# HOWEVER, for SOME UNKNOWN REASON, this command will fail unless you:
# 1) Wait 15 minutes; or
# 2) At least "*look at*" the New Certificate Template in the Certificate Templates Console GUI.
# The Certificate Templates Console GUI is launched by navigating Server Manager-->Tools-->Certificate Authority-->right-click
# the folder "Certificate Templates"--> select "Manage". From the Certificate Templates Console GUI, "look at" the New
# Certificate Template by double-clicking on it and then clicking either "OK" or "Cancel" buttons.
# NOTE: Restarting the certsvc service does NOT seem to help consistently. Only #1 and/or #2 above seems to be effective.
# Once the conditions of either #1 or #2 above are satisfied, the following command will succeed:
# Add-CATemplate -Name $NewTemplName -Force


# Output all attributes for your new Certificate Template to a text file
Get-ADObject $NewADObject -Properties * | Out-File "$CertGenWorking\$AttributesFile"

##### END Add New Cert Template to List of Cert Templates to Issue #####

##### END Creating the New Certificate Template #####

}

# Generate-CertTemplate

