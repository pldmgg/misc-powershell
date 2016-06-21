<#
.SYNOPSIS
    This script/function generates a New Certificate Template AND Publishes it for use.  It does NOT generate actual certificates.
    This script attempts to simplify Certificate Template creation by copying Certificate Template attributes from existing
    default Certificate Templates to the New Certificate Template.

    This can be run as a script by uncommenting the very last line calling the Generate-CertTemplate function, or by simply loading the
    entire function into your current PowerShell shell and then calling it.

    IMPORTANT NOTE1: By running the function without any parameters, the user will be walked through several prompts. 
    This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.

.DESCRIPTION
    This function/script is split into the following sections (ctl-f to jump to each of these sections)
    - Helper Functions
    - Variable Validation
    - Additional High-Level Variable Prep
    - $IntendedPurposeValues / $ExtKeyUse Adjudication
    - $KeyUsageValues / $AppPol Adjudication
    - Reconcile any $IntendedPurposeValues/$ExtKeyUse Dependencies on $KeyUsageValues/$AppPol
    - Creating the New Certificate Template
    - Important Note to User


    IMPORTANT NOTE2: Please note that after the script/function concludes, when you review the values found in the 'Intended Purpose' column
    of the certsrv GUI or the Certificate Template Console GUI, these values reflect ALL of the purposes that you could potentially use 
    the certificates generated from your New Certificate Template for.  These purposes are based on a combination of 3 variables provided
    to the script by the user:
    1) An existing certificate template that you base your New Certificate Template off of (derived from $displayNameForBasisTemplate or $cnForBasisTemplate)
    2) The Intended Purpose value(s) that you provided to the script (derived from $IntendedPurposeValuesPrep)
    3) The Key Usage value(s) that you provided to the script (derived from $KeyUsageValuesPrep)

    IMPORTANT NOTE3: Please review the explanation for each of the variables/parameters that can/should be changed below.

    1) $ADObject - The LDAP object that the new Cert Template is based on. To view all LDAP objects that this new template can be based on, launch
    ADSI Edit (simply type "adsiedit" in cmd prompt and Connect To "Configuration") and navigate to:
    CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
    Note that the navigation tree in ADSI Edit actually starts with the right-most entry in the above path after the domain suffix and prefix
    In other words, to navigate to the above path in ADSI Edit, progress Configuration->Services->Public Key Services->Certificate Templates

    2) $displayNameForBasisTemplate - This variable can be set to any "displayName" value (like "Computer" or "Code Signing") found under the properties of
    any LDAP object under CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]

    IMPORTANT NOTE4: This variable must be a "displayName" value. For example, there is NO SPACE in the string "CodeSigning" on the following LDAP attribute:
    CN=CodeSigning,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
    ...HOWEVER, right-click the object (use adsiedit) and observe the Attribute "displayName".  The Value "Code Signing" DOES CONTAIN a space.

    IMPORTANT NOTE5: Sometimes LDAP objects have a completely different "displayName" attribute than one would expect. For example, the displayName for the LDAP object
    CN=Machine,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
    ...is "Computer" NOT "Machine"

    3) $cnForBasisTemplate - This variable can be set to any "cn" value (like "Machine" or "CodeSigning") found under the properties of
    any LDAP object under CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]

    IMPORTANT NOTE6: This variable must be a "cn" value. This is typically what you see at a glance when browsing LDAP objects using ADSI Edit. However,
    just to be certain, right-click the object, select "Properties" and observe the Value of the Attribute "cn".

    4) $CertGenWorking - Directory that all output files will be written to (currently, the only output is $AttributesFile). Recommend using this directory to save 
    actual certificates (as opposed to the certificate template that this script generates) in the future when they are generated. Using a network location 
    is perfectly fine. 

    (Note that actual certificate generation is outside scope of this script).

    5) $NewTemplName - The name that you would like to give the New Cert Template. This name will appear
     - In adsiedit under CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
     - In certsrv under "Certificate Templates"
     - In the Certificate Templates Console (launched by right-clicking "Certificate Templates" in certsrv and then clicking "Manage")
     - Under the new LDAP Object's "displayName" attribute
     - Under the new LDAP Object's "cn" attribute
     NOTE: This script ensures that "displayName" AND "cn" attributes of the new LDAP object match in order to reduce future confusion.

    6) $IssuingCertAuth - Name of Server that acts as Certificate Authority that actually issues certificates.  This can be a Subordinate CA, Intermediate CA,
    or both depending on your setup (it can also be a Root CA, but this should only be the case if you are creating you first Subordinate CA). 
    IMPORTANT: The Name of the Server must be able to be resolved via DNS, and it CANNOT be an IP Address.

    7) $AttributesFile - All attributes assigned to the new Certificate Template will be written to the file specified in the variable. 
    The contents of this file are used almost immediately after creation in this script.  It is left on the filesystem under $CertGenWorking for later review by personnel.

    8) $CustomExpirationPeriodInYears - Number of years you would like all certificates generated off of this new template to be good for.  Currently, this script
    only supports values of "1" or "2"

    9) $IntendedPurposeValuesPrep - This is an array of one (1) or more values that will (usually) reflect the value(s) displayed 
    for the "Intended Purpose" column in crtsrv and the Certificate Templates Console. 
    Valid array values for $IntendedPurposeValues below are as follows:
    The following values, once set, WILL appear under the Intended Purposes" column:
    "Code Signing","Client Authentication","Server Authentication","Private Key Archival","Key Recovery Agent","Directory Service Email Replication",
    "Key recovery agent","OCSP signing"

    The following values WILL NOT appear under the Intended Purposes column even if they are set:
    "Microsoft Trust List Signing","EFS","Secure E-mail","Certificate Request Agent","Smart Card Logon","File recovery",
    "IPSec IKE Intermediate","KDC authentication","Key usage"

    For more information, see: https://technet.microsoft.com/en-us/library/cc730826(v=ws.10).aspx
    AND
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
    AND
    https://technet.microsoft.com/en-us/library/cc731792(v=ws.11).aspx

    9) $ExtKeyUse - This is an array of one (1) or more OID numbers derived from $IntendedPurposes that will provide the value(s) for the "Intended Purpose" 
    column in crtsrv and the Certificate Templates Console.
    This array also influences $AppPol below (to clarify it doesn't impact the $AppPol array itself, rather, it affects what shows up in 
    Certificate Templates Console->Properties->Extensions->Key Usage)!!

    Side Note: If you want to manually figure out what OID number will provide the desired Intended Purpose value(s) (as opposed to just using 
    the $IntendedPurposes array), follow these steps:
        - Launch the Certificate Templates Console
        - Find an existing certificate template with Intended Purpose value(s) you would like your new template to have.
        - Launch ADSI Edit, navigate to that existing template's LDAP object under 
        CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
        - Right-click the LDAP object and select Properties
        - Find the Attribute called PKIExtendedKeyUsage. The OID Number(s) you want to use is in the Value column.

    For more information, see: https://technet.microsoft.com/en-us/library/cc730826(v=ws.10).aspx
    AND
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
    AND
    https://technet.microsoft.com/en-us/library/cc731792(v=ws.11).aspx

    10) $KeyUsageValuesPrep - This is an array of one (1) or more values that will reflect the value(s) displayed via:
    Certificate Templates Console->Properties->Extensions->Key Usage
    Valid array values for $KeyUsageValues are as follows:
    "Digital Signature", "Encryption", "Signature and Encryption", "CRL Signing", "Certificate Signing"

    For more information, see: https://technet.microsoft.com/en-us/library/cc730826(v=ws.10).aspx
    AND
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378155(v=vs.85).aspx
    AND
    https://technet.microsoft.com/en-us/library/cc731792(v=ws.11).aspx

    11) $AppPol - This is an array of one (1) or more OID numbers derived from $KeyUsageValues that will that will reflect the value(s) displayed via:
    Certificate Templates Console->Properties->Extensions->Key Usage
    This array also impacts $ExtKeyUse (to clarify it doesn't impact the $AppPol array itself, rather, it affects what shows up in the "Intended Purpose" 
    column in crtsrv and the Certificate Templates Console.)!!

    Side Note: If you want to manually figure out what OID number will provide the desired Intended Purpose value(s) (as opposed to just using 
    the $IntendedPurposes array), follow these steps:
        - Launch the Certificate Templates Console
        - Find an existing certificate template with Intended Purpose value(s) you would like your new template to have.
        - Launch ADSI Edit, navigate to that existing template's LDAP object under 
        CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[domain prefix],DC=[domain suffix]
        - Right-click the LDAP object and select Properties
        - Find the Attribute called msPKI-Certificate-Application-Policy. The OID Number(s) you want to use is in the Value column.

    For more information, see: https://technet.microsoft.com/en-us/library/cc730826(v=ws.10).aspx
    AND
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa378155(v=vs.85).aspx

.DEPENDENCIES
    1) PSPKI Module (See: https://pspki.codeplex.com/)
    2) Remote Server Administration Tools (RSAT), specifically:
        - Role Administration Tools
        - AD DS and ADLDS Tools
        - Active Directory Administrative Center
        - AD DS Snap-Ins and Command-Line Tools
        - AD LDS Snap-Ins and Command-Line Tools

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

#>

Function Generate-CertTemplate {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False)]
    $displayNameForBasisTemplate,

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
    $AttributesFile = "NewCertTemplate_Attributes.txt",

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


##### BEGIN Helper Functions #####

# The following "Find-LDAPObject" and "Get-RootDSE" functions were taken from:
# https://gallery.technet.microsoft.com/scriptcenter/Using-SystemDirectoryServic-0adf7ef5

Add-Type @'
public enum EncryptionType
{
    None=0,
    Kerberos,
    SSL
}
'@
Add-Type -AssemblyName System.DirectoryServices.Protocols

Function Find-LdapObject {
    Param (
        [parameter(Mandatory = $true)]
        [String] 
            #Search filter in LDAP syntax
        $searchFilter,
        
        [parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [Object] 
            #DN of container where to search
        $searchBase,
        
        [parameter(Mandatory = $false)]
        [String] 
            #LDAP server name
            #Default: Domain Controller of current domain
        $LdapServer=[String]::Empty,
        
        [parameter(Mandatory = $false)]
        [Int32] 
            #LDAP server port
            #Default: 389
        $Port=389,
        
        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.LdapConnection]
            #existing LDAPConnection object.
            #When we perform many searches, it is more effective to use the same conbnection rather than create new connection for each search request.
            #Default: $null, which means that connection is created automatically using information in LdapServer and Port parameters
        $LdapConnection,
        
        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.SearchScope]
            #Search scope
            #Default: Subtree
        $searchScope="Subtree",
        
        [parameter(Mandatory = $false)]
        [String[]]
            #List of properties we want to return for objects we find.
            #Default: empty array, meaning no properties are returned
        $PropertiesToLoad=@(),
        
        [parameter(Mandatory = $false)]
        [String]
            #Name of attribute for ASQ search. Note that searchScope must be set to Base for this type of seach
            #Default: empty string
        $ASQ,
        
        [parameter(Mandatory = $false)]
        [UInt32]
            #Page size for paged search. Zero means that paging is disabled
            #Default: 100
        $PageSize=100,
        
        [parameter(Mandatory = $false)]
        [String[]]
            #List of properties that we want to load as byte stream.
            #Note: Those properties must also be present in PropertiesToLoad parameter. Properties not listed here are loaded as strings
            #Default: empty list, which means that all properties are loaded as strings
        $BinaryProperties=@(),

        [parameter(Mandatory = $false)]
        [UInt32]
            #Number of seconds before connection times out.
            #Default: 120 seconds
        $TimeoutSeconds = 120,

        [parameter(Mandatory = $false)]
        [EncryptionType]
            #Type of encryption to use.
            #Applies only when existing connection is not passed
        $EncryptionType="None",

        [parameter(Mandatory = $false)]
        [System.Net.NetworkCredential]
            #Use different credentials when connecting
        $Credential=$null
    )

    Process {
        #we want dispose LdapConnection we create
        [Boolean]$bDisposeConnection=$false
        #range size for ranged attribute retrieval
        #Note that default in query policy is 1500; we set to 1000
        $rangeSize=1000

        try {
            if($LdapConnection -eq $null) {
                if($Credential -ne $null) {
                    $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection((new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)), $Credential)
                } else {
        	        $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port))
                }
                $bDisposeConnection=$true
                switch($EncryptionType) {
                    "None" {break}
                    "SSL" {
                        $options=$LdapConnection.SessionOptions
                        $options.ProtocolVersion=3
                        $options.StartTransportLayerSecurity($null)
                        break               
                    }
                    "Kerberos" {
                        $LdapConnection.SessionOptions.Sealing=$true
                        $LdapConnection.SessionOptions.Signing=$true
                        break
                    }
                }
            }
            if($pageSize -gt 0) {
                #paged search silently fails when chasing referrals
                $LdapConnection.SessionOptions.ReferralChasing="None"
            }

            #build request
            $rq=new-object System.DirectoryServices.Protocols.SearchRequest
            
            #search base
            switch($searchBase.GetType().Name) {
                "String" 
                {
                    $rq.DistinguishedName=$searchBase
                }
                default 
                {
                    if($searchBase.distinguishedName -ne $null) 
                    {
                        $rq.DistinguishedName=$searchBase.distinguishedName
                    }
                    else
                    {
                        return
                    }
                }
            }

            #search filter in LDAP syntax
            $rq.Filter=$searchFilter

            #search scope
            $rq.Scope=$searchScope

            #attributes we want to return - nothing now, and then use ranged retrieval for the propsToLoad
            $rq.Attributes.Add("1.1") | Out-Null

            #paged search control for paged search
            if($pageSize -gt 0) {
                [System.DirectoryServices.Protocols.PageResultRequestControl]$pagedRqc = new-object System.DirectoryServices.Protocols.PageResultRequestControl($pageSize)
                $rq.Controls.Add($pagedRqc) | Out-Null
            }

            #server side timeout
            $rq.TimeLimit=(new-object System.Timespan(0,0,$TimeoutSeconds))

            if(-not [String]::IsNullOrEmpty($asq)) {
                [System.DirectoryServices.Protocols.AsqRequestControl]$asqRqc=new-object System.DirectoryServices.Protocols.AsqRequestControl($ASQ)
                $rq.Controls.Add($asqRqc) | Out-Null
            }
            
            #initialize output objects via hashtable --> faster than add-member
            #create default initializer beforehand
            $propDef=@{}
            #we always return at least distinguishedName
            #so add it explicitly to object template and remove from propsToLoad if specified
            $propDef.Add("distinguishedName","")
            $PropertiesToLoad=@($propertiesToLoad | where-object {$_ -ne "distinguishedName"})
                        
            #prepare template for output object
            foreach($prop in $PropertiesToLoad) {
               $propDef.Add($prop,@())
            }

            #process paged search in cycle or go through the processing at least once for non-paged search
            while ($true)
            {
                $rsp = $LdapConnection.SendRequest($rq, (new-object System.Timespan(0,0,$TimeoutSeconds))) -as [System.DirectoryServices.Protocols.SearchResponse];
                
                #for paged search, the response for paged search result control - we will need a cookie from result later
                if($pageSize -gt 0) {
                    [System.DirectoryServices.Protocols.PageResultResponseControl] $prrc=$null;
                    if ($rsp.Controls.Length -gt 0)
                    {
                        foreach ($ctrl in $rsp.Controls)
                        {
                            if ($ctrl -is [System.DirectoryServices.Protocols.PageResultResponseControl])
                            {
                                $prrc = $ctrl;
                                break;
                            }
                        }
                    }
                    if($prrc -eq $null) {
                        #server was unable to process paged search
                        throw "Find-LdapObject: Server failed to return paged response for request $SearchFilter"
                    }
                }
                #now process the returned list of distinguishedNames and fetch required properties using ranged retrieval
                foreach ($sr in $rsp.Entries)
                {
                    $dn=$sr.DistinguishedName
                    #we return results as powershell custom objects to pipeline
                    #initialize members of result object (server response does not contain empty attributes, so classes would not have the same layout
                    #create empty custom object for result, including only distinguishedName as a default
                    $data=new-object PSObject -Property $propDef
                    $data.distinguishedName=$dn
                    
                    #load properties of custom object, if requested, using ranged retrieval
                    foreach ($attrName in $PropertiesToLoad) {
                        $rqAttr=new-object System.DirectoryServices.Protocols.SearchRequest
                        $rqAttr.DistinguishedName=$dn
                        $rqAttr.Scope="Base"
                        
                        $start=-$rangeSize
                        $lastRange=$false
                        while ($lastRange -eq $false) {
                            $start += $rangeSize
                            $rng = "$($attrName.ToLower());range=$start`-$($start+$rangeSize-1)"
                            $rqAttr.Attributes.Clear() | Out-Null
                            $rqAttr.Attributes.Add($rng) | Out-Null
                            $rspAttr = $LdapConnection.SendRequest($rqAttr)
                            foreach ($sr in $rspAttr.Entries) {
                                if($sr.Attributes.AttributeNames -ne $null) {
                                    #LDAP server changes upper bound to * on last chunk
                                    $returnedAttrName=$($sr.Attributes.AttributeNames)
                                    #load binary properties as byte stream, other properties as strings
                                    if($BinaryProperties -contains $attrName) {
                                        $vals=$sr.Attributes[$returnedAttrName].GetValues([byte[]])
                                    } else {
                                        $vals = $sr.Attributes[$returnedAttrName].GetValues(([string])) # -as [string[]];
                                    }
                                    $data.$attrName+=$vals
                                    if($returnedAttrName.EndsWith("-*") -or $returnedAttrName -eq $attrName) {
                                        #last chunk arrived
                                        $lastRange = $true
                                    }
                                } else {
                                    #nothing was found
                                    $lastRange = $true
                                }
                            }
                        }

                        #return single value as value, multiple values as array, empty value as null
                        switch($data.$attrName.Count) {
                            0 {
                                $data.$attrName=$null
                                break;
                            }
                            1 {
                                $data.$attrName = $data.$attrName[0]
                                break;
                            }
                            default {
                                break;
                            }
                        }
                    }
                    #return result to pipeline
                    $data
                }
                if($pageSize -gt 0) {
                    if ($prrc.Cookie.Length -eq 0) {
                        #last page --> we're done
                        break;
                    }
                    #pass the search cookie back to server in next paged request
                    $pagedRqc.Cookie = $prrc.Cookie;
                } else {
                    #exit the processing for non-paged search
                    break;
                }
            }
        }
        finally {
            if($bDisposeConnection) {
                #if we created the connection, dispose it here
                $LdapConnection.Dispose()
            }
        }
    }
}

Function Get-RootDSE {
    Param (
        [parameter(Mandatory = $false)]
        [String] 
            #LDAP server name
            #Default: closest DC
        $LdapServer=[String]::Empty,
        
        [parameter(Mandatory = $false)]
        [Int32] 
            #LDAP server port
            #Default: 389
        $Port=389,
        [parameter(Mandatory = $false)]
        [System.DirectoryServices.Protocols.LdapConnection]
            #existing LDAPConnection object.
            #When we perform many searches, it is more effective to use the same conbnection rather than create new connection for each search request.
            #Default: $null, which means that connection is created automatically using information in LdapServer and Port parameters
        $LdapConnection,
        
        [parameter(Mandatory = $false)]
        [System.Net.NetworkCredential]
            #Use different credentials when connecting
        $Credential=$null

    )
    
    Process {
        #we want dispose LdapConnection we create
        [Boolean]$bDisposeConnection=$false

        try {
            if($LdapConnection -eq $null) {
                if($Credential -ne $null) {
                    $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection((new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port)), $Credential)
                } else {
        	        $LdapConnection=new-object System.DirectoryServices.Protocols.LdapConnection(new-object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($LdapServer, $Port))
                }
                $bDisposeConnection=$true
            }
            
			#initialize output objects via hashtable --> faster than add-member
            #create default initializer beforehand
            # $PropertiesToLoad=@("rootDomainNamingContext", "configurationNamingContext", "schemaNamingContext","defaultNamingContext","dnsHostName")
            $propDef=@{"rootDomainNamingContext"=@(); "configurationNamingContext"=@(); "schemaNamingContext"=@();"defaultNamingContext"=@();"dnsHostName"=@()}
            #foreach($prop in $PropertiesToLoad) {
            #     $propDef.Add($prop,@())
            #}
            #build request
            $rq=new-object System.DirectoryServices.Protocols.SearchRequest
            $rq.Scope = "Base"
            $rq.Attributes.AddRange($propDef.Keys) | Out-Null
            [System.DirectoryServices.Protocols.ExtendedDNControl]$exRqc = new-object System.DirectoryServices.Protocols.ExtendedDNControl("StandardString")
            $rq.Controls.Add($exRqc) | Out-Null
            
            $rsp=$LdapConnection.SendRequest($rq)
            
            $data=new-object PSObject -Property $propDef
            
            $data.configurationNamingContext = (($rsp.Entries[0].Attributes["configurationNamingContext"].GetValues([string]))[0]).Split(';')[1];
            $data.schemaNamingContext = (($rsp.Entries[0].Attributes["schemaNamingContext"].GetValues([string]))[0]).Split(';')[1];
            $data.rootDomainNamingContext = (($rsp.Entries[0].Attributes["rootDomainNamingContext"].GetValues([string]))[0]).Split(';')[2];
            $data.defaultNamingContext = (($rsp.Entries[0].Attributes["defaultNamingContext"].GetValues([string]))[0]).Split(';')[2];
            $data.dnsHostName = ($rsp.Entries[0].Attributes["dnsHostName"].GetValues([string]))[0]
            $data
        }
        finally {
            if($bDisposeConnection) {
                #if we created the connection, dispose it here
                $LdapConnection.Dispose()
            }
        }
    }
}

##### END Helper Functions #####


##### BEGIN Variable Validation #####
$DomainPrefix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 0
$DomainSuffix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 1
$LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainPrefix,DC=$DomainSuffix"
$AllCertificateTemplateLDAPObjects = Find-LdapObject -SearchFilter:"(distinguishedName=*)" -SearchBase:$LDAPSearchBase

$ValidDisplayNames = foreach ($obj1 in $AllCertificateTemplateLDAPObjects) {
    $obj2 = $obj1 | Select-Object -ExpandProperty distinguishedName
    Get-ADObject $obj2 -Properties displayName | Select-Object -ExpandProperty DisplayName
}
$ValidDisplayNamesAsStringPrep = foreach ($obj1 in $ValidDisplayNames) {
    $obj1+','
}
$ValidDisplayNamesAsString = [string]$ValidDisplayNamesAsStringPrep

$ValidCNNames = foreach ($obj1 in $AllCertificateTemplateLDAPObjects) {
    $obj2 = $obj1 | Select-Object -ExpandProperty distinguishedName
    Get-ADObject $obj2 -Properties Name | Select-Object -ExpandProperty Name
}
$ValidCNNamesAsStringPrep = foreach ($obj1 in $ValidCNNames) {
    $obj1+','
}
$ValidCNNamesAsString = [string]$ValidCNNamesAsStringPrep

if ($displayNameForBasisTemplate -eq $null -and $cnForBasisTemplate -eq $null) {
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

    $displayNameOrCNSwitch = Read-Host -Prompt "Would you like to use a displayName or CN value in order to choose an existing Certificate Template? [displayName,CN]"
    if ($displayNameOrCNSwitch -eq "displayName") {
        $displayNameForBasisTemplate = Read-Host -Prompt "Please enter the displayName of the Certificate Template you would like to use as your base"
    }
    if ($displayNameOrCNSwitch -eq "CN") {
        $cnForBasisTemplate = Read-Host -Prompt "Please enter the CN of the Certificate Template you would like to use as your base"
    }
}

if ($displayNameForBasisTemplate -ne $null) {
    # First validate the user-provided displayName
    if ($ValidDisplayNames -notcontains $displayNameForBasisTemplate) {
        Write-Host “$($displayNameForBasisTemplate) is not a valid displayName for an existing certificate template."
        Write-Host "Valid displayNames for existing certificate templates are as follows:”
        Write-Host $ValidDisplayNames
        exit
    }
    # Then get the CN of the LDAP Object based on the displayName
    $cnForBasisTemplatePrep = Find-LdapObject -SearchFilter:"(displayName=$displayNameForBasisTemplate)" -SearchBase:$LDAPSearchBase | Select-Object -ExpandProperty distinguishedName
    $cnForBasisTemplate = Get-ADObject $cnForBasisTemplatePrep -Properties Name | Select-Object -ExpandProperty Name
}

if ($cnForBasisTemplate -ne $null) {
    # First validate the user-provided CN
    if ($ValidCNNames -notcontains $cnForBasisTemplate) {
        Write-Host “$($cnForBasisTemplate) is not a valid displayName for an existing certificate template."
        Write-Host "Valid displayNames for existing certificate templates are as follows:”
        Write-Host $ValidCNNames
        exit
    }
    # Then get the displayName of the LDAP Object based on the CN
    $displayNameForBasisTemplatePrep = Find-LdapObject -SearchFilter:"(Name=$cnForBasisTemplate)" -SearchBase:$LDAPSearchBase | Select-Object -ExpandProperty distinguishedName
    $displayNameForBasisTemplate = Get-ADObject $displayNameForBasisTemplatePrep -Properties displayName | Select-Object -ExpandProperty displayName
}

$ValidIntendedPurposeValues = @("Code Signing","Client Authentication","Server Authentication","Private Key Archival","Key Recovery Agent","Directory Service Email Replication",`
"Key Recovery Agent","OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Certificate Request Agent","Smart Card Logon","File Recovery",`
"IPSec IKE Intermediate","KDC Authentication","Key Usage")
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
    [array]$IntendedPurposeValuesPrep = (Read-Host -Prompt "Please enter one (or more) Intended Purpose values separated by commas").split(",") | %{$_.trim()}
}
foreach ($obj1 in $IntendedPurposeValuesPrep) {
    if ($ValidIntendedPurposeValues -notcontains $obj1) {
        Write-Host “$($IntendedPurposeValuesPrep) is not a valid IntendedPurpose. Valid displayNames are as follows:”
        $ValidIntendedPurposeValuesString
        exit
    }
}

$ValidKeyUsageValues = @("Digital Signature","Encryption","CRL Signing","Certificate Signing")
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
    [array]$KeyUsageValuesPrep = (Read-Host -Prompt "Please enter one (or more) Key Usage Policy values separated by commas").split(",") | %{$_.trim()}
}
foreach ($obj1 in $KeyUsageValuesPrep) {
    if ($ValidKeyUsageValues -notcontains $obj1) {
        Write-Host “$($KeyUsageValuesPrep) is not a valid IntendedPurpose. Valid displayNames are as follows:”
        Write-Host ""
        $ValidKeyUsageValuesString
        Write-Host ""
        exit
    }
}

if (Test-Path $CertGenWorking) {
    Write-Host "CertGenWorking directory already exists...No need to create directory"
}
else {
    mkdir $CertGenWorking
}

if (Test-Connection $IssuingCertAuth) {
    Write-Host "Successfully contacted the server acting as the Issuing Certificate Authority"
}
else {
    Write-Host "Cannot contact the server acting as the Issuing Certificate Authority. Halting!"
    exit
}

if ($CustomExpirationPeriodInYears -eq "1" -or $CustomExpirationPeriodInYears -eq "2") {
    Write-Host "CustomExpirationPeriodInYears is valid...Continuing..."
}
else {
    Write-Host "Value for variable CustomExpirationPeriodInYears can only be '1' or '2'.  Please adjust the value and try again."
}

if ($AllowPrivateKeyExport -eq "Yes" -or $AllowPrivateKeyExport -eq "y" -or $AllowPrivateKeyExport -eq "No" -or $AllowPrivateKeyExport -eq "n") {
    Write-Host "AllowPrivateKeyExport option is valid...Continuing..."
}
else {
    Write-Host "Value for variable AllowPrivateKeyExport can only be 'Yes' or 'No'.  Please adjust the value and try again."
}

##### END Variable Validation #####


##### BEGIN Additional High-Level Variable Prep #####
$ADObject = "CN=$cnForBasisTemplate,$LDAPSearchBase"
$ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
$ADSI = [ADSI]"LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
$BasisTemplateLDAPObjectDirectoryEntry = $ADSI.psbase.children | where {$_.displayName -contains $displayNameForBasisTemplate}

# Using [System.Collections.ArrayList] so that Add and Remove methods work as expected and only operate on a single array 
# instead of destroying and recreating arrays everytime an item is added/removed
[System.Collections.ArrayList]$IntendedPurposeValues = $IntendedPurposeValuesPrep
[array]$ExtKeyUsePrep = @()
[System.Collections.ArrayList]$ExtKeyUse = $ExtKeyUsePrep

# Using [System.Collections.ArrayList] so that Add and Remove methods work as expected and only operate on a single array 
# instead of destroying and recreating arrays everytime an item is added/removed
[System.Collections.ArrayList]$KeyUsageValues = $KeyUsageValuesPrep
[array]$AppPolPrep = @()
[System.Collections.ArrayList]$AppPol = $AppPolPrep

##### END Additional High-Level Variable Prep #####


##### BEGIN $IntendedPurposeValues / $ExtKeyUse Adjudication #####

foreach ($obj1 in $IntendedPurposeValues) {
    if ($obj1 -eq "Code Signing") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Code Signing"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Client Authentication") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Workstation Authentication"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Private Key Archival") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "CA Exchange"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Directory Service Email Replication") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Directory Email Replication"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Key Recovery Agent") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Key Recovery Agent"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "OCSP Signing") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "OCSP Response Signing"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Server Authentication") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Web Server"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Key Recovery Agent") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Key Recovery Agent"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    ##### Below this point, Intended Purposes will be set but WILL NOT show up in the Certificate Templates Console under Intended Purpose column #####
    if ($obj1 -eq "EFS") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Basic EFS"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Secure E-Mail") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Exchange User"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Certificate Request Agent") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Enrollment Agent"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "Microsoft Trust List Signing") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "Trust List Signing"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    # Note: "Smartcard Logon" pKIExtendedKeyUsage actually has 2 OIDs - one for Client Authentication and one for Smartcard Logon. Instead of including logic
    # to only return the Smartcard Logon OID, it is just hardcoded
    if ($obj1 -eq "Smartcard Logon") {
        $ExtKeyUse.Add("1.3.6.1.4.1.311.20.2.2")
    }
    if ($obj1 -eq "File Recovery") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "EFS Recovery Agent"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    if ($obj1 -eq "IPSec IKE Intermediate") {
        $displayNameOfDefaultTemplateWithDesiredIntendedPurpose = "IPSec"
        $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose = $ADSI.psbase.children | where {$_.displayName -contains $displayNameOfDefaultTemplateWithDesiredIntendedPurpose}
        [array]$OIDValuesToAddToExtKeyUseArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose.pKIExtendedKeyUsage
        [array]$OIDValuesToAddToAppPolArray = $LDAPObjectDirectoryEntryOfDefaultTemplateWithDesiredIntendedPurpose."msPKI-Certificate-Application-Policy"
        foreach ($obj2 in $OIDValuesToAddToExtKeyUseArray) {
            $ExtKeyUse.Add("$obj2")
        }
        foreach ($obj3 in $OIDValuesToAddToAppPolArray) {
            $AppPol.Add("$obj3")
        }
    }
    # Note: "Kerberos Authentication" pKIExtendedKeyUsage actually has 4 OIDs - Client Authentication, Server Authentication, Smartcard Logon, and KDC Authentication. 
    # Instead of including logic to only return the KDC Authentication OID, it is just hardcoded
    if ($obj1 -eq "KDC Authentication") {
        $ExtKeyUse.Add("1.3.6.1.5.2.3.5")
    }
    # Note: "User" pKIExtendedKeyUsage actually has 3 OIDs - EFS, Secure E-Mail, and Key Usage. 
    # Instead of including logic to only return the Key Usage OID, it is just hardcoded
    if ($obj1 -eq "Key Usage") {
        $ExtKeyUse.Add("1.3.6.1.4.1.311.10.3.4")
    }
}

##### END $IntendedPurposeValues / $ExtKeyUse Adjudication #####

##### BEGIN $KeyUsageValues / $AppPol Adjudication #####

foreach ($obj1 in $KeyUsageValues) {
    if ($obj1 -eq "Digital Signature") {
        # There are a lot of different OIDs for different types of Digital Signatures.
        # For additional options and more detail, see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
        $AppPol.Add("1.3.6.1.5.5.7.3.3") # Allows cert to be used to sign code
        $AppPol.Add("1.3.6.1.4.1.311.10.3.12") # Allows cert to be used to sign documents
    }
    if ($obj1 -eq "Encryption") {
        # There are several different OIDs for allowing Encryption for different purposes.
        # For additional options and more detail, see: https://msdn.microsoft.com/en-us/library/windows/desktop/aa378132(v=vs.85).aspx
        $AppPol.Add("1.3.6.1.4.1.311.10.3.4") # Allows cert tobe used to encrypt files by using the Encrypting File System (EFS).
        $AppPol.Add("1.3.6.1.4.1.311.10.3.4.1") # Allows cert to be used to decrypt files encrypted using EFS
        $AppPol.Add("1.3.6.1.5.5.7.3.4") # Allows cert to be used to encrypt email messages
    }
    if ($obj1 -eq "CRL Signing") {
        # There are a lot of different OIDs for different types of Digital Signatures
        $AppPol.Add("1.3.6.1.4.1.311.10.3.9") # Allows cert to perform CRL Signing
        $AppPol.Add("1.3.6.1.4.1.311.20.1") # The certificate can be used to sign a request for automatic enrollment in a certificate trust list (CTL).
        $AppPol.Add("1.3.6.1.4.1.311.10.3.1") # The certificate can be used to sign a CTL.
        $AppPol.Add("1.3.6.1.4.1.311.20.2.1") # The certificate can be used by an enrollment agent.
    }
    if ($obj1 -eq "Certificate Signing") {
        # There are a lot of different OIDs for different types of Digital Signatures
        $AppPol.Add("1.3.6.1.4.1.311.10.3.10") # The certificate can be used to sign cross certificate and subordinate certification authority certificate requests.
    }
}

##### END $KeyUsageValues / $AppPol Adjudication #####

##### BEGIN Reconcile any $IntendedPurposeValues/$ExtKeyUse Dependencies on $KeyUsageValues/$AppPol #####

if ($IntendedPurposeValues -match "OCSP Signing") {
    $AppPol.Add("1.3.6.1.5.5.7.3.9") # The certificate can be used for Online Certificate Status Protocol (OCSP) signing.
    $AppPol.Add("1.3.6.1.5.5.7.3.1") # The certificate can be used for OCSP authentication.
}
if ($IntendedPurposeValues -match "IPSec IKE Intermediate") {
    $AppPol.Add("1.3.6.1.5.5.8.2.2") # The certificate can be used for Internet Key Exchange (IKE).
}
if ($IntendedPurposeValues -match "File Recovery") {
    if ($KeyUsageValues -notmatch "Encryption") {
        $AppPol.Add("1.3.6.1.4.1.311.10.3.4") # Allows cert tobe used to encrypt files by using the Encrypting File System (EFS).
        $AppPol.Add("1.3.6.1.4.1.311.10.3.4.1") # Allows cert to be used to decrypt files encrypted using EFS
    }
}
if ($IntendedPurposeValues -match "Smartcard Logon") {
    $AppPol.Add("1.3.6.1.4.1.311.20.2.2") # The certificate enables an individual to log on to a computer by using a smart card.
}
if ($IntendedPurposeValues -match "Microsoft Trust List Signing" -or $IntendedPurposeValues -contains "Certificate Request Agent") {
    if ($KeyUsageValues -notmatch "CRL Signing") {
        $AppPol.Add("1.3.6.1.4.1.311.10.3.9") # Allows cert to perform CRL Signing
        $AppPol.Add("1.3.6.1.4.1.311.20.1") # The certificate can be used to sign a request for automatic enrollment in a certificate trust list (CTL).
        $AppPol.Add("1.3.6.1.4.1.311.10.3.1") # The certificate can be used to sign a CTL.
        $AppPol.Add("1.3.6.1.4.1.311.20.2.1") # The certificate can be used by an enrollment agent.
    }
}
if ($IntendedPurposeValues -match "Secure E-mail") {
    if ($KeyUsageValues -notmatch "Encryption") {
        $AppPol.Add("1.3.6.1.5.5.7.3.4") # Allows cert to be used to encrypt email messages
    }
}

##### END Reconcile any $IntendedPurposeValues/$ExtKeyUse dependencies on $KeyUsageValues/$AppPol #####


##### BEGIN Creating the New Certificate Template #####

# Generate a Unique OID for this new Certificate Template
$OIDRandComp = (Get-Random -Maximum 999999999999999).tostring('d15')
$OIDRandComp = $OIDRandComp.Insert(8,'.')
Get-ADObject $ADObject -Properties msPKI-Cert-Template-OID | Out-File $CertGenWorking\$AttributesFile
$CompOIDLine = Get-Content $CertGenWorking\$AttributesFile | Select-String -Pattern "msPKI-Cert-Template-OID"
$CompOIDValue = $CompOIDLine -replace "msPKI-Cert-Template-OID : ", ""
$NewCompTemplOID = $CompOIDValue.subString(0,$CompOIDValue.length-3)+$OIDRandComp
$CompPrivKeyFlRand = (Get-Random -Maximum 99999999).tostring('d8')

$NewTempl = $ADSI.Create("pKICertificateTemplate", "CN=$NewTemplName")
$NewTempl.put("distinguishedName","CN=$NewTemplName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")

$NewTempl.put("flags","131680")
$NewTempl.put("displayName","$NewTemplName")
$NewTempl.put("revision","100")
$NewTempl.put("pKIDefaultKeySpec","1")

$NewTempl.put("pKIMaxIssuingDepth","0")
$pkiCritExt = "2.5.29.17","2.5.29.15"
$NewTempl.put("pKICriticalExtensions",$pkiCritExt)

#--------------

$NewTempl.put("msPKI-RA-Signature","0")
$NewTempl.put("msPKI-Enrollment-Flag","0")
if ($AllowPrivateKeyExport -eq "Yes" -or $AllowPrivateKeyExport -eq "y") {
    # Allow Private Key Export
    $NewTempl.put("msPKI-Private-Key-Flag","50659344")
}
if ($AllowPrivateKeyExport -eq "No" -or $AllowPrivateKeyExport -eq "n") {
    # Private Key Export Not Allowed
    $NewTempl.put("msPKI-Private-Key-Flag","50659328")
}
$NewTempl.put("msPKI-Certificate-Name-Flag","1")
$NewTempl.put("msPKI-Minimal-Key-Size","2048")
$NewTempl.put("msPKI-Template-Schema-Version","2")
$NewTempl.put("msPKI-Template-Minor-Revision","1")
$NewTempl.put("msPKI-Cert-Template-OID","$NewCompTemplOID")

#------

# Actually create the initial LDAP Object...Subsequent commands will modify it...
$NewTempl.Setinfo()
# Reference for New LDAP Object
$NewADObject = Get-ADObject "CN=$NewTemplName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainPrefix,DC=$DomainSuffix"

# Adding all values from $ExtKeyUse one at a time, but you can use a hashtable as well
foreach ($obj1 in $ExtKeyUse) {
    Set-ADObject $NewADObject -Add @{pKIExtendedKeyUsage=$obj1}
}

# Adding all values from $AppPol one at a time, but you can use a hashtable as well
foreach ($obj1 in $AppPol) {
    Set-ADObject $NewADObject -Add @{"msPKI-Certificate-Application-Policy"=$obj1}
}

if ($CustomExpirationPeriodInYears -eq "1") {
    # For 1 Year Expiration, Copy Value From Default Computer Template
    $ComputerTempl = $ADSI.psbase.children | where {$_.displayName -contains "Computer"}
    if (Compare-Object -ReferenceObject $NewTempl.pKIExpirationPeriod -DifferenceObject $ComputerTempl.pKIExpirationPeriod) {
        Write-Host "There are differences between NewTempl.pkiExpirationPeriod and ComputerTempl.pkiExpirationPeriod. Setting NewTempl equal to ComputerTempl"
        <#
            # This whole block attempted to add hex string to Octal Attribute Editor in the LDAP object attribute, but it's not worth the effort
            # so just copy from the ComputerTempl. Same goes for all attributes is subsequent if statements
            $ConverttoHexPrep1 = $ComputerTempl.pKIExpirationPeriod.ToString().Split(" ")
            $ConverttoHexPrep2 = foreach ($obj1 in $ConverttoHexPrep1) {
                “{0:x}” -f [Int]$obj1
            }
            $ConverttoHexPrep3 = [string]$ConverttoHexPrep2
            #Set-ADObject $NewADObject -Replace @{pkiExpirationPeriod=$ConverttoHexPrep3}
        #>
        $NewTempl.pKIExpirationPeriod = $ComputerTempl.pKIExpirationPeriod
    }
    else {
        Write-Host "pkiExpirationPeriod is already set to 1 year...No action taken"
    }
}
if ($CustomExpirationPeriodInYears -eq "2") {
    # For 2 Year Expiration, Copy Value From Default WebServer Template
    $WebServTempl = $ADSI.psbase.children | where {$_.displayName -contains "Web Server"}
    if (Compare-Object -ReferenceObject $NewTempl.pKIExpirationPeriod -DifferenceObject $WebServTempl.pKIExpirationPeriod) {
        Write-Host "There are differences between NewTempl.pkiExpirationPeriod and WebServTempl.pkiExpirationPeriod. Setting NewTempl equal to WebServTempl"
        $NewTempl.pKIExpirationPeriod = $WebServTempl.pKIExpirationPeriod
    }
    else {
        Write-Host "pkiExpirationPeriod is already set to 2 years...No action taken"
    }
}

# For Microsoft Base Cryptographic Provider v1.0 and Microsoft Enhanced Cryptographic Provider v1.0, Copy from User Template
$UserTempl = $ADSI.psbase.children | where {$_.displayName -contains "User"}
if (Compare-Object -ReferenceObject $NewTempl.pKIDefaultCSPs -DifferenceObject $UserTempl.pKIDefaultCSPs) {
    Write-Host "There are differences between NewTempl.pKIDefaultCSPs and UserTempl.pKIDefaultCSPs. Setting NewTempl equal to UserTempl"
    $NewTempl.pKIDefaultCSPs = $UserTempl.pKIDefaultCSPs
}
else {
    Write-Host "NewTempl.pKIDefaultCSPs already matches UserTempl.pKIDefaultCSPs...No action taken"
}

# Get pKIOverlapPeriod from $BasisTemplateLDAPObjectDirectoryEntry and add it to $NewTempl
if (Compare-Object -ReferenceObject $NewTempl.pKIOverlapPeriod -DifferenceObject $BasisTemplateLDAPObjectDirectoryEntry.pKIOverlapPeriod) {
    Write-Host "There are differences between NewTempl.pKIOverlapPeriod and BasisTemplateLDAPObjectDirectoryEntry.pKIOverlapPeriod. Setting NewTempl equal to BasisTemplateLDAPObjectDirectoryEntry"
    $NewTempl.pKIOverlapPeriod = $BasisTemplateLDAPObjectDirectoryEntry.pKIOverlapPeriod
}
else {
    Write-Host "pKIOverlapPeriod is already set according to BasisTemplate...No action taken"
}

# Get pKIKeyUsage from $BasisTemplateLDAPObjectDirectoryEntry and add it to $NewTempl
if (Compare-Object -ReferenceObject $NewTempl.pKIKeyUsage -DifferenceObject $BasisTemplateLDAPObjectDirectoryEntry.pKIKeyUsage) {
    Write-Host "There are differences between NewTempl.pKIKeyUsage and BasisTemplateLDAPObjectDirectoryEntry.pKIKeyUsage. Setting NewTempl equal to BasisTemplateLDAPObjectDirectoryEntry"
    #Set-ADObject $NewADObject -Replace @{pKIKeyUsage=$BasisTemplateLDAPObjectDirectoryEntry.pKIKeyUsage.ToString()}
    $NewTempl.pKIKeyUsage = $BasisTemplateLDAPObjectDirectoryEntry.pKIKeyUsage
}
else {
    Write-Host "pKIKeyUsage is already set according to BasisTemplate...No action taken"
}

# Permissions...
$AdObj = New-Object System.Security.Principal.NTAccount("Domain Computers")
$identity = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
$adRights = "ExtendedRight"
$type = "Allow"

$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
$NewTempl.psbase.ObjectSecurity.SetAccessRule($ACE)
$NewTempl.psbase.commitchanges()

# Add New Cert Template to List of Cert Templates to Issue
# If you are using the PSPKI Module #
Import-Module PSPKI -Prefix PSPKI
$GetNewTemplate = Get-PSPKICertificateTemplate -Name $NewTemplName
Get-PSPKICertificationAuthority -Name $IssuingCertAuth | Get-PSPKICATemplate | Add-PSPKICATemplate -Template $GetNewTemplate | Set-PSPKICATemplate

# If you prefer NOT using the PSPKI Module, and PowerShell version 4 or higher is available, uncomment the below Add-CATemplate command #
# HOWEVER, this requires a manual step of publishing the template via the Certificate Templates Console GUI so that is appears in crtsrv #
#Add-CATemplate -Name $NewTemplName -Force

# Output all attributes for your new Certificate Template to a text file
Get-ADObject $NewADObject -Properties * | Out-File $CertGenWorking\$AttributesFile

##### END Creating the New Certificate Template #####

##### BEGIN Important Note to User #####
Write-Host ""
Write-Host ""
Write-Host "IMPORTANT NOTE: Please note that when you review the values found in the 'Intended Purpose' column"
Write-Host "of the certsrv GUI or the Certificate Template Console GUI, these values reflect ALL of the purposes that you"
Write-Host "could potentially use the certificates generated from your New Certificate Template for.  These purposes are"
Write-Host "based on a combination of 3 variables provided to the script: 1) An existing certificate template that you based"
Write-Host "your New Certificate Template off of; 2) The Intended Purpose value(s) that you provided to the script; and"
Write-Host "3) The Key Usage value(s) that you provided to the script"
##### END Important Note to User #####

}

# Generate-CertTemplate