<#
.SYNOPSIS
    This function/script creates a CoreOS Cluster on AWS and configures the etcd2 service on each host for TLS communication
    over the private ipv4 interface (as opposed to the public ipv4 interface).

    Several CoreOS Cloud Config files must exist prior to running this script, and the script/function Generate-Certificate.ps1
    must be available to be sourced.  Get the Generate-Certificate.ps1 function/script here:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-Certificate.ps1

.DESCRIPTION
    This script/function uses the AWS PowerShell Tools cmdlet "New-EC2Instance" to create new CoreOS instances. The parameter "-UserData" is used
    to load the Phase 1 Cloud Config on each host, which then chain-loads subsequent CoreOS Cloud Configs.

    This script/function uses the following CoreOS Cloud Config files:
    - Phase 1 Template File
        ORIGINAL LOCATION: $CloudConfigTemplateRoot\$Phase1CloudConfigTemplateFile
        MUST EXIST PRIOR TO RUNNING SCRIPT: Yes
        PURPOSE: Sets unique hostname, users, and configures SSH access
        Writes and starts systemd service that pulls Phase 1.5 Cloud Config Template File.
        DYNAMICALLY WRITTEN/REWRITTEN: Yes
        FINAL OUTPUT LOCATION(S): $OutputDirectory\phase1-[hostname]-setup-ssh-and-pull-phase1.5.yml
        UPLOADED TO AWS S3: No 
        AWS S3 LOCATION: N/A
        IMPORTANT NOTE #1: Must be less than 16KB or AWS won't accept it in the New-EC2Instance -UserDataFile parameter
        IMPORTANT NOTE #2: There are 2 SSH keys used in the Phase 1 Cloud Config Template. The purpose of the 
        "aws-coreos-primary-ssh-key" is to allow for SSH access from your workstation to any of the CoreOS Hosts in the cluster.
        PRIOR TO RUNNING this script/function, this key should be available in your AWS EC2 Dashboard under Network & Security --> Key Pairs.
        The purpose of "aws-coreos-temp-ssh-key" is for one-time dissemination and configuration of ~/.ssh/authorized_keys,
        ~/.ssh/config, ~/.ssh/known_hosts, and ~/.ssh/ssh_host_rsa_key to all hosts under all user accounts (including root)
        so that:
            1) Users logged into any CoreOS Host in the cluster can log into any other CoreOS host in the cluster; and
            2) "fleetctl ssh" works properly
        The "aws-coreos-temp-ssh-key" must exist PRIOR TO RUNNING this script/function, BUT it does NOT have to exist IN AWS. The 
        the public cert and *UNPROTECTED PRIVATE KEY* must be written to the Phase 1 CoreOS Cloud Config. The security risk is
        minimal, however, because the "aws-coreos-temp-ssh-key" is immediately removed from all CoreOS Hosts once etcd2 and fleet
        report that the cluster is up and running/healthy.
    - Phase 1.5 Template File
        ORIGINAL LOCATION: N/A
        MUST EXIST PRIOR TO RUNNING SCRIPT: No
        PURPOSE: Writes certificates needed for etcd2 TLS communication to each CoreOS host.
        Writes and starts systemd service that pulls Phase2 Cloud Config Template File.
        DYNAMICALLY WRITTEN/REWRITTEN: Yes
        FINAL OUTPUT LOCATION(S): $OutputDirectory\phase1.5-[hostname]-write-certs-and-pull-phase2.yml
        UPLOADED TO AWS S3: Yes
        AWS S3 LOCATION: $AWSRootURL\$AWSBucketName\$AWSS3BucketFolder\phase1.5-[hostname]-write-certs-and-pull-phase2.yml
    - Phase 2 Template File
        ORIGINAL LOCATION: $CloudConfigTemplateRoot\$Phase2CloudConfigTemplateFile
        MUST EXIST PRIOR TO RUNNING SCRIPT: Yes
        PURPOSE: On the CoreOS hosts, sets environment variables and configures fleet and etcd2 (EXCLUDING TLS). 
        The Phase 2 Cloud Config dynamically writes another Cloud Config here: /home/core/etcd2-and-fleet-cloud-config.yml 
        The systemd unit execute-cloud-config-for-etcd2-and-fleet.service uses coreos-cloudinit --from-file /home/core/etcd2-and-fleet-cloud-config.yml
        to make fleet and etcd2 configuration changes. Fleet and etcd2 services are NOT started. 
        Writes and starts systemd service that pulls MASTER Cloud Config Template File.
        DYNAMICALLY WRITTEN/REWRITTEN: Yes
        FINAL OUTPUT LOCATION(S): $OutputDirectory\$Phase2CloudConfigTemplateFile
        UPLOADED TO AWS S3: Yes
        AWS S3 LOCATION: $AWSRootURL\$AWSBucketName\aws-coreos-test-cluster\$Phase2CloudConfigTemplateFile
    - MASTER Template File
        ORIGINAL LOCATION: $CloudConfigTemplateRoot\$MASTERCloudConfigTemplateFile
        MUST EXIST PRIOR TO RUNNING SCRIPT: Yes
        PURPOSE: Adds etcd2 systemd drop-in unit for TLS communications. Starts etcd2 and fleet services. AND EVERYTHING ELSE.
        DYNAMICALLY WRITTEN/REWRITTEN: Yes
        FINAL OUTPUT LOCATION(S): $OutputDirectory\$MASTERCloudConfigTemplateFile
        UPLOADED TO AWS S3: Yes
        AWS S3 LOCATION: $AWSRootURL\$AWSBucketName\$AWSS3BucketFolder\$MASTERCloudConfigTemplateFile

    This script/function requests and receives new Client-Server Certificates from a Microsoft Issuing Certificate Authority on your local
    network via the ADCS Web Enrollment Website by sourcing Generate-Certificate.ps1 and running the Generate-Certificate function. These 
    certificates are written to the Cloud Config file "phase1.5-[hostname]-write-certs-and-pull-phase2.yml" (one for each host), which is 
    then uploaded to AWS S3 where the CoreOS hosts pull them using "coreos-cloudinit --from-url".
    NOTE: If the workstation running this script/function is connected to the same domain as the Issuing Certificate Authority, you have the option
    of requesting/receiving the client-server certificates without using the ADCS Web Enrollment website. To do so, simply remove the following
    parameters from the Generate-Certificate function:
        -RequestViaWebEnrollment "$RequestViaWebEnrollment" `
        -ADCSWebEnrollmentURL "$ADCSWebEnrollmentURL" `
        -ADCSWebAuthType "$ADCSWebAuthType" `
        -ADCSWebAuthUserName "$ADCSWebAuthUserName" `

.DEPENDENCIES
    1) AWS PowerShell Tools - https://aws.amazon.com/powershell/
    2) Win32 OpenSSL - https://indy.fulgan.com/SSL/
    3) Access to Microsoft ADCS Web Enrollment website OR workstation must be part to same domain as Microsoft Issuing Certificate Authority

.PARAMETER
    1) $HelperFunctionSourceDirectory - Path to directory that contains Generate-Certificate.ps1

    2) $AWSIAMProfile - The AWS IAM Profile that will be used to authenticate against AWS. This is NOT synonymous with an IAM User Account. It is
    a profile created specifically to load credentialls and other AWS enironment varibles into your PowerShell session. See AWS PowerShell Tools
    Documentation for details.

    If you leave this variable blank, or if the IAM Profile specified has not been established on the local host under the current Windows Account,
    the Set-AWSEnvHelper function will walk you through creating a new IAM Profile.

    3) $DefaultAWSRegion - The AWS Region where the new CoreOS EC2 instances will be created.

    4) $HostNames - A comma separated list of unique hostnames for each of your CoreOS machines. You must have at least 3 machines at a minimum.

    5) $CoreOSAMIImageID - The AWS EC2 Image ID for the version of CoreOS that you would like deployed.

    6) $VPCSecurityGroup - The AWS VPC that the new EC2 Instances will be a part of. (Make sure that routing rules are in place to allow SSH from your location)

    7) $InstanceType - The type of AWS EC2 Instance. Example: t2.micro

    8) $AWSKeyNameForSSH - The SSH Key generated via AWS to be used to SSH into the CoreOS machines.

    9) $OutputDirectory - Path to directory that will contain all file outputs from this script/function.

    10) $CloudConfigTemplateRoot - Path to directory that contains Phase 1, 2, and MASTER CoreOS Cloud Config Templates.

    11) $Phase1CloudConfigTemplateFile - File name (not path) of the Phase 1 CoreOS Cloud COnfig Template

    12) $Phase2CloudConfigTemplateFile - File name (not path) of the Phase 2 CoreOS Cloud Config Template

    13) $MASTERCloudConfigTemplateFile - File name (not path) of the MASTER CoreOS Cloud Config Template

    14) $AWSS3URLRoot - The prefix of a URL used to access your S3 Buckets via HTTP. Example: https://s3.amazonaws.com

    15) $AWSS3BucketName - The name of the AWS S3 bucket that dynamically written CoreOS Cloud Config files will be written to. Also, the bucket that CoreOS
    hosts will look at in order to pull subsequent Cloud Config files using "coreos-cloudinit --from-url"

    16) $AWSS3BucketFolder - You may have a specific folder within your AWS S3 Bucket that you would like CoreOS Cloud Config files to be written to. If so,
    use this parameter to specify the name of the folder.

#### BELOW THIS POINT are parameters for the Generate-Certificate script/function that Create-AWSCoreOSCluster sources ######

    17) $BasisTemplate - Either the CN or the displayName of the Certificate Template that you are basing this New Certificate on.
    IMPORTANT NOTE: If you are requesting the new certificates via the ADCS Web Enrollment Website (which is the default setting for this 
    Create-AWSCoreOSCluster script/function) the Certificate Template will ONLY appear in the Certificate Template drop-down on the ADCS 
    Web Enrollment website (which makes it a valid option for this parameter) if msPKITemplateSchemaVersion is "2" or "1" AND 
    pKIExpirationPeriod is 1 year or LESS.  See the Generate-CertTemplate.ps1 script/function for more details here:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-CertTemplate.ps1

    18) $Organization - Company Name. Will be added to "Subject" field of the new certificates generated by Generate-Certificate script/function.

    19) $OrganizationalUnit - Company Department. Will be added to "Subject" field of the new certificates generated by Generate-Certificate script/function.

    20) $Locality - City. Will be added to "Subject" field of the new certificates generated by Generate-Certificate script/function.

    21) $State - State. Will be added to "Subject" field of the new certificates generated by Generate-Certificate script/function.

    22) $Country - Country. Will be added to "Subject" field of the new certificates generated by Generate-Certificate script/function.

    23) $PFXPwdAsSecureString - A Plaintext Password OR a Secure String object. (Plaintext will be converted to a Secure String 
    by the Generate-Certificate script/function). In order to export a .pfx file from the Local Certificate Store, a password must be supplied
    (or permissions based on user accounts must be configured beforehand, but this is outside the scope of the Generate-Certificate script/function). 
    ***IMPORTANT*** This same password is applied to $ProtectedPrivateKeyOut if $UseOpenSSL = "Yes"
    ***IMPORTANT*** To avoid providing this password in plaintext on the command line, recommend using Generate-EncryptedPwdFile.ps1 and 
    Decrypt-EncryptedPwdFile.ps1 to pass this parameter. See:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1
    https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1

    24) $KeyUsageValue - Default value is hex value "0xa0" which maps to "Signing" and "Key Encipherment".
    These are the values needed for certificates used in CoreOS etcd2 TLS communication.
    See the following for more details:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-Certificate.ps1
    https://coreos.com/os/docs/latest/generate-self-signed-certificates.html

    25) $IntendedPurposeValuesPrep - Default value is "Client Authentication, Server Authentication".
    These are the values needed for certificates used in CoreOS etcd2 TLS communication.
    See the following for more details:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-Certificate.ps1
    https://coreos.com/os/docs/latest/generate-self-signed-certificates.html

    26) $RequestViaWebEnrollment - If this parameter is set to "Yes" (which is the default setting for this Create-AWSCoreOSCluster script/function), 
    then the Generate-Certificate script/function will use the Invoke-WebRequest cmdlet will be used to POST data to the ADCS Web Enrollment website 
    specified by $ADCSWebEnrollmentURL (see below) in order to request/receive certificates. If this parameter is set to "No", then PowerShell cmdlets 
    will be used that assume that the workstation running this script is also joined to the same domain as the Issuing Certificate Authority. Under this
    scenario, no other ADCS parameters are needed.

    27) $ADCSWebEnrollmentURL - URL of ADCS Web Enrollment website. Use this parameter only if $RequestViaWebEnrollment = "Yes" (which is the default setting).
    Example: https://pki.test.lab/certsrv

    28) $ADCSWebAuthType - The IIS Web Server hosting the ADCS Web Enrollment site can be configured to use Windows Authentication, Basic
    Authentication, or both. Specify either "Windows" or "Basic" for this parameter. Default setting is "Windows". Use this parameter 
    only if $RequestViaWebEnrollment = "Yes" (which is the default setting).

    29) $ADCSWebAuthUserName - A username with permission to access the ADCS Web Enrollment site. If $ADCSWebAuthType = "Basic", then
    INCLUDE the domain prefix as part of the username. Example: test2\testadmin . If $ADCSWebAuthType = "Windows", then DO NOT INCLUDE
    the domain prefix as part of the username. Example: testadmin
    (NOTE: If you mix up the above username formatting, then the script will figure it out. This is more of an FYI.)
    Use this parameter only if $RequestViaWebEnrollment = "Yes" (which is the default setting).

    30) $ADCSWebAuthPass - A Plaintext Password OR a Secure String object. (Plaintext will be converted to a Secure String by the script).
    If this parameter is left blank, the user will be prompted for secure input. If using this script as part of a larger automated process, 
    use a wrapper function to pass this parameter securely (this is outside the scope of this script).
    Use this parameter only if $RequestViaWebEnrollment = "Yes" (which is the default setting).
    ***IMPORTANT*** To avoid providing this password in plaintext on the command line, recommend using Generate-EncryptedPwdFile.ps1 and 
    Decrypt-EncryptedPwdFile.ps1 to pass this parameter. See:
    https://github.com/pldmgg/misc-powershell/blob/master/Generate-EncryptedPwdFile.ps1
    https://github.com/pldmgg/misc-powershell/blob/master/Decrypt-EncryptedPwdFile.ps1

    31) $UseOpenSSL - Indicates whether the Win32 OpenSSL binary should be used to extract certificates/keys in a format readily used in Linux environments. 
    Default value "Yes" is currently required in order to successfully run this script/function.

    32) $PathToWin32OpenSSL - Path to the Win32 OpenSSL binaries on your filesystem.
    Recommend using latest version from https://indy.fulgan.com/SSL/

    33) $StripPrivateKeyOfPassword - Default value "Yes" is currently required in order to successfully run this script/function.
    Generates an unprotected private key file that is part of the CoreOS host public/private key pair.

    34) $AddSAN - Set this parameter to "Yes" if you intend to include Subject Alternate Names (SANs) on the New Certificate. The default value
    "Yes" is required in order to run this script successfully (this is critical to get etcd2 TLS communication working properly).

    35) $TypesofSANObjectsToAdd - A comma separated list of SAN Object Types. All possible values are: DNS, Distinguished Name,
    URL, IP Address, Email, UPN, or GUID. Default value of "DNS, IP Address" is required for etcd2 TLS communications.

.EXAMPLE
    Create-AWSCoreOSCluster `
    -HelperFunctionSourceDirectory "V:\powershell" `
    -OutputDirectory "P:\CoreOS\Other_Configs\dynamic-configs\test1" `
    -AWSIAMProfile "pdadminprofile" `
    -DefaultAWSRegion "us-east-1" `
    -CoreOSChannel "Alpha" `
    -AWSAMIVirtType "HVM" `
    -InstanceType "t2.micro" `
    -HostNames "aws-coreos1, aws-coreos2, aws-coreos3" `
    -VPCSecurityGroup "sg-ce5f61b5" `
    -AWSKeyNameForSSH "aws-coreos-primary-ssh-key" `
    -CloudConfigTemplateRoot "P:\CoreOS\Other_Configs" `
    -Phase1CloudConfigTemplateFile "phase1-aws-coreos-template.yml" `
    -Phase2CloudConfigTemplateFile "phase2-setup-env-config-etcd2-and-fleet-and-pull-master.yml" `
    -MASTERCloudConfigTemplateFile "cloud-config-for-AWS-cluster-MASTER.yml" `
    -AWSS3URLRoot "https://s3.amazonaws.com" `
    -AWSS3BucketName "coreoscloudconfigs" `
    -AWSS3BucketFolder "aws-coreos-test-cluster" `
    -BasisTemplate "CertTempl171" `
    -Organization "Fictional Company Inc" `
    -OrganizationalUnit "DevOps" `
    -Locality "Portland" `
    -State "Oregon" `
    -Country "US" `
    -PFXPwdAsSecureString "Unsecure321!" `
    -RequestViaWebEnrollment "Yes" `
    -ADCSWebEnrollmentURL "https://pki.zero.lab/certsrv" `
    -ADCSWebAuthType "Windows" `
    -ADCSWebAuthUserName "zeroadmin" `
    -ADCSWebAuthPass "Insecure321!" `
    -PathToWin32OpenSSL "C:\openssl-1.0.2h-i386-win32"

.OUTPUTS
    

#>

Function Create-AWSCoreOSCluster {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $HelperFunctionSourceDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that contains the Generate-Certificate.ps1, 
        New-HashTableFromHTML.ps1, and Decrypt-EncryptedPwdFile.ps1 helper scripts/functions"),

        [Parameter(Mandatory=$False)]
        $OutputDirectory = $(Read-Host -Prompt "Please enter the the full path to the directory to which all output files will be written"),

        [Parameter(Mandatory=$False)]
        $AWSIAMProfile = $(Read-Host -Prompt "Please enter the AWS PowerShell Tools IAM Profile that you would like to use for this session"),

        [Parameter(Mandatory=$False)]
        $DefaultAWSRegion = $(Read-Host -Prompt "Please enter the AWS Region that the EC2 instances will be deployed to"),

        [Parameter(Mandatory=$False)]
        $AWSAMIVirtType,

        [Parameter(Mandatory=$False)]
        $CoreOSChannel,

        [Parameter(Mandatory=$False)]
        $CoreOSAMIImageID,

        [Parameter(Mandatory=$False)]
        $HostNames = $(Read-Host -Prompt "Please enter the name of each CoreOS Host in your cluster. Separate each name with a comma."),

        [Parameter(Mandatory=$False)]
        $VPCSecurityGroup = $(Read-Host -Prompt "Please enter the VPC Security Group that the CoreOS Cluster will be a part of."),

        [Parameter(Mandatory=$False)]
        $InstanceType = $(Read-Host -Prompt "Please enter the AWS EC2 Instance Type that you would like to use for each of the CoreOS hosts"),

        [Parameter(Mandatory=$False)]
        $AWSKeyNameForSSH = $(Read-Host -Prompt "Please enter the name of the AWS SSH Key that will be used to remote into the CoreOS Hosts"),

        [Parameter(Mandatory=$False)]
        $CloudConfigTemplateRoot = $(Read-Host -Prompt "Please enter the full path to the directory that contains the CoreOS Cloud Config Template files"),

        [Parameter(Mandatory=$False)]
        $Phase1CloudConfigTemplateFile = $(Read-Host -Prompt "Please enter the name of the Phase 1 CoreOS Cloud Config Template .yml file"),

        [Parameter(Mandatory=$False)]
        $Phase2CloudConfigTemplateFile = $(Read-Host -Prompt "Please enter the name of the Phase 2 CoreOS Cloud Config Template .yml file"),

        [Parameter(Mandatory=$False)]
        $MASTERCloudConfigTemplateFile = $(Read-Host -Prompt "Please enter the name of the MASTER Cloud Config Template .yml file"),
        
        [Parameter(Mandatory=$False)]
        $AWSS3URLRoot = $(Read-Host -Prompt "Please enter the root URL that you use for AWS S3.
        Example: https://s3.amazonaws.com"),

        [Parameter(Mandatory=$False)]
        $AWSS3BucketName = $(Read-Host -Prompt "Please enter the name of the AWS S3 Bucket that you are using to post and store CoreOS Cloud Config files"),

        [Parameter(Mandatory=$False)]
        $AWSS3BucketFolder,

        # BEGIN Parameters for Generate-Certificate function #

        [Parameter(Mandatory=$False)]
        $BasisTemplate = $(Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificates
        to be based on"),

        [Parameter(Mandatory=$False)]
        $Organization = $(Read-Host -Prompt "Please enter the name of the the Company that will appear on the New Certificates"),

        [Parameter(Mandatory=$False)]
        $OrganizationalUnit = $(Read-Host -Prompt "Please enter the name of the Department that you work for within your Company"),

        [Parameter(Mandatory=$False)]
        $Locality = $(Read-Host -Prompt "Please enter the City where your Company is located"),

        [Parameter(Mandatory=$False)]
        $State = $(Read-Host -Prompt "Please enter the State where your Company is located"),

        [Parameter(Mandatory=$False)]
        $Country = $(Read-Host -Prompt "Please enter the Country where your Company is located"),

        [Parameter(Mandatory=$False)]
        $PFXPwdAsSecureString = $(Read-Host -Prompt "Please enter the password you would like to use for the PFX Certificate Export operation.
        NOTE: This password must *always* be set, even if you plan on removing it later (recommended) using the parameter `$StripPrivateKeyOfPassword = 'Yes'"),

        # For etcd2 TLS communication, *must* set $KeyUsageValue = "0xa0"
        [Parameter(Mandatory=$False)]
        $KeyUsageValue = "0xa0",

        # For etcd2 TLS communication, *must* set $IntendedPurposeValuesPrep = "Client Authentication, Server Authentication"
        [Parameter(Mandatory=$False)]
        $IntendedPurposeValuesPrep = "Client Authentication, Server Authentication",

        # If the workstation being used to run this script/function is NOT part of the same domain as the Issuing Certificate Authority, we must use
        # the ADCS Web Enrollment site for the certificate request. $RequestViaWebEnrollment should be set to "Yes", and $ADCSWebEnrollmentURL should be set.
        [Parameter(Mandatory=$False)]
        $RequestViaWebEnrollment = $(Read-Host -Prompt "Would you like to request certificates via the ADCS Web Enrollment site? 
        WARNING: If NOT, make sure the workstation running this script is part of the same domain as the Issuing Certificate Authority. [Yes/No]"),

        [Parameter(Mandatory=$False)]
        $ADCSWebEnrollmentURL,

        # $ADCSWebAuthType options are "Windows" or "Basic"
        [Parameter(Mandatory=$False)]
        $ADCSWebAuthType,

        [Parameter(Mandatory=$False)]
        $ADCSWebAuthUserName,

        [Parameter(Mandatory=$False)]
        $ADCSWebAuthPass,

        # Highly recommend always using Win32-OpenSSL from https://indy.fulgan.com/SSL/
        [Parameter(Mandatory=$False)]
        $UseOpenSSL = "Yes",

        [Parameter(Mandatory=$False)]
        $PathToWin32OpenSSL = $(Read-Host -Prompt "Please enter the full path to the directory that contains Win32-OpenSSL"),

        [Parameter(Mandatory=$False)]
        $StripPrivateKeyOfPassword = "Yes",

        # For etcd2 TLS communication, the certificates need Subject Alternate Names with DNS and IP Address
        [Parameter(Mandatory=$False)]
        $AddSAN = "Yes",

        # For etcd2 TLS communication, the certificates need Subject Alternate Names with DNS and IP Address
        [Parameter(Mandatory=$False)]
        $TypesofSANObjectsToAdd = "DNS, IP Address"

    )

    ##### BEGIN Helper Functions and Libraries #####

    ## Sourced Scripts/Functions ##
    . "$HelperFunctionSourceDirectory\Generate-Certificate.ps1"
    . "$HelperFunctionSourceDirectory\Decrypt-EncryptedPwdFile.ps1"
    . "$HelperFunctionSourceDirectory\New-HashTableFromHTML.ps1"

    ## Native Helper Functions ##
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

    Function Generate-RandomString() {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [int]$length = $(Read-Host -Prompt "Please enter the number of characters you would like the string to be"),

            [Parameter(Mandatory=$False)]
            $NumbersAndLettersOnly,

            [Parameter(Mandatory=$False)]
            $LimitSpecialCharsToNumberRowOnKeyBoard
        )

        # Make sure only ONE of the parameters $NumbersAndLettersOnly OR $LimitSpecialCharsToNumberRowOnKeyBoard is used...
        if ($NumbersAndLettersOnly -ne $null -and $LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
            Write-Host "Please only use EITHER the NumbersAndLettersOnly paramter OR the LimitSpecialCharsToNumberRowOnKeyBoard parameter. Halting!"
            return
        }

        # Validate $NumbersAndLettersOnly if it is used...
        if ($NumbersAndLettersOnly -ne $null) {
            if (! ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y" -or $NumbersAndLettersOnly -eq "No" -or $NumbersAndLettersOnly -eq "n") ) {
                Write-Host "The value $NumbersAndLettersOnly is not valid for the parameter NumbersAndLettersOnly. Please enter either 'Yes' or 'No'"
                $NumbersAndLettersOnly = Read-Host -Prompt "Would you like to limit the string to ONLY numbers and letters? [Yes/No]"
                if (! ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y" -or $NumbersAndLettersOnly -eq "No" -or $NumbersAndLettersOnly -eq "n") ) {
                    Write-Host "The value $NumbersAndLettersOnly is not valid for the parameter NumbersAndLettersOnly. Please enter either 'Yes' or 'No'. Halting!"
                    return
                }
            }
        }

        # Validate $LimitSpecialCharsToNumberRowOnKeyBoard if it is used...
        if ($LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
            if (! ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y" `
            -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "No" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "n") ) {
                Write-Host "The value $LimitSpecialCharsToNumberRowOnKeyBoard is not valid for the parameter LimitSpecialCharsToNumberRowOnKeyBoard. Please enter either 'Yes' or 'No'"
                $LimitSpecialCharsToNumberRowOnKeyBoard = Read-Host -Prompt "Would you like to limit special characters those available on the number row of keys on your keyboard? [Yes/No]"
                if (! ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y" `
                -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "No" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "n") ) {
                    Write-Host "The value $LimitSpecialCharsToNumberRowOnKeyBoard is not valid for the parameter LimitSpecialCharsToNumberRowOnKeyBoard. Halting!"
                    return
                }
            }
        }

        $ascii = $NULL;For ($a=33;$a –le 126;$a++) {$ascii+=,[char][byte]$a }

        if ($NumbersAndLettersOnly -ne $null) {
            if ($NumbersAndLettersOnly -eq "Yes" -or $NumbersAndLettersOnly -eq "y") {
                $ascii = $($ascii | Select-String -Pattern '[\w]').Matches.Value
            }
        }

        if ($LimitSpecialCharsToNumberRowOnKeyBoard -ne $null) {
            if ($LimitSpecialCharsToNumberRowOnKeyBoard -eq "Yes" -or $LimitSpecialCharsToNumberRowOnKeyBoard -eq "y") {
                $ascii = $($ascii | Select-String -Pattern '([\w])|(!)|(@)|(#)|(%)|(\^)|(&)|(\*)|(\()|(\))|(-)|(=)|(\+)').Matches.Value
            }
        }

        For ($loop=1; $loop –le $length; $loop++) {
            $TempString+=($ascii | Get-Random)
        }

        Write-Output $TempString
    }

    ##### END Helper Functions and Libraries #####

    ##### BEGIN Parameter Transforms #####

    $HostNamesArray = $HostNames.Split(",").Trim()

    ##### End Parameter Transforms #####

    ##### BEGIN Validation #####

    # Check AWS PowerShell Tools Dependency...
    if (((Get-Module -ListAvailable -Name AWSPowerShell | Select-String -Pattern AWSPowerShell).Matches.Success) -eq $true) {
        Write-Host "AWSPowerShell Module is available. Continuing..."
    }
    else {
        Write-Host "AWSPowerShell Module is NOT available. This script requires the AWSPowerShell Module from https://aws.amazon.com/powershell. Please make this module available and try again."
        return
    }

    # Validate $HelperFunctionSourceDirectory ...
    if (Test-Path $HelperFunctionSourceDirectory) {
        Write-Host "The path to the directory containing Helper Functions is valid. Continuing..."
    }
    else {
        Write-Host "The path to the directory containing Helper Functions is NOT valid. Please enter a valid path to a directory."
        $HelperFunctionSourceDirectory = Read-Host -Prompt "Please enter a valid path to a directory."
        if (Test-Path $HelperFunctionSourceDirectory) {
            Write-Host "The path to the directory containing Helper Functions is valid. Continuing..."
        }
        else {
            Write-Host "The path to the directory containing Helper Functions is NOT valid"
            return
        }
    }

    # If $AWSAMIVirtType has been provided, validate it...
    $ValidAWSVirtTypes = @("HVM","PV")
    if ($AWSAMIVirtType -ne $null) {
        if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
            Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Valid AWS AMI Virtualization types are as follows:"
            $ValidAWSVirtTypes
            $AWSAMIVirtType = Read-Host -Prompt "Please enter a valid AWS AMI Virtualization Type [HVM/PV]"
            if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
                Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Halting!"
                return
            }
        }
    }

    # Define $ValidCoreOSChannels
    $ValidCoreOSChannels = @("Alpha","Beta","Stable")
    # Load latest CoreOS Channel AWS AMI Table from https://coreos.com/os/docs/latest/booting-on-ec2.html to help with validation
    # NOTE: The below New-HashTableFromHTML function produces $global:FinalHashTable
    # If $CoreOSChannel has been provided, use it to target the appropriate table from the website
    if ($CoreOSChannel -ne $null) {
        # Immediately validate $CoreOSChannel because we're going to use it to generate a reference HashTable
        # Validate $CoreOSChannel ...
        if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
            Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Valid CoreOS channels are as follows:"
            $ValidCoreOSChannels
            $CoreOSChannel = Read-Host -Prompt "Please enter a valid CoreOS Channel [alpha/beta/stable]"
            if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
                Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Halting!"
                return
            }
        }

        New-HashTableFromHTML `
        -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
        -ParentHTMLElementTagName "div" `
        -ParentHTMLElementClassName "tab-pane" `
        -ParentHTMLElementID "$CoreOSChannel" `
        -JavaScriptUsedToGenTable "No"

        $CoreOSAMITable = $global:FinalHashTable
        Remove-Variable -Name "FinalHashTable" -Scope Global

        # Define other needed validation arrays #

        # Define $ValidEC2AWSRegions...
        $ValidEC2AWSRegions = $CoreOSAMITable.Keys

        # Immediately validate $DefaultAWSRegion because we're going to use it to help define $ValidCoreOSAMIImageIDs
        # Validate $DefaultAWSRegion ...
        if ($ValidEC2AWSRegions -contains $DefaultAWSRegion) {
            Write-Host "$DefaultAWSRegion is a valid AWS EC2 region. Continuing..."
        }
        else {
            Write-Host "$DefaultAWSRegion is NOT a valid AWS EC2 region. Valid AWS EC2 regions are as follows:"
            $ValidEC2AWSRegions
            $DefaultAWSRegion = Read-Host -Prompt "Please enter a valid AWS EC2 region"
            if ($ValidEC2AWSRegions -contains $DefaultAWSRegion) {
                Write-Host "$DefaultAWSRegion is a valid AWS EC2 region. Continuing..."
            }
            else {
                Write-Host "$DefaultAWSRegion is NOT a valid AWS EC2 region. Halting!"
                return
            }
        }

        # Define $ValidCoreOSAMIImageIDs...
        # If $AWSAMIVirtType HAS been provided, then we can define $CoreOSAMIImageID precisely...
        if ($AWSAMIVirtType -ne $null) {
            $CoreOSAMIImageID = $CoreOSAMITable.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
            $ValidCoreOSAMIImageIDs = $CoreOSAMIImageID 
        }
        # If $AWSAMIVirtType has NOT been provided, we still have more than one possibility for $CoreOSAMIImageID, so we define $ValidCoreOSAMIImageIDs
        if ($AWSAMIVirtType -ne $null) {
            $ValidCoreOSAMIImageIDs = $CoreOSAMITable.$DefaultAWSRegion.'AMI ID'.Keys
        }
    }
    # If $CoreOSChannel has NOT been provided, load up ALL tables for ALL channels from the CoreOS website
    if ($CoreOSChannel -eq $null) {
        foreach ($channel in $ValidCoreOSChannels) {
            New-HashTableFromHTML `
            -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
            -ParentHTMLElementTagName "div" `
            -ParentHTMLElementClassName "tab-pane" `
            -ParentHTMLElementID "$channel" `
            -JavaScriptUsedToGenTable "No"

            New-Variable -Name "CoreOSAMITable$channel" -Value "$global:FinalHashTable"
            Remove-Variable -Name "FinalHashTable" -Scope Global
        }

        # Define other needed validation arrays #

        # Define $ValidEC2AWSRegions...
        # If the Keys in all of the different channel HashTables are the same, then use the Keys from one of them as the definitive
        # list of valid AWS Regions. It doesn't matter which table you decide to use. The below arbitrarily uses Keys from $CoreOSAMITableAlpha
        if ([string]$($CoreOSAMITableAlpha.Keys | Sort-Object -Descending) -eq [string]$($CoreOSAMITableBeta.Keys | Sort-Object -Descending) -and `
        [string]$($CoreOSAMITableAlpha.Keys | Sort-Object -Descending) -eq [string]$($CoreOSAMITableStable.Keys | Sort-Object -Descending) -and `
        [string]$($CoreOSAMITableBeta.Keys | Sort-Object -Descending) -eq [string]$($CoreOSAMITableStable.Keys | Sort-Object -Descending)) { 
            $ValidEC2AWSRegions = $CoreOSAMITableAlpha.Keys
        }
        # If the number of Keys (i.e. AWS Regions) in any of the above HashTables has the highest count of the three, use that as the definitive
        # list of valid AWS Regions
        if ($CoreOSAMITableAlpha.Keys.Count -gt $CoreOSAMITableBeta.Keys.Count -and $CoreOSAMITableAlpha.Keys.Count -gt $CoreOSAMITableStable.Keys.Count ) {
            $ValidEC2AWSRegions = $CoreOSAMITableAlpha.Keys
        }
        if ($CoreOSAMITableBeta.Keys.Count -gt $CoreOSAMITableAlpha.Keys.Count -and $CoreOSAMITableBeta.Keys.Count -gt $CoreOSAMITableStable.Keys.Count ) {
            $ValidEC2AWSRegions = $CoreOSAMITableBeta.Keys
        }
        if ($CoreOSAMITableStable.Keys.Count -gt $CoreOSAMITableAlpha.Keys.Count -and $CoreOSAMITableStable.Keys.Count -gt $CoreOSAMITableBeta.Keys.Count ) {
            $ValidEC2AWSRegions = $CoreOSAMITableStable.Keys
        }

        # Immediately validate $DefaultAWSRegion because we're going to use it to help define $ValidCoreOSAMIImageIDs
        # Validate $DefaultAWSRegion ...
        if ($ValidEC2AWSRegions -contains $DefaultAWSRegion) {
            Write-Host "$DefaultAWSRegion is a valid AWS EC2 region. Continuing..."
        }
        else {
            Write-Host "$DefaultAWSRegion is NOT a valid AWS EC2 region. Valid AWS EC2 regions are as follows:"
            $ValidEC2AWSRegions
            $DefaultAWSRegion = Read-Host -Prompt "Please enter a valid AWS EC2 region"
            if ($ValidEC2AWSRegions -contains $DefaultAWSRegion) {
                Write-Host "$DefaultAWSRegion is a valid AWS EC2 region. Continuing..."
            }
            else {
                Write-Host "$DefaultAWSRegion is NOT a valid AWS EC2 region. Halting!"
                return
            }
        }

        # Define $ValidCoreOSAMIImageIDs...
        # If $AWSAMIVirtType has been provided, then use it to help filter valid AMI IDs...
        if ($AWSAMIVirtType -ne $null) {
            $CoreOSAlphaAMIImageIDs = $CoreOSAMITableAlpha.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
            $CoreOSBetaAMIImageIDs = $CoreOSAMITableBeta.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
            $CoreOSStableAMIImageIDs = $CoreOSAMITableStable.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
        }
        # If $AWSAMIVirtType has NOT been provided, then grab valid AMI IDs with the information available...
        if ($AWSAMIVirtType -eq $null) {
            $CoreOSAlphaAMIImageIDs = $CoreOSAMITableAlpha.$DefaultAWSRegion.'AMI ID'.Keys
            $CoreOSBetaAMIImageIDs = $CoreOSAMITableBeta.$DefaultAWSRegion.'AMI ID'.Keys 
            $CoreOSStableAMIImageIDs = $CoreOSAMITableStable.$DefaultAWSRegion.'AMI ID'.Keys
        }
        $ValidCoreOSAMIImageIDs = $CoreOSAlphaAMIImageIDs+$CoreOSBetaAMIImageIDs+$CoreOSStableAMIImageIDs
    }

    # If $CoreOSAMIImageID has been provided, validate it...
    if ($CoreOSAMIImageID -ne $null) {
        if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
        }
        else {
            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. Valid CoreOS AWS AMI Image IDs are as follows:"
            $ValidCoreOSAMIImageIDs
            $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
            if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
            }
            else {
                Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. 
                Please EITHER check for a valid `$CoreOSAMIImageID value on https://coreos.com/os/docs/latest/booting-on-ec2.html,
                OR simply use the `$CoreOSChannel and `$AWSAMIVirtType parameters while leaving the `$CoreOSAMIImageID parameter blank."
                return
            }
        }
    }
    # If $CoreOSAMIImageID has NOT been provided, figure it out...
    # To figure it out, we already have $DefaultAWSRegion, so we need $CoreOSChannel and $AWSAMIVirtType
    if ($CoreOSAMIImageID -eq $null) {
        if ($CoreOSChannel -eq $null) {
            if ($AWSAMIVirtType -eq $null) {
                Write-Host "In order to create new AWS EC2 CoreOS instances, a valid AWS AMI Image ID must be provided."
                Write-Host "You can specify the AWS AMI Image ID **directly** using the `$CoreOSAMIImageID parameter, 
                or it can be determined **indirectly** by specifying the `$CoreOSChannel AND `$AWSAMIVirtType parameters."
                $DetermineAMIImageIDSwitch = Read-Host -Prompt "Would you like to specify `$CoreOSAMIImageID directly or indirectly? [direct/indirect]"
                if ($DetermineAMIImageIDSwitch -eq "direct") {
                    $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                    if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                    }
                    else {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. Valid CoreOS AWS AMI Image IDs are as follows:"
                        $ValidCoreOSAMIImageIDs
                        $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                        if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                        }
                        else {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. 
                            Please EITHER check for a valid `$CoreOSAMIImageID value on https://coreos.com/os/docs/latest/booting-on-ec2.html,
                            OR simply use the `$CoreOSChannel and `$AWSAMIVirtType parameters while leaving the `$CoreOSAMIImageID parameter blank."
                            return
                        }
                    }
                }
                if ($DetermineAMIImageIDSwitch -eq "indirect") {
                    $CoreOSChannel = Read-Host -Prompt "Please enter a valid CoreOS Channel [alpha/beta/stable]"
                    if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
                        Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Valid CoreOS channels are as follows:"
                        $ValidCoreOSChannels
                        $CoreOSChannel = Read-Host -Prompt "Please enter a valid CoreOS Channel [alpha/beta/stable]"
                        if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
                            Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Halting!"
                            return
                        }
                    }
                    $AWSAMIVirtType = Read-Host -Prompt "Please enter a valid AWS AMI Virtualization Type [HVM/PV]"
                    if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
                        Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Valid AWS AMI Virtualization types are as follows:"
                        $ValidAWSVirtTypes
                        $AWSAMIVirtType = Read-Host -Prompt "Please enter a valid AWS AMI Virtualization Type [HVM/PV]"
                        if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
                            Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Halting!"
                            return
                        }
                    }

                    $CoreOSAMIImageID = $(Get-Variable -Name "CoreOSAMITable$CoreOSChannel" -ValueOnly).$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
                }
            }
            if ($AWSAMIVirtType -ne $null) {
                Write-Host "In order to create new AWS EC2 CoreOS instances, a valid AWS AMI Image ID must be provided."
                Write-Host "You can specify the AWS AMI Image ID **directly** using the `$CoreOSAMIImageID parameter, 
                or it can be determined **indirectly** by specifying the `$CoreOSChannel AND `$AWSAMIVirtType parameters."
                $DetermineAMIImageIDSwitch = Read-Host -Prompt "Would you like to specify `$CoreOSAMIImageID directly or indirectly? [direct/indirect]"
                if ($DetermineAMIImageIDSwitch -eq "direct") {
                    $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                    if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                    }
                    else {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. Valid CoreOS AWS AMI Image IDs are as follows:"
                        $ValidCoreOSAMIImageIDs
                        $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                        if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                        }
                        else {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. 
                            Please EITHER check for a valid `$CoreOSAMIImageID value on https://coreos.com/os/docs/latest/booting-on-ec2.html,
                            OR simply use the `$CoreOSChannel and `$AWSAMIVirtType parameters while leaving the `$CoreOSAMIImageID parameter blank."
                            return
                        }
                    }
                }
                if ($DetermineAMIImageIDSwitch -eq "indirect") {
                    # $AWSAMIVirtType was already validated above since it was provided initially

                    # $CoreOSChannel has NOT been provided, so prompt user to provide and then validate
                    $CoreOSChannel = Read-Host -Prompt "Please enter a valid CoreOS Channel [alpha/beta/stable]"
                    if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
                        Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Valid CoreOS channels are as follows:"
                        $ValidCoreOSChannels
                        $CoreOSChannel = Read-Host -Prompt "Please enter a valid CoreOS Channel [alpha/beta/stable]"
                        if ($ValidCoreOSChannels -notcontains $CoreOSChannel) {
                            Write-Host "The CoreOS Channel $CoreOSChannel is NOT a valid CoreOS Channel. Halting!"
                            return
                        }
                    }

                    $CoreOSAMIImageID = $(Get-Variable -Name "CoreOSAMITable$CoreOSChannel" -ValueOnly).$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
                }
            }
        }
        if ($CoreOSChannel -ne $null) {
            if ($AWSAMIVirtType -eq $null) {
                Write-Host "In order to create new AWS EC2 CoreOS instances, a valid AWS AMI Image ID must be provided."
                Write-Host "You can specify the AWS AMI Image ID **directly** using the `$CoreOSAMIImageID parameter, 
                or it can be determined **indirectly** by specifying the `$CoreOSChannel AND `$AWSAMIVirtType parameters."
                $DetermineAMIImageIDSwitch = Read-Host -Prompt "Would you like to specify `$CoreOSAMIImageID directly or indirectly? [direct/indirect]"
                if ($DetermineAMIImageIDSwitch -eq "direct") {
                    $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                    if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                    }
                    else {
                        Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. Valid CoreOS AWS AMI Image IDs are as follows:"
                        $ValidCoreOSAMIImageIDs
                        $CoreOSAMIImageID = Read-Host -Prompt "Please enter a valid CoreOS AWS AMI Image ID"
                        if ($ValidCoreOSAMIImageIDs -contains $CoreOSAMIImageID) {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is valid. Continuing..."
                        }
                        else {
                            Write-Host "The CoreOS AWS AMI Image ID $CoreOSAMIImageID is NOT valid. 
                            Please EITHER check for a valid `$CoreOSAMIImageID value on https://coreos.com/os/docs/latest/booting-on-ec2.html,
                            OR simply use the `$CoreOSChannel and `$AWSAMIVirtType parameters while leaving the `$CoreOSAMIImageID parameter blank."
                            return
                        }
                    }
                }
                if ($DetermineAMIImageIDSwitch -eq "indirect") {
                    # $CoreOSChannel has already been provided, and validated above when the $CoreOSAMITable was generated
                    
                    # $AWSAMIVirtType has NOT been provided, so prompt user to provide and then validate
                    $AWSAMIVirtType = Read-Host -Prompt "Please enter a valid AWS AMI Virtualization Type [HVM/PV]"
                    if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
                        Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Valid AWS AMI Virtualization types are as follows:"
                        $ValidAWSVirtTypes
                        $AWSAMIVirtType = Read-Host -Prompt "Please enter a valid AWS AMI Virtualization Type [HVM/PV]"
                        if ($ValidAWSVirtTypes -notcontains $AWSAMIVirtType) {
                            Write-Host "$AWSAMIVirtType is NOT a valid AWS AMI Virtualization Type. Halting!"
                            return
                        }
                    }

                    $CoreOSAMIImageID = $CoreOSAMITable.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
                }
            }
            if ($AWSAMIVirtType -ne $null) {
                # $AWSAMIVirtType was already validated above since it was provided initially

                # You now have enough information to identify $CoreOSAMIImageID
                $CoreOSAMIImageID = $CoreOSAMITable.$DefaultAWSRegion.'AMI Type'.$AWSAMIVirtType
            }
        }
    }

    # At this point, we've defined and validated $CoreOSAMIImageID
    Write-Host "The CoreOS AWS AMI Image ID has beend defined and validated as $CoreOSAMIImageID" 

    # Validate $VPCSecurityGroup ...
    $ValidSecurityGroups = (Get-EC2SecurityGroup).GroupId
    if ($ValidSecurityGroups -notcontains $VPCSecurityGroup) {
        Write-Host "$VPCSecurityGroup is NOT a valid AWS EC2 Security Group. Valid AWS EC2 Security Groups are as follows:"
        $ValidSecurityGroups
        $VPCSecurityGroup = Read-Host -Prompt "Please enter a valid AWS EC2 Security Group."
        if ($ValidSecurityGroups -notcontains $VPCSecurityGroup) {
            Write-Host "$VPCSecurityGroup is NOT a valid AWS EC2 Security Group. Halting!"
            return
        }
    }

    # Validate $InstanceType ...
    # Scrape https://aws.amazon.com/ec2/instance-types
    New-HashTableFromHTML `
    -TargetURL "https://aws.amazon.com/ec2/instance-types" `
    -ParentHTMLElementClassName "aws-table" `
    -ParentHTMLElementTagName "div" `
    -JavaScriptUsedToGenTable "No" `
    -TextUniqueToTargetTable "Clock Speed (GHz)"

    $ValidEC2InstanceTypes = $global:FinalHashTable.Keys
    Remove-Variable -Name "FinalHashTable" -Scope Global

    if ($ValidEC2InstanceTypes -notcontains $InstanceType) {
        Write-Host "The Instance Type $InstanceType is not a valid AWS EC2 Instance Type. Valid AWS EC2 Instance Types are as follows:"
        [string]$ValidEC2InstanceTypes -replace "[\s]",", "
        $InstanceType = Read-Host -Prompt "Please enter a valid AWS EC2 Instance Type"
        if ($ValidEC2InstanceTypes -notcontains $InstanceType) {
            Write-Host "The Instance Type $InstanceType is not a valid AWS EC2 Instance Type. Halting!"
            return
        }
    }

    # Validate $AWSKeyNameForSSH ...
    $ValidEC2KeyNames = (Get-EC2KeyPair).KeyName
    if ($ValidEC2KeyNames -notcontains $AWSKeyNameForSSH) {
        Write-Host "$AWSKeyNameForSSH is NOT a valid/available AWS EC2 Key Pair Name. Valid Key Pair Names are as follows:"
        $ValidEC2KeyNames
        $AWSKeyNameForSSH = Read-Host -Prompt "Please enter a valid AWS EC2 Key Pair Name"
        if ($ValidEC2KeyNames -notcontains $AWSKeyNameForSSH) {
            Write-Host "$AWSKeyNameForSSH is NOT a valid/available AWS EC2 Key Pair Name. Halting!"
            return
        }
    }

    # Validate $OutputDirectory ...
    if (Test-Path $OutputDirectory) {
        Write-Host "Output Directory path is valid. Continuing..."
    }
    else {
        Write-Host "Output Directory path is NOT valid. Attempting to create directory..."
        mkdir $OutputDirectory
        if ($? -ne $true) {
            Write-Host "Unable to create directory. Please make sure the path for the parameter OutputDirectory is valid and try again."
            return
        }
    }

    # Validate $CloudConfigTemplateRoot ...
    if (Test-Path $CloudConfigTemplateRoot) {
        Write-Host "Cloud Config Template Root Directory path is valid. Continuing..."
    }
    else {
        Write-Host "Cloud Config Template Root Directory path is NOT valid. Attempting to create directory..."
        mkdir $CloudConfigTemplateRoot
        if ($? -ne $true) {
            Write-Host "Unable to create directory. Please make sure the path for the parameter CloudConfigTemplateRoot is valid and try again."
            return
        }
    }

    ##### END Validation #####

    Write-Host ""
    Write-Host "Updating Cloud Configs..."
    Write-Host ""

    # Remove Phase 2 Cloud Config on AWS S3 if it exists already. We don't want the new CoreOS EC2 instances accidentally pulling an old version...
    Write-Host ""
    Write-Host "Removing old version of Phase2 Cloud Config from AWS S3 if it exists..."
    Write-Host ""  
    Remove-S3Object -BucketName $AWSS3BucketName -Key "$AWSS3BucketFolder/$Phase2CloudConfigTemplateFile" -Force

    # Eventhough there is no chance that the new CoreOS EC2 instances could accidentally pull an old version of MASTER Cloud Config
    # remove it from AWS S3 if it exists already to future-proof.
    Write-Host ""
    Write-Host "Removing old version of MASTER Cloud Config from AWS S3 if it exists..."
    Write-Host "" 
    Remove-S3Object -BucketName $AWSS3BucketName -Key "$AWSS3BucketFolder/$MASTERCloudConfigTemplateFile" -Force

    # Generate new discovery URL for new hosts to check-into
    #DiscoveryURL = $(Invoke-WebRequest https://discovery.etcd.io/new?size=$($HostNamesArray.Count)).Content

    # Update MASTER Cloud Config with Number of Hosts in Cluster and $DefaultAWSRegion and Upload to AWS S3
    # NOTE: Below we use the [array]$LineToBeReplacedN and foreach structure so that whether the thing you want to replace is a specific string or
    # an entire line, the structure is basically the same.
    $MASTERCloudConfig = Get-Content "$CloudConfigTemplateRoot\$MASTERCloudConfigTemplateFile"
    [array]$LineToBeReplaced4 = ($MASTERCloudConfig | Select-String -Pattern "} -ne [0-9]").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced4) {
        $obj2 = $obj1 -replace "} -ne [0-9]","} -ne $($HostNamesArray.Count)"
        $MASTERCloudConfig = $MASTERCloudConfig.Replace("$obj1","$obj2")
    }
    $UpdatedMASTERCloudConfig = $MASTERCloudConfig
    # Writing $UpdatedMASTERCloudConfig to a file that has the same name as $MASTERCloudConfigTemplateFile but in $OutputDirectory
    Set-Content -Path "$OutputDirectory\$MASTERCloudConfigTemplateFile" -Value $UpdatedMASTERCloudConfig
    Write-S3Object -BucketName $AWSS3BucketName -Key "$AWSS3BucketFolder/$MASTERCloudConfigTemplateFile" -File "$OutputDirectory\$MASTERCloudConfigTemplateFile"

    Write-Host ""
    Write-Host "Creating New AWS EC2 Instances ..."
    Write-Host ""

    # Initialize Array of PSObjects where each PSObject contains the desired properties of the New Host
    $ArrayofNewHostPSObjects = @()
    # Dynamically create Phase 1 Cloud Configs for Each Host in New Cluster Using Template File
    # Then, create the new EC2 Instances and Get New Public and Private IP Addresses
    # Then, generate client-server certificates for the unique coreos host
    foreach ($obj1 in $HostNamesArray) {
        # Create Phase 1 Cloud Configs for Each Host - Modify Phase1CloudConfigTemplate references to HostName and URL for the host-specific phase1.5 cloud config
        $Phase1CloudConfigTemplate = Get-Content "$CloudConfigTemplateRoot\$Phase1CloudConfigTemplateFile"
        [array]$LineToBeReplaced5 = $Phase1CloudConfigTemplate | Select-String -Pattern "hostname:" | Sort-Object | Get-Unique
        foreach ($obj2 in $LineToBeReplaced5) {
            $obj3 = $obj2 -replace "$obj2","hostname: `"$obj1`""
            $Phase1CloudConfigTemplate = $Phase1CloudConfigTemplate.Replace("$obj2","$obj3")
        }
        [array]$LineToBeReplaced6 = ($Phase1CloudConfigTemplate | Select-String -Pattern "ExecStart=/usr/bin/coreos-cloudinit --from-url").Line | Sort-Object | Get-Unique
        foreach ($obj4 in $LineToBeReplaced6) {
            $obj5 = $obj4 -replace "$obj4","        ExecStart=/usr/bin/coreos-cloudinit --from-url=$AWSS3URLRoot/$AWSS3BucketName/$AWSS3BucketFolder/phase1.5-$obj1-write-certs-and-pull-phase2.yml"
            $Phase1CloudConfigTemplate = $Phase1CloudConfigTemplate.Replace("$obj4","$obj5")
        }
        $UpdatedPhase1CloudConfig = $Phase1CloudConfigTemplate
        Set-Content -Path "$OutputDirectory\phase1-$obj1-setup-ssh-and-pull-phase1.5.yml" -Value $UpdatedPhase1CloudConfig

        # Create the New EC2 Instances and Get New Public and Private IP Addresses
        New-EC2Instance -ImageId $CoreOSAMIImageID -SecurityGroupId $VPCSecurityGroup -MinCount 1 -MaxCount 1 -InstanceType $InstanceType `
        -KeyName $AWSKeyNameForSSH -EncodeUserData -UserDataFile "$OutputDirectory\phase1-$obj1-setup-ssh-and-pull-phase1.5.yml" `
        | Select-Object -ExpandProperty ReservationId -OutVariable reservationid

        # Give AWS some time to finish standing up the new EC2 instance...
        Write-Host "Giving AWS and extra 10 seconds to finish standing up EC2 Host $obj1..."
        Sleep 10
        $reservation = New-Object 'collections.generic.list[string]'
        $reservation.add("$reservationid")
        $filter_reservation = New-Object Amazon.EC2.Model.Filter -Property @{Name = "reservation-id"; Values = $reservation}
        $newinstance = (Get-EC2Instance -Filter $filter_reservation).Instances
        $newinstanceid = $newinstance.InstanceId
        $newinstanceid
        $tag = New-Object Amazon.EC2.Model.Tag
        $tag.Key = "Name"
        $tag.Value = "$obj1"
        Sleep 5
        New-EC2Tag -Resource $newinstanceid -Tag $tag
        # Wait for the network on the new EC2 instance to be ready...
        Write-Host "Giving AWS and extra 25 seconds to turn on networking for $obj1..."
        Sleep 25
        $newinstancepublicip = ((Get-EC2Instance).Instances | Where-Object {$_.InstanceId -match "$newinstanceid"}).PublicIpAddress
        $newinstancepublicip
        $newinstanceprivateip = ((Get-EC2Instance).Instances | Where-Object {$_.InstanceId -match "$newinstanceid"}).PrivateIpAddress
        $newinstanceprivateip

        # Generate Client-Server Certificates for Each CoreOS Host
        Generate-Certificate -CertGenWorking $OutputDirectory `
        -BasisTemplate "$BasisTemplate" `
        -CertificateCN "$obj1-client-server-cert" `
        -Organization "$Organization" `
        -OrganizationalUnit "$OrganizationalUnit" `
        -Locality "$Locality" `
        -State "$State" `
        -Country "$Country" `
        -MachineKeySet "FALSE" `
        -SecureEmail "No" `
        -UserProtected "No" `
        -PFXPwdAsSecureString "$PFXPwdAsSecureString" `
        -KeyUsageValue "$KeyUsageValue" `
        -IntendedPurposeValuesPrep "$IntendedPurposeValuesPrep" `
        -RequestViaWebEnrollment "$RequestViaWebEnrollment" `
        -ADCSWebEnrollmentURL "$ADCSWebEnrollmentURL" `
        -ADCSWebAuthType "$ADCSWebAuthType" `
        -ADCSWebAuthUserName "$ADCSWebAuthUserName" `
        -ADCSWebAuthPass "$ADCSWebAuthPass" `
        -UseOpenSSL "$UseOpenSSL" `
        -PathToWin32OpenSSL "$PathToWin32OpenSSL" `
        -StripPrivateKeyOfPassword "$StripPrivateKeyOfPassword" `
        -AddSAN "$AddSAN" `
        -TypesofSANObjectsToAdd "$TypesofSANObjectsToAdd" `
        -DNSSANObjects "$obj1" `
        -IPAddressSANObjects "$newinstanceprivateip"

        # Create New PSObject for the New CoresOS Host with all properties of the New Host and add it to the $ArrayofNewHostPSObjects
        New-Variable -Name "NewHost$obj1" -Value $(
            New-Object PSObject -Property @{
                CoreOSHostName      = $obj1
                ReservationId       = $reservationid
                InstanceID          = $newinstanceid
                PublicIP            = $newinstancepublicip
                PrivateIP           = $newinstanceprivateip
                CertFileOutputs     = $GenerateCertificateFileOutputHashGlobal
                CertContents        = $CertNamevsContentsHashGlobal
            }
        )
        $ArrayofNewHostPSObjects += $(Get-Variable -Name "NewHost$obj1" -ValueOnly)

        # Create Phase 1.5 Cloud Config Files for Each Host
        Set-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "#cloud-config" 
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "write_files:"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$obj1-client-server-key.pem`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
        foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$($GenerateCertificateFileOutputHashGlobal.EndPointUnProtectedPrivateKey)" -Encoding Ascii)) {
            Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        }
        # Alternate to above...
        #foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\NewCertificate_$obj1-client-server-cert_unprotected_private_key_.key" -Encoding Ascii)) {
        #    Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        #}
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$obj1-client-server.pem`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
        foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$($GenerateCertificateFileOutputHashGlobal.EndPointPublicCertFile)" -Encoding Ascii)) {
            Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        }
        # Alternate to above...
        #foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$EndPointPublicCertFile" -Encoding Ascii)) {
        #    Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        #}
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$($GenerateCertificateFileOutputHashGlobal.IntermediateCAPublicCertFile)`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
        foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$($GenerateCertificateFileOutputHashGlobal.IntermediateCAPublicCertFile)" -Encoding Ascii)) {
            Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        }
        # Alternate to above...
        #foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$IntermediateCAPublicCertFile" -Encoding Ascii)) {
        #    Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        #}
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$($GenerateCertificateFileOutputHashGlobal.RootCAPublicCertFile)`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
        foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$($GenerateCertificateFileOutputHashGlobal.RootCAPublicCertFile)" -Encoding Ascii)) {
            Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        }
        # Alternate to above...
        #foreach ($obj2 in $(Get-Content -Path "$OutputDirectory\$RootCAPublicCertFile" -Encoding Ascii)) {
        #    Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
        #}
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "coreos:"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  units:"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    - name: pull-phase2-cloud-config.service"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      command: start"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      content: |"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        [Unit]"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        Description=Pull phase2 cloud config"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value ""
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        [Service]"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        Restart=on-failure"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        RestartSec=60"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        RemainAfterExit=no"
        Add-Content -Path "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        ExecStart=/usr/bin/coreos-cloudinit --from-url=$AWSS3URLRoot/$AWSS3BucketName/$AWSS3BucketFolder/$Phase2CloudConfigTemplateFile"

        # Upload Phase 1.5 Cloud Configs to AWS S3
        Write-S3Object -BucketName $AWSS3BucketName -Key "$AWSS3BucketFolder/phase1.5-$obj1-write-certs-and-pull-phase2.yml" -File "$OutputDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml"

    }

    # After all of the New EC2 Instance have been stood up, they should all be polling AWS S3 for Phase 2 Cloud Config
    # We could take advantage of the etcd2 discovery service to setup the cluster, but have found that this works inconsistently
    # so, we will just manually update Phase 2 Cloud Config with the IP Addresses of all CoreOS Hosts in the cluster.

    # Update Phase2 Cloud Config with new unique ETCD_INITIAL_CLUSTER_TOKEN and ETCD_INITIAL_CLUSTER and Upload Cloud Config to AWS S3 Bucket
    # NOTE: Below we use the [array]$LineToBeReplacedN and foreach structure so that whether the thing you want to replace is a specific string or
    # an entire line, the structure is basically the same.
    $Phase2CloudConfig = Get-Content "$CloudConfigTemplateRoot\$Phase2CloudConfigTemplateFile"
    <#
    [array]$LineToBeReplaced1 = ($Phase2CloudConfig | Select-String -Pattern "https://discovery.etcd.io").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced1) {
        $obj2 = $obj1 -replace "$obj1","        echo `"ETCD_DISCOVERY=$DiscoveryURL`" >> /etc/etcd2-metadata"
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }
    #>
    [array]$LineToBeReplaced3 = ($Phase2CloudConfig | Select-String -SimpleMatch "region").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced3) {
        $obj2 = $obj1 -replace "region=[\w]{1,10}-[\w]{1,10}-[\w]{1,10}","region=$DefaultAWSRegion"
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }

    $ETCDInitialClusterToken = Generate-RandomString -length 15 -NumbersAndLettersOnly "Yes"

    [array]$LineToBeReplaced7 = ($Phase2CloudConfig | Select-String -Pattern "ETCD_INITIAL_CLUSTER_TOKEN=").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced7) {
        $obj2 = $obj1 -replace "ETCD_INITIAL_CLUSTER_TOKEN=[\w\W]{1,32}`"","ETCD_INITIAL_CLUSTER_TOKEN=$ETCDInitialClusterToken`""
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }

    $ETCDInitialClusterPrep1 = $(foreach ($obj1 in $ArrayofNewHostPSObjects) {
        $obj1.CoreOSHostName+"="+"http://"+$obj1.PrivateIP+":2380,"
    }) | Out-String
    $ETCDInitialClusterPrep2 = $ETCDInitialClusterPrep1 -replace "[\s]",""
    # Remove trailing comma in ETCDInitialClusterPrep2 string...
    $position = $ETCDInitialClusterPrep2.LastIndexOf(",")
    $ETCDInitialCluster = $ETCDInitialClusterPrep2.Substring(0, $position)

    [array]$LineToBeReplaced8 = ($Phase2CloudConfig | Select-String -Pattern "ETCD_INITIAL_CLUSTER=").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced8) {
        $obj2 = $obj1 -replace "$obj1","        echo `"ETCD_INITIAL_CLUSTER=$ETCDInitialCluster`" >> /etc/etcd2-metadata"
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }
    # Update references to RootCA...
    [array]$LineToBeReplaced9 = ($Phase2CloudConfig | Select-String -Pattern "RootCA.pem").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced9) {
        # In the below $obj2 definition, we are arbitrarily using Index 0 (i.e. the PSObject for the first New host created), because the 
        # RootCAPublicCertFile is the same for ALL of the new hosts
        $obj2 = $obj1 -replace "RootCA.pem","$($ArrayofNewHostPSObjects[0].CertFileOutputs.RootCAPublicCertFile)"
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }
    # Update references to Intermediate CA...
    [array]$LineToBeReplaced10 = ($Phase2CloudConfig | Select-String -Pattern "IssuingCA.pem").Line | Sort-Object | Get-Unique
    foreach ($obj1 in $LineToBeReplaced10) {
        # In the below $obj2 definition, we are arbitrarily using Index 0 (i.e. the PSObject for the first New host created), because the 
        # IntermediateCAPublicCertFile is the same for ALL of the new hosts
        $obj2 = $obj1 -replace "IssuingCA.pem","$($ArrayofNewHostPSObjects[0].CertFileOutputs.IntermediateCAPublicCertFile)"
        $Phase2CloudConfig = $Phase2CloudConfig.Replace("$obj1","$obj2")
    }
    $UpdatedPhase2CloudConfig = $Phase2CloudConfig
    # Writing $UpdatedPhase2CloudConfig to a file that has the same name as $Phase2CloudConfigTemplateFile but in $OutputDirectory
    Set-Content -Path "$OutputDirectory\$Phase2CloudConfigTemplateFile" -Value $UpdatedPhase2CloudConfig
    Write-S3Object -BucketName $AWSS3BucketName -Key "$AWSS3BucketFolder/$Phase2CloudConfigTemplateFile" -File "$OutputDirectory\$Phase2CloudConfigTemplateFile"

    Write-Host ""
    Write-Host "Phase2 Cloud Config has been posted to AWS S3"
    Write-Host ""
    Write-Host "Create-AWSCoreOSCluster COMPLETE"


}

Create-AWSCoreOSCluster `
-HelperFunctionSourceDirectory "V:\powershell" `
-OutputDirectory "P:\CoreOS\Other_Configs\dynamic-configs\test1" `
-AWSIAMProfile "pdadminprofile" `
-DefaultAWSRegion "us-east-1" `
-CoreOSChannel "Alpha" `
-AWSAMIVirtType "HVM" `
-InstanceType "t2.micro" `
-HostNames "aws-coreos1, aws-coreos2, aws-coreos3" `
-VPCSecurityGroup "sg-ce5f61b5" `
-AWSKeyNameForSSH "aws-coreos-primary-ssh-key" `
-CloudConfigTemplateRoot "P:\CoreOS\Other_Configs" `
-Phase1CloudConfigTemplateFile "phase1-aws-coreos-template.yml" `
-Phase2CloudConfigTemplateFile "phase2-setup-env-config-etcd2-and-fleet-and-pull-master.yml" `
-MASTERCloudConfigTemplateFile "cloud-config-for-AWS-cluster-MASTER.yml" `
-AWSS3URLRoot "https://s3.amazonaws.com" `
-AWSS3BucketName "coreoscloudconfigs" `
-AWSS3BucketFolder "aws-coreos-test-cluster" `
-BasisTemplate "CertTempl171" `
-Organization "Fictional Company Inc" `
-OrganizationalUnit "DevOps" `
-Locality "Portland" `
-State "Oregon" `
-Country "US" `
-PFXPwdAsSecureString "Unsecure321!" `
-RequestViaWebEnrollment "Yes" `
-ADCSWebEnrollmentURL "https://pki.zero.lab/certsrv" `
-ADCSWebAuthType "Windows" `
-ADCSWebAuthUserName "zeroadmin" `
-ADCSWebAuthPass "Insecure321!" `
-PathToWin32OpenSSL "C:\openssl-1.0.2h-i386-win32"

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOrsx9zhwYMW5/Fkf1dGOjrFM
# 1/ygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQLua27Pkwf
# hEJtUjalg4vBlshN1jANBgkqhkiG9w0BAQEFAASCAQCGMO/YbleRaG+sYMGR3Q8B
# i0V3PmWi+XO3P/IM9wJ5iuoAtp2wHWU4LBe/SvEW5a3Yv88kDzdm9es79UIf8MGM
# qrQAbJsdPT9pAzlrE8A0+W/Tf5lvrA5ja/Tdc8H4NYKhaC9dn4tL+6oLkeEWYWc+
# SLyn792g3rivzVt3sGRHrcHI6Feq4YwHQ+I/+xScBaxDayldwCCfYFdBgYdMFkOg
# 6Ac4/mTa3jz/8NIACNueoMyDfdtzhC+lO47NA7kFqkzl/C0tM6pcEoczL/SDMQWU
# 3P2ANXv1iEHo3gPzfmwadknf+BHTFgAozvjl8XSCMSYAdV/0zacIC/cgw08SvsoO
# SIG # End signature block
