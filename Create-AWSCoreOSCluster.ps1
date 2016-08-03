Function Create-AWSCoreOSCluster {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $HelperFunctionSourceDirectory = "V:\powershell",

        [Parameter(Mandatory=$False)]
        $AWSIAMProfile = "pdadminprofile",

        [Parameter(Mandatory=$False)]
        $DefaultAWSRegion = "us-east-1",

        [Parameter(Mandatory=$False)]
        $NumberOfHostsInCluster = "3",

        [Parameter(Mandatory=$False)]
        $HostNames = "aws-coreos1, aws-coreos2, aws-coreos3",

        [Parameter(Mandatory=$False)]
        $CoreOSAMIImageID = "ami-0c2aa81b",

        [Parameter(Mandatory=$False)]
        $VPCSecurityGroup = "sg-ce5f61b5",

        [Parameter(Mandatory=$False)]
        $InstanceType = "t2.micro",

        [Parameter(Mandatory=$False)]
        $KeyName = "aws-coreos-primary-ssh-key",

        [Parameter(Mandatory=$False)]
        $CloudConfigDirectory = "P:\CoreOS\Other_Configs\dynamic-configs\test1",

        [Parameter(Mandatory=$False)]
        $RootCAPubCert = "ZeroDC01_Public_Cert.cer",

        [Parameter(Mandatory=$False)]
        $SubCAPubCert = "ZeroSCA_Public_Cert.cer",

        [Parameter(Mandatory=$False)]
        $CloudConfigTemplateRoot = "P:\CoreOS\Other_Configs",

        [Parameter(Mandatory=$False)]
        $Phase1CloudConfigTemplateFile = "phase1-aws-coreos-template.yml",

        [Parameter(Mandatory=$False)]
        $Phase2CloudConfigFile = "phase2-setup-env-config-etcd2-and-fleet-and-pull-master.yml",

        [Parameter(Mandatory=$False)]
        $AWSS3BucketCoreOSURLRoot = "https://s3.amazonaws.com/coreoscloudconfigs",

        [Parameter(Mandatory=$False)]
        $AWSS3BucketName = "coreoscloudconfigs"

    )

##### BEGIN Helper Functions #####

. "$HelperFunctionSourceDirectory\Generate-Certificate.ps1"


function Set-AWSEnvHelper
{
    Import-Module AWSPowerShell
    if ((Get-AWSCredentials -ListProfiles | Select-String -Pattern pdadminprofile).Matches.Success) {
        Write-Host "The AWS Credential Profile $AWSIAMProfile is available...Loading profile for this session..."
        Set-AWSCredentials -ProfileName $AWSIAMProfile
        Get-AWSCredentials -ListProfiles
        $global:StoredAWSRegion = $DefaultAWSRegion
    }
    else {
        Write-Host "The AWS Credential Profile $AWSIAMProfile has not been created under this Windows Account on this machine."
        $AWSpdadminAccessKey = Read-Host -Prompt "Please enter the AccessKey for AWS IAM user $($AWSIAMProfile -replace 'profile','')"
        $AWSpdadminSecretKey = Read-Host -Prompt "Please enter the SecretKey for AWS IAM user $($AWSIAMProfile -replace 'profile','')"
        Set-AWSCredentials -AccessKey $AWSpdadminAccessKey -SecretKey $AWSpdadminSecretKey -StoreAs $AWSIAMProfile
        Set-AWSCredentials -ProfileName $AWSIAMProfile
        Get-AWSCredentials -ListProfiles
        $global:StoredAWSRegion = $DefaultAWSRegion
    } 
}

##### END Helper Functions #####

##### BEGIN Variable Transforms #####

$HostNamesArray = $HostNames.Split(",").Trim()

##### End Variable Transforms #####

# Set AWS Profile
Set-AWSEnvHelper

# Generate new discovery URL for new hosts to check-into
$DiscoveryURL = (Invoke-WebRequest https://discovery.etcd.io/new?size=$($HostNamesArray.Count)).tostring() -split "[`r`n]"

# Update Phase2 Cloud Config with new $DiscoveryUrl and Upload to AWS S3 Bucket
$Phase2CloudConfig = Get-Content "$CloudConfigTemplateRoot\$Phase2CloudConfigFile"
$LineToBeReplaced = $Phase2CloudConfig | Select-String -Pattern "https://discovery.etcd.io"
$UpdatedPhase2CloudConfig = $Phase2CloudConfig -replace "$LineToBeReplaced","        echo `"ETCD_DISCOVERY=$DiscoveryURL`" >> /etc/etcd2-metadata"
Set-Content -Path "$CloudConfigDirectory\$Phase2CloudConfigFile" -Value $UpdatedPhase2CloudConfig
Write-S3Object -BucketName coreoscloudconfigs -Key "aws-coreos-test-cluster/$Phase2CloudConfigFile" -File "$CloudConfigDirectory\$Phase2CloudConfigFile"

# Dynamically create Phase 1 Cloud Configs for Each Host in New Cluster Using Template File
# Then, create the new EC2 Instances and Get New Public and Private IP Addresses
# Then, generate client-server certificates for the unique coreos host
foreach ($obj1 in $HostNamesArray) {
    # Create Phase 1 Cloud Configs for Each Host
    $Phase1CloudConfigTemplate = Get-Content "$CloudConfigTemplateRoot\$Phase1CloudConfigTemplateFile"
    $LineToBeReplaced1 = $Phase1CloudConfigTemplate | Select-String -Pattern "hostname:"
    $LineToBeReplaced2 = $Phase1CloudConfigTemplate | Select-String -Pattern "ExecStart"
    $UpdatedPhase1CloudConfig = ($Phase1CloudConfigTemplate -replace "$LineToBeReplaced1","hostname: `"$obj1`"") `
    -replace "$LineToBeReplaced2","        ExecStart=/usr/bin/coreos-cloudinit --from-url=$AWSS3BucketCoreOSURLRoot/aws-coreos-test-cluster/phase1.5-$obj1-write-certs-and-pull-phase2.yml"
    Set-Content -Path "$CloudConfigDirectory\phase1-$obj1-setup-ssh-and-pull-phase1.5.yml" -Value $UpdatedPhase1CloudConfig

    # Create the New EC2 Instances and Get New Public and Private IP Addresses
    New-EC2Instance -ImageId $CoreOSAMIImageID -SecurityGroupId $VPCSecurityGroup -MinCount 1 -MaxCount 1 -InstanceType $InstanceType -KeyName $KeyName -EncodeUserData -UserDataFile "$CloudConfigDirectory\phase1-$obj1-setup-ssh-and-pull-phase1.5.yml" | Select-Object -ExpandProperty ReservationId -OutVariable reservationid
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
    Sleep 25
    $newinstancepublicip = ((Get-EC2Instance).Instances | Where-Object {$_.InstanceId -match "$newinstanceid"}).PublicIpAddress
    $newinstancepublicip
    $newinstanceprivateip = ((Get-EC2Instance).Instances | Where-Object {$_.InstanceId -match "$newinstanceid"}).PrivateIpAddress
    $newinstanceprivateip

    # Generate Client-Server Certificates for Each CoreOS Host
    Generate-Certificate -CertGenWorking $CloudConfigDirectory `
    -BasisTemplate "CertTempl171" `
    -CertificateCN "$obj1-client-server-cert" `
    -Organization "DiMaggio Inc" `
    -OrganizationalUnit "Development" `
    -Locality "Philadelphia" `
    -State "PA" `
    -Country "US" `
    -MachineKeySet "FALSE" `
    -SecureEmail "No" `
    -UserProtected "No" `
    -PFXPwdAsSecureString "Unsecure321!" `
    -KeyUsageValue "0xa0" `
    -IntendedPurposeValuesPrep "Client Authentication, Server Authentication" `
    -RequestViaWebEnrollment "Yes" `
    -ADCSWebEnrollmentURL "https://pki.zero.lab/certsrv" `
    -ADCSWebAuthType "Windows" `
    -ADCSWebAuthUserName "zeroadmin" `
    -ADCSWebAuthPass "Insecure321!" `
    -UseOpenSSL "Yes" `
    -PathToWin32OpenSSL "C:\openssl-1.0.2h-i386-win32" `
    -StripPrivateKeyOfPassword "Yes" `
    -AddSAN "Yes" `
    -TypesofSANObjectsToAdd "DNS, IP Address" `
    -DNSSANObjects $obj1 `
    -IPAddressSANObjects $newinstanceprivateip

    # Create Phase 1.5 Cloud Config Files for Each Host
    Set-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "#cloud-config" 
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "write_files:"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$obj1-client-server-key.pem`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
    foreach ($obj2 in $(Get-Content -Path "$CloudConfigDirectory\NewCertificate_$obj1-client-server-cert_unprotected_private_key_.key" -Encoding Ascii)) {
        Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
    }
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/$obj1-client-server.pem`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
    foreach ($obj2 in $(Get-Content -Path "$CloudConfigDirectory\$obj1-client-server-cert_Public_Cert.cer" -Encoding Ascii)) {
        Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
    }
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/ZeroSCA.zero.lab_ZeroSCA_base64.pem`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
    foreach ($obj2 in $(Get-Content -Path "$CloudConfigDirectory\$SubCAPubCert" -Encoding Ascii)) {
        Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
    }
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  - path: `"/home/core/ZeroDC01.zero.lab_ZERODC01_base64.pem`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    permissions: `"0644`""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    owner: root"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    content: |"
    foreach ($obj2 in $(Get-Content -Path "$CloudConfigDirectory\$RootCAPubCert" -Encoding Ascii)) {
        Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      $obj2"
    }
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "coreos:"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "  units:"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "    - name: pull-phase2-cloud-config.service"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      command: start"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "      content: |"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        [Unit]"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        Description=Pull phase2 cloud config"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value ""
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        [Service]"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        Type=oneshot"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        RemainAfterExit=no"
    Add-Content -Path "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml" -Value "        ExecStart=/usr/bin/coreos-cloudinit --from-url=$AWSS3BucketCoreOSURLRoot/aws-coreos-test-cluster/phase2-setup-env-config-etcd2-and-fleet-and-pull-master.yml"

    # Upload Phase 1.5 Cloud Configs to AWS S3
    Write-S3Object -BucketName $AWSS3BucketName -Key "aws-coreos-test-cluster/phase1.5-$obj1-write-certs-and-pull-phase2.yml" -File "$CloudConfigDirectory\phase1.5-$obj1-write-certs-and-pull-phase2.yml"

}

}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJl3u76lQQlISRv5Kqccu/6My
# TnCgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRCKY6Alyg1
# VUTaGjwgnPVxjF8Y1TANBgkqhkiG9w0BAQEFAASCAQAyCIdsq9Mr0Iwg2072jZ6p
# S12yZegfIAh/oCwQkjsI4N1wc1N4njVwkz2Ur1N6YYxMcxNvcPhctLjF1O90ASm+
# 1GwN83w7oPM1MAS86y3p77aW95vGN1F9r70KyfN2XwRDcvMqa+ZRidSlhj0iPlC0
# vwsyZnOOJSeagb2zkyKzqVvNdYHqUwbfbWl+2me7q5xvrk2aLeCyTV+QsNxSDXYi
# etzs8pwTebq6HQwqIVqU80bGnYB9I6Sai+9j/s7sdfVyyVJweaHblAubi8MjtXHa
# /7zOy7GPbGK6fMt0Q/LHbMYj/mrWFJwVeQxkO5naRX8susdjtla6DXfXrfVm0Jb6
# SIG # End signature block
