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
            if ($CreateNewAWSIAMProfileSwtich -eq "Yes" -or $CreateNewAWSIAMProfileSwtich -eq "y") {
                $AWSAccessKey = Read-Host -Prompt "Please enter the AccessKey for AWS IAM user $AWSProfile"
                $AWSSecretKey = Read-Host -Prompt "Please enter the SecretKey for AWS IAM user $AWSProfile"
                Set-AWSCredentials -AccessKey $AWSAccessKey -SecretKey $AWSSecretKey -StoreAs $AWSProfile
            }
            if ($CreateNewAWSIAMProfileSwtich -eq "No" -or $CreateNewAWSIAMProfileSwtich -eq "n") {
                $AWSProfile = Read-Host -Prompt "Please enter the AWS IAM Profile you would like to use in this PowerShell session."
                if ($ValidAWSIAMProfiles -notcontains $AWSProfile) {
                    Write-Host "$AWSIAMProfile is NOT a valid AWS IAM Profile available to PowerShell under the current Windows user account. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
    
    # Validate $AWSRegion parameter...
    $ValidAWSRegions = @("eu-central-1","ap-northeast-1","ap-northeast-2","ap-south-1","sa-east-1","ap-southeast-2",`
    "ap-southeast-1","us-east-1","us-east-2","us-west-2","us-west-1","eu-west-1")
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
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Set the AWS IAM Profile and Default AWS Region
    $global:SetAWSCredentials = "Set-AWSCredentials -ProfileName $AWSProfile"
    $global:StoredAWSRegion = $AWSRegion

    Write-Host "Use the following command to complete setting the AWS Environment in your current scope:
    Invoke-Expression `$global:SetAWSCredentials"

    $global:FunctionResult = "0"
}