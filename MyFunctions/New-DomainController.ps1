function New-DomainController {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[a-zA-Z1-9]{4,10}$")]
        [string]$DesiredHostName,

        [Parameter(Mandatory=$True)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomainName,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$NewDomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [string]$ServerIP,

        [Parameter(Mandatory=$True)]
        [pscredential]$PSRemotingLocalAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$RemoteDSCDirectory,

        [Parameter(Mandatory=$False)]
        [string]$DSCResultsDownloadDirectory
    )

    #region >> Prep

    if (!$RemoteDSCDirectory) {
        $RemoteDSCDirectory = "C:\DSCConfigs"
    }
    if (!$DSCResultsDownloadDirectory) {
        $DSCResultsDownloadDirectory = "$HOME\Downloads\DSCConfigResultsFor$DesiredHostName"
    }
    if ($LocalAdministratorAccountCredentials.UserName -ne "Administrator") {
        Write-Error "The -LocalAdministratorAccount PSCredential must have a UserName property equal to 'Administrator'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $NewDomainShortName = $($NewDomainName -split "\.")[0]
    if ($NewDomainAdminCredentials.UserName -notmatch "$NewDomainShortName\\[\w]+$") {
        Write-Error "The User Account provided to the -NewDomainAdminCredentials parameter must be in format: $NewDomainShortName\\<UserName>`nHalting!"
        $global:FunctionResult = "1"
        return
    }
    if ($NewDomainAdminCredentials.UserName -match "$NewDomainShortName\\Administrator$") {
        Write-Error "The User Account provided to the -NewDomainAdminCredentials cannot be: $NewDomainShortName\\Administrator`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    $CharacterIndexToSplitOn = [Math]::Round($(0..$($NewDomainAdminCredentials.UserName.Length) | Measure-Object -Average).Average)
    $NewDomainAdminFirstName = $NewDomainAdminCredentials.UserName.SubString(0,$CharacterIndexToSplitOn)
    $NewDomainAdminLastName = $NewDomainAdminCredentials.UserName.SubString($CharacterIndexToSplitOn,$($($NewDomainAdminCredentials.UserName.Length)-$CharacterIndexToSplitOn))

    $NewBackupDomainAdminFirstName = $($NewDomainAdminCredentials.UserName -split "\\")[-1]
    $NewBackupDomainAdminLastName =  "backup"

    # Get the needed DSC Resources in preparation for copying them to the Remote Host
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $NeededDSCResources = @(
        "xPSDesiredStateConfiguration"
        "xActiveDirectory"
    )
    [System.Collections.ArrayList]$FailedDSCResourceInstall = @()
    foreach ($DSCResource in $NeededDSCResources) {
        try {
            $null = Install-Module $DSCResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedDSCResourceInstall.Add($DSCResource)
            continue
        }
    }
    if ($FailedDSCResourceInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedDSCResourceInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }
    $DSCModulesToTransfer = foreach ($DSCResource in $NeededDSCResources) {
        $Module = Get-Module -ListAvailable $DSCResource
        "$($($Module.ModuleBase -split $DSCResource)[0])\$DSCResource"
    }

    $PSDSCVersion = $(Get-Module -ListAvailable -Name PSDesiredStateConfiguration).Version[-1].ToString()
    $xActiveDirectoryVersion = $(Get-Module -ListAvailable -Name xActiveDirectory).Version[-1].ToString()
    $xPSDSCVersion = $(Get-Module -ListAvailable -Name xPSDesiredStateConfiguration).Version[-1].ToString()

    # Make sure WinRM in Enabled and Running on $env:ComputerName
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

        try {
            $null = Enable-PSRemoting -Force
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
    if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
        $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    }

    # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
    $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

    $IPsToAddToWSMANTrustedHosts = @($ServerIP)
    foreach ($IPAddr in $IPsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $IPAddr) {
            $null = $CurrentTrustedHostsAsArray.Add($IPAddr)
        }
    }
    $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

    #endregion >> Prep


    #region >> Helper Functions

    $NewSelfSignedCertUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/ThirdPartyRefactors/Functions/New-SelfSignedCertificateEx.ps1"
    Invoke-Expression $([System.Net.WebClient]::new().DownloadString($NewSelfSignedCertUrl))

    function Get-DSCEncryptionCert {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [string]$MachineName,
    
            [Parameter(Mandatory=$True)]
            [string]$ExportDirectory
        )
    
        if (!$(Test-Path $ExportDirectory)) {
            Write-Error "The path '$ExportDirectory' was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        $CertificateFriendlyName = "DSC Credential Encryption"
        $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
            $_.FriendlyName -eq $CertificateFriendlyName
        } | Select-Object -First 1
    
        if (!$Cert) {
            $NewSelfSignedCertExSplatParams = @{
                Subject             = "CN=$Machinename"
                EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
                KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
                SAN                 = $MachineName
                FriendlyName        = $CertificateFriendlyName
                Exportable          = $True
                StoreName           = 'My'
                StoreLocation       = 'LocalMachine'
                KeyLength           = 2048
                ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
                AlgorithmName       = "RSA"
                SignatureAlgorithm  = "SHA256"
            }
    
            New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams
    
            # There is a slight delay before new cert shows up in Cert:
            # So wait for it to show.
            while (!$Cert) {
                $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
            }
        }
    
        $null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\DSCEncryption.cer"
    
        $CertInfo = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $CertInfo.Import("$ExportDirectory\DSCEncryption.cer")
    
        [pscustomobject]@{
            CertFile        = Get-Item "$ExportDirectory\DSCEncryption.cer"
            CertInfo        = $CertInfo
        }
    }

    #endregion >> Helper Functions

    
    #region >> Rename Computer

    $RenameComputerSB = {
        # Make sure the Local 'Administrator' account has its password set
        $UserAccount = Get-LocalUser -Name "Administrator"
        $UserAccount | Set-LocalUser -Password $args[0]
        Rename-Computer -NewName $args[1] -LocalCredential $args[2] -Force -Restart -ErrorAction SilentlyContinue
    }
    $InvCmdRenameComputerSplatParams = @{
        ComputerName    = $ServerIP
        Credential      = $PSRemotingLocalAdminCredentials
        ScriptBlock     = $RenameComputerSB
        ArgumentList    = $LocalAdministratorAccountCredentials.Password,$DesiredHostName,$PSRemotingLocalAdminCredentials
        ErrorAction     = "SilentlyContinue"
    }
    try {
        Invoke-Command @InvCmdRenameComputerSplatParams
    }
    catch {
        Write-Error "Problem with renaming the $ServerIP to $DesiredHostName! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Sleeping for 5 minutes to give the Server a chance to restart after name change..."
    Start-Sleep -Seconds 300

    #endregion >> Rename Computer


    #region >> Wait For HostName Change
    
    # Waiting for maximum of 15 minutes for the Server to accept new PSSessions Post Name Change Reboot...
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $ServerIP -Credential $PSRemotingLocalAdminCredentials -Name "To$DesiredHostName" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'To$DesiredHostName' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'To$DesiredHostName' using Local Admin account '$($PSRemotingLocalAdminCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }

    #endregion >> Wait for HostName Change

    
    #region >> Prep DSC On the RemoteHost

    try {
        # Copy the DSC PowerShell Modules to the Remote Host
        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $DSCModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = Get-PSSession -Name "To$DesiredHostName"
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        $FunctionsForRemoteUse = @(
            ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
            ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        )

        $DSCPrepSB = {
            # Load the functions we packed up:
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

            if (!$(Test-Path $using:RemoteDSCDirectory)) {
                $null = New-Item -ItemType Directory -Path $using:RemoteDSCDirectory -Force
            }

            if ($($env:PSModulePath -split ";") -notcontains $using:ProgramFilesPSModulePath) {
                $env:PSModulePath = $using:ProgramFilesPSModulePath + ";" + $env:PSModulePath
            }

            # Setup WinRM
            try {
                $null = Enable-PSRemoting -Force -ErrorAction Stop
            }
            catch {
                $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'
            
                try {
                    $null = Enable-PSRemoting -Force
                }
                catch {
                    Write-Error $_
                    Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            
            # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
            if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
                $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
            }

            $DSCEncryptionCACertInfo = Get-DSCEncryptionCert -MachineName $using:DesiredHostName -ExportDirectory $using:RemoteDSCDirectory

            #### Configure the Local Configuration Manager (LCM) ####
            if (Test-Path "$using:RemoteDSCDirectory\$using:DesiredHostName.meta.mof") {
                Remove-Item "$using:RemoteDSCDirectory\$using:DesiredHostName.meta.mof" -Force
            }
            Configuration LCMConfig {
                Node "localhost" {
                    LocalConfigurationManager {
                        ConfigurationMode = "ApplyAndAutoCorrect"
                        RefreshFrequencyMins = 30
                        ConfigurationModeFrequencyMins = 15
                        RefreshMode = "PUSH"
                        RebootNodeIfNeeded = $True
                        ActionAfterReboot = "ContinueConfiguration"
                        CertificateId = $DSCEncryptionCACertInfo.CertInfo.Thumbprint
                    }
                }
            }
            # Create the .meta.mof file
            $LCMMetaMOFFileItem = LCMConfig -OutputPath $using:RemoteDSCDirectory
            if (!$LCMMetaMOFFileItem) {
                Write-Error "Problem creating the .meta.mof file for $using:DesiredHostName!"
                return
            }
            # Make sure the .mof file is directly under $usingRemoteDSCDirectory alongside the encryption Cert
            if ($LCMMetaMOFFileItem.FullName -ne "$using:RemoteDSCDirectory\$($LCMMetaMOFFileItem.Name)") {
                Copy-Item -Path $LCMMetaMOFFileItem.FullName -Destination "$using:RemoteDSCDirectory\$($LCMMetaMOFFileItem.Name)" -Force
            }

            # Apply the .meta.mof (i.e. LCM Settings)
            Write-Host "Applying LCM Config..."
            $null = Set-DscLocalConfigurationManager -Path $using:RemoteDSCDirectory -Force

            # Output the DSC Encryption Certificate Info
            $DSCEncryptionCACertInfo
        }

        $DSCEncryptionCACertInfo = Invoke-Command -Session $(Get-PSSession -Name "To$DesiredHostName") -ScriptBlock $DSCPrepSB

        if (!$(Test-Path $DSCResultsDownloadDirectory)) {
            $null = New-Item -ItemType Directory -Path $DSCResultsDownloadDirectory
        }
        $CopyItemSplatParams = @{
            Path            = "$RemoteDSCDirectory\DSCEncryption.cer"
            Recurse         = $True
            Destination     = "$DSCResultsDownloadDirectory\DSCEncryption.cer"
            FromSession       = Get-PSSession -Name "To$DesiredHostName"
            Force           = $True   
        }
        Copy-Item @CopyItemSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Prep DSC On the RemoteHost


    #region >> Apply DomainController DSC Config

    # The below commented config info is loaded in the Invoke-Command ScriptBlock, but is also commented out here
    # so that it's easier to review $StandaloneRootCAConfigAsStringPrep
    <#
    $ConfigData = @{
        AllNodes = @(
            @{

                NodeName = '*'
                PsDscAllowDomainUser = $true
                PsDscAllowPlainTextPassword = $true
            }
            @{
                NodeName = $DesiredHostName
                Purpose = 'Domain Controller'
                WindowsFeatures = 'AD-Domain-Services','RSAT-AD-Tools'
                RetryCount = 20
                RetryIntervalSec = 30
            }
        )

        NonNodeData = @{
            DomainName = $NewDomainName
            ADGroups = 'Information Systems'
            OrganizationalUnits = 'Information Systems','Executive'
            AdUsers = @(
                @{
                    FirstName = $NewBackupDomainAdminFirstName
                    LastName = $NewBackupDomainAdminLastName
                    Department = 'Information Systems'
                    Title = 'System Administrator'
                }
            )
        }
    }
    #>

    $NewDomainControllerConfigAsStringPrep = @'
configuration NewDomainController {
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$NewDomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdministratorAccountCredentials
    )

'@ + @"

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion $PSDSCVersion
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration' -ModuleVersion $xPSDSCVersion
    Import-DscResource -ModuleName 'xActiveDirectory' -ModuleVersion $xActiveDirectoryVersion

"@ + @'

    $NewDomainAdminUser = $($NewDomainAdminCredentials.UserName -split "\\")[-1]
    $NewDomainAdminUserBackup = $NewDomainAdminUser + "backup"
            
    Node $AllNodes.where({ $_.Purpose -eq 'Domain Controller' }).NodeName
    {
        @($ConfigurationData.NonNodeData.ADGroups).foreach({
            xADGroup $_
            {
                Ensure = 'Present'
                GroupName = $_
                DependsOn = '[xADUser]FirstUser'
            }
        })

        @($ConfigurationData.NonNodeData.OrganizationalUnits).foreach({
            xADOrganizationalUnit $_
            {
                Ensure = 'Present'
                Name = ($_ -replace '-')
                Path = ('DC={0},DC={1}' -f ($ConfigurationData.NonNodeData.DomainName -split '\.')[0], ($ConfigurationData.NonNodeData.DomainName -split '\.')[1])
                DependsOn = '[xADUser]FirstUser'
            }
        })

        @($ConfigurationData.NonNodeData.ADUsers).foreach({
            xADUser "$($_.FirstName) $($_.LastName)"
            {
                Ensure = 'Present'
                DomainName = $ConfigurationData.NonNodeData.DomainName
                GivenName = $_.FirstName
                SurName = $_.LastName
                UserName = ('{0}{1}' -f $_.FirstName, $_.LastName)
                Department = $_.Department
                Path = ("OU={0},DC={1},DC={2}" -f $_.Department, ($ConfigurationData.NonNodeData.DomainName -split '\.')[0], ($ConfigurationData.NonNodeData.DomainName -split '\.')[1])
                JobTitle = $_.Title
                Password = $NewDomainAdminCredentials
                DependsOn = "[xADOrganizationalUnit]$($_.Department)"
            }
        })

        ($Node.WindowsFeatures).foreach({
            WindowsFeature $_
            {
                Ensure = 'Present'
                Name = $_
            }
        })        
        
        xADDomain ADDomain          
        {             
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainAdministratorCredential = $LocalAdministratorAccountCredentials
            SafemodeAdministratorPassword = $LocalAdministratorAccountCredentials
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainUserCredential = $LocalAdministratorAccountCredentials
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[xADDomain]ADDomain"
        }

        xADUser FirstUser
        {
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainAdministratorCredential = $LocalAdministratorAccountCredentials
            UserName = $NewDomainAdminUser
            Password = $NewDomainAdminCredentials
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADGroup DomainAdmins {
            GroupName = 'Domain Admins'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }
        
        xADGroup EnterpriseAdmins {
            GroupName = 'Enterprise Admins'
            GroupScope = 'Universal'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }

        xADGroup GroupPolicyOwners {
            GroupName = 'Group Policy Creator Owners'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }

        xADGroup SchemaAdmins {
            GroupName = 'Schema Admins'
            GroupScope = 'Universal'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }
    }         
}
'@

    try {
        $NewDomainControllerConfigAsString = [scriptblock]::Create($NewDomainControllerConfigAsStringPrep).ToString()
    }
    catch {
        Write-Error $_
        Write-Error "There is a problem with the NewDomainController DSC Configuration Function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $NewDomainControllerSB = {
        #### Apply the DSC Configuration ####
        # Load the NewDomainController DSC Configuration function
        $using:NewDomainControllerConfigAsString | Invoke-Expression

        $NewDomainControllerConfigData = @{
            AllNodes = @(
                @{
                    NodeName = '*'
                    PsDscAllowDomainUser = $true
                    #PsDscAllowPlainTextPassword = $true
                    CertificateFile = $using:DSCEncryptionCACertInfo.CertFile.FullName
                    Thumbprint = $using:DSCEncryptionCACertInfo.CertInfo.Thumbprint
                }
                @{
                    NodeName = $using:DesiredHostName
                    Purpose = 'Domain Controller'
                    WindowsFeatures = 'AD-Domain-Services','RSAT-AD-Tools'
                    RetryCount = 20
                    RetryIntervalSec = 30
                }
            )
    
            NonNodeData = @{
                DomainName = $using:NewDomainName
                ADGroups = 'Information Systems'
                OrganizationalUnits = 'Information Systems','Executive'
                AdUsers = @(
                    @{
                        FirstName = $using:NewBackupDomainAdminFirstName
                        LastName = $using:NewBackupDomainAdminLastName
                        Department = 'Information Systems'
                        Title = 'System Administrator'
                    }
                )
            }
        }

        # IMPORTANT NOTE: The resulting .mof file (representing the DSC configuration), will be in the
        # directory "$using:RemoteDSCDir\STANDALONE_ROOTCA"
        if (Test-Path "$using:RemoteDSCDirectory\$($using:DesiredHostName).mof") {
            Remove-Item "$using:RemoteDSCDirectory\$($using:DesiredHostName).mof" -Force
        }
        $NewDomainControllerConfigSplatParams = @{
            NewDomainAdminCredentials               = $using:NewDomainAdminCredentials
            LocalAdministratorAccountCredentials    = $using:LocalAdministratorAccountCredentials
            OutputPath                              = $using:RemoteDSCDirectory
            ConfigurationData                       = $NewDomainControllerConfigData
        }
        $MOFFileItem = NewDomainController @NewDomainControllerConfigSplatParams
        if (!$MOFFileItem) {
            Write-Error "Problem creating the .mof file for $using:DesiredHostName!"
            return
        }

        # Make sure the .mof file is directly under $usingRemoteDSCDirectory alongside the encryption Cert
        if ($MOFFileItem.FullName -ne "$using:RemoteDSCDirectory\$($MOFFileItem.Name)") {
            Copy-Item -Path $MOFFileItem.FullName -Destination "$using:RemoteDSCDirectory\$($MOFFileItem.Name)" -Force
        }

        # Apply the .mof (i.e. setup the New Domain Controller)
        Write-Host "Applying NewDomainController Config..."
        Start-DscConfiguration -Path $using:RemoteDSCDirectory -Force -Wait
    }

    Invoke-Command -Session $(Get-PSSession -Name "To$DesiredHostName") -ScriptBlock $NewDomainControllerSB

    Write-Host "Sleeping for 5 minutes to give the new Domain Controller a chance to finish implementing config..."
    Start-Sleep -Seconds 300

    Write-Host "Done" -ForegroundColor Green

    #endregion >> Apply DomainController DSC Config
}


# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrv/MnAz6vaY8fO3uqWShmRl3
# qi+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKlatfzoC1BljMgy
# LvRGWrjvWjraMA0GCSqGSIb3DQEBAQUABIIBAF5ghOHHO1GnpGyvAm5MAhGAHJxL
# 51gC6qUu3d86sAe7gW74ZaEHuFjGosvNr2zPD8n2KOhEXikgElDg56aovu3KcKBU
# p2x7VUb5idKT8VNygcKawFXTv9QgMD3m6gU720TwqZ+SoyvNtpiubqtwR8rNBniy
# JKa/+7vxM9DKNFFyWHjbQY+Vi4s8KmzhAvlYCDXWHShsf/c5Bd60w9jux2HFv4wc
# E7BS54vOiscqMa9OJZ0in4mR2YZA9OSVe9alJZUIOnX5jxrWbMAviBJdJOWj5Lxk
# fmg2HaMkXvxMYxiAdljDvb9pDIkdkoJixvx6x2KpEccqB8YR6tF3ceRH9hQ=
# SIG # End signature block
