# NOTE: For additional guidance, see:
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831348(v=ws.11)
function New-SubordinateCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$RootCAIPOrFQDN,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$SubCAIPOrFQDN,

        [Parameter(Mandatory=$False)]
        [ValidateSet("EnterpriseSubordinateCA")]
        [string]$CAType,

        [Parameter(Mandatory=$False)]
        [string]$NewComputerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$NewWebServerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$FileOutputDirectory,

        [Parameter(Mandatory=$False)]
        <#
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        #>
        [ValidateSet("Microsoft Software Key Storage Provider")]
        [string]$CryptoProvider,

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        [int]$KeyLength,

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        [string]$HashAlgorithm,

        # For now, stick to just using RSA
        [Parameter(Mandatory=$False)]
        #[ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [ValidateSet("RSA")]
        [string]$KeyAlgorithmValue,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
        [string]$CDPUrl,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
        [string]$AIAUrl
    )

    #region >> Helper Functions

    function NewUniqueString {
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

    function TestIsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function ResolveHost {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(TestIsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                $ResolutionInfo.AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
            }
        }
        if (TestIsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        # At this point, we have $RemoteHostArrayOfIPAddresses...
        [System.Collections.ArrayList]$RemoteHostFQDNs = @()
        foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
            try {
                $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
                continue
            }
            if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                $null = $RemoteHostFQDNs.Add($FQDNPrep)
            }
        }
    
        if ($RemoteHostFQDNs.Count -eq 0) {
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
    
        [System.Collections.ArrayList]$HostNameList = @()
        [System.Collections.ArrayList]$DomainList = @()
        foreach ($fqdn in $RemoteHostFQDNs) {
            $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
            if ($PeriodCheck) {
                $HostName = $($fqdn -split "\.")[0]
                $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
            }
            else {
                $HostName = $fqdn
                $Domain = "Unknown"
            }
    
            $null = $HostNameList.Add($HostName)
            $null = $DomainList.Add($Domain)
        }
    
        if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
            [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
            # Test to see if we can reach the IP Addresses
            foreach ($ip in $RemoteHostArrayOfIPAddresses) {
                if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                    $null = $SuccessfullyPingedIPs.Add($ip)
                }
            }
    
            if ($SuccessfullyPingedIPs.Count -eq 0) {
                Write-Error "Unable to resolve $HostNameOrIP! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
        if ($FQDNPrep -match ',') {
            $FQDN = $($FQDNPrep -split ',')[0]
        }
        else {
            $FQDN = $FQDNPrep
        }
    
        $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
        if ($DomainPrep -match ',') {
            $Domain = $($DomainPrep -split ',')[0]
        }
        else {
            $Domain = $DomainPrep
        }
    
        [pscustomobject]@{
            IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
            FQDN            = $FQDN
            HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
            Domain          = $Domain
        }
    
        ##### END Main Body #####
    
    }

    function GetDomainController {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$False)]
            [String]$Domain,

            [Parameter(Mandatory=$False)]
            [switch]$UseLogonServer
        )
    
        ##### BEGIN Helper Functions #####
    
        function Parse-NLTest {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [string]$Domain
            )
    
            while ($Domain -notmatch "\.") {
                Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
                $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
            }
    
            if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
                Write-Error "Unable to find nltest.exe! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $DomainPrefix = $($Domain -split '\.')[0]
            $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
            if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
                Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
                return
            }
            $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
            if ($PrimaryDomainControllerPrep -match '\\\\') {
                $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
            }
            else {
                $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
            }
    
            $PrimaryDomainController
        }
    
        ##### END Helper Functions #####
    
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
        $PartOfDomain = $ComputerSystemCim.PartOfDomain
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        ##### BEGIN Main Body #####
    
        if (!$PartOfDomain -and !$Domain) {
            Write-Error "$env:ComputerName is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $ThisMachinesDomain = $ComputerSystemCim.Domain
    
        # If we're in a PSSession, [system.directoryservices.activedirectory] won't work due to Double-Hop issue
        # So just get the LogonServer if possible
        if ($Host.Name -eq "ServerRemoteHost" -or $UseLogonServer) {
            if (!$Domain -or $Domain -eq $ThisMachinesDomain) {
                $Counter = 0
                while ([string]::IsNullOrWhitespace($DomainControllerName) -or $Counter -le 20) {
                    $DomainControllerName = $(Get-CimInstance win32_ntdomain).DomainControllerName
                    if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                        Write-Warning "The win32_ntdomain CimInstance has a null value for the 'DomainControllerName' property! Trying again in 15 seconds (will try for 5 minutes total)..."
                        Start-Sleep -Seconds 15
                    }
                    $Counter++
                }

                if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                    $IPOfDNSServerWhichIsProbablyDC = $(Resolve-DNSName $ThisMachinesDomain).IPAddress
                    $DomainControllerFQDN = $(ResolveHost -HostNameOrIP $IPOfDNSServerWhichIsProbablyDC).FQDN
                }
                else {
                    $LogonServer = $($DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
                    $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
                }
    
                [pscustomobject]@{
                    FoundDomainControllers      = [array]$DomainControllerFQDN
                    PrimaryDomainController     = $DomainControllerFQDN
                }
    
                return
            }
            else {
                Write-Error "Unable to determine Domain Controller(s) network location due to the Double-Hop Authentication issue! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        if ($Domain) {
            try {
                $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
            }
            catch {
                Write-Verbose "Cannot connect to current forest."
            }
    
            if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
                try {
                    $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                    [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                }
                catch {
                    try {
                        Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                        Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                        $PrimaryDomainController = Parse-NLTest -Domain $Domain
                        [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
                try {
                    Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                    Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            try {
                $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            catch {
                Write-Verbose "Cannot connect to current forest."
    
                try {
                    $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                    [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                }
                catch {
                    $Domain = $ThisMachinesDomain
    
                    try {
                        $CurrentUser = "$(whoami)"
                        Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                        Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                        if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                            Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                        }
                        Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                        Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                        $PrimaryDomainController = Parse-NLTest -Domain $Domain
                        [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
        }
    
        [pscustomobject]@{
            FoundDomainControllers      = $FoundDomainControllers
            PrimaryDomainController     = $PrimaryDomainController
        }
    
        ##### END Main Body #####
    }

    function SetupSubCA {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [pscredential]$DomainAdminCredentials,

            [Parameter(Mandatory=$True)]
            [System.Collections.ArrayList]$NetworkInfoPSObjects,

            [Parameter(Mandatory=$True)]
            [ValidateSet("EnterpriseSubordinateCA")]
            [string]$CAType,

            [Parameter(Mandatory=$True)]
            [string]$NewComputerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$NewWebServerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$FileOutputDirectory,

            [Parameter(Mandatory=$True)]
            [ValidateSet("Microsoft Software Key Storage Provider")]
            [string]$CryptoProvider,

            [Parameter(Mandatory=$True)]
            [ValidateSet("2048","4096")]
            [int]$KeyLength,

            [Parameter(Mandatory=$True)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
            [string]$HashAlgorithm,

            [Parameter(Mandatory=$True)]
            [ValidateSet("RSA")]
            [string]$KeyAlgorithmValue,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
            [string]$CDPUrl,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
            [string]$AIAUrl
        )

        # Make sure we can find the Domain Controller(s)
        try {
            $DomainControllerInfo = GetDomainController -Domain $(Get-CimInstance win32_computersystem).Domain -UseLogonServer -WarningAction SilentlyContinue
            if (!$DomainControllerInfo -or $DomainControllerInfo.PrimaryDomainController -eq $null) {throw "Unable to find Primary Domain Controller! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
        $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

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

        $ItemsToAddToWSMANTrustedHosts = @(
            $RelevantRootCANetworkInfo.FQDN
            $RelevantRootCANetworkInfo.HostName
            $RelevantRootCANetworkInfo.IPAddress
            $RelevantSubCANetworkInfo.FQDN
            $RelevantSubCANetworkInfo.HostName
            $RelevantSubCANetworkInfo.IPAddress
        )
        foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
            if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                $null = $CurrentTrustedHostsAsArray.Add($NetItem)
            }
        }
        $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

        # Mount the RootCA Temporary SMB Share To Get the Following Files
        <#
        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        -a----        5/22/2018   8:09 AM           1524 CustomComputerTemplate.ldf
        -a----        5/22/2018   8:09 AM           1517 CustomWebServerTemplate.ldf
        -a----        5/22/2018   8:07 AM            841 RootCA.alpha.lab_ROOTCA.crt
        -a----        5/22/2018   8:09 AM           1216 RootCA.alpha.lab_ROOTCA_base64.cer
        -a----        5/22/2018   8:09 AM            483 ROOTCA.crl
        #>
        # This also serves as a way to determine if the Root CA is ready
        while (!$RootCASMBShareMount) {
            $NewPSDriveSplatParams = @{
                Name            = "R"
                PSProvider      = "FileSystem"
                Root            = "\\$($RelevantRootCANetworkInfo.FQDN)\RootCAFiles"
                Credential      = $DomainAdminCredentials
                ErrorAction     = "SilentlyContinue"
            }
            $RootCASMBShareMount = New-PSDrive @NewPSDriveSplatParams

            if (!$RootCASMBShareMount) {
                $NewPSDriveSplatParams
                Write-Host "Waiting for RootCA SMB Share to become available. Sleeping for 15 seconds..."
                Start-Sleep -Seconds 15
            }
        }

        if (!$FileOutputDirectory) {
            $FileOutputDirectory = "C:\NewSubCAOutput"
        }
        if (!$(Test-Path $FileOutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $FileOutputDirectory 
        }
        
        try {
            Import-Module PSPKI -ErrorAction Stop
        }
        catch {
            try {
                $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
                $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module PSPKI -ErrorAction Stop
                Import-Module PSPKI -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        
        try {
            Import-Module ServerManager -ErrorAction Stop
        }
        catch {
            Write-Error "Problem importing the ServerManager Module! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $WindowsFeaturesToAdd = @(
            "Adcs-Cert-Authority"
            "Adcs-Web-Enrollment"
            "Adcs-Enroll-Web-Pol"
            "Adcs-Enroll-Web-Svc"
            "Web-Mgmt-Console"
            "RSAT-AD-Tools"
        )
        foreach ($FeatureName in $WindowsFeaturesToAdd) {
            $SplatParams = @{
                Name    = $FeatureName
            }
            if ($FeatureName -eq "Adcs-Cert-Authority") {
                $SplatParams.Add("IncludeManagementTools",$True)
            }

            try {
                $null = Add-WindowsFeature @SplatParams
            }
            catch {
                Write-Error "Problem with 'Add-WindowsFeature $FeatureName'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        #region >> Install ADCSCA
        try {
            $CertRequestFile = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".csr"
            $FinalCryptoProvider = $KeyAlgorithmValue + "#" + $CryptoProvider
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantSubCANetworkInfo.DomainLDAPString
                OutputCertRequestFile       = $CertRequestFile
                Force                       = $True
                ErrorAction                 = "Stop"
            }
            $null = Install-AdcsCertificationAuthority @InstallADCSCertAuthSplatParams *>"$FileOutputDirectory\InstallAdcsCertificationAuthority.log"
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Install-AdcsCertificationAuthority cmdlet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Copy RootCA .crt and .crl From Network Share to SubCA CertEnroll Directory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination "C:\Windows\System32\CertSrv\CertEnroll" -Force

        # Copy RootCA .crt and .crl From Network Share to the $FileOutputDirectory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination $FileOutputDirectory -Force

        # Install the RootCA .crt to the Certificate Store
        Write-Host "Installing RootCA Certificate via 'certutil -addstore `"Root`" <RootCertFile>'..."
        [array]$RootCACrtFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crt"
        if ($RootCACrtFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crt file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrtFile.Count -gt 1) {
            $RootCACrtFile = $RootCACrtFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.FQDN + "_" + $RelevantRootCANetworkInfo.HostName + '.crt')}
        }
        if ($RootCACrtFile -eq 1) {
            $RootCACrtFile = $RootCACrtFile[0]
        }
        $null = certutil -f -addstore "Root" "$($RootCACrtFile.FullName)"

        # Install RootCA .crl
        Write-Host "Installing RootCA CRL via 'certutil -addstore `"Root`" <RootCRLFile>'..."
        [array]$RootCACrlFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crl"
        if ($RootCACrlFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crl file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrlFile.Count -gt 1) {
            $RootCACrlFile = $RootCACrlFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.HostName + '.crl')}
        }
        if ($RootCACrlFile -eq 1) {
            $RootCACrlFile = $RootCACrlFile[0]
        }
        $null = certutil -f -addstore "Root" "$($RootCACrlFile.FullName)"

        # Create the Certdata IIS folder
        $CertDataIISFolder = "C:\inetpub\wwwroot\certdata"
        if (!$(Test-Path $CertDataIISFolder)) {
            $null = New-Item -ItemType Directory -Path $CertDataIISFolder -Force
        }

        # Stage certdata IIS site and enable directory browsing
        Write-Host "Enable directory browsing for IIS via appcmd.exe..."
        Copy-Item -Path "$FileOutputDirectory\*" -Recurse -Destination $CertDataIISFolder -Force
        $null = & "C:\Windows\system32\inetsrv\appcmd.exe" set config "Default Web Site/certdata" /section:directoryBrowse /enabled:true

        # Update DNS Alias
        Write-Host "Update DNS with CNAME that refers 'pki.$($RelevantSubCANetworkInfo.DomainName)' to '$($RelevantSubCANetworkInfo.FQDN)' ..."
        $LogonServer = $($(Get-CimInstance win32_ntdomain).DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
        $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
        Invoke-Command -ComputerName $DomainControllerFQDN -Credential $DomainAdminCredentials -ScriptBlock {
            $NetInfo = $using:RelevantSubCANetworkInfo
            Add-DnsServerResourceRecordCname -Name "pki" -HostnameAlias $NetInfo.FQDN -ZoneName $NetInfo.DomainName
        }

        # Request and Install SCA Certificate from Existing CSR
        $RootCACertUtilLocation = "$($RelevantRootCANetworkInfo.FQDN)\$($RelevantRootCANetworkInfo.HostName)" 
        $SubCACertUtilLocation = "$($RelevantSubCANetworkInfo.FQDN)\$($RelevantSubCANetworkInfo.HostName)"
        $SubCACerFileOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".cer"
        $CertificateChainOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".p7b"
        $SubCACertResponse = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".rsp"
        $FileCheck = @($SubCACerFileOut,$CertificateChainOut,$SubCACertResponse)
        foreach ($FilePath in $FileCheck) {
            if (Test-Path $FilePath) {
                Remove-Item $FilePath -Force
            }
        }

        Write-Host "Submitting certificate request for SubCA Cert Authority using certreq..."
        $RequestID = $(certreq -f -q -config "$RootCACertUtilLocation" -submit "$CertRequestFile").split('"')[2]
        Write-Host "Request ID is $RequestID"
        if (!$RequestID) {
            $RequestID = 2
            Write-Host "Request ID is $RequestID"
        }
        Start-Sleep -Seconds 5
        Write-Host "Retrieving certificate request for SubCA Cert Authority using certreq..."
        $null = certreq -f -q -retrieve -config $RootCACertUtilLocation $RequestID $SubCACerFileOut $CertificateChainOut
        Start-Sleep -Seconds 5
        

        # Install the Certificate Chain on the SubCA
        # Manually create the .p7b file...
        <#
        $CertsCollections = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $X509Cert2Info = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $X509Cert2Info.Import($SubCACerFileOut)
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        $null = $chain.Build($X509Cert2Info)
        $chain.ChainElements | ForEach-Object {[void]$CertsCollections.Add($_.Certificate)}
        $chain.Reset()
        Set-Content -Path $CertificateChainOut -Value $CertsCollections.Export("pkcs7") -Encoding Byte
        #>
        Write-Host "Accepting $SubCACerFileOut using certreq.exe ..."
        $null = certreq -f -q -accept $SubCACerFileOut
        Write-Host "Installing $CertificateChainOut to $SubCACertUtilLocation ..."
        $null = certutil -f -config $SubCACertUtilLocation -installCert $CertificateChainOut
  
        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        # Enable the Subordinate CA to issue Certificates with Subject Alternate Names (SAN)
        Write-Host "Enable the Subordinate CA to issue Certificates with Subject Alternate Names (SAN) via certutil command..."
        $null = certutil -f -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

        try {
            $null = Stop-Service certsvc -Force -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Stopped") {
            Write-Host "Waiting for the 'certsvc' service to stop..."
            Start-Sleep -Seconds 5
        }

        # Install Certification Authority Web Enrollment
        try {
            Write-Host "Running Install-AdcsWebEnrollment cmdlet..."
            $null = Install-AdcsWebEnrollment -Force *>"$FileOutputDirectory\InstallAdcsWebEnrollment.log"
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Start-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        while (!$ADCSEnrollWebSvcSuccess) {
            try {
                Write-Host "Running Install-AdcsEnrollmentWebService cmdlet..."
                $EWebSvcSplatParams = @{
                    AuthenticationType          = "UserName"
                    ApplicationPoolIdentity     = $True
                    CAConfig                    = $SubCACertUtilLocation
                    Force                       = $True
                    ErrorAction                 = "Stop"
                }
                # Install Certificate Enrollment Web Service
                $ADCSEnrollmentWebSvcInstallResult = Install-AdcsEnrollmentWebService @EWebSvcSplatParams *>"$FileOutputDirectory\ADCSEnrWebSvcInstall.log"
                $ADCSEnrollWebSvcSuccess = $True
                $ADCSEnrollmentWebSvcInstallResult | Export-CliXml "$HOME\ADCSEnrollmentWebSvcInstallResult.xml"
            }
            catch {
                try {
                    $null = Restart-Service certsvc -Force -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                while ($(Get-Service certsvc).Status -ne "Running") {
                    Write-Host "Waiting for the 'certsvc' service to start..."
                    Start-Sleep -Seconds 5
                }

                Write-Host "The 'Install-AdcsEnrollmentWebService' cmdlet failed. Trying again in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }

        # Publish SubCA CRL
        # Generate New CRL and Copy Contents of CertEnroll to $FileOutputDirectory
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        Write-Host "Publishing SubCA CRL ..."
        $null = certutil -f -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert SubCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.crt"}
        $null = certutil -f -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')
        
        # Copy SubCA CRL From SubCA CertEnroll directory to C:\inetpub\wwwroot\certdata" do
        $SubCACrlFileItem = $(Get-ChildItem -Path "C:\Windows\System32\CertSrv\CertEnroll" -File | Where-Object {$_.Name -match "\.crl"} | Sort-Object -Property LastWriteTime)[-1]
        Copy-Item -Path $SubCACrlFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACrlFileItem.Name)" -Force
        
        # Copy SubCA Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        $SubCACerFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.cer"}
        Copy-Item $SubCACerFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACerFileItem.Name)"

        # Import New Certificate Templates that were exported by the RootCA to a Network Share
        # NOTE: This shouldn't be necessary if we're using and Enterprise Root CA. If it's a Standalone Root CA,
        # this IS necessary.
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewComputerTemplateCommonName + '.ldf')
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewWebServerTemplateCommonName + '.ldf')
        
        try {
            # Add New Cert Templates to List of Temps to Issue using the PSPKI Module
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Request PKI WebServer Alias Certificate
        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        Write-Host "Requesting PKI Website WebServer Certificate..."
        $PKIWebsiteCertFileOut = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).cer"
        $PKIWebSiteCertInfFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).inf"
        $PKIWebSiteCertRequestFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).csr"
        $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
FriendlyName = pki.$($RelevantSubCANetworkInfo.DomainName)
Subject = "CN=pki.$($RelevantSubCANetworkInfo.DomainName)"
KeyLength = 2048
HashAlgorithm = SHA256
Exportable = TRUE
KeySpec = 1
KeyUsage = 0xa0
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=pki.$($RelevantSubCANetworkInfo.DomainName)&"
_continue_ = "ipaddress=$($RelevantSubCANetworkInfo.IPAddress)&"
"@

        $inf | Out-File $PKIWebSiteCertInfFile
        # NOTE: The generation of a Certificate Request File using the below "certreq.exe -new" command also adds the CSR to the 
        # Client Machine's Certificate Request Store located at PSDrive "Cert:\CurrentUser\REQUEST"
        # There doesn't appear to be an equivalent to this using PowerShell cmdlets
        $null = certreq.exe -f -new "$PKIWebSiteCertInfFile" "$PKIWebSiteCertRequestFile"
        $null = certreq.exe -f -submit -attrib "CertificateTemplate:$NewWebServerTemplateCommonName" -config "$SubCACertUtilLocation" "$PKIWebSiteCertRequestFile" "$PKIWebsiteCertFileOut"

        if (!$(Test-Path $PKIWebsiteCertFileOut)) {
            Write-Error "There was a problem requesting a WebServer Certificate from the Subordinate CA for the PKI (certsrv) website! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Received $PKIWebsiteCertFileOut..."
        }

        # Copy PKI SubCA Alias Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        Copy-Item -Path $PKIWebsiteCertFileOut -Destination "C:\inetpub\wwwroot\certdata\pki.$($RelevantSubCANetworkInfo.DomainName).cer"

        # Get the Thumbprint of the pki website certificate
        # NOTE: At this point, pki.<domain>.cer Certificate should already be loaded in the SubCA's (i.e. $env:ComputerName's)
        # Certificate Store. The thumbprint is how we reference the specific Certificate in the Store.
        $X509Cert2Info = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $X509Cert2Info.Import($PKIWebsiteCertFileOut)
        $PKIWebsiteCertThumbPrint = $X509Cert2Info.ThumbPrint
        $SubCACertThumbprint = $(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "CN=$env:ComputerName,"}).Thumbprint

        # Install the PKIWebsite Certificate under Cert:\CurrentUser\My
        Write-Host "Importing the PKI Website Certificate to Cert:\CurrentUser\My ..."
        $null = Import-Certificate -FilePath $PKIWebsiteCertFileOut -CertStoreLocation "Cert:\LocalMachine\My"
        $PKICertSerialNumber = $(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint}).SerialNumber
        # Make sure it is ready to be used by IIS by ensuring the Private Key is readily available
        Write-Host "Make sure PKI Website Certificate is ready to be used by IIS by running 'certutil -repairstore'..."
        $null = certutil -repairstore "My" $PKICertSerialNumber

        Write-Host "Running Install-AdcsEnrollmentPolicyWebService cmdlet..."
        while (!$ADCSEnrollmentPolicySuccess) {
            try {
                $EPolSplatParams = @{
                    AuthenticationType      = "UserName"
                    SSLCertThumbprint       = $SubCACertThumbprint
                    Force                   = $True
                    ErrorAction             = "Stop"
                }
                $ADCSEnrollmentPolicyInstallResult = Install-AdcsEnrollmentPolicyWebService @EPolSplatParams
                $ADCSEnrollmentPolicySuccess = $True
                $ADCSEnrollmentPolicyInstallResult | Export-CliXml "$HOME\ADCSEnrollmentPolicyInstallResult.xml"
            }
            catch {
                try {
                    $null = Restart-Service certsvc -Force -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                while ($(Get-Service certsvc).Status -ne "Running") {
                    Write-Host "Waiting for the 'certsvc' service to start..."
                    Start-Sleep -Seconds 5
                }

                Write-Host "The 'Install-AdcsEnrollmentPolicyWebService' cmdlet failed. Trying again in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }

        try {
            Write-Host "Configuring CRL, CDP, AIA, CA Auditing..."
            # Configure CRL, CDP, AIA, CA Auditing
            # Update CRL Validity period
            $null = certutil -f -setreg CA\\CRLPeriod "Weeks"
            $null = certutil -f -setreg CA\\CRLPeriodUnits 4
            $null = certutil -f -setreg CA\\CRLOverlapPeriod "Days"
            $null = certutil -f -setreg CA\\CRLOverlapUnits 3

            # Remove pre-existing http CDP, add custom CDP
            $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http#*" } | Remove-CACrlDistributionPoint -Force
            $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

            # Remove pre-existing http AIA, add custom AIA
            $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" } | Remove-CAAuthorityInformationAccess -Force
            $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force

            # Enable all event auditing
            $null = certutil -f -setreg CA\\AuditFilter 127
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        # Configure HTTPS Binding
        try {
            Write-Host "Configuring IIS https binding to use $PKIWebsiteCertFileOut..."
            Import-Module WebAdministration
            Remove-Item IIS:\SslBindings\*
            $null = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint} | New-Item IIS:\SslBindings\0.0.0.0!443
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Configure Application Settings
        Write-Host "Configuring IIS Application Settings via appcmd.exe..."
        $null = & "C:\Windows\system32\inetsrv\appcmd.exe" set config /commit:MACHINE /section:appSettings /+"[key='Friendly Name',value='$($RelevantSubCANetworkInfo.DomainName) Domain Certification Authority']"

        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        try {
            Restart-Service iisadmin -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service iisadmin).Status -ne "Running") {
            Write-Host "Waiting for the 'iis' service to start..."
            Start-Sleep -Seconds 5
        }

        [pscustomobject]@{
            PKIWebsiteUrls                  = @("https://pki.$($RelevantSubCANetworkInfo.DomainName)/certsrv","https://pki.$($RelevantSubCANetworkInfo.IPAddress)/certsrv")
            PKIWebsiteCertSSLCertificate    = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint}
            AllOutputFiles                  = Get-ChildItem $FileOutputDirectory
        }
    }

    #endregion >> Helper Functions

    
    #region >> Initial Prep

    $ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$ElevationCheck) {
        Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @(
        [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAIPOrFQDN
        }
    )
    if ($PSBoundParameters['SubCAIPOrFQDN']) {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $SubCAIPOrFQDN
        }
    }
    else {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationObjsToResolve.Add($SubCAPSObj)

    [System.Collections.ArrayList]$NetworkInfoPSObjects = @()
    foreach ($NetworkLocationObj in $NetworkLocationObjsToResolve) {
        if ($($NetworkLocation -split "\.")[0] -ne $env:ComputerName -and
        $NetworkLocation -ne $PrimaryIP -and
        $NetworkLocation -ne "$env:ComputerName.$($(Get-CimInstance win32_computersystem).Domain)"
        ) {
            try {
                $NetworkInfo = ResolveHost -HostNameOrIP $NetworkLocationObj.NetworkLocation
                $DomainName = $NetworkInfo.Domain
                $FQDN = $NetworkInfo.FQDN
                $IPAddr = $NetworkInfo.IPAddressList[0]
                $DomainShortName = $($DomainName -split "\.")[0]
                $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','

                if (!$NetworkInfo -or $DomainName -eq "Unknown" -or !$DomainName -or $FQDN -eq "Unknown" -or !$FQDN) {
                    throw "Unable to gather Domain Name and/or FQDN info about '$NetworkLocation'! Please check DNS. Halting!"
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

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

            $ItemsToAddToWSMANTrustedHosts = @($IPAddr,$FQDN,$($($FQDN -split "\.")[0]))
            foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
                if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                    $null = $CurrentTrustedHostsAsArray.Add($NetItem)
                }
            }
            $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
            Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
        }
        else {
            $DomainName = $(Get-CimInstance win32_computersystem).Domain
            $DomainShortName = $($DomainName -split "\.")[0]
            $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','
            $FQDN = $env:ComputerName + '.' + $DomainName
            $IPAddr = $PrimaryIP
        }

        $PSObj = [pscustomobject]@{
            ServerPurpose       = $NetworkLocationObj.ServerPurpose
            FQDN                = $FQDN
            HostName            = $($FQDN -split "\.")[0]
            IPAddress           = $IPAddr
            DomainName          = $DomainName
            DomainShortName     = $DomainShortName
            DomainLDAPString    = $DomainLDAPString
        }
        $null = $NetworkInfoPSObjects.Add($PSObj)
    }

    $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
    $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

    # Set some defaults if certain paramters are not used
    if (!$CAType) {
        $CAType = "EnterpriseSubordinateCA"
    }
    if (!$NewComputerTemplateCommonName) {
        #$NewComputerTemplateCommonName = $DomainShortName + "Computer"
        $NewComputerTemplateCommonName = "Machine"
    }
    if (!$NewWebServerTemplateCommonName) {
        #$NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
        $NewWebServerTemplateCommonName = "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\NewSubCAOutput"
    }
    if (!$CryptoProvider) {
        $CryptoProvider = "Microsoft Software Key Storage Provider"
    }
    if (!$KeyLength) {
        $KeyLength = 2048
    }
    if (!$HashAlgorithm) {
        $HashAlgorithm = "SHA256"
    }
    if (!$KeyAlgorithmValue) {
        $KeyAlgorithmValue = "RSA"
    }
    if (!$CDPUrl) {
        $CDPUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupSubCA Helper Function Splat Parameters
    $SetupSubCASplatParams = @{
        DomainAdminCredentials              = $DomainAdminCredentials
        NetworkInfoPSObjects                = $NetworkInfoPSObjects
        CAType                              = $CAType
        NewComputerTemplateCommonName       = $NewComputerTemplateCommonName
        NewWebServerTemplateCommonName      = $NewWebServerTemplateCommonName
        FileOutputDirectory                 = $FileOutputDirectory
        CryptoProvider                      = $CryptoProvider
        KeyLength                           = $KeyLength
        HashAlgorithm                       = $HashAlgorithm
        KeyAlgorithmValue                   = $KeyAlgorithmValue
        CDPUrl                              = $CDPUrl
        AIAUrl                              = $AIAUrl
    }

    # Install any required PowerShell Modules...
    [array]$NeededModules = @(
        "PSPKI"
    )
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    [System.Collections.ArrayList]$FailedModuleInstall = @()
    foreach ($ModuleResource in $NeededModules) {
        try {
            $null = Install-Module $ModuleResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedModuleInstall.Add($ModuleResource)
            continue
        }
    }
    if ($FailedModuleInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedModuleInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }

    [array]$ModulesToTransfer = foreach ($ModuleResource in $NeededModules) {
        $Module = Get-Module -ListAvailable $ModuleResource
        "$($($Module.ModuleBase -split $ModuleResource)[0])\$ModuleResource"
    }

    #endregion >> Initial Prep


    #region >> Do SubCA Install

    if ($RelevantSubCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCA"

        # Try to create a PSSession to the server that will become the Subordate CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $SubCAPSSession = New-PSSession -ComputerName $RelevantSubCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$SubCAPSSession) {
            Write-Error "Unable to create a PSSession to the intended Subordinate CA Server at '$($RelevantSubCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Transfer any required PowerShell Modules
        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $ModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = $SubCAPSSession
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        # Get ready to run SetupSubCA function remotely as a Scheduled task to that certreq/certutil don't hang due to double-hop issue...

        $FunctionsForRemoteUse = @(
            ${Function:GetDomainController}.Ast.Extent.Text
            ${Function:SetupSubCA}.Ast.Extent.Text
        )

        # Invoke-CommandAs Module looked promising, but doesn't actually work (it just hangs). Maybe in future updates...
        # For more info, see: https://github.com/mkellerman/Invoke-CommandAs
        <#
        if (![bool]$(Get-Module -ListAvailable Invoke-CommandAs -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "Installing 'Invoke-CommandAs' PowerShell Module..."
                $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
                $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module Invoke-CommandAs -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            Write-Host "Importing 'Invoke-CommandAs' PowerShell Module..."
            Import-Module Invoke-CommandAs -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        Write-Host "This will take about 2 hours...go grab a coffee...or 2..."

        Invoke-CommandAs -Session $SubCAPSSession -ScriptBlock {
            Start-Transcript -Path "C:\NewSubCATask.log" -Append
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

            $SetupSubCASplatParams = @{
                DomainAdminCredentials              = $using:DomainAdminCredentials
                NetworkInfoPSObjects                = $using:NetworkInfoPSObjects
                CAType                              = $using:CAType
                NewComputerTemplateCommonName       = $using:NewComputerTemplateCommonName
                NewWebServerTemplateCommonName      = $using:NewWebServerTemplateCommonName
                FileOutputDirectory                 = $using:FileOutputDirectory
                CryptoProvider                      = $using:CryptoProvider
                KeyLength                           = $using:KeyLength
                HashAlgorithm                       = $using:HashAlgorithm
                KeyAlgorithmValue                   = $using:KeyAlgorithmValue
                CDPUrl                              = $using:CDPUrl
                AIAUrl                              = $using:AIAUrl
            }
            
            SetupSubCA @SetupSubCASplatParams
            Stop-Transcript

        } -As $DomainAdminCredentials
        #>

        Write-Host "This will take about 2 hours...go grab a coffee...or 2..."

        $DomainAdminAccount = $DomainAdminCredentials.UserName
        $DomainAdminPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainAdminCredentials.Password))
        $Output = Invoke-Command -Session $SubCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            ${Function:GetDomainController}.Ast.Extent.Text | Out-File "$HOME\GetDomainController.ps1"
            ${Function:SetupSubCA}.Ast.Extent.Text | Out-File "$HOME\SetupSubCA.ps1"
            $using:NetworkInfoPSObjects | Export-CliXml "$HOME\NetworkInfoPSObjects.xml"
            
            $ExecutionScript = @'
Start-Transcript -Path "$HOME\NewSubCATask.log" -Append

. "$HOME\GetDomainController.ps1"
. "$HOME\SetupSubCA.ps1"
$NetworkInfoPSObjects = Import-CliXML "$HOME\NetworkInfoPSObjects.xml"

'@ + @"

`$DomainAdminPwdSS = ConvertTo-SecureString '$using:DomainAdminPwd' -AsPlainText -Force
`$DomainAdminCredentials = [pscredential]::new("$using:DomainAdminAccount",`$DomainAdminPwdSS)

"@ + @'

$SetupSubCASplatParams = @{
    DomainAdminCredentials              = $DomainAdminCredentials
    NetworkInfoPSObjects                = $NetworkInfoPSObjects

'@ + @"
    
    CAType                              = "$using:CAType"
    NewComputerTemplateCommonName       = "$using:NewComputerTemplateCommonName"
    NewWebServerTemplateCommonName      = "$using:NewWebServerTemplateCommonName"
    FileOutputDirectory                 = "$using:FileOutputDirectory"
    CryptoProvider                      = "$using:CryptoProvider"
    KeyLength                           = "$using:KeyLength"
    HashAlgorithm                       = "$using:HashAlgorithm"
    KeyAlgorithmValue                   = "$using:KeyAlgorithmValue"
    CDPUrl                              = "$using:CDPUrl"
    AIAUrl                              = "$using:AIAUrl"
}

"@ + @'

    SetupSubCA @SetupSubCASplatParams -OutVariable Output -ErrorAction SilentlyContinue -ErrorVariable NewSubCAErrs

    $Output | Export-CliXml "$HOME\SetupSubCAOutput.xml"

    if ($NewSubCAErrs) {
        Write-Warning "Ignored errors are as follows:"
        Write-Error ($NewSubCAErrs | Out-String)
    }

    Stop-Transcript

    # Delete this script file after it is finished running
    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force

'@
            Set-Content -Path "$HOME\NewSubCAExecutionScript.ps1" -Value $ExecutionScript

            $Trigger = New-ScheduledTaskTrigger -Once -At $(Get-Date).AddSeconds(10)
            $Trigger.EndBoundary = $(Get-Date).AddHours(4).ToString('s')
            # IMPORTANT NORE: The double quotes around the -File value are MANDATORY. They CANNOT be single quotes or without quotes
            # or the Scheduled Task will error out!
            Register-ScheduledTask -Force -TaskName NewSubCA -User $using:DomainAdminCredentials.UserName -Password $using:DomainAdminPwd -Action $(
                New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File `"$HOME\NewSubCAExecutionScript.ps1`""
            ) -Trigger $Trigger -Settings $(New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01)

            Start-Sleep -Seconds 15

            if ($(Get-ScheduledTask -TaskName 'NewSubCA').State -eq "Ready") {
                Start-ScheduledTask -TaskName "NewSubCA"
            }

            $Counter = 1
            while ((Get-ScheduledTask -TaskName 'NewSubCA').State  -ne 'Ready') {
                Write-Host "Waiting for Scheduled Task 'NewSubCA' to complete..."
                Write-Host "We have waited for $($Counter*15/60) minutes..."
                Start-Sleep -Seconds 15
                $Counter++
            }

            Unregister-ScheduledTask -TaskName "NewSubCA" -Confirm:$False

            Import-CliXML "$HOME\SetupSubCAOutput.xml"
        }
    }
    else {
        $Output = SetupSubCA @SetupSubCASplatParams
    }

    $Output

    #endregion >> Do SubCA Install

    
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaiOaA46R9llBtK8eLw1ZCw41
# Vougggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFL2aWMeLtkw5AEW9
# nfMM8I6x+PgzMA0GCSqGSIb3DQEBAQUABIIBABlOHjS+GeUp7HO+kPnLnkHg5BFT
# I4/p6PptZNVsfZMzbn/HUy3QuSrgKKRb6lEmAI96IdKcNh6BDEz9i8Dzok/gJTe5
# DoxmKUv+hko6Bz1jWRDhHt+Vb5my1aERPYQVnlZTfFLc5DCo6bvCCK4hIx65itvC
# Dqk8J0OEDJeK2ERUCyyNWQTo1pQJ5EI9ZYrBc/pZuLtAm1FW7jCgdIT+YIzVUEJ7
# jzF4wuCk+QMe/K2PH/s2Uzf96sCThjdI9/q3BeVyQwxnJ3EAQJdhe7UNFKpD0/Zl
# XvIPYKAE3i81sXhqponK7x/DHCeqba2MU971GaS0PtEkrqgo42n9mYXOaQw=
# SIG # End signature block
