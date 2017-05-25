<#
.SYNOPSIS
    Configures Git installed on Windows via GitDesktop to authenticate via https or ssh.
    Optionally, clone all repos from the GitHub User you authenticate as.

.DESCRIPTION
    See Synopsis.

.EXAMPLE
    $GitAuthParams = @{
        GitHubUserName = "pldmgg"
        GitHubEmail = "pldmgg@genericemailprovider.com"
        AuthMethod = "https"
        PersonalAccessToken = "234567ujhgfw456734567890okfd3456"
    }

    Setup-GitAuthentication @GitAuthParams

.EXAMPLE
    $GitAuthParams = @{
        GitHubUserName = "pldmgg"
        GitHubEmail = "pldmgg@genericemailprovider.com"
        AuthMethod = "ssh"
        NewSSHKeyName "gitauth_rsa"
    }

    Setup-GitAuthentication @GitAuthParams

.EXAMPLE
    $GitAuthParams = @{
        GitHubUserName = "pldmgg"
        GitHubEmail = "pldmgg@genericemailprovider.com"
        AuthMethod = "ssh"
        ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa" 
    }
    
    Setup-GitAuthentication @GitAuthParams

#>

function Setup-GitAuthentication {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = $(Read-Host -Prompt "Please enter your GitHub Username"),

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail = $(Read-Host -Prompt "Please the primary GitHub email address associated with $GitHubUserName"),

        [Parameter(Mandatory=$False)]
        [ValidateSet("https","ssh")]
        [string]$AuthMethod  = $(Read-Host -Prompt "Please select the Authentication Method you would like to use. [https/ssh]"),

        [Parameter(Mandatory=$False)]
        [string]$PersonalAccessToken,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [string]$ExistingSSHPrivateKeyPath
    )

    ##### BEGIN Parameter Validation #####
    if ($AuthMethod -eq "https" -and !$PersonalAccessToken) {
        $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication."
    }

    if ($ExistingSSHPrivateKeyPath) {
        $ExistingSSHPrivateKeyPath = $(Resolve-Path $ExistingSSHPrivateKeyPath -ErrorAction SilentlyContinue).Path
        if (!$(Test-Path "$ExistingSSHPrivateKeyPath")) {
            Write-Verbose "Unable to find $ExistingSSHPrivateKeyPath! Halting!"
            Write-Error "Unable to find $ExistingSSHPrivateKeyPath! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If no specific ExistingSSHPrivateKeyPath is provided, assume it's in the default GitDesktop directory
    if ($AuthMethod -eq "ssh" -and !$ExistingSSHPrivateKeyPath -and !$NewSSHKeyName) {
        $ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa"
    }

    ##### END Parameter Validation #####


    ##### BEGIN Helper Functions #####

    function Check-Elevation {
       [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
          New-Object System.Security.Principal.WindowsPrincipal(
             [System.Security.Principal.WindowsIdentity]::GetCurrent());

       [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
          [System.Security.Principal.WindowsBuiltInRole]::Administrator;

       if($currentPrincipal.IsInRole($administratorsRole))
       {
          return $true;
       }
       else
       {
          return $false;
       }
    }

    function Update-PackageManagement {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$False)]
            $Credentials
        )

        ##### BEGIN Helper Functions #####

        function New-SudoSession {
            [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
            Param(
                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply UserName and Password'
                )]
                [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply UserName and Password'
                )]
                $Password,

                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply Credentials'
                )]
                [System.Management.Automation.PSCredential]$Credentials

            )

            ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

            if ($UserName -and !$Password -and !$Credentials) {
                $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            }

            if ($UserName -and $Password) {
                if ($Password.GetType().FullName -eq "System.String") {
                    $Password = ConvertTo-SecureString $Password -AsPlainText -Force
                }
                $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
            }

            $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
            $LocalHostFQDN = "$env:ComputerName.$Domain"

            ##### END Variable/Parameter Transforms and PreRunPrep #####

            ##### BEGIN Main Body #####

            $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
            $CredDelRegLocationParent = $CredDelRegLocation | Split-Path -Parent
            $AllowFreshValue = "WSMAN/$LocalHostFQDN"
            $tmpFileXmlPrep = [IO.Path]::GetTempFileName()
            $UpdatedtmpFileXmlName = $tmpFileXmlPrep -replace "\.tmp",".xml"
            $tmpFileXml = $UpdatedtmpFileXmlName
            $TranscriptPath = "$HOME\Open-SudoSession_Transcript_$UserName_$(Get-Date -Format MM-dd-yyy_hhmm_tt).txt"

            $WSManGPOTempConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
try {`$CurrentAllowFreshCredsProperties = Get-ChildItem -Path $CredDelRegLocation | ? {`$_.PSChildName -eq 'AllowFreshCredentials'}} catch {}
try {`$CurrentAllowFreshCredsValues = foreach (`$propNum in `$CurrentAllowFreshCredsProperties) {`$(Get-ItemProperty -Path '$CredDelRegLocation\AllowFreshCredentials').`$propNum}} catch {}

if (!`$(Test-WSMan)) {`$WinRMConfigured = 'false'; winrm quickconfig /force; Start-Sleep -Seconds 5} else {`$WinRMConfigured = 'true'}
try {`$CredSSPServiceSetting = `$(Get-ChildItem WSMan:\localhost\Service\Auth\CredSSP).Value} catch {}
try {`$CredSSPClientSetting = `$(Get-ChildItem WSMan:\localhost\Client\Auth\CredSSP).Value} catch {}
if (`$CredSSPServiceSetting -eq 'false') {Enable-WSManCredSSP -Role Server -Force}
if (`$CredSSPClientSetting -eq 'false') {Enable-WSManCredSSP -DelegateComputer localhost -Role Client -Force}

if (!`$(Test-Path $CredDelRegLocation)) {`$Status = 'CredDelKey DNE'}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds DNE'}
if (`$(Test-Path $CredDelRegLocation) -and `$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds AlreadyExists'}

if (!`$(Test-Path $CredDelRegLocation)) {New-Item -Path $CredDelRegLocation}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {New-Item -Path $CredDelRegLocation\AllowFreshCredentials}

if (`$CurrentAllowFreshCredsValues -notcontains '$AllowFreshValue') {Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFresh -Value `$(`$CurrentAllowFreshCredsProperties.Count+1) -Type DWord; Start-Sleep -Seconds 2; Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name `$(`$CurrentAllowFreshCredsProperties.Count+1) -Value '$AllowFreshValue' -Type String}
New-Variable -Name 'OrigAllowFreshCredsState' -Value `$([pscustomobject][ordered]@{OrigAllowFreshCredsProperties = `$CurrentAllowFreshCredsProperties; OrigAllowFreshCredsValues = `$CurrentAllowFreshCredsValues; Status = `$Status; OrigWSMANConfigStatus = `$WinRMConfigured; OrigWSMANServiceCredSSPSetting = `$CredSSPServiceSetting; OrigWSMANClientCredSSPSetting = `$CredSSPClientSetting; PropertyToRemove = `$(`$CurrentAllowFreshCredsProperties.Count+1)})
`$(Get-Variable -Name 'OrigAllowFreshCredsState' -ValueOnly) | Export-CliXml -Path $tmpFileXml
exit"
"@
            $WSManGPOTempConfigFinal = $WSManGPOTempConfig -replace "`n","; "

            # IMPORTANT NOTE: You CANNOT use the RunAs Verb if UseShellExecute is $false, and you CANNOT use
            # RedirectStandardError or RedirectStandardOutput if UseShellExecute is $true, so we have to write
            # output to a file temporarily
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "powershell.exe"
            $ProcessInfo.RedirectStandardError = $false
            $ProcessInfo.RedirectStandardOutput = $false
            $ProcessInfo.UseShellExecute = $true
            $ProcessInfo.Arguments = $WSManGPOTempConfigFinal
            $ProcessInfo.Verb = "RunAs"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $WSManAndRegStatus = Import-CliXML $tmpFileXml

            $ElevatedPSSession = New-PSSession -Name "ElevatedSessionFor$UserName" -Authentication CredSSP -Credential $Credentials

            New-Variable -Name "NewSessionAndOriginalStatus" -Scope Global -Value $(
                [pscustomobject][ordered]@{
                    ElevatedPSSession   = $ElevatedPSSession
                    OriginalWSManAndRegistryStatus   = $WSManAndRegStatus
                }
            ) -Force
            
            $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly)

            # Cleanup 
            Remove-Item $tmpFileXml

            ##### END Main Body #####

        }

        function Remove-SudoSession {
            [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
            Param(
                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply UserName and Password'
                )]
                [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply UserName and Password'
                )]
                $Password,

                [Parameter(
                    Mandatory=$False,
                    ParameterSetName='Supply Credentials'
                )]
                [System.Management.Automation.PSCredential]$Credentials,

                [Parameter(Mandatory=$True)]
                $OriginalConfigInfo = $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly).OriginalWSManAndRegistryStatus,

                [Parameter(
                    Mandatory=$True,
                    ValueFromPipeline=$true,
                    Position=0
                )]
                [System.Management.Automation.Runspaces.PSSession]$SessionToRemove

            )

            ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

            if ($OriginalConfigInfo -eq $null) {
                Write-Warning "Unable to determine the original configuration of WinRM/WSMan and AllowFreshCredentials Registry prior to using New-SudoSession. No configuration changes will be made/reverted."
                Write-Warning "The only action will be removing the Elevated PSSession specified by the -SessionToRemove parameter."
            }

            if ($UserName -and !$Password -and !$Credentials -and $OriginalConfigInfo -ne $null) {
                $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            }

            if ($UserName -and $Password) {
                if ($Password.GetType().FullName -eq "System.String") {
                    $Password = ConvertTo-SecureString $Password -AsPlainText -Force
                }
                $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
            }

            $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
            $LocalHostFQDN = "$env:ComputerName.$Domain"

            ##### END Variable/Parameter Transforms and PreRunPrep #####

            ##### BEGIN Main Body #####

            if ($OriginalConfigInfo -ne $null) {
                $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
                $CredDelRegLocationParent = $CredDelRegLocation | Split-Path -Parent
                $AllowFreshValue = "WSMAN/$LocalHostFQDN"
                $tmpFileXmlPrep = [IO.Path]::GetTempFileName()
                $UpdatedtmpFileXmlName = $tmpFileXmlPrep -replace "\.tmp",".xml"
                $tmpFileXml = $UpdatedtmpFileXmlName
                $TranscriptPath = "$HOME\Remove-SudoSession_Transcript_$UserName_$(Get-Date -Format MM-dd-yyy_hhmm_tt).txt"

                $WSManGPORevertConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
if ('$($OriginalConfigInfo.Status)' -eq 'CredDelKey DNE') {Remove-Item -Recurse $CredDelRegLocation -Force}
if ('$($OriginalConfigInfo.Status)' -eq 'AllowFreshCreds DNE') {Remove-Item -Recurse $CredDelRegLocation\AllowFreshCredentials -Force}
if ('$($OriginalConfigInfo.Status)' -eq 'AllowFreshCreds AlreadyExists') {Remove-ItemProperty $CredDelRegLocation\AllowFreshCredentials\AllowFreshCredentials -Name $($WSManAndRegStatus.PropertyToRemove) -Force}
if ('$($OriginalConfigInfo.OrigWSMANConfigStatus)' -eq 'false') {Stop-Service -Name WinRm; Set-Service WinRM -StartupType "Manual"}
if ('$($OriginalConfigInfo.OrigWSMANServiceCredSSPSetting)' -eq 'false') {Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value `$false}
if ('$($OriginalConfigInfo.OrigWSMANClientCredSSPSetting)' -eq 'false') {Set-Item -Path WSMan:\localhost\Client\Auth\CredSSP -Value `$false}
exit"
"@
                $WSManGPORevertConfigFinal = $WSManGPORevertConfig -replace "`n","; "

                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                $ProcessInfo.FileName = "powershell.exe"
                $ProcessInfo.RedirectStandardError = $false
                $ProcessInfo.RedirectStandardOutput = $false
                $ProcessInfo.UseShellExecute = $true
                $ProcessInfo.Arguments = $WSManGPORevertConfigFinal
                $ProcessInfo.Verb = "RunAs"
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                $Process.WaitForExit()

            }

            Remove-PSSession $SessionToRemove

            ##### END Main Body #####

        }

        ##### END Helper Functions #####


        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        # Check to see if we're behind a proxy
        if ([System.Net.WebProxy]::GetDefaultProxy().Address -ne $null) {
            $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
            [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyAddress)
            [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        }

        if (!$(Check-Elevation) -and !$Credentials) {
            $UserName = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).split("\"))[1]
            $Psswd = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Psswd
        }
        if ($Credentials) {
            $UserName = $Credentials.UserName
            $Psswd = $Credentials.Password
        }
        $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        $DomainPre = $($Domain -split "\.")[0]
        $UpdatedUserName = "$DomainPre\$UserName"
        if ($Psswd) {
            $UpdatedCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UpdatedUserName, $Psswd
        }
        $LocalHostFQDN = "$env:ComputerName.$Domain"

        # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
        if (!$(Check-Elevation)) {
            try {
                $global:ElevatedPSSession = New-PSSession -Name "TempElevatedSession "-Authentication CredSSP -Credential $Credentials -ErrorAction SilentlyContinue
                if (!$ElevatedPSSession) {
                    throw
                }
                $CredSSPAlreadyConfigured = $true
            }
            catch {
                $SudoSession = New-SudoSession -Credentials $Credentials
                $ElevatedPSSession = $SudoSession.ElevatedPSSession
                $NeedToRevertAdminChangesIfAny = $true
            }
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        if ($PSVersionTable.PSVersion.Major -lt 5) {
            if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
                Write-Host "Downlaoding PackageManagement .msi installer..."
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi"` -OutFile "$HOME\Downloads\PackageManagement_x64.msi"
                msiexec /i "$HOME\Downloads\PackageManagement_x64.msi" /quiet /norestart ACCEPTEULA=1
                Start-Sleep -Seconds 3
            }
            while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
                Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
                Start-Sleep -Seconds 1
            }
            Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
        }

        $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PackageManagement"}).Version | Measure-Object -Maximum).Maximum
        $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

        if ($(Get-Module).Name -notcontains "PackageManagement") {
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        }
        if ($(Get-Module).Name -notcontains "PowerShellGet") {
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
        }
        # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
        # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
        # do it beforehand.
        if ($(Get-PackageProvider).Name -notcontains "NuGet") {
            Install-PackageProvider "NuGet" -Scope CurrentUser -Force
            Register-PackageSource -Name 'nuget.org' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap

            # Instead, we'll install the NuGet CLI from the Chocolatey repo...
            Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
            # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
            Set-PackageSource -Name Chocolatey -Trusted

            Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
            while (!$(Find-Package Nuget.CommandLine)) {
                Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                Start-Sleep -Seconds 2
            }

            # Next, install the NuGet CLI using the Chocolatey Repo
            if (Check-Elevation) {
                Install-Package Nuget.CommandLine -Source chocolatey
            }
            else {
                if ($ElevatedPSSession) {
                    Invoke-Command -Session $ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}
                }
            }
            
            # Ensure $env:Path includes C:\Chocolatey\bin
            if ($($env:Path -split ";") -notcontains "C:\Chocolatey\bin") {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path`C:\Chocolatey\bin"
                }
                else {
                    $env:Path = "$env:Path;C:\Chocolatey\bin"
                }
            }
            # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
            $NuGetSymlinkTest = Get-ChildItem "C:\Chocolatey\bin" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
            $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
            $TestRealNuGetPath = Test-Path $RealNuGetPath
            if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
                if (Check-Elevation) {
                    New-Item -Path C:\Chocolatey\bin\NuGet.exe -ItemType SymbolicLink -Value $RealNuGetPath
                }
                else {
                    if ($ElevatedPSSession) {
                        Invoke-Command -Session $ElevatedPSSession -Scriptblock {New-Item -Path C:\Chocolatey\bin\NuGet.exe -ItemType SymbolicLink -Value $using:RealNuGetPath}
                    }
                }
            }
        }
        # Next, set the PSGallery PowerShellGet PackageProvider Source to Trusted
        if ($(Get-PackageSource | Where-Object {$_.Name -eq "PSGallery"}).IsTrusted -eq $False) {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }

        # Next, update PackageManagement and PowerShellGet where possible
        [version]$MinimumVer = "1.0.0.1"
        $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
        $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version
        Write-Host "PackageManagement Latest Version is: $PackageManagementLatestVersion"
        Write-Host "PowerShellGetLatestVersion Latest Version is: $PowerShellGetLatestVersion"

        # Take care of updating PowerShellGet before PackageManagement since PackageManagement won't be able to update with PowerShellGet
        # still loaded in the current PowerShell Session
        if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
            }
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PackageManagementLatestVersion -Force
                Write-Host "Installing latest version of PackageManagement..."
                if (Check-Elevation) {
                    Install-Module -Name "PackageManagement" -Force
                }
                else {
                    if ($ElevatedPSSession) {
                        Invoke-Command -Session $ElevatedPSSession -Scriptblock {Install-Module -Name "PackageManagement" -RequiredVersion $using:PackageManagementLatestVersion -Force}
                    }
                }
                
            }
        }
        if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                # Before Updating the PowerShellGet Module, we must unload it from the current PowerShell Session
                # Remove-Module -Name "PowerShellGet"
                # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
                # and it will not update it.
                #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
                Write-Host "Installing latest version of PowerShellGet..."
                if (Check-Elevation) {
                    Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
                }
                else {
                    if ($ElevatedPSSession) {
                        Invoke-Command -Session $ElevatedPSSession -Scriptblock {Install-Module -Name "PowerShellGet" -RequiredVersion $using:PowerShellGetLatestVersion -Force}
                    }
                }
                
            }
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force
                Write-Host "Installing latest version of PowerShellGet..."
                if (Check-Elevation) {
                    Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
                }
                else {
                    if ($ElevatedPSSession) {
                        Invoke-Command -Session $ElevatedPSSession -Scriptblock {Install-Module -Name "PowerShellGet" -RequiredVersion $using:PowerShellGetLatestVersion -Force}
                    }
                }
            }
        }

        # Reset the LatestLocallyAvailableVersion variables to reflect latest available, and then load them into the current session
        $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PackageManagement"}).Version | Measure-Object -Maximum).Maximum
        $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

        Remove-Module -Name "PowerShellGet"
        Remove-Module -Name "PackageManagement"

        if ($(Get-Host).Name -ne "Package Manager Host") {
            Write-Host "We are NOT in the Visual Studio Package Management Console. Continuing..."
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion

            # Make sure all Repos Are Trusted
            $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
            $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
            foreach ($RepoObject in $RepoObjectsForTrustCheck) {
                if ($RepoObject.IsTrusted -ne $true) {
                    Set-PackageSource -Name $RepoObject.Name -Trusted
                }
            }
        }
        if ($(Get-Host).Name -eq "Package Manager Host") {
            Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet

            # Make sure all Repos Are Trusted
            $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
            $RepoObjectsForTrustCheck = Get-PackManPackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
            foreach ($RepoObject in $RepoObjectsForTrustCheck) {
                if ($RepoObject.IsTrusted -ne $true) {
                    Set-PackManPackageSource -Name $RepoObject.Name -Trusted
                }
            }
        }

        if ($NeedToRevertAdminChangesIfAny) {
            Remove-SudoSession -Credentials $Credentials -OriginalConfigInfo $SudoSession.OriginalWSManAndRegistryStatus -SessionToRemove $SudoSession.ElevatedPSSession
        }
    }

    function Unzip-File {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,Position=0)]
            [string]$PathToZip,
            [Parameter(Mandatory=$true,Position=1)]
            [string]$TargetDir
        )
        
        Write-Host "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        # Load System.IO.Compression.Filesystem 
        [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

        # Unzip file
        [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
    }

    <#
    .Synopsis
        Refactored From: https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

        Provides access to Windows CredMan basic functionality for client scripts

        ****************** IMPORTANT ******************
        *
        * If you use this script from the PS console, you 
        * should ALWAYS pass the Target, User and Password
        * parameters using single quotes:
        * 
        *   .\CredMan.ps1 -AddCred -Target 'http://server' -User 'JoeSchmuckatelli' -Pass 'P@55w0rd!'
        * 
        * to prevent PS misinterpreting special characters 
        * you might use as PS reserved characters
        * 
        ****************** IMPORTANT ******************

    .Description
        Provides the following API when dot-sourced
        Del-Cred
        Enum-Creds
        Read-Cred
        Write-Cred

        Supports the following cmd-line actions
        AddCred (requires -User, -Pass; -Target is optional)
        DelCred (requires -Target)
        GetCred (requires -Target)
        RunTests (no cmd-line opts)
        ShoCred (optional -All parameter to dump cred objects to console)

    .INPUTS
        See function-level notes

    .OUTPUTS
          Cmd-line usage: console output relative to success or failure state
          Dot-sourced usage:
          ** Successful Action **
          * Del-Cred   : Int = 0
          * Enum-Cred  : PsUtils.CredMan+Credential[]
          * Read-Cred  : PsUtils.CredMan+Credential
          * Write-Cred : Int = 0
          ** Failure **
          * All API    : Management.Automation.ErrorRecord

    .NOTES
        Author: Jim Harrison (jim@isatools.org)
        Date  : 2012/05/20
        Vers  : 1.5

        Updates:
        2012/10/13
                - Fixed a bug where the script would only read, write or delete GENERIC 
                credentials types. 
                    - Added #region blocks to clarify internal functionality
                    - Added 'CredType' param to specify what sort of credential is to be read, 
                    created or deleted (not used for -ShoCred or Enum-Creds)
                    - Added 'CredPersist' param to specify how the credential is to be stored;
                    only used in Write-Cred
                    - Added 'All' param for -ShoCreds to differentiate between creds summary
                    list and detailed creds dump
                    - Added CRED_FLAGS enum to make the credential struct flags values clearer
                    - Improved parameter validation
                    - Expanded internal help (used with Get-Help cmdlet)
                    - Cmd-line functions better illustrate how to interpret the results when 
                    dot-sourcing the script

    .PARAMETER AddCred
        Specifies that you wish to add a new credential or update an existing credentials
        -Target, -User and -Pass parameters are required for this action

    .PARAMETER Comment
        Specifies the information you wish to place in the credentials comment field

    .PARAMETER CredPersist
        Specifies the credentials storage persistence you wish to use
        Valid values are: "SESSION", "LOCAL_MACHINE", "ENTERPRISE"
        NOTE: if not specified, defaults to "ENTERPRISE"
        
    .PARAMETER CredType
        Specifies the type of credential object you want to store
        Valid values are: "GENERIC", "DOMAIN_PASSWORD", "DOMAIN_CERTIFICATE",
        "DOMAIN_VISIBLE_PASSWORD", "GENERIC_CERTIFICATE", "DOMAIN_EXTENDED",
        "MAXIMUM", "MAXIMUM_EX"
        NOTE: if not specified, defaults to "GENERIC"
        ****************** IMPORTANT ******************
        *
        * I STRONGLY recommend that you become familiar 
        * with http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        * before you create new credentials with -CredType other than "GENERIC"
        * 
        ****************** IMPORTANT ******************

    .PARAMETER DelCred
        Specifies that you wish to remove an existing credential
        -CredType may be required to remove the correct credential if more than one is
        specified for a target

    .PARAMETER GetCred
        Specifies that you wish to retrieve an existing credential
        -CredType may be required to access the correct credential if more than one is
        specified for a target

    .PARAMETER Pass
        Specifies the credentials password

    .PARAMETER RunTests
        Specifies that you wish to run built-in Win32 CredMan functionality tests

    .PARAMETER ShoCred
        Specifies that you wish to retrieve all credential stored for the interactive user
        -All parameter may be used to indicate that you wish to view all credentials properties
        (default display is a summary list)

    .PARAMETER Target
        Specifies the authentication target for the specified credentials
        If not specified, the -User information is used

    .PARAMETER User
        Specifies the credentials username
        

    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://blogs.msdn.com/b/peerchan/archive/2005/11/01/487834.aspx

    .EXAMPLE
        .\CredMan.ps1 -AddCred -Target 'http://aserver' -User 'UserName' -Password 'P@55w0rd!' -Comment 'cuziwanna'
        Stores the credential for 'UserName' with a password of 'P@55w0rd!' for authentication against 'http://aserver' and adds a comment of 'cuziwanna'

    .EXAMPLE
        .\CredMan.ps1 -DelCred -Target 'http://aserver' -CredType 'DOMAIN_PASSWORD'
        Removes the credential used for the target 'http://aserver' as credentials type 'DOMAIN_PASSWORD'

    .EXAMPLE
        .\CredMan.ps1 -GetCred -Target 'http://aserver'
        Retreives the credential used for the target 'http://aserver'

    .EXAMPLE
        .\CredMan.ps1 -ShoCred
        Retrieves a summary list of all credentials stored for the interactive user

    .EXAMPLE
        .\CredMan.ps1 -ShoCred -All
        Retrieves a detailed list of all credentials stored for the interactive user

    #>

    #requires -version 2

    function Manage-StoredCredentials {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false)]
            [Switch] $AddCred,

            [Parameter(Mandatory=$false)]
            [Switch]$DelCred,
            
            [Parameter(Mandatory=$false)]
            [Switch]$GetCred,
            
            [Parameter(Mandatory=$false)]
            [Switch]$ShoCred,

            [Parameter(Mandatory=$false)]
            [Switch]$RunTests,
            
            [Parameter(Mandatory=$false)]
            [ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>]
            [String]$Target,

            [Parameter(Mandatory=$false)]
            [ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>]
            [String]$User,

            [Parameter(Mandatory=$false)]
            [ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>]
            [String]$Pass,

            [Parameter(Mandatory=$false)]
            [ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>]
            [String]$Comment,

            [Parameter(Mandatory=$false)]
            [Switch]$All,

            [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
            "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC",

            [Parameter(Mandatory=$false)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String]$CredPersist = "ENTERPRISE"
        )

        #region Pinvoke
        #region Inline C#
        [String] $PsCredmanUtils = @"
        using System;
        using System.Runtime.InteropServices;

        namespace PsUtils
        {
            public class CredMan
            {
                #region Imports
                // DllImport derives from System.Runtime.InteropServices
                [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
                private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

                [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
                private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

                [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
                private static extern void CredFree([In] IntPtr cred);

                [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
                private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

                [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
                private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
                #endregion

                #region Fields
                public enum CRED_FLAGS : uint
                {
                    NONE = 0x0,
                    PROMPT_NOW = 0x2,
                    USERNAME_TARGET = 0x4
                }

                public enum CRED_ERRORS : uint
                {
                    ERROR_SUCCESS = 0x0,
                    ERROR_INVALID_PARAMETER = 0x80070057,
                    ERROR_INVALID_FLAGS = 0x800703EC,
                    ERROR_NOT_FOUND = 0x80070490,
                    ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
                    ERROR_BAD_USERNAME = 0x8007089A
                }

                public enum CRED_PERSIST : uint
                {
                    SESSION = 1,
                    LOCAL_MACHINE = 2,
                    ENTERPRISE = 3
                }

                public enum CRED_TYPE : uint
                {
                    GENERIC = 1,
                    DOMAIN_PASSWORD = 2,
                    DOMAIN_CERTIFICATE = 3,
                    DOMAIN_VISIBLE_PASSWORD = 4,
                    GENERIC_CERTIFICATE = 5,
                    DOMAIN_EXTENDED = 6,
                    MAXIMUM = 7,      // Maximum supported cred type
                    MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                public struct Credential
                {
                    public CRED_FLAGS Flags;
                    public CRED_TYPE Type;
                    public string TargetName;
                    public string Comment;
                    public DateTime LastWritten;
                    public UInt32 CredentialBlobSize;
                    public string CredentialBlob;
                    public CRED_PERSIST Persist;
                    public UInt32 AttributeCount;
                    public IntPtr Attributes;
                    public string TargetAlias;
                    public string UserName;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct NativeCredential
                {
                    public CRED_FLAGS Flags;
                    public CRED_TYPE Type;
                    public IntPtr TargetName;
                    public IntPtr Comment;
                    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                    public UInt32 CredentialBlobSize;
                    public IntPtr CredentialBlob;
                    public UInt32 Persist;
                    public UInt32 AttributeCount;
                    public IntPtr Attributes;
                    public IntPtr TargetAlias;
                    public IntPtr UserName;
                }
                #endregion

                #region Child Class
                private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
                {
                    public CriticalCredentialHandle(IntPtr preexistingHandle)
                    {
                        SetHandle(preexistingHandle);
                    }

                    private Credential XlateNativeCred(IntPtr pCred)
                    {
                        NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                        Credential cred = new Credential();
                        cred.Type = ncred.Type;
                        cred.Flags = ncred.Flags;
                        cred.Persist = (CRED_PERSIST)ncred.Persist;

                        long LastWritten = ncred.LastWritten.dwHighDateTime;
                        LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                        cred.LastWritten = DateTime.FromFileTime(LastWritten);

                        cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                        cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                        cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                        cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                        cred.CredentialBlobSize = ncred.CredentialBlobSize;
                        if (0 < ncred.CredentialBlobSize)
                        {
                            cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                        }
                        return cred;
                    }

                    public Credential GetCredential()
                    {
                        if (IsInvalid)
                        {
                            throw new InvalidOperationException("Invalid CriticalHandle!");
                        }
                        Credential cred = XlateNativeCred(handle);
                        return cred;
                    }

                    public Credential[] GetCredentials(int count)
                    {
                        if (IsInvalid)
                        {
                            throw new InvalidOperationException("Invalid CriticalHandle!");
                        }
                        Credential[] Credentials = new Credential[count];
                        IntPtr pTemp = IntPtr.Zero;
                        for (int inx = 0; inx < count; inx++)
                        {
                            pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                            Credential cred = XlateNativeCred(pTemp);
                            Credentials[inx] = cred;
                        }
                        return Credentials;
                    }

                    override protected bool ReleaseHandle()
                    {
                        if (IsInvalid)
                        {
                            return false;
                        }
                        CredFree(handle);
                        SetHandleAsInvalid();
                        return true;
                    }
                }
                #endregion

                #region Custom API
                public static int CredDelete(string target, CRED_TYPE type)
                {
                    if (!CredDeleteW(target, type, 0))
                    {
                        return Marshal.GetHRForLastWin32Error();
                    }
                    return 0;
                }

                public static int CredEnum(string Filter, out Credential[] Credentials)
                {
                    int count = 0;
                    int Flags = 0x0;
                    if (string.IsNullOrEmpty(Filter) ||
                        "*" == Filter)
                    {
                        Filter = null;
                        if (6 <= Environment.OSVersion.Version.Major)
                        {
                            Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                        }
                    }
                    IntPtr pCredentials = IntPtr.Zero;
                    if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
                    {
                        Credentials = null;
                        return Marshal.GetHRForLastWin32Error(); 
                    }
                    CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
                    Credentials = CredHandle.GetCredentials(count);
                    return 0;
                }

                public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
                {
                    IntPtr pCredential = IntPtr.Zero;
                    Credential = new Credential();
                    if (!CredReadW(target, type, 0, out pCredential))
                    {
                        return Marshal.GetHRForLastWin32Error();
                    }
                    CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
                    Credential = CredHandle.GetCredential();
                    return 0;
                }

                public static int CredWrite(Credential userCredential)
                {
                    if (!CredWriteW(ref userCredential, 0))
                    {
                        return Marshal.GetHRForLastWin32Error();
                    }
                    return 0;
                }

                #endregion

                private static int AddCred()
                {
                    Credential Cred = new Credential();
                    string Password = "Password";
                    Cred.Flags = 0;
                    Cred.Type = CRED_TYPE.GENERIC;
                    Cred.TargetName = "Target";
                    Cred.UserName = "UserName";
                    Cred.AttributeCount = 0;
                    Cred.Persist = CRED_PERSIST.ENTERPRISE;
                    Cred.CredentialBlobSize = (uint)Password.Length;
                    Cred.CredentialBlob = Password;
                    Cred.Comment = "Comment";
                    return CredWrite(Cred);
                }

                private static bool CheckError(string TestName, CRED_ERRORS Rtn)
                {
                    switch(Rtn)
                    {
                        case CRED_ERRORS.ERROR_SUCCESS:
                            Console.WriteLine(string.Format("'{0}' worked", TestName));
                            return true;
                        case CRED_ERRORS.ERROR_INVALID_FLAGS:
                        case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                        case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                        case CRED_ERRORS.ERROR_NOT_FOUND:
                        case CRED_ERRORS.ERROR_BAD_USERNAME:
                            Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                            break;
                        default:
                            Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                            break;
                    }
                    return false;
                }

                /*
                 * Note: the Main() function is primarily for debugging and testing in a Visual 
                 * Studio session.  Although it will work from PowerShell, it's not very useful.
                 */
                public static void Main()
                {
                    Credential[] Creds = null;
                    Credential Cred = new Credential();
                    int Rtn = 0;

                    Console.WriteLine("Testing CredWrite()");
                    Rtn = AddCred();
                    if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
                    {
                        return;
                    }
                    Console.WriteLine("Testing CredEnum()");
                    Rtn = CredEnum(null, out Creds);
                    if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
                    {
                        return;
                    }
                    Console.WriteLine("Testing CredRead()");
                    Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                    if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                    {
                        return;
                    }
                    Console.WriteLine("Testing CredDelete()");
                    Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
                    if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
                    {
                        return;
                    }
                    Console.WriteLine("Testing CredRead() again");
                    Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                    if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                    {
                        Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
                    }
                }
            }
        }
"@
        #endregion

        $PsCredMan = $null
        try
        {
            $PsCredMan = [PsUtils.CredMan]
        }
        catch
        {
            #only remove the error we generate
            #$Error.RemoveAt($Error.Count-1)
        }
        if($null -eq $PsCredMan)
        {
            Add-Type $PsCredmanUtils
        }
        #endregion

        #region Internal Tools
        [HashTable] $ErrorCategory = @{0x80070057 = "InvalidArgument";
                                       0x800703EC = "InvalidData";
                                       0x80070490 = "ObjectNotFound";
                                       0x80070520 = "SecurityError";
                                       0x8007089A = "SecurityError"}

        function Get-CredType {
            Param (
                [Parameter(Mandatory=$true)]
                [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
                "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
                [String]$CredType
            )
            
            switch($CredType) {
                "GENERIC" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC}
                "DOMAIN_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD}
                "DOMAIN_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE}
                "DOMAIN_VISIBLE_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD}
                "GENERIC_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE}
                "DOMAIN_EXTENDED" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED}
                "MAXIMUM" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM}
                "MAXIMUM_EX" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX}
            }
        }

        function Get-CredPersist {
            Param (
                [Parameter(Mandatory=$true)]
                [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
                [String] $CredPersist
            )
            
            switch($CredPersist) {
                "SESSION" {return [PsUtils.CredMan+CRED_PERSIST]::SESSION}
                "LOCAL_MACHINE" {return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE}
                "ENTERPRISE" {return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE}
            }
        }
        #endregion

        #region Dot-Sourced API
        function Del-Creds {
        <#
        .Synopsis
            Deletes the specified credentials

        .Description
            Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

        .INPUTS
            See function-level notes

        .OUTPUTS
            0 or non-0 according to action success
            [Management.Automation.ErrorRecord] if error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

            Param (
                [Parameter(Mandatory=$true)]
                [ValidateLength(1,32767)]
                [String] $Target,

                [Parameter(Mandatory=$false)]
                [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
                "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
                [String] $CredType = "GENERIC"
            )
            
            [Int]$Results = 0
            try {
                $Results = [PsUtils.CredMan]::CredDelete($Target, $(Get-CredType $CredType))
            }
            catch {
                return $_
            }
            if(0 -ne $Results) {
                [String]$Msg = "Failed to delete credentials store for target '$Target'"
                [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
                [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
                return $ErrRcd
            }
            return $Results
        }

        function Enum-Creds {
        <#
        .Synopsis
          Enumerates stored credentials for operating user

        .Description
          Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

        .INPUTS
          
        .OUTPUTS
          [PsUtils.CredMan+Credential[]] if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Filter
          Specifies the filter to be applied to the query
          Defaults to [String]::Empty
          
        #>

            Param (
                [Parameter(Mandatory=$false)]
                [AllowEmptyString()]
                [String]$Filter = [String]::Empty
            )
            
            [PsUtils.CredMan+Credential[]]$Creds = [Array]::CreateInstance([PsUtils.CredMan+Credential], 0)
            [Int]$Results = 0
            try {
                $Results = [PsUtils.CredMan]::CredEnum($Filter, [Ref]$Creds)
            }
            catch {
                return $_
            }
            switch($Results) {
                0 {break}
                0x80070490 {break} #ERROR_NOT_FOUND
                default {
                    [String]$Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
                    [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
                    [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
                    return $ErrRcd
                }
            }
            return $Creds
        }

        function Read-Creds {
        <#
        .Synopsis
            Reads specified credentials for operating user

        .Description
            Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

        .INPUTS

        .OUTPUTS
            [PsUtils.CredMan+Credential] if successful
            [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
            If not provided, the username is used as the target
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

            Param (
                [Parameter(Mandatory=$true)]
                [ValidateLength(1,32767)]
                [String]$Target,

                [Parameter(Mandatory=$false)]
                [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
                "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
                [String]$CredType = "GENERIC"
            )
            
            #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
            if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) { 
                [String]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
                [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
                [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
                return $ErrRcd
            }
            [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
            [Int]$Results = 0
            try {
                $Results = [PsUtils.CredMan]::CredRead($Target, $(Get-CredType $CredType), [Ref]$Cred)
            }
            catch {
                return $_
            }
            
            switch($Results) {
                0 {break}
                0x80070490 {return $null} #ERROR_NOT_FOUND
                default {
                    [String] $Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
                    [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
                    [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
                    return $ErrRcd
                }
            }
            return $Cred
        }

        function Write-Creds {
        <#
        .Synopsis
          Saves or updates specified credentials for operating user

        .Description
          Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

        .INPUTS

        .OUTPUTS
          [Boolean] true if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
          Specifies the URI for which the credentials are associated
          If not provided, the username is used as the target
          
        .PARAMETER UserName
          Specifies the name of credential to be read
          
        .PARAMETER Password
          Specifies the password of credential to be read
          
        .PARAMETER Comment
          Allows the caller to specify the comment associated with 
          these credentials
          
        .PARAMETER CredType
          Specifies the desired credentials type; defaults to 
          "CRED_TYPE_GENERIC"

        .PARAMETER CredPersist
          Specifies the desired credentials storage type;
          defaults to "CRED_PERSIST_ENTERPRISE"
        #>

            Param (
                [Parameter(Mandatory=$false)]
                [ValidateLength(0,32676)]
                [String]$Target,

                [Parameter(Mandatory=$true)]
                [ValidateLength(1,512)]
                [String]$UserName,

                [Parameter(Mandatory=$true)]
                [ValidateLength(1,512)]
                [String]$Password,

                [Parameter(Mandatory=$false)]
                [ValidateLength(0,256)]
                [String]$Comment = [String]::Empty,

                [Parameter(Mandatory=$false)]
                [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
                "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
                [String]$CredType = "GENERIC",

                [Parameter(Mandatory=$false)]
                [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
                [String]$CredPersist = "ENTERPRISE"
            )

            if ([String]::IsNullOrEmpty($Target)) {
                $Target = $UserName
            }
            #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
            if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) {
                [String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
                [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
                [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
                return $ErrRcd
            }
            if ([String]::IsNullOrEmpty($Comment)) {
                $Comment = [String]::Format("Last edited by {0}\{1} on {2}",$Env:UserDomain,$Env:UserName,$Env:ComputerName)
            }
            [String]$DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
            [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
            
            switch($Target -eq $UserName -and 
            $("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType)) {
                $true  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET}
                $false  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::NONE}
            }
            $Cred.Type = Get-CredType $CredType
            $Cred.TargetName = $Target
            $Cred.UserName = $UserName
            $Cred.AttributeCount = 0
            $Cred.Persist = Get-CredPersist $CredPersist
            $Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
            $Cred.CredentialBlob = $Password
            $Cred.Comment = $Comment

            [Int] $Results = 0
            try {
                $Results = [PsUtils.CredMan]::CredWrite($Cred)
            }
            catch {
                return $_
            }

            if(0 -ne $Results) {
                [String] $Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
                [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
                [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
                return $ErrRcd
            }
            return $Results
        }

        #endregion

        #region Cmd-Line functionality
        function CredManMain {
        #region Adding credentials
            if ($AddCred) {
                if([String]::IsNullOrEmpty($User) -or [String]::IsNullOrEmpty($Pass)) {
                    Write-Host "You must supply a user name and password (target URI is optional)."
                    return
                }
                # may be [Int32] or [Management.Automation.ErrorRecord]
                [Object]$Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
                if (0 -eq $Results) {
                    [Object]$Cred = Read-Creds $Target $CredType
                    if ($null -eq $Cred) {
                        Write-Host "Credentials for '$Target', '$User' was not found."
                        return
                    }
                    if ($Cred -is [Management.Automation.ErrorRecord]) {
                        return $Cred
                    }

                    New-Variable -Name "AddedCredentialsObject" -Value $(
                        [pscustomobject][ordered]@{
                            UserName    = $($Cred.UserName)
                            Password    = $($Cred.CredentialBlob)
                            Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                            Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                            Comment     = $($Cred.Comment)
                        }
                    )

                    return $AddedCredentialsObject
                }
                # will be a [Management.Automation.ErrorRecord]
                return $Results
            }
        #endregion  

        #region Removing credentials
            if ($DelCred) {
                if (-not $Target) {
                    Write-Host "You must supply a target URI."
                    return
                }
                # may be [Int32] or [Management.Automation.ErrorRecord]
                [Object]$Results = Del-Creds $Target $CredType 
                if (0 -eq $Results) {
                    Write-Host "Successfully deleted credentials for '$Target'"
                    return
                }
                # will be a [Management.Automation.ErrorRecord]
                return $Results
            }
        #endregion

        #region Reading selected credential
            if ($GetCred) {
                if(-not $Target) {
                    Write-Host "You must supply a target URI."
                    return
                }
                # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
                [Object]$Cred = Read-Creds $Target $CredType
                if ($null -eq $Cred) {
                    Write-Host "Credential for '$Target' as '$CredType' type was not found."
                    return
                }
                if ($Cred -is [Management.Automation.ErrorRecord]) {
                    return $Cred
                }

                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                )

                return $AddedCredentialsObject
            }
        #endregion

        #region Reading all credentials
            if ($ShoCred) {
                # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
                [Object]$Creds = Enum-Creds
                if ($Creds -split [Array] -and 0 -eq $Creds.Length) {
                    Write-Host "No Credentials found for $($Env:UserName)"
                    return
                }
                if ($Creds -is [Management.Automation.ErrorRecord]) {
                    return $Creds
                }

                $ArrayOfCredObjects = @()
                foreach($Cred in $Creds) {
                    New-Variable -Name "AddedCredentialsObject" -Value $(
                        [pscustomobject][ordered]@{
                            UserName    = $($Cred.UserName)
                            Password    = $($Cred.CredentialBlob)
                            Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                            Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                            Comment     = $($Cred.Comment)
                        }
                    ) -Force

                    if ($All) {
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Alias" -Value "$($Cred.TargetAlias)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "AttribCnt" -Value "$($Cred.AttributeCount)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Attribs" -Value "$($Cred.Attributes)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Flags" -Value "$($Cred.Flags)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "PwdSize" -Value "$($Cred.CredentialBlobSize)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Storage" -Value "$($Cred.Persist)"
                        $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Type" -Value "$($Cred.Type)"
                    }

                    $ArrayOfCredObjects +=, $AddedCredentialsObject
                }
                return $ArrayOfCredObjects
            }
        #endregion

        #region Run basic diagnostics
            if($RunTests) {
                [PsUtils.CredMan]::Main()
            }
        #endregion
        }
        #endregion

        CredManMain
    }

    Function Check-InstalledPrograms {
        [CmdletBinding(
            PositionalBinding=$True,
            DefaultParameterSetName='Default Param Set'
        )]
        Param(
            [Parameter(
                Mandatory=$False,
                ParameterSetName='Default Param Set'
            )]
            [string]$ProgramTitleSearchTerm,

            [Parameter(
                Mandatory=$False,
                ParameterSetName='Default Param Set'
            )]
            [string[]]$HostName = $env:COMPUTERNAME,

            [Parameter(
                Mandatory=$False,
                ParameterSetName='Secondary Param Set'
            )]
            [switch]$AllADWindowsComputers

        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $RegPaths = @("HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####
        # Get a list of Windows Computers from AD
        if ($AllADWindowsComputers) {
            $ComputersArray = $(Get-ADComputer -Filter * -Property * | Where-Object {$_.OperatingSystem -like "*Windows*"}).Name
        }
        else {
            $ComputersArray = $HostName
        }

        foreach ($computer in $ComputersArray) {
            if ($computer -eq $env:COMPUTERNAME -or $computer.Split("\.")[0] -eq $env:COMPUTERNAME) {
                try {
                    $InstalledPrograms = foreach ($regpath in $RegPaths) {Get-ItemProperty $regpath}
                    if (!$?) {
                        throw
                    }
                }
                catch {
                    Write-Warning "Unable to find registry path(s) on $computer. Skipping..."
                    continue
                }
            }
            else {
                try {
                    $InstalledPrograms = Invoke-Command -ComputerName $computer -ScriptBlock {
                        foreach ($regpath in $RegPaths) {
                            Get-ItemProperty $regpath
                        }
                    } -ErrorAction SilentlyContinue
                    if (!$?) {
                        throw
                    }
                }
                catch {
                    Write-Warning "Unable to connect to $computer. Skipping..."
                    continue
                }
            }

            if ($ProgramTitleSearchTerm) {
                $InstalledPrograms | Where-Object {$_.DisplayName -like "*$ProgramTitleSearchTerm*"}
            }
            else {
                $InstalledPrograms
            }
        }

        ##### END Main Body #####

    }

    function Initialize-GitEnvironment {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [switch]$SkipSSHSetup = $false,

            [Parameter(Mandatory=$False)]
            [string]$ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa"

        )

        # Check to make sure Git Desktop is Installed
        $GitDesktopCheck1 = Check-InstalledPrograms -ProgramTitleSearchTerm "GitDesktop"
        $GitDesktopCheck2 = Resolve-Path "$env:LocalAppData\GitHub\PoshGit_*" -ErrorAction SilentlyContinue
        $GitDesktopCheck3 = Resolve-Path "$env:LocalAppData\GitHub\PortableGit_*" -ErrorAction SilentlyContinue
        $GitDesktopCheck4 = $(Get-ChildItem -Recurse -Path "$env:LocalAppData\Apps" | Where-Object {$_.Name -match "^gith..tion*" -and $_.FullName -notlike "*manifests*" -and $_.FullName -notlike "*\Data\*"}).FullName
        if (!$GitDesktopCheck1 -and !$GitDesktopCheck2 -and !$GitDesktopCheck3 -and !$GitDesktopCheck4) {
            Write-Verbose "GitDesktop is NOT currently installed! Halting!"
            Write-Error "GitDesktop is NOT currently installed! Halting!"
            $global:FunctionResult = "1"
            return
        }


        # Set the Git PowerShell Environment
        if ($env:github_shell -eq $null) {
            $env:github_posh_git = $(Resolve-Path "$env:LocalAppData\GitHub\PoshGit_*" -ErrorAction Continue).Path
            $env:github_git = $(Resolve-Path "$env:LocalAppData\GitHub\PortableGit_*" -ErrorAction Continue).Path
            $env:PLINK_PROTOCOL = "ssh"
            $env:TERM = "msys"
            $env:HOME = $HOME
            $env:TMP = $env:TEMP = [system.io.path]::gettemppath()
            if ($env:EDITOR -eq $null) {
              $env:EDITOR = "GitPad"
            }

            # Setup PATH
            $pGitPath = $env:github_git
            #$appPath = Resolve-Path "$env:LocalAppData\Apps\2.0\XE9KPQJJ.N9E\GALTN70J.73D\gith..tion_317444273a93ac29_0003.0003_5794af8169eeff14"
            $appPath = $(Get-ChildItem -Recurse -Path "$env:LocalAppData\Apps" | Where-Object {$_.Name -match "^gith..tion*" -and $_.FullName -notlike "*manifests*" -and $_.FullName -notlike "*\Data\*"}).FullName
            while (!$appPath) {
                Write-Host "Waiting for `$appPath..."
                $appPath = $(Get-ChildItem -Recurse -Path "$env:LocalAppData\Apps" | Where-Object {$_.Name -match "^gith..tion*" -and $_.FullName -notlike "*manifests*" -and $_.FullName -notlike "*\Data\*"}).FullName
                Start-Sleep -Seconds 1
            }
            $HighestNetVer = $($(Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework" | Where-Object {$_.Name -match "^v[0-9]"}).Name -replace "v","" | Measure-Object -Maximum).Maximum
            $msBuildPath = "$env:SystemRoot\Microsoft.NET\Framework\v$HighestNetVer"
            $lfsamd64Path = "$env:LocalAppData\GitHub\lfs-amd*"

            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$pGitPath\cmd;$pGitPath\usr\bin;$pGitPath\usr\share\git-tfs;$lfsamd64Path;$appPath;$msBuildPath"
            }
            else {
                $env:Path = "$env:Path;$pGitPath\cmd;$pGitPath\usr\bin;$pGitPath\usr\share\git-tfs;$lfsamd64Path;$appPath;$msBuildPath"
            }

            $env:github_shell = $true
            $env:git_install_root = $pGitPath
            if ($env:github_posh_git) {
                $env:posh_git = "$env:github_posh_git\profile.example.ps1"
            }

            # Setup SSH
            if (!$SkipSSHSetup) {
                & "$appPath\GitHub.exe" --set-up-ssh

                if (!$(Get-Module -List -Name posh-git)) {
                    if ($PSVersionTable.PSVersion.Major -ge 5) {
                        Install-Module posh-git -Scope CurrentUser
                        Import-Module posh-git -Verbose
                    }
                    if ($PSVersionTable.PSVersion.Major -lt 5) {
                        Update-PackageManagement
                        Install-Module posh-git -Scope CurrentUser
                        Import-Module posh-git -Verbose
                    }
                }
                Start-SshAgent
                Add-SshKey $ExistingSSHPrivateKeyPath
            }
        } 
        else {
            Write-Verbose "GitHub shell environment already setup"
        }
    }


    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
    if (! $(Test-Path "$HOME\Documents\GitHub")) {
        Write-Verbose "The path $HOME\Documents\GitHub was not found! Is Git Desktop Installed? Halting!"
        Write-Error "The path $HOME\Documents\GitHub was not found! Is Git Desktop Installed? Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    Set-Location "$HOME\Documents\GitHub"

    if (!$(Get-Command git -ErrorAction SilentlyContinue)) {
        $global:FunctionResult = "0"
        Initialize-GitEnvironment
        if ($global:FunctionResult -eq "1") {
            Write-Verbose "The Initialize-GitEnvironment function failed! Halting!"
            Write-Error "The Initialize-GitEnvironment function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    git config --global user.name "$GitHubUserName"
    git config --global user.email "$GitHubEmail"


    if ($AuthMethod -eq "https") {
        git config --global credential.helper wincred


        $ManageStoredCredsParams = @{
            Target  = "git:https://$PersonalAccessToken@github.com"
            User    = $PersonalAccessToken
            Pass    = 'x-oauth-basic'
            Comment = "Saved By Manage-StoredCredentials.ps1"
        }

        Manage-StoredCredentials -AddCred @ManageStoredCredsParams

        # Test https OAuth2 authentication
        # More info here: https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell
        $Token = "$GitHubUserName`:$PersonalAccessToken"
        $Base64Token = [System.Convert]::ToBase64String([char[]]$Token)
        $Headers = @{
            Authorization = "Basic {0}" -f $Base64Token
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessToken").Name
        Write-Host "Writing Public and Private Repos to demonstrate https authentication success..."
        Write-Host "$($PublicAndPrivateRepos -join ", ") "
    }

    if ($AuthMethod -eq "ssh") {
        # Setup OpenSSH-Win32 if it isn't already
        try {
            $OpenSSHWin32Check = Get-Command ssh-keygen
        }
        catch {
            Write-Verbose "ssh-keygen is not part of PowerShell PATH"
        }
        if (!$OpenSSHWin32Check) {
            $OpenSSHWin32ReleaseSiteContent = Invoke-WebRequest -Uri "https://github.com/PowerShell/Win32-OpenSSH/releases"
            $OpenSSHWin32ReleaseLinks = $OpenSSHWin32ReleaseSiteContent.Links | Where-Object {$_.href -like "*/download/*" -and $_.href -like "*Win32.zip*"}
            $OpenSSHWin32Versions = $OpenSSHWin32ReleaseLinks.href | foreach {
                $($_ | Select-String -Pattern "v[0-9]+.[0-9]+.[0-9]+.[0-9]+").Matches.Value -replace "v",""
            } | Sort-Object | Get-Unique
            $OpenSSHWin32LatestVersion = $($OpenSSHWin32Versions | % {[version]$_} | Measure-Object -Maximum).Maximum
            $VersionAsString = $OpenSSHWin32Versions | Where-Object {[version]$_ -eq $OpenSSHWin32LatestVersion}
            $Finalhref = $($OpenSSHWin32ReleaseLinks | Where-Object {$_.href -like "*$VersionAsString*"}).href
            $FinalFileName = $Finalhref | Split-Path -Leaf
            $FinalDownloadURI = "https://github.com$Finalhref"

            Invoke-WebRequest -Uri $FinalDownloadURI -OutFile "$HOME\Downloads\$FinalFileName"

            # Unzip the Archive
            if (!$(Test-Path "C:\OpenSSH-Win32")) {
                New-Item -Type Directory -Path "C:\OpenSSH-Win32"
            }
            if (!$(Test-path "C:\OpenSSH-Win32\ssh-keygen.exe")) {
                if ($PSVersionTable.PSVersion.Major -lt 3) {   
                    Unzip-File -PathToZip "$HOME\Downloads\$FinalFileName" -TargetDir "$env:SystemDrive\"
                }
            }
            if ($PSVersionTable.PSVersion.Major -ge 3) {
                Expand-Archive -Path "$HOME\Downloads\$FinalFileName" -DestinationPath "$env:SystemDrive\"
            }

            # Add the directory to the PATH
            if ($($env:Path -split ";") -notcontains "C:\OpenSSH-Win32") {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path`C:\OpenSSH-Win32"
                }
                else {
                    $env:Path = "$env:Path;C:\OpenSSH-Win32"
                }
            }

            $OpenSSHWin32Check = Get-Command ssh-keygen
        }
        if (!$OpenSSHWin32Check) {
            Write-Verbose "ssh-keygen is still not recognized as a valid command. Check your `$env:Path! Halting!"
            Write-Error "ssh-keygen is still not recognized as a valid command. Check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }


        if ($ExistingSSHPrivateKeyPath) {
            # Check To Make Sure Online GitHub Account is aware of Existing Public Key
            $PubSSHKeys = Invoke-Restmethod -Uri "https://api.github.com/users/$GitHubUserName/keys"
            $tempfileLocations = @()
            foreach ($PubKeyObject in $PubSSHKeys) {
                $tmpFile = [IO.Path]::GetTempFileName()
                $PubKeyObject.key | Out-File $tmpFile -Encoding ASCII

                $tempfileLocations +=, $tmpFile
            }
            $SSHPubKeyFingerPrintsFromGitHub = foreach ($TempPubSSHKeyFile in $tempfileLocations) {
                $PubKeyFingerPrintPrep = ssh-keygen -E md5 -lf $TempPubSSHKeyFile
                $PubKeyFingerPrint = $($PubKeyFingerPrintPrep -split " ")[1] -replace "MD5:",""
                $PubKeyFingerPrint
            }
            # Cleanup Temp Files
            foreach ($TempPubSSHKeyFile in $tempfileLocations) {
                Remove-Item $TempPubSSHKeyFile
            }

            $GitHubOnlineIsAware = @()
            foreach ($fingerprint in $SSHPubKeyFingerPrintsFromGitHub) {
                $ExistingSSHPubKeyPath = "$ExistingSSHPrivateKeyPath.pub"
                $LocalPubKeyFingerPrintPrep = ssh-keygen -E md5 -lf $ExistingSSHPubKeyPath
                $LocalPubKeyFingerPrint = $($LocalPubKeyFingerPrintPrep -split " ")[1] -replace "MD5:",""
                if ($fingerprint -eq $LocalPubKeyFingerPrint) {
                    $GitHubOnlineIsAware +=, $fingerprint
                }
            }

            if ($GitHubOnlineIsAware.Count -gt 0) {
                Write-Verbose "GitHub Online Account is aware of existing public key $ExistingSSHPrivateKeyPath.pub"

                # Start the ssh agent and add your new key to it
                if (!$(Get-Module -List -Name posh-git)) {
                    if ($PSVersionTable.PSVersion.Major -ge 5) {
                        Install-Module posh-git -Scope CurrentUser
                        Import-Module posh-git -Verbose
                    }
                    if ($PSVersionTable.PSVersion.Major -lt 5) {
                        Update-PackageManagement
                        Install-Module posh-git -Scope CurrentUser
                        Import-Module posh-git -Verbose
                    }
                }
                Start-SshAgent
                Add-SshKey $ExistingSSHPrivateKeyPath
            }
            if ($GitHubOnlineIsAware.Count -eq 0) {
                Write-Verbose "The GitHub Online Account is not aware of the local public SSH key $ExistingSSHPrivateKeyPath.pub! Copy it to `"Settings`" -> `"SSH and GPG Keys`" on your GitHub Account via web browser. Halting!"
                Write-Error "The GitHub Online Account is not aware of the local public SSH key $ExistingSSHPrivateKeyPath.pub! Copy it to `"Settings`" -> `"SSH and GPG Keys`" on your GitHub Account via web browser. Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                $ProcessInfo.FileName = "ssh.exe"
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $fale
                $ProcessInfo.Arguments = "-T git@github.com"
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                $Process.WaitForExit()
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr

                if ($AllOutput -match $GitHubUserName) {
                    Write-Host "GitHub Authentication for $GitHubUserName using SSH was successful."
                }
                else {
                    Write-Warning "GitHub Authentication for $GitHubUserName using SSH was NOT successful. Please check your connection and/or keys."
                }
            }
        }
        if ($NewSSHKeyName) {
            # Create a new public/private keypair
            # WARNING: Null password WILL prompt the user for a new password. On Linux, you can use the parameter:
            #   -N ""
            # This doesn't work on OpenSSH-Win32 for some reason.

            if (!$(Test-Path "$HOME\.ssh")) {
                New-Item -Type Directory -Path "$HOME\.ssh"
            }
            if (!$NewSSHKeyPwd) {
                ssh-keygen.exe -b 2048 -t rsa -f "$HOME\.ssh\$NewSSHKeyName"
            }
            if ($NewSSHKeyPwd -ne $null) {
                ssh-keygen.exe -b 2048 -t rsa -f "$HOME\.ssh\$NewSSHKeyName" -q -N "$NewSSHKeyPwd"
            }

            # Start the ssh agent and add your new key to it
            if (!$(Get-Module -List -Name posh-git)) {
                if ($PSVersionTable.PSVersion.Major -ge 5) {
                    Install-Module posh-git -Scope CurrentUser
                    Import-Module posh-git -Verbose
                }
                if ($PSVersionTable.PSVersion.Major -lt 5) {
                    Update-PackageManagement
                    Install-Module posh-git -Scope CurrentUser
                    Import-Module posh-git -Verbose
                }
            }
            Start-SshAgent
            Add-SshKey "$HOME\.ssh\$NewSSHKeyName"

            Write-Host "Success! Now add $HOME\.ssh\$NewSSHKeyName.pub to your GitHub Account via Web Browser by:"
            Write-Host "    1) Navigating to Settings"
            Write-Host "    2) In the user settings sidebar, click SSH and GPG keys."
            Write-Host "    3) Add SSH Key"
            Write-Host "    4) Enter a descriptive Title like: SSH Key for Paul-MacBookPro auth"
            Write-Host "    5) Paste your key into the Key field."
            Write-Host "    6) Click Add SSH key."
        }
    }


    ##### END Main Body #####

}





# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2xVwWOVgIO6OvZSu1wfqlZzJ
# 6CqgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRrogcf39ld
# TXd6+y7bcfUHtASeZzANBgkqhkiG9w0BAQEFAASCAQCc7micJTK7YhYB13qB1j3K
# 4yyyRqJ/u8/l+tZCWCaHy2O6XDO2/DTDNspc67/I3N3pk55xb55DkR5ya32gkBXs
# 0JH63qi7ggqzKnPJP5TIqb5GVhXphxbJviXB53ECogWBd05KU+DqTV4RCpWrc68W
# 5U5COyc2xZsOSRpi5YAGfuTD8ZW7SrMDGy1zq00MyuD16nZXRhErDLP1Gn4Xl7VW
# dVmtoD2wpRb0cRBeH9BMva/P/yqGqBBmwD6poLUN04eLCSM/U2t1WhfuL6/HHHLV
# rkmw5q4vRNZMpPQ+xjuargsjkta8He6oGK429CAT32v6PJ5o6QneMDEcq50/+ez4
# SIG # End signature block
