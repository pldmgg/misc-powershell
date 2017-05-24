<#
.SYNOPSIS
    Sets up the GitHub Git Shell Environment in PowerShell

.DESCRIPTION
    Sets up the proper PATH and ENV to use GitHub for Window's shell environment
    
    This is a refactored version of $env:LOCALAPPDATA\GitHub\shell.ps1 that gets installed
    with GitDesktop for Windows.

.PARAMETER SkipSSHSetup
    If true, skips calling GitHub.exe to autoset and upload ssh-keys

.EXAMPLE
    Initialize-GitEnvironment

#>

function Initialize-GitEnvironment {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$SkipSSHSetup = $false,

        [Parameter(Mandatory=$False)]
        [string]$ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa"

    )

    ##### BEGIN Native Helper Functions #####

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

    function Update-PackageManagement {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$False)]
            $Credentials
        )

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
                $env:Path = "$env:Path;C:\Chocolatey\bin"
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

    ##### END Native Helper Functions #####

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
        $env:github_posh_git = Resolve-Path "$env:LocalAppData\GitHub\PoshGit_*" -ErrorAction Continue
        $env:github_git = Resolve-Path "$env:LocalAppData\GitHub\PortableGit_*" -ErrorAction Continue
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
        $HighestNetVer = $($(Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework" | Where-Object {$_.Name -match "^v[0-9]"}).Name -replace "v","" | Measure-Object -Maximum).Maximum
        $msBuildPath = "$env:SystemRoot\Microsoft.NET\Framework\v$HighestNetVer"
        $lfsamd64Path = Resolve-Path "$env:LocalAppData\GitHub\lfs-*"

        $env:Path = "$env:Path;$pGitPath\cmd;$pGitPath\usr\bin;$pGitPath\usr\share\git-tfs;$lfsamd64Path;$appPath;$msBuildPath"

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





# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzdMNdoKyvECb5x102+q57Gsh
# VySgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQlEx6jHmKz
# cWXJs3dM1JauEz0f6DANBgkqhkiG9w0BAQEFAASCAQAvNaZEMfI2sGaQQATkU3hT
# QiVmGiCnz/UhbX7d0lX0P8qFqXzKp0w0q4xHcE2XnqQExVywgiSEFzJrox55UKVz
# 5krR/eH9M2zqgftlcldqe3mVj82U3938QSWwmzi0KdxXKrlou9z7mfesUKrsgXNv
# Msr2bCogMKqb/dbZol/sx9UP3zE8UEa8RLUrvJOKijTcaZ1/vsKQrZAnoHkCYGt1
# j11jYsCi+1ZRQpoFeXxyDPkFr7eGDFLmNQqHwAShuszE5zL4Q/oXDAUDy7tSR2tY
# eNne/3EA2pDVxExX4GLTaKz1MT+W+htx5btaKApTDjZHC18nyA5BIjHAnrN5ZWsD
# SIG # End signature block
