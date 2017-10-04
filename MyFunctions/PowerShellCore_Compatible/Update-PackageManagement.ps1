<#
.SYNOPSIS
    Install and/or Update the PackageManagement PowerShell Module and/or the PowerShellGet PowerShell Module.

    IMPORTANT: This script can be used on systems with PowerShell Version 3 and higher

.DESCRIPTION
    PowerShell versions 3 and 4 do NOT have the PackageManagement and PowerShellGet Modules installed by default.
    If you are running PowerShell 3 or 4 and these modules are NOT installed, it will download PackageMangement_x64.msi
    from Microsoft and install it (thereby installing the Modules) and upgrade the Modules the latest version available
    in the PSGallery PackageProvider Source repo (NOTE: The PackageManagement module is not able to be upgraded beyond
    version 1.0.0.1 on PowerShell 3 or 4, unless you upgrade PowerShell itself to version 5 or higher).

    PowerShell version 5 and higher DOES come with PackageManagement and PowerShellGet Modules (both version
    1.0.0.1) by default. This script will install the latest versions of these Modules ALONGSIDE
    (i.e. SIDE-BY-SIDE MODE) the older versions...because that's apparently how Microsoft wants to
    handle this for the time being.

    At the conclusion of this script, the PowerShell Sessionw will have the latest versions of the PackageManagement and 
    PowerShellGet Modules loaded via Import-Module. (Verify with Get-Module).

.NOTES
    ##### Regarding PowerShell Versions Lower than 5 #####

    Installation of the PackageManagement_x64.msi is necessary. Installing this .msi gives us version 1.0.0.1 of the 
    PackageManagement Module and version 1.0.0.1 of PowerShellGet Module (as well as the PowerShellGet PackageProvider 
    and the PowerShellGet PackageProvider Source called PSGallery).

    However, these are NOT the latest versions of these Modules. You can update the PowerShellGet Module from 1.0.0.1 to
    the latest version by using Install-Module -Force. Unfortunately, it is not possible to update the PackageManagement
    Module itself using this method, because it will complain about it being in use (which it is, since the Install-Module
    cmdlet belongs to the PackageManagement Module).

    It is important to note that updating PowerShellGet using Install-Module -Force in PowerShell versions lower than 5
    actually REMOVES 1.0.0.1 and REPLACES it with the latest version. (In PowerShell version 5 and higher, it installs
    the new version of the Module ALONGSIDE the old version.)

    There is currently no way to update the PackageManagement Module to a version newer than 1.0.0.1 without actually updating
    PowerShell itself to version 5 or higher.


    ##### Regarding PowerShell Versions 5 And Higher #####

    The PackageManagement Module version 1.0.0.1 and PowerShellGet Module version 1.0.0.1 are already installed.

    It is possible to update both Modules using Install-Module -Force, HOWEVER, the newer versions will be installed
    ALONGSIDE (aka SIDE-BY-SIDE mode) the older versions. In future PowerShell Sessions, you need to specify which version
    you want to use when you import the module(s) using Import-Module -RequiredVersion

.EXAMPLE
    Update-PackageManagement

#>

function Update-PackageManagement {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $Credentials
    )

    ##### BEGIN Helper Functions #####
    function Check-Elevation {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") {
            [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )
    
            [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
            if($currentPrincipal.IsInRole($administratorsRole)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        if ($PSVersionTable.Platform -eq "Unix") {
            if ($(whoami) -eq "root") {
                return $true
            }
            else {
                return $false
            }
        }
    }

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") {
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
    }

    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        # Check to see if we're behind a proxy
        if ([System.Net.WebProxy]::GetDefaultProxy().Address -ne $null) {
            $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
            [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyAddress)
            [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        }
    }
    # TODO: Figure out how to identify default proxy on PowerShell Core...

    if (!$(Check-Elevation) -and !$Credentials) {
        $UserName = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).split("\"))[1]
        $Psswd = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
        $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Psswd
    }
    if ($Credentials) {
        $UserName = $Credentials.UserName
        $Psswd = $Credentials.Password
    }
    $Domain = $env:USERDNSDOMAIN
    $DomainPre = $env:USERDOMAIN
    $UpdatedUserName = "$DomainPre\$UserName"
    if ($Psswd) {
        $UpdatedCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UpdatedUserName, $Psswd
    }
    $LocalHostFQDN = "$env:ComputerName.$Domain"

    # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
    if (!$(Check-Elevation)) {
        if ($PSVersionTable.Platform -eq "Unix") {
            Write-Error "The Update-PackageManagement function must be run with elevated privileged. Please run PowerShell using 'sudo' and try the function again. Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            if (!$global:ElevatedPSSession) {
                try {
                    $global:ElevatedPSSession = New-PSSession -Name "TempElevatedSession "-Authentication CredSSP -Credential $Credentials -ErrorAction SilentlyContinue
                    if (!$ElevatedPSSession) {
                        throw
                    }
                    $CredSSPAlreadyConfigured = $true
                }
                catch {
                    $SudoSession = New-SudoSession -Credentials $Credentials
                    $global:ElevatedPSSession = $SudoSession.ElevatedPSSession
                    $NeedToRevertAdminChangesIfAny = $true
                }
            }
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    if ($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSEdition -eq "Desktop") {
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

        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") {
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
        # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
        # and it will not update it.
        #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
        Write-Host "Installing latest version of PowerShellGet..."
        if (Check-Elevation) {
            #Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
            Install-Module -Name "PowerShellGet" -Force
        }
        else {
            if ($ElevatedPSSession) {
                Invoke-Command -Session $ElevatedPSSession -Scriptblock {Install-Module -Name "PowerShellGet" -RequiredVersion $using:PowerShellGetLatestVersion -Force}
            }
        }
    }

    # Reset the LatestLocallyAvailableVersion variables to reflect latest available, and then load them into the current session
    $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PackageManagement"}).Version | Measure-Object -Maximum).Maximum
    $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

    $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
    $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
    Write-Host "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Host "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

    if ($CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestLocallyAvailableVersion) {
        # Need to remove PowerShellGet first since it depends on PackageManagement
        Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
        Remove-Module -Name "PowerShellGet"
        Write-Host "Removing Module PackageManagement $CurrentlyLoadedPackageManagementVersion ..."
        Remove-Module -Name "PackageManagement"
    
        if ($(Get-Host).Name -ne "Package Manager Host") {
            Write-Host "We are NOT in the Visual Studio Package Management Console. Continuing..."
            
            # Need to Import PackageManagement first since it's a dependency for PowerShellGet
            Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion ..."
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
            Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
        }
        if ($(Get-Host).Name -eq "Package Manager Host") {
            Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
    
            # Need to Import PackageManagement first since it's a dependency for PowerShellGet
            Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PackMan' - Example: Get-PackManPackage"
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan
            Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet
        }
    }
    
    # Reset CurrentlyLoaded Variables
    $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
    $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
    Write-Host "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Host "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
    
    if ($CurrentlyLoadedPowerShellGetVersion -lt $PowerShellGetLatestLocallyAvailableVersion) {
        Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
        Remove-Module -Name "PowerShellGet"
    
        if ($(Get-Host).Name -ne "Package Manager Host") {
            Write-Host "We are NOT in the Visual Studio Package Management Console. Continuing..."
            
            Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion     
        }
        if ($(Get-Host).Name -eq "Package Manager Host") {
            Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
    
            Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet
        }
    }

    # Make sure all Repos Are Trusted
    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") {
        $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
    }
    if ($PSVersionTable.Platform -eq "Unix") {
        $BaselineRepoNames = @("nuget.org","PSGallery")
    }
    if ($(Get-Module -Name PackageManagement).ExportedCommands -ne $null) {
        $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
    
        foreach ($RepoObject in $RepoObjectsForTrustCheck) {
            if ($RepoObject.IsTrusted -ne $true) {
                Set-PackageSource -Name $RepoObject.Name -Trusted
            }
        }
    }

    $ErrorsArrayReversed = $($Error.Count-1)..$($Error.Count-4) | foreach {$Error[$_]}
    $CheckForError = try {$ErrorsArrayReversed[0].ToString()} catch {$null}
    if ($CheckForError -eq "Assembly with same name is already loaded") {
        Write-Warning $(
            "The latest version of the PackageManagement Module does not check for certain assemblies that could already be loaded" +
            " (which is almost certainly the case if you are using PowerShell Core). Please close this PowerShell Session," +
            " start a new one, and rerun the Update-PackageManagement function in order to move past this race condition."
        )
    }

    if ($NeedToRevertAdminChangesIfAny) {
        Remove-SudoSession -Credentials $Credentials -OriginalConfigInfo $SudoSession.OriginalWSManAndRegistryStatus -SessionToRemove $SudoSession.ElevatedPSSession
    }
}











# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpPgrCTXFidzQDI9t9zNRCT9K
# EIigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFL53ejB73k0igu9s
# +J4mi+NBq9OwMA0GCSqGSIb3DQEBAQUABIIBAH0ZaA11y9z/Zv1elZ6fhmCrJVZB
# 8QlQJycpeo8PHDvsY/hmJ0XoY0rwZjqrAVLxMEw26jkMx2kpR4gnvaaoVBE+89mW
# zjgt1mPU9MbwUejFtZAxv5BzCJ72UVHN+dRf3E1seNjj+nKAsxVDk2qFF+ptu0ao
# URhbfU8AfPyBnCv7JYekf1W5UC2/PCRMDqdI5NOiwZkKxAG+oIvjfZ0xs4dk3gYs
# ezPnHRcfXU7+9FAk2g7ClGnURy+nC6Ocv2ZO16/5ThPXfhmPx6QmhUmgpqdqQfxM
# FMvJ81P9KUNNjoXrNqaQhRNHZ7JhWu9QImubNbpOjysC/TL5WanvMfeSp2k=
# SIG # End signature block
