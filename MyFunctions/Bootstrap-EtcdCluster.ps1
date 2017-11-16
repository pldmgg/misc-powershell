<##
.SYNOPSIS
    Bootstrap an etcd cluster of Windows machines.    

.DESCRIPTION
    Installs etcd as a Windows Service on a specified group of Windows machines.

    This established a reliable way to store key/value pairs across a cluster of machines and
    provides a relatively easy way to coordinate tasks among them.    

.PARAMETER HostNamesOrIPsOfHostsInCluster
    This parameter is MANDATORY.

    This parameter takes an array of strings (must be 3 or more), each of which represents a DNS-resolvable
    hostname or IP Address of **Windows Machines** that you would like to become members of the NEW etcd Cluster.
    
.PARAMETER LocalHostDataDirectory
    This parameter is OPTIONAL.

    This parameter takes a string that represents a full path to a directory that is available locally on
    each of the Cluster Members.

    If this parameter is not used, the default value is "C:\etcd"

    NOTE: The specified directory must ALREADY EXIST on the Remote Hosts. If it does not, the function will
    halt.

.PARAMETER RemoteHostCredentials
    This parameter is OPTIONAL.

    This parameter takes a PSCredential object that represents a single set of credentials (i.e. Username and
    Password) that can be used to access ALL Remote Hosts specified by the -HostNamesOrIPsOfHostsInCluster
    parameter.

.EXAMPLE
    Bootstrap-EtcdCluster -HostNamesOrIPsOfHostsInCluster @("win16chef","win12ws","win12chef")    

.EXAMPLE
    Bootstrap-EtcdCluster -HostNamesOrIPsOfHostsInCluster @("win16chef","win12ws","win12chef") -LocalHostDataDirectory "E:\etcd"    

.OUTPUTS
    A PSCustomObject with properties 'ClusterHealth' and 'MemberList' 
#>

function Bootstrap-EtcdCluster {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$HostNamesOrIPsOfHostsInCluster,

        [Parameter(Mandatory=$False)]
        [string]$LocalHostDataDirectory,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$RemoteHostCredentials
    )

    ##### BEGIN Native Helper Functions #####

    function Update-PackageManagement {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$False)]
            [switch]$UseChocolatey,
    
            [Parameter(Mandatory=$False)]
            [switch]$InstallNuGetCmdLine
        )
    
        ##### BEGIN Helper Functions #####
    
        function Check-Elevation {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
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
    
        function Get-NativePath {
            [CmdletBinding()]
            Param( 
                [Parameter(Mandatory=$True)]
                [string[]]$PathAsStringArray
            )
        
            $PathAsStringArray = foreach ($pathPart in $PathAsStringArray) {
                $SplitAttempt = $pathPart -split [regex]::Escape([IO.Path]::DirectorySeparatorChar)
                
                if ($SplitAttempt.Count -gt 1) {
                    foreach ($obj in $SplitAttempt) {
                        $obj
                    }
                }
                else {
                    $pathPart
                }
            }
            $PathAsStringArray = $PathAsStringArray -join [IO.Path]::DirectorySeparatorChar
        
            $PathAsStringArray
        
        }
    
        function Pause-ForWarning {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$True)]
                [int]$PauseTimeInSeconds,
        
                [Parameter(Mandatory=$True)]
                $Message
            )
        
            Write-Warning $Message
            Write-Host "To answer in the affirmative, press 'y' on your keyboard."
            Write-Host "To answer in the negative, press any other key on your keyboard, OR wait $PauseTimeInSeconds seconds"
        
            $timeout = New-Timespan -Seconds ($PauseTimeInSeconds - 1)
            $stopwatch = [diagnostics.stopwatch]::StartNew()
            while ($stopwatch.elapsed -lt $timeout){
                if ([Console]::KeyAvailable) {
                    $keypressed = [Console]::ReadKey("NoEcho").Key
                    Write-Host "You pressed the `"$keypressed`" key"
                    if ($keypressed -eq "y") {
                        $Result = $true
                        break
                    }
                    if ($keypressed -ne "y") {
                        $Result = $false
                        break
                    }
                }
        
                # Check once every 1 second to see if the above "if" condition is satisfied
                Start-Sleep 1
            }
        
            if (!$Result) {
                $Result = $false
            }
            
            $Result
        }
    
        ##### END Helper Functions #####
    
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
        if (!$(Check-Elevation)) {
            Write-Error "The Update-PackageManagement function must be run with elevated privileges. Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if (!$([Environment]::Is64BitProcess)) {
            Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -ne "Win32NT" -and $UseChocolatey) {
            Write-Error "The Chocolatey Repo should only be added on a Windows OS! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if ($InstallNuGetCmdLine -and !$UseChocolatey) {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                    $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to use the Chocolatey Package Provider (NOTE: This is NOT an installation of the chocolatey command line)?"
                    $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                    if ($WarningResponse) {
                        $UseChocolatey = $true
                    }
                }
                else {
                    $UseChocolatey = $true
                }
            }
            elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to install Chocolatey Command Line Tools in order to install NuGet Command Line Tools?"
                    $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                    if ($WarningResponse) {
                        $UseChocolatey = $true
                    }
                }
                else {
                    $UseChocolatey = $true
                }
            }
            elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
                $WarningMessage = "The NuGet Command Line Tools binary nuget.exe can be downloaded, but will not be able to be run without Mono. Do you want to download the latest stable nuget.exe?"
                $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                if ($WarningResponse) {
                    Write-Host "Downloading latest stable nuget.exe..."
                    $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "nuget.exe")
                    Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $OutFilePath
                }
                $UseChocolatey = $false
            }
        }
    
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
            # Check to see if we're behind a proxy
            if ([System.Net.WebProxy]::GetDefaultProxy().Address -ne $null) {
                $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
                [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyAddress)
                [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
            }
        }
        # TODO: Figure out how to identify default proxy on PowerShell Core...
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
                Write-Host "Downloading PackageManagement .msi installer..."
                $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "PackageManagement_x64.msi")
                Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi" -OutFile $OutFilePath
                
                $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                $MSIFullPath = $OutFilePath
                $MSIParentDir = $MSIFullPath | Split-Path -Parent
                $MSIFileName = $MSIFullPath | Split-Path -Leaf
                $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
                $logFile = Get-NativePath -PathAsStringArray @($MSIParentDir, "$MSIFileNameOnly$DateStamp.log")
                $MSIArguments = @(
                    "/i"
                    $MSIFullPath
                    "/qn"
                    "/norestart"
                    "/L*v"
                    $logFile
                )
                # Install PowerShell Core
                Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
            }
            while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
                Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
                Start-Sleep -Seconds 1
            }
            Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
        }
    
        # Set LatestLocallyAvailable variables...
        $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PackageManagement"}).Version | Measure-Object -Maximum).Maximum
        $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Measure-Object -Maximum).Maximum
    
        if ($(Get-Module).Name -notcontains "PackageManagement") {
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        }
        if ($(Get-Module).Name -notcontains "PowerShellGet") {
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
        }
    
        if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0 -or
            $(Get-Module -Name PowerShellGet).ExportedCommands.Count -eq 0
        ) {
            Write-Warning "Either PowerShellGet or PackagementManagement Modules were not able to be loaded Imported successfully due to an update initiated within the current session. Please close this PowerShell Session, open a new one, and run this function again."
    
            $Result = [pscustomobject][ordered]@{
                PackageManagementUpdated  = $false
                PowerShellGetUpdated      = $false
                NewPSSessionRequired      = $true
            }
    
            $Result
            return
        }
    
        # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
        # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
        # do it beforehand.
        if ($(Get-PackageProvider).Name -notcontains "NuGet") {
            Install-PackageProvider "NuGet" -Scope CurrentUser -Force
            Register-PackageSource -Name 'nuget.org' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap
        }
    
        if ($UseChocolatey) {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                # Install the Chocolatey Package Provider to be used with PowerShellGet
                if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                    Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
                    # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
                    Set-PackageSource -Name Chocolatey -Trusted
    
                    # Make sure packages installed via Chocolatey PackageProvider are part of $env:Path
                    [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
                    [System.Collections.ArrayList]$ChocolateyPathsFinal = @()
                    $env:ChocolateyPSProviderPath = "C:\Chocolatey"
    
                    if (Test-Path $env:ChocolateyPSProviderPath) {
                        if (Test-Path "$env:ChocolateyPSProviderPath\lib") {
                            $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\lib" -Directory | foreach {
                                Get-ChildItem $_.FullName -Recurse -File
                            } | foreach {
                                if ($_.Extension -eq ".exe") {
                                    $_.Directory.FullName
                                }
                            }) | foreach {
                                $null = $ChocolateyPathsPrep.Add($_)
                            }
                        }
                        if (Test-Path "$env:ChocolateyPSProviderPath\bin") {
                            $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\bin" -Directory | foreach {
                                Get-ChildItem $_.FullName -Recurse -File
                            } | foreach {
                                if ($_.Extension -eq ".exe") {
                                    $_.Directory.FullName
                                }
                            }) | foreach {
                                $null = $ChocolateyPathsPrep.Add($_)
                            }
                        }
                    }
                    
                    if ($ChocolateyPathsPrep) {
                        foreach ($ChocoPath in $ChocolateyPathsPrep) {
                            if ($(Test-Path $ChocoPath) -and $OriginalEnvPathArray -notcontains $ChocoPath) {
                                $null = $ChocolateyPathsFinal.Add($ChocoPath)
                            }
                        }
                    }
                
                    try {
                        $ChocolateyPathsFinal = $ChocolateyPathsFinal | Sort-Object | Get-Unique
                    }
                    catch {
                        [System.Collections.ArrayList]$ChocolateyPathsFinal = @($ChocolateyPathsFinal)
                    }
                    if ($ChocolateyPathsFinal.Count -ne 0) {
                        $ChocolateyPathsAsString = $ChocolateyPathsFinal -join ";"
                    }
    
                    foreach ($ChocPath in $ChocolateyPathsFinal) {
                        if ($($env:Path -split ";") -notcontains $ChocPath) {
                            if ($env:Path[-1] -eq ";") {
                                $env:Path = "$env:Path$ChocPath"
                            }
                            else {
                                $env:Path = "$env:Path;$ChocPath"
                            }
                        }
                    }
    
                    Write-Host "Updated `$env:Path is:`n$env:Path"
    
                    if ($InstallNuGetCmdLine) {
                        # Next, install the NuGet CLI using the Chocolatey Repo
                        try {
                            Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                            while (!$(Find-Package Nuget.CommandLine)) {
                                Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                                Start-Sleep -Seconds 2
                            }
                            
                            Get-Package NuGet.CommandLine -ErrorAction SilentlyContinue
                            if (!$?) {
                                throw
                            }
                        } 
                        catch {
                            Install-Package Nuget.CommandLine -Source chocolatey -Force
                        }
                        
                        # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
                        $NuGetSymlinkTest = Get-ChildItem "C:\Chocolatey\bin" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
                        $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
                        $TestRealNuGetPath = Test-Path $RealNuGetPath
                        if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
                            New-Item -Path "C:\Chocolatey\bin\NuGet.exe" -ItemType SymbolicLink -Value $RealNuGetPath
                        }
                    }
                }
            }
            if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                # Install the Chocolatey Command line
                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                    # there is a Web Proxy between you and the Internet
                    $env:chocolateyUseWindowsCompression = 'true'
                    $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 6>&1
                    $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                    $ChocolateyInstallLogFile = Get-NativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                    $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
                }
    
                if ($InstallNuGetCmdLine) {
                    if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                        Write-Error "Unable to find chocolatey.exe, however, it should be installed. Please check your System PATH and `$env:Path and try again. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        # 'choco update' aka 'cup' will update if already installed or install if not installed
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.WorkingDirectory = $NuGetPackagesPath
                        $ProcessInfo.FileName = "cup"
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = "nuget.commandline -y"
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
                        $stderr = $($Process.StandardError.ReadToEnd()).Trim()
                        $AllOutput = $stdout + $stderr
                        $AllOutput = $AllOutput -split "`n"
                    }
                    # NOTE: The chocolatey install should take care of setting $env:Path and System PATH so that
                    # choco binaries and packages installed via chocolatey can be found here:
                    # C:\ProgramData\chocolatey\bin
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
        Write-Verbose "PackageManagement Latest Version is: $PackageManagementLatestVersion"
        Write-Verbose "PowerShellGetLatestVersion Latest Version is: $PowerShellGetLatestVersion"
    
        if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
            }
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
                #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PackageManagementLatestVersion -Force
                Write-Host "Installing latest version of PackageManagement..."
                Install-Module -Name "PackageManagement" -Force
                $PackageManagementUpdated = $True
            }
        }
        if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
            # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
            # and it will not update it.
            Write-Host "Installing latest version of PowerShellGet..."
            #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
            #Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
            Install-Module -Name "PowerShellGet" -Force
            $PowerShellGetUpdated = $True
        }
    
        # Reset the LatestLocallyAvailable variables, and then load them into the current session
        $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PackageManagement"}).Version | Measure-Object -Maximum).Maximum
        $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Measure-Object -Maximum).Maximum
        Write-Verbose "Latest locally available PackageManagement version is $PackageManagementLatestLocallyAvailableVersion"
        Write-Verbose "Latest locally available PowerShellGet version is $PowerShellGetLatestLocallyAvailableVersion"
    
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
    
        if ($CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestLocallyAvailableVersion) {
            # Need to remove PowerShellGet first since it depends on PackageManagement
            Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            Remove-Module -Name "PowerShellGet"
            Write-Host "Removing Module PackageManagement $CurrentlyLoadedPackageManagementVersion ..."
            Remove-Module -Name "PackageManagement"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion ..."
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Verbose "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PackMan' - Example: Get-PackManPackage"
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
        }
        
        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
        
        if ($CurrentlyLoadedPowerShellGetVersion -lt $PowerShellGetLatestLocallyAvailableVersion) {
            if (!$ImportPSGetProblems) {
                Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            }
            Remove-Module -Name "PowerShellGet"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet
            }
        }
    
        # Make sure all Repos Are Trusted
        if ($UseChocolatey -and $($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5)) {
            $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
        }
        else {
            $BaselineRepoNames = @("nuget.org","PSGallery")
        }
        if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -gt 0) {
            $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
        
            foreach ($RepoObject in $RepoObjectsForTrustCheck) {
                if ($RepoObject.IsTrusted -ne $true) {
                    Set-PackageSource -Name $RepoObject.Name -Trusted
                }
            }
        }
    
        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "The FINAL loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "The FINAL loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
    
        #$ErrorsArrayReversed = $($Error.Count-1)..$($Error.Count-4) | foreach {$Error[$_]}
        #$CheckForError = try {$ErrorsArrayReversed[0].ToString()} catch {$null}
        if ($($ImportPackManProblems | Out-String) -match "Assembly with same name is already loaded" -or 
            $CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestVersion -or
            $(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0
        ) {
            Write-Warning "The PackageManagement Module has been updated and requires and brand new PowerShell Session. Please close this session, start a new one, and run the function again."
            $NewPSSessionRequired = $true
        }
    
        $Result = [pscustomobject][ordered]@{
            PackageManagementUpdated  = if ($PackageManagementUpdated) {$true} else {$false}
            PowerShellGetUpdated      = if ($PowerShellGetUpdated) {$true} else {$false}
            NewPSSessionRequired      = if ($NewPSSessionRequired) {$true} else {$false}
        }
    
        $Result
    }

    function Get-NetworkInfo {
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$False)]
            [ValidateSet("Up","Down")]
            [string]$InterfaceStatus,
    
            [Parameter(Mandatory=$False)]
            [ValidateSet("IPv4","IPv6")]
            [string]$AddressFamily
        )
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        if ($AddressFamily) {
            if ($AddressFamily -eq "IPv4") {
                $AddrFam = "InterNetwork"
            }
            if ($AddressFamily -eq "IPv6") {
                $AddrFam = "InterNetworkV6"
            }
        }
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        ##### BEGIN Main Body #####
    
        [System.Collections.Arraylist]$PSObjectCollection = @()
        $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    
        $InterfacesToExplore = $interfaces
        if ($InterfaceStatus) {
            $InterfacesToExplore = $InterfacesToExplore | Where-Object {$_.OperationalStatus -eq $InterfaceStatus}
        }
        if ($AddressFamily) {
            $InterfacesToExplore = $InterfacesToExplore | Where-Object {$($_.GetIPProperties().UnicastAddresses | foreach {$_.Address.AddressFamily}) -contains $AddrFam}
        }
    
        foreach ($adapter in $InterfacesToExplore) {
            $ipprops = $adapter.GetIPProperties()
            $ippropsPropertyNames = $($ipprops | Get-Member -MemberType Property).Name
    
            if ($AddressFamily) {
                $UnicastAddressesToExplore = $ipprops.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq $AddrFam}
            }
            else {
                $UnicastAddressesToExplore = $ipprops.UnicastAddresses
            }
    
            foreach ($ip in $UnicastAddressesToExplore) {
                $FinalPSObject = [pscustomobject]@{}
                
                $adapterPropertyNames = $($adapter | Get-Member -MemberType Property).Name
                foreach ($adapterPropName in $adapterPropertyNames) {
                    $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                    if ($FinalPSObjectMemberCheck -notcontains $adapterPropName) {
                        $FinalPSObject | Add-Member -MemberType NoteProperty -Name $adapterPropName -Value $($adapter.$adapterPropName)
                    }
                }
                
                foreach ($ippropsPropName in $ippropsPropertyNames) {
                    $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                    if ($FinalPSObjectMemberCheck -notcontains $ippropsPropName -and
                    $ippropsPropName -ne "UnicastAddresses" -and $ippropsPropName -ne "MulticastAddresses") {
                        $FinalPSObject | Add-Member -MemberType NoteProperty -Name $ippropsPropName -Value $($ipprops.$ippropsPropName)
                    }
                }
                    
                $ipUnicastPropertyNames = $($ip | Get-Member -MemberType Property).Name
                foreach ($UnicastPropName in $ipUnicastPropertyNames) {
                    $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                    if ($FinalPSObjectMemberCheck -notcontains $UnicastPropName) {
                        $FinalPSObject | Add-Member -MemberType NoteProperty -Name $UnicastPropName -Value $($ip.$UnicastPropName)
                    }
                }
                
                $null = $PSObjectCollection.Add($FinalPSObject)
            }
        }
    
        $PSObjectCollection
    
        ##### END Main Body #####
            
    }

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ## BEGIN Native Helper Functions ##
    
        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }
    
        ## END Native Helper Functions ##
        
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                [System.Net.Dns]::GetHostEntry($HostNamePrep).AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
                
                [System.Collections.ArrayList]$RemoteHostFQDNs = @()
                foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
                    try {
                        $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
                    }
                    catch {
                        Write-Verbose "Unable to resolve $HostIP. Please check your DNS config."
                        continue
                    }
                    if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                        $null = $RemoteHostFQDNs.Add($FQDNPrep)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add([System.Net.Dns]::GetHostEntry($HostIPPrep).HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
        }
        if ($RemoteHostFQDNs.Count -eq 0) {
            Write-Error "Unable to determine FQDN of $HostNameOrIP! Halting!"
        }
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0 -or $RemoteHostFQDNs.Count -eq 0) {
            $global:FunctionResult = "1"
            return
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
    
        [pscustomobject]@{
            IPAddressList   = $RemoteHostArrayOfIPAddresses
            FQDN            = $RemoteHostFQDNs[0]
            HostName        = $HostNameList[0].ToLowerInvariant()
            Domain          = $DomainList[0]
        }
    
        ##### END Main Body #####
    
    }

    function Install-Etcd {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [pscustomobject]$ClusterMemberFQDNandIPInfo,
    
            [Parameter(Mandatory=$True)]
            [string]$LocalHostDataDirectory,
    
            [Parameter(Mandatory=$True)]
            [string]$UpdatePackageManagementFunctionAsString,
    
            [Parameter(Mandatory=$False)]
            [ValidateSet(1,2,3)]
            [int]$FireWallProfile = 3
        )
    
        ##### BEGIN Native Helper Functions #####
    
        function Check-Elevation {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
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
    
        function Compare-ObjectProperties {
            Param(
                [PSObject]$ReferenceObject,
                [PSObject]$DifferenceObject 
            )
            $objprops = $ReferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
            $objprops += $DifferenceObject | Get-Member -MemberType Property,NoteProperty | % Name
            $objprops = $objprops | Sort | Select -Unique
            $diffs = @()
            foreach ($objprop in $objprops) {
                $diff = Compare-Object $ReferenceObject $DifferenceObject -Property $objprop
                if ($diff) {            
                    $diffprops = @{
                        PropertyName=$objprop
                        RefValue=($diff | ? {$_.SideIndicator -eq '<='} | % $($objprop))
                        DiffValue=($diff | ? {$_.SideIndicator -eq '=>'} | % $($objprop))
                    }
                    $diffs += New-Object PSObject -Property $diffprops
                }        
            }
            if ($diffs) {return ($diffs | Select PropertyName,RefValue,DiffValue)}     
        }
    
        # Get Firewall Info solution from: https://serverfault.com/questions/221075/how-to-know-currently-open-ports-on-the-windows-firewall 
        $ProtocolLibrary = [pscustomobject]@{
            1       = "ICMP"
            6       = "TCP"
            17      = "UDP"
            47      = "GRE"
            51      = "IPSec"
            50      = "ESP"
            8       = "EGP"
            3       = "GGP"
            20      = "HMP"
            88      = "IGMP"
            66      = "RVD"
            89      = "OSPF"
            12      = "PUP"
            27      = "RDP"
            46      = "RSVP"
        }
    
        $ActionLibrary = [pscustomobject]@{
            0        = "Deny"
            1        = "Allow"
        }
    
        $DirectionLibrary = [pscustomobject]@{
            0        = "Outbound"
            1        = "Inbound"
        }
    
        $ProfileLibrary = [pscustomobject]@{
            1           = "Domain"
            2           = "Private"
            3           = @("Domain","Private")
            4           = "Public"
            5           = @("Domain","Public")
            6           = @("Private","Public")
            2147483647  = @("Domain","Private","Public")
        }
        
        function Get-EnabledRules {
            Param($profile)
            $rules = (New-Object -comObject HNetCfg.FwPolicy2).rules
            $rules = $rules | where-object {$_.Enabled -eq $true}
            $rules = $rules | where-object {$_.Profiles -bAND $profile}
            $rules
        }
    
        function Run-Binary {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$True)]
                [string]$BinaryPath,
        
                [Parameter(Mandatory=$False)]
                [string]$Arguments,
    
                [Parameter(Mandatory=$False)]
                [string]$WaitForExitMS = 2000
            )
    
            if (!$(Test-Path $BinaryPath)) {
                Write-Error "The path $BinaryPath was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $BinaryPath | Split-Path -Leaf
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.UseShellExecute = $false
            if ($Arguments) {
                $ProcessInfo.Arguments = $Arguments
            }
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit($WaitForExitMS)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr
        
            [pscustomobject]@{
                Stdout      = $stdout
                Stderr      = $stderr
                AllOutput   = $AllOutput
            }
        }
        
    
        ##### END Native Helper Functions #####
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        if (!$(Check-Elevation)) {
            Write-Error "The Install-Etcd function must be run with Elevated privileges (i.e. run PowerShell via Run As Administrator). Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if (!$(Test-Path $LocalHostDataDirectory)) {
            Write-Warning "The directory $LocalHostDataDirectory does not exist on $env:ComputerName!"
            $LocalHostDataDirectory = Read-Host -Prompt "Please enter the full path to a directory that exists on $env:ComputerName"
            if (!$(Test-Path $LocalHostDataDirectory)) {
                Write-Error "Unable to find path $LocalHostDataDirectory on $env:ComputerName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        # Delete any existing info within the $LocalHostDataDirectory
        $DataDirItems = Get-ChildItem $LocalHostDataDirectory
        foreach ($item in $DataDirItems) {
            Remove-Item -Recurse $item.FullName -Force
        }
    
        # Dot Source the Update-PackageManagement scriptblock
        try {
            $UpdatePackageManagementFunctionAsScriptBlock = [scriptblock]::Create($UpdatePackageManagementFunctionAsString)
            . $UpdatePackageManagementFunctionAsScriptBlock
        }
        catch {
            Write-Error "Unable to load Update-PackageManagement function. Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        $LocalHostInfo = $ClusterMemberFQDNandIPInfo | Where-Object {$_.FQDN -match $env:ComputerName}
        if (!$LocalHostInfo) {
            Write-Error "Unable to find Cluster Member that matches local host computer name $env:CompuerName! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $LocalHostFQDN = $LocalHostInfo.FQDN
        $LocalHostIP = $LocalHostInfo.IPAddressList[0]
        $LocalHostName = $LocalHostInfo.HostName
    
        $InitialClusterString = "$LocalHostName=http://$LocalHostIP`:2380"
        foreach ($ClusterMember in $ClusterMemberFQDNandIPInfo) {
            if ($ClusterMember.HostName -ne $env:ComputerName) {
                $InitialClusterString = $InitialClusterString + ",$($ClusterMember.Hostname)=http://$($ClusterMember.IPAddressList[0])`:2380"
            }
        }
    
        try {
            # Set Firewall Rules if necessary
            $FireWallRules = Get-EnabledRules -Profile $FireWallProfile
            $FireWallRule2380 = $FireWallRules | Where-Object {$($_.LocalPorts -split ",") -contains 2380 -and $_.Direction -eq 1} 
            $FireWallRule2379 = $FireWallRules | Where-Object {$($_.LocalPorts -split ",") -contains 2379 -and $_.Direction -eq 1}
            if ($FireWallRule2380.Profiles -eq "2147483647") {
                Write-Warning "The current Windows Firewall Profile allows Inbound to Port 2380 on Domain, Private, AND Public scopes. Public is NOT recommended."
            }
            if ($FireWallRule2379.Profiles -eq "2147483647") {
                Write-Warning "The current Windows Firewall Profile allows Inbound to Port 2379 on Domain, Private, AND Public scopes. Public is NOT recommended."
            }
            if (!$FireWallRule2380) {
                # Make sure ports 2370 and 2380 are open
                New-NetFirewallRule -DisplayName 'etcd Advertise Peers Port Inbound' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('2380')
                #New-NetFirewallRule -DisplayName 'etcd Advertise Peers Port Outbound' -Profile @('Domain', 'Private') -Direction Outbound -Action Allow -Protocol TCP -LocalPort @('2380')
            }
            if (!$FireWallRule2379) {
                New-NetFirewallRule -DisplayName 'etcd Advertise Clients Port Inbound' -Profile @('Domain', 'Private') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('2379')
                #New-NetFirewallRule -DisplayName 'etcd Advertise Clients Port Outbound' -Profile @('Domain', 'Private') -Direction Outbound -Action Allow -Protocol TCP -LocalPort @('2379')
            }
        }
        catch {
            Write-Warning "Unable to set appropriate Windows Firewall rules for $env:ComputerName! Halting!"
            Write-Error $Error[0]
            $global:FunctionResult = "1"
            return
        }
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
        $UpdatePackManResult = Update-PackageManagement -UseChocolatey
        if (![bool]$UpdatePackManResult) {
            Write-Error "The Update-PackageManagement function failed! Halting!"
            $global:FunctionResult = "1"
            result
        }
    
        # Make sure the Chocolatey binary paths are part of our $env:Path
        # If the chocolatey cmdline is not installed, assume that we should look for chocolatey
        # binaries under C:\Chocolatey recursively, else, assume we should look under
        # C:\ProgramData\chocolatey\lib recursively
        if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
            $ChocolateyPath = "C:\Chocolatey"
        }
        else {
            $ChocolateyPath = "$($($(Get-Command choco).Source -split "chocolatey")[0])chocolatey"
        }
        [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
        [System.Collections.ArrayList]$ChocolateyPathsToAddToEnvPath = @()
        if (Test-Path $ChocolateyPath) {
            $OtherChocolateyPathsToAdd = $(Get-ChildItem $ChocolateyPath -Directory | foreach {
                Get-ChildItem $_.FullName -Recurse -File
            } | foreach {
                if ($_.Extension -eq ".exe" -or $_.Extension -eq ".bat") {
                    $_.Directory.FullName
                }
            }) | foreach {
                $null = $ChocolateyPathsPrep.Add($_)
            }
    
            foreach ($ChocoPath in $ChocolateyPathsPrep) {
                if ($(Test-Path $ChocoPath) -and $($env:Path -split ";") -notcontains $ChocoPath) {
                    $null = $ChocolateyPathsToAddToEnvPath.Add($ChocoPath)
                }
            }
    
            foreach ($ChocoPath in $ChocolateyPathsToAddToEnvPath) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path" + $ChocolateyPath + ";"
                }
                else {
                    $env:Path = "$env:Path" + ";" + $ChocoPath
                }
            }
        }
        else {
            Write-Verbose "Unable to find Chocolatey Path $ChocolateyPath."
        }
        
    
        $EtcdServiceCimInstance = Get-CimInstance -Class Win32_Service -Filter "Name='etcd'"
        # If the etcd Windows Service doesn't point to the nssm.exe binary, then delete it
        if ($EtcdServiceCimInstance) {
            if ($EtcdServiceCimInstance.PathName -notmatch "nssm.exe" -or !$(Test-Path $EtcdServiceCimInstance.PathName)) {
                # Neet to use Get-WMIObject because Get-CimInstance doesn't give us the Delete() method
                $EtcdServiceToDelete = Get-WMIObject -Class Win32_Service -Filter "Name='etcd'"
                $EtcdServiceToDelete.Delete()
                $WindowsServiceDeleted = $true
            }
        }
        else {
            $WindowsServiceDNE = $true
        }
    
        # If we're in any weird install state, uninstall and reinstall. Install-Package etcd should
        # take care of creating the Windows Service pointing to the nssm.exe binary...
        if ($(Get-Package etcd -ErrorAction SilentlyContinue).Status -ne "Installed" -or $WindowsServiceDeleted -or $WindowsServiceDNE) {
            Uninstall-Package etcd -ErrorAction SilentlyContinue
            $EtcdPackageInstall = Install-Package etcd
            if (![bool]$EtcdPackageInstall) {
                Write-Error "'Install-Package etcd' failed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        # ...but it might not. So double check that it's there...
        $EtcdServiceCimInstance = Get-CimInstance -Class Win32_Service -Filter "Name='etcd'"
        if (!$EtcdServiceCimInstance) {
            Write-Verbose "The etcd service still needs to be installed!"
    
            if ($(Get-Package nssm -ErrorAction SilentlyContinue).Status -ne "Installed") {
                $NSSMPackageInstall = Install-Package nssm
            }
    
            # NOTE: NSSM binary should be readily available because we just updated our $env:Path with
            # all Chocolatey paths right after we ran the Update-PackageManagement cmdlet above and
            # `Install-Package nssm` above should also take care of updating $env:Path...
    
            # Check To See if nssm recognizes etcd as an installed service
            $NSSMPath = $(Get-Command nssm).Source
            $CheckServiceOutput = Run-Binary -BinaryPath $NSSMPath -Arguments "status etcd"
            # If there isn't an NSSM Service called etcd, create/install it with NSSM
            if ($CheckServiceOutput.AllOutput -match "service does not exist") {
                $CheckNSSMServiceInstallOutput = Run-Binary -BinaryPath $NSSMPath -Arguments "install etcd `"C:\ProgramData\etcd\etcd.exe`" `"--config-file C:\ProgramData\etcd\etcd.config.yml`""
                if ($CheckNSSMServiceInstallOutput.AllOutput -notmatch "installed successfully") {
                    Write-Error "Something went wrong when attemting to install the etcd service with nssm! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            
            # Now, the actual Windows Service called etcd (as opposed to the above nssm service of the same name)
            # needs to be created
            $EtcdWindowsService = New-Service -Name "etcd" -BinaryPathName $NSSMPath -DisplayName "etcd" -StartupType Automatic -Description "Etcd key/value pair cluster"
            if (![bool]$EtcdWindowsService) {
                Write-Error "Unable to create the etcd Windows Service pointing to the NSSM binary! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        # Make sure NSSM References the etcd.config.yml file
        $NSSMPath = $(Get-Command nssm).Source
        $SetNSSMServiceAppSet = Run-Binary -BinaryPath $NSSMPath -Arguments "set etcd Application `"C:\ProgramData\etcd\etcd.exe`"" 
        $SetNSSMServiceAppArgsSet = Run-Binary -BinaryPath $NSSMPath -Arguments "set etcd AppParameters `"--config-file C:\ProgramData\etcd\etcd.config.yml`""
    
        # Make sure etcdctl is part of your $env:Path
        if (!$(Get-Command etcdctl -ErrorAction SilentlyContinue)) {
            # Try and find etcdctl
            # First, make sure C:\ProgramData\etcd is part of $env:Path, because that's where etcdctl usually is
            if ($($env:Path -split ";") -notcontains "C:\ProgramData\etcd") {
                if (Test-Path "C:\ProgramData\etcd") {
                    if ($env:Path[-1] -eq ";") {
                        $env:Path = "$env:Path" + "C:\ProgramData\etcd" + ";"
                    }
                    else {
                        $env:Path = "$env:Path" + ";" + "C:\ProgramData\etcd"
                    }
                }
                else {
                    Write-Verbose "Unable to find the directory C:\ProgramData\etcd. Did something go wrong with etcd installation?"
                }
            }
    
            # If we still can't find etcdctl, then we have no idea where it is and need to halt.
            if (!$(Get-Command etcdctl -ErrorAction SilentlyContinue)) {
                Write-Error "Can't find etcdctl.exe! Use the -Verbose parameter to find out which directories were checked. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        
        # Get Discovery Url
        # $NumberOfHostsInCluster = 3
        # $NewDiscoveryUrl = $(Invoke-WebRequest -Uri "https://discovery.etcd.io/new?size=$NumberOfHostsInCluster").Content
    
        ##### BEGIN Etcd Config File C:\ProgramData\etcd\etcd.config.yml #####
    
    #region
    
        # From: https://github.com/coreos/etcd/blob/master/etcd.conf.yml.sample
        $EtcdConfigFile = @" 
# This is the configuration file for the etcd server.

# Human-readable name for this member.
name: '$LocalHostName'

# Path to the data directory.
data-dir: '$LocalHostDataDirectory'

# Path to the dedicated wal directory.
wal-dir:

# Number of committed transactions to trigger a snapshot to disk.
snapshot-count: 10000

# Time (in milliseconds) of a heartbeat interval.
heartbeat-interval: 100

# Time (in milliseconds) for an election to timeout.
election-timeout: 1000

# Raise alarms when backend size exceeds the given quota. 0 means use the
# default quota.
quota-backend-bytes: 0

# List of comma separated URLs to listen on for peer traffic.
# 0.0.0.0 means that all IPs on all interfaces will listen on the specified port
listen-peer-urls: http://0.0.0.0:2380

# List of comma separated URLs to listen on for client traffic.
# 0.0.0.0 means that all IPs on all interfaces will listen on the specified port
listen-client-urls: http://0.0.0.0:2379

# Maximum number of snapshot files to retain (0 is unlimited).
max-snapshots: 5

# Maximum number of wal files to retain (0 is unlimited).
max-wals: 5

# Comma-separated white list of origins for CORS (cross-origin resource sharing).
cors:

# List of this member's peer URLs to advertise to the rest of the cluster.
# The URLs needed to be a comma-separated list.
initial-advertise-peer-urls: http://$LocalHostIP`:2380

# List of this member's client URLs to advertise to the public.
# The URLs needed to be a comma-separated list.
advertise-client-urls: http://$LocalHostIP`:2379

# Discovery URL used to bootstrap the cluster.
discovery:

# Valid values include 'exit', 'proxy'
discovery-fallback: 'proxy'

# HTTP proxy to use for traffic to discovery service.
discovery-proxy:

# DNS domain used to bootstrap initial cluster.
discovery-srv:

# Initial cluster configuration for bootstrapping.
initial-cluster: $InitialClusterString

# Initial cluster token for the etcd cluster during bootstrap.
initial-cluster-token: 'etcd-cluster-1'

# Initial cluster state ('new' or 'existing').
initial-cluster-state: 'new'

# Reject reconfiguration requests that would cause quorum loss.
strict-reconfig-check: true

# Accept etcd V2 client requests
enable-v2: true

# Enable runtime profiling data via HTTP server
enable-pprof: true

# Valid values include 'on', 'readonly', 'off'
proxy: 'off'

# Time (in milliseconds) an endpoint will be held in a failed state.
proxy-failure-wait: 5000

# Time (in milliseconds) of the endpoints refresh interval.
proxy-refresh-interval: 30000

# Time (in milliseconds) for a dial to timeout.
proxy-dial-timeout: 1000

# Time (in milliseconds) for a write to timeout.
proxy-write-timeout: 5000

# Time (in milliseconds) for a read to timeout.
proxy-read-timeout: 0

client-transport-security:
    # DEPRECATED: Path to the client server TLS CA file.
    ca-file:

    # Path to the client server TLS cert file.
    cert-file:

    # Path to the client server TLS key file.
    key-file:

    # Enable client cert authentication.
    client-cert-auth: false

    # Path to the client server TLS trusted CA key file.
    trusted-ca-file:

    # Client TLS using generated certificates
    auto-tls: true

peer-transport-security:
    # DEPRECATED: Path to the peer server TLS CA file.
    ca-file:

    # Path to the peer server TLS cert file.
    cert-file:

    # Path to the peer server TLS key file.
    key-file:

    # Enable peer client cert authentication.
    peer-client-cert-auth: false

    # Path to the peer server TLS trusted CA key file.
    trusted-ca-file:

    # Peer TLS using generated certificates.
    auto-tls: true

# Enable debug-level logging for etcd.
debug: false

# Specify a particular log level for each etcd package (eg: 'etcdmain=CRITICAL,etcdserver=DEBUG'.
log-package-levels:

# Specify 'stdout' or 'stderr' to skip journald logging even when running under systemd.
log-output: default

# Force to create a new one member cluster.
force-new-cluster: false
"@
    
    #endregion
        
        ##### END Etcd Config File C:\ProgramData\etcd\etcd.config.yml #####
    
        if (!$(Test-Path "C:\ProgramData\etcd\etcd.exe")) {
            Write-Error "Unable to find etcd.exe needed in order to establish the etcd service! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        Set-Content -Path "C:\ProgramData\etcd\etcd.config.yml" -Value $EtcdConfigFile
    
        if (!$(Get-Service etcd)) {
            try {
                $EtcdService = New-Service -Name "etcd" -BinaryPathName "C:\ProgramData\etcd\etcd.exe --config-file C:\ProgramData\etcd\etcd.config.yml" -DisplayName "etcd" -StartupType Automatic -Description "Etcd key/value pair cluster"
                if (![bool]$EtcdService) {
                    throw
                }
    
                $null = sc.exe failure etcd reset=86400 actions= restart/60000/restart/60000/restart/60000
            }
            catch {
                Write-Error "Unable create new etcd service using the New-Service cmdlet! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        
        [pscustomobject]@{
            EtcdPackage = Get-Package etcd
            EtcdService = Get-Service etcd
        }
    }

    ##### END Native Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Error "The Install-Etcd function must be run with Elevated privileges (i.e. run PowerShell via Run As Administrator). Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($HostNamesOrIPsOfHostsInCluster.Count -lt 3) {
        Write-Error "A minimum of 3 hosts are required in order to establish quorum. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$LocalHostDataDirectory) {
        $LocalHostDataDirectory = "C:\etcd"
    }

    # Challenge Bootstrapping new Cluster, because if a preivous cluster was established using these hosts
    # all previous cluster data will be wiped out!
    Write-Warning "You are bootstrapping a NEW Etcd Cluster. If any data exists in $LocalHostDataDirectory on each of the Cluster Members, then that data will be completely deleted!"
    $ShouldWeContinue = Read-Host -Prompt "Do you want to continue? [Yes\No]"
    $ValidContinueChoices = @("Yes","yes","Y","y","No","no","N","n")
    if ($ValidContinueChoices -notcontains $ShouldWeContinue) {
        Write-Error "$ShouldWeContinue is not a valid option!. Valid options are Yes, Y, No, N. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ShouldWeContinue -match "No|no|N|n") {
        Write-Error "User does not want to continue! Halting!"
        $global:FunctionResult = "1"
        return
    }


    # Prep Update-PackageManagement function to be sent within an Invoke-Command scriptblock
    [System.Collections.ArrayList]$GetUpdatePackageManagementFunction = $(Get-Command Update-PackageManagement).Definition -split "`n"
    $GetUpdatePackageManagementFunction.Insert(0, "function Update-PackageManagement {")
    $GetUpdatePackageManagementFunction.Insert($GetUpdatePackageManagementFunction.Count, "}")
    $GetUpdatePackageManagementFunctionAsString = $GetUpdatePackageManagementFunction -join "`n"

    # Prep Install-Etcd function to be sent within an Invoke-Command scriptblock
    [System.Collections.ArrayList]$InstallEtcdFunction = $(Get-Command Install-Etcd).Definition -split "`n"
    $InstallEtcdFunction.Insert(0, "function Install-Etcd {")
    $InstallEtcdFunction.Insert($InstallEtcdFunction.Count, "}")
    $InstallEtcdFunctionAsString = $InstallEtcdFunction -join "`n"

    [System.Collections.ArrayList]$ClusterMemberFQDNandIPInfo = @()
    [System.Collections.ArrayList]$ResolveHostFailures = @()
    foreach ($ClusterMember in $HostNamesOrIPsOfHostsInCluster) {
        try {
            $FQDNandIPInfo = Resolve-Host -HostNameOrIP $ClusterMember -ErrorAction SilentlyContinue

            if (![bool]$FQDNandIPInfo) {
                throw
            }

            $null = $ClusterMemberFQDNandIPInfo.Add($FQDNandIPInfo)
        }
        catch {
            $null = $ResolveHostFailures.Add($ClusterMember)
        }
    }
    if ($ResolveHostFailures.Count -gt 0) {
        Write-Error "Unable to resolve the following host(s) via DNS query: $($ResolveHostFailures -join ', '). Halting!"
        $global:FunctionResult = "1"
        return
    }

    # At this point, cluster member info is contained within $ClusterMemberFQDNandIPInfo
    # i.e. $HostNamesOrIPsOfHostsInCluster has become $ClusterMemberFQDNandIPInfo

    $InstallEtcdParams = @{
        ClusterMemberFQDNandIPInfo              = $ClusterMemberFQDNandIPInfo
        LocalHostDataDirectory                  = $LocalHostDataDirectory
        UpdatePackageManagementFunctionAsString = $GetUpdatePackageManagementFunctionAsString
    }

    [System.Collections.ArrayList]$EtcdInstallSuccess = @()
    [System.Collections.ArrayList]$EtcdInstallFailure = @()
    foreach ($ClusterMember in $ClusterMemberFQDNandIPInfo) {        
        try {
            Write-Host "Configuring etcd on $($ClusterMember.FQDN) ... Please wait ..."
            # NOTE that the Install-Etcd function returns `Get-Package etcd` and `Get-Service etcd` 
            # details even if the package and service are already installed/configured. So this try block
            # throws only if there is a legitimate error and nothing is returned.
            $InstallEtcdResult = Invoke-Command -ComputerName $ClusterMember.FQDN -ScriptBlock {
                # Dot Source the Install-Etcd function
                $InstallEtcdSB = [scriptblock]::Create($using:InstallEtcdFunctionAsString)
                . $InstallEtcdSB
                Install-Etcd @using:InstallEtcdParams
            }

            if (![bool]$InstallEtcdResult) {
                throw
            }

            $InstallSuccess = [pscustomobject]@{
                ClusterMember       = $ClusterMember
                InstallEtcdResult   = $InstallEtcdResult
            }

            $null = $EtcdInstallSuccess.Add($InstallSuccess)
        }
        catch {
            if ($Error[0] -match "Connecting to remote server") {
                try {
                    if (!$RemoteHostCredentials) {
                        Write-Warning "Connecting to remote server $($ClusterMember.FQDN) failed using credentials of the current user."
                        $UserName = Read-Host -Prompt "Please enter a user name with access to $($ClusterMember.FQDN)"
                        $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString

                        $Creds = New-Object System.Management.Automation.PSCredential ($UserName, $Password)
                    }
                    else {
                        $Creds = $RemoteHostCredentials
                    }

                    # Adding Credentials Property to $ClusterMember PSCustomObject for use in later remote commands...
                    $ClusterMember | Add-Member -MemberType NoteProperty -Name Credentials -Value $Creds

                    $InstallEtcdResult = Invoke-Command -ComputerName $ClusterMember.FQDN -Credential $Creds -ScriptBlock {
                        # Dot Source the Install-Etcd function
                        $InstallEtcdSB = [scriptblock]::Create($using:InstallEtcdFunctionAsString)
                        . $InstallEtcdSB
                        Install-Etcd @using:InstallEtcdParams
                    }
                
                    if (![bool]$InstallEtcdResult) {
                        throw
                    }

                    $InstallSuccess = [pscustomobject]@{
                        ClusterMember       = $ClusterMember
                        InstallEtcdResult   = $InstallEtcdResult
                    }
        
                    $null = $EtcdInstallSuccess.Add($InstallSuccess)
                    
                }
                catch {
                    Write-Error $Error[0]
                    Write-Warning "Etcd install on $($ClusterMember.FQDN) failed! Moving on to etcd installation on next Cluster Member..."

                    $null = $EtcdInstallFailure.Add($ClusterMember)
                    continue
                }
            }
            else {
                Write-Error $Error[0]
                $null = $EtcdInstallFailure.Add($ClusterMember)
                continue
            }
        }
    }

    if ($EtcdInstallFailure.Count -gt 0) {
        $FailedClusterMembers = $EtcdInstallFailure | foreach {$_.FQDN}
        Write-Warning "Unable to install etcd on the following Cluster Members: $($FailedClusterMembers -join ', ')"
        Write-Error "Unable to setup cluster! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($EtcdInstallSuccess.ClusterMember.Count -eq $HostNamesOrIPsOfHostsInCluster.Count) {
        $NewClusterInfo = $EtcdInstallSuccess.ClusterMember
    }
    else {
        Write-Error "Unable to define NewClusterInfo after running the Install-Etcd function on the Cluster Members! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # At this point, cluster member info is contained within $NewClusterInfo

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    Write-Host "Starting etcd service on each of the Cluster Members ..."

    [System.Collections.ArrayList]$EtcdStartServiceSuccess = @()
    [System.Collections.ArrayList]$EtcdStartServiceFailure = @()
    foreach ($ClusterMember in $NewClusterInfo) {
        try {
            $StartEtcdService = Invoke-Command -ComputerName $ClusterMember.FQDN -ScriptBlock {
                # Make sure $LocalHostDataDirectory is clean
                if (Test-Path $using:LocalHostDataDirectory) {
                    $DataDirItems = Get-ChildItem $using:LocalHostDataDirectory
                    foreach ($item in $DataDirItems) {
                        Remove-Item -Recurse $item.FullName -Force
                    }
                }
                Start-Service etcd
                Get-Service etcd
            } -ErrorAction SilentlyContinue

            if (![bool]$StartEtcdService) {
                throw
            }

            $ClusterMemberEtcdServiceInfo = [pscustomobject]@{
                ClusterMember       = $ClusterMember
                EtcdServiceStatus   = $StartEtcdService
            }

            $null = $EtcdStartServiceSuccess.Add($ClusterMemberEtcdServiceInfo)
        }
        catch {
            if ($Error[0] -match "Connecting to remote server") {
                try {
                    if ($ClusterMember.Credentials) {
                        $Creds = $ClusterMember.Credentials

                        $StartEtcdService = Invoke-Command -ComputerName $ClusterMember.FQDN -Credential $Creds -ScriptBlock {
                            # Make sure $LocalHostDataDirectory is clean
                            if (Test-Path $using:LocalHostDataDirectory) {
                                $DataDirItems = Get-ChildItem $using:LocalHostDataDirectory
                                foreach ($item in $DataDirItems) {
                                    Remove-Item -Recurse $item.FullName -Force
                                }
                            }
                            Start-Service etcd
                            Get-Service etcd
                        } -ErrorAction SilentlyContinue
                        
                        if (![bool]$StartEtcdService) {
                            throw
                        }

                        $ClusterMemberEtcdServiceInfo = [pscustomobject]@{
                            ClusterMember       = $ClusterMember
                            EtcdServiceStatus   = $StartEtcdService
                        }
            
                        $null = $EtcdStartServiceSuccess.Add($ClusterMemberEtcdServiceInfo)
                    }
                    else {
                        $NetworkProblem = $true
                        throw
                    }
                }
                catch {
                    if ($NetworkProblem) {
                        Write-Warning "Starting the service etcd on $($ClusterMember.FQDN) failed due to a network connection issue! Moving on to try and start the service on next Cluster Member..."
                    }
                    else {
                        Write-Error $Error[0]
                        Write-Warning "Starting the service etcd on $($ClusterMember.FQDN) failed! Moving on to try and start the service on next Cluster Member..."
                    }

                    $null = $EtcdStartServiceFailure.Add($ClusterMember)
                    continue
                }
            }
            else {
                Write-Error $Error[0]
                $null = $EtcdInstallFailure.Add($ClusterMember)
                continue
            }
        }
    }

    if ($EtcdStartServiceFailure.Count -gt 0) {
        Write-Error "Failed to start the etcd Service on the following Cluster Members: $($EtcdStartServiceFailure.FQDN -join ', ')! Please check the status of the service on each host! Halting!"
        $BootstrapStatus = "Check Etcd Service on Cluster Members"
    }

    [System.Collections.ArrayList]$NeedToCheckEtcdServiceOnTheseHosts = @()
    foreach ($ClusterMemberEtcdServiceObj in $EtcdStartServiceSuccess) {
        if ($EtcdStartServiceSuccess.EtcdServiceStatus.Status -ne "Running") {
            $null = $NeedToCheckEtcdServiceOnTheseHosts.Add($ClusterMemberEtcdServiceObj.ClusterMember)
        }
    }

    if ($NeedToCheckEtcdServiceOnTheseHosts.Count -gt 0) {
        Write-Warning "The status of the etcd Service on the following Cluster Members is not reporting 'Started': $($NeedToCheckEtcdServiceOnTheseHosts.FQDN -join ', ')"
        Write-Warning "Please check the etcd Service on each of the Cluster Members!"
        $BootstrapStatus = "Check Etcd Service on Cluster Members"
    }

    # Check Cluster Health and Member List and output PSCustomObject
    $ClusterHealth = etcdctl cluster-health
    $i = 0

    if ($($ClusterHealth -join "`n") -match "unhealthy") {
        do {
            $i++
            Write-Host "Waiting for all cluster members to contact each other..."
            Start-Sleep -Seconds 2
            $ClusterHealth = etcdctl cluster-health
        } until ($i -eq 5 -or $($ClusterHealth -join "`n") -notmatch "unhealthy")
    }

    if ($($ClusterHealth -join "`n") -match "unhealthy") {
        Write-Error "The Cluster Members are having trouble contacting each other. The cluster is currently unhealthy. Please check network connectivity and/or the etcd service on each Cluster Member."
    }

    $MemberList = etcdctl member list

    # This is just to look pretty...
    Write-Host "`nCluster Health:`n"
    foreach ($entry in $ClusterHealth) {
        Write-Host $entry
    }

    Write-Host "`nMember List:`n"
    foreach ($entry in $MemberList) {
        Write-Host $entry
    }

    Write-Host "`n"

    # This is the actual output of the function that can be captured
    [pscustomobject]@{
        ClusterHealth = $ClusterHealth
        MemberList = $MemberList
    }

    <#
    PS C:\Users\testadmin> etcdctl cluster-health
    member 37c7293f829e1c56 is healthy: got healthy result from http://192.168.2.41:2379
    member 3d38fc7e73d8fa48 is healthy: got healthy result from http://192.168.2.30:2379
    member 87466d9de01c47d0 is healthy: got healthy result from http://192.168.2.145:2379
    cluster is healthy

    PS C:\Users\testadmin> etcdctl member list
    37c7293f829e1c56: name=Win16Chef peerURLs=http://192.168.2.41:2380 clientURLs=http://192.168.2.41:2379 isLeader=true
    3d38fc7e73d8fa48: name=win12chef peerURLs=http://192.168.2.30:2380 clientURLs=http://192.168.2.30:2379 isLeader=false
    87466d9de01c47d0: name=win12ws peerURLs=http://192.168.2.145:2380 clientURLs=http://192.168.2.145:2379 isLeader=false


    etcdctl set foo bar
    etcdctl exec-watch foo -- powershell.exe -NoProfile -Command "Write-Host 'Hi'"
    #>

    ##### END Main Body #####

}



















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUY48ckU8RMynI9U8NTWL2LypD
# CDSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPTY3i6KeHElBHax
# vSp0FRzhqD6uMA0GCSqGSIb3DQEBAQUABIIBABVbprl88KnXule1mJreE88vP2t1
# eIB2qpb9sRaYyf9GBpzU3tL79hou3C3LkA9gZYybjVcyvQqBlAak5cDuDAXpIIM8
# nWO/mcaJnAph09unD7mJDYSAf4paWo78ti98ApApSCZO1O3vEzurOZiCsdJLHaNs
# lH9hQPvzwxp62N6Q7dOWkwfelbdEXQCjiR9oRP0pCrnx/rqayoeqUQABCsTbcy4F
# +4MvX4Axw890UqnAAsfwgA0MFvoPti9y52Vhe+PUrwtzjkU8saknd18GYTLG99nl
# l3YtVNwDanXElSo1SZ+eKsB+tVUjlHXb0ydd7UXGdMFzwM8qKTcxDk0RIrs=
# SIG # End signature block
