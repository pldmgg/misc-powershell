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

function Verify-Directory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $DirectoryPath
    )

    ##### BEGIN Main Body #####

    $pos = $DirectoryPath.LastIndexOf("\")
    $DirectoryNameOnly = $DirectoryPath.Substring($pos+1)

    if (!$($([uri]$DirectoryPath).IsAbsoluteURI -and $($([uri]$DirectoryPath).IsLoopBack -or $([uri]$DirectoryPath).IsUnc)) -or
    $($DirectoryNameOnly | Select-String -Pattern "\.")) {
        Write-Verbose "$DirectoryPath is not a valid directory path! Halting!"
        Write-Error "$DirectoryPath is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $DirectoryPath)) {
        Write-Verbose "The path $DirectoryPath was not found! Halting!"
        Write-Error "The path $DirectoryPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Main Body #####
}


function Reflect-Cmdlet {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $CmdletOrFunc = $(Read-Host -Prompt "Please enter the name of the PowerShell cmdlet or function that you would like to investigate.")
    )

    ##### BEGIN Helper Functions #####

    function Expand-Zip {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,Position=0)]
            [string]$PathToZip,
            [Parameter(Mandatory=$true,Position=1)]
            [string]$TargetDir
        )
        
        Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Expand-Archive -Path $PathToZip -DestinationPath $TargetDir
        }
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            # Load System.IO.Compression.Filesystem 
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

            # Unzip file
            [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
        }
    }

    ##### END Helper Functions #####


    ##### BEGIN Main Body #####

    # See: https://powershell.org/forums/topic/how-i-can-see-powershell-module-methods-source-code/
    # For Functions
    if ($(Get-Command $CmdletOrFunc -ErrorAction SilentlyContinue).CommandType -eq "Function") {
        if ($(Get-Command $CmdletOrFunc -ErrorAction SilentlyContinue).ScriptBlock.File -ne $null) {
            $functionLocation = $(Get-Command $CmdletOrFunc).ScriptBlock.File
        }
        else {
            Write-Verbose "Unable to find the file that contains this function's code. Halting!"
            Write-Error "Unable to find the file that contains this function's code. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
    }
    

    # For Cmdlets (i.e. C# dll-based)
    if ($(Get-Command $CmdletOrFunc -ErrorAction SilentlyContinue).CommandType -eq "Cmdlet") {
        if (!$(Get-Command ILSpy -ErrorAction SilentlyContinue)) {
            $ILSpySite = Invoke-WebRequest -Uri "http://ilspy.net/"
            $ILSpyBinaryZip = $($ILSpySite.Links | ? {$_.href -like "*master*" -and $_.href -like "*.zip*" -and $_.href -like "*Binar*"}).href
            $ILSpyBinaryZipFileName = $ILSpyBinaryZip | Split-Path -Leaf
            $ILSpyBinaryZipFolderName = $ILSpyBinaryZipFileName -replace ".zip","" | Split-Path -Leaf
            Invoke-WebRequest -Uri $ILSpyBinaryZip -OutFile "$HOME\Downloads\$ILSpyBinaryZipFileName"
            if (!$(Test-Path "$HOME\Downloads\$ILSpyBinaryZipFolderName")) {
                New-Item -Type Directory -Path "$HOME\Downloads\$ILSpyBinaryZipFolderName"
            }
            Expand-Zip -PathToZip "$HOME\Downloads\$ILSpyBinaryZipFileName" -TargetDir "$HOME\Downloads\$ILSpyBinaryZipFolderName"
            Copy-Item -Recurse -Path "$HOME\Downloads\$ILSpyBinaryZipFolderName" -Destination "$HOME\Documents\$ILSpyBinaryZipFolderName"

            $EnvPathArray = $env:Path -split ";"
            if ($EnvPathArray -notcontains "$HOME\Documents\$ILSpyBinaryZipFolderName") {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$HOME\Documents\$ILSpyBinaryZipFolderName"
                }
                else {
                    $env:Path = "$env:Path;$HOME\Documents\$ILSpyBinaryZipFolderName"
                }
            }
        }

        if ($(Get-Command $CmdletOrFunc).ImplementingType.Assembly.Location -ne $null) {
            $dllLocation = $(Get-Command $CmdletOrFunc).ImplementingType.Assembly.Location
        }
        else {
            Write-Verbose "Unable to find the dll file that $CmdletOrFunc is based on. It is possble that multiple dlls are used to create this cmdlet. Halting!"
            Write-Error "Unable to find the dll file that $CmdletOrFunc is based on. It is possble that multiple dlls are used to create this cmdlet. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($functionLocation) {
        $(Get-Command $CmdletOrFunc).ScriptBlock
    }
    if ($dllLocation) {
        ILSpy $dllLocation

        Write-Host "Please wait up to 10 seconds for the ILSpy GUI to open."
    }

    # For CIM commands, browse the cdxml files in the command's module directory

    ##### END Main Body #####

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
function Update-PackageManagement {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        [switch]$UseChocolatey,

        [Parameter(Mandatory=$False)]
        [switch]$InstallNuGetCmdLine
    )

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
            $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to use the Chocolatey Package Provider (NOTE: This is NOT an installation of the chocolatey command line)?"
            $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
            if ($WarningResponse) {
                $UseChocolatey = $true
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
            $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to install Chocolatey Command Line Tools in order to install NuGet Command Line Tools?"
            $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
            if ($WarningResponse) {
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
                    Start-Process "cup" -ArgumentList "nuget.commandline -y" -Wait -NoNewWindow
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
    Write-Host "PackageManagement Latest Version is: $PackageManagementLatestVersion"
    Write-Host "PowerShellGetLatestVersion Latest Version is: $PowerShellGetLatestVersion"

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
    Write-Host "Latest locally available PackageManagement version is $PackageManagementLatestLocallyAvailableVersion"
    Write-Host "Latest locally available PowerShellGet version is $PowerShellGetLatestLocallyAvailableVersion"

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
            # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
            Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion ..."
            $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -ErrorVariable ImportPackManProblems 2>&1 6>&1
            Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
            $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -ErrorVariable ImportPSGetProblems 2>&1 6>&1
        }
        if ($(Get-Host).Name -eq "Package Manager Host") {
            Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
    
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
    Write-Host "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Host "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
    
    if ($CurrentlyLoadedPowerShellGetVersion -lt $PowerShellGetLatestLocallyAvailableVersion) {
        if (!$ImportPSGetProblems) {
            Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
        }
        Remove-Module -Name "PowerShellGet"
    
        if ($(Get-Host).Name -ne "Package Manager Host") {
            Write-Host "We are NOT in the Visual Studio Package Management Console. Continuing..."
            
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
    Write-Host "The FINAL loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Host "The FINAL loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

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


<#
.SYNOPSIS
    The Register-FileIOWatcher function watches one or more files and/or subdirectories (and their contents) within a specified
    Target Directory for particular file events. When an event occurs, the specified action will be taken.

.DESCRIPTION
    See SYNOPSIS and PARAMETER sections.

.PARAMETER TargetDir
    This parameter is MANDATORY.

    This parameter takes a string that represents a directory that contains one or more files and/or subdirectories that you
    would like to monitor for changes.

.PARAMETER FilesToWatchRegexMatch
    This parameter is OPTIONAL.

    This parameter takes a regex value that specifies one or more files or subdirectories to monitor within the $TargetDir.

    Either this parameter or FilesToWatchEasyMatch MUST be used.

.PARAMETER FilesToWatchEasyMatch
    This parameter is OPTIONAL

    This parameter takes a string value that is pseudo-regex. It accepts wildcard characters. Examples:

        *.*             matches    All files
        *.txt           matches    All files with a "txt" extension.
        *recipe.doc     matches    All files ending in "recipe" with a "doc" extension.
        win*.xml        matches    All files beginning with "win" with an "xml" extension.
        Sales*200?.xls  matches    Files such as "Sales_July_2001.xls","Sales_Aug_2002.xls","Sales_March_2004.xls"
        MyReport.Doc    matches    Only MyReport.doc

    NOTE: You CANNOT use multiple filters such as "*.txt|*.doc". If you would like this functionality, use the
    FilesToWatchRegexMatch parameter.

    Either this parameter or FilesToWatchRegexMatch MUST be used.

.PARAMETER IncludeSubdirectories
    This parameter is OPTIONAL.

    This parameter is a switch. Include it if you want to monitor subdirectories (and their contents) within $TargetDir.

.PARAMETER Trigger
    This parameter is MANDATORY.

    This parameter takes a string and must be one of the following values:
    "Changed","Created","Deleted","Disposed","Error","Renamed"

    This parameter specifies when a particular event (and its associated action) are triggered.

.PARAMETER LogDir
    This parameter is MANDATORY.

    This parameter takes a string that represents a path to a directory that will contain a folder called "FileIOWatcherEvents"
    that contains .xml files that represent PSCustomObjects that contain the results of a triggered event. These PSCustomObjects
    can be imported back into PowerShell at a future time for analysis by using:

    $EventTriggerResultCustomObject = Import-Clixml "$LogDir\FileIOWatcherEvents\<FriendlyNameForEvent>_<SourceIdentifierLast4>_<EventIdentifier>.xml"

    For more information on this, see the NOTES section.

.PARAMETER FriendlyNameForEvent
    This parameter is OPTIONAL.

    This parameter takes a string that will become the name of the object that becomes available in the scope that runs this function after
    the function concludes.

    For example if the function is run as follows...
        Register-FileIOWatcher -TargetDir "$TestTargetDir" `
        -FilesToWatchEasyMatch "SpecificDoc.txt" `
        -Trigger "Changed" `
        -LogDir $LogDirectory `
        -FriendlyNameForEvent "EventForSpecificDocChange" `
        -ActionToTakeScriptBlock $ActionToTake
    ...you will be able to see the result of the function by calling the variable $EventForSpecificDocChange.

.PARAMETER ActionToTakeScriptBlock
    This parameter is MANDATORY.

    This parameter takes EITHER a string (that will later be converted to a scriptblock object), or a scriptblock object.

    The scriptblock provided to this parameter defines specifically what action will take place when an event is triggered.

.EXAMPLE
    Try the following:
    (IMPORTANT: Make sure the characters '@ are justified all-the-way to the left regardless of indentations elsewhere)

    $TestTargetDir = "$HOME"
    $DirName = $HOME | Split-Path -Leaf
    $LogDirectory = "M:\Logs\PowerShell"
    $GCITest = Get-ChildItem -Path "$HOME\Downloads"

    $ActionToTake = @'
Write-Host "Hello there!"

Write-Host "Writing Register-FileIOWatcher value for parameter -Trigger"
Write-Host "$Trigger"
Write-Host "Writing fullname of the first item in `$GCITest object index to STDOUT"
Write-Host "$($GCITest[0].FullName)"
Write-Host "Setting new variable `$AltGCI equal to `$GCITest"
$AltGCI = $GCITest
Write-Host "Writing `$AltGCI out to file `$HOME\Documents\AltGCIOutput.txt"
$AltGCI | Out-File $HOME\Documents\AltGCIOutput.txt

Write-Host "Bye!"
'@

    Register-FileIOWatcher -TargetDir "$TestTargetDir" `
    -FilesToWatchEasyMatch "SpecificDoc.txt" `
    -Trigger "Changed" `
    -LogDir $LogDirectory `
    -FriendlyNameForEvent "EventForSpecificDocChange" `
    -ActionToTakeScriptBlock $ActionToTake

    Next, create/make a change to the file $HOME\SpecificDoc.txt and save it. This will trigger the
    $ActionToTake scriptblock. (Note that $ActionToTake is actually a string that is converted a scriptblock object 
    by the function). Anything in the scriptblock using the Write-Host cmdlet will appear in STDOUT in your active PowerShell 
    session. If your scriptblock does NOT use the Write-Host cmdlet, it will NOT appear in your active PowerShell session
    (but, of course, the operations will still occur).

.OUTPUTS
    Output for this function is a System.Management.Automation.PSEventJob object named after the string provided to the
    -FriendlyNameForEvent parameter. If the -FriendlyNameForEvent parameter is not used, the System.Management.Automation.PSEventJob
    object will be called $EventFor<TargetDirName>.

.NOTES
    KNOWN BUG:
    There is a known bug with System.IO.FileSystemWatcher objects involving triggers firing multiple times for 
    singular events. For details, see: http://stackoverflow.com/questions/1764809/filesystemwatcher-changed-event-is-raised-twice 

    This function works around this bug by using Size as opposed to LastWrite time in the IO.FIleSystemWatcher object's
    NotifyFilter property. However, there is one drawback to this workaround: If the file is modified and remains
    EXACTLY the same size (not very likely, but still possible), then the event will NOT trigger.

    HOW TO ANALYZE TRIGGERED EVENT RESULTS:
    To analyze results of a triggered event, perform the following steps

    Get the Event's SourceIdentifier and the last 4 characters of the SourceIdentifier. Assuming we are using the output from our
    above EXAMPLE (i.e. $EventForSpecificDocChange), we get this information by doing the following:
        $EventForSpecificDocChangeSourceIdentifier = $EventForSpecificDocChange.Name
        $EventForSpecificDocChangeSourceIdentifierLast4 = $EventForSpecificFocChangeSourceIdentifier.Substring($EventForSpecificFocChangeSourceIdentifier.Length-4)

    After a change is made to SpecificDoc.txt...

    ...EITHER analyze the Subscriber Event itself:
        $SubscriberEventForSpecificDocChange = Get-EventSubscriber | Where-Object {$_.SubscriberId -eq $EventForSpecificFocChangeSourceIdentifier}

    ...OR (RECOMMENDED), import more comprehensive and friendly information from the log file generated when an event triggers:
        $LogFileForLatestSpecificDocChangeTrigger = $(Get-ChildItem "$LogDirectory\FileIOWatcherEvents" | Where-Object {
            $_.Name -like "*$EventForSpecificDocChangeSourceIdentifierLast4*"
        } | Sort-Object -Property "LastWriteTime")[-1].FullName

        $PSCustomObjectForSpecificDocChangeEvent = Import-Clixml $LogFileForLatestSpecificDocChangeTrigger

    The contents of the PSCustomObject imported via Import-Clixml are as follows:

        Event                    : System.Management.Automation.PSEventArgs
        SubscriberEvent          : System.Management.Automation.PSEventSubscriber
        SourceIdentifier         : f73d1f49-241e-40bc-a356-1bb02c79c162
        FilesThatChanged         : SpecificDoc.txt
        TriggerType              : Changed
        FilesThatChangedFullPath : C:\Users\testadmin\SpecificDoc.txt
        TimeStamp                : 2/12/2017 11:58:40 AM

    To review the scriptblock that was executed, either use:
        $SubscriberEventForSpecificDocChange.Action.Command

    ...or, if you imported the log file to use the PSCustomObject:
        $PSCustomObjectForSpecificDocChangeEvent.SubscriberEvent.Action.Command

    TO UNREGISTER AN EVENT AFTER IT HAS BEEN CREATED USING THIS FUNCTION:
    Unregister-Event -SourceIdentifier $EventForSpecificDocChangeSourceIdentifier

#>

Function Register-FileIOWatcher {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$TargetDir = $(Read-Host -Prompt "Please enter the full path to the directory that contains the file(s) you would like to watch."),

        [Parameter(Mandatory=$False)]
        [regex]$FilesToWatchRegexMatch,

        [Parameter(Mandatory=$False)]
        [string]$FilesToWatchEasyMatch,

        [Parameter(Mandatory=$False)]
        [switch]$IncludeSubdirectories,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Changed","Created","Deleted","Disposed","Error","Renamed")]
        $Trigger,

        [Parameter(Mandatory=$True)]
        [string]$LogDir, # Directory where logging of triggered events will be stored. A folder called FileIOWatcherEvents will be created and all logs will be saved inside. Logs XML representations of PSCustomObjects, so they can me imported back into PowerShell at a later time for analysis.

        [Parameter(Mandatory=$False)]
        [string]$FriendlyNameForEvent, # This string will be the name of the variable that this function outputs. If blank, the name will be "EventFor<TargetDirName>"

        [Parameter(Mandatory=$True)]
        $ActionToTakeScriptBlock, # Can be a string or a scriptblock. If string, the function will handle converting it to a scriptblock object.

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Make sure $TargetDir is a valid path
    $TargetDirNameOnly = $TargetDir | Split-Path -Leaf
    $LogDirFileIOFolder = "FileIOWatcherEvents"
    $FullLogDirLocation = "$LogDir\$LogDirFileIOFolder"

    if ( !$($([uri]$TargetDir).IsAbsoluteURI -and $($([uri]$TargetDir).IsLoopBack -or $([uri]$TargetDir).IsUnc)) ) {
        Write-Verbose "$TargetDir is not a valid directory path! Halting!"
        Write-Error "$TargetDir is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $TargetDir)) {
        Write-Verbose "The path $TargetDir was not found! Halting!"
        Write-Error "The path $TargetDir was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ( !$($([uri]$LogDir).IsAbsoluteURI -and $($([uri]$LogDir).IsLoopBack -or $([uri]$LogDir).IsUnc)) ) {
        Write-Verbose "$LogDir is not a valid directory path! Halting!"
        Write-Error "$LogDir is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $LogDir)) {
        Write-Verbose "The path $LogDir was not found! Halting!"
        Write-Error "The path $LogDir was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $FullLogDirLocation)) {
        New-Item -Path $FullLogDirLocation -ItemType Directory | Out-Null
    }

    if ($FilesToWatchRegexMatch -and $FilesToWatchEasyMatch) {
        Write-Verbose "Please use *either* the `$FilesToWatchRegexMatch parameter *or* the `$FilesToWatchEasyMatch parameter. Halting!"
        Write-Error "Please use *either* the `$FilesToWatchRegexMatch parameter *or* the `$FilesToWatchEasyMatch parameter. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$FilesToWatchRegexMatch -and !$FilesToWatchEasyMatch) {
        Write-Verbose "You must use either the `$FilesToWatchRegexMatch parameter or the `$FilesToWatchEasyMatch parameter in order to specify which files you would like to watch in the directory `"$TargetDir`". Halting!"
        Write-Error "You must use either the `$FilesToWatchRegexMatch parameter or the `$FilesToWatchEasyMatch parameter in order to specify which files you would like to watch in the directory `"$TargetDir`". Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($ActionToTakeScriptBlock.GetType()).FullName -eq "System.Management.Automation.ScriptBlock") {
        $UpdatedActionToTakeScriptBlock = $ActionToTakeScriptBlock
    }
    if ($($ActionToTakeScriptBlock.GetType()).FullName -eq "System.String") {
        $UpdatedActionToTakeScriptBlock = [scriptblock]::Create($ActionToTakeScriptBlock)
    }
    if ($($ActionToTakeScriptBlock.GetType()).FullName -notmatch "System.Management.Automation.ScriptBlock|System.String") {
        Write-Verbose "The value passed to the `$ActionToTakeScriptBlock parameter must either be a System.Management.Automation.ScriptBlock or System.String! Halting!"
        Write-Error "The value passed to the `$ActionToTakeScriptBlock parameter must either be a System.Management.Automation.ScriptBlock or System.String! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $Watcher = New-Object IO.FileSystemWatcher
    $Watcher.Path = $TargetDir
    # Setting NotifyFilter to FileName, DirectoryName, and Size as opposed to FileName, DirectoryName, and LastWrite
    # prevents the bug that causes the trigger fire twice on Change to LastWrite time.
    # Bug: http://stackoverflow.com/questions/1764809/filesystemwatcher-changed-event-is-raised-twice
    $watcher.NotifyFilter = "FileName, DirectoryName, Size"
    # NOTE: The Filter property can't handle normal regex, so if $FileToWatchRegexMatch is used, just temporarily set it to 
    # every file and do the regex check in the $FilesToWatchRegexMatchClause which is ultimately added to the 
    # $AlwaysIncludeInScriptBlock script block
    if ($FilesToWatchRegexMatch) {
        $Watcher.Filter = "*.*"
    }
    if ($FilesToWatchEasyMatch) {
        $Watcher.Filter = $FilesToWatchEasyMatch
    }
    if ($IncludeSubdirectories) {
        $Watcher.IncludeSubdirectories = $True
    }
    $Watcher.EnableRaisingEvents = $True

    # Adding Array elements in this manner becaue order is important
    [System.Collections.ArrayList]$FunctionParamVarsToPassToScriptBlock = @("TargetDir")
    if ($FilesToWatchRegexMatch) {
        $FunctionParamVarsToPassToScriptBlock.Add("FilesToWatchRegexMatch") | Out-Null
    }
    if ($FilesToWatchEasyMatch) {
        $FunctionParamVarsToPassToScriptBlock.Add("FilesToWatchEasyMatch") | Out-Null
    }
    if ($IncludeSubdirectories) {
        $FunctionParamVarsToPassToScriptBlock.Add("IncludeSubdirectories") | Out-Null
    }
    $FunctionParamVarsToPassToScriptBlock.Add("Trigger") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("LogDir") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("FullLogDirLocation") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("FriendlyNameForEvent") | Out-Null

    $FunctionArgsToBeUsedByActionToTakeScriptBlock = @()
    foreach ($VarName in $FunctionParamVarsToPassToScriptBlock) {
        # The below $StringToBePassedToScriptBlock is valid because all of the function parameters can be represented as strings
        $StringToBePassedToScriptBlock = "`$$VarName = '$(Get-Variable -Name $VarName -ValueOnly)'"
        $FunctionArgsToBeUsedByActionToTakeScriptBlock += $StringToBePassedToScriptBlock
    }
    $UpdatedFunctionArgsToBeUsedByActionToTakeScriptBlockAsString = $($FunctionArgsToBeUsedByActionToTakeScriptBlock | Out-String).Trim()

    if ($FilesToWatchRegexMatch) {
        $FilesToWatchRegexMatchClause = @"
`$FilesOfConcern = @()
foreach (`$file in `$FilesThatChanged) {
    if (`$file -match `'$FilesToWatchRegexMatch`') {
        `$FilesOfConcern += `$file
    }
}
if (`$FilesOfConcern.Count -lt 1) {
    Write-Verbose "The files that were $Trigger in the target directory $TargetDir do not match the specified regex. No action taken."
    return
}
"@
    }

    if ($FriendlyNameForEvent) {
        $NameForEventClause = @"
`$NewVariableName = "$FriendlyNameForEvent`_`$SourceIdentifierAbbrev`_`$EventIdentifier"
"@
    }
    if (!$FriendlyNameForEvent) {
        $NameForEventClause = @"
`$NewVariableName = "FileIOWatcherFor$TargetDirNameOnly`_`$SourceIdentifierAbbrev`_`$EventIdentifier"
"@
    }

    # Always include the following in whatever scriptblock is passed to $ActionToTakeScriptBlock parameter
    # NOTE: $Event is an automatic variable that becomes available in the context of the Register-ObjectEvent cmdlet
    # For more information, see:
    # https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/register-objectevent
    # https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables

    $AlwaysIncludeInScriptBlock = @"

############################################################
# BEGIN Always Included ScriptBlock
############################################################

`$FilesThatChanged = `$Event.SourceEventArgs.Name
`$FilesThatChangedFullPath = `$Event.SourceEventArgs.FullPath

$FilesToWatchRegexMatchClause

`$PSEvent = `$Event
`$SourceIdentifier = `$Event.SourceIdentifier
`$SourceIdentifierAbbrev = `$SourceIdentifier.Substring(`$SourceIdentifier.Length - 4)
`$PSEventSubscriber = Get-EventSubscriber | Where-Object {`$_.SourceIdentifier -eq `$SourceIdentifier}
`$EventIdentifier = `$Event.EventIdentifier
`$TriggerType = `$Event.SourceEventArgs.ChangeType
`$TimeStamp = `$Event.TimeGenerated

$NameForEventClause

New-Variable -Name "`$NewVariableName" -Value `$(
    [pscustomobject][ordered]@{
        Event                      = `$PSEvent
        SubscriberEvent            = `$PSEventSubscriber
        SourceIdentifier           = `$SourceIdentifier
        FilesThatChangedFullPath   = `$FilesThatChangedFullPath
        FilesThatChanged           = `$FilesThatChanged
        TriggerType                = `$TriggerType
        TimeStamp                  = `$TimeStamp
    }
)

##### BEGIN Function Args Passed To ScriptBlock #####

$UpdatedFunctionArgsToBeUsedByActionToTakeScriptBlockAsString

##### END Function Args Passed To ScriptBlock  #####

`$(Get-Variable -Name "`$NewVariableName" -ValueOnly) | Export-Clixml `$FullLogDirLocation\`$NewVariableName.xml

############################################################
# END Always Included ScriptBlock
############################################################

#############################################################################
# BEGIN ScriptBlock Passed In Using The Parameter -ActionToTakeScriptBlock
#############################################################################

"@

    $Action = [scriptblock]::Create($AlwaysIncludeInScriptBlock+"`n"+$UpdatedActionToTakeScriptBlock.ToString())

    if ($FriendlyNameForEvent) {
        New-Variable -Name "$FriendlyNameForEvent" -Scope Script -Value $(
            Register-ObjectEvent -InputObject $Watcher -EventName "$Trigger" -Action $Action
        )
        if (!$Silent) {
            Get-Variable -Name "$FriendlyNameForEvent" -ValueOnly
        }
    }
    if (!$FriendlyNameForEvent) {
        New-Variable -Name "EventFor$TargetDirNameOnly" -Scope Script -Value $(
            Register-ObjectEvent -InputObject $Watcher -EventName "$Trigger" -Action $Action
        )
        if (!$Silent) {
            Get-Variable -Name "EventFor$TargetDirNameOnly" -ValueOnly
        }
    }

    ##### END Main Body #####
}


function Limit-DirectorySize {
    [CmdletBinding(PositionalBinding=$True)]
    Param( 
        [Parameter(Mandatory=$False)]
        $Directory = $(Read-Host -Prompt "Please enter the full path to the directory that will be assigned a size limit."),

        [Parameter(Mandatory=$False)]
        $SizeLimitInGB = $(Read-Host -Prompt "Please enter the maximum size in GB that you would like to allow the directory $Directory to grow to")
    )

    ## BEGIN Native Helper Functions ##

    # The below Convert-Size function is from:
    # http://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/2376
    function Convert-Size {
        [cmdletbinding()]
        param(
            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$From,

            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$To,

            [Parameter(Mandatory=$True)]
            [double]$Value,

            [Parameter(Mandatory=$False)]
            [int]$Precision = 4
        )

        switch($From) {
            "Bytes" {$Value = $Value }
            "KB" {$Value = $Value * 1024 }
            "MB" {$Value = $Value * 1024 * 1024}
            "GB" {$Value = $Value * 1024 * 1024 * 1024}
            "TB" {$Value = $Value * 1024 * 1024 * 1024 * 1024}
        }            
                    
        switch ($To) {
            "Bytes" {return $value}
            "KB" {$Value = $Value/1KB}
            "MB" {$Value = $Value/1MB}
            "GB" {$Value = $Value/1GB}
            "TB" {$Value = $Value/1TB}
        }

        return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $DirectoryName = $Directory | Split-Path -Leaf
    $SizeLimitInBytes = Convert-Size -From GB -To Bytes -Value $SizeLimitInGB
    $DirSizeInBytes = $(Get-ChildItem $Directory | Measure-Object -Property Length -sum).sum

    if ( !$($([uri]$Directory).IsAbsoluteURI -and $($([uri]$Directory).IsLoopBack -or $([uri]$Directory).IsUnc)) ) {
        Write-Verbose "$Directory is not a valid directory path! Halting!"
        Write-Error "$Directory is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (! $(Test-Path $Directory)) {
        Write-Verbose "The path $Directory was not found! Halting!"
        Write-Error "The path $Directory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    if ($DirSizeInBytes -gt $SizeLimitInBytes) {
        # Remove as many of the oldest files as necessary to get back under the size limit
        $DifferenceBetweenLimitandActual = $DirSizeInBytes-$SizeLimitInBytes
        $DirContentsOldToNew = Get-ChildItem $Directory | Where-Object {!$_.PSIsContainer} | Sort-Object -Property "LastWriteTime"
        
        $FilesToDeleteArray = @()
        $NewSum = 0
        for ($i=0; $i -lt $DirContentsOldToNew.Count; $i++) {
            if ($NewSum -lt $DifferenceBetweenLimitandActual) {
                $OldSum = $NewSum
                $NewSum = $OldSum+$DirContentsOldToNew[$i].Length
                $FilesToDeleteArray += $($DirContentsOldToNew[$i].FullName)
            }
        }

        foreach ($Item in $FilesToDeleteArray) {
            Remove-Item -Path $Item -Force
        }
    }

    ##### END Main Body #####

}


<#
.SYNOPSIS
    Enables logging of Interactive and Uninteractive PowerShell Sessions organized by computer, user, and PowerShell Process Identifier (PID).

    While it is true that the Group Policy setting...

        Windows Components -> Administrative Templates -> Windows PowerShell -> Turn on PowerShell Script Block Logging 

    ...exists for this purpose, parsing the resulting Windows Event Log messages is very difficult, has limitations, and is
    not really conducive to quickly figuring out what PowerShell commands were executed by a particular user on a specific
    system, at a specific time/date. Also, according to Microsoft this GPO, "only serves as a record of last resort" (see:
    https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)

.DESCRIPTION
    This module organizes logging of PowerShell Sessions into four (4) different categories:

    1) Interactive History:
        Two types of files created by this Start-PSLogging module fall into this category:
            A) A .txt file (referred to as $ConsoleHistoryPath) written to by the PSReadline module as a
            result of: Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath. Each line in this text
            file contains ONLY the text from the command line. The file name of $ConsoleHistoryPath will be
            in the format:

                $env:COMPUTERNAME`_$PowerShellUserAccount`_ConsoleHost_History.txt

            NOTE: This is the file that PSReadline refers to when you press the up arrow on your keyboard to
            scroll through previously executed commands within an Interactive PowerShell Session.

            B) A .csv file (referred to as $InteractivePSHistoryPath) that is written to whenever $ConsoleHistoryPath 
            is modified. Each line in this .csv file is in the specialized format Microsoft.PowerShell.Commands.HistoryInfo,
            which is created by exporting the results of the Get-History cmdlet. The file name of $InteractivePSHistoryPath
            will be in the format:

                $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Interactive_PShistory.csv

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    2) Uninteractive History:
        Any powershell scripts/functions that run on a schedule or in an otherwise unattended mode fall into this category.

        ****IMPORTANT NOTE: If these unattended scripts do NOT load the Start-PSLogging Module, then they will NOT be included
        in the Uninteractive History ****or any other log mentioned below****.

        A .csv file (referred to as $UninteractivePSHistoryPath) that is written to whenever a PowerShell process exits (i.e.
        uses Register-EngineEvent PowerShell.Exiting). Each line in this .csv file is in the specialized format
        Microsoft.PowerShell.Commands.HistoryInfo, which is created by exporting the results of the Get-History cmdlet. 
        The file name of $UninteractivePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Uninteractive_PShistory.csv

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    3) SystemWide History:
        Captures both Interactive and Uninteractive History in chronological order. In other words, when reviewing this log,
        it is possible to see several entries from an Interactive PowerShell session followed by several entries from an
        Uninteractive PowerShell session.

        A .csv file (referred to as $SystemWidePSHistoryPath) that is written to whenever $InteractivePSHistoryPath or 
        $UninteractivePSHistoryPath are modified. Each line in this .csv file is in the specialized format
        Microsoft.PowerShell.Commands.HistoryInfo, which is created by exporting the results of the Get-History cmdlet. 
        The file name of $SystemWidePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$PowerShellUserAccount`_SystemWide_History.csv

        IMPORTANT NOTE: Uninteractive History will NOT be logged if this Start-PSLogging Module is not loaded in
        the unattended PowerShell processes.

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    4) All STDOUT for Both Interactive and Uninteractive PowerShell Sessions
        Uses Start-Transcript cmdlet to log all of STDOUT for both Interactive and Uninteractive sessions.

        A .txt file (refrred to as $PSTranscriptPath) that is written to whenever a PoweShell process exits. The
        file name of $UninteractivePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Transcript_$(get-date -f yyyyMMdd-HHmmss).txt

        IMPORTANT NOTE: Uninteractive STDOUT History will NOT be logged if this Start-PSLogging Module is not loaded in
        the unattended PowerShell processes.


.NOTES
    IMPORTANT NOTE: If Uninteractive PowerShell Sessions/Processes do NOT load the Start-PSLogging Module, then they will NOT
    be logged!

.PARAMETER ConsoleHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that the PSReadline Module will write Interactive
    PowerShell console commands to. This directory will contain the .txt file $ConsoleHistoryPath that is referenced by:
        Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath

.PARAMETER InteractivePSHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of Interactive PowerShell
    Sessions in .csv files.

.PARAMETER UninteractivePSHistDir
    This parameter is MADATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of PowerShell Sessions that
    are NOT interactive in .csv files (as long as these unattended sessions load the Start-PSLogging Module).

.PARAMETER SystemWidePSHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of ALL PowerShell Sessions 
    from a particular host (i.e. $env:COMPUTERNAME), from both Interactive and Uninteractive sessions, in .csv files.

.PARAMETER PSTranscriptDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store transcripts of STDOUT for ALL PowerShell 
    Sessions from a particular host (i.e. $env:COMPUTERNAME), from both Interactive and Uninteractive sessions, in .txt files.

.PARAMETER FileIOWatcherEventLogDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store records of each time a FileIOWatcher 
    Event is triggered. In other words, it stores Register-FileIOWatcher function logs in .xml files.

.EXAMPLE
    $LogDir = "K:\Logs\PowerShell"
    Start-PSLogging -LogDirectory $LogDir -SubDirectorySizeLimitInGB 1

.EXAMPLE
    $LogDir = "M:\Logs\PowerShell"
    Start-PSLogging -ConsoleHistDir "M:\Logs\Powershell\PS_Interactive_History" `
    -InteractivePSHistDir "M:\Logs\Powershell\PS_Interactive_History" `
    -UninteractivePSHistDir "M:\Logs\Powershell\PS_Uninteractive_History" `
    -SystemWidePSHistDir "M:\Logs\Powershell\PS_SystemWide_History" `
    -PSTranscriptDir "M:\Logs\Powershell\PS_Session_Transcripts" `
    -FileIOWatcherEventLogDir "M:\Logs\Powershell" `
    -SubDirectorySizeLimitInGB 2

    NOTE: In the above example, the "FileIOWatcherEventLogDir" parameter creates a directory called FileIOWatcherEvents
    under M:\Logs\PowerShell\

.OUTPUTS
    Outputs for this function are three (3) System.Management.Automation.PSEventJob objects that come as output from the 
    Register-FileIOWatcher function. These objects will be available in the scope that calls this function and be named

        $EventForPSReadlineConsoleHistoryChange
        $EventForInteractivePSHistoryChange
        $EventForUninteractivePSHistoryChange

    These FileIOWatcher Events can also be reviewed via the Get-EventSubscriber cmdlet in the PowerShell session/process 
    that uses this function.

#>

function Start-PSLogging {
    [CmdletBinding(PositionalBinding=$True)]
    Param(

        [Parameter(Mandatory=$False)]
        [string]$LogDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that will contain all logging subdirectories"),

        [Parameter(Mandatory=$False)]
        $SubDirectorySizeLimitInGB = $(Read-Host -Prompt "Five subdirectories under $LogDirectory will be created (if they don't already exist). Please enter the size limit in GB that will apply to EACH of these subdirectories"),

        [Parameter(Mandatory=$False)]
        [string]$InteractivePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$UninteractivePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$SystemWidePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$PSTranscriptDir,

        [Parameter(Mandatory=$False)]
        [string]$FileIOWatcherEventLogDir
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $whoamiSanitizedForFileName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -replace "\\","-"
    if (Check-Elevation) {
        $PowerShellUserAccount = "Elevated_$whoamiSanitizedForFileName"
    }
    else {
        $PowerShellUserAccount = $whoamiSanitizedForFileName
    }

    if (!$InteractivePSHistDir) {
        $InteractivePSHistDir = "$LogDirectory\PS_Interactive_History"
        $ConsoleHistDir = $InteractivePSHistDir
    }
    if (!$UninteractivePSHistDir) {
        $UninteractivePSHistDir = "$LogDirectory\PS_Uninteractive_History"
    }
    if (!$SystemWidePSHistDir) {
        $SystemWidePSHistDir = "$LogDirectory\PS_SystemWide_History"
    }
    if (!$PSTranscriptDir) {
        $PSTranscriptDir = "$LogDirectory\PS_Session_Transcripts"
    }
    if (!$FileIOWatcherEventLogDir) {
        $FileIOWatcherEventLogDir = "$LogDirectory"
    }

    if (!$(Test-Path $InteractivePSHistDir)) {
        New-Item -Type Directory -Path $InteractivePSHistDir
    }
    if (!$(Test-Path $UninteractivePSHistDir)) {
        New-Item -Type Directory -Path $UninteractivePSHistDir
    }
    if (!$(Test-Path $SystemWidePSHistDir)) {
        New-Item -Type Directory -Path $SystemWidePSHistDir
    }
    if (!$(Test-Path $PSTranscriptDir)) {
        New-Item -Type Directory -Path $PSTranscriptDir
    }
    if (!$(Test-Path $FileIOWatcherEventLogDir)) {
        New-Item -Type Directory -Path $FileIOWatcherEventLogDir
    }

    Verify-Directory -DirectoryPath $LogDirectory
    Verify-Directory -DirectoryPath $InteractivePSHistDir
    Verify-Directory -DirectoryPath $UninteractivePSHistDir
    Verify-Directory -DirectoryPath $SystemWidePSHistDir
    Verify-Directory -DirectoryPath $PSTranscriptDir

    $ConsoleHistoryFileName = "$env:COMPUTERNAME`_$PowerShellUserAccount`_ConsoleHost_History.txt"
    $ConsoleHistoryPath = "$ConsoleHistDir\$ConsoleHistoryFileName"

    $InteractivePSHistoryFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Interactive_PShistory.csv"
    $InteractivePSHistoryPath = "$InteractivePSHistDir\$InteractivePSHistoryFileName"

    $UninteractivePSHistoryFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Uninteractive_PShistory.csv"
    $UninteractivePSHistoryPath = "$UninteractivePSHistDir\$UninteractivePSHistoryFileName"

    $SystemWidePSHistoryFileName = "$env:COMPUTERNAME`_$PowerShellUserAccount`_SystemWide_History.csv"
    $SystemWidePSHistoryPath = "$SystemWidePSHistDir\$SystemWidePSHistoryFileName"

    $PSTranscriptFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Transcript_$(get-date -f yyyyMMdd-HHmmss).txt"
    $PSTranscriptPath = "$PSTranscriptDir\$PSTranscriptFileName"

    # Update-PackageManagement and Ensure PSReadline is installed and updated to latest version and writes out to $ConsoleHistoryPath

    if ($(Get-Module -Name PSReadLine) -eq $null) {
        if ($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PSReadline"}) -eq $null) {
            Update-PackageManagement
            Install-Module -Name "PSReadline" -Force
        }
    }
    $PSReadlineLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PSReadline"}).Version | Measure-Object -Maximum).Maximum
    $PSReadlineLatestAvailableVersion = $(Find-Module PSReadline).Version
    if ($PSReadlineLatestLocallyAvailableVersion -lt $PSReadlineLatestAvailableVersion) {
        Install-Module -Name "PSReadline" -Force
    }
    # Reset LatestLocallyAvailableVersion...
    $PSReadlineLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PSReadline"}).Version | Measure-Object -Maximum).Maximum
    Remove-Module -Name "PSReadline"
    Import-Module "PSReadline" -RequiredVersion $PSReadlineLatestLocallyAvailableVersion

    if ($(Get-PSReadlineOption).HistorySavePath -ne $ConsoleHistoryPath) {
        Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath
    }

    # Load up the history from $SystemWidePSHistoryPath so that ALL User's history is available in current session 
    if (Test-Path $SystemWidePSHistoryPath) {
        Import-Csv $SystemWidePSHistoryPath | Add-History
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


     ##### BEGIN Main Body #####
    # Setup File Watchers and Log Interactions
    # Run each File Watcher in its own runspace (if appropriate)
    # Add each Register-FileIOWatcher scriptblock to the below $ArrayOfFileIOWatcherPSObjects, and
    # loop through them when creating Runspaces
    $ArrayOfFileIOWatcherPSObjects = @()

    $RegisterFileIOWatcherFunctionAsString = "function Register-FileIOWatcher {`n"+$(Reflect-Cmdlet Register-FileIOWatcher).ToString()+"`n}"
    $LimitDirSizeFunctionAsString = "function Limit-DirectorySize {`n"+$(Reflect-Cmdlet Limit-DirectorySize).ToString()+"`n}"

    # The below SendHistoryToRunSpaces adds sends the last index of Get-History in current session to $global:synchash$i.History
    # property in the first 3 runspaces ($i = 0, $i = 1) upon modification of $ConsoleHistoryPath via PSReadline
    $SendHistoryToRunSpacesScriptBlock = @"
    `$global:syncHash0.History = `$(Get-History)[-1]
"@

    $SHTRParams = @{
        TargetDir = "$ConsoleHistDir"
        FilesToWatchEasyMatch = "$ConsoleHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForSendingHistoryToRunspacesOnPSReadlineConsoleHistoryChange"
        ActionToTakeScriptBlock = $SendHistoryToRunSpacesScriptBlock
    }
    Register-FileIOWatcher @SHTRParams -Silent


    # The below ConsoleHistoryWatcher adds Interactive PowerShell Sessions to $InteractivePSHistoryPath and $SystemWidePSHistoryPath 
    # when $ConsoleHistoryPath is "Changed"
    # NOTE: "Changed" triggers on file creation as well as modification, so no need for a separate Watcher Event on file creation.
    $ConsoleHistoryWatcherScriptBlockPrep = @"
Write-Verbose "The file `$FilesThatChangedFullPath was `$TriggerType at `$TimeStamp"
try {
    `$TryGettingHistory = `$syncHash.History
}
catch {
    Write-Verbose "Fewer than 1 command has been executed in PowerShell at this time."
}
if (`$TryGettingHistory) {
    if (!`$(Test-Path "$InteractivePSHistoryPath")) {
        #`$TryGettingHistory | Export-Csv "$InteractivePSHistoryPath"
        `$MockCsvContent = '#TYPE Microsoft.PowerShell.Commands.HistoryInfo'+"``n"+'"Id","CommandLine","ExecutionStatus","StartExecutionTime","EndExecutionTime"'
        Set-Content -Path "$InteractivePSHistoryPath" -Value `$MockCsvContent
        `$TryGettingHistory | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$InteractivePSHistoryPath"
        `$TryGettingHistory | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$SystemWidePSHistoryPath"
    }
    else {
        `$TryGettingHistory | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$InteractivePSHistoryPath"
        `$TryGettingHistory | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$SystemWidePSHistoryPath"
    }
}
if (!`$TryGettingHistory) {
    if (!`$(Test-Path "$InteractivePSHistoryPath")) {
        `$MockCsvContent = '#TYPE Microsoft.PowerShell.Commands.HistoryInfo'+"``n"+'"Id","CommandLine","ExecutionStatus","StartExecutionTime","EndExecutionTime"'
        Set-Content -Path "$InteractivePSHistoryPath" -Value `$MockCsvContent
    }
    else {
        Write-Verbose "The Interactive PowerShell History file $InteractivePSHistoryPath already exists, but no history is available in the current PowerShell Session. No action taken"
    }
}
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$ConsoleHistoryWatcherScriptBlock = [scriptblock]::Create($ConsoleHistoryWatcherScriptBlockPrep)
    
    <#
    $CHWParams = @{
        TargetDir = "$ConsoleHistDir"
        FilesToWatchEasyMatch = "$ConsoleHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForPSReadlineConsoleHistoryChange"
        ActionToTakeScriptBlock = $ConsoleHistoryWatcherScriptBlock
    }
    #>

    $CHWRunspaceScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$ConsoleHistDir" -FilesToWatchEasyMatch "$ConsoleHistoryFileName" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForPSReadlineConsoleHistoryChange" -ActionToTakeScriptBlock `$ConsoleHistoryWatcherScriptBlock
"@
    $ArrayOfFileIOWatcherPSObjects +=, $CHWRunspaceScriptBlock


    # The below Register-EngineEvent PowerShell.Exiting adds Uninteractive PowerShell Sessions to $UninteractivePSHistoryPath
    # This should NOT be in a Runspace
    $RegisterEngineEventScriptBlockAsString = @"
if (!`$([Environment]::UserInteractive)) {
    Get-History | Export-Csv $UninteractivePSHistoryPath
    Get-PSSession | Where-Object {`$_.state -ne "Opened"} | Remove-PSSession
}
"@
    $RegisterEngineEventScriptBlock = [scriptblock]::Create($RegisterEngineEventScriptBlockAsString)
    Register-EngineEvent PowerShell.Exiting -Action $RegisterEngineEventScriptBlock | Out-Null

    # The below PSExitActionWatcher adds Uninteractive PowerShell Sessions to $SystemWidePSHistoryPath upon
    # modification of $UninteractivePSHistoryPath
    $PSExitActionWatcherScriptBlockPrep = @"
Write-Verbose "The file `$FilesThatChangedFullPath was `$TriggerType at `$TimeStamp"
if (!`$(Test-Path "$SystemWidePSHistoryPath")) {
    `$(Get-Content `$FilesThatChangedFullPath)[-1] | Set-Content "$SystemWidePSHistoryPath"
}
else {
    # Removes Column Headers (i.e. object property names) and appends file at DestPath
    `$(Get-Content `$FilesThatChangedFullPath)[-1] | Add-Content "$SystemWidePSHistoryPath"
}
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$PSExitActionWatcherScriptBlock = [scriptblock]::Create($PSExitActionWatcherScriptBlockPrep)

    <#
    $UPSHParams = @{
        TargetDir = "$UninteractivePSHistDir"
        FilesToWatchEasyMatch = "$UninteractivePSHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForUninteractivePSHistoryChange"
        ActionToTakeScriptBlock = $PSExitActionWatcherScriptBlock
    }
    #>

    $UPSHRunspaceScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$UninteractivePSHistDir" -FilesToWatchEasyMatch "$UninteractivePSHistoryFileName" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForUninteractivePSHistoryChange" -ActionToTakeScriptBlock `$PSExitActionWatcherScriptBlock
"@
    $ArrayOfFileIOWatcherPSObjects +=, $UPSHRunspaceScriptBlock


     # Start-Transcript writes all of STDOUT from an Interactive PowerShell Session to $PSTranscriptPath
     # ****upon closing the Interactive PowerShell Session.****. This should NOT be in a Runspace.
    if (!$(Test-Path $PSTranscriptPath)) {
        New-Item -Path $PSTranscriptPath -ItemType File
    }
    Start-Transcript -Path $PSTranscriptPath -Append


    # The below SubDirectorySizeWatcher monitors each of the subdirectories under $LogDirectory and ensures each of them
    # stays under the size limit indicated by $SubDirectorySizeLimitInGB by deleting as many of the oldest files as
    # is necessary to bring the size of the given subdirectory back under the $SubDirectorySizeLimitInGB
    $SubDirectorySizeWatcherScriptBlock1Prep = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $InteractivePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$SubDirectorySizeWatcherScriptBlock1 = [scriptblock]::Create($SubDirectorySizeWatcherScriptBlock1Prep)

    <#
    $IPSHSizeWatcherParams = @{
        TargetDir = "$InteractivePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForInteractivePSHistoryDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock1
    }
    #>

    $IPSHSizeWatcherScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$InteractivePSHistDir" -FilesToWatchEasyMatch "*.*" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForInteractivePSHistoryDirSize" -ActionToTakeScriptBlock `$SubDirectorySizeWatcherScriptBlock1
"@
    $ArrayOfFileIOWatcherPSObjects +=, $IPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock2Prep = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $UninteractivePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$SubDirectorySizeWatcherScriptBlock2 = [scriptblock]::Create($SubDirectorySizeWatcherScriptBlock2Prep)

    <#
    $UPSHSizeWatcherParams = @{
        TargetDir = "$UninteractivePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForUninteractivePSHistoryDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock2
    }
    #>

    $UPSHSizeWatcherScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$UninteractivePSHistDir" -FilesToWatchEasyMatch "*.*" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForUninteractivePSHistoryDirSize" -ActionToTakeScriptBlock `$SubDirectorySizeWatcherScriptBlock2
"@
    $ArrayOfFileIOWatcherPSObjects +=, $UPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock3Prep = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $SystemWidePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$SubDirectorySizeWatcherScriptBlock3 = [scriptblock]::Create($SubDirectorySizeWatcherScriptBlock3Prep)

    <#
    $SWPSHSizeWatcherParams = @{
        TargetDir = "$SystemWidePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForSystemWidePSHistDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock3
    }
    #>

    $SWPSHSizeWatcherScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$SystemWidePSHistDir" -FilesToWatchEasyMatch "*.*" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForSystemWidePSHistDirSize" -ActionToTakeScriptBlock `$SubDirectorySizeWatcherScriptBlock3
"@
    $ArrayOfFileIOWatcherPSObjects +=, $SWPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock4Prep = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $PSTranscriptDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@
# The below ScriptBlock Object evaluates all of the Unescaped Variables Above.
# The ScriptBlock Object gets passed to the Runspace
$SubDirectorySizeWatcherScriptBlock4 = [scriptblock]::Create($SubDirectorySizeWatcherScriptBlock4Prep)

    <#
    $TranscriptSizeWatcherParams = @{
        TargetDir = "$PSTranscriptDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForPSTranscriptDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock4
    }
    #>

    $TranscriptSizeWatcherScriptBlock = @"
$RegisterFileIOWatcherFunctionAsString
Register-FileIOWatcher -TargetDir "$PSTranscriptDir" -FilesToWatchEasyMatch "*.*" -Trigger "Changed" -LogDir "$FileIOWatcherEventLogDir" -FriendlyNameForEvent "EventForPSTranscriptDirSize" -ActionToTakeScriptBlock `$SubDirectorySizeWatcherScriptBlock4
"@
    $ArrayOfFileIOWatcherPSObjects +=, $TranscriptSizeWatcherScriptBlock



    ##### BEGIN RUNSPACES #####

    ##### BEGIN Runspace Manager Runspace #####
    # Thanks to Boe Prox and Stephen Owen for this solution managing multiple Runspaces
    # See: https://foxdeploy.com/2016/05/17/part-v-powershell-guis-responsive-apps-with-progress-bars/

    $script:JobCleanup = [hashtable]::Synchronized(@{})
    $script:Jobs = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $jobCleanup.Flag = $True
    $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
    $RunspaceMgrRunspace.ApartmentState = "STA"
    $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
    $RunspaceMgrRunspace.Open()
    $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobCleanup",$jobCleanup)
    $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$jobs)
    $jobCleanup.PowerShell = [PowerShell]::Create().AddScript({
        # Routine to handle completed Runspaces
        do {
            foreach($runspace in $jobs) {
                if ($runspace.Runspace.isCompleted) {
                    [void]$runspace.PowerShell.EndInvoke($runspace.Runspace)
                    $runspace.PowerShell.Dispose()
                    $runspace.Runspace = $null
                    $runspace.PowerShell = $null
                }
            }
            # Clean Out Unused Runspace Jobs
            $temphash = $jobs.clone()
            $temphash | Where-Object {
                $_.runspace -eq $null
            } | foreach {
                $jobs.remove($_)
            }
            Start-Sleep -Seconds 1
        } while ($jobsCleanup.Flag)
    })
    $jobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
    $jobCleanup.Thread = $jobCleanup.PowerShell.BeginInvoke()

    ##### END Runspace Manager Runspace #####

    ##### BEGIN Setup Runspace Creation Loop #####

    $AllParams = $($PSBoundParameters.GetEnumerator())
    $OtherVarsToPassToRunspaces = @("ConsoleHistDir","ConsoleHistoryFileName","ConsoleHistoryPath","InteractivePSHistoryFileName",
    "InteractivePSHistoryPath","UninteractivePSHistoryFileName","UninteractivePSHistoryPath","SystemWidePSHistoryFileName",
    "SystemWidePSHistoryPath","PSTranscriptFileName","PSTranscriptPath","FileIOWatcherEventLogDir")
    $BlockVarsToPassToRunspaces = @("ConsoleHistoryWatcherScriptBlock",
    "PSExitActionWatcherScriptBlock","LimitDirSizeFunctionAsString","SubDirectorySizeWatcherScriptBlock1",
    "SubDirectorySizeWatcherScriptBlock2","SubDirectorySizeWatcherScriptBlock3","SubDirectorySizeWatcherScriptBlock4",
    "IPSHSizeWatcherScriptBlock","UPSHSizeWatcherScriptBlock","SWPSHSizeWatcherScriptBlock","TranscriptSizeWatcherScriptBlock")

    $PSInstanceCollection = @()
    $RunSpaceCollection = @()
    $AsyncHandleCollection = @()
    # Prepare and Create Runspaces for each Excel SpreadSheet
    for ($i=0; $i -lt $ArrayOfFileIOWatcherPSObjects.Count; $i++)
    {
        New-Variable -Name "syncHash$i" -Scope Global -Value $([hashtable]::Synchronized(@{}))
        $syncHashCollection +=, $(Get-Variable -Name "syncHash$i" -ValueOnly)

        New-Variable -Name "Runspace$i" -Value $([runspacefactory]::CreateRunspace())
        $(Get-Variable -Name "Runspace$i" -ValueOnly).ApartmentState = "STA"
        $(Get-Variable -Name "Runspace$i" -ValueOnly).ThreadOptions = "ReuseThread"
        $(Get-Variable -Name "Runspace$i" -ValueOnly).Open()
        # Pass all function Parameters to the Runspace
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("AllParams",$AllParams)
        foreach ($ParamKVP in $AllParams) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("$($ParamKVP.Key)",$(Get-Variable -Name "$($ParamKVP.Key)" -ValueOnly))
        }
        # Pass all other needed Variables to the Runspace
        foreach ($VarName in $OtherVarsToPassToRunspaces) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable($VarName,$(Get-Variable -Name $VarName -ValueOnly))
        }
        foreach ($VarName1 in $BlockVarsToPassToRunspaces) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable($VarName1,$(Get-Variable -Name $VarName1 -ValueOnly))
        }
        # Pass syncHash$i to the Runspace
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("syncHash",$(Get-Variable -Name "syncHash$i" -ValueOnly))
        # Pass Runspace Manager Synchronized Hashtable and Synctronized Arraylist
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("JobCleanup",$script:JobCleanup)
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("Jobs",$script:Jobs)
        # Pass the Register-FileIOWatcher ScriptBlock to the Runspace
        #$(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("FileIOWatcherEventLogDir",$FileIOWatcherEventLogDir)
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("FileIOWatcherScriptBlock",$ArrayOfFileIOWatcherPSObjects[$i])


        New-Variable -Name "PSInstance$i" -Value $([System.Management.Automation.PowerShell]::Create())
        $(Get-Variable -Name "PSInstance$i" -ValueOnly).AddScript({
            ## BEGIN Main Code to run in Runspace ##

            $syncHash.CompleteFlag = "Working"
            
            # Re-Import Any PS Modules

            # Run the FileIO Watcher ScriptBlock
            $Result = Invoke-Expression "$FileIOWatcherScriptBlock"
            $syncHash.Add("RegisterIOWatcher$i",$Result)

            $syncHash.CompleteFlag = "Complete"

            ## END Main Code to run in Runspace ##
        })

        # Start the Runspace in the PSInstance
        $(Get-Variable -Name "PSInstance$i" -ValueOnly).Runspace = $(Get-Variable -Name "Runspace$i" -ValueOnly)
        New-Variable -Name "AsyncHandle$i" -Value $($(Get-Variable -Name "PSInstance$i" -ValueOnly).BeginInvoke())

        $RunSpaceCollection +=, $(Get-Variable -Name "Runspace$i" -ValueOnly)
        $PSInstanceCollection +=, $(Get-Variable -Name "PSInstance$i" -ValueOnly)
        $AsyncHandleCollection +=, $(Get-Variable -Name "AsyncHandle$i" -ValueOnly)

        # Add the $PSInstance$i Job (with its accompanying $PSInstance$i.Runspace) to the array of jobs (i.e. $script.Jobs)
        # that the Runspace Manager Runspace is handling
        $script:Jobs +=, $(Get-Variable -Name "PSInstance$i" -ValueOnly)
    }

    ##### END Setup Runspace Creation Loop #####

    ##### END RUNSPACES #####


    ##### END Main Body #####

}
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwvvewXjzumqavv3I1Oji54fH
# zZugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFONcgAzmwSaXvhgb
# qEcIXYMPQ+1CMA0GCSqGSIb3DQEBAQUABIIBABpYetWCC2pBb4O9CXgPdJDR3C1s
# dEZ0jV+h9jKLXToEKD0N7eWD92qQ2Vr/ijRI44ZWT51yahGE5nJoyKHem62zmMs3
# Cz+i1+z4VJkz09X1btAP2sGmN9BpqFtqOE7xWqUsDTZscCHe/Uvz502jQDDEPeKD
# 9FO1h73cY5SACVnllqcn9lMtJO/lJCOym8O1Y4D4zBbhrwb9At4stTg/aQaenZTI
# mNnpYGGFXfVaX5q9sTDH5n8HF4QovVBoqh0kHR5Be77YbtU1kW1eLjIjnFoKLTyg
# ZMdh9bsRLRnRxque4suwN0zeCYuC/+L3agCu+RCWGvo9QxcapiWglgFuTG8=
# SIG # End signature block
