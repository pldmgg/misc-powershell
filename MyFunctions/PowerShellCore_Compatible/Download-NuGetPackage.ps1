function Download-NuGetPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AssemblyName,

        [Parameter(Mandatory=$False)]
        [string]$NuGetPkgDownloadPath,

        [Parameter(Mandatory=$False)]
        [switch]$AllowPreRelease
    )

    ##### BEGIN Helper Native Functions #####

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
    
    function Unzip-File {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,Position=0)]
            [string]$PathToZip,
            
            [Parameter(Mandatory=$true,Position=1)]
            [string]$TargetDir,
    
            [Parameter(Mandatory=$false,Position=2)]
            [string[]]$SpecificItem
        )
    
        if ($PSVersionTable.PSEdition -eq "Core") {
            [System.Collections.ArrayList]$AssembliesToCheckFor = @("System.Console","System","System.IO",
                "System.IO.Compression","System.IO.Compression.Filesystem","System.IO.Compression.ZipFile"
            )
    
            [System.Collections.ArrayList]$NeededAssemblies = @()
    
            foreach ($assembly in $AssembliesToCheckFor) {
                try {
                    [System.Collections.ArrayList]$Failures = @()
                    try {
                        $TestLoad = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
                        if (!$TestLoad) {
                            throw
                        }
                    }
                    catch {
                        $null = $Failures.Add("Failed LoadWithPartialName")
                    }
    
                    try {
                        $null = Invoke-Expression "[$assembly]"
                    }
                    catch {
                        $null = $Failures.Add("Failed TabComplete Check")
                    }
    
                    if ($Failures.Count -gt 1) {
                        $Failures
                        throw
                    }
                }
                catch {
                    Write-Host "Downloading $assembly..."
                    $NewAssemblyDir = "$HOME\Downloads\$assembly"
                    $NewAssemblyDllPath = "$NewAssemblyDir\$assembly.dll"
                    if (!$(Test-Path $NewAssemblyDir)) {
                        New-Item -ItemType Directory -Path $NewAssemblyDir
                    }
                    if (Test-Path "$NewAssemblyDir\$assembly*.zip") {
                        Remove-Item "$NewAssemblyDir\$assembly*.zip" -Force
                    }
                    $OutFileBaseNamePrep = Invoke-WebRequest "https://www.nuget.org/api/v2/package/$assembly" -DisableKeepAlive -UseBasicParsing
                    $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
                    Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/$assembly" -OutFile "$NewAssemblyDir\$OutFileBaseName"
                    Expand-Archive -Path "$NewAssemblyDir\$OutFileBaseName" -DestinationPath $NewAssemblyDir
    
                    $PossibleDLLs = Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {$_.Name -eq "$assembly.dll" -and $_.Parent -notmatch "net[0-9]" -and $_.Parent -match "core|standard"}
    
                    if ($PossibleDLLs.Count -gt 1) {
                        Write-Warning "More than one item within $NewAssemblyDir\$OutFileBaseName matches $assembly.dll"
                        Write-Host "Matches include the following:"
                        for ($i=0; $i -lt $PossibleDLLs.Count; $i++){
                            "$i) $($($PossibleDLLs[$i]).FullName)"
                        }
                        $Choice = Read-Host -Prompt "Please enter the number corresponding to the .dll you would like to load [0..$($($PossibleDLLs.Count)-1)]"
                        if ($(0..$($($PossibleDLLs.Count)-1)) -notcontains $Choice) {
                            Write-Error "The number indicated does is not a valid choice! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
    
                        if ($PSVersionTable.Platform -eq "Win32NT") {
                            # Install to GAC
                            [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                            $publish = New-Object System.EnterpriseServices.Internal.Publish
                            $publish.GacInstall($PossibleDLLs[$Choice].FullName)
                        }
    
                        # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                        Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"
    
                        # Remove everything else that was extracted with Expand-Archive
                        Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                            $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                            $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                        } | Remove-Item -Recurse -Force
                        
                    }
                    if ($PossibleDLLs.Count -lt 1) {
                        Write-Error "No matching .dll files were found within $NewAssemblyDir\$OutFileBaseName ! Halting!"
                        continue
                    }
                    if ($PossibleDLLs.Count -eq 1) {
                        if ($PSVersionTable.Platform -eq "Win32NT") {
                            # Install to GAC
                            [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                            $publish = New-Object System.EnterpriseServices.Internal.Publish
                            $publish.GacInstall($PossibleDLLs.FullName)
                        }
    
                        # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                        Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"
    
                        # Remove everything else that was extracted with Expand-Archive
                        Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                            $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                            $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                        } | Remove-Item -Recurse -Force
                    }
                }
                $AssemblyFullInfo = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
                if (!$AssemblyFullInfo) {
                    $AssemblyFullInfo = [System.Reflection.Assembly]::LoadFile("$NewAssemblyDir\$assembly.dll")
                }
                if (!$AssemblyFullInfo) {
                    Write-Error "The assembly $assembly could not be found or otherwise loaded! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $null = $NeededAssemblies.Add([pscustomobject]@{
                    AssemblyName = "$assembly"
                    Available = if ($AssemblyFullInfo){$true} else {$false}
                    AssemblyInfo = $AssemblyFullInfo
                    AssemblyLocation = $AssemblyFullInfo.Location
                })
            }
    
            if ($NeededAssemblies.Available -contains $false) {
                $AssembliesNotFound = $($NeededAssemblies | Where-Object {$_.Available -eq $false}).AssemblyName
                Write-Error "The following assemblies cannot be found:`n$AssembliesNotFound`nHalting!"
                $global:FunctionResult = "1"
                return
            }
    
            $Assem = $NeededAssemblies.AssemblyInfo.FullName
    
            $Source = @"
            using System;
            using System.IO;
            using System.IO.Compression;
    
            namespace MyCore.Utils
            {
                public static class Zip
                {
                    public static void ExtractAll(string sourcepath, string destpath)
                    {
                        string zipPath = @sourcepath;
                        string extractPath = @destpath;
    
                        using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Update))
                        {
                            archive.ExtractToDirectory(extractPath);
                        }
                    }
    
                    public static void ExtractSpecific(string sourcepath, string destpath, string specificitem)
                    {
                        string zipPath = @sourcepath;
                        string extractPath = @destpath;
                        string itemout = @specificitem.Replace(@"\","/");
    
                        //Console.WriteLine(itemout);
    
                        using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                        {
                            foreach (ZipArchiveEntry entry in archive.Entries)
                            {
                                //Console.WriteLine(entry.FullName);
                                //bool satisfied = new bool();
                                //satisfied = entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1;
                                //Console.WriteLine(satisfied);
    
                                if (entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1)
                                {
                                    string finaloutputpath = extractPath + "\\" + entry.Name;
                                    entry.ExtractToFile(finaloutputpath, true);
                                }
                            }
                        } 
                    }
                }
            }
"@
    
            $CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
            $CheckMyCoreUtilsDownloadIdLoaded = $CurrentLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.Zip*"}
            if ($CheckMyCoreUtilsDownloadIdLoaded -eq $null) {
                Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source
            }
            else {
                Write-Warning "The Namespace MyCore.Utils Class Zip is already loaded!"
            }
            
            if (!$SpecificItem) {
                [MyCore.Utils.Zip]::ExtractAll($PathToZip, $TargetDir)
            }
            else {
                [MyCore.Utils.Zip]::ExtractSpecific($PathToZip, $TargetDir, $SpecificItem)
            }
        }
    
    
        if ($PSVersionTable.PSEdition -eq "Desktop" -and $($($PSVersionTable.Platform -and $PSVersionTable.Platform -eq "Win32NT") -or !$PSVersionTable.Platform)) {
            if ($SpecificItem) {
                foreach ($item in $SpecificItem) {
                    if ($SpecificItem -match "\\") {
                        $SpecificItem = $SpecificItem -replace "\\","\\"
                    }
                }
            }
    
            ##### BEGIN Native Helper Functions #####
            function Get-ZipChildItems {
                [CmdletBinding()]
                Param(
                    [Parameter(Mandatory=$false,Position=0)]
                    [string]$ZipFile = $(Read-Host -Prompt "Please enter the full path to the zip file")
                )
    
                $shellapp = new-object -com shell.application
                $zipFileComObj = $shellapp.Namespace($ZipFile)
                $i = $zipFileComObj.Items()
                Get-ZipChildItems_Recurse $i
            }
    
            function Get-ZipChildItems_Recurse {
                [CmdletBinding()]
                Param(
                    [Parameter(Mandatory=$true,Position=0)]
                    $items
                )
    
                foreach($si in $items) {
                    if($si.getfolder -ne $null) {
                        # Loop through subfolders 
                        Get-ZipChildItems_Recurse $si.getfolder.items()
                    }
                    # Spit out the object
                    $si
                }
            }
    
            ##### END Native Helper Functions #####
    
            ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
            if (!$(Test-Path $PathToZip)) {
                Write-Verbose "The path $PathToZip was not found! Halting!"
                Write-Error "The path $PathToZip was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($(Get-ChildItem $PathToZip).Extension -ne ".zip") {
                Write-Verbose "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
                Write-Error "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $ZipFileNameWExt = $(Get-ChildItem $PathToZip).Name
    
            ##### END Variable/Parameter Transforms and PreRun Prep #####
    
            ##### BEGIN Main Body #####
    
            Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"
    
            if (!$SpecificItem) {
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
            if ($SpecificItem) {
                $ZipSubItems = Get-ZipChildItems -ZipFile $PathToZip
    
                foreach ($searchitem in $SpecificItem) {
                    [array]$potentialItems = foreach ($item in $ZipSubItems) {
                        if ($item.Path -match $searchitem) {
                            $item
                        }
                    }
    
                    $shell = new-object -com shell.application
    
                    if ($potentialItems.Count -eq 1) {
                        $shell.Namespace($TargetDir).CopyHere($potentialItems[0], 0x14)
                    }
                    if ($potentialItems.Count -gt 1) {
                        Write-Warning "More than one item within $ZipFileNameWExt matches $searchitem."
                        Write-Host "Matches include the following:"
                        for ($i=0; $i -lt $potentialItems.Count; $i++){
                            "$i) $($($potentialItems[$i]).Path)"
                        }
                        $Choice = Read-Host -Prompt "Please enter the number corresponding to the item you would like to extract [0..$($($potentialItems.Count)-1)]"
                        if ($(0..$($($potentialItems.Count)-1)) -notcontains $Choice) {
                            Write-Warning "The number indicated does is not a valid choice! Skipping $searchitem..."
                            continue
                        }
                        for ($i=0; $i -lt $potentialItems.Count; $i++){
                            $shell.Namespace($TargetDir).CopyHere($potentialItems[$Choice], 0x14)
                        }
                    }
                    if ($potentialItems.Count -lt 1) {
                        Write-Warning "No items within $ZipFileNameWExt match $searchitem! Skipping..."
                        continue
                    }
                }
            }
            ##### END Main Body #####
        }
    }

    function Update-PackageManagement {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$False)]
            [switch]$AddChocolateyPackageProvider,
    
            [Parameter(Mandatory=$False)]
            [switch]$InstallNuGetCmdLine,
    
            [Parameter(Mandatory=$False)]
            [switch]$LoadUpdatedModulesInSameSession
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
    
        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -ne "Win32NT" -and $AddChocolateyPackageProvider) {
            Write-Error "The Chocolatey Repo should only be added on a Windows OS! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        if ($InstallNuGetCmdLine -and !$AddChocolateyPackageProvider) {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                    $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to use the Chocolatey Package Provider (NOTE: This is NOT an installation of the chocolatey command line)?"
                    $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                    if ($WarningResponse) {
                        $AddChocolateyPackageProvider = $true
                    }
                }
                else {
                    $AddChocolateyPackageProvider = $true
                }
            }
            elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to install Chocolatey Command Line Tools in order to install NuGet Command Line Tools?"
                    $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                    if ($WarningResponse) {
                        $AddChocolateyPackageProvider = $true
                    }
                }
                else {
                    $AddChocolateyPackageProvider = $true
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
                $AddChocolateyPackageProvider = $false
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
                Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
            }
            while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
                Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
                Start-Sleep -Seconds 1
            }
            Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
        }
    
        # We need to load whatever versions of PackageManagement/PowerShellGet are available on the Local Host in order
        # to use the Find-Module cmdlet to find out what the latest versions of each Module are...
    
        # ...but because there are sometimes issues with version compatibility between PackageManagement/PowerShellGet,
        # after loading the latest PackageManagement Module we need to try/catch available versions of PowerShellGet until
        # one of them actually loads
        
        # Set LatestLocallyAvailable variables...
        $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
        $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
        $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
        $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
        $PSGetLocallyAvailableVersions = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Sort-Object -Property Version | Get-Unique
        $PSGetLocallyAvailableVersions = $PSGetLocallyAvailableVersions | Sort-Object -Descending
        
    
        if ($(Get-Module).Name -notcontains "PackageManagement") {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
            }
            else {
                Import-Module "PackageManagement"
            }
        }
        if ($(Get-Module).Name -notcontains "PowerShellGet") {
            foreach ($version in $PSGetLocallyAvailableVersions) {
                try {
                    $ImportedPSGetModule = Import-Module "PowerShellGet" -RequiredVersion $version -PassThru -ErrorAction SilentlyContinue
                    if (!$ImportedPSGetModule) {throw}
    
                    break
                }
                catch {
                    continue
                }
            }
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
    
        if ($AddChocolateyPackageProvider) {
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
        try {
            $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
        }
        catch {
            $PackageManagementLatestVersion = $PackageManagementLatestLocallyAvailableVersion
        }
        try {
            $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version
        }
        catch {
            $PowerShellGetLatestVersion = $PowerShellGetLatestLocallyAvailableVersion
        }
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
                Install-Module -Name "PackageManagement" -Force -WarningAction SilentlyContinue
                $PackageManagementUpdated = $True
            }
        }
        if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
            # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
            # and it will not update it.
            Write-Host "Installing latest version of PowerShellGet..."
            #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
            #Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
            Install-Module -Name "PowerShellGet" -Force -WarningAction SilentlyContinue
            $PowerShellGetUpdated = $True
        }
    
        # Reset the LatestLocallyAvailable variables, and then load them into the current session
        $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
        $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
        $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
        $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
        Write-Verbose "Latest locally available PackageManagement version is $PackageManagementLatestLocallyAvailableVersion"
        Write-Verbose "Latest locally available PowerShellGet version is $PowerShellGetLatestLocallyAvailableVersion"
    
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
    
        if ($PackageManagementUpdated -eq $True -or $PowerShellGetUpdated -eq $True) {
            $NewPSSessionRequired = $True
            if ($LoadUpdatedModulesInSameSession) {
                if ($PowerShellGetUpdated -eq $True) {
                    $PSGetWarningMsg = "Loading the latest installed version of PowerShellGet " +
                    "(i.e. PowerShellGet $($PowerShellGetLatestLocallyAvailableVersion.ToString()) " +
                    "in the current PowerShell session will break some PowerShellGet Cmdlets!"
                    Write-Warning $PSGetWarningMsg
                }
                if ($PackageManagementUpdated -eq $True) {
                    $PMWarningMsg = "Loading the latest installed version of PackageManagement " +
                    "(i.e. PackageManagement $($PackageManagementLatestLocallyAvailableVersion.ToString()) " +
                    "in the current PowerShell session will break some PackageManagement Cmdlets!"
                    Write-Warning $PMWarningMsg
                }
            }
        }
    
        if ($LoadUpdatedModulesInSameSession) {
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
            if ($AddChocolateyPackageProvider -and $($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5)) {
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
        }
    
        $Result = [pscustomobject][ordered]@{
            PackageManagementUpdated                     = if ($PackageManagementUpdated) {$true} else {$false}
            PowerShellGetUpdated                         = if ($PowerShellGetUpdated) {$true} else {$false}
            NewPSSessionRequired                         = if ($NewPSSessionRequired) {$true} else {$false}
            PackageManagementCurrentlyLoaded             = Get-Module -Name PackageManagement
            PowerShellGetCurrentlyLoaded                 = Get-Module -Name PowerShellGet
            PackageManagementLatesLocallyAvailable       = $PackageManagementLatestLocallyAvailableVersionItem
            PowerShellGetLatestLocallyAvailable          = $PowerShellGetLatestLocallyAvailableVersionItem
        }
    
        $Result
    }

    ##### END Helper Native Functions #####

    ##### BEGIN Parameter Validation #####

    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        if (!$NuGetPkgDownloadPath) {
            $NuGetPkgDownloadPath = Read-Host -Prompt "Please enter the path to the directory where the $AssemblyName NuGet Package will be downloaded to"
        }
    }

    <#
    if ($PSVersionTable.PSEdition -eq "Desktop" -and $NuGetPkgDownloadPath) {
        Write-Error "The -NuGetPkgDownloadPath parameter is only meant to be used with PowerShell Core! Halting!"
        $global:FunctionResult = "1"
        return
    }
    #>
    
    ##### END Parameter Validation #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $s = [IO.Path]::DirectorySeparatorChar

    if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadPath) {
        $NuGetPackageUri = "https://www.nuget.org/api/v2/package/$AssemblyName"
        try {
            $OutFileBaseNamePrep = Invoke-WebRequest $NuGetPackageUri -DisableKeepAlive -UseBasicParsing
            $RequestResponseUri = if ($PSVersionTable.PSEdition -eq "Core") {
                $OutFileBaseNamePrep.BaseResponse.RequestMessage.RequestUri.OriginalString
            }
            else {
                $OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri
            }
            $OutFileBaseName = $($RequestResponseUri -split "$s")[-1] -replace "nupkg","zip"
            $DllFileName = $OutFileBaseName -replace "zip","dll"
        }
        catch {
            $OutFileBaseName = "$AssemblyName`_LatestAsOf_$(Get-Date -Format MMddyy).zip"
        }

        $TestPath = $NuGetPkgDownloadPath
        $BrokenDir = while (-not (Test-Path $TestPath)) {
            $CurrentPath = $TestPath
            $TestPath = Split-Path $TestPath
            if (Test-Path $TestPath) {$CurrentPath}
        }

        if ([String]::IsNullOrWhitespace([System.IO.Path]::GetExtension($NuGetPkgDownloadPath))) {
            # Assume it's a directory
            if ($BrokenDir) {
                if ($BrokenDir -eq $NuGetPkgDownloadPath) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $FinalNuGetPkgPath = Get-NativePath @($BrokenDir, $OutFileBaseName)
            }
            else {
                if ($(Get-ChildItem $NuGetPkgDownloadPath).Count -ne 0) {
                    $NewDir = Get-NativePath @($NuGetPkgDownloadPath, [System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                $FinalNuGetPkgPath = Get-NativePath @($NewDir, $OutFileBaseName)
            }
        }
        else {
            # Assume it's a file
            $OutFileBaseName = $NuGetPkgDownloadPath | Split-Path -Leaf
            $extension = [System.IO.Path]::GetExtension($OutFileBaseName)
            if ($extension -ne ".zip") {
                $OutFileBaseName = $OutFileBaseName -replace "$extension",".zip"
            }

            if ($BrokenDir) {
                Write-Host "BrokenDir is $BrokenDir"
                if ($BrokenDir -eq $($NuGetPkgDownloadPath | Split-Path -Parent)) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $FinalNuGetPkgPath = Get-NativePath @($BrokenDir, $OutFileBaseName)
            }
            else {
                if ($(Get-ChildItem $($NuGetPkgDownloadPath | Split-Path -Parent)).Count -ne 0) {
                    $NewDir = Get-NativePath @($($NuGetPkgDownloadPath | Split-Path -Parent), [System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                
                $FinalNuGetPkgPath = Get-NativePath @($NewDir, $OutFileBaseName)
            }
        }

        $NuGetPkgDownloadPathParentDir = $FinalNuGetPkgPath | Split-Path -Parent
    }
    if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadPath) {
        $NuGetConfigContent = Get-Content $(Get-NativePath @($env:AppData, "NuGet", "nuget.config"))
        $NuGetRepoPathCheck = $NuGetConfigContent | Select-String -Pattern '<add key="repositoryPath" value=' -ErrorAction SilentlyContinue
        if ($NuGetRepoPathCheck -ne $null) {
            $NuGetPackagesPath = $($($NuGetRepoPathCheck.Line.Trim() -split 'value=')[-1] -split ' ')[0] -replace '"',''
        }
        else {
            $NuGetPackagesPath = Get-NativePath @($HOME, ".nuget", "packages")
        }

        $NuGetPkgDownloadPathParentDir = Get-NativePath @($NuGetPackagesPath, $AssemblyName)
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $PossibleSubDirs = @(
            [pscustomobject]@{
                Preference      = 3
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
            }
            [pscustomobject]@{
                Preference      = 1
                SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
            }
            [pscustomobject]@{
                Preference      = 2
                SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
            }
        )
    }
    else {
        $PossibleSubDirs = @(
            [pscustomobject]@{
                Preference      = 8
                SubDirectory    = $(Get-NativePath @("lib", "net40"))
            }
            [pscustomobject]@{
                Preference      = 7
                SubDirectory    = $(Get-NativePath @("lib", "net45"))
            }
            [pscustomobject]@{
                Preference      = 6
                SubDirectory    = $(Get-NativePath @("lib", "net451"))
            }
            [pscustomobject]@{
                Preference      = 5
                SubDirectory    = $(Get-NativePath @("lib", "net46"))
            }
            [pscustomobject]@{
                Preference      = 4
                SubDirectory    = $(Get-NativePath @("lib", "net461"))
            }
            [pscustomobject]@{
                Preference      = 3
                SubDirectory    = $(Get-NativePath @("lib", "net462"))
            }
            [pscustomobject]@{
                Preference      = 2
                SubDirectory    = $(Get-NativePath @("lib", "net47"))
            }
            [pscustomobject]@{
                Preference      = 1
                SubDirectory    = $(Get-NativePath @("lib", "net471"))
            }
            [pscustomobject]@{
                Preference      = 15
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.0"))
            }
            [pscustomobject]@{
                Preference      = 14
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.1"))
            }
            [pscustomobject]@{
                Preference      = 13
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.2"))
            }
            [pscustomobject]@{
                Preference      = 12
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.3"))
            }
            [pscustomobject]@{
                Preference      = 11
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.4"))
            }
            [pscustomobject]@{
                Preference      = 10
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.5"))
            }
            [pscustomobject]@{
                Preference      = 9
                SubDirectory    = $(Get-NativePath @("lib", "netstandard1.6"))
            }
            [pscustomobject]@{
                Preference      = 16
                SubDirectory    = $(Get-NativePath @("lib", "netstandard2.0"))
            }
            [pscustomobject]@{
                Preference      = 17
                SubDirectory    = $(Get-NativePath @("lib", "netcoreapp2.0"))
            }
        )
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    
    ##### BEGIN Main Body #####
    if ($($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT") -and !$NuGetPkgDownloadPath) {
        $null = Update-PackageManagement -InstallNuGetCmdLine

        if (!$(Get-Command nuget.exe -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find nuget.exe, however, it should be installed. Please check your System PATH and `$env:Path and try again. Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.WorkingDirectory = $NuGetPackagesPath
            $ProcessInfo.FileName = "nuget.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            if ($AllowPreRelease) {
                $ProcessInfo.Arguments = "install $AssemblyName -PreRelease"
            }
            else {
                $ProcessInfo.Arguments = "install $AssemblyName"
            }
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
            $stderr = $($Process.StandardError.ReadToEnd()).Trim()
            $AllOutput = $stdout + $stderr
            $AllOutput = $AllOutput -split "`n"

            if ($($AllOutput | Select-String -Pattern "is already installed").Matches.Success) {
                $AlreadyInstalledMessage = $($AllOutput | Select-String -Pattern "is already installed").Line.Trim()
                $AssemblyFolderName = $($AlreadyInstalledMessage -split '"')[1].Trim()
                Write-Host $AlreadyInstalledMessage
                $NuGetPkgDownloadPathParentDir = $($NuGetPackagesPath + $s + $AssemblyFolderName)
            }

            if ($($AllOutput | Select-String -Pattern "Successfully installed").Matches.Success) {
                $AddedPackageMessage = $($AllOutput | Select-String -Pattern "Added package").Line
                $AssemblyFolderName = $($AddedPackageMessage -split "'")[1].Trim()
                $SuccessfullyInstalledMessage = $($AllOutput | Select-String -Pattern "Successfully installed").Line.Trim()
                Write-Host $($SuccessfullyInstalledMessage + $s + $AssemblyFolderName)
                $NuGetPkgDownloadPathParentDir = $($($SuccessfullyInstalledMessage -split " ")[-1].Trim() + $s + $AssemblyFolderName)
            }

            if ($stderr -match "Unable to find package") {
                throw
            }
        }
        catch {
            Write-Error "NuGet.exe was unable to find a package called $AssemblyName! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") -or $NuGetPkgDownloadPath) {
        try {
            # Download the NuGet Package
            Write-Host "Downloading $AssemblyName NuGet Package to $FinalNuGetPkgPath ..."
            Invoke-WebRequest -Uri $NuGetPackageUri -OutFile $FinalNuGetPkgPath
            Write-Host "NuGet Package has been downloaded to $FinalNuGetPkgPath"
        }
        catch {
            Write-Error "Unable to find $AssemblyName via the NuGet API! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Step through possble Zip File SubDirs and get the most highst available compatible version of the Assembly
        try {
            Write-Host "Attempting to extract NuGet zip file $FinalNuGetPkgPath to $NuGetPkgDownloadPathParentDir ..."
            if ($(Get-ChildItem $NuGetPkgDownloadPathParentDir).Count -gt 1) {
                foreach ($item in $(Get-ChildItem $NuGetPkgDownloadPathParentDir)) {
                    if ($item.Extension -ne ".zip") {
                        $item | Remove-Item -Recurse -Force
                    }
                }
            }
            Unzip-File -PathToZip $FinalNuGetPkgPath -TargetDir $NuGetPkgDownloadPathParentDir
            Write-Host "NuGet Package is available here: $NuGetPkgDownloadPathParentDir"
        }
        catch {
            Write-Warning "The Unzip-File function failed with the following error:"
            Write-Error $$_
            $global:FunctionResult = "1"
            return
        }
    }

    [System.Collections.ArrayList]$NuGetPackageActualSubDirs = @()
    $(Get-ChildItem -Recurse $NuGetPkgDownloadPathParentDir -File -Filter "*.dll").DirectoryName | foreach {
        $null = $NuGetPackageActualSubDirs.Add($_)
    }
    
    [System.Collections.ArrayList]$FoundSubDirsPSObjects = @()
    foreach ($pdir in $PossibleSubDirs) {
        foreach ($adir in $NuGetPackageActualSubDirs) {
            $IndexOfSlash = $pdir.SubDirectory.IndexOf($s)
            $pdirToRegexPattern = {
                $UpdatedString = $pdir.SubDirectory.Remove($IndexOfSlash, 1)
                $UpdatedString.Insert($IndexOfSlash, [regex]::Escape($s))
            }.Invoke()

            if ($adir -match $pdirToRegexPattern) {
                $FoundDirPSObj = [pscustomobject]@{
                    Preference   = $pdir.Preference
                    Directory    = $adir
                }
                $null = $FoundSubDirsPSObjects.Add($FoundDirPSObj)
            }
        }
    }

    $TargetDir = $($FoundSubDirsPSObjects | Sort-Object -Property Preference)[0].Directory
    $AssemblyPath = Get-NativePath @($TargetDir, $(Get-ChildItem $TargetDir -File -Filter "*.dll").Name)
    
    [pscustomobject]@{
        NuGetPackageDirectory   = $NuGetPkgDownloadPathParentDir
        AssemblyToLoad          = $AssemblyPath
    }
    

    <#
    $CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $CheckAssemblyIsLoaded = $CurrentLoadedAssemblies | Where-Object {$_.FullName -like "$AssemblyName*"}
    if ($CheckAssemblyIsLoaded -eq $null) {
        Add-Type -Path $AssemblyPath
    }
    else {
        Write-Warning "The Assembly $AssemblyName is already loaded!"
    }
    #>

    
    ##### END Main Body #####

}















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZ5xZYb3mZ737EGxhqYFVXSOB
# +6+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFO2eMDLCifYr8Kii
# EzC+tFlVDGjsMA0GCSqGSIb3DQEBAQUABIIBAJNwSTI7eKJ6+41bnb1c5NWrA5+E
# E2bh60sCGnAe1ini+hU6uVBXqvbVd1xQNhsB9m9uudJ6U08lHmx4NVo2s7D6Sna/
# 4KIDowJzWMoncSyRH3fxXKUcPvYpTkMyNRcEozVLmBl5L1OKQMA41dXyI0rWF30C
# SvkU2Vwo6i9cee6646G081Iuukl5YEgXAL1ktkwqKieSZtqy7P8UhXhN7MVXn3/1
# SnhfM/KOubCPol266wX7EHaKvgVLz04anH/0Y9h2KbNJNpySZ4exzvI/gHNkCzxT
# CKUF+hCRghrT9gfctvOBoKrcXHeU/NkSiMgBQcF1ajfPCo1GByqEGZx8Bpw=
# SIG # End signature block
