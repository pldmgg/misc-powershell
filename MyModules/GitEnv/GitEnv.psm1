[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

function GetElevation {
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

function New-UniqueString {
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

        Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source

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

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
    if (!$(GetElevation)) {
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

function Install-ChocolateyCmdLine {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement
    )

    ##### BEGIN Native Helper Functions #####

    function GetElevation {
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

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Invoke-WebRequest fix...
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $UPMResult = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($global:FunctionResult -eq "1" -or $UPMResult -eq $null) {throw "The Update-PackageManagement function failed!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        # The below Install-Package Chocolatey screws up $env:Path, so restore it afterwards
        $OriginalEnvPath = $env:Path

        # Installing Package Providers is spotty sometimes...Using while loop 3 times before failing
        $Counter = 0
        while ($(Get-PackageProvider).Name -notcontains "Chocolatey" -and $Counter -lt 3) {
            Install-PackageProvider -Name Chocolatey -Force -Confirm:$false -WarningAction SilentlyContinue
            $Counter++
            Start-Sleep -Seconds 5
        }
        if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
            Write-Error "Unable to install the Chocolatey Package Provider / Repo for PackageManagement/PowerShellGet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Package -Name Chocolatey -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
            # NOTE: The PackageManagement install of choco is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package Chocolatey -Provider Chocolatey -Force -Confirm:$false -ErrorVariable ChocoInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($ChocoInstallError.Count -gt 0) {
                Write-Warning "There was a problem installing the Chocolatey CmdLine via PackageManagement/PowerShellGet!"
                $InstallViaOfficialScript = $True
                Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
            }

            if ($ChocoInstallError.Count -eq 0) {
                $PMPGetInstall = $True
            }
        }

        # Try and find choco.exe
        try {
            Write-Host "Refreshing `$env:Path..."
            $global:FunctionResult = "0"
            $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
            
            if ($RCEErr.Count -gt 0 -and
            $global:FunctionResult -eq "1" -and
            ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                throw "The Refresh-ChocolateyEnv function failed! Halting!"
            }
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
            Write-Error $($RCEErr | Out-String)
            $global:FunctionResult = "1"
            return
        }

        if ($PMPGetInstall) {
            # It's possible that PowerShellGet didn't run the chocolateyInstall.ps1 script to actually install the
            # Chocolatey CmdLine. So do it manually.
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Warning "Unable to find Chocolatey directory! Halting!"
                Write-Host "Installing via official script at https://chocolatey.org/install.ps1"
                $InstallViaOfficialScript = $True
            }
            
            if ($ChocolateyPath) {
                $ChocolateyInstallScript = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyinstall.ps1").FullName | Where-Object {
                    $_ -match ".*?chocolatey\.[0-9].*?chocolateyinstall.ps1$"
                }

                if (!$ChocolateyInstallScript) {
                    Write-Warning "Unable to find chocolateyinstall.ps1!"
                    $InstallViaOfficialScript = $True
                }
            }

            if ($ChocolateyInstallScript) {
                try {
                    Write-Host "Trying PowerShellGet Chocolatey CmdLine install script from $ChocolateyInstallScript ..." -ForegroundColor Yellow
                    & $ChocolateyInstallScript
                }
                catch {
                    Write-Error $_
                    Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                    if ([bool]$(Get-Package $ProgramName)) {
                        Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # If we still can't find choco.exe, then use the Chocolatey install script from chocolatey.org
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue) -or $InstallViaOfficialScript) {
            $ChocolateyInstallScriptUrl = "https://chocolatey.org/install.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($ChocolateyInstallScriptUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to install Chocolatey via the official chocolatey.org script! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PMPGetInstall = $False
        }
        
        # If we STILL can't find choco.exe, then Refresh-ChocolateyEnv a third time...
        #if (![bool]$($env:Path -split ";" -match "chocolatey\\bin")) {
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            # ...and then find it again and add it to $env:Path via Refresh-ChocolateyEnv function
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    
                    if ($RCEErr.Count -gt 0 -and
                    $global:FunctionResult -eq "1" -and
                    ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                        throw "The Refresh-ChocolateyEnv function failed! Halting!"
                    }
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        # If we STILL can't find choco.exe, then give up...
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find choco.exe after install! Check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Finished installing Chocolatey CmdLine." -ForegroundColor Green

            try {
                cup chocolatey-core.extension -y
            }
            catch {
                Write-Error "Installation of chocolatey-core.extension via the Chocolatey CmdLine failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            $ChocoModulesThatRefreshEnvShouldHaveLoaded = @(
                "chocolatey-core"
                "chocolateyInstaller"
                "chocolateyProfile"
                "chocolateysetup"
            )

            foreach ($ModName in $ChocoModulesThatRefreshEnvShouldHaveLoaded) {
                if ($(Get-Module).Name -contains $ModName) {
                    Write-Host "The $ModName Module has been loaded from $($(Get-Module -Name $ModName).Path)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Warning "The Chocolatey CmdLine is already installed!"
    }

    ##### END Main Body #####
}

function Refresh-ChocolateyEnv {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ChocolateyDirectory
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Fix any potential $env:Path mistakes...
    <#
    if ($env:Path -match ";;") {
        $env:Path = $env:Path -replace ";;",";"
    }
    #>

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        if ($ChocolateyDirectory) {
            $ChocolateyPath = $ChocolateyDirectory
        }
        else {
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Error "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        $ChocolateyPath = "$($($(Get-Command choco).Source -split "chocolatey")[0])chocolatey"
    }
    [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
    [System.Collections.ArrayList]$ChocolateyPathsToAddToEnvPath = @()
    if (Test-Path $ChocolateyPath) {
        $($(Get-ChildItem $ChocolateyPath -Directory | foreach {
            Get-ChildItem $_.FullName -Recurse -File
        } | foreach {
            if ($_.Extension -eq ".exe" -or $_.Extension -eq ".bat") {
                $_.Directory.FullName
            }
        }) | Sort-Object | Get-Unique) | foreach {
            $null = $ChocolateyPathsPrep.Add($_.Trim("\\"))
        }

        foreach ($ChocoPath in $ChocolateyPathsPrep) {
            if ($(Test-Path $ChocoPath) -and $($env:Path -split ";") -notcontains $ChocoPath -and $ChocoPath -ne $null) {
                $null = $ChocolateyPathsToAddToEnvPath.Add($ChocoPath)
            }
        }

        foreach ($ChocoPath in $ChocolateyPathsToAddToEnvPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path" + $ChocoPath + ";"
            }
            else {
                $env:Path = "$env:Path" + ";" + $ChocoPath
            }
        }
    }
    else {
        Write-Verbose "Unable to find Chocolatey Path $ChocolateyPath."
    }

    # Remove any repeats in $env:Path
    $UpdatedEnvPath = $($($($env:Path -split ";") | foreach {
        if (-not [System.String]::IsNullOrWhiteSpace($_)) {
            $_.Trim("\\")
        }
    }) | Select-Object -Unique) -join ";"

    # Next, find chocolatey-core.psm1, chocolateysetup.psm1, chocolateyInstaller.psm1, and chocolateyProfile.psm1
    # and import them
    $ChocoCoreModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolatey-core.psm1").FullName
    $ChocoSetupModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateysetup.psm1").FullName
    $ChocoInstallerModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyInstaller.psm1").FullName
    $ChocoProfileModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyProfile.psm1").FullName

    $ChocoModulesToImportPrep = @($ChocoCoreModule, $ChocoSetupModule, $ChocoInstallerModule, $ChocoProfileModule)
    [System.Collections.ArrayList]$ChocoModulesToImport = @()
    foreach ($ModulePath in $ChocoModulesToImportPrep) {
        if ($ModulePath -ne $null) {
            $null = $ChocoModulesToImport.Add($ModulePath)
        }
    }

    foreach ($ModulePath in $ChocoModulesToImport) {
        Remove-Module -Name $([System.IO.Path]::GetFileNameWithoutExtension($ModulePath)) -ErrorAction SilentlyContinue
        Import-Module -Name $ModulePath
    }

    $UpdatedEnvPath

    ##### END Main Body #####

}

function Install-Program {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [string]$CommandName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePowerShellGet,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$ForceChocoInstallScript,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [string]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$ScanCDriveForMainExeIfNecessary,

        [Parameter(Mandatory=$False)]
        [switch]$ResolveCommandPath = $True,

        [Parameter(Mandatory=$False)]
        [switch]$PreRelease
    )

    ##### BEGIN Native Helper Functions #####

    # The below function adds Paths from System PATH that aren't present in $env:Path (this probably shouldn't
    # be an issue, because $env:Path pulls from System PATH...but sometimes profile.ps1 scripts do weird things
    # and also $env:Path wouldn't necessarily be updated within the same PS session where a program is installed...)
    function Synchronize-SystemPathEnvPath {
        $SystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        
        $SystemPathArray = $SystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $EnvPathArray = $env:Path -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        
        # => means that $EnvPathArray HAS the paths but $SystemPathArray DOES NOT
        # <= means that $SystemPathArray HAS the paths but $EnvPathArray DOES NOT
        $PathComparison = Compare-Object $SystemPathArray $EnvPathArray
        [System.Collections.ArrayList][Array]$SystemPathsThatWeWantToAddToEnvPath = $($PathComparison | Where-Object {$_.SideIndicator -eq "<="}).InputObject

        if ($SystemPathsThatWeWantToAddToEnvPath.Count -gt 0) {
            foreach ($NewPath in $SystemPathsThatWeWantToAddToEnvPath) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$NewPath"
                }
                else {
                    $env:Path = "$env:Path;$NewPath"
                }
            }
        }
    }

    # Outputs [System.Collections.ArrayList]$ExePath
    function Adjudicate-ExePath {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$ProgramName,

            [Parameter(Mandatory=$True)]
            [string]$OriginalSystemPath,

            [Parameter(Mandatory=$True)]
            [string]$OriginalEnvPath,

            [Parameter(Mandatory=$True)]
            [string]$FinalCommandName,

            [Parameter(Mandatory=$False)]
            [string]$ExpectedInstallLocation
        )

        # ...search for it in the $ExpectedInstallLocation if that parameter is provided by the user...
        if ($ExpectedInstallLocation) {
            [System.Collections.ArrayList][Array]$ExePath = $(Get-ChildItem -Path $ExpectedInstallLocation -File -Recurse -Filter "*$FinalCommandName.exe").FullName
        }
        # If we don't have $ExpectedInstallLocation provided...
        if (!$ExpectedInstallLocation) {
            # ...then we can compare $OriginalSystemPath to the current System PATH to potentially
            # figure out which directories *might* contain the main executable.
            $OriginalSystemPathArray = $OriginalSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $OriginalEnvPathArray = $OriginalEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}

            $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            $CurrentSystemPathArray = $CurrentSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $CurrentEnvPath = $env:Path
            $CurrentEnvPathArray = $CurrentEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            

            $OriginalVsCurrentSystemPathComparison = Compare-Object $OriginalSystemPathArray $CurrentSystemPathArray
            $OriginalVsCurrentEnvPathComparison = Compare-Object $OriginalEnvPathArray $CurrentEnvPathArray

            [System.Collections.ArrayList]$DirectoriesToSearch = @()
            if ($OriginalVsCurrentSystemPathComparison -ne $null) {
                # => means that $CurrentSystemPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewSystemPathDirs = $($OriginalVsCurrentSystemPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewSystemPathDirs.Count -gt 0) {
                    foreach ($dir in $NewSystemPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }
            if ($OriginalVsCurrentEnvPathComparison -ne $null) {
                # => means that $CurrentEnvPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewEnvPathDirs = $($OriginalVsCurrentEnvPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewEnvPathDirs.Count -gt 0) {
                    foreach ($dir in $NewEnvPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }

            if ($DirectoriesToSearch.Count -gt 0) {
                $DirectoriesToSearchFinal = $($DirectoriesToSearch | Sort-Object | Get-Unique) | foreach {if (Test-Path $_) {$_}}
                $DirectoriesToSearchFinal = $DirectoriesToSearchFinal | Where-Object {$_ -match "$ProgramName"}

                [System.Collections.ArrayList]$ExePath = @()
                foreach ($dir in $DirectoriesToSearchFinal) {
                    [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*$FinalCommandName.exe").FullName
                    if ($ExeFiles.Count -gt 0) {
                        $null = $ExePath.Add($ExeFiles)
                    }
                }

                # If there IS a difference in original vs current System PATH / $Env:Path, but we 
                # still DO NOT find the main executable in those diff directories (i.e. $ExePath is still not set),
                # it's possible that the name of the main executable that we're looking for is actually
                # incorrect...in which case just tell the user that we can't find the expected main
                # executable name and provide a list of other .exe files that we found in the diff dirs.
                if (!$ExePath -or $ExePath.Count -eq 0) {
                    [System.Collections.ArrayList]$ExePath = @()
                    foreach ($dir in $DirectoriesToSearchFinal) {
                        [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*.exe").FullName
                        foreach ($File in $ExeFiles) {
                            $null = $ExePath.Add($File)
                        }
                    }
                }
            }
        }

        $ExePath | Sort-Object | Get-Unique
    }

    function GetElevation {
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

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Invoke-WebRequest fix...
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if (!$(GetElevation)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must be ran from an elevated PowerShell Session (i.e. 'Run as Administrator')! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UseChocolateyCmdLine) {
        $NoUpdatePackageManagement = $True
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $null = Install-PackageProvider -Name Chocolatey -Force -Confirm:$False
    $null = Set-PackageSource -Name chocolatey -Trusted -Force

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $null = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($UPMErr -and $global:FunctionResult -eq "1") {throw "The Update-PackageManagement function failed! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UseChocolateyCmdLine -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine)) {
        if (![bool]$(Get-Command Install-ChocolateyCmdLine -ErrorAction SilentlyContinue)) {
            $InstallCCFunctionUrl = "$MyFunctionsUrl/Install-ChocolateyCmdLine.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallCCFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Install-ChocolateyCmdLine function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If PackageManagement/PowerShellGet is installed, determine if $ProgramName is installed
    if ([bool]$(Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        $PackageManagementInstalledPrograms = Get-Package

        # If teh Current Installed Version is not equal to the Latest Version available, then it's outdated
        if ($PackageManagementInstalledPrograms.Name -contains $ProgramName) {
            $PackageManagementCurrentInstalledPackage = $PackageManagementInstalledPrograms | Where-Object {$_.Name -eq $ProgramName}
            $PackageManagementLatestVersion = $(Find-Package -Name $ProgramName -Source chocolatey -AllVersions | Sort-Object -Property Version)[-1]
        }
    }

    # If the Chocolatey CmdLine is installed, get a list of programs installed via Chocolatey
    if ([bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        $ChocolateyInstalledProgramsPrep = clist --local-only
        $ChocolateyInstalledProgramsPrep = $ChocolateyInstalledProgramsPrep[1..$($ChocolateyInstalledProgramsPrep.Count-2)]

        [System.Collections.ArrayList]$ChocolateyInstalledProgramsPSObjects = @()

        foreach ($program in $ChocolateyInstalledProgramsPrep) {
            $programParsed = $program -split " "
            $PSCustomObject = [pscustomobject]@{
                ProgramName     = $programParsed[0]
                Version         = $programParsed[1]
            }

            $null = $ChocolateyInstalledProgramsPSObjects.Add($PSCustomObject)
        }

        # Also get a list of outdated packages in case this Install-Program function is used to update a package
        $ChocolateyOutdatedProgramsPrep = choco outdated
        $UpperLineMatch = $ChocolateyOutdatedProgramsPrep -match "Output is package name"
        $LowerLineMatch = $ChocolateyOutdatedProgramsPrep -match "Chocolatey has determined"
        $UpperIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($UpperLineMatch) + 2
        $LowerIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($LowerLineMatch) - 2
        $ChocolateyOutdatedPrograms = $ChocolateyOutdatedProgramsPrep[$UpperIndex..$LowerIndex]

        [System.Collections.ArrayList]$ChocolateyOutdatedProgramsPSObjects = @()
        foreach ($line in $ChocolateyOutdatedPrograms) {
            $ParsedLine = $line -split "\|"
            $Program = $ParsedLine[0]
            $CurrentInstalledVersion = $ParsedLine[1]
            $LatestAvailableVersion = $ParsedLine[2]

            $PSObject = [pscustomobject]@{
                ProgramName                 = $Program
                CurrentInstalledVersion     = $CurrentInstalledVersion
                LatestAvailableVersion      = $LatestAvailableVersion
            }

            $null = $ChocolateyOutdatedProgramsPSObjects.Add($PSObject)
        }
    }

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }
    $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}

    # Save the original System PATH and $env:Path before we do anything, just in case
    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalEnvPath = $env:Path
    Synchronize-SystemPathEnvPath
    $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install $ProgramName if it's not already or if it's outdated...
    if ($($PackageManagementInstalledPrograms.Name -notcontains $ProgramName  -and
    $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) -or
    $PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -or
    $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    ) {
        if ($UsePowerShellGet -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine) -or 
        $PackageManagementInstalledPrograms.Name -contains $ProgramName -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName
        ) {
            $InstallPackageSplatParams = @{
                Name            = $ProgramName
                Force           = $True
                ErrorAction     = "SilentlyContinue"
                ErrorVariable   = "InstallError"
                WarningAction   = "SilentlyContinue"
            }
            if ($PreRelease) {
                $LatestVersion = $(Find-Package $ProgramName -AllVersions)[-1].Version
                $InstallPackageSplatParams.Add("MinimumVersion",$LatestVersion)
            }
            # NOTE: The PackageManagement install of $ProgramName is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package @InstallPackageSplatParams
            if ($InstallError.Count -gt 0) {
                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                Write-Warning "There was a problem installing $ProgramName via PackageManagement/PowerShellGet!"
                
                if ($UsePowerShellGet) {
                    Write-Error "One or more errors occurred during the installation of $ProgramName via the the PackageManagement/PowerShellGet Modules failed! Installation has been rolled back! Halting!"
                    Write-Host "Errors for the Install-Package cmdlet are as follows:"
                    Write-Error $($InstallError | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Trying install via Chocolatey CmdLine..."
                    $PMInstall = $False
                }
            }
            else {
                $PMInstall = $True

                # Since Installation via PackageManagement/PowerShellGet was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = $($(Refresh-ChocolateyEnv -ErrorAction SilentlyContinue) -split ";" | foreach {
                    if (-not [System.String]::IsNullOrWhiteSpace($_) -and $(Test-Path $_)) {$_}
                }) -join ";"
            }
        }

        if (!$PMInstall -or $UseChocolateyCmdLine -or
        $ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName
        ) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr

                # The first time we attempt to Refresh-ChocolateyEnv, Chocolatey CmdLine and/or the
                # Chocolatey Package Provider legitimately might not be installed,
                # so if the Refresh-ChocolateyEnv function throws that error, we can ignore it
                if ($RCEErr.Count -gt 0 -and
                $global:FunctionResult -eq "1" -and
                ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            # Make sure Chocolatey CmdLine is installed...if not, install it
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $global:FunctionResult = "0"
                    $null = Install-ChocolateyCmdLine -NoUpdatePackageManagement -ErrorAction SilentlyContinue -ErrorVariable ICCErr
                    if ($ICCErr -and $global:FunctionResult -eq "1") {throw "The Install-ChocolateyCmdLine function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Install-ChocolateyCmdline function are as follows:"
                    Write-Error $($ICCErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }

            try {
                # TODO: Figure out how to handle errors from choco.exe. Some we can ignore, others
                # we shouldn't. But I'm not sure what all of the possibilities are so I can't
                # control for them...
                if ($PreRelease) {
                    $null = cup $ProgramName --pre -y
                }
                else {
                    $null = cup $ProgramName -y
                }
                $ChocoInstall = $true

                # Since Installation via the Chocolatey CmdLine was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue
            }
            catch {
                Write-Error "There was a problem installing $ProgramName using the Chocolatey cmdline! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
            ## BEGIN Try to Find Main Executable Post Install ##

            # Now the parent directory of $ProgramName's main executable should be part of the SYSTEM Path
            # (and therefore part of $env:Path). If not, try to find it in Chocolatey directories...
            if ($(Get-Command $FinalCommandName -ErrorAction SilentlyContinue).CommandType -eq "Alias") {
                while (Test-Path Alias:\$FinalCommandName) {
                    Remove-Item Alias:\$FinalCommandName
                }
            }

            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {throw "The Refresh-ChocolateyEnv function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
            
            # If we still can't find the main executable...
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) {
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue
                
                if ($ExpectedInstallLocation) {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                }
                else {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                }
            }

            # Determine if there's an exact match for the $FinalCommandName
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                if ($ExePath.Count -ge 1) {
                    if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                        $FoundExactCommandMatch = $True
                    }
                }
            }

            # If we STILL can't find the main executable...
            if ($(![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) -or 
            $(!$FoundExactCommandMatch -and $PSBoundParameters['CommandName']) -or 
            $($ResolveCommandPath -and !$FoundExactCommandMatch) -or $ForceChocoInstallScript) {
                # If, at this point we don't have $ExePath, if we did a $ChocoInstall, then we have to give up...
                # ...but if we did a $PMInstall, then it's possible that PackageManagement/PowerShellGet just
                # didn't run the chocolateyInstall.ps1 script that sometimes comes bundled with Packages from the
                # Chocolatey Package Provider/Repo. So try running that...
                if ($ChocoInstall) {
                    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                        Write-Warning "Unable to find main executable for $ProgramName!"
                        $MainExeSearchFail = $True
                    }
                }
                if ($PMInstall -or $ForceChocoInstallScript) {
                    [System.Collections.ArrayList]$PossibleChocolateyInstallScripts = @()
                    
                    if (Test-Path "C:\Chocolatey") {
                        $ChocoScriptsA = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsA) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }
                    if (Test-Path "C:\ProgramData\chocolatey") {
                        $ChocoScriptsB = Get-ChildItem -Path "C:\ProgramData\chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsB) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }

                    [System.Collections.ArrayList][Array]$ChocolateyInstallScriptSearch = $PossibleChocolateyInstallScripts.FullName | Where-Object {$_ -match ".*?$ProgramName.*?chocolateyinstall.ps1$"}
                    if ($ChocolateyInstallScriptSearch.Count -eq 0) {
                        Write-Warning "Unable to find main the Chocolatey Install Script for $ProgramName PowerShellGet install!"
                        $MainExeSearchFail = $True
                    }
                    if ($ChocolateyInstallScriptSearch.Count -eq 1) {
                        $ChocolateyInstallScript = $ChocolateyInstallScriptSearch[0]
                    }
                    if ($ChocolateyInstallScriptSearch.Count -gt 1) {
                        $ChocolateyInstallScript = $($ChocolateyInstallScriptSearch | Sort-Object LastWriteTime)[-1]
                    }
                    
                    if ($ChocolateyInstallScript) {
                        try {
                            Write-Host "Trying the Chocolatey Install script from $ChocolateyInstallScript..." -ForegroundColor Yellow
                            & $ChocolateyInstallScript

                            # Now that the $ChocolateyInstallScript ran, search for the main executable again
                            Synchronize-SystemPathEnvPath
                            $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue

                            if ($ExpectedInstallLocation) {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                            }
                            else {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                            }

                            # If we STILL don't have $ExePath, then we have to give up...
                            if (!$ExePath -or $ExePath.Count -eq 0) {
                                Write-Warning "Unable to find main executable for $ProgramName!"
                                $MainExeSearchFail = $True
                            }
                        }
                        catch {
                            Write-Error $_
                            Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                            # If PackageManagement/PowerShellGet is ERRONEOUSLY reporting that the program was installed
                            # use the Uninstall-Package cmdlet to wipe it out. This scenario happens when PackageManagement/
                            # PackageManagement/PowerShellGet gets a Package from the Chocolatey Package Provider/Repo but
                            # fails to run the chocolateyInstall.ps1 script for some reason.
                            if ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
                                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                            }

                            # Now we need to try the Chocolatey CmdLine. Easiest way to do this at this point is to just
                            # invoke the function again with the same parameters, but specify -UseChocolateyCmdLine
                            $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
                            $InstallProgramSplatParams = @{}
                            foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
                                $key = $kvpair.Key
                                $value = $BoundParametersDictionary[$key]
                                if ($key -notmatch "UsePowerShellGet|ForceChocoInstallScript" -and $InstallProgramSplatParams.Keys -notcontains $key) {
                                    $InstallProgramSplatParams.Add($key,$value)
                                }
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "UseChocolateyCmdLine") {
                                $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "NoUpdatePackageManagement") {
                                $InstallProgramSplatParams.Add("NoUpdatePackageManagement",$True)
                            }
                            Install-Program @InstallProgramSplatParams

                            return
                        }
                    }
                }
            }

            ## END Try to Find Main Executable Post Install ##
        }
    }
    else {
        if ($ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName) {
            Write-Warning "$ProgramName is already installed via the Chocolatey CmdLine!"
            $AlreadyInstalled = $True
        }
        elseif ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
            Write-Warning "$ProgramName is already installed via PackageManagement/PowerShellGet!"
            $AlreadyInstalled = $True
        }
    }

    # If we weren't able to find the main executable (or any potential main executables) for
    # $ProgramName, offer the option to scan the whole C:\ drive (with some obvious exceptions)
    if ($MainExeSearchFail -and $($ResolveCommandPath -or $PSBoundParameters['CommandName']) -and
    ![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
        if (!$ScanCDriveForMainExeIfNecessary -and $ResolveCommandPath -and !$PSBoundParameters['CommandName']) {
            $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            while ($ScanCDriveChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$ScanDriveChoice is not a valid input. Please enter 'Yes' or 'No'"
                $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            }
        }

        if ($ScanCDriveChoice -match "Yes|yes|Y|y" -or $ScanCDriveForMainExeIfNecessary) {
            $DirectoriesToSearchRecursively = $(Get-ChildItem -Path "C:\" -Directory | Where-Object {$_.Name -notmatch "Windows|PerfLogs|Microsoft"}).FullName
            [System.Collections.ArrayList]$ExePath = @()
            foreach ($dir in $DirectoriesToSearchRecursively) {
                $FoundFiles = $(Get-ChildItem -Path $dir -Recurse -File).FullName
                foreach ($FilePath in $FoundFiles) {
                    if ($FilePath -match "(.*?)$FinalCommandName([^\\]+)") {
                        $null = $ExePath.Add($FilePath)
                    }
                }
            }
        }
    }

    if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
        # Finalize $env:Path
        if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
            $PathToAdd = $($ExePath -match "\\$FinalCommandName.exe$") | Split-Path -Parent
            if ($($env:Path -split ";") -notcontains $PathToAdd) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path" + $PathToAdd + ";"
                }
                else {
                    $env:Path = "$env:Path" + ";" + $PathToAdd
                }
            }
        }
        $FinalEnvPathArray = $env:Path -split ";" | foreach {if(-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $FinalEnvPathString = $($FinalEnvPathArray | foreach {if (Test-Path $_) {$_}}) -join ";"
        $env:Path = $FinalEnvPathString

        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
            # Try to determine Main Executable
            if (!$ExePath -or $ExePath.Count -eq 0) {
                $FinalExeLocation = "NotFound"
            }
            elseif ($ExePath.Count -eq 1) {
                $UpdatedFinalCommandName = $ExePath | Split-Path -Leaf

                try {
                    $FinalExeLocation = $(Get-Command $UpdatedFinalCommandName -ErrorAction SilentlyContinue).Source
                }
                catch {
                    $FinalExeLocation = $ExePath
                }
            }
            elseif ($ExePath.Count -gt 1) {
                if (![bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                    Write-Warning "No exact match for main executable $FinalCommandName.exe was found. However, other executables associated with $ProgramName were found."
                }
                $FinalExeLocation = $ExePath
            }
        }
        else {
            $FinalExeLocation = $(Get-Command $FinalCommandName).Source
        }
    }

    if ($ChocoInstall) {
        $InstallManager = "choco.exe"
        $InstallCheck = $(clist --local-only $ProgramName)[1]
    }
    if ($PMInstall -or [bool]$(Get-Package $ProgramName -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
        $InstallManager = "PowerShellGet"
        $InstallCheck = Get-Package $ProgramName -ErrorAction SilentlyContinue
    }

    if ($AlreadyInstalled) {
        $InstallAction = "AlreadyInstalled"
    }
    elseif ($PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -or
    $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    ) {
        $InstallAction = "Updated"
    }
    else {
        $InstallAction = "FreshInstall"
    }

    $env:Path = Refresh-ChocolateyEnv

    [pscustomobject]@{
        InstallManager      = $InstallManager
        InstallAction       = $InstallAction
        InstallCheck        = $InstallCheck
        MainExecutable      = $FinalExeLocation
        OriginalSystemPath  = $OriginalSystemPath
        CurrentSystemPath   = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        OriginalEnvPath     = $OriginalEnvPath
        CurrentEnvPath      = $env:Path
    }

    ##### END Main Body #####
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

    $uninstallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    $RegPaths = @(
        "HKLM:$uninstallWow6432Path",
        "HKLM:$uninstallPath",
        "HKCU:$uninstallWow6432Path",
        "HKCU:$uninstallPath"
    )
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    # Get a list of Windows Computers from AD
    if ($AllADWindowsComputers) {
        $ComputersArray = $(Get-ADComputer -Filter * -Property * | Where-Object {$_.OperatingSystem -like "*Windows*"}).Name
    }
    else {
        $ComputersArray = $env:COMPUTERNAME
    }

    foreach ($computer in $ComputersArray) {
        if ($computer -eq $env:COMPUTERNAME -or $computer.Split("\.")[0] -eq $env:COMPUTERNAME) {
            try {
                $InstalledPrograms = foreach ($regpath in $RegPaths) {if (Test-Path $regpath) {Get-ItemProperty $regpath}}
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
                        if (Test-Path $regpath) {
                            Get-ItemProperty $regpath
                        }
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

function Set-WindowStyle {
    <#
    .LINK
    https://gist.github.com/jakeballard/11240204
    #>

    [CmdletBinding(DefaultParameterSetName = 'InputObject')]
    param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelinebyPropertyName = $True)]
        [Object[]] $InputObject,
        [Parameter(Position = 1)]
        [ValidateSet('FORCEMINIMIZE', 'HIDE', 'MAXIMIZE', 'MINIMIZE', 'RESTORE', 'SHOW', 'SHOWDEFAULT', 'SHOWMAXIMIZED', 'SHOWMINIMIZED', 'SHOWMINNOACTIVE', 'SHOWNA', 'SHOWNOACTIVATE', 'SHOWNORMAL')]
        [string] $Style = 'SHOW'
    )

    BEGIN {
        $WindowStates = @{
            'FORCEMINIMIZE'   = 11
            'HIDE'            = 0
            'MAXIMIZE'        = 3
            'MINIMIZE'        = 6
            'RESTORE'         = 9
            'SHOW'            = 5
            'SHOWDEFAULT'     = 10
            'SHOWMAXIMIZED'   = 3
            'SHOWMINIMIZED'   = 2
            'SHOWMINNOACTIVE' = 7
            'SHOWNA'          = 8
            'SHOWNOACTIVATE'  = 4
            'SHOWNORMAL'      = 1
        }

$Win32ShowWindowAsync = Add-Type -MemberDefinition @'
[DllImport("user32.dll")] 
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
'@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
    
    }

    PROCESS {
        foreach ($process in $InputObject) {
            $Win32ShowWindowAsync::ShowWindowAsync($process.MainWindowHandle, $WindowStates[$Style]) | Out-Null
            Write-Verbose ("Set Window Style '{1} on '{0}'" -f $MainWindowHandle, $Style)
        }
    }
}

<#
    .Synopsis
        Provides access to Windows Credential Manager basic functionality for client scripts. Allows the user
        to add, delete, and show credentials within the Windows Credential Manager.

        Refactored From: https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

        ****************** IMPORTANT ******************
        *
        * If you use this script from the PS console, you 
        * should ALWAYS pass the Target, User and Password
        * parameters using single quotes:
        * 
        *  .\CredMan.ps1 -AddCred -Target 'http://server' -User 'JoeSchmuckatelli' -Pass 'P@55w0rd!'
        * 
        * to prevent PS misinterpreting special characters 
        * you might use as PS reserved characters
        * 
        ****************** IMPORTANT ******************

    .Description
        See .SYNOPSIS

    .NOTES
        Original Author: Jim Harrison (jim@isatools.org)
        Date  : 2012/05/20
        Vers  : 1.5

    .PARAMETER AddCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it in conjunction with -Target, -User, and -Pass
        parameters to add a new credential or update existing credentials.

    .PARAMETER Comment
        This parameter is OPTIONAL.

        This parameter takes a string that represents additional information that you wish
        to place in the credentials comment field. Use with the -AddCred switch.

    .PARAMETER CredPersist
        This parameter is OPTIONAL, however, it has a default value of "ENTERPRISE".

        This parameter takes a string. Valid values are:
        "SESSION", "LOCAL_MACHINE", "ENTERPRISE"
        
        ENTERPRISE persistance means that the credentials will survive logoff and reboot.
        
    .PARAMETER CredType
        This parameter is OPTIONAL, however, it has a default value of "GENERIC".

        This parameter takes a string. Valid values are:
        "GENERIC", "DOMAIN_PASSWORD", "DOMAIN_CERTIFICATE",
        "DOMAIN_VISIBLE_PASSWORD", "GENERIC_CERTIFICATE", "DOMAIN_EXTENDED",
        "MAXIMUM", "MAXIMUM_EX"
        
        ****************** IMPORTANT ******************
        *
        * I STRONGLY recommend that you become familiar 
        * with http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        * before you create new credentials with -CredType other than "GENERIC"
        * 
        ****************** IMPORTANT ******************

    .PARAMETER DelCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove existing credentials. If more than one
        credential sets have the same -Target, you must use this switch in conjunction with the
        -CredType parameter.

    .PARAMETER GetCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to retrieve an existing credential. The
        -CredType parameter may be required to access the correct credential if more set
        of credentials have the same -Target.

    .PARAMETER Pass
        This parameter is OPTIONAL, however, it is MANDATORY if the -AddCred switch is used.

        This parameter takes a string that represents tha secret/password that you would like to store.

    .PARAMETER RunTests
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will run built-in Win32 CredMan
        functionality tests.

    .PARAMETER ShoCred
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will retrieve all credentials stored for
        the interactive user.

    .PARAMETER Target
        This parameter is OPTIONAL, however, it is MANDATORY unless the -ShoCred switch is used.

        This parameter takes a string that specifies the authentication target for the specified credentials
        If not specified, the value provided to the -User parameter is used.

    .PARAMETER User
        This parameter is OPTIONAL.

        This parameter takes a string that represents the credential's UserName.
        

    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://blogs.msdn.com/b/peerchan/archive/2005/11/01/487834.aspx

    .EXAMPLE
        # Stores the credential for 'UserName' with a password of 'P@55w0rd!' for authentication against 'http://aserver' and adds a comment of 'cuziwanna'
        Manage-WinCreds -AddCred -Target 'http://aserver' -User 'UserName' -Password 'P@55w0rd!' -Comment 'cuziwanna'

    .EXAMPLE
        # Removes the credential used for the target 'http://aserver' as credentials type 'DOMAIN_PASSWORD'
        Manage-WinCreds -DelCred -Target 'http://aserver' -CredType 'DOMAIN_PASSWORD'

    .EXAMPLE
        # Retreives the credential used for the target 'http://aserver'
        Manage-WinCreds -GetCred -Target 'http://aserver'

    .EXAMPLE
        # Retrieves a summary list of all credentials stored for the interactive user
        Manage-WinCreds -ShoCred

    .EXAMPLE
        # Retrieves a detailed list of all credentials stored for the interactive user
        Manage-WinCreds -ShoCred -All

#>
function Manage-WinCreds {
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
     try {$Error.RemoveAt($Error.Count-1)} catch {Write-Verbose "No past errors yet..."}
    
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

                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Alias" -Value "$($Cred.TargetAlias)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "AttribCnt" -Value "$($Cred.AttributeCount)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Attribs" -Value "$($Cred.Attributes)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Flags" -Value "$($Cred.Flags)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "PwdSize" -Value "$($Cred.CredentialBlobSize)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Storage" -Value "$($Cred.Persist)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Type" -Value "$($Cred.Type)"

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


function Install-GitCmdLine {
    [CmdletBinding()]
    Param ()

    Install-Program -ProgramName git -CommandName git
}

function Install-GitDesktop {
    [CmdletBinding()]
    Param ()

    #Install-Program -ProgramName github-desktop
    Install-Program -ProgramName github-desktop -ResolveCommandPath:$False -UseChocolateyCmdLine
}

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

        Setup-GitCmdLine @GitAuthParams

    .EXAMPLE
        $GitAuthParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@genericemailprovider.com"
            AuthMethod = "ssh"
            NewSSHKeyName "gitauth_rsa"
        }

        Setup-GitCmdLine @GitAuthParams

    .EXAMPLE
        $GitAuthParams = @{
            GitHubUserName = "pldmgg"
            GitHubEmail = "pldmgg@genericemailprovider.com"
            AuthMethod = "ssh"
            ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa" 
        }
        
        Setup-GitCmdLine @GitAuthParams

#>
function Configure-GitCmdLine {
    [CmdletBinding(DefaultParameterSetname='AuthSetup')]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = $(Read-Host -Prompt "Please enter your GitHub Username"),

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail = $(Read-Host -Prompt "Please the primary GitHub email address associated with $GitHubUserName"),

        [Parameter(Mandatory=$False)]
        [ValidateSet("https","ssh")]
        [string]$AuthMethod = $(Read-Host -Prompt "Please select the Authentication Method you would like to use. [https/ssh]"),

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        [string]$ExistingSSHPrivateKeyPath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        [string]$NewSSHKeyName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        $NewSSHKeyPwd,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='SSH Auth'
        )]
        [switch]$DownloadAndSetupDependencies,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='HTTPS Auth'
        )]
        [securestring]$PersonalAccessToken,

        [Parameter(Mandatory=$False)]
        [switch]$AllowAwaitModuleInstall
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep ######

    $CurrentUser = $($([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name -split "\\")[-1]

    # Make sure git cmdline is installed
    if (![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        $ExpectedGitPath = "C:\Program Files\Git\cmd"
        if ($($env:Path -split ";") -notcontains [regex]::Escape($ExpectedGitPath)) {
            if (Test-Path $ExpectedGitPath) {
                $env:Path = $ExpectedGitPath + ";" + $env:Path
            }
        }
    }
    if (![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find git.exe! Try installing with the 'Install-GitCmdLine' function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure global config for UserName and Email Address is configured
    git config --global user.name "$GitHubUserName"
    git config --global user.email "$GitHubEmail"

    if ($ExistingSSHPrivateKeyPath -or $NewSSHKeyName -or $NewSSHKeyPwd -or $DownloadAndSetupDependencies) {
        $AuthMethod = "ssh"
    }
    if ($PersonalAccessToken) {
        $AuthMethod = "https"
    }
    if (!$AuthMethod) {
        $AuthMethod = "ssh"
    }

    if ($AuthMethod -eq "https" -and
    $($DownloadAndSetupDependencies -or $ExistingSSHPrivateKeyPath -or $NewSSHKeyName -or $NewSSHKeyPwd -or $AllowAwaitModuleInstall)
    ) {
        $ErrMsg = "The parameters -DownloadAndSetupDependencies, -ExistingSSHPrivateKeyPath, -NewSSHKeyName, " +
        "-NewSSHKeyPwd, and/or -AllowAwaitModuleInstall should only be used when -AuthMethod is `"ssh`"! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    # NOTE: We do NOT need to force use of -ExistingSSHPrivateKeyPath or -NewSSHKeyName when -AuthMethod is "ssh"
    # because Setup-GitCmdLine function can handle things if neither are provided
    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))

        git config --global credential.helper wincred

        # Alternate Stored Credentials Format
        <#
        $ManageStoredCredsParams = @{
            Target  = "git:https://$PersonalAccessToken@github.com"
            User    = $PersonalAccessToken
            Pass    = 'x-oauth-basic'
            Comment = "Saved By Manage-WinCreds.ps1"
        }
        #>
        $ManageStoredCredsParams = @{
            Target  = "git:https://$GitHubUserName@github.com"
            User    = $GitHubUserName
            Pass    = $PersonalAccessTokenPT
            Comment = "Saved By Manage-WinCreds.ps1"
        }
        $null = Manage-WinCreds -AddCred @ManageStoredCredsParams

        # Test https OAuth2 authentication
        # More info here: https://channel9.msdn.com/Blogs/trevor-powershell/Automating-the-GitHub-REST-API-Using-PowerShell
        $GitHubAuthSuccess = Test-GitAuthentication -GitHubUserName $GitHubUserName -AuthMethod $AuthMethod -PersonalAccessToken $PersonalAccessToken
        if ($GitHubAuthSuccess) {
            $env:GitCmdLineConfigured = "True"
        }
    }
    if ($AuthMethod -eq "ssh") {
        if ($ExistingSSHPrivateKeyPath) {
            try {
                $ExistingSSHPrivateKeyPath = $(Resolve-Path $ExistingSSHPrivateKeyPath -ErrorAction Stop).Path
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if (Test-Path "$HOME\.ssh\github_rsa") {
                $ExistingSSHPrivateKeyPath = "$HOME\.ssh\github_rsa"
            }
            else {
                if ($NewSSHKeyPwd) {
                    if ($NewSSHKeyPwd.GetType().FullName -eq "System.Security.SecureString") {
                        # Convert SecureString to PlainText
                        $NewSSHKeyPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewSSHKeyPwd))
                    }
                }
                if (!$NewSSHKeyName) {
                    $NewSSHKeyName = "github_rsa"
                }
                $SSHKeyGenPath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "*ssh-keygen.exe").FullName
                $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -q -N `"$NewSSHKeyPwd`" -C `"GitAuthFor$CurrentUser`""
                $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -q -C `"GitAuthFor$CurrentUser`""

                if (!$(Test-Path "$HOME\.ssh")) {
                    New-Item -Type Directory -Path "$HOME\.ssh"
                }
            
                # Create new public/private keypair
                if ($NewSSHKeyPwd) {
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $($SSHKeyGenPath | Split-Path -Parent)
                    $ProcessInfo.FileName = $SSHKeyGenPath
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = $SSHKeyGenArgumentsString
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr
            
                    if ($AllOutput -match "fail|error") {
                        Write-Error $AllOutput
                        Write-Error "The 'ssh-keygen command failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    if (!$AllowAwaitModuleInstall -and $(Get-Module -ListAvailable).Name -notcontains "Await") {
                        Write-Warning "This function needs to install the PowerShell Await Module in order to generate a private key with a null password."
                        $ProceedChoice = Read-Host -Prompt "Would you like to proceed? [Yes\No]"
                        while ($ProceedChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                            Write-Host "$ProceedChoice is NOT a valid choice! Please enter 'Yes' or 'No'"
                            $ProceedChoice = Read-Host -Prompt "Would you like to proceed? [Yes\No]"
                        }
            
                        if ($ProceedChoice -match "No|no|N|n") {
                            Write-Error "User chose not to proceed! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    if ($AllowAwaitModuleInstall -or $ProceedChoice -match "Yes|yes|Y|y") {
                        # Need PowerShell Await Module (Windows version of Linux Expect) for ssh-keygen with null password
                        if ($(Get-Module -ListAvailable).Name -notcontains "Await") {
                            # Install-Module "Await" -Scope CurrentUser
                            # Clone PoshAwait repo to .zip
                            Invoke-WebRequest -Uri "https://github.com/pldmgg/PoshAwait/archive/master.zip" -OutFile "$HOME\PoshAwait.zip"
                            $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                            $null = [IO.Directory]::CreateDirectory($tempDirectory)
                            Unzip-File -PathToZip "$HOME\PoshAwait.zip" -TargetDir "$tempDirectory"
                            if (!$(Test-Path "$HOME\Documents\WindowsPowerShell\Modules\Await")) {
                                $null = New-Item -Type Directory "$HOME\Documents\WindowsPowerShell\Modules\Await"
                            }
                            Copy-Item -Recurse -Path "$tempDirectory\PoshAwait-master\*" -Destination "$HOME\Documents\WindowsPowerShell\Modules\Await"
                            Remove-Item -Recurse -Path $tempDirectory -Force
            
                            if ($($env:PSModulePath -split ";") -notcontains "$HOME\Documents\WindowsPowerShell\Modules") {
                                $env:PSModulePath = "$HOME\Documents\WindowsPowerShell\Modules" + ";" + $env:PSModulePath
                            }
                        }
                    }
            
                    # Make private key password $null
                    Import-Module Await
                    if ($(Get-Module).Name -notcontains "Await") {
                        Write-Error "Unable to load the Await Module! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
            
                    Start-AwaitSession
                    Start-Sleep -Seconds 1
                    Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
                    $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
                    Start-Sleep -Seconds 1
                    Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$($SSHKeyGenPath | Split-Path -Parent)'"
                    Start-Sleep -Seconds 1
                    #Send-AwaitCommand "Invoke-Expression `"& '$SSHKeyGenPath' $SSHKeyGenArgumentsNoPwdString`""
                    Send-AwaitCommand ".\ssh-keygen.exe $SSHKeyGenArgumentsNoPwdString"
                    Start-Sleep -Seconds 2
                    # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
                    Send-AwaitCommand ""
                    Start-Sleep -Seconds 2
                    # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
                    Send-AwaitCommand ""
                    Start-Sleep -Seconds 1
                    $SSHKeyGenConsoleOutput = Receive-AwaitResponse
            
                    # If Stop-AwaitSession errors for any reason, it doesn't return control, so we need to handle in try/catch block
                    try {
                        Stop-AwaitSession
                    }
                    catch {
                        if ($PSAwaitProcess.Id -eq $PID) {
                            Write-Error "The PSAwaitSession never spawned! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Stop-Process -Id $PSAwaitProcess.Id
                            while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                                Write-Host "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                                Start-Sleep -Seconds 1
                            }
                        }
                    }
                }

                if (!$(Test-Path "$HOME\.ssh\$NewSSHKeyName")) {
                    Write-Error "ssh-keygen did not successfully create the public/private keypair! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    $ExistingSSHPrivateKeyPath = "$HOME\.ssh\$NewSSHKeyName"
                }
            }
        }

        $null = git config core.sshCommand "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath)) -F /dev/null" 2>&1
        $env:GIT_SSH_COMMAND = "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath))"

        # Check To Make Sure Online GitHub Account is aware of Existing Public Key
        $GitHubAuthSuccess = Test-GitAuthentication -GitHubUserName $GitHubUserName -AuthMethod $AuthMethod -ExistingSSHPrivateKeyPath $ExistingSSHPrivateKeyPath
        if (!$GitHubAuthSuccess) {
            Write-Host ""
            Write-Host "GitHub Authentication was successfully configured on the client machine, however, we were not able to successfully authenticate to GitHub using '$ExistingSSHPrivateKeyPath'"
            Write-Host "Please add '$HOME\.ssh\$ExistingSSHPrivateKeyPath.pub' to your GitHub Account via Web Browser by:"
            Write-Host "    1) Navigating to Settings"
            Write-Host "    2) In the user settings sidebar, click SSH and GPG keys."
            Write-Host "    3) Add SSH Key"
            Write-Host "    4) Enter a descriptive Title like: SSH Key for Paul-MacBookPro auth"
            Write-Host "    5) Paste your key into the Key field."
            Write-Host "    6) Click Add SSH key."
        }
        else {
            $env:GitCmdLineConfigured = "True"
        }
    }

    ##### END Main Body #####
}

function Test-GitAuthentication {
    [CmdletBinding(DefaultParameterSetName='ssh')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$GitHubUserName,

        [Parameter(Mandatory=$True)]
        [ValidateSet("https","ssh")]
        [string]$AuthMethod,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='ssh'
        )]
        [string]$ExistingSSHPrivateKeyPath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='http'
        )]
        [securestring]$PersonalAccessToken
    )

    if ($AuthMethod -eq "ssh") {
        if (!$ExistingSSHPrivateKeyPath) {
            if (!$(Test-Path "$HOME\.ssh\github_rsa")) {
                $ExistingSSHPrivateKeyPath = Read-Host -Prompt "Please enter the full path to your github_rsa ssh private key."
            }
        }
        if (!$(Test-Path $ExistingSSHPrivateKeyPath)) {
            Write-Error "Unable to find path to existing Private Key '$ExistingSSHPrivateKeyPath'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $SSHKeyGenPath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "*ssh-keygen.exe").FullName
        if (!$SSHKeyGenPath) {
            Write-Error "Unable to fing git CmdLine instance of ssh-keygen.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $SSHExePath = $(Get-ChildItem "C:\Program Files\Git" -Recurse -Filter "ssh.exe").FullName
        if (!$SSHExePath) {
            Write-Error "Unable to fing git CmdLine instance of ssh.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Check To Make Sure Online GitHub Account is aware of Existing Public Key
        $PubSSHKeys = Invoke-Restmethod -Uri "https://api.github.com/users/$GitHubUserName/keys"
        $tempfileLocations = @()
        foreach ($PubKeyObject in $PubSSHKeys) {
            $tmpFile = [IO.Path]::GetTempFileName()
            $PubKeyObject.key | Out-File $tmpFile -Encoding ASCII

            $tempfileLocations +=, $tmpFile
        }
        $SSHPubKeyFingerPrintsFromGitHub = foreach ($TempPubSSHKeyFile in $tempfileLocations) {
            $PubKeyFingerPrintPrep = & "$SSHKeyGenPath" -E md5 -lf "$TempPubSSHKeyFile"
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
            $LocalPubKeyFingerPrintPrep = & "$SSHKeyGenPath" -E md5 -lf "$ExistingSSHPubKeyPath"
            $LocalPubKeyFingerPrint = $($LocalPubKeyFingerPrintPrep -split " ")[1] -replace "MD5:",""
            if ($fingerprint -eq $LocalPubKeyFingerPrint) {
                $GitHubOnlineIsAware +=, $fingerprint
            }
        }

        if ($GitHubOnlineIsAware.Count -gt 0) {
            Write-Host "GitHub Online Account is aware of existing public key $ExistingSSHPubKeyPath. Testing the connection..." -ForegroundColor Green

            $null = git config core.sshCommand "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath)) -F /dev/null" 2>&1
            $env:GIT_SSH_COMMAND = "ssh -i $([regex]::Escape($ExistingSSHPrivateKeyPath))"

            # Test the connection
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = $SSHExePath
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "-o `"StrictHostKeyChecking=no`" -i `"$ExistingSSHPrivateKeyPath`" -T git@github.com"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match $GitHubUserName) {
                Write-Host "GitHub Authentication via SSH for $GitHubUserName using '$ExistingSSHPrivateKeyPath' was successful." -ForegroundColor Green
                $True
            }
            else {
                Write-Warning "GitHub Authentication for $GitHubUserName using SSH was NOT successful. Please check your connection and/or keys."
                $False
            }
        }
    }
    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
        $Headers = @{
            Authorization = "token $PersonalAccessTokenPT"
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos").Name
        # Rest API Alternate Method
        <#
        $Token = "$GitHubUserName`:$PersonalAccessTokenPT"
        $Base64Token = [System.Convert]::ToBase64String([char[]]$Token)
        $Headers = @{
            Authorization = "Basic {0}" -f $Base64Token
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessTokenPT").Name
        #>

        if ($PublicAndPrivateRepos -ne $null) {
            Write-Host "GitHub Authentication via https for $GitHubUserName was successful!" -ForegroundColor Green
            $True
        }
        else {
            Write-Warning "GitHub Authentication via https for $GitHubUserName was NOT successful. Please check your Personal Authentication Token."
            $False
        }
    }
}

function New-GitRepo {
    [CmdletBinding(DefaultParameterSetName="https")]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$NewRepoLocalPath = $($(Get-Location).Path),

        [Parameter(Mandatory=$True)]
        [string]$NewRepoDescription,

        [Parameter(Mandatory=$False)]
        [string]$GitIgnoreContent,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Public","Private")]
        [string]$PublicOrPrivate,

        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = "pldmgg",

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail = "pldmgg@mykolab.com",

        [Parameter(Mandatory=$False)]
        [ValidateSet("https")]
        [string]$AuthMethod = "https",

        [Parameter(
            Mandatory=$False,
            ParameterSetName='ssh'
        )]
        [string]$ExistingSSHPrivateKeyPath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='http'
        )]
        [securestring]$PersonalAccessToken
    )

    if (!$GitHubUserName) {
        $GitHubUserName = Read-Host -Prompt "Please enter your GitHub Username"
    }
    if (!$AuthMethod) {
        $AuthMethod = Read-Host -Prompt "Please select the Authentication Method you would like to use. [https/ssh]"
    }

    if ($AuthMethod -eq "https") {
        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter the GitHub Personal Access Token you would like to use for https authentication." -AsSecureString
        }

        # Convert SecureString to PlainText
        $PersonalAccessTokenPT = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
    }
    if ($AuthMethod -eq "ssh") {
        if (!$ExistingSSHPrivateKeyPath) {
            if (!$(Test-Path "$HOME\.ssh\github_rsa")) {
                $ExistingSSHPrivateKeyPath = Read-Host -Prompt "Please enter the full path to your github_rsa ssh private key."
            }
        }
        if (!$(Test-Path $ExistingSSHPrivateKeyPath)) {
            Write-Error "Unable to find path to existing Private Key '$ExistingSSHPrivateKeyPath'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($env:GitCmdLineConfigured -ne "True" -or ![bool]$(Get-Command git -ErrorAction SilentlyContinue)) {
        $ConfigGitCmdLineSplatParams = @{
            GitHubUserName      = $GitHubUserName
            GitHubEmail         = $GitHubEmail
            AuthMethod          = $AuthMethod
        }
        if ($AuthMethod -eq "https") {
            $ConfigGitCmdLineSplatParams.Add("PersonalAccessToken",$PersonalAccessToken)
        }
        if ($AuthMethod -eq "ssh") {
            $ConfigGitCmdLineSplatParams.Add("ExistingSSHPrivateKeyPath",$ExistingSSHPrivateKeyPath)
        }

        Configure-GitCmdLine @ConfigGitCmdLineSplatParams
    }

    $NewRepoName = $NewRepoLocalPath | Split-Path -Leaf

    if ($AuthMethod -eq "https") {
        $Headers = @{
            Authorization = "token $PersonalAccessTokenPT"
        }
        $PublicAndPrivateRepos = $(Invoke-RestMethod -Headers $Headers -Uri "https://api.github.com/user/repos").Name
        
        # Make Sure $NewRepoName is Unique
        $FinalNewRepoName = New-UniqueString -ArrayOfStrings $PublicAndPrivateRepos -PossibleNewUniqueString $NewRepoName
    }
    if ($AuthMethod -eq "ssh") {
        #Placeholder
    }

    if ($FinalNewRepoName -ne $NewRepoName) {
        Write-Warning "A repo with the Name '$NewRepoName' already exists! Final Repo Name will be '$FinalNewRepoName'"
        $ContinuePrompt = Read-Host -Prompt "Are you sure you want to create a new Git Repos with the name '$FinalNewRepoName'? [Yes\No]"
        while ($ContinuePrompt -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "'$ContinuePrompt' is not a valid option. Please enter 'Yes' or 'No'" -ForegroundColor Yellow
            $ContinuePrompt = Read-Host -Prompt "Are you sure you want to create a new Git Repos with the name '$FinalNewRepoName'? [Yes\No]"
        }

        if ($ContinuePrompt -notmatch "Yes|yes|Y|y") {
            Write-Error "User chose not to proceed. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FinalNewRepoLocalPath = "$($NewRepoLocalPath | Split-Path -Parent)\$FinalNewRepoName"
    }
    else {
        $FinalNewRepoLocalPath = $NewRepoLocalPath
    }

    if (!$(Test-Path $FinalNewRepoLocalPath)) {
        $null = New-Item -Type Directory -Path $FinalNewRepoLocalPath -Force
    }

    Push-Location $FinalNewRepoLocalPath

    $ReadMeDefaultContent = @"
[![Build status](https://ci.appveyor.com/api/projects/status/github/$GitHubUserName/$FinalNewRepoName?branch=master&svg=true)](https://ci.appveyor.com/project/$GitHubUserName/sudo/branch/master)


# $FinalNewRepoName
<Synopsis>

## Getting Started

``````powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the $FinalNewRepoName folder to a module path (e.g. `$env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module $FinalNewRepoName

# Import the module.
    Import-Module $FinalNewRepoName    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module $FinalNewRepoName

# Get help
    Get-Help <$FinalNewRepoName Function> -Full
    Get-Help about_$FinalNewRepoName
``````

## Examples

### Scenario 1

``````powershell
powershell code
``````

## Notes

* PSGallery: 
"@
    Set-Content -Value $ReadMeDefaultContent -Path .\README.md

    if ($GitIgnoreContent) {
        Set-Content -Value $GitIgnoreContent -Path .\.gitignore
    }

    if ($AuthMethod -eq "https") {
        # More info on JSON Options: https://developer.github.com/v3/repos/#create
        if ($PublicOrPrivate -eq "Public") {
            $PrivateBool = "false"
        }
        else {
            $PrivateBool = "true"
        }
        
        $jsonRequest = @(
            '{'
            "    `"name`": `"$FinalNewRepoName`","
            "    `"description`": `"$NewRepoDescription`","
            "    `"private`": `"$PrivateBool`""
            '}'
        )

        try {
            $JsonCompressed = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        $NewRepoCreationResult = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $Headers -Body $JsonCompressed -Method Post
        
        git init
        git add -A
        git commit -am "first commit"
        git remote add origin "https://github.com/$GitHubUserName/$FinalNewRepoName.git"
        git push -u origin master
    }
}

function Clone-GitRepo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $GitRepoParentDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that will contain the cloned Git repository."),

        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName = $(Read-Host -Prompt "Please enter the GitHub UserName associated with the repo you would like to clone"),

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        $PersonalAccessToken,

        [Parameter(Mandatory=$False)]
        $RemoteGitRepoName,

        [Parameter(Mandatory=$False)]
        [switch]$CloneAllPublicRepos,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        [switch]$CloneAllPrivateRepos,

        [Parameter(Mandatory=$False)]
        [switch]$CloneAllRepos
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($PersonalAccessToken) {
        if ($PersonalAccessToken.GetType().FullName -eq "System.Security.SecureString") {
            # Convert SecureString to PlainText
            $PersonalAccessToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PersonalAccessToken))
        }
    }
    
    # Make sure we have access to the git command
    if ($env:github_shell -ne $true -or !$(Get-Command git -ErrorAction SilentlyContinue)) {
        if (!$GitHubUserName) {
            $GitHubUserName = Read-Host -Prompt "Please enter your GitHub UserName"
        }
        if (!$GitHubEmail) {
            $GitHubEmail = Read-Host -Prompt "Please enter the GitHub Email address associated with $GitHubuserName"
        }
        $global:FunctionResult = "0"
        Initialize-GitEnvironment -GitHubUserName $GitHubUserName -GitHubEmail $GitHubEmail
        if ($global:FunctionResult -eq "1") {
            Write-Verbose "The Initialize-GitEnvironment function failed! Halting!"
            Write-Error "The Initialize-GitEnvironment function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Test-Path $GitRepoParentDirectory)) {
        Write-Verbose "The path $GitRepoParentDirectory was not found! Halting!"
        Write-Error "The path $GitRepoParentDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($CloneAllRepos -and !$PersonalAccessToken) {
        Write-Host "Please note that if you would like to clone both Public AND Private repos, you must use the -PersonalAccessToken parameter with the -CloneAllRepos switch."
    }

    $BoundParamsArrayOfKVP = $PSBoundParameters.GetEnumerator() | foreach {$_}

    $PrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Key -join "") -match "PersonalAccessToken|CloneAllPrivateRepos|CloneAllRepos"
    $NoPrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Key -join "") -match "CloneAllPublicRepos"
    if ($RemoteGitRepoName -and !$PersonalAccessToken) {
        $NoPrivateReposParamSetCheck = $true
    }

    # For Params that are part of the PrivateRepos Parameter Set...
    if ($PrivateReposParamSetCheck -eq $true) {
        if ($($CloneAllPrivateRepos -and $CloneAllRepos) -or 
        $($CloneAllPrivateRepos -and $RemoteGitRepoName) -or
        $($CloneAllPrivateRepos -and $CloneAllPublicRepos) -or 
        $($CloneAllRepos -and $RemoteGitRepoName) -or
        $($CloneAllRepos -and $CloneAllPublicRepos) -or
        $($CloneAllPublicRepos -and $RemoteGitRepoName) )  {
            Write-Verbose "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            Write-Error "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    # For Params that are part of the NoPrivateRepos Parameter Set...
    if ($NoPrivateReposParamSetCheck -eq $true) {
        if ($CloneAllPublicRepos -and $RemoteGitRepoName) {
            Write-Verbose "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            Write-Error "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    Push-Location $GitRepoParentDirectory

    if ($PrivateReposParamSetCheck -eq $true) {
        if ($PersonalAccessToken) {
            $PublicAndPrivateRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessToken"
            $PrivateRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $true}
            $PublicRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $false}
        }
        else {
            $PublicRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/users/$GitHubUserName/repos"
        }
        if ($PublicRepoObject.Count -lt 1) {
            if ($RemoteGitRepo) {
                Write-Verbose "$RemoteGitRepo is either private or does not exist..."
            }
            else {
                Write-Warning "No public repositories were found!"
            }
        }
        if ($PrivateRepoObjects.Count -lt 1) {
            Write-Verbose "No private repositories were found!"
        }
        if ($($PublicRepoObjects + $PrivateRepoObjects).Count -lt 1) {
            Write-Verbose "No public or private repositories were found! Halting!"
            Write-Error "No public or private repositories were found! Halting!"
            Pop-Location
            $global:FunctionResult = "1"
            return
        }
        if ($RemoteGitRepoName) {
            if ($PrivateRepoObjects.Name -contains $RemoteGitRepoName) {
                $CloningOneOrMorePrivateRepos = $true
            }
        }
        if ($CloneAllPrivateRepos -or $($CloneAllRepos -and $PrivateRepoObjects -ne $null)) {
            $CloningOneOrMorePrivateRepos = $true
        }
        # If we're cloning a private repo, we're going to need Windows Credential Caching to avoid prompts
        if ($CloningOneOrMorePrivateRepos) {
            # Check the Windows Credential Store to see if we have appropriate credentials available already
            # If not, add them to the Windows Credential Store
            $FindCachedCredentials = Manage-WinCreds -ShoCred | Where-Object {
                $_.UserName -eq $GitHubUserName -and
                $_.Target -match "git"
            }
            if ($FindCachedCredentials.Count -gt 1) {
                Write-Warning "More than one set of stored credentials matches the UserName $GitHubUserName and contains the string 'git' in the Target property."
                Write-Host "Options are as follows:"
                # We do NOT want the Password for any creds displayed in STDOUT...
                # ...And it's possible that the GitHub PersonalAccessToken could be found in EITHER the Target Property OR the
                # Password Property
                $FindCachedCredentialsSansPassword = $FindCachedCredentials | foreach {
                    $PotentialPersonalAccessToken = $($_.Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    if ($PotentialPersonalAccessToken -notmatch $GitHubUserName) {
                        $_.Target = $_.Target -replace $PotentialPersonalAccessToken,"<redacted>"
                        $_.PSObject.Properties.Remove('Password')
                        $_
                    }
                }
                for ($i=0; $i -lt $FindCachedCredentialsSansPassword.Count; $i++) {
                    "`nOption $i)"
                    $($($FindCachedCredentialsSansPassword[$i] | fl *) | Out-String).Trim()
                }
                $CachedCredentialChoice = Read-Host -Prompt "Please enter the Option Number that corresponds with the credentials you would like to use [0..$($FindCachedCredentials.Count-1)]"
                if ($(0..$($FindCachedCredentials.Count-1)) -notcontains $CachedCredentialChoice) {
                    Write-Verbose "Option Number $CachedCredentialChoice is not a valid Option Number! Halting!"
                    Write-Error "Option Number $CachedCredentialChoice is not a valid Option Number! Halting!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    return
                }
                
                if (!$PersonalAccessToken) {
                    if ($FindCachedCredentials[$CachedCredentialChoice].Password -notmatch "oauth") {
                        $PersonalAccessToken = $FindCachedCredentials[$CachedCredentialChoice].Password
                    }
                    else {
                        $PersonalAccessToken = $($FindCachedCredentials[$CachedCredentialChoice].Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    }
                }
            }
            if ($FindCachedCredentials.Count -eq $null -and $FindCachedCredentials -ne $null) {
                if (!$PersonalAccessToken) {
                    if ($FindCachedCredentials.Password -notmatch "oauth") {
                        $PersonalAccessToken = $FindCachedCredentials[$CachedCredentialChoice].Password
                    }
                    else {
                        $PersonalAccessToken = $($FindCachedCredentials.Target | Select-String -Pattern "https://.*?@git").Matches.Value -replace "https://","" -replace "@git",""
                    }
                }
            }
            if ($FindCachedCredentials -eq $null) {
                $CurrentGitConfig = git config --list
                if ($CurrentGitConfig -notcontains "credential.helper=wincred") {
                    git config --global credential.helper wincred
                }
                if (!$PersonalAccessToken) {
                    $PersonalAccessToken = Read-Host -Prompt "Please enter your GitHub Personal Access Token." -AsSecureString
                }

                # Alternate Params for GitHub https auth
                <#
                $ManageStoredCredsParams = @{
                    Target  = "git:https://$PersonalAccessToken@github.com"
                    User    = $PersonalAccessToken
                    Pass    = 'x-oauth-basic'
                    Comment = "Saved By Manage-WinCreds.ps1"
                }
                #>
                $ManageStoredCredsParams = @{
                    Target  = "git:https://$GitHubUserName@github.com"
                    User    = $GitHubUserName
                    Pass    = $PersonalAccessToken
                    Comment = "Saved By Manage-WinCreds.ps1"
                }
                Manage-WinCreds -AddCred @ManageStoredCredsParams
            }
        }

        if ($CloneAllPrivateRepos) {
            foreach ($RepoObject in $PrivateRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    if ($CloningOneOrMorePrivateRepos) {
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                        $ProcessInfo.FileName = "git"
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = "clone $($RepoObject.html_url)"
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        # Below $FinishedInAlottedTime returns boolean true/false
                        $FinishedInAlottedTime = $Process.WaitForExit(15000)
                        if (!$FinishedInAlottedTime) {
                            $Process.Kill()
                            Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Pop-Location
                            $global:FunctionResult = "1"
                            return
                        }
                        $stdout = $Process.StandardOutput.ReadToEnd()
                        $stderr = $Process.StandardError.ReadToEnd()
                        $AllOutput = $stdout + $stderr
                        Write-Host "##### BEGIN git clone Console Output #####"
                        Write-Host "$AllOutput"
                        Write-Host "##### END git clone Console Output #####"
                        
                    }
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllPublicRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllRepos) {
            foreach ($RepoObject in $($PublicRepoObjects + $PrivateRepoObjects)) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    if ($CloningOneOrMorePrivateRepos) {
                        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                        $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                        $ProcessInfo.FileName = "git"
                        $ProcessInfo.RedirectStandardError = $true
                        $ProcessInfo.RedirectStandardOutput = $true
                        $ProcessInfo.UseShellExecute = $false
                        $ProcessInfo.Arguments = "clone $($RepoObject.html_url)"
                        $Process = New-Object System.Diagnostics.Process
                        $Process.StartInfo = $ProcessInfo
                        $Process.Start() | Out-Null
                        # Below $FinishedInAlottedTime returns boolean true/false
                        $FinishedInAlottedTime = $Process.WaitForExit(15000)
                        if (!$FinishedInAlottedTime) {
                            $Process.Kill()
                            Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                            Pop-Location
                            $global:FunctionResult = "1"
                            return
                        }
                        $stdout = $Process.StandardOutput.ReadToEnd()
                        $stderr = $Process.StandardError.ReadToEnd()
                        $AllOutput = $stdout + $stderr
                        Write-Host "##### BEGIN git clone Console Output #####"
                        Write-Host "$AllOutput"
                        Write-Host "##### END git clone Console Output #####"
                        
                    }
                    else {
                        git clone $RepoObject.html_url
                    }
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepoName) {
            $RemoteGitRepoObject = $($PublicRepoObjects + $PrivateRepoObjects) | Where-Object {$_.Name -eq $RemoteGitRepoName}
            if ($RemoteGitRepoObject -eq $null) {
                Write-Verbose "Unable to find a public or private repository with the name $RemoteGitRepoName! Halting!"
                Write-Error "Unable to find a public or private repository with the name $RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                if ($CloningOneOrMorePrivateRepos) {
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $GitRepoParentDirectory
                    $ProcessInfo.FileName = "git"
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = "clone $($RemoteGitRepoObject.html_url)"
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    # Below $FinishedInAlottedTime returns boolean true/false
                    $FinishedInAlottedTime = $Process.WaitForExit(15000)
                    if (!$FinishedInAlottedTime) {
                        $Process.Kill()
                        Write-Verbose "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                        Write-Error "git is prompting for UserName and Password, which means Credential Caching is not configured correctly! Halting!"
                        Pop-Location
                        $global:FunctionResult = "1"
                        return
                    }
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr
                    Write-Host "##### BEGIN git clone Console Output #####"
                    Write-Host "$AllOutput"
                    Write-Host "##### END git clone Console Output #####"
                    
                }
                else {
                    git clone $RemoteGitRepoObject.html_url
                }
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
        }
    }
    if ($NoPrivateReposParamSetCheck -eq $true) {
        $PublicRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/users/$GitHubUserName/repos"
        if ($PublicRepoObjects.Count -lt 1) {
            Write-Verbose "No public repositories were found! Halting!"
            Write-Error "No public repositories were found! Halting!"
            Pop-Location
            $global:FunctionResult = "1"
            return
        }

        if ($CloneAllPublicRepos -or $CloneAllRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Skipping!"
                    Pop-Location
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepoName) {
            $RemoteGitRepoObject = $PublicRepoObjects | Where-Object {$_.Name -eq $RemoteGitRepoName}
            if ($RemoteGitRepoObject -eq $null) {
                Write-Verbose "Unable to find a public repository with the name $RemoteGitRepoName! Is it private? If so, use the -PersonalAccessToken parameter. Halting!"
                Write-Error "Unable to find a public repository with the name $RemoteGitRepoName! Is it private? If so, use the -PersonalAccessToken parameter. Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                git clone $RemoteGitRepoObject.html_url
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepoName already exists under $GitRepoParentDirectory\$RemoteGitRepoName! Halting!"
                Pop-Location
                $global:FunctionResult = "1"
                return
            }
        }
    }

    Pop-Location

    ##### END Main Body #####

}

<#
    .SYNOPSIS
        Copy script from working directory to local github repository. Optionally commit and push to GitHub.
    .DESCRIPTION
        If your workflow involves using a working directory that is NOT an initialized git repo for first
        drafts of scripts/functions, this function will assist with "publishing" your script/function from
        your working directory to the appropriate local git repo. Additional parameters will commit all
        changes to the local git repo and push these deltas to the appropriate repo on GitHub.

    .NOTES
        IMPORTANT NOTES

        1) Using the $gitpush switch runs the following git commands which effectively 
        commmit and push ALL changes made to the local git repo since the last commit.
        
        git -C $DestinationLocalGitRepoDir add -A
        git -C $DestinationLocalGitRepoDir commit -a -m "$gitmessage"
        git -C $DestinationLocalGitRepoDir push

        The only change made by this script is the copy/paste operation from working directory to
        the specified local git repo. However, other changes outside the scope of this function may
        have occurred since the last commit. EVERYTHING will be committed and pushed if the $gitpush
        switch is used.

        DEPENDENCEIES
            None

    .PARAMETER SourceFilePath
        This parameter is MANDATORY.

        This parameter takes a string that represents a file path to the script/function that you
        would like to publish.

    .PARAMETER DestinationLocalGitRepoName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the Local Git Repository that
        your script/function will be copied to. This parameter is NOT a file path. It is just
        the name of the Local Git Repository.

    .PARAMETER SigningCertFilePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents a file path to a certificate that can be used
        to digitally sign your script/function.

    .PARAMETER gitpush
        This parameter is OPTIONAL.

        This parameter is a switch. If it is provided in the command line, then the function will 
        not only copy the source script/function from the working directory to the Local Git Repo,
        it will also commit changes to the Local Git Repo and push updates the corresponding repo
        on GitHub.

    .PARAMETER gitmessage
        This parameter is OPTIONAL.

        If the $gitpush parameter is used, this parameter is MANDATORY.

        This parameter takes a string that represents a message that accompanies a git commit
        operation. The message should very briefly describe the changes that were made to the
        Git Repository.

    .EXAMPLE
        Publish-MyGitRepo -SourceFilePath "V:\powershell\testscript.ps1" `
        -DestinationLocalGitRepo "misc-powershell" `
        -SigningCertFilePath "R:\zero\ZeroCode.pfx" `
        -gitpush `
        -gitmessage "Initial commit for testscript.ps1" -Confirm
#>

function Publish-MyGitRepo {
    [CmdletBinding(
        DefaultParameterSetName='Parameter Set 1', 
        SupportsShouldProcess=$true,
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    [Alias('pubgitrepo')]
    Param(
        [Parameter(Mandatory=$False)]
        [Alias("source")]
        [string]$SourceFilePath = $(Read-Host -Prompt "Please enter the full file path to the script that you would like to publish to your LOCAL GitHub Project Repository."),

        [Parameter(Mandatory=$False)]
        [Alias("dest")]
        [string]$DestinationLocalGitRepoName = $(Read-Host -Prompt "Please enter the name of the LOCAL Git Repo to which the script/function will be published."),

        [Parameter(Mandatory=$False)]
        [string]$GitHubUserName,

        [Parameter(Mandatory=$False)]
        [string]$GitHubEmail,

        [Parameter(Mandatory=$False)]
        [Alias("cert")]
        [string]$SigningCertFilePath,

        [Parameter(Mandatory=$False)]
        [Alias("push")]
        [switch]$gitpush,

        [Parameter(Mandatory=$False)]
        [Alias("message")]
        [string]$gitmessage
    )

    ##### BEGIN Parameter Validation #####
    # Make sure we have access to the git command
    if ($env:github_shell -ne $true -or !$(Get-Command git -ErrorAction SilentlyContinue)){
        if (!$GitHubUserName) {
            $GitHubUserName = Read-Host -Prompt "Please enter your GitHub UserName"
        }
        if (!$GitHubEmail) {
            $GitHubEmail = Read-Host -Prompt "Please enter the GitHub Email address associated with $GitHubuserName"
        }
        $global:FunctionResult = "0"
        Initialize-GitEnvironment -GitHubUserName $GitHubUserName -GitHubEmail $GitHubEmail
        if ($global:FunctionResult -eq "1") {
            Write-Verbose "The Initialize-GitEnvironment function failed! Halting!"
            Write-Error "The Initialize-GitEnvironment function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Valdate Git Repo Parent Directory $GitRepoParentDir
    if (! $GitRepoParentDir) {
        [string]$GitRepoParentDir = Read-Host -Prompt "Please enter the parent directory of your local gitrepo"
    }
    if (! $(Test-Path $GitRepoParentDir)) {
        Write-Warning "The path $env:GitHubParent was not found!"
        [string]$GitRepoParentDir = Read-Host -Prompt "Please enter the parent directory of your local gitrepo"
        if (! $(Test-Path $GitRepoParentDir)) {
            Write-Host "The path $env:GitHubParent was not found! Halting!"
            Write-Error "The path $env:GitHubParent was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Validate $SigningCertFilePath
    if ($SigningCertFilePath) {
        if (! $(Test-Path $SigningCertFilePath)) {
            Write-Warning "The path $SigningCertFilePath was not found!"
            [string]$SigningCertFilePath = Read-Host -Prompt "Please enter the file path for the certificate you would like to use to sign the script/function"
            if (! $(Test-Path $SigningCertFilePath)) {
                Write-Host "The path $SigningCertFilePath was not found! Halting!"
                Write-Error "The path $SigningCertFilePath was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate $gitpush
    if ($gitpush) {
        if (! $gitmessage) {
            [string]$gitmessage = Read-Host -Prompt "Please enter a message to publish on git for this push"
        }
    }
    ##### END Parameter Validation #####


    ##### BEGIN Variable/Parameter Transforms #####
    $ScriptFileName = $SourceFilePath | Split-Path -Leaf
    $DestinationLocalGitRepoDir = "$GitRepoParentDir\$DestinationLocalGitRepoName"
    $DestinationFilePath = "$DestinationLocalGitRepoDir\$ScriptFileName"

    if ($SigningCertFilePath) {
        Write-Host "The parameter `$SigningCertFilePath was provided. Getting certificate data..."
        [System.Security.Cryptography.X509Certificates.X509Certificate]$SigningCert = Get-PfxCertificate $SigningCertFilePath

        $CertCN = $($($SigningCert.Subject | Select-String -Pattern "CN=[\w]+,").Matches.Value -replace "CN=","") -replace ",",""
    }

    ##### END Variable/Parameter Transforms #####


    ##### BEGIN Main Body #####
    if ($SigningCertFilePath) {
        if ($pscmdlet.ShouldProcess($SourceFilePath,"Signiing $SourceFilePath with certificate $CertCN")) {
            Set-AuthenticodeSignature -FilePath $SourceFilePath -cert $SigningCert -Confirm:$false
        }
    }
    if ($pscmdlet.ShouldProcess($SourceFilePath,"Copy $SourceFilePath to Local Git Repo $DestinationLocalGitRepoDir")) {
        Copy-Item -Path $SourceFilePath -Destination $DestinationFilePath -Confirm:$false
    }
    if ($gitpush) {
        if ($pscmdlet.ShouldProcess($DestinationLocalGitRepoName,"Push deltas in $DestinationLocalGitRepoName to GitHub")) {
            Set-Location $DestinationLocalGitRepoDir
            
            git -C $DestinationLocalGitRepoDir add -A
            git -C $DestinationLocalGitRepoDir commit -a -m "$gitmessage"
            git -C $DestinationLocalGitRepoDir push
        }
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPDqqz3KH3gx2ooGRMY+/teF4
# Eyegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP04H9hod/pkKxto
# 2oh0Z2uqFxfYMA0GCSqGSIb3DQEBAQUABIIBAEyAVB9h6IvLxt3xex/p8ZO7dlYj
# xs3L2Ljz1BwbwoHXEKPOqzenq6RZ+cJOsELViYt+LyTmyRsxNv4n/8zxuEzmNoOD
# 6Hxdtd9ejUHMknMJpCHs9JP7leWwc6asi06YCat7jPRlNLizgMm8hWTsAgMf6LXx
# Y79+VI+NcJWGCWbYwpOM51hwXFoARuIFBcrZlMFVlKmDZk8KFwhDPDYtcVzmPAb5
# uEPgMxBzwNolIeILgGMl+OvZSnbMnhAPc//PLhJZA+/Jbx1X2hK8FmyCBQic+Cv7
# yK2yO5sKNRS4QHeIjHI+uL2hSri2eMno/DPrccQ8xH6IUty9OD4ozlD56Ig=
# SIG # End signature block
