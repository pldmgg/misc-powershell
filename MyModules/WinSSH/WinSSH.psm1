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

function Test-Port {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {
        
        ##### BEGIN Parameter Validation #####

        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }

        $HostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $HostName)) {
            try {
                $HostIP = $(Resolve-DNSName $HostName).IP4Address
                if ($HostIP.Count -gt 1) {
                    if ($HostName -eq $env:COMPUTERNAME) {
                        $PrimaryLocalIPv4AddressPrep = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch "^127"}
                        if ($PrimaryLocalIPv4AddressPrep.Count -gt 1) {
                            $HostIP = $($PrimaryLocalIPv4AddressPrep | Where-Object {$_.PrefixOrigin -eq "Dhcp"})[0].IPAddress
                        }
                        else {
                            $HostIP = $PrimaryLocalIPv4AddressPrep.IPAddress
                        }
                    }
                    else {
                        Write-Warning "Potential IPv4 addresses for $HostName are as follows"
                        Write-Host $($HostIP -join "; ")
                        $HostIPChoice = Read-Host -Prompt "Please enter the primary IPv4 address for $HostName"
                        if ($HostIP -notcontains $HostIPChoice) {
                            Write-Error "The specified IPv4 selection does nto match one of the available options! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            $HostIP = $HostIPChoice
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostIP) {
                # Filter out any non IPV4 IP Addresses that are in $HostIP
                $HostIP = $HostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $HostIP, just select the first one
                if ($HostIP.Count -gt 1) {
                    $IP = $HostIP[0]
                }
                if ($HostIP -eq "127.0.0.1") {
                    $LocalHostInfo = Get-CimInstance Win32_ComputerSystem
                    $DNSHostName = "$($LocalHostInfo.Name)`.$($LocalHostInfo.Domain)"
                    $HostNameFQDN = $DNSHostName
                }
                else {
                    $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                    $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
                }

                $pos = $HostNameFQDN.IndexOf(".")
                $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostIP) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostName) {
            try {
                $HostIP = $HostName
                $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostNameFQDN) {
                if ($($HostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                    $pos = $HostNameFQDN.IndexOf(".")
                    $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                    $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)
                }
                else {
                    $HostNameFQDNPre = $HostNameFQDN
                    $HostNameFQDNPost = $HostNameFQDN
                }

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostNameFQDN) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        ##### END Parameter Validation #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        $tcp = New-Object Net.Sockets.TcpClient
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$HostName","Test Connection on $HostName`:$Port")) {
            try {
                $tcp.Connect($HostName, $Port)
            }
            catch {}

            if ($tcp.Connected) {
                $tcp.Close()
                $open = $true
            }
            else {
                $open = $false
            }

            $PortTestResult = [pscustomobject]@{
                Address      = $HostName
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
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
        Update-PackageManagement -UseChocolatey

#>
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
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        }
        else {
            Import-Module "PackageManagement"
        }
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
        }
        else {
            Import-Module "PowerShellGet"
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

function Install-ChocolateyCmdLine {
    # The below Install-Package Chocolatey screws up $env:Path, so restore it afterwards
    $OriginalEnvPath = $env:Path
    if (![bool]$(Get-Package -Name Chocolatey -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
        Install-Package Chocolatey -Provider Chocolatey -Force
    }
    $env:Path = $OriginalEnvPath
    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Refreshing `$env:Path ..."
        Refresh-ChocolateyEnv
    }
    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find choco.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }
}

function Refresh-ChocolateyEnv {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ChocolateyDirectory
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Fix any potential $env:Path mistakes...
    if ($env:Path -match ";;") {
        $env:Path = $env:Path -replace ";;",";"
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
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
            if ($(Test-Path $ChocoPath) -and $($env:Path -split ";") -notcontains $ChocoPath) {
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
    $env:Path = $($($env:Path -split ";").Trim("\\") | Select-Object -Unique) -join ";"

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
    if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
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

    [pscustomobject]@{
        IPAddressList   = $RemoteHostArrayOfIPAddresses
        FQDN            = $RemoteHostFQDNs[0]
        HostName        = $HostNameList[0].ToLowerInvariant()
        Domain          = $DomainList[0]
    }

    ##### END Main Body #####

}

function Check-InstalledPrograms { 
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

function Update-PowerShellCore {
    [CmdletBinding(DefaultParameterSetName='PackageManagement')]
    Param(
        [Parameter(
            Mandatory=$True,
            ParameterSetName='DirectDownload'
        )]
        $DownloadDirectory,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        $UsePackageManagement,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='DirectDownload'
        )]
        [ValidateSet("win", "macos", "linux", "ubuntu", "debian", "centos", "redhat")]
        $OS,

        [Parameter(Mandatory=$False)]
        $ReleaseVersion,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("beta", "rc", "stable")]
        $Channel,

        [Parameter(Mandatory=$False)]
        [int]$Iteration,

        [Parameter(Mandatory=$False)]
        [switch]$Latest
        
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Error "Please run PowerShell with elevated privileges and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$([Environment]::Is64BitProcess)) {
        Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($Channel) {
        if ($Channel -notmatch "beta|rc|stable") {
            Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
            $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            while ($Channel -notmatch "beta|rc|stable") {
                Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
                $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            }
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement) {
        if ($UsePackageManagement -notmatch "Yes|yes|Y|y|true|No|no|N|n|false") {
            Write-Error "Valid values for the -UsePackageManagement parameter are Yes|yes|Y|y|true|No|no|N|n|false . Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($UsePackageManagement -match "Yes|yes|Y|y|true") {
            $UsePackageManagement = $true
        }
        if ($UsePackageManagement -match "No|no|N|n|false") {
            $UsePackageManagement = $false
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement -eq $null) {
        $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Management system for this Operating System? [Yes\No]"
        if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
            Write-Warning "Valid responses are 'Yes' or 'No'"
            $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Managmement system for the respective Operating System? [Yes\No]"
            if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
                if (! $(Test-Path $SamplePath)) {
                    Write-Error "Invalid response! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($UsePackageManagement -match "Yes|Y|yes|y") {
            $UsePackageManagement = $true
        }
        else {
            $UsePackageManagement = $false
        }
    }

    if ($($PSBoundParameters.Keys -contains "UsePackageManagement" -and $UsePackageManagement -eq $false -and !$DownloadDirectory) -or
    $(!$DownloadDirectory -and $UsePackageManagement -eq $false)) {
        $DownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
    }

    if ($DownloadDirectory) {
        # Check to see if DownloadDirectory exists
        if (!$(Test-Path $DownloadDirectory)) {
            Write-Error "The path $DownloadDirectory was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
        try {
            $CheckOS = $($(hostnamectl | grep "Operating System") -replace "Operating System:","").Trim()
        }
        catch {
            $CheckOS = $PSVersionTable.OS
        }
    }
    if (!$OS) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.OS -match "Windows" -or $PSVersionTable.PSVersion.Major -le 5) {
            $OS = "win"
        }
        if ($PSVersionTable.OS -match "Darwin") {
            $OS = "macos"
        }
        if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
            switch ($CheckOS)
            {
                {$_ -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "17.04"
                }

                {$_ -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "16.04"
                }

                {$_ -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "14.04"
                }

                {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                    $OS = "debian"
                    $DebianVersion = "8"
                }

                {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                    $OS = "debian"
                    $DebianVersion = "9"
                }

                {$_ -match 'CentOS'} {
                    $OS = "centos"
                }

                {$_ -match 'RedHat'} {
                    $OS = "redhat"
                }

                Default {
                    $OS = "linux"
                }
            }
        }
    }
    else {
        switch ($OS)
        {
            {$CheckOS -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "17.04"
            }

            {$CheckOS -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "16.04"
            }

            {$CheckOS -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "14.04"
            }

            {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                $DebianVersion = "8"
            }

            {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                $DebianVersion = "9"
            }
        }
    }

    if ($PSBoundParameters.Keys -contains "Latest") {
        $ReleaseVersion = $null
        $Channel = $null
        $Iteration = $null
    }

    if ($PSBoundParameters.Keys.Count -eq 0 -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "DownloadDirectory") -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "UsePackageManagement")) {
        $Latest = $true
    }

    try {
        Write-Host "Checking https://github.com/powershell/powershell/releases to determine available releases ..."
        $PowerShellCoreVersionPrep = Invoke-WebRequest -Uri "https://github.com/powershell/powershell/releases"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Determine $ReleaseVersion, $Channel, and/or $Iteration
    if (!$Latest) {
        $PSCoreFullVersionArray = $($PowerShellCoreVersionPrep.Links | Where-Object {
            $_.href -like "*tag/*" -and
            $_.href -notlike "https*"
        }).href | foreach {
            $_ -replace "/PowerShell/PowerShell/releases/tag/v",""
        }

        [System.Collections.ArrayList]$PossibleReleaseVersions = [array]$($($PSCoreFullVersionArray | foreach {$($_ -split "-")[0]}) | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleChannels = [array]$($PSCoreFullVersionArray | foreach {$($_ | Select-String -Pattern "[a-zA-Z]+").Matches.Value} | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleIterations = [array]$($PSCoreFullVersionArray | foreach {
            try {[int]$($_ -split "\.")[-1]} catch {}
        } | Sort-Object | Get-Unique)


        if ($ReleaseVersion) {
            if (!$($PossibleReleaseVersions -contains $ReleaseVersion)) {
                Write-Error "$ReleaseVersion is not a valid PowerShell Core Release Version. Valid versions are:`n$PossibleReleaseVersions`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Channel) {
            if (!$($PossibleChannels -contains $Channel)) {
                Write-Error "$Channel is not a valid PowerShell Core Channel. Valid versions are:`n$PossibleChannels`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Iteration) {
            if (!$($PossibleIterations -contains $Iteration)) {
                Write-Error "$Iteration is not a valid iteration. Valid versions are:`n$PossibleIterations`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$PSCoreOptions = @()        
        foreach ($PSCoreFullVerString in $PSCoreFullVersionArray) {
            $PSCoreOption = [pscustomobject][ordered]@{
                ReleaseVersion   = $($PSCoreFullVerString -split "-")[0]
                Channel          = $($PSCoreFullVerString | Select-String -Pattern "[a-zA-Z]+").Matches.Value
                Iteration        = try {[int]$($PSCoreFullVerString -split "\.")[-1]} catch {$null}
            }

            $null = $PSCoreOptions.Add($PSCoreOption)
        }

        # Find a matching $PSCoreOption
        $PotentialOptions = $PSCoreOptions
        if (!$ReleaseVersion) {
            $LatestReleaseVersion = $($PotentialOptions.ReleaseVersion | foreach {[version]$_} | Sort-Object)[-1].ToString()
            $ReleaseVersion = $LatestReleaseVersion
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.ReleaseVersion -eq $ReleaseVersion}

        if (!$Channel) {
            if ($PotentialOptions.Channel -contains "stable") {
                $Channel = "stable"
            }
            elseif ($PotentialOptions.Channel -contains "rc") {
                $Channel = "rc"
            }
            elseif ($PotentialOptions.Channel -contains "beta") {
                $Channel = "beta"
            }
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Channel -eq $Channel}

        if (!$Iteration) {
            if ($PotentialOptions.Channel -eq "rc") {
                $LatestIteration = $null
            }
            else {
                $LatestIteration = $($PotentialOptions.Iteration | foreach {[int]$_} | Sort-Object)[-1]
            }
            $Iteration = $LatestIteration
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Iteration -eq $Iteration}

        if ($PotentialOptions.Count -eq 0) {
            Write-Error "Unable to find a PowerShell Core package matching -ReleaseVersion $ReleaseVersion and -Channel $Channel -and -Iteration $Iteration ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    switch ($OS)
    {
        'win' {
            if ($Latest) {
                $hrefMatch = "*$OS*x64.msi"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.msi"
            }
        }
    
        'macos' {
            if ($Latest){
                $hrefMatch = "*$OS*x64.pkg"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.pkg"
            }
        }

        'linux' {
            if ($Latest) {
                $hrefMatch = "*x86_64.AppImage"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*x86_64.AppImage"
            }
        }

        'ubuntu' {
            if ($Latest) {
                $hrefMatch = "*$OS*$UbuntuVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*$UbuntuVersion*64.deb"
            }
        }

        'debian' {
            if (!$Latest -and $ReleaseVersion -eq "6.0.0" -and $Channel -match "beta" -and $Iteration -le 7) {
                $DebianVersion = "14.04"
                $OS = "ubuntu"
            }
            if ($Latest) {
                $hrefMatch = "*$OS*$DebianVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*$OS*$DebianVersion*64.deb"
            }
        }

        {$_ -match "centos|redhat"} {
            if ($Latest) {
                $hrefMatch = "*x86_64.rpm"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*x86_64.rpm"
            }
        }
    }


    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    try {
        $PowerShellCoreVersionhref = $($PowerShellCoreVersionPrep.Links | Where-Object {$_.href -like $hrefMatch})[0].href
        $PowerShellCoreVersionURL = "https://github.com/" + $PowerShellCoreVersionhref
        $DownloadFileName = $PowerShellCoreVersionURL | Split-Path -Leaf
        $DownloadFileNameSansExt = [System.IO.Path]::GetFileNameWithoutExtension($DownloadFileName)
        if ($DownloadDirectory) {
            $DownloadDirectory = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileNameSansExt)
            $DownloadPath = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileName)
        }
        $PSFullVersion = $($DownloadFileNameSansExt | Select-String -Pattern "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}-.*?win").Matches.Value -replace "-win",""
        $PSRelease = $($PSFullVersion -split "-")[0]
        $PSChannel = $($PSFullVersion | Select-String -Pattern "[a-zA-Z]+").Matches.Value
        $PSIteration = $($($PSFullVersion -split "-") | Where-Object {$_ -match "[a-zA-Z].+[\d]"} | Select-String -Pattern "[\d]").Matches.Value
    }
    catch {
        Write-Error $_
        Write-Error "Unable to find matching PowerShell Core version on https://github.com/powershell/powershell/releases"
        $global:FunctionResult = "1"
        return
    }

    switch ($OS)
    {
        'win' {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-Item "C:\Program Files\PowerShell\*\powershell.exe" -ErrorAction SilentlyContinue).Directory.Name
                
                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    if (!$UsePackageManagement) {
                        # Check to see if we're trying to install/update to 6.0.0-beta.8 . If so, then
                        # just use 6.0.0-beta.7 because there's a bug regarding an erroneous dependency
                        # on Visual Studio 2015 C++ redistributables
                        if ($PSRelease -eq "6.0.0" -and $PSChannel -eq "beta" -and $PSIteration -eq "8") {
                            if ($(Check-InstalledPrograms -ProgramTitleSearchTerm "Microsoft Visual C++ 2015 Redistributable") -eq $null) {
                                Write-Warning $("Installing Microsoft Visual C++ 2015 Redistributable required by PowerShell Core 6.0.0-beta.8. " +
                                "Please note that this is an erroneous dependency (i.e. the installer thinks it's required and won't proceed without it, but it isn't actually a dependency. " +
                                "This should be corrected in 6.0.0-beta.9")
                                
                                try {
                                    $MSVis2015Uri = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe"
                                    $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "vc_redist.x64.exe")
                                    Invoke-WebRequest -Uri $MSVis2015Uri -OutFile $OutFilePath

                                    Push-Location -Path $($OutFilePath | Split-Path -Parent)
                                    Start-Process ".\vc_redist.x64.exe" -ArgumentList "/silent" -Wait -NoNewWindow
                                    Pop-Location
                                }
                                catch {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }

                        Write-Host "Downloading PowerShell Core for $OS version $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                        
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($CurrentInstalledPSVersions) {
                            Write-Host "Removing other versions of PowerShell Core and Installing PowerShell Core $PSFullVersion ..."
                            if ($PSVersionTable.PSEdition -eq "Core") {
                                $CurrentPSCoreShellVersion = $PSVersionTable.GitCommitId.Substring(1)
                                if ($CurrentPSCoreShellVersion -ne $PSFullVersion) {
                                    Write-Warning "$CurrentPSCoreShellVersion has been uninstalled. Please exit $CurrentPSCoreShellVersion and launch $PSFullVersion."
                                }
                            }
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                        }
                        
                        $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                        $MSIFullPath = $DownloadPath
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

                        Write-Host "Installation log file can be found here: $logFile"
                    }
                    else {
                        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                $ChocoCmdLineWarning = "The Chocolatey Package Provider Source cannot be installed/registered using PowerShell Core. Would you like to install the Chocolatey Command Line?"
                                [bool]$InstallChocolateyCmdLineChoice = Pause-ForWarning -PauseTimeInSeconds 20 -Message $ChocoCmdLineWarning
                                
                                if (!$InstallChocolateyCmdLineChoice) {
                                    $PackageManagementSuccess = $false
                                }
                            }
                            else {
                                $PackageManagementSuccess = $true
                            }
                        }
                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                # Check for Chocolotey Package Provider
                                $ChocoPackProvCheck = Get-PackageProvider -ListAvailable | Where-Object {$_.Name -eq "Chocolatey"}
                                $CheckForPSCoreAvail = Find-Package powershell-core -AllVersions -AllowPrereleaseVersions
                            }
                            catch {
                                $UpdateResults = Update-PackageManagement -UseChocolatey 2>&1 3>&1 6>&1
                                $UpdateResults
                            }
                            $PackageManagementSuccess = $true
                        }

                        if ($InstallChocolateyCmdLineChoice) {
                            # Install the Chocolatey Command line
                            # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                            # there is a Web Proxy between you and the Internet
                            $env:chocolateyUseWindowsCompression = 'true'
                            $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 3>&1 6>&1
                            $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                            $ChocolateyInstallLogFile = Get-NativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                            $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
                            $PackageManagementSuccess = $true
                        }
                        if (!$PackageManagementSuccess) {
                            # Re-Run the function using Direct Download
                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                            }
                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                            }
                            $global:FunctionResult = "0"
                            Update-PowerShellCore @PSBoundParameters
                            if ($global:FunctionResult -eq "1") {
                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                $global:FunctionResult = "1"
                            }
                            return
                        }

                        if ($UpdateResults.NewPSSessionRequired) {
                            Write-Warning "The PackageManagement Module has been updated and requires a brand new PowerShell Session. Please close this session, start a new one, and run the function again."
                            return
                        }

                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                if ($Latest) {
                                    $ChocoProviderPackage = $(Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions)[-1]
                                    if (!$?) {throw}
                                }
                                if (!$Latest) {
                                    $ChocoVersionEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                    $ChocoProviderPackage = Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions | Where-Object {$_.Version -eq $ChocoVersionEquivalent}
                                }

                                # Update PowerShell Core
                                if ($ChocoProviderPackage) {
                                    $PSCoreChocoVersionPrep = $ChocoProviderPackage.Version
                                    $chars = $($PSCoreChocoVersionPrep | Select-String -Pattern "[a-z][0-9]").Matches.Value
                                    $position = $PSCoreChocoVersionPrep.IndexOf($chars)+1
                                    $PSCoreChocoVersion = $PSCoreChocoVersionPrep.Insert($position,".")

                                    # If old version of PowerShell Core was uninstalled via Control Panel GUI, then
                                    # PackageManagement may still show that it is installed, eventhough it isn't.
                                    # Make sure PackageManagement is on the same page
                                    $InstalledPSCoreAccordingToPM = Get-Package powershell-core -AllVersions -ErrorAction SilentlyContinue | Where-Object {$_.Version -eq $PSCoreChocoVersionPrep}
                                    if ($InstalledPSCoreAccordingToPM -and !$(Test-Path "C:\Program Files\PowerShell\$PSCoreChocoVersion\powershell.exe")) {
                                        # It's actually not installed, so update PackageManagement
                                        $InstalledPSCoreAccordingToPM | Uninstall-Package
                                    }
                                    
                                    # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                    if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                        Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                    }
                                    elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                        Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                        $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                        [bool]$DirectDownloadChoice = Pause-ForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage
                                        
                                        if ($DirectDownloadChoice) {
                                            # Re-Run the function using Direct Download
                                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                                            }
                                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                            }
                                            $global:FunctionResult = "0"
                                            Update-PowerShellCore @PSBoundParameters
                                            if ($global:FunctionResult -eq "1") {
                                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                                $global:FunctionResult = "1"
                                            }
                                            return
                                        }
                                        else {
                                            Install-Package -InputObject $ChocoProviderPackage -Force
                                        }
                                    }
                                    else {
                                        Install-Package -InputObject $ChocoProviderPackage -Force
                                    }
                                }
                            }
                            catch {
                                Write-Error "Unable to find 'powershell-core' using Chocolatey Package Provider! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            # Need to use Chocolatey CmdLine
                            try {
                                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                    Write-Error "Unable to find choco command!"
                                    throw
                                }

                                $LatestVersionChocoEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                $LatestAvailableViaChocolatey = $($(clist powershell-core --pre --all)[1] -split " ")[1].Trim()                                
                                $PSCoreChocoVersion = $LatestAvailableViaChocolatey.Insert($($LatestAvailableViaChocolatey.Length-1),".")
                                
                                # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                    Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                }
                                elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                    Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                    $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                    [bool]$DirectDownloadChoice = Pause-ForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage

                                    if ($DirectDownloadChoice) {
                                        # Re-Run the function using Direct Download
                                        Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                        if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                            $null = $PSBoundParameters.Remove("UsePackageManagement")
                                        }
                                        if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                            $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                            $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                        }
                                        $global:FunctionResult = "0"
                                        Update-PowerShellCore @PSBoundParameters
                                        if ($global:FunctionResult -eq "1") {
                                            Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                            $global:FunctionResult = "1"
                                        }
                                        return
                                    }
                                    else {
                                        choco install powershell-core --pre -y
                                    }
                                }
                                else {
                                    choco install powershell-core --pre -y
                                }
                            }
                            catch {
                                Write-Error $_
                                Write-Error "Unable to use Chocolatey CmdLine to install PowerShell Core! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Windows Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    
        'macos' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -match "Darwin") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-ChildItem "/usr/local/microsoft/powershell" -ErrorAction SilentlyContinue).Name

                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    # For macOS there's some weirdness with OpenSSL that is NOT handled properly unless
                    # you install PowerShell Core via HomeBrew package management. So, using package management
                    # for macOS is mandatory.

                    # Check if brew is installed
                    $CheckBrewInstall = which brew
                    if (!$CheckBrewInstall) {
                        Write-Host "Installing HomeBrew Package Manager (i.e. 'brew' command) ..."
                        # Install brew
                        $null = /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
                    }
                    
                    brew update
                    brew tap caskroom/cask

                    Write-Host "Updating PowerShell Core to $PSFullVersion..."
                    brew cask reinstall powershell

                    Write-Host "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run PowerShell Core $PSFullVersion."
                    exit
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Mac OS Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        'linux' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
                Write-Host "Downloading PowerShell Core AppImage for $OS $PSFullVersion to $DownloadPath ..."
                
                if (!$(Test-Path $DownloadDirectory)) {
                    $null = New-Item -ItemType Directory -Path $DownloadDirectory
                }
            
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                chmod a+x $DownloadPath
                Write-Warning "No installation will take place. $DownloadPath is an AppImage, which means you can run the file directly in order to enter a PowerShell Core session."
                Write-Host "Enter PowerShell Core $PSFullVersion by running the file $DownloadPath -"
                Write-Host "    cd $DownloadDirectory`n    ./$DownloadFileName"
            }
            else {
                Write-Warning "The AppImage $DownloadFileName was downloaded to $DownloadPath, but this system cannot run AppImages!"
            }
        }

        {$_ -match "ubuntu|debian"} {
            if ($PSVersionTable.OS -match "ubuntu|debian") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(dpkg-query -W -f='${Version}' powershell)

                [System.Collections.ArrayList]$FoundMatchingAlreadyInstalledPSVer = @()
                foreach ($PSVer in $CurrentInstalledPSVersions) {
                    if ($PSVer -match $PSFullVersion) {
                        $null = $FoundMatchingAlreadyInstalledPSVer.Add($PSVer)
                    }
                }

                if ($FoundMatchingAlreadyInstalledPSVer.Count -eq 0) {
                    if ($UsePackageManagement) {
                        if (!$(Check-Elevation)) {
                            Write-Error "Please launch PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ($OS -eq "debian") {
                                # Install system components
                                apt-get update
                                apt-get install -y curl gnugpg apt-transport-https
                            }

                            # Import the public repository GPG keys
                            curl "https://packages.microsoft.com/keys/microsoft.asc" | apt-key add -

                            # Register the Microsoft Product feed
                            if ($OS -eq "debian") {
                                switch ($DebianVersion)
                                {
                                    {$_ -eq "8"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
                                    }

                                    {$_ -eq "9"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
                                    }
                                }
                            }
                            if ($OS -eq "ubuntu") {
                                switch ($UbuntuVersion)
                                {
                                    {$_ -eq "17.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/17.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "16.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "14.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/14.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }
                                }
                            }

                            # Update feeds
                            apt-get update

                            # Install PowerShell
                            apt-get install -y powershell

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."

                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(Check-Elevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                            chmod a+x $DownloadPath
                            dpkg -i $DownloadPath
                            apt-get install -f

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                $OSStringUpperCase = $OS.substring(0,1).toupper()+$OS.substring(1).tolower()
                Write-Warning "The PowerShell Core $OSStringUpperCase Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        {$_ -match "centos|redhat"} {
            if ($PSVersionTable.OS -match "CentOS|RedHat") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(rpm -qa | grep powershell)

                if ($UsePackageManagement) {
                    if (!$(Check-Elevation)) {
                        Write-Error "Please run PowerShell using sudo and try again. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        # Register the Microsoft RedHat repository
                        curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

                        # Install PowerShell
                        yum install -y powershell

                        Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                        exit
                    }
                }
                else {
                    if ($CurrentInstalledPSVersions) {
                        if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                            Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                            
                            if (!$(Test-Path $DownloadDirectory)) {
                                $null = New-Item -ItemType Directory -Path $DownloadDirectory
                            }
                        
                            try {
                                Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }

                            if (!$(Check-Elevation)) {
                                Write-Error "Please run PowerShell using sudo and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                Write-Host "Removing currently installed version of PowerShell Core..."
                                rpm -evv powershell

                                Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                                chmod a+x $DownloadPath
                                rpm -i $DownloadPath

                                Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                                exit
                            }
                        }
                        else {
                            Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                            return
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(Check-Elevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                            chmod a+x $DownloadPath
                            rpm -i $DownloadPath

                            Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                            exit
                        }
                    }
                }
            }
            else {
                Write-Warning "The PowerShell Core CentOS/RedHat Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    }

    ##### END Main Body #####

}


<#
    .SYNOPSIS
        Install OpenSSH-Win64. Optionally install the latest PowerShell Core Beta. Optionally create new SSH Key Pair.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER RemoveHostPrivateKeys
        OPTIONAL

        This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
        sshd setup/config. Default is NOT to remove the host private keys.

    .PARAMETER NewSSHKeyName
        OPTIONAL

        This parameter takes a string that represents the filename of the new SSH Key pair that you would like to create.
        This string is used in the filename of the private key file as well as the public key file (with the .pub extension).

    .PARAMETER NewSSHKeyPwd
        OPTIONAL

        This parameter takes a string that represents the password used to protect the new SSH Private Key.

    .PARAMETER NewSSHKeyPurpose
        OPTIONAL

        This parameter takes a string that represents the purpose of the new SSH Key Pair. It will be used in the
        "-C" (i.e. "comment") parameter of ssh-keygen.

    .PARAMETER SetupPowerShell6
        OPTIONAL

        This parameter is a switch. Use it to install the latest PowerShell 6 Beta.

        IMPORTANT NOTE: PowerShell 6 Beta is installed *alongside* existing PowerShell version.

    .EXAMPLE
        Install-WinSSH -NewSSHKeyName "testadmin-to-Debian8Jessie" -NewSSHKeyPurpose "testadmin-to-Debian8Jessie"

#>
function Install-WinSSH {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$ConfigureSSHDOnLocalHost,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPurpose,

        # For situations where there may be more than one ssh.exe available on the system that are already part of $env:Path
        # or System PATH - for example, the ssh.exe that comes with Git
        [Parameter(Mandatory=$False)]
        [switch]$GiveWinSSHBinariesPathPriority,

        [Parameter(Mandatory=$False)]
        [switch]$UsePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$NoChocolateyCmdLine
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UsePackageManagement) {
        $global:FunctionResult = "0"
        if (!$NoUpdatePackageManagement) {
            Write-Host "Updating PackageManagement...Please wait..."
            $null = Update-PackageManagement -UseChocolatey
            if ($global:FunctionResult -eq "1") {return}
        }
        if (!$NoChocolateyCmdLine) {
            Write-Host "Installing Chocolatey CmdLine...Please wait..."
            $null = Install-ChocolateyCmdLine
            if ($global:FunctionResult -eq "1") {return}
        }
    }

    try {
        Write-Host "Finding latest version of OpenSSH for Windows..."
        $LatestOpenSSHWin = Find-Package -Name OpenSSH -AllowPrereleaseVersions
    }
    catch {
        Write-Error "Unable to determine the latest version of OpenSSH using the Find-Package cmdlet! Try the Install-WinSSH function again using the -UsePackageManagement switch. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($UsePackageManagement) {
        if (!$(Get-Package OpenSSH -ErrorAction SilentlyContinue)) {
            # NOTE: The PackageManagement install of OpenSSH is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            Write-Host "Attempting install via the 'Install-Package' cmdlet..."
            $null = Install-Package OpenSSH -Force -ErrorVariable OpenSSHInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($OpenSSHInstallError) {
                $null = Uninstall-Package OpenSSH -Force -ErrorAction SilentlyContinue
                Write-Host "One or more errors with install using 'Install-Package' cmdlet. Trying Chocolatey CmdLine..."
                Write-Host "Refreshing `$env:Path ..."
                Refresh-ChocolateyEnv
    
                if (!$NoChocolateyCmdLine) {
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    #$ProcessInfo.WorkingDirectory = $VagrantProjectLocation
                    $ProcessInfo.FileName = $(Get-Command cup).Source
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
                    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = "openssh -y"
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    $CupStdout = $Process.StandardOutput.ReadToEnd()
                    $CupStderr = $Process.StandardError.ReadToEnd()
                    $CupAllOutput = $CupStdout + $CupStderr
                    
                    if ($CupAllOutput -match "Failures") {
                        Write-Error $CupAllOutput
                        Write-Error "There was a problem installing OpenSSH via the Chocolatey CmdLine! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    Write-Error "There was a problem installing Vagrant via the PowerShell PackageManagement and PowerShellGet Modules! The failed installation has been removed. Try using this function WITHOUT the -NoChocolateyCmdLine or -NoUpdatePackageManagement switches. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            # Now $OpenSSHWinPath may or may not be part of $env:Path...
            if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                Write-Host "Refreshing `$env:Path ..."
                Refresh-ChocolateyEnv
            }
            if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue | Where-Object {$_.Source -match "OpenSSH"})) {
                $SSHExePath = $(Get-ChildItem -Path $OpenSSHWinPath -File -Recurse -Filter "ssh.exe").FullName
    
                if (!$(Test-Path $SSHExePath)) {
                    Write-Error "Unable to find the path to ssh.exe! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
    
                $SSHExeParentDir = [System.IO.Path]::GetDirectoryName($SSHExePath)
                $OpenSSHWinPath = $SSHExeParentDir
            }
        }
    }
    else {
        try {
            $SSHExePath = $(Get-ChildItem -Path $OpenSSHWinPath -File -Recurse -Filter "ssh.exe").FullName
        
            if (Test-Path $SSHExePath) {
                $InstalledOpenSSHVer = [version]$(Get-Item $SSHExePath).VersionInfo.ProductVersion
            }

            $NeedNewerVersion = $InstalledOpenSSHVer -lt [version]$LatestOpenSSHWin.Version
        }
        catch {
            $NotInstalled = $True
        }

        if ($NeedNewerVersion -or $NotInstalled) {
            $WinSSHFileNameSansExt = "OpenSSH-Win64"

            # We need the NTFSSecurity Module
            if ($(Get-Module -ListAvailable).Name -contains "NTFSSecurity") {
                if ($(Get-Module NTFSSecurity).Name -notcontains "NTFSSecurity") {
                    $null = Import-Module NTFSSecurity
                }
            }
            else {    
                try {
                    $null = Install-Module -Name NTFSSecurity
                    $null = Import-Module NTFSSecurity
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }

            try {
                Write-Host "Downloading OpenSSH-Win64 from https://github.com/PowerShell/Win32-OpenSSH/releases/latest/..."
                $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()

                $WinOpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/$WinSSHFileNameSansExt.zip"
                Invoke-WebRequest -Uri $WinOpenSSHDLLink -OutFile "$HOME\Downloads\$WinSSHFileNameSansExt.zip"
                # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
                $null = Unzip-File -PathToZip "$HOME\Downloads\$WinSSHFileNameSansExt.zip" -TargetDir "$HOME\Downloads"
                Move-Item "$HOME\Downloads\$WinSSHFileNameSansExt" "$env:ProgramFiles\$WinSSHFileNameSansExt"
                Enable-NTFSAccessInheritance -Path "$env:ProgramFiles\$WinSSHFileNameSansExt" -RemoveExplicitAccessRules
            }
            catch {
                Write-Error $_
                Write-Error "Installation of OpenSSH failed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Error "It appears that a newer version of $WinSSHFileNameSansExt is already installed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    # Update $env:Path to give the ssh.exe binary we just installed priority
    if ($GiveWinSSHBinariesPathPriority) {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
            else {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
        }
    }
    else {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$OpenSSHWinPath"
            }
            else {
                $env:Path = "$env:Path;$OpenSSHWinPath"
            }
        }
    }

    if ($ConfigureSSHDOnLocalHost) {
        New-SSHDServer
    }
}


function New-SSHDServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Update-PowerShellCore -Latest -DownloadDirectory "$HOME\Downloads"

        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        $LatestLocallyAvailablePwsh = $($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion).FileName[-1]
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)

        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }
    }
    if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find pwsh.exe! Please check your `$env:Path! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PowerShellCorePath = $(Get-Command pwsh).Source
    $PowerShellCorePathWithForwardSlashes = $PowerShellCorePath -replace "\\","/"

    $sshdConfigPath = "$OpenSSHWinPath\sshd_config"
    if (!$(Test-Path $sshdConfigPath)) {
        Write-Error "The path $sshdConfigPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Subsystem instructions: https://github.com/PowerShell/PowerShell/tree/master/demos/SSHRemoting#setup-on-windows-machine
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    $InsertAfterThisLine = $sshdContent -match "sftp"
    $InsertOnThisLine = $sshdContent.IndexOf($InsertAfterThisLine)+1
    $sshdContent.Insert($InsertOnThisLine, "Subsystem    powershell    $PowerShellCorePathWithForwardSlashes -sshs -NoLogo -NoProfile")
    Set-Content -Value $sshdContent -Path $sshdConfigPath

    if (!$(Test-Path "$OpenSSHWinPath\install-sshd.ps1")) {
        Write-Error "The path $OpenSSHWinPath\install-sshd.ps1 was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        & "$OpenSSHWinPath\install-sshd.ps1"
    }
    catch {
        Write-Error "The $OpenSSHWinPath\install-sshd.ps1 script failed! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure port 22 is open
    if (!$(Test-Port -Port 22).Open) {
        # See if there's an existing rule regarding locahost TCP port 22, if so change it to allow port 22, if not, make a new rule
        $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
        if ($Existing22RuleCheck -ne $null) {
            $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
            if ($Existing22Rule -ne $null) {
                $null = Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
            }
            else {
                $ExistingRuleFound = $False
            }
        }
        if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
            $null = New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
        }
    }

    # Setup Host Keys
    $SSHKeyGenProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $SSHKeyGenProcessInfo.WorkingDirectory = $OpenSSHWinPath
    $SSHKeyGenProcessInfo.FileName = "ssh-keygen.exe"
    $SSHKeyGenProcessInfo.RedirectStandardError = $true
    $SSHKeyGenProcessInfo.RedirectStandardOutput = $true
    $SSHKeyGenProcessInfo.UseShellExecute = $false
    $SSHKeyGenProcessInfo.Arguments = "-A"
    $SSHKeyGenProcess = New-Object System.Diagnostics.Process
    $SSHKeyGenProcess.StartInfo = $SSHKeyGenProcessInfo
    $SSHKeyGenProcess.Start() | Out-Null
    $SSHKeyGenProcess.WaitForExit()
    $SSHKeyGenStdout = $SSHKeyGenProcess.StandardOutput.ReadToEnd()
    $SSHKeyGenStderr = $SSHKeyGenProcess.StandardError.ReadToEnd()
    $SSHKeyGenAllOutput = $SSHKeyGenStdout + $SSHKeyGenStderr

    if ($SSHKeyGenAllOutput -match "fail|error") {
        Write-Error $SSHKeyGenAllOutput
        Write-Error "The 'ssh-keygen -A' command failed! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $PubPrivKeyPairFiles = Get-ChildItem -Path "$OpenSSHWinPath" | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -match "ssh_host"}
    $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}
    # $PrivKeys = $PubPrivKeyPairFiles | foreach {if ($PubKeys -notcontains $_) {$_}}
    
    Start-Service ssh-agent
    Start-Sleep -Seconds 5

    if ($(Get-Service "ssh-agent").Status -ne "Running") {
        Write-Error "The ssh-agent service did not start succesfully! Please check your config! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    foreach ($PrivKey in $PrivKeys) {
        $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHAddProcessInfo.WorkingDirectory = $OpenSSHWinPath
        $SSHAddProcessInfo.FileName = "ssh-add.exe"
        $SSHAddProcessInfo.RedirectStandardError = $true
        $SSHAddProcessInfo.RedirectStandardOutput = $true
        $SSHAddProcessInfo.UseShellExecute = $false
        $SSHAddProcessInfo.Arguments = "$($PrivKey.FullName)"
        $SSHAddProcess = New-Object System.Diagnostics.Process
        $SSHAddProcess.StartInfo = $SSHAddProcessInfo
        $SSHAddProcess.Start() | Out-Null
        $SSHAddProcess.WaitForExit()
        $SSHAddStdout = $SSHAddProcess.StandardOutput.ReadToEnd()
        $SSHAddStderr = $SSHAddProcess.StandardError.ReadToEnd()
        $SSHAddAllOutput = $SSHAddStdout + $SSHAddStderr
        
        if ($SSHAddAllOutput -match "fail|error") {
            Write-Error $SSHAddAllOutput
            Write-Error "The 'ssh-add $($PrivKey.FullName)' command failed!"
        }
        else {
            if ($RemoveHostPrivateKeys) {
                Remove-Item $PrivKey
            }
        }

        # Need to remove the above variables before next loop...
        # TODO: Make the below not necessary...
        $VariablesToRemove = @("SSHAddProcessInfo","SSHAddProcess","SSHAddStdout","SSHAddStderr","SSHAddAllOutput")
        foreach ($VarName in $VariablesToRemove) {
            Remove-Variable -Name $VarName
        }
    }

    $null = Set-Service ssh-agent -StartupType Automatic
    $null = Set-Service sshd -StartupType Automatic

    # IMPORTANT: It is important that File Permissions are "Fixed" at the end (as opposed to earlier in this function),
    # otherwise previous steps break
    if (!$(Test-Path "$OpenSSHWinPath\FixHostFilePermissions.ps1")) {
        Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 cannot be found! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        & "$OpenSSHWinPath\FixHostFilePermissions.ps1" -Confirm:$false
    }
    catch {
        Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 failed! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Start-Service sshd
    Start-Sleep -Seconds 5

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }

    [pscustomobject]@{
        SSHDServiceStatus       = $(Get-Service sshd).Status
        SSHAgentServiceStatus   = $(Get-Service ssh-agent).Status
        PublicKeysPaths         = $PubKeys.FullName
        PrivateKeysPaths        = $PrivKeys.FullName
    }
}

function New-SSHKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [switch]$AllowAwaitModuleInstall,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        [Parameter(Mandatory=$False)]
        [switch]$ShowNextSteps,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$False)]
        [switch]$AddToRemoteHostAuthKeys,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUserName
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($AddToRemoteHostAuthKeys -and !$RemoteHost) {
        $RemoteHost = Read-Host -Prompt "Please enter an IP, FQDN, or DNS-resolvable Host Name that represents the Remote Host you would like to share your new public key with."
    }
    if ($RemoteHost -and !$AddToRemoteHostAuthKeys) {
        $AddToRemoteHostAuthKeys = $True
    }

    if ($RemoteHost) {
        try {
            $RemoteHostNetworkInfo = Resolve-Host -HostNameOrIP $RemoteHost -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($RemoteHost -or $AddToRemoteHostAuthKeys -and !$RemoteHostUserName) {
        $RemoteHostUserName = Read-Host -Prompt "Please enter a UserName that has access to $RemoteHost"
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path "$HOME\.ssh")) {
        $null = New-Item -Type Directory -Path "$HOME\.ssh"
    }

    $SSHKeyOutFile = "$HOME\.ssh\$NewSSHKeyName"
    if (!$NewSSHKeyPurpose) {
        $NewSSHKeyPurpose = "Default Purpose"
    }

    $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`" -C `"$NewSSHKeyPurpose`""
    $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -C `"$NewSSHKeyPurpose`""
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Create new public/private keypair
    if ($NewSSHKeyPwd) {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.WorkingDirectory = $OpenSSHWinPath
        $ProcessInfo.FileName = "ssh-keygen.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
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
            }
        }

        # Make private key password $null
        Import-Module Await
        if (!$?) {
            Write-Error "Unable to load the Await Module! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Start-AwaitSession
        Start-Sleep -Seconds 1
        Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$OpenSSHWinPath'"
        Start-Sleep -Seconds 1
        Send-AwaitCommand "ssh-keygen $SSHKeyGenArgumentsNoPwdString"
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
                Write-Verbose "The PSAwaitSession never spawned! Halting!"
                Write-Error "The PSAwaitSession never spawned! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Stop-Process -Id $PSAwaitProcess.Id
            }
        }
    }

    $PubPrivKeyPairFiles = Get-ChildItem -Path "$HOME\.ssh" | Where-Object {$_.Name -match "$NewSSHKeyName"}
    $PubKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

    if (!$PubKey -or !$PrivKey) {
        Write-Error "The New SSH Key Pair was NOT created! Check the output of the ssh-keygen.exe command below! Halting!"
        Write-Host ""
        Write-Host "##### BEGIN ssh-keygen Console Output From PSAwaitSession #####" -ForegroundColor Yellow
        Write-Host $SSHKeyGenConsoleOutput
        Write-Host "##### END ssh-keygen Console Output From PSAwaitSession #####" -ForegroundColor Yellow
        Write-Host ""
        $global:FunctionResult = "1"
        return
    }

    if ($AddToSSHAgent) {
        if ($(Get-Service ssh-agent).Status -ne "Running") {
            $SSHDErrMsg = "The ssh-agent service is NOT curently running! This means that $HOME\.ssh\$NewSSHKeyName.pub cannot be added" +
            " in order to authorize remote hosts to use it to allow ssh access to this local machine! Please ensure that the sshd service" +
            " is running and try adding the new public key again using 'ssh-add.exe $HOME\.ssh\$NewSSHKeyName.pub'"
            Write-Error $SSHDErrMsg
            $global:FunctionResult = "1"
            return
        }

        # Add the New Private Key to the ssh-agent
        $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHAddProcessInfo.WorkingDirectory = $OpenSSHWinPath
        $SSHAddProcessInfo.FileName = "ssh-add.exe"
        $SSHAddProcessInfo.RedirectStandardError = $true
        $SSHAddProcessInfo.RedirectStandardOutput = $true
        $SSHAddProcessInfo.UseShellExecute = $false
        $SSHAddProcessInfo.Arguments = "$($PrivKey.FullName)"
        $SSHAddProcess = New-Object System.Diagnostics.Process
        $SSHAddProcess.StartInfo = $SSHAddProcessInfo
        $SSHAddProcess.Start() | Out-Null
        $SSHAddProcess.WaitForExit()
        $SSHAddStdout = $SSHAddProcess.StandardOutput.ReadToEnd()
        $SSHAddStderr = $SSHAddProcess.StandardError.ReadToEnd()
        $SSHAddAllOutput = $SSHAddStdout + $SSHAddStderr
        
        if ($SSHAddAllOutput -match "fail|error") {
            Write-Error $SSHAddAllOutput
            Write-Error "The 'ssh-add $($PrivKey.FullName)' command failed!"
        }
        else {
            if ($RemovePrivateKey) {
                Remove-Item $PrivKey.FullName
            }
        }

        [System.Collections.ArrayList]$PublicKeysAccordingToSSHAgent = @()
        $(ssh-add -L) | foreach {
            $null = $PublicKeysAccordingToSSHAgent.Add($_)
        }
        $ThisPublicKeyAccordingToSSHAgent = $PublicKeysAccordingToSSHAgent | Where-Object {$_ -match "$NewSSHKeyName$"}
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToSSHAgent -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromSSHAgent = $($ThisPublicKeyAccordingToSSHAgent -split " ")[0..$ArrayPositionBeforeComment] -join " "

        $ThisPublicKeyAccordingToFile = Get-Content $PubKey.FullName
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToFile -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromFile = $($ThisPublicKeyAccordingToFile -split " ")[0..$ArrayPositionBeforeComment] -join " "

        if ($PublicKeySansCommentFromSSHAgent -ne $PublicKeySansCommentFromFile) {
            Write-Error "The public key according to the ssh-agent does NOT match the public key content in $($PubKey.FullName)! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "The Private Key $PublicKeyLocationFinal has been added to the ssh-agent service." -ForegroundColor Green
        if ($ShowNextSteps) {
            Get-PublicKeyAuthInstructions -PublicKeyLocation $PubKey.FullName -PrivateKeyLocation $PrivKey.FullName
        }
        
        if (!$RemovePrivateKey) {
            Write-Host "It is now safe to delete the private key (i.e. $($PrivKey.FullName)) since it has been added to the." -ForegroundColor Yellow
        }
    }
    else {
        if ($ShowNextSteps) {
            Get-PublicKeyAuthInstructions -PublicKeyLocation $PubKey.FullName -PrivateKeyLocation $PrivKey.FullName
        }
    }

    if ($AddToRemoteHostAuthKeys) {
        Add-PublicKeyToRemoteHost -PublicKeyPath $PubKey.FullName -RemoteHost $RemoteHostNetworkInfo.FQDN -RemoteHostUserName $RemoteHostUserName
        
        if (!$AddToSSHAgent) {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh -i $PubKey.FullName $RemoteHostUserName@$($RemoteHostNetworkInfo.FQDN)" -ForegroundColor Green
        }
        else {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh $RemoteHostUserName@$($RemoteHostNetworkInfo.FQDN)" -ForegroundColor Green
        }
    } 

    [pscustomobject]@{
        PublicKeyFilePath       = $PubKey.FullName
        PrivateKeyFilePath      = if (!$RemovePrivateKey) {$PrivKey.FullName} else {"PrivateKey was deleted after being added to the ssh-agent"}
        PublicKeyContent        = Get-Content "$HOME\.ssh\$NewSSHKeyName.pub"
    }

    ##### END Main Body #####

}

function Add-PublicKeyToRemoteHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PublicKeyPath,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostUserName
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Test-Path $PublicKeyPath)) {
        Write-Error "The path $PublicKeyPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $RemoteHostNetworkInfo = Resolve-Host -HostNameOrIP $RemoteHost -ErrorAction Stop
    }
    catch {
        Write-Error "Unable to resolve $RemoteHost! Halting!"
        $global:FunctionResult = "1"
        return
    }    
    
    if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find ssh.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PubKeyContent = Get-Content $PublicKeyPath

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    ssh $RemoteHostUserName@$($RemoteHostNetworkInfo.FQDN) "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"

    ##### END Main Body #####
}

function Fix-SSHPermissions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$HomeFolderAndSubItemsOnly,

        [Parameter(Mandatory=$False)]
        [switch]$OpenSSHWin64FolderAndSubItemsOnly
    )

    if ($(Get-Module -ListAvailable).Name -contains "NTFSSecurity") {
        if ($(Get-Module NTFSSecurity).Name -notcontains "NTFSSecurity") {
            $null = Import-Module NTFSSecurity
        }
    }
    else {    
        try {
            $null = Install-Module -Name NTFSSecurity
            $null = Import-Module NTFSSecurity
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$HomeFolderAndSubItemsOnly) {
        # Fix Permissions on C:\Program Files\OpenSSH-Win64 Directory ...
        $OpenSSHWin64DirSecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$env:ProgramFiles\OpenSSH-Win64"
        $OpenSSHWin64DirSecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $OpenSSHWin64DirSecurityDescriptor | Clear-NTFSAccess
        $OpenSSHWin64DirSecurityDescriptor | Enable-NTFSAccessInheritance
        $OpenSSHWin64DirSecurityDescriptor | Set-NTFSSecurityDescriptor

        # Fix Permissions on files that have their Permissions Inherited from C:\Program Files ...
        [System.Collections.ArrayList]$InheritedFromPF = @(
            "C:\Program Files\OpenSSH-Win64\FixHostFilePermissions.ps1"
            "C:\Program Files\OpenSSH-Win64\FixUserFilePermissions.ps1"
            "C:\Program Files\OpenSSH-Win64\install-sshd.ps1"
            "C:\Program Files\OpenSSH-Win64\libcrypto.dll"
            "C:\Program Files\OpenSSH-Win64\OpenSSHUtils.psd1"
            "C:\Program Files\OpenSSH-Win64\OpenSSHUtils.psm1"
            "C:\Program Files\OpenSSH-Win64\scp.exe"
            "C:\Program Files\OpenSSH-Win64\Set-SSHDefaultShell.ps1"
            "C:\Program Files\OpenSSH-Win64\sftp.exe"
            "C:\Program Files\OpenSSH-Win64\sftp-server.exe"
            "C:\Program Files\OpenSSH-Win64\ssh.exe"
            "C:\Program Files\OpenSSH-Win64\ssh-add.exe"
            "C:\Program Files\OpenSSH-Win64\ssh-agent.exe"
            "C:\Program Files\OpenSSH-Win64\sshd.exe"
            "C:\Program Files\OpenSSH-Win64\ssh-keygen.exe"
            "C:\Program Files\OpenSSH-Win64\ssh-keyscan.exe"
            "C:\Program Files\OpenSSH-Win64\ssh-shellhost.exe"
            "C:\Program Files\OpenSSH-Win64\uninstall-sshd.ps1"
        )

        foreach ($file in $InheritedFromPF) {
            if (Test-Path $file) {
                $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $file
                $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                $SecurityDescriptor | Clear-NTFSAccess
                $SecurityDescriptor | Enable-NTFSAccessInheritance
                $SecurityDescriptor | Set-NTFSSecurityDescriptor

                Remove-Variable -Name "SecurityDescriptor"
            }
        }

        # Fix Permissions on files and directory with explicit permissions
        # These files DO NOT inherit any permissions...
        [System.Collections.ArrayList]$ItemsWithPermsExplicitlyDefined = @(
            "C:\Program Files\OpenSSH-Win64\logs"
            "C:\Program Files\OpenSSH-Win64\ssh_host_dsa_key"
            "C:\Program Files\OpenSSH-Win64\ssh_host_dsa_key.pub"
            "C:\Program Files\OpenSSH-Win64\ssh_host_ecdsa_key"
            "C:\Program Files\OpenSSH-Win64\ssh_host_ecdsa_key.pub"
            "C:\Program Files\OpenSSH-Win64\ssh_host_ed25519_key"
            "C:\Program Files\OpenSSH-Win64\ssh_host_ed25519_key.pub"
            "C:\Program Files\OpenSSH-Win64\ssh_host_rsa_key"
            "C:\Program Files\OpenSSH-Win64\ssh_host_rsa_key.pub"
            "C:\Program Files\OpenSSH-Win64\sshd_config"
        )

        foreach ($item in $ItemsWithPermsExplicitlyDefined) {
            if (Test-Path $item) {
                $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $item
                $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                $SecurityDescriptor | Clear-NTFSAccess
                $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderOnly
                $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderOnly
                $SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "Read, Synchronize" -AppliesTo ThisFolderOnly
                $SecurityDescriptor | Set-NTFSSecurityDescriptor

                Remove-Variable -Name "SecurityDescriptor"
            }
        }

        # Finally, log files inherit from C:\Program Files\OpenSSH-Win64\logs
        $OpenSSHWin64LogFiles = $(Get-ChildItem "$env:ProgramFiles\OpenSSH-Win64\logs").FullName
        foreach ($item in $OpenSSHWin64LogFiles) {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $item
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Enable-NTFSAccessInheritance
            $SecurityDescriptor | Set-NTFSSecurityDescriptor

            Remove-Variable -Name "SecurityDescriptor"
        }
    }

    if (!$OpenSSHWin64FolderAndSubItemsOnly) {
        # Now, fix permissions on $HOME, $HOME/.ssh, and all files within $HOME/.ssh
        $HomePermissions = Get-NTFSAccess $HOME
        if ($HomePermissions.Account -notcontains "NT SERVICE\sshd" -or
        $($HomePermissions | Where-Object {$_.Account -eq "NT SERVICE\sshd"}).AccessRights -ne "ReadAndExecute, Synchronize"
        ) {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $HOME
            #$SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "Read, Synchronize" -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Set-NTFSSecurityDescriptor

            Remove-Variable -Name "SecurityDescriptor"
        }

        $HOMEDotSSHPermissions = Get-NTFSAccess "$HOME\.ssh"
        if ($HOMEDotSSHPermissions.Account -notcontains "NT SERVICE\sshd" -or
        $($HOMEDotSSHPermissions | Where-Object {$_.Account -eq "NT SERVICE\sshd"}).AccessRights -ne "ReadAndExecute, Synchronize"
        ) {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$HOME\.ssh"
            #$SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "Read, Synchronize" -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor

            Remove-Variable -Name "SecurityDescriptor"
        }

        $DotSSHFilesThatShouldInheritFromDotSSH = @("$HOME\.ssh\known_hosts","$HOME\.ssh\authorized_keys")
        foreach ($file in $DotSSHFilesThatShouldInheritFromDotSSH) {
            if (Test-Path $file) {
                $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $file
                $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                $SecurityDescriptor | Clear-NTFSAccess
                $SecurityDescriptor | Enable-NTFSAccessInheritance
                $SecurityDescriptor | Set-NTFSSecurityDescriptor

                Remove-Variable -Name "SecurityDescriptor"
            }
        }

        $PossiblePublicAndPrivateKeys = $(Get-ChildItem "$HOME\.ssh" -File | Where-Object {$_.Name -notmatch "known_hosts|authorized_keys"}).FullName
        [System.Collections.ArrayList]$PublicKeys = @()
        [System.collections.ArrayList]$PrivateKeys = @()
        foreach ($file in $PossiblePublicAndPrivateKeys) {
            $FileContent = Get-Content $file
            if ($FileContent.Count -eq 1 -and $FileContent.Length -gt 300) {
                $null = $PublicKeys.Add($file)
            }
            else {
                $null = $PrivateKeys.Add($file)
            }
        }

        foreach ($PubKey in $PublicKeys) {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $PubKey
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "Read" -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Set-NTFSSecurityDescriptor

            Remove-Variable -Name "SecurityDescriptor"
        }

        foreach ($PrivKey in $PrivateKeys) {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $PrivKey
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT SERVICE\sshd" -AccessRights "Read" -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Add-NTFSAccess -Account "$(whoami)" -AccessRights FullControl -AppliesTo ThisFolderOnly
            $SecurityDescriptor | Set-NTFSSecurityDescriptor

            Remove-Variable -Name "SecurityDescriptor"
        }
    }
}

function Get-PublicKeyAuthInstructions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PublicKeyLocation,

        [Parameter(Mandatory=$False)]
        [string]$PrivateKeyLocation
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($PublicKeyLocation) {
        $PublicKeyLocationFinal = $PublicKeyLocation
    }
    else {
        $PublicKeyLocationFinal = "SamplePubKey.pub"
    }
    if ($PrivateKeyLocation) {
        $PrivateKeyLocationFinal = $PrivateKeyLocation
    }
    else {
        $PrivateKeyLocationFinal = "SamplePrivKey"
    }

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Reference for below info:
    # https://github.com/PowerShell/Win32-OpenSSH/issues/815
    # https://github.com/PowerShell/Win32-OpenSSH/issues/409 

    $Headers1 = @"

##### INFORMATION #####
## WINDOWS TO LINUX PUBLIC KEY AUTH ##

"@

    $Info1 = @"
In order to SSH from this computer (i.e. $env:ComputerName) to a Remote Host WITHOUT the need for a password,
add the content of the RSA Public Key (i.e. $PublicKeyLocationFinal) to '~/.ssh/authorized_keys' on your Remote Linux Host.
Permissions on the ~/.ssh directory should be 700 and permissions on the ~/.ssh/authorized_keys file should be 644.
Check permissions with...

    stat -c "%a %n" ~/.ssh
    stat -c "%a %n" ~/.ssh/authorized_keys

...and change permissions with 'chmod'

"@

    $Headers2 = "## WINDOWS TO WINDOWS PUBLIC KEY AUTH ##`n"

    $Info2 = @"
If the Remote Host is a Windows machine running sshd, add the content of the RSA Public Key (i.e. $PublicKeyLocationFinal) to the
C:\Users\<User>\.ssh\authorized_keys file on your Remote Host. Permissions MUST be as follows...

    C:\Users\<User>\.ssh\authorized_keys
        Administrators      = Full Control
        SYSTEM              = Full Control
        NT SERVICE\sshd     = Read, Synchronize

    C:\Users\<User>\.ssh
        NT Service\sshd     = ReadAndExecute, Synchronize

    C:\Users\<User>
        NT Service\sshd     = ReadAndExecute, Synchronize

    NOTE #1: 'Read, Synchronize' translates to:
        'Read permissions'
        'Read attributes'
        'Read extended attributes'
        'List folder / read data'

    NOTE #2: 'ReadAndExecute, Synchronize' translates to:
        'Traverse folder / execute file'
        'Read permissions'
        'Read attributes'
        'Read extended attributes'
        'List folder / read data'

"@

    $ImportantNote1 = "If you need to fix permissions on any of the above on the Windows Remote Host, " +
    "the sshd service on the Remote Host must be restarted!`n"

    $ImportantNote2 = @"
The syntax for logging into a Remote Host with a Local Account available on the Remote Host is...

    ssh -i $PrivateKeyLocationFinal <RemoteHostUserName>@<RemoteHostNameOrFQDNOrIP>

...where $PrivateKeyLocationFinal is a private key file on the client and $PublicKeyLocationFinal is a public
key that has been added to .ssh/authorized_keys on the Remote Windows Host.

"@

    $ImportantNote3 = @"
If you would like to login to a Remote Windows Host using a Domain Account (as opposed to a Local
Account on the Remote Host), the syntax is...

    ssh -i $PrivateKeyLocationFinal -l <UserName>@<FullDomain> <RemoteHostName>.<FullDomain>

...where $PrivateKeyLocationFinal is a private key file on the client and $PublicKeyLocationFinal is a public
key that has been added to .ssh/authorized_keys on the Remote Windows Host.

"@

    Write-Host $Headers1 -ForegroundColor Yellow
    Write-Host $Info1
    Write-Host $Headers2 -ForegroundColor Yellow
    Write-Host $Info2
    Write-Host "IMPORTANT NOTE #1:" -ForegroundColor Yellow
    Write-Host $ImportantNote1
    Write-Host "IMPORTANT NOTE #2:" -ForegroundColor Yellow
    Write-Host $ImportantNote2
    Write-Host "IMPORTANT NOTE #3:" -ForegroundColor Yellow
    Write-Host $ImportantNote3
}

















































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9omDdiPS7L+3y0/pddZ99xiS
# 5Zegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFI+qjmCzJI2k31vG
# 3339S3XhpfdSMA0GCSqGSIb3DQEBAQUABIIBAE0RRKKFHmz0drPlPAoNYxLXDdqm
# 5Q+5yddwFb15KDxrhgbAN3JND+7mrmZJbyqF6bM+vmOQXaoXsttOfolrAiXlKAfU
# bukSGGR1EsJ3UZvtEZSNhzV6LDOyJQ+REiJeW8N7c+zfY0mvyqqEYUZHTQWS25P7
# 03DPDpXsNvLVVz/yN4pGR7y4cZPBo6Qr0oR/XR1XJBPMNBdVzAkVfePXHwK66q+z
# 6o0a9AzyxVpSUIYUKorfnod0GvalViXSzrY0RmJc3R8gVCC7Do0HPNiMnK3LcLzy
# 48WQtUra5JqK+6fEqwjvVly+DUx7w50RlNIn5mJc18m97Dx8XRjug/JdifU=
# SIG # End signature block
