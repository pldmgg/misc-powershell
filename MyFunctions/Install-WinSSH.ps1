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
        [bool]$GiveWinSSHBinariesPathPriority = $True,

        [Parameter(Mandatory=$False)]
        [switch]$UsePackageManagement
     )

    ## BEGIN Native Helper Functions ##
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

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UsePackageManagement) {
        # Load and Run Update-PackageManagement function
        $UpdatePMString = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/PowerShellCore_Compatible/Update-PackageManagement.ps1"
        $UpdatePMScriptBlock = [scriptblock]::Create($UpdatePMString.Content)
        . $UpdatePMScriptBlock
        Update-PackageManagement -UseChocolatey
    }

    $LatestOpenSSHWin = Find-Package -Name OpenSSH -AllowPrereleaseVersions

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($UsePackageManagement) {
        try {
            $LatestOpenSSHWin | Install-Package -ErrorAction Stop

            if ($ConfigureSSHDOnLocalHost) {
                & "C:\Chocolatey\lib\openssh.$($LatestOpenSSHWin.Version)\tools\chocolateyinstall.ps1" -SSHServerFeature -SSHAgentFeature
            }
            else {
                "C:\Chocolatey\lib\openssh.$($LatestOpenSSHWin.Version)\tools\chocolateyinstall.ps1"
            }

            $OpenSSHWinPath = $(Get-ChildItem $env:ProgramFiles -Filter *OpenSSH* | Sort-Object -Property LastWriteTime)[-1].FullName
        }
        catch {
            Write-Error $_
            Write-Error "Installation of OpenSSH failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        $WinSSHFileNameSansExt = "OpenSSH-Win64"
        if ([version]$(Get-Item "$env:ProgramFiles\$WinSSHFileNameSansExt\ssh.exe").VersionInfo.ProductVersion -lt [version]$LatestOpenSSHWin.Version) {
            try {
                Write-Host "Downloading OpenSSH-Win64 from https://github.com/PowerShell/Win32-OpenSSH/releases/latest/..."
                $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()

                $WinOpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/$WinSSHFileNameSansExt.zip"
                Invoke-WebRequest -Uri $WinOpenSSHDLLink -OutFile "$HOME\Downloads\$WinSSHFileNameSansExt.zip"
                # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
                Unzip-File -PathToZip "$HOME\Downloads\$WinSSHFileNameSansExt.zip" -TargetDir "$HOME\Downloads"
                Move-Item "$HOME\Downloads\$WinSSHFileNameSansExt" "$env:ProgramFiles\$WinSSHFileNameSansExt"
                Enable-NTFSAccessInheritance -Path "$env:ProgramFiles\$WinSSHFileNameSansExt" -RemoveExplicitAccessRules

                $OpenSSHWinPath = "$env:ProgramFiles\$WinSSHFileNameSansExt"
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

    Write-Host "Installing $WinSSHFileNameSansExt to $OpenSSHWinPath"
    
    ##### Update :Path that is specific to the current PowerShell Session #####
    if ($GiveWinSSHBinariesPathPriority) {
        $env:Path = "$OpenSSHWinPath;$env:Path"
    }
    else {
        if ($env:Path[-1] -eq ";") {
            $env:Path = "$env:Path$OpenSSHWinPath"
        }
        else {
            $env:Path = "$env:Path;$OpenSSHWinPath"
        }
    }

    if ($ConfigureSSHDOnLocalHost) {
        $sshdConfigPath = "$OpenSSHWinPath\sshd_config"

        # Below comment block is only needed if we want the default shell on $env:ComputerName (i.e. the sshd server) to be PowerShell Core when another host remotes to it
        <#
        $sshdContent = Get-Content $sshdConfigPath
        $LineToReplace = $sshdContent | Where-Object {$_ -like "*sftp-server.exe*"}
        $UpdatedsshdContent = $sshdContent -replace "$LineToReplace","$LineToReplace`nSubsystem   powershell C:/Program Files/PowerShell/6.0.0-beta.3/powershell.exe $PowerShell6Path -sshs -NoLogo -NoProfile"
        Set-Content -Value $UpdatedsshdContent -Path $sshdConfigPath
        #>

        if (Test-Path "$OpenSSHWinPath\install-sshd.ps1") {
            & "$OpenSSHWinPath\install-sshd.ps1"
        }
        else {
            Write-Warning "The SSHD Service still needs to be configured!"
        }

        # Make sure port 22 is open
        if (!$(Test-Port -Port 22).Open) {
            # See if there's an existing rule regarding locahost TCP port 22
            $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
            if ($Existing22RuleCheck -ne $null) {
                $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
                if ($Existing22Rule -ne $null) {
                    Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
                }
                else {
                    $ExistingRuleFound = $False
                }
            }
            if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
                New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
            }
        }

        # Setup Host Keys
        Push-Location $OpenSSHWinPath

        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "ssh-keygen.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.WorkingDirectory = $pwd.Path
        $ProcessInfo.Arguments = "-A"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr
        
        $PubPrivKeyPairFiles = Get-ChildItem -Path "$OpenSSHWinPath" | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -like "*ssh_host*"}
        $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
        $PrivKeys = $PubPrivKeyPairFiles | foreach {if ($PubKeys -notcontains $_) {$_}}
        
        Start-Service ssh-agent

        Start-Sleep -Seconds 5

        if ($(Get-Service "ssh-agent").Status -ne "Running") {
            Write-Verbose "The ssh-agent service did not start succesfully! Halting!"
            Write-Error "The ssh-agent service did not start succesfully! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        foreach ($PrivKey in $PrivKeys) {
            ssh-add.exe $PrivKey.FullName

            if ($RemoveHostPrivateKeys) {
                Remove-Item $PrivKey
            }
        }

        Pop-Location

        Set-Service ssh-agent -StartupType Automatic

        Set-Service sshd -StartupType Automatic

        # IMPORTANT: It is important that File Permissions are "Fixed" at the end, otherwise previous steps break
        & "$OpenSSHWinPath\FixHostFilePermissions.ps1" -Confirm:$false

        Start-Service sshd

        Start-Sleep -Seconds 5

        if ($(Get-Service sshd).Status -ne "Running") {
            Write-Verbose "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
            Write-Error "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($NewSSHKeyName) {
        # Create new public/private keypair
        if (!$(Test-Path "$HOME\.ssh")) {
            New-Item -Type Directory -Path "$HOME\.ssh"
        }

        if ($NewSSHKeyPwd) {
            ssh-keygen.exe -t rsa -b 2048 -f "$HOME\.ssh\$NewSSHKeyName" -q -N "$NewSSHKeyPwd" -C "$NewSSHKeyPurpose"
        }
        else {
             # Need PowerShell Await Module (Windows version of Linux Expect) for ssh-keygen with null password
            if ($(Get-Module -ListAvailable).Name -notcontains "Await") {
                # Install-Module "Await" -Scope CurrentUser
                # Clone PoshAwait repo to .zip
                Invoke-WebRequest -Uri "https://github.com/pldmgg/PoshAwait/archive/master.zip" -OutFile "$HOME\PoshAwait.zip"
                $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                [IO.Directory]::CreateDirectory($tempDirectory)
                Unzip-File -PathToZip "$HOME\PoshAwait.zip" -TargetDir "$tempDirectory"
                if (!$(Test-Path "$HOME\Documents\WindowsPowerShell\Modules\Await")) {
                    New-Item -Type Directory "$HOME\Documents\WindowsPowerShell\Modules\Await"
                }
                Copy-Item -Recurse -Path "$tempDirectory\PoshAwait-master\*" -Destination "$HOME\Documents\WindowsPowerShell\Modules\Await"
                Remove-Item -Recurse -Path $tempDirectory -Force
            }

            # Make private key password $null
            Import-Module Await
            if (!$?) {
                Write-Verbose "Unable to load the Await Module! Halting!"
                Write-Error "Unable to load the Await Module! Halting!"
                $global:FunctionResult = "1"
                return
            }

            Start-AwaitSession
            Start-Sleep -Seconds 1
            Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            Send-AwaitCommand "ssh-keygen.exe -t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -C `"$NewSSHKeyPurpose`""
            Start-Sleep -Seconds 2
            Send-AwaitCommand ""
            Start-Sleep -Seconds 2
            Send-AwaitCommand ""
            Start-Sleep -Seconds 1
            $SSHKeyGenConsoleOutput = Receive-AwaitResponse
            Write-hOst ""
            Write-Host "##### BEGIN ssh-keygen Console Output From PSAwaitSession #####"
            Write-Host "$SSHKeyGenConsoleOutput"
            Write-Host "##### END ssh-keygen Console Output From PSAwaitSession #####"
            Write-Host ""
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

        if (!$(Test-Path "$HOME\.ssh\$NewSSHKeyName")) {
            Write-Verbose "The New SSH Key Pair was NOT created! Halting!"
            Write-Error "The New SSH Key Pair was NOT created! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Add the New Private Key to the ssh-agent
        ssh-add.exe "$HOME\.ssh\$NewSSHKeyName"

        Write-Host "Add the following RSA Public Key to ~/.ssh/authorized_keys on your linux host"
        Write-Host "$(Get-Content $HOME\.ssh\$NewSSHKeyName.pub)"
    }

    ##### END Main Body #####

}









# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcNMwKO0cxAkIHnGBXzSDC/xr
# 6qWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCCXH6PXjGsnUtN9
# V/j35Qo7PAEgMA0GCSqGSIb3DQEBAQUABIIBAEdkk20+fR5CFlVS5LjF/Stoylix
# FJJ8gvWhxXoryGZIXzkTzRn7zh0T2csaho3T+1N3HxjsnXbq4zhvI3QL5qz5wf/o
# 1At5aaoDrEXj4CCz4nAr0Y835pfFHQNYAdEJimg+WAxEczIedewxnBMF8BvVERxg
# AheQRQimfqymyVC2eZsbFN0JKEDDLZ3kyPCNr4mdUMNXqGvnq593cNnWaXctwRMI
# jYJit6jWIuYP9EzOxK/3/SYItd+3vp8cTHE06O9xeUfdTSoG/T6zFIqEYEf6Qhto
# yJP23AZmnKl//J+YID3assCTKGuXovWL36GmqNauwYHwTPQqIaknEGs7Hak=
# SIG # End signature block
