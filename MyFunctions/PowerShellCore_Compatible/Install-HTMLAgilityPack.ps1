<#
.SYNOPSIS
    Downloads HTMLAgilityPack NuGet Package and loads it in the current PSSession

.DESCRIPTION
    See SYNOPSIS

.PARAMETER NuGetPkgDownloadPath
    MANDATORY

    This parameter takes a string that represents a full path to a directory that will contain the NuGet Package or a full path to the file .nupkg file.
    
    NOTE: If you use a full path to a file, any file extension other than .zip (like .nupkg) will be replaced with .zip

.EXAMPLE
    Install-HTMLAgilityPack -NuGetPkgDownloadPath "$HOME\Downloads\HTMLAgilityPack\HTMLAgilityPack.zip"

#>

function Install-HTMLAgilityPack {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory=$True)]
        [string]$NuGetPkgDownloadPath
    )

    ##### BEGIN Helper Functions #####

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
            $CheckMyCoreUtilsDownloadIsLoaded = $CurrentLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.Zip*"}
            if ($CheckMyCoreUtilsDownloadIsLoaded -eq $null) {
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

    function Invoke-WebRequestMyCoreUtilsDL {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$Uri,
    
            [Parameter(Mandatory=$True)]
            [string]$OutFile
        )
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        # Load MyCore.Utiles.Download
        $DefaultAssembliesToLoad = @("Microsoft.CSharp","System","System.Core","System.Linq","System.IO","System.IO.FileSystem"
        "System.Console","System.Collections","System.Collections.Generic","System.Runtime","System.Runtime.Extensions")
        
        [System.Collections.ArrayList]$AdditionalAssembliesToCheckFor = @("System.Net.Http","System.Threading.Tasks")
        
        $AssembliesToCheckFor = $DefaultAssembliesToLoad + $AdditionalAssembliesToCheckFor
        
        [System.Collections.ArrayList]$FoundAssemblies = @()
        [System.Collections.ArrayList]$FinalUsingStatements = @()
        foreach ($assem in $AssembliesToCheckFor) {
            $global:FunctionResult = 0
            
            $GetAssembliesResult = Get-Assemblies -AssemblyName $assem -ErrorAction SilentlyContinue
            
            if ($global:FunctionResult -eq 1) {
                Write-Verbose "The Get-Assemblies function failed for $assem!"
                $global:FunctionResult = "1"
                continue
            }
        
            $null = $FoundAssemblies.Add($GetAssembliesResult)
        
            $FinalUsingStatement = Get-AssemblyUsingStatement -AssemblyName $assem -AssemblyFullInfo $GetAssembliesResult.FullName -Silent -ErrorAction SilentlyContinue
            $null = $FinalUsingStatements.Add($FinalUsingStatement)
        }
        
        if ($FoundAssemblies.Count -eq 0) {
            Write-Error "Unable to find ANY Assmeblies! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($FinalUsingStatements.Count -eq 0) {
            Write-Error "Unable to create ANY 'using' statements! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $usingStatementsAsString = $($FinalUsingStatements | Sort-Object | Get-Unique) -join "`n"
        
        $ReferencedAssemblies = $FoundAssemblies.FullName | Sort-Object | Get-Unique
        
        # Using Type Extensions in PowerShell see: https://powershell.org/forums/topic/how-do-i-use-extension-methods-in-zipfileextensionsclass/
        
        $TypeDefinition = @"
        $usingStatementsAsString
        
        namespace MyCore.Utils
        { 
            public class Download
            {
                public static bool ValidateUrl(string p_strValue)
                {
                    if (Uri.IsWellFormedUriString(p_strValue, UriKind.RelativeOrAbsolute))
                    {
                        Uri l_strUri = new Uri(p_strValue);
                        return (l_strUri.Scheme == Uri.UriSchemeHttp || l_strUri.Scheme == Uri.UriSchemeHttps);
                    }
                    else
                    {
                        return false;
                    }
                }
        
                public async Task<bool> FileDownload(string url, string outputPath)
                {
                    // Declare some variables before the try/catch block
                    string exception = null;
                    bool isValidUrl = ValidateUrl(url);
                    string outputPathParentDir = System.IO.Directory.GetParent(outputPath).ToString();
        
                    try
                    {
                        if (!isValidUrl)
                        {
                            exception = "The Url" + url + "is not in the correct format! Halting!";
                            throw new InvalidOperationException(exception);
                        }
                        if (!System.IO.Directory.Exists(outputPathParentDir))
                        {
                            exception = "The directory" + outputPathParentDir + "does not exist! Halting!";
                            throw new InvalidOperationException(exception);
                        }
        
                        
                        var client = new HttpClient();
                        using (HttpResponseMessage response = client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).Result)
                        {
                            response.EnsureSuccessStatusCode();
                
                            using (Stream contentStream = await response.Content.ReadAsStreamAsync(), fileStream = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 8192, true))
                            {
                                var totalRead = 0L;
                                var totalReads = 0L;
                                var buffer = new byte[8192];
                                var isMoreToRead = true;
                
                                do
                                {
                                    var read = await contentStream.ReadAsync(buffer, 0, buffer.Length);
                                    if (read == 0)
                                    {
                                        isMoreToRead = false;
                                    }
                                    else
                                    {
                                        await fileStream.WriteAsync(buffer, 0, read);
                
                                        totalRead += read;
                                        totalReads += 1;
                
                                        if (totalReads % 2000 == 0)
                                        {
                                            Console.WriteLine(string.Format("total bytes downloaded so far: {0:n0}", totalRead));
                                        }
                                    }
                                }
                                while (isMoreToRead);
                            }
                        }
                        
                        return true;
                    }
                    catch
                    {
                        Console.WriteLine(exception);
                        return false;
                    }
                }
            }
        }
"@
        
        $CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
        $CheckMyCoreUtilsDownloadIsLoaded = $CurrentLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.Download*"}
        if ($CheckMyCoreUtilsDownloadIsLoaded -eq $null) {
            Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
        }
        else {
            Write-Warning "The namespace MyCore.Utils Class Download is already loaded!"
        }
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        ##### BEGIN Main Body #####
        
        # Download the file
        ([MyCore.Utils.Download]::new()).FileDownload($Uri,$OutFile)
    
        ##### END Main Body #####
    
    }

    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $HTMLAgilityPackUri = "https://www.nuget.org/api/v2/package/HTMLAgilityPack"
    try {
        $OutFileBaseNamePrep = Invoke-WebRequest $HTMLAgilityPackUri -DisableKeepAlive -UseBasicParsing
        $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
        $DllFileName = $OutFileBaseName -replace "zip","dll"
    }
    catch {
        $OutFileBaseName = "HTMLAgilityPack_LatestAsOf_$(Get-Date -Format MMddyy).zip"
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

            $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
        }
        else {
            if ($(Get-ChildItem $NuGetPkgDownloadPath).Count -ne 0) {
                $NewDir = "$NuGetPkgDownloadPath\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                $null = New-Item -ItemType Directory -Path $NewDir -Force
            }
            $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
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

            $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
        }
        else {
            if ($(Get-ChildItem $($NuGetPkgDownloadPath | Split-Path -Parent)).Count -ne 0) {
                $NewDir = "$($NuGetPkgDownloadPath | Split-Path -Parent)\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                $null = New-Item -ItemType Directory -Path $NewDir -Force
            }
            
            $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
        }
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $subdir = "lib\netstandard2.0"
    }
    else {
        $subdir = "lib\net45"
    }

    $NuGetPkgDownloadPathParentDir = $FinalNuGetPkgPath | Split-Path -Parent

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    
    ##### BEGIN Main Body #####
    # Download the NuGet Package
    Write-Host "Downloading HTMLAgilityPack NuGet Package to $FinalNuGetPkgPath..."
    Invoke-WebRequest -Uri $HTMLAgilityPackUri -OutFile $FinalNuGetPkgPath

    # Extract the appropriate assembly
    Write-Host "Extracting $subdir\HTMLAgilityPack.dll ..."
    Unzip-File -PathToZip $FinalNuGetPkgPath -TargetDir $NuGetPkgDownloadPathParentDir -SpecificItem "$subdir\HTMLAgilityPack.dll"
    
    $CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $CheckMyCoreUtilsDownloadIsLoaded = $CurrentLoadedAssemblies | Where-Object {$_.FullName -like "HtmlAgilityPack*"}
    if ($CheckMyCoreUtilsDownloadIsLoaded -eq $null) {
        Add-Type -Path "$NuGetPkgDownloadPathParentDir\HTMLAgilityPack.dll"
    }
    else {
        Write-Warning "The Assembly HTMLAgilityPack is already loaded!"
    }

    
    ##### END Main Body #####

}















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFUk8B3fb5aJ4+8mC+QywxMFw
# ivygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHai3CykmMYVwQIM
# v1TKVKCWTeFXMA0GCSqGSIb3DQEBAQUABIIBADSmuTceT1iKhgqxkcarFXAGTZnA
# 6xmPQ4DK1B4KniL5L9zznl3DTWznUQz2U7IxslMfpGQnsUcVBI4iviiK2OJ8PM6A
# G7w2E+pHvq+eRAA/dyucwpgTOrwgPVL1nSKyEpo6NsJl3mN/BcBGEtialca53JH8
# mjHvMzFJPJfk8HI/3iAOXaq7J3bPvGVhGQcyUxAABgFGuHGce/lNxC/7gngcHaBs
# iKvcleeeOvWc5o8QLS/mTperrxfyFIxh0NQbgLSx+ppMdp3xspUuADzGgxgiT9Er
# JgmRlNj9JAhDYwdxvBepKwdWDmwBTKkWT5MKXjadQg4OIbVx9klUzvQegpU=
# SIG # End signature block
