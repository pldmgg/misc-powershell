<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.NOTES
    DEPENDENCEIES
        Helper scripts/functions and/or binaries needed for the function to work.
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    $PubCertsLocationsArray = @(
        "C:\Certs\Testing\ZeroCode_Public_Cert.pem",
        "C:\Certs\Testing\ZeroDC01_Public_Cert.pem",
        "C:\Certs\Testing\ZeroSCA_Public_Cert.pem"
    )

    Create-PFXFromOpenSSLCerts -PrivateKeyFilePath "C:\Certs\Testing\ZeroCode_unprotected_private_key.pem" `
    -PubCerts $PubCertsLocationsArray `
    -OutputDirectory "C:\Certs\Testing"

.EXAMPLE
    $PubCertificates = "C:\Certs\Testing\ZeroCode_all_public_keys_in_chain.pem"

    Create-PFXFromOpenSSLCerts -PrivateKeyFilePath "C:\Certs\Testing\ZeroCode_unprotected_private_key.pem"`
    -PubCerts $PubCertificates`
    -OutputDirectory "C:\Certs\Testing"

.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>

function Create-PFXFromOpenSSLCerts {

    [CmdletBinding(
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PrivateKeyFilePath = $(Read-Host -Prompt "Please enter the full path to the private key file."),

        [Parameter(Mandatory=$False)]
        $PubCerts, # Can be a string that represents a file path or an array of strings that represent file paths.

        [Parameter(Mandatory=$False)]
        [string]$OutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written")
    )

    ##### REGION Helper Functions and Libraries #####

    ## BEGIN Native Helper Functions ##

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

    function Check-SameObject {
        [CmdletBinding()]
        Param( 
            [Parameter(
                Mandatory=$False,
                Position=1
            )]
            [string]$VariableName,

            [Parameter(
                Mandatory=$False,
                Position=1
            )]
            [int32]$HashCode
        )

        ##### BEGIN Parameter Validation #####

        if (!$VariableName -and !$HashCode) {
            Write-Verbose "You must use either the parameter `$VariableName or `$HashCode! Halting!"
            Write-Error "You must use either the parameter `$VariableName or `$HashCode! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($VariableName -and $HashCode) {
            Write-Verbose "Please use either the parameter `$VariableName or the parameter `$HashCode! Halting!"
            Write-Error "Please use either the parameter `$VariableName or the parameter `$HashCode! Halting!"
            $global:FunctionResult = "1"
            return
        }

        ##### END Parameter Validation #####

        if ($VariableName) {
            try {
                $HashCode = $(Get-Variable $VariableName -ValueOnly -ErrorAction Stop).GetHashCode()
            }
            catch {
                Write-Error "Variable $VariableName does not exist or does not have an associated HashCode"
            }
        }

        # Get Variables where the variable has a value, and HashCode the equals $HashCode, and does NOT have a name that matches $VariableName or 'HashCode'
        $VariableNameExclusionArray = @("$VariableName","HashCode")
        $SameObjects = Get-Variable | Where-Object {$_.Value -and $_.Value.GetHashCode() -eq $HashCode -and $_.Name -notin $VariableNameExclusionArray}
        $SameObjects
    }
    ## END Native Helper Functions ##

    ##### REGION END Helper Functions and Libraries #####


    ##### BEGIN Parameter Validation #####
    if (! $(Test-Path $PrivateKeyFilePath)) {
        Write-Verbose "The path $PrivateKeyFilePath was not found! Halting!"
        Write-Error "The path $PrivateKeyFilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($PubCerts -eq $null) {
        Write-Verbose "The parameter `$PubCerts was not provided! It requires string representing a file path or an array of file paths. Halting!"
        Write-Error "The parameter `$PubCerts was not provided! It requires string representing a file path or an array of file paths. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$($PubCerts.GetType().Name -eq "String" -or $PubCerts.GetType().BaseType.Name -eq "Array")) {
        Write-Verbose "The object passed to the parameter `$PubCerts must be a string or an array! Halting!"
        Write-Error "The object passed to the parameter `$PubCerts must be a string or an array! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PrivateKeyFileContent = Get-Content $PrivateKeyFilePath
    $PrivateKeyFileEncryptedCheck = $PrivateKeyFileContent | Select-String -Pattern "Encrypted"
    $PrivateKeyFileUnEncryptedCheck = $PrivateKeyFileContent | Select-String -Pattern "BEGIN RSA PRIVATE KEY"
    if ($PrivateKeyFileEncryptedCheck -or !$PrivateKeyFileUnEncryptedCheck) {
        $DecryptedPrivateKeyFilePath = $PrivateKeyFilePath -replace '\.','_Decrypted.'
        $tmpFileError = [IO.Path]::GetTempFileName()
        $tmpFileSuccess = [IO.Path]::GetTempFileName()
        
        & openssl.exe rsa -in $PrivateKeyFilePath -out $DecryptedPrivateKeyFilePath 2> $tmpFileError 1> $tmpFileSuccess
        
        $tmpFileErrorContent = Get-Content $tmpFileError
        $tmpFileSuccessContent = Get-Content $tmpFileStdOutOrSuccess

        Remove-Item -Path $tmpFileError -Force
        Remove-Item -Path $tmpFileSuccess -Force

        if ($tmpFileErrorContent -and !$tmpFileSuccessContent) {
            Write-Verbose "OpenSSL failed to decrypt $PrivateKeyFilePath! Please check your password and try again. Halting!"
            Write-Error "OpenSSL failed to decrypt $PrivateKeyFilePath! Please check your password and try again. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Check for Win32 or Win64 OpenSSL Binary
    if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        Write-Host "Downloading openssl.exe from https://indy.fulgan.com/SSL/..."
        $LatestWin64OpenSSLVer = $($($(Invoke-WebRequest -Uri https://indy.fulgan.com/SSL/).Links | Where-Object {$_.href -like "*[a-z]-x64*"}).href | Sort-Object)[-1]
        Invoke-WebRequest -Uri "https://indy.fulgan.com/SSL/$LatestWin64OpenSSLVer" -OutFile "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer"
        $SSLDownloadUnzipDir = $(Get-ChildItem "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer").BaseName
        if (! $(Test-Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir")) {
            New-Item -Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir" -ItemType Directory
        }
        Unzip-File -PathToZip "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer" -TargetDir "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
        # Add OpenSSL to $env:Path
        if ($env:Path[-1] -eq ";") {
            $env:Path = "$env:Path$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
        }
        else {
            $env:Path = "$env:Path;$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
        }
    }

    $pos = $PrivateKeyFilePath.LastIndexOf("\")
    $PrivKeyDir = $PrivateKeyFilePath.Substring(0, $pos)
    $PrivKeyFile = $PrivateKeyFilePath.Substring($pos+1)
    $PrivKeyFileName = $($PrivKeyFile -split '\.')[0]

    if ($PubCerts.Count -eq 1 -and $PubCerts.GetType().Name -eq "String") {
        if (! $(Test-Path $PubCerts)) {
            Write-Verbose "The path $PubCerts was not found! Halting!"
            Write-Error "The path $PubCerts was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $UpdatedPubCertFilePath = $PubCerts
    }
    
    $RegexLocalOrUNCPath = '^(([a-zA-Z]:\\)|(\\\\))(((?![<>:"/\\|?*]).)+((?<![ .])\\)?)*$'
    if ($PubCerts.Count -eq 1 -and $PubCerts.GetType().BaseType.Name -eq "Array") {
        $NameOfVariableInArray = Check-SameObject -HashCode "$($($PubCerts[0]).GetHashCode())" | Out-String
        if ($PubCerts[0].GetType().Name -ne "String") {
            Write-Warning "The object `"$NameofVariableInArray`" within the array `$PubCerts is not a string.  Attempting to convert to string..."

            try {
                $UpdatedPubCertFilePath = $PubCerts[0] | Out-String
            }
            catch {
                $ThrowError = $true
            }

            if ($ThrowError) {
                Write-Verbose "The object `"$NameofVariableInArray`" cannot be converted to a string! Halting!"
                Write-Error "The object `"$NameofVariableInArray`" cannot be converted to a string! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($UpdatedPubCertFilePath) {
                $PotentialPathsArray = $($UpdatedPubCertFilePath | Select-String -Pattern $RegexLocalOrUNCPath -AllMatches).Matches.Value
            }
        }
        if ($PubCerts[0].GetType().Name -eq "String") {
            $PotentialPathsArray = $($PubCerts[0] | Select-String -Pattern $RegexLocalOrUNCPath -AllMatches).Matches.Value
        }

        # Distill one or more strings that are valid paths from unknown object in index 0 of $PubCerts array
        $UpdatedPotentialPathsArray = foreach ($potentialpath in $PotentialPathsArray) {
            if ($([uri]$potentialpath).IsAbsoluteURI -and $($([uri]$potentialpath).IsLoopBack -or $([uri]$potentialpath).IsUnc)) {
                $potentialpath
            }
        }
        if ($UpdatedPotentialPathsArray -eq 1) {
            $UpdatedPubCertFilePath = $UpdatedPotentialPathsArray[0]
            if (! $(Test-Path $UpdatedPubCertFilePath)) {
                Write-Verbose "The path $PubCerts was not found! Halting!"
                Write-Error "The path $PubCerts was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($UpdatedPotentialPathsArray -gt 1) {
            $UpdatedPubCertFilePath = $UpdatedPotentialPathsArray
            foreach ($obj2 in $UpdatedPubCertFilePath) {
                if (! $(Test-Path $obj2)) {
                    Write-Verbose "The path $obj2 was not found! Halting!"
                    Write-Error "The path $obj2 was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($UpdatedPotentialPathsArray -lt 1) {
            Write-Verbose "Unable to distill valid file path from unexpected object $NameOfVariableInArray! Halting!"
            Write-Error "Unable to distill valid file path from unexpected object $NameOfVariableInArray! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($PubCerts.Count -gt 1 -and $PubCerts.GetType().BaseType.Name -eq "Array") {
        $UpdatedPubCertFilePath = @()
        foreach ($obj1 in $PubCerts) {
            $NameOfVariableInArray = Check-SameObject -HashCode "$($obj1.GetHashCode())" | Out-String
            if ($obj1.GetType().Name -ne "String") {
                Write-Warning "The object `"$NameofVariableInArray`" within the array `$PubCerts is not a string.  Attempting to convert to string..."

                try {
                    $UpdatedPubCertFilePath = $obj1 | Out-String
                }
                catch {
                    $ThrowError = $true
                }

                if ($ThrowError) {
                    Write-Verbose "The object `"$NameofVariableInArray`" cannot be converted to a string! Halting!"
                    Write-Error "The object `"$NameofVariableInArray`" cannot be converted to a string! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                if ($UpdatedPubCertFilePath) {
                    $PotentialPathsArray = $($UpdatedPubCertFilePath | Select-String -Pattern $RegexLocalOrUNCPath -AllMatches).Matches.Value
                }
            }
            if ($obj1.GetType().Name -eq "String") {
                $PotentialPathsArray = $($obj1 | Select-String -Pattern $RegexLocalOrUNCPath -AllMatches).Matches.Value
            }

            # Distill one or more strings that are valid paths from unknown object in index 0 of $PubCerts array
            $UpdatedPotentialPathsArray = foreach ($potentialpath in $PotentialPathsArray) {
                if ($([uri]$potentialpath).IsAbsoluteURI -and $($([uri]$potentialpath).IsLoopBack -or $([uri]$potentialpath).IsUnc)) {
                    $potentialpath
                }
            }
            if ($UpdatedPotentialPathsArray -eq 1) {
                $obj2 = $UpdatedPotentialPathsArray[0]
                if (! $(Test-Path $obj2)) {
                    Write-Verbose "The path $obj1 was not found!"
                    Write-Warning "The path $obj1 was not found!"
                    continue
                }
                $UpdatedPubCertFilePath += $obj2
            }
            if ($UpdatedPotentialPathsArray -gt 1) {
                foreach ($obj2 in $UpdatedPotentialPathsArray) {
                    if (! $(Test-Path $obj2)) {
                        Write-Verbose "The path $obj2 was not found! Halting!"
                        Write-Error "The path $obj2 was not found! Halting!"
                        continue
                    }
                    $UpdatedPubCertFilePath += $obj2
                }
            }
            if ($UpdatedPotentialPathsArray -lt 1) {
                Write-Verbose "Unable to distill valid file path from unexpected object $NameOfVariableInArray! Halting!"
                Write-Error "Unable to distill valid file path from unexpected object $NameOfVariableInArray! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($UpdatedPubCertFilePath -lt 1) {
            Write-Verbose "No valid file paths were found! Halting!"
            Write-Error "No valid file paths were found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Next, figure out where the private key is and whether it is password protected. If it is, strip it of its password.

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    if ($UpdatedPubCertFilePath.Count -eq 1) {
        $FriendlyName = $($($(certutil -dump $UpdatedPubCertFilePath) -join "`n" | Select-String "Subject:[\s]{1,20}CN=.*?[\s]").Matches.Value -split "=")[-1].Trim()
        $AllPubCertsFilePath = $UpdatedPubCertFilePath
    }
    if ($UpdatedPubCertFilePath.Count -gt 1) {
        $FriendlyName = foreach ($PubCertFile in $UpdatedPubCertFilePath) {
            $CertDumpContent = certutil -dump $PubCertFile

            $SubjectTypePrep = $CertDumpContent | Select-String -Pattern "Subject Type="
            if ($SubjectTypePrep) {
                $SubjectType = $SubjectTypePrep.Line.Split("=")[-1]
            }
            $RootCertFlag = $CertDumpContent | Select-String -Pattern "Subject matches issuer"

            if ($SubjectType -eq "CA" -and $RootCertFlag) {
                $RootCACert = $True
            }
            else {
                $RootCACert = $False
            }
            if ($SubjectType -eq "CA" -and !$RootCertFlag) {
                $IntermediateCACert = $True
            }
            else {
                $IntermediateCACert = $False
            }
            if ($RootCACert -eq $False -and $IntermediateCACert -eq $False) {
                $EndPointCert = $True
            }
            else {
                $EndPointCert = $False
            }

            if ($EndPointCert -eq $True) {
                $($($CertDumpContent -join "`n" | Select-String "Subject:[\s]{1,20}CN=.*?[\s]").Matches.Value -split "=")[-1].Trim()
            }
        }

        $AllPubCertsFilePath = "$OutputDirectory\$FriendlyName`_AllPubCerts.pem"
        if (Test-Path "$AllPubCertsFilePath") {
            Remove-Item "$AllPubCertsFilePath" -Force
        }
        foreach ($PubCertFile in $UpdatedPubCertFilePath) {
            $content = Get-Content $PubCertFile
            Add-Content -Path "$AllPubCertsFilePath" -Value $content
        }
    }
    if ($UpdatedPubCertFilePath -lt 1) {
        Write-Verbose "Unable to find public certificates! Halting!"
        Write-Error "Unable to find public certificates! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Create New PFX
    & openSSL.exe pkcs12 -export -in "$AllPubCertsFilePath" -inkey "$PrivateKeyFilePath" -name "$FriendlyName"-out "$OutputDirectory\$FriendlyName.pfx"

}


# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJyq44Us5CUH/ZFUckPfmrkiG
# ooSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLvYqSQTmZae772C
# vR0m0fzmLz8cMA0GCSqGSIb3DQEBAQUABIIBAJsmmnSGT91rccNxxNIjbiAUAd2n
# c1MtShWqgKRAxczWwojDQL9/eK7+q0SWT7//veC3nRn3eodRETq43RecL65fp50r
# Ip1WlL8x1UsU3i/SKBDkj08vTTAMe/qc3BJcXK+YM7OA+yIGwzFlvCPxQGHo+H9q
# RADTbx4Mp1ipO121RnrVnVF1jWz9wBvT+tcU6KWNgUtmr9z9kJUZFftyTFeY/wc7
# J2yn8BPrnxR1KL45hl5VfgDWk6iD52Mj0BX4MHuQyWYVbCMdRhudXolk1PQpjojP
# LDstnsMd1ojBh5mz20St2GTtN516hnQOeqRKCqCAXkmuvLIrtb+x2J7Z718=
# SIG # End signature block
