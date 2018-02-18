<#
.SYNOPSIS
    If a System.Security.Cryptography.X509Certificates.X509Certificate2 object has properties...
        HasPrivateKey        : True
        PrivateKey           :
    ...and you would like to get the System.Security.Cryptography.RSACryptoServiceProvider object that should be in
    the PrivateKey property, use this function.

.DESCRIPTION
    See SYNOPSIS

.NOTES
    Depends on Extract-PfxCerts and therefore depends on openssl.exe.

    NOTE: Nothing needs to be installed in order to use openssl.exe.

    IMPORTANT NOTE REGARDING -CertObject PARAMETER:
    If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
    *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
    private key in the .pfx is password protected.

    Instead, use the following:
        $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
        $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    
    If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
        $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
        $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

    WARNING: This function defaults to temporarily writing the unprotected private key to its own file in -TempOutputDirectory.
    The parameter -CleanupOpenSSLOutputs is set to $true by default, so the unprotected private key will only exist on the file
    system for a couple seconds.  If you would like to keep the unprotected private key on the file system, set the
    -CleanupOpenSSLOutputs parameter to $false.

.PARAMETER CertObject
    Mandatory.

    Must be a System.Security.Cryptography.X509Certificates.X509Certificate2 object.

    If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
    *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
    private key in the .pfx is password protected.

    Instead, use the following:
        $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
        $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    
    If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
        $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
        $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

.PARAMETER TempOutputDirectory
    Mandatory.

    Must be a full path to a directory. Punlic certificates and the private key within the -CertObject will *temporarily*
    be written to this directory as a result of the helper function Extract-PfxCerts.

.PARAMETER CertPwd
    Optional.

    This parameter must be a System.Security.SecureString.

    This parameter is Mandatory if the private key in the .pfx is password protected.

.PARAMETER CleanupOpenSSLOutputs
    Optional.

    Must be Boolean.

    During this function, openssl.exe is used to extract all public certs and the private key from the -CertObject. Each of these
    certs and the key are written to separate files in -TempOutputDirectory. This parameter removes these file outputs at the
    conclusion of the function. This parameter is set to $true by default.

.EXAMPLE
    # If the private key in the .pfx is password protected...
    PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
    Please enter the Certificate's Private Key password: ***************
    PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

.EXAMPLE
    # If the private key in the .pfx is NOT password protected...
    PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"

.EXAMPLE
    # Getting -CertObject from the Certificate Store where private key is password protected...
    PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
    Please enter the Certificate's Private Key password: ***************
    PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
    PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

.EXAMPLE
    # Getting -CertObject from the Certificate Store where private key is NOT password protected...
    PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
    PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"
#>
function Get-PrivateKeyProperty {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObject,

        [Parameter(Mandatory=$True)]
        $TempOutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [bool]$CleanupOpenSSLOutputs = $true,

        [Parameter(Mandatory=$False)]
        [switch]$DownloadAndAddOpenSSLToPath

    )

    ##### BEGIN Native Helper Functions ######

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
                        $null = New-Item -ItemType Directory -Path $NewAssemblyDir
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

    function Extract-PFXCerts {
        [CmdletBinding(
            PositionalBinding=$true,
            ConfirmImpact='Medium'
        )]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$PFXFilePath = $(Read-Host -Prompt "Please enter the full path to the .pfx file."),

            [Parameter(Mandatory=$False)]
            $PFXFilePwd, # This is only needed if the .pfx contains a password-protected private key, which should be the case 99% of the time

            [Parameter(Mandatory=$False)]
            [bool]$StripPrivateKeyPwd = $true,

            [Parameter(Mandatory=$False)]
            [string]$OutputDirectory, # If this parameter is left blank, all output files will be in the same directory as the original .pfx

            [Parameter(Mandatory=$False)]
            [switch]$DownloadAndAddOpenSSLToPath
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        # Check for Win32 or Win64 OpenSSL Binary
        if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
            if ($DownloadAndAddOpenSSLToPath) {
                Write-Host "Downloading openssl.exe from https://indy.fulgan.com/SSL/..."
                $LatestWin64OpenSSLVer = $($($(Invoke-WebRequest -Uri https://indy.fulgan.com/SSL/).Links | Where-Object {$_.href -like "*[a-z]-x64*"}).href | Sort-Object)[-1]
                Invoke-WebRequest -Uri "https://indy.fulgan.com/SSL/$LatestWin64OpenSSLVer" -OutFile "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer"
                $SSLDownloadUnzipDir = $(Get-ChildItem "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer").BaseName
                if (! $(Test-Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir")) {
                    $null = New-Item -Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir" -ItemType Directory
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
            else {
                Write-Verbose "The Extract-PFXCerts function requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
                Write-Error "The Extract-PFXCerts function requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
        if ($PFXFilePwd) {
            if ($PFXFilePwd.GetType().FullName -eq "System.Security.SecureString") {
                $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXFilePwd))
            }
            if ($PFXFilePwd.GetType().FullName -eq "System.String") {
                $PwdForPFXOpenSSL = $PFXFilePwd
            }
        }

        $privpos = $PFXFilePath.LastIndexOf("\")
        $PFXFileDir = $PFXFilePath.Substring(0, $privpos)
        $PFXFileName = $PFXFilePath.Substring($privpos+1)
        $PFXFileNameSansExt = $($PFXFileName.Split("."))[0]

        if (!$OutputDirectory) {
            $OutputDirectory = $PFXFileDir
        }

        $ProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_protected_private_key"+".pem"
        $UnProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_unprotected_private_key"+".pem"
        $AllPublicKeysInChainOut = "$PFXFileNameSansExt"+"_all_public_keys_in_chain"+".pem"
        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Parameter Validation #####
        if (!$(Test-Path $PFXFilePath)) {
            Write-Verbose "The path $PFXFilePath was not found! Halting!"
            Write-Error "The path $PFXFilePath was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (! $(Test-Path $OutputDirectory)) {
            Write-Verbose "The path $OutputDirectory was not found! Halting!"
            Write-Error "The path $OutputDirectory was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        ##### END Parameter Validation #####


        ##### BEGIN Main Body #####
        # The .pfx File could (and most likely does) contain a private key
        # Extract Private Key and Keep It Password Protected
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:$PwdForPFXOpenSSL"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
                throw
            }
        }
        catch {
            try {
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                $ProcessInfo.FileName = "openssl.exe"
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:"
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                $Process.WaitForExit()
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr

                if ($AllOutput -match "error") {
                    Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                    throw
                }
            }
            catch {
                $PFXFilePwdFailure = $true
            }
        }
        if ($PFXFilePwdFailure -eq $true) {
            Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
            Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
            $global:FunctionResult = "1"
            return
        }
        

        if ($StripPrivateKeyPwd) {
            # Strip Private Key of Password
            & openssl.exe rsa -in "$PFXFileDir\$ProtectedPrivateKeyOut" -out "$OutputDirectory\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
        }

        New-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -Value $(
            if ($StripPrivateKeyPwd) {
                [pscustomobject][ordered]@{
                    ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                    UnProtectedPrivateKeyFilePath   = "$OutputDirectory\$UnProtectedPrivateKeyOut"
                }
            }
            else {
                [pscustomobject][ordered]@{
                    ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                    UnProtectedPrivateKeyFilePath   = $null
                }
            }
        )
        

        # Setup $ArrayOfPubCertPSObjects for PSCustomObject Collection
        $ArrayOfPubCertPSObjects = @()
        # The .pfx File Also Contains ALL Public Certificates in Chain 
        # The below extracts ALL Public Certificates in Chain
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:$PwdForPFXOpenSSL"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
                throw
            }
        }
        catch {
            try {
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                $ProcessInfo.FileName = "openssl.exe"
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:"
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                $Process.WaitForExit()
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr

                if ($AllOutput -match "error") {
                    Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                    throw
                }
            }
            catch {
                $PFXFilePwdFailure = $true
            }
        }
        if ($PFXFilePwdFailure -eq $true) {
            Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
            Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
            $global:FunctionResult = "1"
            return
        }
        New-Variable -Name "CertObj$PFXFileNameSansExt" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                CertName                = "$PFXFileNameSansExt`AllPublicKCertsInChain"
                AllCertInfo             = Get-Content "$OutputDirectory\$AllPublicKeysInChainOut"
                FileLocation            = "$OutputDirectory\$AllPublicKeysInChainOut"
            }
        ) -Force

        $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$PFXFileNameSansExt" -ValueOnly)


        # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
        # These files should have the EXACT SAME CONTENT as the .cer counterparts
        $PublicKeySansChainPrep1 = $(Get-Content "$OutputDirectory\$AllPublicKeysInChainOut") -join "`n"
        $PublicKeySansChainPrep2 = $($PublicKeySansChainPrep1 -replace "-----END CERTIFICATE-----","-----END CERTIFICATE-----;;;").Split(";;;")
        $PublicKeySansChainPrep3 = foreach ($obj1 in $PublicKeySansChainPrep2) {
            if ($obj1 -like "*[\w]*") {
                $obj1.Trim()
            }
        }
        # Setup PSObject for Certs with CertName and CertValue
        foreach ($obj1 in $PublicKeySansChainPrep3) {
            $CertNamePrep = $($obj1).Split("`n") | foreach {if ($_ | Select-String "subject") {$_}}
            $CertName = $($CertNamePrep | Select-String "CN=([\w]|[\W]){1,1000}$").Matches.Value -replace "CN=",""
            $IndexNumberForBeginCert = $obj1.Split("`n") | foreach {
                if ($_ -match "-----BEGIN CERTIFICATE-----") {
                    [array]::indexof($($obj1.Split("`n")),$_)
                }
            }
            $IndexNumberForEndCert = $obj1.Split("`n") | foreach {
                if ($_ -match "-----End CERTIFICATE-----") {
                    [array]::indexof($($obj1.Split("`n")),$_)
                }
            }
            $CertValue = $($($obj1.Split("`n"))[$IndexNumberForBeginCert..$IndexNumberForEndCert] | Out-String).Trim()
            $AttribFriendlyNamePrep = $obj1.Split("`n") | Select-String "friendlyName"
            if ($AttribFriendlyNamePrep) {
                $AttribFriendlyName = $($AttribFriendlyNamePrep.Line).Split(":")[-1].Trim()
            }
            $tmpFile = [IO.Path]::GetTempFileName()
            $CertValue.Trim() | Out-File $tmpFile -Encoding Ascii

            $CertDumpContent = certutil -dump $tmpfile

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

            New-Variable -Name "CertObj$CertName" -Scope Script -Value $(
                [pscustomobject][ordered]@{
                    CertName                = $CertName
                    FriendlyName            = $AttribFriendlyName
                    CertValue               = $CertValue.Trim()
                    AllCertInfo             = $obj1.Trim()
                    RootCACert              = $RootCACert
                    IntermediateCACert      = $IntermediateCACert
                    EndPointCert            = $EndPointCert
                    FileLocation            = "$OutputDirectory\$($CertName)_Public_Cert.pem"
                }
            ) -Force

            $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$CertName" -ValueOnly)

            Remove-Item -Path $tmpFile -Force
            Remove-Variable -Name "tmpFile" -Force
        }

        # Write each CertValue to Separate Files (i.e. writing all public keys in chain to separate files)
        foreach ($obj1 in $ArrayOfPubCertPSObjects) {
            if ($(Test-Path $obj1.FileLocation) -and !$Force) {
                Write-Verbose "The extracted Public cert $($obj1.CertName) was NOT written to $OutputDirectory because it already exists there!"
            }
            if (!$(Test-Path $obj1.FileLocation) -or $Force) {
                $obj1.CertValue | Out-File "$($obj1.FileLocation)" -Encoding Ascii
                Write-Verbose "Public certs have been extracted and written to $OutputDirectory"
            }
        }

        New-Variable -Name "PubAndPrivInfoOutput" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                PublicKeysInfo      = $ArrayOfPubCertPSObjects
                PrivateKeyInfo      = $(Get-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -ValueOnly)
            }
        ) -Force

        $(Get-Variable -Name "PubAndPrivInfoOutput" -ValueOnly)
        
        $global:FunctionResult = "0"
        ##### END Main Body #####

    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($CertObject.PrivateKey -eq $null -and $CertObject.HasPrivateKey -eq $false -or $CertObject.HasPrivateKey -ne $true) {
        Write-Verbose "There is no Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object (for real though)! Halting!"
        Write-Error "There is no Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object (for real though)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        if (!$DownloadAndAddOpenSSLToPath) {
            Write-Verbose "The Helper Function Extract-PFXCerts requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            Write-Error "The Helper Function Extract-PFXCerts requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $CertName = $($CertObject.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
    try {
        $pfxbytes = $CertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        [System.IO.File]::WriteAllBytes("$TempOutputDirectory\$CertName.pfx", $pfxbytes)
    }
    catch {
        Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Trying to import `$CertObject to Cert:\LocalMachine\My Store..."
        # NOTE: The $CertObject.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
        
        # Check to see if it's already in the Cert:\LocalMachine\My Store
        if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $CertObject.Thumbprint) {
            Write-Host "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
        }
        else {
            Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
            $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $X509Store.Add($CertObject)
        }

        Write-Host "Attempting to export `$CertObject from Cert:\LocalMachine\My Store to .pfx file..."

        if (!$CertPwd) {
            $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
        }

        $null = Export-PfxCertificate -FilePath "$TempOutputDirectory\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($CertObject.Thumbprint)" -Password $CertPwd

    }

    # NOTE: If openssl.exe isn't already available, the Extract-PFXCerts function downloads it and adds it to $env:Path
    if ($CertPwd) {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -PFXFilePwd $CertPwd -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }
    else {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath -eq $null) {
        # Strip Private Key of Password
        $UnProtectedPrivateKeyOut = "$($(Get-ChildItem $PathToCertFile).BaseName)"+"_unprotected_private_key"+".pem"
        & openssl.exe rsa -in $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath -out "$HOME\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
        $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath = "$HOME\$UnProtectedPrivateKeyOut"
    }

    #Write-Host "Loading opensslkey.cs from https://github.com/sushihangover/SushiHangover-PowerShell/blob/master/modules/SushiHangover-RSACrypto/opensslkey.cs"
    $opensslkeysource = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sushihangover/SushiHangover-PowerShell/master/modules/SushiHangover-RSACrypto/opensslkey.cs").Content
    try {
        Add-Type -TypeDefinition $opensslkeysource
    }
    catch {
        if ($_.Exception -match "already exists") {
            Write-Verbose "The JavaScience.Win32 assembly (i.e. opensslkey.cs) is already loaded. Continuing..."
        }
    }
    $PemText = [System.IO.File]::ReadAllText($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath)
    $PemPrivateKey = [javascience.opensslkey]::DecodeOpenSSLPrivateKey($PemText)
    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = [javascience.opensslkey]::DecodeRSAPrivateKey($PemPrivateKey)
    $RSA

    # Cleanup
    if ($CleanupOpenSSLOutputs) {
        $ItemsToRemove = @(
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath
        ) + $global:PubCertAndPrivKeyInfo.PublicKeysInfo.FileLocation

        foreach ($item in $ItemsToRemove) {
            Remove-Item $item
        }
    }

    ##### END Main Body #####

}
















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUg/JucKJb+ygVzX9awn4y07gv
# w7ugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFK22zF2YXtcEeccT
# F9ojsRsDJY80MA0GCSqGSIb3DQEBAQUABIIBAL0uvlsxvlBqw91/RYwh5lZ6/fpu
# eZsG3aUu3uLvTpmsoQiLNXNJIqr3a3NmAR3Gt15OzBWAT3Vc9bdxk/nkhOlJOGn9
# Weefmqygde8Hh0o+J77tFbYhKWoZ+vpVP8FVMYd9E+WF7AFIS/Lkejwa14fJyv5e
# TQEBzkvVjh5UL8nEAwEny60sdJHNNQhM/3qeQrSfH+Pwn9hTzBlBhsc+iAg5U1q4
# Sn1ZodONW/K6lLedzUHGXuTRBZZz/lqkZI4uIrMCnLQYcUpg2O3y5l+EO9kVE3xg
# QArWky6uFzccKy9bBAAV6YfjUgOnrBTppOb7OmF8QnBFDDg5uEJLSKjZ9V4=
# SIG # End signature block
