# References:
# https://github.com/sushihangover/SushiHangover-PowerShell/tree/master/modules/SushiHangover-RSACrypto
# http://www.jensign.com/opensslkey/index.html
# https://stackoverflow.com/questions/1496793/rsa-encryption-getting-bad-length
# http://www.technical-recipes.com/2013/using-rsa-to-encrypt-large-data-files-in-c/
# http://www.obviex.com/samples/Encryption.aspx
# https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
# https://blog.kloud.com.au/2016/04/21/using-saved-credentials-securely-in-powershell-scripts/ # Not used, but good info

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

# Adds -password parameter to normal Get-PFXCertificate so that you can provide in advance and avoid prompt
function Get-PfxCertificateBetter {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Position=0, Mandatory=$true, ParameterSetName='ByPath')] [string[]] $filePath,
        [Parameter(Mandatory=$true, ParameterSetName='ByLiteralPath')] [string[]] $literalPath,

        [Parameter(Position=1, ParameterSetName='ByPath')] 
        [Parameter(Position=1, ParameterSetName='ByLiteralPath')] [string] $password,

        [Parameter(Position=2, ParameterSetName='ByPath')]
        [Parameter(Position=2, ParameterSetName='ByLiteralPath')] [string] 
        [ValidateSet('DefaultKeySet','Exportable','MachineKeySet','PersistKeySet','UserKeySet','UserProtected')] $x509KeyStorageFlag = 'DefaultKeySet'
    )

    if($PsCmdlet.ParameterSetName -eq 'ByPath'){
        $literalPath = Resolve-Path $filePath 
    }

    if(!$password){
        # if the password parameter isn't present, just use the original cmdlet
        $cert = Get-PfxCertificate -literalPath $literalPath
    } else {
        # otherwise use the .NET implementation
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($literalPath, $password, $X509KeyStorageFlag)
    }

    return $cert
}

<#
.SYNOPSIS
    This function uses openssl.exe to extract all public certificates and private key from a .pfx file. Each public certificate
    and the private key is written to its own separate file in the specified. OutputDirectory. If openssl.exe is not available
    on the current system, it is downloaded to the Current User's Downloads folder and added to $env:Path.

    NOTE: Nothing is installed.

.DESCRIPTION
    See SYNOPSIS.

.NOTES
    Depends on openssl.exe.

    NOTE: Nothing needs to be installed in order to use openssl.exe.

.PARAMETER PFXFilePath
    Mandatory.

    This parameter takes a string that represents the full path to a .pfx file

.PARAMETER PFXFilePwd
    Optional.

    This parameter takes a string (i.e. plain text password) or a secure string.

    If the private key in the .pfx file is password protected, use this parameter.

.PARAMETER StripPrivateKeyPwd
    Optional.

    This parameter takes a boolean $true or $false.

    By default, this function writes the private key within the .pfx to a file in a protected format, i.e.
        -----BEGIN PRIVATE KEY-----
        -----END PRIVATE KEY-----

    If you set this parameter to $true, then this function will ALSO (in addition to writing out the above protected
    format to its own file) write the unprotected private key to its own file with format
        -----BEGIN RSA PRIVATE KEY----
        -----END RSA PRIVATE KEY----

    WARNING: This parameter is set to $true by default.

.PARAMETER OutputDirectory
    Optional.

    This parameter takes a string that represents a file path to a *directory* that will contain all file outputs.

    If this parameter is not used, all file outputs are written to the same directory as the .pfx file.

.PARAMETER DownloadAndAddOpenSSLToPath
    Optional.

    This parameter downloads openssl.exe from https://indy.fulgan.com/SSL/ to the current user's Downloads folder,
    and adds openssl.exe to $env:Path.

    WARNING: If openssl.exe is not already part of your $env:Path prior to running this function, this parameter
    becomes MANDATORY, or the function will fail.

.EXAMPLE
    # If your private key is password protected...
    $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
    $PFXSigningPwdAsSecureString = Read-Host -Prompt "Please enter the private key's password" -AsSecureString
    $OutDir = "C:\Certs\Testing2"

    Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
    -PFXFilePwd $PFXSigningPwdAsSecureString `
    -StripPrivateKeyPwd $true `
    -OutputDirectory $OutDir

.EXAMPLE
    # If your private key is NOT password protected...
    $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
    $OutputDirectory = "C:\Certs\Testing2"

    Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
    -StripPrivateKeyPwd $true `
    -OutputDirectory $OutDir
#>
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

        Export-PfxCertificate -FilePath "$TempOutputDirectory\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($CertObject.Thumbprint)" -Password $CertPwd

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
    #$opensslkeysource = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sushihangover/SushiHangover-PowerShell/master/modules/SushiHangover-RSACrypto/opensslkey.cs").Content
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


<#
.SYNOPSIS 
Generates a random AES key.

.DESCRIPTION
Generates a random AES key based on the desired key size.

.PARAMETER KeySize
Number of bits the generated key will have.

.EXAMPLE

$key = Create-AESKey

This example generates a random 256-bit AES key and stores it in the variable $key.

.NOTES
Author: Tyler Siegrist
Date: 8/23/2016
https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
function Create-AESKey() {
    Param(
       [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
       [Int]$KeySize=256
    )

    try {
        $AESProvider = New-Object "System.Security.Cryptography.AesManaged"
        $AESProvider.KeySize = $KeySize
        $AESProvider.GenerateKey()
        return [System.Convert]::ToBase64String($AESProvider.Key)
    }
    catch {
        Write-Error $_
    }
}

<#
.SYNOPSIS 
Encrypts a file using AES.

.DESCRIPTION
Encrypts a file using an AES key.

.PARAMETER FileToEncrypt
File(s) to be encrypted

.PARAMETER Key
AES key to be used for encryption.

.EXAMPLE

$key = Create-AESKey
Encrypt-File 'C:\file.ext' $key

This example encrypts C:\file.ext with the key stored in the variable $key.

.NOTES
Author: Tyler Siegrist
Date: 8/23/2016
https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
Function Encrypt-File {
    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToEncrypt,
       [Parameter(Mandatory=$true, Position=2)]
       [String]$Key,
       [Parameter(Mandatory=$false, Position=3)]
       [String]$Suffix
    )

    #Load dependencies
    try {
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
    }
    catch {
        Write-Error 'Could not load required assembly.'
        Return
    }

    #Configure AES
    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        $KeySize = $EncryptionKey.Length*8
        $AESProvider = New-Object 'System.Security.Cryptography.AesManaged'
        $AESProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESProvider.BlockSize = 128
        $AESProvider.KeySize = $KeySize
        $AESProvider.Key = $EncryptionKey
    }
    catch {
        Write-Error 'Unable to configure AES, verify you are using a valid key.'
        Return
    }

    Write-Verbose "Encryping $($FileToEncrypt.Count) File(s) with the $KeySize-bit key $Key"

    #Used to store successfully encrypted file names.
    $EncryptedFiles = @()
    
    foreach ($File in $FileToEncrypt) {
        <#
        if ($File.Name.EndsWith($Suffix)) {
            Write-Error "$($File.FullName) already has a suffix of '$Suffix'."
            Continue
        }
        #>

        #Open file to encrypt
        try {
            $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
        }
        catch {
            Write-Error "Unable to open $($File.FullName) for reading."
            Continue
        }

        #Create destination file
        $DestinationFile = "$($File.FullName).aesencrypted"
        try {
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
        }
        catch {
            Write-Error "Unable to open $DestinationFile for writing."
            $FileStreamReader.Close()
            Continue
        }
    
        #Write IV length & IV to encrypted file
        $AESProvider.GenerateIV()
        $FileStreamWriter.Write([System.BitConverter]::GetBytes($AESProvider.IV.Length), 0, 4)
        $FileStreamWriter.Write($AESProvider.IV, 0, $AESProvider.IV.Length)

        Write-Verbose "Encrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        #Encrypt file
        try {
            $Transform = $AESProvider.CreateEncryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            do {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            while ($Count -gt 0)
    
            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()

            #Delete unencrypted file
            Remove-Item $File.FullName
            Write-Verbose "Successfully encrypted $($File.FullName)"
            $EncryptedFiles += $DestinationFile
        }
        catch {
            Write-Error "Failed to encrypt $($File.FullName)."
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $DestinationFile
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesEncryptedwAESKey -Value $EncryptedFiles
    return $Result
}

<#
.SYNOPSIS 
Decrypts a file using AES.

.DESCRIPTION
Decrypts a file using an AES key.

.PARAMETER FileToDecrypt
File(s) to be decrypted

.PARAMETER Key
AES key to be used for decryption.

.EXAMPLE

Decrypt-File 'C:\file.ext.encrypted' $key

This example decrypts C:\file.ext.encrypted with the key stored in the variable $key.

.NOTES
Author: Tyler Siegrist
Date: 8/23/2016
https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
Function Decrypt-File {
    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToDecrypt,
       [Parameter(Mandatory=$true, Position=2)]
       [String]$Key,
       [Parameter(Mandatory=$false, Position=3)]
       [String]$Suffix
    )
 
    #Load dependencies
    try {
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
    }
    catch {
        Write-Error 'Could not load required assembly.'
        Return
    }

    #Configure AES
    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        $KeySize = $EncryptionKey.Length*8
        $AESProvider = New-Object 'System.Security.Cryptography.AesManaged'
        $AESProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESProvider.BlockSize = 128
        $AESProvider.KeySize = $KeySize
        $AESProvider.Key = $EncryptionKey
    }
    catch {
        Write-Error 'Unable to configure AES, verify you are using a valid key.'
        Return
    }

    Write-Verbose "Encryping $($FileToDecrypt.Count) File(s) with the $KeySize-bit key $Key"

    #Used to store successfully decrypted file names.
    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()

    foreach ($File in $FileToDecrypt) {
        #Verify filename
        <#
        if(-not $File.Name.EndsWith($Suffix)) {
            Write-Error "$($File.FullName) does not have an extension of '$Suffix'."
            Continue
        }
        #>

        #Open file to decrypt
        try {
            $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
        }
        catch {
            Write-Error "Unable to open $($File.FullName) for reading."
            Continue
        }
    
        #Create destination file
        $DestinationFile = "$($File.FullName).decrypted"
        try {
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
        }
        catch {
            Write-Error "Unable to open $DestinationFile for writing."
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            Remove-Item $DestinationFile -Force
            Continue
        }

        #Get IV
        try {
            [Byte[]]$LenIV = New-Object Byte[] 4
            $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($LenIV,  0, 3) | Out-Null
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0)
            [Byte[]]$IV = New-Object Byte[] $LIV
            $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
            $FileStreamReader.Read($IV, 0, $LIV) | Out-Null
            $AESProvider.IV = $IV
        }
        catch {
            Write-Warning "Unable to read IV from $($File.FullName), verify this file was made using the included Encrypt-File function."
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            Remove-Item $DestinationFile -Force
            $FailedToDecryptFiles += $File
            Continue
        }

        Write-Verbose "Decrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        #Decrypt
        try {
            $Transform = $AESProvider.CreateDecryptor()
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            Do
            {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            While ($Count -gt 0)

            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()

            #Delete encrypted file
            Remove-Item $File.FullName
            Write-Verbose "Successfully decrypted $($File.FullName)"
            $DecryptedFiles += $DestinationFile
        }
        catch {
            Write-Error "Failed to decrypt $($File.FullName)."
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $DestinationFile
            $FailedToDecryptFiles += $File
        }        
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesDecryptedwAESKey -Value $DecryptedFiles
    $Result | Add-Member -MemberType NoteProperty -Name FilesFailedToDecrypt -Value $FailedToDecryptFiles
    return $Result
}


<#
.SYNOPSIS
    This function can encrypt a String, Array of Strings, File, or Files in a Directory. Strings and Arrays of Strings passed
    to the -ContentToEncrypt parameter are written to their own separate encrypted files on the file system. Encrypting one or
    more Files creates a NEW encrypted version of the original File(s). It DOES NOT TOUCH the original unencrypted File(s).

.DESCRIPTION
    See SYNOPSIS.

.NOTES
    Please use this function responsibly.

    IMPORTANT NOTE #1:
    The Certificate used for RSA Encryption is written out (in .pfx format) to the same directory as the encrypted
    file outputs. If AES encryption is needed for larger Files, the RSA-encrypted AES Key is written to the same directory
    as the encrypted file outputs.

    You will ALWAYS need a private key from your Certificate's public/private pair in order to decrypt content
    encrypted via this function. You will be able to get this private key from the .pfx file that you provide
    to the -PathToCertFile parameter, or from the Certificate in the Cert:\LocalMachine\My store that you provide
    to the -CNofCertInStore parameter of this function.

    You will SOMETIMES need the AES Key to decrypt larger files that were encrypted using AES encryption.

    IMPORTANT NOTE #2:
    It is up to you to store the public/private key pair and the RSA-encrypted AES Key appropriately.

    Note that the public/private key pair will be found EITHER in a .pfx file in the same directory as encrypted
    file outputs OR in Cert:\LocalMachine\My OR in BOTH locations. Note that the RSA-encrypted AES Key will be
    found in a file in the same directory as encrypted file outputs.

.PARAMETER ContentType
    Optional, but HIGHLY recommended.

    This parameter takes a string with one of the following values:
        String
        ArrayOfStrings
        File
        Directory

    If -ContentToEncrypt is a string, -ContentType should be "String".
    If -ContentToEncrypt is an array of strings, -ContentType should be "ArrayOfStrings".
    If -ContentToEncrypt is a string that represents a full path to a file, -ContentType should be "File".
    If -ContentToEncrypt is a string that represents a full path to a directory, -ContentType should be "Directory".

.PARAMETER ContentToEncrypt
    Mandatory.

    This parameter takes a string that is either:
        - A string
        - An array of strings
        - A string that represents a full path to a file
        - A string that represents a full path to a directory

.PARAMETER Recurse
    Optional.

    This parameter is a switch. It should only be used if -ContentType is "Directory". The function will fail
    immediately if this parameter is used and -ContentType is NOT "Directory".

    If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
    encrypted.

    If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
    all files within subdirectories under the directory specified by -ContentToEncrypt are encrypted.

.PARAMETER FileToOutput
    Optional.

    This parameter specifies a full path to a NEW file that will contain encrypted information. This parameter should
    ONLY be used if -ContentType is "String" or "ArrayOfStrings". If this parameter is used and -ContentType is NOT
    "String" or "ArrayOfStrings", the function will immediately fail.

.PARAMETER PathToCertFile
    Optional.

    This parameter takes a string that represents the full path to a .pfx file. The public certificate in the
    .pfx file will be used for RSA encryption.

    NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
    AES Key that was used to encrypt the information.

.PARAMETER CNOfCertInStore
    Optional.

    This parameter takes a string that represents the Common Name (CN) of the public certificate used for RSA
    encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My).

    NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
    AES Key that was used to encrypt the information.

.PARAMETER CertPwd
    Optional. (However, this parameter is mandatory if the certificate is password protected).

    This parameter takes a System.Security.SecureString that represents the password for the certificate.

    Use this parameter if the certificate is password protected.

.EXAMPLE
    # String Encryption Example
    # NOTE: If neither -PathToCertFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
    # created and added to Cert:\LocalMachine\My

    PS C:\Users\zeroadmin> New-EncryptedFile -ContentType "String" -ContentToEncrypt "MyPLaInTeXTPwd321!" -FileToOutput $HOME\MyPwd.txt

    FileEncryptedViaRSA                : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted
    FileEncryptedViaAES                :
    OriginalFile                       :
    CertficateUsedForRSAEncryption     : [Subject]
                                           CN=MyPwd

                                         [Issuer]
                                           CN=MyPwd

                                         [Serial Number]
                                           6BD1BF9FACE6F0BB4EFFC31597E9B970

                                         [Not Before]
                                           6/2/2017 10:39:31 AM

                                         [Not After]
                                           6/2/2018 10:59:31 AM

                                         [Thumbprint]
                                           34F3526E85C04CEDC79F26C2B086E52CF75F91C3

    LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
    UnprotectedAESKey                  :
    RSAEncryptedAESKey                 :
    RSAEncryptedAESKeyLocation         :
    AllFileOutputs                     : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted 

.EXAMPLE
    # ArrayOfStrings Encryption Example
    PS C:\Users\zeroadmin> $foodarray = @("fruit","vegetables","meat")
    PS C:\Users\zeroadmin> New-EncryptedFile -ContentType ArrayOfStrings -ContentToEncrypt $foodarray -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -FileToOutput $HOME\Food.txt

    FilesEncryptedViaRSA               : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                         C:\Users\zeroadmin\Food.txt2.rsaencrypted}
    FilesEncryptedViaAES               :
    OriginalFiles                      :
    CertficateUsedForRSAEncryption     : [Subject]
                                           CN=ArrayOfStrings

                                         [Issuer]
                                           CN=ArrayOfStrings

                                         [Serial Number]
                                           32E38D18591854874EC467B73332EA76

                                         [Not Before]
                                           6/1/2017 4:13:36 PM

                                         [Not After]
                                           6/1/2018 4:33:36 PM

                                         [Thumbprint]
                                           C8CC2B8B03E33821A69B35F10B04D74E40A557B2

    LocationOfCertUsedForRSAEncryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
    UnprotectedAESKey                  :
    RSAEncryptedAESKey                 :
    RSAEncryptedAESKeyLocation         :
    AllFileOutputs                     : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                         C:\Users\zeroadmin\Food.txt2.rsaencrypted}

.EXAMPLE
    # File Encryption Example
    PS C:\Users\zeroadmin> $ZeroTestPwd = Read-Host -Prompt "Enter password for ZeroTest Cert" -AsSecureString
    Enter password for ZeroTest Cert: ***********************
    PS C:\Users\zeroadmin> New-EncryptedFile -ContentType File -ContentToEncrypt C:\Users\zeroadmin\tempdir\lorumipsum.txt -CNofCertInStore "ZeroTest" -CertPwd $ZeroTestPwd

    FileEncryptedViaRSA                :
    FileEncryptedViaAES                : C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted
    OriginalFile                       : C:\Users\zeroadmin\tempdir\lorumipsum.txt.original
    CertficateUsedForRSAEncryption     : [Subject]
                                           CN=ZeroTesting.zero.lab

                                         [Issuer]
                                           <redacted>

                                         [Serial Number]
                                           <redacted>

                                         [Not Before]
                                           <redacted>

                                         [Not After]
                                           <redacted>

                                         [Thumbprint]
                                           <redacted>

    LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
    UnprotectedAESKey                  : E0588dE3siWEOAyM7A5+6LKqC5tG1egxXTfsUUE5sNM=
    RSAEncryptedAESKey                 : NkKjOwd8T45u1Hpn0CL9m5zD/97PG9GNnJCShh0vOUTn+m+E2nLFxuW7ChKiHCVtP1vD2z+ckW3kk1va3PAfjw3/hfm9zi2qn4Xu7kPdWL1owDdQyvBuUPTc35
                                         FSqaIJxxdsqWLnUHo1PINY+2usIPT5tf57TbTKbAg5q/RXOzCeUS+QQ+nOKMgQGnadlUVyyIYo2JRdzzKaTSHRwK4QFdDk/PUy39ei2FVOIlwitiAkWTyjFAb6
                                         x+kMCgOVDuALGOyVVBdNe+BDrrWgqnfRSCHSZoQKfnkA0dj0tuE2coYNwGQ6SVUmiDrdklBrnKl69cIFf8lkTSsUqGdq9bbaag==
    RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted
    AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\lorumipsum.txt.original,
                                         C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted}

.EXAMPLE
    # Directory Encryption Example
    # NOTE: If neither -PathToCertFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
    # created and added to Cert:\LocalMachine\My

    PS C:\Users\zeroadmin> New-EncryptedFile -ContentType Directory -ContentToEncrypt C:\Users\zeroadmin\tempdir
    Please enter the desired CN for the new Self-Signed Certificate: TempDirEncryption


    FilesEncryptedViaRSA               :
    FilesEncryptedViaAES               : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                         C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted}
    OriginalFiles                      : {C:\Users\zeroadmin\tempdir\agricola.txt.original, C:\Users\zeroadmin\tempdir\dolor.txt.original,
                                         C:\Users\zeroadmin\tempdir\lorumipsum.txt.original}
    CertficateUsedForRSAEncryption     : [Subject]
                                           CN=TempDirEncryption

                                         [Issuer]
                                           CN=TempDirEncryption

                                         [Serial Number]
                                           52711274E381F592437E8C18C7A3241C

                                         [Not Before]
                                           6/2/2017 10:57:26 AM

                                         [Not After]
                                           6/2/2018 11:17:26 AM

                                         [Thumbprint]
                                           F2EFEBB37C37844A230961447C7C91C1DE13F1A5

    LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
    UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
    RSAEncryptedAESKey                 : sUshzhMfrbO5FgOGw1Nsx9g5hrnsdUHsJdx8SltK8UeNcCWq8Rsk6dxC12NjrxUSHTSrPYdn5UycBqXB+PNltMebAj80I3Zsh5xRsSbVRSS+fzgGJTUw7ya98J
                                         7vKISUaurBTK4C4Czh1D2bgT7LNADO7qAUgbnv+xdqxgIexlOeNsEkzG10Tl+DxkUVgcpJYbznoTXPUVnj9AZkcczRd2EWPcV/WZnTZwmtH+Ill7wbXSG3R95d
                                         dbQLZfO0eOoBB/DAYWcPkifxJf+20s25xA8MKl7pNpDUbVhGhp61VCaaEqr6QlgihtluqWZeRgHEY3xSzz/UVHhzjCc6Rs9aPw==
    RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
    AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                         C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\agricola.txt.original...}


#>
function New-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        $ContentType,

        [Parameter(Mandatory=$True)]
        $ContentToEncrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        $FileToOutput,

        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd
    )

    ##### BEGIN Parameter Validation #####

    if ($ContentToEncrypt.GetType().Fullname -eq "System.String" -and !$ContentType) {
        $ContentType = "String"
    }
    if ($ContentToEncrypt.GetType().Fullname -match "System.String\[\]|System.Object\[\]" -and !$ContentType) {
        $ContentType = "ArrayOfStrings"
    }

    if ($ContentType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        $FileToOutput = Read-Host -Prompt "Please enter the full path to the new Encrypted File you would like to generate."
    }
    if ($ContentType -match "String|ArrayOfStrings" -and !$ContentToEncrypt) {
        $ContentToEncrypt = Read-Host -Prompt "Please enter the string that you would like to encrypt and output to $FileToOutput"
    }

    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    if ($ContentType -eq "File" -and $ContentToEncrypt -notmatch $RegexFilePath) {
        Write-Verbose "The -ContentType specified was `"File`" but $ContentToEncrypt does not appear to be a valid file path. This is either because a full path was not provided of the file does not have a file extenstion. Please correct and try again. Halting!"
        Write-Error "The -ContentType specified was `"File`" but $ContentToEncrypt does not appear to be a valid file path. This is either because a full path was not provided of the file does not have a file extenstion. Please correct and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "File" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the New-EncryptedFile function. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the New-EncryptedFile function. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $ContentToEncrypt -notmatch $RegexDirectoryPath) {
        Write-Verbose "The -ContentType specified was `"Directory`" but $ContentToEncrypt does not appear to be a valid directory path. This is either because a full path was not provided or because the directory name ends with something similar to `".letters`". Please correct and try again. Halting!"
        Write-Error "The -ContentType specified was `"Directory`" but $ContentToEncrypt does not appear to be a valid directory path. This is either because a full path was not provided or because the directory name ends with something similar to `".letters`". Please correct and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new encrypted files in the specified Directory. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new encrypted files in the specified Directory. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $ContentType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        Write-Error "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($ContentType -eq "String" -and $ContentToEncrypt.GetType().FullName -ne "System.String") {
        Write-Verbose "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToEncrypt.GetType().FullName -notmatch "System.String\[\]|System.Object\[\]") {
        Write-Verbose "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToEncrypt.GetType().FullName -match "System.Object\[\]") {
        $InspectArrayObjects = $(foreach ($obj in $ContentToEncrypt) {
            $obj.GetType().FullName
        }) | Sort-Object | Get-Unique
        if ($InspectArrayObjects -ne "System.String") {
            Write-Verbose "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            Write-Error "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($ContentType -eq "File" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Verbose "The path $ContentToEncrypt was not found! Halting!"
        Write-Error "The path $ContentToEncrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Verbose "The path $ContentToEncrypt was not found! Halting!"
        Write-Error "The path $ContentToEncrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Recurse $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Verbose "No files were found in the directory $ContentToEncrypt. Halting!"
            Write-Error "No files were found in the directory $ContentToEncrypt. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $position = $FileToOutput.LastIndexOf("\")
        $FileToOutputDirectory = $FileToOutput.Substring(0, $position)
        $FileToOutputFile = $FileToOutput.Substring($position+1)
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (! $(Test-Path $FileToOutputDirectory)) {
            Write-Host "The directory $FileToOutputDirectory does not exist. Please check the path."
            $FileToOutput = Read-Host -Prompt "Please enter the full path to the output file that will be created"
            if (! $(Test-Path $FileToOutputDirectory)) {
                Write-Error "The directory $FileToOutputDirectory does not exist. Please check the path. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($PathToCertFile -and $CNofCertInStore) {
        Write-Host "Please use *either* a .pfx certificate file *or*  a certificate in the user's local certificate store to encrypt the file"
        $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
        if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
            Write-Host "Continuing..."
        }
        else {
            Write-Host "The string entered did not match either 'File' or 'Store'. Please type either 'File' or 'Store'"
            $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
            if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
                Write-Host "Continuing..."
            }
            else {
                Write-Error "The string entered did not match either 'File' or 'Store'. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($WhichCertSwitch -eq "File") {
            Remove-Variable -Name "CNofCertInStore" -Force -ErrorAction SilentlyContinue
        }
        if ($WhichCertSwitch -eq "Store") {
            Remove-Variable -Name "PathToCertFile" -Force -ErrorAction SilentlyContinue
        }
    }

    # Validate PathToCertFile
    if ($PathToCertFile) { 
        if (! (Test-Path $PathToCertFile)) {
            Write-Host "The $PathToCertFile was not found. Please check to make sure the file exists."
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file. Example: C:\ps_scripting.pfx"
            if (! (Test-Path $PathToCertFile)) {
                Write-Error "The .pfx certificate file was not found at the path specified. Halting."
                $global:FunctionResult = "1"
                return
            }
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Host "Either the Private Key is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate $($TestCertObj.Subject). If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                Write-Warning "Incorrect certificate password"
                $CertPwdFailure = $true
            }
        }
        if ($CertPwdFailure) {
            Write-Verbose "The password supplied for certificate is incorrect! Halting!"
            Write-Error "The password supplied for certificate is incorrect! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Validate CNofCertInStore
    if ($CNofCertInStore) {
        $Cert1 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})

        if ($Cert1.Count -gt 1) {
            Write-Host "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. 
            A list of available Certificates in the User Store are as follows:"
            foreach ($obj1 in $(Get-ChildItem "Cert:\LocalMachine\My").Subject) {$obj1.Split(",")[0]}
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to encrypt the file"
            $Cert1 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})
            if ($Cert1.Count -gt 1) {
                Write-Error "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Cert1.Count -lt 1) {
            Write-Verbose "Unable to find a a certificate matching CN=$CNofCertInStore in `"Cert:\LocalMachine\My`"! Halting!"
            Write-Error "Unable to find a a certificate matching CN=$CNofCertInStore in `"Cert:\LocalMachine\My`"! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($(-not $PSBoundParameters['PathToCertFile']) -and $(-not $PSBoundParameters['CNofCertInStore'])) {
        if ($FileToOutput) {
            # Create the Self-Signed Cert and add it to the Personal Local Machine Store
            # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
            $LocalMachineCerts = Get-ChildItem Cert:\LocalMachine\My
            $FoundMatchingExistingCert = $LocalMachineCerts | Where-Object {$_.Subject -match "CN=$FileToOutputFileSansExt"}
            if ($FoundMatchingExistingCert.Count -gt 1) {
                $FoundMatchingExistingCert = $FoundMatchingExistingCert[0]
            }
            if ($FoundMatchingExistingCert) {
                $Cert1 = $FoundMatchingExistingCert
            }
            else {
                $Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$FileToOutputFileSansExt" -KeyExportPolicy "Exportable"
            }
        }
        else {
            $CNOfNewCert = Read-Host -Prompt "Please enter the desired CN for the new Self-Signed Certificate"

            # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
            $LocalMachineCerts = Get-ChildItem Cert:\LocalMachine\My
            $FoundMatchingExistingCert = $LocalMachineCerts | Where-Object {$_.Subject -match "CN=$CNOfNewCert"}
            if ($FoundMatchingExistingCert.Count -gt 0) {
                $UseExistingCertQuery = Read-Host -Prompt "There is already a Certificate with a Common Name (CN) matching $CNOfNewCert in the Local Machine Store. Would you like to use the *old* Certificate or create a *new* one? [old/new]"
                if ($UseExistingCertQuery -notmatch "old|new" -or $UseExistingCertQuery -eq "old") {
                    Write-Host "Using existing certificate..."
                    if ($FoundMatchingExistingCert.Count -gt 1) {
                        $FoundMatchingExistingCert = $FoundMatchingExistingCert[0]
                    }
                    $Cert1 = $FoundMatchingExistingCert
                }
                if ($UseExistingCertQuery -eq "new") {
                    $Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$CNOfNewCert`ForEncryption" -KeyExportPolicy "Exportable"
                }
            }
            else {
                $Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$CNOfNewCert" -KeyExportPolicy "Exportable"
            }
        }
    }

    # If user did not explicitly use $PathToCertFile, export the $Cert1 to a .pfx file in the same directory as $FileToOutput
    # so that it's abundantly clear that it was used for encryption, even if it's already in the Cert:\LocalMachine\My Store
    if (!$PathToCertFile) {
        $CertName = $($Cert1.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        try {
            if ($FileToOutput) {
                $PfxOutputDir = $FileOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $ContentType -eq "File") {
                $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
            }
            if (!$FileToOutput -and $ContentType -eq "Directory") {
                $PfxOutputDir = $ContentToEncrypt
            }
            $pfxbytes = $Cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $pfxbytes)
        }
        catch {
            Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Asking for password to try and generate new .pfx file..."
            # NOTE: The $Cert1.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
            
            # Check to see if it's already in the Cert:\LocalMachine\My Store
            if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $Cert1.Thumbprint) {
                Write-Verbose "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
            }
            else {
                Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
                $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $X509Store.Add($Cert1)
            }

            Write-Host "Attempting to export $CertName from Cert:\LocalMachine\My Store to .pfx file..."

            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
            }

            try {
                Export-PfxCertificate -FilePath "$PfxOutputDir\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($Cert1.Thumbprint)" -Password $CertPwd
                $ExportPfxCertificateSuccessful = $true
            }
            catch {
                Write-Host "Creating a .pfx of containing the public certificate used for encryption failed, but this is not strictly necessary and is only attempted for future convenience. Continuing..."
                $ExportPfxCertificateSuccessful = $false
            }
        }
    }

    # If $Cert1 does NOT have a PrivateKey, ask the user if they're ABSOLUTELY POSITIVE they have the private key
    # before proceeding with encryption
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -eq $false -or $Cert1.HasPrivateKey -ne $true) {
        Write-Warning "Windows reports that there is NO Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object!"
        $ShouldWeContinue = Read-Host -Prompt "Are you ABSOLUTELY SURE you have the private key somewhere and want to proceed with encryption? [Yes\No]"
        if ($ShouldWeContinue -match "Y|y|Yes|yes") {
            $AreYouReallyCertain = Read-Host -Prompt "Are you REALLY REALLY CERTAIN you want to proceed with encryption? Encryption will NOT proceed unless you type the word 'Affirmative'"
            if ($AreYouReallyCertain -ne "Affirmative") {
                Write-Verbose "User specified halt! Halting!"
                Write-Error "User specified halt! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ShouldWeContinue -notmatch "Y|y|Yes|yes") {
            Write-Verbose "User specified halt! Halting!"
            Write-Error "User specified halt! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####
    $MaxNumberOfBytesThatCanBeEncryptedViaRSA = ((2048 - 384) / 8) + 37
    if ($ContentType -eq "String") {
        $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt)

        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            Write-Error "The string `$ContentToEncrypt is to large to encrypt via this method. Try writing it to a file first and then using this function to encrypt that file."
            $global:FunctionResult = "1"
            return
        }

        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$FileToOutput.rsaencrypted"

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FileEncryptedViaRSA                 = "$FileToOutput.rsaencrypted"
                FileEncryptedViaAES                 = $null
                OriginalFile                        = $null
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $null
                RSAEncryptedAESKey                  = $null
                RSAEncryptedAESKeyLocation          = $null
                AllFileOutputs                      = $(if ($PathToCertFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
            }
        )

        $Output
    }
    if ($ContentType -eq "ArrayOfStrings") {
        $RSAEncryptedFiles = @()
        for ($i=0; $i -lt $ContentToEncrypt.Count; $i++) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt[$i])

            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                Write-Warning "The string in index $i of the `$ContentToEncrypt array is to large to encrypt via this method. Skipping..."
                continue
            }

            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$FileToOutput$i.rsaencrypted"

            $RSAEncryptedFiles += "$FileToOutput$i.rsaencrypted"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FilesEncryptedViaRSA                = $RSAEncryptedFiles
                FilesEncryptedViaAES                = $null
                OriginalFiles                       = $null
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $null
                RSAEncryptedAESKey                  = $null
                RSAEncryptedAESKeyLocation          = $null
                AllFileOutputs                      = $(if ($PathToCertFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
            }
        )

        $Output
    }
    if ($ContentType -eq "File") {
        $OriginalFile = $ContentToEncrypt

        # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
        $EncodedBytes1 = Get-Content $ContentToEncrypt -Encoding Byte -ReadCount 0

        # If the file content is small enough, encrypt via RSA
        if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$($(Get-ChildItem $ContentToEncrypt).BaseName).rsaencrypted"
        }
        # If the file content is too large, encrypt via AES and then Encrypt the AES Key via RSA
        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $AESKeyDir = $ContentToEncrypt | Split-Path -Parent
            $AESKeyFileNameSansExt = $(Get-ChildItem $ContentToEncrypt).BaseName

            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $ContentToEncrypt -Destination "$ContentToEncrypt.original"

            $AESKey = Create-AESKey
            $FileEncryptionInfo = Encrypt-File $ContentToEncrypt $AESKey

            # Save $AESKey for later use in the same directory as $ContentToEncrypt
            # $bytes = [System.Convert]::FromBase64String($AESKey)
            # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey",$bytes)
            $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"

            # Encrypt the AESKey File using RSA asymetric encryption
            # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
            $EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileNameSansExt.aeskey" -Encoding Byte -ReadCount 0
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"
            Remove-Item "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"
        }

        $FileEncryptedViaRSA = $(if (!$AESKey) {"$($(Get-ChildItem $ContentToEncrypt).BaseName).rsaencrypted"})
        $FileEncryptedViaAES = $(if ($AESKey) {$FileEncryptionInfo.FilesEncryptedwAESKey})
        $RSAEncryptedAESKeyLocation = $(if ($AESKey) {"$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"})
        $RSAEncryptedFileName = $(if ($FileEncryptedViaRSA) {$FileEncryptedViaRSA})
        $AESEncryptedFileName = if ($FileEncryptedViaAES) {$FileEncryptedViaAES}

        $AllFileOutputsPrep = $RSAEncryptedFileName,$AESEncryptedFileName,"$OriginalFile.original",$RSAEncryptedAESKeyLocation
        $AllFileOutputs = $AllFileOutputsPrep | foreach {if ($_ -ne $null) {$_}}
        if (!$PathToCertFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FileEncryptedViaRSA                 = $FileEncryptedViaRSA
                FileEncryptedViaAES                 = $FileEncryptedViaAES
                OriginalFile                        = "$OriginalFile.original"
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $(if ($AESKey) {$FileEncryptionInfo.AESKey})
                RSAEncryptedAESKey                  = $(if ($AESKey) {$EncryptedString1})
                RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
                AllFileOutputs                      = $AllFileOutputs
            }
        )

        $Output
    }
    if ($ContentType -eq "Directory") {
        if (!$Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
        }
        if ($Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Recurse $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
        }
        
        [array]$FilesToEncryptViaRSA = @()
        [array]$FilesToEncryptViaAES = @()
        foreach ($file in $FilesToEncryptPrep) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0

            # If the file content is small enough, encrypt via RSA
            if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaRSA += $file
            }
            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaAES += $file
            }
        }
        foreach ($file in $FilesToEncryptViaAES) {
            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $file -Destination "$file.original"
        }

        # Start Doing the Encryption
        foreach ($file in $FilesToEncryptViaRSA) {
            $EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$($(Get-ChildItem $file).BaseName).rsaencrypted"
        }

        $AESKeyDir = $ContentToEncrypt
        $AESKeyFileName = "$($AESKeyDir | Split-Path -Leaf).aeskey"
        $AESKey = Create-AESKey
        $FileEncryptionInfo = Encrypt-File $FilesToEncryptViaAES $AESKey

        # Save $AESKey for later use in the same directory as $file
        # $bytes = [System.Convert]::FromBase64String($AESKey)
        # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileName.aeskey",$bytes)
        $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileName"

        # Encrypt the AESKey File using RSA asymetric encryption
        # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
        $EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileName" -Encoding Byte -ReadCount 0
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileName.rsaencrypted"
        Remove-Item "$AESKeyDir\$AESKeyFileName"

        $RSAEncryptedAESKeyLocation = if ($FilesToEncryptViaAES.Count -ge 1) {"$AESKeyDir\$AESKeyFileName.rsaencrypted"}
        $OriginalFilesPrep = $FilesToEncryptViaRSA + $FilesToEncryptViaAES
        $OriginalFiles = foreach ($file in $OriginalFilesPrep) {"$file.original"}
        $RSAEncryptedFileNames = foreach ($file in $FilesToEncryptViaRSA) {
            "$file.rsaencrypted"
        }
        $AESEncryptedFileNames = foreach ($file in $FilesToEncryptViaAES) {
            "$file.aesencrypted"
        }

        $AllFileOutputsPrep = $RSAEncryptedFileNames,$AESEncryptedFileNames,$OriginalFiles,$RSAEncryptedAESKeyLocation
        $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}
        if (!$PathToCertFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FilesEncryptedViaRSA                = $RSAEncryptedFileNames
                FilesEncryptedViaAES                = $AESEncryptedFileNames
                OriginalFiles                       = $OriginalFiles
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $FileEncryptionInfo.AESKey
                RSAEncryptedAESKey                  = $EncryptedString1
                RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
                AllFileOutputs                      = $AllFileOutputs
            }
        )

        $Output
    }

    ##### END Main Body #####
}




<#
.SYNOPSIS
    This function decrypts a String, an Array of Strings, a File, or Files in a Directory that were encrypted using the
    New-EncryptedFile function.

.DESCRIPTION
    See SYNOPSIS.

.NOTES
    IMPORTANT NOTES:
    This function identifies a file as RSA encrypted or AES encrypted according to the file's extension. For example,
    a file with an extension ".rsaencrypted" is identified as encrypted via RSA. A file with an extension ".aesencrypted"
    is identified as encrypted via AES. If the file(s) you intend to decrypt do not have either of these file extensions,
    or if you are decrypting a String or ArrayOfStrings in an interactive PowerShell Session, then you can use the
    -TypeOfEncryptionUsed parameter and specify either "RSA" or "AES".

    If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "String" or "ArrayOfStrings", RSA decryption
    will be used.
    If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "File", AES decryption will be used.
    If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "Directory", both RSA and AES decryption will be
    attempted on each file.

.PARAMETER ContentType
    Mandatory.

    This parameter takes a string with one of the following values:
        String
        ArrayOfStrings
        File
        Directory

    If -ContentToEncrypt is a string, -ContentType should be "String".
    If -ContentToEncrypt is an array of strings, -ContentType should be "ArrayOfStrings".
    If -ContentToEncrypt is a string that represents a full path to a file, -ContentType should be "File".
    If -ContentToEncrypt is a string that represents a full path to a directory, -ContentType should be "Directory".

.PARAMETER ContentToEncrypt
    Mandatory.

    This parameter takes a string that is either:
        - A string
        - An array of strings
        - A string that represents a full path to a file
        - A string that represents a full path to a directory

.PARAMETER Recurse
    Optional.

    This parameter is a switch. It should only be used if -ContentType is "Directory". The function will fail
    immediately if this parameter is used and -ContentType is NOT "Directory".

    If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
    decrypted.

    If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
    all files within subdirectories under the directory specified by -ContentToEncrypt are decrypted.

.PARAMETER FileToOutput
    Optional.

    This parameter specifies a full path to a NEW file that will contain decrypted information. This parameter should
    ONLY be used if -ContentType is "String" or "ArrayOfStrings". If this parameter is used and -ContentType is NOT
    "String" or "ArrayOfStrings", the function will immediately fail.

.PARAMETER PathToCertFile
    Optional. (However, either -PathToCertFile or -CNOfCertInStore are required.)

    This parameter takes a string that represents the full path to a .pfx file that was used for encryption. The
    private key in the .pfx file will be used for decryption.

    NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
    AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

.PARAMETER CNOfCertInStore
    Optional. (However, either -PathToCertFile or -CNOfCertInStore are required.)

    This parameter takes a string that represents the Common Name (CN) of the certificate that was used for RSA
    encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My). The
    private key in the certificate will be used for decryption.

    NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
    AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

.PARAMETER CertPwd
    Optional. (However, this parameter is mandatory if the certificate is password protected).

    This parameter takes a System.Security.SecureString that represents the password for the certificate.

    Use this parameter if the certificate is password protected.

.PARAMETER TypeOfEncryptionUsed
    Optional.

    This parameter takes a string with value of either "RSA" or "AES".

    If you want to force this function to use a particular type of decryption, use this parameter.

    If this parameter is NOT used and -ContentType is "String" or "ArrayOfStrings", RSA decryption will be used.
    If this parameter is NOT used and -ContentType is "File", AES decryption will be used.
    If this parameter is NOT used and -ContentType is "Directory", both RSA and AES decryption will be attempted
    on each file.

.PARAMETER AESKey
    Optional.

    This parameter takes a Base64 string that represents the AES Key used for AES Encryption. This same key will be used
    for AES Decryption.

.PARAMETER AESKeyLocation
    Optional.

    This parameter takes a string that represents a full file path to a file that contains the AES Key originally used
    for encryption. 

    If the file extension ends with ".rsaencrypted", this function will use the specified Certificate
    (i.e. the certificate specified via -PathToCertFile or -CNOfCertInStore parameters, specifically the private key
    contained therein) to decrypt the file, revealing the base64 string that represents the AES Key used for AES Encryption.

    If the file extension does NOT end with ".rsaencrypted", the function will assume that the the file contains the
    Base64 string that represents the AES key originally used for AES Encryption.

.PARAMETER NoFileOutput
    Optional.

    This parameter is a switch. If you do NOT want decrypted information written to a file, use this parameter. The
    decrypted info will ONLY be written to console as part of the DecryptedContent Property of the PSCustomObject output.

.EXAMPLE
    # Decrypting an Encrypted String without File Outputs
    PS C:\Users\zeroadmin> $EncryptedStringTest = Get-Content C:\Users\zeroadmin\other\MySecret.txt.rsaencrypted
    PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType String -ContentToDecrypt $EncryptedStringTest -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput

    Doing RSA Decryption

    DecryptedFiles                     :
    FailedToDecryptFiles               : {}
    CertUsedDuringDecryption           : [Subject]
                                           CN=ArrayOfStrings

                                         [Issuer]
                                           CN=ArrayOfStrings

                                         [Serial Number]
                                           32E38D18591854874EC467B73332EA76

                                         [Not Before]
                                           6/1/2017 4:13:36 PM

                                         [Not After]
                                           6/1/2018 4:33:36 PM

                                         [Thumbprint]
                                           C8CC2B8B03E33821A69B35F10B04D74E40A557B2

    PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
    LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
    UnprotectedAESKey                  :
    LocationOfAESKey                   :
    AllFileOutputs                     :
    DecryptedContent                   : THisISmYPWD321!

.EXAMPLE
    # Decrypting an Array Of Strings without File Outputs
    PS C:\Users\zeroadmin> $enctext0 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt0.rsaencrypted
    PS C:\Users\zeroadmin> $enctext1 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt1.rsaencrypted
    PS C:\Users\zeroadmin> $enctext2 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt2.rsaencrypted
    PS C:\Users\zeroadmin> $enctextarray = @($enctext0,$enctext1,$enctext2)
    PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType ArrayOfStrings -ContentToDecrypt $enctextarray -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput
    Doing RSA Decryption


    DecryptedFiles                     :
    FailedToDecryptFiles               : {}
    CertUsedDuringDecryption           : [Subject]
                                           CN=ArrayOfStrings

                                         [Issuer]
                                           CN=ArrayOfStrings

                                         [Serial Number]
                                           32E38D18591854874EC467B73332EA76

                                         [Not Before]
                                           6/1/2017 4:13:36 PM

                                         [Not After]
                                           6/1/2018 4:33:36 PM

                                         [Thumbprint]
                                           C8CC2B8B03E33821A69B35F10B04D74E40A557B2

    PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
    LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
    UnprotectedAESKey                  :
    LocationOfAESKey                   :
    AllFileOutputs                     :
    DecryptedContent                   : {fruit, vegetables, meat}

.EXAMPLE
    # Decrypting a File
    PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType File -ContentToDecrypt C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
    Doing AES Decryption


    DecryptedFiles                     : C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted
    FailedToDecryptFiles               : {}
    CertUsedDuringDecryption           : [Subject]
                                           CN=TempDirEncryption

                                         [Issuer]
                                           CN=TempDirEncryption

                                         [Serial Number]
                                           52711274E381F592437E8C18C7A3241C

                                         [Not Before]
                                           6/2/2017 10:57:26 AM

                                         [Not After]
                                           6/2/2018 11:17:26 AM

                                         [Thumbprint]
                                           F2EFEBB37C37844A230961447C7C91C1DE13F1A5

    PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
    LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
    UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
    LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
    AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                         C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
    DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                         praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                         great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                         because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                         are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                         pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                         trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                         who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                         avoids a pain that produces no resultant pleasure?", ...}

.EXAMPLE
    # Decrypting All Files in a Directory
    PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType Directory -ContentToDecrypt C:\Users\zeroadmin\tempdir -Recurse -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
    Doing AES Decryption
    WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\dolor.txt.original, verify this file was made using the included Encrypt-File function.
    WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\dolor.txt.original failed...Will try RSA Decryption...
    WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted, verify this file was made using the included Encrypt-File function.
    WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted failed...Will try RSA Decryption...
    WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original, verify this file was made using the included Encrypt-File function.
    WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original failed...Will try RSA Decryption...


    DecryptedFiles                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                         C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                         C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted}
    FailedToDecryptFiles               : {C:\Users\zeroadmin\tempdir\dolor.txt.original, C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original}
    CertUsedDuringDecryption           : [Subject]
                                           CN=TempDirEncryption

                                         [Issuer]
                                           CN=TempDirEncryption

                                         [Serial Number]
                                           52711274E381F592437E8C18C7A3241C

                                         [Not Before]
                                           6/2/2017 10:57:26 AM

                                         [Not After]
                                           6/2/2018 11:17:26 AM

                                         [Thumbprint]
                                           F2EFEBB37C37844A230961447C7C91C1DE13F1A5

    PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
    LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
    UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
    LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
    AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                         C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                         C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted,
                                         C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
    DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                         praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                         great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                         because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                         are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                         pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                         trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                         who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                         avoids a pain that produces no resultant pleasure?", ...}


#>
function Decrypt-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        $ContentType,

        [Parameter(Mandatory=$True)]
        $ContentToDecrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        $FileToOutput,
        
        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AES","RSA")]
        $TypeOfEncryptionUsed,

        [Parameter(Mandatory=$False)]
        $AESKey,

        [Parameter(Mandatory=$False)]
        $AESKeyLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoFileOutput
    )

    ##### BEGIN Parameter Validation #####

    if ($ContentToDecrypt.GetType().Fullname -eq "System.String" -and !$ContentType) {
        $ContentType = "String"
    }
    if ($ContentToDecrypt.GetType().Fullname -match "System.String\[\]|System.Object\[\]" -and !$ContentType) {
        $ContentType = "ArrayOfStrings"
    }

    if ($ContentType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        if (!$NoFileOutput) {
            $FileToOutput = Read-Host -Prompt "Please enter the full path to the New File that will contain the Decrypted string."
        }
        if ($NoFileOutput) {
            $FileToOutput = $(Get-Location).Path
        }
    }
    if ($ContentType -match "String|ArrayOfStrings" -and !$ContentToDecrypt) {
        $ContentToDecrypt = Read-Host -Prompt "Please enter the string that you would like to Decrypt and output to $FileToOutput"
    }
    if ($ContentType -eq "File" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the Decrypt-EncryptedFile function. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the Decrypt-EncryptedFile function. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new decrypted files in the specified Directory. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new decrypted files in the specified Directory. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $ContentType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        Write-Error "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($ContentType -eq "String" -and $ContentToDecrypt.GetType().FullName -ne "System.String") {
        Write-Verbose "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToDecrypt.GetType().FullName -notmatch "System.String\[\]|System.Object\[\]") {
        Write-Verbose "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToDecrypt.GetType().FullName -match "System.Object\[\]") {
        $InspectArrayObjects = $(foreach ($obj in $ContentToDecrypt) {
            $obj.GetType().FullName
        }) | Sort-Object | Get-Unique
        if ($InspectArrayObjects -ne "System.String") {
            Write-Verbose "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            Write-Error "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($ContentType -eq "File" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Verbose "The path $ContentToDecrypt was not found! Halting!"
        Write-Error "The path $ContentToDecrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Verbose "The path $ContentToDecrypt was not found! Halting!"
        Write-Error "The path $ContentToDecrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Verbose "No files were found in the directory $ContentToDecrypt. Halting!"
            Write-Error "No files were found in the directory $ContentToDecrypt. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $position = $FileToOutput.LastIndexOf("\")
        $FileToOutputDirectory = $FileToOutput.Substring(0, $position)
        $FileToOutputFile = $FileToOutput.Substring($position+1)
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (! $(Test-Path $FileToOutputDirectory)) {
            Write-Host "The directory $FileToOutputDirectory does not exist. Please check the path."
            $FileToOutput = Read-Host -Prompt "Please enter the full path to the output file that will be created"
            if (! $(Test-Path $FileToOutputDirectory)) {
                Write-Error "The directory $FileToOutputDirectory does not exist. Please check the path. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }


    # Gather the Cert Used For RSA Decryption and the AES Key (if necessary)
    if ($PathToCertFile -ne $null -and $CNofCertInStore -ne $null) {
        Write-Host "Please use *either* a .pfx certificate file *or*  a certificate in the user's local certificate store to decrypt the password file"
        $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
        if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
            Write-Host "Continuing..."
        }
        else {
            Write-Host "The string entered did not match either 'File' or 'Store'. Please type either 'File' or 'Store'"
            $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
            if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
                Write-Host "Continuing..."
            }
            else {
                Write-Error "The string entered did not match either 'File' or 'Store'. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($WhichCertSwitch -eq "File") {
            Remove-Variable -Name "PathToCertInStore" -Force -ErrorAction SilentlyContinue
        }
        if ($WhichCertSwitch -eq "Store") {
            Remove-Variable -Name "PathToCertFile" -Force -ErrorAction SilentlyContinue
        }
    }

    if ($PathToCertFile -eq $null -and $CNofCertInStore -eq $null) {
        $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been loaded in the certificate Store in order to decrypt the file? [File/Store]"
        if ($FileOrStoreSwitch -eq "File" -or $FileOrStoreSwitch -eq "Store") {
            Write-Host "Continuing..."
        }
        else {
            Write-Host "The string entered did not match either 'File' or 'Store'. Please type either 'File' or 'Store'"
            $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been loaded in the certificate Store? [File,Store]"
            if ($FileOrStoreSwitch -eq "File" -or $FileOrStoreSwitch -eq "Store") {
                Write-Host "Continuing..."
            }
            else {
                Write-Error "The string entered did not match either 'File' or 'Store'. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate PathToCertFile
    if ($PathToCertFile -or $FileOrStoreSwitch -eq "File") { 
        if ($FileOrStoreSwitch -eq "File") {
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file."
        }
        if (!$(Test-Path $PathToCertFile)) {
            Write-Host "The $PathToCertFile was not found. Please check to make sure the file exists."
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file. Example: C:\ps_scripting.pfx"
            if (!$(Test-Path $PathToCertFile)) {
                Write-Error "The .pfx certificate file was not found at the path specified. Halting."
                $global:FunctionResult = "1"
                return
            }
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Host "Either the Private Key is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate $($TestCertObj.Subject). If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                Write-Warning "Incorrect certificate password"
                $CertPwdFailure = $true
            }
        }
        if ($CertPwdFailure) {
            Write-Verbose "The password supplied for certificate is incorrect! Halting!"
            Write-Error "The password supplied for certificate is incorrect! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    # Validate CNofCertInStore {
    if ($CNofCertInStore -or $FileOrStoreSwitch -eq "Store") {
        if ($FileOrStoreSwitch -eq "Store") {
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to decrypt the password file"
        }
        $Cert2 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})

        if ($Cert2.Count -gt 1) {
            Write-Host "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. 
            A list of available Certificates in the User Store are as follows:"
            foreach ($obj1 in $(Get-ChildItem "Cert:\LocalMachine\My").Subject) {$obj1.Split(",")[0]}
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to decrypt the password file"
            $Cert2 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})
            if ($PathToCertInStore.Count -gt 1) {
                Write-Error "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Make sure we have the Private Key
    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $true) {
        if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
            Write-Warning "Windows reports that the certificate being used for decryption has a Private Key (which is necessary for decryption), but the Private Key information is not readily available."
            $UseOpenSSLQuery = Read-Host -Prompt "Do you want to download OpenSSL to $HOME\Downloads and add it to your `$env:Path? [Yes\No]"
            if ($UseOpenSSLQuery -match "Y|y|Yes|yes") {
                try {
                    $ContentToDecryptParentDirTest = $ContentToDecrypt | Split-Path -Parent
                    $TempOutputDirPrep = $(Resolve-Path $ContentToDecryptParentDirTest -ErrorAction SilentlyContinue).Path
                    if (!$TempOutputDirPrep) {
                        throw
                    }

                    New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                    $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
                }
                catch {
                    if ($NoFileOutput) {
                        $TempOutputDirPrep = $(Get-Location).Path
                    }
                    else {
                        $TempOutputDirPrep = $FileToOutput | Split-Path -Parent
                    }

                    New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                    $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
                }
                if ($CertPwd) {
                    $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -CertPwd $CertPwd -DownloadAndAddOpenSSLToPath
                }
                else {
                    $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -DownloadAndAddOpenSSLToPath
                }
            }
            else {
                Write-Verbose "Unable to get Private Key Info without openssl and therefore unable to decrypt $ContentToDecrypt! Halting!"
                Write-Error "Unable to get Private Key Info without openssl and therefore unable to decrypt $ContentToDecrypt! Halting!"
                $FunctionResult = "1"
                return
            }
        }
        else {
            try {
                $ContentToDecryptParentDirTest = $ContentToDecrypt | Split-Path -Parent
                $TempOutputDirPrep = $(Resolve-Path $ContentToDecryptParentDirTest -ErrorAction SilentlyContinue).Path
                if (!$TempOutputDirPrep) {
                    throw
                }

                New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
            }
            catch {
                if ($NoFileOutput) {
                    $TempOutputDirPrep = $(Get-Location).Path
                }
                else {
                    if ($FileToOutput) {
                        $TempOutputDirPrep = $FileToOutput | Split-Path -Parent
                    }
                }

                New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
            }
            if ($CertPwd) {
                $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -CertPwd $CertPwd
            }
            else {
                $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir
            }
        }
        if ($PrivateKeyInfo.KeySize -eq $null) {
            Write-Verbose "Openssl failed to get Private Key Info from $($Cert2.Subject) ! Halting!"
            Write-Error "Failed to get Private Key Info from $($Cert2.Subject) ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $false) {
        Write-Verbose "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        Write-Error "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Figure out if we need an AES key. If so, get it.
    if ($TypeOfEncryptionUsed -eq "AES" -or $ContentToDecrypt -match "\.aesencrypted" -or $AESKey -or $AESKeyLocation) {
        $NeedAES = $true
    }
    if ($ContentType -eq "Directory" -and $TypeOfEncryptionUsed -ne "RSA") {
        # Default to $NeedAES since the Decryption Code Block where ContentType is "Directory" can handle both AES and RSA
        # by first trying AES Decryption, and if that fails, trying RSA Decryption
        $NeedAES = $true
    }
    if ($NeedAES) {
        if (!$AESKey -and !$AESKeyLocation) {
            $AESKeyLocation = Read-Host -Prompt "Please enter the full path to the file that contains the AES Key used to originally encrypt $ContentToDecrypt"
        }
        if (!$AESKey -and $AESKeyLocation) {
            if (!$(Test-Path $AESKeyLocation)) {
                Write-Verbose "The path $AESKeyLocation was not found! Halting!"
                Write-Error "The path $AESKeyLocation was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($(Get-ChildItem $AESKeyLocation).Extension -eq ".rsaencrypted") {
                $EncryptedBase64String = Get-Content $AESKeyLocation
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedBase64String)
                #$EncryptedBytes2 = [System.IO.File]::ReadAllBytes($AESKeyLocation)
                if ($PrivateKeyInfo) {
                    $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                }
                else {
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                }
                #$AESKey = [System.Convert]::ToBase64String($DecryptedBytes2)
                $DecryptedContent2 = [system.text.encoding]::Unicode.GetString($DecryptedBytes2)
                #$DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                # Need to write $DecryptedContent2 to tempfile to strip BOM if present
                $tmpFile = [IO.Path]::GetTempFileName()
                [System.IO.File]::WriteAllLines($tmpFile, $DecryptedContent2.Trim())
                $AESKey = Get-Content $tmpFile
                Remove-Item $tmpFile -Force
            }
            # If the $AESKeyLocation file extension is not .rsaencrypted, assume it's the unprotected AESKey
            if ($(Get-ChildItem $AESKeyLocation).Extension -ne ".rsaencrypted"){
                $AESKey = Get-Content $AESKeyLocation
            }
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####

    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()
    $TryRSADecryption = @()
    # Do RSA Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -eq "RSA"-or !$NeedAES) {
        Write-Host "Doing RSA Decryption"
        if ($ContentType -eq "String" -or $ContentType -eq "File") {
            if ($ContentType -eq "String") {
                $EncryptedString2 = $ContentToDecrypt
                $OutputFile = "$FileToOutput.decrypted"
            }
            if ($ContentType -eq "File") {
                $EncryptedString2 = Get-Content $ContentToDecrypt
                $OutputFile = "$ContentToDecrypt.decrypted"
            }

            try {
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                if ($PrivateKeyInfo) {
                    $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                }
                else {
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                }
                $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                $DecryptedContent2 = $DecryptedContent2.Trim()
                # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                $DecryptedFiles += $OutputFile
            }
            catch {
                Write-Error $_
                $FailedToDecryptFiles += $Outputfile
            }
        }
        if ($ContentType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = "$FileToOutput$i.decrypted"
                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($ArrayOfEncryptedStrings[$i])
                    if ($PrivateKeyInfo) {
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    }
                    else {
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $Outputfile
                }
            }
        }
        if ($ContentType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                $EncryptedString2 = Get-Content $file
                $OutputFile = "$file.decrypted"

                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                    if ($PrivateKeyInfo) {
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    }
                    else {
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $Outputfile
                }
            }
        }
    }
    # Do AES Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -eq "AES" -or $NeedAES) {
        Write-Host "Doing AES Decryption"
        if ($ContentType -eq "String" -or $ContentType -eq "File") {
            if ($ContentType -eq "String") {
                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                [System.IO.File]::WriteAllLines($tmpfileRenamed, $ContentToDecrypt)

                try {
                    $FileDecryptionInfo = Decrypt-File $tmpFileRenamed -Key $AESKey
                    # Now we're left with a file $tmpFile containing decrypted info. Copy it to $FileToOutput
                    Move-Item -Path $tmpFile -Destination $FileToOutput

                    $DecryptedFiles += $FileToOutput
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $FileToOutput
                }
            }
            if ($ContentType -eq "File") {
                <#
                if ($(Get-ChildItem $ContentToDecrypt).Extension -ne ".aesencrypted") {
                    Rename-Item -Path $ContentToDecrypt -NewName "$ContentToDecrypt.aesencrypted"
                    $UpdatedContentToDecrypt = "$ContentToDecrypt.aesencrypted"
                }
                else {
                    $UpdatedContentToDecrypt = $ContentToDecrypt
                }
                #>

                try {
                    $FileDecryptionInfo = Decrypt-File $ContentToDecrypt -Key $AESKey
                    $DecryptedFiles += "$ContentToDecrypt.decrypted"
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $ContentToDecrypt
                }
                
            }
        }
        if ($ContentType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = "$FileToOutput$i"

                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                [System.IO.File]::WriteAllLines($tmpfileRenamed, $ArrayOfEncryptedStrings[$i])

                try {
                    $FileDecryptionInfo = Decrypt-File $tmpFileRenamed -Key $AESKey
                    # Now we're left with a file $tmpFile containing decrypted info. Copy it to $FileToOutput
                    Move-Item -Path $tmpFile -Destination $OutputFile

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $OutputFile
                }
            }
        }
        if ($ContentType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                $FileExtenstion = $(Get-ChildItem $file).Extension
                if ($FileExtension -eq ".aesencrypted" -or $TypeOfEncryptionUsed -eq "AES" -or !$TypeOfEncryptionUsed) {
                    #Rename-Item -Path $file -NewName "$($(Get-ChildItem $file).Name).aesencrypted"
                    #$UpdatedContentToDecrypt = "$file.aesencrypted"

                    try {
                        $FileDecryptionInfo = Decrypt-File $file -Key $AESKey
                        if ($($FileDecryptionInfo.FilesFailedToDecrypt).Count -gt 0) {
                            $TryRSADecryption += $($FileDecryptionInfo.FilesFailedToDecrypt).FullName
                            throw
                        }

                        $DecryptedFiles += "$file.decrypted"
                    }
                    catch {
                        $AESDecryptionFailed = $true
                        Write-Warning "AES Decryption of $file failed...Will try RSA Decryption..."
                    }
                }
            }
            foreach ($file in $TryRSADecryption) {
                $EncryptedString2 = Get-Content $file
                $OutputFile = "$file.decrypted"

                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                    if ($PrivateKeyInfo) {
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    }
                    else {
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    }
                    $DecryptedContent2 = [system.text.encoding]::Unicode.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    #Write-Error $_
                    $FailedToDecryptFiles += $(Get-ChildItem $file).FullName
                }
            }
        }
    }

    # Output
    if ($PrivateKeyInfo) {
        $CertName = $($Cert2.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        $PFXCertUsedForPrivateKeyExtraction = "$TempOutputDir\$CertName.pfx"
    }

    $AllFileOutputsPrep = $DecryptedFiles,$PFXCertUsedForPrivateKeyExtraction
    $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}


    New-Variable -Name "Output" -Value $(
        [pscustomobject][ordered]@{
            DecryptedFiles                          = $(if ($NoFileOutput) {$null} else {$DecryptedFiles})
            FailedToDecryptFiles                    = $FailedToDecryptFiles
            CertUsedDuringDecryption                = $Cert2
            PFXCertUsedForPrivateKeyExtraction      = $PFXCertUsedForPrivateKeyExtraction
            LocationOfCertUsedDuringDecryption      = $(if ($PathToCertFile) {$PathToCertFile} else {"Cert:\LocalMachine\My"})
            UnprotectedAESKey                       = $AESKey
            LocationOfAESKey                        = $AESKeyLocation
            AllFileOutputs                          = $(if ($NoFileOutput) {$null} else {$AllFileOutputs})
            DecryptedContent                        = $(foreach ($file in $DecryptedFiles) {Get-Content $file})
        }
    )
    
    $Output

    # Cleanup
    if ($NoFileOutput) {
        foreach ($item in $DecryptedFiles) {
            Remove-Item $item -Force
        }
        if ($TempOutputDir) {
            Remove-Item -Recurse $TempOutputDir -Force
        }
    }

    ##### END Main Body #####
    $global:FunctionResult = "0"
}


# Below $opensslkeysource from http://www.jensign.com/opensslkey/index.html
$opensslkeysource = @'

//**********************************************************************************
//
// OpenSSLKey
// .NET 2.0  OpenSSL Public & Private Key Parser
//
// Copyright (c) 2008  JavaScience Consulting,  Michel Gallant
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//***********************************************************************************
//
//  opensslkey.cs
//
//  Reads and parses:
//    (1) OpenSSL PEM or DER public keys
//    (2) OpenSSL PEM or DER traditional SSLeay private keys (encrypted and unencrypted)
//    (3) PKCS #8 PEM or DER encoded private keys (encrypted and unencrypted)
//  Keys in PEM format must have headers/footers .
//  Encrypted Private Key in SSLEay format not supported in DER
//  Removes header/footer lines.
//  For traditional SSLEAY PEM private keys, checks for encrypted format and
//  uses PBE to extract 3DES key.
//  For SSLEAY format, only supports encryption format: DES-EDE3-CBC
//  For PKCS #8, only supports PKCS#5 v2.0  3des.
//  Parses private and public key components and returns .NET RSA object.
//  Creates dummy unsigned certificate linked to private keypair and
//  optionally exports to pkcs #12
//
// See also: 
//  http://www.openssl.org/docs/crypto/pem.html#PEM_ENCRYPTION_FORMAT 
//**************************************************************************************

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.ComponentModel;


namespace JavaScience {

    public class Win32 {
        [DllImport("crypt32.dll", SetLastError=true)]
            public static extern IntPtr CertCreateSelfSignCertificate(
                IntPtr hProv,
                ref CERT_NAME_BLOB pSubjectIssuerBlob,
                uint dwFlagsm,
                ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
                IntPtr pSignatureAlgorithm,
                IntPtr pStartTime,
                IntPtr pEndTime,
                IntPtr other) ;
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertStrToName(
                uint dwCertEncodingType,
                String pszX500,
                uint dwStrType,
                IntPtr pvReserved,
                [In, Out] byte[] pbEncoded,
                ref uint pcbEncoded,
                IntPtr other);
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertFreeCertificateContext(
                IntPtr hCertStore);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_KEY_PROV_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszContainerName;  
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszProvName;  
        public uint dwProvType;  
        public uint dwFlags;  
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_NAME_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

public class opensslkey {
    const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
    const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
    const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
    const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
    const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
    const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
    const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
    const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;

    // static byte[] pempublickey;
    // static byte[] pemprivatekey;
    // static byte[] pkcs8privatekey;
    // static byte[] pkcs8encprivatekey;

    static bool verbose = false;

    public static void Main(String[] args) {
  
        if(args.Length == 1)
            if(args[0].ToUpper() == "V")
                verbose = true;

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write("\nRSA public, private or PKCS #8  key file to decode: ");
        String filename = Console.ReadLine().Trim();
        if (filename == "")  //exit while(true) loop
            return;
        if (!File.Exists(filename)) {
            Console.WriteLine("File \"{0}\" does not exist!\n", filename);
            return; 
        }

        StreamReader sr = File.OpenText(filename);
        String pemstr = sr.ReadToEnd().Trim();
        sr.Close();
        if(pemstr.StartsWith("-----BEGIN"))
            DecodePEMKey(pemstr);
        else
            DecodeDERKey(filename);
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodePEMKey(String pemstr) {
        byte[] pempublickey;
        byte[] pemprivatekey;
        byte[] pkcs8privatekey;
        byte[] pkcs8encprivatekey;

        if(pemstr.StartsWith(pempubheader) && pemstr.EndsWith(pempubfooter)) {
            Console.WriteLine("Trying to decode and parse a PEM public key ..");
            pempublickey = DecodeOpenSSLPublicKey(pemstr);
            if(pempublickey != null)
            {
                if(verbose)
                  showBytes("\nRSA public key", pempublickey) ;
                //PutFileBytes("rsapubkey.pem", pempublickey, pempublickey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeX509PublicKey(pempublickey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlpublickey =rsa.ToXmlString(false) ;
                Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            }       
        }
        else if(pemstr.StartsWith(pemprivheader) && pemstr.EndsWith(pemprivfooter)) {
            Console.WriteLine("Trying to decrypt and parse a PEM private key ..");
            pemprivatekey = DecodeOpenSSLPrivateKey(pemstr);
            if(pemprivatekey != null)
            {
                if(verbose)
                  showBytes("\nRSA private key", pemprivatekey) ;
                //PutFileBytes("rsaprivkey.pem", pemprivatekey, pemprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeRSAPrivateKey(pemprivatekey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlprivatekey =rsa.ToXmlString(true) ;
                Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                ProcessRSA(rsa);
            }
        }
        else if(pemstr.StartsWith(pemp8header) && pemstr.EndsWith(pemp8footer)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 PrivateKeyInfo ..");
            pkcs8privatekey = DecodePkcs8PrivateKey(pemstr);
            if(pkcs8privatekey != null)
            {
                if(verbose)
                  showBytes("\nPKCS #8 PrivateKeyInfo", pkcs8privatekey) ;
                //PutFileBytes("PrivateKeyInfo", pkcs8privatekey, pkcs8privatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8privatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                 ProcessRSA(rsa) ; 
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else if(pemstr.StartsWith(pemp8encheader) && pemstr.EndsWith(pemp8encfooter)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 EncryptedPrivateKeyInfo ..");
            pkcs8encprivatekey = DecodePkcs8EncPrivateKey(pemstr);
            if(pkcs8encprivatekey != null) {
                if(verbose)
                  showBytes("\nPKCS #8 EncryptedPrivateKeyInfo", pkcs8encprivatekey) ;
                //PutFileBytes("EncryptedPrivateKeyInfo", pkcs8encprivatekey, pkcs8encprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeEncryptedPrivateKeyInfo(pkcs8encprivatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                  ProcessRSA(rsa) ;
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else {
            Console.WriteLine("Not a PEM public, private key or a PKCS #8");
            return;
        }
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodeDERKey(String filename) {
        RSACryptoServiceProvider rsa = null ;
        byte[] keyblob = GetFileBytes(filename);
        if(keyblob == null)
            return;

        rsa =  DecodeX509PublicKey(keyblob);
        if (rsa !=null) {
            Console.WriteLine("\nA valid SubjectPublicKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlpublickey =rsa.ToXmlString(false) ;
            Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            return;
        }       

        rsa =  DecodeRSAPrivateKey(keyblob);
        if (rsa != null) {
            Console.WriteLine("\nA valid RSAPrivateKey\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa) ;
            return;
        }

        rsa =  DecodePrivateKeyInfo(keyblob);   //PKCS #8 unencrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 PrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }

        rsa =  DecodeEncryptedPrivateKeyInfo(keyblob);  //PKCS #8 encrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 EncryptedPrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }
        Console.WriteLine("Not a binary DER public, private or PKCS #8 key");
        return;
    }

    public static void ProcessRSA(RSACryptoServiceProvider rsa) {
        if(verbose)
            showRSAProps(rsa);
        Console.Write("\n\nExport RSA private key to PKCS #12 file?  (Y or N) ");
        String resp = Console.ReadLine().ToUpper() ;
        if (resp == "Y"  || resp == "YES")
            RSAtoPKCS12(rsa) ;
    }

    //--------  Generate pkcs #12 from an RSACryptoServiceProvider  ---------
    public static void RSAtoPKCS12(RSACryptoServiceProvider rsa) {
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        String keycontainer = keyInfo.KeyContainerName;
        uint keyspec    = (uint) keyInfo.KeyNumber;
        String provider = keyInfo.ProviderName;
        uint cspflags = 0;  //CryptoAPI Current User store;   LM would be CRYPT_MACHINE_KEYSET  = 0x00000020
        String fname = keycontainer + ".p12" ;
        //---- need to pass in rsa since underlying keycontainer is not persisted and might be deleted too quickly ---
        byte[] pkcs12 = GetPkcs12(rsa, keycontainer, provider, keyspec , cspflags) ;
        if ( (pkcs12 !=null)  && verbose)
            showBytes("\npkcs #12", pkcs12);
        if(pkcs12 !=null){
            PutFileBytes(fname, pkcs12, pkcs12.Length) ;
            Console.WriteLine("\nWrote pkc #12 file '{0}'\n",  fname) ;
            }
        else
            Console.WriteLine("\nProblem getting pkcs#12") ;
    }

    //--------   Get the binary PKCS #8 PRIVATE key   --------
    public static byte[] DecodePkcs8PrivateKey(String instr) {
        const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
        const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if(!pemstr.StartsWith(pemp8header) || !pemstr.EndsWith(pemp8footer))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemp8header, "") ;  //remove headers/footers, if present
        sb.Replace(pemp8footer, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {  
            binkey = Convert.FromBase64String(pubstr) ;
        } catch(System.FormatException) {       //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
     }

//------- Parses binary asn.1 PKCS #8 PrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(pkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;


bt = binr.ReadByte();
if(bt != 0x02)
    return null;

twobytes = binr.ReadUInt16();

if(twobytes != 0x0001)
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

bt = binr.ReadByte();
if(bt != 0x04)  //expect an Octet string 
    return null;

bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
if(bt == 0x81)
    binr.ReadByte();
else
 if(bt == 0x82)
    binr.ReadUInt16();
//------ at this stage, the remaining sequence should be the RSA private key

  byte[] rsaprivkey = binr.ReadBytes((int)(lenstream -mem.Position)) ;
    RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
  return rsacsp;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

 }

//--------   Get the binary PKCS #8 Encrypted PRIVATE key   --------
public static byte[] DecodePkcs8EncPrivateKey(String instr) 
  {
 const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
 const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemp8encheader) || !pemstr.EndsWith(pemp8encfooter))
    return null;
       StringBuilder sb = new StringBuilder(pemstr) ;
       sb.Replace(pemp8encheader, "") ;  //remove headers/footers, if present
       sb.Replace(pemp8encfooter, "") ;

String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{  
     binkey = Convert.FromBase64String(pubstr) ;
    }
   catch(System.FormatException) {      //if can't b64 decode, data is not valid
    return null;
    }
  return binkey;
 }


//------- Parses binary asn.1 EncryptedPrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeEncryptedPrivateKeyInfo(byte[] encpkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] OIDpkcs5PBES2 = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0D } ;
   byte[] OIDpkcs5PBKDF2  = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0C } ;
   byte[] OIDdesEDE3CBC = {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07} ;
   byte[] seqdes = new byte[10] ;
   byte[] seq = new byte[11];
   byte[] salt ;
   byte[] IV;
   byte[] encryptedpkcs8;
   byte[] pkcs8;

   int saltsize, ivsize, encblobsize;
   int iterations;

 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(encpkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();   //inner sequence
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBES2))  //is it a OIDpkcs5PBES2 ?
    return null;

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBKDF2)) //is it a OIDpkcs5PBKDF2 ?
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for salt
    return null;
saltsize = binr.ReadByte();
salt = binr.ReadBytes(saltsize);

if(verbose)
    showBytes("Salt for pbkd", salt);
bt=binr.ReadByte();
if (bt != 0x02)     //expect an integer for PBKF2 interation count
    return null;

int itbytes = binr.ReadByte();  //PBKD2 iterations should fit in 2 bytes.
if(itbytes ==1)
    iterations = binr.ReadByte();
else if(itbytes == 2)
    iterations = 256*binr.ReadByte() + binr.ReadByte();
else
    return null;
if(verbose)
    Console.WriteLine("PBKD2 iterations {0}", iterations);

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seqdes = binr.ReadBytes(10);        //read the Sequence OID
if(!CompareBytearrays(seqdes, OIDdesEDE3CBC))   //is it a OIDdes-EDE3-CBC ?
    return null;

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for IV
    return null;
ivsize = binr.ReadByte();   // IV byte size should fit in one byte (24 expected for 3DES)
IV= binr.ReadBytes(ivsize);
if(verbose)
    showBytes("IV for des-EDE3-CBC", IV);

bt=binr.ReadByte();
if(bt != 0x04)      // expect octet string for encrypted PKCS8 data
    return null;


bt = binr.ReadByte();

if(bt == 0x81)
    encblobsize = binr.ReadByte();  // data size in next byte
else if(bt == 0x82)
    encblobsize = 256*binr.ReadByte() + binr.ReadByte() ;
else
    encblobsize = bt;       // we already have the data size


encryptedpkcs8 = binr.ReadBytes(encblobsize) ;
//if(verbose)
//  showBytes("Encrypted PKCS8 blob", encryptedpkcs8) ;


SecureString secpswd = GetSecPswd("Enter password for Encrypted PKCS #8 ==>") ;
pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations) ;
if(pkcs8 == null)   // probably a bad pswd entered.
    return null;

//if(verbose)
//  showBytes("Decrypted PKCS #8", pkcs8) ;
 //----- With a decrypted pkcs #8 PrivateKeyInfo blob, decode it to an RSA ---
  RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8) ;
  return rsa;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }


 }

    //  ------  Uses PBKD2 to derive a 3DES key and decrypts data --------
    public static byte[] DecryptPBDK2(byte[] edata, byte[] salt, byte[]IV, SecureString secpswd, int iterations)
    {
        CryptoStream decrypt = null;

        IntPtr unmanagedPswd = IntPtr.Zero;
        byte[] psbytes = new byte[secpswd.Length] ;
        unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
        Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
        Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

      try
        {
        Rfc2898DeriveBytes kd = new Rfc2898DeriveBytes(psbytes, salt, iterations);
        TripleDES decAlg = TripleDES.Create();
        decAlg.Key = kd.GetBytes(24);
        decAlg.IV = IV;
        MemoryStream memstr = new MemoryStream();
        decrypt = new CryptoStream(memstr,decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        decrypt.Write(edata, 0, edata.Length);
        decrypt.Flush();
        decrypt.Close() ;   // this is REQUIRED.
        byte[] cleartext = memstr.ToArray();
        return cleartext;
        }
       catch (Exception e)
        { 
         Console.WriteLine("Problem decrypting: {0}", e.Message) ;
         return null;
        }
    }

    //--------   Get the binary RSA PUBLIC key   --------
    public static byte[] DecodeOpenSSLPublicKey(String instr) {
        const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
        const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if (!pemstr.StartsWith(pempubheader) || !pemstr.EndsWith(pempubfooter))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pempubheader, "") ;  //remove headers/footers, if present
        sb.Replace(pempubfooter, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {
            binkey = Convert.FromBase64String(pubstr) ;
        }
        catch(System.FormatException) {     //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
    }

//------- Parses binary asn.1 X509 SubjectPublicKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(x509key) ;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8103)  //data read as little endian order (actual data order for Bit String is 03 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8203)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

bt = binr.ReadByte();
if(bt != 0x00)      //expect null byte next
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();
byte lowbyte = 0x00;
byte highbyte = 0x00;

if(twobytes == 0x8102)  //data read as little endian order (actual data order for Integer is 02 81)
    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
else if(twobytes == 0x8202) {
    highbyte = binr.ReadByte(); //advance 2 bytes
    lowbyte = binr.ReadByte();
    }
else
    return null;
 byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;   //reverse byte order since asn.1 key uses big endian order
 int modsize = BitConverter.ToInt32(modint, 0) ;

byte firstbyte = binr.ReadByte();
binr.BaseStream.Seek(-1, SeekOrigin.Current);

 if(firstbyte == 0x00)  {   //if first byte (highest order) of modulus is zero, don't include it
    binr.ReadByte();    //skip this null byte
    modsize -=1  ;  //reduce modulus buffer size by 1
    }

  byte[] modulus = binr.ReadBytes(modsize); //read the modulus bytes

  if(binr.ReadByte() != 0x02)           //expect an Integer for the exponent data
    return null;
  int expbytes = (int) binr.ReadByte() ;        // should only need one byte for actual exponent data (for all useful values)
  byte[] exponent = binr.ReadBytes(expbytes);


  showBytes("\nExponent", exponent);
  showBytes("\nModulus", modulus) ;    

 // ------- create RSACryptoServiceProvider instance and initialize with public key -----
  RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
  RSAParameters RSAKeyInfo = new RSAParameters();
  RSAKeyInfo.Modulus = modulus;
  RSAKeyInfo.Exponent = exponent;
  RSA.ImportParameters(RSAKeyInfo);
  return RSA;
 }
 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

}

    //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
    public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey) {
        byte[] MODULUS, E, D, P, Q, DP, DQ, IQ ;

        // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
        MemoryStream  mem = new MemoryStream(privkey) ;
        BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
        byte bt = 0;
        ushort twobytes = 0;
        int elems = 0;
        try {
            twobytes = binr.ReadUInt16();
            if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
                binr.ReadByte();    //advance 1 byte
            else if(twobytes == 0x8230)
                binr.ReadInt16();   //advance 2 bytes
            else
                return null;

            twobytes = binr.ReadUInt16();
            if(twobytes != 0x0102)  //version number
                return null;
            bt = binr.ReadByte();
            if(bt !=0x00)
                return null;

            //------  all private key components are Integer sequences ----
            elems = GetIntegerSize(binr);
            MODULUS = binr.ReadBytes(elems);

            elems = GetIntegerSize(binr);
            E = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            D = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            P = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            Q = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DP = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DQ = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            IQ = binr.ReadBytes(elems) ;

            if(verbose) {
                showBytes("\nModulus", MODULUS) ;    
                showBytes("\nExponent", E);
                showBytes("\nD", D);
                showBytes("\nP", P);
                showBytes("\nQ", Q);
                showBytes("\nDP", DP);
                showBytes("\nDQ", DQ);
                showBytes("\nIQ", IQ);
            }

            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAparams = new RSAParameters();
            RSAparams.Modulus =MODULUS;
            RSAparams.Exponent = E;
            RSAparams.D = D;
            RSAparams.P = P;
            RSAparams.Q = Q;
            RSAparams.DP = DP;
            RSAparams.DQ = DQ;
            RSAparams.InverseQ = IQ;
            RSA.ImportParameters(RSAparams);
            return RSA;
        } catch(Exception){
            return null; 
        } finally { 
            binr.Close(); 
        }
    }

private static int GetIntegerSize(BinaryReader binr) {
  byte bt = 0;
  byte lowbyte = 0x00;
  byte highbyte = 0x00;
  int count = 0;
 bt = binr.ReadByte();
if(bt != 0x02)      //expect integer
    return 0;
bt = binr.ReadByte();

if(bt == 0x81)
    count = binr.ReadByte();    // data size in next byte
else
if(bt == 0x82) {
    highbyte = binr.ReadByte(); // data size in next 2 bytes
    lowbyte = binr.ReadByte();
    byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;
    count = BitConverter.ToInt32(modint, 0) ;
    }
else {
    count = bt;     // we already have the data size
}



 while(binr.ReadByte() == 0x00) {   //remove high order zeros in data
    count -=1;
    }
 binr.BaseStream.Seek(-1, SeekOrigin.Current);      //last ReadByte wasn't a removed zero, so back up a byte
 return count;
}




//-----  Get the binary RSA PRIVATE key, decrypting if necessary ----
public static byte[] DecodeOpenSSLPrivateKey(String instr) 
  {
  const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
  const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter))
    return null;

       StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemprivheader, "") ;  //remove headers/footers, if present
        sb.Replace(pemprivfooter, "") ;

String pvkstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{        // if there are no PEM encryption info lines, this is an UNencrypted PEM private key
    binkey = Convert.FromBase64String(pvkstr) ;
    return binkey;
    }
   catch(System.FormatException) {      //if can't b64 decode, it must be an encrypted private key
    //Console.WriteLine("Not an unencrypted OpenSSL PEM private key");  
    }

 StringReader str = new StringReader(pvkstr);

//-------- read PEM encryption info. lines and extract salt -----
 if(!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED")) 
    return null;
 String saltline = str.ReadLine();
 if(!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,") )
    return null;
 String saltstr =  saltline.Substring(saltline.IndexOf(",") + 1).Trim() ;
 byte[] salt = new byte[saltstr.Length/2]; 
 for (int i=0; i <salt.Length; i++)  
    salt[i] = Convert.ToByte(saltstr.Substring (i*2, 2), 16); 
 if(! (str.ReadLine() == ""))
    return null;

//------ remaining b64 data is encrypted RSA key ----
String encryptedstr =  str.ReadToEnd() ;

 try{   //should have b64 encrypted RSA key now
    binkey = Convert.FromBase64String(encryptedstr) ;
 }
   catch(System.FormatException) {  // bad b64 data.
    return null;
    }

//------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

    SecureString  despswd = GetSecPswd("Enter password to derive 3DES key==>") ;
   //Console.Write("\nEnter password to derive 3DES key: ");
   //String pswd = Console.ReadLine();
  byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
  if(deskey == null)
    return null;
  //showBytes("3DES key", deskey) ;

//------ Decrypt the encrypted 3des-encrypted RSA private key ------
 byte[] rsakey = DecryptKey(binkey, deskey, salt);  //OpenSSL uses salt value in PEM header also as 3DES IV
if(rsakey !=null) 
    return rsakey;  //we have a decrypted RSA private key
else {
    Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.");
    return null;
   }
 }


    // ----- Decrypt the 3DES encrypted RSA private key ----------
    public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV) {
        MemoryStream memst = new MemoryStream(); 
        TripleDES alg = TripleDES.Create(); 
        alg.Key = desKey; 
        alg.IV = IV; 
        try {
            CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write); 
            cs.Write(cipherData, 0, cipherData.Length); 
            cs.Close(); 
        } catch(Exception exc) {
            Console.WriteLine(exc.Message); 
            return null;
        }
        byte[] decryptedData = memst.ToArray(); 
        return decryptedData; 
    }

//-----   OpenSSL PBKD uses only one hash cycle (count); miter is number of iterations required to build sufficient bytes ---
 private static byte[] GetOpenSSL3deskey(byte[] salt, SecureString secpswd, int count, int miter )  {
    IntPtr unmanagedPswd = IntPtr.Zero;
    int HASHLENGTH = 16;    //MD5 bytes
    byte[] keymaterial = new byte[HASHLENGTH*miter] ;     //to store contatenated Mi hashed results


    byte[] psbytes = new byte[secpswd.Length] ;
    unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
    Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
    Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

    //UTF8Encoding utf8 = new UTF8Encoding();
    //byte[] psbytes = utf8.GetBytes(pswd);

    // --- contatenate salt and pswd bytes into fixed data array ---
    byte[] data00 = new byte[psbytes.Length + salt.Length] ;
    Array.Copy(psbytes, data00, psbytes.Length);        //copy the pswd bytes
    Array.Copy(salt, 0, data00, psbytes.Length, salt.Length) ;  //concatenate the salt bytes

    // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
    MD5 md5 = new MD5CryptoServiceProvider();
    byte[] result = null;
    byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

    for(int j=0; j<miter; j++)
    {
    // ----  Now hash consecutively for count times ------
    if(j == 0)
        result = data00;    //initialize 
    else {
        Array.Copy(result, hashtarget, result.Length);
        Array.Copy(data00, 0, hashtarget, result.Length, data00.Length) ;
        result = hashtarget;
            //Console.WriteLine("Updated new initial hash target:") ;
            //showBytes(result) ;
    }

    for(int i=0; i<count; i++)
        result = md5.ComputeHash(result);
     Array.Copy(result, 0, keymaterial, j*HASHLENGTH, result.Length);  //contatenate to keymaterial
    }
    //showBytes("Final key material", keymaterial);
    byte[] deskey = new byte[24];
   Array.Copy(keymaterial, deskey, deskey.Length) ;

   Array.Clear(psbytes, 0,  psbytes.Length);
   Array.Clear(data00, 0, data00.Length) ;
   Array.Clear(result, 0, result.Length) ;
   Array.Clear(hashtarget, 0, hashtarget.Length) ;
   Array.Clear(keymaterial, 0, keymaterial.Length) ;

   return deskey; 
 }






//------   Since we are using an RSA with nonpersisted keycontainer, must pass it in to ensure it isn't colledted  -----
private static byte[] GetPkcs12(RSA rsa, String keycontainer, String cspprovider, uint KEYSPEC, uint cspflags)
 {
  byte[] pfxblob    = null;
  IntPtr hCertCntxt = IntPtr.Zero;

  String DN = "CN=Opensslkey Unsigned Certificate";

    hCertCntxt =  CreateUnsignedCertCntxt(keycontainer, cspprovider, KEYSPEC, cspflags, DN) ;
    if(hCertCntxt == IntPtr.Zero){
        Console.WriteLine("Couldn't create an unsigned-cert\n") ;
        return null;
    }
 try{
    X509Certificate cert = new X509Certificate(hCertCntxt) ;    //create certificate object from cert context.
    //X509Certificate2UI.DisplayCertificate(new X509Certificate2(cert)) ;   // display it, showing linked private key
    SecureString pswd = GetSecPswd("Set PFX Password ==>") ;
    pfxblob = cert.Export(X509ContentType.Pkcs12, pswd);
  }

 catch(Exception exc) 
 { 
    Console.WriteLine( "BAD RESULT" + exc.Message);
    pfxblob = null;
 }
    
rsa.Clear() ;
if(hCertCntxt != IntPtr.Zero)
    Win32.CertFreeCertificateContext(hCertCntxt) ;
  return pfxblob;
}




private static IntPtr CreateUnsignedCertCntxt(String keycontainer, String provider, uint KEYSPEC, uint cspflags, String DN) {
 const uint AT_KEYEXCHANGE  = 0x00000001;
 const uint AT_SIGNATURE        = 0x00000002;
 const uint CRYPT_MACHINE_KEYSET    = 0x00000020;
 const uint PROV_RSA_FULL       = 0x00000001;
 const String MS_DEF_PROV       = "Microsoft Base Cryptographic Provider v1.0";
 const String MS_STRONG_PROV    =  "Microsoft Strong Cryptographic Provider";
 const String MS_ENHANCED_PROV  = "Microsoft Enhanced Cryptographic Provider v1.0";
 const uint CERT_CREATE_SELFSIGN_NO_SIGN        = 1 ;
 const uint X509_ASN_ENCODING   = 0x00000001;
 const uint CERT_X500_NAME_STR  = 3;
 IntPtr hCertCntxt = IntPtr.Zero;
 byte[] encodedName = null;
 uint cbName = 0;

 if( provider != MS_DEF_PROV && provider != MS_STRONG_PROV && provider != MS_ENHANCED_PROV)
    return IntPtr.Zero;
 if(keycontainer == "")
    return IntPtr.Zero;
 if( KEYSPEC != AT_SIGNATURE &&  KEYSPEC != AT_KEYEXCHANGE)
    return IntPtr.Zero;
 if(cspflags != 0 && cspflags != CRYPT_MACHINE_KEYSET)   //only 0 (Current User) keyset is currently used.
    return IntPtr.Zero;
if (DN == "")
    return IntPtr.Zero;


if(Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
 {
    encodedName = new byte[cbName] ;
    Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
 }

  CERT_NAME_BLOB subjectblob = new CERT_NAME_BLOB();
  subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
  Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
  subjectblob.cbData = encodedName.Length;

  CRYPT_KEY_PROV_INFO pInfo = new CRYPT_KEY_PROV_INFO();
  pInfo.pwszContainerName = keycontainer;
  pInfo.pwszProvName = provider;
  pInfo.dwProvType = PROV_RSA_FULL;
  pInfo.dwFlags = cspflags;
  pInfo.cProvParam = 0;
  pInfo.rgProvParam = IntPtr.Zero;
  pInfo.dwKeySpec = KEYSPEC;

 hCertCntxt = Win32.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
 if(hCertCntxt == IntPtr.Zero)
     showWin32Error(Marshal.GetLastWin32Error());
 Marshal.FreeHGlobal(subjectblob.pbData);
 return hCertCntxt ;
}




 private static SecureString GetSecPswd(String prompt)
  {
        SecureString password = new SecureString();

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write(prompt);
        Console.ForegroundColor = ConsoleColor.Magenta;

        while (true)
            {
            ConsoleKeyInfo cki = Console.ReadKey(true);
                if (cki.Key == ConsoleKey.Enter)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (cki.Key == ConsoleKey.Backspace)
                {
                    // remove the last asterisk from the screen...
                    if (password.Length > 0)
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        password.RemoveAt(password.Length - 1);
                    }
                }
                else if (cki.Key == ConsoleKey.Escape)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (Char.IsLetterOrDigit(cki.KeyChar) || Char.IsSymbol(cki.KeyChar))
                {
                    if (password.Length < 20)
                    {
                        password.AppendChar(cki.KeyChar);
                        Console.Write("*");
                    }
                    else
                    {
                        Console.Beep();
                    }
                } 
                else
                {
                    Console.Beep();
                }
            }
  }

    private static bool CompareBytearrays(byte [] a, byte[] b) {
        if(a.Length != b.Length)
            return false;
        int i =0;
        foreach(byte c in a) {
            if(c != b[i] ) 
                return false;
            i++;
        }
        return true;
     } 

    private static void showRSAProps(RSACryptoServiceProvider rsa) {
        Console.WriteLine("RSA CSP key information:");
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        Console.WriteLine("Accessible property: " + keyInfo.Accessible);
        Console.WriteLine("Exportable property: " + keyInfo.Exportable);
        Console.WriteLine("HardwareDevice property: " + keyInfo.HardwareDevice);
        Console.WriteLine("KeyContainerName property: " + keyInfo.KeyContainerName);
        Console.WriteLine("KeyNumber property: " + keyInfo.KeyNumber.ToString());
        Console.WriteLine("MachineKeyStore property: " + keyInfo.MachineKeyStore);
        Console.WriteLine("Protected property: " + keyInfo.Protected);
        Console.WriteLine("ProviderName property: " + keyInfo.ProviderName);
        Console.WriteLine("ProviderType property: " + keyInfo.ProviderType);
        Console.WriteLine("RandomlyGenerated property: " + keyInfo.RandomlyGenerated);
        Console.WriteLine("Removable property: " + keyInfo.Removable);
        Console.WriteLine("UniqueKeyContainerName property: " + keyInfo.UniqueKeyContainerName);
    }

    private static void showBytes(String info, byte[] data){
        Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
        for(int i=1; i<=data.Length; i++){  
            Console.Write("{0:X2}  ", data[i-1]) ;
            if(i%16 == 0)
                Console.WriteLine();
        }
        Console.WriteLine("\n\n");
    }


    private static byte[] GetFileBytes(String filename) {
        if(!File.Exists(filename))
            return null;
        Stream stream=new FileStream(filename,FileMode.Open);
        int datalen = (int)stream.Length;
        byte[] filebytes =new byte[datalen];
        stream.Seek(0,SeekOrigin.Begin);
        stream.Read(filebytes,0,datalen);
        stream.Close();
        return filebytes;
    }

    private static void PutFileBytes(String outfile, byte[] data, int bytes) {
        FileStream fs = null;
        if(bytes > data.Length) {
            Console.WriteLine("Too many bytes");
            return;
        }
        try {
            fs = new FileStream(outfile, FileMode.Create);
            fs.Write(data, 0, bytes);
        } catch(Exception e) {
            Console.WriteLine(e.Message) ; 
        }
        finally {
            fs.Close();
        }
    }

    private static void showWin32Error(int errorcode) {
        Win32Exception myEx=new Win32Exception(errorcode);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Error code:\t 0x{0:X}", myEx.ErrorCode);
        Console.WriteLine("Error message:\t {0}\n", myEx.Message);
        Console.ForegroundColor = ConsoleColor.Gray;
    }


    }
}

'@


# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSbfN/SNCk/fTVj+G1Sbu5mbG
# dKCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKAaSPsJKdECvYmZ
# ZL81lZTfawTUMA0GCSqGSIb3DQEBAQUABIIBALzdq5j3D7+6zGuYFBmqxad2XnXl
# Qf+VY4srGibo2uW6vIJKdxPRi75MBRrYLzzNPvYo3Gc7v7qt8sNOMpyZhZp0l7K3
# IPMG31y5bOmqHUD2ewrl0/B1R6tI6bpYfLlv8s40QXCXf/kBjpvB3YcMohklIAps
# dhRNrNN8ktg2SYFZt61sv5zO1TW9CylYEQ7DHqXYv/ijWtR0me8xRVTaR5Y7PjZg
# PH+MyY1JHBnle6noU2v1W3/I+qnAMjGIf45kNzRVT8uMTLiTTGCCUKf6v3xDls+9
# aWyh6bQ+7VxBEtVorSsLUhUVF80aEl+NOAc699A4tVHmXkdSF2uvQ6eXHKQ=
# SIG # End signature block
