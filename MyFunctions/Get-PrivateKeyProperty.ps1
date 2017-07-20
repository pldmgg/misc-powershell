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

        if ($SpecificItem) {
            foreach ($item in $SpecificItem) {
                if ($SpecificItem -match "\\") {
                    $SpecificItem = $SpecificItem -replace "\\","\\"
                }
            }
        }

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
        if ($Error[0].Exception -match "already exists") {
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
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU1nSopAsaaGASuyPryxUvw0Z6
# SLSgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE1MDkwOTA5NTAyNFoXDTE3MDkwOTEwMDAyNFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmRIzy6nwK
# uqvhoz297kYdDXs2Wom5QCxzN9KiqAW0VaVTo1eW1ZbwZo13Qxe+6qsIJV2uUuu/
# 3jNG1YRGrZSHuwheau17K9C/RZsuzKu93O02d7zv2mfBfGMJaJx8EM4EQ8rfn9E+
# yzLsh65bWmLlbH5OVA0943qNAAJKwrgY9cpfDhOWiYLirAnMgzhQd3+DGl7X79aJ
# h7GdVJQ/qEZ6j0/9bTc7ubvLMcJhJCnBZaFyXmoGfoOO6HW1GcuEUwIq67hT1rI3
# oPx6GtFfhCqyevYtFJ0Typ40Ng7U73F2hQfsW+VPnbRJI4wSgigCHFaaw38bG4MH
# Nr0yJDM0G8XhAgMBAAGjggECMIH/MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQW
# BBQ4uUFq5iV2t7PneWtOJALUX3gTcTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBR2
# lbqmEvZFA0XsBkGBBXi2Cvs4TTAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vcGtp
# L2NlcnRkYXRhL1plcm9EQzAxLmNybDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUH
# MAKGIGh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb0RDMDEuY3J0MA0GCSqGSIb3DQEB
# CwUAA4IBAQAUFYmOmjvbp3goa3y95eKMDVxA6xdwhf6GrIZoAg0LM+9f8zQOhEK9
# I7n1WbUocOVAoP7OnZZKB+Cx6y6Ek5Q8PeezoWm5oPg9XUniy5bFPyl0CqSaNWUZ
# /zC1BE4HBFF55YM0724nBtNYUMJ93oW/UxsWL701c3ZuyxBhrxtlk9TYIttyuGJI
# JtbuFlco7veXEPfHibzE+JYc1MoGF/whz6l7bC8XbgyDprU1JS538gbgPBir4RPw
# dFydubWuhaVzRlU3wedYMsZ4iejV2xsf8MHF/EHyc/Ft0UnvcxBqD0sQQVkOS82X
# +IByWP0uDQ2zOA1L032uFHHA65Bt32w8MIIFmzCCBIOgAwIBAgITWAAAADw2o858
# ZSLnRQAAAAAAPDANBgkqhkiG9w0BAQsFADA9MRMwEQYKCZImiZPyLGQBGRYDTEFC
# MRQwEgYKCZImiZPyLGQBGRYEWkVSTzEQMA4GA1UEAxMHWmVyb1NDQTAeFw0xNTEw
# MjcxMzM1MDFaFw0xNzA5MDkxMDAwMjRaMD4xCzAJBgNVBAYTAlVTMQswCQYDVQQI
# EwJWQTEPMA0GA1UEBxMGTWNMZWFuMREwDwYDVQQDEwhaZXJvQ29kZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8LM3f3308MLwBHi99dvOQqGsLeC11p
# usrqMgmEgv9FHsYv+IIrW/2/QyBXVbAaQAt96Tod/CtHsz77L3F0SLuQjIFNb522
# sSPAfDoDpsrUnZYVB/PTGNDsAs1SZhI1kTKIjf5xShrWxo0EbDG5+pnu5QHu+EY6
# irn6C1FHhOilCcwInmNt78Wbm3UcXtoxjeUl+HlrAOxG130MmZYWNvJ71jfsb6lS
# FFE6VXqJ6/V78LIoEg5lWkuNc+XpbYk47Zog+pYvJf7zOric5VpnKMK8EdJj6Dze
# 4tJ51tDoo7pYDEUJMfFMwNOO1Ij4nL7WAz6bO59suqf5cxQGd5KDJ1ECAwEAAaOC
# ApEwggKNMA4GA1UdDwEB/wQEAwIHgDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3
# FQiDuPQ/hJvyeYPxjziDsLcyhtHNeIEnofPMH4/ZVQIBZAIBBTAdBgNVHQ4EFgQU
# a5b4DOy+EUyy2ILzpUFMmuyew40wHwYDVR0jBBgwFoAUOLlBauYldrez53lrTiQC
# 1F94E3EwgeMGA1UdHwSB2zCB2DCB1aCB0qCBz4aBq2xkYXA6Ly8vQ049WmVyb1ND
# QSxDTj1aZXJvU0NBLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NlcnRp
# ZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmli
# dXRpb25Qb2ludIYfaHR0cDovL3BraS9jZXJ0ZGF0YS9aZXJvU0NBLmNybDCB4wYI
# KwYBBQUHAQEEgdYwgdMwgaMGCCsGAQUFBzAChoGWbGRhcDovLy9DTj1aZXJvU0NB
# LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
# Tj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NBQ2VydGlmaWNhdGU/YmFz
# ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCsGCCsGAQUFBzAC
# hh9odHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EuY3J0MBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQEL
# BQADggEBACbc1NDl3NTMuqFwTFd8NHHCsSudkVhuroySobzUaFJN2XHbdDkzquFF
# 6f7KFWjqR3VN7RAi8arW8zESCKovPolltpp3Qu58v59qZLhbXnQmgelpA620bP75
# zv8xVxB9/xmmpOHNkM6qsye4IJur/JwhoHLGqCRwU2hxP1pu62NUK2vd/Ibm8c6w
# PZoB0BcC7SETNB8x2uKzJ2MyAIuyN0Uy/mGDeLyz9cSboKoG6aQibnjCnGAVOVn6
# J7bvYWJsGu7HukMoTAIqC6oMGerNakhOCgrhU7m+cERPkTcADVH/PWhy+FJWd2px
# ViKcyzWQSyX93PcOj2SsHvi7vEAfCGcxggH1MIIB8QIBATBUMD0xEzARBgoJkiaJ
# k/IsZAEZFgNMQUIxFDASBgoJkiaJk/IsZAEZFgRaRVJPMRAwDgYDVQQDEwdaZXJv
# U0NBAhNYAAAAPDajznxlIudFAAAAAAA8MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTtdShml57m
# 5lbn6IBEjngyMS+iqTANBgkqhkiG9w0BAQEFAASCAQBKV5X/nNs52BdwunbTYAbe
# wSX1DNE9A82JEN4VRCVdVffun3TGjljalLQmQXTJFcWJcIGAUCQdtQgjKKGrHGFq
# zo4SDgpSWzALyq/wUHOhUVHs5X57NAtpwMy8Lq79trjwTY65tOF9W3LAw5eId0M6
# WO51cJXRX+8tTrjXUnP6ZLWW2zRYgkj2EaDQqXTgpNGMmbzVviQdeMFwVLVOOl1/
# biL8Zr4Y+0XrHIRSWKLNAjypy/HwQEcvLQjvPXdgoEcel82JJXxt9pSaJX4sIY/p
# GdhXOM/Oq2ZFZzPs5/Uz9SaK3WVxm3H/ZBcH1NLMlQ+JlAs9/ItRMRjcMT5pMkUb
# SIG # End signature block
