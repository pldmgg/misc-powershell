# Decrypt-EncryptedPwdFile Function requires Get-PfxCertificateBetter function in order to pass the certificate's password in
# Understanding Certificate Store and Locations of Public/Private Keys:
# http://paulstovell.com/blog/x509certificate2


function Decrypt-EncryptedPwdFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $EncryptedPwdFileInput = $(Read-Host -Prompt "Please enter the full path to the file you would like to decrypt"),
        
        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd
    )

    ##### BEGIN Helper Functions #####

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

        ##### REGION Helper Functions and Libraries #####

        ## BEGIN Sourced Helper Functions ##

        ## END Sourced Helper Functions ##

        ## BEGIN Native Helper Functions ##
        function Unzip-File {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,Position=0)]
                [string]$PathToZip,
                [Parameter(Mandatory=$true,Position=1)]
                [string]$TargetDir
            )
            
            Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

            if ($PSVersionTable.PSVersion.Major -ge 5) {
                Expand-Archive -Path $PathToZip -DestinationPath $TargetDir -Force
            }
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                # Load System.IO.Compression.Filesystem 
                [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

                # Unzip file
                [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
            }
        }
        ## END Native Helper Functions ##

        ##### REGION END Helper Functions and Libraries #####


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
        $ArrayOfPubCertPSObjects = @()
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
                Write-Warning "The extracted Public cert $($obj1.CertName) was NOT written to $OutputDirectory because it already exists there!"
            }
            if (!$(Test-Path $obj1.FileLocation) -or $Force) {
                $obj1.CertValue | Out-File "$($obj1.FileLocation)" -Encoding Ascii
                Write-Host "Public certs have been extracted and written to $OutputDirectory"
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

    function Update-PrivateKeyProperty {
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
            $PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -PFXFilePwd $CertPwd -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
        }
        else {
            $PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

        if ($PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath -eq $null) {
            # Strip Private Key of Password
            $UnProtectedPrivateKeyOut = "$($(Get-ChildItem $PathToCertFile).BaseName)"+"_unprotected_private_key"+".pem"
            & openssl.exe rsa -in $PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath -out "$HOME\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
            $PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath = "$HOME\$UnProtectedPrivateKeyOut"
        }

        Write-Host "Loading opensslkey.cs from https://github.com/sushihangover/SushiHangover-PowerShell/blob/master/modules/SushiHangover-RSACrypto/opensslkey.cs"
        $opensslkeysource = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sushihangover/SushiHangover-PowerShell/master/modules/SushiHangover-RSACrypto/opensslkey.cs").Content
        Add-Type -TypeDefinition $opensslkeysource
        $PemText = [System.IO.File]::ReadAllText($PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath)
        $PemPrivateKey = [javascience.opensslkey]::DecodeOpenSSLPrivateKey($PemText)
        [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = [javascience.opensslkey]::DecodeRSAPrivateKey($PemPrivateKey);
        $RSA

        # Cleanup
        if ($CleanupOpenSSLOutputs) {
            $ItemsToRemove = @(
                $PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath
                $PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath
            ) + $PubCertAndPrivKeyInfo.PublicKeysInfo.FileLocation

            foreach ($item in $ItemsToRemove) {
                Remove-Item $item
            }
        }

        ##### END Main Body #####

    }

    ##### END Helper Functions #####

    ##### BEGIN Parameter Validation #####

    # Validate EncryptedPwdFileInput
    if (-not $PSBoundParameters['EncryptedPwdFileInput']) {
        $EncryptedPwdFileInput = Read-Host -Prompt "Please enter the full path to the encrypted password file. 
        Example: C:\encryptedpwd.txt"
    }
    if ($PSBoundParameters['EncryptedPwdFileInput'] -or $EncryptedPwdFileInput) {
        if (! (Test-Path $EncryptedPwdFileInput)) {
            Write-Host "Cannot find $EncryptedPwdFileInput. Please ensure the file is present and try again."
            $EncryptedPwdFileInput = Read-Host -Prompt "Please enter the full path to the encrypted password file.
            Example: C:\encryptedpwd.txt"
            if (! (Test-Path $EncryptedPwdFileInput)) {
                Write-Error "Cannot find $EncryptedPwdFileInput. Please ensure the file is present and try again. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

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
        $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been 
        loaded in the certificate Store in order to decrypt the password file? [File/Store]"
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
        if (! (Test-Path $PathToCertFile)) {
            Write-Host "The $PathToCertFile was not found. Please check to make sure the file exists."
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file. 
            Example: C:\ps_scripting.pfx"
            if (! (Test-Path $PathToCertFile)) {
                Write-Error "The .pfx certificate file was not found at the path specified. Halting."
                $global:FunctionResult = "1"
                return
            }
        }

        # Generate Test CertObj to see if it is password protected
        if ($CertPwd) {
            $TestCertObj = Get-PfxCertificateBetter $PathToCertFile -Password $CertPwd
        }
        else {
            $TestCertObj = Get-PfxCertificateBetter $PathToCertFile
        }
        try {
            $pfxbytes = $TestCertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            $Cert2 = $TestCertObj
        }
        catch {
            Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Creating System.Security.Cryptography.X509Certificates.X509Certificate2 object using .Net..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the *certificate* $($TestCertObj.Subject)" -AsSecureString
            }
            $Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
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

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####

    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $true) {
        if ($CertPwd) {
            $PrivateKeyInfo = Update-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $($EncryptedPwdFileInput | Split-Path -Parent) -CertPwd $CertPwd -DownloadAndAddOpenSSLToPath
        }
        else {
            $PrivateKeyInfo = Update-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $($EncryptedPwdFileInput | Split-Path -Parent) -DownloadAndAddOpenSSLToPath
        }
    }
    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $false) {
        Write-Verbose "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        Write-Error "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $EncryptedPwd2 = Get-Content $EncryptedPwdFileInput
    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedPwd2)
    if ($PrivateKeyInfo) {
        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
    }
    else {
        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
    }
    $DecryptedPwd2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
    Write-Output $DecryptedPwd2

    ##### END Main Body #####
    $global:FunctionResult = "0"
}






# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnlMGp533L9mLmY4PckgnwcXl
# J/GgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQ+3ukg+mxs
# dc+Vkp720FCyV4qXGjANBgkqhkiG9w0BAQEFAASCAQBDSdTwwJKrjkRXmeKXH16Q
# RWmcVoELJ9WQ7UA1wtrH+hXzPS9wC0PEC8mQ4kJ61xWE+jPtQl0Y6VtqExlfENRV
# q6LJa6IFnGaJlFGDXB20hRMVafQmr8mexMzHY5hnCvYo7Cd4HLAO/grlF1jDQDZf
# 0qrc2myWtE0YnZ+wBJgqWk7It/LK9L9URAXTNZWYGUvqfiY+wXhrdmvLPSbrpU/O
# yjzxDJxNWY5DjBewluSl09wlIIOosMvDJd9B6U8LRA0kB0o5lg5MRXzk4vUASWYJ
# X+5MtgeQBWILxnQ8QmdezXXVxKt5AM3QjgFTiQt3PKNitCKMpusVpmRkRR5OWZ9a
# SIG # End signature block
