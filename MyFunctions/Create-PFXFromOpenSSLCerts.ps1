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

        $ZipFileNameWExt = $(Get-ChildItem $PathToZip).name

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

            foreach($searchitem in $SpecificItem) {
                [array]$potentialItems = foreach ($item in $ZipSubItems) {
                    if ($($item.Path -split "$ZipFileNameWExt\\")[-1] -match "$searchitem") {
                        $item
                    }
                }

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
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2R9OWeP4vz4oK3uauYTDOyBp
# d2ygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTU+LeaNQyV
# MrWU5imExHZKLcweAzANBgkqhkiG9w0BAQEFAASCAQBPviuxtGsexTSgmIw6g6b1
# 0+tsLcUvIo1RY+dEueqJ2idZWFVro7mHag3P2h33M4VYjCST/uLGh7P+dL2ceLa9
# ybgPDA8nlrXTLGvjvqtEqZ4E2mGlSqzNSZIhHR23DeE0ykiI17ItNVmz5X5NoXCa
# SM+T2lFIObScc835kAzUeiP211A6K4SMde9uiICTAXA+RA80m3tTvJdiSFnKr7GC
# Snl5qdcgXW0HX6oYCPzjkzpx8EjV3S6aWy1jNS4ZsxjAyIC4Bhv3r8O6X4OrnRBy
# 4a8CGOvV95achv4pKhpsGSYwOdLjKj+IEvEb7LowyzaSPsKmIQ92/Z4tm+QMdf3k
# SIG # End signature block
