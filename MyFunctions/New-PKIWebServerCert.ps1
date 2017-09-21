# Request PKI WebServer Alias Certificate
# IMPORTANT NOTE: Run this from the Subordinate CA Server hosting the ADCS Website

##### BEGIN Helper Functions #####

Function Get-RegistryKeyTimestamp {
    <#
        .SYNOPSIS
            Retrieves the registry key timestamp from a local or remote system.

        .DESCRIPTION
            Retrieves the registry key timestamp from a local or remote system.

        .PARAMETER RegistryKey
            Registry key object that can be passed into function.

        .PARAMETER SubKey
            The subkey path to view timestamp.

        .PARAMETER RegistryHive
            The registry hive that you will connect to.

            Accepted Values:
            ClassesRoot
            CurrentUser
            LocalMachine
            Users
            PerformanceData
            CurrentConfig
            DynData

        .NOTES
            Name: Get-RegistryKeyTimestamp
            Author: Boe Prox
            Version History:
                1.0 -- Boe Prox 17 Dec 2014
                    -Initial Build

        .EXAMPLE
            $RegistryKey = Get-Item "HKLM:\System\CurrentControlSet\Control\Lsa"
            $RegistryKey | Get-RegistryKeyTimestamp | Format-List

            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/16/2014 10:16:35 PM

            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key.

        .EXAMPLE
            Get-RegistryKeyTimestamp -Computername Server1 -RegistryHive LocalMachine -SubKey 'System\CurrentControlSet\Control\Lsa' |
            Format-List

            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/17/2014 6:46:08 AM

            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key of the remote system.

        .INPUTS
            System.String
            Microsoft.Win32.RegistryKey

        .OUTPUTS
            Microsoft.Registry.Timestamp
    #>
    [OutputType('Microsoft.Registry.Timestamp')]
    [cmdletbinding(
        DefaultParameterSetName = 'ByValue'
    )]
    Param (
        [parameter(ValueFromPipeline=$True, ParameterSetName='ByValue')]
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [parameter(ParameterSetName='ByPath')]
        [string]$SubKey,
        [parameter(ParameterSetName='ByPath')]
        [Microsoft.Win32.RegistryHive]$RegistryHive,
        [parameter(ParameterSetName='ByPath')]
        [string]$Computername
    )
    Begin {
        #region Create Win32 API Object
        Try {
            [void][advapi32]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
            #endregion Module Builder

            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')

            #region RegQueryInfoKey Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                    [System.Text.StringBuilder], #Class Name
                    [UInt32 ].MakeByRefType(),  #Class Length
                    [UInt32], #Reserved
                    [UInt32 ].MakeByRefType(), #Subkey Count
                    [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                    [UInt32 ].MakeByRefType(), #Max Class Length
                    [UInt32 ].MakeByRefType(), #Value Count
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Security Descriptor Size           
                    [long].MakeByRefType() #LastWriteTime
                ) #Method Parameters
            )

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(       
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )

            $FieldValueArray = [Object[]] @(
                'RegQueryInfoKey', #CASE SENSITIVE!!
                $True
            )

            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('advapi32.dll'),
                $FieldArray,
                $FieldValueArray
            )

            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion RegQueryInfoKey Method

            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Constant Variables
        $ClassLength = 255
        [long]$TimeStamp = $null
        #endregion Constant Variables

        #region Registry Key Data
        If ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            #Get registry key data
            $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computername).OpenSubKey($SubKey)
            If ($RegistryKey -isnot [Microsoft.Win32.RegistryKey]) {
                Throw "Cannot open or locate $SubKey on $Computername"
            }
        }

        $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
        $RegistryHandle = $RegistryKey.Handle
        #endregion Registry Key Data

        #region Retrieve timestamp
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        )
        Switch ($Return) {
            0 {
               #Convert High/Low date to DateTime Object
                $LastWriteTime = [datetime]::FromFileTime($TimeStamp)

                #Return object
                $Object = [pscustomobject]@{
                    FullName = $RegistryKey.Name
                    Name = $RegistryKey.Name -replace '.*\\(.*)','$1'
                    LastWriteTime = $LastWriteTime
                }
                $Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                $Object
            }
            122 {
                Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
            }
            Default {
                Throw "Error ($return) occurred"
            }
        }
        #endregion Retrieve timestamp
    }
}

##### END Helper Functions #####

$CertGenWorkingDir = "$HOME\Downloads\CertGenWorking"
if (!$(Test-Path $CertGenWorkingDir)) {
    New-Item -ItemType Directory -Name CertGenWorking -Path $($CertGenWorkingDir | Split-Path -Parent)
}
$RootCALoc = "ZeroDC01.zero.lab\ZeroDC01"
$SubCALoc = "ZeroSCA.zero.lab\ZeroSCA"
$infFile = "$CertGenWorkingDir\NewPKIWebCertReq_Config_pki.zero.lab.inf"
$requestFile = "$CertGenWorkingDir\NewPKIWebCertReq_pki.zero.lab.csr"
$CertFileOut = "$CertGenWorkingDir\pki.zero.lab_base64.cer"
$CertificateChain = "$CertGenWorkingDir\pki.zero.lab.p7b"

$inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=pki.zero.lab"
KeySpec = 1
KeyLength = 2048
Exportable = TRUE
FriendlyName = "pki"
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
"@

$inf | Out-File $infFile
certreq.exe -new "$infFile" "$requestFile"
Sleep -Seconds 5
certreq.exe -attrib "CertificateTemplate:ZeroWebServ" -config "$SubCALoc" -submit "$requestFile" "$CertFileOut"
Sleep -Seconds 5
certreq.exe -accept "$CertFileOut"

# Copy $CertFileOut to C:\inetpub\wwwroot\certdata and C:\Windows\System32\CertSrv\CertEnroll
Copy-Item -Path $CertFileOut -Destination "C:\inetpub\wwwroot\certdata" -Force
Copy-Item -Path $CertFileOut -Destination "C:\Windows\System32\CertSrv\CertEnroll" -Force

# Make since there might be other certs that match '$_Subject -like "CN=pki*"', determine the
# correct cert by seeing which thumbprint was just recently written to the registry
$PotentialCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "CN=pki*" }
$CertRegPath1 = "HKLM:\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\"
$CertRegPath2 = "HKCU:\Software\Microsoft\SystemCertificates\MY\Certificates\"
if (Test-Path $CertRegPath1) {
    $PotentialCertsInRegistry1 = Get-ChildItem $CertRegPath1
    if (Test-Path $CertRegPath2) {
        $PotentialCertsInRegistry2 = Get-ChildItem $CertRegPath2

        $PotentialCertsInRegistry = $PotentialCertsInRegistry1 + $PotentialCertsInRegistry2
    }
    else {
        $PotentialCertsInRegistry = $PotentialCertsInRegistry1
    }
}
foreach ($certInRegistry in $PotentialCertsInRegistry) {
    $certInRegistry | Add-Member -Name LastWriteTime -Value $(Get-RegistryKeyTimestamp $certInRegistry).LastWriteTime -MemberType NoteProperty -Force
}
# Sort PotentialCertsInRegistry By LastWriteTime (where the latest is at the bottom)
$PotentialCertsInRegistry = $PotentialCertsInRegistry | Sort-Object -Property LastWriteTime

# Compare the thumbprints
$CertInStoreToUse = foreach ($potentialCert in $PotentialCerts) {
    if ($PotentialCertsInRegistry[-1].PSChildName -eq $potentialCert.Thumbprint) {
        $potentialCert
    }
}
if ($CertInStoreToUse.Count -gt 1) {
    $CertInStoreToUse = $CertInStoreToUse[0]
}
if ($CertInStoreToUse.Count -lt 1) {
    Write-Error "No Certificate in the Certificate Store matches the thumbprint of the last certificate to be written to the registry! Halting!"
    $global:FunctionResult = "1"
}

# Finally, Update IIS SslBindings
Import-Module WebAdministration
Remove-Item IIS:\SslBindings\*
$CertInStoreToUse | New-Item IIS:\SslBindings\0.0.0.0!443

Write-Host @"
# IMPORTANT NOTE: You will most likely need an updated .crl from your RootCA and/or your SubCA.
# On the RootCA and/or the SubCA, use...
#     certutil -crl
# ...which will publish a new .crl to C:\Windows\System32\CertSrv\CertEnroll. Copy the .crl file(s)
# the the following locations on your SubCA:
# C:\Windows\System32\CertSrv\CertEnroll
# C:\inetpub\wwwroot\certdata
"@