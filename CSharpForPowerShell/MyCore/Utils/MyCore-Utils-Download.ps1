# USAGE EXAMPLES
<#
**** EXAMPLE 1 ****

PS C:\Users\testadmin> ([MyCore.Utils.Download]::new()).FileDownload("https://www.nuget.org/api/v2/package/HTMLAgilityPack","C:\Users\testadmin\Downloads\HTMLAgilityPack.zip")

Result                  : True
Id                      : 1
Exception               :
Status                  : RanToCompletion
IsCanceled              : False
IsCompleted             : True
IsCompletedSuccessfully : True
CreationOptions         : None
AsyncState              :
IsFaulted               : False
AsyncWaitHandle         : System.Threading.ManualResetEvent
CompletedSynchronously  : False

#>

function Get-Assemblies {
    [CmdletBinding(DefaultParameterSetName="AssemNameWild")]
    Param(
        [Parameter(Mandatory=$True,ParameterSetName="AssemNameWild")]
        [string]$AssemblyName,

        [Parameter(Mandatory=$True,ParameterSetName="AssemNameLoc")]
        [string]$AssemblyLocation
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $AssemblyBaseClassCount = $($AssemblyName -split "\.").Count

    [System.Collections.ArrayList]$AttemptedAssemblyPermutations = @()

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $GACDir = $CurrentlyLoadedAssemblies[0].Location | Split-Path -Parent

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($AssemblyLocation) {
        try {
            $AssemblyLocationFullPath = $(Resolve-Path $AssemblyLocation).Path
        }
        catch {
            Write-Error $Error[0]
            $global:FunctionResult = 1
            return
        }

        try {
            $AssemblyFullInfo = [System.Reflection.Assembly]::LoadFile($AssemblyLocationFullPath)
        }
        catch {
            Write-Error $Error[0]
            $global:FunctionResult = 1
            return
        }

        $AssemblyName = $($AssemblyFullInfo.FullName -split ",")[0]

        # Re-Get CurrentlyloadedAssemblies because now the .dll file has been loaded... 
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    }

    if ($($CurrentlyLoadedAssemblies.FullName | foreach {$($_ -split ",")[0]}) -contains $AssemblyName) {
        Write-Verbose "$AssemblyName is already loaded"
        $WorkingAssemblyReference = $CurrentlyLoadedAssemblies | Where-Object {$($_.FullName -split ",")[0] -eq $AssemblyName}
    }
    else {
        try {
            [System.Collections.ArrayList]$Failures = @()
            try {
                $AssemPartName = [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
                if (!$AssemPartName) {
                    throw
                }
                $WorkingAssemblyReference = $AssemPartName
            }
            catch {
                $null = $Failures.Add("Failed LoadWithPartialName")
            
                try {
                    $AssemTab = $(Invoke-Expression "[$AssemblyName]").Assembly
                    $WorkingAssemblyReference = $AssemTab
                }
                catch {
                    $null = $Failures.Add("Failed TabComplete Check")
                
                    try {
                        $GACChildItems = Get-ChildItem -Recurse $GACDir
                        $AssemblyFileLocation  = foreach ($childitem in $GACChildItems) {
                            if ($_.Name -like "*$AssemblyName.dll") {
                                $_.FullName
                                break
                            }
                        }
                        if ($AssemblyFileLocation) {
                            $AssemLoadFile = [System.Reflection.Assembly]::LoadFile($AssemblyFileLocation)
                            if ($AssemLoadFile) {
                                $WorkingAssemblyReference = $AssemLoadFile
                            }
                            else {
                                throw
                            }
                        }
                        else {
                            throw
                        }
                    }
                    catch {
                        $null = $Failures.Add("Failed LoadFile Check")

                        try {
                            if ($AssemblyName -eq "System.Collections.Generic") {
                                $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match "$AssemblyName.IEnumerable"}    
                            }
                            else {
                                $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match $AssemblyName}
                            }

                            if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferencePrep | Where-Object {$($_.FullName -split ",")[0] -eq $AssemblyName}
                                if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                    $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferenceCheck | Where-Object {$($_.FullName -split ",")[0] -match $AssemblyName}
                                }
                            }

                            $WorkingAssemblyReference = $WorkingAssemblyReferenceCheck
                        }
                        catch {
                            $null = $Failures.Add("CurrentlyLoaded Check")
                        }
                    }
                }
            }

            if ($Failures.Count -gt 3) {
                throw
            }
        }
        catch {
            $null = $AttemptedAssemblyPermutations.Add($AssemblyName)

            if ($AssemblyBaseClassCount -ge 3) {
                for ($i=0; $i -lt $($AssemblyBaseClassCount-2); $i++) {
                    $AssemblyName = $AssemblyName.Substring(0, $AssemblyName.LastIndexOf("."))

                    [System.Collections.ArrayList]$Failures = @()
                    try {
                        $Assem = [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
                        if (!$Assem) {
                            throw
                        }
                        $WorkingAssemblyReference = $Assem
                        break
                    }
                    catch {
                        $null = $Failures.Add("Failed LoadWithPartialName")
                    
                        try {
                            $Assem = $(Invoke-Expression "[$AssemblyName]").Assembly
                            $WorkingAssemblyReference = $Assem
                            break
                        }
                        catch {
                            $null = $Failures.Add("Failed TabComplete Check")
                        
                            try {
                                $GACChildItems = Get-ChildItem -Recurse $GACDir
                                $AssemblyFileLocation  = foreach ($childitem in $GACChildItems) {
                                    if ($_.Name -like "*$AssemblyName.dll") {
                                        $_.FullName
                                        break
                                    }
                                }
                                if ($AssemblyFileLocation) {
                                    $AssemLoadFile = [System.Reflection.Assembly]::LoadFile($AssemblyFileLocation)
                                    if ($AssemLoadFile) {
                                        $WorkingAssemblyReference = $AssemLoadFile
                                    }
                                    else {
                                        throw
                                    }
                                }
                                else {
                                    throw
                                }
                            }
                            catch {
                                $null = $Failures.Add("Failed LoadFile Check")

                                try {
                                    if ($AssemblyName -eq "System.Collections.Generic") {
                                        $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match "$AssemblyName.IEnumerable"}    
                                    }
                                    else {
                                        $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match $AssemblyName}
                                    }
        
                                    if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                        $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferencePrep | Where-Object {$($_.FullName -split ",")[0] -like "$AssemblyName*"}
                                        if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                            $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferenceCheck | Where-Object {$($_.FullName -split ",")[0] -match $AssemblyName}
                                        }
                                    }
        
                                    $WorkingAssemblyReference = $WorkingAssemblyReferenceCheck
                                }
                                catch {
                                    $null = $Failures.Add("CurrentlyLoaded Check")
                                }
                            }
                        }
                    }

                    if ($Failures.Count -gt 3) {
                        $null = $AttemptedAssemblyPermutations.Add($AssemblyName)
                    }
                }
            }
        }
    }

    if (!$WorkingAssemblyReference) {
        Write-Error "The following attempts at loading the assembly $AssemblyName were made and ALL failed:`n$AttemptedAssemblyPermutations`nHalting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $WorkingAssemblyReference
    }

    ##### END Main Body #####
}


function Get-AssemblyUsingStatement {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AssemblyName,

        [Parameter(Mandatory=$True)]
        $AssemblyFullInfo,

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Make sure the $AssemblyName matches the $AssemblyFullInfo
    
    if ($AssemblyName -notlike "*$($($AssemblyFullInfo.FullName -split ",")[0])*") {
        Write-Error "The Assembly Reference '$($AssemblyFullInfo.FullName)' does not contain the Assembly Name $AssemblyName! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $UsingStatement = "using $AssemblyName;"

    $AssemblyBaseClassCount = $($AssemblyName -split "\.").Count

    [System.Collections.ArrayList]$AttemptedUsingStatements = @()

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    try {
        $WarningPreference = "SilentlyContinue"
        Add-Type -ReferencedAssemblies $AssemblyFullInfo -TypeDefinition $UsingStatement -IgnoreWarnings -ErrorAction SilentlyContinue
        $WarningPreference = "Continue"
        $UsingStatementWorks = $true
        $FinalUsingStatement = $UsingStatement
    }
    catch {
        $null = $AttemptedUsingStatements.Add($UsingStatement)
        if (!$Silent) {
            Write-Error "$($Error[1])"
        }
        if ($AssemblyBaseClassCount -ge 3) {
            for ($i=0; $i -lt $($AssemblyBaseClassCount-2); $i++) {
                $AssemblyName = $AssemblyName.Substring(0, $AssemblyName.LastIndexOf("."))
                $UsingStatement = "using $AssemblyName;"

                try {
                    Add-Type -ReferencedAssemblies $AssemblyFullInfo -TypeDefinition $UsingStatement -ErrorAction SilentlyContinue
                    $FinalUsingStatement = "using $AssemblyName;"
                    break
                }
                catch {
                    $null = $AttemptedUsingStatements.Add($UsingStatement)
                    if (!$Silent) {
                        Write-Error "$($Error[1])"
                    }
                    if ($i -eq ($AssemblyBaseClassCount-1)) {
                        $FinalUsingStatement = $null
                    }
                }
            }
        }
        else {
            $FinalUsingStatement = $null
        }
    }

    if ($FinalUsingStatement -eq $null) {
        Write-Error "The following `"using`" statements were attempted for $AssemblyName and ALL failed:`n$AttemptedUsingStatements`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalUsingStatement

    ##### END Main Body #####
}


$DefaultAssembliesToLoad = @("Microsoft.CSharp","System","System.Core","System.Linq","System.IO","System.IO.FileSystem"
"System.Console","System.Collections","System.Collections.Generic","System.Runtime","System.Runtime.Extensions")

[System.Collections.ArrayList]$AdditionalAssembliesToCheckFor = @("System.Net.Http","System.Threading.Tasks")

$AssembliesToCheckFor = $DefaultAssembliesToLoad + $AdditionalAssembliesToCheckFor

[System.Collections.ArrayList]$FoundAssemblies = @()
[System.Collections.ArrayList]$FinalUsingStatements = @()
foreach ($assem in $AssembliesToCheckFor) {
    $global:FunctionResult = 0
    
    $GetAssembliesResult = Get-Assemblies -AssemblyName $assem
    
    if ($global:FunctionResult -eq 1) {
        Write-Error "The Get-Assemblies function failed for $assem!"
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

Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition











# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpjqz4N5Hy5rJ3dijuHa9oSX+
# Kp2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJNbeRQOzypPfLIP
# xuspoUmgbUirMA0GCSqGSIb3DQEBAQUABIIBAIYWUXQuKtoNUY0BHWJjSLkZwMkt
# AcEU7viIxveSLEYeemkk9czC4yFsl55lM3AQZQjmaBzrKv4eAbLRoHkXnsUpd9bE
# Kd+9Kfvs5/HHAYdj9/MSK5G7Wdyp7KLDGLbhGkdG72dmNjmPwnzCslIloMZoD6UJ
# w18GshaOOvvCLWbSaFX9aErns+KSGrR4fA1ugVaVeGURp1xSuBByKeZtgc0YcCke
# 5T1seY9pX8pH+vdJyF8977+ljLiIzKLD3A76L7NJuOBcWJHlIAZBY7+W22tMSkd3
# aGLi+DPeVKewVPILwce3y/Uaqe5hi/gAkf8e6SNY59hAUsolO3ZNXTtAUK4=
# SIG # End signature block
