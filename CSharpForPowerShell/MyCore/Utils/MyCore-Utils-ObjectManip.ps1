# USAGE EXAMPLES
<#
**** EXAMPLE 1: ****

PS C:\Users\testadmin> $ht1 = @{a = "one"; b = "two"; c = "three"}
PS C:\Users\testadmin> $ht2 = @{d = "four"; e = "five"; f = "six"}
PS C:\Users\testadmin> $ht3 = @{g = "seven"; h = "eight"; i = "nine"}
PS C:\Users\testadmin> $htarray = $($ht1,$ht2,$ht3)
PS C:\Users\testadmin> $htarray2 = [MyCore.Utils.ObjectManip]::DeepCopy($htarray)

PS C:\Users\testadmin> $htarray.GetHashCode()
47337841
PS C:\Users\testadmin> $htarray2.GetHashCode()
7381545
PS C:\Users\testadmin> [System.Object]::ReferenceEquals($htarray,$htarray2)
False

**** EXAMPLE 2 ****

PS C:\Users\testadmin> $psobj1 = [pscustomobject][ordered]@{a = "one"; b = "two"; c = "three"}
PS C:\Users\testadmin> $psobj2 = [pscustomobject][ordered]@{d = "four"; e = "five"; f = "six"}
PS C:\Users\testadmin> $psobj3 = [pscustomobject][ordered]@{g = "seven"; h = "eight"; i = "nine"}
PS C:\Users\testadmin> $psobjarray = @($psobj1,$psobj2,$psobj3)
PS C:\Users\testadmin> $psobjarray2 = [MyCore.Utils.ObjectManip]::DeepCopy($psobjarray)

PS C:\Users\testadmin> $psobjarray.GetHashCode()
541656
PS C:\Users\testadmin> $psobjarray2.GetHashCode()
58439199
PS C:\Users\testadmin> [System.Object]::ReferenceEquals($psobjarray,$psobjarray2)
False

**** EXAMPLE 3 ****

PS C:\Users\testadmin> $test = "hi"
# IMPORTANT NOTE: The below is the same as doing: $test2 = [System.String]::new($test)
PS C:\Users\testadmin> $test2 = [MyCore.Utils.ObjectManip]::DeepCopy([System.String]::new($test))
# IMPORTANT NOTE: When it comes to plain strings, the HashCodes will be the same, but the References will not be equal
PS C:\Users\testadmin> $test.GetHashCode()
334115657
PS C:\Users\testadmin> $test2.GetHashCode()
334115657
PS C:\Users\testadmin> [System.Object]::ReferenceEquals($test,$test2)
False
PS C:\Users\testadmin> $test3 = $test
PS C:\Users\testadmin> [System.Object]::ReferenceEquals($test,$test3)
True


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

$DefaultAssembliesToLoad = @("Microsoft.CSharp","System","System.Core","System.Linq","System.IO",
"System.Console","System.Collections","System.Collections.Generic","System.Runtime","System.Runtime.Extensions")

[System.Collections.ArrayList]$AdditionalAssembliesToCheckFor = @("System.Runtime.Serialization.Formatters.Binary")

$AssembliesToCheckFor = $DefaultAssembliesToLoad + $AdditionalAssembliesToCheckFor

[System.Collections.ArrayList]$FoundAssemblies = @()
[System.Collections.ArrayList]$FinalUsingStatements = @()
foreach ($assem in $AssembliesToCheckFor) {
    $global:FunctionResult = 0
    
    $GetAssembliesResult = Get-Assemblies -AssemblyName $assem
    
    if ($global:FunctionResult -eq 1) {
        Write-Error "The Get-Assemblies function failed for $assem! Halting!"
        $global:FunctionResult = "1"
        return
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

$TypeDefinition = @"
$usingStatementsAsString

namespace MyCore.Utils
{
    public static class ObjectManip
    {
        public static T DeepCopy<T>(T other)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ms, other);
                ms.Position = 0;
                return (T)formatter.Deserialize(ms);
            }
        }
    }
}
"@

Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition


























# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTNHRUKNyUWOCu1nRFp5hCBK7
# wH2gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTL/48HxmpO
# R4KYbwrhPvd+gKs3VDANBgkqhkiG9w0BAQEFAASCAQBMslMj3os6MaGO8VvLbHfo
# 56EGZ0QuJuXEbYIS+Wl694xY4bj12WSipvuuD8NG4M8I4FEDCmyyN+lGM0oA/FIl
# m9sojv8g0pC8sSHHnVCK2LmOYtt7wQarcZdVknot6T0ZB5Y1wBDTBJi+wpyn1Faw
# UXgg78ywyknO2Q6+yys+ATD/M5qhBlAIKXKTw8t6fgXLE8aSInpCUQheghLudADK
# RAGJpv5uakPwNfFzcf3jDibCFRDgxvCp6PpagZx4I4P/5taFo7TVImTr6lMbSNs5
# QIw4NkGguJYyVQecj0u1PFwpGsHgOQz+oaoJuFWPPzgX3KE9GsqgNy6v8BiLEux/
# SIG # End signature block
