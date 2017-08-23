<#
.SYNOPSIS
    Creates an object of a generic type. Originally from:

    https://web.archive.org/web/20090926122811/http://www.leeholmes.com/blog/CreatingGenericTypesInPowerShell.aspx

.DESCRIPTION
    Using Generics in PowerShell can get really ugly. For example, the following in CSharp...

        var listofstrings = new List<string>();

    ...must be written as follows in PowerShell...

        $listofstrings = New-Object -TypeName 'System.Collections.Generic.List`1[[System.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]]'

    This function makes it so that you can do something like this...

        $listofstrings = New-GenericObject System.Collections.Generic.List System.String


.PARAMETER typeName
    MANDATORY

    The generic object typeName.

.PARAMETER typeParameters
    MANDATORY

    Type parameters.

.PARAMETER constructorParameters
    OPTIONAL

    Constructor parameters.

.EXAMPLE
    # Simple generic collection 
    $list = New-GenericObject System.Collections.ObjectModel.Collection System.Int32

.EXAMPLE
    # Generic dictionary with two types
    New-GenericObject System.Collections.Generic.Dictionary System.String,System.Int32    

.EXAMPLE
    # Generic list as the second type to a generic dictionary 
    $secondType = New-GenericObject System.Collections.Generic.List Int32 
    New-GenericObject System.Collections.Generic.Dictionary System.String,$secondType.GetType()

.EXAMPLE
    # Generic type with a non-default constructor 
    New-GenericObject System.Collections.Generic.LinkedListNode System.Int32 10

.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>

function New-GenericObject {    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$typeName = $(Read-Host -Prompt "Please specify a generic type name"),

        [Parameter(Mandatory=$False)]
        [string]$typeParameters = $(Read-Host -Prompt "Please specify the type parameters"),

        [Parameter(Mandatory=$False)]
        [string]$constructorParameters
    ) 

    ## Create the generic type name 
    $genericTypeName = $typeName + '`' + $typeParameters.Count 
    $genericType = [Type] $genericTypeName 

    if(-not $genericType) 
    { 
        throw "Could not find generic type $genericTypeName" 
    } 

    ## Bind the type arguments to it 
    [type[]] $typedParameters = $typeParameters 
    $closedType = $genericType.MakeGenericType($typedParameters) 
    if(-not $closedType) 
    { 
        throw "Could not make closed type $genericType" 
    } 

    ## Create the closed version of the generic type 
    ,[Activator]::CreateInstance($closedType, $constructorParameters)
}

# NOTE: System, System.Core, and System.Collections are always loaded in PowerShell by default
$NeededAssemblies = @("System","System.Core","System.Collections")
$CurrentLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

$ReferencedAssemblies = $(foreach ($neededAssem in $NeededAssemblies) {
    $CurrentLoadedAssemblies | Where-Object {$($_.FullName -split ",")[0] -eq $neededAssem}
}).FullName

if ($ReferencedAssemblies.Count -lt $NeededAssemblies.Count) {
    Write-Error "One or more necessary assemblies are not already loaded! Halting!"
    $global:FunctionResult = "1"
    return
}

# Since PowerShell can't run without mscorlib.dll by default, the below is unnecessary. But leaving it in as a template for 
# future scenarios that rely on external assemblies.
$IEnumerableTypeLoadedCheck = $CurrentLoadedAssemblies | Where-Object {$_.GetTypes().FullName -match "System.Collections.Generic.IEnumerable"}
if (!$IEnumerableLoadedCheck) {
    Add-Type -AssemblyName mscorlib
}
$IEnumerableTypeLoadedCheck = $CurrentLoadedAssemblies | Where-Object {$_.GetTypes().FullName -match "System.Collections.Generic.IEnumerable"}

# Using Type Extensions in PowerShell see: https://powershell.org/forums/topic/how-do-i-use-extension-methods-in-zipfileextensionsclass/

$TypeDefinition = @"
using System;
using System.Linq;
using System.Collections.Generic;

namespace PaulD.Extensions
{ 
    public static class IEnumerableCombinatorics
    {
        // IEnumerable Extension Methods from: 
        // https://stackoverflow.com/questions/12473575/combinations-of-multiple-list/12473845#12473845
        // This method takes two sequences of T, and returns
        //  - each element of the first sequence,
        //        wrapped in its own one-element sequence
        //  - each element of the second sequence,
        //        wrapped in its own one-element sequence
        //  - each pair of elements (one from each sequence),
        //        as a two-element sequence.
        // e.g. { 1 }.CrossWith({ 2 }) returns { { 1 }, { 2 }, { 1, 2 } }
        public static IEnumerable<IEnumerable<T>> CrossWith<T>(this IEnumerable<T> source1, IEnumerable<T> source2)
        {
            foreach (T s1 in source1) yield return new[] { s1 };
            foreach (T s2 in source2) yield return new[] { s2 };
            foreach (T s1 in source1)
                foreach (T s2 in source2)
                    yield return new[] { s1, s2 };
        }

        // This method takes a sequence of sequences of T and a sequence of T,
        //     and returns
        //  - each sequence from the first sequence
        //  - each element of the second sequence,
        //        wrapped in its own one-element sequence
        //  - each pair, with the element from the second sequence appended to the
        //        sequence from the first sequence.
        // e.g. { { 1, 2 } }.CrossWith({ 3 }) returns
        //      { { 1, 2 }, { 3 }, { 1, 2, 3 } }
        public static IEnumerable<IEnumerable<T>> CrossWith<T>(this IEnumerable<IEnumerable<T>> source1, IEnumerable<T> source2)
        {
            foreach (IEnumerable<T> s1 in source1) yield return s1;
            foreach (T s2 in source2) yield return new[] { s2 };
            foreach (IEnumerable<T> s1 in source1)
                foreach (T s2 in source2)
                    yield return s1.Concat(new[] { s2 }).ToArray();
        }
    }
}
"@

Add-Type -ReferencedAssemblies $IEnumerableTypeLoadedCheck.FullName -TypeDefinition $TypeDefinition

$TypeNameToUpdatePrep = New-GenericObject System.Collections.Generic.List System.String
$TypeNameToUpdate = $TypeNameToUpdatePrep.GetType().FullName

Update-TypeData -TypeName $TypeNameToUpdate -MemberType ScriptMethod -MemberName CrossWith -Value {
    switch ($args.Count)
    {
        1 { [PaulD.Extensions.IEnumerableCombinatorics]::CrossWith($this, $args[0]) }
        default { throw "No overload for [PaulD.Extensions.IEnumerableCombinatorics]::CrossWith takes the specified number of parameters. It can take 1 and only 1 parameters." }
    }  
}

$NetCoreStringsArray = @(".Net Core, Version=1.0", ".Net Core, Version=1.1", ".Net Core, Version=2.0", ".Net Core + Platform Extensions, Version=1.0")
$NetCoreStrings = New-GenericObject System.Collections.Generic.List System.String
foreach ($netcoreString in $NetCoreStringsArray) {
    $NetCoreStrings.Add($netcoreString)
}
$NetFrameworkStringsArray = @(".Net Framework, Version=1.1", ".Net Framework, Version=2.0", ".Net Framework, Version=3.0", ".Net Framework, Version=3.5", ".Net Framework, Version=4.0", ".Net Framework, Version=4.5", ".Net Framework, Version=4.5.1", ".Net Framework, Version=4.5.2", ".Net Framework, Version=4.6", ".Net Framework, Version=4.6.1", ".Net Framework, Version=4.6.2", ".Net Framework, Version=4.7")
$NetFrameworkStrings = New-GenericObject System.Collections.Generic.List System.String
foreach ($netframeworkString in $NetFrameworkStringsArray) {
    $NetFrameworkStrings.Add($netframeworkString)
}
$NetStandardStringsArray = @(".Net Standard, Version=1.0", ".Net Standard, Version=1.1", ".Net Standard, Version=1.2", ".Net Standard, Version=1.3", ".Net Standard, Version=1.4", ".Net Standard, Version=1.5", ".Net Standard, Version=1.6", ".Net Standard, Version=2.0", ".Net Standard + Platform Extensions, Version=1.6", ".Net Standard + Platform Extensions, Version=2.0")
$NetStandardStrings = New-GenericObject System.Collections.Generic.List System.String
foreach ($netstandardString in $NetStandardStringsArray) {
    $NetStandardStrings.Add($netstandardString)
}


$Combos = Invoke-Expression "[$TypeNameToUpdate]`$NetCoreStrings.CrossWith([$TypeNameToUpdate]`$NetFrameworkStrings.CrossWith([$TypeNameToUpdate]`$NetStandardStrings))"

# NOTE: $Combos.Count should equal ~714



















# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJPdweRPOxDISMJxK/5LuxLpx
# fOCgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT+c4V6h4Xd
# f6bMxkouVjdKzy1wADANBgkqhkiG9w0BAQEFAASCAQAJvpJUP/LD8Z6Bv535VN7b
# 9LeVhJlBTWJakPl9FQQ0TV5Lfc1l1q/qsorNilT3Vi9c7+itLUme4Z+E6JLMnHe9
# /ny8noUhcLDV1GLfMHBTmeaCFJIMUz/L7CWyRk7cyJtwIpFuT47vOyjRcYG+HBjf
# HlL1cjdOPGrYdxl139CYmJ7hXLZ1wKf5UhVXCR5cTQYpXDDTX8a2o6PBm/vW/11F
# ozz7RwP6QFsxDlYZvHJkQkMqe/v9ESnatl+flnwYPdVATAs/TVHhep1z7MgjOftS
# huqa1PcnO1TRrSWRXO0vdt4EsIdU/ejdPWDTvg02QnZUl/OxhH4V9X67e9DFA3JZ
# SIG # End signature block
