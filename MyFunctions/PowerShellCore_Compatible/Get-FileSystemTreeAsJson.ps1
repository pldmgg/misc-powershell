# Much of the C# Code was put together from the following links:
# https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/file-system/how-to-iterate-through-a-directory-tree
# https://stackoverflow.com/questions/26615480/how-to-transform-an-array-of-file-paths-into-a-hierarchical-json-structure
function Get-FileSystemTreeAsJson {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$RootDirectory,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\.json$")]
        [string]$JsonFileOutputPath
    )

    #region >> Prep

    if (!$(Test-Path $RootDirectory)) {
        Write-Error "Unable to find the path '$RootDirectory'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $($JsonFileOutputPath | Split-Path -Parent))) {
        Write-Error "Unable to find the path '$($JsonFileOutputPath | Split-Path -Parent)'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $InitialOutput = $JsonFileOutputPath -replace "\.json",".txt"

    function Get-NewtonsoftJsonNuget {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$ExpectedLocation
        )
    
        if ($PSVersionTable.PSEdition -eq "Desktop") {
            if (!$ExpectedLocation) {
                $ExpectedLocation = "$HOME\.nuget\packages\Newtonsoft.Json"
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core") {
            $ExpectedLocation = $(Get-Command pwsh).Source | Split-Path -Parent
    
            try {
                $DLLToLoad = $(Resolve-Path "$ExpectedLocation\Newtonsoft.Json.dll" -ErrorAction Stop).Path
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
    
            try {
                Add-Type -Path $DLLToLoad -ErrorAction Stop
            }
            catch {
                if ($_.Exception -match "already exists") {
                    Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session. Continuing..."
                }
                else {
                    Write-Error $_
                    Write-Error "Unable to load Newtonsoft.Json! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    
        # If Newtonsoft.Json is already loaded, don't do anything
        if (![bool]$($CurrentlyLoadedAssemblies.FullName -match "Newtonsoft\.Json")) {
            try {
                $NewtonsoftJsonDir = $(Resolve-Path $ExpectedLocation -ErrorAction Stop).Path
                $LatestVersionPath = $(Get-ChildItem -Path $ExpectedLocation -Directory | Sort-Object -Property LastWriteTime)[-1].FullName
                $DLLToLoad = $(Resolve-Path "$LatestVersionPath\lib\netstandard2.0\Newtonsoft.Json.dll" -ErrorAction Stop).Path
            }
            catch {
                # Get NuGet.CommandLine so we can install Newtonsoft.Json
                if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                    try {
                        if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                            $null = Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
                            $null = Set-PackageSource -Name Chocolatey -Trusted
                        }
                        $null = Install-Package -Name Nuget.CommandLine -Confirm:$False -Force
                    }
                    catch {
                        Write-Error "Problem with 'Install-Package -Name Nuget.CommandLine'! Halting!"
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
    
                    # Make sure nuget.bat or nuget.exe is part of $envPath
                    if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                        # Since NuGet.CommandLine is from the chocolatey repository, nuget.bat/nuget.exe should be
                        # under either C:\Chocolatey or C:\ProgramData\chocolatey
                        if (Test-Path "C:\Chocolatey") {
                            $RootDriveSearch = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "nuget.exe"
                        }
                        if (Test-Path "$env:ProgramData\chocolatey") {
                            $ProgramDataSearch = Get-ChildItem -Path "$env:ProgramData\chocolatey" -Recurse -File -Filter "nuget.exe"
                        }
                        
                        if (!$RootDriveSearch -and !$ProgramDataSearch) {
                            Write-Error "Unable to find nuget.exe from newly installed package Nuget.CommandLine!"
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($RootDriveSearch) {
                            $NugetExeParentDir = $RootDriveSearch.Directory.FullName
                        }
                        elseif ($ProgramDataSearch) {
                            $NugetExeParentDir = $ProgramDataSearch.Directory.FullName
                        }
    
                        # Add $NugetExeParentDir to $env:Path
                        $CurrentEnvPathArray = $env:Path -split ";"
                        if ($CurrentEnvPathArray -notcontains $NugetExeParentDir) {
                            # Place $NugetExeParentDir at start so latest openssl.exe get priority
                            $env:Path = "$NugetExeParentDir;$env:Path"
                        }
                    }
                }
                
                if (![bool]$(Get-Command nuget -ErrorAction SilentlyContinue)) {
                    Write-Error "There was a problem adding nuget.exe to `$env:Path"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    # Now we have nuget.exe, so install Newtonsoft.Json
                    $null = & $(Get-Command nuget).Source install Newtonsoft.Json
    
                    try {
                        $NewtonsoftJsonDir = $(Resolve-Path $ExpectedLocation -ErrorAction Stop).Path
                        $LatestVersionPath = $(Get-ChildItem -Path $ExpectedLocation -Directory | Sort-Object -Property LastWriteTime)[-1].FullName
                        $DLLToLoad = $(Resolve-Path "$LatestVersionPath\lib\netstandard2.0\Newtonsoft.Json.dll" -ErrorAction Stop).Path
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
    
            try {
                Add-Type -Path $DLLToLoad -ErrorAction Stop
            }
            catch {
                if ($_.Exception -match "already exists") {
                    Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session."
                }
                else {
                    Write-Error $_
                    Write-Error "Unable to load Newtonsoft.Json! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            Write-Warning "Newtonsoft.Json.dll is already loaded in the current PowerShell Session."
        }
    }

    try {
        $null = Get-NewtonsoftJsonNuget
    }
    catch {
        Write-Error "Problem loading Newtonsoft.Json! Halting!"
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    
    #endregion >> Prep

    $AssembliesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {
        $_.GetName().Name -eq "Microsoft.CSharp"
        $_.GetName().Name -eq "mscorlib"
        $_.GetName().Name -eq "System"
        $_.GetName().Name -eq "System.Collections"
        $_.GetName().Name -eq "System.Core"
        $_.GetName().Name -eq "System.IO"
        $_.GetName().Name -eq "System.Linq"
        $_.GetName().Name -eq "System.Runtime"
        $_.GetName().Name -eq "System.Runtime.Extensions"
        $_.GetName().Name -eq "System.Runtime.InteropServices"
        $_.GetName().Name -eq "Newtonsoft.Json"
    }
    $AssembliesFullInfo = $AssembliesFullInfo | Where-Object {$_.IsDynamic -eq $False}
    
    $usingStatementsAsString = @"
using Microsoft.CSharp;
using System.Collections.Generic;
using System.Collections;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime;
using System;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
"@
    
    $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

    $TypeDefinition = @"
$usingStatementsAsString

namespace MyCore.Utils
{
    public class FileSystemContent
    {
        static System.Collections.Specialized.StringCollection log = new System.Collections.Specialized.StringCollection();

        public void Tree(string rootPath, string outputPath)
        {
            System.IO.DirectoryInfo rootDir = new System.IO.DirectoryInfo(rootPath);
            WalkDirectoryTree(rootDir, outputPath);

            // Write out all the files that could not be processed.
            //Console.WriteLine("Files with restricted access:");
            //foreach (string s in log)
            //{
                //Console.WriteLine(s);
            //}
        }

        public void WalkDirectoryTree(System.IO.DirectoryInfo root, string outputPath)
        {
            System.IO.FileInfo[] files = null;
            System.IO.DirectoryInfo[] subDirs = null;

            // First, process all the files directly under this folder
            try
            {
                files = root.GetFiles("*.*");
            }
            catch (UnauthorizedAccessException e)
            {
                // This code just writes out the message and continues to recurse.
                // You may decide to do something different here. For example, you
                // can try to elevate your privileges and access the file again.
                //log.Add(e.Message);
                Console.WriteLine(e.Message);
            }
            catch (System.IO.DirectoryNotFoundException e)
            {
                Console.WriteLine(e.Message);
            }

            if (files != null)
            {
                using (StreamWriter w = new StreamWriter(outputPath, append: true))
                {
                    foreach (System.IO.FileInfo fi in files)
                    {
                        // In this example, we only access the existing FileInfo object. If we
                        // want to open, delete or modify the file, then
                        // a try-catch block is required here to handle the case
                        // where the file has been deleted since the call to TraverseTree().
                        //Console.WriteLine(fi.FullName);
                        w.WriteLine(fi.FullName);
                    }
                }
                    
                // Now find all the subdirectories under this directory.
                subDirs = root.GetDirectories();

                foreach (System.IO.DirectoryInfo dirInfo in subDirs)
                {
                    // Resursive call for each subdirectory.
                    WalkDirectoryTree(dirInfo, outputPath);
                }
            }
        }
    }

    class Dir
    {
        public string Name { get; set; }
        public Dictionary<string, Dir> Dirs { get; set; }
        public HashSet<string> Files { get; set; }

        public Dir(string name)
        {
            Name = name;
            Dirs = new Dictionary<string, Dir>();
            Files = new HashSet<string>();
        }

        public Dir FindOrCreate(string path, bool mightBeFile = true)
        {
            int i = path.IndexOf(System.IO.Path.DirectorySeparatorChar);
            if (i > -1)
            {
                Dir dir = FindOrCreate(path.Substring(0, i), false);
                return dir.FindOrCreate(path.Substring(i + 1), true);
            }

            if (path == "") return this;

            // if the name is at the end of a path and contains a "." 
            // we assume it is a file (unless it is "." by itself)
            if (mightBeFile && path != "." && path.Contains("."))
            {
                Files.Add(path);
                return this;
            }

            Dir child;
            if (Dirs.ContainsKey(path))
            {
                child = Dirs[path];
            }
            else
            {
                child = new Dir(path);
                Dirs.Add(path, child);
            }
            return child;
        }
    }

    class DirConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return (objectType == typeof(Dir));
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            Dir dir = (Dir)value;
            JObject obj = new JObject();
            if (dir.Files.Count > 0)
            {
                JArray files = new JArray();
                foreach (string name in dir.Files)
                {
                    files.Add(new JValue(name));
                }
                obj.Add("list_of_files", files);
            }
            foreach (var kvp in dir.Dirs)
            {
                obj.Add(kvp.Key, JToken.FromObject(kvp.Value, serializer));
            }
            obj.WriteTo(writer);
        }

        public override bool CanRead
        {
            get { return false; }
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }
    }


    public class TreeToJson
    {
        public static void Convert(string rootDirectoryPath, string initialOutputPath, string jsonOutputPath)
        {
            var test = new FileSystemContent();
            test.Tree(rootDirectoryPath, initialOutputPath);
            var dirArray = File.ReadAllLines(initialOutputPath);
            Dir root = new Dir("");
            foreach (string dir in dirArray)
            {
                root.FindOrCreate(dir);
            }

            JsonSerializerSettings settings = new JsonSerializerSettings();
            settings.Converters.Add(new DirConverter());
            settings.Formatting = Newtonsoft.Json.Formatting.Indented;

            using (StreamWriter w = new StreamWriter(jsonOutputPath))
            {
                //string json = JsonConvert.SerializeObject(root, settings);
                w.WriteLine(JsonConvert.SerializeObject(root, settings));
            }
        }
    }
}
"@


    $CheckMyCoreUtilsDownloadIdLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.TreeToJson"}
    if ($CheckMyCoreUtilsDownloadIdLoaded -eq $null) {
        Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition -WarningAction SilentlyContinue
    }
    else {
        Write-Verbose "The Namespace MyCore.Utils Class TreeToJson is already loaded and available!"
    }

    [MyCore.Utils.TreeToJson]::Convert($RootDirectory,$InitialOutput,$JsonFileOutputPath)

}

    
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnzJ0B0jT9q3V0tBYK0AuzjuC
# K+Kgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGQ+4JXXFzEqla2K
# 9eSSfT/5T3PwMA0GCSqGSIb3DQEBAQUABIIBALPBpSyx9+sy+v1gtKnWs9gy8PK/
# tefgyjOiQmK01lK3z+3ApNtbsoIK5vKaAdEUscJdwjQGsVHSGN3xdUb8YJI+uz0X
# eaexMaqeXSSO5hEszNYaUogPSecy2aQ+B2ucGcTRGvZK6VLP7Ch0ndaGquT/nLwv
# g6FvhVdAtOp2y8JmTFg9k3YTENC5iko4SJBWDcVfQW/kX4Zlkuqx1EBuT1fYxPfa
# w1cxHX1Ju4S4m5wgjIFd0Tc2KJ6AtBF2f6uHib5mtIL+woflNm72cijyHUwOtZm0
# roXX1aD5rd/vzL9JBw8uvPa9abIajHORCwUfS+cHTtaV1clP+qZkioJeWEw=
# SIG # End signature block
