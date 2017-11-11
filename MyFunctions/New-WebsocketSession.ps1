<#
.SYNOPSIS
    Start a new interactive WebSockets Session

.DESCRIPTION
    See .Synopsis

.NOTES
    Depends on third-party library WebSocket-Sharp:
    https://github.com/sta/websocket-sharp    

.PARAMETER WSEndpointUrl
    This parameter is MANDATORY.

    This parameter takes a string that represents a URL to a WebSocket endpoint.

.EXAMPLE
    PS C:\Users\testadmin> [MyCore.Utils.WebsocketClient]::StartWSSession("wss://ws.blockchain.info/inv")

    Type 'exit' to exit.

    > {"op":"ping"}
    {"op":"pong"}
    WebSocket Message:
    > exit

    WebSocket Close (1001):
    PS C:\Users\testadmin>

#>

function New-WebsocketSession {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$WSEndpointUrl,

        [Parameter(Mandatory=$False)]
        [string]$PathToWebSocketSharpDLL
    )

    ##### BEGIN Native Helper Functions #####

    function Download-WebSocketsSharp {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$NuGetPkgDownloadPath
        )
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
        $($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
            $WebSocketSharpUri = "https://www.nuget.org/api/v2/package/WebSocketSharp/1.0.3-rc11"
        }
        if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
            $WebSocketSharpUri = "https://www.nuget.org/api/v2/package/WebSocketSharp-netstandard"
        }
    
        try {
            $OutFileBaseNamePrep = Invoke-WebRequest $WebSocketSharpUri -DisableKeepAlive -UseBasicParsing
            $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
            $DllFileName = $OutFileBaseName -replace "zip","dll"
            
            if (!$OutFileBaseName) {
                throw
            }
        }
        catch {
            $OutFileBaseName = "WebSocketSharp_LatestAsOf_$(Get-Date -Format MMddyy).zip"
        }
    
        $TestPath = $NuGetPkgDownloadPath
        $BrokenDir = while (-not (Test-Path $TestPath)) {
            $CurrentPath = $TestPath
            $TestPath = Split-Path $TestPath
            if (Test-Path $TestPath) {$CurrentPath}
        }
    
        if ([String]::IsNullOrWhitespace([System.IO.Path]::GetExtension($NuGetPkgDownloadPath))) {
            # Assume it's a directory
            if ($BrokenDir) {
                if ($BrokenDir -eq $NuGetPkgDownloadPath) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
    
                $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
            }
            else {
                if ($(Get-ChildItem $NuGetPkgDownloadPath).Count -ne 0) {
                    $NewDir = "$NuGetPkgDownloadPath\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
            }
        }
        else {
            # Assume it's a file
            $OutFileBaseName = $NuGetPkgDownloadPath | Split-Path -Leaf
            $extension = [System.IO.Path]::GetExtension($OutFileBaseName)
            if ($extension -ne ".zip") {
                $OutFileBaseName = $OutFileBaseName -replace "$extension",".zip"
            }
    
            if ($BrokenDir) {
                Write-Host "BrokenDir is $BrokenDir"
                if ($BrokenDir -eq $($NuGetPkgDownloadPath | Split-Path -Parent)) {
                    $null = New-Item -ItemType Directory -Path $BrokenDir -Force
                }
                else {
                    Write-Error "The path $TestPath was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
    
                $FinalNuGetPkgPath = "$BrokenDir\$OutFileBaseName"
            }
            else {
                if ($(Get-ChildItem $($NuGetPkgDownloadPath | Split-Path -Parent)).Count -ne 0) {
                    $NewDir = "$($NuGetPkgDownloadPath | Split-Path -Parent)\$([System.IO.Path]::GetFileNameWithoutExtension($OutFileBaseName))"
                    $null = New-Item -ItemType Directory -Path $NewDir -Force
                }
                
                $FinalNuGetPkgPath = "$NewDir\$OutFileBaseName"
            }
        }
    
        if ($PSVersionTable.PSEdition -eq "Core") {
            $subdir = "lib\netstandard2.0"
        }
        else {
            $subdir = "lib"
        }
    
        $NuGetPkgDownloadPathParentDir = $FinalNuGetPkgPath | Split-Path -Parent
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
        
        ##### BEGIN Main Body #####
    
        # Download the NuGet Package
        Write-Host "Downloading WebSocketSharp NuGet Package to $FinalNuGetPkgPath..."
        Invoke-WebRequest -Uri $WebSocketSharpUri -OutFile $FinalNuGetPkgPath
    
        Write-Host "Extracting WebSocketSharp NuGet Package ..."
        Expand-Archive -Path $FinalNuGetPkgPath -DestinationPath $NuGetPkgDownloadPathParentDir
    
        $AssemblyPath = "$NuGetPkgDownloadPathParentDir\$subdir\websocket-sharp.dll"
    
        [pscustomobject]@{
            NuGetPackageDirectory   = $NuGetPkgDownloadPathParentDir
            AssemblyToLoad          = $AssemblyPath
        }
        
        ##### END Main Body #####
    
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($PSVersionTable.PSEdition -eq "Core") {
        Write-Error "This function can only be run on Windows PowerShell 5.1! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PathToWebSocketSharpDLL) {
        if (! $(Test-Path $PathToWebSocketSharpDLL)) {
            Write-Error "The path $PathToWebSocketSharpDLL was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $WebSocketSharpAssemblyInfo = $CurrentlyLoadedAssemblies | Where-Object {$_.GetName().Name -eq "websocket-sharp"}
    
    if (!$WebSocketSharpAssemblyInfo) {
        if (!$PathToWebSocketSharpDLL) {
            $WebSocketSharpDLInfo = Download-WebSocketsSharp -NuGetPkgDownloadPath "$HOME\Downloads"
            $AssemblyToLoad = $WebSocketSharpDLInfo.AssemblyToLoad
            Add-Type -Path $AssemblyToLoad
        }
        else {
            Add-Type -Path $PathToWebSocketSharpDLL
        }
    }
    
    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $WebSocketSharpAssemblyInfo = $CurrentlyLoadedAssemblies | Where-Object {$_.GetName().Name -eq "websocket-sharp"}

    $AssembiesFullInfo = $CurrentlyLoadedAssemblies | Where-Object {
        $_.GetName().Name -eq "Microsoft.CSharp" -or
        $_.GetName().Name -eq "mscorlib" -or
        $_.GetName().Name -eq "System" -or
        $_.GetName().Name -eq "System.Collections" -or
        $_.GetName().Name -eq "System.Core" -or
        $_.GetName().Name -eq "System.IO" -or
        $_.GetName().Name -eq "System.Linq" -or
        $_.GetName().Name -eq "System.Runtime" -or
        $_.GetName().Name -eq "System.Runtime.Extensions" -or
        $_.GetName().Name -eq "System.Runtime.InteropServices" -or
        $_.GetName().Name -eq "System.Threading" -or
        $_.GetName().Name -eq "websocket-sharp"
    }
    $AssembiesFullInfo = $AssembiesFullInfo | Where-Object {$_.IsDynamic -eq $False}

    $ReferencedAssemblies = $AssembiesFullInfo.FullName | Sort-Object | Get-Unique

    $usingStatementsAsString = @"
    using Microsoft.CSharp;
    using System.Collections.Generic;
    using System.Collections;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Runtime;
    using System.Threading;
    using System;
    using WebSocketSharp;
    using System.Net.WebSockets;
"@

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # From: https://github.com/sta/websocket-sharp/blob/master/Example/Program.cs

    $TypeDefinition = @"
    $usingStatementsAsString

    namespace MyCore.Utils
    { 
        public class WebSocketClient
        {
            public static void StartWSSession(string url)
            {
                using (var nf = new Notifier ())
                using (var ws = new WebSocketSharp.WebSocket(url))
                {
                    // Set the WebSocket events.
            
                    ws.OnOpen += (sender, e) => ws.Send("Hi, there!");
            
                    ws.OnMessage += (sender, e) =>
                        nf.Notify(
                        new NotificationMessage
                        {
                            Summary = "WebSocket Message",
                            //Body = !e.IsPing ? e.Data : "Received a ping.",
                            Icon = "notification-message-im"
                        }
                        );

                    ws.OnMessage += (sender, e) =>
                        Console.WriteLine(e.Data);
            
                    ws.OnError += (sender, e) =>
                        nf.Notify(
                        new NotificationMessage
                        {
                            Summary = "WebSocket Error",
                            Body = e.Message,
                            Icon = "notification-message-im"
                        }
                        );

                    ws.OnError += (sender, e) =>
                        Console.WriteLine(e.Message);
            
                    ws.OnClose += (sender, e) =>
                        nf.Notify(
                        new NotificationMessage
                        {
                            Summary = String.Format("WebSocket Close ({0})", e.Code),
                            Body = e.Reason,
                            Icon = "notification-message-im"
                        }
                        );

                    ws.OnClose += (sender, e) =>
                        Console.WriteLine(e.Reason);
            
                    // Connect to the server.
                    ws.Connect();
            
                    // Connect to the server asynchronously.
                    //ws.ConnectAsync ();
            
                    Console.WriteLine("\nType 'exit' to exit.\n");
                    while (true)
                    {
                        Thread.Sleep(1000);
                        Console.Write("> ");
                        var msg = Console.ReadLine();
                        if (msg == "exit")
                            break;
            
                        // Send a text message.
                        ws.Send(msg);
                    }
                }
            }
        }

        internal class NotificationMessage
        {
            public string Body
            {
                get; set;
            }
        
            public string Icon
            {
                get; set;
            }
        
            public string Summary
            {
                get; set;
            }
        
            public override string ToString()
            {
                return String.Format("{0}: {1}", Summary, Body);
            }
        }
        
        internal class Notifier : IDisposable
        {
            private volatile bool _enabled;
            private ManualResetEvent _exited;
            private Queue<NotificationMessage> _queue;
            private object _sync;
        
            public Notifier()
            {
                _enabled = true;
                _exited = new ManualResetEvent(false);
                _queue = new Queue<NotificationMessage>();
                _sync = ((ICollection)_queue).SyncRoot;
        
                ThreadPool.QueueUserWorkItem(
                    state =>
                    {
                        while (_enabled || Count > 0)
                        {
                            var msg = dequeue();
                            if (msg != null)
                            {
                                Console.WriteLine(msg);
                            }
                            else
                            {
                                Thread.Sleep(500);
                            }
                        }
                        
                        _exited.Set();
                    }
                );
            }
        
            public int Count
            {
                get
                {
                    lock (_sync)
                        return _queue.Count;
                }
            }
        
            private NotificationMessage dequeue()
            {
                lock (_sync)
                    return _queue.Count > 0 ? _queue.Dequeue() : null;
            }
        
            public void Close()
            {
                _enabled = false;
                _exited.WaitOne();
                _exited.Close();
            }
        
            public void Notify(NotificationMessage message)
            {
                lock (_sync)
                {
                    if (_enabled)
                        _queue.Enqueue(message);
                }
            }
        
            void IDisposable.Dispose()
            {
                Close();
            }
        }

        
    }
"@

    $CheckMyCoreUtilsWebSocketClientLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.WebSocketClient*"}
    if ($CheckMyCoreUtilsWebSocketClientLoaded -eq $null) {
        Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
    }
    else {
        Write-Verbose "The Namespace MyCore.Utils Class WebSocketClient is already loaded and available!"
    }

    [MyCore.Utils.WebsocketClient]::StartWSSession($WSEndpointUrl)

    ##### END Main Body #####

}














# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUazgMRxggMX+57DFUi6ywpVus
# ngKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOdax67rBj0l1K5+
# pNpVFCu9rfB7MA0GCSqGSIb3DQEBAQUABIIBADrz3fhGWq/sqDEZgwRs7L17/Ori
# HfXMS1wsKfOgdC8gwCpcDD24CQFtXmUf5fDJWjDCGovnxusYbf/ILt67Xx5E49dM
# XbvGFBXbPNL16QkozhXE6KhabNYMKJvXLxPaiwAWDoz+y07qfxGgctCtOCJMHObT
# 8xb6lVDLUO3Oysoy8nVfe1z+SzypgFd9QCymbCS4WAi9YVPNaH6m3D/MJb77F1ae
# LDkF2rnVvQmAh3ImYpAvlEyWtNogJCKWUyIeOp4fVhbeLEoyzuewGtxw/N6S4F+d
# dO85WV6XRuZm8L3h0L785TEMSiTaVeNsT78NXRIcpe/R3gcd8DNQ6lct/CM=
# SIG # End signature block
