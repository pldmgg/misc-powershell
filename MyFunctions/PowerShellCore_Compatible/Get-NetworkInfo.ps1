<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.NOTES
    DEPENDENCIES
        Helper scripts/functions and/or binaries needed for the function to work.
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
.COMPONENT
    The component this cmdlet belongs to
.ROLE
    The role this cmdlet belongs to
.FUNCTIONALITY
    The functionality that best describes this cmdlet
#>
function Get-NetworkInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$True)]
        [ValidateSet("Up","Down")]
        [string]$InterfaceStatus,

        [Parameter(Mandatory=$True)]
        [ValidateSet("IPv4","IPv6")]
        [string]$AddressFamily
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
    $($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        $AssembliesToLoad = @(
            "Microsoft.CSharp"
            "mscorlib"
            "System"
            "System.Collections"
            "System.Core"
            "System.IO"
            "System.Linq"
            "System.Net.NetworkInformation"
            "System.Net.Primitives"
            "System.Runtime"
            "System.Runtime.Extensions"
        )
    }
    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        $AssembliesToLoad = @(
            "Microsoft.CSharp"
            "System"
            "System.Collections"
            "System.Console"
            "System.Core"
            "System.IO"
            "System.Linq"
            "System.Net.NetworkInformation"
            "System.Net.Primitives"
            "System.Net.Sockets"
            "System.Private.CoreLib"
            "System.Runtime"
            "System.Runtime.Extensions"
        )
    }

    $usingStatementsAsString = @"
    using Microsoft.CSharp;
    using System.Collections.Generic;
    using System.Collections;
    using System.IO;
    using System.Linq;
    using System.Net.NetworkInformation;
    using System.Net.Sockets;
    using System.Net;
    using System.Runtime;
    using System;
"@

    [System.Collections.ArrayList]$AssembliesFullInfo = @()
    foreach ($AssemblyName in $AssembliesToLoad) {
        $AssemCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.GetName().Name -eq $AssemblyName}
        if (!$AssemCheck) {
            $AssemblyInfo = [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
            $null = $AssembliesFullInfo.Add($AssemblyInfo)
        }
        else {
            $null = $AssembliesFullInfo.Add($AssemCheck)
        }
    }
    $AssembliesFullInfo = $AssembliesFullInfo | Where-Object {$_.IsDynamic -eq $False}

    $ReferencedAssemblies = $AssembliesFullInfo.FullName | Sort-Object | Get-Unique

    $AllAdapterProps = @"
adapterProperties.Add("Id", adapter.Id.ToString());
adapterProperties.Add("Name", adapter.Name.ToString());
adapterProperties.Add("Description", adapter.Description.ToString());
adapterProperties.Add("OperationalStatus", adapter.OperationalStatus.ToString());
adapterProperties.Add("Speed", adapter.Speed.ToString());
adapterProperties.Add("IsReceiveOnly", adapter.IsReceiveOnly.ToString());
adapterProperties.Add("SupportsMulticast", adapter.SupportsMulticast.ToString());
adapterProperties.Add("NetworkInterfaceType", adapter.NetworkInterfaceType.ToString());
"@

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or 
    $($PSVersionTable.PSVersion.Major -lt 5 -and $PSVersionTable.PSVersion.Major -ge 3)) {
        # Adapter Properties for Windows...
        $adapterProps = $AllAdapterProps

        $DynamicDnsProperty = 'adapterProperties.Add("IsDynamicDnsEnabled", ipProps.IsDynamicDnsEnabled.ToString());'

        # IP Properties for Windows...
        $ipProps = @"
        ipProperties.Add("AddressPreferredLifetime", ip.AddressPreferredLifetime.ToString());
        ipProperties.Add("AddressValidLifetime", ip.AddressValidLifetime.ToString());
        ipProperties.Add("DhcpLeaseLifetime", ip.DhcpLeaseLifetime.ToString());
        ipProperties.Add("DuplicateAddressDetectionState", ip.DuplicateAddressDetectionState.ToString());
        ipProperties.Add("PrefixOrigin", ip.PrefixOrigin.ToString());
        ipProperties.Add("SuffixOrigin", ip.SuffixOrigin.ToString());
        ipProperties.Add("IPv4Mask", ip.IPv4Mask.ToString());
        ipProperties.Add("PrefixLength", ip.PrefixLength.ToString());
        ipProperties.Add("Address", ip.Address.ToString());
        ipProperties.Add("IsDnsEligible", ip.IsDnsEligible.ToString());
        ipProperties.Add("IsTransient", ip.IsTransient.ToString());
"@
    }
    if ($PSVersionTable.Platform -ne $null -and $PSVersionTable.Platform -ne "Win32NT") {
        # Adapter Properties for Linux...
        $adapterProps = $($AllAdapterProps -split "`n" | Where-Object {$_ -notlike "*IsReceiveOnly*"}) -join "`n"

        # IP Properties for Linux...
        $ipProps = @"
        ipProperties.Add("IPv4Mask", ip.IPv4Mask.ToString());
        ipProperties.Add("Address", ip.Address.ToString());
"@
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $TypeDefinition = @"
    $usingStatementsAsString
    
    namespace MyCore.Utils
    { 
        public class NetworkInfo
        {
            public static List<InterfaceDetails> GetIPInfo(string operationalStatus = "Up", string ipAddressFamily = "IPv4")
            {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                List<InterfaceDetails> output = new List<InterfaceDetails>();
            
                AddressFamily addrFam = new AddressFamily();
                if (ipAddressFamily == "IPv4")
                {
                    addrFam = AddressFamily.InterNetwork;
                }
                else
                {
                    addrFam = AddressFamily.InterNetworkV6;
                }
            
                OperationalStatus opStat = new OperationalStatus();
                if (operationalStatus == "Up")
                {
                    opStat = OperationalStatus.Up;
                }
                else
                {
                    opStat = OperationalStatus.Down;
                }
            
                foreach (NetworkInterface adapter in interfaces)
                {
                    var ipProps = adapter.GetIPProperties();
            
                    foreach (var ip in ipProps.UnicastAddresses)
                    {
                        if ((adapter.OperationalStatus == opStat) && (ip.Address.AddressFamily == addrFam))
                        {
                            InterfaceDetails intDetails = new InterfaceDetails();
                            Dictionary<string, string> adapterProperties = new Dictionary<string, string>();
                            Dictionary<string, string> ipProperties = new Dictionary<string, string>();
                            
                            adapterProperties.Add("IsDnsEnabled", ipProps.IsDnsEnabled.ToString());
                            adapterProperties.Add("DnsSuffix", ipProps.DnsSuffix.ToString());
                            $DynamicDnsProperty
                            adapterProperties.Add("DnsAddresses", String.Join(", ", ipProps.DnsAddresses));
                            List<string> GatewayAddressList = new List<string>();
                            foreach (GatewayIPAddressInformation address in ipProps.GatewayAddresses)
                            {
                                GatewayAddressList.Add(address.Address.ToString());
                            }
                            adapterProperties.Add("GatewayAddresses", String.Join(", ", GatewayAddressList));
                            adapterProperties.Add("DhcpServerAddresses", String.Join(", ", ipProps.DhcpServerAddresses));
                            $adapterProps
                            
                            

                            $ipProps

                            intDetails.adapterProperties = adapterProperties;
                            intDetails.ipProperties = ipProperties;
                            
                            output.Add(intDetails);
                        }
                    }
                }
                
                return output;
            }
        }
    
        public class InterfaceDetails
        {
            public Dictionary<string, string> adapterProperties { get; set; }
            public Dictionary<string, string> ipProperties { get; set; }
        }
    }
"@

    $CheckMyCoreUtilsNetworkInfoLoaded = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes -like "MyCore.Utils.NetworkInfo*"}
    if ($CheckMyCoreUtilsNetworkInfoLoaded -eq $null) {
        Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition
    }
    else {
        Write-Verbose "The Namespace MyCore.Utils Class NetworkInfo is already loaded and available!"
    }

    $ResultsPrep = [MyCore.Utils.NetworkInfo]::GetIPInfo($InterfaceStatus, $AddressFamily)
    $ResultsPrep2 = $($ResultsPrep.GetEnumerator())

    [System.Collections.ArrayList]$Results = @()
    for ($i=0; $i -lt $ResultsPrep2.Count; $i++) {
        $IPProperties = $ResultsPrep2[$i].ipProperties
        $AdapterProperties = $ResultsPrep2[$i].adapterProperties
        $resultht = $IPProperties + $AdapterProperties

        $result = [pscustomobject]@{}
        foreach ($key in $resultht.Keys) {
            $result | Add-Member -MemberType NoteProperty -Name $key -Value $resultht[$key]
        }
        
        $null = $Results.Add($result)
    }

    $Results

    ##### END Main Body #####
        
}






















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5cCZwmS543Gy0INKAeD4Un0a
# p6Ogggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFI1VIXGiR3AbXtGX
# FM5L7WT9cBDRMA0GCSqGSIb3DQEBAQUABIIBAH1hZQAc5WvyKZJbKjI9TwjAmnyQ
# 7tEXC3CRh/D5hOk/G7J2AI0f5nFja9b6pijIN5HzB93RTilPthV799kxx7qxKYJF
# BLCjMk1EQ87RG0OvDsD9sAorfpJMsBvKN5nIwHXsbTHsWJx3oBm0D+5DlznESpie
# qknkIclSVINa5xFWkba9sfozJKT1okCMfedGEBQaKbjj1FHrWMGfgecZf61wyT6+
# N+M+FpHtFQmp1eVKrP+0d36TW8Vr9Uv9j745qzq49Al0OrcYKPUR7ji3iOWMRY5y
# hhzaLxye8OSQbxCf0uFO/x4YbWVCsbVbVKBjDI0lKoFBDBoBt/EnqE2IeG8=
# SIG # End signature block
