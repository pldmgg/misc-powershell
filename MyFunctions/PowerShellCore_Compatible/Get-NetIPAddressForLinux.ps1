function Get-NetIPAddressForLinux {
    [CmdletBinding()]
    $source = @"
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Net;
using System.Net.NetworkInformation;

public class NetworkInfo
{
    public class InterfaceInfo
    {
        public string Interface { get; set; }
        public string InterfaceAlias { get; set; }
        public string Status { get; set; }
        public string IPv4Address { get; set; }
        public string IPv4SubnetMask { get; set; }
        public string IPv6Address { get; set; }
        public int IPv6PrefixLength { get; set; }
    }

    public static InterfaceInfo[] GetNetworkInformation()
    {
        List<InterfaceInfo> result = new List<InterfaceInfo>();

        // Get all network interfaces on the system
        NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (NetworkInterface netInterface in networkInterfaces)
        {
            InterfaceInfo info = new InterfaceInfo();
            info.Interface = netInterface.Name;
            info.InterfaceAlias = netInterface.Description;
            info.Status = netInterface.OperationalStatus.ToString();

            // Get IP properties for each interface
            IPInterfaceProperties ipProperties = netInterface.GetIPProperties();

            // Get Unicast IP Addresses (IPv4 and IPv6)
            foreach (UnicastIPAddressInformation ip in ipProperties.UnicastAddresses)
            {
                if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) // IPv4
                {
                    info.IPv4Address = ip.Address.ToString();
                    info.IPv4SubnetMask = ip.IPv4Mask.ToString();
                }
                else if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) // IPv6
                {
                    info.IPv6Address = ip.Address.ToString();
                    info.IPv6PrefixLength = ip.PrefixLength;
                }
            }

            result.Add(info);
        }

        return result.ToArray();
    }
}
"@

    # Compile the C# code and load the assembly using Add-Type
    try {Add-Type -TypeDefinition $source} catch { Write-Host $_.Exception.Message }

    # Output the result of the GetNetworkInformation method
    [NetworkInfo]::GetNetworkInformation()
}