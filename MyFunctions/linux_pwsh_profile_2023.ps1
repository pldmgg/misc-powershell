function Cache-SudoPwd {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [securestring]$SudoPass,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession
    )

    if ($PSSession) {
        if ($PSVersionTable.PSVersion -ge [version]'7.1') {
            Invoke-Command $PSSession -ScriptBlock {
                param([securestring]$SudoPassSS)
                $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPassSS))) | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @($SudoPass)
        } else {
            Invoke-Command $PSSession -ScriptBlock {
                param([String]$SudoPassPT)
                $null = $SudoPassPT | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass)))
        }
    } else {
        if (!$PSSenderInfo) {
            Write-Error -Message "You must be running this function from within a PSSession or provide a PSSession object via the -PSSession parameter! Halting!"
            return
        }
        $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass))) | sudo -S whoami 2>&1
        if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
    }
}


function presudo {Cache-SudoPwd -SudoPass $(Read-Host 'Enter sudo password' -AsSecureString)}


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


<#
.SYNOPSIS
    Get all information about interfaces on your local machine

.DESCRIPTION
    See .SYNOPSIS

.PARAMETER InterfaceStatus
    This parameter is OPTIONAL.
    
    This parameter takes a string that has a value of either "Up" or "Down".

.PARAMETER AddressFamily
    This parameter is OPTIONAL.

    This parameter takes a string that has a value of either "IPv4" or "IPv6"

.EXAMPLE
    # On Windows
    PS C:\Users\testadmin> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"

.EXAMPLE
    # On Linux
    PS /home/pdadmin/Downloads> Get-NetworkInfo interfaceStatus "Up" -AddressFamily "IPv4"
#>
function Get-NetworkInfo {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateSet("Up","Down")]
        [string]$InterfaceStatus,

        [Parameter(Mandatory=$False)]
        [ValidateSet("IPv4","IPv6")]
        [string]$AddressFamily
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($AddressFamily) {
        if ($AddressFamily -eq "IPv4") {
            $AddrFam = "InterNetwork"
        }
        if ($AddressFamily -eq "IPv6") {
            $AddrFam = "InterNetworkV6"
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    [System.Collections.Arraylist]$PSObjectCollection = @()
    $interfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()

    $InterfacesToExplore = $interfaces
    if ($InterfaceStatus) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$_.OperationalStatus -eq $InterfaceStatus}
    }
    if ($AddressFamily) {
        $InterfacesToExplore = $InterfacesToExplore | Where-Object {$($_.GetIPProperties().UnicastAddresses | foreach {$_.Address.AddressFamily}) -contains $AddrFam}
    }

    foreach ($adapter in $InterfacesToExplore) {
        $ipprops = $adapter.GetIPProperties()
        $ippropsPropertyNames = $($ipprops | Get-Member -MemberType Property).Name

        if ($AddressFamily) {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses | Where-Object {$_.Address.AddressFamily -eq $AddrFam}
        }
        else {
            $UnicastAddressesToExplore = $ipprops.UnicastAddresses
        }

        foreach ($ip in $UnicastAddressesToExplore) {
            $FinalPSObject = [pscustomobject]@{}
            
            $adapterPropertyNames = $($adapter | Get-Member -MemberType Property).Name
            foreach ($adapterPropName in $adapterPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $adapterPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $adapterPropName -Value $($adapter.$adapterPropName)
                }
            }
            
            foreach ($ippropsPropName in $ippropsPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $ippropsPropName -and
                $ippropsPropName -ne "UnicastAddresses" -and $ippropsPropName -ne "MulticastAddresses") {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $ippropsPropName -Value $($ipprops.$ippropsPropName)
                }
            }
                
            $ipUnicastPropertyNames = $($ip | Get-Member -MemberType Property).Name
            foreach ($UnicastPropName in $ipUnicastPropertyNames) {
                $FinalPSObjectMemberCheck = $($FinalPSObject | Get-Member -MemberType NoteProperty).Name
                if ($FinalPSObjectMemberCheck -notcontains $UnicastPropName) {
                    $FinalPSObject | Add-Member -MemberType NoteProperty -Name $UnicastPropName -Value $($ip.$UnicastPropName)
                }
            }
            
            $null = $PSObjectCollection.Add($FinalPSObject)
        }
    }

    $PSObjectCollection

    ##### END Main Body #####
        
}


function Process-ICM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$True)]
        [string]$Command
    )

    # Validate [string]$Command has a line in it that indicates $OutputThatICareAbout is below here...
    $OutputIndicatorLine = ($Command -split "`n") -match 'SuccessOutput'
    if (!$OutputIndicatorLine) {
        Write-Error "The Command you provided does not have a line with the string 'SuccessOutput' (including single quotes)`
        that indicates where the output you care about is. Halting!"
        return
    }

    Invoke-Command -Session $PSSession {Invoke-Expression -Command $using:Command} -ErrorVariable icmErrs 2>&1 | Tee-Object -Variable icmAllOutput *>$null

    $ErrsThatICareAbout = $icmErrs.Exception.Message -notmatch '^NotSpecified'
    #if ($ErrsThatICareAbout.Count -gt 0) {$ErrsThatICareAbout | foreach {Write-Error $_}}
    $OutputThatICareAbout = $icmAllOutput[($icmAllOutput.IndexOf('SuccessOutput') + 1)..$icmAllOutput.Count]
    #if ($OutputThatICareAbout.Count -gt 0) {$OutputThatICareAbout | foreach {$_}}

    [pscustomobject]@{
        Errors = $icmErrs
        Output = $icmAllOutput
        RealErrors = $ErrsThatICareAbout
        RealOutput = $OutputThatICareAbout
    }

    Write-Host $OutputThatICareAbout
}