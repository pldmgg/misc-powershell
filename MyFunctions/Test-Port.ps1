function Test-Port {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {
        
        ##### BEGIN Parameter Validation #####

        function Test-IsValidIPAddress([string]$IPAddress) {
            [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
            [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
            Return  ($Valid -and $Octets)
        }

        $HostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $HostName)) {
            try {
                $HostIP = $(Resolve-DNSName $HostName).IPAddress
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostIP) {
                # Filter out any non IPV4 IP Addresses that are in $HostIP
                $HostIP = $HostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $HostIP, just select the first one
                if ($HostIP.Count -gt 1) {
                    $IP = $HostIP[0]
                }
                if ($HostIP -eq "127.0.0.1") {
                    $LocalHostInfo = Get-CimInstance Win32_ComputerSystem
                    $DNSHostName = "$($LocalHostInfo.Name)`.$($LocalHostInfo.Domain)"
                    $HostNameFQDN = $DNSHostName
                }
                else {
                    $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                    $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
                }

                $pos = $HostNameFQDN.IndexOf(".")
                $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostIP) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostName) {
            try {
                $HostIP = $HostName
                $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
            }
            catch {
                Write-Verbose "Unable to resolve $HostName!"
            }
            if ($HostNameFQDN) {
                if ($($HostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                    $pos = $HostNameFQDN.IndexOf(".")
                    $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                    $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)
                }
                else {
                    $HostNameFQDNPre = $HostNameFQDN
                    $HostNameFQDNPost = $HostNameFQDN
                }

                $HostNetworkInfoArray += $HostIP
                $HostNetworkInfoArray += $HostNameFQDN
                $HostNetworkInfoArray += $HostNameFQDNPre
            }
            if (!$HostNameFQDN) {
                Write-Error "Unable to resolve $HostName! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        ##### END Parameter Validation #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        $tcp = New-Object Net.Sockets.TcpClient
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$HostName","Test Connection on $HostName`:$Port")) {
            try {
                $tcp.Connect($HostName, $Port)
            }
            catch {}

            if ($tcp.Connected) {
                $tcp.Close()
                $open = $true
            }
            else {
                $open = $false
            }

            $PortTestResult = [pscustomobject]@{
                Address      = $HostName
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}