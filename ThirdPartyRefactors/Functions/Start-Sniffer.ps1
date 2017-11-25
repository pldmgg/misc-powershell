<#
.SYNOPSIS
    A .Net based PowerShell packet sniffer that outputs PSCustomObjects, Json, and/or XML.

    It does NOT sniff https.

.DESCRIPTION
    A .Net based PowerShell packet sniffer ("promiscuous mode" must be supported by hardware/driver)

    Originally From: https://github.com/sperner/PowerShell/blob/master/Sniffer.ps1

    Updated by Paul DiMaggio | pldmgg@github.com | /u/fourierswager (reddit)

.PARAMETER 


.PARAMETER LocalIP
    This parameter is OPTIONAL.

    This parameter takes a string that represents the IPv4 Address on your local machine that could be the
    Source or Destination of the packet being sniffed.
    
    If this parameter is not provided, it will be determined automatically.

.PARAMETER ScanIP
    This parameter is OPTIONAL.

    This parrameter takes a string that represents an IPv4 IP Address that could be the Source or Destination
    of the packet being sniffed. If used, packets that do not match this value are NOT collected.

.PARAMETER Protocol
    This parameter is OPTIONAL.

    This parameter takes a string that represents the protocol (TCP, UDP, IGMP, ICMP, or all). If used, packets
    that do not match this value are NOT collected.

.PARAMETER Port
    This parameter is OPTIONAL.

    This parameter takes a string that represents a port number that could be the Source Port or Destination Port
    of the packet being sniffed. If used, packets that do not match this value are NOT collected.

.PARAMETER LocalPort
    This parameter is OPTIONAL.

    This parameter takes an integer that represents a port number being used by your local machine. If used,
    packets that do not match this value are NOT collected.

.PARAMETER RemotePort
    This parameter is OPTIONAL.

    This paramter takes an integer that represents a port number being used by the Remote Host. If used,
    packets that do not match this value are NOT collected.

.PARAMETER Seconds
    This parameter is OPTIONAL.

    This parameter takes an integer that represents the number of seconds until the Start-Sniffer function
    times out. If this parameter is not used or if the value supplied is 0, then there is no timeout.

.PARAMETER ResolveHosts
    This parameter is OPTIONAL.

    This parameter is a switch. If used, packet capure output will attempt to resolve source and 
    destination IP Addresses to Host Names using DNS.

.PARAMETER CaptureOutput
    This parameter is OPTIONAL.

    This parameter takes a boolean $true/$false value that indicates whether or not the output of this function
    can be saved to a variable in PowerShell. The default value for this parameter is $true. If it is $false,
    output will still be sent to STDOUT, but will NOT be able to be saved to a variable

    In the below, $test will contain the results of Start-Sniffer as an Array of PSCustomObjects. No STDOUT will
    be seen by the user.
        PS C:\Users\testadmin> $test = Start-Sniffer -RemotePort 3128 -OutputFile 'C:\Users\testadmin\Downloads\PacketTrace_WIN16CHEF.xml'

    In the below, $test will be $null, however, all of the packets captured by Start-Sniffer will be written to STDOUT.
        PS C:\Users\testadmin> $test = Start-Sniffer -CaptureOutput $false -RemotePort 3128 -OutputFile 'C:\Users\testadmin\Downloads\PacketTrace_WIN16CHEF.xml'

.PARAMETER OutputFile
    This parameter is MANDATORY.

    This parameter takes a string that represents a full path to a .xml or .json file that will contain all packet
    capture output.

.PARAMETER MaxEntries
    This parameter is OPTIONAL.

    This parameter takes an integer that represents the number of packet capture logs that will be available for
    review as output from this function (be it saved in a variable or written to a .xml or .json file).

.EXAMPLE
    Start-Sniffer -RemotePort 3128 -ScanIP 192.168.7.129 -OutputFile 'C:\Users\testadmin\Downloads\PacketTrace_WIN16CHEF.json' -ResolveHosts

.OUTPUTS
    Either Json or PSCustomObjects to STDOUT and/or written to a .json/.xml file specified by the -OutputFile parameter.
#>
function Start-Sniffer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$LocalIP = "NotSpecified",
        
        [Parameter(Mandatory=$False)]
        [String]$ScanIP="all",
        
        [Parameter(Mandatory=$False)]
        [String]$Protocol = "all",
        
        [Parameter(Mandatory=$False)]
        [String]$Port = "all",

        [Parameter(Mandatory=$False)]
        [int]$LocalPort,

        [Parameter(Mandatory=$False)]
        [int]$RemotePort,
        
        [Parameter(Mandatory=$False)]
        [Int]$Seconds = 0,
        
        [Parameter(Mandatory=$False)]
        [switch]$ResolveHosts,
        
        [Parameter(Mandatory=$False)]
        [bool]$CaptureOutput = $True,

        [Parameter(Mandatory=$False)]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -match "\.xml|\.json"})]
        [string]$OutputFile,

        [Parameter(Mandatory=$False)]
        [int]$MaxEntries = 10000,

        [Parameter(Mandatory=$False)]
        [switch]$Help
        
    )

    ##### BEGIN Helper Functions #####

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    # Convert from big to little endian & convert to uint16
    Function NetworkToHostUInt16($address) {
        [Array]::Reverse($address)
        [BitConverter]::ToUInt16($address, 0)
    }

    # Convert from big to little endian & convert to uint32
    Function NetworkToHostUInt32($address) {
        [Array]::Reverse($address)
        [BitConverter]::ToUInt32($address, 0)
    }

    # Convert from big to little endian & convert to string
    Function ByteToString($address) {
        $AsciiEncoding = New-Object System.Text.ASCIIEncoding
        $AsciiEncoding.GetString($address)
    }


    # Get IP-address <-> hostname
    $hosts = @{} 							# array for hostnames
    Function resolve($IPAddress) {
        $data = $hosts."$($IPAddress.IPAddressToString)"
        if ($data) {
            if ($IPAddress.IPAddressToString -eq $data) {
                return [System.Net.IPAddress]$IPAddress
            }
            else {
                return $data
            }
        }
        else {
            # much faster than [System.Net.DNS]::GetHostEntry()
            $null,$null,$null,$data = nslookup $IPAddress.IPAddressToString 2>$null
            $data = $data -match "Name:"
            if ($data -match "Name:") {
                $data = $data[0] -replace "Name:\s+",""
                $hosts."$($IPAddress.IPAddressToString)" = "$data"
                return $data
            }
            else {
                $hosts."$($IPAddress.IPAddressToString)" = "$($IPAddress.IPAddressToString)"
                return $IPAddress
            }
        }
    }

    # Read protocols from services
    Function getService($port) {
        $protocols = foreach($line in $serviceFile) {            
            # not empty lines
            if(-not $line)	{
                continue
            }

            # split lines into name, port+proto, alias+comment
            $serviceName, $portAndProtocol, $aliasesAndComments = $line.Split(' ', [StringSplitOptions]'RemoveEmptyEntries')

            # split port+proto into port, proto
            $portNumber, $protocolName = $portAndProtocol.Split("/")            

            if($portNumber -eq $port) {
                return $serviceName
            }
        }
    }


    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($CaptureOutput -and !$OutputFile) {
        $OutputFile = Read-Host -Prompt "Please enter a full path to a .xml or .json file that will contain the trace output data in the form of an array of PSCustomObjects."
        if ([System.IO.Path]::GetExtension($OutputFile) -notmatch "\.xml|\.json") {
            Write-Error "$OutputFile does not have a .xml or .json extension! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($MaxEntries -gt 10000) {
        Write-Host "The maximum -MaxEntries value is 10000. Setting to 10000..."
        $MaxEntries = 10000
    }

    if ($Port -ne "all") {
        if ($LocalPort -or $RemotePort) {
            Write-Error "Please use *either* the -Port parameter OR the -LocalPort/-RemotePort parameters! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $Port = [int]$Port
        }
        catch {
            Write-Error "$Port is not a valid Port number! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($LocalIP -ne "NotSpecified") {
        if (!$(Test-IsValidIPAddress -IPAddress $LocalIP)) {
            Write-Error "$LocalIP is not a valid IPv4 address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($ScanIP -ne "all") {
        if (!$(Test-IsValidIPAddress -IPAddress $ScanIP)) {
            Write-Error "$ScanIP is not a valid IPv4 address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Help / display usage
    if ($Help) {
        Write-Host "usage: $($MyInvocation.MYCommand) [-LocalIP <String>] [-ScanIP <String>] [-Protocol <String>] [-Port <String>] [-Seconds <Int32>] [-ResolveHosts]"
        return
    }

    # Params
    $starttime = Get-Date
    $byteIn = New-Object Byte[] 4			# source
    $byteOut = New-Object Byte[] 4			# destination
    $byteData = New-Object Byte[] 4096		# size of data

    $byteIn[0] = 1  						# enable promiscuous mode
    $byteIn[1-3] = 0
    $byteOut[0-3] = 0

    # TCP Flags
    $TCPFIN = [Byte]0x01
    $TCPSYN = [Byte]0x02
    $TCPRST = [Byte]0x04
    $TCPPSH = [Byte]0x08
    $TCPACK = [Byte]0x10
    $TCPURG = [Byte]0x20

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Read "services" file
    $servicesFilePath = "$env:windir\System32\drivers\etc\services"
    # <service name>  <port number>/<protocol>  [aliases...]   [#<comment>]            
    $serviceFile = [IO.File]::ReadAllText("$env:windir\System32\drivers\etc\services") -split ([Environment]::NewLine) -notlike "#*"

    
    # Get local IP-Address
    if ($LocalIP -eq "NotSpecified") {
        if ($ScanIP -ne "all") {
            $LocalIP = $(Find-NetRoute -RemoteIPAddress $ScanIP | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
        }
        else {
            $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric)[0].NextHop
            $LocalIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
        }
    }
    if ($LocalIP.Count -gt 1) {
        Write-Host "Possible LocalIP addresses are:"
        for ($i=0; $i -lt $LocalIP.Count; $i++) {
            Write-Host "$i) $($LocalIP[$i])"
        }
        $ValidIPChoiceNumbers = 0..$($LocalIP.Count-1)
        $IPChoice = Read-Host -Prompt "Please enter the number that corresponds to the Local IP Address you would like to use. [$($ValidChoiceNumbers -join ', ')]"
        if ($ValidIPChoiceNumbers -notcontains $IPChoice) {
            Write-Error "$IPChoice is not a valid choice! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($LocalIP) {
        if ($(Get-NetIPAddress -AddressFamily IPv4).IPAddress -notcontains $LocalIP) {
            Write-Error "$LocalIP is NOT an IP Address assigned to this local host (i.e. $env:ComputerName)! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    Write-Host "Using Local IP $LocalIP..."
    Write-Host ""


    # Open a raw ip socket
    # More on Sockets here: https://codereview.stackexchange.com/questions/86759/receiving-all-data-comes-from-web-in-system-net-socket
    $Socket = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP)
    # Include the ip header
    $Socket.SetSocketOption("IP", "HeaderIncluded", $true)
    # Big packet buffer (in bytes)
    #$Socket.ReceiveBufferSize = 1024000
    $Socket.ReceiveBufferSize = 512000
    #$Socket.ReceiveBufferSize = 24576
    #$Socket.ReceiveBufferSize = 8192
    #$Socket.ReceiveBufferSize = 1024
    # Create ip endpoint
    $Endpoint = New-Object System.Net.IPEndpoint([Net.IPAddress]"$LocalIP", 0)
    $Socket.Bind($Endpoint)
    # Enable promiscuous mode
    [void]$Socket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll, $byteIn, $byteOut)

    Write-Host "Press ESC to stop the packet sniffer ..." -fore yellow
    Write-Host "IMPORTANT NOTE: There is about a 30 second delay between network activity and output!" -fore yellow
    Write-Host ""
    $ESCKey = 27
    $running = $true


    # Start sniffing
    [System.Collections.ArrayList]$PacketCustomObjects = @()
    while ($running) {
        # when a key was pressed...
        if ($host.ui.RawUi.KeyAvailable) {
            $key = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyUp,IncludeKeyDown")
            # if ESC was pressed, stop sniffing
            if ($key.VirtualKeyCode -eq $ESCkey) {
                $running = $false
            }
        }
        # timeout after $Seconds...
        if ($Seconds -ne 0 -and ($([DateTime]::Now) -gt $starttime.addseconds($Seconds))) {
            $running = $false
        }
        # no packets in card buffer...
        if (-not $Socket.Available) {
            start-sleep -milliseconds 300
            continue
        }

        # receive data
        $rData = $Socket.Receive($byteData, 0, $byteData.length, [Net.Sockets.SocketFlags]::None)
        # decode the packet
        $MemoryStream = New-Object System.IO.MemoryStream($byteData, 0, $rData)
        $BinaryReader = New-Object System.IO.BinaryReader($MemoryStream)

        # b1 - version & header length
        $VerHL = $BinaryReader.ReadByte()
        # b2 - type of service
        $TOS= $BinaryReader.ReadByte()
        # b3,4 - total length
        $Length = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
        # b5,6 - identification
        $Ident = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
        # b7,8 - flags & offset
        $FlagsOff = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
        # b9 - time to live
        $TTL = $BinaryReader.ReadByte()
        # b10 - protocol
        $ProtocolNumber = $BinaryReader.ReadByte()
        # b11,12 - header checksum
        $Checksum = [Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
        # b13-16 - source ip address
        $SourceIP = $BinaryReader.ReadUInt32()
        $SourceIP = [System.Net.IPAddress]$SourceIP
        # b17-20 - destination ip address
        $DestinationIP = $BinaryReader.ReadUInt32()
        $DestinationIP = [System.Net.IPAddress]$DestinationIP

        # get ip version (bits 0-3)
        $ipVersion = [int]"0x$(('{0:X}' -f $VerHL)[0])"
        # get header length (bits 4-7)
        $HeaderLength = [int]"0x$(('{0:X}' -f $VerHL)[1])" * 4

        # header includes Options...
        if ($HeaderLength -gt 20) {
            [void]$BinaryReader.ReadBytes( $HeaderLength - 20 )  # should probably do something with this later
        }

        $Data = ""
        $TCPFlagsString = @()  				# make this an array
        $TCPWindow = ""
        $SequenceNumber = ""

        switch ($ProtocolNumber) {
            1 {  
                # ICMP
                $ProtocolDesc = "ICMP"
                $sourcePort = [uint16]0
                $destPort = [uint16]0
                $ICMPType = $BinaryReader.ReadByte()
                $ICMPCode = $BinaryReader.ReadByte()
                switch ($ICMPType) {
                    0 {$ICMPTypeDesc = "Echo reply"; break}
                    3 {
                        $ICMPTypeDesc = "Destination unreachable"
                        switch ($ICMPCode) {
                            0	{$ICMPCodeDesc = "Network not reachable"; break}
                            1	{$ICMPCodeDesc = "Host not reachable"; break}
                            2	{$ICMPCodeDesc = "Protocol not reachable"; break}
                            3	{$ICMPCodeDesc = "Port not reachable"; break}
                            4	{$ICMPCodeDesc = "Fragmentation needed"; break}
                            5	{$ICMPCodeDesc = "Route not possible"; break}
                            13	{$ICMPCodeDesc = "Administratively not possible"; break}
                            default	{$ICMPCodeDesc = "Other ($_)"}
                        }
                        break
                    }
                    4	{$ICMPTypeDesc = "Source quench"; break}
                    5	{$ICMPTypeDesc = "Redirect"; break}
                    8	{$ICMPTypeDesc = "Echo request"; break}
                    9	{$ICMPTypeDesc = "Router advertisement"; break}
                    10	{$ICMPTypeDesc = "Router solicitation"; break}
                    11	{
                        $ICMPTypeDesc = "Time exceeded"
                        switch( $ICMPCode ) {
                            0	{$ICMPCodeDesc = "TTL exceeded"; break}
                            1	{$ICMPCodeDesc = "While fragmenting exceeded"; break}
                            default	{$ICMPCodeDesc = "Other ($_)"}
                        }
                        break
                    }
                    12	{$ICMPTypeDesc = "Parameter problem"; break}
                    13	{$ICMPTypeDesc = "Timestamp"; break}
                    14	{$ICMPTypeDesc = "Timestamp reply"; break}
                    15	{$ICMPTypeDesc = "Information request"; break}
                    16	{$ICMPTypeDesc = "Information reply"; break}
                    17	{$ICMPTypeDesc = "Address mask request"; break}
                    18	{$ICMPTypeDesc = "Address mask reply"; break}
                    30	{$ICMPTypeDesc = "Traceroute"; break}
                    31	{$ICMPTypeDesc = "Datagram conversion error"; break}
                    32	{$ICMPTypeDesc = "Mobile host redirect"; break}
                    33	{$ICMPTypeDesc = "Where-are-you"; break}
                    34	{$ICMPTypeDesc = "I-am-here"; break}
                    35	{$ICMPTypeDesc = "Mobile registration request"; break}
                    36	{$ICMPTypeDesc = "Mobile registration reply"; break}
                    37	{$ICMPTypeDesc = "Domain name request"; break}
                    38	{$ICMPTypeDesc = "Domain name reply"; break}
                    39	{$ICMPTypeDesc = "SKIP"; break}
                    40	{$ICMPTypeDesc = "Photuris"; break}
                    41	{$ICMPTypeDesc = "Experimental mobility protocol"; break}
                    default	{$ICMPTypeDesc = "Other ($_)"}
                }
                $ICMPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
                $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength - 32))
                break
            }
            2 {
                # IGMP
                $ProtocolDesc = "IGMP"
                $sourcePort = [uint16]0
                $destPort = [uint16]0
                $IGMPType = $BinaryReader.ReadByte()
                $IGMPMaxRespTime = $BinaryReader.ReadByte()
                $IGMPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
                $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength - 32))
                break
            }
            6 {
                # TCP
                $ProtocolDesc = "TCP"
                $sourcePort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                $destPort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                $serviceDesc = getService( $destPort )
                $SequenceNumber = NetworkToHostUInt32 $BinaryReader.ReadBytes(4)
                $AckNumber = NetworkToHostUInt32 $BinaryReader.ReadBytes(4)
                $TCPHeaderLength = [int]"0x$(('{0:X}' -f $BinaryReader.ReadByte())[0])" * 4
                $TCPFlags = $BinaryReader.ReadByte()
                switch ($TCPFlags) {
                    { $_ -band $TCPFIN } { $TCPFlagsString += "<FIN>" }
                    { $_ -band $TCPSYN } { $TCPFlagsString += "<SYN>" }
                    { $_ -band $TCPRST } { $TCPFlagsString += "<RST>" }
                    { $_ -band $TCPPSH } { $TCPFlagsString += "<PSH>" }
                    { $_ -band $TCPACK } { $TCPFlagsString += "<ACK>" }
                    { $_ -band $TCPURG } { $TCPFlagsString += "<URG>" }
                }
                $TCPWindow = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                $TCPChecksum = [System.Net.IPAddress]::NetworkToHostOrder($BinaryReader.ReadInt16())
                $TCPUrgentPointer = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                # get to start of data...
                if ($TCPHeaderLength -gt 20) {
                    [void]$BinaryReader.ReadBytes($TCPHeaderLength - 20)
                }
                # if SYN flag is set, sequence number is initial, then first data octet is ISN + 1
                if ($TCPFlags -band $TCPSYN) {
                    $ISN = $SequenceNumber
                    #$SequenceNumber = $BinaryReader.ReadBytes(1)
                    [void]$BinaryReader.ReadBytes(1)
                }
                $Data = ByteToString $BinaryReader.ReadBytes($Length - ($HeaderLength + $TCPHeaderLength))
                break
            }
            17 { 
                # UDP
                $ProtocolDesc = "UDP"
                $sourcePort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                $destPort = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                $serviceDesc = getService( $destPort )
                $UDPLength = NetworkToHostUInt16 $BinaryReader.ReadBytes(2)
                [void]$BinaryReader.ReadBytes(2)
                # subtract udp header length (2 octets) and convert octets to bytes
                $Data = ByteToString $BinaryReader.ReadBytes(($UDPLength - 2) * 4)
                break
            }
            default {
                $ProtocolDesc = "Other ($_)"
                $sourcePort = 0
                $destPort = 0
            }
        }

        $BinaryReader.Close()
        $memorystream.Close()
        $Data = $Data.toCharArray(0, $Data.length)

        # resolve IP addresses to hostnames...
        if ($ResolveHosts) {
            # $DestinationHostName = ([System.Net.DNS]::GetHostEntry($DestinationIP.IPAddressToString)).Hostname
            $DestinationHostName = resolve($DestinationIP)
            # $SourceHostName = ([System.Net.DNS]::GetHostEntry($SourceIP.IPAddressToString)).Hostname
            $SourceHostName = resolve($SourceIP)
        }

        $PSCustomObjOutput = [pscustomobject]@{}

        function NoCaptureOutput {
            Write-Host "Time:`t`t$(get-date)"
            Write-Host "Version:`t$ipVersion`t`t`tProtocol:`t$ProtocolNumber = $ProtocolDesc"
            Write-Host "Destination:`t$DestinationIP`t`tSource:`t`t$SourceIP"
            if ($ResolveHosts) {
                Write-Host "DestinationHostName`t$DestinationHostName`tSourceHostName`t$SourceHostName"
            }
            Write-Host "DestPort:`t$destPort`t`t`tSourcePort:`t$sourcePort"
            switch ($ProtocolDesc) {
                "ICMP" {
                    Write-Host "Type:`t`t$ICMPType`t`t`tDescription:`t$ICMPTypeDesc"
                    Write-Host "Code:`t`t$ICMPCode`t`t`tDescription:`t$ICMPCodeDesc"
                    break
                }
                "IGMP" {
                    Write-Host "Type:`t`t$IGMPType`t`t`tMaxRespTime:`t$($IGMPMaxRespTime*100)ms"
                    break
                }
                "TCP" {
                    Write-Host "Sequence:`t$SequenceNumber`t`tAckNumber:`t$AckNumber"
                    Write-Host "Window:`t`t$TCPWindow`t`t`tFlags:`t`t$TCPFlagsString"
                    Write-Host "Service:`t$serviceDesc"
                    break
                }
                "UDP" {
                    Write-Host "Service:`t$serviceDesc"
                    break
                }
            }
            for ($index = 0; $index -lt $Data.length; $index++) {
                # eliminate non ascii characters...
                if ($Data[$index] -lt 33 -or $Data[$index] -gt 126) {
                    $Data[$index] = '.'
                }
            }
            $OFS=""	# eliminate spaces from output of char array
            Write-Host "Data: $Data"
            Write-Host "----------------------------------------------------------------------"
            try {
                $SetContentFilePath = "$($OutputFile | Split-Path -Parent)\Latest_Packet.txt"
                Set-Content -Path $SetContentFilePath -Value $($(
                    "Time:`t`t$(get-date)"
                    "Version:`t$ipVersion`t`t`tProtocol:`t$ProtocolNumber = $ProtocolDesc"
                    "Destination:`t$DestinationIP`t`tSource:`t`t$SourceIP"
                    "DestinationHostName`t$DestinationHostName`tSourceHostName`t$SourceHostName"
                    "DestPort:`t$destPort`t`t`tSourcePort:`t$sourcePort"
                    "Type:`t`t$ICMPType`t`t`tDescription:`t$ICMPTypeDesc"
                    "Code:`t`t$ICMPCode`t`t`tDescription:`t$ICMPCodeDesc"
                    "Type:`t`t$IGMPType`t`t`tMaxRespTime:`t$($IGMPMaxRespTime*100)ms"
                    "Sequence:`t$SequenceNumber`t`tAckNumber:`t$AckNumber"
                    "Window:`t`t$TCPWindow`t`t`tFlags:`t`t$TCPFlagsString"
                    "Service:`t$serviceDesc"
                    "Data: $($Data -join '')"
                    "----------------------------------------------------------------------"
                ) -join "`n") -Force -ErrorAction SilentlyContinue

                if (!$?) {
                    throw
                }
            }
            catch {
                Write-Verbose "Unable to write to $SetContentFilePath - The file is already in use!"
            }
        }

        function CaptureOutput {
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Time -Value $(Get-Date)
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Version -Value $ipVersion
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Protocol -Value $([pscustomobject]@{$ProtocolNumber = $ProtocolDesc})
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Destination -Value $DestinationIP
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Source -Value $SourceIP

            if ($ResolveHosts) {
                Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name DestinationHostName -Value $DestinationHostName
                Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name SourceHostName -Value $SourceHostName
            }

            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name DestPort -Value $destPort
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name SourcePort -Value $sourcePort
            
            switch ($ProtocolDesc) {
                "ICMP" {
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Type -Value $ICMPType
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name TypeDescription -Value $ICMPTypeDesc
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Code -Value $ICMPCodeDesc
                    break
                }
                "IGMP" {
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Type -Value $IGMPType
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name MaxRespTime -Value $("$($IGMPMaxRespTime*100)ms")
                    break
                }
                "TCP" {
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Sequence -Value $SequenceNumber
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name AckNumber -Value $AckNumber
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Window -Value $TCPWindow
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Flags -Value $TCPFlagsString
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Service -Value $serviceDesc
                    break
                }
                "UDP" {
                    Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name Service -Value $serviceDesc
                    break
                }
            }
            for ($index = 0; $index -lt $Data.length; $index++) {
                # eliminate non ascii characters...
                if ($Data[$index] -lt 33 -or $Data[$index] -gt 126) {
                    $Data[$index] = '.'
                }
            }
            $OFS=""	# eliminate spaces from output of char array
            Add-Member -InputObject $PSCustomObjOutput -MemberType NoteProperty -Name "Data" -Value $($Data -join "")

            if ($($PSCustomObjOutput.PSObject.Properties) -ne $null) {
                if ([System.IO.Path]::GetExtension($OutputFile) -eq ".json") {
                    $PSCustomObjOutput | ConvertTo-JSON -Compress
                }
                if ([System.IO.Path]::GetExtension($OutputFile) -eq ".xml") {
                    $PSCustomObjOutput
                }
                if ($PacketCustomObjects.Count -gt $MaxEntries) {
                    $PacketCustomObjects.RemoveAt(0)
                }
                try {
                    $SetContentFilePath = "$($OutputFile | Split-Path -Parent)\Latest_Packet.txt"
                    Set-Content -Path $SetContentFilePath -Value $PSCustomObjOutput -Force -ErrorAction SilentlyContinue
                    
                    if (!$?) {
                        throw
                    }
                }
                catch {
                    Write-Verbose "Unable to write to $SetContentFilePath - The file is already in use!"
                }
                $null = $PacketCustomObjects.Add($PSCustomObjOutput)
                $PSCustomObjOutput = $null
            }
        }

        if (!$CaptureOutput) {
            if (($Protocol -eq "all") -or ($Protocol -eq $ProtocolDesc)) {
                if (($Port -eq "all") -or ($Port -eq $sourcePort) -or ($Port -eq $destPort)) {
                    #if( $ScanIP -eq $SourceIp -and $ScanIP -eq $DestinationIP )
                    if (($ScanIP -eq "all") -or ($ScanIP -eq $SourceIp) -or ($ScanIP -eq $DestinationIP)) {
                        if (!$RemotePort -and !$LocalPort) {
                            NoCaptureOutput
                        }
                        if ($LocalPort -or $RemotePort) {
                            if (($LocalPort -eq $sourcePort -and $LocalPort -ne $null) -or 
                            ($RemotePort -eq $destPort -and $RemotePort -ne $null)) {
                                NoCaptureOutput
                            }
                        }
                    }
                }
            }
        }
        
        if ($CaptureOutput) {
            if (($Protocol -eq "all") -or ($Protocol -eq $ProtocolDesc)) {
                if (($Port -eq "all") -or ($Port -eq $sourcePort) -or ($Port -eq $destPort)) {
                    #if( $ScanIP -eq $SourceIp -and $ScanIP -eq $DestinationIP )
                    if (($ScanIP -eq "all") -or ($ScanIP -eq $SourceIp) -or ($ScanIP -eq $DestinationIP)) {
                        if (!$RemotePort -and !$LocalPort) {
                            CaptureOutput
                        }
                        if ($LocalPort -or $RemotePort) {
                            if (($LocalPort -eq $sourcePort -and $LocalPort -ne $null) -or 
                            ($RemotePort -eq $destPort -and $RemotePort -ne $null)) {
                                CaptureOutput
                            }
                        }
                    }
                }
            }
        }
    }

    if (!$running) {
        if ([System.IO.Path]::GetExtension($OutputFile) -eq ".xml") {
            Export-CliXML -InputObject $PacketCustomObjects -Path $OutputFile
        }
        else {
            $JsonObjects = $PacketCustomObjects | foreach {$_ | ConvertTo-Json -Compress}
            $JsonObjects | Out-File $OutputFile
        }
        
        Remove-Item "$($OutputFile | Split-Path -Parent)\Latest_Packet.txt" -Force -ErrorAction SilentlyContinue
    }
    
    ##### END Main Body #####

}
























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgyr9yznKaIheQs+5kiFlyTfO
# f5Kgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHJlVARWXGJvg252
# UXVFjgX1pdpRMA0GCSqGSIb3DQEBAQUABIIBAJdh5WbjgquyRTDQl76ynBdrgVp8
# t5dOvVDO6jB9Urfr6dPAD+Ko0mPQ/NCJ4Qjyf5Br691EEN65lKrQsXP5f9LGP2SV
# lYSdo2fLXDL66WCgWxivqFLVH0Qr8gxkht20BaQSByHmrxY8zTkTEEtdjVNlrkdl
# 4EDbm/IjKCGtrHRe5ky8BCto77H2oK4tdMBhxK1Tp4A06LWVlhXvEksB5jAdPDX4
# GPtig7DKig4MKkuRKNZGBl/m7RUZUU+ncTvLBghlsscLR/n69jNDsDwAVdOtBLn0
# XzlbLgc4bwh+Xi7wMgCDId3FEbBYfbZ8+wyIdCTCvbjO9HheBcGDbPA1jks=
# SIG # End signature block
