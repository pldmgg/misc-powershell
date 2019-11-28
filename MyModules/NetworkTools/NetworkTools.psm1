function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

function Resolve-Host {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$HostNameOrIP
    )

    ##### BEGIN Main Body #####

    $RemoteHostNetworkInfoArray = @()
    if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
        try {
            $HostNamePrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $IPv4AddressFamily = "InterNetwork"
            $IPv6AddressFamily = "InterNetworkV6"

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
            $ResolutionInfo.AddressList | Where-Object {
                $_.AddressFamily -eq $IPv4AddressFamily
            } | foreach {
                if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                    $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                }
            }
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"

            if ($HostNameOrIP -match "\.") {
                try {
                    $HostNamePrep = $($HostNameOrIP -split "\.")[0]
                    Write-Verbose "Trying to resolve $HostNameOrIP using only HostName: $HostNamePrep!"

                    [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                    $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                    $ResolutionInfo.AddressList | Where-Object {
                        $_.AddressFamily -eq $IPv4AddressFamily
                    } | foreach {
                        if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                            $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                        }
                    }
                }
                catch {
                    Write-Verbose "Unable to resolve $HostNamePrep!"
                }
            }
        }
    }
    if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
        try {
            $HostIPPrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)

            [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
        }
    }

    if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
        Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # At this point, we have $RemoteHostArrayOfIPAddresses...
    [System.Collections.ArrayList]$RemoteHostFQDNs = @()
    foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
        try {
            $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
        }
        catch {
            Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
            continue
        }
        if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
            $null = $RemoteHostFQDNs.Add($FQDNPrep)
        }
    }

    if ($RemoteHostFQDNs.Count -eq 0) {
        $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
    }

    [System.Collections.ArrayList]$HostNameList = @()
    [System.Collections.ArrayList]$DomainList = @()
    foreach ($fqdn in $RemoteHostFQDNs) {
        $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
        if ($PeriodCheck) {
            $HostName = $($fqdn -split "\.")[0]
            $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
        }
        else {
            $HostName = $fqdn
            $Domain = "Unknown"
        }

        $null = $HostNameList.Add($HostName)
        $null = $DomainList.Add($Domain)
    }

    if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
        [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
        # Test to see if we can reach the IP Addresses
        foreach ($ip in $RemoteHostArrayOfIPAddresses) {
            try {
                $null = [System.Net.NetworkInformation.Ping]::new().Send($ip,1000)
                $null = $SuccessfullyPingedIPs.Add($ip)
            }
            catch {
                Write-Verbose "Unable to ping $ip..."
                continue
            }
        }
    }

    $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
    if ($FQDNPrep -match ',') {
        $FQDN = $($FQDNPrep -split ',')[0]
    }
    else {
        $FQDN = $FQDNPrep
    }

    $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
    if ($DomainPrep -match ',') {
        $Domain = $($DomainPrep -split ',')[0]
    }
    else {
        $Domain = $DomainPrep
    }

    [pscustomobject]@{
        IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
        FQDN            = $FQDN
        HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
        Domain          = $Domain
    }

    ##### END Main Body #####

}

function Format-XML {
    [CmdletBinding()]
    Param ([Parameter(ValueFromPipeline=$true,Mandatory=$true)][string]$xmlcontent)
    $xmldoc = New-Object -TypeName System.Xml.XmlDocument
    $xmldoc.LoadXml($xmlcontent)
    $sw = New-Object System.IO.StringWriter
    $writer = New-Object System.Xml.XmlTextwriter($sw)
    $writer.Formatting = [System.XML.Formatting]::Indented
    $xmldoc.WriteContentTo($writer)
    $sw.ToString()
}

Function Check-InstalledPrograms {
    [CmdletBinding(
        PositionalBinding=$True,
        DefaultParameterSetName='Default Param Set'
    )]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string]$ProgramTitleSearchTerm,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string[]]$HostName = $env:COMPUTERNAME,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Secondary Param Set'
        )]
        [switch]$AllADWindowsComputers

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $uninstallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    $RegPaths = @(
        "HKLM:$uninstallWow6432Path",
        "HKLM:$uninstallPath",
        "HKCU:$uninstallWow6432Path",
        "HKCU:$uninstallPath"
    )
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    # Get a list of Windows Computers from AD
    if ($AllADWindowsComputers) {
        $ComputersArray = $(Get-ADComputer -Filter * -Property * | Where-Object {$_.OperatingSystem -like "*Windows*"}).Name
    }
    else {
        $ComputersArray = $env:COMPUTERNAME
    }

    foreach ($computer in $ComputersArray) {
        if ($computer -eq $env:COMPUTERNAME -or $computer.Split("\.")[0] -eq $env:COMPUTERNAME) {
            try {
                $InstalledPrograms = foreach ($regpath in $RegPaths) {if (Test-Path $regpath) {Get-ItemProperty $regpath}}
                if (!$?) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to find registry path(s) on $computer. Skipping..."
                continue
            }
        }
        else {
            try {
                $InstalledPrograms = Invoke-Command -ComputerName $computer -ScriptBlock {
                    foreach ($regpath in $RegPaths) {
                        if (Test-Path $regpath) {
                            Get-ItemProperty $regpath
                        }
                    }
                } -ErrorAction SilentlyContinue
                if (!$?) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to connect to $computer. Skipping..."
                continue
            }
        }

        if ($ProgramTitleSearchTerm) {
            $InstalledPrograms | Where-Object {$_.DisplayName -like "*$ProgramTitleSearchTerm*"}
        }
        else {
            $InstalledPrograms
        }
    }

    ##### END Main Body #####

}

function Install-NirsoftCPorts {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$AddToSystemPath
    )
    
    $CheckForCPorts = Get-Command cports.exe -ErrorAction SilentlyContinue
    if (!$CheckForCPorts) {
        try {
            if (-not [System.Environment]::Is64BitOperatingSystem) {
                $OutFilePath = "$HOME\Downloads\cports.zip"
                Invoke-WebRequest -Uri "http://www.nirsoft.net/utils/cports.zip" -OutFile $OutFilePath
            }
            else {
                $OutFilePath = "$HOME\Downloads\cports-x64.zip"
                Invoke-WebRequest -Uri "http://www.nirsoft.net/utils/cports-x64.zip" -OutFile $OutFilePath
            }

            $CPortsExeParentDir = $OutFilePath -replace "\.zip",""
            Expand-Archive -Path $OutFilePath -DestinationPath $CPortsExeParentDir -Force
        }
        catch {
            Write-Error "Unable to download Nirsoft CPorts network utility! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        Write-Host "cports.exe is already installed and available in the current PowerShell Session!"
        $global:FunctionResult = "0"
        return
    }

    # Update $env:Path that is specific to the current PowerShell Session #####
    $CurrentEnvPathArray = $env:Path -split ";"
    if ($CurrentEnvPathArray -notcontains $CPortsExeParentDir) {
        if ($env:Path[-1] -eq ";") {
            $env:Path = "$env:Path$CPortsExeParentDir"
        }
        else {
            $env:Path = "$env:Path;$CPortsExeParentDir"
        }
    }
    
    if ($AddToSystemPath) {
        # Update System PATH that applies to all contexts system-wide
        $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $CurrentSystemPathArray = $CurrentSystemPath -split ";"
        if ($CurrentSystemPathArray -notcontains $CPortsExeParentDir) {
            if ($CurrentSystemPath[-1] -eq ";") {
                $UpdatedSystemPath = "$CurrentSystemPath$CPortsExeParentDir"
            }
            else {
                $UpdatedSystemPath = "$CurrentSystemPath;$CPortsExeParentDir"
            }
        }
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value $UpdatedSystemPath
    }
    if (!$CheckForCPorts -and !$AddToSystemPath) {
        Write-Warning "cports.exe has been added to your `$env:Path for this PowerShell session only!"
        Write-Host "To permanently add cports.exe to your system PATH (and therefore, your `$env:Path, use the following:"
        Write-Host @"
`$CurrentSystemPath = `$(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
if (`$CurrentSystemPathArray -notcontains $CPortsExeParentDir) {
    if (`$CurrentSystemPath[-1] -eq ";") {
        `$UpdatedSystemPath = "`$CurrentSystemPath$CPortsExeParentDir"
    }
    else {
        `$UpdatedSystemPath = "`$CurrentSystemPath;$CPortsExeParentDir"
    }
}
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value `$UpdatedSystemPath
"@
    }
}

function Invoke-PSTrace {
    [OutputType([System.Diagnostics.Eventing.Reader.EventLogRecord])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [switch]$OpenWithMessageAnalyzer,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Microsoft-Windows-TCPIP","Microsoft-Windows-NDIS-PacketCapture")]
        [string]$ETWProvider,

        [Parameter(Mandatory=$false)]
        [pscredential]$Credential,

        [Parameter(Mandatory=$false)]
        [string]$FilterByHostNameOrIPAddress,

        [Parameter(Mandatory=$false)]
        [int]$FilterByPort
    )

    DynamicParam 
    {
        $ParameterName = 'ETWProvider' 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $False
        $AttributeCollection.Add($ParameterAttribute)
        $arrSet = logman query providers | Foreach-Object {$_.split('{')[0].trimend()} | Select-Object -Skip 3 | Select-Object -SkipLast 2
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }

    begin
    {
        if (!$(Test-IsValidIPAddress -IPAddress $FilterByHostNameOrIPAddress)) {
            try {
                $RemoteHostInfo = Resolve-Host -HostNameOrIP $FilterByHostNameOrIPAddress

                if (!$RemoteHostInfo) {
                    throw
                }

                if ($Port) {
                    $IPAddressesParamValue = "$($RemoteHostInfo.IPAddressList[0]):$FilterByPort"
                }
                else {
                    $IPAddressesParamValue = $RemoteHostInfo.IPAddressList[0]
                }
            }
            catch {
                Write-Error "Unable to resolve $FilterByHostNameOrIPAddress! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if ($Port) {
                $IPAddressesParamValue = "$FilterByHostNameOrIPAddress`:$FilterByPort"
            }
            else {
                $IPAddressesParamValue = $FilterByHostNameOrIPAddress
            }
        }
        
        if ($OpenWithMessageAnalyzer) {
            $UseMessageAnalyzer = $True
            $MMAInstallCheck = Check-InstalledPrograms -ProgramTitleSearchTerm "Microsoft Message Analyzer"
            if (![bool]$MMAInstallCheck) { 
                Write-Warning "You used the -OpenWithMessageAnalyzer switch, but Microsoft Message Analyzer is not installed. Installing it could take up to 10 minutes."
                $InstallMMAChoice = Read-Host -Prompt "Do you want to install Microsoft Message Analyzer? [Yes\No]"
                $ValidMMAInstallChoices = @("Yes","yes","Y","y","No","no","N","n")
                if ($ValidMMAInstallChoices -notcontains $InstallMMAChoice) {
                    Write-Error "$InstallMMAChoice is not a valid option. Valid options are Yes/No. Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                if ($InstallMMAChoice -match "Yes|yes|Y|y") {
                    Write-Host "Installing Microsoft Message Analyzer..."

                    $global:FunctionResult = "0"
                    Install-MicrosoftMessageAnalyzer

                    if ($global:FunctionResult -eq "1") {
                        Write-Warning "The Install-MicrosoftMessageAnalyzer function failed! We will not use Message Analyzer..."
                        $UseMessageAnalyzer = $False
                    }
                }
            }
        }
    }
    process 
    {
        #Remove any existing sessions
        Get-CimSession -ComputerName $ComputerName -ErrorAction SilentlyContinue | Remove-CimSession -Confirm:$False
        Get-NetEventSession -Name "Session1" -ErrorAction SilentlyContinue | Remove-NetEventSession -Confirm:$False
        Remove-Item -Path "C:\Windows\Temp\$ComputerName-Trace.etl" -Force -Confirm:$False -ErrorAction SilentlyContinue
        
        #Create new session
        try {
            $Cim = New-CimSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            # RealtimeLocal, RealtimeRPC, SaveToFile
            New-NetEventSession -Name "Session1" -CimSession $Cim -LocalFilePath "C:\Windows\Temp\$ComputerName-Trace.etl" -ErrorAction Stop -CaptureMode SaveToFile | Out-Null
        }
        catch {
            Write-Error $_
            Break
        }

        if ($ETWProvider) {
            $null = Add-NetEventProvider -CimSession $Cim -Name $ETWProvider -SessionName "Session1"
        }
        else {
            $null = Add-NetEventPacketCaptureProvider -CimSession $Cim -SessionName "Session1" -Level 4 -CaptureType Physical -EtherType 0x0800 -IPAddresses $IPAddressesParamValue -IpProtocols 6,17
        }

        Start-NetEventSession -Name "Session1" -CimSession $Cim
        
        if (Get-NetEventSession -CimSession $Cim) {
            Write-Host "Packet Trace logs regarding $IPAddressesParamValue are being saved to 'C:\Windows\Temp\$ComputerName-Trace.etl'"
            Write-Host "Note that logs where the 'Message' contains 'Capture Rule' are always generated and do not indicate network activity."
            Read-Host "To stop the Packet Trace either press enter or kill this PowerShell process $PID from another PowerShell Session by using 'Stop-Process -Id $PID'"
        }

        Stop-NetEventSession -Name 'Session1' -CimSession $Cim
        
        if ($ETWProvider) {
            Remove-NetEventProvider -Name $ETWProvider -CimSession $Cim
        }
        
        Remove-NetEventSession -Name 'Session1' -CimSession $Cim  
        Remove-CimSession -CimSession $Cim -Confirm:$False 
        
        if ($ComputerName -notmatch "$env:Computername|LocalHost") {
            Copy-Item -Path "\\$ComputerName\C$\Windows\Temp\$ComputerName-trace.etl" -Destination 'C:\Windows\Temp' -Force
        }

        Get-CimSession -ComputerName $ComputerName -ErrorAction SilentlyContinue | Remove-CimSession -Confirm:$False
        
        if ($UseMessageAnalyzer) {
             Start-Process -FilePath 'C:\Program Files\Microsoft Message Analyzer\MessageAnalyzer.exe' -ArgumentList "C:\Windows\Temp\$ComputerName-trace.etl"
        }
        else {
            if ($ETWProvider) {
                Get-WinEvent -Path "C:\Windows\Temp\$ComputerName-trace.etl" -Oldest | foreach {
                    if ($_.Message -match $IPAddressesParamValue) {
                        $_
                    } 
                }
            }
            else {
                Get-WinEvent -Path "C:\Windows\Temp\$ComputerName-trace.etl" -Oldest
            }
        }
    }
}


<#
.SYNOPSIS
    A .Net based PowerShell packet sniffer that outputs PSCustomObjects, Json, and/or XML.

    It does NOT sniff https.

.DESCRIPTION
    A .Net based PowerShell packet sniffer ("promiscuous mode" must be supported by hardware/driver)

    Originally From: https://github.com/sperner/PowerShell/blob/master/Sniffer.ps1

    Updated by Paul DiMaggio | pldmgg@github.com | /u/fourierswager (reddit)

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

    This parameter is a switch. If NOT used output of this function is written to STDOUT using Write-Host. If it
    IS used output can be captured in a variable and is also written to a file (see the -OutputFile parameter).

.PARAMETER OutputFile
    This parameter is MANDATORY.

    This parameter takes a string that represents a full path to a .xml or .json file that will contain all packet
    capture output.

.PARAMETER MaxEntries
    This parameter is OPTIONAL.

    This parameter takes an integer that represents the number of packet capture logs that will be available for
    review as output from this function (be it saved in a variable or written to a .xml or .json file).

.EXAMPLE
    Start-Sniffer -CaptureOutput

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
        [switch]$CaptureOutput,

        [Parameter(Mandatory=$False)]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -match "\.xml|\.json"})]
        [string]$OutputFile = "$HOME\Downloads\PacketCapture_$(Get-Date -Format MMddyy_hhmmss)",

        [Parameter(Mandatory=$False)]
        [int]$MaxEntries = 10000,

        [Parameter(Mandatory=$False)]
        [switch]$Help,

        [Parameter(Mandatory=$False)]
        [switch]$SuppressStdOutMsgs
    )

    ##### BEGIN Helper Functions #####

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

    # Make sure $OutputFile doesn't exist
    if (Test-Path $OutputFile) {
        Write-Error "The path $OutputFile already exists! Halting!"
        $global:FunctionResult = "1"
        return
    }

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

    if (!$SuppressStdOutMsgs) {
        Write-Host "Using Local IP $LocalIP..."
        Write-Host ""
    }

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

    if (!$SuppressStdOutMsgs) {
        Write-Host "Press ESC to stop the packet sniffer ..." -fore yellow
        Write-Host "IMPORTANT NOTE: There is about a 30 second delay between network activity and output!" -fore yellow
        Write-Host ""
    }
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
                    $OutputContent = $PSCustomObjOutput | ConvertTo-JSON
                }
                if ([System.IO.Path]::GetExtension($OutputFile) -eq ".xml") {
                    $OutputContent = $($PSCustomObjOutput | ConvertTo-XML).OuterXml | Format-Xml
                }
                if ($PacketCustomObjects.Count -gt $MaxEntries) {
                    $PacketCustomObjects.RemoveAt(0)
                }
                try {
                    $SetContentFilePath = $OutputFile
                    Add-Content -Path $SetContentFilePath -Value $OutputContent -Force -ErrorAction SilentlyContinue
                    
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

        if ($CaptureOutput) {
            $PacketCustomObjects
        }
        
        Remove-Item "$($OutputFile | Split-Path -Parent)\Latest_Packet.txt" -Force -ErrorAction SilentlyContinue
    }
    
    ##### END Main Body #####

}

<#
.SYNOPSIS
    Some of us are forced to use bad software. Sometimes this software can hold TCP connections open
    to the detriment of the software itself business operations. Othertimes, it can send meaningless traffic
    that actually slows things down. And sometimes, we just would like the ability monitor these programs
    for bad behavior instead of needing to manually close TCP Connections or kill processes altogether.

    This function will watch for TCP connections and/or packet communications created by the specified
    BadProgramName, filtered by a combination of LocalIP, LocalPort, RemoteHostNameOrIP, and/or RemotePort
    parameters.

    This function cannot watch https traffic.

    If you want to watch for (and subsequently kill) a TCP Connection that has been open too long (regardless
    of State, and whether or not packets are actively being sent/received), then use the -TCPPipeTimeoutInSeconds
    parameter. If you want to watch for and subsequently kill an open TCP Connection in which has NOT been
    sending/receiving packets for a length of time, use the NoTrafficTimeOutInSeconds parameter. To watch for
    TCP Connections that are sending/receiving packets over **too long** a period of time, use the
    PersistentTrafficTimeoutInSeconds paramter. Optionally, combine any of the aforementioned with the
    ProblematicData parameter to kill a TCP Connection when packet data matches the string provided to the
    ProblematicData parameter (this parameter can also be used by itself).

.DESCRIPTION
    See Synopsis

    IMPORTANT NOTE 1: The goal of this function is to kill ONLY ONE SPECIFIC TCP connection. NOT more than one
    TCP Connection and NOT entire programs/processes. If one specific TCP connection cannot be determined by the
    combination of parameters used, then the user will receive an interactive prompt to choose.

    IMPORTANT NOTE 2: While this function watches and subsequently decides to kill a specific TCP connection,
    the behavior of the bad program might be such that it just immediately creates a new TCP connection. However,
    the hope is that in this case, refreshing this TCP connection may lead to better software performance.
    
    If you want to keep watching for bad behavior even after this function decides to kill a TCP connection, then
    use the -PerpetualWatch switch. This will put the function in a loop until it is killed manually (either
    with Ctrl+C in the case of running interactively), or by killing the powershell.exe process in the case of
    running non-interactively).

    IMPORTANT NOTE 3: This function makes use of Nirsoft's cports.exe utilit in order to kill specific TCP
    connections. If cports.exe is not already part of your $env:Path, it will be downloaded to
    $HOME\Downloads\cports-x64.zip and extracted to $HOME\Downloads\cports-x64. $HOME\Downloads\cports-x64
    will be added to youe $env:Path for the current PowerShell Session. 

.PARAMETER BadProgramName
    This parameter is MANDATORY.

    This parameter takes a string that represents the name of the name of the Program that generates the
    problematic TCP connection(s). The name used should match the name of the process according to PowerShell's
    Get-Process cmdlet.

.PARAMETER RemotePort
    This parameter is OPTIONAL.
    
    This parameter takes an integer that represents the Port Number on the Remote Host that BadProgram
    connects to.

.PARAMETER RemoteHostNameOrIP
    This parameter is OPTIONAL. (But strongly recommended)

    This parameter takes a string that represents either an IP Address or a DNS-resolvable Host Name.

.PARAMETER LocalPort
    This parameter is OPTIONAL.

    This parameter takes an integer that represents the Local Port used by the BadProgram to reach out
    to the Remote Host.

.PARAMETER LocalIP
    This parameter is OPTIONAL.

    This parameter takes a string that represents an IP Addrress on the local host that the BadProgram
    uses to reach out to the Remote Host. If this parameter is not specified, it is determined by
    checking which port on your local host gets its IP Address via DHCP. 
    
    In cases where your local host has multiple NICs and multiple IP Addresses assigned via multiple
    DHCP Servers, it is strongly recommended that you use this parameter. Otherwise, this function will
    arbitrarily choose a local IP Address.

.PARAMETER SnifferOutputFile
    This parameter is MANDATORY.

    This parameter takes a string that represents a full path to either an .xml or .json file that is a
    log of all of the packets sniffed by the Start-Sniffer function. A maximum of 10000 packet capture
    records will be stored in this file. This maximum can be changed by changing the default value for
    the $MaxEntries parameter in the Start-Sniffer function. There is no way to change this value
    directly using the Watch-ProgramConnection function.

.PARAMETER TCPPipeTimeoutInSeconds
    This parameter is OPTIONAL.

    This parameter takes an integer that represents seconds until this function kills the open TCP
    Connection that it determines that it should watch based on the other parameters provided. This TCP
    Connection is killed at the end of this time period regardless of connection State, and regardless of
    whether or not packets are actively being sent/received.

.PARAMETER PersistentTrafficTimeoutInSeconds
    This parameter is OPTIONAL.

    This parameter takes an integer that represents seconds until this function kills an open TCP
    Connection (as determined by the other parameters) that continues to send/receive packets for the
    duration of the number of seconds specified.

.PARAMETER NoTrafficTimeoutInSeconds
    This parameter is OPTIONAL.

    This parameter takes an integer that represents seconds until this function kills an open TCP
    Connection (as determined by the other parameters), that has NOT been sending/receiving packets
    for the duration of the number of seconds specified.

.PARAMETER ProblematicData
    This parameter is MANDATORY.

    This parameter takes an string that represents data contained in the TCP communication between local and
    remote host that the admin determines to be the cause of the detrimental state in the BadProgram.

.PARAMETER PerpetualWatch
    This parameter is OPTIONAL.

    This parameter takes a boolean $true/$false value. If $false, the Watch-BadProgramConnection function will
    end after one TCP connection is killed. If $true, then the function will run in a loop - once it determines
    that it needs to kill a specific TCP connection, then it will start watching again using the exact same
    parameters.
    
    WARNING: This may lead to an interactive prompt to choose a specific TCP connection if one cannot be determined
    using the parameters provided, so this function cannot really be used as a service that just runs in the background. 

.EXAMPLE
    $Params = @{
        BadProgramName = "iexplore"
        RemotePort = 3128
        RemoteHostNameOrIP = "192.168.7.129"
        SnifferOutputFile = "$HOME\Downloads\PacketTrace_$env:ComputerName.json"
        ProblematicData = "GET\./squid-internal-static"
    }

    Watch-BadProgramConnection @Params

.EXAMPLE
    $Params = @{
        BadProgramName = "iexplore"
        RemotePort = 3128
        RemoteHostNameOrIP = "192.168.7.129"
        SnifferOutputFile = "$HOME\Downloads\PacketTrace_$env:ComputerName.json"
        TCPPipeTimeoutInSeconds = 45
    }

    Watch-BadProgramConnection @Params

.EXAMPLE
    $Params = @{
        BadProgramName = "iexplore"
        RemotePort = 3128
        RemoteHostNameOrIP = "192.168.7.129"
        SnifferOutputFile = "$HOME\Downloads\PacketTrace_$env:ComputerName.json"
        PersistentTrafficTimeoutInSeconds = 45
    }

    Watch-BadProgramConnection @Params

.EXAMPLE
    $Params = @{
        BadProgramName = "iexplore"
        RemotePort = 3128
        RemoteHostNameOrIP = "192.168.7.129"
        SnifferOutputFile = "$HOME\Downloads\PacketTrace_$env:ComputerName.json"
        NoTrafficTimeoutInSeconds = 45
    }

    Watch-BadProgramConnection @Params

.EXAMPLE
    $Params = @{
        BadProgramName = "iexplore"
        RemotePort = 3128
        RemoteHostNameOrIP = "192.168.7.129"
        SnifferOutputFile = "$HOME\Downloads\PacketTrace_$env:ComputerName.json"
        PersistentTrafficTimeoutInSeconds = 45
        ProblematicData = "GET\./squid-internal-static"
    }

    Watch-BadProgramConnection @Params

.OUTPUTS
    This function outputs a log of all packets captured while the function is running to the 
    json or xml file specified by the -SnifferOutputFile parameter. This log can be
    easily imported back into PowerShell for analysis after the fact.

#>
function Watch-BadProgramConnection {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$BadProgramName,

        [Parameter(Mandatory=$False)]
        [int]$RemotePort,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostNameOrIP,

        [Parameter(Mandatory=$False)]
        [int]$LocalPort,

        [Parameter(Mandatory=$False)]
        [string]$LocalIP,

        [Parameter(Mandatory=$True)]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -eq ".json"})]
        [string]$SnifferOutputFile,

        [Parameter(Mandatory=$False)]
        [int]$TCPPipeTimeoutInSeconds, # This is a time limit dependent on the the TCP Pipe, regardless of State (Established, TimeWait, etc), and regardless of whether or not packets are actually being sent/received

        [Parameter(Mandatory=$False)]
        [int]$PersistentTrafficTimeoutInSeconds, # This is a time limit dependent on whether or not packets are being sent/received within the specified TCP connection

        [Parameter(Mandatory=$False)]
        [int]$NoTrafficTimeoutInSeconds, # This is a time limit dependent on whether or not packets are being sent/received within the specified TCP connection

        [Parameter(Mandatory=$False)]
        [string]$ProblematicData,

        [Parameter(Mandatory=$False)]
        [bool]$PerpetualWatch = $False
    )


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if (!$ProblematicData -and !$TCPPipeTimeoutInSeconds -and !$PersistentTrafficTimeoutInSeconds -and !$NoTrafficTimeoutInSeconds) {
        Write-Error "You must use must use one of the following parameters: -TCPPipeTimeoutInSeconds -PersistentTrafficTimeoutInSeconds -NoTrafficTimeoutInSeconds -ProblematicData! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SnifferOutputFileParentDir = $SnifferOutputFile | Split-Path -Parent
    if (!$(Test-Path $SnifferOutputFileParentDir)) {
        Write-Error "The directory $SnifferOutputFileParentDir was not found! Unable to save to $SnifferOutputFile Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PotentialBadProgramProcesses = Get-Process -Name $BadProgramName
    if (!$PotentialBadProgramProcesses) {
        Write-Error "Unable to find a process with the name $BadProgramName! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($RemoteHostNameOrIP) {
        if (!$(Test-IsValidIPAddress -IPAddress $RemoteHostNameOrIP)) {
            try {
                $RemoteHostInfo = Resolve-Host -HostNameOrIP $RemoteHostNameOrIP

                if (!$RemoteHostNameInfo) {
                    throw
                }

                $RemoteIP = $RemoteHostInfo.IPAddressList[0]
            }
            catch {
                Write-Error "Unable to resolve $RemoteHostNameOrIP! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $RemoteIP = $RemoteHostNameOrIP
        }
    }


    if (!$LocalIP) {
        if ($RemoteHostNameOrIP) {
            $LocalIP = $(Find-NetRoute -RemoteIPAddress $RemoteIP | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
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

    # Get All of the Bound Parameters for use multiple times in the Main Body
    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters

    # Need to Install Nirsoft Cports.exe utility in order to easily close specific TCP connections
    try {
        $global:FunctionResult = "0"
        Install-NirsoftCPorts

        if ($global:FunctionResult -eq "1") {
            throw
        }
    }
    catch {
        Write-Error "Unable to install Nirsoft Cports.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Need to start Sniffer as soon as possible...
    # Prep Start-Sniffer function to be loaded within a separate powershell.exe process
    <#
    [System.Collections.ArrayList]$StartSnifferFunction = $(Get-Command Start-Sniffer).Definition -split "`n"
    $StartSnifferFunction.Insert(0, "function Start-Sniffer {")
    $StartSnifferFunction.Insert($StartSnifferFunction.Count, "}")
    $StartSnifferFunctionAsString = $StartSnifferFunction -join "`n"
    $tmpfl = "C:\Windows\Temp\Start-Sniffer.ps1"
    Set-Content -Path $tmpfl -Value $StartSnifferFunctionAsString
    #>
    $ModulePSD1Path = $(Get-Module -ListAvailable Network-SnifferTools).Path

    $BinPath = $(Get-Command powershell.exe).Source

    # Create $StartSnifferArgsAsString
    $FunctionName = $PSCmdlet.MyInvocation.InvocationName
    [System.Collections.ArrayList]$TCPParametersAsStringArray = @()
    foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
        switch ($kvpair.Key) {
            'RemotePort'            { $null = $TCPParametersAsStringArray.Add("-RemotePort $RemotePort") }
            'RemoteHostNameOrIP'    { $null = $TCPParametersAsStringArray.Add("-ScanIP $RemoteIP") }
            'LocalPort'             { $null = $TCPParametersAsStringArray.Add("-LocalPort $LocalPort") }
            'LocalIP'               { $null = $TCPParametersAsStringArray.Add("-LocalIP $LocalIP") }
        }
    }
    $StartSnifferArgsAsString = $TCPParametersAsStringArray -join " "

    #$RunBinArgs = "-NoProfile -WindowStyle Hidden -Command `"& {. '$tmpfl'; Start-Sniffer $StartSnifferArgsAsString -OutputFile '$SnifferOutputFile' -ResolveHosts -SuppressStdOutMsgs}`""
    $RunBinArgs = "-NoProfile -WindowStyle Hidden -Command `"& {Import-Module $ModulePSD1Path; Start-Sniffer $StartSnifferArgsAsString -OutputFile '$SnifferOutputFile' -ResolveHosts -SuppressStdOutMsgs}`""
    $InvokeExpressionString = "$BinPath $RunBinArgs"
    #Write-Host "Running Job: $InvokeExpressionString"

    # Makes sure there isn't already a Sniffer Job running befor starting a new one
    Stop-Job -Name Sniffer -ErrorAction SilentlyContinue
    Remove-Job -Name Sniffer -ErrorAction SilentlyContinue
    $null = Start-Job -Name Sniffer -Scriptblock {Invoke-Expression $args[0]} -ArgumentList $InvokeExpressionString
    $OtherPSProcessId = $(Get-Process -Name powershell | Sort-Object -Property StartTime)[-1].Id

    Write-Host "Sniffer is ready to receive network activity regarding $RemoteIP on Port $RemotePort ..."


    # Determine the TCP Connection that we will watch..
    $GetNetTCPConnParams = @{}
    [System.Collections.ArrayList]$ParametersAsStringArray = @()
    foreach ($kvPair in $BoundParametersDictionary.GetEnumerator()) {
        if ($kvPair.Key -match "RemotePort|RemoteIP|LocalPort|LocalIP") {
            $null = $GetNetTCPConnParams.Add($kvpair.Key,$(Get-Variable -Name $kvpair.Key -ValueOnly))
        }
    }
    $null = $GetNetTCPConnParams.Add("State","Established")
    $null = $GetNetTCPConnParams.Add("LocalAddress",$LocalIP)

    Write-Host "Waiting for a TCP Connection that matches the parameters provided..."
    
    while (!$TCPConnectionToKill) {
        try {
            $PotentialTCPConnectionsToKill = Get-NetTCPConnection @GetNetTCPConnParams -ErrorAction SilentlyContinue

            if (!$PotentialTCPConnectionsToKill) {
                throw
            }
        }
        catch {
            Write-Verbose "Unable to find a TCP connection that matches the parameters specified!"
        }

        if ($PotentialBadProgramProcesses.Count -ge 1) {
            $PotentialBadProgramPIDs = $($PotentialBadProgramProcesses.Id | Sort-Object | Get-Unique) -join '|'
            $PotentialTCPConnectionsToKill = $PotentialTCPConnectionsToKill | Where-Object {$_.OwningProcess -match $PotentialBadProgramPIDs}
        }
        elseif ($PotentialBadProgramProcesses.Count -lt 1) {
            Write-Verbose "Can't find any TCP connections based on parameters supplied to Get-TCPConnection cmdlet!"
        }
        
        if ($PotentialTCPConnectionsToKill.Count -le 1) {
            $TCPConnectionToKill = $PotentialTCPConnectionsToKill
        }
        if ($PotentialTCPConnectionsToKill.Count -gt 1) {
            Write-Host "Which TCP Connection would you like to monitor? Available choices are:"
            for ($i=0; $i -lt $PotentialTCPConnectionsToKill.Count; $i++) {
                $choiceString = "`nChoice # $i`:`n`n" + "$($PotentialTCPConnectionsToKill[$i] | Out-String)".Trim() + "`n"
                Write-Host $choiceString
            }
        
            $ValidChoices = (0..$($PotentialTCPConnectionsToKill.Count-1))
        
            $TCPConnectionChoice = Read-Host -Prompt "Please select $($ValidChoices -Join ', ')"
            if ($ValidChoices -notcontains $TCPConnectionChoice) {
                Write-Error "$TCPConnectionChoice is NOT a valid choice! Halting!"
                $global:FunctionResult = "1"
                return
            }
        
            $TCPConnectionToKill = $PotentialTCPConnectionsToKill[$TCPConnectionChoice]
        }
    }

    $ConnectionPipeExistsStartTime = Get-Date

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    Write-Host "The TCP Connection we are watching is:"
    Write-Host $($TCPConnectionToKill | Out-String)
    
    Write-Host "Waiting for Sniffer to start capturing output..."

    try {
        $CheckJobOutput = $(Get-Job -Name Sniffer).ChildJobs.Output[0]

        if (!$CheckJobOutput -or $CheckJobOutput[0] -eq $null) {
            throw
        }
    }
    catch {
        Write-Verbose "No ouput yet..."
    }
    while (!$CheckJobOutput) {
        try {
            $CheckJobOutput = $(Get-Job -Name Sniffer).ChildJobs.Output[0]

            if (!$CheckJobOutput -or $CheckJobOutput[0] -eq $null) {
                throw
            }
        }
        catch {
            Write-Verbose "Waiting for Sniffer to capture output..."
        }
        
        Start-Sleep -Seconds 1
    }

    # Give the network stack some time to start sending packets to our Sniffer socket
    Write-Host "Waiting for Sniffer to output packets received..."
    #Write-Verbose "Sleeping for $NetworkStackWaitTime seconds..."
    #Start-Sleep -Seconds $NetworkStackWaitTime

    $ConnectionStillExists = $TCPConnectionToKill
    $Time = 0
    while ($ReceiveJobJson.Count -eq 0 -and $ConnectionStillExists) {
        Write-Verbose "Waiting for Sniffer to output packets received..."
        # Make sure there's still a TCP Connection matching $TCPConnectionToKill
        [System.Collections.ArrayList]$NetTCPParametersAsStringArray = @()
        foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
            switch ($kvpair.Key) {
                'RemotePort'            { $null = $NetTCPParametersAsStringArray.Add("-RemotePort $RemotePort") }
                'RemoteHostNameOrIP'    { $null = $NetTCPParametersAsStringArray.Add("-RemoteAddress $RemoteIP") }
                'LocalPort'             { $null = $NetTCPParametersAsStringArray.Add("-LocalPort $LocalPort") }
                'LocalIP'               { $null = $NetTCPParametersAsStringArray.Add("-LocalAddress $LocalIP") }
            }
        }
        $GetNetTCPArgsAsString = $NetTCPParametersAsStringArray -join " "
        $ConnectionStillExists = Invoke-Expression -Command "Get-NetTCPConnection $GetNetTCPArgsAsString -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue
        
        if (!$ConnectionStillExists) {
            Write-Warning "The TCP Connection that we were watching closed on its own! Nothing to monitor!"
            # Break the while loop... 
            break
        }

        $CurrentJobOutput =  $(Get-Job -Name Sniffer).ChildJobs.Output
        if ($CurrentJobOutput.Count -gt 0) {
            $ReceiveJobJson = $CurrentJobOutput
        }
        else {
            [System.Collections.Arraylist]$ReceiveJobJson = @()
        }
        if ($ReceiveJobJson.Count -gt 0) {
            try {
                [datetime]$ReceivedMorePacketsDateTime = $($ReceiveJobJson[-1] | ConvertFrom-Json).Time.DateTime
            }
            catch {
                Write-Verbose "Still waiting for Sniffer to output packets received..."
            }
        }

        $Time++
        if ($NoTrafficTimeoutInSeconds) {
            if ($Time -gt $NoTrafficTimeoutInSeconds) {
                Stop-Job -Name Sniffer
                Remove-Job -Name Sniffer
                Write-Error "No network communication detected on the TCP Connection for over $NoTrafficTimeoutInSeconds! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($TCPPipeTimeoutInSeconds) {
            if ($Time -gt $TCPPipeTimeoutInSeconds) {
                Stop-Job -Name Sniffer
                Remove-Job -Name Sniffer
                Write-Error "The TCP Connection has lasted for over $TCPPipeTimeoutInSeconds! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        Start-Sleep -Seconds 1
    }

    $StartedReceivingPacketsStartTime = [datetime]::MinValue
    $StoppedReceivingPacketsStartTime = [datetime]::MinValue
    $NoPacketsReceivedDateTime = [datetime]::MinValue
    $ReceivedMorePacketsTimer = 0
    while ($ConnectionStillExists) {
        # Make sure there's still a TCP Connection matching $TCPConnectionToKill
        [System.Collections.ArrayList]$NetTCPParametersAsStringArray = @()
        foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
            switch ($kvpair.Key) {
                'RemotePort'            { $null = $NetTCPParametersAsStringArray.Add("-RemotePort $RemotePort") }
                'RemoteHostNameOrIP'    { $null = $NetTCPParametersAsStringArray.Add("-RemoteAddress $RemoteIP") }
                'LocalPort'             { $null = $NetTCPParametersAsStringArray.Add("-LocalPort $LocalPort") }
                'LocalIP'               { $null = $NetTCPParametersAsStringArray.Add("-LocalAddress $LocalIP") }
            }
        }
        $GetNetTCPArgsAsString = $NetTCPParametersAsStringArray -join " "
        $ConnectionStillExists = Invoke-Expression -Command "Get-NetTCPConnection $GetNetTCPArgsAsString -ErrorAction SilentlyContinue" -ErrorAction SilentlyContinue

        if (!$ConnectionStillExists) {
            Write-Warning "The TCP Connection that we were watching closed on its own! Nothing to monitor!"
            # Break the while loop... 
            break
        }
        if ($TCPPipeTimeoutInSeconds) {
            if ($($(Get-Date) - $ConnectionPipeExistsStartTime) -gt $(New-TimeSpan -Seconds $TCPPipeTimeoutInSeconds)) {
                $KillTCPConnection = $true
                Write-Host "The TCP Pipe has lasted for longer than the specified TCPPipeTimeoutInSeconds: $TCPPipeTimeoutInSeconds! Killing TCP connection..."
            }
        }

        #$ReceiveJobPrepInternal = Receive-Job -Name Sniffer
        if ($($(Get-Job -Name Sniffer).ChildJobs.Output).Count -gt $ReceiveJobJson.Count) {
            Write-Host "Received more Packets..."
            $CurrentJobOutput = $(Get-Job -Name Sniffer).ChildJobs.Output
            $ReceiveJobJson = $CurrentJobOutput
            
            $ReceivedMorePackets = $true
            [datetime]$ReceivedMorePacketsDateTime = $($ReceiveJobJson[-1] | ConvertFrom-Json).Time.DateTime

            if ($ProblematicData) {
                [System.Collections.ArrayList]$ProblemDataFound = @()
                foreach ($jsonString in $ReceiveJobJson) {
                    if ($($($jsonString | ConvertFrom-JSON).Data -match $ProblematicData)) {
                        $null = $ProblemDataFound.Add("True")
                    }
                }
                if ($ProblemDataFound -contains "True") {
                    Write-Warning "ProblematicData detected! Killing the TCP Connection!"
                    $KillTCPConnection = $true
                }
            }
        }
        else {
            $ReceivedMorePackets = $false
            $NoPacketsReceivedDateTime = $ReceivedMorePacketsDateTime
        }

        try {
            if (!$ReceivedMorePackets -and $NoPacketsReceivedDateTime -ne [datetime]::MinValue) {
                $AmountOfTimeWithoutNetworkCommunication = $(Get-Date) - $NoPacketsReceivedDateTime

                if ($AmountOfTimeWithoutNetworkCommunication -gt $(New-Timespan -Seconds 15)) {
                    $ReceivedMorePacketsTimer = 0
                }
            }

            if ($ReceivedMorePackets) {
                $ReceivedMorePacketsTimer++
                $AmountOfTimeWithPersistentNetworkCommunication = New-Timespan -Seconds $ReceivedMorePacketsTimer
            }
        }
        catch {
            Write-Verbose "Either `$NoPacketsReceivedDateTime or `$ReceivedMorePacketsDateTime has not been set..."
        }

        if ($NoTrafficTimeoutInSeconds) {
            Write-Verbose "NoTraffic Time: $AmountOfTimeWithoutNetworkCommunication"
            if ($AmountOfTimeWithoutNetworkCommunication -gt $(New-TimeSpan -Seconds $NoTrafficTimeoutInSeconds)) {
                Write-Host "There hasn't been any network communication on the TCP connection we are monitoring for at least $NoTrafficTimeoutInSeconds second(s)..."
                $KillTCPConnection = $true
            }
        }
        
        if ($PersistentTrafficTimeoutInSeconds) {
            Write-Verbose "PersistentTraffic Time: $AmountOfTimeWithPersistentNetworkCommunication"
            if ($AmountOfTimeWithPersistentNetworkCommunication -gt $(New-TimeSpan -Seconds $PersistentTrafficTimeoutInSeconds)) {
                Write-Host "There has been persistent network communication on the TCP connection we are monitoring for at least $PersistentTrafficTimeoutInSeconds second(s)..."
                $KillTCPConnection = $true
            }
        }

        if ($KillTCPConnection) {
            # Kill the specific TCP Connections
            # cports.exe /close <Local Address> <Local Port> <Remote Address> <Remote Port> {Process Name/ID}
            [System.Collections.ArrayList]$cportParametersAsStringArray = @("*","*","*")
            foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
                switch ($kvpair.Key) {
                    'LocalPort'             { $null = $cportParametersAsStringArray.RemoveAt(0); $cportParametersAsStringArray.Insert(0,$LocalPort) }
                    'RemoteHostNameOrIP'    { $null = $cportParametersAsStringArray.RemoveAt(1); $cportParametersAsStringArray.Insert(1,$RemoteIP) }
                    'RemotePort'            { $null = $cportParametersAsStringArray.RemoveAt(2); $cportParametersAsStringArray.Insert(2,$RemotePort) }
                }
            }
            $OtherParams = $cportParametersAsStringArray -join " "
            $cportsInvokeExpressionString = "cports.exe /close $LocalIP" + " " + $OtherParams + " " + $TCPConnectionToKill.OwningProcess
            
            Write-Host ""
            Write-Host "Killing TCP Connection with the following cports.exe command:"
            Write-Host "cports.exe /close <Local Address> <Local Port> <Remote Address> <Remote Port> {Process Name/ID}"
            Write-Host $cportsInvokeExpressionString
            Write-Host ""
            
            Invoke-Expression -Command $cportsInvokeExpressionString
            
            # break out of the while loop
            break
        }

        Start-Sleep -Seconds 1
    }

    Write-Host "Exporting Packet Capture and cleaning up..."
    Write-Verbose "Removing the Sniffer job. This also kills the separate PowerShell process $OtherPSProcessId..."

    try {
        Stop-Job -Name Sniffer
        Remove-Job -Name Sniffer
    }
    catch {
        Stop-Process -Id $OtherPSProcessId -Force
        Stop-Job -Name Sniffer
        Remove-Job -Name Sniffer
    }

    $SnifferOutputFileExt = [System.IO.Path]::GetExtension($SnifferOutputFile)
    $SnifferOutputFile = $SnifferOutputFile -replace $SnifferOutputFileExt,"$(Get-Date -Format MMddyy_hhmmss)$SnifferOutputFileExt"
    if ($SnifferOutputFileExt -eq ".xml") {
        $ReceiveJobPSObjects = $ReceiveJobJson | foreach {$_ | ConvertFrom-JSON}
        Export-CliXML -InputObject $ReceiveJobPSObjects -Path $SnifferOutputFile
    }
    else {
        $ReceiveJobJson | Out-File $SnifferOutputFile
    }

    if (Test-Path $tmpfl) {
        Remove-Item -Path $tmpfl -Force
    }

    Write-Host "Logs of packet captures can be found here: $SnifferOutputFile"
    Write-Host "If desired, import the packet capture log back into PowerShell by using:"
    if ($SnifferOutputFileExt -eq ".xml") {
        Write-Host "`$PacketCaptureResults = Import-CliXml -Path $SnifferOutputFile"
    }
    else {
        Write-Host "`$PacketCaptureResults = Get-Content -Path $SnifferOutputFile | foreach {`$_ | ConvertFrom-Json}"
    }

    if ($PerpetualWatch) {
        Write-Host "We are using PerpetualWatch Mode!"
        Write-Host "Continuing to watch for TCP connections that match the parameters specified..."
        $FunctionName = $PSCmdlet.MyInvocation.InvocationName
        [System.Collections.ArrayList]$PerpParametersAsStringArray = @()
        foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
            if ($BoundParametersDictionary[$kvpair.Key].GetType().FullName -eq "System.Boolean") {
                $null = $PerpParametersAsStringArray.Add("-$($kvpair.Key)" + " " + '$' + "$($BoundParametersDictionary[$kvpair.Key])")
            }
            elseif ($BoundParametersDictionary[$kvpair.Key].GetType().FullName -eq "System.Management.Automation.SwitchParameter") {
                $null = $PerpParametersAsStringArray.Add("-$($kvpair.Key)")
            }
            elseif ($($kvpair.Key) -eq "SnifferOutputFile") {
                $null = $PerpParametersAsStringArray.Add("-$($kvpair.Key)" + " " + "'" + "$($BoundParametersDictionary[$kvpair.Key])" + "'")
            }
            else {
                $null = $PerpParametersAsStringArray.Add("-$($kvpair.Key)" + " " + "$($BoundParametersDictionary[$kvpair.Key])")
            }
        }
        $InvokeExpressionWatchBadProgramString = $FunctionName + " " + $($PerpParametersAsStringArray -join " ")

        Write-Host "Restarting the Watch-BadProgram function again using the same parameters, i.e. -"
        Write-Host $InvokeExpressionWatchBadProgramString
        Invoke-Expression -Command $InvokeExpressionWatchBadProgramString
    }

    ##### END Main Body #####

}

