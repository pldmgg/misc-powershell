function Check-Elevation {
    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

        if($currentPrincipal.IsInRole($administratorsRole)) {
            return $true
        }
        else {
            return $false
        }
    }
    
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -eq "root") {
            return $true
        }
        else {
            return $false
        }
    }
}

Function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

function Test-Port {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $RemoteMachine = $(Read-Host -Prompt "Please enter the IP Address of the remote host."),

        [Parameter(Mandatory=$False)]
        [int]$RemotePort = $(Read-Host -Prompt "Please enter the port number listening on the remote host.")
    )

    Begin {
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        $tcp = New-Object Net.Sockets.TcpClient
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$RemoteMachine","Test Connection on $RemoteMachine`:$RemotePort")) {
            try {
                $tcp.Connect($RemoteMachine, $RemotePort)
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
                Address      = $RemoteMachine
                Port    = $RemotePort
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}

function Get-UserSessionViaQuery {
    <#  
    .SYNOPSIS  
        Retrieves all user sessions from local or remote computers(s)

    .DESCRIPTION
        Retrieves all user sessions from local or remote computer(s).
        
        Note:   Requires query.exe in order to run
        Note:   This works against Windows Vista and later systems provided the following registry value is in place
                HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\AllowRemoteRPC = 1
        Note:   If query.exe takes longer than 15 seconds to return, an error is thrown and the next computername is processed.  Suppress this with -erroraction silentlycontinue
        Note:   If $sessions is empty, we return a warning saying no users.  Suppress this with -warningaction silentlycontinue

    .PARAMETER computername
        Name of computer(s) to run session query against
                  
    .parameter parseIdleTime
        Parse idle time into a timespan object

    .parameter timeout
        Seconds to wait before ending query.exe process.  Helpful in situations where query.exe hangs due to the state of the remote system.
                        
    .FUNCTIONALITY
        Computers

    .EXAMPLE
        Get-usersession -computername "server1"

        Query all current user sessions on 'server1'

    .EXAMPLE
        Get-UserSession -computername $servers -parseIdleTime | ?{$_.idletime -gt [timespan]"1:00"} | ft -AutoSize

        Query all servers in the array $servers, parse idle time, check for idle time greater than 1 hour.

    .NOTES
        Thanks to Boe Prox for the ideas - http://learn-powershell.net/2010/11/01/quick-hit-find-currently-logged-on-users/

    .LINK
        http://gallery.technet.microsoft.com/Get-UserSessions-Parse-b4c97837

    #> 
    [cmdletbinding()]
    Param(
        [Parameter(
            Position = 0,
            ValueFromPipeline = $True)]
        [string[]]$ComputerName = "",

        [Parameter(Mandatory=$False)]
        [switch]$ParseIdleTime,

        [Parameter(Mandatory=$False)]
        [validaterange(0,120)]
        [int]$Timeout = 15,

        [Parameter(Mandatory=$False)]
        [string]$Uname,

        [Parameter(Mandatory=$False)]
        [string]$Pword
    )

    Begin
    {
        if ($Uname) {
            $UserNameFormatOne = $Uname | Select-String -Pattern "\\"
            $UserNameFormatTwo = $Uname | Select-String -Pattern "@"
            if ($UserNameFormatOne) {
                $Uname = $Uname.Split("\")[-1]
            }
            if ($UserNameFormatTwo) {
                $Uname = $Uname.Split("@")[0]
            }
        }

        if ($Uname) {
            if (!$Pword) {
                $Pword = Read-Host -Prompt "Please enter the password for $Uname" -AsSecureString
            }
        }
        if ($Pword) {
            if (!$Uname) {
                $Uname = Read-Host -Prompt "Please enter a UserName with access to all Computers listed in the -ComputerName parameter"
            }
        }

        $RemoteHostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $ComputerName[0])) {
            try {
                $RemoteHostIP = $(Resolve-DNSName $ComputerName[0]).IPAddress
            }
            catch {
                Write-Verbose "Unable to resolve $($ComputerName[0])!"
            }
            if ($RemoteHostIP) {
                # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
                $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
                if ($RemoteHostIP.Count -gt 1) {
                    $RemoteHostIP = $RemoteHostIP[0]
                }
                $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
                $pos = $RemoteHostNameFQDN.IndexOf(".")
                $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                $RemoteHostUserName = "$Uname@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostIP) {
                Write-Error "Unable to resolve $($ComputerName[0])! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $ComputerName[0]) {
            try {
                $RemoteHostIP = $ComputerName[0]
                $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
            }
            catch {
                Write-Verbose "Unable to resolve $($ComputerName[0])!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN
                }
                $RemoteHostUserName = "$Uname@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostNameFQDN) {
                Write-Error "Unable to resolve $($ComputerName[0])! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    Process
    {
        ForEach($computer in $ComputerName)
        {
        
            #start query.exe using .net and cmd /c.  We do this to avoid cases where query.exe hangs

                #build temp file to store results.  Loop until we see the file
                    Try
                    {
                        $Started = Get-Date
                        $tempFile = [System.IO.Path]::GetTempFileName()
                        
                        Do{
                            start-sleep -Milliseconds 300
                            
                            if( ((Get-Date) - $Started).totalseconds -gt 10)
                            {
                                Throw "Timed out waiting for temp file '$TempFile'"
                            }
                        }
                        Until(Test-Path -Path $tempfile)
                    }
                    Catch
                    {
                        Write-Error "Error for '$Computer': $_"
                        Continue
                    }

                #Record date.  Start process to run query in cmd.  I use starttime independently of process starttime due to a few issues we ran into
                    $Started = Get-Date
                    # If the Computers are on a different Domain, use PSExec
                    if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                        $DomainPre = $($RemoteHostNameFQDNPost -split "\.")[0]

                        # If PSExec isn't found, download it and add it to Sytem32
                        if (!$(Get-Command -CommandType Application | Where-Object {$_.Name -like "*PsExec*"})) {
                            Write-Host "Downloading PSExec64.exe from https://live.sysinternals.com/PsExec64.exe..."
                            Invoke-WebRequest -Uri "https://live.sysinternals.com/PsExec64.exe" -OutFile "$UserHome\Downloads\PSExec64.exe"
                            Copy-Item -Path "$UserHome\Downloads\PSExec64.exe" -Destination "$env:WindowsSystem32Root\PsExec64.exe" -Force
                        }

                        $p = Start-Process -FilePath "$($(Get-Command cmd).Source)" -ArgumentList "/c psexec64 \\$computer -u $DomainPre\$Uname -p $Pword quser /server:$computer > $tempfile" -WindowStyle hidden -passthru
                    }
                    else {
                        $p = Start-Process -FilePath "$($(Get-Command cmd).Source)" -ArgumentList "/c query user /server:$computer > $tempfile" -WindowStyle hidden -passthru
                    }

                #we can't read in info or else it will freeze.  We cant run waitforexit until we read the standard output, or we run into issues...
                #handle timeouts on our own by watching hasexited
                    $stopprocessing = $false
                    do
                    {
                    
                        #check if process has exited
                            $hasExited = $p.HasExited
                
                        #check if there is still a record of the process
                            Try
                            {
                                $proc = Get-Process -id $p.id -ErrorAction stop
                            }
                            Catch
                            {
                                $proc = $null
                            }

                        #sleep a bit
                            start-sleep -seconds .5

                        #If we timed out and the process has not exited, kill the process
                            if( ( (Get-Date) - $Started ).totalseconds -gt $timeout -and -not $hasExited -and $proc)
                            {
                                $p.kill()
                                $stopprocessing = $true
                                Write-Error "$computer`: Query.exe took longer than $timeout seconds to execute."
                                Write-Warning "Unable to output Get-UserSessionViaQuery result for $computer. Continuing..."
                            }
                    }
                    until($hasexited -or $stopProcessing -or -not $proc)
                    
                    if($stopprocessing)
                    {
                        Continue
                    }

                    #if we are still processing, read the output!
                        try
                        {
                            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                                # Remove PSExec Header from $tempfile
                                [System.Collections.ArrayList]$tempcontent = Get-Content $tempfile
                                $DesiredStartingIndex =  [array]::indexof($tempcontent,$($tempcontent | Select-String -Pattern "USERNAME"))
                                $tempcontent.RemoveRange(0,$DesiredStartingIndex)
                                Set-Content -Value $tempcontent -Path $tempfile
                                Set-Content -Value $tempcontent -Path "$HOME\notdomain.txt"
                            }
                            else {
                                Get-Content $tempFile | Set-Content -Path "$HOME\domain.txt"
                            }
                            $sessions = Get-Content $tempfile -ErrorAction stop
                            Remove-Item $tempfile -force
                        }
                        catch
                        {
                            Write-Error "Could not process results for '$computer' in '$tempfile': $_"
                            continue
                        }
        
            #handle no results
            if($sessions){

                1..($sessions.count - 1) | Foreach-Object {
            
                    #Start to build the custom object
                    $temp = "" | Select ComputerName, Username, SessionName, SessionId, State, IdleTime, LogonTime
                    $temp.ComputerName = $computer

                    #The output of query.exe is dynamic. 
                    #strings should be 82 chars by default, but could reach higher depending on idle time.
                    #we use arrays to handle the latter.

                    if($sessions[$_].length -gt 5){
                        
                        #if the length is normal, parse substrings
                        if($sessions[$_].length -le 82){
                           
                            $temp.Username = $sessions[$_].Substring(1,22).trim()
                            $temp.SessionName = $sessions[$_].Substring(23,19).trim()
                            $temp.SessionId = $sessions[$_].Substring(42,4).trim()
                            $temp.State = $sessions[$_].Substring(46,8).trim()
                            $temp.IdleTime = $sessions[$_].Substring(54,11).trim()
                            $logonTimeLength = $sessions[$_].length - 65
                            try{
                                $temp.LogonTime = Get-Date $sessions[$_].Substring(65,$logonTimeLength).trim() -ErrorAction stop
                            }
                            catch{
                                #Cleaning up code, investigate reason behind this.  Long way of saying $null....
                                $temp.LogonTime = $sessions[$_].Substring(65,$logonTimeLength).trim() | Out-Null
                            }

                        }
                        
                        #Otherwise, create array and parse
                        else{                                       
                            $array = $sessions[$_] -replace "\s+", " " -split " "
                            $temp.Username = $array[1]
                
                            #in some cases the array will be missing the session name.  array indices change
                            if($array.count -lt 9){
                                $temp.SessionName = ""
                                $temp.SessionId = $array[2]
                                $temp.State = $array[3]
                                $temp.IdleTime = $array[4]
                                try
                                {
                                    $temp.LogonTime = Get-Date $($array[5] + " " + $array[6] + " " + $array[7]) -ErrorAction stop
                                }
                                catch
                                {
                                    $temp.LogonTime = ($array[5] + " " + $array[6] + " " + $array[7]).trim()
                                }
                            }
                            else{
                                $temp.SessionName = $array[2]
                                $temp.SessionId = $array[3]
                                $temp.State = $array[4]
                                $temp.IdleTime = $array[5]
                                try
                                {
                                    $temp.LogonTime = Get-Date $($array[6] + " " + $array[7] + " " + $array[8]) -ErrorAction stop
                                }
                                catch
                                {
                                    $temp.LogonTime = ($array[6] + " " + $array[7] + " " + $array[8]).trim()
                                }
                            }
                        }

                        #if specified, parse idle time to timespan
                        if($parseIdleTime){
                            $string = $temp.idletime
                
                            #quick function to handle minutes or hours:minutes
                            function Convert-ShortIdle {
                                param($string)
                                if($string -match "\:"){
                                    [timespan]$string
                                }
                                else{
                                    New-TimeSpan -Minutes $string
                                }
                            }
                
                            #to the left of + is days
                            if($string -match "\+"){
                                $days = New-TimeSpan -days ($string -split "\+")[0]
                                $hourMin = Convert-ShortIdle ($string -split "\+")[1]
                                $temp.idletime = $days + $hourMin
                            }
                            #. means less than a minute
                            elseif($string -like "." -or $string -like "none"){
                                $temp.idletime = [timespan]"0:00"
                            }
                            #hours and minutes
                            else{
                                $temp.idletime = Convert-ShortIdle $string
                            }
                        }
                
                        #Output the result
                        $temp
                    }
                }
            }            
            else
            {
                Write-Warning "'$computer': No sessions found"
            }

            if (Test-Path $tempfile) {
                Remove-Item $tempfile -force
            }
        }
    }
}


Function Get-LHSCimSession {
    <#
    .SYNOPSIS
        Create CIMSessions to retrieve WMI data.

    .DESCRIPTION
        The Get-CimInstance cmdlet in PowerShell V3 can be used to retrieve WMI information
        from a remote computer using the WSMAN protocol instead of the legacy WMI service
        that uses DCOM and RPC. However, the remote computers must be running PowerShell
        3 and WSMAN protocol version 3. When querying a remote computer,
        Get-CIMInstance setups a temporary CIMSession. However, if the remote computer is
        running PowerShell 2.0 this will fail. You have to manually create a CIMSession
        with a CIMSessionOption to use the DCOM protocol. This Script does it for you
        and creates a CimSession depending on the remote Computer capabilities.

    .PARAMETER ComputerName
        The computer name(s) to connect to. 
        Default to local Computer

    .PARAMETER Credential
        [Optional] alternate Credential to connect to remote computer.

    .EXAMPLE
        $CimSession = Get-LHSCimSession -ComputerName PC1
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession
        Remove-CimSession -CimSession $CimSession    

    .EXAMPLE
        $cred = Get-Credential Domain01\User02 
        $CimSession = Get-LHSCimSession -ComputerName PC1 -Credential $cred
        $Volume = Get-CimInstance -ClassName Win32_Volume -Filter "Name = 'C:\\'" -CimSession $CimSession
        Remove-CimSession -CimSession $CimSession 

    .INPUTS
        System.String, you can pipe ComputerNames to this Function

    .OUTPUTS
        An array of Microsoft.Management.Infrastructure.CimSession objects

    .NOTES
        to get rid of CimSession because of testing use the following to remove all CimSessions
        Get-CimSession | Remove-CimSession -whatif

        Most of the CIM Cmdlets do not have a -Credential parameter. The only way to specify 
        alternate credentials is to manually build a new CIM session object, and pass that 
        into the -CimSession parameter on the other cmdlets.

        AUTHOR: Pasquale Lantella 
        LASTEDIT: 
        KEYWORDS: CIMSession

    .LINK
        The Lonely Administrator: Get CIMInstance from PowerShell 2.0 
        http://jdhitsolutions.com/blog/2013/04/get-ciminstance-from-powershell-2-0/

    #Requires -Version 3.0
    #>
    [cmdletbinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimSession')]
    Param(
        [Parameter(Position=0,Mandatory=$False,ValueFromPipeline=$True,
            HelpMessage='An array of computer names. The default is the local computer.')]
        [alias("CN")]
        [string[]]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Creds,

        [Parameter(Mandatory=$False)]
        [switch]$UseSSL
    )

    BEGIN {
        Set-StrictMode -Version Latest
        ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name

        # Test if Local Host is running WSMan 3 or higher
        Function Test-IsWsman3 {
        # Test if WSMan is greater or eqaul Version 3.0
        # Tested against Powershell 4.0
            [cmdletbinding()]
            Param(
                [Parameter(Position=0,ValueFromPipeline)]
                [string]$LocalComputerName=$env:computername
            )

            Begin {
                #a regular expression pattern to match the ending
                [regex]$rx="\d\.\d$"
            }
            Process {
                $result = $Null
                Try {
                    $result = Test-WSMan -ComputerName $LocalComputerName -ErrorAction Stop
                }
                Catch {
                    # Write-Error $_
                    $False
                }
                if ($result) {
                    $m = $rx.match($result.productversion).value
                    if ($m -ge '3.0') {
                        $True
                    }
                    else {
                        $False
                    }
                }
            } #process
            End {}
        } #end Test-IsWSMan
    } # end BEGIN

    PROCESS {
        Write-Verbose "${CmdletName}: Starting Process Block"
        Write-Debug ("PROCESS:`n{0}" -f ($PSBoundParameters | Out-String))
        
        $CimSessionObjectArray = @()
        ForEach ($Computer in $ComputerName)
        {
            # Test if Remote Host has WSMan available 
            IF (Test-WSMan -ComputerName $Computer) {
                $SessionParams = @{
                      ComputerName = $Computer
                      ErrorAction = 'Stop'
                }
                if ($PSBoundParameters['Creds'])
                {
                    Write-Verbose "Adding alternate credential for CIMSession"
                    $SessionParams.Add("Credential",$Creds)
                }

                If (Test-IsWsman3 -LocalComputerName $Computer)
                {
                    $option = New-CimSessionOption -Protocol WSMan 
                    $SessionParams.SessionOption = $Option
                }
                Else
                {
                    $option = New-CimSessionOption -Protocol DCOM
                    $SessionParams.SessionOption = $Option
                }

                try {
                    $CimSession = New-CimSession @SessionParams
                }
                catch {
                    if ($PSBoundParameters['Creds']) {
                        Write-Warning "Failed to establish CimSession with $Computer! Please check your Credentials."
                    }
                    if (!$($PSBoundParameters['Creds'])) {
                        Write-Warning @"
Failed to establish CimSession with $Computer! If $Computer is NOT on the same domain as $env:ComputerName
(i.e.  $($(Get-WMIObject Win32_ComputerSystem).Domain)), please use the -Credential parameter.
"@
                    }

                    # Move on to the next Computer in foreach loop
                    continue
                }
                
                New-Variable -Name "$Computer`CimSession" -Value $(
                    [pscustomobject][ordered]@{
                        ComputerName   = $Computer
                        CimSession   = $CimSession
                        CimSessionObjName = "$Computer`CimSession"
                    }
                ) -Force

                $CimSessionObjectArray +=, $(Get-Variable -Name "$Computer`CimSession" -ValueOnly)
            }
            Else {
                Write-Warning "WSMan (i.e. WinRM service) not available on $Computer...Continuing..."
            } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)  
        } # end ForEach ($Computer in $ComputerName)

        if ($CimSessionObjectArray.Count -lt 1) {
            Write-Verbose "Unable to create CimSessions for any of the ComputerNames provided! Halting!"
            Write-Error "Unable to create CimSessions for any of the ComputerNames provided! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($CimSessionObjectArray.Count -ge 1) {
            foreach ($CimSesObj in $CimSessionObjectArray) {
                Write-Verbose "Created CimSession for $($CimSesObj.ComputerName)"
            }
        }

        $CimSessionObjectArray
    } # end PROCESS

    END { Write-Verbose "Function ${CmdletName} finished." }

} # end Function Get-LHSCimSession


function Get-UserSessionViaCim {
    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$CompName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserName = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1]),
 
        [Parameter(Mandatory=$False)]
        $Password,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$False)]
        [switch]$UseSSL
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($UserName -and $Password -and $Credential) {
        Write-Verbose "Please use EITHER the Credential parameter OR the UserName and Password parameters! Halting!"
        Write-Error "Please use EITHER the Credential parameter OR the UserName and Password parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserName) {
        $UserNameFormatOne = $RemoteHostUser | Select-String -Pattern "\\"
        $UserNameFormatTwo = $RemoteHostUser | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $UserName = $UserName.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $UserName = $UserName.Split("@")[0]
        }
    }

    if ($Password) {
        if ($Password.GetType().FullName -eq "System.String") {
            $Password = ConvertTo-SecureString $Passwd -AsPlainText -Force
        }
    }

    $LogonTypeTranslated = @{
        "0" = "Local System"
        "2" = "Local Console Logon" #(Interactive)
        "3" = "Network (PSRemoting)" # (MSDN says 3 explicitly does NOT cover RDP, but testing proves otherwise)
        "4" = "Scheduled Task" # (Batch)
        "5" = "Service Account" # (Service)
        "7" = "ScreenSaver Unlock" #(Unlock)
        "8" = "Cleartext Network Logon" # (NetworkCleartext)
        "9" = "RunAs Using Alt Creds" #(NewCredentials)
        "10" = "RDP\TS\RemoteAssistance" #(RemoteInteractive)
        "11" = "Local Console w/Cached Creds" #(CachedInteractive)
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    # NOTE: $defaultDisplaySet, $defaultDisplayPropertySet, and $PSStandardMembers below will be used towards
    # the end of the below foreeach ($Comp in $CompName) loop...
    # Configure a default display set for CustomObject TypeName Logon.Info
    $defaultDisplaySet = "LogonId","SessionId","SessionName","UpdatedName","Status","IdleTime","LogonTypeTranslated","UpdatedStartTime","AuthenticationPackage","RelevantWSManInfo","UpdatedDomain"
    # Create the default property display set
    #$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
    Update-TypeData -TypeName Logon.Info -DefaultDisplayPropertySet $defaultDisplaySet -ErrorAction SilentlyContinue
    #$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

    $UserSessionInfoObjArray = @()
    foreach ($Comp in $CompName) {
        $RemoteHostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $Comp)) {
            try {
                $RemoteHostIP = $(Resolve-DNSName $Comp).IPAddress
            }
            catch {
                Write-Verbose "Unable to resolve $Comp!"
            }
            if ($RemoteHostIP) {
                # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
                $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
                if ($RemoteHostIP.Count -gt 1) {
                    $RemoteHostIP = $RemoteHostIP[0]
                }
                $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
                $pos = $RemoteHostNameFQDN.IndexOf(".")
                $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                $RemoteHostUserName = "$UserName@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostIP) {
                Write-Error "Unable to resolve $Comp! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $Comp) {
            try {
                $RemoteHostIP = $CompName[0]
                $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
            }
            catch {
                Write-Verbose "Unable to resolve $RemoteHost!"
            }
            if ($RemoteHostNameFQDN) {
                if ($($RemoteHostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                }
                else {
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN
                }
                $RemoteHostUserName = "$UserName@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostNameFQDN) {
                Write-Error "Unable to resolve $Comp! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($UserName -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
        $($CompName -ne $env:COMPUTERNAME -and $CompName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
        $CompName.Count -gt 1) {
            if ($Credential) {
                $FinalCreds = $Credential
            }
            else {
                if (!$Password) {
                    $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
                }
                # If $CompName[0] is on a different Domain, change $UserName to $RemoteHostUserName
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                    $UserName = $RemoteHostUserName
                }
                $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
            }
        }

        if ($UserName -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
        $($CompName -ne $env:COMPUTERNAME -and $CompName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
        $CompName.Count -gt 1) {
            try {
                $CimSessionObj = Get-LHSCimSession -ComputerName $Comp -Creds $FinalCreds
                
                if (!$CimSessionObj) {
                    throw
                }
            }
            catch {
                Write-Warning "The credentials used for $Comp did not work. Skipping $Comp"
                continue
            }
        }
        else {
            $CimSessionObj = Get-LHSCimSession -ComputerName $Comp
        }

        New-Variable -Name "$Comp`LoggedOnUserCimInfo" -Value $(Get-CimInstance -ClassName Win32_LoggedOnUser -CimSession $CimSessionObj.CimSession) -Force
        New-Variable -Name "$Comp`LogOnSessionCimInfo" -Value $(Get-CimInstance -ClassName Win32_LogOnSession -CimSession $CimSessionObj.CimSession) -Force
        New-Variable -Name "$Comp`LogonsReconciled" -Value $(
            $(Get-Variable -Name "$Comp`LogOnSessionCimInfo" -ValueOnly) | foreach {
                if ($($(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly).Dependent.LogonId) -contains $_.LogonId) {
                    $_
                }
            }
        ) -Force

        # Convert $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly) to a PSCustomObject in order
        # to change the default Properties/NoteProperties that are displayed without losing the rest of
        # the Properties under the hood (which is what would happen with Select-Object). For more info:
        # https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
        New-Variable -Name "$Comp`FinalLogons" -Value $(New-Object -TypeName System.Collections.ArrayList)
        for ($li=0; $li -lt $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly).Count; $li++) {
            $LTT = $LogonTypeTranslated[$($($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonType.ToString())]
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "LogonTypeTranslated" -Value $LTT
            
            $UpdatedName = foreach ($obj2 in $(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly)) {
                if ($obj2.Dependent.LogonId -eq $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonId) {
                    $obj2.Antecedent.Name
                }
            }
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value $UpdatedName

            $UpdatedDomain = foreach ($obj3 in $(Get-Variable -Name "$Comp`LoggedOnUserCimInfo" -ValueOnly)) {
                if ($obj3.Dependent.LogonId -eq $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).LogonId) {
                    $obj3.Antecedent.Domain
                }
            }
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedDomain" -Value $UpdatedDomain

            [System.DateTimeOffset]$UpdatedStartTimePrep = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).StartTime
            $UpdatedStartTime = $UpdatedStartTimePrep.UtcDateTime
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "UpdatedStartTime" -Value $UpdatedStartTime

            # SessionID for a Particular Account
            <#
            $SessionIdPrep = $(Get-Process -IncludeUserName | Where-Object {$_.UserName -like "*$UpdatedName"}) | Group-Object -Property SessionId | Sort-Object -Property Count -Descending
            if ($SessionIdPrep -ne $null) {
                $SessionId = $SessionIdPrep[0].Name
            }
            else {
                $SessionId = ""
            }
            #>
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "SessionId" -Value ""

            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "SessionName" -Value ""
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "IdleTime" -Value ""
            $(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Add-Member -MemberType NoteProperty -Name "RelevantWSManInfo" -Value ""

            $ArrayOfProperties = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li] | Get-Member | Where-Object {$_.MemberType -match "Property|NoteProperty"}).Name
            $CustomObjectHashTable = @{}
            for ($pi=0; $pi -lt $ArrayOfProperties.Count; $pi++) {
                $Key = $ArrayOfProperties[$pi]
                $Value = $($(Get-Variable -Name "$Comp`LogonsReconciled" -ValueOnly)[$li]).$($ArrayOfProperties[$pi])
                $CustomObjectHashTable.Add($Key,$Value)
            }
            New-Variable -Name "$Comp`CustomLogonObj$li" -Value $(
                New-Object PSObject -Property $CustomObjectHashTable
            )
            # Change the TypeName to Logon.Info
            $(Get-Variable -Name "$Comp`CustomLogonObj$li" -ValueOnly).PSObject.TypeNames.Insert(0,'Logon.Info')
            # $(Get-Variable -Name "$Comp`LogonsCustom" -ValueOnly) | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            
            # Finally, add it to $Comp`FinalLogons object array
            $(Get-Variable -Name "$Comp`FinalLogons" -ValueOnly).Add($(Get-Variable -Name "$Comp`CustomLogonObj$li" -ValueOnly)) | Out-Null
        }

        New-Variable -Name "$Comp`LogonSessions" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                ComputerName   = $Comp
                LogonSessions   = $(Get-Variable -Name "$Comp`FinalLogons" -ValueOnly)
            }
        ) -Force

        $UserSessionInfoObjArray +=, $(Get-Variable -Name "$Comp`LogonSessions" -ValueOnly)

        Remove-CimSession -CimSession $CimSessionObj.CimSession
    }

    Write-Warning "Results may contain stale entries (i.e. accounts may have since logged off or otherwise disconnected) unless `"Status`" explicitly has a value"
    $UserSessionInfoObjArray

    ##### END Main Body #####

}


function Get-WsManServerInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$RemoteComputer = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserAccount = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1]),
        
        [Parameter(Mandatory=$False)]
        $Psswd,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$RemoteCreds,

        [Parameter(Mandatory=$False)]
        [switch]$UseSSL,

        [Parameter(Mandatory=$False)]
        [switch]$DoNotProbeWSManClients

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($UserAccount -and $Psswd -and $RemoteCreds) {
        Write-Verbose "Please use EITHER the RemoteCreds parameter OR the UserAccount and Psswd parameters! Halting!"
        Write-Error "Please use EITHER the RemoteCreds parameter OR the UserAccount and Psswd parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserAccount) {
        $UserNameFormatOne = $UserAccount | Select-String -Pattern "\\"
        $UserNameFormatTwo = $UserAccount | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $UserAccount = $UserAccount.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $UserAccount = $UserAccount.Split("@")[0]
        }
    }

    if ($Psswd) {
        if ($Psswd.GetType().FullName -eq "System.String") {
            $Psswd = ConvertTo-SecureString $Psswd -AsPlainText -Force
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    $WSManServerMapping = @()
    if ($UserAccount -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($RemoteComputer -ne $env:COMPUTERNAME -and $RemoteComputer -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $RemoteComputer.Count -gt 1) {
        for ($i=0; $i -lt $RemoteComputer.Count; $i++) {
            $RemoteHostNetworkInfoArray = @()
            if (! $(Test-IsValidIPAddress -IPAddress $RemoteComputer[$i])) {
                try {
                    $RemoteHostIP = $(Resolve-DNSName $RemoteComputer[$i]).IPAddress
                }
                catch {
                    Write-Verbose "Unable to resolve $($RemoteComputer[$i])!"
                }
                if ($RemoteHostIP) {
                    # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
                    $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                    # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
                    if ($RemoteHostIP.Count -gt 1) {
                        $RemoteHostIP = $RemoteHostIP[0]
                    }
                    $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                    $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
                    $pos = $RemoteHostNameFQDN.IndexOf(".")
                    $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                    $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                    $RemoteHostUserName = "$UserAccount@$RemoteHostNameFQDNPost"

                    $RemoteHostNetworkInfoArray += $RemoteHostIP
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                }
                if (!$RemoteHostIP) {
                    Write-Error "Unable to resolve $($RemoteComputer[$i])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            if (Test-IsValidIPAddress -IPAddress $RemoteComputer[$i]) {
                try {
                    $RemoteHostIP = $RemoteComputer[$i]
                    $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
                    $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
                }
                catch {
                    Write-Warning "Unable to resolve $RemoteComputer to HostName using rDNS lookup. Please ensure there is a PTR record available for $RemoteComputer on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteHostNameFQDN) {
                    if ($($RemoteHostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteHostNameFQDN.IndexOf(".")
                        $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                        $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                        $RemoteHostNameFQDNPost = $RemoteHostNameFQDN
                    }
                    $RemoteHostUserName = "$UserAccount@$RemoteHostNameFQDNPost"

                    $RemoteHostNetworkInfoArray += $RemoteHostIP
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                    $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                }
                if (!$RemoteHostNameFQDN) {
                    Write-Error "Unable to resolve $RemoteComputer! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            if ($RemoteCreds) {
                $FinalCreds = $RemoteCreds
            }
            else {
                if (!$Psswd) {
                    $Psswd = Read-Host -Prompt "Please enter the password for $UserAccount" -AsSecureString
                }
                # If $ComputerName[0] is on a different Domain, change $UserAccount to $RemoteHostUserName
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                    $UserAccount = $RemoteHostUserName
                }
                $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccount, $Psswd
            }

            # Collect Information About WSManServer
            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                # Test $FinalCreds against WSManServer. If they don't work, move on to the next hostname in $RemoteComputer
                try {
                    $RemoteWSmanServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[$i] -ConnectionURI "http://$($RemoteComputer[$i]):5985/wsman" -ResourceURI "shell" -Enumerate -Credential $FinalCreds

                    if (!$RemoteWSmanServerWSManInstances) {
                        throw
                    }
                }
                catch {
                    Write-Warning "The credentials used for $($RemoteComputer[$i]) did not work. Skipping $($RemoteComputer[$i])"
                    continue
                }
                
                $RemoteServerProcesses = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    try {
                        Get-Process -IncludeUserName
                    }
                    catch {
                        Get-Process
                    }
                } -Credential $FinalCreds

                $RemoteServerWSMANTCPConnections = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
                } -Credential $FinalCreds
            }
            else {
                $RemoteWSmanServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[$i] -ConnectionURI "http://$($RemoteComputer[$i]):5985/wsman" -ResourceURI "shell" -Enumerate
                $RemoteServerProcesses = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    try {
                        Get-Process -IncludeUserName
                    }
                    catch {
                        Get-Process
                    }
                }

                $RemoteServerWSMANTCPConnections = Invoke-Command -ComputerName $RemoteComputer[$i] -ScriptBlock {
                    Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
                }
            }
            
            $RemoteWSManServerClientIPs = $RemoteWSmanServerWSManInstances.ClientIP
            $RemoteServerWSManProcesses = foreach ($WSManInstance in $RemoteWSmanServerWSManInstances) {
                $RemoteServerProcesses | Where-Object {$_.Id -eq $WSManInstance.ProcessId}
            }
            $RemoteServerWSManProcesses = foreach ($Process in $RemoteServerWSManProcesses) {
                # Add a UtcCreationTime NoteProperty
                $UtcTimePrep1 = $Process.StartTime
                $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
                $Process | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
                $Process
            }

            # Determine WSMAN Server TCP Connections
            # IMPORTANT NOTE: The Get-NetTCPConnection CreationTime property is accurate for the WSMANServer, but not
            # WSMan Clients. Since it's accurate for the WSManServer, we can feel comfortable doing the below
            $RemoteServerWSMANTCPConnections = foreach ($tcpobj in $RemoteServerWSMANTCPConnections) {
                # Add a UtcCreationTime NoteProperty
                $UtcTimePrep1 = $tcpobj.CreationTime
                $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
                $tcpobj | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
                $tcpobj
            }

            $WSManClientMapping = @()
            if (!$DoNotProbeWSManClients) {
                foreach ($ClientIP in $RemoteWSManServerClientIPs) {
                    try {
                        $NameHost = $(Resolve-DNSName $ClientIP).NameHost
                    }
                    catch {
                        Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                        continue
                    }

                    $InvCmdCollection = @()
                    # Determine if the Credentials that worked on WSManServer will work on WSManClient
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            
                        } -Credential $FinalCreds
                        $InvCmd1DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                        $InvCmdCollection +=, $InvCmd1DateTime

                        if (!$RemoteClientProcesses) {
                            throw
                        }

                        $ClientCreds = $FinalCreds
                    }
                    catch {
                        Write-Warning "Credentials provided for WSManClient $NameHost are not valid."
                        $InputNewCredsAsk = Read-Host -Prompt "Would you like to supply different credentials for $NameHost? [Yes/No]"
                        if ($InputNewCredsAsk -match "Yes|yes|Y|y") {
                            $tempuname = Read-Host -Prompt "Please enter the name of a User Account that has access to $NameHost"
                            $temppwd = Read-Host -Prompt "Please enter the password for $tempuname" -AsSecureString
                            $ClientCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $tempuname,$temppwd
                        }
                        else {
                            Write-Warning "Skipping gathering data for WSManClient $NameHost"
                            continue
                        }
                    }
                    if (!$RemoteClientProcesses) {
                        Write-Host "RemoteClientProcesses still not defined. Trying newly entered ClientCreds..."
                        try {
                            $RemoteClientProcesses = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                                try {
                                    Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                catch {
                                    Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                
                            } -Credential $ClientCreds
                            $InvCmd2DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                            $InvCmdCollection +=, $InvCmd2DateTime

                            if (!$RemoteClientProcesses) {
                                throw
                            }
                        }
                        catch {
                            Write-Warning "Credentials provided for WSManClient $NameHost are not valid. Skipping gathering data for WSManClient $NameHost"
                            continue
                        }
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    } -Credential $ClientCreds
                    $InvCmd3DateTime = $([System.DateTimeOffset]$(Get-Date)).UtcDateTime
                    $InvCmdCollection +=, $InvCmd3DateTime

                    foreach ($ClientTCPIPConnection in $RemoteWSManClientTCPIPConnections) {
                        # Since the Get-NetTCPConnection CreationTime property is only reliable on Windows 10 and
                        # Windows Server 2016 and higher, we need to probe each client to determine if their OS
                        # is Windows 10 or Windows Server 2016 or higher. If not, then make sure the
                        # WSManClientTCPConnection and ConnectionStartTime properties are null and the
                        # PossibleWSManClientTCPConnections and PossibleConnectionStartTime properties are
                        # filled in.
                        #$ClientOSCheck = Invoke-Command -ComputerName $NameHost -ScriptBlock {
                        #    [version]$($(Get-CimInstance -ClassName Win32_OperatingSystem).Version)
                        #} -Credential $FinalCreds

                        # Add a UtcCreationTime NoteProperty
                        $UtcTimePrepA = $ClientTCPIPConnection.CreationTime
                        $UtcTimePrepB = [System.DateTimeOffset]$UtcTimePrepA
                        $ClientTCPIPConnection | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrepB -Force

                        # Map TCP Connections to Processes where possible
                        $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $RemoteServerWSMANTCPConnections) {
                            if ($ClientTCPIPConnection.LocalPort -eq $WSManServerTCPConnection.RemotePort -and
                            $WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                                $WSManServerTCPConnection
                            }
                        }
                        $MappedWSManServerProcess = foreach ($Process in $RemoteServerProcesses) {
                            $WSManServProcId = $($RemoteWSmanServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                            if ($Process.Id -eq $WSManServProcId) {
                                $Process
                            }
                        }
                        $MappedWSManClientTCPConnection = $ClientTCPIPConnection
                        $MappedWSManClientProcess = $RemoteClientProcesses | Where-Object {
                            $_.Id -eq $ClientTCPIPConnection.OwningProcess
                        }
                        if ($MappedWSManServerProcess) {
                            $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                        }
                        else {
                            $MappedConnectionStartTime = ""
                        }
                        if ($MappedWSManServerTCPConnection.CreationTime) {
                            [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $MappedWSManServerTCPConnection.CreationTime
                            $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                        }
                        else {
                            $MappedWSManServerActivityUTCDateTime = ""
                        }

                        New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                            [pscustomobject][ordered]@{
                                WSManServerName                     = $RemoteComputer[$i]
                                WSManServerProcess                  = $MappedWSManServerProcess
                                WSManServerTCPConnection            = $MappedWSManServerTCPConnection
                                WSManClientName                     = $NameHost
                                WSManClientProcess                  = $MappedWSManClientProcess
                                WSManClientTCPConnection            = $MappedWSManClientTCPConnection
                                ConnectionStartTime                 = $MappedConnectionStartTime
                                MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                            }
                        ) -Force

                        if ($MappedWSManServerActivityUTCDateTime) {
                            # Filter out TCP Connections made by this function via Invoke-Command
                            New-Variable -Name "TimeCheck$($MappedWSManServerTCPConnection.RemotePort)" -Value $(
                                $($([System.DateTimeOffset]$(Get-Date)).UtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds
                            ) -Force

                            $InvCmdTimeCheck = @()
                            foreach ($InvCmdUtcDateTime in $InvCmdCollection) {
                                $InvCmdTimeCheck +=, $($($InvCmdUtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds -gt 3)
                            }
                            if ($InvCmdTimeCheck -contains $false) {
                                $AddMatch = $false
                            }
                            else {
                                $AddMatch = $true
                            }

                            if ($MappedWSManServerTCPConnection -and $AddMatch -and
                            $(Get-Variable -Name "TimeCheck$($MappedWSManServerTCPConnection.RemotePort)" -ValueOnly) -gt 3 -and
                            $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -or
                            $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress)) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        else {
                            if ($MappedWSManServerTCPConnection -and
                            $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -or
                            $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress)) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                    }
                }
            }
            else {
                foreach ($ClientIP in $RemoteWSManServerClientIPs) {
                    try {
                        $NameHost = $(Resolve-DNSName $ClientIP).NameHost
                    }
                    catch {
                        Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                        continue
                    }

                    # Map TCP Connections to Processes where possible
                    $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $RemoteServerWSMANTCPConnections) {
                        if ($WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                            $WSManServerTCPConnection
                        }
                    }

                    foreach ($WSManServTCPObj in $MappedWSManServerTCPConnection) {
                        $MappedWSManServerProcess = foreach ($Process in $RemoteServerProcesses) {
                            $WSManServProcId = $($RemoteWSmanServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                            if ($Process.Id -eq $WSManServProcId) {
                                $Process
                            }
                        }
                        if ($MappedWSManServerProcess) {
                            $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                        }
                        else {
                            $MappedConnectionStartTime = ""
                        }
                        if ($WSManServTCPObj.CreationTime) {
                            [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $WSManServTCPObj.CreationTime
                            $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                        }
                        else {
                            $MappedWSManServerActivityUTCDateTime = ""
                        }

                        New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                            [pscustomobject][ordered]@{
                                WSManServerName                     = $RemoteComputer[$i]
                                WSManServerProcess                  = $MappedWSManServerProcess
                                WSManServerTCPConnection            = $WSManServTCPObj
                                WSManClientName                     = $NameHost
                                ConnectionStartTime                 = $MappedConnectionStartTime
                                MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                            }
                        ) -Force

                        # Filter out TCP Connections made by this function via Invoke-Command
                        if ($MappedWSManServerActivityUTCDateTime) {
                            New-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -Value $(
                                $($([System.DateTimeOffset]$(Get-Date)).UtcDateTime - $MappedWSManServerActivityUTCDateTime).TotalSeconds
                            ) -Force

                            if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -and
                            $(Get-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -ValueOnly) -gt 3) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        else {
                            if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress) {
                                $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                            }
                        }
                        <#
                        if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $RemoteHostNameFQDN).IPAddress -and
                        $($WSManServTCPObj.UtcCreationTime.UtcDateTime).TimeOfDay -ne "00:00:00" -and 
                        $(Get-Variable -Name "TimeCheck$($WSManServTCPObj.RemotePort)" -ValueOnly) -gt 3) {
                            $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                        }
                        #>
                    }
                }
            }

            # Attempt to Identify the initial connection versus the connection that actually handle WinRM Activity
            $UpdatedWSManClientMappingPrep = $WSManClientMapping | Group-Object -Property MostRecentConnectionActivity
            $Connections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -gt 1}).Group
            $InitialConnections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -eq 1}).Group
            $ActiveConnections = foreach ($connection in $Connections) {
                if ($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess") {
                    if ($connection.MostRecentConnectionActivity -and
                    $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00" -and
                    $connection.WSManClientProcess -ne $null) {
                        $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                        $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                        $connection
                    }
                }
                else {
                    if ($connection.MostRecentConnectionActivity -and
                    $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00") {
                        $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                        $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                        $connection
                    }
                }
            }

            $InactiveConnections = foreach ($connection in $Connections) {
            if (!$($connection.MostRecentConnectionActivity) -or
                $($connection.MostRecentConnectionActivity).TimeOfDay -eq "00:00:00" -or
                $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientTCPConnection" -and $connection.WSManClientTCPConnection -eq $null) -or
                $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess" -and $connection.WSManClientProcess -eq $null)) {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false -Force
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false -Force
                    $connection
                }
            }

            $InitialConnections = foreach ($connection in $InitialConnections) {
                $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false
                $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $true
                $connection
            }
            $UpdatedWSManClientMapping = $InactiveConnections + $ActiveConnections + $InitialConnections

            New-Variable -Name "PSRemotingInfoFor$($RemoteComputer[$i])" -Value $(
                [pscustomobject][ordered]@{
                    WSManServer         = $RemoteComputer[$i]
                    WSManClientMapping  = $UpdatedWSManClientMapping
                }
            )

            $WSManServerMapping +=, $(Get-Variable -Name "PSRemotingInfoFor$($RemoteComputer[$i])" -ValueOnly)

            Remove-Variable -Name "ClientCreds" -Force -ErrorAction SilentlyContinue
        }
    }
    else {
        # NOTE: In this else clause, all references to $RemoteComputer[$i] actually refer to the localhost
        $LocalServerWSManInstances = Get-WSManInstance -ComputerName $RemoteComputer[0] -ConnectionURI "http://$($RemoteComputer[0]):5985/wsman" -ResourceURI "shell" -Enumerate
        $LocalWSManServerClientIPs = $LocalServerWSManInstances.ClientIP
        $LocalServerProcesses = try {Get-Process -IncludeUserName} catch {Get-Process}
        $LocalWSManServerProcesses = foreach ($WSManInstance in $LocalServerWSManInstances) {
            $LocalServerProcesses | Where-Object {$_.Id -eq $WSManInstance.ProcessId}
        }
        $LocalWSManServerProcesses = foreach ($Process in $LocalWSManServerProcesses) {
            # Add a UtcCreationTime NoteProperty
            $UtcTimePrep1 = $Process.StartTime
            $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
            $Process | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
            $Process
        }

        $LocalServerWSMANTCPConnections = Get-NetTCPConnection | Where-Object {$_.LocalPort -match "5985|5986"}
        $LocalServerWSMANTCPConnections = foreach ($tcpobj in $LocalServerWSMANTCPConnections) {
            # Add a UtcCreationTime NoteProperty
            $UtcTimePrep1 = $tcpobj.CreationTime
            $UtcTimePrep2 = [System.DateTimeOffset]$UtcTimePrep1
            $tcpobj | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrep2 -Force
            $tcpobj
        }

        $WSManClientMapping = @()
        if (!$DoNotProbeWSManClients) {
            foreach ($ClientIP in $LocalWSManServerClientIPs) {
                $RemoteClientNetworkInfoArray = @()
                try {
                    $RemoteClientName = $(Resolve-DNSName $ClientIP).NameHost
                    $RemoteClientNameFQDN = $(Resolve-DNSName $RemoteClientName).Name
                }
                catch {
                    Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteClientNameFQDN) {
                    if ($($RemoteClientNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteClientNameFQDN.IndexOf(".")
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN.Substring(0, $pos)
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN
                    }
                    $RemoteClientUserName = "$UserAccount@$RemoteClientNameFQDNPost"

                    $RemoteClientNetworkInfoArray += $ClientIP
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDN
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDNPre
                }
                if (!$RemoteClientNameFQDN) {
                    Write-Error "Unable to resolve $ClientIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # If $ClientIP is on a different Domain, determine Credentials
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteClientNameFQDNPost) {
                    $UserAccount = $RemoteClientUserName

                    if (!$Psswd -and !$RemoteCreds) {
                        $Psswd = Read-Host -Prompt "Please enter the password for $UserAccount" -AsSecureString
                        $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAccount, $Psswd
                    }
                    if ($RemoteCreds) {
                        $FinalCreds = $RemoteCreds
                    }

                    # Determine if the Credentials for $ClientIP work
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            
                        } -Credential $FinalCreds

                        if (!$RemoteClientProcesses) {
                            throw
                        }

                        $ClientCreds = $FinalCreds
                    }
                    catch {
                        Write-Warning "Credentials provided for WSManClient $RemoteClientNameFQDN are not valid."
                        $InputNewCredsAsk = Read-Host -Prompt "Would you like to supply different credentials for $RemoteClientNameFQDN? [Yes/No]"
                        if ($InputNewCredsAsk -match "Yes|yes|Y|y") {
                            $tempuname = Read-Host -Prompt "Please enter the name of a User Account that has access to $RemoteClientNameFQDN"
                            $temppwd = Read-Host -Prompt "Please enter the password for $tempuname" -AsSecureString
                            $ClientCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $tempuname,$temppwd
                        }
                        else {
                            Write-Warning "Skipping gathering data for WSManClient $RemoteClientNameFQDN"
                            continue
                        }
                    }
                    if (!$RemoteClientProcesses) {
                        Write-Host "RemoteClientProcesses still not defined. Trying newly entered ClientCreds..."
                        try {
                            $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                                try {
                                    Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                catch {
                                    Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                                }
                                
                            } -Credential $ClientCreds

                            if (!$RemoteClientProcesses) {
                                throw
                            }
                        }
                        catch {
                            Write-Warning "Credentials provided for WSManClient $RemoteClientNameFQDN are not valid. Skipping gathering data for WSManClient $RemoteClientNameFQDN"
                            continue
                        }
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    } -Credential $ClientCreds
                }
                else {
                    # Determine if the Credentials for $ClientIP work
                    try {
                        $RemoteClientProcesses = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                            try {
                                Get-Process -IncludeUserName | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                            catch {
                                Get-Process | Where-Object {$_.ProcessName -eq "powershell"}
                            }
                        }

                        if (!$RemoteClientProcesses) {
                            throw
                        }
                    }
                    catch {
                        Write-Warning "Unable to run remote command on $RemoteClientNameFQDN! Please ensure you are using a Domain Admin account on the $RemoteClientNameFQDNPost Domain. Skipping gathering data for WSManClient $RemoteClientNameFQDN..."
                        continue
                    }

                    $RemoteWSManClientTCPIPConnections = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                        Get-NetTCPConnection | Where-Object {
                            $_.RemotePort -match "5985|5986" -and
                            $_.LocalAddress -notmatch '::' -and
                            $_.RemoteAddress -notmatch '::'
                        }
                    }
                }

                foreach ($ClientTCPIPConnection in $RemoteWSManClientTCPIPConnections) {
                    # Since the Get-NetTCPConnection CreationTime property is only reliable on Windows 10 and
                    # Windows Server 2016 and higher, we need to probe each client to determine if their OS
                    # is Windows 10 or Windows Server 2016 or higher. If not, then make sure the
                    # WSManClientTCPConnection and ConnectionStartTime properties are null and the
                    # PossibleWSManClientTCPConnections and PossibleConnectionStartTime properties are
                    # filled in.
                    #$ClientOSCheck = Invoke-Command -ComputerName $RemoteClientNameFQDN -ScriptBlock {
                    #    [version]$($(Get-CimInstance -ClassName Win32_OperatingSystem).Version)
                    #} -Credential $FinalCreds

                    # Add a UtcCreationTime NoteProperty
                    $UtcTimePrepA = $ClientTCPIPConnection.CreationTime
                    $UtcTimePrepB = [System.DateTimeOffset]$UtcTimePrepA
                    $ClientTCPIPConnection | Add-Member -MemberType NoteProperty -Name UtcCreationTime -Value $UtcTimePrepB -Force

                    # Map TCP Connections to Processes where possible
                    $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $LocalServerWSMANTCPConnections) {
                        if ($ClientTCPIPConnection.LocalPort -eq $WSManServerTCPConnection.RemotePort -and
                        $WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                            $WSManServerTCPConnection
                        }
                    }
                    $MappedWSManServerProcess = foreach ($Process in $LocalServerProcesses) {
                        $WSManServProcId = $($LocalServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                        if ($Process.Id -eq $WSManServProcId) {
                            $Process
                        }
                    }
                    $MappedWSManClientTCPConnection = $ClientTCPIPConnection
                    $MappedWSManClientProcess = $RemoteClientProcesses | Where-Object {
                        $_.Id -eq $ClientTCPIPConnection.OwningProcess
                    }
                    if ($MappedWSManServerProcess) {
                        $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                    }
                    else {
                        $MappedConnectionStartTime = ""
                    }
                    if ($MappedWSManServerTCPConnection.CreationTime) {
                        [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $MappedWSManServerTCPConnection.CreationTime
                        $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                    }
                    else {
                        $MappedWSManServerActivityUTCDateTime = ""
                    }

                    New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                        [pscustomobject][ordered]@{
                            WSManServerName                     = $RemoteComputer[0]
                            WSManServerProcess                  = $MappedWSManServerProcess
                            WSManServerTCPConnection            = $MappedWSManServerTCPConnection
                            WSManClientName                     = $RemoteClientNameFQDN
                            WSManClientProcess                  = $MappedWSManClientProcess
                            WSManClientTCPConnection            = $MappedWSManClientTCPConnection
                            ConnectionStartTime                 = $MappedConnectionStartTime
                            MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                        }
                    ) -Force

                    if ($MappedWSManServerTCPConnection -and
                    $($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress -or
                    $MappedWSManClientTCPConnection.RemoteAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress)) {
                        $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                    }
                }
            }
        }
        else {
            foreach ($ClientIP in $LocalWSManServerClientIPs) {
                $RemoteClientNetworkInfoArray = @()
                try {
                    $RemoteClientName = $(Resolve-DNSName $ClientIP).NameHost
                    $RemoteClientNameFQDN = $(Resolve-DNSName $RemoteClientName).Name
                }
                catch {
                    Write-Warning "Unable to resolve $ClientIP to HostName using rDNS lookup. Please ensure there is a PTR record available for $ClientIP on your DNS Server. Moving on to next WSManClient..."
                }
                if ($RemoteClientNameFQDN) {
                    if ($($RemoteClientNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $RemoteClientNameFQDN.IndexOf(".")
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN.Substring(0, $pos)
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN.Substring($pos+1)
                    }
                    else {
                        $RemoteClientNameFQDNPre = $RemoteClientNameFQDN
                        $RemoteClientNameFQDNPost = $RemoteClientNameFQDN
                    }
                    $RemoteClientUserName = "$UserAccount@$RemoteClientNameFQDNPost"

                    $RemoteClientNetworkInfoArray += $ClientIP
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDN
                    $RemoteClientNetworkInfoArray += $RemoteClientNameFQDNPre
                }
                if (!$RemoteClientNameFQDN) {
                    Write-Error "Unable to resolve $ClientIP! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # Map TCP Connections to Processes where possible
                $MappedWSManServerTCPConnection = foreach ($WSManServerTCPConnection in $LocalServerWSMANTCPConnections) {
                    if ($WSManServerTCPConnection.RemoteAddress -eq $ClientIP) {
                        $WSManServerTCPConnection
                    }
                }

                foreach ($WSManServTCPObj in $MappedWSManServerTCPConnection) {
                    $MappedWSManServerProcess = foreach ($Process in $LocalServerProcesses) {
                        $WSManServProcId = $($LocalServerWSManInstances | Where-Object {$_.ClientIP -eq $ClientIP}).ProcessId
                        if ($Process.Id -eq $WSManServProcId) {
                            $Process
                        }
                    }
                    if ($MappedWSManServerProcess) {
                        $MappedConnectionStartTime = $($MappedWSManServerProcess | Sort-Object -Property UtcCreationTime)[0].UtcCreationTime.UtcDateTime
                    }
                    else {
                        $MappedConnectionStartTime = ""
                    }
                    if ($WSManServTCPObj.CreationTime) {
                        [System.DateTimeOffset]$MappedWSManServerActivityUTCDateTimePrep = $WSManServTCPObj.CreationTime
                        $MappedWSManServerActivityUTCDateTime = $MappedWSManServerActivityUTCDateTimePrep.UtcDateTime
                    }
                    else {
                        $MappedWSManServerActivityUTCDateTime = ""
                    }

                    New-Variable -Name "ClientTCPToServerProcessMatch" -Scope Script -Value $(
                        [pscustomobject][ordered]@{
                            WSManServerName                     = $RemoteComputer[0]
                            WSManServerProcess                  = $MappedWSManServerProcess
                            WSManServerTCPConnection            = $WSManServTCPObj
                            WSManClientName                     = $RemoteClientNameFQDN
                            ConnectionStartTime                 = $MappedConnectionStartTime
                            MostRecentConnectionActivity        = $MappedWSManServerActivityUTCDateTime # Looks at WSManServer System Process
                        }
                    ) -Force

                    if ($MappedWSManServerTCPConnection.LocalAddress -eq $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) {
                        $WSManClientMapping +=, $(Get-Variable -Name "ClientTCPToServerProcessMatch" -ValueOnly)
                    }
                }
            }
        }

        # Attempt to Identify the initial connection versus the connection that actually handle WinRM Activity
        $UpdatedWSManClientMappingPrep = $WSManClientMapping | Group-Object -Property MostRecentConnectionActivity
        $Connections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -gt 1}).Group
        $InitialConnections = $($UpdatedWSManClientMappingPrep | Where-Object {$_.Count -eq 1}).Group
        $ActiveConnections = foreach ($connection in $Connections) {
            if ($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess") {
                if ($connection.MostRecentConnectionActivity -and
                $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00" -and
                $connection.WSManClientProcess -ne $null) {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                    $connection
                }
            }
            else {
                if ($connection.MostRecentConnectionActivity -and
                $($connection.MostRecentConnectionActivity).TimeOfDay -ne "00:00:00") {
                    $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $true
                    $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false
                    $connection
                }
            }
        }

        $InactiveConnections = foreach ($connection in $Connections) {
        if (!$($connection.MostRecentConnectionActivity) -or
            $($connection.MostRecentConnectionActivity).TimeOfDay -eq "00:00:00" -or
            $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientTCPConnection" -and $connection.WSManClientTCPConnection -eq $null) -or
            $($($connection | Get-Member -Type NoteProperty).Name -contains "WSManClientProcess" -and $connection.WSManClientProcess -eq $null)) {
                $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false -Force
                $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $false -Force
                $connection
            }
        }

        $InitialConnections = foreach ($connection in $InitialConnections) {
            $connection | Add-Member -MemberType NoteProperty -Name ActiveConnection -Value $false
            $connection | Add-Member -MemberType NoteProperty -Name InitialConnection -Value $true
            $connection
        }
        $UpdatedWSManClientMapping = $InactiveConnections + $ActiveConnections + $InitialConnections

        New-Variable -Name "PSRemotingInfoFor$($RemoteComputer[0])" -Value $(
            [pscustomobject][ordered]@{
                WSManServer         = $RemoteComputer
                WSManClientMapping  = $UpdatedWSManClientMapping
            }
        )

        $WSManServerMapping +=, $(Get-Variable -Name "PSRemotingInfoFor$($RemoteComputer[0])" -ValueOnly)

        Remove-Variable -Name "ClientCreds" -Force -ErrorAction SilentlyContinue
    }

    if ($($WSManServerMapping.WSManClientMapping) -eq $null) {
        Write-Verbose @"
Unable to determine PSRemoting Info for any Computer Names provided to the -RemoteComputer parameter!
This is either because access to the information was denied, or because no PSRemoting Sessions exist for those Computers! Halting!
"@
        Write-Error @"
Unable to determine PSRemoting Info for any Computer Names provided to the -RemoteComputer parameter!
This is either because access to the information was denied, or because no PSRemoting Sessions exist for those Computers! Halting!
"@
        $global:FunctionResult = "1"
        return
    }

    foreach ($result in $WSManServerMapping) {
        $result
    }

    ##### END Main Body #####

}


<#
.SYNOPSIS
    Get-UserSessionEx is capable of outputting User Session information for an array of Computers by combining output from
    query.exe and Get-CimInstance. The goal is to gather all of the most useful Session information in one place.

.DESCRIPTION
    The Get-UserSessionEx function is composed (primarily) of two functions: Get-UserSessionViaQuery and Get-UserSessionViaCim.

    The Get-UserSessionViaQuery function is a *very slightly* modified version of RamblingCookieMonster's Get-UserSession function:
        https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-UserSession.ps1
    
    Sample output of Get-UserSessionViaQuery is as follows:
        ComputerName : localhost
        Username     : testadmin
        SessionName  : rdp-tcp#29
        SessionId    : 2
        State        : Active
        IdleTime     : .
        LogonTime    : 4/23/2017 5:03:00 AM
    
    Pros of Get-UserSessionViaQuery include:
        - Provides information that reflects connection statuses *at the moment* the function is executed
        - Provides the *very userful* "State" and "IdleTime" properties
    Cons of Get-UserSessionViaQuery include:
        - Does not capture all types of Logon Sessions (such as PowerShell Remoting or those initiated by service/system accounts)
        - Does not provide the properties "LogonId" or "AuthenticationPackage" (i.e. NTLM, Kerberos, etc)

    The Get-UserSessionViaCim function is my take on parsing Get-CimInstance results from Win32_LogOnSession and Win32_LoggedOnUser.
    The helper function Get-LHSCimSession assists with using the Get-CimInstance cmdlet against machines that are not part of a
    domain, or in a different domain.

    Sample Output of Get-UserSessionViaCim is as follows (piped to Format-List):
        ComputerName  : Win12Chef.test2.lab
        LogonSessions : {@{Caption=; Name=; IdleTime=; StartTime=3/30/2017 7:54:30 PM; InstallDate=; SessionName=; UpdatedName=SYSTEM; SessionId=; 
                        LogonTypeTranslated=Local System; LogonId=999; PSShowComputerName=True; Description=; PSComputerName=Win12Chef.test2.lab; LogonType=0; 
                        UpdatedDomain=WIN12CHEF; AuthenticationPackage=Negotiate; Status=}, @{Caption=; Name=; IdleTime=; StartTime=4/30/2017 7:15:03 AM; 
                        InstallDate=; SessionName=; UpdatedName=SYSTEM; SessionId=; LogonTypeTranslated=RunAs Using Alt Creds; LogonId=3913930305; 
                        PSShowComputerName=True; Description=; PSComputerName=Win12Chef.test2.lab; LogonType=9; UpdatedDomain=WIN12CHEF; 
                        AuthenticationPackage=Negotiate; Status=}, @{Caption=; Name=; IdleTime=; StartTime=3/30/2017 7:54:40 PM; InstallDate=; SessionName=; 
                        UpdatedName=LOCAL SERVICE; SessionId=; LogonTypeTranslated=Service Account; LogonId=997; PSShowComputerName=True; Description=; 
                        PSComputerName=Win12Chef.test2.lab; LogonType=5; UpdatedDomain=WIN12CHEF; AuthenticationPackage=Negotiate; Status=}, @{Caption=; Name=; 
                        IdleTime=; StartTime=3/30/2017 7:54:36 PM; InstallDate=; SessionName=; UpdatedName=NETWORK SERVICE; SessionId=; LogonTypeTranslated=Service 
                        Account; LogonId=996; PSShowComputerName=True; Description=; PSComputerName=Win12Chef.test2.lab; LogonType=5; UpdatedDomain=WIN12CHEF; 
                        AuthenticationPackage=Negotiate; Status=}...}
    
    Sample Output of the above LogonSessions Property (piped to Format-Table):

LogonId    SessionId UpdatedName     Status LogonTypeTranslated         StartTime             AuthenticationPackage UpdatedDomain PSComputerName     
-------    --------- -----------     ------ -------------------         ---------             --------------------- ------------- --------------     
999                  SYSTEM                 Local System                3/30/2017 7:54:30 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
3913930305           SYSTEM                 RunAs Using Alt Creds       4/30/2017 7:15:03 AM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
997                  LOCAL SERVICE          Service Account             3/30/2017 7:54:40 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
996                  NETWORK SERVICE        Service Account             3/30/2017 7:54:36 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
2079674    1         testadmin       Disc   Local Console Logon         3/30/2017 8:03:38 PM  Negotiate             TEST2         Win12Chef.test2.lab
2079621    1         testadmin       Disc   Local Console Logon         3/30/2017 8:03:38 PM  Kerberos              TEST2         Win12Chef.test2.lab
3352388157           testadmin              Scheduled Task              4/26/2017 9:31:15 AM  Kerberos              TEST2         Win12Chef.test2.lab
3763671589           testadmin              Network (PSRemoting)        4/29/2017 2:17:07 PM  Kerberos              TEST2         Win12Chef.test2.lab
298214               testadmin              Scheduled Task              3/30/2017 7:56:15 PM  Kerberos              TEST2         Win12Chef.test2.lab
3732815451 2         testadminbackup Active RDP\TS\RemoteAssistance     4/29/2017 12:25:36 PM Negotiate             TEST2         Win12Chef.test2.lab
3732815380 2         testadminbackup Active RDP\TS\RemoteAssistance     4/29/2017 12:25:36 PM Kerberos              TEST2         Win12Chef.test2.lab
3915124898           testadminbackup        Network (PSRemoting)        4/30/2017 7:23:45 AM  Kerberos              TEST2         Win12Chef.test2.lab
3914946267           testadminbackup        Network (PSRemoting)        4/30/2017 7:22:07 AM  Kerberos              TEST2         Win12Chef.test2.lab
3915211378           testadminbackup        Network (PSRemoting)        4/30/2017 7:24:09 AM  Kerberos              TEST2         Win12Chef.test2.lab
105719               ANONYMOUS LOGON        Network (PSRemoting)        3/30/2017 7:55:13 PM  NTLM                  WIN12CHEF     Win12Chef.test2.lab
60737      2         DWM-1           Active Local Console Logon         3/30/2017 7:54:38 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
60719      2         DWM-1           Active Local Console Logon         3/30/2017 7:54:38 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
3732809931 2         DWM-2           Active Local Console Logon         4/29/2017 12:25:36 PM Negotiate             WIN12CHEF     Win12Chef.test2.lab
3732809905 2         DWM-2           Active Local Console Logon         4/29/2017 12:25:36 PM Negotiate             WIN12CHEF     Win12Chef.test2.lab
2299070    2         DWM-3           Active Local Console Logon         3/30/2017 8:05:24 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab
2299050    2         DWM-3           Active Local Console Logon         3/30/2017 8:05:24 PM  Negotiate             WIN12CHEF     Win12Chef.test2.lab

    Pros of Get-UserSessionViaCim include:
        - Lists all types of Logon Sessions from all User Accounts
        - Includes "LogonTypeTranslated" Property that illustrates LogonType in plain English
        - Includes "LogonId" and AuthenticationPackage" Properties
    Cons of Get-UserSessionViaCim include:
        - Results may contain stale entries (i.e. accounts may have since logged off or otherwise disconnected)
        - No way to tell if connection is still Active/Idle/Disconnected.


    By comparing Get-UserSessionViaQuery's "LogonTime" property to Get-UserSessionViaCim's "StartTime" property, we can match
    Cim results with Query results, and thereby add "SessionName", "State", and "Idle" properties to certain Cim results.

    WARNING: Get-UserSessionViaQuery's "LogonTime" property is never exactly equal to Get-UserSessionViaCim's "StartTime" property,
    so Get-UserSessionEx matches the entries as long as they are ***within 2 minutes*** of each other AND the Cim LogonType is
    one of the following:
        Local Console Logon
        Network (PSRemoting)
        RDP\TS\RemoteAssistance
        Local Console w/Cached Creds

.NOTES
    WARNING: Get-UserSessionViaQuery's "LogonTime" property is never exactly equal to Get-UserSessionViaCim's "StartTime" property,
    so Get-UserSessionEx matches the entries as long as they are ***within 2 minutes*** of each other AND the Cim LogonType is
    one of the following:
        Local Console Logon
        Network (PSRemoting)
        RDP\TS\RemoteAssistance
        Local Console w/Cached Creds

.PARAMETER HostName
    This parameter is DEFACTO REQUIRED, in that a default value of $env:ComputerName will be used should the function
    be ran without explicitly using this parameter.

    This parameter takes a string or array of strings that represent *DNS-Resolvable* Computer Names, or IP Addresses
    for which there are DNS reverse lookup entries.

.PARAMETER UserAcct
    This parameter is DEFACTO REQUIRED, in that a default value of the user account running PowerShell will be used
    should the function be ran without explicitly using this parameter.

    This parameter takes a string that represents a User Account with access to ALL of the Computer Names defined
    by the "HostName" parameter.

.PARAMETER Passwd
    This parameter is OPTIONAL. However, either the "Passwd" parameter or the "Credentials" parameter must be used.

    This parameter takes either a System.String or a System.Security.SecureString that represents the password for
    UserAcct.

.PARAMETER Credentials
    This parameter is OPTIONAL. However, either the "Credentials" parameter or the "Passwd" parameter must be used.

    This parameter takes a System.Management.Automation.PSCredential (must be composed of a User Account with access
    to ALL of the Computer Names defined by the "HostName" parameter)

.EXAMPLE
    From Domain Admin account on a workstation on the test2.lab Domain, run the following against Computers that
    are also all part of the test2.lab Domain:
        
        Get-UserSessionEx -HostName "Win16Chef","Win12WS.test2.lab","NanoServerVM.test2.lab"

    Sample Output:

    ComputerName           LogonSessions                                                                                                                           
    ------------           -------------                                                                                                                           
    Win16Chef.test2.lab    {@{Caption=; Name=; InstallDate=; UpdatedName=SYSTEM; StartTime=4/23/2017 1:05:48 AM; SessionId=0; LogonTypeTranslated=Local System; ...
    Win12WS.test2.lab      {@{Caption=; Name=; InstallDate=; UpdatedName=SYSTEM; StartTime=4/3/2017 9:30:32 PM; SessionId=0; LogonTypeTranslated=Local System; L...
    NanoServerVM.test2.lab {@{Caption=; Name=; InstallDate=; UpdatedName=SYSTEM; StartTime=4/28/2017 4:28:25 PM; SessionId=0; LogonTypeTranslated=Local System; ...

.EXAMPLE
    From a workstation on a *different* domain, run the following (where "pddomain" is a Domain Admin account on pddomain2.lab):

        Get-UserSessionEx -HostName "PDDC2.pddomain2.lab","PDDC2Rep.pddomain2.lab" -UserAcct pddomain

    Sample Output:

    ComputerName           LogonSessions                                                                                                                           
    ------------           -------------                                                                                                                           
    PDDC2.pddomain2.lab    {@{Caption=; Name=; IdleTime=; StartTime=2/24/2017 6:46:52 AM; InstallDate=; SessionName=; UpdatedName=SYSTEM; SessionId=; LogonTypeT...
    PDDC2Rep.pddomain2.lab {@{Caption=; Name=; IdleTime=; StartTime=3/28/2017 5:34:51 PM; InstallDate=; SessionName=; UpdatedName=SYSTEM; SessionId=; LogonTypeT...

.OUTPUTS
    Array of PSCustomObjects. Each object should have the properties "ComputerName" and "LogonSessions".
    
#>
function Get-UserSessionEx {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [string]$UserAcct = $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1]),
        
        [Parameter(Mandatory=$False)]
        $Passwd,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "The Get-UserSessionEx function must be Run as Administrator! Halting!"
        Write-Error "The Get-UserSessionEx function must be Run as Administrator! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    # TODO: Update all above helper functions to deal with SSL on port 5986
    for ($i=0; $i -lt $HostName.Count; $i++) {
        $Port5985OpenBool = $(Test-Port -RemoteMachine $HostName[$i] -RemotePort 5985).Open
        $Port5986OpenBool = $(Test-Port -RemoteMachine $HostName[$i] -RemotePort 5986).Open

        New-Variable -Name "Host$i" -Value $(
            [pscustomobject][ordered]@{
                ComputerName       = $HostName[$i]
                Port5985Open       = $Port5985OpenBool
                Port5986Open       = $Port5986OpenBool
            }
        )
    }

    if ($UserAcct -and $Passwd -and $Credentials) {
        Write-Verbose "Please use EITHER the Credentials parameter OR the UserAcct and Passwd parameters! Halting!"
        Write-Error "Please use EITHER the Credentials parameter OR the UserAcct and Passwd parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserAcct) {
        $UserNameFormatOne = $UserAcct | Select-String -Pattern "\\"
        $UserNameFormatTwo = $UserAcct | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $UserAcct = $UserAcct.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $UserAcct = $UserAcct.Split("@")[0]
        }
    }

    if ($Passwd) {
        if ($Passwd.GetType().FullName -eq "System.String") {
            $Passwd = ConvertTo-SecureString $Passwd -AsPlainText -Force
        }
    }

    $RemoteHostNetworkInfoArray = @()
    if (! $(Test-IsValidIPAddress -IPAddress $HostName[0])) {
        try {
            $RemoteHostIP = $(Resolve-DNSName $HostName[0]).IPAddress
        }
        catch {
            Write-Verbose "Unable to resolve $($HostName[0])!"
        }
        if ($RemoteHostIP) {
            # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
            $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
            # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
            if ($RemoteHostIP.Count -gt 1) {
                $RemoteHostIP = $RemoteHostIP[0]
            }
            $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
            $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
            $pos = $RemoteHostNameFQDN.IndexOf(".")
            $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
            $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
            $RemoteHostUserName = "$UserAcct@$RemoteHostNameFQDNPost"

            $RemoteHostNetworkInfoArray += $RemoteHostIP
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
        }
        if (!$RemoteHostIP) {
            Write-Error "Unable to resolve $($HostName[0])! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if (Test-IsValidIPAddress -IPAddress $HostName[0]) {
        try {
            $RemoteHostIP = $HostName[0]
            $RemoteHostName = $(Resolve-DNSName $RemoteHostIP).NameHost
            $RemoteHostNameFQDN = $($(Resolve-DNSName $RemoteHostName) | ? {$_.IPAddress -eq $RemoteHostIP}).Name
        }
        catch {
            Write-Verbose "Unable to resolve $HostName!"
        }
        if ($RemoteHostNameFQDN) {
            if ($($RemoteHostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                $pos = $RemoteHostNameFQDN.IndexOf(".")
                $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
            }
            else {
                $RemoteHostNameFQDNPre = $RemoteHostNameFQDN
                $RemoteHostNameFQDNPost = $RemoteHostNameFQDN
            }
            $RemoteHostUserName = "$UserAcct@$RemoteHostNameFQDNPost"

            $RemoteHostNetworkInfoArray += $RemoteHostIP
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
        }
        if (!$RemoteHostNameFQDN) {
            Write-Error "Unable to resolve $HostName! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($HostName -ne $env:COMPUTERNAME -and $HostName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $HostName.Count -gt 1) {
        if ($Credentials) {
            $FinalCreds = $Credentials
        }
        else {
            if (!$Passwd) {
                $Passwd = Read-Host -Prompt "Please enter the password for $UserAcct" -AsSecureString
            }
            # If $CompName[0] is on a different Domain, change $UserName to $RemoteHostUserName
            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                $UserAcct = $RemoteHostUserName
            }
            $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAcct, $Passwd
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($HostName -ne $env:COMPUTERNAME -and $HostName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $HostName.Count -gt 1) {
        $CimResults = Get-UserSessionViaCim -CompName $HostName -Credential $FinalCreds
    }
    else {
        $CimResults = Get-UserSessionViaCim -CompName $HostName
    }

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($HostName -ne $env:COMPUTERNAME -and $HostName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $HostName.Count -gt 1) {
        if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
            $UserNameFormatOne = $UserAcct | Select-String -Pattern "\\"
            $UserNameFormatTwo = $UserAcct | Select-String -Pattern "@"
            if ($UserNameFormatOne) {
                $UserAcct = $UserAcct.Split("\")[-1]
            }
            if ($UserNameFormatTwo) {
                $UserAcct = $UserAcct.Split("@")[0]
            }

            # Since query.exe needs an actual plain text UserName and Password, we need to grab it from
            # $FinalCreds if $Passwd isn't defined
            if ($Passwd) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passwd)
            }
            if (!$Passwd) {
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($FinalCreds.Password)
            }
            
            $PTPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $QueryResults = Get-UserSessionViaQuery -ComputerName $HostName -Uname $UserAcct -Pword $PTPwd
        }
        else {
            $QueryResults = Get-UserSessionViaQuery -ComputerName $HostName
        }
    }
    else {
        $QueryResults = Get-UserSessionViaQuery -ComputerName $HostName
    }

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $($HostName -ne $env:COMPUTERNAME -and $HostName -ne $(Resolve-DNSName $env:COMPUTERNAME).IPAddress) -or
    $HostName.Count -gt 1) {
        try {
            $WSManResults = Get-WsManServerInfo -RemoteComputer $HostName -RemoteCreds $FinalCreds -ErrorAction Stop
        }
        catch {
            Write-Verbose $_
        }
    }
    else {
        try {
            $WSManResults = Get-WsManServerInfo -RemoteComputer $HostName -ErrorAction Stop
        }
        catch {
            Write-Verbose $_
        }
    }


    foreach ($cimobj in $CimResults.LogonSessions) {
        if ($cimobj.LogonTypeTranslated -match "Local Console Logon|Network (PSRemoting)|RDP\\TS\\RemoteAssistance|Local Console w/Cached Creds") {
            foreach ($queryobj in $QueryResults) {
                if ($cimobj.StartTime -ne $null -and $queryobj.LogonTime -ne $null) {
                    if ($($($cimobj.StartTime - $queryobj.LogonTime).TotalMinutes -lt 2) -and
                    $($cimobj.UpdatedName -eq $queryobj.Username -or $cimobj.UpdatedName -like "DWM*")) {
                        $cimobj.Status = $queryobj.State
                        $cimobj.SessionName = $queryobj.SessionName
                        $cimobj.IdleTime = $queryobj.IdleTime
                        $cimobj.SessionId = $queryobj.SessionId
                    }
                }
            }
        }
    }

    # Add WSMan Info where possible
    foreach ($cimobj in $CimResults.LogonSessions) {
        if ($cimobj.LogonTypeTranslated -like "*PSRemoting*") {
            foreach ($wsmanResultObj in $WSManResults) {
                if ($cimobj.PSComputerName -eq $wsmanResultObj.WSManServer) {

                    $ActiveConnectionWSManInfo = foreach ($wsmanclientobj in $wsmanResultObj.WSManClientMapping) {
                        if ($wsmanclientobj.ActiveConnection -eq $true) {
                            if ($($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -lt 1 -and
                            $($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -gt -1) {
                                $wsmanclientobj
                            }
                        }
                    }

                    $InitialConnectionWSManInfo = foreach ($wsmanclientobj in $wsmanResultObj.WSManClientMapping) {
                        if ($wsmanclientobj.InitialConnection -eq $true) {
                            if ($($cimobj.UpdatedStartTime - $wsmanclientobj.ConnectionStartTime).TotalSeconds -lt 2 -and
                            $($cimobj.UpdatedStartTime - $wsmanclientobj.ConnectionStartTime).TotalSeconds -gt -2) {
                                $wsmanclientobj
                            }
                        }
                    }

                    $InitialConnectionLatestActivityWSManInfo = foreach ($wsmanclientobj in $wsmanResultObj.WSManClientMapping) {
                        if ($wsmanclientobj.InitialConnection -eq $true) {
                            if ($($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -lt 1 -and
                            $($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -gt -1) {
                                $wsmanclientobj
                            }
                        }
                    }

                    # Idle connections are DISCONNECTED from the WSManServer, but remain in a idle state on WSManClients
                    # As such, the below $IdleCOnnectionWSManInfo will NEVER return anything because we're comparing
                    # CimInstance info from the WSManServer ONLY
                    <#
                    $IdleConnectionWSManInfo = foreach ($wsmanclientobj in $wsmanResultObj.WSManClientMapping) {
                        if ($wsmanclientobj.ActiveConnection -eq $true -and $wsmanclientobj.InitialConnection -eq $false) {
                            if ($($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -lt 1 -and
                            $($cimobj.UpdatedStartTime - $wsmanclientobj.MostRecentConnectionActivity).TotalSeconds -gt -1) {
                                $wsmanclientobj
                            }
                        }
                    }
                    #>

                    if ($ActiveConnectionWSManInfo) {
                        $cimobj.Status = "Active"
                        $cimobj.RelevantWSManInfo = $ActiveConnectionWSManInfo
                    }
                    if ($InitialConnectionWSManInfo) {
                        $cimobj.Status = "Initial"
                        $cimobj.RelevantWSManInfo = $InitialConnectionWSManInfo
                    }
                    # The below "InitialCheck" status relates to TCP connections designated "Initial"
                    # These "InitialCheck" connection occur periodically over an open PSSession. It is NOT
                    # an indication of a user interactively using a PSSession. It is also NOT an indication
                    # of a PSSession being idle either. Still not sure exactly what triggers this activity.
                    if ($InitialConnectionLatestActivityWSManInfo) {
                        $cimobj.Status = "InitialCheck"
                        $cimobj.RelevantWSManInfo = $InitialConnectionLatestActivityWSManInfo
                    }
                    <#
                    if ($IdleConnectionWSManInfo) {
                        $cimobj.Status = "Idle"
                        $cimobj.RelevantWSManInfo = $IdleConnectionWSManInfo
                    }
                    #>
                }
            }
        }
    }

    if ($CimResults.LogOnSessions) {
        Write-Host "Get-UserSessionEx completed successfully"
    } 
    else {
        Write-Verbose "Unable to return User Session results for any Computers! Please check your Credentials! Halting!"
        Write-Error "Unable to return User Session results for any Computers! Please check your Credentials! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CimResults

    ##### END Main Body #####

}







# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSkJ3FWytLaTybmmcJPXNhPKM
# xs+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHTUmLR15fTdFcs6
# CU7PI4iI5OB6MA0GCSqGSIb3DQEBAQUABIIBAAqi5wMlet25LdL8MPuQrlB32GwA
# AXvtuDBj/bzJYadd8b4owyNtBGjHkp+DbiQRCEGQp4E8aE6FaBMf3bjC/8drV62X
# ZGMwxYcqE9aKpxuaA38Ky09UzHu1sfBsYHcyQOaDMAVyAxU4Ad900rBzwdskJhUe
# wank+bztDEBabz+JI7NT8l1w57ZXfFR+COdnuxjrtWwoXrZGS6Fbm0N7S/w+HVXr
# ApmbBhcneqPnp6vi+veuzUtgp6ZC5qfGAwH65Hh105YWKl9tcRfSkCvIAsPaqI9q
# oKjUNl4ARibBqs1IxlSD5PNPiDBIJY67Mvbx7Plw8tmdX8BsnugOMJbE+ew=
# SIG # End signature block
