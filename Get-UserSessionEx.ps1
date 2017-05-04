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
3763671589           testadmin              Network (PSRemoting or RDP) 4/29/2017 2:17:07 PM  Kerberos              TEST2         Win12Chef.test2.lab
298214               testadmin              Scheduled Task              3/30/2017 7:56:15 PM  Kerberos              TEST2         Win12Chef.test2.lab
3732815451 2         testadminbackup Active RDP\TS\RemoteAssistance     4/29/2017 12:25:36 PM Negotiate             TEST2         Win12Chef.test2.lab
3732815380 2         testadminbackup Active RDP\TS\RemoteAssistance     4/29/2017 12:25:36 PM Kerberos              TEST2         Win12Chef.test2.lab
3915124898           testadminbackup        Network (PSRemoting or RDP) 4/30/2017 7:23:45 AM  Kerberos              TEST2         Win12Chef.test2.lab
3914946267           testadminbackup        Network (PSRemoting or RDP) 4/30/2017 7:22:07 AM  Kerberos              TEST2         Win12Chef.test2.lab
3915211378           testadminbackup        Network (PSRemoting or RDP) 4/30/2017 7:24:09 AM  Kerberos              TEST2         Win12Chef.test2.lab
105719               ANONYMOUS LOGON        Network (PSRemoting or RDP) 3/30/2017 7:55:13 PM  NTLM                  WIN12CHEF     Win12Chef.test2.lab
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
        Network (PSRemoting or RDP)
        RDP\TS\RemoteAssistance
        Local Console w/Cached Creds

.NOTES
    WARNING: Get-UserSessionViaQuery's "LogonTime" property is never exactly equal to Get-UserSessionViaCim's "StartTime" property,
    so Get-UserSessionEx matches the entries as long as they are ***within 2 minutes*** of each other AND the Cim LogonType is
    one of the following:
        Local Console Logon
        Network (PSRemoting or RDP)
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

    function Get-Elevation {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
             [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )

       [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

       if($currentPrincipal.IsInRole($administratorsRole)) {
          return $true;
       }
       else {
          return $false;
       }
    }

    if (!$(Get-Elevation)) {
        Write-Verbose "The Get-UserSessionEx function must be Run as Administrator! Halting!"
        Write-Error "The Get-UserSessionEx function must be Run as Administrator! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ## BEGIN Native Helper Functions ##

    Function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
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
                    $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
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
                    $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
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
            [System.Management.Automation.PSCredential]$Creds
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
                        New-Object PSObject -Property @{
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
	        [System.Management.Automation.PSCredential]$Credential
	    )

	    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if ($($UserName -or $Password) -and $Credential) {
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

        $RemoteHostNetworkInfoArray = @()
        if (! $(Test-IsValidIPAddress -IPAddress $CompName[0])) {
            try {
                $RemoteHostIP = $(Resolve-DNSName $CompName[0]).IPAddress
            }
            catch {
                Write-Verbose "Unable to resolve $($CompName[0])!"
            }
            if ($RemoteHostIP) {
                # Filter out any non IPV4 IP Addresses that are in $RemoteHostIP
                $RemoteHostIP = $RemoteHostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                # If there is still more than one IPAddress string in $RemoteHostIP, just select the first one
                if ($RemoteHostIP.Count -gt 1) {
                    $RemoteHostIP = $RemoteHostIP[0]
                }
                $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
                $pos = $RemoteHostNameFQDN.IndexOf(".")
                $RemoteHostNameFQDNPre = $RemoteHostNameFQDN.Substring(0, $pos)
                $RemoteHostNameFQDNPost = $RemoteHostNameFQDN.Substring($pos+1)
                $RemoteHostUserName = "$UserName@$RemoteHostNameFQDNPost"

                $RemoteHostNetworkInfoArray += $RemoteHostIP
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
            }
            if (!$RemoteHostIP) {
                Write-Error "Unable to resolve $($CompName[0])! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-IsValidIPAddress -IPAddress $CompName[0]) {
            try {
                $RemoteHostIP = $CompName[0]
                $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
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
                Write-Error "Unable to resolve $($CompName[0])! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
        $HostName.Count -gt 1 -or $HostName -ne $env:COMPUTERNAME) {
            if (!Password) {
                $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
            }
            # If $CompName[0] is on a different Domain, change $UserName to $RemoteHostUserName
            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                $UserName = $RemoteHostUserName
            }

            if ($Credential) {
                $FinalCreds = $Credential
            }
            else {
                $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
            }
        }

	    $LogonTypeTranslated = @{
	        "0" = "Local System"
	        "2" = "Local Console Logon" #(Interactive)
	        "3" = "Network (PSRemoting or RDP)" # (MSDN says 3 explicitly does NOT cover RDP, but testing proves otherwise)
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
	    $defaultDisplaySet = "LogonId","SessionId","SessionName","UpdatedName","Status","IdleTime","LogonTypeTranslated","StartTime","AuthenticationPackage","UpdatedDomain"
	    # Create the default property display set
	    #$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
	    Update-TypeData -TypeName Logon.Info -DefaultDisplayPropertySet $defaultDisplaySet -ErrorAction SilentlyContinue
	    #$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

	    $UserSessionInfoObjArray = @()
	    foreach ($Comp in $CompName) {
            if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
            $HostName.Count -gt 1 -or $HostName -ne $env:COMPUTERNAME) {
	           $CimSessionObj = Get-LHSCimSession -ComputerName $Comp -Creds $FinalCreds
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
	            New-Object PSObject -Property @{
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

    ##### END Native Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if ($($UserAcct -or $Passwd) -and $Credentials) {
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
            $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
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
            $RemoteHostNameFQDN = $(Resolve-DNSName $RemoteHostIP).NameHost
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
    $HostName.Count -gt 1 -or $HostName -ne $env:COMPUTERNAME) {
        if (!Passwd) {
            $Passwd = Read-Host -Prompt "Please enter the password for $UserAcct" -AsSecureString
        }
        # If $CompName[0] is on a different Domain, change $UserName to $RemoteHostUserName
        if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
            $UserAcct = $RemoteHostUserName
        }

        if ($Credential) {
            $FinalCreds = $Credentials
        }
        else {
            $FinalCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserAcct, $Passwd
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $HostName.Count -gt 1 -or $HostName -ne $env:COMPUTERNAME) {
        $CimResults = Get-UserSessionViaCim -CompName $HostName -Credential $FinalCreds
    }
    else {
        $CimResults = Get-UserSessionViaCim -CompName $HostName
    }

    if ($UserAcct -ne $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1] -or
    $HostName.Count -gt 1 -or $HostName -ne $env:COMPUTERNAME) {
        if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
            $UserNameFormatOne = $UserAcct | Select-String -Pattern "\\"
            $UserNameFormatTwo = $UserAcct | Select-String -Pattern "@"
            if ($UserNameFormatOne) {
                $UserAcct = $UserAcct.Split("\")[-1]
            }
            if ($UserNameFormatTwo) {
                $UserAcct = $UserAcct.Split("@")[0]
            }

            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Passwd)
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

    foreach ($cimobj in $CimResults.LogonSessions) {
        if ($cimobj.LogonTypeTranslated -match "Local Console Logon|Network (PSRemoting or RDP)|RDP\\TS\\RemoteAssistance|Local Console w/Cached Creds") {
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

    $CimResults

    if ($CimResults) {
        Write-Host "Get-UserSessionEx completed successfully"
    } 
    else {
        Write-Verbose "Unable to return User Session results for any Computers! Please check your Credentials! Halting!"
        Write-Error "Unable to return User Session results for any Computers! Please check your Credentials! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Main Body #####

}






# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIy2HH+mXw5+kaQD+HMtiykya
# 0+qgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQ/BFwpMFQ9
# 5XqRdBZ1PrJoUnL+rjANBgkqhkiG9w0BAQEFAASCAQBTUS1p8MUIa+VCmbzQaKYz
# H4fMV79FVWKF1wVGEfJvALpKPap5vP51A3IOhVey76eBVrZgWGAi+OxTf0sgEeBs
# TiQzoxFwIgxjnMymUxvrCSQB/GOmyX39PTdA3Lvd67hx39yDk/fs/NwaZQBoXouY
# M4bjBPvf3cHq85NP/eSm29DxAUqkXXe7hFTm3LRxCSGNKhwIB3NVw6lJLLVGW5/5
# cTWpLSL6vy5JmTMfRZXfXC+b54JDsZA28T8OaI/JPJ6B8IGGo0fJUx09SKUfX4mY
# jXPnTyDvWW9es5L70HmJbtBy9XeKKob1ZCNDglg66nzFnccln4l3MwEHl8C1aniK
# SIG # End signature block
