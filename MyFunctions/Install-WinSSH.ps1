<#
.SYNOPSIS
    Install OpenSSH-Win64. Optionally install the latest PowerShell Core Beta. Optionally create new SSH Key Pair.

.DESCRIPTION
    See .SYNOPSIS

.PARAMETER RemoveHostPrivateKeys
    OPTIONAL

    This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
    sshd setup/config. Default is NOT to remove the host private keys.

.PARAMETER NewSSHKeyName
    OPTIONAL

    This parameter takes a string that represents the filename of the new SSH Key pair that you would like to create.
    This string is used in the filename of the private key file as well as the public key file (with the .pub extension).

.PARAMETER NewSSHKeyPwd
    OPTIONAL

    This parameter takes a string that represents the password used to protect the new SSH Private Key.

.PARAMETER NewSSHKeyPurpose
    OPTIONAL

    This parameter takes a string that represents the purpose of the new SSH Key Pair. It will be used in the
    "-C" (i.e. "comment") parameter of ssh-keygen.

.PARAMETER SetupPowerShell6
    OPTIONAL

    This parameter is a switch. Use it to install the latest PowerShell 6 Beta.

    IMPORTANT NOTE: PowerShell 6 Beta is installed *alongside* existing PowerShell version.

.EXAMPLE
    Install-WinSSH -NewSSHKeyName "testadmin-to-Debian8Jessie" -NewSSHKeyPurpose "testadmin-to-Debian8Jessie"

#>

function Install-WinSSH {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [switch]$SetupPowerShell6,

        [Parameter(Mandatory=$False)]
        [ValidateSet("alpha", "beta", "stable")]
        [string]$PowerShell6Channel = "beta"
     )

    ## BEGIN Native Helper Functions ##
    function Check-Elevation {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
            New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent());

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
            [System.Security.Principal.WindowsBuiltInRole]::Administrator;

        if($currentPrincipal.IsInRole($administratorsRole)){
            return $true;
        }
        else {
            return $false;
        }
    }

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

    function Unzip-File {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,Position=0)]
            [string]$PathToZip,
            
            [Parameter(Mandatory=$true,Position=1)]
            [string]$TargetDir,

            [Parameter(Mandatory=$false,Position=2)]
            [string[]]$SpecificItem
        )

        ##### BEGIN Native Helper Functions #####
        
        function Get-ZipChildItems {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$false,Position=0)]
                [string]$ZipFile = $(Read-Host -Prompt "Please enter the full path to the zip file")
            )

            $shellapp = new-object -com shell.application
            $zipFileComObj = $shellapp.Namespace($ZipFile)
            $i = $zipFileComObj.Items()
            Get-ZipChildItems_Recurse $i
        }

        function Get-ZipChildItems_Recurse {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,Position=0)]
                $items
            )

            foreach($si in $items) {
                if($si.getfolder -ne $null) {
                    # Loop through subfolders 
                    Get-ZipChildItems_Recurse $si.getfolder.items()
                }
                # Spit out the object
                $si
            }
        }

        ##### END Native Helper Functions #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (!$(Test-Path $PathToZip)) {
            Write-Verbose "The path $PathToZip was not found! Halting!"
            Write-Error "The path $PathToZip was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-ChildItem $PathToZip).Extension -ne ".zip") {
            Write-Verbose "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            Write-Error "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ZipFileNameWExt = $(Get-ChildItem $PathToZip).Name

        if ($SpecificItem) {
            foreach ($item in $SpecificItem) {
                if ($SpecificItem -match "\\") {
                    $SpecificItem = $SpecificItem -replace "\\","\\"
                }
            }
        }

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        if (!$SpecificItem) {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                Expand-Archive -Path $PathToZip -DestinationPath $TargetDir
            }
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                # Load System.IO.Compression.Filesystem 
                [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

                # Unzip file
                [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
            }
        }
        if ($SpecificItem) {
            $ZipSubItems = Get-ZipChildItems -ZipFile $PathToZip

            foreach ($searchitem in $SpecificItem) {
                [array]$potentialItems = foreach ($item in $ZipSubItems) {
                    if ($item.Path -match $searchitem) {
                        $item
                    }
                }

                $shell = new-object -com shell.application

                if ($potentialItems.Count -eq 1) {
                    $shell.Namespace($TargetDir).CopyHere($potentialItems[0], 0x14)
                }
                if ($potentialItems.Count -gt 1) {
                    Write-Warning "More than one item within $ZipFileNameWExt matches $searchitem."
                    Write-Host "Matches include the following:"
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        "$i) $($($potentialItems[$i]).Path)"
                    }
                    $Choice = Read-Host -Prompt "Please enter the number corresponding to the item you would like to extract [0..$($($potentialItems.Count)-1)]"
                    if ($(0..$($($potentialItems.Count)-1)) -notcontains $Choice) {
                        Write-Warning "The number indicated does is not a valid choice! Skipping $searchitem..."
                        continue
                    }
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        $shell.Namespace($TargetDir).CopyHere($potentialItems[$Choice], 0x14)
                    }
                }
                if ($potentialItems.Count -lt 1) {
                    Write-Warning "No items within $ZipFileNameWExt match $searchitem! Skipping..."
                    continue
                }
            }
        }

        ##### END Main Body #####
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Load and Run Update-PackageManagement function
    <#
    $UpdatePMString = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/Update-PackageManagement.ps1"
    $UpdatePMScriptBlock = [scriptblock]::Create($UpdatePMString.Content)
    . $UpdatePMScriptBlock
    Update-PackageManagement
    #>

    if ($SetupPowerShell6) {
        $PowerShell6Path = $(Resolve-Path "$env:ProgramFiles\PowerShell\6*\powershell.exe").Path
        $WindowsOSVersion = [version]$(Get-CimInstance -ClassName Win32_OperatingSystem).Version
        if ($WindowsOSVersion.Major -ge 10) {
            $WinVer = "win10"
        }
        if ($WindowsOSVersion.Major -eq 6 -and $WindowsOSVersion.Minor -eq 3) {
            $WinVer = "win81"
        }
        if (!$WinVer) {
            Write-Verbose "Unable to find installer for Windows Version $($WindowsOSVersion.ToString())! Halting!"
            Write-Error "Unable to find installer for Windows Version $($WindowsOSVersion.ToString())! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if (!$(Test-Path $PowerShell6Path)) {
            $LatestPowerShellCoreVersionPrep = Invoke-WebRequest -Uri "https://github.com/powershell/powershell/releases"
            $LatestPowerShellCoreVersionhref = $($LatestPowerShellCoreVersionPrep.Links | Where-Object {$_.href -like "*$PowerShell6Channel*$WinVer*x64.msi"})[0].href
            $LatestPowerShellCoreVersionURL = "https://github.com/powershell/powershell/releases" + $LatestPowerShellCoreVersionhref
            $DownloadPath = "$HOME\Downloads\$($LatestPowerShellCoreVersionURL | Split-Path -Leaf)"

            Invoke-WebRequest -Uri $LatestPowerShellCoreVersionURL -OutFile $DownloadPath

            $DataStamp = Get-Date -Format yyyyMMddTHHmmss
            $MSIFullPath = $DownloadPath
            $MSIParentDir = $MSIFullPath | Split-Path -Parent
            $MSIFileName = $MSIFullPath | Split-Path -Leaf
            $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
            $logFile = "$MSIParentDir\$MSIFileNameOnly$DataStamp.log"
            $MSIArguments = @(
                "/i"
                $MSIFullPath
                "/qn"
                "/norestart"
                "/L*v"
                $logFile
            )
            # Install PowerShell Core 6
            Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # There's something wrong with the 0.0.16.0 OpenSSH-Win64 Chocolatey Package...
    #if (!$(Get-Package -Name OpenSSH -ErrorAction SilentlyContinue)) {
    if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64")) {
        try {
            # There's something wrong with the 0.0.16.0 OpenSSH-Win64 Chocolatey Package...
            <#
            Install-Package -Name OpenSSH
            if (!$?) {
                throw
            }
            #>
            $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
            $request = [System.Net.WebRequest]::Create($url)
            $request.AllowAutoRedirect = $false
            $response = $request.GetResponse()
            $Win64OpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/OpenSSH-Win64.zip'
            Invoke-WebRequest -Uri $Win64OpenSSHDLLink -OutFile "$HOME\Downloads\OpenSSH-Win64.zip"

            # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
            Unzip-File -PathToZip "$HOME\Downloads\OpenSSH-Win64.zip" -TargetDir "$HOME\Downloads"
            Move-Item "$HOME\Downloads\OpenSSH-Win64" "$env:ProgramFiles\OpenSSH-Win64"
            Enable-NTFSAccessInheritance -Path "$env:ProgramFiles\OpenSSH-Win64" -RemoveExplicitAccessRules
            $OpenSSHWin64Path = "$env:ProgramFiles\OpenSSH-Win64"
            $env:Path = "$OpenSSHWin64Path;$env:Path"
        }
        catch {
            Write-Error $Error[0]
            Write-Error "Installation of OpenSSH failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # NOTE: Installing OpenSSH in the above manner should add all of the ssh utilities to environment PATH
    # ssh Utilities could come from Git or From previously installed Windows OpenSSH. We want to make sure we use Windows OpenSSH
    $PotentialSSHUtilitiesSource = $(Get-Command ssh -All).Source
    $FinalSSHUtilitySourceDir = foreach ($FilePath in $PotentialSSHUtilitiesSource) {
        if ([Environment]::Is64BitProcess) {
            if ($FilePath -like "*OpenSSH-Win64*") {
                $FilePath | Split-Path -Parent
            }
        }
        else {
            if ($FilePath -like "*OpenSSH-Win32*") {
                $FilePath | Split-Path -Parent
            }
        }
    }
    if ([Environment]::Is64BitProcess) {
        $Potential64ArchLocationRegex = $FinalSSHUtilitySourceDir -replace "\\","\\"
        $CheckPath = $env:Path -match $Potential64ArchLocationRegex
        if ($CheckPath) {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $($env:Path -replace "$Potential64ArchLocationRegex","")
        }
        else {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $env:Path
        }
    }
    else {
        $Potential32ArchLocationRegex = $($($FinalSSHUtilitySourceDir -replace "\\","\\") -replace "\(","(") -replace "\)",")"
        $CheckPath = $env:Path -match $Potential32ArchLocationRegex
        if ($CheckPath) {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $($env:Path -replace "$Potential32ArchLocationRegex","")
        }
        else {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $env:Path
        }
    }

    $sshdConfigPath = "$FinalSSHUtilitySourceDir\sshd_config"

    # Add a line for PowerShell under Subsystems in sshd_config
    $sshdContent = Get-Content $sshdConfigPath
    $LineToReplace = $sshdContent | Where-Object {$_ -like "*sftp-server.exe*"}
    $UpdatedsshdContent = $sshdContent -replace "$LineToReplace","$LineToReplace`nSubsystem   powershell C:/Program Files/PowerShell/6.0.0-beta.3/powershell.exe $PowerShell6Path -sshs -NoLogo -NoProfile"
    Set-Content -Value $UpdatedsshdContent -Path $sshdConfigPath

    if (Test-Path "$FinalSSHUtilitySourceDir\install-sshd.ps1") {
        & "$FinalSSHUtilitySourceDir\install-sshd.ps1"
    }
    else {
        Write-Warning "The SSHD Service still needs to be configured!"
    }

    # Make sure port 22 is open
    if (!$(Test-Port -Port 22).Open) {
        # See if there's an existing rule regarding locahost TCP port 22
        $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
        if ($Existing22RuleCheck -ne $null) {
            $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
            if ($Existing22Rule -ne $null) {
                Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
            }
            else {
                $ExistingRuleFound = $False
            }
        }
        if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
            New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
        }
    }

    # Setup Host Keys
    Push-Location $FinalSSHUtilitySourceDir

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "ssh-keygen.exe"
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.WorkingDirectory = $pwd.Path
    $ProcessInfo.Arguments = "-A"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $AllOutput = $stdout + $stderr
    
    $PubPrivKeyPairFiles = Get-ChildItem -Path "$FinalSSHUtilitySourceDir" | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -like "*ssh_host*"}
    $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKeys = $PubPrivKeyPairFiles | foreach {if ($PubKeys -notcontains $_) {$_}}
    
    Start-Service ssh-agent

    Start-Sleep -Seconds 5

    if ($(Get-Service "ssh-agent").Status -ne "Running") {
        Write-Verbose "The ssh-agent service did not start succesfully! Halting!"
        Write-Error "The ssh-agent service did not start succesfully! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    foreach ($PrivKey in $PrivKeys) {
        ssh-add.exe $PrivKey.FullName

        if ($RemoveHostPrivateKeys) {
            Remove-Item $PrivKey
        }
    }

    Pop-Location

    Set-Service sshd -StartupType Automatic
    Set-Service ssh-agent -StartupType Automatic

    # IMPORTANT: It is important that File Permissions are "Fixed" at the end, otherwise previous steps break
    & "$FinalSSHUtilitySourceDir\FixHostFilePermissions.ps1" -Confirm:$false

    Start-Service sshd

    Start-Sleep -Seconds 5

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Verbose "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
        Write-Error "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($NewSSHKeyName) {
        # Create new public/private keypair
        if (!$(Test-Path "$HOME\.ssh")) {
            New-Item -Type Directory -Path "$HOME\.ssh"
        }

        if ($NewSSHKeyPwd) {
            ssh-keygen.exe -t rsa -b 2048 -f "$HOME\.ssh\$NewSSHKeyName" -q -N "$NewSSHKeyPwd" -C "$NewSSHKeyPurpose"
        }
        else {
             # Need PowerShell Await Module (Windows version of Linux Expect) for ssh-keygen with null password
            if ($(Get-Module -ListAvailable).Name -notcontains "Await") {
                # Install-Module "Await" -Scope CurrentUser
                # Clone PoshAwait repo to .zip
                Invoke-WebRequest -Uri "https://github.com/pldmgg/PoshAwait/archive/master.zip" -OutFile "$HOME\PoshAwait.zip"
                $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                [IO.Directory]::CreateDirectory($tempDirectory)
                Unzip-File -PathToZip "$HOME\PoshAwait.zip" -TargetDir "$tempDirectory"
                if (!$(Test-Path "$HOME\Documents\WindowsPowerShell\Modules\Await")) {
                    New-Item -Type Directory "$HOME\Documents\WindowsPowerShell\Modules\Await"
                }
                Copy-Item -Recurse -Path "$tempDirectory\PoshAwait-master\*" -Destination "$HOME\Documents\WindowsPowerShell\Modules\Await"
                Remove-Item -Recurse -Path $tempDirectory -Force
            }

            # Make private key password $null
            Import-Module Await
            if (!$?) {
                Write-Verbose "Unable to load the Await Module! Halting!"
                Write-Error "Unable to load the Await Module! Halting!"
                $global:FunctionResult = "1"
                return
            }

            Start-AwaitSession
            Start-Sleep -Seconds 1
            Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            Send-AwaitCommand "ssh-keygen.exe -t rsa -b 2048 -f `"$HOME\.ssh\$NewSSHKeyName`" -C `"$NewSSHKeyPurpose`""
            Start-Sleep -Seconds 2
            Send-AwaitCommand ""
            Start-Sleep -Seconds 2
            Send-AwaitCommand ""
            Start-Sleep -Seconds 1
            $SSHKeyGenConsoleOutput = Receive-AwaitResponse
            Write-hOst ""
            Write-Host "##### BEGIN ssh-keygen Console Output From PSAwaitSession #####"
            Write-Host "$SSHKeyGenConsoleOutput"
            Write-Host "##### END ssh-keygen Console Output From PSAwaitSession #####"
            Write-Host ""
            # If Stop-AwaitSession errors for any reason, it doesn't return control, so we need to handle in try/catch block
            try {
                Stop-AwaitSession
            }
            catch {
                if ($PSAwaitProcess.Id -eq $PID) {
                    Write-Verbose "The PSAwaitSession never spawned! Halting!"
                    Write-Error "The PSAwaitSession never spawned! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Stop-Process -Id $PSAwaitProcess.Id
                }
            }
        }

        if (!$(Test-Path "$HOME\.ssh\$NewSSHKeyName")) {
            Write-Verbose "The New SSH Key Pair was NOT created! Halting!"
            Write-Error "The New SSH Key Pair was NOT created! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Add the New Private Key to the ssh-agent
        ssh-add.exe "$HOME\.ssh\$NewSSHKeyName"

        Write-Host "Add the following RSA Public Key to ~/.ssh/authorized_keys on your linux host"
        Write-Host "$(Get-Content $HOME\.ssh\$NewSSHKeyName.pub)"
    }

    ##### END Main Body #####

}








# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUg6IU8ku2nMAT5dwKhTY9AGAs
# M/+gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRAM7st+j7A
# MkbmVcANpqK3ZEdBfjANBgkqhkiG9w0BAQEFAASCAQB7okClU2zH4s0Y3NpB2RsH
# QOXF1OBxskO+wYVmT/ohLUEnlcNVmbqhWEXzEw80wa41gbOH5ODzNNhWS14KN3YJ
# yt3bIGS5NF3mPYCaPKM7DHYe43QtAnYVUpDbBiRGfHMbiwaUhIVCkq+GXW9UaSdb
# qhFoalvuhpHioC/ZxE1tGQzNhRlaC1OcfSLL3uQGozS80RckfDVDurKlNnYvlvme
# JoCJraN6Wt5nMil+Sh3hsAVPEd+Ms7501+l7lstBkL/DxHjGDCo1YgrHWrcd0LEd
# 0FqXKuA4t0CgfWNh5vG3iRwi+pnvq/L6ULbuqUWGAG/43J0TIm2EA8Ic+4SeNj9A
# SIG # End signature block
