function Join-NanoServerToDomain {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$DomainToJoin = $(Read-Host -Prompt "Please ener the name of the Domain you would like to to join. Example: test2.lab"),

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession, # Either use $PSession parameter OR $RemoteHostUser and #RemoteHostPwd params

        [Parameter(Mandatory=$True)]
        [string]$RemoteHost = $(Read-Host -Prompt "Please enter the name of the Remote Host that you would like to join to $DomainToJoin."),
        
        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUser, # Only needed if no PSSession. String should just be the username. Don't worry about domain info.

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$RemoteHostPwd # Only needed if no PSSession.

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($(Get-WmiObject Win32_ComputerSystem).Domain -ne $DomainToJoin) {
        Write-Verbose "The Join-RemoteHostToDomain function must be used from a machine that is already joined to $DomainToJoin! Halting!"
        Write-Error "The Join-RemoteHostToDomain function must be used from a machine that is already joined to $DomainToJoin! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($RemoteHostUser -or $RemoteHostPwd) -and $PSSession) {
        Write-Verbose "Please use *EITHER* the -PSSession parameter *OR* the -RemoteHostUser and -RemoteHostPwd parameters! Halting!"
        Write-Error "Please use *EITHER* the -PSSession parameter *OR* the -RemoteHostUser and -RemoteHostPwd parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($RemoteHostUser) {
        $UserNameFormatOne = $RemoteHostUser | Select-String -Pattern "\\"
        $UserNameFormatTwo = $RemoteHostUser | Select-String -Pattern "@"
        if ($UserNameFormatOne) {
            $RemoteHostUser = $RemoteHostUser.Split("\")[-1]
        }
        if ($UserNameFormatTwo) {
            $RemoteHostUser = $RemoteHostUser.Split("@")[0]
        }
    }

    $RemoteHostNetworkInfoArray = @()
    if (! $(Test-IsValidIPAddress -IPAddress $RemoteHost)) {
        try {
            $RemoteHostIP = $(Resolve-DNSName $RemoteHost).IPAddress
        }
        catch {
            Write-Verbose "Unable to resolve $gobal:RemoteHost!"
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
            $RemoteHostUserName = "$RemoteHostUser@$RemoteHostNameFQDNPost"

            $RemoteHostNetworkInfoArray += $RemoteHostIP
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
        }
        if (!$RemoteHostIP) {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if (Test-IsValidIPAddress -IPAddress $RemoteHost) {
        try {
            $RemoteHostIP = $RemoteHost
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
            $RemoteHostUserName = "$RemoteHostUser@$RemoteHostNameFQDNPost"

            $RemoteHostNetworkInfoArray += $RemoteHostIP
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
            $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
        }
        if (!$RemoteHostNameFQDN) {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If $RemoteHost is on a different Domain. change $RemoteHostUser to $RemoteHostUserName
    if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
        $RemoteHostUser = $RemoteHostUserName
    }

    if ($RemoteHostNameFQDNPre -match "[\w]") {
        $RemoteHost = $RemoteHostNameFQDNPre
    }

    if (!$(Get-Command djoin)) {
        Write-Verbose "The Win32 application djoin.exe is required, but it cannot be found! Please check your `$env:Path. Note that djoin.exe is usually found in C:\Windows\System32. Halting!"
        Write-Error "The Win32 application djoin.exe is required, but it cannot be found! Please check your `$env:Path. Note that djoin.exe is usually found in C:\Windows\System32. Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEIGIN Native Helper Functions #####

    function Send-Item {
        [CmdletBinding(PositionalBinding=$True)]
        Param(
            [Parameter(Mandatory=$True)]
            [string[]]$ItemPaths,

            [Parameter(Mandatory=$True)]
            [string]$Destination,
            
            [Parameter(Mandatory=$True)]
            [System.Management.Automation.Runspaces.PSSession]$Session,

            [Parameter(Mandatory=$False)]
            [switch]$DestinationIsAFile,

            [Parameter(Mandatory=$False)]
            [switch]$Silent
        )

        # $Destination must be a directory and NOT a file, so, if user passes a full path to a file with a file extension, or
        # the $DestinationIsAFile switch is used (in the event that the file does not have a file extension), then we reset the
        # variable to the file's parent directory
        $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
        $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'

        if ($Destination -match $RegexFilePath) {
            $Destination = $Destination | Split-Path -Parent
        }

        foreach ($p in $ItemPaths) {
            try {
                if ($([uri]$p).IsUnc) {
                    if (Test-Path -Path $p -PathType Container) {
                        Write-Verbose -Message "[$($p)] is a UNC path. Copying locally first"
                        $tmpDir = [IO.Path]::GetTempPath()
                        $pFolderName = $p | Split-Path -Leaf
                        Copy-Item -Path $p -Destination $tmpDir -Recurse
                        $p = "$tmpDir$pFolderName"
                    }
                    if (!$(Test-Path -Path $p -PathType Container)) {
                        Write-Verbose -Message "[$($p)] is a UNC path. Copying locally first"
                        $pFileName= $p | Split-Path -Leaf
                        $tmpFile = [IO.Path]::GetTempFileName()
                        Copy-Item -Path $p -Destination $tmpFile
                        $p = "$tmpFile$pFileName"
                    }
                }
                if (Test-Path -Path $p -PathType Container) {
                    $files = Get-ChildItem -Path $p -File -Recurse
                    foreach ($file in $Files) {
                        $FinalPath = $file.FullName
                        # Check for subdirectories
                        if ($file.DirectoryName -ne $p) {
                            $FinalDestination = $file.DirectoryName
                        }
                        else {
                            $FinalDestination = $Destination
                        }
                        $FinalSession = $Session

                        Send-Item -ItemPaths $FinalPath -Destination $FinalDestination -Session $FinalSession
                    }
                }
                else {
                    if ($Silent) {
                        Write-Verbose -Message "Starting WinRM copy of [$($p)] to [$($Destination)]"
                    }
                    if (!$Silent) {
                        Write-Host "Starting WinRM copy of [$($p)] to [$($Destination)]"
                    }
                    # Get the source file, and then get its contents
                    $sourceBytes = [System.IO.File]::ReadAllBytes($p);
                    $Length = $sourceBytes.Length
                    $streamChunks = @();
                    
                    # Now break it into chunks to stream.
                    $streamSize = 1MB;
                    for ($position = 0; $position -lt $sourceBytes.Length; $position += $streamSize) {
                        $remaining = $sourceBytes.Length - $position
                        $remaining = [Math]::Min($remaining, $streamSize)
                        
                        $nextChunk = New-Object byte[] $remaining
                        [Array]::Copy($sourcebytes, $position, $nextChunk, 0, $remaining)
                        $streamChunks +=, $nextChunk
                    }
                    $remoteScriptString = @"
        if (-not (Test-Path "$Destination" -PathType Container)) {
            `$null = New-Item "$Destination" -Type Directory -Force
        }
        `$fileDest = "$Destination\`$("$p" | Split-Path -Leaf)"
        ## Create a new array to hold the file content
        `$destBytes = New-Object byte[] $Length
        `$position = 0
        
        ## Go through the input, and fill in the new array of file content
        foreach (`$chunk in `$input)
        {
            [GC]::Collect()
            [Array]::Copy(`$chunk, 0, `$destBytes, `$position, `$chunk.Length)
            `$position += `$chunk.Length
        }
        
        [IO.File]::WriteAllBytes(`$fileDest, `$destBytes)
        
        # Get-Item `$fileDest
        [GC]::Collect()
"@
                    $remoteScript = [scriptblock]::Create($remoteScriptString)

                    # Stream the chunks into the remote script.
                    $streamChunks | Invoke-Command -Session $Session -ScriptBlock $remoteScript
                    if ($Silent) {
                        Write-Verbose -Message "WinRM copy of [$($p)] to [$($Destination)] complete"
                    }
                    if (!$Silent) {
                        Write-Host "WinRM copy of [$($p)] to [$($Destination)] complete"
                    }
                }
                # Cleanup
                if ($tmpDir) {
                    if (Test-Path "$tmpDir$pFolderName") {
                        Remove-Item "$tmpDir$pFolderName" -Recurse
                    }
                }
                if ($tmpFile) {
                    if (Test-Path "$tmpFile$pFileName") {
                        Remove-Item "$tmpFile$pFileName"
                    }
                }
            }
            catch
            {
                Write-Error $_.Exception.Message
            }
        }
    }


    <#
    .SYNOPSIS
        The Send-ItemToRemoteHost uploads one or more files or directories from the LocalHost to the RemoteHost, where
        the terms LocalHost and RemoteHost are context sensitive. In other words, LocalHost can bethought of as
        $env:COMPUTERNAME and RemoteHost can be thought of as a machine *other than* $env:COMPUTERNAME (precluding
        the unlikely circumstance in which $env:COMPUTERNAME is manually changed for some strange reason. That
        being said, the function is NOT dependent on the value of $env:COMPUTERNAME).

        This function was created to adjudicate Send-Item's and Copy-Item's undesirable default behavior, which is
        to OVERWRITE the item if it already exists on the Remote Host. This function checks for the existence of the
        the path(s) on the Remote Host and prompts you for confirmation if they already exist. You can override this behavior
        by using the -ForceSend parameter, which will automatically overwrite the item on the Remote Host without prompt.

    .DESCRIPTION
        See SYNOPSIS

    .PARAMETER ItemsToSendToRemoteHost
        MANDATORY

        This parameter takes an array fo strings that represent paths to file(s) or director(ies) on the Local Host (i.e.
        $env:COMPUTERNAME) that will be sent to the Remote Host.

        If any of the Local Items already exist Remotely under DestinationDirectory, the user will receive a prompt for
        confirmation and the Remote Items will be OVERWRITTEN. You can suppress the confirmation prompt with the ForceSend
        parameter.

        If any of the Local Items do not exist / cannot be found on the Local Host (i.e. $env:COMPUTERNAME), the
        function will halt and no action will be taken.

    .PARAMETER DestinationDirectory
        MANDATORY

        This parameter takes a string that represents a full path to a directory on the Remote Host that items sent to.

        If this directory does NOT exist on the Remote Host, the function will halt and no action will be taken.

    .PARAMETER PSSession
        OPTIONAL

        This parameter takes a System.Management.Automation.Runspaces.PSSession.

        Either this parameter or the RemoteHost and ((RemoteHostUser and RemoteHostPwd) or SICredentials) parameters are required.

    .PARAMETER RemoteHost
        OPTIONAL

        This parameter takes a string that represents a DNS-resolvable host name OR IP Address.

        This parameter is meant to be used with the (RemoteHostUser and RemoteHostPwd) or SICredentials parameters.

    .PARAMETER RemoteHostUser
        OPTIONAL

        This parameter takes a string that represents a UserName that has access to the RemoteHost. All UserName
        formats will work. For example, all of the following are valid:
            testadmin
            test2\testadmin
            testadmin@test2.lab

        This parmeter is meant to be used with the RemoteHost and RemoteHostPwd parameters.

    .PARAMETER RemoteHostPwd
        OPTIONAL

        This parameter takes EITHER a plain text String OR a Secure String that represents the password for RemoteHostUser.

        This parameter is meant to be used with the RemoteHost and RemoteHostUser parameters.

    .PARAMETER SICredentials
        OPTIONAL

        This parameter takes a System.Management.Automation.PSCredential object.

        This parameter is meant to be used with the RemoteHost parameter and should NOT be used with RemoteHostUser,
        RemoteHostPwd, or PSSession.

    .PARAMETER ForceSend
        OPTIONAL

        This parameter is a switch. If used, if there is potential for items within the DestinationDirectory to be overwritten,
        the user will NOT receive a confirmation prompt, and those items will be overwritten.

    .PARAMETER Silent
        OPTIONAL

        This parameter is a switch. If used, it will silence some STDOUT messages, such as notifications of which items
        were sent/received from Remote Host / by Local Host.

    .EXAMPLE
        $Items = @("C:\Users\testadmin\Documents\Spreadsheets","C:\Users\testadmin\Documents\invoice.pdf")
        
        Send-ItemToRemoteHost -PSSession $FileSharingSession -ItemsToSendToRemoteHost $Items -DestinationDirectory "C:\Users\zeroadmin\Documents"

    #>
    function Send-ItemToRemoteHost {
        [CmdletBinding(PositionalBinding=$True)]
        Param(
            [Parameter(
                Mandatory=$True,
                HelpMessage="Please enter an array of strings the represent full paths to file(s) or director(ies) you would like to send to the Remote Host."
            )]
            [string[]]$ItemsToSendToRemoteHost,

            [Parameter(Mandatory=$True)]
            [string]$DestinationDirectory,

            [Parameter(Mandatory=$False)]
            [System.Management.Automation.Runspaces.PSSession]$PSSession,

            [Parameter(Mandatory=$False)]
            [string]$RemoteHost,
            
            [Parameter(Mandatory=$False)]
            [string]$RemoteHostUser,

            [Parameter(Mandatory=$False)]
            [System.Security.SecureString]$RemoteHostPwd,

            [Parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$SICredentials,

            [Parameter(Mandatory=$False)]
            [switch]$ForceSend,

            [Parameter(Mandatory=$False)]
            [switch]$Silent
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        if ($SICredentials) {
            if ($RemoteHostUser -or $RemoteHostPwd) {
                Write-Verbose "Please use *either* the -SICredentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
                Write-Error "Please use *either* the -SICredentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
                $global:FunctionResult = "1"
                return
            }

            $RemoteHostUser = $Credentials.UserName
            $RemoteHostPwd = $Credentials.Password
        }

        if ($RemoteHostUser) {
            $UserNameFormatOne = $RemoteHostUser | Select-String -Pattern "\\"
            $UserNameFormatTwo = $RemoteHostUser | Select-String -Pattern "@"
            if ($UserNameFormatOne) {
                $RemoteHostUser = $RemoteHostUser.Split("\")[-1]
            }
            if ($UserNameFormatTwo) {
                $RemoteHostUser = $RemoteHostUser.Split("@")[0]
            }
        }

        if ($PSSession -and !$RemoteHost) {
            $RemoteHost = $PSSession.ComputerName
        }
        if ($PSSession -and !$RemoteHostUser) {
            $RemoteHostUser = $PSSession.Runspace.ConnectionInfo.Credential.UserName
        }
        if (!$PSSession -and !$RemoteHost) {
            $RemoteHost = Read-Host -Prompt "Please enter the name of the Remote Host that you would like to send items to"
        }
        if (!$PSSession -and !$RemoteHostUser) {
            $RemoteHostUser = Read-Host -Prompt "Please enter a UserName with access to $RemoteHost"
        }

        if ($PSSession -and $RemoteHostUser) {
            if ($PSSession.Runspace.ConnectionInfo.Credential.UserName -notmatch $RemoteHostUser) {
                Write-Verbose "The User Account used to establish the existing PSSession specified by the -PSSession parameter does NOT match $RemoteHostUser! Halting!"
                Write-Error "The User Account used to establish the existing PSSession specified by the -PSSession parameter does NOT match $RemoteHostUser! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($PSSession -and $RemoteHost) {
            if ($PSSession.ComputerName -notmatch $RemoteHost -and $RemoteHost -notmatch $PSSession.ComputerName) {
                Write-Verbose "The existing PSSession specified by the -PSSession parameter is NOT connected to $RemoteHost (it's connected to $($PSSession.ComputerName)! Halting!"
                Write-Error "The existing PSSession specified by the -PSSession parameter is NOT connected to $RemoteHost (it's connected to $($PSSession.ComputerName)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        
        $ItemsToSendToRemoteHost = foreach ($p in $ItemsToSendToRemoteHost) {
            try {
                $UpdatedPath = $(Resolve-Path -Path $p -ErrorAction SilentlyContinue).Path
            }
            catch {
                Write-Warning "Cannot find path $p. It will NOT be send to the Remote Host."
            }
            if ($UpdatedPath) {
                $UpdatedPath
            }
        }

        # Make sure item(s) exist on Local Host
        $ItemsCheckedOnLocalHost = @()
        foreach ($LocalItem in $ItemsToSendToRemoteHost) {
            if (! $(Test-Path $LocalItem)) {
                Write-Verbose "The path $LocalItem was not found on the $env:ComputerName! No files were sent to $RemoteHost. Halting!"
                Write-Error "The path $LocalItem was not found on the $env:ComputerName! No files were sent to $RemoteHost. Halting!"
                $global:FunctionResult = "1"
                return
            }

            $ItemsCheckedOnLocalHost +=, $(Get-Item $LocalItem)
        }

        if (!$PSSession) {
            $FileSharingSession = Get-PSSession | Where-Object {$_.Name -eq "FileSharingSession" -and $_.ComputerName -like "$RemoteHost*"}
            if ($FileSharingSession) {
                Write-Host "Reusing FileSharingSession Session for $RemoteHost!"
            }
            if (!$FileSharingSession) {
                # Create FileSharingSession if it doesn't already exist
                if (!$RemoteHostUser) {
                    $RemoteHostUser = Read-Host -Prompt "Please enter the UserName you would like to use to connect to $RemoteHost"

                    $UserNameFormatOne = $RemoteHostUser | Select-String -Pattern "\\"
                    $UserNameFormatTwo = $RemoteHostUser| Select-String -Pattern "@"
                    if ($UserNameFormatOne) {
                        $RemoteHostUser = $RemoteHostUser.Split("\")[-1]
                    }
                    if ($UserNameFormatTwo) {
                        $RemoteHostUser = $RemoteHostUser.Split("@")[0]
                    }
                }
                if (!$RemoteHostPwd) {
                    $RemoteHostPwd = Read-Host -Prompt "Please enter the password for $RemoteHostUser" -AsSecureString
                }

                $RemoteHostNetworkInfoArray = @()
                if (! $(Test-IsValidIPAddress -IPAddress $RemoteHost)) {
                    try {
                        $RemoteHostIP = $(Resolve-DNSName $RemoteHost).IPAddress
                    }
                    catch {
                        Write-Verbose "Unable to resolve $gobal:RemoteHost!"
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
                        $RemoteHostUserName = "$RemoteHostUser@$RemoteHostNameFQDNPost"

                        $RemoteHostNetworkInfoArray += $RemoteHostIP
                        $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                        $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                    }
                    if (!$RemoteHostIP) {
                        Write-Error "Unable to resolve $RemoteHost! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if (Test-IsValidIPAddress -IPAddress $RemoteHost) {
                    try {
                        $RemoteHostIP = $RemoteHost
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
                        $RemoteHostUserName = "$RemoteHostUser@$RemoteHostNameFQDNPost"

                        $RemoteHostNetworkInfoArray += $RemoteHostIP
                        $RemoteHostNetworkInfoArray += $RemoteHostNameFQDN
                        $RemoteHostNetworkInfoArray += $RemoteHostNameFQDNPre
                    }
                    if (!$RemoteHostNameFQDN) {
                        Write-Error "Unable to resolve $RemoteHost! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }

                # If $RemoteHost is on a different Domain. change $RemoteHostUser to $RemoteHostUserName format
                if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                    $RemoteHostUser = $RemoteHostUserName
                }

                # Set WinRM on LocalHost to Trust the ComputerName and IP Address of the RemoteHost
                # Check Local WinRM Config to make sure $RemoteHost is on the list of TrustedHosts
                if (Get-Elevation) {
                    $CurrentTrustedHosts = $(Get-ChildItem WSMan:\localhost\Client\TrustedHosts).Value
                    $UpdatedTrustedHostsArrayPrep = $CurrentTrustedHosts -split ", "
                    [System.Collections.ArrayList]$UpdatedTrustedHostsArray = $UpdatedTrustedHostsArrayPrep
                    $NeededUpdates = @()
                    foreach ($obj1 in $RemoteHostNetworkInfoArray) {
                        if ($UpdatedTrustedHostsArrayPrep -notcontains $obj1) {
                            $UpdatedTrustedHostsArray.Add("$obj1")
                            $NeededUpdates += $obj1
                        }
                    }
                    if ($NeededUpdates.Count -gt 0) {
                        $UpdatedTrustedHostsArray = $UpdatedTrustedHostsArray | % {if ($_ -match "[\w]") {$_}}
                        $UpdatedTrustedHostsArrayString = $UpdatedTrustedHostsArray -join ", "
                        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsArrayString
                        Remove-Variable -Name NeededUpdates -Force
                    }
                    else {
                        Write-Host "The current winrm config already trusts $RemoteHost. Continuing..."
                    }
                }
                else {
                    Write-Warning "No changes will be made to the winrm config. The winrm config can only be changed if PowerShell is launched as admin. Connection may still be possible. Continuing..." 
                }

                $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
                $FileSharingSession = New-PSSession $RemoteHost -Credential $RemoteHostCredential -Name FileSharingSession
            }
        }
        if ($PSSession) {
            Write-Host "Reusing $($PSSession.Name) Session for $RemoteHost!"
            $RemoteHostCredential = $PSSession.Runspace.ConnectionInfo.Credential
            $FileSharingSession = $PSSession
        }

        # Make sure the Destination Directory Exists on the Remote Host
        $DestinationDirectoryExists = Invoke-Command -Session $FileSharingSession -ScriptBlock {Test-Path $using:DestinationDirectory}
        if (!$DestinationDirectoryExists) {
            Write-Verbose "The path $DestinationDirectory does NOT exist on $RemoteHost! Halting!"
            Write-Error "The path $DestinationDirectory does NOT exist on $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Check to see if the files already exist on RemoteHost in the $DestinationDirectory
        $RemotePaths = @()
        foreach ($LocalItem in $ItemsCheckedOnLocalHost) {
            if ($LocalItem -is [System.IO.DirectoryInfo]) {
                if ($($DestinationDirectory | Split-Path -Leaf) -eq $($LocalItem.Name)) {
                    $DestinationPath = $DestinationDirectory
                }
                else {
                    $DestinationPath = "$DestinationDirectory\$($LocalItem.Name)"
                }
            }
            if ($LocalItem -isnot [System.IO.DirectoryInfo]) {
                $DestinationPath = "$DestinationDirectory\$($LocalItem.Name)"
            }
            $RemotePaths += $DestinationPath
        }
        
        $ItemsCheckedOnRemoteHost = Test-RemotePaths -PSSession $FileSharingSession -ItemsToCheckForOnRemoteHost $RemotePaths

        ##### END Variable/Parameter Transforms and PreRun Prep #####


        ##### BEGIN Main Body #####

        $ConfirmedSentItems = @()
        foreach ($LocalItem in $ItemsCheckedOnLocalHost) {
            if ($LocalItem -is [System.IO.DirectoryInfo]) {
                $MatchingRemoteItem = $ItemsCheckedOnRemoteHost | Where-Object {$_.BaseName -eq $LocalItem.BaseName}
                if ($MatchingRemoteItem.FoundOnRemoteHost -eq $False) {
                    if ($PSVersionTable.PSVersion.Major -ge 5) {
                        if ($($DestinationDirectory | Split-Path -Leaf) -eq $($LocalItem.Name)) {
                            $FinalDestination = $DestinationDirectory
                        }
                        else {
                            $FinalDestination = "$DestinationDirectory\$($LocalItem.Name)"
                        }

                        if (!$Silent) {
                            Write-Host "`nSending $($LocalItem.FullName) and its contents to $FinalDestination on $RemoteHost"
                        }
                        if ($Silent) {
                            Write-Verbose "`nSending $($LocalItem.FullName) to $FinalDestination on $RemoteHost"
                        }

                        Copy-Item -Recurse -Path $LocalItem -Destination $FinalDestination -ToSession $FileSharingSession

                        $ConfirmedSentItems += $LocalItem.FullName
                    }
                    else {
                        $FakeFinalDestination = "$DestinationDirectory\$($LocalItem.Name)"
                        if (!$Silent) {
                            Write-Host "`nSending $($LocalItem.FullName) and its contents to $FakeFinalDestination on $RemoteHost"
                        }
                        if ($Silent) {
                            Write-Verbose "`nSending $($LocalItem.FullName) to $FakeFinalDestination on $RemoteHost"
                        }
                        $ItemsToSend = Get-ChildItem -Recurse $LocalItem
                        foreach ($item in $ItemsToSend) {
                            $FinalDestinationTail = $($LocalItem.FullPath -split "$DestinationDirectory\\")[-1]
                            $FinalDestination = "$DestinationDirectory\$FinalDestinationTail"
                            Send-Item -ItemPaths $LocalItem.FullName -Destination $FinalDestination -Session $FileSharingSession
                        }

                        $ConfirmedSentItems += $LocalItem.FullName
                    }
                }
                if ($MatchingRemoteItem.FoundOnRemoteHost -eq $True) {
                    Write-Host "$($MatchingRemoteItem.FullName)"
                    if (!$ForceSend) {
                        Write-Warning "The item $($LocalItem.Name) already exists on the Remote Host $RemoteHost in $DestinationDirectory."
                        $ForceSendPrompt = Read-Host -Prompt "Are you sure you want to overwrite the directory $($MatchingRemoteItem.Name) on the $RemoteHost ? [Yes/No]"
                    }
                    if ($ForceSend -or $ForceSendPrompt -match "Yes|Y|yes|y") {
                        Invoke-Command -Session $FileSharingSession -ScriptBlock {Remove-Item -Recurse $using:MatchingRemoteItem.FullName -Force}
                        
                        if ($PSVersionTable.PSVersion.Major -ge 5) {
                            if ($($DestinationDirectory | Split-Path -Leaf) -eq $($LocalItem.Name)) {
                                $FinalDestination = $DestinationDirectory
                            }
                            else {
                                $FinalDestination = "$DestinationDirectory\$($LocalItem.Name)"
                            }
                            
                            if (!$Silent) {
                                Write-Host "`nSending $($LocalItem.FullName) and its contents to $FinalDestination on $RemoteHost"
                            }
                            if ($Silent) {
                                Write-Verbose "`nSending $($LocalItem.FullName) to $FinalDestination on $RemoteHost"
                            }
                            Copy-Item -Recurse -Path $LocalItem -Destination $FinalDestination -ToSession $FileSharingSession

                            $ConfirmedSentItems += $LocalItem.FullName
                        }
                        else {
                            $FakeFinalDestination = "$DestinationDirectory\$($LocalItem.Name)"
                            if (!$Silent) {
                                Write-Host "`nSending $($LocalItem.FullName) and its contents to $FakeFinalDestination on $RemoteHost"
                            }
                            if ($Silent) {
                                Write-Verbose "`nSending $($LocalItem.FullName) to $FakeFinalDestination on $RemoteHost"
                            }
                            $ItemsToSend = Get-ChildItem -Recurse $LocalItem
                            foreach ($item in $ItemsToSend) {
                                $FinalDestinationTail = $($LocalItem.FullPath -split "$DestinationDirectory\\")[-1]
                                $FinalDestination = "$DestinationDirectory\$FinalDestinationTail"
                                Send-Item -ItemPaths $LocalItem.FullName -Destination $FinalDestination -Session $FileSharingSession
                            }

                            $ConfirmedSentItems += $LocalItem.FullName
                        }
                    }
                }
            }
            if ($LocalItem -isnot [System.IO.DirectoryInfo]) {
                $FinalDestination = "$DestinationDirectory\$($LocalItem.Name)"
                $MatchingRemoteItem = $ItemsCheckedOnRemoteHost | Where-Object {$_.BaseName -eq $LocalItem.BaseName}
                if ($MatchingRemoteItem.FoundOnRemoteHost -eq $False) {
                    if (!$Silent) {
                        Write-Host "`nSending $($LocalItem.FullName) and its contents to $FinalDestination on $RemoteHost"
                    }
                    if ($Silent) {
                        Write-Verbose "`nSending $($LocalItem.FullName) to $FinalDestination on $RemoteHost"
                    }
                    if ($PSVersionTable.PSVersion.Major -ge 5) {
                        Copy-Item -Path $LocalItem -Destination $FinalDestination -ToSession $FileSharingSession
                    }
                    else {
                        Send-Item -ItemPaths $LocalItem.FullName -Destination $FinalDestination -Session $FileSharingSession
                    }

                    $ConfirmedSentItems += $LocalItem.FullName
                }
                if ($MatchingRemoteItem.FoundOnRemoteHost -eq $True) {
                    if (!$ForceSend) {
                        Write-Warning "The item $($LocalItem.name) already exists on the Remote Host $RemoteHost in $DestinationDirectory."
                        $ForceSendPrompt = Read-Host -Prompt "Are you sure you want to overwrite the file $($MatchingRemoteItem.Name) on the $RemoteHost ? [Yes/No]"
                    }
                    if ($ForceSend -or $ForceSendPrompt -match "Yes|Y|yes|y") {
                        if (!$Silent) {
                            Write-Host "`nSending $($LocalItem.FullName) to $FinalDestination on $RemoteHost"
                        }
                        if ($Silent) {
                            Write-Verbose "`nSending $($LocalItem.FullName) to $FinalDestination on $RemoteHost"
                        }
                        if ($PSVersionTable.PSVersion.Major -ge 5) {
                            Copy-Item -Path $LocalItem -Destination $FinalDestination -ToSession $FileSharingSession
                        }
                        else {
                            Send-Item -ItemPaths $LocalItem.FullName -Destination $FinalDestination -Session $FileSharingSession
                        }

                        $ConfirmedSentItems += $LocalItem.FullName
                    }
                }
            }
        }

        $ConfirmedSentItems

        ##### END Main Body #####
    }

    ##### END Native Helper Functions #####


    ##### BEGIN Main Body #####

    if ($PSSession) {
        $PSSessionComputerName = if ($($PSSession.ComputerName | Select-String -Pattern "\.").Matches.Success -eq $true) {
            $($PSSession.ComputerName -split "\.")[0]
        } else {
            $PSSession.ComputerName
        }
        if ($PSSessionComputerName -ne $RemoteHost) {
            Write-Verbose "The supplied PSSession $($PSSession.Name) is not connected to $RemoteHost! It is instead connected to $($PSSession.ComputerName) Halting!"
            Write-Error "The supplied PSSession $($PSSession.Name) is not connected to $RemoteHost! It is instead connected to $($PSSession.ComputerName) Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$PSSession) {
        if (!$RemoteHostUser) {
            $RemoteHostUser = Read-Host -Prompt "Please enter username for a Local Administrator on $RemoteHost"
        }
        if (!$RemoteHostPwd) {
            $RemoteHostPwd = Read-Host -Prompt "Please enter the password for $RemoteHostUser" -AsSecureString
        }

        $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
        try {
            $FileSharingSession = New-PSSession $RemoteHost -Credential $RemoteHostCredential -Name FileSharingSession
        }
        catch {
            Write-Verbose "$RemoteHost denied the WinRM connection. Please check your credentials and/or user authorization in $RemoteHost`'s WinRM config! Halting!"
        }
        if (!$FileSharingSession) {
            Write-Error "$RemoteHost denied the WinRM connection. Please check your credentials and/or user authorization in $RemoteHost`'s WinRM config! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $PSSession = $FileSharingSession
    }

    $tmpFile = [IO.Path]::GetTempFileName()
    $tmpFileNameOnly = Split-Path $tmpFile -Leaf
    try {
        $ProvisionTheComputerResult = Start-Process -FilePath "$($(Get-Command djoin).Source)" -ArgumentList "/provision /domain $DomainToJoin /machine $RemoteHost /savefile $tmpfile" -NoNewWindow -PassThru -Wait
        if ($ProvisionTheComputerResult.ExitCode -ne 0) {
            throw
        }
    } catch {
        Write-Warning "Unable to provision the computer using djoin.exe without the /REUSE parameter. Trying /REUSE parameter..."
    }
    if ($ProvisionTheComputerResult.ExitCode -ne 0) {
        try {
            $ProvisionTheComputerResult = Start-Process -FilePath "$($(Get-Command djoin).Source)" -ArgumentList "/provision /domain $DomainToJoin /machine $RemoteHost /savefile $tmpfile /REUSE" -NoNewWindow -PassThru -Wait
            if ($ProvisionTheComputerResult.ExitCode -ne 0) {
                throw
            }
        } catch {
            Write-Warning "Unable to provision the computer using djoin.exe with the /REUSE parameter! Halting!"
            Write-Error "Unable to provision the computer using djoin.exe with the /REUSE parameter! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    if ($ProvisionTheComputerResult.ExitCode -ne 0) {
        Write-Verbose "Unable to provision the computer using djoin.exe! Halting!"
        Write-Error "Unable to provision the computer using djoin.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Send-ItemToRemoteHost -RemoteHost $RemoteHost -PSSession $PSSession -ItemsToSendToRemoteHost $tmpfile -DestinationDirectory "C:" -Force

    # NOTE: Start-Process appatently doesn't work on PowerShell Core on Nano Server. Receive error: The member "Handlecount" is not present.
    <#
    $djoinProcessString = @"
        Start-Process -FilePath "$($(Get-Command djoin).Source)" -ArgumentList "/requestodj /loadfile C:\$tmpFile /windowspath C:\Windows /localos" -NoNewWindow -PassThru -Wait
    "@
    #>
    $djoinProcessString = "djoin /requestodj /loadfile C:\$tmpFileNameOnly /windowspath C:\Windows /localos"
    $djoinProcessScriptBlock = [scriptblock]::Create($djoinProcessString)
    Invoke-Command -Session $PSSession -ScriptBlock $djoinProcessScriptBlock
    $djoinRequestODJResult = Invoke-Command -Session $PSSession -ScriptBlock {$LASTEXITCODE}

    if ($djoinRequestODJResult -ne 0) {
        Write-Verbose "Failed to join $RemoteHost to $DomainToJoin! Halting!"
        Write-Error "Failed to join $RemoteHost to $DomainToJoin! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($djoinRequestODJResult -eq 0) {
        # NOTE: Start-Process apparently doesn't work on PowerShell Core on Nano Server. Receive error: The member "Handlecount" is not present.
        <#
        $RestartRemoteHostString = @"
            Start-Process -FilePath "$($(Get-Command shutdown).Source)" -ArgumentList "/r /t 5" -NoNewWindow -PassThru -Wait
        "@
        #>
        $RestartRemoteHostString = "shutdown /r /t 5"
        $RestartRemoteHostScriptBlock = [scriptblock]::Create($RestartRemoteHostString)
        Invoke-Command -Session $PSSession -ScriptBlock $RestartRemoteHostScriptBlock
        $RestartRemoteHostResult = Invoke-Command -Session $PSSession -ScriptBlock {$LASTEXITCODE}

        if ($RestartRemoteHostResult -ne 0) {
            Write-Warning "Failed to restart $RemoteHost after successfully joining it to $DomainToJoin! Please ensure $RemoteHost restarts!"
        }
        else {
            Write-Host "Successfully joined $RemoteHost to $DomainToJoin and restarted $RemoteHost"
        }
    }

    ##### END Main Body #####
}












# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUa/ncpOgXdML7SG6weTz9Ikpg
# NaygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBR00/xEG0MI
# gDI+brpuOT8TZHCI2zANBgkqhkiG9w0BAQEFAASCAQBcjTqW+DOS85lmLi0+5n2L
# kmZTUdTEU9QULs6xiv4xfCpfOCHgRRB2pSs/YpnKT8vACNMDhJ4qJKB6MYS9mE7r
# j1sPHCVFLjwRjytObmSDPWu0DGsHORG7hCzEGpDfYCRrFW3ERrKLPKr33K08+J0b
# IDYgcyyGyHnZeRiKUOquCijvcbz4yCg1ZKM8Qba3cU4hAzMdMSoBOlYjcCDu8kxD
# vXD6UNtzN6q9Nx3rC9yg7vsUOZWUsORcFXY5R6+K7UBKMF00ZwI7OvT0nasYaQm2
# 3jESTAEeARyfhBhz/e8snfQ0tWBQRZZvWOe+oyPB0Rej5jI/UfQMct4aVwJsr025
# SIG # End signature block
