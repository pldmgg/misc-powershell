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
                if (Check-Elevation) {
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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMpaRxkyYgGkeSI+3pUOf/ecN
# 5g6gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFE2JCiYa8XM7jYMl
# FX09KjGpNeaYMA0GCSqGSIb3DQEBAQUABIIBAFlV7G91zEmVcM4EhIlAe0aH3dK7
# gCkZZ1YXHScSLxjWmdQSK+3seuQ8hmnmoNueqwWahleN93iMQT+y0PY1s2lln//j
# hvmAQmi6iJnbQXtxs3qk71K87whAR+TuJkA6I9C7rq5SsRUszXLsgGQVYXYejNCp
# 2MCNTGRmQr+sqaw5p8waEeaQ3CFKwtzevxZhe7dGtC1f2PpUDymRhTkcvGr/Y/pf
# ZijZacBpY/b5Pkx0YlRRaTulU/0uYMdp6w4ZfRz6SA9x+vfXaC2lLMb8FVzldqCY
# DYAMD/WyXgxxTJmb57X+kerx9+OQ9nRM4bNow59Ke8VgmaSeKN70qDK4ELs=
# SIG # End signature block
