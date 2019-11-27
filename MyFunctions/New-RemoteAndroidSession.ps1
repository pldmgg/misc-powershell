<#
    .SYNOPSIS
        This function starts a **fully controllable** **graphical** remote session with an android device
        on the same network.

        If your Android device *is* rooted, install the app 'ADB Wireless (root)' and launch it. Then, this
        function will successfully connect

        If your Android device *is not* rooted, install the app 'ADB Wireless (no root)', launch it, and
        follow the instructions in the app. Then, this function will work.

        This function currently only works on Windows 10.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES
        If you receive an error like...
        
            ERROR: "adb push" returned with value 1
            Press any key to continue...
        
        ...then temporarily connect your android device to your Windows machine via USB, select the appropriate
        prompts on your Android device to have it trust your Windows machine, and then from Windows, run...
        
            C:\Users\zeroadmin\Downloads\scrcpy-win64-v1.11> .\adb tcpip 5555
        
        ...then feel free to disconnect the USB cable and use this function as normal.

    .PARAMETER IPOfAndroidDevice
        This parameter is MANDATORY.

        This parameter takes a string that represents the IP Address of the Android Device.

    .PARAMETER ScrcpyPort
        This parameter is OPTIONAL, but it has a default value of '5555'

        This parameter takes a string that represents the Port Number that adbd is allowing TCPIP connections on.

    .PARAMETER PathToScrcpyBinaries
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to the directory that contains scrcpy.exe
        and adb.exe.

        This parameter should *not* be used with the -DownloadLatestScrcpy switch.

    .PARAMETER DownloadLatestScrcpy
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will download the latest win64 scrcpy binaries to
        $HOME\Downloads\$ZipFileNameWithoutExtension and unzip them there.

        This parameter should *not* be used with the PathToScrcpyBinaries parameter.

    .EXAMPLE
        # If you already have adb.exe and scrcpy.exe in a directory on your machine...

        PS C:\Users\zeroadmin> New-RemoteAndroidSession -IPOfAndroidDevice "192.168.2.3" -PathToScrcpyBinaries "$HOME\Downloads\scrcpy-win64-v1.11"

    .EXAMPLE
        # If you already have adb.exe and scrcpy.exe in a directory on your machine and that directory is already
        # part of your $env:PATH

        PS C:\Users\zeroadmin> New-RemoteAndroidSession -IPOfAndroidDevice "192.168.2.3"
    
    .EXAMPLE
        # If you **do not** have adb.exe and scrcpy.exe in a directory on your machine...

        PS C:\Users\zeroadmin> New-RemoteAndroidSession -IPOfAndroidDevice "192.168.2.3" -DownloadLatestScrcpy
        
#>
function New-RemoteAndroidSession {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$IPOfAndroidDevice,

        [Parameter(Mandatory=$False)]
        [string]$ScrcpyPort = "5555",

        [Parameter(Mandatory=$False)]
        [string]$PathToScrcpyBinaries,

        [Parameter(Mandatory=$False)]
        [switch]$DownloadLatestScrcpy
    )

    #region >> Helper Functions

    function GetElevation {
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

    #endregion >> Helper Functions


    #region >> Prep

    if ($PSVersionTable.Platform -ne 'Win32NT') {
        if ($PathToScrcpyBinaries) {
            Write-Error "The -PathToScrcpyBinaries parameter should only be used on Windows systems. Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $AptResult = Get-Command apt -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to find package manager 'apt'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $SnapResult = Get-Command snap -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to find package manager 'snap'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # If we need to install/update adb or scrcpy, we need to be running this function as root
        $NeedPackages = $False

        try {
            $ADBPackageCheck = Get-Command adb -ErrorAction Stop
        }
        catch {
            $NeedPackages = $True
        }

        try {
            $ScrcpyPackageCheck = Get-Command scrcpy -ErrorAction Stop
        }
        catch {
            $NeedPackages = $True
        }

        if ($DownloadLatestScrcpy -or $NeedPackages) {
            if (!$(GetElevation)) {
                Write-Error "You must run PowerShell from an elevated prompt (i.e. 'sudo pwsh') in order to install/update adb and/or scrcpy! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    try {
        $null = [ipaddress]$IPOfAndroidDevice
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($PathToScrcpyBinaries -and $DownloadLatestScrcpy) {
        Write-Error "Please use *either* the -PathToScrcpyBinaries parameter *or* the -DownloadLatestScrcpy parameter, not both. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $IPAndPortString = $IPOfAndroidDevice + ':' + $ScrcpyPort

    #endregion >> Prep

    #region >> Main

    if ($PSVersionTable.Platform -eq 'Win32NT') {
        if ($DownloadLatestScrcpy) {
            $releaseInfo = Invoke-RestMethod 'https://api.github.com/repos/Genymobile/scrcpy/releases/latest'
            $target = $releaseInfo.assets | Where-Object {$_.Name.Contains('win64')}
            $destination = Join-Path "$HOME\Downloads" -ChildPath $target.Name
            $ExpansionDirectory = "$HOME\Downloads" + '\' + $($target.Name -replace '.zip')

            if (Test-Path $destination) {
                #$null = Remove-Item $destination -Recurse -Force -ErrorAction Stop
                Write-Error "The download destination path '$destination' already exists! Please delete it and try again. Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                $IWRResult = Invoke-WebRequest -Uri $target.browser_download_url -OutFile $destination -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            try {
                $ExpandArchiveResult = Expand-Archive -Path $destination -DestinationPath $ExpansionDirectory -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            $PathToScrcpyBinaries = $ExpansionDirectory
        }
        else {
            if ($PathToScrcpyBinaries) {
                if (! $(Test-Path $PathToScrcpyBinaries)) {
                    Write-Error "The path '$PathToScrcpyBinaries' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
        
                if (! $(Test-Path "$PathToScrcpyBinaries\adb.exe")) {
                    Write-Error "The path '$PathToScrcpyBinaries\adb.exe' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                
                if (! $(Test-Path "$PathToScrcpyBinaries\scrcpy.exe")) {
                    Write-Error "The path '$PathToScrcpyBinaries\scrcpy.exe' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
        
                #Set-Location $PathToScrcpyBinaries
                $ADBPath = "$PathToScrcpyBinaries\adb.exe"
                $ScrcpyPath = "$PathToScrcpyBinaries\scrcpy.exe"
            }
            else {
                try {
                    $ADBCheck = Get-Command adb -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
        
                try {
                    $ScrcpyCheck = Get-Command scrcpy -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
        
                $ADBPath = $ADBCheck.Source
                $ScrcpyPath = $ScrcpyCheck.Source
            }
        }

        # At this point, we should have $ADBPath and $ScrcpyPath
        if (!$ScrcpyPath) {
            Write-Error "Failed to identify `$ScrcpyPath! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if (!$ADBPath) {
            Write-Error "Failed to identify `$ADBPath! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Disconnect any existing adb connections
        # NOTE: $ADBDisconnectResult should contain the string 'disconnected everything'
        $ADBDisconnectResult = & $ADBPath disconnect
        
        # Create an adb connection to the Android Device
        # NOTE: $ADBConnectResult should contain the string 'connected to $IPAndPortString'
        $ADBConnectResult = & $ADBPath connect $IPAndPortString

        # Fire Up scrcpy
        $ScrcpyResult = & $ScrcpyPath --bit-rate 2M --max-size 800
    }

    if ($PSVersionTable.Platform -ne 'Win32NT') {
        if ($DownloadLatestScrcpy -or $NeedPackages) {
            $null = snap install scrcpy
            $null = apt install adb
        }

        # Disconnect any existing adb connections
        # NOTE: $ADBDisconnectResult should contain the string 'disconnected everything'
        $ADBDisconnectResult = adb disconnect

        # Create an adb connection to the Android Device
        # NOTE: $ADBConnectResult should contain the string 'connected to $IPAndPortString'
        $ADBConnectResult = adb connect $IPAndPortString

        # Fire Up scrcpy
        $ScrcpyResult = scrcpy --bit-rate 2M --max-size 800
    }

    $ScrcpyResult
    
    #endregion >> Main

}
