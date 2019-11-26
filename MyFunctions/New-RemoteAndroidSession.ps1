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

    if ($PSVersionTable.Platform -ne 'Win32NT') {
        Write-Error "This function is meant to be used on Windows! Halting!"
        $global:FunctionResult = "1"
        return
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
    $IPAndPortString = $IPOfAndroidDevice + ':' + $ScrcpyPort
    $ADBConnectResult = & $ADBPath connect $IPAndPortString

    # Fire Up scrcpy
    $ScrcpyResult = & $ScrcpyPath --bit-rate 2M --max-size 800

}




