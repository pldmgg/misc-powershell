#############################################################################################################

<#

GNU LESSER GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>

Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.

This version of the GNU Lesser General Public License incorporates the terms and conditions of version 3 of the GNU General
Public License, supplemented by the additional permissions listed below.

0. Additional Definitions.

As used herein, “this License” refers to version 3 of the GNU Lesser General Public License, and the “GNU GPL” refers to
version 3 of the GNU General Public License.

“The Library” refers to a covered work governed by this License, other than an Application or a Combined Work as defined below.

An “Application” is any work that makes use of an interface provided by the Library, but which is not otherwise based on the
Library. Defining a subclass of a class defined by the Library is deemed a mode of using an interface provided by the Library.

A “Combined Work” is a work produced by combining or linking an Application with the Library. The particular version of the
Library with which the Combined Work was made is also called the “Linked Version”.

The “Minimal Corresponding Source” for a Combined Work means the Corresponding Source for the Combined Work, excluding any
source code for portions of the Combined Work that, considered in isolation, are based on the Application, and not on the
Linked Version.

The “Corresponding Application Code” for a Combined Work means the object code and/or source code for the Application, including
any data and utility programs needed for reproducing the Combined Work from the Application, but excluding the System Libraries
of the Combined Work.

1. Exception to Section 3 of the GNU GPL.

You may convey a covered work under sections 3 and 4 of this License without being bound by section 3 of the GNU GPL.

2. Conveying Modified Versions.

If you modify a copy of the Library, and, in your modifications, a facility refers to a function or data to be supplied by an
Application that uses the facility (other than as an argument passed when the facility is invoked), then you may convey a copy
of the modified version:

a) under this License, provided that you make a good faith effort to ensure that, in the event an Application does not supply
the function or data, the facility still operates, and performs whatever part of its purpose remains meaningful, or
b) under the GNU GPL, with none of the additional permissions of this License applicable to that copy.

3. Object Code Incorporating Material from Library Header Files.

The object code form of an Application may incorporate material from a header file that is part of the Library. You may convey
such object code under terms of your choice, provided that, if the incorporated material is not limited to numerical parameters,
data structure layouts and accessors, or small macros, inline functions and templates (ten or fewer lines in length), you do both
of the following:

a) Give prominent notice with each copy of the object code that the Library is used in it and that the Library and its use are
covered by this License.
b) Accompany the object code with a copy of the GNU GPL and this license document.

4. Combined Works.

You may convey a Combined Work under terms of your choice that, taken together, effectively do not restrict modification of the
portions of the Library contained in the Combined Work and reverse engineering for debugging such modifications, if you also do
each of the following:

a) Give prominent notice with each copy of the Combined Work that the Library is used in it and that the Library and its use are
covered by this License.
b) Accompany the Combined Work with a copy of the GNU GPL and this license document.
c) For a Combined Work that displays copyright notices during execution, include the copyright notice for the Library among these
notices, as well as a reference directing the user to the copies of the GNU GPL and this license document.
d) Do one of the following:
0) Convey the Minimal Corresponding Source under the terms of this License, and the Corresponding Application Code in a form
suitable for, and under terms that permit, the user to recombine or relink the Application with a modified version of the Linked
Version to produce a modified Combined Work, in the manner specified by section 6 of the GNU GPL for conveying Corresponding Source.
1) Use a suitable shared library mechanism for linking with the Library. A suitable mechanism is one that (a) uses at run time a
copy of the Library already present on the user's computer system, and (b) will operate properly with a modified version of the
Library that is interface-compatible with the Linked Version.
e) Provide Installation Information, but only if you would otherwise be required to provide such information under section 6 of
the GNU GPL, and only to the extent that such information is necessary to install and execute a modified version of the Combined
Work produced by recombining or relinking the Application with a modified version of the Linked Version. (If you use option 4d0,
the Installation Information must accompany the Minimal Corresponding Source and Corresponding Application Code. If you use option
4d1, you must provide the Installation Information in the manner specified by section 6 of the GNU GPL for conveying Corresponding
Source.)

5. Combined Libraries.

You may place library facilities that are a work based on the Library side by side in a single library together with other
library facilities that are not Applications and are not covered by this License, and convey such a combined library under
terms of your choice, if you do both of the following:

a) Accompany the combined library with a copy of the same work based on the Library, uncombined with any other library facilities,
conveyed under the terms of this License.
b) Give prominent notice with the combined library that part of it is a work based on the Library, and explaining where to find
the accompanying uncombined form of the same work.
6. Revised Versions of the GNU Lesser General Public License.

The Free Software Foundation may publish revised and/or new versions of the GNU Lesser General Public License from time to time.
Such new versions will be similar in spirit to the present version, but may differ in detail to address new problems or concerns.

Each version is given a distinguishing version number. If the Library as you received it specifies that a certain numbered version
of the GNU Lesser General Public License “or any later version” applies to it, you have the option of following the terms and
conditions either of that published version or of any later version published by the Free Software Foundation. If the Library as
you received it does not specify a version number of the GNU Lesser General Public License, you may choose any version of the GNU
Lesser General Public License ever published by the Free Software Foundation.

If the Library as you received it specifies that a proxy can decide whether future versions of the GNU Lesser General Public
License shall apply, that proxy's public statement of acceptance of any version is permanent authorization for you to choose
that version for the Library.

#>

#############################################################################################################


function Get-Elevation {
   [System.Security.Principal.WindowsPrincipal]$CurrentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
         [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )

   [System.Security.Principal.WindowsBuiltInRole]$AdministratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

   if($CurrentPrincipal.IsInRole($AdministratorsRole)) {
      return $true;
   }
   else {
      return $false;
   }
}

function Test-IsNonInteractiveShell {
    if ([Environment]::UserInteractive) {
        foreach ($arg in [Environment]::GetCommandLineArgs()) {
            # Test each Arg for match of abbreviated '-NonInteractive' command.
            if ($arg -like '-NonI*') {
                return $true
            }
            else {
                return $false
            }
        }
    }
    if (!$([Environment]::UserInteractive)) {
        return $true
    }
}

function Verify-Directory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        $DirectoryPath
    )

    ##### BEGIN Main Body #####

    $pos = $DirectoryPath.LastIndexOf("\")
    $DirectoryNameOnly = $DirectoryPath.Substring($pos+1)

    if (!$($([uri]$DirectoryPath).IsAbsoluteURI -and $($([uri]$DirectoryPath).IsLoopBack -or $([uri]$DirectoryPath).IsUnc)) -or
    $($DirectoryNameOnly | Select-String -Pattern "\.")) {
        Write-Verbose "$DirectoryPath is not a valid directory path! Halting!"
        Write-Error "$DirectoryPath is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $DirectoryPath)) {
        Write-Verbose "The path $DirectoryPath was not found! Halting!"
        Write-Error "The path $DirectoryPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Main Body #####
}


function Update-PackageManagement {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
            Write-Host "Downlaoding PackageManagement .msi installer..."
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi"` -OutFile "$HOME\Downloads\PackageManagement_x64.msi"
            msiexec /i "$HOME\Downloads\PackageManagement_x64.msi" /quiet /norestart ACCEPTEULA=1
            Start-Sleep -Seconds 3
        }
        while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
            Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
            Start-Sleep -Seconds 1
        }
        Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
    }

    $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PackageManagement"}).Version | Measure-Object -Maximum).Maximum
    $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
    }
    # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
    # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
    # do it beforehand.
    if ($(Get-PackageProvider).Name -notcontains "NuGet") {
        Install-PackageProvider "NuGet" -Scope CurrentUser -Force
        Register-PackageSource -Name 'nuget.org' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap

        # Instead, we'll install the NuGet CLI from the Chocolatey repo...
        Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
        # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
        Set-PackageSource -Name Chocolatey -Trusted

        Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
        while (!$(Find-Package Nuget.CommandLine)) {
            Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
            Start-Sleep -Seconds 2
        }

        # Next, install the NuGet CLI using the Chocolatey Repo
        Install-Package Nuget.CommandLine -Source chocolatey
        
        # Ensure $env:Path includes C:\Chocolatey\bin
        if ($($env:Path -split ";") -notcontains "C:\Chocolatey\bin") {
            $env:Path = "$env:Path;C:\Chocolatey\bin"
        }
        # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
        $NuGetSymlinkTest = Get-ChildItem "$env:ChocolateyPath" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
        $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
        $TestRealNuGetPath = Test-Path $RealNuGetPath
        if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
            cmd.exe /c mklink C:\Chocolatey\bin\NuGet.exe $RealNuGetPath
        }
    }
    # Next, set the PSGallery PowerShellGet PackageProvider Source to Trusted
    if ($(Get-PackageSource | Where-Object {$_.Name -eq "PSGallery"}).IsTrusted -eq $False) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    # Next, update PackageManagement and PowerShellGet where possible
    [version]$MinimumVer = "1.0.0.1"
    $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
    $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version

    # Take care of updating PowerShellGet before PackageManagement since PackageManagement won't be able to update with PowerShellGet
    # still loaded in the current PowerShell Session
    if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PackageManagementLatestVersion -Force
            Write-Host "Installing latest version of PackageManagement..."
            Install-Module -Name "PackageManagement" -Force
        }
    }
    if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            # Before Updating the PowerShellGet Module, we must unload it from the current PowerShell Session
            # Remove-Module -Name "PowerShellGet"
            # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
            # and it will not update it.
            #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
            Write-Host "Installing latest version of PowerShellGet..."
            Install-Module -Name "PowerShellGet" -Force
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force
            Write-Host "Installing latest version of PowerShellGet..."
            Install-Module -Name "PowerShellGet" -Force
        }
    }

    # Reset the LatestLocallyAvailableVersion variables to reflect latest available, and then load them into the current session
    $PackageManagementLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PackageManagement"}).Version | Measure-Object -Maximum).Maximum
    $PowerShellGetLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PowerShellGet"}).Version | Measure-Object -Maximum).Maximum

    Remove-Module -Name "PowerShellGet"
    Remove-Module -Name "PackageManagement"

    if ($(Get-Host).Name -ne "Package Manager Host") {
        Write-Host "We are NOT in the Visual Studio Package Management Console. Continuing..."
        Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion

        # Make sure all Repos Are Trusted
        $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
        $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
        foreach ($RepoObject in $RepoObjectsForTrustCheck) {
            if ($RepoObject.IsTrusted -ne $true) {
                Set-PackageSource -Name $RepoObject.Name -Trusted
            }
        }
    }
    if ($(Get-Host).Name -eq "Package Manager Host") {
        Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
        Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan
        Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet

        # Make sure all Repos Are Trusted
        $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
        $RepoObjectsForTrustCheck = Get-PackManPackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
        foreach ($RepoObject in $RepoObjectsForTrustCheck) {
            if ($RepoObject.IsTrusted -ne $true) {
                Set-PackManPackageSource -Name $RepoObject.Name -Trusted
            }
        }
    }
}


<#
.SYNOPSIS
    The Register-FileIOWatcher function watches one or more files and/or subdirectories (and their contents) within a specified
    Target Directory for particular file events. When an event occurs, the specified action will be taken.

.DESCRIPTION
    See SYNOPSIS and PARAMETER sections.

.PARAMETER TargetDir
    This parameter is MANDATORY.

    This parameter takes a string that represents a directory that contains one or more files and/or subdirectories that you
    would like to monitor for changes.

.PARAMETER FilesToWatchRegexMatch
    This parameter is OPTIONAL.

    This parameter takes a regex value that specifies one or more files or subdirectories to monitor within the $TargetDir.

    Either this parameter or FilesToWatchEasyMatch MUST be used.

.PARAMETER FilesToWatchEasyMatch
    This parameter is OPTIONAL

    This parameter takes a string value that is pseudo-regex. It accepts wildcard characters. Examples:

        *.*             matches    All files
        *.txt           matches    All files with a "txt" extension.
        *recipe.doc     matches    All files ending in "recipe" with a "doc" extension.
        win*.xml        matches    All files beginning with "win" with an "xml" extension.
        Sales*200?.xls  matches    Files such as "Sales_July_2001.xls","Sales_Aug_2002.xls","Sales_March_2004.xls"
        MyReport.Doc    matches    Only MyReport.doc

    NOTE: You CANNOT use multiple filters such as "*.txt|*.doc". If you would like this functionality, use the
    FilesToWatchRegexMatch parameter.

    Either this parameter or FilesToWatchRegexMatch MUST be used.

.PARAMETER IncludeSubdirectories
    This parameter is OPTIONAL.

    This parameter is a switch. Include it if you want to monitor subdirectories (and their contents) within $TargetDir.

.PARAMETER Trigger
    This parameter is MANDATORY.

    This parameter takes a string and must be one of the following values:
    "Changed","Created","Deleted","Disposed","Error","Renamed"

    This parameter specifies when a particular event (and its associated action) are triggered.

.PARAMETER LogDir
    This parameter is MANDATORY.

    This parameter takes a string that represents a path to a directory that will contain a folder called "FileIOWatcherEvents"
    that contains .xml files that represent PSCustomObjects that contain the results of a triggered event. These PSCustomObjects
    can be imported back into PowerShell at a future time for analysis by using:

    $EventTriggerResultCustomObject = Import-Clixml "$LogDir\FileIOWatcherEvents\<FriendlyNameForEvent>_<SourceIdentifierLast4>_<EventIdentifier>.xml"

    For more information on this, see the NOTES section.

.PARAMETER FriendlyNameForEvent
    This parameter is OPTIONAL.

    This parameter takes a string that will become the name of the object that becomes available in the scope that runs this function after
    the function concludes.

    For example if the function is run as follows...
        Register-FileIOWatcher -TargetDir "$TestTargetDir" `
        -FilesToWatchEasyMatch "SpecificDoc.txt" `
        -Trigger "Changed" `
        -LogDir $LogDirectory `
        -FriendlyNameForEvent "EventForSpecificDocChange" `
        -ActionToTakeScriptBlock $ActionToTake
    ...you will be able to see the result of the function by calling the variable $EventForSpecificDocChange.

.PARAMETER ActionToTakeScriptBlock
    This parameter is MANDATORY.

    This parameter takes EITHER a string (that will later be converted to a scriptblock object), or a scriptblock object.

    The scriptblock provided to this parameter defines specifically what action will take place when an event is triggered.

.EXAMPLE
    Try the following:
    (IMPORTANT: Make sure the characters '@ are justified all-the-way to the left regardless of indentations elsewhere)

    $TestTargetDir = "$HOME"
    $DirName = $HOME | Split-Path -Leaf
    $LogDirectory = "M:\Logs\PowerShell"
    $GCITest = Get-ChildItem -Path "$HOME\Downloads"

    $ActionToTake = @'
Write-Host "Hello there!"

Write-Host "Writing Register-FileIOWatcher value for parameter -Trigger"
Write-Host "$Trigger"
Write-Host "Writing fullname of the first item in `$GCITest object index to STDOUT"
Write-Host "$($GCITest[0].FullName)"
Write-Host "Setting new variable `$AltGCI equal to `$GCITest"
$AltGCI = $GCITest
Write-Host "Writing `$AltGCI out to file `$HOME\Documents\AltGCIOutput.txt"
$AltGCI | Out-File $HOME\Documents\AltGCIOutput.txt

Write-Host "Bye!"
'@

    Register-FileIOWatcher -TargetDir "$TestTargetDir" `
    -FilesToWatchEasyMatch "SpecificDoc.txt" `
    -Trigger "Changed" `
    -LogDir $LogDirectory `
    -FriendlyNameForEvent "EventForSpecificDocChange" `
    -ActionToTakeScriptBlock $ActionToTake

    Next, create/make a change to the file $HOME\SpecificDoc.txt and save it. This will trigger the
    $ActionToTake scriptblock. (Note that $ActionToTake is actually a string that is converted a scriptblock object 
    by the function). Anything in the scriptblock using the Write-Host cmdlet will appear in STDOUT in your active PowerShell 
    session. If your scriptblock does NOT use the Write-Host cmdlet, it will NOT appear in your active PowerShell session
    (but, of course, the operations will still occur).

.OUTPUTS
    Output for this function is a System.Management.Automation.PSEventJob object named after the string provided to the
    -FriendlyNameForEvent parameter. If the -FriendlyNameForEvent parameter is not used, the System.Management.Automation.PSEventJob
    object will be called $EventFor<TargetDirName>.

.NOTES
    KNOWN BUG:
    There is a known bug with System.IO.FileSystemWatcher objects involving triggers firing multiple times for 
    singular events. For details, see: http://stackoverflow.com/questions/1764809/filesystemwatcher-changed-event-is-raised-twice 

    This function works around this bug by using Size as opposed to LastWrite time in the IO.FIleSystemWatcher object's
    NotifyFilter property. However, there is one drawback to this workaround: If the file is modified and remains
    EXACTLY the same size (not very likely, but still possible), then the event will NOT trigger.

    HOW TO ANALYZE TRIGGERED EVENT RESULTS:
    To analyze results of a triggered event, perform the following steps

    Get the Event's SourceIdentifier and the last 4 characters of the SourceIdentifier. Assuming we are using the output from our
    above EXAMPLE (i.e. $EventForSpecificDocChange), we get this information by doing the following:
        $EventForSpecificDocChangeSourceIdentifier = $EventForSpecificDocChange.Name
        $EventForSpecificDocChangeSourceIdentifierLast4 = $EventForSpecificFocChangeSourceIdentifier.Substring($EventForSpecificFocChangeSourceIdentifier.Length-4)

    After a change is made to SpecificDoc.txt...

    ...EITHER analyze the Subscriber Event itself:
        $SubscriberEventForSpecificDocChange = Get-EventSubscriber | Where-Object {$_.SubscriberId -eq $EventForSpecificFocChangeSourceIdentifier}

    ...OR (RECOMMENDED), import more comprehensive and friendly information from the log file generated when an event triggers:
        $LogFileForLatestSpecificDocChangeTrigger = $(Get-ChildItem "$LogDirectory\FileIOWatcherEvents" | Where-Object {
            $_.Name -like "*$EventForSpecificDocChangeSourceIdentifierLast4*"
        } | Sort-Object -Property "LastWriteTime")[-1].FullName

        $PSCustomObjectForSpecificDocChangeEvent = Import-Clixml $LogFileForLatestSpecificDocChangeTrigger

    The contents of the PSCustomObject imported via Import-Clixml are as follows:

        Event                    : System.Management.Automation.PSEventArgs
        SubscriberEvent          : System.Management.Automation.PSEventSubscriber
        SourceIdentifier         : f73d1f49-241e-40bc-a356-1bb02c79c162
        FilesThatChanged         : SpecificDoc.txt
        TriggerType              : Changed
        FilesThatChangedFullPath : C:\Users\testadmin\SpecificDoc.txt
        TimeStamp                : 2/12/2017 11:58:40 AM

    To review the scriptblock that was executed, either use:
        $SubscriberEventForSpecificDocChange.Action.Command

    ...or, if you imported the log file to use the PSCustomObject:
        $PSCustomObjectForSpecificDocChangeEvent.SubscriberEvent.Action.Command

    TO UNREGISTER AN EVENT AFTER IT HAS BEEN CREATED USING THIS FUNCTION:
    Unregister-Event -SourceIdentifier $EventForSpecificDocChangeSourceIdentifier

#>

Function Register-FileIOWatcher {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$TargetDir = $(Read-Host -Prompt "Please enter the full path to the directory that contains the file(s) you would like to watch."),

        [Parameter(Mandatory=$False)]
        [regex]$FilesToWatchRegexMatch,

        [Parameter(Mandatory=$False)]
        [string]$FilesToWatchEasyMatch,

        [Parameter(Mandatory=$False)]
        [switch]$IncludeSubdirectories,

        [Parameter(Mandatory=$True)]
        [ValidateSet("Changed","Created","Deleted","Disposed","Error","Renamed")]
        $Trigger,

        [Parameter(Mandatory=$True)]
        [string]$LogDir, # Directory where logging of triggered events will be stored. A folder called FileIOWatcherEvents will be created and all logs will be saved inside. Logs XML representations of PSCustomObjects, so they can me imported back into PowerShell at a later time for analysis.

        [Parameter(Mandatory=$False)]
        [string]$FriendlyNameForEvent, # This string will be the name of the variable that this function outputs. If blank, the name will be "EventFor<TargetDirName>"

        [Parameter(Mandatory=$True)]
        $ActionToTakeScriptBlock, # Can be a string or a scriptblock. If string, the function will handle converting it to a scriptblock object.

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Make sure $TargetDir is a valid path
    $TargetDirNameOnly = $TargetDir | Split-Path -Leaf
    $LogDirFileIOFolder = "FileIOWatcherEvents"
    $FullLogDirLocation = "$LogDir\$LogDirFileIOFolder"

    if ( !$($([uri]$TargetDir).IsAbsoluteURI -and $($([uri]$TargetDir).IsLoopBack -or $([uri]$TargetDir).IsUnc)) ) {
        Write-Verbose "$TargetDir is not a valid directory path! Halting!"
        Write-Error "$TargetDir is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $TargetDir)) {
        Write-Verbose "The path $TargetDir was not found! Halting!"
        Write-Error "The path $TargetDir was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ( !$($([uri]$LogDir).IsAbsoluteURI -and $($([uri]$LogDir).IsLoopBack -or $([uri]$LogDir).IsUnc)) ) {
        Write-Verbose "$LogDir is not a valid directory path! Halting!"
        Write-Error "$LogDir is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $LogDir)) {
        Write-Verbose "The path $LogDir was not found! Halting!"
        Write-Error "The path $LogDir was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Test-Path $FullLogDirLocation)) {
        New-Item -Path $FullLogDirLocation -ItemType Directory | Out-Null
    }

    if ($FilesToWatchRegexMatch -and $FilesToWatchEasyMatch) {
        Write-Verbose "Please use *either* the `$FilesToWatchRegexMatch parameter *or* the `$FilesToWatchEasyMatch parameter. Halting!"
        Write-Error "Please use *either* the `$FilesToWatchRegexMatch parameter *or* the `$FilesToWatchEasyMatch parameter. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$FilesToWatchRegexMatch -and !$FilesToWatchEasyMatch) {
        Write-Verbose "You must use either the `$FilesToWatchRegexMatch parameter or the `$FilesToWatchEasyMatch parameter in order to specify which files you would like to watch in the directory `"$TargetDir`". Halting!"
        Write-Error "You must use either the `$FilesToWatchRegexMatch parameter or the `$FilesToWatchEasyMatch parameter in order to specify which files you would like to watch in the directory `"$TargetDir`". Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($ActionToTakeScriptBlock.GetType()).FullName -eq "System.Management.Automation.ScriptBlock") {
        $UpdatedActionToTakeScriptBlock = $ActionToTakeScriptBlock
    }
    if ($($ActionToTakeScriptBlock.GetType()).FullName -eq "System.String") {
        $UpdatedActionToTakeScriptBlock = [scriptblock]::Create($ActionToTakeScriptBlock)
    }
    if ($($ActionToTakeScriptBlock.GetType()).FullName -notmatch "System.Management.Automation.ScriptBlock|System.String") {
        Write-Verbose "The value passed to the `$ActionToTakeScriptBlock parameter must either be a System.Management.Automation.ScriptBlock or System.String! Halting!"
        Write-Error "The value passed to the `$ActionToTakeScriptBlock parameter must either be a System.Management.Automation.ScriptBlock or System.String! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $Watcher = New-Object IO.FileSystemWatcher
    $Watcher.Path = $TargetDir
    # Setting NotifyFilter to FileName, DirectoryName, and Size as opposed to FileName, DirectoryName, and LastWrite
    # prevents the bug that causes the trigger fire twice on Change to LastWrite time.
    # Bug: http://stackoverflow.com/questions/1764809/filesystemwatcher-changed-event-is-raised-twice
    $watcher.NotifyFilter = "FileName, DirectoryName, Size"
    # NOTE: The Filter property can't handle normal regex, so if $FileToWatchRegexMatch is used, just temporarily set it to 
    # every file and do the regex check in the $FilesToWatchRegexMatchClause which is ultimately added to the 
    # $AlwaysIncludeInScriptBlock script block
    if ($FilesToWatchRegexMatch) {
        $Watcher.Filter = "*.*"
    }
    if ($FilesToWatchEasyMatch) {
        $Watcher.Filter = $FilesToWatchEasyMatch
    }
    if ($IncludeSubdirectories) {
        $Watcher.IncludeSubdirectories = $True
    }
    $Watcher.EnableRaisingEvents = $True

    # Adding Array elements in this manner becaue order is important
    [System.Collections.ArrayList]$FunctionParamVarsToPassToScriptBlock = @("TargetDir")
    if ($FilesToWatchRegexMatch) {
        $FunctionParamVarsToPassToScriptBlock.Add("FilesToWatchRegexMatch") | Out-Null
    }
    if ($FilesToWatchEasyMatch) {
        $FunctionParamVarsToPassToScriptBlock.Add("FilesToWatchEasyMatch") | Out-Null
    }
    if ($IncludeSubdirectories) {
        $FunctionParamVarsToPassToScriptBlock.Add("IncludeSubdirectories") | Out-Null
    }
    $FunctionParamVarsToPassToScriptBlock.Add("Trigger") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("LogDir") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("FullLogDirLocation") | Out-Null
    $FunctionParamVarsToPassToScriptBlock.Add("FriendlyNameForEvent") | Out-Null

    $FunctionArgsToBeUsedByActionToTakeScriptBlock = @()
    foreach ($VarName in $FunctionParamVarsToPassToScriptBlock) {
        # The below $StringToBePassedToScriptBlock is valid because all of the function parameters can be represented as strings
        $StringToBePassedToScriptBlock = "`$$VarName = '$(Get-Variable -Name $VarName -ValueOnly)'"
        $FunctionArgsToBeUsedByActionToTakeScriptBlock += $StringToBePassedToScriptBlock
    }
    $UpdatedFunctionArgsToBeUsedByActionToTakeScriptBlockAsString = $($FunctionArgsToBeUsedByActionToTakeScriptBlock | Out-String).Trim()

    if ($FilesToWatchRegexMatch) {
        $FilesToWatchRegexMatchClause = @"
`$FilesOfConcern = @()
foreach (`$file in `$FilesThatChanged) {
    if (`$file -match `'$FilesToWatchRegexMatch`') {
        `$FilesOfConcern += `$file
    }
}
if (`$FilesOfConcern.Count -lt 1) {
    Write-Verbose "The files that were $Trigger in the target directory $TargetDir do not match the specified regex. No action taken."
    return
}
"@
    }

    if ($FriendlyNameForEvent) {
        $NameForEventClause = @"
`$NewVariableName = "$FriendlyNameForEvent`_`$SourceIdentifierAbbrev`_`$EventIdentifier"
"@
    }
    if (!$FriendlyNameForEvent) {
        $NameForEventClause = @"
`$NewVariableName = "FileIOWatcherFor$TargetDirNameOnly`_`$SourceIdentifierAbbrev`_`$EventIdentifier"
"@
    }

    # Always include the following in whatever scriptblock is passed to $ActionToTakeScriptBlock parameter
    # NOTE: $Event is an automatic variable that becomes available in the context of the Register-ObjectEvent cmdlet
    # For more information, see:
    # https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/register-objectevent
    # https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.core/about/about_automatic_variables

    $AlwaysIncludeInScriptBlock = @"

############################################################
# BEGIN Always Included ScriptBlock
############################################################

`$FilesThatChanged = `$Event.SourceEventArgs.Name
`$FilesThatChangedFullPath = `$Event.SourceEventArgs.FullPath

$FilesToWatchRegexMatchClause

`$PSEvent = `$Event
`$SourceIdentifier = `$Event.SourceIdentifier
`$SourceIdentifierAbbrev = `$SourceIdentifier.Substring(`$SourceIdentifier.Length - 4)
`$PSEventSubscriber = Get-EventSubscriber | Where-Object {`$_.SourceIdentifier -eq `$SourceIdentifier}
`$EventIdentifier = `$Event.EventIdentifier
`$TriggerType = `$Event.SourceEventArgs.ChangeType
`$TimeStamp = `$Event.TimeGenerated

$NameForEventClause

New-Variable -Name "`$NewVariableName" -Value `$(
    [pscustomobject][ordered]@{
        Event                      = `$PSEvent
        SubscriberEvent            = `$PSEventSubscriber
        SourceIdentifier           = `$SourceIdentifier
        FilesThatChangedFullPath   = `$FilesThatChangedFullPath
        FilesThatChanged           = `$FilesThatChanged
        TriggerType                = `$TriggerType
        TimeStamp                  = `$TimeStamp
    }
)

##### BEGIN Function Args Passed To ScriptBlock #####

$UpdatedFunctionArgsToBeUsedByActionToTakeScriptBlockAsString

##### END Function Args Passed To ScriptBlock  #####

`$(Get-Variable -Name "`$NewVariableName" -ValueOnly) | Export-Clixml `$FullLogDirLocation\`$NewVariableName.xml

############################################################
# END Always Included ScriptBlock
############################################################

#############################################################################
# BEGIN ScriptBlock Passed In Using The Parameter -ActionToTakeScriptBlock
#############################################################################

"@

    $Action = [scriptblock]::Create($AlwaysIncludeInScriptBlock+"`n"+$UpdatedActionToTakeScriptBlock.ToString())

    if ($FriendlyNameForEvent) {
        New-Variable -Name "$FriendlyNameForEvent" -Scope Script -Value $(
            Register-ObjectEvent -InputObject $Watcher -EventName "$Trigger" -Action $Action
        )
        if (!$Silent) {
            Get-Variable -Name "$FriendlyNameForEvent" -ValueOnly
        }
    }
    if (!$FriendlyNameForEvent) {
        New-Variable -Name "EventFor$TargetDirNameOnly" -Scope Script -Value $(
            Register-ObjectEvent -InputObject $Watcher -EventName "$Trigger" -Action $Action
        )
        if (!$Silent) {
            Get-Variable -Name "EventFor$TargetDirNameOnly" -ValueOnly
        }
    }

    ##### END Main Body #####
}


function Limit-DirectorySize {
    [CmdletBinding(PositionalBinding=$True)]
    Param( 
        [Parameter(Mandatory=$False)]
        $Directory = $(Read-Host -Prompt "Please enter the full path to the directory that will be assigned a size limit."),

        [Parameter(Mandatory=$False)]
        $SizeLimitInGB = $(Read-Host -Prompt "Please enter the maximum size in GB that you would like to allow the directory $Directory to grow to")
    )

    ## BEGIN Native Helper Functions ##

    # The below Convert-Size function is from:
    # http://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/2376
    function Convert-Size {
        [cmdletbinding()]
        param(
            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$From,

            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$To,

            [Parameter(Mandatory=$True)]
            [double]$Value,

            [Parameter(Mandatory=$False)]
            [int]$Precision = 4
        )

        switch($From) {
            "Bytes" {$Value = $Value }
            "KB" {$Value = $Value * 1024 }
            "MB" {$Value = $Value * 1024 * 1024}
            "GB" {$Value = $Value * 1024 * 1024 * 1024}
            "TB" {$Value = $Value * 1024 * 1024 * 1024 * 1024}
        }            
                    
        switch ($To) {
            "Bytes" {return $value}
            "KB" {$Value = $Value/1KB}
            "MB" {$Value = $Value/1MB}
            "GB" {$Value = $Value/1GB}
            "TB" {$Value = $Value/1TB}
        }

        return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $DirectoryName = $Directory | Split-Path -Leaf
    $SizeLimitInBytes = Convert-Size -From GB -To Bytes -Value $SizeLimitInGB
    $DirSizeInBytes = $(Get-ChildItem $Directory | Measure-Object -Property Length -sum).sum

    if ( !$($([uri]$Directory).IsAbsoluteURI -and $($([uri]$Directory).IsLoopBack -or $([uri]$Directory).IsUnc)) ) {
        Write-Verbose "$Directory is not a valid directory path! Halting!"
        Write-Error "$Directory is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (! $(Test-Path $Directory)) {
        Write-Verbose "The path $Directory was not found! Halting!"
        Write-Error "The path $Directory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    if ($DirSizeInBytes -gt $SizeLimitInBytes) {
        # Remove as many of the oldest files as necessary to get back under the size limit
        $DifferenceBetweenLimitandActual = $DirSizeInBytes-$SizeLimitInBytes
        $DirContentsOldToNew = Get-ChildItem $Directory | Where-Object {!$_.PSIsContainer} | Sort-Object -Property "LastWriteTime"
        
        $FilesToDeleteArray = @()
        $NewSum = 0
        for ($i=0; $i -lt $DirContentsOldToNew.Count; $i++) {
            if ($NewSum -lt $DifferenceBetweenLimitandActual) {
                $OldSum = $NewSum
                $NewSum = $OldSum+$DirContentsOldToNew[$i].Length
                $FilesToDeleteArray += $($DirContentsOldToNew[$i].FullName)
            }
        }

        foreach ($Item in $FilesToDeleteArray) {
            Remove-Item -Path $Item -Force
        }
    }

    ##### END Main Body #####

}


<#
.SYNOPSIS
    Enables logging of Interactive and Uninteractive PowerShell Sessions organized by computer, user, and PowerShell Process Identifier (PID).

    While it is true that the Group Policy setting...

        Windows Components -> Administrative Templates -> Windows PowerShell -> Turn on PowerShell Script Block Logging 

    ...exists for this purpose, parsing the resulting Windows Event Log messages is very difficult, has limitations, and is
    not really conducive to quickly figuring out what PowerShell commands were executed by a particular user on a specific
    system, at a specific time/date. Also, according to Microsoft this GPO, "only serves as a record of last resort" (see:
    https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/)

.DESCRIPTION
    This module organizes logging of PowerShell Sessions into four (4) different categories:

    1) Interactive History:
        Two types of files created by this Start-PSLogging module fall into this category:
            A) A .txt file (referred to as $ConsoleHistoryPath) written to by the PSReadline module as a
            result of: Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath. Each line in this text
            file contains ONLY the text from the command line. The file name of $ConsoleHistoryPath will be
            in the format:

                $env:COMPUTERNAME`_$PowerShellUserAccount`_ConsoleHost_History.txt

            NOTE: This is the file that PSReadline refers to when you press the up arrow on your keyboard to
            scroll through previously executed commands within an Interactive PowerShell Session.

            B) A .csv file (referred to as $InteractivePSHistoryPath) that is written to whenever $ConsoleHistoryPath 
            is modified. Each line in this .csv file is in the specialized format Microsoft.PowerShell.Commands.HistoryInfo,
            which is created by exporting the results of the Get-History cmdlet. The file name of $InteractivePSHistoryPath
            will be in the format:

                $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Interactive_PShistory.csv

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    2) Uninteractive History:
        Any powershell scripts/functions that run on a schedule or in an otherwise unattended mode fall into this category.

        ****IMPORTANT NOTE: If these unattended scripts do NOT load the Start-PSLogging Module, then they will NOT be included
        in the Uninteractive History ****or any other log mentioned below****.

        A .csv file (referred to as $UninteractivePSHistoryPath) that is written to whenever a PowerShell process exits (i.e.
        uses Register-EngineEvent PowerShell.Exiting). Each line in this .csv file is in the specialized format
        Microsoft.PowerShell.Commands.HistoryInfo, which is created by exporting the results of the Get-History cmdlet. 
        The file name of $UninteractivePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Uninteractive_PShistory.csv

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    3) SystemWide History:
        Captures both Interactive and Uninteractive History in chronological order. In other words, when reviewing this log,
        it is possible to see several entries from an Interactive PowerShell session followed by several entries from an
        Uninteractive PowerShell session.

        A .csv file (referred to as $SystemWidePSHistoryPath) that is written to whenever $InteractivePSHistoryPath or 
        $UninteractivePSHistoryPath are modified. Each line in this .csv file is in the specialized format
        Microsoft.PowerShell.Commands.HistoryInfo, which is created by exporting the results of the Get-History cmdlet. 
        The file name of $SystemWidePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$PowerShellUserAccount`_SystemWide_History.csv

        IMPORTANT NOTE: Uninteractive History will NOT be logged if this Start-PSLogging Module is not loaded in
        the unattended PowerShell processes.

        IMPORTANT NOTE: STDOUT is NOT captured. Only Command Line entries are captured.

    4) All STDOUT for Both Interactive and Uninteractive PowerShell Sessions
        Uses Start-Transcript cmdlet to log all of STDOUT for both Interactive and Uninteractive sessions.

        A .txt file (refrred to as $PSTranscriptPath) that is written to whenever a PoweShell process exits. The
        file name of $UninteractivePSHistoryPath will be in the format:

            $env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Transcript_$(get-date -f yyyyMMdd-HHmmss).txt

        IMPORTANT NOTE: Uninteractive STDOUT History will NOT be logged if this Start-PSLogging Module is not loaded in
        the unattended PowerShell processes.


.NOTES
    IMPORTANT NOTE: If Uninteractive PowerShell Sessions/Processes do NOT load the Start-PSLogging Module, then they will NOT
    be logged!

.PARAMETER ConsoleHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that the PSReadline Module will write Interactive
    PowerShell console commands to. This directory will contain the .txt file $ConsoleHistoryPath that is referenced by:
        Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath

.PARAMETER InteractivePSHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of Interactive PowerShell
    Sessions in .csv files.

.PARAMETER UninteractivePSHistDir
    This parameter is MADATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of PowerShell Sessions that
    are NOT interactive in .csv files (as long as these unattended sessions load the Start-PSLogging Module).

.PARAMETER SystemWidePSHistDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store the History of ALL PowerShell Sessions 
    from a particular host (i.e. $env:COMPUTERNAME), from both Interactive and Uninteractive sessions, in .csv files.

.PARAMETER PSTranscriptDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store transcripts of STDOUT for ALL PowerShell 
    Sessions from a particular host (i.e. $env:COMPUTERNAME), from both Interactive and Uninteractive sessions, in .txt files.

.PARAMETER FileIOWatcherEventLogDir
    This parameter is MANDATORY.

    This parameter takes a string that represents the full path to the directory that will store records of each time a FileIOWatcher 
    Event is triggered. In other words, it stores Register-FileIOWatcher function logs in .xml files.

.EXAMPLE
    $LogDir = "K:\Logs\PowerShell"
    Start-PSLogging -LogDirectory $LogDir -SubDirectorySizeLimitInGB 1

.EXAMPLE
    $LogDir = "M:\Logs\PowerShell"
    Start-PSLogging -ConsoleHistDir "M:\Logs\Powershell\PS_Interactive_History" `
    -InteractivePSHistDir "M:\Logs\Powershell\PS_Interactive_History" `
    -UninteractivePSHistDir "M:\Logs\Powershell\PS_Uninteractive_History" `
    -SystemWidePSHistDir "M:\Logs\Powershell\PS_SystemWide_History" `
    -PSTranscriptDir "M:\Logs\Powershell\PS_Session_Transcripts" `
    -FileIOWatcherEventLogDir "M:\Logs\Powershell" `
    -SubDirectorySizeLimitInGB 2

    NOTE: In the above example, the "FileIOWatcherEventLogDir" parameter creates a directory called FileIOWatcherEvents
    under M:\Logs\PowerShell\

.OUTPUTS
    Outputs for this function are three (3) System.Management.Automation.PSEventJob objects that come as output from the 
    Register-FileIOWatcher function. These objects will be available in the scope that calls this function and be named

        $EventForPSReadlineConsoleHistoryChange
        $EventForInteractivePSHistoryChange
        $EventForUninteractivePSHistoryChange

    These FileIOWatcher Events can also be reviewed via the Get-EventSubscriber cmdlet in the PowerShell session/process 
    that uses this function.

#>

function Start-PSLogging {
    [CmdletBinding(PositionalBinding=$True)]
    Param(

        [Parameter(Mandatory=$False)]
        [string]$LogDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that will contain all logging subdirectories"),

        [Parameter(Mandatory=$False)]
        $SubDirectorySizeLimitInGB = $(Read-Host -Prompt "Five subdirectories under $LogDirectory will be created (if they don't already exist). Please enter the size limit in GB that will apply to EACH of these subdirectories"),

        [Parameter(Mandatory=$False)]
        [string]$InteractivePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$UninteractivePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$SystemWidePSHistDir,

        [Parameter(Mandatory=$False)]
        [string]$PSTranscriptDir,

        [Parameter(Mandatory=$False)]
        [string]$FileIOWatcherEventLogDir
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $whoamiSanitizedForFileName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -replace "\\","-"
    if (Get-Elevation) {
        $PowerShellUserAccount = "Elevated_$whoamiSanitizedForFileName"
    }
    else {
        $PowerShellUserAccount = $whoamiSanitizedForFileName
    }

    if (!$InteractivePSHistDir) {
        $InteractivePSHistDir = "$LogDirectory\PS_Interactive_History"
        $ConsoleHistDir = $InteractivePSHistDir
    }
    if (!$UninteractivePSHistDir) {
        $UninteractivePSHistDir = "$LogDirectory\PS_Uninteractive_History"
    }
    if (!$SystemWidePSHistDir) {
        $SystemWidePSHistDir = "$LogDirectory\PS_SystemWide_History"
    }
    if (!$PSTranscriptDir) {
        $PSTranscriptDir = "$LogDirectory\PS_Session_Transcripts"
    }
    if (!$FileIOWatcherEventLogDir) {
        $FileIOWatcherEventLogDir = "$LogDirectory"
    }

    if (!$(Test-Path $InteractivePSHistDir)) {
        New-Item -Type Directory -Path $InteractivePSHistDir
    }
    if (!$(Test-Path $UninteractivePSHistDir)) {
        New-Item -Type Directory -Path $UninteractivePSHistDir
    }
    if (!$(Test-Path $SystemWidePSHistDir)) {
        New-Item -Type Directory -Path $SystemWidePSHistDir
    }
    if (!$(Test-Path $PSTranscriptDir)) {
        New-Item -Type Directory -Path $PSTranscriptDir
    }
    if (!$(Test-Path $FileIOWatcherEventLogDir)) {
        New-Item -Type Directory -Path $FileIOWatcherEventLogDir
    }

    Verify-Directory -DirectoryPath $LogDirectory
    Verify-Directory -DirectoryPath $InteractivePSHistDir
    Verify-Directory -DirectoryPath $UninteractivePSHistDir
    Verify-Directory -DirectoryPath $SystemWidePSHistDir
    Verify-Directory -DirectoryPath $PSTranscriptDir

    $ConsoleHistoryFileName = "$env:COMPUTERNAME`_$PowerShellUserAccount`_ConsoleHost_History.txt"
    $ConsoleHistoryPath = "$ConsoleHistDir\$ConsoleHistoryFileName"

    $InteractivePSHistoryFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Interactive_PShistory.csv"
    $InteractivePSHistoryPath = "$InteractivePSHistDir\$InteractivePSHistoryFileName"

    $UninteractivePSHistoryFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Uninteractive_PShistory.csv"
    $UninteractivePSHistoryPath = "$UninteractivePSHistDir\$UninteractivePSHistoryFileName"

    $SystemWidePSHistoryFileName = "$env:COMPUTERNAME`_$PowerShellUserAccount`_SystemWide_History.csv"
    $SystemWidePSHistoryPath = "$SystemWidePSHistDir\$SystemWidePSHistoryFileName"

    $PSTranscriptFileName = "$env:COMPUTERNAME`_$pid`_$PowerShellUserAccount`_Transcript_$(get-date -f yyyyMMdd-HHmmss).txt"
    $PSTranscriptPath = "$PSTranscriptDir\$PSTranscriptFileName"

    # Update-PackageManagement and Ensure PSReadline is installed and updated to latest version and writes out to $ConsoleHistoryPath

    if ($(Get-Module -Name PSReadLine) -eq $null) {
        if ($(Get-Module -ListAvailable | Where-Object {$_.Name -eq "PSReadline"}) -eq $null) {
            Update-PackageManagement
            Install-Module -Name "PSReadline" -Force
        }
    }
    $PSReadlineLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PSReadline"}).Version | Measure-Object -Maximum).Maximum
    $PSReadlineLatestAvailableVersion = $(Find-Module PSReadline).Version
    if ($PSReadlineLatestLocallyAvailableVersion -lt $PSReadlineLatestAvailableVersion) {
        Install-Module -Name "PSReadline" -Force
    }
    # Reset LatestLocallyAvailableVersion...
    $PSReadlineLatestLocallyAvailableVersion = $($(Get-Module -ListAvailable | Where-Object {$_.Name -eq"PSReadline"}).Version | Measure-Object -Maximum).Maximum
    Remove-Module -Name "PSReadline"
    Import-Module "PSReadline" -RequiredVersion $PSReadlineLatestLocallyAvailableVersion

    if ($(Get-PSReadlineOption).HistorySavePath -ne $ConsoleHistoryPath) {
        Set-PSReadlineOption -HistorySavePath $ConsoleHistoryPath
    }

    # Load up the history from $SystemWidePSHistoryPath so that ALL User's history is available in current session 
    if (Test-Path $SystemWidePSHistoryPath) {
        Import-Csv $SystemWidePSHistoryPath | Add-History
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    # Setup File Watchers and Log Interactions
    # Run each File Watcher in its own runspace (if appropriate)
    # Add each Register-FileIOWatcher scriptblock to the below $ArrayOfFileIOWatcherPSObjects, and
    # loop through them when creating Runspaces
    $ArrayOfFileIOWatcherPSObjects = @()


    # The below ConsoleHistoryWatcher adds Interactive PowerShell Sessions to $InteractivePSHistoryPath when $ConsoleHistoryPath is "Changed"
    # NOTE: "Changed" triggers on file creation as well as modification, so no need for a separate Watcher Event on file creation.
    $ConsoleHistoryWatcherScriptBlock = @"
Write-Verbose "The file `$FilesThatChangedFullPath was `$TriggerType at `$TimeStamp"
try {
    `$TryGettingHistory = `$(Get-History)[-1]
}
catch {
    Write-Verbose "Fewer than 1 command has been executed in PowerShell at this time."
}
if (`$TryGettingHistory) {
    if (!`$(Test-Path "$InteractivePSHistoryPath")) {
        #`$(Get-History)[-1] | Export-Csv "$InteractivePSHistoryPath"
        `$MockCsvContent = '#TYPE Microsoft.PowerShell.Commands.HistoryInfo'+"``n"+'"Id","CommandLine","ExecutionStatus","StartExecutionTime","EndExecutionTime"'
        Set-Content -Path "$InteractivePSHistoryPath" -Value `$MockCsvContent
    }
    else {
        `$LastCommandInCsvFormat = `$(Get-History)[-1] | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
        `$pos = `$LastCommandInCsvFormat.IndexOf(",")
        `$LastCommandWithoutId = `$LastCommandInCsvFormat.Substring(`$pos+1)

        if (`$LastCommandInCsvFormat -ne `$(Get-Content "$InteractivePSHistoryPath")[-1] -and
        `$(Get-Content "$InteractivePSHistoryPath")[-1] -notlike "*`$LastCommandWithoutId") {
            if (`$(Test-Path "$SystemWidePSHistoryPath")) {
                if (`$(Get-Content "$SystemWidePSHistoryPath")[-1] -notlike "*`$LastCommandWithoutId") {
                    # Removes Column Headers (i.e. object property names) and appends file at DestPath
                    `$(Get-History)[-1] | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$InteractivePSHistoryPath"
                }
            }
            if (!`$(Test-Path "$SystemWidePSHistoryPath")) {
                # Removes Column Headers (i.e. object property names) and appends file at DestPath
                `$(Get-History)[-1] | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$InteractivePSHistoryPath"
            }
        }
    }
}
if (!`$TryGettingHistory) {
    if (!`$(Test-Path "$InteractivePSHistoryPath")) {
        `$MockCsvContent = '#TYPE Microsoft.PowerShell.Commands.HistoryInfo'+"``n"+'"Id","CommandLine","ExecutionStatus","StartExecutionTime","EndExecutionTime"'
        Set-Content -Path "$InteractivePSHistoryPath" -Value `$MockCsvContent
    }
    else {
        Write-Verbose "The Interactive PowerShell History file "$InteractivePSHistoryPath" already exists, but no history is available in the current PowerShell Session. No action taken"
    }
}
"@
    
    <#
    $CHWParams = @{
        TargetDir = "$ConsoleHistDir"
        FilesToWatchEasyMatch = "$ConsoleHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForPSReadlineConsoleHistoryChange"
        ActionToTakeScriptBlock = $ConsoleHistoryWatcherScriptBlock
    }
    #>

    $CHWRunspaceScriptBlock = {
        Register-FileIOWatcher -TargetDir "$ConsoleHistDir" `
        -FilesToWatchEasyMatch "$ConsoleHistoryFileName" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForPSReadlineConsoleHistoryChange" `
        -ActionToTakeScriptBlock $ConsoleHistoryWatcherScriptBlock -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $CHWRunspaceScriptBlock


    # The below InteractivePSWatcher adds Interactive PowerShell Sessions to $SystemWidePSHistoryPath upon 
    # modification of $InteractivePSHistoryPath
    $InteractivePSWatcherScriptBlock = @"
Write-Verbose "The file `$FilesThatChangedFullPath was `$TriggerType at `$TimeStamp"
try {
    `$TryGettingHistory = `$(Get-History)[-1]
}
catch {
    Write-Verbose "Fewer than 1 command has been executed in PowerShell at this time."
}
if (`$TryGettingHistory) {
    if (!`$(Test-Path "$SystemWidePSHistoryPath")) {
        `$(Get-History)[-1] | Export-Csv "$SystemWidePSHistoryPath"
    }
    else {
        `$LastCommandInCsvFormat = `$(Get-History)[-1] | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1
        `$pos = `$LastCommandInCsvFormat.IndexOf(",")
        `$LastCommandWithoutId = `$LastCommandInCsvFormat.Substring(`$pos+1)
        `$LastCommandWithoutIdPrep = `$LastCommandInCsvFormat

        if (`$LastCommandInCsvFormat -ne `$(Get-Content "$SystemWidePSHistoryPath")[-1] -and 
        `$(Get-Content "$SystemWidePSHistoryPath")[-1] -notlike "*`$LastCommandWithoutId" -and 
        `$(Get-Content "$SystemWidePSHistoryPath") -notcontains `$LastCommandInCsvFormat) {
            # Removes Column Headers (i.e. object property names) and appends file at DestPath
            `$(Get-History)[-1] | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content "$SystemWidePSHistoryPath"
        }
    }
}
"@

    <#
    $IPSHParams = @{
        TargetDir = "$InteractivePSHistDir"
        FilesToWatchEasyMatch = "$InteractivePSHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForInteractivePSHistoryChange"
        ActionToTakeScriptBlock = $InteractivePSWatcherScriptBlock
    }
    #>

    $IPSHRunspaceScriptBlock = {
        Register-FileIOWatcher -TargetDir "$InteractivePSHistDir" `
        -FilesToWatchEasyMatch "$InteractivePSHistoryFileName" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForInteractivePSHistoryChange" `
        -ActionToTakeScriptBlock $InteractivePSWatcherScriptBlock -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $IPSHRunspaceScriptBlock


    # The below Register-EngineEvent PowerShell.Exiting adds Uninteractive PowerShell Sessions to $UninteractivePSHistoryPath
    # This should NOT be in a Runspace
    $RegisterEngineEventScriptBlockAsString = @"
if (!`$([Environment]::UserInteractive)) {
    Get-History | Export-Csv $UninteractivePSHistoryPath
    Get-PSSession | Where-Object {`$_.state -ne "Opened"} | Remove-PSSession
}
"@
    $RegisterEngineEventScriptBlock = [scriptblock]::Create($RegisterEngineEventScriptBlockAsString)
    Register-EngineEvent PowerShell.Exiting -Action $RegisterEngineEventScriptBlock | Out-Null

    # The below PSExitActionWatcher adds Uninteractive PowerShell Sessions to $SystemWidePSHistoryPath upon
    # modification of $UninteractivePSHistoryPath
    $PSExitActionWatcherScriptBlock = @"
Write-Verbose "The file `$FilesThatChangedFullPath was `$TriggerType at `$TimeStamp"
if (!`$(Test-Path "$SystemWidePSHistoryPath")) {
    `$(Get-Content `$FilesThatChangedFullPath)[-1] | Set-Content "$SystemWidePSHistoryPath"
}
else {
    # Removes Column Headers (i.e. object property names) and appends file at DestPath
    `$(Get-Content `$FilesThatChangedFullPath)[-1] | Add-Content "$SystemWidePSHistoryPath"
}
"@

    <#
    $UPSHParams = @{
        TargetDir = "$UninteractivePSHistDir"
        FilesToWatchEasyMatch = "$UninteractivePSHistoryFileName"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForUninteractivePSHistoryChange"
        ActionToTakeScriptBlock = $PSExitActionWatcherScriptBlock
    }
    #>

    $UPSHRunspaceScriptBlock = {
        Register-FileIOWatcher -TargetDir "$UninteractivePSHistDir" `
        -FilesToWatchEasyMatch "$UninteractivePSHistoryFileName" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForUninteractivePSHistoryChange" `
        -ActionToTakeScriptBlock $PSExitActionWatcherScriptBlock -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $UPSHRunspaceScriptBlock


     # Start-Transcript writes all of STDOUT from an Interactive PowerShell Session to $PSTranscriptPath
     # ****upon closing the Interactive PowerShell Session.****. This should NOT be in a Runspace.
    if (!$(Test-Path $PSTranscriptPath)) {
        New-Item -Path $PSTranscriptPath -ItemType File
    }
    Start-Transcript -Path $PSTranscriptPath -Append


    # The below SubDirectorySizeWatcher monitors each of the subdirectories under $LogDirectory and ensures each of them
    # stays under the size limit indicated by $SubDirectorySizeLimitInGB by deleting as many of the oldest files as
    # is necessary to bring the size of the given subdirectory back under the $SubDirectorySizeLimitInGB
    $LimitDirSizeFunctionAsString = @'
function Limit-DirectorySize {
    [CmdletBinding(PositionalBinding=$True)]
    Param( 
        [Parameter(Mandatory=$False)]
        $Directory = $(Read-Host -Prompt "Please enter the full path to the directory that will be assigned a size limit."),

        [Parameter(Mandatory=$False)]
        $SizeLimitInGB = $(Read-Host -Prompt "Please enter the maximum size in GB that you would like to allow the directory $Directory to grow to")
    )

    ## BEGIN Native Helper Functions ##

    # The below Convert-Size function is from:
    # http://techibee.com/powershell/convert-from-any-to-any-bytes-kb-mb-gb-tb-using-powershell/2376
    function Convert-Size {
        [cmdletbinding()]
        param(
            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$From,

            [Parameter(Mandatory=$True)]
            [validateset("Bytes","KB","MB","GB","TB")]
            [string]$To,

            [Parameter(Mandatory=$True)]
            [double]$Value,

            [Parameter(Mandatory=$False)]
            [int]$Precision = 4
        )

        switch($From) {
            "Bytes" {$Value = $Value }
            "KB" {$Value = $Value * 1024 }
            "MB" {$Value = $Value * 1024 * 1024}
            "GB" {$Value = $Value * 1024 * 1024 * 1024}
            "TB" {$Value = $Value * 1024 * 1024 * 1024 * 1024}
        }            
                    
        switch ($To) {
            "Bytes" {return $value}
            "KB" {$Value = $Value/1KB}
            "MB" {$Value = $Value/1MB}
            "GB" {$Value = $Value/1GB}
            "TB" {$Value = $Value/1TB}
        }

        return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $DirectoryName = $Directory | Split-Path -Leaf
    $SizeLimitInBytes = Convert-Size -From GB -To Bytes -Value $SizeLimitInGB
    $DirSizeInBytes = $(Get-ChildItem $Directory | Measure-Object -Property Length -sum).sum

    if ( !$($([uri]$Directory).IsAbsoluteURI -and $($([uri]$Directory).IsLoopBack -or $([uri]$Directory).IsUnc)) ) {
        Write-Verbose "$Directory is not a valid directory path! Halting!"
        Write-Error "$Directory is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (! $(Test-Path $Directory)) {
        Write-Verbose "The path $Directory was not found! Halting!"
        Write-Error "The path $Directory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    if ($DirSizeInBytes -gt $SizeLimitInBytes) {
        # Remove as many of the oldest files as necessary to get back under the size limit
        $DifferenceBetweenLimitandActual = $DirSizeInBytes-$SizeLimitInBytes
        $DirContentsOldToNew = Get-ChildItem $Directory | Where-Object {!$_.PSIsContainer} | Sort-Object -Property "LastWriteTime"
        
        $FilesToDeleteArray = @()
        $NewSum = 0
        for ($i=0; $i -lt $DirContentsOldToNew.Count; $i++) {
            if ($NewSum -lt $DifferenceBetweenLimitandActual) {
                $OldSum = $NewSum
                $NewSum = $OldSum+$DirContentsOldToNew[$i].Length
                $FilesToDeleteArray += $($DirContentsOldToNew[$i].FullName)
            }
        }

        foreach ($Item in $FilesToDeleteArray) {
            Remove-Item -Path $Item -Force
        }
    }

    ##### END Main Body #####

}
'@


    $SubDirectorySizeWatcherScriptBlock1 = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $InteractivePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@

    <#
    $IPSHSizeWatcherParams = @{
        TargetDir = "$InteractivePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForInteractivePSHistoryDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock1
    }
    #>

    $IPSHSizeWatcherScriptBlock = {
        Register-FileIOWatcher -TargetDir "$InteractivePSHistDir" `
        -FilesToWatchEasyMatch "*.*" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForInteractivePSHistoryDirSize" `
        -ActionToTakeScriptBlock $SubDirectorySizeWatcherScriptBlock1 -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $IPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock2 = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $UninteractivePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@

    <#
    $UPSHSizeWatcherParams = @{
        TargetDir = "$UninteractivePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForUninteractivePSHistoryDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock2
    }
    #>

    $UPSHSizeWatcherScriptBlock = {
        Register-FileIOWatcher -TargetDir "$UninteractivePSHistDir" `
        -FilesToWatchEasyMatch "*.*" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForUninteractivePSHistoryDirSize" `
        -ActionToTakeScriptBlock $SubDirectorySizeWatcherScriptBlock2 -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $UPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock3 = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $SystemWidePSHistDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@

    <#
    $SWPSHSizeWatcherParams = @{
        TargetDir = "$SystemWidePSHistDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForSystemWidePSHistDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock3
    }
    #>

    $SWPSHSizeWatcherScriptBlock = {
        Register-FileIOWatcher -TargetDir "$SystemWidePSHistDir" `
        -FilesToWatchEasyMatch "*.*" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForSystemWidePSHistDirSize" `
        -ActionToTakeScriptBlock $SubDirectorySizeWatcherScriptBlock3 -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $SWPSHSizeWatcherScriptBlock


    $SubDirectorySizeWatcherScriptBlock4 = @"
$LimitDirSizeFunctionAsString
Limit-DirectorySize -Directory $PSTranscriptDir -SizeLimitInGB $SubDirectorySizeLimitInGB
"@

    <#
    $TranscriptSizeWatcherParams = @{
        TargetDir = "$PSTranscriptDir"
        FilesToWatchEasyMatch = "*.*"
        Trigger = "Changed"
        LogDir = $FileIOWatcherEventLogDir
        FriendlyNameForEvent = "EventForPSTranscriptDirSize"
        ActionToTakeScriptBlock = $SubDirectorySizeWatcherScriptBlock4
    }
    #>

    $TranscriptSizeWatcherScriptBlock = {
        Register-FileIOWatcher -TargetDir "$PSTranscriptDir" `
        -FilesToWatchEasyMatch "*.*" `
        -Trigger "Changed" `
        -LogDir $FileIOWatcherEventLogDir `
        -FriendlyNameForEvent "EventForPSTranscriptDirSize" `
        -ActionToTakeScriptBlock $SubDirectorySizeWatcherScriptBlock4 -Silent
    }
    $ArrayOfFileIOWatcherPSObjects +=, $TranscriptSizeWatcherScriptBlock



    ##### BEGIN RUNSPACES #####

    ##### BEGIN Runspace Manager Runspace #####
    # Thanks to Boe Prox and Stephen Owen for this solution managing multiple Runspaces
    # See: https://foxdeploy.com/2016/05/17/part-v-powershell-guis-responsive-apps-with-progress-bars/

    $script:JobCleanup = [hashtable]::Synchronized(@{})
    $script:Jobs = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $jobCleanup.Flag = $True
    $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
    $RunspaceMgrRunspace.ApartmentState = "STA"
    $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
    $RunspaceMgrRunspace.Open()
    $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobCleanup",$jobCleanup)
    $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$jobs)
    $jobCleanup.PowerShell = [PowerShell]::Create().AddScript({
        # Routine to handle completed Runspaces
        do {
            foreach($runspace in $jobs) {
                if ($runspace.Runspace.isCompleted) {
                    [void]$runspace.PowerShell.EndInvoke($runspace.Runspace)
                    $runspace.PowerShell.Dispose()
                    $runspace.Runspace = $null
                    $runspace.PowerShell = $null
                }
            }
            # Clean Out Unused Runspace Jobs
            $temphash = $jobs.clone()
            $temphash | Where-Object {
                $_.runspace -eq $null
            } | foreach {
                $jobs.remove($_)
            }
            Start-Sleep -Seconds 1
        } while ($jobsCleanup.Flag)
    })
    $jobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
    $jobCleanup.Thread = $jobCleanup.PowerShell.BeginInvoke()

    ##### END Runspace Manager Runspace #####

    ##### BEGIN Setup Runspace Creation Loop #####

    $AllParams = $($PSBoundParameters.GetEnumerator())
    $OtherVarsToPassToRunspaces = @("ConsoleHistDir","ConsoleHistoryFileName","ConsoleHistoryPath","InteractivePSHistoryFileName",
    "InteractivePSHistoryPath","UninteractivePSHistoryFileName","UninteractivePSHistoryPath","SystemWidePSHistoryFileName",
    "SystemWidePSHistoryPath","PSTranscriptFileName","PSTranscriptPath","FileIOWatcherEventLogDir")
    $BlockVarsToPassToRunspaces = @("ConsoleHistoryWatcherScriptBlock","InteractivePSWatcherScriptBlock",
    "PSExitActionWatcherScriptBlock","LimitDirSizeFunctionAsString","SubDirectorySizeWatcherScriptBlock1",
    "SubDirectorySizeWatcherScriptBlock2","SubDirectorySizeWatcherScriptBlock3","SubDirectorySizeWatcherScriptBlock4",
    "IPSHSizeWatcherScriptBlock","UPSHSizeWatcherScriptBlock","SWPSHSizeWatcherScriptBlock","TranscriptSizeWatcherScriptBlock")

    $PSInstanceCollection = @()
    $RunSpaceCollection = @()
    $AsyncHandleCollection = @()
    # Prepare and Create Runspaces for each Excel SpreadSheet
    for ($i=0; $i -lt $ArrayOfFileIOWatcherPSObjects.Count; $i++)
    {
        New-Variable -Name "syncHash$i" -Value $([hashtable]::Synchronized(@{}))
        $syncHashCollection +=, $(Get-Variable -Name "syncHash$i" -ValueOnly)

        New-Variable -Name "Runspace$i" -Value $([runspacefactory]::CreateRunspace())
        $(Get-Variable -Name "Runspace$i" -ValueOnly).ApartmentState = "STA"
        $(Get-Variable -Name "Runspace$i" -ValueOnly).ThreadOptions = "ReuseThread"
        $(Get-Variable -Name "Runspace$i" -ValueOnly).Open()
        # Pass all function Parameters to the Runspace
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("AllParams",$AllParams)
        foreach ($ParamKVP in $AllParams) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("$($ParamKVP.Key)",$(Get-Variable -Name "$($ParamKVP.Key)" -ValueOnly))
        }
        # Pass all other needed Variables to the Runspace
        foreach ($VarName in $OtherVarsToPassToRunspaces) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable($VarName,$(Get-Variable -Name $VarName -ValueOnly))
        }
        foreach ($VarName1 in $BlockVarsToPassToRunspaces) {
            $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable($VarName1,$(Get-Variable -Name $VarName1 -ValueOnly))
        }
        # Pass syncHash$i to the Runspace
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("syncHash",$(Get-Variable -Name "syncHash$i" -ValueOnly))
        # Pass Runspace Manager Synchronized Hashtable and Synctronized Arraylist
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("JobCleanup",$script:JobCleanup)
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("Jobs",$script:Jobs)
        # Pass the Register-FileIOWatcher ScriptBlock to the Runspace
        #$(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("FileIOWatcherEventLogDir",$FileIOWatcherEventLogDir)
        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("FileIOWatcherScriptBlock",$ArrayOfFileIOWatcherPSObjects[$i])


        New-Variable -Name "PSInstance$i" -Value $([System.Management.Automation.PowerShell]::Create())
        $(Get-Variable -Name "PSInstance$i" -ValueOnly).AddScript({
            ## BEGIN Main Code to run in Runspace ##

            $syncHash.CompleteFlag = "Working"
            
            # Re-Import Any PS Modules

            # Run the FileIO Watcher ScriptBlock
            Invoke-Expression "$FileIOWatcherScriptBlock"

            $syncHash.CompleteFlag = "Complete"

            ## END Main Code to run in Runspace ##
        })

        # Start the Runspace in the PSInstance
        $(Get-Variable -Name "PSInstance$i" -ValueOnly).Runspace = $(Get-Variable -Name "Runspace$i" -ValueOnly)
        New-Variable -Name "AsyncHandle$i" -Value $($(Get-Variable -Name "PSInstance$i" -ValueOnly).BeginInvoke())

        $RunSpaceCollection +=, $(Get-Variable -Name "Runspace$i" -ValueOnly)
        $PSInstanceCollection +=, $(Get-Variable -Name "PSInstance$i" -ValueOnly)
        $AsyncHandleCollection +=, $(Get-Variable -Name "AsyncHandle$i" -ValueOnly)

        # Add the $PSInstance$i Job (with its accompanying $PSInstance$i.Runspace) to the array of jobs (i.e. $script.Jobs)
        # that the Runspace Manager Runspace is handling
        $script:Jobs +=, $(Get-Variable -Name "PSInstance$i" -ValueOnly)
    }

    ##### END Setup Runspace Creation Loop #####

    ##### END RUNSPACES #####


    ##### END Main Body #####

}


# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUvKij2lnsw4EzgbOmYyOTk0r
# T1ygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS5bv2PgWiY
# wlhtWwgeKLm1V50EMjANBgkqhkiG9w0BAQEFAASCAQA2K6CLLiYo7YrPsnS6uMMn
# XSd7J+f6bfCxzJpvcCAiVzUzUdQRNS7mg/gGFhyDwmGOw3QQ5gVtOJTPpklkX2av
# 9Q8jfP7RHQfZ09P0ETCoY8+rFvzilNQqOZwszTWQufC+R32W7Onvi7kLtlL4nISF
# WKvdgQSRlAQLRNV1DoyM/cMjjih5NF4LFkXp+a+95bCYDzHrhyEBEnYGTRYhqKP0
# kYbJuubyJGlfHzuSqbVNx1AF6Kr5kDW3BF+p65IHrNVV+0MXlfPmi2YPsIRSUizU
# amunNy/7aKgpTELnzcryjAqSCqEiyO04SDjfqTfGiTVVPOYEKlvTEYysm2zuAUJ1
# SIG # End signature block
