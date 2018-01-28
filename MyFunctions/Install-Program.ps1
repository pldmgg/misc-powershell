<#
    .SYNOPSIS
        Install a Program using PackageManagement/PowerShellGet OR the Chocolatey Cmdline.

    .DESCRIPTION
        This function was written to make program installation on Windows as easy and generic
        as possible by leveraging existing solutions such as PackageManagement/PowerShellGet
        and the Chocolatey CmdLine.

        The function defaults to using PackageManagement/PowerShellGet. If that fails for
        whatever reason, then the Chocolatey CmdLine is used. You can also use appropriate
        parameters to specifically use EITHER PackageManagement/PowerShellGet OR the
        Chocolatey CmdLine

    .PARAMETER ProgramName
        This parameter is MANDATORY.

        This paramter takes a string that represents the name of the program that you'd like to install.

    .PARAMETER UsePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch that makes the function attempt program installation using ONLY
        PackageManagement/PowerShellGet Modules. Install using those modules fails for whatever
        reason, the function halts and returns the relevant error message(s).

        Installation via the Chocolatey CmdLine will NOT be attempted.

    .PARAMETER UseChocolateyCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch that makes the function attemt program installation using ONLY
        the Chocolatey CmdLine. If installation via the Chocolatey CmdLine fails for whatever reason,
        the function halts and returns the relevant error message(s)

    .PARAMETER ExpectedInstallLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a directory that contains the
        main executable for the installed program. This directory does NOT have to be the immediate
        parent directory of the .exe.

        If you are absolutely certain you know where on the filesystem the program will be installed,
        then use this parameter to speed things up.

    .PARAMETER CommandName
        This parameter is OPTIONAL.

        This parameter takes a string that represents the name of the main executable for the installed
        program. For example, if you are installing 7zip, the value of this parameter should be (under
        most circumstances) '7z'.

    .PARAMETER NoUpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch that suppresses this function's default behavior, which is to try
        and update PackageManagement/PowerShellGet Modules before attempting to use them to install
        the desired program. Updating these modules can take up to a minute, so use this switch
        if you want to skip the attempt to update.

    .EXAMPLE
        Install-Program -ProgramName kubernetes-cli -CommandName kubectl.exe

    .EXAMPLE
        Install-Program -ProgramName awscli -CommandName aws.exe -UsePackageManagement

    .EXAMPLE
        Install-Program -ProgramName VisualStudioCode -CommandName Code.exe -UseChocolateyCmdLine

    .EXAMPLE
        # If the Program Name and Main Executable are the same, then this is all you need...
        Install-Program -ProgramName vagrant

#>
function Install-Program {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [string]$CommandName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePackageManagement,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$ForceChocoInstallScript,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [string]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$ScanCDriveForMainExeIfNecessary
    )

    ##### BEGIN Native Helper Functions #####

    # The below function adds Paths from System PATH that aren't present in $env:Path (this probably shouldn't
    # be an issue, because $env:Path pulls from System PATH...but sometimes profile.ps1 scripts do weird things
    # and also $env:Path wouldn't necessarily be updated within the same PS session where a program is installed...)
    function Synchronize-SystemPathEnvPath {
        $SystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        
        $SystemPathArray = $SystemPath -split ";" | foreach {if ($_ -match "[\w]") {$_}}
        $EnvPathArray = $env:Path -split ";" | foreach {if ($_ -match "[\w]") {$_}}
        
        # => means that $EnvPathArray HAS the paths but $SystemPathArray DOES NOT
        # <= means that $SystemPathArray HAS the paths but $EnvPathArray DOES NOT
        $PathComparison = Compare-Object $SystemPathArray $EnvPathArray
        [System.Collections.ArrayList][Array]$SystemPathsThatWeWantToAddToEnvPath = $($PathComparison | Where-Object {$_.SideIndicator -eq "<="}).InputObject

        if ($SystemPathsThatWeWantToAddToEnvPath.Count -gt 0) {
            foreach ($NewPath in $SystemPathsThatWeWantToAddToEnvPath) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$NewPath"
                }
                else {
                    $env:Path = "$env:Path;$NewPath"
                }
            }
        }
    }

    # Outputs [System.Collections.ArrayList]$ExePath
    function Adjudicate-ExePath {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$ProgramName,

            [Parameter(Mandatory=$True)]
            [string]$OriginalSystemPath,

            [Parameter(Mandatory=$True)]
            [string]$OriginalEnvPath,

            [Parameter(Mandatory=$True)]
            [string]$FinalCommandName,

            [Parameter(Mandatory=$False)]
            [string]$ExpectedInstallLocation
        )

        # ...search for it in the $ExpectedInstallLocation if that parameter is provided by the user...
        if ($ExpectedInstallLocation) {
            [System.Collections.ArrayList][Array]$ExePath = $(Get-ChildItem -Path $ExpectedInstallLocation -File -Recurse -Filter "*$FinalCommandName.exe").FullName
        }
        # If we don't have $ExpectedInstallLocation provided...
        if (!$ExpectedInstallLocation) {
            # ...then we can compare $OriginalSystemPath to the current System PATH to potentially
            # figure out which directories *might* contain the main executable.
            $OriginalSystemPathArray = $OriginalSystemPath -split ";" | foreach {if ($_ -match "[\w]") {$_}}
            $OriginalEnvPathArray = $OriginalEnvPath -split ";" | foreach {if ($_ -match "[\w]") {$_}}

            $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            $CurrentSystemPathArray = $CurrentSystemPath -split ";" | foreach {if ($_ -match "[\w]") {$_}}
            $CurrentEnvPath = $env:Path
            $CurrentEnvPathArray = $CurrentEnvPath -split ";" | foreach {if ($_ -match "[\w]") {$_}}
            

            $OriginalVsCurrentSystemPathComparison = Compare-Object $OriginalSystemPathArray $CurrentSystemPathArray
            $OriginalVsCurrentEnvPathComparison = Compare-Object $OriginalEnvPathArray $CurrentEnvPathArray

            [System.Collections.ArrayList]$DirectoriesToSearch = @()
            if ($OriginalVsCurrentSystemPathComparison -ne $null) {
                # => means that $CurrentSystemPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewSystemPathDirs = $($OriginalVsCurrentSystemPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewSystemPathDirs.Count -gt 0) {
                    foreach ($dir in $NewSystemPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }
            if ($OriginalVsCurrentEnvPathComparison -ne $null) {
                # => means that $CurrentEnvPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewEnvPathDirs = $($OriginalVsCurrentEnvPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewEnvPathDirs.Count -gt 0) {
                    foreach ($dir in $NewEnvPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }

            if ($DirectoriesToSearch.Count -gt 0) {
                $DirectoriesToSearchFinal = $($DirectoriesToSearch | Sort-Object | Get-Unique) | foreach {if (Test-Path $_) {$_}}
                $DirectoriesToSearchFinal = $DirectoriesToSearchFinal | Where-Object {$_ -match "$ProgramName"}

                [System.Collections.ArrayList]$ExePath = @()
                foreach ($dir in $DirectoriesToSearchFinal) {
                    [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*$FinalCommandName.exe").FullName
                    if ($ExeFiles.Count -gt 0) {
                        $null = $ExePath.Add($ExeFiles)
                    }
                }

                # If there IS a difference in original vs current System PATH / $Env:Path, but we 
                # still DO NOT find the main executable in those diff directories (i.e. $ExePath is still not set),
                # it's possible that the name of the main executable that we're looking for is actually
                # incorrect...in which case just tell the user that we can't find the expected main
                # executable name and provide a list of other .exe files that we found in the diff dirs.
                if (!$ExePath -or $ExePath.Count -eq 0) {
                    [System.Collections.ArrayList]$ExePath = @()
                    foreach ($dir in $DirectoriesToSearchFinal) {
                        [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*.exe").FullName
                        foreach ($File in $ExeFiles) {
                            $null = $ExePath.Add($File)
                        }
                    }
                }
            }
        }

        $ExePath | Sort-Object | Get-Unique
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($UseChocolateyCmdLine) {
        $NoUpdatePackageManagement = $True
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $null = Update-PackageManagement -UseChocolatey -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($UPMErr -and $global:FunctionResult-eq "1") {throw}
        }
        catch {
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            foreach ($error in $UPMErr) {Write-Error $($error | Out-String)}
            Write-Error "The Update-PackageManagement function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UseChocolateyCmdLine -or $(!$UsePackageManagement -and !$UseChocolateyCmdLine)) {
        if (![bool]$(Get-Command Install-ChocolateyCmdLine -ErrorAction SilentlyContinue)) {
            $InstallCCFunctionUrl = "$MyFunctionsUrl/Install-ChocolateyCmdLine.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallCCFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Install-ChocolateyCmdLine function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If the Chocolatey CmdLine is installed, get a list of programs installed via Chocolatey
    if ([bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        $ChocolateyInstalledProgramsPrep = clist --local-only
        $ChocolateyInstalledProgramsPrep = $ChocolateyInstalledProgramsPrep[1..$($ChocolateyInstalledProgramsPrep.Count-2)]

        [System.Collections.ArrayList]$ChocolateyInstalledProgramsPSObjects = @()

        foreach ($program in $ChocolateyInstalledProgramsPrep) {
            $programParsed = $program -split " "
            $PSCustomObject = [pscustomobject]@{
                ProgramName     = $programParsed[0]
                Version         = $programParsed[1]
            }

            $null = $ChocolateyInstalledProgramsPSObjects.Add($PSCustomObject)
        }
    }

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }

    $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}

    # Save the original System PATH and $env:Path before we do anything, just in case
    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalEnvPath = $env:Path

    Synchronize-SystemPathEnvPath

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install $ProgramName if it's not already...
    if (![bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue) -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) {
        if ($UsePackageManagement -or $(!$UsePackageManagement -and !$UseChocolateyCmdLine)) {
            # NOTE: The PackageManagement install of $ProgramName is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package $ProgramName -Force -ErrorVariable InstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            if ($InstallError.Count -gt 0) {
                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                Write-Warning "There was a problem installing $ProgramName via PackageManagement/PowerShellGet!"
                
                if ($UsePackageManagement) {
                    Write-Error "One or more errors occurred during the installation of $ProgramName via the the PackageManagement/PowerShellGet Modules failed! Installation has been rolled back! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Trying install via Chocolatey CmdLine..."
                    $PMInstall = $False
                }
            }
            else {
                $PMInstall = $True

                # Since Installation via PackageManagement/PowerShellGet was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
            }
        }

        if (!$PMInstall -or $UseChocolateyCmdLine) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr

                # The first time we attempt to Refresh-ChocolateyEnv, Chocolatey CmdLine and/or the
                # Chocolatey Package Provider legitimately might not be installed,
                # so if the Refresh-ChocolateyEnv function throws that error, we can ignore it
                if ($RCEErr.Count -gt 0 -and
                $global:FunctionResult -eq "1" -and
                ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                    throw
                }
            }
            catch {
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                foreach ($error in $RCEErr) {Write-Error $($error | Out-String)}
                Write-Error "The Refresh-ChocolateyEnv function failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            # Make sure Chocolatey CmdLine is installed...if not, install it
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $global:FunctionResult = "0"
                    $null = Install-ChocolateyCmdLine -NoUpdatePackageManagement -ErrorAction SilentlyContinue -ErrorVariable ICCErr
                    if ($ICCErr -and $global:FunctionResult -eq "1") {throw}
                }
                catch {
                    Write-Host "Errors from the Install-ChocolateyCmdline function are as follows:"
                    foreach ($error in $ICCErr) {Write-Error $($error | Out-String)}
                    Write-Error "The Install-ChocolateyCmdLine function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            try {
                # TODO: Figure out how to handle errors from choco.exe. Some we can ignore, others
                # we shouldn't. But I'm not sure what all of the possibilities are so I can't
                # control for them...
                $null = cup $ProgramName -y
                $ChocoInstall = $true

                # Since Installation via the Chocolatey CmdLine was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
            }
            catch {
                Write-Error "There was a problem installing $ProgramName using the Chocolatey cmdline! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        
        ## BEGIN Try to Find Main Executable Post Install ##

        # Now the parent directory of $ProgramName's main executable should be part of the SYSTEM Path
        # (and therefore part of $env:Path). If not, try to find it in Chocolatey directories...
        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {throw}
            }
            catch {
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                foreach ($error in $RCEErr) {Write-Error $($error | Out-String)}
                Write-Error "The Refresh-ChocolateyEnv function failed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # If we still can't find the main executable...
        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) {
            if ($ExpectedInstallLocation) {
                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
            }
            else {
                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
            }
        }
        
        # If we STILL can't find the main executable...
        if ($(![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) -or $ForceChocoInstallScript) {
            # If, at this point we don't have $ExePath, if we did a $ChocoInstall, then we have to give up...
            # ...but if we did a $PMInstall, then it's possible that PackageManagement/PowerShellGet just
            # didn't run the chocolateyInstall.ps1 script that sometimes comes bundled with Packages from the
            # Chocolatey Package Provider/Repo. So try running that...
            if (!$ExePath -or $ExePath.Count -eq 0 -or $ForceChocoInstallScript) {
                if ($ChocoInstall) {
                    Write-Warning "Unable to find main executable for $ProgramName!"
                    $MainExeSearchFail = $True
                }
                if ($PMInstall -or $($PMInstall -and $ForceChocoInstallScript)) {
                    [System.Collections.ArrayList]$PossibleChocolateyInstallScripts = @()
                    
                    if (Test-Path "C:\Chocolatey") {
                        $ChocoScriptsA = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1"
                        foreach ($Script in $ChocoScriptsA) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }
                    if (Test-Path "C:\ProgramData\chocolatey") {
                        $ChocoScriptsB = Get-ChildItem -Path "C:\ProgramData\chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1"
                        foreach ($Script in $ChocoScriptsB) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }

                    [System.Collections.ArrayList][Array]$ChocolateyInstallScriptSearch = $PossibleChocolateyInstallScripts.FullName | Where-Object {$_ -match ".*?$ProgramName.*?chocolateyinstall.ps1$"}
                    if ($ChocolateyInstallScriptSearch.Count -eq 0) {
                        Write-Warning "Unable to find main the Chocolatey Install Script for $ProgramName PowerShellGet install!"
                        $MainExeSearchFail = $True
                    }
                    if ($ChocolateyInstallScriptSearch.Count -eq 1) {
                        $ChocolateyInstallScript = $ChocolateyInstallScriptSearch[0]
                    }
                    if ($ChocolateyInstallScriptSearch.Count -gt 1) {
                        $ChocolateyInstallScript = $($ChocolateyInstallScriptSearch | Sort-Object LastWriteTime)[-1]
                    }
                    
                    if ($ChocolateyInstallScript) {
                        try {
                            Write-Host "Trying the Chocolatey Install script from $ChocolateyInstallScript..." -ForegroundColor Yellow
                            & $ChocolateyInstallScript

                            # Now that the $ChocolateyInstallScript ran, search for the main executable again
                            Synchronize-SystemPathEnvPath

                            if ($ExpectedInstallLocation) {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                            }
                            else {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                            }

                            # If we STILL don't have $ExePath, then we have to give up...
                            if (!$ExePath -or $ExePath.Count -eq 0) {
                                Write-Warning "Unable to find main executable for $ProgramName!"
                                $MainExeSearchFail = $True
                            }
                        }
                        catch {
                            Write-Error $_
                            Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                            # If PackageManagement/PowerShellGet is ERRONEOUSLY reporting that the program was installed
                            # use the Uninstall-Package cmdlet to wipe it out. This scenario happens when PackageManagement/
                            # PackageManagement/PowerShellGet gets a Package from the Chocolatey Package Provider/Repo but
                            # fails to run the chocolateyInstall.ps1 script for some reason.
                            if ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
                                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                            }

                            # Now we need to try the Chocolatey CmdLine. Easiest way to do this at this point is to just
                            # invoke the function again with the same parameters, but specify -UseChocolateyCmdLine
                            $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
                            $InstallProgramSplatParams = @{}
                            foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
                                $key = $kvpair.Key
                                $value = $BoundParametersDictionary[$key]
                                if ($key -notmatch "UsePackageManagement|ForceChocoInstallScript" -and $InstallProgramSplatParams.Keys -notcontains $key) {
                                    $InstallProgramSplatParams.Add($key,$value)
                                }
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "UseChocolateyCmdLine") {
                                $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "NoUpdatePackageManagement") {
                                $InstallProgramSplatParams.Add("NoUpdatePackageManagement",$True)
                            }
                            Install-Program @InstallProgramSplatParams

                            return
                        }
                    }
                }
            }
        }

        ## END Try to Find Main Executable Post Install ##
    }
    else {
        if ($ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName) {
            Write-Warning "$ProgramName is already installed via the Chocolatey CmdLine!"
        }
        elseif ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
            Write-Warning "$ProgramName is already installed via PackageManagement/PowerShellGet!"
        }
    }

    # If we weren't able to find the main executable (or any potential main executables) for
    # $ProgramName, offer the option to scan the whole C:\ drive (with some obvious exceptions)
    if ($MainExeSearchFail) {
        if (!$ScanCDriveForMainExeIfNecessary) {
            $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            while ($ScanCDriveChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$ScanDriveChoice is not a valid input. Please enter 'Yes' or 'No'"
                $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            }
        }

        if ($ScanCDriveChoice -match "Yes|yes|Y|y" -or $ScanCDriveForMainExeIfNecessary) {
            Write-Host "Searching for the newly installed $FinalCommandName.exe...Please wait..."
            $DirectoriesToSearchRecursively = $(Get-ChildItem -Path "C:\" -Directory | Where-Object {$_.Name -notmatch "Windows|PerfLogs|Microsoft"}).FullName
            [System.Collections.ArrayList]$ExePath = @()
            foreach ($dir in $DirectoriesToSearchRecursively) {
                $FoundFiles = $(Get-ChildItem -Path $dir -Recurse -File).FullName
                foreach ($FilePath in $FoundFiles) {
                    if ($FilePath -match "(.*?)$FinalCommandName([^\\]+)") {
                        $null = $ExePath.Add($FilePath)
                    }
                }
            }
        }
    }

    # Finalize $env:Path
    if ([bool]$($ExePath -match "\\cmake.exe$")) {
        $PathToAdd = $($ExePath -match "\\cmake.exe$") | Split-Path -Parent
        if ($($env:Path -split ";") -notcontains $PathToAdd) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path" + $PathToAdd + ";"
            }
            else {
                $env:Path = "$env:Path" + ";" + $PathToAdd
            }
        }
    }
    $FinalEnvPathArray = $env:Path -split ";" | foreach {if($_ -match "[\w]") {$_}}
    $FinalEnvPathString = $($FinalEnvPathArray | foreach {if (Test-Path $_) {$_}}) -join ";"
    $env:Path = $FinalEnvPathString

    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
        # Try to determine Main Executable
        if (!$ExePath -or $ExePath.Count -eq 0) {
            $FinalExeLocation = "NotFound"
        }
        elseif ($ExePath.Count -eq 1) {
            $UpdatedFinalCommandName = $ExePath | Split-Path -Leaf

            try {
                $FinalExeLocation = $(Get-Command $UpdatedFinalCommandName -ErrorAction SilentlyContinue).Source
            }
            catch {
                $FinalExeLocation = $ExePath
            }
        }
        elseif ($ExePath.Count -gt 1) {
            if (![bool]$($ExePath -match "\\cmake.exe$")) {
                Write-Warning "No exact match for main executable $FinalCommandName.exe was found. However, other executables associated with $ProgramName were found."
            }
            $FinalExeLocation = $ExePath
        }
    }
    else {
        $FinalExeLocation = $(Get-Command $FinalCommandName).Source
    }

    if ($ChocoInstall -or $(clist --local-only) -match $ProgramName) {
        $InstallManager = "choco.exe"
        $InstallCheck = $(clist --local-only $ProgramName)[1]
    }
    if ($PMInstall -or [bool]$(Get-Package $ProgramName -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
        $InstallManager = "PowerShellGet"
        $InstallCheck = Get-Package $ProgramName -ErrorAction SilentlyContinue
    }

    [pscustomobject]@{
        InstallManager      = $InstallManager
        InstallCheck        = $InstallCheck
        MainExecutable      = $FinalExeLocation
        OriginalSystemPath  = $OriginalSystemPath
        CurrentSystemPath   = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        OriginalEnvPath     = $OriginalEnvPath
        CurrentEnvPath      = $env:Path
    }

    ##### END Main Body #####
}






































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUn4bFa+nfWYzUnhw1riDHBQCQ
# 2r+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOFBJ1AHqfT9Qh5L
# 7eykZWjlVfYCMA0GCSqGSIb3DQEBAQUABIIBAG4vgAtoaS6GFGP9AGvzD6zxFYWA
# XI7RFhnQCtTbfmr5HjZ7iZBVdQn1rQe6ImhUAG6fBYodbAGOF+rrsP2U0ZR8RE/r
# cGd7SjW9CxT4FO/JOvcnfhD6raaGFWcAga9lbCYkHHh4MJ8gyIqNjTDXd0O+tvuu
# ea/cmfcD2nh/3H9Zf3UVRi7I5NwP+D/0IFKM8k1IlHQCMyO+7uh+0RE8kDiQOVyR
# H4QcKaOEE94hUvTDj+ljdbW+2i40bUJa+YwL4I1G+F/e1NcF1Kk3YcGwL1jQEsSo
# C8j9NILYq8H26zt1aHrU0N6ApXSZJElwczomoxO+iq4aQzXt5jq+AqsCGr4=
# SIG # End signature block
