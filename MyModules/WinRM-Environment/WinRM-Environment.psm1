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

function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

# The below Unzip-File function is only used in the event that you want that you want to edit a file
# (be it local or remote) *within* the PowerShell console using the Edit-FileWinRM function. It is used
# to unzip the "Vim For Windows" zip file that is downloaded by the Edit-FileWinRM function if the
# -EditInConsole parameter is specified.
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

    $ZipFileNameWExt = $(Get-ChildItem $PathToZip).name

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

        foreach($searchitem in $SpecificItem) {
            [array]$potentialItems = foreach ($item in $ZipSubItems) {
                if ($($item.Path -split "$ZipFileNameWExt\\")[-1] -match "$searchitem") {
                    $item
                }
            }

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


# The below Write-WelcomeMessage function is used solely in the New-InteractivePSSession function
function Write-WelcomeMessage {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession
    )

    $SetupScriptBlock = @"
function Get-Elevation {
    [System.Security.Principal.WindowsPrincipal]`$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
         [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )

   [System.Security.Principal.WindowsBuiltInRole]`$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

   if(`$currentPrincipal.IsInRole(`$administratorsRole)) {
      return `$true;
   }
   else {
      return `$false;
   }
}

if (Get-Elevation) {
    `$PowerShellUserAccount = "ELEVATED `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}
else {
    `$PowerShellUserAccount = `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
}

Get-Date
Write-Host "``nYou are `$PowerShellUserAccount on `$env:COMPUTERNAME`n"

"@

    [System.Collections.ArrayList]$ScriptBlockPrepArrayOfLines = $SetupScriptBlock -split "`n"

    $ScriptBlockFinalString = $ScriptBlockPrepArrayOfLines | Out-String
    New-Variable -Name "ScriptBlock$($PSSession.Name)" -Scope Local -Value $([scriptblock]::Create($ScriptBlockFinalString))

    $InvokeCommandString = 'Invoke-Command -Session $PSSession -ScriptBlock $(Get-Variable -Name "ScriptBlock$($PSSession.Name)" -ValueOnly)'
    Invoke-Expression $InvokeCommandString
}


# The below Initialize-PSProfileInRemoteSession use Get-Content to read the specified profile.ps1 into memory and then
# load it in the Remote PSSession.
# File Transfers Possible? = FALSE
function Initialize-PSProfileInRemoteSession {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

         # Below $ProfileToLoadOnRemoteHost must be a full file path to an existing file on the Remote Host
        [Parameter(Mandatory=$True)]
        [string]$ProfileToLoadOnRemoteHost = $(Read-Host -Prompt "Please enter the full file path to the profile.ps1 on the Local Host that you would like to load in the Remote PSSession on the Remote Host.")
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $ProfileToLoadOnRemoteHost)) {
        Write-Verbose "The path $ProfileToLoadOnRemoteHost was not found! Halting!"
        Write-Error "The path $ProfileToLoadOnRemoteHost was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $ProfileToLoadOnRemoteHost = $(Resolve-Path -Path $ProfileToLoadOnRemoteHost).Path
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $ScriptBlockString = Get-Content $ProfileToLoadOnRemoteHost | Out-String
    $FinalScriptBlock = [scriptblock]::Create($ScriptBlockString)

    Invoke-Command -Session $PSSession -ScriptBlock $FinalScriptBlock

    ##### END Main Body #####
}


<#
.SYNOPSIS
    The Initialize-ModulesInRemoteSession function loads the specified Modules that are loaded in the Local Session in the Remote
    PSSession, where the terms Local and Remote are context sensitive. In other words LocalHost can be thought of as
    $env:COMPUTERNAME and RemoteHost can be thought of as a machine *other than* $env:COMPUTERNAME (precluding
    the unlikely circumstance in which $env:COMPUTERNAME is manually changed for some strange reason. That
    being said, the function is NOT dependent on the value of $env:COMPUTERNAME).

    Before loading modules in ther Remote Session, the function determines which host (Local or Remote) has the
    latest version of a given Module and ensures that the latest version is the one loaded in the Remote PSSession.
    This could involve transferring the Module directory and its contents from the Local Host to the Remote Host
    filesystem.

.DESCRIPTION
    See SYNOPSIS. For more specific information, see the LocalModulesToIncludeInRemoteSession parameter.

.PARAMETER PSSession
    MANDATORY

    This parameter takes a System.Management.Automation.Runspaces.PSSession.

.PARAMETER LocalModulesToIncludeInRemoteSession
    OPTIONAL

    This parameter takes an array of strings that represent the names of PowerShell Modules that 
    are currently loaded in the local session that the user would like loaded in the Remote PSSession.
    If the referenced Module(s) are NOT already loaded in the local session or do not exist locally,
    the function ignores those references.

    Before any of the referenced locally-loaded Modules are forwarded to the Remote PSSession, this function
    checks to see if the referenced Module is ALREADY loaded and/or AVAILABLE in the Remote PSSession.

    If the local Module is loaded or available on the Remote Host, but the version number of the Module on
    the Remote Host is older than the local Module, this function  COPIES THE LOCAL DIRECTORY to the
    Remote Host and places it under $HOME\Documents\WindowsPowerShell\Modules. This will OVERWRITE the old version
    of the Module on the Remote Host.

    If the locally-loaded Module is loaded or available on the Remote Host, but the Remote Host has the latest version
    of the Module, the latest version will simply be loaded in the Remote PSSession and no file transfers will occur.

    If the locally-loaded Module is NOT loaded on the Remote Host BUT IS available on the Remote Host, this function
    determines which host has the latest version and acts according to the behavior previously outlined.

    If the locally-loaded Module is NOT loaded on the Remote Host and IS NOT available on the Remote Host, this function
    COPIES THE LOCAL DIRECTORY to the Remote Host and places it under $HOME\Documents\WindowsPowerShell\Modules.

    IMPORTANT NOTE: If neither the LocalModulesToIncludeFromRemoteSession nor LocalModulesToExcludeFromRemoteSession
    parameters are used, ALL locally-loaded Modules are loaded in the Remote PSSession.

.PARAMETER LocalModulesToExcludeFromRemoteSession
    OPTIONAL

    This parameter takes an array of strings that represent the names of PowerShell Modules that 
    are currently loaded in the local session that the user DOES NOT want loaded in the Remote PSSession.
    The latest version of the remainder of locally-loaded Modules are loaded in the Remote PSSession.
    Note that the latest version may already be on the Remote Host.

    If any Modules referenced by this parameter are NOT loaded locally, they will be ignored.

    The logic explained in the LocalModulesToIncludeInRemoteSession parameter is then applied to the 
    locally-loaded Modules that have NOT been explicitly excluded by this parameter. 


.PARAMETER WinRMEnvironmentOnly
    OPTIONAL

    This parameter is a switch. If it is used, ONLY this WinRM-Environment Module along with its dependencies
    are loaded in the Remote-PSSession. Currently, the WinRM-Environment Module's only dependency is
    the UserSessionEx Module.

.PARAMETER ForceSend
    OPTIONAL

    This parameter is a switch. If used, the locally-loaded Module will be copied to the Remote Host
    regardless of whether or not it could overwrite a version the same Module on the Remote Host, and regardless
    of the version that may already be on the Remote Host. 

.EXAMPLE
    $LocalVarsToForwardToRemoteSession = @("ArrayOfBeerNames","FoodPriceHashtable")

    Send-LocalObjects -PSSession $FileSharingSession -LocalVarsToForward $LocalVarsToForwardToRemoteSession
#>
function Initialize-ModulesInRemoteSession {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$False)]
        [string[]]$LocalModulesToIncludeInRemoteSession, # Takes an array of strings representing Module Names

        [Parameter(Mandatory=$False)]
        [string[]]$LocalModulesToExcludeFromRemoteSession, # Takes an array of strings representing Module Names

        [Parameter(Mandatory=$False)]
        [switch]$WinRMEnvironmentOnly,

        [Parameter(Mandatory=$False)]
        [switch]$ForceSend
    )

    # Check username and home path for $PSSession
    $RemoteHostHomePath = Invoke-Command -Session $PSSession -ScriptBlock {$HOME}
    $RemoteHostUser = $PSSession.Runspace.ConnectionInfo.Credential.UserName
    $RemoteHost = $PSSession.ComputerName

    # Define Modules in Current Session
    $CurrentLocalLoadedModules = Get-Module
    # Define Modules to Load in Remote Session
    if ($WinRMEnvironmentOnly) {
        $ThisModule = $ExecutionContext.SessionState.Module
        $ThisModuleDependencies = $ThisModule.RequiredModules
        $ModulesToLoadOnRemoteHost = @()
        # NOTE: We MUST load WinRMEnvironment Module Dependencies BEFORE the WinRMEnvironment Module, so
        # the dependency module objects must be added to the array first...
        foreach ($DepMod in $ThisModuleDependencies) {
            $ModulesToLoadOnRemoteHost +=, $DepMod
        }
        $ModulesToLoadOnRemoteHost +=, $ThisModule
    }
    if ($LocalModulesToIncludeInRemoteSession) {
        $ModulesToLoadOnRemoteHost = foreach ($Module in $CurrentLocalLoadedModules) {
            if ($LocalModulesToIncludeInRemoteSession -contains $Module.Name) {
                $Module
            }
        }
    }
    if ($LocalModulesToExcludeInRemoteSession) {
        $ModulesToLoadOnRemoteHost = foreach ($Module in $CurrentLocalLoadedModules) {
            if ($LocalModulesToExcludeInRemoteSession -notcontains $Module.Name) {
                $Module
            }
        }
    }
    if (!$WinRMEnvironmentOnly -and !$LocalModulesToExcludeInRemoteSession -and !$LocalModulesToIncludeInRemoteSession) {
        $ModulesToLoadOnRemoteHost = $CurrentLocalLoadedModules
    }

    # Get this Module's Name
    # In this context $PSScriptRoot returns the Module's Directory, NOT any .psm1 files
    # $PSScriptRoot
    # In this context, $PSCommandPath returns the full path to this file
    # $PSCommandPath
    # $ModuleName = $ExecutionContext.SessionState.Module.Name
    # $ThisModule = Get-Module $ModuleName
    # $ModuleDirectoryPath = $(Get-Module $ModuleName).ModuleBase
    # $ModuleDependenciesArrayOfDirPaths = $(Get-Module $ModuleName).RequiredModules.ModuleBase

    $RemoteModuleStatusScriptBlock = {
        $ModuleStatusCollection = @()
        foreach ($Module in $using:ModulesToLoadOnRemoteHost) {
            if ($(Get-Module | Where-Object {$_.Name -eq $Module.Name}) -eq $null) {
                if ($(Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module.Name}) -eq $null) {
                    New-Variable -Name "$($Module.Name)" -Value $(
                        [pscustomobject][ordered]@{
                            ModuleName   = "$($Module.Name)"
                            Status       = "NotAvailable"
                        }
                    ) -Force

                    $ModuleStatusCollection +=, $(Get-Variable -Name "$($Module.Name)" -ValueOnly)
                }
                else {
                    if ($(Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module.Name}).Version -lt $Module.Version) {
                        New-Variable -Name "$($Module.Name)" -Value $(
                            [pscustomobject][ordered]@{
                                ModuleName   = "$($Module.Name)"
                                Status       = "NeedsUpdate"
                                ModuleObject = Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module.Name}
                            }
                        ) -Force

                        $ModuleStatusCollection +=, $(Get-Variable -Name "$($Module.Name)" -ValueOnly)
                    }
                    else {
                        New-Variable -Name "$($Module.Name)" -Value $(
                            [pscustomobject][ordered]@{
                                ModuleName   = "$($Module.Name)"
                                Status       = "AlreadyLatest"
                                ModuleObject = Get-Module -ListAvailable | Where-Object {$_.Name -eq $Module.Name}
                            }
                        ) -Force

                        $ModuleStatusCollection +=, $(Get-Variable -Name "$($Module.Name)" -ValueOnly)
                    }
                }
            }
            else {
                New-Variable -Name "$($Module.Name)" -Value $(
                    [pscustomobject][ordered]@{
                        ModuleName   = "$($Module.Name)"
                        Status       = "ImportInRemoteSession"
                        ModuleObject = Get-Module | Where-Object {$_.Name -eq $Module.Name}
                    }
                ) -Force

                $ModuleStatusCollection +=, $(Get-Variable -Name "$($Module.Name)" -ValueOnly)
            }
        }
        $ModuleStatusCollection
    }

    $RemoteModuleStatus = Invoke-Command -Session $PSSession -ScriptBlock $RemoteModuleStatusScriptBlock

    # Split $RemoteModuleStatus into separate arrays based on their status to reduce the number of Invoke-Command operations
    $RemoteModulesNotAvailable = $RemoteModuleStatus | Where-Object {$_.Status -eq "NotAvailable"}
    $RemoteModulesNeedsUpdate = $RemoteModuleStatus | Where-Object {$_.Status -eq "NeedsUpdate"}
    $RemoteModulesAlreadyLatest = $RemoteModuleStatus | Where-Object {$_.Status -eq "AlreadyLatest"}
    $RemoteModulesImportInRemoteSession = $RemoteModuleStatus | Where-Object {$_.Status -eq "ImportInRemoteSession"}

    foreach ($obj in $RemoteModulesNotAvailable) {
        # Get the equivalent local module
        $MatchingLocalModule = Get-Module -Name $obj.ModuleName
        Send-ItemToRemoteHost -ItemsToSendToRemoteHost $MatchingLocalModule.ModuleBase -DestinationDirectory "$RemoteHostHomePath\Documents\WindowsPowerShell\Modules" -PSSession $PSSession -ForceSend
        Invoke-Command -Session $PSSession -ScriptBlock {Import-Module $using:obj.ModuleName}
    }
    foreach ($obj in $RemoteModulesNeedsUpdate) {
        $DestDir = $obj.ModuleObject.ModuleBase | Split-Path -Parent
        Send-ItemToRemoteHost -ItemsToSendToRemoteHost $obj.ModuleBase -DestinationDirectory $DestDir -PSSession $PSSession -ForceSend
        Invoke-Command -Session $PSSession -ScriptBlock {Import-Module $using:obj.ModuleName}
    }

    $DontTouchTheseModules = @()
    foreach ($obj in $RemoteModulesAlreadyLatest) {$DontTouchTheseModules +=, $obj}
    foreach ($obj in $RemoteModulesImportInRemoteSession) {$DontTouchTheseModules +=, $obj}
    foreach ($obj in $DontTouchTheseModules) {
        if ($ForceSend) {
            $DestDir = $obj.ModuleObject.ModuleBase | Split-Path -Parent
            Send-ItemToRemoteHost -ItemsToSendToRemoteHost $obj.ModuleObject.ModuleBase -DestinationDirectory $DestDir -PSSession $PSSession -ForceSend
        }
        Invoke-Command -Session $PSSession -ScriptBlock {Import-Module $using:obj.ModuleName}
    }
}


# Helps with sending local variables to the RemoteHost
# Used in the Send-LocalObjects function
function Add-ParamToScriptBlockString {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        $ArrayOfLinesInput,

        [Parameter(Mandatory=$True)]
        $ScriptBlockAsString
    )

    $LineNumberOfEndOfParamBlock = [array]::indexof($ArrayOfLinesInput,")")
    $LineNumberOfNameOfLastParam = $LineNumberOfEndOfParamBlock-1
    $EndOfCurrentScriptBlockLineNumber = $ArrayOfLinesInput.Count

    $UpdatedLastParamWithComma = "$($ArrayOfLinesInput[$($LineNumberOfNameOfLastParam)]),`n"
    $ArrayOfLinesInput.RemoveAt($LineNumberOfNameOfLastParam)
    $ArrayOfLinesInput.Insert($LineNumberOfNameOfLastParam,$UpdatedLastParamWithComma)
    $ArrayOfLinesInput.RemoveAt($LineNumberOfEndOfParamBlock)

    $ScriptBlockAsArrayOfLines = $ScriptBlockAsString -split "`n"
    for ($i=0; $i -lt $ScriptBlockAsArrayOfLines.Count; $i++) {
        $ArrayOfLinesInput.Insert($($LineNumberOfEndOfParamBlock+$i),$ScriptBlockAsArrayOfLines[$i])
    }

    return $ArrayOfLinesInput
}

# The below Add-MainBodyToScriptBlockString is not used and should be removed. Saving for potential later use.
# It's purpose is to add a a script in the form of a string after the dynamically created CmdletBinding and
# Parameter blocks (which are created using Add-ParamToScriptBlockString)
function Add-MainBodyToScriptBlockString {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        $ArrayOfLinesInput,

        [Parameter(Mandatory=$True)]
        $ScriptBlockAsString
    )

    $EndOfCurrentScriptBlockLineNumber = $ArrayOfLinesInput.Count

    $ScriptBlockAsArrayOfLines = $ScriptBlockAsString -split "`n"
    for ($i=0; $i -lt $ScriptBlockAsArrayOfLines.Count; $i++) {
        $NextLine = $EndOfCurrentScriptBlockLineNumber+$i
        $ArrayOfLinesInput.Insert($NextLine,$ScriptBlockAsArrayOfLines[$i])
    }

    return $ArrayOfLinesInput
}


<#
.SYNOPSIS
    The Send-LocalObjects function loads variables from the Local PSSession in the Remote PSSession.

.DESCRIPTION
    See SYNOPSIS

.PARAMETER PSSession
    MANDATORY

    This parameter takes a System.Management.Automation.Runspaces.PSSession.

.PARAMETER LocalVarsToForward
    MANDATORY

    This parameter takes an array of strings that represent the names of variable names loaded in the local session.

.PARAMETER Silent
    OPTIONAL

    This parameter is a switch. If used, it silences a warning about Environment Variables that are forwarded to
    the Remote Host.

.EXAMPLE
    $LocalVarsToForwardToRemoteSession = @("ArrayOfBeerNames","FoodPriceHashtable")

    Send-LocalObjects -PSSession $FileSharingSession -LocalVarsToForward $LocalVarsToForwardToRemoteSession

#>
function Send-LocalObjects {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$False)]
        [string[]]$LocalVarsToForward, # Must be an array of strings of variable names (without $). If null, then only the default $AlwaysForwardVars will be forwarded

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )
    
    $LocalHostName = $env:COMPUTERNAME

    # Define Variables that should ALWAYS be forwarded to Remote Host
    $LocalHostUserNameFullAcct = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $LocalHostUserName = $LocalHostUserNameFullAcct.Split("\") | Select-Object -Index 1
    $LocalHostComputerName = $env:COMPUTERNAME
    $LocalHostPowerShellSessionInfo = Get-Process -PID $pid

    # Get-UserSessionEx can only be executed if session is elevated
    if (Get-Elevation) {
        if (!$global:LocalHostUserSession) {
            if ($(Get-Command Get-UserSessionEx -ErrorAction SilentlyContinue) -ne $null)
                $global:LocalHostUserSession = Get-UserSessionEx
            }
            else {
                $global:LocalHostUserSession = $null
            }
        }
    }
    else {
        if (!$global:LocalHostUserSession) {
            $global:LocalHostUserSession = $null
        }
    }

    $AlwaysForwardVars = @(
        "LocalHostUserNameFullAcct",
        "LocalHostUserName",
        "LocalHostComputerName",
        "LocalHostPowerShellSessionInfo",
        "LocalHostUserSession"
    )
    # Filter out potential null elements from array
    $LocalVarsToForward = $($AlwaysForwardVars+$LocalVarsToForward) | foreach {if ($_ -ne $null) {$_}}
    
    $EnvironmentVariables = @()
    $NonEnvironmentVariables = @()
    foreach ($PotentialVar in $LocalVarsToForward) {
        if ($(Get-Variable | Where-Object {$_.Name -eq "$PotentialVar"}).Value) {
            Write-Verbose "$PotentialVar is NOT an environment variable"
            $NonEnvironmentVariables += $PotentialVar
        }
        if ($(Get-ChildItem Env: | Where-Object {$_.Name -eq "$PotentialVar"}).Value) {
            Write-Verbose "$PotentialVar IS an environment variable"
            $EnvironmentVariables += $PotentialVar
        }
        if (!$($(Get-Variable | Where-Object {$_.Name -eq "$PotentialVar"}).Value) -and !$($(Get-ChildItem Env: | Where-Object {$_.Name -eq "$PotentialVar"}).Value)) {
            Write-Warning "The variable $PotentialVar was not found. Skipping..."
        }
    }

    if ($EnvironmentVariables.Count -gt 0) {
        if (!$Silent) {
            Write-Warning @"
The specified Environment Variables from the Local Host will be forwarded to the Remote Host $($PSSession.ComputerName), but they will NOT be set as Environment Variables on the Remote Host.
Instead, you will be able to call them by simply using `$VariableName (as opposed to `$env:VariableName) while in the Remote Session.
"@
        }
    }

    # The idea below is that we generate an anonymous function (i.e. scriptblock) dynamically by adding parameters to it based
    # on LocalVarsToForward, and pass the values of those Local Variables to their similarly named parameters via
    # Invoke-Command's -ArgumentList parameter.
    #
    # IMPORTANT NOTE: The correct value gets passed to the appropriate parameter based purely on the position of the
    # parameter and the position of the value in the -ArgumentList array. For example, the first parameter in our
    # anonymous function is LocalHostName, and the first value in the -ArgumentList array is $LocalHostName.
    # Also note that because of the nature of scoping for the -ScriptBlock parameter of the Invoke-Command cmdlet, the
    # scriptblock doesn't actually need to return anything in order for the variables to be set in the Remote Session - it only
    # needs default values set for the parameters in the scriptblock.
    #
    # The dynamic function starts with the baseline CmdletBinding and Parameter Blocks, and adds to them as necessary
    # using the Add-ParamToScriptBlockString function. The resulting string is then converted to a scriptblock, which
    # is used in Invoke-Command.
    $SetupScriptBlock = @"
[CmdletBinding(PositionalBinding=`$True)]
Param(
    [Parameter(Mandatory=`$False)]
    `$LocalHostName = "$LocalHostName"
)
"@

    [System.Collections.ArrayList]$ScriptBlockPrepArrayOfLines = $SetupScriptBlock -split "`n"

    # Extend the scriptblock-string by adding params that match LocalVarsToForward so that they are available on the Remote Host
    foreach ($AdditionalParam in $($NonEnvironmentVariables+$EnvironmentVariables)) {
        New-Variable -Name "ScriptBlock$AdditionalParam" -Value @"
    [Parameter(Mandatory=`$False)]
    `$$AdditionalParam
)
"@
        $ScriptBlockPrepArrayOfLines = Add-ParamToScriptBlockString -ArrayOfLinesInput $ScriptBlockPrepArrayOfLines -ScriptBlockAsString $(Get-Variable -Name "ScriptBlock$AdditionalParam" -ValueOnly)
    }

    $ParamBlockFinalString = $ScriptBlockPrepArrayOfLines | Out-String
    New-Variable -Name "ParamScriptBlock$($PSSession.Name)" -Scope Local -Value $([scriptblock]::Create($ParamBlockFinalString))

    $InvokeCommandString = 'Invoke-Command -Session $PSSession -ScriptBlock $(Get-Variable -Name "ParamScriptBlock$($PSSession.Name)" -ValueOnly) -ArgumentList $LocalHostName'
    # Add to the -ArgumnetList parameter...
    foreach ($AdditionalParam in $NonEnvironmentVariables) {
        $InvokeCommandString = "$InvokeCommandString"+","+"`$(Get-Variable -Name `"$AdditionalParam`" -ValueOnly)"
    }
    foreach ($AdditionalParam in $EnvironmentVariables) {
        $InvokeCommandString = "$InvokeCommandString"+","+"`$(Get-ChildItem Env: | Where-Object {`$_.Name -eq `"$AdditionalParam`"}).Value"
    }

    # Inject the LocalVars into the $PSSession with Remote Host, i.e. make them available in the $PSSession when using: Enter-PSsession -Session $PSSession
    Invoke-Expression $InvokeCommandString
}


<#
.SYNOPSIS 
    The Test-RemotePaths function checks for the existence of paths on a Remote Host. It returns an array of PSCustomObjects
    that mimic certain properties present in Get-ChildItem Objects (such as FullName, DirectoryName, etc). It adds the
    boolean property "FoundOnRemoteHost" to these PSCustomObjects.
#>
function Test-RemotePaths {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$True)]
        [string[]]$ItemsToCheckForOnRemoteHost # Must be a string or array of strings representing full file path(s).
    )

    ##### BEGIN Main Body #####

    # Ensure the format of strings passed to $FilesToCheckForOnRemoteHost and $DirectoriesToCheckForOnRemoteHost can represent
    # valid file/directory paths
    foreach ($item in $ItemsToCheckForOnRemoteHost) {
        if (!$($([uri]$item).IsAbsoluteURI -and $($([uri]$item).IsLoopBack -or $([uri]$item).IsUnc))) {
            Write-Verbose "The path `"$item`" is not in a valid format! Halting!"
            Write-Error "The file path `"$item`" is not in a valid format! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    $ItemsCheckedOnRemoteHost = @()
    for ($i=0; $i -lt $ItemsToCheckForOnRemoteHost.Count; $i++) {
        $itemfullpath = $ItemsToCheckForOnRemoteHost[$i]
        $parentdir = $itemfullpath | Split-Path -Parent
        $itemtail = $itemfullpath | Split-Path -Leaf
        if ($($itemtail | Select-String -Pattern "\.").Matches.Success) {
            $itemname = $itemtail.Split("\.")[0]
        }
        else {
            $itemname = $itemtail
        }

        New-Variable -Name "ItemCheckScriptBlock$itemname$i`FinalString" -Value "Test-Path `"$itemfullpath`"" -Force

        New-Variable -Name "ItemCheckScriptBlock$itemname$i" -Value $(
            [scriptblock]::Create($(Get-Variable -Name "ItemCheckScriptBlock$itemname$i`FinalString" -ValueOnly))
        ) -Force

        $InvokeCommandString = "Invoke-Command -Session `$PSSession -ScriptBlock `$(Get-Variable -Name `"ItemCheckScriptBlock$itemname$i`" -ValueOnly)"

        $FoundItemOnRemoteHostBool = Invoke-Expression $InvokeCommandString

        New-Variable -Name "$itemname$i`OnRemoteHostStatus" -Scope Local -Value $(
            [pscustomobject][ordered]@{
                FullName            = $itemfullpath
                DirectoryName       = $parentdir
                Name                = $itemtail
                BaseName            = $itemname
                FoundOnRemoteHost   = $FoundItemOnRemoteHostBool
            }
        ) -Force
        
        $ItemsCheckedOnRemoteHost +=, $(Get-Variable -Name "$itemname$i`OnRemoteHostStatus" -ValueOnly)
    }
    
    $ItemsCheckedOnRemoteHost

    ##### END Main Body #####
}


# In the context of this WinRM-Environment Module, the below Send-Item function is ONLY used in the Send-ItemToRemoteHost
# function - and only then if the PowerShell Version is less than 5. Otherwise, if the PowerShell Version is 5 or higher,
# Copy-Item is used instead since there is a -Session parameter available.
<#
.SYNOPSIS
    The Send-Item function sends a file (or folder of folders/files recursively) to a remote computer over a previously established WinRm
    session. 

    This function was originally built by Lee Holmes (http://poshcode.org/2216) to simply send a file. It was updated by Adam Bertram
    (https://github.com/adbertram/Random-PowerShell-Work/blob/master/File-Folder%20Management/Send-File.ps1) so that local or 
    UNC directories and their contents could be sent to the Remote Host.

    This iteration updates the $Destination parameter so that it does not assume that the string passed is a parent directory of
    the file/folder's ultimate destination.  In other words, prior to this iteration:
        Send-File -Path C:\test.txt -Destination C:\test.txt -Session $session
    ...resulted in the creation of a *directory* called C:\test.txt on the Remote Host that contained the file test.txt (i.e. 
    C:\test.txt\test.txt). Now it just creates the file C:\test.txt on the Remote Host.
    
    Note that the original syntax using parent directory still works too:
        Send-File -Path C:\test.txt -Destination C:\ -Session $session
    ...results in the file C:\test.txt being created on the Remote Host.

    The UNC logic has also been adjusted.

.PARAMETER Path
    The local or UNC file or folder path that you'd like to copy to the RemoteHost over the WinRM session. This also supports
    multiple paths in a comma-delimited format, or as an array of strings.

    If this is a UNC path to a file/folder, it will be copied locally temporarily. If it's a folder, it will recursively copy
    all files and folders to the destination.

.PARAMETER Destination
    The full path to the file or directory that will be created/recreated on the remote computer.

.PARAMETER Session
    The remote session. Create with New-PSSession.

.EXAMPLE
    $session = New-PSSession -ComputerName MYSERVER
    Send-File -Path C:\test.txt -Destination C:\ -Session $session

    This example will copy the file C:\test.txt to be C:\test.txt on the computer MYSERVER

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.IO.FileInfo

#>
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
                Write-Warning "No changes will be made to the winrm config Trusted Hosts list. The winrm config can only be changed if PowerShell is launched as admin. Connection may still be possible. Continuing..." 
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


<#
.SYNOPSIS
    The Receive-ItemFromRemoteHost function downloads one or more files or directories from a RemoteHost
    to the LocalHost, where the terms LocalHost and RemoteHost are context sensitive. In other words, LocalHost can be
    thought of as $env:COMPUTERNAME and RemoteHost can be thought of as a machine *other than* $env:COMPUTERNAME
    (precluding the unlikely circumstance in which $env:COMPUTERNAME is manually changed for some strange reason. That
    being said, the function is NOT dependent on the value of $env:COMPUTERNAME). 

.DESCRIPTION
    See SYNOPSIS

.PARAMETER ItemsToReceiveFromRemoteHost
    MANDATORY

    This parameter takes an array fo strings that represent paths to file(s) or director(ies) that exist on the Remote Host.

    If any of the Remote Items already exist Locally under DestinationDirectory, the user will receive a prompt for
    confirmation and the Local Items will be OVERWRITTEN. You can suppress the confirmation prompt with the ForceReceive
    parameter.

    Only items specified in this array that are actually present on the Remote Host will actually be downloaded
    to DestinationDirectory. If they do not exist on the RemoteHost, they will be skipped.

.PARAMETER DestinationDirectory
    MANDATORY

    This parameter takes a string that represents a full path to a directory on the Local Host that items will be dowloaded to.

.PARAMETER PSSession
    OPTIONAL

    This parameter takes a System.Management.Automation.Runspaces.PSSession.

    Either this parameter or the RemoteHost and ((RemoteHostUser and RemoteHostPwd) or RICredentials) parameters are required.

.PARAMETER RemoteHost
    OPTIONAL

    This parameter takes a string that represents a DNS-resolvable host name OR IP Address.

    This parameter is meant to be used with the (RemoteHostUser and RemoteHostPwd) or RICredentials parameters.

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

.PARAMETER RICredentials
    OPTIONAL

    This parameter takes a System.Management.Automation.PSCredential object.

    This parameter is meant to be used with the RemoteHost parameter and should NOT be used with RemoteHostUser,
    RemoteHostPwd, or PSSession.

.PARAMETER ForceReceive
    OPTIONAL

    This parameter is a switch. If used, if there is potential for items within the DestinationDirectory to be overwritten,
    the user will NOT receive a confirmation prompt, and those items will be overwritten.

.PARAMETER Silent
    OPTIONAL

    This parameter is a switch. If used, it will silence some STDOUT messages, such as notifications of which items
    were sent/received from Remote Host / by Local Host.

.EXAMPLE
    $Items = @("C:\Users\zeroadmin\Documents\Spreadsheets","C:\Users\zeroadmin\Documents\invoice.pdf")
    
    Receive-ItemFromRemoteHost -PSSession $FileSharingSession -ItemsToReceiveFromRemoteHost $Items -DestinationDirectory $HOME\Downloads

#>
function Receive-ItemFromRemoteHost {
    [CmdletBinding(PositionalBinding=$true)]
    Param(
        [Parameter(
            Mandatory=$True,
            HelpMessage="Please enter an array of strings that represent full path(s) to file(s) or directories on the Remote Host that you would like to receive."
        )]
        [string[]]$ItemsToReceiveFromRemoteHost,

        [Parameter(
            Mandatory=$True,
            HelpMessage="Please enter a full path to a directory on the Local Host that items from the RemoteHost will be downloaded to"
        )]
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
        [System.Management.Automation.PSCredential]$RICredentials,

        [Parameter(Mandatory=$False)]
        [switch]$ForceReceive,

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($RICredentials) {
        if ($RemoteHostUser -or $RemoteHostPwd) {
            Write-Verbose "Please use *either* the -RICredentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
            Write-Error "Please use *either* the -RICredentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
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

    # Check To Make Sure $DestinationDirectory exists on Local Host
    if (! $(Test-Path $DestinationDirectory)) {
        Write-Verbose "The Directory $DestinationDirectory was not found on the Local Host! Please ensure the parameter -DestinationDirectory refers to an existing directory. Halting!"
        Write-Error "The Directory $DestinationDirectory was not found on the Local Host! Please ensure the parameter -DestinationDirectory refers to an existing directory. Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    # Check to see if the folders/files already exist under the Local Host's Destination Directory
    $ItemsAlreadyExist = @()
    foreach ($item in $ItemsToReceiveFromRemoteHost) {
        $ItemLeaf = $item | Split-Path -Leaf
        $UpdatedLocalPath = "$DestinationDirectory\$ItemLeaf"
        if (Test-Path $UpdatedLocalPath) {
            $ItemsAlreadyExist += $UpdatedLocalPath
        }
    }
    if ($ItemsAlreadyExist.Count -gt 0) {
        if (!$Silent) {
            foreach ($existingItem in $ItemsAlreadyExist) {
                Write-Warning "The item $existingItem already exists on the Local Host!"
                if (!$ForceReceive) {
                    $ContinuePrompt = Read-Host -Prompt "Do you want to overwrite $existingItem ? (WARNING: If $existingItem is a folder, ALL contents will be replaced and no original contents will remain!) [Yes/No]"
                    if ($ContinuePrompt -notmatch "Y|y|Yes|yes|Continue|continue") {
                        Write-Verbose "Halting!"
                        Write-Error "Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
        }
        if ($ForceReceive -or $ContinuePrompt -match "Y|y|Yes|yes|Continue|continue") {
            Write-Warning "Local items will be overwritten. Continuing..."
        }
    }
    
    if (!$PSSession) {
        $FileSharingSession = Get-PSSession | Where-Object {$_.Name -eq "FileSharingSession" -and $_.ComputerName -like "*$RemoteHost*"}
        if ($FileSharingSession) {
            Write-Host "Reusing FileSharingSession Session for $RemoteHost!"
            $PotentialRemoteHostCredentials = Get-Variable | Where-Object {
                try {
                    $check = $_.Value.GetType().FullName -eq "System.Management.Automation.PSCredential"
                } catch {}
                if ($check -and $_.Value) {
                    $check
                }
            }
            $PotentialFileSharingSessionRemoteHostCredentials = $PotentialRemoteHostCredentials.Value | Where-Object {$_.UserName -like "*$RemoteHostUser"}
            if ($PotentialFileSharingSessionRemoteHostCredentials.Count -eq 1) {
                $RemoteHostCredential = $PotentialFileSharingSessionRemoteHostCredentials
            }
            if ($PotentialFileSharingSessionRemoteHostCredentials.Count -gt 1) {
                Write-Warning "Multiple credentials with a Username like $RemoteHostUser have been found. Choices are as follows:"
                $PotentialFileSharingSessionRemoteHostCredentials
                $Choice = Read-Host -Prompt "Please select the credentials you would like to forward to the Remote Host by typing '1' for the first choice, '2' for the second choice, and so on. [1/2/N]"
                $RemoteHostCredential = $PotentialFileSharingSessionRemoteHostCredentials[$($Choice-1)]
            }
            if ($PotentialFileSharingSessionRemoteHostCredentials.Count -lt 1) {
                if (!$RemoteHostPwd) {
                    $RemoteHostPwd = Read-Host -Prompt "Please enter the password for $RemoteHostUser" -AsSecureString
                }
                $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
            }
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

            # If $RemoteHost is on a different Domain. change $RemoteHostUser to $RemoteHostUserName
            if ($(Get-WMIObject Win32_ComputerSystem).Domain -ne $RemoteHostNameFQDNPost) {
                $RemoteHostUser = $RemoteHostUserName
            }

            # Set WinRM on LocalHost to Trust the ComputerName and IP Address of the RemoteHost
            # Check Local WinRM Config to make sure $RemoteHost is on the list of TrustedHosts
            if (Get-Elevation) {
                $CurrentTrustedHosts = $(ls WSMan:\localhost\Client\TrustedHosts).Value
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
                Write-Warning "No changes will be made to the winrm config Trusted Hosts list. The winrm config can only be changed if PowerShell is launched as admin. Connection may still be possible. Continuing..." 
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

    $LocalVarsToForwardToRemoteSession = @()
    if ($RemoteHostUser -eq $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -or
    $RemoteHostUser -eq $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -split "\\")[-1]) {
        $LocalVarsToForwardToRemoteSession += "RemoteHostCredential"
    }
    
    if ($LocalVarsToForwardToRemoteSession.Count -gt 0) {
        Send-LocalObjects -PSSession $FileSharingSession -LocalVarsToForward $LocalVarsToForwardToRemoteSession
    }

    Initialize-ModulesInRemoteSession -PSSession $FileSharingSession -WinRMEnvironmentOnly

    # Check to make sure all of the Paths in $Path exist on the Remote Host
    $ItemsCheckedOnRemoteHost = Test-RemotePaths -PSSession $FileSharingSession -ItemsToCheckForOnRemoteHost $ItemsToReceiveFromRemoteHost

    if ($ItemsCheckedOnRemoteHost.FoundOnRemoteHost -notcontains $True) {
        Write-Verbose "None of the paths passed to the -Path parameter were found on the Remote Host! Halting!"
        Write-Error "None of the paths passed to the -Path parameter were found on the Remote Host! Halting!"
        $global:FunctionResult = "1"
        return
    }
    foreach ($ItemCheckObject in $ItemsCheckedOnRemoteHost) {
        if ($ItemCheckObject.FoundOnRemoteHost -eq $False) {
            Write-Warning "The path $($ItemCheckObject.FullName) was NOT found on the Remote Host! Continuing..."
        }
    }

    $FinalItemsToDownload = foreach ($ItemCheckObject in $ItemsCheckedOnRemoteHost) {
        if ($ItemCheckObject.FoundOnRemoteHost -eq $True) {
            $ItemCheckObject
        }
    }

    $LocalVarsToForwardToRemoteSession = @("FinalItemsToDownload")
    Send-LocalObjects -PSSession $FileSharingSession -LocalVarsToForward $LocalVarsToForwardToRemoteSession

    $ReturnTripScriptBlock = @"
if (`$Host.Name -eq "ServerRemoteHost") {
    Write-Verbose "You are currently in a Remote PSSession"

    if (`$PSSenderInfo.ConnectedUser -eq `$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)) {
        Write-Verbose "`$RemoteHostCredential has previously been forwarded by New-InteractivePSSession function and is already available in current scope"
        `$ReturnHostCredential = `$RemoteHostCredential
    }
    else {
        `$ReturnHostUserName = `$PSSenderInfo.ConnectedUser
        `$ReturnHostPwd = Read-Host -Prompt "Please enter the password for `$ReturnHostUserName" -AsSecureString
        `$ReturnHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList `$ReturnHostUserName, `$ReturnHostPwd
    }

    # Create ReturnTripFileSharingSession if it doesn't already exist
    # Variable `$LocalHostComputerName has previously been forwarded by Send-LocalObjects function
    `$ReturnTripFileSharingSession = Get-PSSession | Where-Object {`$_.Name -eq "ReturnTripFileSharingSession" -and `$_.ComputerName -like "*`$LocalHostComputerName*"}
    if (!`$ReturnTripFileSharingSession) {
        `$ReturnTripFileSharingSession = New-PSSession `$LocalHostComputerName -Credential `$ReturnHostCredential -Name ReturnTripFileSharingSession
    }

    foreach (`$Item in `$FinalItemsToDownload) {
        Send-ItemToRemoteHost -ItemsToSendToRemoteHost `$Item.FullName -DestinationDirectory $DestinationDirectory -PSSession `$ReturnTripFileSharingSession -ForceSend
    }
}
"@

    $ScriptBlockForFileSharingSession = [scriptblock]::Create($ReturnTripScriptBlock)

    Invoke-Command -Session $FileSharingSession -ScriptBlock $ScriptBlockForFileSharingSession

    ##### END Main Body #####

}


<#
.SYNOPSIS
    The Edit-FileWinRM function is capable of editing files on the LocalHost or a RemoteHost, where the terms
    LocalHost and RemoteHost are context sensitive. In other words, LocalHost can be thought of as $env:COMPUTERNAME
    and Remote Host can be thought of as a machine *other than* $env:COMPUTERNAME (precluding the unlikely 
    circumstance in which $env:COMPUTERNAME is manually changed for some strange reason. That being said, the function
    is NOT dependent on the value of $env:COMPUTERNAME).

    If you use the function within a Remote PSSession, you will edit the file in the console using Vim for Windows.
    If you don't have Vim for Windows, it will be downloaded from http://www.vim.org/download.php and unzipped in
    $HOME\Downloads. Then, vim.exe will be copied to $HOME\vim.exe and a default .vimrc config file will be generated
    at $HOME\.vimrc. Then vim.exe will be run. Nothing is installed.

    If you use the function outside of a Remote PSSession, you can specify whatever Editor you would like to use
    that is installed on the local system.

    If you don't specify an Editor at all, the function looks for some of the most popular Editors where they can be
    expected to be found on the local filesystem. It'll use the first one that it finds.

    TODO: Make this function capable of digesting a hashtable environment table listing Editor preferences.

.DESCRIPTION
    See SYNOPSIS

.PARAMETER FilePath
    MANDATORY

    This parameter takes a string that represents a full path to a file that you would like to edit. The file path
    can be on the Local Host or on a Remote Host.

.PARAMETER Editor
    OPTIONAL

    This parameter takes a string that represents a full path to a an Editor executable (like sublime.exe, code.exe, etc).

    If you use this function within a PSSession, this parameter will essentially be ignored, since editing within
    the PowerShell Console requires Vim for Windows.

.PARAMETER EditInConsole
    OPTIONAL

    This parameter is a switch. If used, Vim for Windows will be used to edit the file within the PowerShell console.

.PARAMETER PSSession
    OPTIONAL

    This parameter takes a System.Management.Automation.Runspaces.PSSession.

.PARAMETER RemoteHost
    OPTIONAL

    This parameter takes a string that represents a DNS-resolvable host name OR an IP Address. Use this parameter if
    you would like to edit a file on a Remote Host.

.PARAMETER RemoteHostUser
    OPTIONAL

    This parameter takes a string that represents a UserName that has access to the RemoteHost. All UserName
    formats will work. For example, all of the following are valid:
        testadmin
        test2\testadmin
        testadmin@test2.lab

    Either use this parameter and RemoteHostPwd parameter OR the Credentials parameter if you would like to edit a
    file on a Remote Host.

.PARAMETER RemoteHostPwd
    OPTIONAL

    This parameter takes EITHER a plain text String OR a Secure String that represents the password for RemoteHostUser.

    Either use this parameter and RemoteHostUser parameter OR the Credentials parameter if you would like to edit a
    file on a Remote Host.

.PARAMETER Credentials
    OPTONAL

    This parameter takes a System.Management.Automation.PSCredential object. 

    Either use this parameter or the RemoteHostUser and RemoteHostPwd parameters if you would like to edit a file
    on a Remote Host.

.EXAMPLE
    # Edit File present on the Local Host WITHOUT being in a PSSession (i.e. you're just in the normal PowerShell Console)
    Edit-FileWinRM -FilePath $HOME\.gitconfig -Editor "C:\Program Files (x86)\Microsoft VS Code\Code.exe"

.EXAMPLE
    # Edit File present on a Remote Host WITHOUT being in a PSSession (i.e. you're just in the normal PowerShell Console)
    $Params = @{
        FilePath = "C:\Users\zeroadmin\.gitconfig"
        Editor = "C:\Program Files (x86)\Microsoft VS Code\Code.exe"
        RemoteHost = "Win12Chef"
        Credentials = $MyCreds
    }
    Edit-FileWinRM @Params

.EXAMPLE
    # Edit File present on the Local Host (i.e. $env:COMPUTERNAME) WHILE IN a PSSession
    Edit-FileWinRM -FilePath $HOME\.gitconfig

.EXAMPLE
    # Edit File present on a Remote Host (i.e. tertiary target) WHILE IN a PSSession
    $Params = @{
        FilePath = "C:\Users\zeroadmin\.gitconfig"
        RemoteHost = "Exchange01"
        Credentials = $MyCreds
    }
    Edit-FileWinRM @Params

#>
function Edit-FileWinRM {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$FilePath = $(Read-Host -Prompt "Please enter the full path to the file that you would like to edit"),

        [Parameter(Mandatory=$False)]
        [string]$Editor, # The full path to the Text Editor executable

        [Parameter(Mandatory=$False)]
        [switch]$EditInConsole,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUser,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$RemoteHostPwd,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$Credentials
    )

    ##### BEGIN Main Body #####
    # Determine if we're editing a file on the local host, where local host is defined as the machine the current
    # PSSession is running on
    # Assume $FilePath is on the Local Host
    if (!$($RemoteHost -or $RemoteHostUser -or $RemoteHostPwd -or $PSSession)) {
        if (! $(Test-Path $FilePath)) {
            Write-Verbose "The path $FilePath was not found! Halting!"
            Write-Error "The path $FilePath was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FilePath = $(Resolve-Path -Path $FilePath).Path
        $FileName = $FilePath | Split-Path -Leaf

        # If we're in a Remote PSSession, we MUST use Vim
        if ($Host.Name -eq "ServerRemoteHost") {
            if ($Editor -notlike "*vim*") {
                Write-Warning "You can only use the vim text editor while in a Remote PSSession! Using vim..."
                $Editor = $null
            }
            $EditInConsole = $true
        }

        if ($Editor -and !$EditInConsole) {
            if (! $(Test-Path $Editor)) {
                Write-Verbose "The path $Editor was not found! Halting!"
                Write-Error "The path $Editor was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $Editor = $(Resolve-Path -path $Editor).Path
        }
        if ($EditInConsole) {
            $VimEditorPaths = @(
                "$HOME\Downloads\vim.exe",
                "C:\Windows\System32\vim.exe",
                "$HOME\Documents\vim.exe"
            )
            $FoundVimEditor = @()
            foreach ($VimPath in $VimEditorPaths) {
                if (Test-Path $VimPath) {
                    $FoundVimEditor += $VimPath
                    break
                }
            }
            if ($FoundVimEditor.Count -eq 1) {
                $Editor = $FoundVimEditor[0]
            }
            if ($FoundVimEditor.Count -lt 1) {
                $LatestVimForWin32 = $($(Invoke-WebRequest -Uri "http://www.vim.org/download.php").Links | Where-Object {$_.href -like "*w32*.zip"}).href
                $LatestVimForWin32ZipFileName = $LatestVimForWin32 | Split-Path -Leaf
                Invoke-WebRequest -Uri "$LatestVimForWin32" -OutFile "$HOME\Downloads\$LatestVimForWin32ZipFileName"
                Unzip-File -PathToZip "$HOME\Downloads\$LatestVimForWin32ZipFileName" -TargetDir "$HOME\Downloads"
                $FullPathToVimExe = $(Get-ChildItem "$HOME\Downloads\vim" -Recurse | Where-Object {$_.Name -like "*vim*.exe"}).FullName
                Copy-Item -Path "$FullPathToVimExe" -Destination "$HOME\vim.exe"
                Set-Content -Path "$HOME\.vimrc" -Value "set viminfo+=n$HOME\_viminfo`nset backspace=2`nset backspace=indent,eol,start`nset shortmess=at`nset cmdheight=2`nsilent!"
                $Editor = "$HOME\vim.exe"
            }
        }
        if (!$Editor -and !$EditInConsole -and $Host.Name -ne "ServerRemoteHost") {
            $PreferredEditorPaths = @(
                "C:\Program Files (x86)\Sublime Text 3\sublime_text.exe",
                "C:\Program Files\Sublime Text 3\sublime_text.exe",
                "C:\Program Files (x86)\Microsoft VS Code\Code.exe",
                "C:\Program Files\Microsoft VS Code\Code.exe",
                "$HOME\Downloads\vim.exe",
                "C:\Windows\System32\vim.exe",
                "$HOME\Documents\vim.exe",
                "C:\Atom\atom.exe",
                "C:\Program Files\Notepad++\Notepad++.exe",
                "C:\Program Files\Windows NT\Accessories\wordpad.exe",
                "C:\Windows\System32\notepad.exe"
            )
            $FirstAvailableEditor = @()
            foreach ($EditorPath in $PreferredEditorPaths) {
                if (Test-Path $EditorPath) {
                    $FirstAvailableEditor += $EditorPath
                    break
                }
            }
            if ($FirstAvailableEditor.Count -eq 1) {
                $Editor = $FirstAvailableEditor[0]
            }
            if ($FirstAvailableEditor.Count -lt 1) {
                Write-Verbose "No text editors were found! Halting!"
                Write-Error "No text editors were found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        Start-Process $Editor $FilePath
    }
    # Assume $FilePath is on a Remote Host
    if ($RemoteHost -or $RemoteHostUser -or $RemoteHostPwd -or $PSSession) {
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

        if (!$PSSession) {
            $FileSharingSession = Get-PSSession | Where-Object {$_.Name -eq "FileSharingSession" -and $_.ComputerName -like "*$RemoteHost*"}
            if ($FileSharingSession) {
                Write-Host "Reusing FileSharingSession Session for $RemoteHost!"
                $PotentialRemoteHostCredentials = Get-Variable | Where-Object {
                    try {
                        $check = $_.Value.GetType().FullName -eq "System.Management.Automation.PSCredential"
                    } catch {}
                    if ($check -and $_.Value) {
                        $check
                    }
                }
                $PotentialFileSharingSessionRemoteHostCredentials = $PotentialRemoteHostCredentials.Value | Where-Object {$_.UserName -like "*$RemoteHostUser"}
                if ($PotentialFileSharingSessionRemoteHostCredentials.Count -eq 1) {
                    $RemoteHostCredential = $PotentialFileSharingSessionRemoteHostCredentials
                }
                if ($PotentialFileSharingSessionRemoteHostCredentials.Count -gt 1) {
                    Write-Warning "Multiple credentials with a Username like $RemoteHostUser have been found. Choices are as follows:"
                    $PotentialFileSharingSessionRemoteHostCredentials
                    $Choice = Read-Host -Prompt "Please select the credentials you would like to forward to the Remote Host by typing '1' for the first choice, '2' for the second choice, and so on. [1/2/N]"
                    $RemoteHostCredential = $PotentialFileSharingSessionRemoteHostCredentials[$($Choice-1)]
                }
                if ($PotentialFileSharingSessionRemoteHostCredentials.Count -lt 1) {
                    if (!$RemoteHostPwd) {
                        $RemoteHostPwd = Read-Host -Prompt "Please enter the password for $RemoteHostUser" -AsSecureString
                    }
                    $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
                }
            }
            if (!$FileSharingSession) {
                # Create FileSharingSession if it doesn't already exist
                if (!$Credentials) {
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

                # Set WinRM on LocalHost to Trust the ComputerName and IP Address of the RemoteHost
                # Check Local WinRM Config to make sure $RemoteHost is on the list of TrustedHosts
                if (Get-Elevation) {
                    $CurrentTrustedHosts = $(ls WSMan:\localhost\Client\TrustedHosts).Value
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
                    Write-Warning "No changes will be made to the winrm config Trusted Hosts list. The winrm config can only be changed if PowerShell is launched as admin. Connection may still be possible. Continuing..." 
                }

                if ($Credentials) {
                    $FileSharingSession = New-PSSession $RemoteHost -Credential $Credentials -Name FileSharingSession
                }
                else {
                    $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
                    $FileSharingSession = New-PSSession $RemoteHost -Credential $RemoteHostCredential -Name FileSharingSession
                }
            }
        }
        if ($PSSession) {
            Write-Host "Reusing $($PSSession.Name) Session for $RemoteHost!"
            $RemoteHostCredential = $PSSession.Runspace.ConnectionInfo.Credential
            $FileSharingSession = $PSSession
        }
        
        $FileName = $FilePath | Split-Path -Leaf
        $LocalHostFileDestination = "$HOME\Documents\$FileName"
        $LocalHostFileDestinationParent = $LocalHostFileDestination | Split-Path -Parent

        Receive-ItemFromRemoteHost -PSSession $FileSharingSession -ItemsToReceiveFromRemoteHost $FilePath -DestinationDirectory $LocalHostFileDestinationParent -ForceReceive

        # If we're in a Remote PSSession, we MUST use Vim
        if ($Host.Name -eq "ServerRemoteHost") {
            if ($Editor -notlike "*vim*") {
                Write-Warning "You can only use the vim text editor while in a Remote PSSession! Using vim..."
                $Editor = $null
            }
            $EditInConsole = $true
        }

        if ($Editor -and !$EditInConsole) {
            if (! $(Test-Path $Editor)) {
                Write-Verbose "The path $Editor was not found! Halting!"
                Write-Error "The path $Editor was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $Editor = $(Resolve-Path -path $Editor).Path
        }
        if ($EditInConsole) {
            $VimEditorPaths = @(
                "$HOME\Downloads\vim.exe",
                "C:\Windows\System32\vim.exe",
                "$HOME\Documents\vim.exe"
            )
            $FoundVimEditor = @()
            foreach ($VimPath in $VimEditorPaths) {
                if (Test-Path $VimPath) {
                    $FoundVimEditor += $VimPath
                    break
                }
            }
            if ($FoundVimEditor.Count -eq 1) {
                $Editor = $FoundVimEditor[0]
            }
            if ($FoundVimEditor.Count -lt 1) {
                $LatestVimForWin32 = $($(Invoke-WebRequest -Uri "http://www.vim.org/download.php").Links | Where-Object {$_.href -like "*w32*.zip"}).href
                $LatestVimForWin32ZipFileName = $LatestVimForWin32 | Split-Path -Leaf
                Invoke-WebRequest -Uri "$LatestVimForWin32" -OutFile "$HOME\Downloads\$LatestVimForWin32ZipFileName"
                Unzip-File -PathToZip "$HOME\Downloads\$LatestVimForWin32ZipFileName" -TargetDir "$HOME\Downloads"
                $FullPathToVimExe = $(Get-ChildItem "$HOME\Downloads\vim" -Recurse | Where-Object {$_.Name -like "*vim*.exe"}).FullName
                Copy-Item -Path "$FullPathToVimExe" -Destination "$HOME\vim.exe"
                Set-Content -Path "$HOME\.vimrc" -Value "set viminfo+=n$HOME\_viminfo`nset backspace=2`nset backspace=indent,eol,start`nset shortmess=at`nset cmdheight=2`nsilent!"
                $Editor = "$HOME\vim.exe"
            }
        }
        if (!$Editor -and !$EditInConsole -and $Host.Name -ne "ServerRemoteHost") {
            $PreferredEditorPaths = @(
                "C:\Program Files (x86)\Sublime Text 3\sublime_text.exe",
                "C:\Program Files\Sublime Text 3\sublime_text.exe",
                "C:\Program Files (x86)\Microsoft VS Code\Code.exe",
                "C:\Program Files\Microsoft VS Code\Code.exe",
                "$HOME\Downloads\vim.exe",
                "C:\Windows\System32\vim.exe",
                "$HOME\Documents\vim.exe",
                "C:\Atom\atom.exe",
                "C:\Program Files\Notepad++\Notepad++.exe",
                "C:\Program Files\Windows NT\Accessories\wordpad.exe",
                "C:\Windows\System32\notepad.exe"
            )
            $FirstAvailableEditor = @()
            foreach ($EditorPath in $PreferredEditorPaths) {
                if (Test-Path $EditorPath) {
                    $FirstAvailableEditor += $EditorPath
                    break
                }
            }
            if ($FirstAvailableEditor.Count -eq 1) {
                $Editor = $FirstAvailableEditor[0]
            }
            if ($FirstAvailableEditor.Count -lt 1) {
                Write-Verbose "No text editors were found! Halting!"
                Write-Error "No text editors were found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        Start-Process $Editor $LocalHostFileDestination

        # After user is finished making edits to file locally, press any key to send the file back to original host
        Write-Host "Press any key to upload file back to remote host..."
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        Send-ItemToRemoteHost -ItemsToSendToRemoteHost $LocalHostFileDestination -DestinationDirectory $($FilePath | Split-Path -Parent) -PSSession $FileSharingSession -ForceSend

        Remove-Item -Path $LocalHostFileDestination
    }

    ##### END Main Body #####

}


<#
.SYNOPSIS
    The New-InteractivePSSession creates and enters a new interactive PSSession connected to a Remote Server 
    and optionally forward aspects of your local environment to your remote session.

    TODO: Add the ability to digest an environment variable that contains a hashtable of default parameters
    and their values.

.DESCRIPTION
    This function includes parameters to forward/load the following to/in your New Remote PSSession:

    1) Variables

    2) A PowerShell Profile

    3) Currently Loaded Modules

    4) Files and/or Directories (and their contents)

    This way, you'll be able to get a seamless experience PSRemoting from one machine to another.

.PARAMETER RemoteHost
    MANDATORY

    This parameter takes a string that represents a DNS-resolvable host name OR IP Address. A host name / IP
    that refers to a Remote Host is meant to be used, but Local Host will also work.

    NOTE: If you already have a PSSession named "InteractiveSession" connected to the machine referenced by 
    this parameter, then that existing PSSession will be used.

    IMPORTANT NOTE: If the RemoteHost is not part of your Trusted Hosts list (in WinRM config), then it will
    be added.

.PARAMETER RemoteHostUser
    MANDATORY

    This parameter takes a string that represents a UserName that has access to the RemoteHost. All UserName
    formats will work. For example, all of the following are valid:
        testadmin
        test2\testadmin
        testadmin@test2.lab

.PARAMETER RemoteHostPwd
    MANDATORY

    This parameter takes EITHER a plain text String OR a Secure String that represents the password for RemoteHostUser.

.PARAMETER LocalVarsToForwardToRemoteSession
    OPTIONAL
    ALIAS - localvars

    This parameter takes an array of strings, each of which represents the name of a variable currently defined in your
    local session. This can include environment variables.

    NOTE: When referencing environment variable names in this parameter, omit the "env:" prefix. For example, if you
    would like to forward $env:GitHome to the new Remote PSSession, reference it in this parameter via "GitHome".

    IMPORTANT NOTE:
    Environment variables passed to the new Remote PSSession will NOT have the $env: prefix (i.e.
    they will NOT be listed under "Get-ChildItem env:") in the Remote PSSession. Instead, they can simply be referred
    to WITHOUT the $env: prefix. To use our above "GitHome" example, while in the Remote PSSession, the variable can
    be referenced via $GitHome (NOT $env:GitHome).

.PARAMETER ItemsToForwardToRemoteHost
    OPTIONAL
    ALIAS - items

    This parameter takes an array of strings, each of which must represent a full path to either a file or a directory
    on the local host.

    If this parameter is used, then the "DestinationDirectory" parameter becomes MANDATORY.

    IMPORTANT NOTE:
    If the file(s) or director(ies) referenced by this parameter already exist in the DestinationDirectory
    on the RemoteHost, this function will prompt the user for confirmation BEFORE OVERWRITING the file(s) or director(ies)
    in the DestinationDirectory. The prompt can be bypassed by using the "ForceSend" parameter.

.PARAMETER DestinationDirectory
    OPTIONAL

    This parameter takes a string that represents the full path to an existing directory on the Remote Host. If the
    directory does not already exist, the function will halt before doing anything.

    This parameter is ONLY meant to be used if the parameter ItemsToForwardToRemoteHost is used.

.PARAMETER ModulesToForwardToRemoteHost
    OPTIONAL
    ALIAS - modules

    This parameter takes an array of strings that represent the names of PowerShell Modules that are currently loaded
    in the local session. If the referenced Module(s) are NOT already loaded in the local session or do not exist,
    the function will halt before doing anything.

    Before any of the referenced locally-loaded Modules are forwarded to the Remote PSSession, this function
    checks to see if the referenced Module is ALREADY loaded or AVAILABLE in the Remote PSSession.

    If the locally-loaded Module is loaded or available on the Remote Host, but the version number of the Module on
    the Remote Host is older than the locally-loaded Module, this function  COPIES THE LOCAL DIRECTORY to the
    Remote Host and places it under $HOME\Documents\WindowsPowerShell\Modules. This will OVERWRITE the old version
    of the Module on the Remote Host.

    If the locally-loaded Module is loaded or available on the Remote Host, but the Remote Host has the latest version
    of the Module, the latest version will simply be loaded in the Remote PSSession and no file transfers will occur.

    If the locally-loaded Module is NOT loaded on the Remote Host BUT IS available on the Remote Host, this function
    determines which host has the latest version and acts according to the behavior previously outlined.

    If the locally-loaded Module is NOT loaded on the Remote Host and IS NOT available on the Remote Host, this function
    COPIES THE LOCAL DIRECTORY to the Remote Host and places it under $HOME\Documents\WindowsPowerShell\Modules.

    IMPORTANT NOTE:
    The latest version of this WinRM-Environment Module is ALWAYS used in the Remote PSSession,
    regardless of whether or not this parameter is used. If that means that the the version of the WinRM-Environment
    Module on the Local Host is the latest, then a it will be copied to the Remote Host under
    $HOME\Documents\WindowsPowerShell\Modules - overwriting the older version if present.

.PARAMETER ProfileToLoad
    OPTIONAL

    This parameter takes a string that represents a full path to a .ps1 file. This .ps1 file is meant to be
    your local session's PowerShell Profile, but in reality, it can be ANY .ps1 file.

    The contents of the .ps1 file are read into memory, turned into a scriptblock and loaded in the Remote
    PSSession. No file transfers occur.

.PARAMETER MiscellaneousScriptBlockToLoad
    OPTIONAL

    This parameter takes EITHER a string expression OR a scriptblock that you would like executed in the Remote
    PSSession.

.PARAMETER SendBaselinePSConfigFiles
    OPTIONAL

    This parameter is a switch. If used, it will copy the following files from the Local Host to the same locations
    on the Remote Host (that is, if they are present on the Local Host to begin with) ...
        "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\profile.ps1",
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.config",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe.config",
        "C:\Windows\System32\WindowsPowerShell\v1.0\wsmprovhost.exe.config",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\wsmprovhost.exe.config"
    ...and all contents of the following directories
        "C:\Windows\System32\WindowsPowerShell\v1.0\SessionConfig",
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\SessionConfig"

    If any of the aforementioned items already exist on the Remote Host, the function will prompt the user for
    confirmation BEFORE OVERWRITING the items on the Remote Host.

.PARAMETER ForceSend
    OPTIONAL

    This parameter is a switch. It is only meant to be used with either ItemsToForwardToRemoteHost,
    ModulesToForwardToRemoteHost, or SendBaselinePSConfigFiles. If used, if items that could be potentially
    overwritten exist on the Remote Host, the user will NOT receive a confirmation prompt.

.EXAMPLE
    $Params = @{
        RemoteHost = "Win12Chef"
        RemoteHostUser = "testadmin"
        LocalVarsToForwardToRemoteSession = "ArrayOfBeerNames","FoodPriceHashtable"
        ItemsToForwardToRemoteHost = "$HOME\tempdir1","$HOME\tempdir2"
        DestinationDirectory "C:\Users\zeroadmin"
        ModulesToForwardToRemoteHost "NTFSSecurity"
    }

    New-InteractivePSSession @Params

#>
function New-InteractivePSSession {
    [CmdletBinding(PositionalBinding=$True)]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$RemoteHost = $(Read-Host -Prompt "Please enter the name of the Remote Host that you would like to log into."),
        
        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUser = $(Read-Host -Prompt "Please enter the UserName you would like to use to log into $RemoteHost."),

        [Parameter(Mandatory=$False)]
        $RemoteHostPwd = $(Read-Host -Prompt "Please enter the password for $RemoteHostUser" -AsSecureString),

        # Must be array of strings representing the name of variable(s) desired to be forwarded
        [Parameter(Mandatory=$False)]
        [Alias("localvars")]
        [string[]]$LocalVarsToForwardToRemoteSession,

        # Must be array of strings representing full file paths and/or full directory paths present on Local Host.
        # They will NOT be sent if they already exist on the Remote Host, unless $ForceSend switch is used, in which case the remote file will be OVERWRITTEN.
        [Parameter(Mandatory=$False)]
        [Alias("items")]
        [string[]]$ItemsToForwardToRemoteHost,

        [Parameter(Mandatory=$False)]
        [string]$DestinationDirectory,

        [Parameter(Mandatory=$False)]
        [Alias("modules")]
        [string[]]$ModulesToForwardToRemoteHost,

        # Must be a string representing a full file path to the profile.ps1 on the Local Host that will be sent to the RemoteHost and loaded in the RemoteHost PSSession.
        [Parameter(Mandatory=$False)]
        [string]$ProfileToLoad,

        [Parameter(Mandatory=$False)]
        [string]$MiscellaneousScriptBlockToLoad,

        # Using this switch means that a hardcoded list of $BaseLinePSConfigfiles will be sent to Remote Host. They will NOT be sent if they already exist on Remote Host,
        # unless $ForceSend switch is used, in which case the remote file will be OVERWRITTEN.
        [Parameter(Mandatory=$False)]
        [switch]$SendBaselinePSConfigFiles,

        [Parameter(Mandatory=$False)]
        [switch]$ForceSend # Use this switch if you want to send files/directories to the Remote Host even if they already exist there
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    
    if ($ItemsToForwardToRemoteHost -and !$DestinationDirectory) {
        $DestinationDirectory = Read-Host -Prompt "Please enter a full path to a Directory on the Remote Host that the specified items will be sent to."
    }
    if ($DestinationDirectory) {
        if ($DestinationDirectory -notmatch $RegexDirectoryPath) {
            Write-Verbose "The path $DestinationDirectory does not appear to be a directory! Halting!"
            Write-Error "The path $DestinationDirectory does not appear to be a directory! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($DestinationDirectory -and !$ItemsToForwardToRemoteHost) {
        Write-Verbose "The -DestinationDirectory parameter requires use of the -ItemsToForwardToRemoteHost parameter! Halting!"
        Write-Error "The -DestinationDirectory parameter requires use of the -ItemsToForwardToRemoteHost parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($SendBaselinePSConfigFiles) {
        $PotentialConfigFilesOnRemoteHost = @(
            "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1",
            "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\profile.ps1",
            "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe.config",
            "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe.config",
            "C:\Windows\System32\WindowsPowerShell\v1.0\wsmprovhost.exe.config",
            "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\wsmprovhost.exe.config"
        )
        $Sys32PSConfigs = $(Get-ChildItem -Path "C:\Windows\System32\WindowsPowerShell\v1.0\SessionConfig" -Recurse).FullName
        $SysWow64PSConfigs = $(Get-ChildItem -Path "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\SessionConfig" -Recurse).FullName
        $PSSessionConfigFiles = $Sys32PSConfigs+$SysWow64PSConfigs
        # Filter out any potentiall null elements in array
        $PSSessionConfigFiles = $PSSessionConfigFiles | foreach {if ($_ -ne $null) {$_}}
        $BaselinePSConfigItems = $PotentialConfigFilesOnRemoteHost+$PSSessionConfigFiles

        if ($ItemsToForwardToRemoteHost) {
            $FinalItemsToForwardToRemoteHost = $ItemsToForwardToRemoteHost+$BaselinePSConfigItems+$ProfileToLoad
        }
        else {
            $FinalItemsToForwardToRemoteHost = $BaselinePSConfigItems+$ProfileToLoad
        }

        if (!$ForceSend) {
            Write-Warning "The following files will be OVERWRITTEN on the $RemoteHost :`n$($FinalItemsToForwardToRemoteHost | Out-String)"
            $ContinueQuery = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
            if ($ContinueQuery -notmatch "Yes|yes|Y|y") {
                Write-Verbose "Halting!"
                Write-Error "Halting!"
                $global:FunctionResult = "1"
                return
            }
            $ForceSend = $true
        }
    }
    else {
        if ($ItemsToForwardToRemoteHost) {
            $FinalItemsToForwardToRemoteHost = $ItemsToForwardToRemoteHost
        }
    }

    if ($Credentials) {
        if ($RemoteHostUser -or $RemoteHostPwd) {
            Write-Verbose "Please use *either* the -Credentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
            Write-Error "Please use *either* the -Credentials parameter *or* the -RemoteHostUser and -RemoteHostPwd parameters. Halting!"
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

    if ($ProfileToLoad) {
        if (! $(Test-Path $ProfileToLoad)) {
            Write-Verbose "The path $ProfileToLoad was not found! Halting!"
            Write-Error "The path $ProfileToLoad was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ProfileToLoad = $(Resolve-Path -Path $ProfileToLoad).Path
        $ProfileToLoadFileNamewExt = $ProfileToLoad | Split-Path -Leaf
    }

    $RemoteHostNetworkInfoArray = @()
    if (! $(Test-IsValidIPAddress -IPAddress $RemoteHost)) {
        try {
            $RemoteHostIP = $(Resolve-DNSName $RemoteHost).IPAddress
        }
        catch {
            Write-Verbose "Unable to resolve $RemoteHost!"
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

    # Set WinRM on LocalHost to Trust the ComputerName and IP Address of the RemoteHost
    # Check Local WinRM Config to make sure $global:RemoteHost is on the list of TrustedHosts
    if (Get-Elevation) {
        $CurrentTrustedHosts = $(ls WSMan:\localhost\Client\TrustedHosts).Value
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
        Write-Warning "No changes will be made to the winrm config Trusted Hosts list. The winrm config can only be changed if PowerShell is launched as admin. Connection may still be possible. Continuing..."
    }

    $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    ## BEGIN FileSharingSession ##
    # The File Sharing session is NOT meant to be used interactively with Enter-PSSession. Instead it is simply checking
    # for config files on the Remote Host such that the PowerShel experience on the RemoteHost is the same as the PowerShell
    # experience on the Local Host.
    # First, check for an existing FileSharing session. 
    $FileSharingSession = Get-PSSession | Where-Object {$_.Name -eq "FileSharingSession" -and $_.ComputerName -like "*$global:RemoteHost*"}
    if ($FileSharingSession) {
        Write-Host "Reusing FileSharingSession Session for $RemoteHost!"
    }
    if (!$FileSharingSession) {
        $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd

        try {
            $FileSharingSession = New-PSSession $RemoteHost -Credential $RemoteHostCredential -Name FileSharingSession
        }
        catch {
            Write-Warning "$RemoteHost denied the WinRM connection. Please check your credentials and/or user authorization and/or list of Trusted Hosts in WinRM config! Halting!"
        }
        if (!$global:FileSharingSession) {
            Write-Error "$RemoteHost denied the WinRM connection. Please check your credentials and/or user authorization and/or list of Trusted Hosts in WinRM config! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Check username and home path for $PSSession
    $RemoteHostHomePath = Invoke-Command -Session $FileSharingSession -ScriptBlock {$HOME}
    $RemoteHostUserNameFullAcct = Invoke-Command -Session $FileSharingSession -ScriptBlock {[System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
    # Make sure that $RemoteHostHomePath\Documents\WindowsPowerShell\Modules exists
    Invoke-Command -Session $FileSharingSession -ScriptBlock {
        if (!$(Test-Path "$using:RemoteHostHomePath\Documents\WindowsPowerShell")) {
            New-Item -Type Directory -Path "$using:RemoteHostHomePath\Documents\WindowsPowerShell"
        }
        if (!$(Test-Path "$using:RemoteHostHomePath\Documents\WindowsPowerShell\Modules")) {
            New-Item -Type Directory -Path "$using:RemoteHostHomePath\Documents\WindowsPowerShell\Modules"
        }
    }

    if ($FinalItemsToForwardToRemoteHost) {
        if ($ForceSend) {
            if (!$DestinationDirectory) {
                $ConfirmedSentItems = Send-ItemToRemoteHost -PSSession $FileSharingSession `
                -ItemsToSendToRemoteHost $FinalItemsToForwardToRemoteHost -ForceSend -Silent
            }
            else {
                $ConfirmedSentItems = Send-ItemToRemoteHost -PSSession $FileSharingSession `
                -ItemsToSendToRemoteHost $FinalItemsToForwardToRemoteHost -DestinationDirectory $DestinationDirectory `
                -ForceSend -Silent
            }
        }
        if (!$ForceSend) {
            if (!$DestinationDirectory) {
                $ConfirmedSentItems = Send-ItemToRemoteHost -PSSession $FileSharingSession `
                -ItemsToSendToRemoteHost $FinalItemsToForwardToRemoteHost
            }
            else {
                $ConfirmedSentItems = Send-ItemToRemoteHost -PSSession $FileSharingSession `
                -ItemsToSendToRemoteHost $FinalItemsToForwardToRemoteHost -DestinationDirectory $DestinationDirectory
            }
        }
    }

    Get-PSSession | Where-Object {$_.Name -eq "FileSharingSession"} | Remove-PSSession

    ## END FileSharingSession ##

    ## BEGIN InteractiveSession ##

    # The Interactive session IS meant to be used interactively using Enter-PSSession.
    $InteractiveSession = Get-PSSession | Where-Object {$_.Name -eq "InteractiveSession" -and $_.ComputerName -like "*$global:RemoteHost*"}
    if ($InteractiveSession) {
        Write-Host "Reusing InteractiveSession Session for $RemoteHost!"
    }
    if (!$InteractiveSession) {
        $RemoteHostCredential = New-Object -typename System.Management.Automation.PSCredential -ArgumentList $RemoteHostUser, $RemoteHostPwd
        
        $InteractiveSession = New-PSSession $RemoteHost -Credential $RemoteHostCredential -Name InteractiveSession
    }

    if ($RemoteHostUser -eq $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -or
    $RemoteHostUser -eq $($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -split "\\")[-1]) {
        $LocalVarsToForwardToRemoteSession += "RemoteHostCredential"
    }

    if ($LocalVarsToForwardToRemoteSession) {
        Send-LocalObjects -PSSession $InteractiveSession -LocalVarsToForward $LocalVarsToForwardToRemoteSession -Silent
    }
    else {
        Send-LocalObjects -PSSession $InteractiveSession -Silent
    }

    Write-Host "Entering PSSession `$InteractiveSession..."
    Write-Host "Writing Welcome Message..."
    Write-WelcomeMessage -PSSession $InteractiveSession
    
    Initialize-ModulesInRemoteSession -PSSession $InteractiveSession -WinRMEnvironmentOnly
    if ($ModulesToForwardToRemoteHost) {
        Initialize-ModulesInRemoteSession -PSSession $InteractiveSession -LocalModulesToIncludeInRemoteSession $ModulesToForwardToRemoteHost
    }
    if ($ProfileToLoad) {
        Initialize-PSProfileInRemoteSession -PSSession $InteractiveSession -ProfileToLoadOnRemoteHost $ProfileToLoad
    }
    if ($MiscellaneousScriptBlockToLoad) {
        if ($MiscellaneousScriptBlockToLoad.GetType().FullName -eq "System.Management.Automation.ScriptBlock") {
            $FinalMiscScriptBlock = $MiscellaneousScriptBlockToLoad
        }
        if ($MiscellaneousScriptBlockToLoad.GetType().FullName -eq "System.String") {
            $FinalMiscScriptBlock = [scriptblock]::Create($MiscellaneousScriptBlockToLoad)
        }

        Invoke-Command -Session $InteractiveSession -ScriptBlock $FinalMiscScriptBlock
    
    }

    Enter-PSSession $InteractiveSession

    ## END InteractiveSession ##


    ##### END Main Body #####

}











# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxAp0NYV6CIZjcIrQid3R8iDz
# LgKgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTZHL32qQ2R
# R8BYl68IsbVkJJashDANBgkqhkiG9w0BAQEFAASCAQAgeP+tNR2+LK7shYxz7CjX
# ywbvW65fQVbDc7oNkZuk4zK5HmE1PioLRYl3X+U9Nm3C5zocNeSIstyrHylSxgE8
# tGK7PbDpFVBwe426eC7MZcXUOZrG/i2TBv8LA863cEpBM0ST4cEUaAYtXnBwUvX4
# Cqfllhfw8z8DoMxWH31O4bbdGVXfGw/O8d+0sOa8hdCMp0lu96xYOlWC4lPO4+1x
# +VTVA7aLsUgK4IIvtKXIpwdsoyrUVOzb5q2+u+L+vz5gnuCvU9vOWx953p7NIXq0
# sV2kSa1MxV13PtdvaAZfLmbE8aI5QVO5nPigO4fWOL86q1qEcEkqN4K6788b3S+b
# SIG # End signature block
