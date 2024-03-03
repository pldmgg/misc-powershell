<#
.SYNOPSIS
    Enables the new Windows 11 right-click context menu for all users
.DESCRIPTION
    Reference: https://www.elevenforum.com/t/disable-show-more-options-context-menu-in-windows-11.1589/
.NOTES
    DEPENDENCEIES
        - winget
        - choco
        - psexec
        - Nirsoft AdvancedRun.exe (https://www.nirsoft.net/utils/advanced_run.html)
        because we need to set Owner and Permissions for certain Registry Keys as TrustedInstaller
.EXAMPLE
    Enable-NewWin11ContextMenuForAllUsers
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Enable-NewWin11ContextMenuForAllUsers {
    [CmdletBinding()]
    Param()

    #$RegFileUri = "https://www.elevenforum.com/attachments/enable_show_more_options_context_menu_for_all_users-reg.63779/"
    $RegistryFileContent = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}]
@="File Explorer Context Menu"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InProcServer32]
@="C:\\Windows\\System32\\Windows.UI.FileExplorer.dll"
"ThreadingModel"="Apartment"
'@

    $RegFileOutputDir = "C:\Scripts\bin"
    if (-NOT $(Test-Path $RegFileOutputDir)) {$null = New-Item -Path $RegFileOutputDir -ItemType Directory -Force}
    $RegFileOutFilePath = "$RegFileOutputDir\Enable_win11_context_menu_for_all_users.reg"
    $RegistryFileContent | Out-File -FilePath $RegFileOutFilePath -Force

    # Install AdvancedRun.exe if necessary
    if (-NOT $(Get-Command advancedrun -ErrorAction SilentlyContinue)) {
        $AdvancedRunExePath = "$HOME\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
        if (-NOT $(Test-Path $AdvancedRunExePath)) {
            #Write-Error "Unable to find AdvancedRun.exe! Halting!"
            winget install AdvancedRun
        }
    } else {
        $AdvancedRunExePath = $(Get-Command advancedrun).Source
    }
    # Check to make sure we have AdvancedRun.exe just in case we had to use winget to install
    if (-NOT $(Get-Command advancedrun -ErrorAction SilentlyContinue)) {
        $AdvancedRunExePath = "$HOME\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
        if (-NOT $(Test-Path $AdvancedRunExePath)) {
            Write-Error "Unable to find AdvancedRun.exe! Halting!"
        }
    } else {
        $AdvancedRunExePath = $(Get-Command advancedrun).Source
    }

    # Install PSExec.exe if necessary
    if (-NOT $(Get-Command psexec -ErrorAction SilentlyContinue)) {
        $PSExecExePath = "C:\ProgramData\chocolatey\bin\PsExec.exe"
        if (-NOT $(Test-Path $PSExecExePath)) {
            choco install psexec -y
        }
    } else {
        $PSExecExePath = $(Get-Command psexec).Source
    }
    # Check to make sure we have PSExec.exe just in case we had to use chocolatey to install
    if (-NOT $(Get-Command psexec -ErrorAction SilentlyContinue)) {
        $PSExecExePath = "C:\ProgramData\chocolatey\bin\PsExec.exe"
        if (-NOT $(Test-Path $PSExecExePath)) {
            Write-Error "Unable to find psexec.exe! Halting!"
        }
    } else {
        $PSExecExePath = $(Get-Command psexec).Source
    }

    # Ensure Registry Permissions are set properly
    # Use AdvancedRun.exe to run Set-RegistryPermsForDisableNewWin11ContextMeny.ps1 as TrustedInstaller (i.e. /RunAs 8)
    $SetRegistryPermsFileOutputDir = "C:\Scripts\powershell"
    if (-NOT $(Test-Path $SetRegistryPermsFileOutputDir)) {$null = New-Item -Path $SetRegistryPermsFileOutputDir -ItemType Directory -Force}
    $FuncName = "Set-RegistryPermsForWin11ContextMenuModifications"
    $SetRegistryPermsOutFilePath = $SetRegistryPermsFileOutputDir + '\' + $FuncName + '.ps1'
    ${Function:Set-RegistryPermsForWin11ContextMenuModifications}.Ast.Extent.Text + "`n" + $FuncName | Out-File -FilePath $SetRegistryPermsOutFilePath -Force
    
    Write-Host "Setting registry permissions for Enable-NewWin11ContextMenuForAllUsers ..."
    $PowerShellPath = $(Get-Command powershell.exe).Source
    # IMPORTANT NOTE: Registry ownership/permissions won't be set properly unless we use PSExec.exe to run
    # AdvancedRun.exe as SYSTEM which subsequently runs the powershell script as TrustedInstaller (i.e. /RunAs 8)
    $PSExecCommand = @"
& $AdvancedRunExePath /EXEFilename $PowerShellPath /CommandLine '$SetRegistryPermsOutFilePath' /RunAs 8 /Run
"@
    & PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -Command "$PSExecCommand"
    #& $AdvancedRunExePath /EXEFilename $(Get-Command powershell.exe).Source /CommandLine 'C:\Scripts\powershell\Set-RegistryPermsForWin11ContextMenuModifications.ps1' /RunAs 8 /Run

    #reg import $OutFilePath
    Write-Host "Enabling the new Windows 11 right-click context menu for all users via $RegFileOutFilePath ..."
    & regedit.exe /s "$RegFileOutFilePath"
    #& reg import "$RegFileOutFilePath" >$null 2>&1
    Get-Process explorer | Stop-Process -Force
}


<#
.SYNOPSIS
    Enables the new Windows 11 right-click context menu for all users
.DESCRIPTION
    Reference: https://www.elevenforum.com/t/disable-show-more-options-context-menu-in-windows-11.1589/
.NOTES
    DEPENDENCEIES
        - winget
        - choco
        - psexec
        - Nirsoft AdvancedRun.exe (https://www.nirsoft.net/utils/advanced_run.html)
        because we need to set Owner and Permissions for certain Registry Keys as TrustedInstaller
.EXAMPLE
    Disable-NewWin11ContextMenuForAllUsers
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Disable-NewWin11ContextMenuForAllUsers {
    [CmdletBinding()]
    Param()

    #$RegFileUri = "https://www.elevenforum.com/attachments/disable_show_more_options_context_menu_for_all_users-reg.63778/"
    $RegistryFileContent = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}]
@="File Explorer Context Menu"

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InProcServer32]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InProcServer32]
@=""
'@

    $RegFileOutputDir = "C:\Scripts\bin"
    if (-NOT $(Test-Path $RegFileOutputDir)) {$null = New-Item -Path $RegFileOutputDir -ItemType Directory -Force}
    $RegFileOutFilePath = "$RegFileOutputDir\Disable_win11_context_menu_for_all_users.reg"
    $RegistryFileContent | Out-File -FilePath $RegFileOutFilePath -Force

    # Install AdvancedRun.exe if necessary
    if (-NOT $(Get-Command advancedrun -ErrorAction SilentlyContinue)) {
        $AdvancedRunExePath = "$HOME\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
        if (-NOT $(Test-Path $AdvancedRunExePath)) {
            $AdvancedRunExePath = "C:\Users\ttadmin\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
            if (-NOT $(Test-Path $AdvancedRunExePath)) {
                #Write-Error "Unable to find AdvancedRun.exe! Halting!"
                winget install AdvancedRun
            }
        }
    } else {
        $AdvancedRunExePath = $(Get-Command advancedrun).Source
    }
    # Check to make sure we have AdvancedRun.exe just in case we had to use winget to install
    if (-NOT $(Get-Command advancedrun -ErrorAction SilentlyContinue)) {
        $AdvancedRunExePath = "$HOME\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
        if (-NOT $(Test-Path $AdvancedRunExePath)) {
            $AdvancedRunExePath = "C:\Users\ttadmin\AppData\Local\Microsoft\WinGet\Links\advancedrun.exe"
            if (-NOT $(Test-Path $AdvancedRunExePath)) {
                Write-Error "Unable to find AdvancedRun.exe! Halting!"
                return
            }
        }
    } else {
        $AdvancedRunExePath = $(Get-Command advancedrun).Source
    }

    # Install PSExec.exe if necessary
    if (-NOT $(Get-Command psexec -ErrorAction SilentlyContinue)) {
        $PSExecExePath = "C:\ProgramData\chocolatey\bin\PsExec.exe"
        if (-NOT $(Test-Path $PSExecExePath)) {
            choco install psexec -y
        }
    } else {
        $PSExecExePath = $(Get-Command psexec).Source
    }
    # Check to make sure we have PSExec.exe just in case we had to use chocolatey to install
    if (-NOT $(Get-Command psexec -ErrorAction SilentlyContinue)) {
        $PSExecExePath = "C:\ProgramData\chocolatey\bin\PsExec.exe"
        if (-NOT $(Test-Path $PSExecExePath)) {
            Write-Error "Unable to find psexec.exe! Halting!"
        }
    } else {
        $PSExecExePath = $(Get-Command psexec).Source
    }

    # Ensure Registry Permissions are set properly
    # Use AdvancedRun.exe to run Set-RegistryPermsForDisableNewWin11ContextMeny.ps1 as TrustedInstaller (i.e. /RunAs 8)
    $SetRegistryPermsFileOutputDir = "C:\Scripts\powershell"
    if (-NOT $(Test-Path $SetRegistryPermsFileOutputDir)) {$null = New-Item -Path $SetRegistryPermsFileOutputDir -ItemType Directory -Force}
    $FuncName = "Set-RegistryPermsForWin11ContextMenuModifications"
    $SetRegistryPermsOutFilePath = $SetRegistryPermsFileOutputDir + '\' + $FuncName + '.ps1'
    ${Function:Set-RegistryPermsForWin11ContextMenuModifications}.Ast.Extent.Text + "`n" + $FuncName | Out-File -FilePath $SetRegistryPermsOutFilePath -Force
    
    Write-Host "Setting registry permissions for Disable-NewWin11ContextMenuForAllUsers ..."
    $PowerShellPath = $(Get-Command powershell.exe).Source
    # IMPORTANT NOTE: Registry ownership/permissions won't be set properly unless we use PSExec.exe to run
    # AdvancedRun.exe as SYSTEM which subsequently runs the powershell script as TrustedInstaller (i.e. /RunAs 8)
    $PSExecCommand = @"
& $AdvancedRunExePath /EXEFilename $PowerShellPath /CommandLine '$SetRegistryPermsOutFilePath' /RunAs 8 /Run
"@
    & PsExec.exe -i -s powershell.exe -ExecutionPolicy Bypass -Command "$PSExecCommand"
    #& $AdvancedRunExePath /EXEFilename $(Get-Command powershell.exe).Source /CommandLine 'C:\Scripts\powershell\Set-RegistryPermsForWin11ContextMenuModifications.ps1' /RunAs 8 /Run

    #reg import $OutFilePath
    Write-Host "Disabling the new Windows 11 right-click context menu for all users via $RegFileOutFilePath ..."
    & regedit.exe /s "$RegFileOutFilePath"
    #& reg import "$RegFileOutFilePath" >$null 2>&1
    Get-Process explorer | Stop-Process -Force
}


<#
.SYNOPSIS
    Sets the registry permissions for the new Windows 11 right-click context menu
    IMPORTANT NOTE: This function must be run as TrustedInstaller and therefore must be called via AdvancedRun.exe
.DESCRIPTION
    Reference: https://www.elevenforum.com/t/disable-show-more-options-context-menu-in-windows-11.1589/
.NOTES
    DEPENDENCEIES
        - Nirsoft AdvancedRun.exe (https://www.nirsoft.net/utils/advanced_run.html)
        because we need to set Owner and Permissions for certain Registry Keys as TrustedInstaller
.EXAMPLE
    Set-RegistryPermsForWin11ContextMenuModifications
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Set-RegistryPermsForWin11ContextMenuModifications {
    [CmdletBinding()]
    Param()

    # Make sure permissions on the below registry key are:
    # Owner = Administrators
    # Administrators = Full Control
    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}
    $keyPath = "HKLM:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"

    # Check Owner and update if necessary
    $acl = Get-Acl -Path $keyPath
    $currentOwner = $acl.Owner
    $LocalAdministratorsGroupSID = $(Get-LocalGroup Administrators).SID.Value
    $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier($LocalAdministratorsGroupSID)
    $administrators = $administratorsSid.Translate([System.Security.Principal.NTAccount])

    try { 
        if ($currentOwner -ne $administrators.Value) {
            # Owner is not Administrators, proceed to set the owner
            $acl.SetOwner($administrators)
            Set-Acl -Path $keyPath -AclObject $acl
            Write-Host "Owner set to Administrators."
        } else {
            Write-Host "Owner is already set to Administrators."
        }

        # Check Administrators have Full Control
        $acl = Get-Acl -Path $keyPath
        $adminFullControl = $acl.Access | Where-Object {
            $_.IdentityReference -eq $administrators.Value -and
            $_.RegistryRights -eq "FullControl" -and
            $_.AccessControlType -eq "Allow"
        }
        if ($adminFullControl -eq $null) {
            # Full Control permission for Administrators is not set, proceed to add it
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.AddAccessRule($rule)
            Set-Acl -Path $keyPath -AclObject $acl
            Write-Host "Full Control permission for Administrators has been added."
        } else {
            Write-Host "Administrators already have Full Control permission."
        }
    } catch {
        Write-Error $_
        return
    }
}


<#
.SYNOPSIS
    Creates a context menu item for copying SharePoint Online and local file links to the clipboard
.DESCRIPTION
    Reference: 
.NOTES
    DEPENDENCEIES
        - run-hidden.exe (https://github.com/stax76/run-hidden) because we don't want to see the PowerShell window when the script runs
.EXAMPLE
    Create-SPOLocalLinkContextMenu
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Create-SPOLocalLinkContextMenu {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [string]$ContextMenuName = "Copy Links To Clipboard",

        [Parameter(Mandatory = $False)]
        [string]$OnlineRootFolder = "$HOME\CompanyName\SharePointSite - Documents\",

        [Parameter(Mandatory = $False)]
        [string]$SharePointBaseUrl = "https://companyname.sharepoint.com/sites/sharepointsite/Documents/Forms/AllItems.aspx?id=%2Fsites%2FSharePointSite%2FDocuments",

        [Parameter(Mandatory = $False)]
        [string]$LibraryFolderID = '6495bcd2-cd10-4968-becf-c5cab8033e5a'
    )

    $GetLinksScriptDir = "C:\Scripts\powershell"
    $GetLinksScriptName = "Get-SPOAndLocalLinks.ps1"
    $GetLinksScriptPath = "$GetLinksScriptDir\$GetLinksScriptName"
    $BinDir = "C:\Scripts\bin"
    $RunHiddenExePath = "$BinDir\run-hidden.exe"
    $RunHiddenZipPath = "$BinDir\run-hidden.zip"
    if (-NOT $(Test-Path $GetLinksScriptDir)) {$null = New-Item -Path $GetLinksScriptDir -ItemType Directory -Force}
    if (-NOT $(Test-Path $BinDir)) {$null = New-Item -Path $BinDir -ItemType Directory -Force}

    $registryPathForFile = "Registry::HKEY_CLASSES_ROOT\*\shell\$ContextMenuName"
    $registryPathForDir = "Registry::HKEY_CLASSES_ROOT\Directory\shell\$ContextMenuName"
    $registryPathForDirBack = "Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\$ContextMenuName"
    $commandPathForFile = "$registryPathForFile\\command"
    $commandPathForDir = "$registryPathForDir\\command"
    $commandPathForDirBack = "$registryPathForDirBack\\command"

    # Create the Get-SPOAndLocalLinks.ps1 script
    $GetLinksScriptContent = @'
param (
    [string]$localPath
)

'@ + @"

`$OnlineRootFolder = '$OnlineRootFolder'
`$SharePointBaseUrl = '$SharePointBaseUrl'
# Get the below `$libraryFodlerID by opening in browser and exploring several different folders in the Document Library and observing what comes after &viewid= in the URL
`$LibraryFolderID = '$LibraryFolderID'

"@ + @'

# Make sure $localPath is somewhere in the $OnlineRootFolder
$OnlineRootFolderArray = $OnlineRootFolder -split '\\'
$localPathArray = $localPath -split '\\'
$PathCheckArray = [System.Collections.ArrayList]::new()
0..$($OnlineRootFolderArray.Count - 2) | foreach {
    if ($OnlineRootFolderArray[$_] -eq $localPathArray[$_]) {
        $null = $PathCheckArray.Add($True)
    } else {
        $null = $PathCheckArray.Add($False)
    }
}
if ($PathCheckArray -contains $False) {
    Write-Error "We are not checking a file or directory under '$OnlineRootFolder'! Halting!"
    return
}

$relativePath = $localPath.Replace($OnlineRootFolder, "").Replace("\", "/")
$pathChunks = $relativePath -split '/'
$finalPathString = [System.Collections.Generic.List[string]]::new()
$i = 0
foreach ($chunk in $pathChunks) {
    if ($i -lt ($pathChunks.Count - 1)) {
        $finalPathString.Add(('%2F' + $chunk))
    } else {
        $finalPathString.Add(('&viewid=' + $LibraryFolderID))
        $finalPathString.Add(('&view=7&q=' + $chunk))
    }
    $i++
}
$sharePointUrl = $SharePointBaseUrl + ($finalPathString -join '')

# The idea here is that people will be sharing these links/paths, so we need
# to make sure that the local path is accessible to the recipient...
$finalLocalPath = '%UserProfile%' + '\' + ($localPathArray[3..($localPathArray.Count - 1)] -join '\')
# Combine both links with a newline
$bothLinks = "$sharePointUrl`nOR`n$finalLocalPath"

# Copy to clipboard
$bothLinks | Set-Clipboard

# If $localpath refers to a file (as opposed to directory) release it to the cloud because it will have been downloaded locally after this
$Item = Get-Item -Path $localPath
if (-not $Item.PSIsContainer) {
    attrib.exe $localPath +U -P /S
}
'@

    Write-Host "Creating $GetLinksScriptPath ..."
    $GetLinksScriptContent | Out-File -FilePath $GetLinksScriptPath -Force

    $commandForRegAdd = @"
$RunHiddenExePath powershell.exe -File ""$GetLinksScriptPath"" ""%1""
"@

    try {
        # Make sure the run-hidden.exe is installed
        if (!(Test-Path $RunHiddenExePath)) {
            #Write-Error "run-hidden.exe not found! Halting!"
            #return
            Write-Host "Downloading run-hidden.exe ..."
            $null = Invoke-WebRequest -Uri "https://github.com/stax76/run-hidden/releases/download/v1.2/run-hidden-v1.2.zip" -OutFile $RunHiddenZipPath
            $null = Expand-Archive -Path $RunHiddenZipPath -DestinationPath $BinDir -Force
        }

        Write-Host "Creating Registry keys for $ContextMenuName ..."
        # NOTE: Test-Path does not work reliably with the Registry provider...sometimes it just hangs
        #if (-not (Test-Path $registryPathForFile)) {$null = New-Item -Path $registryPathForFile -Force}
        & reg add "HKCR\*\shell\$ContextMenuName" /f
        #if (-not (Test-Path $registryPathForDir)) {$null = New-Item -Path $registryPathForDir -Force}
        & reg add "HKCR\Directory\shell\$ContextMenuName" /f
        #if (-not (Test-Path $registryPathForDirBack)) {$null = New-Item -Path $registryPathForDirBack -Force}
        & reg add "HKCR\Directory\Background\shell\$ContextMenuName" /f

        Write-Host "Adding Registry keys for $ContextMenuName ..."
        #if (-not (Test-Path $commandPathForFile)) {$null = New-Item -Path $commandPathForFile -Force}
        #& reg add "HKCR\*\shell\$ContextMenuName\command" /f
        & reg add "HKCR\*\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
        #if (-not (Test-Path $commandPathForDir)) {$null = New-Item -Path $commandPathForDir -Force}
        #& reg add "HKCR\Directory\shell\$ContextMenuName\command" /f
        & reg add "HKCR\Directory\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
        #if (-not (Test-Path $commandPathForDirBack)) {$null = New-Item -Path $commandPathForDirBack -Force}
        #& reg add "HKCR\Directory\Background\shell\$ContextMenuName\command" /f
        & reg add "HKCR\Directory\Background\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
    } catch {
        Write-Error $_
        return
    }

    # Set the registry "command" key to invoke the PowerShell script with the selected file path
    #Set-ItemProperty -Path $commandPathForFile -Name "(Default)" -Value $command -PropertyType String -Force
    #Write-Host "Adding Registry keys for $ContextMenuName ..."
    #& reg add "HKCR\*\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
    #& reg add "HKCR\Directory\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
    #& reg add "HKCR\Directory\Background\shell\$ContextMenuName\command" /t REG_SZ /d "$commandForRegAdd" /f
}