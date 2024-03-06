function Get-Elevation {
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
    & PsExec.exe -accepteula -i -s powershell.exe -ExecutionPolicy Bypass -Command "$PSExecCommand"
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
    & PsExec.exe -accepteula -i -s powershell.exe -ExecutionPolicy Bypass -Command "$PSExecCommand"
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
    $parentKeyPath = "HKLM:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}"
    $subKeyPath = $parentKeyPath + '\' + "InProcServer32"
    $keyPathArray = @($parentKeyPath, $subKeyPath)

    foreach ($keyPath in $keyPathArray) {
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
        [Parameter(Mandatory = $True)]
        [string]$ContextMenuName, # "Copy Links To Clipboard"

        [Parameter(Mandatory = $True)]
        [string]$OnlineRootFolder, # "$HOME\CompanyName\SharePointSite - Documents\"

        [Parameter(Mandatory = $True)]
        [string]$SharePointBaseUrl, # "https://companyname.sharepoint.com/sites/sharepointsite/Documents/Forms/AllItems.aspx?id=%2Fsites%2FSharePointSite%2FDocuments"

        [Parameter(Mandatory = $True)]
        [string]$LibraryFolderID # '6495bcd2-cd10-4968-becf-c5cab8033e5a'
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

    # Make sure $OnlineRootFolder does not expand $HOME
    if ($OnlineRootFolder -match [regex]::Escape($HOME)) {
        $OnlineRootFolder = $OnlineRootFolder -replace [regex]::Escape($HOME),'$HOME'
    }

    # Create the Get-SPOAndLocalLinks.ps1 script
    $GetLinksScriptContent = @'
param (
    [string]$localPath
)

'@ + @"

`$OnlineRootFolder = "$OnlineRootFolder"
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
$bothLinks = "Web Browser Link:`n$sharePointUrl`n`nOR`n`nWindows File Explorer Link:`n$finalLocalPath"

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

        Write-Host "Adding Registry keys for $ContextMenuName \command ..."
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
}


<#
.SYNOPSIS
    Creates a context menu item for copying SharePoint Online and local file links to the clipboard
.DESCRIPTION
    ##### BEGIN Create/Register New App in Azure #####
    # In Azure Dashboard, follow these steps:
    <#
    1) Navigate to https://portal.azure.com/
    2) Hamburger menu -> Micrsoft Entra ID (formerly Azure Active Directory) -> App registrations -> Select "All applications" to see everything -> New registration
    3) Fill out "Name" field -> Under "Supported account types" select "Accounts in this organizational directory only (Company only - Single tenant)"
    4) Under "Redirect URI (optional)" use the "Select a platform" dropdown and choose "Single-page Application (SPA)" and URI field should be "https://login.live.com/oauth20_desktop.srf"
    5) Take note: "Application (client) ID" = $AppClientID | "Directory (tenant)" = $TenantID
    6) In the left-hand menu, click "API Permissions" -> Click "Add a permission" -> Click "Microsoft Graph" -> Click "Delegated permissions" ->
    In the "Select permissions" Search field search for and add the following permissions:
    - Files.Read
    - Files.Read.All
    - Files.Read.Selected
    - Files.ReadWrite
    - Files.ReadWrite.All
    - Files.ReadWrite.AppFolder
    - Files.ReadWrite.Selected
    - Sites.Read.All
    - Sites.ReadWrite.All
    - User.Read
    - User.ReadWrite
    7) Do the same for "Application permissions" as in step 6, i.e. "API Permissions" -> Click "Add a permission" -> Click "Microsoft Graph" -> Click "Application permissions" ->
    In the "Select permissions" Search field search for and add the following permissions:
    - Files.Read.All
    - Files.ReadWrite.All
    - Sites.Read.All
    - Sites.ReadWrite.All
    - User.Read.All
    - User.ReadWrite.All
    8) Grant Admin Consent for all of the above permissions by clicking "Grant admin consent for <Org Name>"
    9) In the left-hand menu, click on "Manifest" -> Ctrl + F for "oauth2AllowIdTokenImplicitFlow" and set to "true ->
    Ctrl + F for "oauth2AllowImplicitFlow" and set to "true" so that it looks like the following:

        "oauth2AllowIdTokenImplicitFlow": true,
        "oauth2AllowImplicitFlow": true,
    10) In the left-hand menu, click on "Authentication" -> Delete the SPA Platform entry -> Click "Add a platform" ->
    Select "Mobile and desktop applications" -> Check the checkbox for URI "https://login.live.com/oauth20_desktop.srf" -> Click Save
    11) If you want the App itself (as opposed to the logged-in user) to have the ability to upload files to SharePoint do the following:
    - On the left-hand menu, click on "Certificates & secrets" -> Click "New client secret" ->
    Take not that "Value" = $AppClientSecretValue
    - On the left-hand menu, click "API Permissions" -> Click "Add a permission" -> Click "Microsoft Graph" ->
    Click "Application permissions" -> Search for "Site.ReadWrite.All" -> Select the checkbox and click "Add permissions"

    ##### END Create/Register New App in Azure #####

    ##### BEGIN Setup Certificate Based Authentication #####

    # If you haven't done so already, create a new self-signed certificate and upload it to your OneDriveAPI App in Azure
    # Create a new self-signed certificate
    # Find existing Veeam365App certificates installed in the Windows certificate Store on
    Get-ChildItem -Path "Cert:\" -Recurse -Force | Where-Object {-not $_.PSIsContainer -and $_.Subject -match "OneDriveAPI"}

    # First find the existing registered app here: https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview
    # Generate App Certificate Instructions...
    $certname = "CompanyOneDriveAPIApp2024"
    $cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
    # Export Public Cert
    Export-Certificate -Cert $cert -FilePath "$HOME\Downloads\$certname.cer"
    # Export .pfx which contains Public Cert AND Private Key
    $mypwd = ConvertTo-SecureString -String "mypasswd!" -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath "$HOME\Downloads\$certname.pfx" -Password $mypwd
    # Double-Click the resulting .pfx file and install it to "Cert:\LocalMachine\My" (it is already under "Cert:\CurrentUser\My" after New-SelfSignedCertificate commmand)
    # Now upload .cer to Azure under your App's "Certificates and Secrets"
    # Take Note of the Thumbprint of certificate via:
    (Get-ChildItem -Path "Cert:\" -Recurse -Force | Where-Object {-not $_.PSIsContainer -and $_.Subject -match "OneDriveAPI"}).Thumbprint | Get-Unique

    ##### END Setup Certificate Based Authentication #####
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
function Create-SyncWithOneDriveContextMenu {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$tenantId,

        [Parameter(Mandatory = $True)]
        [string]$clientId,

        [Parameter(Mandatory = $True)]
        [string]$certificateThumbprint,

        [Parameter(Mandatory = $True)]
        [string]$siteName,

        [Parameter(Mandatory = $True)]
        [string]$TargetDocumentLibrary,

        [Parameter(Mandatory = $True)]
        [string]$LocalDirEquivalentToDocumentLibraryRoot,

        [Parameter(Mandatory = $False)]
        [string]$ContextMenuName = "SyncWithOneDrive",

        [Parameter(Mandatory = $False)]
        [string]$pfxFilePath
    )

    # Install the Microsoft Graph PowerShell SDK
    #Install-Module Microsoft.Graph -AllowClobber -Force -Confirm:$False
    $ModuleName = 'Microsoft.Graph'
    if (!$(Get-Module -ListAvailable $ModuleName -ErrorAction SilentlyContinue)) {
        try {
            $InstallModuleResult = Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
            # WARNING: Don't try to import the entire module...it takes like 5 minutes
            # Instead just use the cmdlets directly and PowerShell will import specifically what you need from the Module at that time
            #Import-Module Microsoft.Graph
            # Alternate Module Install Method
            <#
            Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            Save-Module -Name $ModuleName -Path "$env:ProgramFiles\WindowsPowerShell\Modules" -Force -Confirm:$False -ErrorAction Stop
            #>
        } catch {
            Write-Warning $_.Exception.Message
            Write-Error "Unable to install $ModuleName module! Halting!"
            return
        }
    }

    $BinDir = "C:\Scripts\bin"
    $RunHiddenExePath = "$BinDir\run-hidden.exe"
    $RunHiddenZipPath = "$BinDir\run-hidden.zip"
    $UploadFileToSPOScriptDir = 'C:\Scripts\powershell'
    $UploadFileToSPOScriptPath = "$UploadFileToSPOScriptDir\Upload-FileToSPOViaMSGraphPSSDK.ps1"
    $CertsDir = "C:\Scripts\certs"
    if (-NOT $(Test-Path $UploadFileToSPOScriptDir)) {$null = New-Item -Path $UploadFileToSPOScriptDir -ItemType Directory -Force}
    if (-NOT $(Test-Path $BinDir)) {$null = New-Item -Path $BinDir -ItemType Directory -Force}
    if (-NOT $(Test-Path $CertsDir)) {$null = New-Item -Path $CertsDir -ItemType Directory -Force}

    $PSRegistryCommand = @"
$RunHiddenExePath powershell.exe -File "$UploadFileToSPOScriptPath" "%1"
"@

    # Make sure the run-hidden.exe is installed
    if (!(Test-Path $RunHiddenExePath)) {
        #Write-Error "run-hidden.exe not found! Halting!"
        #return
        Write-Host "Downloading run-hidden.exe ..."
        $null = Invoke-WebRequest -Uri "https://github.com/stax76/run-hidden/releases/download/v1.2/run-hidden-v1.2.zip" -OutFile $RunHiddenZipPath
        $null = Expand-Archive -Path $RunHiddenZipPath -DestinationPath $BinDir -Force
    }

    if ($PSVersionTable.Platform -ne 'Win32NT' -and $PSVersionTable.PSEdition -ne 'Desktop') {
        Write-Error "Only run the {0} function from a Windows operating system! Halting!" -f $MyInvocation.MyCommand
        $global:FunctionResult = "1"
        return
    }

    if (!$(Get-Elevation)) {
        Write-Error "You must run this script/function as Administrator! Halting!"
        $global:FunctionResult = 1
        return
    }

    # Install the OneDriveAPI Azure App Certificate in the Windows Certificate Store If it's not already there
    # Then search Windows Certificate Store for the Thumbprint
    $CurrentUserMyCheck = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object {$_.Thumbprint -eq $certificateThumbprint}
    $LocalMachineMyCheck = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq $certificateThumbprint}
    # Load it into the certificate store if it doesn't already exist
    if (!$CurrentUserMyCheck -or !$LocalMachineMyCheck) {
        $PfxFilePwdSS = Read-Host -Prompt 'Enter password for .pfx file' -AsSecureString
    }
    if (!$CurrentUserMyCheck) {
        # Import the .pfx to the Current User's Personal Store
        $null = Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation Cert:\CurrentUser\My -Password $PfxFilePwdSS
    }
    if (!$LocalMachineMyCheck) {
        # Import the .pfx to the Local Machine's Personal Store
        $null = Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxFilePwdSS
    }

    # Add the registry keys for the context menu entry
    $RegistryPathsToCheck = @(
        'Registry::HKEY_CLASSES_ROOT\*\shell\{0}\command' -f $ContextMenuName
        'Registry::HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\{0}\command' -f $ContextMenuName
    )
    foreach ($RegPath in $RegistryPathsToCheck) {
        Push-Location -PSPath 'Registry::HKEY_CLASSES_ROOT\*\'
        $RelativePath = $RegPath -replace 'Registry::HKEY_CLASSES_ROOT\\\*','.'

        if (!$(Test-Path -PSPath $RegPath)) {    
            $null = New-Item -Path $RelativePath -Force -ErrorAction Stop
        }

        # Check the (Default) String/REG_SZ values for the "command" key
        $RegistryItem = Get-Item $RelativePath
        $RegItemDefaultValue = $($RegistryItem | Get-ItemProperty).'(default)'
        if ($RegItemDefaultValue -ne $PSRegistryCommand) {
            # Update the (Default) String/REG_SZ values for the "command" keys
            $null = Set-Item -Path $RelativePath -Value $PSRegistryCommand
        }
        
        Pop-Location
    }

    # Create the Upload-FileToSPOViaMSGraphPSSDK.ps1.ps1 script
    $UploadFileToSPOViaMSGraphPSSDKScriptContent = @'
param (
    [string[]]$LocalFilesToUpload
)

'@ + @"

# Get your OneDriveAPI App's ClientID and TenantID from the Azure Dashboard
`$tenantId = '$tenantId'
`$clientId = '$clientId'
`$certificateThumbprint = '$certificateThumbprint'
`$siteName = '$siteName'
`$TargetDocumentLibrary = '$TargetDocumentLibrary'
`$LocalDirEquivalentToDocumentLibraryRoot = '$LocalDirEquivalentToDocumentLibraryRoot'

"@ + @'

# Connect to Microsoft Graph
# The below is non-interactive and uses a certificate
Connect-MgGraph -TenantId $tenantId -ClientId $clientId -CertificateThumbprint $certificateThumbprint -NoWelcome

# Get $siteId and $driveId
$SiteInfo = Get-MgSite -Search $sitename
$SiteId = $SiteInfo.Id
$DocumentLibraries = @(Get-MgSiteDrive -SiteId $SiteId | Where-Object {$_.DriveType -eq "documentLibrary"})
# SIDE NOTE: Review Site Collection Storage via $DocumentLibraries.Quota
# Get the specific document libary you want to upload to
$LibraryItem = $DocumentLibraries | Where-Object {$_.Name -eq $TargetDocumentLibrary}
# Fetch DriveId for the specific Document Library
$driveId = $LibraryItem.Id

# Upload a file to the Document Library
# IMPORTANT NOTE: The below $LocalFilesToUpload is pulled from the "%1" in the registry command key value, i.e.
# "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoExit -File "C:\Scripts\powershell\Upload-FileToSPOViaMSgraphPSSDK.ps1" "%1"
foreach ($FilePath in $LocalFilesToUpload) {
    # Make sure $FilePath actually exists
    if (!$(Test-Path -Path $FilePath)) {
        Write-Error "$FilePath does not exist! Check the path and try again. Halting!"
        return
    }

    # IMPORTANT NOTE: The below Get-Content actually downloads the file to the local hard drive if it's not already,
    # so this is a necessary step to prevent scenario where we try to upload a file that is not actually on localhost
    $null = Get-Content -Path $FilePath
    $FileItemToUpload = Get-Item -Path $FilePath 
    $FileToUpload = $FileItemToUpload.FullName
    $FileName = $FileItemToUpload.Name
    $DirPath = $FilePath -replace [regex]::Escape($LocalDirEquivalentToDocumentLibraryRoot),'' -replace $FileName,'' -replace '\\','/'
    $UploadUrl = 'https://graph.microsoft.com/v1.0/sites/' + $siteId + '/drives/' + $driveId + '/root:' + $DirPath + $FileName + ':/content'
    #https://graph.microsoft.com/v1.0/sites/{site-id}/drives/{drive-id}/root:/ProjectDocuments/Report.pdf:/content
    $FileContent = Get-Content -Path $FileToUpload -Raw
    Invoke-MgGraphRequest -Uri $UploadUrl -Method PUT -Body $FileContent -ContentType "text/plain"
}
'@

    Write-Host "Creating $UploadFileToSPOScriptPath ..."
    $UploadFileToSPOViaMSGraphPSSDKScriptContent | Out-File -FilePath $UploadFileToSPOScriptPath -Force

}
