function Add-OneDriveRightClickMenu {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$MenuOptionTitle,
        
        [Parameter(Mandatory=$True)]
        [string]$PathTo365FileUploadScript
    )

    #region >> Helper Functions

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
    
    #endregion >> Helper Functions


    #region >> Prep

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

    # Make sure $PathTo365FileUploadScript exists. If not, halt.
    if (!$(Test-Path -Path $PathTo365FileUploadScript)) {
        Write-Error "The path '$PathTo365FileUploadScript' does not exist! Halting!"
        return
    }

    #New-PSDrive -Name "HKCR" -PSProvider "Registry" -PSPath 'Registry::HKEY_CLASSES_ROOT'

    #endregion >> Prep

    #region >> Main

    # Create the following Registry Keys if they don't already exist
    # HKEY_CLASSES_ROOT\*\shell\SyncWithOneDrive\command
    # Everything up to Computer\HKEY_CLASSES_ROOT\*\shell should already exist by default
    # HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\SyncWithOneDrive\command
    # Everything up to Computer\HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers should exist by default

    $RegistryPathsToCheck = @(
        'Registry::HKEY_CLASSES_ROOT\*\shell\{0}\command' -f $MenuOptionTitle
        'Registry::HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\{0}\command' -f $MenuOptionTitle
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
        $RegValueTarget = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoExit -File "{0}" "%1"' -f $PathTo365FileUploadScript
        if ($RegItemDefaultValue -ne $RegValueTarget) {
            # Update the (Default) String/REG_SZ values for the "command" keys
            $null = Set-Item -Path $RelativePath -Value $RegValueTarget
        }
        
        Pop-Location
    }

    #endregion >> Main
}

$AddRightClickParams = @{
    MenuOptionTitle             = '{placeholder}' # Some string that can fit in the mouse right-click menu
    PathTo365FileUploadScript   = '{placeholder}' # Full Path to Invoke-365FileUpload.ps1, for example 'C:\Scripts\powershell\Invoke-365FileUpload.ps1'
}
Add-OneDriveRightClickMenu @AddRightClickParams
