<#
.SYNOPSIS
    PowerShell function wrapper for the command

    code --folder-uri vscode-remote://ssh-remote+adminuser@192.168.1.2/C:/Users/adminuser

.DESCRIPTION
    See Synopsis

.NOTES
    DEPENDENCEIES
        ssh.exe
.PARAMETER
    N parameter
.PARAMETER
    N+1 parameter
.EXAMPLE
    Start-VSCodeRemote -RemoteUserName "adminuser" -RemoteIPAddress "192.168.1.2" -RemoteWorkingDir "C:\Users\adminuser"
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>
function Start-VSCodeRemote {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$RemoteUserName, # Example: "adminuser"

        [Parameter(Mandatory=$True)]
        [string]$RemoteIPAddress, # Example: "192.168.1.2"

        [Parameter(Mandatory=$True)]
        [string]$RemoteWorkingDir # Example: "C:\Users\adminuser"
    )

    # Make sure we have all of the necessary binaries on the local machine
    try {
        $null = Get-Command ssh -ErrorAction Stop
    } catch {
        Write-Error $_
        return
    }

    # Check to make sure local VSCode instance has the necessary extensions installed
    $RequiredExtensions = @(
        "ms-vscode-remote.remote-ssh"
        "ms-vscode-remote.remote-ssh-edit"
        "ms-vscode-remote.remote-wsl"
        "ms-vscode-remote.remote-wsl-edit"
        "ms-vscode-remote.vscode-remote-extensionpack"
        "ms-vscode-remote.remote-containers"
        "ms-vscode.remote-explorer"
        "ms-vscode.remote-server"
    )
    $InstalledExtensions = code --list-extensions
    $MissingExtensions = $RequiredExtensions | Where-Object {$InstalledExtensions -notcontains $_}
    if ($MissingExtensions) {
        Write-Warning "The following extensions are missing from the local VSCode instance: $MissingExtensions"
        # Install the missing extensions
        $MissingExtensions | ForEach-Object {
            code --install-extension $_
        }
    }

    $CmdString = "code --folder-uri vscode-remote://ssh-remote+$RemoteUserName@$RemoteIPAddress/$RemoteWorkingDir"
    Write-Host "`$CmdString is $CmdString"

    Invoke-Expression $CmdString

}
