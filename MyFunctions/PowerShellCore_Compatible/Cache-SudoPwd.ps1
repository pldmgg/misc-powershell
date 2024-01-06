<#
    .SYNOPSIS
        Cache your sudo password in PSSession with remote Linux machine so you can easily run sudo commands

    .DESCRIPTION
        See SYNOPSIS

    .PARAMETER SudoPass
        REQUIRED. Takes a [securestring] of your sudo password

    .PARAMETER PSSession
        OPTIONAL. Takes an existing [System.Management.Automation.Runspaces.PSSession] (create via New-PSSession)

    .EXAMPLE
        # Example Usage for PSSession with Remote Host #
        Cache-SudoPwd -PSSession $PSSession -SudoPass $(Read-Host 'Enter sudo password' -AsSecureString)
        Invoke-Command $PSSession {sudo whoami}

    .EXAMPLE
        # Example usage *within* a PSSession #
        # Load the function in the existing PSSession
        $FunctionsForRemoteUse = @(
            ${Function:Cache-SudoPwd}.Ast.Extent.Text
        )
        Invoke-Command -Session $PSSession -ScriptBlock {$using:FunctionsForRemoteUse | foreach {Invoke-Expression $_}}
        # Enter the PSSession
        Enter-PSSession $PSSession
        Cache-SudoPwd -SudoPass $(Read-Host 'Enter sudo password' -AsSecureString)
        # Now you can run sudo commands interactively in the PSSession
        sudo whoami
#>
function Cache-SudoPwd {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [securestring]$SudoPass,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession
    )

    if ($PSSession) {
        if ($PSVersionTable.PSVersion -ge [version]'7.1') {
            Invoke-Command $PSSession -ScriptBlock {
                param([securestring]$SudoPassSS)
                $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPassSS))) | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @($SudoPass)
        } else {
            Invoke-Command $PSSession -ScriptBlock {
                param([String]$SudoPassPT)
                $null = $SudoPassPT | sudo -S whoami 2>&1
                if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
            } -ArgumentList @([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass)))
        }
    } else {
        if (!$PSSenderInfo) {
            Write-Error -Message "You must be running this function from within a PSSession or provide a PSSession object via the -PSSession parameter! Halting!"
            return
        }
        $null = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SudoPass))) | sudo -S whoami 2>&1
        if ($LastExitCode -ne 0) {Write-Error -Message "Failed to cache sudo password"; return}
    }
}