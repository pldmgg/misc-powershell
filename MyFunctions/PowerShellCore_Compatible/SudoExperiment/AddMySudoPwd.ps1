<#
    .SYNOPSIS
        Edits /etc/sudoers to remove configuration that allows the current user to run 'sudo pwsh' without needing to enter a sudo password.

    .DESCRIPTION
        See SYNOPSIS

    .EXAMPLE
        # Launch pwsh and...

        Add-MySudoPwd
        
#>
function AddMySudoPwd {
    [CmdletBinding()]
    Param()

    #region >> Prep

    if ($PSVersionTable.Platform -ne "Unix") {
        Write-Error "This function is meant for use on Linux! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    # 'Get-SudoStatus' cannnot be run as root...
    if (GetElevation) {
        $GetElevationAsString = ${Function:GetElevation}.Ast.Extent.Text
        $GetMySudoStatusAsString = ${Function:Get-MySudoStatus}.Ast.Extent.Text
        $FinalScript = $GetElevationAsString + "`n" + $GetMySudoStatusAsString + "`n" + "Get-MySudoStatus"
        $PwshScriptBytes = [System.Text.Encoding]::Unicode.GetBytes($FinalScript)
        $EncodedCommand = [Convert]::ToBase64String($PwshScriptBytes)
        $GetSudoStatusResult = su $env:SUDO_USER -c "pwsh -EncodedCommand $EncodedCommand" | ConvertFrom-Json
    }
    else {
        $GetSudoStatusResult = GetMySudoStatus | ConvertFrom-Json
    }
    
    if (!$GetSudoStatusResult.HasSudoPrivileges) {
        Write-Error "The user does not appear to have sudo privileges on $env:HOSTNAME! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    if ($GetSudoStatusResult.PasswordPrompt) {
        Write-Host "The account '$(whoami)' is already configured to prompt for a sudo password! No changes made." -ForegroundColor Green
        return
    }

    $DomainName = $GetSudoStatusResult.DomainInfo.DomainName
    $DomainNameShort = $GetSudoStatusResult.DomainInfo.DomainNameShort
    $UserNameShort = $GetSudoStatusResult.DomainInfo.UserNameShort

    #endregion >> Prep

    #region >> Main

    # cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH = /bin/pwsh' > /dev/null && echo present || echo absent
    [System.Collections.Generic.List[PSObject]]$UpdateSudoersScriptPrep = @()
    if ($DomainNameShort) {
        $RemoveUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && sed -i '/$DomainNameShort..$UserNameShort ALL.*SUDO_PWSH/d' /etc/sudoers || echo 'NotFound'"
    }
    else {
        $RemoveUserString = "cat /etc/sudoers | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && sed -i '/$UserNameShort ALL.*SUDO_PWSH/d' /etc/sudoers || echo 'NotFound'"
    }
    $UpdateSudoersScriptPrep.Add($RemoveUserString)
    $UpdateSudoersScript = $UpdateSudoersScriptPrep -join '; '

    $null = sudo bash -c "$UpdateSudoersScript"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "There was an issue updating /etc/sudoers! Please review. Halting!"
        $global:FunctionResult = "1"
        return
    }

    "Success"

    #endregion >> Main
}