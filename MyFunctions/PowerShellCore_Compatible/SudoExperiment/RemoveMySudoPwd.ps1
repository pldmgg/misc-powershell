<#
    .SYNOPSIS
        Edits /etc/sudoers to allow the current user to run 'sudo pwsh' without needing to enter a sudo password.

    .DESCRIPTION
        See SYNOPSIS

    .EXAMPLE
        # Launch pwsh and...

        Remove-SudoPwd
        
#>
function RemoveMySudoPwd {
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
    
    $DomainName = $GetSudoStatusResult.DomainInfo.DomainName
    $DomainNameShort = $GetSudoStatusResult.DomainInfo.DomainNameShort
    $UserNameShort = $GetSudoStatusResult.DomainInfo.UserNameShort

    if (!$GetSudoStatusResult.PasswordPrompt) {
        # Check /etc/sudoers to make sure the desired entry is actually there and we're not just within 10 minutes of having entered the sudo pwd previously
        if ($DomainNameShort) {
            $SudoersCheckScript = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        else {
            $SudoersCheckScript = "cat /etc/sudoers | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        $SudoersCheck = sudo bash -c "$SudoersCheckScript"

        if ($SudoersCheck -eq "present") {
            Write-Host "The account '$(whoami)' is already allowed to run 'sudo pwsh' without being prompted for a password! No changes made." -ForegroundColor Green
            return
        }
    }

    #endregion >> Prep

    #region >> Main

    # cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH = /bin/pwsh' > /dev/null && echo present || echo absent
    [System.Collections.Generic.List[PSObject]]$UpdateSudoersScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        "cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH =' > /dev/null && echo present || echo 'Cmnd_Alias SUDO_PWSH = '`"`$pscorepath`" | sudo EDITOR='tee -a' visudo"
        "cat /etc/sudoers | grep -Eic 'Defaults!SUDO_PWSH !requiretty' > /dev/null && echo present || echo 'Defaults!SUDO_PWSH !requiretty' | sudo EDITOR='tee -a' visudo"
    )
    if ($DomainNameShort) {
        $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && echo present || echo '%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
    }
    else {
        $AddUserString = "cat /etc/sudoers | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && echo present || echo '$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
    }
    $UpdateSudoersScriptPrep.Add($AddUserString)
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