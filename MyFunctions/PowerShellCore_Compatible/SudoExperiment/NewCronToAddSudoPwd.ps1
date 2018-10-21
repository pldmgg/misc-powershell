function NewCronToAddSudoPwd {
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
        $GetMySudoStatusAsString = ${Function:GetMySudoStatus}.Ast.Extent.Text
        $FinalScript = $GetElevationAsString + "`n" + $GetMySudoStatusAsString + "`n" + "GetMySudoStatus"
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
        Write-Host "The account '$(whoami)' is already configured to be prompted for a password when running 'sudo pwsh'! No changes made." -ForegroundColor Green
        return
    }

    $DomainName = $GetSudoStatusResult.DomainInfo.DomainName
    $DomainNameShort = $GetSudoStatusResult.DomainInfo.DomainNameShort
    $UserNameShort = $GetSudoStatusResult.DomainInfo.UserNameShort

    #endregion >> Prep

    #region >> Main

    if ($DomainNameShort) {
        $RemoveUserString = "grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && sed -i '/$DomainNameShort..$UserNameShort ALL.*SUDO_PWSH/d' /etc/sudoers"
    }
    else {
        $RemoveUserString = "grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && sed -i '/$UserNameShort ALL.*SUDO_PWSH/d' /etc/sudoers"
    }

    $BashScriptPrep = @(
        'set -f'
        "croncmd=\`"sleep 10; ps aux | grep -v grep | grep -Eic '$PID.*pwsh' && echo pwshStillRunning || cat /etc/sudoers.d/pwsh-nosudo.conf | $RemoveUserString && ( crontab -l | grep 'ps aux.*cat /etc/sudoers' ) | crontab -\`""
        'cronjob=\"* * * * * $croncmd\"'
        "( crontab -l | grep 'ps aux.*cat /etc/sudoers'; echo \`"`$cronjob\`" ) | crontab -"
    )
    $BashScript = $BashScriptPrep -join '; '
    
    sudo bash -c "$BashScript"

    #endregion >> Main
}