function NewCronToAddSudoPwd {
    [CmdletBinding()]
    Param()

    #region >> Prep

    if (GetElevation) {
        Write-Error "You cannot run this function as root! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $GetSudoStatusResult = GetMySudoStatus | ConvertFrom-Json
    
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

    # $BashScript should look like:
    <#
        $BashScript = @'
set -f; croncmd=\"sleep 30; ps aux | grep -Eic '121348.*pwsh' && echo pwshStillRunning || cat /etc/sudoers | grep -Eic 'pdadmin ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && sed -i '/pdadmin ALL.*SUDO_PWSH/d' /etc/sudoers && ( crontab -l | grep '^ps aux.*cat /etc/sudoers' ) | crontab -\"; cronjob=\"* * * * * $croncmd\"; ( crontab -l | grep '^ps aux.*cat /etc/sudoers'; echo \"$cronjob\" ) | crontab -
'@

    # Straight bash
    set -f; croncmd="sleep 30; ps aux | grep -Eic '121348.*pwsh' && echo pwshStillRunning || cat /etc/sudoers | grep -Eic 'pdadmin ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && sed -i '/pdadmin ALL.*SUDO_PWSH/d' /etc/sudoers && ( crontab -l | grep '^ps aux.*cat /etc/sudoers' ) | crontab -"; cronjob="* * * * * $croncmd"; ( crontab -l | grep '^ps aux.*cat /etc/sudoers'; echo "$cronjob" ) | crontab -

    # 
    set -f; croncmd="sleep 30; ps aux | grep -v grep | grep -Eic '121348.*pwsh' && echo pwshStillRunning || cat /etc/sudoers | grep -Eic 'pdadmin ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && sed -i '/pdadmin ALL.*SUDO_PWSH/d' /etc/sudoers && ( crontab -l | grep '^ps aux.*cat /etc/sudoers' ) | crontab -"; cronjob="* * * * * $croncmd"; ( crontab -l | grep '^ps aux.*cat /etc/sudoers'; echo "$cronjob" ) | crontab -
    
    $BashScript = @'
set -f; croncmd=\"sleep 30; ps aux | grep -v grep | grep -Eic '121348.*pwsh' && echo pwshStillRunning || cat /etc/sudoers | grep -Eic 'pdadmin ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && sed -i '/pdadmin ALL.*SUDO_PWSH/d' /etc/sudoers && ( crontab -l | grep '^ps aux.*cat /etc/sudoers' ) | crontab -\"; cronjob=\"* * * * * $croncmd\"; ( crontab -l | grep '^ps aux.*cat /etc/sudoers'; echo \"$cronjob\" ) | crontab -
'@
    #>

    $BashScriptPrep = @(
        'set -f'
        "croncmd=\`"sleep 30; ps aux | grep -v grep | grep -Eic '$PID.*pwsh' && echo pwshStillRunning || cat /etc/sudoers | $RemoveUserString && ( crontab -l | grep '^ps aux.*cat /etc/sudoers' ) | crontab -\`""
        'cronjob=\"* * * * * $croncmd\"'
        "( crontab -l | grep '^ps aux.*cat /etc/sudoers'; echo \`"`$cronjob\`" ) | crontab -"
    )
    $BashScript = $BashScriptPrep -join '; '

    $BashScript
    
    sudo bash -c "$BashScript"

    #endregion >> Main
}