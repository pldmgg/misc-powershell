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
    
    $DomainName = $GetSudoStatusResult.DomainInfo.DomainName
    $DomainNameShort = $GetSudoStatusResult.DomainInfo.DomainNameShort
    $UserNameShort = $GetSudoStatusResult.DomainInfo.UserNameShort

    if (!$GetSudoStatusResult.PasswordPrompt) {
        # Check /etc/sudoers to make sure the desired entry is actually there and we're not just within 10 minutes of having entered the sudo pwd previously
        if ($DomainNameShort) {
            $SudoersCheckScript = "cat /etc/sudoers.d/pwsh-nosudo.conf | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        else {
            $SudoersCheckScript = "cat /etc/sudoers.d/pwsh-nosudo.conf | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        $SudoersCheck = sudo bash -c "$SudoersCheckScript"

        if ($SudoersCheck -eq "present") {
            Write-Host "The account '$(whoami)' is already allowed to run 'sudo pwsh' without being prompted for a password! No changes made." -ForegroundColor Green
            return
        }
    }

    #endregion >> Prep

    #region >> Main

    $PwshLocation = $(Get-Command pwsh).Source
    $SudoConfPath = "/etc/sudoers.d/pwsh-nosudo.conf"
    if ($DomainNameShort) {
        $AddUserString = "%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH"
        $RegexDefinition = "`$UserStringRegex = [regex]::Escape(`"%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH`")"
    } else {
        $AddUserString = "$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH"
        $RegexDefinition = "`$UserStringRegex = [regex]::Escape(`"$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH`")"
    }
    $EditSudoersdFilePrep = @(
        $RegexDefinition    
        '[System.Collections.Generic.List[PSObject]]$UpdateSudoersContent = @('
        "    'Cmnd_Alias SUDO_PWSH = $PwshLocation'"
        "    'Defaults!SUDO_PWSH !requiretty'"
        "    '$AddUserString'"
        ')'
        'if (!$(Test-Path "/etc/sudoers.d")) {'
        '    $null = New-Item -ItemType Directory -Path "/etc/sudoers.d" -Force'
        '    sudo chmod 750 /etc/sudoers.d'
        '}'
        "if (!`$(Test-Path '$SudoConfPath')) {"
        "    Set-Content -Path '$SudoConfPath' -Force -Value `$UpdateSudoersContent"
        "    sudo chmod 440 '$SudoConfPath'"
        '    "sudoConfigUpdated"'
        '}'
        'else {'
        "    [System.Collections.ArrayList][array]`$PwshSudoConfContent = @(Get-Content '$SudoConfPath')"
        '    $MatchingLine = $PwshSudoConfContent -match $UserStringRegex'
        '    if ($MatchingLine) {'
        '        "sudoConfigAlreadyPresent"'
        '    }'
        '    else {'
        '        foreach ($Line in $UpdateSudoersContent) {'
        '            if (![bool]$($PwshSudoConfContent -match [regex]::Escape($Line))) {'
        "                Add-Content -Path '$SudoConfPath' -Value `$Line"
        '            }'
        '        }'
        '        "sudoConfigUpdated"'
        '    }'
        '}'
    )
    $EditSudoersdFile = $EditSudoersdFilePrep -join "`n"

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($EditSudoersdFile)
    $EncodedCommand = [Convert]::ToBase64String($Bytes)
    $Result = sudo pwsh -EncodedCommand $EncodedCommand

    if (!$Result) {
        Write-Error "There was an issue checking/updating '/etc/sudoers.d/pwsh-nosudo.conf'! Please review. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $Result

    <#
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
    #>

    #endregion >> Main
}