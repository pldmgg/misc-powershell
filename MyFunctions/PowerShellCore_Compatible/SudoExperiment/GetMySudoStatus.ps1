<#
    .SYNOPSIS
        Determines if the specified user has sudo privileges on a Remote Host, and if so, whether or not they are prompted for a
        sudo password when running 'sudo pwsh'.

        Returns a pscustomobject with bool properties 'HasSudoPrivileges' and 'PasswordPrompt'.

    .DESCRIPTION
        See SYNOPSIS

    .EXAMPLE
        # Launch pwsh and...

        GetMySudoStatus
        
#>
function GetMySudoStatus {
    [CmdletBinding()]
    Param()

    #region >> Prep

    if (GetElevation) {
        Write-Error "The Get-MySudoStatus function cannot be run as root! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # On Linux, under a Domain Account, 'whoami' returns something like: zeroadmin@zero.lab
    # On Linux, under a Local Account, 'whoami' returns something like: vagrant
    # On Windows under a Domain Account, 'whoami' returns something like: zero\zeroadmin
    # On Windows under a Local Account, 'whoami' returns something like: pdadmin
    $UserName = whoami
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if ($UserName -match '\\') {
            $DomainNameShort = $($UserName -split '\\')[0]
            $UserNameShort = $($UserName -split '\\')[-1]
        }
        else {
            $UserNameShort = $UserName
        }
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if ($UserName -match '@') {
            $DomainName = $($UserName -split "@")[-1]
            $DomainNameShort = $($DomainName -split '\.')[0]
            $UserNameShort = $($UserName -split "@")[0]
        }
        else {
            $UserNameShort = $UserName
        }
    }

    #endregion >> Prep

    #region >> Main

    $PSVerTablePwshBytes = [System.Text.Encoding]::Unicode.GetBytes('$PSVersionTable')
    $EncodedCommand = [Convert]::ToBase64String($PSVerTablePwshBytes)

    [System.Collections.ArrayList]$CheckSudoStatusScriptPrep = @(
        $('prompt=$(sudo -n pwsh -EncodedCommand {0} 2>&1)' -f $EncodedCommand)
        $('if [ $? -eq 0 ]; then echo {0}; elif echo $prompt | grep -q {1}; then echo {2}; else echo {3}; fi' -f "'NoPasswordPrompt'","'^sudo'","'PasswordPrompt'","'NoSudoPrivileges'")
    )
    $CheckSudoStatusScript = $CheckSudoStatusScriptPrep -join '; '
    $Output = bash -c "$CheckSudoStatusScript"
    
    if ($Output -match 'NoPasswordPrompt') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $True
            PasswordPrompt      = $False
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }
    elseif ($Output -match 'PasswordPrompt') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $True
            PasswordPrompt      = $True
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }
    elseif ($Output -match 'NoSudoPrivileges') {
        $FinalOutput = [pscustomobject]@{
            HasSudoPrivileges   = $False
            PasswordPrompt      = $False
            IsDomainAccount     = if ($DomainName -or $DomainNameShort) {$True} else {$False}
            DomainInfo          = [pscustomobject]@{
                DomainName  = $DomainName
                DomainNameShort = $DomainNameShort
                UserNameShort = $UserNameShort
            }
            BashOutput          = $Output
        }
    }

    $FinalOutput | ConvertTo-Json

    #endregion >> Main
}