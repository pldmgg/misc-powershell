function Check-Elevation {
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
    Creates an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session.

.DESCRIPTION
    Using WSMan's CredSSP Authentication mechanism, this function creates a New PSSession via the New-PSSession
    cmdlet named "ElevatedPSSessionFor<UserName>". You can then run elevated commandsin the Elevated PSSession by
    either entering the Elevated PSSession via Enter-PSSession cmdlet or by using the Invoke-Command cmdlet with
    its -Session parameter.

    This function will NOT run in a PowerShell Session that was launched using "Run As Administrator".

    When used in a Non-Elevated PowerShell session, this function:

    1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
    configuration changes are made)

    2) Checks the Local Group Policy Object...
        Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
    ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

    3) Creates an Elevated PSSession using the New-PSSession cmdlet

    4) Outputs a PSCustomObject that contains two Properties:
    - ElevatedPSSession - Contains the object [PSSession]ElevatedPSSessionFor<UserName>
    - OriginalWSManAndRegistryStatus - Contains another PSCustomObject with the following Properties -
        OrigAllowFreshCredsProperties  : [A string the represents a registry path to the AllowFreshCredentials Key]
        OrigAllowFreshCredsValues      : [A string that represents the original Values/Properties of the AllowFreshCredentials Key if it existed before this function was run]
        Status                         : [Can be one of the following 3 strings - CredDelKey DNE/AllowFreshCreds DNE/AllowFreshCreds AlreadyExists]
        OrigWSMANConfigStatus          : [If WSMAN/WinRM was already enabled prior to this function being run, this value will be 'true']
        OrigWSMANServiceCredSSPSetting : [The value of WSMan:\localhost\Service\Auth\CredSSP prior to running this function - can be 'true' or 'false']
        OrigWSMANClientCredSSPSetting  : [The value of WSMan:\localhost\Client\Auth\CredSSP prior to running this function - can be 'true' or 'false']
        PropertyToRemove               : [If the AllowFreshCreds Registry Key does not contain a Property that has the value "WSMan/<LocalHostFQDN>" it will be added.
                                         PropertyToRemove will contain the Name of this added Registry Property, which, for the AllowFreshCredentials Key, is a number.]

.NOTES
    Recommend assigning this function to a variable when it is used so that it can be referenced in the companion
    function Remove-SudoSession. If you do NOT assign a variable to this function when it is used, you can always
    reference this function's PSCustomObject output by calling $global:NewSessionAndOriginalStatus, which is a
    Global Scope variable created when this function is run. $global:NewSessionAndOriginalStatus.OriginalWSManAndRegistryStatus
    can be used for Remove-SudoSession's -OriginalConfigInfo parameter, and $global:NewSessionAndOriginalStatus.ElevatedPSSesion
    can be used for Remove-SudoSession's -SessionToRemove parameter.

.PARAMETER UserName
    This is a string that represents a UserName with Administrator privileges. Defaults to current user.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Password
    This can be either a plaintext string or a secure string that represents the password for the -UserName.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Credentials
    This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

.EXAMPLE
    PS C:\Users\zeroadmin> New-SudoSession -UserName zeroadmin -Credentials $MyCreds

    ElevatedPSSession                      OriginalWSManAndRegistryStatus
    -----------------                      ------------------------------
    [PSSession]ElevatedSessionForzeroadmin @{OrigAllowFreshCredsProperties=HKEY_LOCAL_MACHINE\Software\Policies\Microsoft...

    PS C:\Users\zeroadmin> Get-PSSession

     Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
     -- ----            ------------    ------------    -----         -----------------     ------------
      1 ElevatedSess... localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

    PS C:\Users\zeroadmin> Enter-PSSession -Name ElevatedSessionForzeroadmin
    [localhost]: PS C:\Users\zeroadmin\Documents> 

.EXAMPLE
    PS C:\Users\zeroadmin> $MyElevatedSession = New-SudoSession -UserName zeroadmin -Credentials $MyCreds
    PS C:\Users\zeroadmin> Get-PSSession

     Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
     -- ----            ------------    ------------    -----         -----------------     ------------
      1 ElevatedSess... localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

    PS C:\Users\zeroadmin> Invoke-Command -Session $MyElevatedSession.ElevatedPSSession -Scriptblock {Install-Package Nuget.CommandLine -Source chocolatey}

.OUTPUTS
    See DESCRIPTION and NOTES sections

#>
function New-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        $Password,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply Credentials'
        )]
        [System.Management.Automation.PSCredential]$Credentials

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (Check-Elevation) {
        Write-Verbose "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserName -and !$Password -and !$Credentials) {
        $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
    }

    if ($UserName -and $Password) {
        if ($Password.GetType().FullName -eq "System.String") {
            $Password = ConvertTo-SecureString $Password -AsPlainText -Force
        }
        $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
    }

    $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
    $LocalHostFQDN = "$env:ComputerName.$Domain"

    ##### END Variable/Parameter Transforms and PreRunPrep #####

    ##### BEGIN Main Body #####

    $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
    $CredDelRegLocationParent = $CredDelRegLocation | Split-Path -Parent
    $AllowFreshValue = "WSMAN/$LocalHostFQDN"
    $tmpFileXmlPrep = [IO.Path]::GetTempFileName()
    $UpdatedtmpFileXmlName = $tmpFileXmlPrep -replace "\.tmp",".xml"
    $tmpFileXml = $UpdatedtmpFileXmlName
    $TranscriptPath = "$HOME\Open-SudoSession_Transcript_$UserName_$(Get-Date -Format MM-dd-yyy_hhmm_tt).txt"

    $WSManGPOTempConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
try {`$CurrentAllowFreshCredsProperties = Get-ChildItem -Path $CredDelRegLocation | ? {`$_.PSChildName -eq 'AllowFreshCredentials'}} catch {}
try {`$CurrentAllowFreshCredsValues = foreach (`$propNum in `$CurrentAllowFreshCredsProperties) {`$(Get-ItemProperty -Path '$CredDelRegLocation\AllowFreshCredentials').`$propNum}} catch {}

if (!`$(Test-WSMan)) {`$WinRMConfigured = 'false'; winrm quickconfig /force; Start-Sleep -Seconds 5} else {`$WinRMConfigured = 'true'}
try {`$CredSSPServiceSetting = `$(Get-ChildItem WSMan:\localhost\Service\Auth\CredSSP).Value} catch {}
try {`$CredSSPClientSetting = `$(Get-ChildItem WSMan:\localhost\Client\Auth\CredSSP).Value} catch {}
if (`$CredSSPServiceSetting -eq 'false') {Enable-WSManCredSSP -Role Server -Force}
if (`$CredSSPClientSetting -eq 'false') {Enable-WSManCredSSP -DelegateComputer localhost -Role Client -Force}

if (!`$(Test-Path $CredDelRegLocation)) {`$Status = 'CredDelKey DNE'}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds DNE'}
if (`$(Test-Path $CredDelRegLocation) -and `$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds AlreadyExists'}

if (!`$(Test-Path $CredDelRegLocation)) {New-Item -Path $CredDelRegLocation}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {New-Item -Path $CredDelRegLocation\AllowFreshCredentials}

if (`$CurrentAllowFreshCredsValues -notcontains '$AllowFreshValue') {Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFresh -Value `$(`$CurrentAllowFreshCredsProperties.Count+1) -Type DWord; Start-Sleep -Seconds 2; Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name `$(`$CurrentAllowFreshCredsProperties.Count+1) -Value '$AllowFreshValue' -Type String}
New-Variable -Name 'OrigAllowFreshCredsState' -Value `$([pscustomobject][ordered]@{OrigAllowFreshCredsProperties = `$CurrentAllowFreshCredsProperties; OrigAllowFreshCredsValues = `$CurrentAllowFreshCredsValues; Status = `$Status; OrigWSMANConfigStatus = `$WinRMConfigured; OrigWSMANServiceCredSSPSetting = `$CredSSPServiceSetting; OrigWSMANClientCredSSPSetting = `$CredSSPClientSetting; PropertyToRemove = `$(`$CurrentAllowFreshCredsProperties.Count+1)})
`$(Get-Variable -Name 'OrigAllowFreshCredsState' -ValueOnly) | Export-CliXml -Path $tmpFileXml
exit"
"@
    $WSManGPOTempConfigFinal = $WSManGPOTempConfig -replace "`n","; "

    # IMPORTANT NOTE: You CANNOT use the RunAs Verb if UseShellExecute is $false, and you CANNOT use
    # RedirectStandardError or RedirectStandardOutput if UseShellExecute is $true, so we have to write
    # output to a file temporarily
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "powershell.exe"
    $ProcessInfo.RedirectStandardError = $false
    $ProcessInfo.RedirectStandardOutput = $false
    $ProcessInfo.UseShellExecute = $true
    $ProcessInfo.Arguments = $WSManGPOTempConfigFinal
    $ProcessInfo.Verb = "RunAs"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    $WSManAndRegStatus = Import-CliXML $tmpFileXml

    $ElevatedPSSession = New-PSSession -Name "ElevatedSessionFor$UserName" -Authentication CredSSP -Credential $Credentials

    New-Variable -Name "NewSessionAndOriginalStatus" -Scope Global -Value $(
        [pscustomobject][ordered]@{
            ElevatedPSSession   = $ElevatedPSSession
            OriginalWSManAndRegistryStatus   = $WSManAndRegStatus
        }
    ) -Force
    
    $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly)

    # Cleanup 
    Remove-Item $tmpFileXml

    ##### END Main Body #####

}

<#
.SYNOPSIS
    Sudo for PowerShell! This function allows you to run an expression as if you were in "Run as Administrator" mode.

.DESCRIPTION
    Using WSMan's CredSSP Authentication mechanism, this function allows you to run expressions in "Run as Administrator"
    mode. This function is perfect for scripts/functions/modules that have one or two lines that absolutely need to be
    Run As Administrator, but otherwise do not need elevated permissions.

    When used in a Non-Elevated PowerShell session, this function:

    1) Checks to make sure WinRM/WSMan is enabled and configured to allow CredSSP Authentication (if not then
    configuration changes are made)

    2) Checks the Local Group Policy Object...
        Computer Configuration -> Administrative Templates -> System -> Credentials Delegation -> Allow Delegating Fresh Credentials
    ...to make sure it is enabled and configured to allow connections via WSMAN/<LocalHostFQDN>

    3) Creates an Elevated PSSession using the New-PSSession cmdlet

    4) Runs the expression passed to the -Expression parameter in the Elevated PSSession

    5) Removes the Elevated PSSession and reverts all changes made (if any) to Local Group Policy and WSMAN/WinRM config.

.PARAMETER UserName
    This is a string that represents a UserName with Administrator privileges. Defaults to current user.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Password
    This can be either a plaintext string or a secure string that represents the password for the -UserName.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Credentials
    This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

.PARAMETER Expression
    This a *string* that represents a PowerShell expression that will be Run as Administrator. Usage is similar
    to the -Command parameter of the Invoke-Expession cmdlet. See:
    https://msdn.microsoft.com/en-us/powershell/reference/5.1/microsoft.powershell.utility/invoke-expression

.EXAMPLE
    $ModuleToInstall = "PackageManagement"
    $LatestVersion = $(Find-Module PackageManagement).Version
    # PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
    $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'

    Start-SudoSession -Credentials $MyCreds -Expression $InstallModuleExpression

.OUTPUTS
    Depends on the -Expression parameter

#>
function Start-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    [Alias('sudo')]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        $Password,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply Credentials'
        )]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$True)]
        [string]$Expression

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
    if (Check-Elevation) {
        Write-Verbose "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UserName -and !$Password -and !$Credentials) {
        $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
    }

    if ($UserName -and $Password) {
        if ($Password.GetType().FullName -eq "System.String") {
            $Password = ConvertTo-SecureString $Password -AsPlainText -Force
        }
        $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
    }

    $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
    $LocalHostFQDN = "$env:ComputerName.$Domain"

    # Find the variables in the $Expression string
    $InitialRegexMatches = $($Expression | Select-String -Pattern "\$[\w]+:[\w]+([\W]|[^\s]|[\s]|$)|\$[\w]+([\W]|[^\s]|[\s]|$)" -AllMatches).Matches.Value
    if ($InitialRegexMatches.Count -gt 0) {
        $TrimmedRegexMatches = $InitialRegexMatches | % {$_.Substring(0,$_.Length-1)}
        [array]$VariableNames = $TrimmedRegexmatches -replace "\$",""
        # Redefine variables within this function's scope
        foreach ($varname in $VariableNames) {
            if ($varname -like "*script:*") {
                New-Variable -Name $varname -Value $(Get-Variable -Name $varname -Scope 2 -ValueOnly)
            }
            if ($varname -like "*local:*" -or $varname -notmatch "script:|global:") {
                New-Variable -Name $varname -Value $(Get-Variable -Name $varname -Scope 1 -ValueOnly)
            }
        }

        $UpdatedVariableArray = @()
        foreach ($varname in $VariableNames) {
            New-Variable -Name "SuperVar" -Value $(
                [pscustomobject][ordered]@{
                    Name    = $varname
                    Value   = Get-Variable -Name $varname -ValueOnly
                }
            )
            
            $UpdatedVariableArray +=, $(Get-Variable -Name "SuperVar" -ValueOnly)
        }
        # Update the string references to variables in the $Expression string if any of them are scope-special
        for ($i=0; $i -lt $VariableNames.Count; $i++) {
            $Expression = $Expression -replace "$($VariableNames[$i])","args[$i]"
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
    $CredDelRegLocationParent = $CredDelRegLocation | Split-Path -Parent
    $AllowFreshValue = "WSMAN/$LocalHostFQDN"
    $tmpFileXmlPrep = [IO.Path]::GetTempFileName()
    $UpdatedtmpFileXmlName = $tmpFileXmlPrep -replace "\.tmp",".xml"
    $tmpFileXml = $UpdatedtmpFileXmlName
    $TranscriptPath = "$HOME\Start-SudoSession_Transcript_$UserName_$(Get-Date -Format MM-dd-yyy_hhmm_tt).txt"

    $WSManGPOTempConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
try {`$CurrentAllowFreshCredsProperties = Get-ChildItem -Path $CredDelRegLocation | ? {`$_.PSChildName -eq 'AllowFreshCredentials'}} catch {}
try {`$CurrentAllowFreshCredsValues = foreach (`$propNum in `$CurrentAllowFreshCredsProperties) {`$(Get-ItemProperty -Path '$CredDelRegLocation\AllowFreshCredentials').`$propNum}} catch {}

if (!`$(Test-WSMan)) {`$WinRMConfigured = 'false'; winrm quickconfig /force; Start-Sleep -Seconds 5} else {`$WinRMConfigured = 'true'}
try {`$CredSSPServiceSetting = `$(Get-ChildItem WSMan:\localhost\Service\Auth\CredSSP).Value} catch {}
try {`$CredSSPClientSetting = `$(Get-ChildItem WSMan:\localhost\Client\Auth\CredSSP).Value} catch {}
if (`$CredSSPServiceSetting -eq 'false') {Enable-WSManCredSSP -Role Server -Force}
if (`$CredSSPClientSetting -eq 'false') {Enable-WSManCredSSP -DelegateComputer localhost -Role Client -Force}

if (!`$(Test-Path $CredDelRegLocation)) {`$Status = 'CredDelKey DNE'}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds DNE'}
if (`$(Test-Path $CredDelRegLocation) -and `$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {`$Status = 'AllowFreshCreds AlreadyExists'}

if (!`$(Test-Path $CredDelRegLocation)) {New-Item -Path $CredDelRegLocation}
if (`$(Test-Path $CredDelRegLocation) -and !`$(Test-Path $CredDelRegLocation\AllowFreshCredentials)) {New-Item -Path $CredDelRegLocation\AllowFreshCredentials}

if (`$CurrentAllowFreshCredsValues -notcontains '$AllowFreshValue') {Set-ItemProperty -Path $CredDelRegLocation -Name ConcatenateDefaults_AllowFresh -Value `$(`$CurrentAllowFreshCredsProperties.Count+1) -Type DWord; Start-Sleep -Seconds 2; Set-ItemProperty -Path $CredDelRegLocation\AllowFreshCredentials -Name `$(`$CurrentAllowFreshCredsProperties.Count+1) -Value '$AllowFreshValue' -Type String}
New-Variable -Name 'OrigAllowFreshCredsState' -Value `$([pscustomobject][ordered]@{OrigAllowFreshCredsProperties = `$CurrentAllowFreshCredsProperties; OrigAllowFreshCredsValues = `$CurrentAllowFreshCredsValues; Status = `$Status; OrigWSMANConfigStatus = `$WinRMConfigured; OrigWSMANServiceCredSSPSetting = `$CredSSPServiceSetting; OrigWSMANClientCredSSPSetting = `$CredSSPClientSetting; PropertyToRemove = `$(`$CurrentAllowFreshCredsProperties.Count+1)})
`$(Get-Variable -Name 'OrigAllowFreshCredsState' -ValueOnly) | Export-CliXml -Path $tmpFileXml
exit"
"@
    $WSManGPOTempConfigFinal = $WSManGPOTempConfig -replace "`n","; "

    # IMPORTANT NOTE: You CANNOT use the RunAs Verb if UseShellExecute is $false, and you CANNOT use
    # RedirectStandardError or RedirectStandardOutput if UseShellExecute is $true, so we have to write
    # output to a file temporarily
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "powershell.exe"
    $ProcessInfo.RedirectStandardError = $false
    $ProcessInfo.RedirectStandardOutput = $false
    $ProcessInfo.UseShellExecute = $true
    $ProcessInfo.Arguments = $WSManGPOTempConfigFinal
    $ProcessInfo.Verb = "RunAs"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    $WSManAndRegStatus = Import-CliXML $tmpFileXml

    $ElevatedPSSession = New-PSSession -Name "ElevatedSessionFor$UserName" -Authentication CredSSP -Credential $Credentials

    if ($InitialRegexMatches.Count -gt 0) {
        $UpdatedVariableArrayNames = foreach ($varname in $UpdatedVariableArray.Name) {
            "`$"+"$varname"
        }
        [string]$FinalArgumentList = $UpdatedVariableArrayNames -join ","

        # If there is only one argument to pass to the scriptblock, the special $args variable within the scriptblock BECOMES
        # that argument, as opposed to being an array of psobjects that contains one element, i.e. the single argument object
        # So we need to fake it out
        if ($UpdatedVariableArray.Count -eq 1) {
            $FinalArgumentList = "$FinalArgumentList"+","+"`"`""
        }

        # Time for the magic...
        Invoke-Expression "Invoke-Command -Session `$ElevatedPSSession -ArgumentList $FinalArgumentList -Scriptblock {$Expression}"
    }
    else {
        Invoke-Expression "Invoke-Command -Session `$ElevatedPSSession -Scriptblock {$Expression}"
    }

    # Cleanup
    $WSManGPORevertConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
if ('$($WSManAndRegStatus.Status)' -eq 'CredDelKey DNE') {Remove-Item -Recurse $CredDelRegLocation -Force}
if ('$($WSManAndRegStatus.Status)' -eq 'AllowFreshCreds DNE') {Remove-Item -Recurse $CredDelRegLocation\AllowFreshCredentials -Force}
if ('$($WSManAndRegStatus.Status)' -eq 'AllowFreshCreds AlreadyExists') {Remove-ItemProperty $CredDelRegLocation\AllowFreshCredentials\AllowFreshCredentials -Name $($WSManAndRegStatus.PropertyToRemove) -Force}
if ('$($WSManAndRegStatus.OrigWSMANConfigStatus)' -eq 'false') {Stop-Service -Name WinRm; Set-Service WinRM -StartupType "Manual"}
if ('$($WSManAndRegStatus.OrigWSMANServiceCredSSPSetting)' -eq 'false') {Set-ItemProperty -Path WSMan:\localhost\Service\Auth\CredSSP -Value `$false}
if ('$($WSManAndRegStatus.OrigWSMANClientCredSSPSetting)' -eq 'false') {Set-ItemProperty -Path WSMan:\localhost\Client\Auth\CredSSP -Value `$false}
exit"
"@
    $WSManGPORevertConfigFinal = $WSManGPORevertConfig -replace "`n","; "

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "powershell.exe"
    $ProcessInfo.RedirectStandardError = $false
    $ProcessInfo.RedirectStandardOutput = $false
    $ProcessInfo.UseShellExecute = $true
    $ProcessInfo.Arguments = $WSManGPOTempConfigFinal
    $ProcessInfo.Verb = "RunAs"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()

    Remove-Item $tmpFileXml -Force
    Remove-PSSession $ElevatedPSSession

    ##### END Main Body #####

}



<#
.SYNOPSIS
    Removes an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session and
    and reverts any changes in WSMAN/WinRM and GPO configuration made by the companion New-SudoSession function.

    This is a companion function with New-SudoSession. If you DO NOT want to ensure that WinRM/WSMan and GPO configuration
    is as it was prior to running New-SudoSession, there is no reason to use this function. You can simply use...
        Get-PSSession | Remove-PSession
    ...like any other normal PSSession.

    If you DO want to ensure that WinRM/WSMan and GPO configuration is as it was prior to running New-SudoSession, then
    use this function with its -RevertConfig switch and -OriginalConfigInfo parameter.

.DESCRIPTION
    Removes an Elevated (i.e. "Run As Administrator") PSSession for the current user in the current PowerShell Session and
    and reverts any changes in WSMAN/WinRM and GPO configuration made by the companion New-SudoSession function.
    
    This is a companion function with New-SudoSession. If you DO NOT want to ensure that WinRM/WSMan and GPO configuration
    is as it was prior to running New-SudoSession, there is no reason to use this function. You can simply use...
        Get-PSSession | Remove-PSession
    ...like any other normal PSSession.

    If you DO want to ensure that WinRM/WSMan and GPO configuration is as it was prior to running New-SudoSession, then
    use this function with its -RevertConfig switch and -OriginalConfigInfo parameter.

.PARAMETER UserName
    This is a string that represents a UserName with Administrator privileges. Defaults to current user.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Password
    This can be either a plaintext string or a secure string that represents the password for the -UserName.

    This parameter is mandatory if you do NOT use the -Credentials parameter.

.PARAMETER Credentials
    This is a System.Management.Automation.PSCredential object used to create an elevated PSSession.

.PARAMETER OriginalConfigInfo
    A PSCustomObject that can be found in the "OriginalWSManAndRegistryStatus" property of the PSCustomObject generated
    by the New-SudoSession function. The "OriginalWSManAndRegistryStatus" property is itself a PSCustomObject with the
    following properties:
        OrigAllowFreshCredsProperties  : [A string the represents a registry path to the AllowFreshCredentials Key]
        OrigAllowFreshCredsValues      : [A string that represents the original Values/Properties of the AllowFreshCredentials Key if it existed before this function was run]
        Status                         : [Can be one of the following 3 strings - CredDelKey DNE/AllowFreshCreds DNE/AllowFreshCreds AlreadyExists]
        OrigWSMANConfigStatus          : [If WSMAN/WinRM was already enabled prior to this function being run, this value will be 'true']
        OrigWSMANServiceCredSSPSetting : [The value of WSMan:\localhost\Service\Auth\CredSSP prior to running this function - can be 'true' or 'false']
        OrigWSMANClientCredSSPSetting  : [The value of WSMan:\localhost\Client\Auth\CredSSP prior to running this function - can be 'true' or 'false']
        PropertyToRemove               : [If the AllowFreshCreds Registry Key does not contain a Property that has the value "WSMan/<LocalHostFQDN>" it will be added.
                                         PropertyToRemove will contain the Name of this added Registry Property, which, for the AllowFreshCredentials Key, is a number.]

.PARAMETER SessionToRemove
    A System.Management.Automation.Runspaces.PSSession object that you would like to remove. You can use the 
    "ElevatedPSSession" property of the PSCustomObject generated by the New-SudoSession function, or, you can simply
    get whichever PSSession you would like to remove by doing the typical...
        Get-PSSession -Name <Name>
    
    This parameter accepts value from the pipeline.

.EXAMPLE
    Get-PSSession -Name <Name>
    $ModuleToInstall = "PackageManagement"
    $LatestVersion = $(Find-Module PackageManagement).Version
    # PLEASE NOTE the use of single quotes in the below $InstallModuleExpression string
    $InstallModuleExpression = 'Install-Module -Name $ModuleToInstall -RequiredVersion $LatestVersion'

    $SudoSession = New-SudoSession -Credentials $MyCreds -Expression $InstallModuleExpression

    Remove-SudoSession -Credentials $MyCreds -OriginalConfigInfo $SudoSession.OriginalWSManAndRegistryStatus -SessionToRemove $SudoSession.ElevatedPSSession

#>
function Remove-SudoSession {
    [CmdletBinding(DefaultParameterSetName='Supply UserName and Password')]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        [string]$UserName = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split "\\")[-1],

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply UserName and Password'
        )]
        $Password,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Supply Credentials'
        )]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory=$True)]
        $OriginalConfigInfo = $(Get-Variable -Name "NewSessionAndOriginalStatus" -ValueOnly).OriginalWSManAndRegistryStatus,

        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$true,
            Position=0
        )]
        [System.Management.Automation.Runspaces.PSSession]$SessionToRemove

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($OriginalConfigInfo -eq $null) {
        Write-Warning "Unable to determine the original configuration of WinRM/WSMan and AllowFreshCredentials Registry prior to using New-SudoSession. No configuration changes will be made/reverted."
        Write-Warning "The only action will be removing the Elevated PSSession specified by the -SessionToRemove parameter."
    }

    if ($UserName -and !$Password -and !$Credentials -and $OriginalConfigInfo -ne $null) {
        $Password = Read-Host -Prompt "Please enter the password for $UserName" -AsSecureString
    }

    if ($UserName -and $Password) {
        if ($Password.GetType().FullName -eq "System.String") {
            $Password = ConvertTo-SecureString $Password -AsPlainText -Force
        }
        $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password
    }

    $Domain = $(Get-CimInstance -ClassName Win32_ComputerSystem).Domain
    $LocalHostFQDN = "$env:ComputerName.$Domain"

    ##### END Variable/Parameter Transforms and PreRunPrep #####

    ##### BEGIN Main Body #####

    if ($OriginalConfigInfo -ne $null) {
        $CredDelRegLocation = "HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation"
        $CredDelRegLocationParent = $CredDelRegLocation | Split-Path -Parent
        $AllowFreshValue = "WSMAN/$LocalHostFQDN"
        $tmpFileXmlPrep = [IO.Path]::GetTempFileName()
        $UpdatedtmpFileXmlName = $tmpFileXmlPrep -replace "\.tmp",".xml"
        $tmpFileXml = $UpdatedtmpFileXmlName
        $TranscriptPath = "$HOME\Remove-SudoSession_Transcript_$UserName_$(Get-Date -Format MM-dd-yyy_hhmm_tt).txt"

        $WSManGPORevertConfig = @"
-noprofile -WindowStyle Hidden -Command "Start-Transcript -Path $TranscriptPath -Append
if ('$($OriginalConfigInfo.Status)' -eq 'CredDelKey DNE') {Remove-Item -Recurse $CredDelRegLocation -Force}
if ('$($OriginalConfigInfo.Status)' -eq 'AllowFreshCreds DNE') {Remove-Item -Recurse $CredDelRegLocation\AllowFreshCredentials -Force}
if ('$($OriginalConfigInfo.Status)' -eq 'AllowFreshCreds AlreadyExists') {Remove-ItemProperty $CredDelRegLocation\AllowFreshCredentials\AllowFreshCredentials -Name $($WSManAndRegStatus.PropertyToRemove) -Force}
if ('$($OriginalConfigInfo.OrigWSMANConfigStatus)' -eq 'false') {Stop-Service -Name WinRm; Set-Service WinRM -StartupType "Manual"}
if ('$($OriginalConfigInfo.OrigWSMANServiceCredSSPSetting)' -eq 'false') {Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value `$false}
if ('$($OriginalConfigInfo.OrigWSMANClientCredSSPSetting)' -eq 'false') {Set-Item -Path WSMan:\localhost\Client\Auth\CredSSP -Value `$false}
exit"
"@
        $WSManGPORevertConfigFinal = $WSManGPORevertConfig -replace "`n","; "

        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "powershell.exe"
        $ProcessInfo.RedirectStandardError = $false
        $ProcessInfo.RedirectStandardOutput = $false
        $ProcessInfo.UseShellExecute = $true
        $ProcessInfo.Arguments = $WSManGPORevertConfigFinal
        $ProcessInfo.Verb = "RunAs"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()

    }

    Remove-PSSession $SessionToRemove

    ##### END Main Body #####

}







# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+PbNEuzs82kPJ5HwOhw5CJY+
# 2FCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFL/TeRh6eg7TBezy
# +nTTn5HRxK55MA0GCSqGSIb3DQEBAQUABIIBAElmrG5pXHzgR+MIqWb3dAUpRDZU
# ryxCPCdCsFY6U0S+v/EM7HEoblfiBOqVJF1p6ap7Im7ANbsQmd5gzD+oEzEjp7l7
# +c7QkqN9lw7jL05yX6s91rP5NNvY8SpaL9bVt1uq4s+0lksZ07iIRn2x2ifqH31l
# VzItWrFpHATxfl8Cdhjl6YvBZSVpY/J/Bj9fV8V6ezuQjgOS9xC4sB4bJA0SFpQr
# 4JqLkQrA54gWRhJE8DhZtwohynVFAN5m2oRmHkrC3BWn1tt0OXbKxDe61i5oYW3x
# qr46bFmtYYzJgTh3r9/qn/3/voKr+aFQ5ja30tK/8K7r1xfMw+E6q0Ke6aY=
# SIG # End signature block
