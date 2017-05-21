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

    ##### BEGIN Native Helper Functions #####

    function Check-Elevation {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
            New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent());

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
            [System.Security.Principal.WindowsBuiltInRole]::Administrator;

        if($currentPrincipal.IsInRole($administratorsRole))
        {
            return $true;
        }
        else
        {
            return $false;
        }
    }

    if (Check-Elevation) {
        Write-Verbose "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        Write-Error "The current PowerShell Session is already being run with elevated permissions. There is no reason to use the Start-SudoSession function. Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

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
if ($($WSManAndRegStatus.Status) -eq 'CredDelKey DNE') {Remove-Item -Recurse $CredDelRegLocation -Force}
if ($($WSManAndRegStatus.Status) -eq 'AllowFreshCreds DNE') {Remove-Item -Recurse $CredDelRegLocation\AllowFreshCredentials -Force}
if ($($WSManAndRegStatus.Status) -eq 'AllowFreshCreds AlreadyExists') {Remove-ItemProperty $CredDelRegLocation\AllowFreshCredentials\AllowFreshCredentials -Name $($WSManAndRegStatus.PropertyToRemove) -Force}
if ($($WSManAndRegStatus.OrigWSMANConfigStatus) -eq 'false') {Stop-Service -Name WinRm; Set-Service WinRM -StartupType "Manual"}
if ($($WSManAndRegStatus.OrigWSMANServiceCredSSPSetting) -eq 'false') {Set-ItemProperty -Path WSMan:\localhost\Server\Auth\CredSSP -Value `$false}
if ($($WSManAndRegStatus.OrigWSMANClientCredSSPSetting) -eq 'false') {Set-ItemProperty -Path WSMan:\localhost\Client\Auth\CredSSP -Value `$false}
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




# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUX3aJdt75g9hXm1w60oz6l2mU
# nuGgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE1MDkwOTA5NTAyNFoXDTE3MDkwOTEwMDAyNFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmRIzy6nwK
# uqvhoz297kYdDXs2Wom5QCxzN9KiqAW0VaVTo1eW1ZbwZo13Qxe+6qsIJV2uUuu/
# 3jNG1YRGrZSHuwheau17K9C/RZsuzKu93O02d7zv2mfBfGMJaJx8EM4EQ8rfn9E+
# yzLsh65bWmLlbH5OVA0943qNAAJKwrgY9cpfDhOWiYLirAnMgzhQd3+DGl7X79aJ
# h7GdVJQ/qEZ6j0/9bTc7ubvLMcJhJCnBZaFyXmoGfoOO6HW1GcuEUwIq67hT1rI3
# oPx6GtFfhCqyevYtFJ0Typ40Ng7U73F2hQfsW+VPnbRJI4wSgigCHFaaw38bG4MH
# Nr0yJDM0G8XhAgMBAAGjggECMIH/MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQW
# BBQ4uUFq5iV2t7PneWtOJALUX3gTcTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA
# QTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBR2
# lbqmEvZFA0XsBkGBBXi2Cvs4TTAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vcGtp
# L2NlcnRkYXRhL1plcm9EQzAxLmNybDA8BggrBgEFBQcBAQQwMC4wLAYIKwYBBQUH
# MAKGIGh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb0RDMDEuY3J0MA0GCSqGSIb3DQEB
# CwUAA4IBAQAUFYmOmjvbp3goa3y95eKMDVxA6xdwhf6GrIZoAg0LM+9f8zQOhEK9
# I7n1WbUocOVAoP7OnZZKB+Cx6y6Ek5Q8PeezoWm5oPg9XUniy5bFPyl0CqSaNWUZ
# /zC1BE4HBFF55YM0724nBtNYUMJ93oW/UxsWL701c3ZuyxBhrxtlk9TYIttyuGJI
# JtbuFlco7veXEPfHibzE+JYc1MoGF/whz6l7bC8XbgyDprU1JS538gbgPBir4RPw
# dFydubWuhaVzRlU3wedYMsZ4iejV2xsf8MHF/EHyc/Ft0UnvcxBqD0sQQVkOS82X
# +IByWP0uDQ2zOA1L032uFHHA65Bt32w8MIIFmzCCBIOgAwIBAgITWAAAADw2o858
# ZSLnRQAAAAAAPDANBgkqhkiG9w0BAQsFADA9MRMwEQYKCZImiZPyLGQBGRYDTEFC
# MRQwEgYKCZImiZPyLGQBGRYEWkVSTzEQMA4GA1UEAxMHWmVyb1NDQTAeFw0xNTEw
# MjcxMzM1MDFaFw0xNzA5MDkxMDAwMjRaMD4xCzAJBgNVBAYTAlVTMQswCQYDVQQI
# EwJWQTEPMA0GA1UEBxMGTWNMZWFuMREwDwYDVQQDEwhaZXJvQ29kZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8LM3f3308MLwBHi99dvOQqGsLeC11p
# usrqMgmEgv9FHsYv+IIrW/2/QyBXVbAaQAt96Tod/CtHsz77L3F0SLuQjIFNb522
# sSPAfDoDpsrUnZYVB/PTGNDsAs1SZhI1kTKIjf5xShrWxo0EbDG5+pnu5QHu+EY6
# irn6C1FHhOilCcwInmNt78Wbm3UcXtoxjeUl+HlrAOxG130MmZYWNvJ71jfsb6lS
# FFE6VXqJ6/V78LIoEg5lWkuNc+XpbYk47Zog+pYvJf7zOric5VpnKMK8EdJj6Dze
# 4tJ51tDoo7pYDEUJMfFMwNOO1Ij4nL7WAz6bO59suqf5cxQGd5KDJ1ECAwEAAaOC
# ApEwggKNMA4GA1UdDwEB/wQEAwIHgDA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3
# FQiDuPQ/hJvyeYPxjziDsLcyhtHNeIEnofPMH4/ZVQIBZAIBBTAdBgNVHQ4EFgQU
# a5b4DOy+EUyy2ILzpUFMmuyew40wHwYDVR0jBBgwFoAUOLlBauYldrez53lrTiQC
# 1F94E3EwgeMGA1UdHwSB2zCB2DCB1aCB0qCBz4aBq2xkYXA6Ly8vQ049WmVyb1ND
# QSxDTj1aZXJvU0NBLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxD
# Tj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NlcnRp
# ZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmli
# dXRpb25Qb2ludIYfaHR0cDovL3BraS9jZXJ0ZGF0YS9aZXJvU0NBLmNybDCB4wYI
# KwYBBQUHAQEEgdYwgdMwgaMGCCsGAQUFBzAChoGWbGRhcDovLy9DTj1aZXJvU0NB
# LENOPUFJQSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxD
# Tj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NBQ2VydGlmaWNhdGU/YmFz
# ZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MCsGCCsGAQUFBzAC
# hh9odHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EuY3J0MBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwDQYJKoZIhvcNAQEL
# BQADggEBACbc1NDl3NTMuqFwTFd8NHHCsSudkVhuroySobzUaFJN2XHbdDkzquFF
# 6f7KFWjqR3VN7RAi8arW8zESCKovPolltpp3Qu58v59qZLhbXnQmgelpA620bP75
# zv8xVxB9/xmmpOHNkM6qsye4IJur/JwhoHLGqCRwU2hxP1pu62NUK2vd/Ibm8c6w
# PZoB0BcC7SETNB8x2uKzJ2MyAIuyN0Uy/mGDeLyz9cSboKoG6aQibnjCnGAVOVn6
# J7bvYWJsGu7HukMoTAIqC6oMGerNakhOCgrhU7m+cERPkTcADVH/PWhy+FJWd2px
# ViKcyzWQSyX93PcOj2SsHvi7vEAfCGcxggH1MIIB8QIBATBUMD0xEzARBgoJkiaJ
# k/IsZAEZFgNMQUIxFDASBgoJkiaJk/IsZAEZFgRaRVJPMRAwDgYDVQQDEwdaZXJv
# U0NBAhNYAAAAPDajznxlIudFAAAAAAA8MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS9nwmnotVU
# 0qBMxX8GMPxBMGneOjANBgkqhkiG9w0BAQEFAASCAQBIIm7Bsr5i7qDpoJ78ltA9
# Ynzu+cMExPQ92xlKbVYzTt0MvmbD+b6wbvRqTL9zupIjVWD6k+QpBY5YL+FvmGdV
# wACGHMagP4ht9m71G438+5h6KioT51sKCfSH0JhNSSFqXTQkoFTKVUuerOhcZMyw
# vC3QV9FEeywDA8tVm0ZDvC5R1GvEojUAUHD4UF1Avn/J+UYMWs8lq1/76IyN6njr
# WPcNu+lU7PjPN9p9i9rxL7eRmpREyXzI+eJ9Z2G6PBIMjmPI/rzyowqwkZUOP8mN
# GX3drgpdU5QxxJ7zsdXm62w6V2E8zpNgKKXujbSkhdcIvL0lCDK/v69QU6DkSAj2
# SIG # End signature block
