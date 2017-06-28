<#
.SYNOPSIS
    Short description
.DESCRIPTION
    Long description
.NOTES
    NOTE
.PARAMETER PowerShell6Path
    N parameter
.EXAMPLE
    Example of how to use this cmdlet
.EXAMPLE
    Another example of how to use this cmdlet
.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    Output from this cmdlet (if any)
#>

function Install-SSH {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PowerShell6Path = "C:\Program Files\PowerShell\6.0.0-beta.3\powershell.exe",

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKeys
     )

    ## BEGIN Native Helper Functions ##
    function Check-Elevation {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
            New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent());

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
            [System.Security.Principal.WindowsBuiltInRole]::Administrator;

        if($currentPrincipal.IsInRole($administratorsRole)){
            return $true;
        }
        else {
            return $false;
        }
    }

    function Test-Port {
        [CmdletBinding()]
        [Alias('testport')]
        Param(
            [Parameter(Mandatory=$False)]
            $HostName = $env:COMPUTERNAME,

            [Parameter(Mandatory=$False)]
            [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
        )

        Begin {
            
            ##### BEGIN Parameter Validation #####

            function Test-IsValidIPAddress([string]$IPAddress) {
                [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
                [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
                Return  ($Valid -and $Octets)
            }

            $HostNetworkInfoArray = @()
            if (! $(Test-IsValidIPAddress -IPAddress $HostName)) {
                try {
                    $HostIP = $(Resolve-DNSName $HostName).IPAddress
                }
                catch {
                    Write-Verbose "Unable to resolve $HostName!"
                }
                if ($HostIP) {
                    # Filter out any non IPV4 IP Addresses that are in $HostIP
                    $HostIP = $HostIP | % {[ipaddress]$_} | % {if ($_.AddressFamily -eq "InterNetwork") {$_.IPAddressToString}}
                    # If there is still more than one IPAddress string in $HostIP, just select the first one
                    if ($HostIP.Count -gt 1) {
                        $IP = $HostIP[0]
                    }
                    if ($HostIP -eq "127.0.0.1") {
                        $LocalHostInfo = Get-CimInstance Win32_ComputerSystem
                        $DNSHostName = "$($LocalHostInfo.Name)`.$($LocalHostInfo.Domain)"
                        $HostNameFQDN = $DNSHostName
                    }
                    else {
                        $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                        $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
                    }

                    $pos = $HostNameFQDN.IndexOf(".")
                    $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                    $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)

                    $HostNetworkInfoArray += $HostIP
                    $HostNetworkInfoArray += $HostNameFQDN
                    $HostNetworkInfoArray += $HostNameFQDNPre
                }
                if (!$HostIP) {
                    Write-Error "Unable to resolve $HostName! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            if (Test-IsValidIPAddress -IPAddress $HostName) {
                try {
                    $HostIP = $HostName
                    $DNSHostName = $(Resolve-DNSName $HostIP).NameHost
                    $HostNameFQDN = $($(Resolve-DNSName $DNSHostName) | ? {$_.IPAddress -eq $HostIP}).Name
                }
                catch {
                    Write-Verbose "Unable to resolve $HostName!"
                }
                if ($HostNameFQDN) {
                    if ($($HostNameFQDN | Select-String -Pattern "\.").Matches.Success) {
                        $pos = $HostNameFQDN.IndexOf(".")
                        $HostNameFQDNPre = $HostNameFQDN.Substring(0, $pos)
                        $HostNameFQDNPost = $HostNameFQDN.Substring($pos+1)
                    }
                    else {
                        $HostNameFQDNPre = $HostNameFQDN
                        $HostNameFQDNPost = $HostNameFQDN
                    }

                    $HostNetworkInfoArray += $HostIP
                    $HostNetworkInfoArray += $HostNameFQDN
                    $HostNetworkInfoArray += $HostNameFQDNPre
                }
                if (!$HostNameFQDN) {
                    Write-Error "Unable to resolve $HostName! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            ##### END Parameter Validation #####

            ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
            
            $tcp = New-Object Net.Sockets.TcpClient
            
            ##### END Variable/Parameter Transforms and PreRun Prep #####
        }

        ##### BEGIN Main Body #####
        Process {
            if ($pscmdlet.ShouldProcess("$HostName","Test Connection on $HostName`:$Port")) {
                try {
                    $tcp.Connect($HostName, $Port)
                }
                catch {}

                if ($tcp.Connected) {
                    $tcp.Close()
                    $open = $true
                }
                else {
                    $open = $false
                }

                $PortTestResult = [pscustomobject]@{
                    Address      = $HostName
                    Port    = $Port
                    Open    = $open
                }
                $PortTestResult
            }
            ##### END Main Body #####
        }
    }

    ## END Native Helper Functions ##

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Load and Run Update-PackageManagement function
    $UpdatePMString = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/Update-PackageManagement.ps1"
    $UpdatePMScriptBlock = [scriptblock]::Create($UpdatePMString.Content)
    . $UpdatePMScriptBlock
    Update-PackageManagement

    # Load Replace-Text function used for modifying sshd_config
    <#
    $ReplaceTextString = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/Replace-Text.ps1"
    $ReplaceTextScriptBlock = [scriptblock]::Create($ReplaceTextString.Content)
    . $ReplaceTextScriptBlock
    #>

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (!$(Get-Package -Name OpenSSH -ErrorAction SilentlyContinue)) {
        try {
            Install-Package -Name OpenSSH
            if (!$?) {
                throw
            }
        }
        catch {
            Write-Verbose "Installation of OpenSSH failed! Halting!"
            Write-Error "Installation of OpenSSH failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # NOTE: Installing OpenSSH in the above manner should add all of the ssh utilities to environment PATH
    # ssh Utilities could come from Git or From previously installed Windows OpenSSH. We want to make sure we use Windows OpenSSH
    $PotentialSSHUtilitiesSource = $(Get-Command ssh -All).Source
    $FinalSSHUtilitySourceDir = foreach ($FilePath in $PotentialSSHUtilitiesSource) {
        if ([Environment]::Is64BitProcess) {
            if ($FilePath -like "*OpenSSH-Win64*") {
                $FilePath | Split-Path -Parent
            }
        }
        else {
            if ($FilePath -like "*OpenSSH-Win32*") {
                $FilePath | Split-Path -Parent
            }
        }
    }
    if ([Environment]::Is64BitProcess) {
        $Potential64ArchLocationRegex = $FinalSSHUtilitySourceDir -replace "\\","\\"
        $CheckPath = $env:Path -match $Potential64ArchLocationRegex
        if ($CheckPath) {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $($env:Path -replace "$Potential64ArchLocationRegex","")
        }
        else {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $env:Path
        }
    }
    else {
        $Potential32ArchLocationRegex = $($($FinalSSHUtilitySourceDir -replace "\\","\\") -replace "\(","(") -replace "\)",")"
        $CheckPath = $env:Path -match $Potential32ArchLocationRegex
        if ($CheckPath) {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $($env:Path -replace "$Potential32ArchLocationRegex","")
        }
        else {
            $env:Path = $FinalSSHUtilitySourceDir + ";" + $env:Path
        }
    }

    $sshdConfigPath = "$FinalSSHUtilitySourceDir\sshd_config"

    # Add a line for PowerShell under Subsystems in sshd_config
    $sshdContent = Get-Content $sshdConfigPath
    $LineToReplace = $sshdContent | Where-Object {$_ -like "*sftp-server.exe*"}
    $UpdatedsshdContent = $sshdContent -replace "$LineToReplace","$LineToReplace`nSubsystem   powershell $PowerShell6Path -sshd -NoLogo -NoProfile"
    Set-Content -Value $UpdatedsshdContent -Path $sshdConfigPath

    if (Test-Path "$FinalSSHUtilitySourceDir\install-sshd.ps1") {
        $FinalSSHUtilitySourceDir\install-sshd.ps1
        $FinalSSHUtilitySourceDir\FixHostFilePermissions.ps1 -Confirm:$false
    }
    else {
        Write-Warning "The SSHD Service still needs to be configured!"
    }

    # Make sure port 22 is open
    if (!$(Test-Port -Port 22).Open) {
        # See if there's an existing rule regarding locahost TCP port 22
        $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
        if ($Existing22RuleCheck -ne $null) {
            $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
            if ($Existing22Rule -ne $null) {
                Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
            }
            else {
                $ExistingRuleFound = $False
            }
        }
        if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
            New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
        }
    }

    # Setup Host Keys
    Start-Service ssh-agent

    Start-Sleep -Seconds 5

    if ($(Get-Service "ssh-agent").Status -ne "Running") {
        Write-Verbose "The ssh-agent service did not start succesfully! Halting!"
        Write-Error "The ssh-agent service did not start succesfully! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path $RootDrive\.ssh)) {
        New-Item -ItemType Directory -Path $RootDrive\.ssh
    }

    Push-Location $RootDrive\.ssh

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "ssh-keygen.exe"
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.WorkingDirectory = $pwd.Path
    $ProcessInfo.Arguments = "-A"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $AllOutput = $stdout + $stderr
    
    $PubPrivKeyPairFiles = Get-ChildItem -Path "$RootDrive\.ssh" | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -like "*ssh_host*"}
    $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKeys = $PubPrivKeyPairFiles | foreach {if ($PubKeys -notcontains $_) {$_}}
    
    foreach ($PrivKey in $PrivKeys) {
        ssh-add.exe $PrivKey.FullName

        if ($RemovePrivateKeys) {
            Remove-Item $PrivKey
        }
    }

    Pop-Location

    Start-Service sshd

    Start-Sleep -Seconds 5

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Verbose "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
        Write-Error "The sshd service did not start succesfully! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }

    Set-Service sshd -StartupType Automatic
    Set-Service ssh-agent -StartupType Automatic

    ##### END Main Body #####

}





# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3Q6G5ReE0Pn3PMLrbCAi5ABX
# mHugggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSXcoEXN6C2
# CVelNi4t5lht5QcFvjANBgkqhkiG9w0BAQEFAASCAQALVNrC1BfGlwIb0Ryl/1nt
# /1Yk+DhoQB17fAvD2Te+6120hlVDrs93q9MBgPKHiWouRUeuEm6lBl8+JMNYWakJ
# bfIpVV+MAYNd/shRSGqNal3z/QLQAOu7eucntmhSJBwBlHE1AbADpHi57KXAXV1h
# ygkwXFYpMNYrKPYmLKbuw72nc/W+aztShTBCa3h6UQhtTmPr3nmEQh+ZbFvwn+lH
# TAlHgA4CWcJqwnvhJ/jPAn9h6ZAJi9hZ5hGtCNZYI8v7tTRJ+d9V/Vywt2owNXO0
# /weMwF4fVXP4ysHMKzZB9maE7le5+YekpPnD/80JTyDIODC/ZtPZ3XLhX1Se6nDq
# SIG # End signature block
