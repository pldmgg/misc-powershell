<#
.SYNOPSIS
    Get Sonic Wall access rules

.DESCRIPTION
    See SYNOPSIS

.PARAMETER SonicWallIPAddress
    MANDATORY

    This parameter takes a string that represents the IPv4 Address of the Management Interface
    on the Sonic Wall Device.

.PARAMETER SonicWallUserName
    MANDATORY

    This parameter takes a string that represents an admin user account with access to the Sonic Wall device. 

.EXAMPLE
    Get-SonicWallRules -SonicWallIPAddress "192.168.2.1" -SonicWallUserName "pldmgg"
#>

function Get-SonicWallRules {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SonicWallIPAddress,

        [Parameter(Mandatory=$True)]
        [string]$SonicWallUserName,

        [Parameter(Mandatory=$False)]
        [string]$SonicWallCommand = "show access-rules custom"
     )

    ##### BEGIN Native Helper Functions #####

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    ##### END Native Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    if (!(Test-Connection -Computer "google.com" -Count 1 -Quiet)) {
        Write-Error "Unable to reach the internet to download https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/Install-WinSSH.ps1! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-IsValidIPAddress -IPAddress $SonicWallIPAddress)) {
        Write-Error "The string $SonicWallIPAddress is not a valid IP Address format! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SonicWallPassword = Read-Host -Prompt "Please enter the password for $SonicWallUserName" -AsSecureString

    # Convert SecureString to PlainText
    $SonicWallPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SonicWallPassword))

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install OpenSSH-Win64 on your machine if it isn't already
    $InstallWinSSHScriptAsString = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/Install-WinSSH.ps1"
    $InstallWinSSHScript = [scriptblock]::Create($InstallWinSSHScriptAsString.Content)
    . $InstallWinSSHScript

    Install-WinSSH

    $OpenSSHWin64Path = "$env:ProgramFiles\OpenSSH-Win64"

    # SSH into the Sonic Wall Device. This will prompt you for a password and potentially
    # prompt you to accept the remote host key if this is your first time SSH-ing into the device
    # ssh -t $SonicWallUserName@$SonicWallIPAddress 'show access-rules custom'

    # Need PowerShell Await Module (Windows version of Linux Expect) for ssh-keygen with null password
    if ($(Get-Module -ListAvailable).Name -notcontains "Await") {
        # Install-Module "Await" -Scope CurrentUser
        # Clone PoshAwait repo to .zip
        Invoke-WebRequest -Uri "https://github.com/pldmgg/PoshAwait/archive/master.zip" -OutFile "$HOME\Downloads\PoshAwait.zip"
        $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
        [IO.Directory]::CreateDirectory($tempDirectory) | Out-Null
        Unzip-File -PathToZip "$HOME\Downloads\PoshAwait.zip" -TargetDir "$tempDirectory"
        if (!$(Test-Path "$HOME\Documents\WindowsPowerShell\Modules\Await")) {
            New-Item -Type Directory "$HOME\Documents\WindowsPowerShell\Modules\Await" | Out-Null
        }
        Copy-Item -Recurse -Path "$tempDirectory\PoshAwait-master\*" -Destination "$HOME\Documents\WindowsPowerShell\Modules\Await"
        Remove-Item -Recurse -Path $tempDirectory -Force
    }

    # Make private key password $null
    Import-Module Await
    if (!$?) {
        Write-Verbose "Unable to load the Await Module! Halting!"
        Write-Error "Unable to load the Await Module! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Start-AwaitSession
    Start-Sleep -Seconds 1
    Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
    $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
    Start-Sleep -Seconds 1
    Send-AwaitCommand "`$env:Path = '$env:Path'"
    Start-Sleep -Seconds 1
    Send-AwaitCommand "Push-Location $OpenSSHWin64Path"
    Start-Sleep -Seconds 1
    Send-AwaitCommand ".\ssh -oStrictHostKeyChecking=no -t $SonicWallUserName@$SonicWallIPAddress '$SonicWallCommand'"
    Start-Sleep -Seconds 2
    $SSHCmdConsoleOutput = Receive-AwaitResponse
    if ($SSHCmdConsoleOutput -like "*no matching key exchange method found*") {
        Send-AwaitCommand ".\ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oStrictHostKeyChecking=no -t $SonicWallUserName@$SonicWallIPAddress 'show access-rules custom'"
        Start-Sleep -Seconds 2
    }
    Send-AwaitCommand "$SonicWallPassword"
    Start-Sleep -Seconds 1
    $SSHCmdConsoleOutput = Receive-AwaitResponse
    Write-hOst ""
    Write-Host "##### BEGIN Sonic Wall '$SonicWallCommand' Console Output #####"
    Write-Host "$SSHCmdConsoleOutput"
    Write-Host "##### END Sonic Wall '$SonicWallCommand' Console Output #####"
    Write-Host ""
    # If Stop-AwaitSession errors for any reason, it doesn't return control, so we need to handle in try/catch block
    try {
        Stop-AwaitSession
    }
    catch {
        if ($PSAwaitProcess.Id -eq $PID) {
            Write-Verbose "The PSAwaitSession never spawned! Halting!"
            Write-Error "The PSAwaitSession never spawned! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Stop-Process -Id $PSAwaitProcess.Id
        }
    }

    ##### END Main Body #####

}







# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8stY163JektQgdE6BGKKm7Il
# vdGgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQXLRPcRh0N
# 4Mgf2XSAV7cXUR7wxjANBgkqhkiG9w0BAQEFAASCAQAJlZ851ULiHNSHLxAtB8vg
# zXnjEnmNWr6fzMCPMsRZI41tKt2Il2ow7/J4+kICjmmaKisPmHoRotOEgQSr721H
# zJH439tebMUGWZmh0se0I+/LglU5k9MagsGOMw8di8SEBCCE23x3jJcueyaL8g4W
# rS/3XIUjdN2gCaw1KVRfCjshfLqUJ/3yPg7uHxMxAcceB70sEWHBPnMkIV4cob9K
# 0y+uq895U/Y/g7byXtmzRHbPsc+oMHFoOPmtYh/kPDlXNWJh2Ye+fPJE4j6C47CT
# VzR6Tp2vJFPDeyb2yTGGbYdxdp/uKrdy1ZxkOVkEy8/33ScLHFWsw2XBDU0hF2sk
# SIG # End signature block
