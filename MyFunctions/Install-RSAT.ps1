function Install-RSAT {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$DownloadDirectory = "$HOME\Downloads",

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestart,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-Host "Please wait..."

    if (!$(Get-Module -ListAvailable -Name ActiveDirectory) -or $Force) {
        $OSInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $OSCimInfo = Get-CimInstance Win32_OperatingSystem
        $OSArchitecture = $OSCimInfo.OSArchitecture

        if ([version]$OSCimInfo.Version -lt [version]"6.3") {
            Write-Error "This function only handles RSAT Installation for Windows 8.1 and higher! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($OSInfo.ProductName -notlike "*Server*") {
            $KBCheck = [bool]$(Get-WmiObject -query 'select * from win32_quickfixengineering' | Where-Object {
                $_.HotFixID -eq 'KB958830' -or $_.HotFixID -eq 'KB2693643'
            })

            if (!$KBCheck -or $Force) {
                if ($([version]$OSCimInfo.Version).Major -lt 10 -and [version]$OSCimInfo.Version -ge [version]"6.3") {
                    if ($OSArchitecture -eq "64-bit") {
                        $OutFileName = "Windows8.1-KB2693643-x64.msu"
                    }
                    if ($OSArchitecture -eq "32-bit") {
                        $OutFileName = "Windows8.1-KB2693643-x86.msu"
                    }

                    $DownloadUrl = "https://download.microsoft.com/download/1/8/E/18EA4843-C596-4542-9236-DE46F780806E/$OutFileName"
                }
                if ($([version]$OSCimInfo.Version).Major -ge 10) {
                    if ([int]$OSInfo.ReleaseId -ge 1803) {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1803-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1803-x86.msu"
                        }
                    }
                    if ([int]$OSInfo.ReleaseId -ge 1709 -and [int]$OSInfo.ReleaseId -lt 1803) {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1709-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS_1709-x86.msu"
                        }
                    }
                    if ([int]$OSInfo.ReleaseId -lt 1709) {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS2016-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "WindowsTH-RSAT_WS2016-x86.msu"
                        }
                    }

                    $DownloadUrl = "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/$OutFileName"
                }

                try {
                    # Make sure the Url exists...
                    $HTTP_Request = [System.Net.WebRequest]::Create($DownloadUrl)
                    $HTTP_Response = $HTTP_Request.GetResponse()
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                try {
                    # Download via System.Net.WebClient is a lot faster than Invoke-WebRequest...
                    $WebClient = [System.Net.WebClient]::new()
                    $WebClient.Downloadfile($DownloadUrl, "$DownloadDirectory\$OutFileName")
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                Write-Host "Beginning installation..."
                if ($AllowRestart) {
                    $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                }
                else {
                    $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /norestart /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                }
                #Start-Process -FilePath $(Get-Command wusa.exe).Source -ArgumentList "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`"" -NoNewWindow -Wait

                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                $ProcessInfo.FileName = $(Get-Command wusa.exe).Source
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
                #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = $Arguments
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                # Below $FinishedInAlottedTime returns boolean true/false
                # Wait 20 seconds for wusa to finish...
                $FinishedInAlottedTime = $Process.WaitForExit(20000)
                if (!$FinishedInAlottedTime) {
                    $Process.Kill()
                }
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr

                # Check the log to make sure there weren't any errors
                # NOTE: Get-WinEvent cmdlet does NOT work consistently on all Windows Operating Systems...
                Write-Host "Reviewing wusa.exe logs..."
                $EventLogReader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new("$DownloadDirectory\wusaRSATInstall.log", [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
                [System.Collections.ArrayList]$EventsFromLog = @()
                
                $Event = $EventLogReader.ReadEvent()
                $null = $EventsFromLog.Add($Event)
                while ($Event -ne $null) {
                    $Event = $EventLogReader.ReadEvent()
                    $null = $EventsFromLog.Add($Event)
                }

                if ($EventsFromLog.LevelDisplayName -contains "Error") {
                    $ErrorRecord = $EventsFromLog | Where-Object {$_.LevelDisplayName -eq "Error"}
                    $ProblemDetails = $ErrorRecord.Properties.Value | Where-Object {$_ -match "[\w]"}
                    $ProblemDetailsString = $ProblemDetails[0..$($ProblemDetails.Count-2)] -join ": "

                    $ErrMsg = "wusa.exe failed to install '$DownloadDirectory\$OutFileName' due to '$ProblemDetailsString'. " +
                    "This could be because of a pending restart. Please restart $env:ComputerName and try the Install-RSAT function again."
                    Write-Error $ErrMsg
                    $global:FunctionResult = "1"
                    return
                }

                if ($AllowRestart) {
                    Restart-Computer -Confirm:$false -Force
                }
                else{
                    $Output = "RestartNeeded"
                }
            }
        }
        if ($OSInfo.ProductName -like "*Server*") {
            #Import-Module ServerManager
            if (!$(Get-WindowsFeature RSAT-AD-Tools).Installed) {
                Write-Host "Beginning installation..."
                if ($AllowRestart) {
                    Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools -Restart
                }
                else {
                    Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools
                    $Output = "RestartNeeded"
                }
            }
        }
    }
    else {
        Write-Warning "RSAT is already installed! No action taken."
    }

    if ($Output -eq "RestartNeeded") {
        Write-Warning "You must restart your computer in order to finish RSAT installation."
    }

    $Output
}




# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwiTlQ0TxzdhgBpKbXmxJNTNE
# C/Kgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCPCH0kfwGabgI71
# zMGcTSAm2/rHMA0GCSqGSIb3DQEBAQUABIIBAIhqqLqnSSZu/q6CWOHACp9hbHu6
# jQlseRenv4xwvy6wsyp+uxOHyOtfO7S5q7zgq4JTKqeTY825GGkmtFFxUcNSYELF
# l8PedBEJ/FHejOPF9PeKyT+fw2DlSwjO1Qj9spzKTKaogU/t4I7ed2WHsfeQriGg
# G1muByYMiaGiwT68qL5vdAs10MAW4b4fRyv/C2UTphHhGOAHV0p/AF9oIkFBI/8v
# YZR+hNwHUpqnYg3N1jvcTkfx0b91xGWU7YD8t62bSUYX71i8LNdaKDQD3Wc/4MJN
# TwAiIgTjobp/GE5rLurDNWoJdDsfk79uxUUu/HVXAn+GtWsKfs/Xt13ZjSY=
# SIG # End signature block
