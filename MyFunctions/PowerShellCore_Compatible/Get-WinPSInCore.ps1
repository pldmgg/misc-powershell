function Get-WinPSInCore {
    [CmdletBinding()]
    [Alias('shim')]
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]
        [Alias("sb")]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [string[]]$VariablesToForward,

        [Parameter(Mandatory=$False)]
        [string[]]$EnvironmentVariablesToForward,

        [Parameter(Mandatory=$False)]
        [string[]]$FunctionsToForward,

        [Parameter(Mandatory=$False)]
        [string[]]$ModulesToForward,

        [Parameter(Mandatory=$False)]
        [switch]$NoWinRM
    )

    if ($PSVersionTable.PSEdition -ne "Core" -or $PSVersionTable.Platform -ne "Win32NT") {
        Write-Error "The '$($MyInvocation.MyCommand.Name)' function is only meant to be used in PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$SetEnvStringArray = @()

    if ($VariablesToForward) {
        $Variables = Get-Variable
        if ($VariablesToForward -notcontains '*') {
            $Variables = foreach ($VarObj in $Variables) {
                if ($VariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetVarsPrep = foreach ($VarObj in $Variables) {
            try {
                $VarValueAsJSON = $VarObj.Value | ConvertTo-Json -Compress
            }
            catch {
                #Write-Warning "Unable to pass the variable '$($VarObj.Name)'..."
            }

            if ($VarValueAsJSON) {
                if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                    $VarStringArr = @(
                        'try {'
                        $('    ${' + $VarObj.Name + '}' + ' = ' + 'ConvertFrom-Json ' + "@'`n$VarValueAsJSON`n'@")
                        '}'
                        'catch {'
                        "    Write-Verbose 'Unable to forward variable $($VarObj.Name)'"
                        '}'
                    )
                }
                else {
                    $VarStringArr = @(
                        'try {'
                        $('    $' + $VarObj.Name + ' = ' + 'ConvertFrom-Json ' + "@'`n$VarValueAsJSON`n'@")
                        '}'
                        'catch {'
                        "    Write-Verbose 'Unable to forward variable $($VarObj.Name)'"
                        '}'
                    )
                }
                $VarStringArr -join "`n"
            }
        }
        $SetVarsString = $SetVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetVarsString)
    }

    # Not a good idea to pass the environment variables...
    if ($EnvironmentVariablesToForward) {
        $EnvVariables = Get-ChildItem Env:\
        if ($EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)
    }

    if ($ModulesToForward) {
        $Modules = Get-Module
        if ($ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }
        $SetModulesPrep = foreach ($ModObj in $Modules) {
            $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                $_.Name -eq "$($ModObj.Name).psd1"
            }).FullName

            $ModStringArray = @(
                'try {'
                "    Import-Module '$($ModObj.Name)' -ErrorAction Stop"
                '}'
                'catch {'
                '    try {'
                "        Import-Module '$ModuleManifestFullPath' -ErrorAction Stop"
                '    }'
                '    catch {'
                "        Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                '    }'
                '}'
            )
            $ModStringArray -join "`n"
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    }

    if ($FunctionsToForward) {
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)
    }

    # Make sure we have Windows PowerShell PSModule Paths
    $PSCorePSModulePath = $env:PSModulePath
    [System.Collections.Arraylist][array]$PSCorePSModulePathArray = $env:PSModulePath -split ';'
    $WinPSPSModulePaths = @(
        'C:\Program Files\WindowsPowerShell\Modules'
        "$HOME\Documents\WindowsPowerShell\Modules"
        'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules'
    )
    foreach ($ModPath in $WinPSPSModulePaths) {
        if ($PSCorePSModulePathArray -notcontains $ModPath) {
            $null = $PSCorePSModulePathArray.Add($ModPath)
        }
    }
    $FinalModPathString = $PSCorePSModulePathArray -join ';'

    # Create Initialization Scripts as needed...
    $InitSBAsStringA = "`$env:PSModulePath = '$FinalModPathString'`n"
    
    if ($SetEnvStringArray.Count -gt 0) {
        # Writing $SetEnvStringArray to a file helps us avoid the byte limit associated with the
        # -args parameter of powershell.exe.
        # See: http://systemcentersynergy.com/max-script-block-size-when-passing-to-powershell-exe-or-invoke-command/
        $SetEnvStringArrayPath = "$HOME\SetEnvStringArray.xml"
        $SetEnvStringArray | Export-CliXml -Path $SetEnvStringArrayPath -Force

        $InitSBAsStringB = @"
`$args = Import-CliXml '$SetEnvStringArrayPath'

"@ + @'

$args | foreach {
    if (![string]::IsNullOrWhiteSpace($_)) {
        #Write-Host "Running $_"
        Invoke-Expression $_
    }
}

'@
    }

    if ($InitSBAsStringB) {
        # NOTE: $InitSBAsStringB coming before $InitSBAsStringA is important regarding $env:PSModulePath
        $FinalSBAsString = $InitSBAsStringB + $InitSBAsStringA + $ScriptBlock.ToString()
    }
    else {
        $FinalSBAsString = $InitSBAsStringA + $ScriptBlock.ToString()
    }
    $FinalSB = [scriptblock]::Create($FinalSBAsString)

    # Output
    if (!$NoWinRM) {
        powershell.exe -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command $FinalSB
    }
    else {
        if (!$global:WinPSSession) {
            $NewPSSessionSplatParams = @{
                ConfigurationName   = 'Microsoft.PowerShell'
                Name                = 'WinPSSession'
                EnableNetworkAccess = $True
            }
            $global:WinPSSession = New-PSSession @NewPSSessionSplatParams
            
            if (!$global:WinPSSession) {
                Write-Error "There was a problem creating the New-PSSession named 'WinPSSession'! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Write-Host "A new PSSession called 'WinPSSession' has been created along with a Global Variable referencing it called `$global:WinPSSession." -ForegroundColor Green
            }
        }
        Invoke-Command -Session $global:WinPSSession -ScriptBlock $FinalSB -HideComputerName
    }

    # Cleanup
    if ($SetEnvStringArrayPath) {
        if (Test-Path $SetEnvStringArrayPath) {
            Remove-Item $SetEnvStringArrayPath -Force
        }
    }
}




# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGuX3NeUwhrEjOMr8tdsL/TKK
# isegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKb73TtUlPJhBS6N
# 4NkdgrA4Y/LBMA0GCSqGSIb3DQEBAQUABIIBAB6ogfUTzF8TJo+r47pNamJaps44
# Bcf2/YEv4rUL9Th6HHx2rJK/RfzHAaISA0PQU+L9XfW40OpPwrxGVcEGEpS1pHQI
# HNVjI3lGNglKDi0cLVe2WwY3pTp6xrSEZFJ0tPVv7D2EI4XoYs33esnunAB0e2ei
# 6K1gbydU+hcZWYYo///uII7RPDnCvbxyiy+e3weeKd6URj2mIVoIaav/XK241wgx
# VMOjRwxVby2VjhxSRjpz6TvU5e3FeyQd6bdm367LuDYqppoFcRIblHfq57Fp6BJ8
# h+/U3DDE4EpEE3A/GZs91KenAHH0CZKKrtDYWWNL6T+YUgtquMeA4n7OmJU=
# SIG # End signature block
