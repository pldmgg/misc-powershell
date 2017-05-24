function Reflect-Cmdlet {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $CmdletOrFunc = $(Read-Host -Prompt "Please enter the name of the PowerShell cmdlet or function that you would like to investigate.")
    )

    ##### BEGIN Helper Functions #####

    function Expand-Zip {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$true,Position=0)]
            [string]$PathToZip,
            [Parameter(Mandatory=$true,Position=1)]
            [string]$TargetDir
        )
        
        Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Expand-Archive -Path $PathToZip -DestinationPath $TargetDir
        }
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            # Load System.IO.Compression.Filesystem 
            [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

            # Unzip file
            [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
        }
    }

    ##### END Helper Functions #####


    ##### BEGIN Main Body #####

    # See: https://powershell.org/forums/topic/how-i-can-see-powershell-module-methods-source-code/
    # For Functions
    if ($(Get-Command $CmdletOrFunc).CommandType -eq "Function") {
        if ($(Get-Command $CmdletOrFunc).ScriptBlock.File -ne $null) {
            $functionLocation = $(Get-Command $CmdletOrFunc).ScriptBlock.File
        }
        else {
            Write-Verbose "Unable to find the file that contains this function's code. Halting!"
            Write-Error "Unable to find the file that contains this function's code. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
    }
    

    # For Cmdlets (i.e. C# dll-based)
    if ($(Get-Command $CmdletOrFunc).CommandType -eq "Cmdlet") {
        if (!$(Get-Command ILSpy)) {
            $ILSpySite = Invoke-WebRequest -Uri "http://ilspy.net/"
            $ILSpyBinaryZip = $($ILSpySite.Links | ? {$_.href -like "*master*" -and $_.href -like "*.zip*" -and $_.href -like "*Binar*"}).href
            $ILSpyBinaryZipFileName = $ILSpyBinaryZip | Split-Path -Leaf
            $ILSpyBinaryZipFolderName = $ILSpyBinaryZipFileName -replace ".zip","" | Split-Path -Leaf
            Invoke-WebRequest -Uri $ILSpyBinaryZip -OutFile "$HOME\Downloads\$ILSpyBinaryZipFileName"
            if (!$(Test-Path "$HOME\Downloads\$ILSpyBinaryZipFolderName")) {
                New-Item -Type Directory -Path "$HOME\Downloads\$ILSpyBinaryZipFolderName"
            }
            Expand-Zip -PathToZip "$HOME\Downloads\$ILSpyBinaryZipFileName" -TargetDir "$HOME\Downloads\$ILSpyBinaryZipFolderName"
            Copy-Item -Recurse -Path "$HOME\Downloads\$ILSpyBinaryZipFolderName" -Destination "$HOME\Documents\$ILSpyBinaryZipFolderName"

            $EnvPathArray = $env:Path -split ";"
            if ($EnvPathArray -notcontains "$HOME\Documents\$ILSpyBinaryZipFolderName") {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$HOME\Documents\$ILSpyBinaryZipFolderName"
                }
                else {
                    $env:Path = "$env:Path;$HOME\Documents\$ILSpyBinaryZipFolderName"
                }
            }
        }

        if ($(Get-Command $CmdletOrFunc).ImplementingType.Assembly.Location -ne $null) {
            $dllLocation = $(Get-Command $CmdletOrFunc).ImplementingType.Assembly.Location
        }
        else {
            Write-Verbose "Unable to find the dll file that $CmdletOrFunc is based on. It is possble that multiple dlls are used to create this cmdlet. Halting!"
            Write-Error "Unable to find the dll file that $CmdletOrFunc is based on. It is possble that multiple dlls are used to create this cmdlet. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($functionLocation) {
        $(Get-Command $CmdletOrFunc).ScriptBlock
    }
    if ($dllLocation) {
        ILSpy $dllLocation

        Write-Host "Please up to 10 seconds for the ILSpy GUI to open."
    }

    # For CIM commands, browse the cdxml files in the command's module directory

    ##### END Main Body #####

}



# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+O170q2Zw5UQs0EUTUuRdfMW
# IAWgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTw7EpEQPAt
# igNpc+r5Ycqg1K86uDANBgkqhkiG9w0BAQEFAASCAQAawKhC8zNZ8LcFvWKBM/jD
# wqWAmmYPLg5J/t5Hb8wtKNPmk5bps8obZSKMlHVKOjqPQ0QeiBRgxhmD1subCLpF
# iFtG0wyvpwLYXXn2f8jwQ7x5MJvA5pZ6Reha0Cf4ouTu0qsHe24udgfckwfUefYe
# YFlB3PnFbX5UIScquqVlusV5F/8pOo5eac6zyI2l1xj7BdgzKg1ZDonqqeixI2sz
# tsYGf32upxzgv/wHW9nQKP8giuGGGmINFRKs+YtkJ/tpDbMrt5bCzzmvofRyDDgL
# oSK3MlmubBuPomvo3qcvskE8pBKHB8Gvf5RaJ6KFsyE9Ds0oSBdWrmr7EidbX3+r
# SIG # End signature block
