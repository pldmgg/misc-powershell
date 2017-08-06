<#
.SYNOPSIS
    This function is for breaking up large log files in a given directory so that each file
    can only be the specified number of lines max (using the -LineNumberToSplitOn parameter).
    When a log file in the specified directory is processed, the original log file will not be
    touched and new log files will be created with filenames matching the original log filename
    appended with "_PartN".

.DESCRIPTION
    See SYNOPSIS

.PARAMETER DirectoryContainingFiles
    MANDATORY

    This parameter takes a string that represents a full path to a directory that contains log files.

.PARAMETER OutputDirectory
    OPTIONAL

    This parameter takes a string that represents a full path to a directory that you would like to
    output the broken-up log files to. If this parameter is not used explicitly, then the broken-up
    log files will be written to the the directory specified by the -DirectoryContainingFiles parameter.

.PARAMETER LineNumberToSplitOn
    MANDATORY

    This parameter takes an integer that represents the maximum number of lines that each broken-up
    log file should contain.

.PARAMETER Recurse
    OPTIONAL

    This parameter is a switch. If used, this function will attempt to break up log files in ALL
    subdirectories under -DirectoryContainingFiles. If not used, this function will only process
    log files immediately under -DirectoryContainingFiles.

.EXAMPLE
    Split-LogFiles -DirectoryContainingFiles C:\Logs -LineNumberToSplitOn 65530 -Recurse

#>

function Split-LogFiles {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        [string]$DirectoryContainingFiles = $(Read-Host -Prompt "Please enter the full path to the directory that contains the files you need to split."),

        [Parameter(Mandatory=$False)]
        [string]$OutputDirectory = $DirectoryContainingFiles,

        [Parameter(Mandatory=$True)]
        [int]$LineNumberToSplitOn,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse

    )

    ### BEGIN Parameter Validation ###

    if (!$(Test-Path $DirectoryContainingFiles)) {
        Write-Error "The path $DirectoryContainingFiles was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($(Get-Item $DirectoryContainingFiles) -isnot [System.IO.DirectoryInfo]) {
        Write-Error "The path $DirectoryContainingFiles is not a directory! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($(Get-Item $OutputDirectory) -isnot [System.IO.DirectoryInfo]) {
        Write-Error "The path $OutputDirectory is not a directory! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ### END Parameter Validation ###

    ### BEGIN Main Body ###

    if ($Recurse) {
        $FilesInDirectory = Get-ChildItem -Recurse $DirectoryContainingFiles | Where-Object {$_.PSIsContainer -eq $false}
    }
    else {
        $FilesInDirectory = Get-ChildItem $DirectoryContainingFiles | Where-Object {$_.PSIsContainer -eq $false}
    }

    $FilesCreatedColection = @()
    foreach ($file in $FilesInDirectory) {
        $FileContent = Get-Content $(Get-Item $file.FullName)
        $LineCount = $FileContent.Count
        if ($LineNumberToSplitOn -gt $LineCount) {
            Write-Warning "No need to split file $($file.Name) on $LineNumberToSplitOn as it only contains $LineCount lines! Skipping..."
            continue
        }
        # Round Up Total Number of Files Needed...
        $TotalNumberOfSplitFiles = [math]::ceiling($($LineCount / $LineNumberToSplitOn))

        if ($TotalNumberOfSplitFiles -gt 1) {
            for ($i=1; $i -lt $($TotalNumberOfSplitFiles+1); $i++) {
                $StartingLine = $LineNumberToSplitOn * $($i-1)
                if ($LineCount -lt $($LineNumberToSplitOn * $i)) {
                    $EndingLine = $LineCount
                }
                if ($LineCount -gt $($LineNumberToSplitOn * $i)) {
                    $EndingLine = $LineNumberToSplitOn * $i
                }

                New-Variable -Name "$($file.BaseName)_Part$i" -Value $(
                    $FileContent[$StartingLine..$EndingLine]
                ) -Force

                $(Get-Variable -Name "$($file.BaseName)_Part$i" -ValueOnly) | Out-File "$DirectoryContainingFiles\$($file.BaseName)_Part$i$($file.Extension)"

                $FilesCreatedCollection +=, $(Get-Variable -Name "$($file.BaseName)_Part$i" -ValueOnly)
            }
        }
    }
}









# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGDu8FLWc9hnAiczYtOynwPGO
# cdKgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBThY/5LA0ml
# x8QdQZ6G/aahVxqEqDANBgkqhkiG9w0BAQEFAASCAQCZj9ky3SauzPw6pEeKbVeb
# 92cUL0DmAM9Kvi61aM1DWGpP3ayMTOiRTwvTY3ClKkERNJEs1kAgWpe8AHO9/Rw9
# HA//1DYed/1e5+uoU9QN/3IzRTG62qDAEIQAu27SboAheHkth4lQPyCCXPLnuZ/g
# FU4qfu6dPb97BRbjYhGmUSXA2nLG4Q5Yr4ZdmyU+5GouNuvt8ccxdOh0YuEAz8nb
# MqpNHtRzIr+N/srO1anlZVreSExqKtF7Ot8c6tQxh2vTRaL4EKuf9hnba+FjNLjE
# VDPofnh/QD4/5j+sdyPz+8W0Sb+V14AwkT+VPllfTW68aox+vxQ2/TciwRicIlFt
# SIG # End signature block
