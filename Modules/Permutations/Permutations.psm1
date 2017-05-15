# Get-PermutationsAll Outputs and Array of Arrays with Different Combos
function Get-PermutationsAll {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [array]$Array
    )

    ##### BEGIN Native Helper Functions #####

    function Get-AllPerms {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            $arr,

            [Parameter(Mandatory=$False)]
            $cur = "",

            [Parameter(Mandatory=$False)]
            $depth = 0,

            [Parameter(Mandatory=$False)]
            $list = @()
        )

        $depth ++
        for ($i = 0; $i -lt $arr.Count; $i++)
        {
            $list += $cur+" "+$arr[$i]        

            if ($depth -lt $arr.Count)
            {
                $list = Get-AllPerms $array ($cur+" "+$arr[$i]) $depth $list
            }       
        }

        $list
    }

    ##### END Native Helper Functions #####

    $InitialResult = Get-AllPerms -arr $Array
    $FinalResultPrep = @()
    $InitialResult | % {$FinalResultPrep +=, $($_ -split " ")}

    $FinalResult = @()
    foreach ($arr in $FinalResultPrep) {
        $UpdatedArr = $arr | % {if ($_ -match "[\w]") {$_}}
        $FinalResult +=, $UpdatedArr
    }
    $FinalResult

}


function Get-PermutationsNoRepeats {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [array[]]$Array
    )

    $ArrayOfArraysWithoutRepeatingElements = @()

    foreach ($arr in $Array) {
        # RepititionCheck is an array of counts
        $RepCheck = $($arr | Group-Object | % {$_.Count}) | Sort-Object | Get-Unique
        $RepCheckValuePrep = @()
        foreach ($Value in $RepCheck) {
            if ($Value -ne 1) {
                $RepCheckValuePrep += $Value
            }
        }
        $RepCheckValueBool = if ($RepCheckValuePrep.Count -ge 1) {
            $true
        }
        else {
            $false
        }

        if ($RepCheck.Count -gt 1 -or $RepCheckValueBool) {
            Write-Verbose "Skip..."
        }
        else {
            $ArrayOfArraysWithoutRepeatingElements +=, $arr
        }
    }

    $ArrayOfArraysWithoutRepeatingElements

}


function Get-SumPossibilities {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $Array,

        [Parameter(Mandatory=$False)]
        [switch]$Hexadecimal
    )

    ##### BEGIN Native Helper Functions #####
    
    function Convert-HexToDec {
        param($hex)

        ForEach ($value in $hex) {
            [Convert]::ToInt32($value,16)
        }
    }

    function Convert-DecToHex {
        param($dec)

        ForEach ($value in $dec) {
            "{0:x}" -f [Int]$value
        }
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Main Body #####
    $AllPerms = Get-PermutationsAll -Array $Array
    $NoRepeats = Get-PermutationsNoRepeats $AllPerms

    if ($Hexadecimal) {
        $UpdatedArrayOfArrays = @()
        foreach ($HexArray in $NoRepeats) {
            $UpdatedHexArray = foreach ($element in $HexArray) {
                Convert-HexToDec $element
            }
            $UpdatedArrayOfArrays +=, $UpdatedHexArray
        }

        $DecArrayCombosSummed = foreach ($DecArray in $UpdatedArrayOfArrays) {
            $($DecArray | Measure-Object -Sum).Sum
        }

        $HexArrayCombosSummed = foreach ($Sum in $DecArrayCombosSummed) {
            Convert-DecToHex $Sum
        }
        
        $HexArrayCombosSummed
    }
    else {
        $DecArrayCombosSummed = foreach ($DecArray in $NoRepeats) {
            try {
                $Sum = $($DecArray | Measure-Object -Sum).Sum
                if (!$Sum) {
                    throw
                }
                else {
                    $Sum
                }
            }
            catch {
                Write-Verbose "Unable to calculate Sum Possibilities! If your array elements contain hexadecimal, please use the -Hexadecimal switch. Otherwise, please ensure all array elements are decimal. Halting!"
                Write-Error "Unable to calculate Sum Possibilities! If your array elements contain hexadecimal, please use the -Hexadecimal switch. Otherwise, please ensure all array elements are decimal. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $DecArrayCombosSummed
    }

    ##### END Main Body #####
}








# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvghYozh3nw51a669fZGgbdga
# +pWgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQimNhK1Va9
# uup0BVfJMUueLhZy0TANBgkqhkiG9w0BAQEFAASCAQBLMjMvmq1wASgxqHbbhuYi
# 8ZQAAZRc0rWbOwSxrJ2iOjbvsnXYY9A+eVJjrcjHPh9aXI53nGuC3HGJiAOB1VFI
# AIr9+hgtbeeGI4cIo9j2Mp7YK8gkDOvlNkW46+kJRPYdbhnbM5X+mF5YkH85Fk2I
# KvMaXp+MElLFH67iKHgxC8/UciUournRT8B4wWHYHVFCaOvGgxzaGDRr9UI48Xo+
# LbqfaiciLhn6G0qQ4GTYmK8+dyAzEnAEDCQAELRUES8Krfe6Zvfy3SXI2NQK6b5F
# 4V1GMZKtoHwiIBivBD7xjjgCYqERv10Y3wtF39RsYi963Vvfzt+akGzheFKc5GMA
# SIG # End signature block
