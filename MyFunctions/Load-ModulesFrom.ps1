function Load-ModulesFrom {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ModuleDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that contains PowerShell Modules you would like to load"),

        [Parameter(Mandatory=$False)]
        [string[]]$ModulesToLoad
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Get current $PSModulePath
    $OriginalPSModulePath = $env:PSModulePath
    $OriginalPSModulePathArr = $OriginalPSModulePath -split ";"

    # Validating a string that is supposed to be a Local or UNC Path
    if ( !$($([uri]$ModuleDirectory).IsAbsoluteURI -and $($([uri]$ModuleDirectory).IsLoopBack -or $([uri]$ModuleDirectory).IsUnc)) ) {
        Write-Error "$ModuleDirectory is not a valid directory path! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path $ModuleDirectory)) {
        Write-Error "The path $ModuleDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $ModuleDirSubDirs = Get-ChildItem -Path $ModuleDirectory -Directory
    if ($ModuleDirSubDirs.Count -lt 1) {
        Write-Error "No Modules were found under $ModuleDirectory! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    if ($ModulesToLoad) {
        [System.Collections.Arraylist]$FinalModulesToLoad = @()
        foreach ($ModName in $ModulesToLoad) {
            if ($ModuleDirSubDirs.Name -notcontains $ModName) {
                Write-Warning "Unable to find $ModName under $ModuleDirectory! Skipping..."
            }
            else {
                foreach ($subdir in $ModuleDirSubDirs) {
                    if ($subdir.Name -eq $ModName) {
                        $null = $FinalModulesToLoad.Add($subdir)
                    }
                }
            }
        }
    }
    else {
        $FinalModulesToLoad = $ModuleDirSubDirs
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    
    $env:PSModulePath = $null

    $env:PSModulePath = $ModuleDirectory

    foreach ($ModItem in $FinalModulesToLoad) {
        Import-Module -Name $ModItem.Name
    }

    if ($OriginalPSModulePathArr -contains $ModuleDirectory) {
        $UpdatedPSModulePath = $OriginalPSModulePath
    }
    else {
        $UpdatedPSModulePath = $OriginalPSModulePath + $ModuleDirectory
    }

    $env:PSModulePath = $UpdatedPSModulePath

    <#
    [System.Collections.ArrayList]$PotentialPSD1FilesToLoad = @()
    [System.Collections.ArrayList]$FinalPSD1FilesToLoad = @()
    foreach ($ModItem in $FinalModulesToLoad) {
        # Make sure the Module is not already loaded...
        if ($(Get-Module).Name -contains $ModItem.Name) {
            Write-Warning "$($ModItem.Name) is already loaded from $($(Get-Module -Name $($ModItem.Name)).ModuleBase)! Skipping..."
            continue
        }
        else {
            # Select .psd1 files at the specified depths as long as there is only ONE .psd1 file
            # in the specified directory at the current depth
            $StartLevel = 0 # 0 = include base folder, 1 = sub-folders only, 2 = start at 2nd level
            $Depth = 2      # How many levels deep to scan
            $BaseDir = $ModItem.FullName     # starting path
            for ($i=$StartLevel; $i -le $Depth; $i++) {
                $Levels = "\*" * $i
                $ProvPath = $(Resolve-Path $BaseDir$Levels).ProviderPath
                $GetPSD1Files = if ($ProvPath -ne $null) {$ProvPath | Get-Item | Where-Object {$_.Extension -eq ".psd1"}}
                New-Variable -Name "ModulePSD1Search$i" -Value $(
                    [pscustomobject][ordered]@{
                        ModuleDirectoryInfoItem   = $ModItem
                        psd1SearchResults         = $GetPSD1Files
                        Depth                     = $i
                    }
                ) -Force

                $null = $PotentialPSD1FilesToLoad.Add($(Get-Variable -Name "ModulePSD1Search$i" -ValueOnly))
                
            }
        }
    }

    $PotentialPSD1FilesGrouped = $PotentialPSD1FilesToLoad | Group-Object -Property ModuleDirectoryInfoItem

    # We only want to load the .psd1 file at the shallowest depth...
    foreach ($PSD1Group in $PotentialPSD1FilesGrouped) {
        for ($i=0; $i -lt $PSD1Group.Group.Count; $i++) {
            if ($PSD1Group.Group[$i].psd1SearchResults.Count -eq 1) {
                $null = $FinalPSD1FilesToLoad.Add($($PSD1Group.Group[$i].psd1SearchResults.FullName))
                break
            }
        }
    }

    foreach ($PSD1File in $FinalPSD1FilesToLoad) {
        Import-Module $PSD1File
    }
    #>

    ##### END Main Body #####

}














# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwMi+Ya2SxEAK23S03zuqyk1P
# ZvOgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBT8T5WHjg0m
# 6Jw/ED5Ol+4m3bj8RDANBgkqhkiG9w0BAQEFAASCAQCOB1/yx4FSNLamunfbx5CZ
# NY/0MtItxhTHEEPKXLA4bHR/aiFiwPNUxGFd57kXTeFH8LSDYfPLcPxyY1JeDNYS
# t3NuuUiioxGZAXAvN5HqQStZ8RKTohK++rtu/d2ZV1KHiRMt5/0LGTg4/pH63B4D
# d679NyIRwG18L7jUYRnv9047zLxTr61pmcUZJZDGVRaS9wmz1+hqa3M8rZhdOk9F
# mZ+iSIbCnz1VN048j+Bp9Oj96S173thUgzhoBNP3rgYedx7WaJiHcFBJJ/OHHr9L
# l+0tOES15j6d9QYf+MHI8ImamlPYnegE7oOzmbJUEjMuStFVyvrDIDacN+Nf2D13
# SIG # End signature block
