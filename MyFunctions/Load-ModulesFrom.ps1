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
        Write-Host "Attempting to load module $($ModItem.Name) from directory $($ModItem.FullName)..."
        Import-Module -Name $(Get-ChildItem $ModItem.FullName -Filter "$(ModItem.Name).psd1").FullName
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
        # Make sure the Module is not already loaded
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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFLj8e1Kb6/7wjq2VWtNVfi8R
# NGygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOGdVK5OOl5xcNGG
# /DXrAJ6zcdWwMA0GCSqGSIb3DQEBAQUABIIBALbP3tKl2yJE8jao1uYj9mqLz+lb
# LjN/IG5I6n8VEBn5r91Ye1rOU3nB7w+dbIFtUNbn0dquIbzK1sHuEbRiH/gIgeBQ
# dkUKeg/VX77BnxiHJG6AgsqOOiUYUjUNEuc96NUO7SKVEoKX2QYPkRNkkCaZchPN
# 9CcMkRvK1Mv/9wS53PBf8nroZCv41QKP2RDiqDfnNcS3avDjo7tNrUDDQkJSWe+G
# 6c3TDYhhEzurHmmhpEx61liyV3gL5+1TmlPWVvs0FasyYJEltUrcwaXEYcFsEO+U
# QvDplTXHgTCu1JNSkquqaDgbIpOv3DgNsZU+g7az8GtOhAcLe9O1gBxYUzw=
# SIG # End signature block
