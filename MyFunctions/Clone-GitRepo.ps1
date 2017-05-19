function Clone-GitRepo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $GitRepoParentDirectory = $(Read-Host -Prompt "Please enter the full path to the directory that will contain the cloned Git repository."),

        [Parameter(
            Mandatory=$False,
            ParameterSetName='NoPrivateRepos'
        )]
        $GitHubUserName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        $PersonalAccessToken,

        [Parameter(Mandatory=$False)]
        $RemoteGitRepoName,

        [Parameter(Mandatory=$False)]
        [switch]$CloneAllPublicRepos,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        [switch]$CloneAllPrivateRepos,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PrivateRepos'
        )]
        [switch]$CloneAllRepos
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Test-Path $GitRepoParentDirectory)) {
        Write-Verbose "The path $GitRepoParentDirectory was not found! Halting!"
        Write-Error "The path $GitRepoParentDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $BoundParamsArrayOfKVP = $PSBoundParameters.GetEnumerator() | foreach {$_}

    $PrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Name -join "") -match "PersonalAccessToken|CloneAllPrivateRepos|CloneAllRepos"
    $NoPrivateReposParamSetCheck = $($BoundParamsArrayOfKVP.Name -join "") -match "GitHubUserName|CloneAllPublicRepos"

    # For Params that are part of the PrivateRepos Parameter Set...
    if ($PrivateReposParamSetCheck) {
        if ($($CloneAllPrivateRepos -and $CloneAllRepos) -or 
        $($CloneAllPrivateRepos -and $RemoteGitRepoName) -or
        $($CloneAllPrivateRepos -and $CloneAllPublicRepos) -or 
        $($CloneAllRepos -and $RemoteGitRepoName) -or
        $($CloneAllRepos -and $CloneAllPublicRepos) -or
        $($CloneAllPublicRepos -and $RemoteGitRepoName) )  {
            Write-Verbose "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            Write-Error "Please use *either* -CloneAllRepos *or* -CloneAllPrivateRepos *or* -RemoteGitRepoName *or* -CloneAllPublicRepos! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$PersonalAccessToken) {
            $PersonalAccessToken = Read-Host -Prompt "Please enter your GitHub Personal Access Token."
        }
    }
    # For Params that are part of the NoPrivateRepos Parameter Set...
    if ($NoPrivateReposParamSetCheck) {
        if ($CloneAllPublicRepos -and $RemoteGitRepoName) {
            Write-Verbose "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            Write-Error "Please use *either* -CloneAllPublicRepos *or* -RemoteGitRepoName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$GitHubUserName) {
            $GitHubUserName = Read-Host -Prompt "Please enter your GitHub UserName."
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($PrivateReposParamSetCheck) {
        $PublicAndPrivateRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/user/repos?access_token=$PersonalAccessToken"
        $PrivateRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $true}
        $PublicRepoObjects = $PublicAndPrivateRepoObjects | Where-Object {$_.private -eq $false}

        if ($CloneAllPrivateRepos) {
            foreach ($RepoObject in $PrivateRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    Set-Location $GitRepoParentDirectory
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllPublicRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    Set-Location $GitRepoParentDirectory
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($CloneAllRepos) {
            foreach ($RepoObject in $PublicAndPrivateRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    Set-Location $GitRepoParentDirectory
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepo) {
            $RemoteGitRepoObject = $PublicAndPrivateRepoObjects | Where-Object {$_.Name -eq $RemoteGitRepo}
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                Set-Location $GitRepoParentDirectory
                git clone $RemoteGitRepoObject.html_url
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    if ($NoPrivateReposParamSetCheck) {
        $Page = "1"
        $PublicRepoObjects = Invoke-RestMethod -Uri "https://api.github.com/users/$GitHubUserName/repos?page=$Page&per_page=100"

        if ($CloneAllPublicRepos) {
            foreach ($RepoObject in $PublicRepoObjects) {
                if (!$(Test-Path "$GitRepoParentDirectory\$($RepoObject.Name)")) {
                    Set-Location $GitRepoParentDirectory
                    git clone $RepoObject.html_url
                }
                else {
                    Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Skipping!"
                    $global:FunctionResult = "1"
                    break
                }
            }
        }
        if ($RemoteGitRepo) {
            $RemoteGitRepoObject = $PublicRepoObjects | Where-Object {$_.Name -eq $RemoteGitRepo}
            if (!$(Test-Path "$GitRepoParentDirectory\$($RemoteGitRepoObject.Name)")) {
                Set-Location $GitRepoParentDirectory
                git clone $RemoteGitRepoObject.html_url
            }
            else {
                Write-Verbose "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Halting!"
                Write-Error "The RemoteGitRepo $RemoteGitRepo already exists under $GitRepoParentDirectory\$RemoteGitRepo! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    ##### END Main Body #####

}




# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUpJ1ntU1YroVyT/esHAcT7UrO
# a9SgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRWZxrup6bU
# 8NEifFji1v2QncE61TANBgkqhkiG9w0BAQEFAASCAQBeqOEXK+MWH14av1dyU3ns
# HgMJReyZo5EMudLWoWmFgaojqGCmX1jNctOsNcYVCVlNvzcRaypdWclJxY+roP73
# yRpcTjBiA+fcMuMB9QmpxsM02cOOTRLCxWOOeubPAUeDdWwg2WjYkd4JAhLi6pl0
# eUlb5XuwUuDw7fHlJpZUu+LsWUahKzcAzMirOg/4NWmFWFGRgs6TKrP4pyvEZSpn
# LyhrTGBUOQpWuLAkWeekrgCrQGmZjbUrLPZeETCevnHxJrJvInhKNwqzLR5XwyA5
# ZCTY4m9qe2CyA3tsLhaB7HAAbLyMdmKR9jYKFaD4UiD//vCBmFkYYfg5x4elJLs1
# SIG # End signature block
