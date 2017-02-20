<#
.SYNOPSIS
    Copy script from working directory to local github repository. Optionally commit and push to GitHub.
.DESCRIPTION
    If your workflow involves using a working directory that is NOT an initialized git repo for first
    drafts of scripts/functions, this function will assist with "publishing" your script/function from
    your working directory to the appropriate local git repo. Additional parameters will commit all
    changes to the local git repo and push these deltas to the appropriate repo on GitHub.

.NOTES
    IMPORTANT NOTES

    1) Using the $gitpush switch runs the following git commands which effectively 
    commmit and push ALL changes made to the local git repo since the last commit.
    
    git -C $DestinationLocalGitRepoDir add -A
    git -C $DestinationLocalGitRepoDir commit -a -m "$gitmessage"
    git -C $DestinationLocalGitRepoDir push

    The only change made by this script is the copy/paste operation from working directory to
    the specified local git repo. However, other changes outside the scope of this function may
    have occurred since the last commit. EVERYTHING will be committed and pushed if the $gitpush
    switch is used.

    DEPENDENCEIES
        None
.PARAMETER SourceFilePath
    This parameter is MANDATORY.

    This parameter takes a string that represents a file path to the script/function that you
    would like to publish.

.PARAMETER DestinationLocalGitRepoName
    This parameter is MANDATORY.

    This parameter takes a string that represents the name of the Local Git Repository that
    your script/function will be copied to. This parameter is NOT a file path. It is just
    the name of the Local Git Repository.

.PARAMETER SigningCertFilePath
    This parameter is OPTIONAL.

    This parameter takes a string that represents a file path to a certificate that can be used
    to digitally sign your script/function.

.PARAMETER gitpush
    This parameter is OPTIONAL.

    This parameter is a switch. If it is provided in the command line, then the function will 
    not only copy the source script/function from the working directory to the Local Git Repo,
    it will also commit changes to the Local Git Repo and push updates the corresponding repo
    on GitHub.

.PARAMETER gitmessage
    This parameter is OPTIONAL.

    If the $gitpush parameter is used, this parameter is MANDATORY.

    This parameter takes a string that represents a message that accompanies a git commit
    operation. The message should very briefly describe the changes that were made to the
    Git Repository.

.EXAMPLE
    Publish-Script -SourceFilePath "V:\powershell\testscript.ps1"`
    -DestinationLocalGitRepo "misc-powershell"`
    -SigningCertFilePath "R:\zero\ZeroCode.pfx"`
    -gitpush`
    -gitmessage "Initial commit for testscript.ps1"
    -Confirm
#>

function Publish-MyScript {

    [CmdletBinding(
        DefaultParameterSetName='Parameter Set 1', 
        SupportsShouldProcess=$true,
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    [Alias('pubscript')]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Parameter Set 1'
        )]
        [Alias("source")]
        [string]$SourceFilePath = $(Read-Host -Prompt "Please enter the full file path to the script that you would like to publish to your LOCAL GitHub Project Repository."),

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Parameter Set 1'
        )]
        [Alias("dest")]
        [string]$DestinationLocalGitRepoName = $(Read-Host -Prompt "Please enter the name of the LOCAL Git Repo to which the script/function will be published."),

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Parameter Set 1'
        )]
        [Alias("cert")]
        [string]$SigningCertFilePath,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Parameter Set 1'
        )]
        [Alias("push")]
        [switch]$gitpush,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Parameter Set 1'
        )]
        [Alias("message")]
        [string]$gitmessage
    )

    ##### REGION Helper Functions and Libraries #####
    ## BEGIN Sourced Helper Functions ##
    ## END Sourced Helper Functions ##
    ## BEGIN Native Helper Functions ##
    ## END Native Helper Functions ##
    ##### REGION END Helper Functions and Libraries #####


    ##### BEGIN Parameter Validation #####
    # Valdate Git Repo Parent Directory $env:GitRepoParent
    if (! $env:GitRepoParent)
    {
        [string]$env:GitRepoParent = Read-Host -Prompt "Please enter the parent directory of your local gitrepo"
    }
    if (! $(Test-Path $env:GitRepoParent))
    {
        Write-Warning "The path $env:GitHubParent was not found!"
        [string]$env:GitRepoParent = Read-Host -Prompt "Please enter the parent directory of your local gitrepo"
        if (! $(Test-Path $env:GitRepoParent))
        {
            Write-Host "The path $env:GitHubParent was not found! Halting!"
            Write-Error "The path $env:GitHubParent was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Validate $SigningCertFilePath
    if ($SigningCertFilePath)
    {
        if (! $(Test-Path $SigningCertFilePath))
        {
            Write-Warning "The path $SigningCertFilePath was not found!"
            [string]$SigningCertFilePath = Read-Host -Prompt "Please enter the file path for the certificate you would like to use to sign the script/function"
            if (! $(Test-Path $SigningCertFilePath))
            {
                Write-Host "The path $SigningCertFilePath was not found! Halting!"
                Write-Error "The path $SigningCertFilePath was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate $gitpush
    if ($gitpush)
    {
        if (! $gitmessage)
        {
            [string]$gitmessage = Read-Host -Prompt "Please enter a message to publish on git for this push"
        }
    }
    ##### END Parameter Validation #####


    ##### BEGIN Variable/Parameter Transforms #####
    $pos = $SourceFilePath.LastIndexOf("\")
    $ScriptFileName = $SourceFilePath.Substring($pos+1)
    $DestinationLocalGitRepoDir = "$env:GitRepoParent\$DestinationLocalGitRepoName"
    $DestinationFilePath = "$DestinationLocalGitRepoDir\$ScriptFileName"

    if ($SigningCertFilePath)
    {
        Write-Host "The parameter `$SigningCertFilePath was provided. Getting certificate data..."
        [System.Security.Cryptography.X509Certificates.X509Certificate]$SigningCert = Get-PfxCertificate $SigningCertFilePath
    }
    ##### END Variable/Parameter Transforms #####


    ##### BEGIN Main Body #####
    if ($pscmdlet.ShouldProcess($SourceFilePath,'Sign Script and Copy to Local Git Repo'))
    {
        if ($SigningCertFilePath)
        {
            Set-AuthenticodeSignature -FilePath $SourceFilePath -cert $SigningCert -Confirm:$false
        }

        Copy-Item -Path $SourceFilePath -Destination $DestinationFilePath -Confirm:$false
    }

    if ($gitpush)
    {
        if ($pscmdlet.ShouldProcess($DestinationLocalGitRepoName,"Push deltas in $DestinationLocalGitRepoName to GitHub"))
        {
            git -C $DestinationLocalGitRepoDir add -A
            git -C $DestinationLocalGitRepoDir commit -a -m "$gitmessage"
            git -C $DestinationLocalGitRepoDir push
        }
    }

    ##### END Main Body #####

}






# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVTBlQWqPQz7VMcIUO+0IpbGG
# zFWgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSVeRR/vPX9
# izvPCh3HdQfuKRN+nTANBgkqhkiG9w0BAQEFAASCAQCNeswPGkf6A46dmKFVpWRG
# 0RwXz81ljYf16On74kGgzmx5Gjj934DzgoD1z384JFRKvg6qSDUDKECv3SBs/yvl
# ZtkgBswMEmS+1Z/yQCa5WxBFYTftULxdBrtMRDI1TtIgxAMMifIP8X5GETfvaWnR
# kc+t2CggWuVGhf7xFG5Hjh6a6uTMaKbj6GP6TVXlHxmhD+/I8MrYDcjSosMuUuW4
# yoDiOT09OTYAnPXEVlM0ZrRo0G6kcRxl7+Ap4RRZP0Gy7IqMXaBxF3oeXGkJ4+IZ
# nV10iBub4zHK4sliIgyZTAqCh/ugIeNScHfu6D2xx3tWdKVbS2u12Zg9Ul+EHziW
# SIG # End signature block
