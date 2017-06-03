function Build-VisualStudioProject {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $PathToCSProjFile = $(Read-Host -Prompt "Please enter the full path to the .csproj file for the Visual Studio Project you would like to compile."),

        [Parameter(Mandatory=$False)]
        [switch]$ReturnAll
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Verify $PathToCSProjFile
    if (!$(Test-Path $PathToCSProjFile)) {
        Write-Verbose "The path $PathToCSProjFile was not found! Halting!"
        Write-Error "The path $PathToCSProjFile was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CSProjParentDir = $PathToCSProjFile | Split-Path -Parent
    Set-Location $CSProjParentDir

    if (!$(Get-Command msbuild -ErrorAction SilentlyContinue)) {
        # Find latest installed version of .Net
        if (!$(Test-Path "C:\Windows\Microsoft.NET\Framework")) {
            Write-Verbose "The path C:\Windows\Microsoft.NET\Framework was not found! Please make sure .NET 4.5 is installed. Halting!"
            Write-Error "The path C:\Windows\Microsoft.NET\Framework was not found! Please make sure .NET 4.5 is installed. Halting!"
            $global:FunctionResult = "1"
            return
        }
        $FoundNetVersions = @()
        Get-ChildItem "C:\Windows\Microsoft.NET\Framework" | % {
            try {
                if ($_.Name[0] -eq "v") {
                    $FoundVersion = [version]$($_.Name).Substring(1)
                    $FoundNetVersions +=, $FoundVersion
                }
            }
            catch {
                Write-Verbose "$_ is NOT a .Net Version directory..."
            }
        }
        if ($FoundNetVersions.Count -lt 1) {
            Write-Verbose "Unable to find .Net Framework versions in C:\Windows\Microsoft.NET\Framework! Halting!"
            Write-Error "Unable to find .Net Framework versions in C:\Windows\Microsoft.NET\Framework! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($FoundNetVersions.Count -ge 1) {
            # Get the Max version and make sure it's 4 or higher
            $MaxNetVer = $($FoundNetVersions | Measure-Object -Maximum).Maximum
            if ($MaxNetVer.Major -ge 4) {
                $MSBuildParentDir = $(Get-ChildItem "C:\Windows\Microsoft.NET\Framework" | Where-Object {$_.Name -like "*$($MaxNetVer.ToString())*"}).FullName
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$MSBuildParentDir"
                }
                else {
                    $env:Path = "$env:Path;$MSBuildParentDir"
                }
            }
            else {
                Write-Verbose "Please make sure .NET 4.5 is installed. Halting!"
                Write-Error "Please make sure .NET 4.5 is installed. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "msbuild.exe"
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = "$PathToCSProjFile"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    #$Process.WaitForExit()
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $AllOutput = $stdout + $stderr

    $AllOutputArrayOfStrings = $AllOutput -split "`n"
    $ProgramLocationPrep = $($AllOutputArrayOfStrings | Select-String -Pattern "(->).+\.exe").Matches.Value
    $RegexFilePath = '(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    $ProgramLocation = $($ProgramLocationPrep | Select-String -Pattern $RegexFilePath).Matches.Value
    $SuccessfulBuild = if ($($AllOutput | Select-String -Pattern "Build succeeded").Matches.Success) {$true} else {$false}

    if ($ReturnAll) {
        New-Variable -Name "Results" -Value $(
            [pscustomobject][ordered]@{
                CompiledProgramLocation   = $ProgramLocation
                SuccessfulBuild           = $SuccessfulBuild
                AllOutput                 = $AllOutput
            }
        )
    }
    else {
        New-Variable -Name "Results" -Value $(
            [pscustomobject][ordered]@{
                CompiledProgramLocation   = $ProgramLocation
                SuccessfulBuild           = $SuccessfulBuild
            }
        )
    }
    
    
    $Results



    ##### END Main Body #####

}






# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtyWM0j0wOAIU8KpXokg1XyaS
# mPygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRc2X+a5C6u
# IopiOgRp2E9hGGsK2jANBgkqhkiG9w0BAQEFAASCAQBINYME5+UA8UMsS563bl9r
# myVV4ZfZHkTi5OSKO3SmzcG8M2At4LZXEjhf8+98BYyCE0TjNcP7zX249SMz/x34
# EKNxZttk6We0B0+TQ0AIbZE/1zJ+bFjZADRBY/du8oJMgeFIhiWjrrK8wygYiH88
# FODBvm+UuuVx/5hBCqh5wIdpD3PAOPhnc9tE8RhhwAUG/5qG5xFWgH1ZPQsKKGW6
# IGXLaM4rUa2YXHiATv+DQI/7kEzWI+VSBYzqyHSZIfMu2VxQZNWfoxt3fdYlAhA6
# Ib9ywbTPPTIY4rH7/hKL7nzMui7EFtwcRER52Svy9Bo4l2bAEQhN50XTpcchOKAW
# SIG # End signature block
