function New-GoogleSearch {
    [CmdletBinding(PositionalBinding=$true)]
    [Alias('google')]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$SearchString = $(Read-Host -Prompt "Please enter your search terms."),

        [Parameter(Mandatory=$False)]
        [string]$JavaScriptUsed = "No"
    )

    ## BEGIN Native Helper Functions ##
    function New-GoogleURL {
        [CmdletBinding(PositionalBinding=$true)]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$SearchArgs
        )

        Begin {
            $query='https://www.google.com/search?q='
        }

        Process {
            $UpdatedSearchString = $SearchArgs.Split(" ")

            $UpdatedSearchString | % {$query = $query + "$_+"}
        }

        End {
            $url = $query.Substring(0,$query.Length-1)
            $url
        }
    }
    ## END Native Helper Functions ##


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $UpdatedURL = New-GoogleURL -SearchArgs $SearchString
    Write-Host "Updated URL is $UpdatedURL"
    $TargetURL = $UpdatedURL
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    if ($JavaScriptUsed -eq "Yes" -or $JavaScriptUsed -eq "y") {
        $ie = New-Object -com InternetExplorer.Application
        $ie.visible=$false
        $ie.navigate("$TargetURL")
        Start-Sleep -Seconds 3
        while($ie.ReadyState -ne 4) {start-sleep -m 1000}
        $global:RawHTML = $ie.Document.body.outerHTML
    }
    if ($JavaScriptUsed -eq "No" -or $JavaScriptUsed -eq "n") { 
        $global:RawHTML = Invoke-WebRequest -Uri "$TargetURL" -UseBasicParsing | Select-Object -ExpandProperty RawContent
    }

    # Confirmed working on PowerShell 4 and 5
    $NewHTMLObject = New-Object -com "HTMLFILE"
    $NewHTMLObject.designMode = "on"
    $global:RawHTML = [System.Text.Encoding]::Unicode.GetBytes($global:RawHTML)
    $NewHTMLObject.write($global:RawHTML)
    $NewHTMLObject.Close()
    $global:NewHTMLObjectBody = $NewHTMLObject.body

    # Alternate method - Requires Visual Studio be installed:
    <#
    Add-Type -Path "C:\Program Files (x86)\Microsoft.NET\Primary Interop Assemblies\Microsoft.mshtml.dll"
    $NewHTMLObject = New-Object -com "HTMLFILE"
    $NewHTMLObject.designMode = "on"
    $global:RawHTML = [System.Text.Encoding]::Unicode.GetBytes($global:RawHTML)
    $NewHTMLObject.IHTMLDocument2_write($global:RawHTML)
    NewHTMLObject.Close()
    $global:NewHTMLObjectBody = $NewHTMLObject.body
    #>

    # Get Search Results
    $SearchResultTitleObjectsArray = $($global:NewHTMLObjectBody).GetElementsByTagName("h3")
    
    $global:ArrayOfSearchResultCustomObjects = @()
    # Since $SearchResultTitleObjectsArray is NOT actually an array (it's a __ComObject), need to use Length instead of Count...
    for ($i=0; $i -lt $SearchResultTitleObjectsArray.Length; $i++) {
        $ResultHeader = $($global:NewHTMLObjectBody).GetElementsByTagName("h3") | Select-Object -Index $i
        $URLDropdown = $($ResultHeader.nextSibling).firstChild
        $URL = $($URLDropdown.innerText).Split("`n")[0]

        try {
            $CachedPrep = $($($($ResultHeader.nextSibling).getElementsByTagName("li") | Where-Object {$_.innerText -eq "Cached"}).GetElementsByTagName("a")).href
        }
        catch {
            Write-Verbose "Search Result does not contain Cached option..."
        }
        if ($CachedPrep) {
            $Cached = "https://google.com/"+"$($CachedPrep -replace 'about:/','')"
        }

        try {
            $SimilarPrep = $($($($ResultHeader.nextSibling).getElementsByTagName("li") | Where-Object {$_.innerText -eq "Similar"}).GetElementsByTagName("a")).href
        }
        catch {
            Write-Verbose "Search Result does not contain Similar option..."
        }
        if ($SimilarPrep) {
            $Similar = "https://google.com/"+"$($SimilarPrep -replace 'about:/','')"
        }

        $Description = $URLDropdown.nextSibling
        $OtherLinks  = $($Description.nextSibling).nextSibling

        New-Variable -Name "HeaderObject$i" -Scope Global -Value $(
            New-Object PSObject -Property @{
                HeaderObject = $($global:NewHTMLObjectBody).GetElementsByTagName("h3") | Select-Object -Index $i
                ResultHeader = $ResultHeader.innerText
                URL = $URL
                Cached = $Cached
                Similar = $Similar
                Description = $Description.innerText
                OtherLinks = $OtherLinks.innerText
            }
        ) -Force

        $global:ArrayOfSearchResultCustomObjects +=, $(Get-Variable -Name "HeaderObject$i" -ValueOnly)

        Remove-Variable -Name "ResultHeader" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "URLDropdown" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "URL" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "CachedPrep" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "Cached" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "SimilarPrep" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "Similar" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "Description" -Force -ErrorAction SilentlyContinue
        Remove-Variable -Name "OtherLinks" -Force -ErrorAction SilentlyContinue
    }

    Write-Host "The object `$global:ArrayOfSearchResultCustomObjects is now available in the current scope"

    ##### END Main Body #####

}

New-GoogleSearch -SearchString "Test Search"
$global:ArrayOfSearchResultCustomObjects | Select-Object ResultHeader,URL,Cached,Similar,Description,OtherLinks | Format-List
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUH7/w93NXK4dzvIaIo8f8WUJO
# 6dSgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS9FUJyv/1G
# KIUrdOvD/I1h3E3qwDANBgkqhkiG9w0BAQEFAASCAQAkAgKEeGFNion8ORrWWKiy
# FgT+9i6hPI8L9gdEbnMiUMmU+EDza/0EqCvSkcfBO78ICVgcCh/O5xvXKpvWtRzo
# oo9twgZslDhh9xTYEDipBeLDZG8oLAAyLkYeu7JwkGkjr9BTtPREUerv4U1jeAGU
# lBsX/tuA0MCH0hg4lWwyf4KnGRpm2XGHT8oXHmByTmpfEhjW+5BsEk0auvLwV/lf
# W84HstP9ZocftEu9gRfIJLwkCab13R3hYlY19ludSB5+QY99id/393B6yzJVvp2C
# igW+e2iUlNMn1jbUM79av9G0iQBigpMxrvfQThRNOwIEOE9CpT9MUtI1449wd7/A
# SIG # End signature block
