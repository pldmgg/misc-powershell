<#
.SYNOPSIS
    Return information about the HTML element that contain the text your want to find on the specified website.

.DESCRIPTION
    See Synopsis.

.NOTES
    None

.PARAMETER TargetUEL
    This parameter is MANDATORY.

    This parameter takes a string that represents the URL of the website you would like to search.

.PARAMETER LetJavaScriptLoad
    This parameter is OPTIONAL.

    This parameter takes a string that represents a positive or negative response (it's essentially a switch). Valid values are:
    "Yes","Y","No", and "N" (not case sensitive)

    A positive value means that the script lets the website load all JavaScript before searching for the specified text. A negative
    value means that the search for the specified text will take place before JavaScript is loaded.

    This parameter's default value is "Yes", i.e. search for text will take place AFTER JavaScript is loaded.

.PARAMETER TextToSearchFor
    This parameter is MANDATORY.

    This parameter takes a string that represents the text you would like to search for on the target website.

.EXAMPLE
    Find-WebsiteText -TargetURL "http://platinumgod.co.uk/afterbirth-plus" -LetJavaScriptLoad "Yes" -TextToSearchFor "UNLOCK:"

.INPUTS
    Inputs to this cmdlet (if any)
.OUTPUTS
    1) $global:FoundResultsArray.Text - An array of strings. Each string represents a full line of text that contains the string
    that you searched for. This is displayed on STDOUT.

    2) $global:FoundResultsArray - An array of Custom PSObjects made available for subsequent manipulation in the PowerShell
    session's Global scope.
#>

function Find-WebsiteText {
    [CmdletBinding(PositionalBinding=$true)]
    [Alias('google')]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$TargetURL = $(Read-Host -Prompt "Please enter the URL for the website you would like to parse."),

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","Y","No","N")]
        [string]$LetJavaScriptLoad = "Yes",

        [Parameter(Mandatory=$False)]
        [string]$TextToSearchFor
    )

    ## BEGIN Native Helper Functions ##

    ## END Native Helper Functions ##


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($LetJavaScriptLoad -match "Yes|Y") {
        $ie = New-Object -com InternetExplorer.Application
        $ie.visible=$false
        $ie.navigate("$TargetURL")
        Start-Sleep -Seconds 3
        while($ie.ReadyState -ne 4) {start-sleep -m 1000}
        $RawHTML = $ie.Document.body.outerHTML
    }
    if ($LetJavaScriptLoad -eq "No" -or $LetJavaScriptLoad -eq "n") { 
        $RawHTML = Invoke-WebRequest -Uri "$TargetURL" -UseBasicParsing | Select-Object -ExpandProperty RawContent
    }

    # Notes Regarding mshtml.dll
    <#
        Microsoft.mshtml.dll is a wrapper for C:\Windows\System32\mshtml.dll that exposes more functionality.

        If your system's Global Assembly Cache (GAC) contains the wrapper dll here:
            C:\Windows\assembly\GAC\Microsoft.mshtml\<VERSION_NUMBER>\Microsoft.mshtml.dll
        ... then $(New-Object -com "htmlfile").GetType()).Name will be "HTMLDocumentClass" as opposed to "__ComObject".
        Microsoft.mshtml.dll will most likely be present in the GAC as a result of a Visual Studio or similar install.

        Check the GAC by using the following:
        Get-ChildItem -Recurse "C:\Windows\assembly" | Where-Object {
            $_.Name -like "*mshtml*" -and 
            !$_.PSIsContainer
        } | Select-Object FullName,VersionInfo

        It is also possible that C:\Program Files (x86)\Microsoft.NET\Primary Interop Assemblies\Microsoft.mshtml.dll exists
        on the system (also likely as a result of Visual Studio or similar install). If Microsoft.mshtml.dll is not available
        in the GAC, you can use the one under Primary Interop Assemblies by running the following:
        Add-Type -Path "C:\Program Files (x86)\Microsoft.NET\Primary Interop Assemblies\Microsoft.mshtml.dll"
        
        In any case, the object resulting from:
        $NewHTMLObject = New-Object -com "HTMLFILE" 
        ...will either be a "__ComObject" or "HTMLDocumentClass"
        
        Explore further Using the following:
        # Get All Available Com Objects
        $GetComClasses = gwmi -Class win32_classiccomclasssetting -ComputerName .
        $GetComClasses | Where-Object {$_.progid -eq "htmlfile"}) | Select-Object progId,.InprocServer32

        # Create New Com Object by referencing ProgID
        $NewHTMLObject = New-Object -ComObject "htmlfile"

        # Create New Com Object by referencing GUID
        $clsid = New-Object Guid '25336920-03F9-11cf-8FD0-00AA00686F13'
        $type = [Type]::GetTypeFromCLSID($clsid)
        $NewHTMLObject = [Activator]::CreateInstance($type)
    #>
    $NewHTMLObject = New-Object -com "HTMLFILE"
    $NewHTMLObject.designMode = "on"
    #$RawHTML = [System.Text.Encoding]::Unicode.GetBytes($RawHTML)
    if ($($NewHTMLObject.GetType()).Name -eq "HTMLDocumentClass") {
        $NewHTMLObject.IHTMLDocument2_write($RawHTML)
    }
    if ($($NewHTMLObject.GetType()).Name -like "*ComObject") {
        $NewHTMLObject.write($RawHTML)
    }
    $NewHTMLObject.Close()
    $global:NewHTMLObjectBody = $NewHTMLObject.body

    # Get All HTML Classes present on website
    $global:HTMLClassesPrep = $($global:NewHTMLObjectBody.GetElementsByTagName("*")).className | Sort-Object | Get-Unique
    $global:HTMLClasses = $global:HTMLClasses += ""
    # Get All HTML Tags
    $global:HTMLTagsPrep = $($global:NewHTMLObjectBody.GetElementsByTagName("*")).tagName | Sort-Object | Get-Unique
    $global:HTMLTags = $global:HTMLTagsPrep += ""

    # First, try finding HTML Classes that contain the text we are searching for...
    [array]$global:filter1 = foreach ($HTMLClassName in $HTMLClasses) {
        $global:NewHTMLObjectBody.GetElementsByClassName("$HTMLClassName") | Where-Object {$($_.innerText | Out-String) -like "*$TextToSearchFor*" }
    }
    # If no HTML Classes contain the text we are looking for, broaden the search to inspect all HTML Tags  
    if ($global:filter1.Count -eq 0) {
        [array]$global:filter1 = foreach ($HTMLTagName in $HTMLTags) {
            $global:NewHTMLObjectBody.GetElementsByTagName("$HTMLTagName") | Where-Object {$($_.innerText | Out-String) -like "*$TextToSearchFor*" }
        }
    }
    # Unfortunately, the innerText of all parentElements all the way up the chain also fulfill the criteria for $filter1,
    # So, in order to get the elements that are at the lowest rung, we need to specify that the elements
    # we want returned should NOT have any children that have innerText that contain the text we are searching for
    [array]$global:filter2 = foreach ($obj1 in $global:filter1) {
        [array]$childrenArray = $($obj1).children
        foreach ($obj2 in $childrenArray) {
            $InnerTextAsString = $($obj2).innerText | Out-String
            if ($InnerTextAsString -notlike "*$TextToSearchFor*") {
                $obj1
            }
        }
    }

    $global:FoundResultsArray = @()
    for ($i=0; $i -lt $global:filter2.Count; $i++) {
        $Object = $filter2[$i]
        New-Variable -Name "FoundTextElementInfo$i" -Scope Local -Value $(
            New-Object PSObject -Property @{
                Object                      = $Object
                Class                       = $Object.className
                Tag                         = $Object.tagName
                Text                        = $Object.innerText
                ParentObject                = $($Object).parentElement
                ParentElementClass          = $($($Object).parentElement).className
                ParentElementTag            = $($($Object).parentElement).tagName
                ParentElementText           = $($($Object).parentElement).innerText
                SiblingObject               = $($Object).nextSibling
                SiblingElementClass         = $($($Object).nextSibling).className
                SiblingElementTag           = $($($Object).nextSibling).tagName
                SiblingElementText          = $($($Object).nextSibling).innerText
                FirstChildObject            = $($Object).firstChild
                FirstChildElementClass      = $($($Object).firstChild).className
                FirstChildElementTag        = $($($Object).firstChild).tagName
                FirstChildElementText       = $($($Object).firstchild).innerText
            }
        )
        
        $global:FoundResultsArray +=, $(Get-Variable -Name "FoundTextElementInfo$i" -ValueOnly)
    }

    # $global:FoundResultsArray | Select-Object Class,Tag,Text | Format-List
    $global:FoundResultsArray.Text
    Write-Host "The object `$global:FoundResultsArray is available in current Scope"

}




# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlRATdOYCPnRd7kTDP/Bm6iXi
# tWygggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBREGSHFqpv7
# TmecxLUCtMbijkZfvzANBgkqhkiG9w0BAQEFAASCAQBnMtzStoLp8m9MgpL3Nxok
# +getjCj89raLcisons9hZocJI/GM0m3lwH+UsDlvGKqxlGhiuCmmjL228puYmQSG
# /PJ7dpq+6vZ3F4UtyuitI8Xpko4nMc9AHHqEvL6U1aK0Vbm/FZ60aQxBMGUNCgDB
# F3fhlyTUl+rYf6VMqAxBMdT3chZPZHManYxpIwOGn3Jn6v4OFEc6T4G1W/XKOY6y
# Vm6ocjbg8/HAk1xKXSsB9FaJoq8p1S+gaQt93sLVSDfsesM9RX8tPo8UmOgbWjk/
# NRfPR2RAvyQS5pDSrYR/uvWlb5/rgie22Dc/mdDB198A8EcyBpBJSuZgXmRLXdor
# SIG # End signature block
