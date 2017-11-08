<#
.SYNOPSIS
    Use PowerShell to search Google and return results to your current PowerShell Session.
.DESCRIPTION
    Search Google using PowerShell and return results as an array of custom PSObjects - one object per entry on Page 1 of Google 
    search results. These custom objects can be easily leveraged for further scripting.
.NOTES
    None.
.PARAMETER SearchString
    This parameter is MANDATORY.

    This parameter takes a string that represents your search terms.

.EXAMPLE
    New-GoogleSearch -SearchString "Test Search"

.OUTPUTS
    Outputs an array of custom PSObjects
#>

function New-GoogleSearch {
    [CmdletBinding(PositionalBinding=$true)]
    [Alias('google')]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$SearchString
    )

    ##### REGION Helper Functions and Libraries #####

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

    function Convert-FromBase64 {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$True)]
            [string]$InputString 
        )

        ##### BEGIN Main Body #####
        try {
            $Output = [System.Text.Encoding]::UNICODE.GetString([System.Convert]::FromBase64String($InputString))
        }
        catch {
            Write-Verbose "`$InputString is NOT a valid base64 string!"
        }
        if (!$Output) {
            Write-Error "`$InputString is NOT a valid base64 string! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($Output) {
            return $Output
        }
        ##### END Main Body #####
    
    }

    function Convert-ToBase64 {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$True)]
            [string]$InputString
        )

        ##### BEGIN Parameter Validation #####
        $RegexLocalOrUNCPath = '^(([a-zA-Z]:\\)|(\\\\))(((?![<>:"/\\|?*]).)+((?<![ .])\\)?)*$'
        # If $InputString is a filepath...
        if ([uri]$InputString.IsAbsoluteURI -and $([uri]$InputString.IsLoopBack -or [uri]$InputString.IsUnc)) {
            if (Test-Path $InputString) {
                try {
                    $Output = [convert]::ToBase64String((get-content "$InputString" -encoding byte))
                }
                catch {
                    Write-Verbose "`$InputString is not able to be converted to a base64 string!"
                }
                if (!$Output) {
                    Write-Error "`$InputString is able to be converted to a base64 string! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                if ($Output) {
                    return $Output
                }
            }
            if (!$(Test-Path $InputString)) {
                Write-Verbose "The path $InputString was not found! Halting!"
                Write-Error "The path $InputString was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        # Else, assume it is just a string of text
        else {
            try {
                $Output = [System.Convert]::ToBase64String([System.Text.Encoding]::UNICODE.GetBytes($InputString))
            }
            catch {
                Write-Verbose "`$InputString is not able to be converted to a base64 string!"
            }
            if (!$Output) {
                Write-Error "`$InputString is able to be converted to a base64 string! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($Output) {
                return $Output
            }
        }
        
        ##### END Main Body #####
    
    }

    function ConvertTo-Scriptblock {
        Param(
            [Parameter(
                Mandatory = $True,
                ValueFromPipeline = $True
            )]
            [string]$string
        )
        $scriptBlock = [scriptblock]::Create($string)
        return $scriptBlock
    }

    function Get-StdResultProperties {
        [CmdletBinding(PositionalBinding=$true)]
        Param(
            [Parameter(Mandatory=$True)]
            $HTMLBody,

            [Parameter(Mandatory=$True)]
            [Alias("cntid")]
            [string]$SearchResultsContainer,

            [Parameter(Mandatory=$True)]
            [Alias("baseobjcl")]
            [string]$BasicObjectClass,

            [Parameter(Mandatory=$True)]
            [Alias("rhcl")]
            [string]$ResultHeaderClass,

            [Parameter(Mandatory=$True)]
            [Alias("urltg")]
            [string]$URLTag,

            [Parameter(Mandatory=$True)]
            [Alias("urlcttg")]
            [string]$URLCitationTag,

            [Parameter(Mandatory=$True)]
            [Alias("imgtg")]
            [string]$ImageTag,

            [Parameter(Mandatory=$True)]
            [Alias("descl")]
            [string]$DescriptionClass,

            [Parameter(Mandatory=$True)]
            [Alias("olcl")]
            [string]$OtherLinksClass
        )

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

        $StandardResultsArrayPrep = $($($HTMLBody).getElementsByTagName('div') |`
        Where-Object {$_.getAttributeNode('id').Value -eq "$SearchResultsContainer"}).children
        [array]$StandardResultsArray = foreach ($obj1 in $StandardResultsArrayPrep) {
            $($obj1).GetElementsByClassName("$BasicObjectClass")
        }

        [System.Collections.ArrayList]$StandardResults = @()
        $ForLoopVariableNames = @("BasicResultObject","ResultHeaderObject","ResultHeader","URLTagCheck","DescriptionClassCheck",
            "URLCitationTagCheck","OtherLinksClassCheck","CheckChildrenRecurse","URLCitationObject","URLCitation","URLPrep","URL",
            "DescriptionObject","Description","OtherLinksObject","OtherLinks","NonStandardResultInfo","CachedPrep1","CachedPrep2",
            "CachedPrep3","CachedPrep4","Cached","SimilarPrep1","SimilarPrep2","SimilarPrep3","Similar","ImageTagCheck",
            "ImageObject","ImagePrep1","ImagePrep2","ImageBase64","ImageDisplay","tmpfile","bytes","DatePosted"
        )
        $null = [Reflection.Assembly]::LoadWithPartialName("System.Web")
        # Below $RegexURL is from: http://daringfireball.net/2010/07/improved_regex_for_matching_urls
        $RegexURL = "(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'`".,<>?«»“”‘’]))"
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
        
        ##### BEGIN Main Body #####

        # Since $StandardResultsArray is NOT actually an array (it's a __ComObject), need to use Length instead of Count...
        for ($i=0; $i -lt $StandardResultsArray.Length; $i++) {
            $BasicResultObject = $StandardResultsArray | Select-Object -Index $i
            $ResultHeaderObject = $($BasicResultObject).GetElementsByClassName("$ResultHeaderClass")
            $ResultHeader = $($ResultHeaderObject).innerText
            if ($ResultHeader -eq $null) {
                continue
            }

            $URLTagCheck = $($($ResultHeaderObject).GetElementsByTagName("$URLTag")).tagName
            $URLCitationTagCheck = $($($BasicResultObject).GetElementsByTagName("$URLCitationTag")).tagName
            $DescriptionClassCheck = $($($BasicResultObject).GetElementsByClassName("$DescriptionClass")).className
            $ImageTagCheck = $($($BasicResultObject).GetElementsByTagName("$ImageTag")).tagName
            $OtherLinksClassCheck = $($($BasicResultObject).GetElementsByClassName("$OtherLinksClass")).className
            [array]$CheckChildrenRecurse = @("$URLTagCheck","$URLCitationTagCheck","$DescriptionClassCheck",
                "$ImageTagCheck","$OtherLinksClassCheck"
            )

            if ($CheckChildrenRecurse -contains "$URLTag") {
                $URLPrep = $($($ResultHeaderObject).GetElementsByTagName("$URLTag")).href
                $URL = $URLPrep -replace 'about:/url\?q=',''
            }
            
            if ($CheckChildrenRecurse -contains "$URLCitationTag") {
                $URLCitationObject = $($BasicResultObject).GetElementsByTagName("$URLCitationTag")
                $URLCitation = $($URLCitationObject).innerText
            }

            if ($CheckChildrenRecurse -contains "$DescriptionClass") {
                $DescriptionObject = $($BasicResultObject).GetElementsByClassName("$DescriptionClass")
                $Description = $($($DescriptionObject).innerText) -replace "`r`n",""

                $DateSplitIndex = $($Description | Select-String -Pattern "[\d]{4}").Matches.Index + 4
                try {
                    if ($DateSplitIndex -gt 4) {
                        [datetime]$DatePosted = $Description.Substring(0, $DateSplitIndex)
                    }
                    else {
                        $DatePosted = $null
                    }
                }
                catch {
                    $DatePosted = $null
                }
            }

            if ($CheckChildrenRecurse -contains "$ImageTagCheck") {
                $ImageObject = $($BasicResultObject).getElementsByTagName("$ImageTag")
                $ImagePrep1 = $($ImageObject).src
                
                if ($ImagePrep1 -match $RegexURL) {
                    # Download the file to a temp location...
                    $tmpFile = [IO.Path]::GetTempFileName()
                    Invoke-WebRequest -URI $ImagePrep1 -OutFile $tmpFile
                    $ImageBase64 = Convert-ToBase64 -InputString $tmpFile
                }
                if ($ImagePrep1 -notmatch $RegexURL -and $ImagePrep1 -ne $null) {
                    $ImagePrep2 = $($ImagePrep1 -split 'base64,','')[1]

                    # If validBase64 string, then set write the file out...
                    if ($(Convert-FromBase64 -InputString "$ImagePrep2" -ErrorAction SilentlyContinue)) {
                        $ImageBase64 = $ImagePrep2
                        # Write the image to a file...
                        $bytes = [Convert]::FromBase64String($ImageBase64)
                        $tmpFile = [IO.Path]::GetTempFileName()
                        [IO.File]::WriteAllBytes("$tmpfile", $bytes)
                    }
                }
            }

            if ($CheckChildrenRecurse -contains "$OtherLinksClassCheck") {
                $OtherLinksObject  = $($BasicResultObject).GetElementsByClassName("$OtherLinksClass")
                $OtherLinks = $($OtherLinksObject).innerText
            }

            if ($(!$CheckChildrenRecurse -contains "$URLTag") -or $(!$CheckChildrenRecurse -contains "$DescriptionClass") -or $(!$CheckChildrenRecurse -contains "$OtherLinksClass")) {
                [array]$NonStandardResultInfo = @(
                    "$($($BasicResultObject).children)",
                    "$($($($BasicResultObject).children).children)",
                    "$($($($($BasicResultObject).children).children).children)"
                )
            }
            else {
                $NonStandardResultInfo = "Not Applicable - results are as expected"
            }

            try {
                $CachedPrep1 = $($($($BasicResultObject).getElementsByTagName("li") | Where-Object {$_.innerText -eq "Cached"}).GetElementsByTagName("a")).outerHtml
            }
            catch {
                Write-Verbose "Search Result does not contain Cached option..."
            }
            if ($CachedPrep1) {
                $CachedPrep2 = $($($($CachedPrep1 -replace 'about:/','') -replace 'href="(.*?)(?=h)',';;;') -split ";;;")[1]
                $CachedPrep3 = $($("https://google.com/url?q="+"$CachedPrep2") -split ";")[0]
                $CachedPrep4 = $($CachedPrep3 -replace 'url\?q=url\?q=','url?q=') -replace 'https://google.com/url\?q=',''
                $Cached = [System.Web.HttpUtility]::UrlDecode($CachedPrep4)
            }

            try {
                $SimilarPrep1 = $($($($BasicResultObject).getElementsByTagName("li") | Where-Object {$_.innerText -eq "Similar"}).GetElementsByTagName("a")).outerHtml
            }
            catch {
                Write-Verbose "Search Result does not contain Similar option..."
            }
            if ($SimilarPrep1) {
                $SimilarPrep2 = $($($($SimilarPrep1 -replace 'about:/','') -replace 'search\?q=related:',';;;search?q=related:') -split ";;;")[1]
                $SimilarPrep3 = $($("https://google.com/search?q=related:"+"$SimilarPrep2") -split ";")[0]
                $Similar = $SimilarPrep3 -replace 'search\?q=related:search\?q=related:','search?q=related:'
            }

            New-Variable -Name "SearchEntry$i" -Scope Global -Value $(
                [pscustomobject][ordered]@{
                    BasicResultObject       = $BasicResultObject
                    ResultHeaderObject      = $ResultHeaderObject
                    ResultHeader            = $ResultHeader
                    URLCitationObject       = $URLCitationObject
                    URLCitation             = $URLCitation
                    URL                     = $URL
                    CachedObject            = $CachedPrep1
                    Cached                  = $Cached
                    SimilarObject           = $SimilarPrep1
                    Similar                 = $Similar
                    DescriptionObject       = $DescriptionObject
                    Description             = $Description
                    ImageObject             = $ImageObject
                    ImageBase64             = $ImageBase64
                    OtherLinksObject        = $OtherLinksObject
                    OtherLinks              = $OtherLinks
                    NonStdResultInfo        = $NonStandardResultInfo
                    DatePosted              = $DatePosted
                }
            ) -Force

            if ($ImageBase64 -ne $null) {
                # Add DisplayImage Method to $SearchEntry$i
                $scriptblock = ConvertTo-Scriptblock -string "Start-Job -ScriptBlock {Show-Image -file `"$tmpfile`" | Out-Null}"
                Add-Member -InputObject $(Get-Variable -Name "SearchEntry$i" -ValueOnly) -Name "DisplayImage" -MemberType ScriptMethod -Value $scriptblock -PassThru
            }

            # $global:StandardResults +=, $(Get-Variable -Name "SearchEntry$i" -ValueOnly)

            $Output = $(Get-Variable -Name "SearchEntry$i" -ValueOnly)
            $null = $StandardResults.Add($Output)

            # Cleanup for next loop
            foreach ($varname in $ForLoopVariableNames) {
                Remove-Variable -Name "$varname" -Force -ErrorAction SilentlyContinue
            }
        }

        $StandardResults

        ##### END Main Body #####
    }

    function Show-Image {
        [CmdletBinding(PositionalBinding=$true)]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$file = $(Read-Host -Prompt "Please enter the full path to the image file you would like to display.")
        )
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        [void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void][Reflection.Assembly]::LoadWithPartialName("System.Drawing")
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
        ##### BEGIN Main Body #####
        [Windows.Forms.Screen]::AllScreens | foreach {
            $maxHeight = ($_.Bounds).Height
            $maxWidth = ($_.Bounds).Width
        }
    
        if (Test-Path $file) {
            # Loading Image
            $pic = [Drawing.Image]::FromFile((Resolve-Path $file).Path)
            $picsize = $pic.Size
            [int]$FormControlTopBarHeight = 39
    
            # Create Form
            $frmMain = New-Object Windows.Forms.Form
            $picArea = New-Object Windows.Forms.PictureBox
    
            # Define Picbox Area
            $picArea.Dock = "Fill"
            $picArea.Image = New-Object Drawing.Bitmap((Resolve-Path $file).Path)
            $picArea.SizeMode = "StretchImage"
    
            # Define Form
            $frmMain.AutoScroll = $true
            $frmMain.Controls.AddRange(@($picArea))
            #$frmMain.FormBorderStyle = "None"
            $frmMain.StartPosition = "CenterScreen"
            $frmMain.Text = $file
            $frmMain.Add_KeyDown( { if ($_.KeyCode -eq "Escape") {$frmMain.Close()} } )
    
            # Adjust Sizing as needed
            if ($picsize.Height -ge $maxHeight -and $picsize.Width -ge $maxWidth) {
                $frmMain.Size = New-Object Drawing.Size($maxWidth, $($maxHeight+$FormControlTopBarHeight))
            }
            else {
                $frmMain.Size = New-Object Drawing.Size($picsize.Width, $($picsize.Height+$FormControlTopBarHeight))
            }
    
            [void]$frmMain.ShowDialog()
            # This can escape locking image file with host
            $pic.Dispose()
        }
        ##### END Main Body #####
    }

    ## END Native Helper Functions ##


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $TargetURL = New-GoogleURL -SearchArgs $SearchString
    Write-Verbose "The Google search URL is $TargetURL"

    <#
    if (Test-Path "$env:ProgramFiles\Internet Explorer\iexplore.exe") {
        $IEVersion = $([version]$(Get-Item "$env:ProgramFiles\Internet Explorer\iexplore.exe").VersionInfo.ProductVersion).Major
        $FoundIE = $true
    }
    elseif (Test-Path "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe") {
        $IEVersion = $([version]$(Get-Item "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe").VersionInfo.ProductVersion).Major
        $FoundIE = $true
    }
    else {
        $FoundIE = $false
    }

    if ($LetJavaScriptLoad -and !$FoundIE) {
        Write-Verbose "Unable to determine IE version..."
    }
    #>

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    <#
    if ($LetJavaScriptLoad) {
        $ie = New-Object -com InternetExplorer.Application
        $ie.visible=$false
        $ie.navigate($TargetURL)
        Start-Sleep -Seconds 3
        while($ie.ReadyState -ne 4) {start-sleep -m 1000}
        $RawHTML = $ie.Document.body.outerHTML

        if ($RawHTML -ne $null) {
            $GotRawHTML = $true
        }
        else {
            $GotRawHTML = $false
        }
    }
    else { 
        $RawHTML = Invoke-WebRequest -Uri "$TargetURL" -UseBasicParsing | Select-Object -ExpandProperty RawContent
    }
    #>

    $RawHTML = Invoke-WebRequest -Uri "$TargetURL" -UseBasicParsing | Select-Object -ExpandProperty RawContent

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
    if ($($NewHTMLObject.GetType()).Name -eq "HTMLDocumentClass") {
        $NewHTMLObject.IHTMLDocument2_write($RawHTML)
    }
    if ($($NewHTMLObject.GetType()).Name -like "*ComObject") {
        $RawHTML = [System.Text.Encoding]::Unicode.GetBytes($RawHTML)
        $NewHTMLObject.write($RawHTML)
    }
    $NewHTMLObject.Close()
    $NewHTMLObjectBody = $NewHTMLObject.body

     ## BEGIN Get Standard Google Results ##

    $StandardResults = Get-StdResultProperties -HTMLBody $NewHTMLObjectBody -cntid "ires" -baseobj "g" -rhcl "r" -urltg "a"-urlcttg "CITE" -imgtg "IMG" -descl "st" -olcl "osl"

    ## END Get Standard Google Results ##

    <#

    ## BEGIN Image Search Result ##

    getElementsByClassName("_Icb _kk _wI")

    ## END Image Search Result ##


    ## BEGIN Get Google "Wikipedia Summary" White Card Result ##

    $WikiSummaryCardArray = foreach ($obj1 in $StandardResultsArrayPrep) {
        $($obj1).GetElementsByClassName("kp-blk")
    }

    for ($i=0; $i -lt $global:StandardResultsArray.Length; $i++) {
        $BasicWikiCardResultObject = $WikiSummaryCardArray | Select-Object -Index $i
        $WikiResultHeaderObject = $($BasicWikiCardResultObject).GetElementsByClassName("_tN")
        $WikiResultHeader = $($WikiResultHeaderObject).innerText
        if ($WikiResultHeader -eq $null) {
            continue
        }

        $WikiResultFocusHeader = $($BasicWikiCardResultObject).GetElementsByClassName("kp-header")

        $WikiResultSummary = $($BasicWikiCardResultObject).GetElementsByClassName("_G1d")

        $WikiAdditionalInfoHeader = $($BasicWikiCardResultObject).GetElementsByClassName("_W5e")

        $WikiAdditionalInfoSubHeaders = $($BasicWikiCardResultObject).GetElementsByClassName("kno-fb-ctx")

        $WikiPeopleAlsoSearchFor = $($BasicWikiCardResultObject).GetElementsByClassName("_W5e")

        $WikiPeopleAlsoSearchForEntries = $($BasicWikiCardResultObject).GetElementsByClassName("_Cdb")
    }

    # Wikipedia Summary
    getElementsByClassName("kp-blk _Z7 _Rqb _RJe").getElementsByClassName("_Tgc")
    # Wikipedia Summary Link Header and URL
    getElementsByClassName("kp-blk _Z7 _Rqb _RJe").getElementsByTagName("h3")
    getElementsByClassName("kp-blk _Z7 _Rqb _RJe").getElementsByTagName("h3").getElementsByClassName("a").href
    getElementsByClassName("kp-blk _Z7 _Rqb _RJe").getElementsByClassName("_Tgc")

    ## END Get Google "Wikipedia Summary" White Card Result ##


    ## BEGIN Get Google White Card Results (Top of Page) ##

    ## END Get Google White Card Results (Top of Page) ##


    ## BEGIN Get Google White Card Results (Bottom of Page) ##

    ## END Get Google White Card Results (Bottom of Page) ##


    ## BEGIN Get Google Weather Card Results ##

    ## END Get Google Weather Card Results ##


    ## BEGIN Get Google Top Stories Results ##

    ## END Get Google Top Stories Results ##


    ## BEGIN Get Google Movies AppBar Results ##

    ## END Get Google Movies AppBar Results ##


    ## BEGIN Get Google "In the news" Results ##

    ## END Get Google "In the news" Results ##


    ## BEGIN Get Google "People also ask" Result ##

    ## END Get Google "People also ask" Result ##


    ## BEGIN Get Google Right-Hand-Side Results ##

    ## BEGIN Get Google Right-Hand-Side Results ##

    #>

    $StandardResults | Select-Object ResultHeader,URL,Cached,Similar,Description,OtherLinks,NonStdResultInfo,DatePosted
    
    ##### END Main Body #####

}

# Archived Code
<#
#$DescriptionObjectTagName = $($DescriptionObject).tagName
#$DescriptionTextTruncated = $($DescriptionObject).textContent
# For more info on this regex, see: http://stackoverflow.com/questions/28436651/replacing-last-occurrence-of-substring-in-string
#$DescriptionPatternToSearchFor = $($DescriptionTextTruncated -replace '(.*)\.\.\.(.*)','$1$2').Trim()
#$Description = $($global:RawHTML | Select-String -Pattern "$($DescriptionPatternToSearchFor)(.*?)(?=</$DescriptionObjectTagName)").Matches.Value



# Compare Results

$Properties = $($YesJavaResults[0] | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"}).Name
foreach ($property in $Properties) {
    for ($i =0; $i -lt $Properties.Count; $i++) {
        if ($YesJavaResults[$i].$property -eq $NoJavaResults[$i].$property) {
            Write-Host "EQUAL YesJavaResults $i $property and NoJavaResults $i $property"
        }
        else {
            Write-Host "NOT EQUAL YesJavaResults $i $property and NoJavaResults $i $property"
        }
    }
}


#>











# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUv+79wUTpt02UO6HgM3S6NZDO
# kpSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFA/T2WGZcgvR3uJW
# GC/XgUBIH4cEMA0GCSqGSIb3DQEBAQUABIIBAHsBwQrbDe2h5wHEpi7HhE1K3I75
# 753Du/4s8e6Mj3bU7BV4Sl4bNcN88SRlYi0fpgBXsJCDIAPfuDP/Vde8VXOGJZeq
# spR13UVksMwcKu8y0sAKZb/NoisDYHHxjesA4kOIFF9oEImdp5uDvnKGJBZ3LoI+
# 5ovPrpTiA2pC2s04Z/JG7RF7k/hB1HBh931umv+xG+OwMiQw4Xl8/xmvJERhheax
# c8X9hX1D9CyYI1qA3t2vcBCGhcuEl348kbY0oGI47C5X3DhCH4ch7IsOJa/7nklN
# D2d/9umt29ZKmY9DL80W8uam5g9VJA2sNmx3mDEFF7nQlni74XG88/ZK9Gg=
# SIG # End signature block
