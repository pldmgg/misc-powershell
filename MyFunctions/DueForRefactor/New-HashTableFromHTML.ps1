<#

.SYNOPSIS
    This function/script generates a multi-dimensional HashTable from a single HTML table (i.e. ONE <table></table> element). 
    
    There are several caveats however:
    1) Row N x Column 1 in the HTML table must contain ONLY ONE VALUE or NO VALUE at all.
    2) Column Headers must contain ONLY ONE VALUE per column or NO VALUE at all.
    3) One-to-many relationships (i.e. one value in Row N x Column 1 and more than one value in Row N x Column 1+N) are only handled properly if Column 1+N 
    contains a MAXIMUM of 2 values. Example: https://coreos.com/os/docs/latest/booting-on-ec2.html

.DESCRIPTION
    This function/script targets a single HTML Table using the parameters provided by the user.  By single HTML Table, we mean a single instance of 
    <table></table> on a webpage.  It results in a multi-dimensional Global HashTable which you can use within the scope that called the script/function
    in the first place.

    For example, by running the following:
        New-HashTableFromHTML `
        -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
        -ParentHTMLElementTagName "div" `
        -ParentHTMLElementClassName "tab-pane" `
        -JavaScriptUsedToGenTable "No" `
        -TextUniqueToTargetTable "ami-9cf707f3"
    
    ...you will be able to easily access any values contained within the HTML table as follows:
    PS C:\Users\testadmin> $global:FinalHashTable.'us-west-1'.'AMI Type'.PV
    ami-ee65149d

.EXAMPLE
    Example #1:
    New-HashTableFromHTML `
    -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
    -ParentHTMLElementTagName "div" `
    -ParentHTMLElementClassName "tab-pane" `
    -ParentHTMLElementID "alpha" `
    -JavaScriptUsedToGenTable "No"
    
    Example #2:
    New-HashTableFromHTML `
    -TargetURL "https://aws.amazon.com/ec2/pricing" `
    -ParentHTMLElementClassName "pricing-table-wrapper" `
    -ParentHTMLElementTagName "div" `
    -JavaScriptUsedToGenTable "Yes" `
    -GrandParentHTMLElementClassName "content reg-us-west-2" `
    -TableTitle "1-Year Term" `
    -TextUniqueToTargetTable "0.004, 0.005, 25, 38, 31, 32, 34, 0.0065"
    
    Example #3:
    New-HashTableFromHTML `
    -TargetURL "http://www.ec2instances.info" `
    -ParentHTMLElementTagName "div" `
    -ParentHTMLElementClassName "dataTables_wrapper" `
    -JavaScriptUsedToGenTable "No" `
    -GrandParentHTMLElementClassName "ec2instances" `
    -TextUniqueToTargetTable "Cluster Compute Eight Extra Large"
    
    Example #4:
    New-HashTableFromHTML `
    -TargetURL "https://aws.amazon.com/ec2/pricing" `
    -ParentHTMLElementClassName "content reg-us-east-1" `
    -ParentHTMLElementTagName "div" `
    -JavaScriptUsedToGenTable "Yes" `
    -TableTitle "General Purpose - Current Generation" `
    -TextUniqueToTargetTable "Linux/UNIX Usage, t2.micro, variable, 0.0065"

    Example #5:
    New-HashTableFromHTML `
    -TargetURL "https://aws.amazon.com/ec2/instance-types" `
    -ParentHTMLElementClassName "aws-table" `
    -ParentHTMLElementTagName "div" `
    -JavaScriptUsedToGenTable "No" `
    -TextUniqueToTargetTable "Clock Speed (GHz), EBS Only"

.NOTES
    WARNING: For each row in the Target HTML Table it takes this script/function about 500ms to process the information. So a table with 100 rows
    will take approximately 50 seconds to finish processing.

.PARAMETERS
    1) $TargetURL - [REQUIRED} The URL that contains the table you would like to convert into a multi-dimensional HashTable

    2) $ParentHTMLElementTagName - [REQUIRED] The HTML Element Tag in the HTML Element that is the immediate *parent* of the <table> element. 
    This value is a generic HTML tag and is NEVER unique to the webpage you are targeting.
    Examples: div, body
    If you are unsure, use 'div'

    3) $ParentHTMLElementClassName - [REQUIRED] The HTML Element ClassName in the HTML Element that is the immediate *parent* of the <table> element. 
    This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks similar to: 
    <div class=$ParentHTMLElementClassName ...

    4) $JavaScriptUsedToGenTable - [REQUIRED] On many websites, JavaScript is used to dynamically generate HTML Tables.  If that is the case with the 
    website you are targeting, then set this parameter to "Yes"

    5) $TextUniqueToTargetTable - [OPTIONAL] In order to help narrow down the HTML Table Target to ONE instance of <table></table>, a comma separated
    list of table cell values unique to the table you are targeting is very helpful. Each cell value should be separated by a comma.

    6) $ParentHTMLElementID - [OPTIONAL] Sometimes, in order to narrow down the HTML Table Target to ONE instance of <table></table>, the 
    it is helpful to specify the HTML Element ID in the HTML Element that is the immediate *parent* of the <table> element. 
    This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks similar to: 
    <div id=$ParentHTMLElementID ...

    7) $GrandParentHTMLElementClassName - [OPTIONAL] Sometimes, in order to narrow down the HTML Table Target to ONE instance of <table></table>,
    it is helpful to indicate the class of the HTML element that is the *grandparent* of <table></table>)
    This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks similar to: 
    <div class=$GrandParentHTMLElementClassName ...

    8) $GrandParentHTMLElementID - [OPTIONAL] Sometimes, in order to narrow down the HTML Table Target to ONE instance of <table></table>,
    it is helpful to indicate the ID of the HTML element that is the *grandparent* of <table></table>)
    This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks similar to: 
    <div id=$GrandParentHTMLElementID ...

    9) $TableTitle - [OPTIONAL] WARNING: Only use this parameter if the targeted table's title is located within HTML as follows: 
    <table><thead><TR><TH>$TableTitle</TH></TR></thead></table>
    Sometimes, in order to narrow down the HTML Table Target to ONE instance of <table></table>, it is helpful to indicate the table's title.
    IMPORTANT NOTE: This parameter has the added feature of changing the Output variable from $global:FinalHashTable to $global:HashTableTitle$TableTitle

.OUTPUTS
    This script/function outputs a multi-dimensional HashTable called $global:FinalHashTable, or, if the $TableTitle parameter is used,
    $global:HashTableTitle$TableTitle.

    For example, by running the following:
        New-HashTableFromHTML `
        -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
        -OuterHTMLElementTagName "div" `
        -OuterHTMLElementClassName "tab-pane" `
        -JavaScriptUsedToGenTable "No" `
        -TextUniqueToTargetTable "ami-9cf707f3"
    
    ...you will be able to easily access any values contained within the HTML table as follows:
    PS C:\Users\testadmin> $global:FinalHashTable.'us-west-1'.'AMI Type'.PV
    ami-ee65149d

#>

function New-HashTableFromHTML {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $TargetURL = $(Read-Host -Prompt "Please enter a URL containing an HTML table that you would like to target"),

        [Parameter(Mandatory=$False)]
        $JavaScriptUsedToGenTable = $(Read-Host -Prompt "If JavaScript is used to dynamically generate the table you are targeting, please enter 'Yes'. [Yes/No]"),

        [Parameter(Mandatory=$False)]
        $ParentHTMLElementTagName = $(Read-Host -Prompt "Please enter the HTML Element Tag that is the parent of the <table> element. 
        This value is a generic HTML element and is NEVER unique to the webpage you are targeting. If you are unsure, type 'div'"),

        [Parameter(Mandatory=$False)]
        $ParentHTMLElementClassName = $(Read-Host -Prompt "Please enter the HTML Element ClassName in the HTML Element that is the immediate parent of the <table> element. 
        This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks like: 
        <$ParentHTMLElementTagName class=[HTML Element ClassName]..."),

        [Parameter(Mandatory=$False)]
        $ParentHTMLElementID,

        [Parameter(Mandatory=$False)]
        $GrandParentHTMLElementClassName,

        [Parameter(Mandatory=$False)]
        $GrandParentHTMLElementID,

        # IMPORTANT NOTE: Only use the $TableTitle parameter if the targeted table's title is located within HTML as follows: 
        # <table><thead><TR><TH>$TableTitle</TH></TR></thead></table>
        [Parameter(Mandatory=$False)]
        $TableTitle,

        [Parameter(Mandatory=$False)]
        [array]$TextUniqueToTargetTable
    )

    ##### BEGIN Parameter Transforms #####
    
    if ($TextUniqueToTargetTable -ne $null) {
        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
    }

    ##### END Parameter Transforms #####

    ##### BEGIN Gather All HTML from WebPage #####

    # If the website uses Javascript to dynamically create the target table, we need to wait for the page to completely finish loading so that we can grab
    # the HTML that is written as a result of JavaScript. The .Net logic waiting for the page to load as presented here 
    # http://pastebin.com/8hPa15ut     via     https://www.reddit.com/r/PowerShell/comments/3z7bxr/help_with_invokewebrequest/cyk5n0t
    # *should* work, but doesn't work *consistently*. The below has proven to be much more consistent, although there is a pretty long wait time of 10 seconds (completely arbitrary)
    # to really ensure the page is finished loading.  Lower wait times may work just fine - it really just depends on the webpage and your internet connection.
    if ($JavaScriptUsedToGenTable -eq "Yes" -or $JavaScriptUsedToGenTable -eq "y") {
        $ie = New-Object -com InternetExplorer.Application
        $ie.visible=$false
        $ie.navigate("$TargetURL")
        Start-Sleep -Seconds 10
        while($ie.ReadyState -ne 4) {start-sleep -m 1000}
        $RawHTML = $ie.Document.body.outerHTML
    }
    if ($JavaScriptUsedToGenTable -eq "No" -or $JavaScriptUsedToGenTable -eq "n") { 
        $RawHTML = Invoke-WebRequest -Uri "$TargetURL" -UseBasicParsing | Select-Object -ExpandProperty RawContent
    }
    Write-Host "Writing total number of lines of HTML on page..."
    $RawHTML.Split("`r`n").Count

    $NewHTMLObject = New-Object -com "HTMLFILE"
    # If there is ANY JavaScript on the webpage, must change "deisgnMode" to "on". Might as well leave this as default setting as it does not impact pages w/o JavaScript.
    # The designMode property must be set BEFORE IHTMLDocument2_write method is used.
    $NewHTMLObject.designMode = "on"
    $NewHTMLObject.IHTMLDocument2_write($RawHTML)
    $NewHTMLObject.Close()
    $NewHTMLObjectBody = $NewHTMLObject.body

    ##### END Gather All HTML from WebPage #####

    ##### BEGIN Logic To Target A Specific Table #####
    # Ends around line 760 #

    $TablesOnPageCount = ([array]$($NewHTMLObjectBody.getElementsByTagName("table"))).Count
    Write-Host ""
    Write-Host "Writing TablesOnPageCount..."
    $TablesOnPageCount
    Write-Host ""
    
    # NOTE: In the below code, if there is 1 object in $TablesOnPage, then the 'Count' method returns $null. 0 objects returns 0, and anything greater than 1 returns the expected Count. 
    # This is because PowerShell leaves $TablesOnPage as a  __ComObject of BaseType System.MarshalByRefObject instead of Object[] of BaseType System.Array when there is only 1 object.
    
    # If there is more than one table on the webpage, figure out which table to actually target.
    if ($TablesOnPageCount -gt 1) {
        # If $TextUniqueToTargetTable -eq $null, try to narrow down the target table using other parameters provided 
        if ($TextUniqueToTargetTable -eq $null) {
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"}).children | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"}).children | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" `
                -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" `
                -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }

            Write-Host "Writing TableTarget.Count without searching for TextUniqueToTable"
            $TableTarget.Count
            
            # If more than one instance of <table></table> is returned using the provided parameters, force user to specify TextUniqueToTargetTable
            if ($TableTargetCount -gt 1) {
                Write-Host "More than one HTML table was found on $TargetURL using the provided parameters."
                [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
            }
        }
        # If $TextUniqueToTargetTable has been provided, use it to narrow down target table after processing all other parameters
        if ($TextUniqueToTargetTable -ne $null) {
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"}).children | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"}).children | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -eq $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" `
                -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -eq $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }
            if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null -and $GrandParentHTMLElementID -ne $null -and $ParentHTMLElementID -ne $null) {
                $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") `
                | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName" `
                -and $_.id -match "$ParentHTMLElementID"} | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName" `
                -and $_.parentElement.id -match "$GrandParentHTMLElementID"}).children `
                | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
            }

            Write-Host "Writing TableTarget.Count prior to searching Unique Text"
            $TableTargetCount = $TableTarget.Count
            Write-Output $TableTargetCount

            $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
            For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                $TableTarget = ([array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"}))
            }

            Write-Host "Writing `$TableTarget.Count (should be 1)"
            $TableTargetCount = $TableTarget.Count
            Write-Output $TableTargetCount
            
            # If $TextUniqueToTargetTable isn't specific enough to filter out all but one table, ask the user to provide different/additional $TextUniqueTotargetTable
            if ($TableTargetCount -gt 1) {
                if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table."
                    [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                    [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                    $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                    For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                        $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                    }
                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table.
                        Try using the -ParentHTMLELementClassName and/or the -TableTitle parameters to assist with targeting a table.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') 
                    and the ParentHTMLElementClassName $GrandParentHTMLElementClassName."
                    Write-Host "Please either adjust TextUniqueTotargetTable and/or ParentHTMLElementClassName in order to better target one specific table"
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, or (3) Both? [1/2/3]"

                    if ($AdjustmentSwitch -ne 1 -or $AdjustmentSwitch -ne 2 -or $AdjustmentSwitch -ne 3) {
                        Write-Host "Please enter either 1, 2, or 3"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, or (3) Both? [1/2/3]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))
                        
                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') 
                    and the TableTitle $TableTitle."
                    Write-Host "Please either adjust TextUniqueTotargetTable and/or TableTitle in order to better target one specific table"
                    Write-Host "IMPORTANT: The TableTitle value MUST be found within a <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct.
                    If it is not, do not use the TableTitle parameter."
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) TableTitle, or (3) Both? [1/2/3]"

                    if ($AdjustmentSwitch -ne 1 -or $AdjustmentSwitch -ne 2 -or $AdjustmentSwitch -ne 3) {
                        Write-Host "Please enter either 1, 2, or 3"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) TableTitle, or (3) Both? [1/2/3]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the combination of the parameters TextUniqueToTargetTable 
                    (i.e. '$TextUniqueToTargetTable'), ParentHTMLElementClassName (i.e. $GrandParentHTMLElementClassName), and TableTitle (i.e. $TableTitle)."
                    Write-Host "Please adjust TextUniqueTotargetTable and/or ParentHTMLElementClassName, and/or TableTitle in order to better target one specific table."
                    Write-Host "IMPORTANT: The TableTitle value MUST be found within a <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct.
                    If it is not, do not use the TableTitle parameter."
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, 
                    (3) TableTitle, (4) 1 and 2, (5) 1 and 3, (6) 2 and 3, or (7) 1,2, and 3? [1/2/3/4/5/6/7]"

                    if ($AdjustmentSwitch -notmatch "[0-7]") {
                        Write-Host "Please enter either 1, 2, 3, 4, 5, 6, or 7"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, 
                        (3) TableTitle, (4) 1 and 2, (5) 1 and 3, (6) 2 and 3, or (7) 1,2, and 3? [1/2/3/4/5/6/7]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 4) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 5) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 6) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 7) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # If the $TextUniqueToTargetTable returns 0 tables, ask the user to provide different/additional $TextUniqueTotargetTable
            if ($TableTargetCount -lt 1) {
                if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -eq $null) {
                    Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found."
                    [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                    [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                    $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                    For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                        $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table.
                        Try using the -ParentHTMLELementClassName and/or the -TableTitle parameters to assist with targeting a table.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -eq $null) {
                    Write-Host "No table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') 
                    and the ParentHTMLElementClassName $GrandParentHTMLElementClassName."
                    Write-Host "Please either adjust TextUniqueTotargetTable and/or ParentHTMLElementClassName in order to better target one specific table"
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, or (3) Both? [1/2/3]"

                    if ($AdjustmentSwitch -ne 1 -or $AdjustmentSwitch -ne 2 -or $AdjustmentSwitch -ne 3) {
                        Write-Host "Please enter either 1, 2, or 3"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, or (3) Both? [1/2/3]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))
                        
                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -eq $null -and $TableTitle -ne $null) {
                    Write-Host "No table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') 
                    and the TableTitle $TableTitle."
                    Write-Host "Please either adjust TextUniqueTotargetTable and/or TableTitle in order to better target one specific table"
                    Write-Host "IMPORTANT: The TableTitle value MUST be found within a <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct.
                    If it is not, do not use the TableTitle parameter."
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) TableTitle, or (3) Both? [1/2/3]"

                    if ($AdjustmentSwitch -ne 1 -or $AdjustmentSwitch -ne 2 -or $AdjustmentSwitch -ne 3) {
                        Write-Host "Please enter either 1, 2, or 3"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) TableTitle, or (3) Both? [1/2/3]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))
                        
                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($GrandParentHTMLElementClassName -ne $null -and $TableTitle -ne $null) {
                    Write-Host "No table was found on $TargetURL based on the combination of the parameters TextUniqueToTargetTable 
                    (i.e. '$TextUniqueToTargetTable'), ParentHTMLElementClassName (i.e. $GrandParentHTMLElementClassName), and TableTitle (i.e. $TableTitle)."
                    Write-Host "Please adjust TextUniqueTotargetTable and/or ParentHTMLElementClassName, and/or TableTitle in order to better target one specific table."
                    Write-Host "IMPORTANT: The TableTitle value MUST be found within a <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct.
                    If it is not, do not use the TableTitle parameter."
                    [int]$AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, 
                    (3) TableTitle, (4) 1 and 2, (5) 1 and 3, (6) 2 and 3, or (7) 1,2, and 3? [1/2/3/4/5/6/7]"

                    if ($AdjustmentSwitch -notmatch "[0-7]") {
                        Write-Host "Please enter either 1, 2, 3, 4, 5, 6, or 7"
                        $AdjustmentSwitch = Read-Host -Prompt "Would you like to adjust (1) TextUniqueToTargetTable, (2) ParentHTMLElementClassName, 
                        (3) TableTitle, (4) 1 and 2, (5) 1 and 3, (6) 2 and 3, or (7) 1,2, and 3? [1/2/3/4/5/6/7]"
                    }
                    if ($AdjustmentSwitch -eq 1) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 2) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 3) {
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 4) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        
                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 5) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()

                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 6) {
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }
                    if ($AdjustmentSwitch -eq 7) {
                        [array]$TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                        [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                        $GrandParentHTMLElementClassName = Read-Host -Prompt "Please enter the class of the HTML element that is the grandparent of the <table> element.
                        For example, in the HTML <div class=content>, the word 'content' would be Parent HTML Element ClassName."
                        $TableTitle = Read-Host -Prompt "Please enter the Table's Title found within the <table><thead><TR><TH>TableTitle</thead></TR></TH></table> HTML construct"

                        $TableTarget = ([array]$($($NewHTMLObjectBody.getElementsByTagName("$ParentHTMLElementTagName") | Where-Object {$_.ClassName -match "$ParentHTMLElementClassName"} `
                        | Where-Object {$_.parentElement.ClassName -match "$GrandParentHTMLElementClassName"}).children `
                        | Where-Object {$_.tagName -eq "TABLE"} | Where-Object {$_.innerText -like "*$TableTitle*"}))

                        $TextUniqueToTargetTableCount = $TextUniqueToTargetTable.Count
                        For ($loop=0; $loop -lt $TextUniqueToTargetTableCount; $loop++) {
                            $TableTarget = [array]$($TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"})
                        }
                    }

                    Write-Host "Writing `$TableTarget.Count (should be 1)"
                    $TableTargetCount = $TableTarget.Count
                    Write-Output $TableTargetCount
                    
                    # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                    if ($TableTargetCount -gt 1) {
                        Write-Host "More than one HTML table was found.  Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                    # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                    if ($TableTargetCount -lt 1) {
                        Write-Host "No table containing matching all parameters was found. Halting!"
                        if ($ie -ne $null) {
                            $ie.Quit()
                        }
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($TableTargetCount -eq 1) {
                Write-Host "The specified TargetTable has been found. Continuing..."
            }
        }

    }
    # If there is only one table on the webpage, just define $TableTarget...
    if ($TablesOnPageCount -eq 1) {
        $TableTarget = [array]$($NewHTMLObjectBody.getElementsByTagName("table") | Where-Object {$_.tagName -eq "table"})
    }
    # If there aren't any tables on the webpage, ask user to check URL and/or check HTML for <table> element tag...
    if ($TablesOnPageCount -lt 1) {
        Write-Host "No tables were found on $TargetURL. Please check the URL and/or ensure that the HTML on the webpage contains the <table> element. Halting!"
        if ($ie -ne $null) {
            $ie.Quit()
        }
        $global:FunctionResult = "1"
        return
    }

    # The result of $TableTarget.getElementsByTagName("TR") is a __ComObject of BaseType System.MarshalByRefObject but we want an array of __ComObjects
    $ArrayofRowsHTMLObjects = $([array]$($TableTarget.getElementsByTagName("TR")))
    $ArrayofRowsHTMLObjectsCount = $ArrayofRowsHTMLObjects.Count

    ##### END Logic To Target A Specific Table #####


    ##### BEGIN Logic to Define $ArrayofArraysColumnValues #####
    # Notes:
    # $ArrayofArraysColumnValues[0] where ([array]$($ArrayofArraysColumnValues[0].GetElementsByTagName("TH")).Count -ge $MaxColumns represents Column Headers, 
    # $ArrayofArraysColumnValues[N] (where N -ne 0 and ([array]$($ArrayofArraysColumnValues[0].GetElementsByTagName("TD")).Count -ge $MaxColumns) 
    # represents each row in the table, and 
    # $ArrayofArraysColumnValues[N][0] represents the first column value in each row (may or may not have a column header)

    # Begin Defining $MaxColumns #

    # Estimate the maximum number of column values in any given row by picking a row in the middle of the table. This defines $MaxColumns (which is an Int32). 
    # This is helpful if:
    # 1) There are headers and subheaders within the table.
    # 2) There are HTML class=rowspan elements used for one-to-many associations. See https://coreos.com/os/docs/latest/booting-on-ec2.html for an example.
    $MiddleRowNumber = $($ArrayofRowsHTMLObjects.Count/2)
    # If it's not a whole number, round down to make it one
    if ($($MiddleRowNumber % 2) -ne 1 -and $($MiddleRowNumber % 2) -ne 0) {
        # Number is NOT whole, so round down
        $MiddleRowNumber = [Math]::Floor([decimal]$MiddleRowNumber)
    }

    # Check if $MiddleRowNumber contains TH or TD elements (should almost always be TD elements)
    $MaxColumnsTestTH = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH"))).Count
    $MaxColumnsTestTD = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD"))).Count
    # Check if $MIddleRowNumber+1 contains TF or TD elements
    $MaxColumnsTestTHPlus1 = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH"))).Count
    $MaxColumnsTestTDPlus1 = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD"))).Count

    # Look at the number of TH or TD elements in $MiddleRowNumber and the row after $MiddleRowNumber and define $MaxColumns as the one with the highest element count
    if ($MaxColumnsTestTH -gt 0) {
        if ($MaxColumnsTestTHPlus1 -gt 0) {
            if ($MaxColumnsTestTH -gt $MaxColumnsTestTHPlus1) {
                $MaxColumns = $MaxColumnsTestTH
            }
            if ($MaxColumnsTestTHPlus1 -gt $MaxColumnsTestTH) {
                $MaxColumns = $MaxColumnsTestTHPlus1
            }
            if ($MaxColumnsTestTH -eq $MaxColumnsTestTHPlus1) {
                $MaxColumns = $MaxColumnsTestTH
            }
        }
    }
    if ($MaxColumnsTestTD -gt 0) {
        if ($MaxColumnsTestTDPlus1 -gt 0) {
            if ($MaxColumnsTestTD -gt $MaxColumnsTestTDPlus1) {
                $MaxColumns = $MaxColumnsTestTD
            }
            if ($MaxColumnsTestTDPlus1 -gt $MaxColumnsTestTD) {
                $MaxColumns = $MaxColumnsTestTDPlus1
            }
            if ($MaxColumnsTestTD -eq $MaxColumnsTestTDPlus1) {
                $MaxColumns = $MaxColumnsTestTD
            }
        }
    }

    Write-Host "Writing maxColumns..."
    Write-Output $MaxColumns

    # End Defining $MaxColumns #

    # Begin Working through $ArrayofArrayColumnValuesPrep Iterations #

    $ArrayofArraysColumnValuesPrep = @()
    [System.Collections.ArrayList]$ArrayofArraysColumnValuesPrep2 = $ArrayofArraysColumnValuesPrep
    
    # For each TR HTML Object...
    For ($loop=0; $loop -lt $ArrayofRowsHTMLObjectsCount; $loop++) {
        Write-Host "Starting loop $loop"
        # If the parent HTML element's tagName is thead, then we know we will be dealing with TH elements.
        if ( $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).parentElement.tagName) -eq "THEAD") {
            Write-Host "Starting THEAD statement"
            $THElementsCount = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH"))).Count
            $THElementsWithTextCount = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Where-Object {$_.innerText -ne $null})).Count
            $THElementsWithTextThatUseColspanColspanCount = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Where-Object {$_.innerText -ne $null})).colspan
            # If the $TableTitle parameter isn't provided, try to figure out if the table has a title. If it does, make the
            # final hashtable's variable name the table title.
            if ($TableTitle -eq $null) {
                # These TH elements may or may not be the actual column headers of the table. They could represent something like the title of the table.
                # If the number of TH elements in the TR element is less than $MaxColumns, and if the number of TH elements that contain innerText is 1
                # (which returns $null with the Length method for __ComObject of BaseType System.MarshalByRefObject), and
                # if the colSpan property on that one TH element is -ge $MaxColumns-2 (doesn't necessarily have to span ALL columns), 
                # then it is most likely the table's title. In wich case, create an empty HashTable Variable with a name reflecting the table's title.
                # Else, assume the table doesn't have a title and create a generic HashTable named FinalHashTable that will contain all of the table values.
                # IMPORTANT NOTE: When attempting to get an object count, code defensively to ensure PowerShell typecasting doesn't
                if ( $THElementsCount -lt $MaxColumns -and $THElementsWithTextCount -eq 1) {
                    Write-Host "Triggering secodnary HashTableTitle if statement"
                    if ( $THElementsWithTextThatUseColspanColspanCount -ge $($MaxColumns-2)) {
                        $THElementInnerText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Where-Object {$_.innerText -ne $null}).innerText
                        # Make Final HashTable Variable out of this Table's Title
                        Write-Host "Triggering creation of HashTableTitle variable..."
                        New-Variable -Name "HashTableTitle$THElementInnerText" -Scope Global -Value @{}
                        #New-Variable -Name "HashTableTitle$loop" -Scope Global -Value @{}
                    }
                }
                else {
                    if ($(Get-Variable -Name "FinalHashTable" -ValueOnly -ErrorAction SilentlyContinue) -eq $null) {
                        # Make Final HashTable Variable name generic, i.e. FinalHashTable
                        Write-Host "Triggering creation of FinalHashTable variable..."
                        New-Variable -Name "FinalHashTable" -Scope Global -Value @{}
                    }
                }
            }
            # If the $TableTitle parameter IS provided, name the final hashtable after the table's title
            if ($TableTitle -ne $null) {
                if ($(Get-Variable -Name "HashTableTitle$TableTitle" -ValueOnly -ErrorAction SilentlyContinue) -eq $null) {
                    New-Variable -Name "HashTableTitle$TableTitle" -Scope Global -Value @{}
                }
            }
            # At this point, the Table's Title (if present) has been processed. Now we need to process the Column Headers
            # If the number of TH elements in the TR element are -ge $MaxColumns, then treat them as Column Headers
            if ( $THElementsCount -ge $MaxColumns) {
                Write-Host "Triggering zeroth if statement"
                New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                    For ($loop2=0; $loop2 -lt $THElementsCount; $loop2++) {
                        $THElementWithTextThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Where-Object {$_.innerText -ne $null} | Select-Object -Index $loop2).rowspan
                        $THElementThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Select-Object -Index $loop2).rowspan
                        $THElementText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH") | Select-Object -Index $loop2).innerText
                        # In cases where rowspan is used in the 1st Column (i.e. $loop2 = 0), precede the value with @ to make parsing later easier.
                        if ( $THElementWithTextThatUsesRowspanRowspanCount -gt 1) {
                            if ($loop2 -eq 0) {
                                "@"+$THElementText.Trim()+";"
                                $rowspan = "Yes"
                            }
                        }
                        # In cases where rowspan is used in any other column (i.e. $loop2 -gt 0), treat it like normal
                        if ( $THElementThatUsesRowspanRowspanCount -gt 1) {
                            if ($loop2 -gt 0) {
                                $THElementText.Trim()+";"
                            }
                        }
                        # In cases where rowspan is NOT used in the 1st Column, precede the value of Index 0 with @ to make parsing later easier.
                        if ( $THElementThatUsesRowspanRowspanCount -le 1 -and $THElementText -ne $null) {
                            if ($loop2 -eq 0) {
                                "@"+$THElementText.Trim()+";"
                            }
                        }
                        # In cases where rowspan is NOT used and we are NOT processing the 1st Column (i.e. $loop2 -gt 0), process normally
                        if ( $THElementThatUsesRowspanRowspanCount -le 1 -and $THElementText -ne $null) {
                            if ($loop2 -gt 0) {
                                $THElementText.Trim()+";"
                            }
                        }
                        # In cases where there is no value in the TH element, fill it in with the word "null"
                        if ( $THElementThatUsesRowspanRowspanCount -le 1 -and $THElementText -eq $null) {
                            "null;"
                        }
                    }
                )
            }
        }
        # If the parent HTML element's tagName is TBODY, then we know we will be dealing with TD elements.
        if ( $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).parentElement.tagName) -eq "TBODY") {
            $RowspanPresentInRow = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).children | Where-Object {$_.rowSpan -gt 1})
            # If the TR element contains a TD element that contains the property rowspan where rowspan -gt 1
            if ( $RowspanPresentInRow -ne $null) {
                # If the Subsequent Row has ONE LESS TD Element than the current Row, assume add the Subsequent Row contains values that should be 
                # added to current Row under current Row's Column 1 (i.e. Index 0) value
                if ($($loop+1) -lt $ArrayofRowsHTMLObjectsCount) {
                    $SubsequentRowTDElementCount = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD"))).Count
                }
                $CurrentRowTDElementCount = $([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD"))).Count
                if ( $SubsequentRowTDElementCount -eq $($CurrentRowTDElementCount-1)) {
                    Write-Host "Triggering first if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -le $CurrentRowTDElementCount; $loop2++) {
                            $TDElementWithTextThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Where-Object {$_.innerText -ne $null} | Select-Object -Index $loop2).rowspan
                            $TDElementThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).rowspan
                            $TDElementText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).innerText
                            # In cases where rowspan is used in the 1st Column (i.e. $loop2 = 0), precede the value with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                    $rowspan = "Yes"
                                }
                            }
                            # In cases where rowspan is used in any other column (i.e. $loop2 -gt 0), treat it like normal
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used in the 1st Column, precede the value of Index 0 with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used and we are NOT processing the 1st Column (i.e. $loop2 -gt 0), process normally
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -eq $null) {
                                "null;"
                            }
                        }
                        For ($loop3=0; $loop3 -le $SubsequentRowTDElementCount; $loop3++) {
                            $TDElementSubsequentRowText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD") | Select-Object -Index $loop3).innerText
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ( $TDElementSubsequentRowText -eq $null) {
                                "null;"
                            }
                            if ( $TDElementSubsequentRowText -ne $null) {
                                $TDElementSubsequentRowText.Trim()+";"
                            }
                        }
                    )
                }
                # If the Subsequent Row does NOT have ONE LESS TD Element than the current Row, just process current row normally
                if ( $SubsequentRowTDElementCount -ne $($CurrentRowTDElementCount-1)) {
                    Write-Host "Triggering second if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -lt $CurrentRowTDElementCount; $loop2++) {
                            $TDElementWithTextThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Where-Object {$_.innerText -ne $null} | Select-Object -Index $loop2).rowspan
                            $TDElementThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).rowspan
                            $TDElementText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).innerText
                            # In cases where rowspan is used in the 1st Column (i.e. $loop2 = 0), precede the value with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                    $rowspan = "Yes"
                                }
                            }
                            # In cases where rowspan is used in any other column (i.e. $loop2 -gt 0), treat it like normal
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used in the 1st Column, precede the value of Index 0 with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used and we are NOT processing the 1st Column (i.e. $loop2 -gt 0), process normally
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -eq $null) {
                                "null;"
                            }
                        }
                    )
                }
            }
            # If "rowspan=2" is NOT present...
            if ( $RowspanPresentInRow -eq $null) {
                # ...And if the current row has the same number of columns (i.e. TD elements) as the Maximum number of columns in the table (i.e. $MaxColumns), then just process the current Row Object
                if ($($loop+1) -lt $ArrayofRowsHTMLObjectsCount) {
                    $SubsequentRowTDElementCount = ([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD"))).Count
                }
                $CurrentRowTDElementCount = $([array]$($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD"))).Count
                if ( $CurrentRowTDElementCount -eq $MaxColumns) {
                    Write-Host "Triggering third if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -lt $CurrentRowTDElementCount; $loop2++) {
                            $TDElementWithTextThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Where-Object {$_.innerText -ne $null} | Select-Object -Index $loop2).rowspan
                            $TDElementThatUsesRowspanRowspanCount = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).rowspan
                            $TDElementText = $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD") | Select-Object -Index $loop2).innerText
                            # In cases where rowspan is used in the 1st Column (i.e. $loop2 = 0), precede the value with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                    $rowspan = "Yes"
                                }
                            }
                            # In cases where rowspan is used in any other column (i.e. $loop2 -gt 0), treat it like normal
                            if ( $TDElementThatUsesRowspanRowspanCount -gt 1) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used in the 1st Column, precede the value of Index 0 with @ to make parsing later easier.
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$TDElementText.Trim()+";"
                                }
                            }
                            # In cases where rowspan is NOT used and we are NOT processing the 1st Column (i.e. $loop2 -gt 0), process normally
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -ne $null) {
                                if ($loop2 -gt 0) {
                                    $TDElementText.Trim()+";"
                                }
                            }
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ( $TDElementThatUsesRowspanRowspanCount -le 1 -and $TDElementText -eq $null) {
                                "null;"
                            }
                        }
                    )
                }
            }
        }
        if ($(Get-Variable -Name "ArrayofColumnValuesforRow$loop" -ErrorAction SilentlyContinue) -ne $null) {
            Write-Host ""
            $(Get-Variable -Name "ArrayofColumnValuesforRow$loop" -ValueOnly)
            Write-Host ""

            if ($(Get-Variable -Name "ArrayofColumnValuesforRow$loop" -ValueOnly) -eq $null) {
                $ArrayofArraysColumnValuesPrep2.Add("null") > $null
            }
            if ($(Get-Variable -Name "ArrayofColumnValuesforRow$loop" -ValueOnly) -ne $null) {
                $ArrayofArraysColumnValuesPrep2.Add("$(Get-Variable -Name "ArrayofColumnValuesforRow$loop" -ValueOnly)") > $null
            }
        }
    }

    # Finalize $ArrayofArraysColumnValues...
    $ArrayofArraysColumnValuesPrep3 = foreach ($obj1 in $ArrayofArraysColumnValuesPrep2) {
        if ($obj1 -ne "null") {
            $obj1.TrimEnd(";")
        }
    }
    $ArrayofArraysColumnValuesPrep4 = $($ArrayofArraysColumnValuesPrep3 | Out-String).Split("@")
    $ArrayofArraysColumnValuesPrep5 = @()
    foreach ($obj1 in $ArrayofArraysColumnValuesPrep4) {
        [array]$obj2 = $obj1.Split(";").Trim()
        # Adding arrays to an an array requires the below syntax.
        # Details: http://stackoverflow.com/questions/6157179/append-an-array-to-an-array-of-arrays-in-powershell
        if ($obj1 -ne $null) {
            $ArrayofArraysColumnValuesPrep5 += , $obj2
        }
    }
    $ArrayofArraysColumnValues = $ArrayofArraysColumnValuesPrep5 | Where-Object {$_ -ne $null}
    $ArrayofArraysColumnValuesCount = $ArrayofArraysColumnValues.Count

    # End Working through $ArrayofArrayColumnValuesPrep Iterations #

    ##### END Logic to Define $ArrayofArraysColumnValue #####

    ###### BEGIN Make Final HashTable #####

    # It is possible that the HTML did NOT use THEAD or TH elements, in which case the creation of the $global:FinalHashTable
    # was not triggered. To make sure it has been created, trigger the below if it doesn't exist at this point.
    if ($(Get-Variable -Name "FinalHashTable" -ValueOnly -ErrorAction SilentlyContinue) -eq $null) {
        # Make Final HashTable Variable name generic, i.e. FinalHashTable
        Write-Host "Triggering creation of FinalHashTable variable..."
        New-Variable -Name "FinalHashTable" -Scope Global -Value @{}
    }

    # If the $rowspan variable is set to "Yes", this means that the 1st Column uses rowspan...
    if ($rowspan -eq "Yes") {
        # Make Interim Hashtable for the rowspan split on the 1st Column 
        # For now, hashtable keys are just hardcoded with the Index number (i.e. $ArrayofArraysColumnValues[$loop][1], etc
        # Because I know in advance that those array elements contain the values for AMIType and AMIID Columns
        $AMITypeHashTable = @{}
        For ($loop=1; $loop -lt $ArrayofArraysColumnValuesCount; $loop++) {
            New-Variable -Name "temphashtableB$loop" -Value @{}
            $interimkeyA = $ArrayofArraysColumnValues[$loop][1]
            $interimvalueA = $ArrayofArraysColumnValues[$loop][2]
            $interimkeyB = $ArrayofArraysColumnValues[$loop][5]
            $interimvalueB = $ArrayofArraysColumnValues[$loop][6]
            $(Get-Variable -Name "temphashtableB$loop" -ValueOnly).Add($interimkeyA,$interimvalueA)
            $(Get-Variable -Name "temphashtableB$loop" -ValueOnly).Add($interimkeyB,$interimvalueB)
        
            $keyB = $ArrayofArraysColumnValues[$loop][0]
            [hashtable]$valueB = $(Get-Variable -Name "temphashtableB$loop" -ValueOnly)
            $AMITypeHashTable.Add($keyB,$valueB)
        }
        
        $AMIIDHashTable = @{}
        For ($loop=1; $loop -lt $ArrayofArraysColumnValuesCount; $loop++) {
            New-Variable -Name "temphashtableC$loop" -Value @{}
            $interimkeyC = $ArrayofArraysColumnValues[$loop][2]
            $interimvalueC = $ArrayofArraysColumnValues[$loop][1]
            $interimkeyD = $ArrayofArraysColumnValues[$loop][6]
            $interimvalueD = $ArrayofArraysColumnValues[$loop][5]
            $(Get-Variable -Name "temphashtableC$loop" -ValueOnly).Add($interimkeyC,$interimvalueC)
            $(Get-Variable -Name "temphashtableC$loop" -ValueOnly).Add($interimkeyD,$interimvalueD)
        
            $keyC = $ArrayofArraysColumnValues[$loop][0]
            [hashtable]$valueC = $(Get-Variable -Name "temphashtableC$loop" -ValueOnly)
            $AMIIDHashTable.Add($keyC,$valueC)
        }

        For ($loop=1; $loop -lt $ArrayofArraysColumnValuesCount; $loop++) {
            New-Variable -Name "temphashtableA$loop" -Value @{}
            For ($loop2=0; $loop2 -lt $ArrayofArraysColumnValues[0].Count; $loop2++) {
                $tempkeyA = $ArrayofArraysColumnValues[0][0]
                $tempvalueA = $ArrayofArraysColumnValues[$loop][0]
                $tempkeyB = $ArrayofArraysColumnValues[0][1]
                $tempvalueB = $($AMITypeHashtable.$($ArrayofArraysColumnValues[$loop][0]))
                $tempkeyC = $ArrayofArraysColumnValues[0][2]
                $tempvalueC = $($AMIIDHashTable.$($ArrayofArraysColumnValues[$loop][0]))
            }

            $(Get-Variable -Name "temphashtableA$loop" -ValueOnly).Add($tempkeyA,$tempvalueA)
            $(Get-Variable -Name "temphashtableA$loop" -ValueOnly).Add($tempkeyB,$tempvalueB)
            $(Get-Variable -Name "temphashtableA$loop" -ValueOnly).Add($tempkeyC,$tempvalueC)

            $keyA = $ArrayofArraysColumnValues[$loop][0]
            [hashtable]$valueA = $(Get-Variable -Name "temphashtableA$loop" -ValueOnly)

            # If the generic FinalHashTable was created because there was no Table Title, add key/value pairs to FinalhashTable
            if ($(Get-Variable -Name "FinalHashTable" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
                $global:FinalHashTable.Add($keyA,$valueA)
            }
            # If the HashTable based on the Table's Title was created, add key/value pairs to it
            if ($(Get-Variable -Name "HashTableTitle$TableTitle" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
                $(Get-Variable -Name "HashTableTitle$TableTitle" -Scope Global -ValueOnly).Add($keyA,$valueA)
            }
        }
    }
    # If the $rowspan variable is NOT set to "Yes", this means that the 1st Column DOES NOT use rowspan...
    if ($rowspan -ne "Yes") {
        For ($loop=1; $loop -lt $ArrayofArraysColumnValuesCount; $loop++) {
            New-Variable -Name "temphashtableA$loop" -Value @{}
            For ($loop2=0; $loop2 -lt $ArrayofArraysColumnValues[0].Count; $loop2++) {
                $tempkeyA = $ArrayofArraysColumnValues[0][$loop2]
                $tempvalueA = $ArrayofArraysColumnValues[$loop][$loop2]
                $(Get-Variable -Name "temphashtableA$loop" -ValueOnly).Add($tempkeyA,$tempvalueA)
            }
            $keyA = $ArrayofArraysColumnValues[$loop][0]
            [hashtable]$valueA = $(Get-Variable -Name "temphashtableA$loop" -ValueOnly)
            
            # If the generic FinalHashTable was created because there was no Table Title, add key/value pairs to FinalhashTable
            if ($(Get-Variable -Name "FinalHashTable" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
                $global:FinalHashTable.Add($keyA,$valueA)
            }
            # If the HashTable based on the Table's Title was created, add key/value pairs to it
            if ($(Get-Variable -Name "HashTableTitle$TableTitle" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
                $(Get-Variable -Name "HashTableTitle$TableTitle" -Scope Global -ValueOnly).Add($keyA,$valueA)
            }
        }
    }

    if ($(Get-Variable -Name "FinalHashTable" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
        Write-Host "The HashTable `$global:FinalHashTable is now available in the current scope"
    }
    # If the HashTable based on the Table's Title was created, add key/value pairs to it
    if ($(Get-Variable -Name "HashTableTitle$TableTitle" -Scope Global -ErrorAction SilentlyContinue) -ne $null) {
        Write-Host "The HashTable `$global:HashTableTitle$TableTitle is now available in the current scope"
    }

    ###### END Make Final HashTable #####

    # Close Internet Explorer if it is running (i.e. stop the iexplorer.exe process)
    # It should only be running if $JavaScriptUsedToGenTable = "Yes"
    if ($ie -ne $null) {
        $ie.Quit()
    }

    $global:FunctionResult = "0"
}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOJooIvZVsx/t5KHg4V4N8G0s
# g02gggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSdjpAm8Ahq
# Vr+7WF5DT15PZ3msOzANBgkqhkiG9w0BAQEFAASCAQBnw7GZcpsqVccVOqQwHPN3
# qRksnj6nevI9Coq4Wafdlv5s4ECSu8Z59LzMfaUautlatA2C2fQ3wnU3cyR3kBi+
# 4tgVWp3x/sEKVk/a53YN+cSCv23Bcs4sq0szniwbmH6/wCQLiGCaMMLzhSzTyzLH
# /vYCsYVeio+sxjMi1Ops4jhjz69TecicllULiOnUM4cSDOo1A9MWUhqjIivvPF+2
# hV0KkdwJdLuRBlk/c8W3Pop23xkGv3sPKiMXhdOkIYdR58QhpXhcEYpIJ3l1+FX2
# xaIA7LtSD23QQTQsWgRLizlgDxJKRqKhz7NVmg7fYmSlQVJuMMDdSyxXJgdKKdSe
# SIG # End signature block
