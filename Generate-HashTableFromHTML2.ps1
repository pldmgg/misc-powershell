function Generate-HashTableFromHTML {
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        $TargetURL = $(Read-Host -Prompt "Please enter a URL containing an HTML table that you would like to target"),

        [Parameter(Mandatory=$False)]
        $JavaScriptUsedToGenTable = $(Read-Host -Prompt "If JavaScript is used to dynamically generate the table you are targeting, please enter 'Yes'. [Yes/No]"),

        [Parameter(Mandatory=$False)]
        $OuterHTMLElementTagName = $(Read-Host -Prompt "Please enter the HTML Element Tag that is the parent of the <table> element. 
        This value is a generic HTML element and is NEVER unique to the webpage you are targeting. If you are unsure, type 'div'"),

        [Parameter(Mandatory=$False)]
        $OuterHTMLElementClassName = $(Read-Host -Prompt "Please enter the HTML Element ClassName in the HTML Element that is the parent of the <table> element. 
        This value COULD BE unique to the webpage you are targeting. This value should be found in html that looks like: 
        <$OuterHTMLElementTagName class=[HTML Element ClassName]..."),

        [Parameter(Mandatory=$False)]
        $TextUniqueToTargetTable
    )

    # Convert $TextUniqueToTargetTable to array
    [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
    
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

    $TablesOnPageCount = $($NewHTMLObjectBody.getElementsByTagName("table")).Count
    Write-Host ""
    Write-Host "Writing TablesOnPageCount..."
    $TablesOnPageCount
    Write-Host ""
    
    # NOTE: In the below code, if there is 1 object in $TablesOnPage, then the 'Count' method returns $null. 0 objects returns 0, and anything greater than 1 returns the expected Count. 
    # This is because PowerShell leaves $TablesOnPage as a  __ComObject of BaseType System.MarshalByRefObject instead of Object[] of BaseType System.Array when there is only 1 object.
    
    # If there is more than one table on the webpage, figure out which table to actually target.
    if ($TablesOnPageCount -ne $null -and $TablesOnPageCount -gt 1) {
        # If the user did NOT provide $TextUniqueToTargetTable, in order to assist targeting a specific table, ask the user to provide $TextUniqueToTargetTable
        if ($TextUniqueToTargetTable -eq $null) {
            Write-Host "More than one HTML table was found on $TargetURL"
            $TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
            [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
        }
        if ($TextUniqueToTargetTable -ne $null) {
            $TableTarget = $NewHTMLObjectBody.getElementsByTagName("$OuterHTMLElementTagName") | Where-Object {$_.ClassName -match "$OuterHTMLElementClassName"}
            For ($loop=0; $loop –lt $TextUniqueToTargetTable.Count; $loop++) {
                $TableTarget = $TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"}
            }
            $TableTargetCount = $TableTarget.Count
            Write-Host ""
            Write-Host "Writing `$TableTarget.Count (should be null)"
            $TableTargetCount
            <#
            Write-Host ""
            Write-Host "Writing TableTarget (should be one HTML Object)"
            $TableTarget
            Write-Host ""
            #>
            # If $TextUniqueToTargetTable isn't specific enough to filter out all but one table, ask the user to provide different/additional $TextUniqueTotargetTable
            if ($TableTargetCount -ne $null -and $TableTargetCount -gt 1) {
                Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table."
                $TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text that is unique to the one table you would like to target. Separate text from different cells with a comma."
                [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                $TableTarget = $NewHTMLObjectBody.getElementsByTagName("$OuterHTMLElementTagName") | Where-Object {$_.ClassName -match "$OuterHTMLElementClassName"}
                For ($loop=0; $loop –lt $TextUniqueToTargetTable.Count; $loop++) {
                    $TableTarget = $TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"}
                }
                $TableTargetCount = $TableTarget.Count
                Write-Host ""
                Write-Host "Writing `$TableTarget.Count (should be null)"
                $TableTargetCount
                <#
                Write-Host ""
                Write-Host "Writing TableTarget (should be one HTML Object)"
                $TableTarget
                Write-Host ""
                #>
                # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                if ($TableTargetCount -ne $null -and $TableTargetCount -gt 1) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table. Halting!"
                    return
                }
                # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                if ($TableTargetCount -ne $null -and $TableTargetCount -lt 1) {
                    Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found. Halting!"
                    return
                }
            }
            # If the $TextUniqueToTargetTable returns 0 tables, ask the user to provide different/additional $TextUniqueTotargetTable
            if ($TableTargetCount -ne $null -and $TableTargetCount -lt 1) {
                Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found."
                $TextUniqueToTargetTable = Read-Host -Prompt "Please enter a text string that is unique to the one table you would like to target"
                [array]$TextUniqueToTargetTable = $TextUniqueToTargetTable.Split(",").Trim()
                $TableTarget = $NewHTMLObjectBody.getElementsByTagName("$OuterHTMLElementTagName") | Where-Object {$_.ClassName -match "$OuterHTMLElementClassName"}
                For ($loop=0; $loop –lt $TextUniqueToTargetTable.Count; $loop++) {
                    $TableTarget = $TableTarget | Where-Object {$_.innerText -like "*$($TextUniqueToTargetTable[$loop])*"}
                }
                $TableTargetCount = $TableTarget.Count
                Write-Host ""
                Write-Host "Writing `$TableTarget.Count (should be null)"
                $TableTargetCount
                <#
                Write-Host ""
                Write-Host "Writing TableTarget (should be one HTML Object)"
                $TableTarget
                Write-Host ""
                #>
                # If the new $TextUniqueTotargetTable isn't specific enough to filter out all but one table, halt the script
                if ($TableTargetCount -ne $null -and $TableTargetCount -gt 1) {
                    Write-Host "More than one HTML table was found on $TargetURL based on the text string (i.e. '$TextUniqueToTargetTable') that is supposedly unique to one table. Halting!"
                    return
                }
                # If the new $TextUniqueToTargetTable returns 0 tables, halt the script
                if ($TableTargetCount -ne $null -and $TableTargetCount -lt 1) {
                    Write-Host "No table containing the unique text $TextUniqueToTargetTable has been found. Halting!"
                    return
                }
            }
            if ($TableTargetCount -eq $null) {
                Write-Host "The specified TargetTable has been found. Continuing..."
            }
        }
    }
    # If there is only one table on the webpage, just define $TableTarget...
    if ($TablesOnPageCount -eq $null) {
        $TableTarget = $NewHTMLObjectBody.getElementsByTagName("table") | Where-Object {$_.tagName -eq "table"}
    }
    # If there aren't any tables on the webpage, ask user to check URL and/or check HTML for <table> element tag...
    if ($TablesOnPageCount -ne $null -and $TablesOnPageCount -lt 1) {
        Write-Host "No tables were found on $TargetURL. Please check the URL and/or ensure that the HTML on the webpage contains the <table> element. Halting!"
        return
    }

    # Create an "Array" (it's actually a __ComObject of BaseType System.MarshalByRefObject) of HTML Objects that represent each row in the table (including the column headers). Target the TR element to do so.
    $ArrayofRowsHTMLObjects = $TableTarget.getElementsByTagName("TR")

    ##### END Logic To Target A Specific Table #####


    ##### BEGIN Logic to Define $ArrayofArraysColumnValues #####
    # $ArrayofArraysColumnValues[0] represents Column Headers, 
    # $ArrayofArraysColumnValues[N] (where N -ne 0) represents each row in the table, and 
    # $ArrayofArraysColumnValues[N][0] represents the first value in each row (may or may not have a column header)
    # $ArrayofArraysColumnValues[N][rowspanplit_first_position_in_arrayofarray] represents the value contained within the first encounter of rowspan split
    # $ArrayofArraysColumnValues[N][rowspanplit_second_position_in_arrayofarray] represents the value contained within the second encounter of rowspan split 

    # IMPORTANT NOTE: Anytime a variable represents an "Array" of HTML Objects, note that it's NOT *actually* an array - it's a __ComObject of BaseType System.MarshalByRefObject
    # As such, the Count method does NOT perform as expected by counting the number of HTML Objects in the "Array". However, using the Length method on a __ComObject performs as 
    # one would expect the Count method to on a normal array

    # Begin Defining $MaxColumns #

    # Estimate the maximum number of column values in any given row by picking a row in the middle of the table. This defines $MaxColumns (which is an Int32). This is helpful if:
    # 1) There are headers and subheaders within the table.
    # 2) There are HTML class=rowspan elements used for one-to-many associations. See https://coreos.com/os/docs/latest/booting-on-ec2.html for an example.
    $MiddleRowNumber = $($ArrayofRowsHTMLObjects.Length/2)
    # If it's not a whole number, round down to make it one
    if ($($MiddleRowNumber % 2) -ne 1 -and $($MiddleRowNumber % 2) -ne 0) {
        # Number is NOT whole, so round down
        $MiddleRowNumber = [Math]::Floor([decimal]$MiddleRowNumber)
    }
    # Check if $MiddleRowNumber contains TH or TD elements (should almost always be TD elements)
    $MaxColumnsTestTH = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH")).Count
    $MaxColumnsTestTD = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD")).Count
    # Check if $MIddleRowNumber+1 contains TF or TD elements
    $MaxColumnsTestTHPlus1 = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH")).Count
    $MaxColumnsTestTDPlus1 = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD")).Count

    # Look at the number of TH or TD elements in $MiddleRowNumber and the row after $MiddleRowNumber and define $MaxColumns as the one with the highest element count
    if ($MaxColumnsTestTH -ne $null) {
        if ($MaxColumnsTestTHPlus1 -ne $null) {
            if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH")).Count -gt $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH")).Count) {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH")).Count
            }
            else {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH")).Count
            }
        }
        if ($MaxColumnsTestTDPlus1 -ne $null) {
            if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH")).Count -gt $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD")).Count) {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TH")).Count
            }
            else {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD")).Count
            }
        }
    }
    if ($MaxColumnsTestTD -ne $null) {
        if ($MaxColumnsTestTDPlus1 -ne $null) {
            if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD")).Count -gt $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD")).Count) {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD")).Count
            }
            else {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TD")).Count
            }
        }
        if ($MaxColumnsTestTHPlus1 -ne $null) {
            if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD")).Count -gt $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH")).Count) {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $MiddleRowNumber).GetElementsByTagName("TD")).Count
            }
            else {
                $MaxColumns = $($($ArrayofRowsHTMLObjects | Select-Object -Index $($MiddleRowNumber+1)).GetElementsByTagName("TH")).Count
            }
        }
    }

    # End Defining $MaxColumns #

    # Begin Working through $ArrayofArrayColumnValuesPrep Iterations #

    $ArrayofArraysColumnValuesPrep = @()
    [System.Collections.ArrayList]$ArrayofArraysColumnValuesPrep2 = $ArrayofArraysColumnValuesPrep
    
    For ($loop=0; $loop –lt $ArrayofRowsHTMLObjects.Length; $loop++) {
        Write-Host "Main - starting loop # $loop"
        $RowHTMLObject = $ArrayofRowsHTMLObjects | Select-Object -Index $loop
        $RowHTMLObject.GetElementsByTagName("TH").Length
        $RowHTMLObject.GetElementsByTagName("TD").Length

        # If the $RowHTMLObject DOES contain TH elements (i.e. IS the table's column headers) and does NOT contain TH elements...
        if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) -ne $null -and $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) -eq $null) {
            # If "rowspan=2" is NOT present...
            if ($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")).outerHTML | Select-String -Pattern "rowspan=2").Matches.Success -ne $true) {
                # ...And if the current row (i.e. the column headers) has the same number of columns (i.e. TH elements) as the Maximum number of columns in the table (i.e. $MaxColumns), then just process the current Row Object
                if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")).Length -eq $MaxColumns) {
                    Write-Host "Triggering zeroth if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -lt $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")).Length); $loop2++) {
                            # In cases where rowspan is used (which it SHOULDN'T be under these circumstances where Column 1 in each and every row is represented by a TD element), precede the value with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -eq $true) {
                                "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                $rowspan = "Yes"
                            }
                            # Any empty cells are filled in with the word "null"
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).innerText -eq $null) {
                                "null;"
                            }
                            # In cases where rowspan is NOT used, precede the value of Index 0 with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).innerText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                                else {
                                    $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                            }
                        }
                    )
                }
            }
        }
        # If the $RowHTMLObject does NOT contain TH elements (i.e. is NOT the table's column headers) and it DOES contain TD elements...
        if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TH")) -eq $null -and $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) -ne $null) {
            # If the Row contains a TD element that contains the element "rowspan=2"...
            if ($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).outerHTML | Select-String -Pattern "rowspan=2").Matches.Success) {
                # If the Subsequent Row has ONE LESS TD Element than the current Row, assume add the Subsequent Row contains values that should be added to current Row under current Row's Column 1 (i.e. Index 0) value
                if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")).Length -eq $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length-1) {
                    Write-Host "Triggering first if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -le $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length); $loop2++) {
                            # In cases where rowspan is used (which it COULD be under these circumstances where Column 1+N has MORE THAN ONE value for what APPEARS to be the same row), precede the value with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=2").Matches.Success -eq $true) {
                                # Skip $loop = 1 because $loop-1 = 0 which does NOT contain any TD elements (it contains TH elements for column headers) 
                                if ($loop -gt 0) {
                                    Write-Host "loop number $loop"
                                    "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                    $rowspan = "Yes"
                                }
                            }
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -eq $null) {
                                "null;"
                            }
                            # In cases where rowspan is NOT used, precede the value of Index 0 with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                                else {
                                    $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                            }
                        }
                        For ($loop3=0; $loop3 -le $($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")).Length); $loop3++) {
                            # In cases where there is no value in the TD element, fill it in with the word "null"
                            if ($($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")) | Select-Object -Index $loop3).innerText -eq $null) {
                                "null;"
                            }
                            if ($($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")) | Select-Object -Index $loop3).innerText -ne $null) {
                                $($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")) | Select-Object -Index $loop3).innerText.Trim()+";"
                            }
                        }
                    )
                }
                # If the Subsequent Row does NOT have ONE LESS TD Element than the current Row, just process current row normally
                if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $($loop+1)).GetElementsByTagName("TD")).Length -ne $($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length-1) {
                    Write-Host "Triggering second if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -lt $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length); $loop2++) {
                            # In cases where rowspan is used (which it SHOULDN'T be under these circumstances where Column 1 in each and every row is represented by a TD element), precede the value with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -eq $true) {
                                "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                $rowspan = "Yes"
                            }
                            # Any empty cells are filled in with the word "null"
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -eq $null) {
                                "null;"
                            }
                            # In cases where rowspan is NOT used, precede the value of Index 0 with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                                else {
                                    $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                            }
                        }
                    )
                }
            }
            # If "rowspan=2" is NOT present...
            if ($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).outerHTML | Select-String -Pattern "rowspan=2").Matches.Success -ne $true) {
                # ...And if the current row has the same number of columns (i.e. TD elements) as the Maximum number of columns in the table (i.e. $MaxColumns), then just process the current Row Object
                if ($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length -eq $MaxColumns) {
                    Write-Host "Triggering third if statement"
                    New-Variable -Name "ArrayofColumnValuesforRow$loop" -Value $(
                        For ($loop2=0; $loop2 -lt $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")).Length); $loop2++) {
                            # In cases where rowspan is used (which it SHOULDN'T be under these circumstances where Column 1 in each and every row is represented by a TD element), precede the value with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -eq $true) {
                                "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                $rowspan = "Yes"
                            }
                            # Any empty cells are filled in with the word "null"
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -eq $null) {
                                "null;"
                            }
                            # In cases where rowspan is NOT used, precede the value of Index 0 with @ to make parsing later easier.
                            if ($($($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).outerHtml | Select-String -Pattern "rowSpan=").Matches.Success -ne $true `
                            -and $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText -ne $null) {
                                if ($loop2 -eq 0) {
                                    "@"+$($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
                                else {
                                    $($($($ArrayofRowsHTMLObjects | Select-Object -Index $loop).GetElementsByTagName("TD")) | Select-Object -Index $loop2).innerText.Trim()+";"
                                }
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

    # End Working through $ArrayofArrayColumnValuesPrep Iterations #

    ##### END Logic to Define $ArrayofArraysColumnValue #####

    ###### BEGIN Make Final HashTable #####

    if ($rowspan -eq "Yes") {
        # Make Interim Hashtable for the rowspan split
        # Need logic to identify WHERE rowspan split is with regards to Column headers. 
        # For now, hashtable keys are just hardcoded with the Index number (i.e. $ArrayofArraysColumnValues[$loop][1], etc
        # Because I know in advance that those array elements contain the values for AMIType and AMIID Columns
        $AMITypeHashTable = @{}
        For ($loop=1; $loop –lt $ArrayofArraysColumnValues.Count; $loop++) {
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
        For ($loop=1; $loop –lt $ArrayofArraysColumnValues.Count; $loop++) {
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

        $global:FinalHashTableA = @{}
        For ($loop=1; $loop –lt $ArrayofArraysColumnValues.Count; $loop++) {
            New-Variable -Name "temphashtableA$loop" -Value @{}
            For ($loop2=0; $loop2 –lt $ArrayofArraysColumnValues[0].Count; $loop2++) {
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
            $global:FinalHashTableA.Add($keyA,$valueA)
        }
    }

    if ($rowspan -ne "Yes") {
        $global:FinalHashTableA = @{}
        For ($loop=1; $loop –lt $ArrayofArraysColumnValues.Count; $loop++) {
            New-Variable -Name "temphashtableA$loop" -Value @{}
            For ($loop2=0; $loop2 –lt $ArrayofArraysColumnValues[0].Count; $loop2++) {
                $tempkeyA = $ArrayofArraysColumnValues[0][$loop2]
                $tempvalueA = $ArrayofArraysColumnValues[$loop][$loop2]
                $(Get-Variable -Name "temphashtableA$loop" -ValueOnly).Add($tempkeyA,$tempvalueA)
            }
            $keyA = $ArrayofArraysColumnValues[$loop][0]
            [hashtable]$valueA = $(Get-Variable -Name "temphashtableA$loop" -ValueOnly)
            $global:FinalHashTableA.Add($keyA,$valueA)
        }
    }

    ###### END Make Final HashTable #####

    Write-Host "The HashTable `$global:FinalHashTableA is now available in the current scope"
}

# Webpage with ***MULTIPLE TABLES*** and Target Table that has ***ONLY ONE*** value per row/column cell
#Generate-HashTableFromHTML -TargetURL "https://coreos.com/os/docs/latest/booting-on-ec2.html" `
#-OuterHTMLElementTagName "div" `
#-OuterHTMLElementClassName "tab-pane" `
#-TextUniqueToTargetTable "The alpha channel"`
#-JavaScriptUsedToGenTable "No"

# Webpage with ***MULTIPLE TABLES*** and Target Table ***COULD HAVE MULTIPLE*** values per row/column cell
#Generate-HashTableFromHTML -TargetURL "https://aws.amazon.com/ec2/instance-types" `
#-OuterHTMLElementTagName "div" `
#-OuterHTMLElementClassName "aws-table" `
#-TextUniqueToTargetTable "Instance Type" `
#-JavaScriptUsedToGenTable "No"

# Webpage with only ***ONE TABLE*** and that table has ***ONLY ONE*** value per row/column cell
#Generate-HashTableFromHTML -TargetURL "http://www.ec2instances.info" `
#-OuterHTMLElementTagName "div" `
#-OuterHTMLElementClassName "dataTables_wrapper" `
#-TextUniqueToTargetTable "Cluster Compute Eight Extra Large" `
#-JavaScriptUsedToGenTable "No"

# Webpage with ***MULTIPLE TABLES*** and Target Table ***COULD HAVE MULTIPLE*** values per row/column cell
#Generate-HashTableFromHTML -TargetURL "https://aws.amazon.com/ec2/pricing" `
#-JavaScriptUsedToGenTable "Yes" `
#-OuterHTMLElementTagName "div" `
#-OuterHTMLElementClassName "content reg-us-east-1" `
#-TextUniqueToTargetTable "Linux/UNIX Usage, t2.micro, variable, 0.0065"

#$($NewHTMLObjectBody.getElementsByClassName("par parsys")).children.GetElementsByTagName("div").id
#$($NewHTMLObjectBody.getElementsByTagName("div")).getElementsByClassName("aws-pricing-table")


# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUumsl6MNxCc57Vw+MJX0l4og7
# 40igggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQ8lSiqq07P
# WwhQ3aBC/6Q7K+FpCzANBgkqhkiG9w0BAQEFAASCAQCcW9S88ImAQ28pwUsAGU9u
# ez+ksfZkqN3aarbWlrBxbIKo7E++v2eWFhF5mUH8AD3a4D9KJCtY06VYwxxuFQsc
# LNnlbBQQqB/Nl55l1WhJWAwP6KTIbTkPcqU6QX8yqsYsxqeo6JOL1e6atkrwQtXH
# oUCcAfldOdVu8h2x65Sj5Z6lSd1Zug0AsnUge8SfKlbv9g+/leZ2GBVR1cIXO0vQ
# LIaM/GdErtu0uVPjDuXkp7MEMItmlbqCjh1g4Nhprx2cySFTpAeq7hN/yQlSo3qZ
# 9/8LBb3Q/GMEYctx623YqZeK5VphWEXhL35A8zqow1xP9YKhxb0d0QpS09RtRnSK
# SIG # End signature block
