<#
.SYNOPSIS

.DESCRIPTION

.DEPENDENCIES

.PARAMETERS

.EXAMPLE

.OUTPUTS

#>

function Replace-Text {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $HelperFunctionSourceDirectory,

        [Parameter(Mandatory=$False)]
        $TextFileSource = $(Read-Host -Prompt "Please enter the full path to the file containing the text you would like to replace"),

        [Parameter(Mandatory=$False)]
        $ReplacementType = $(Read-Host -Prompt "Please enter 'inplace' to replace text directly in $TextFileSource or 'newfile' to create new file with the updated text [inplace/newfile]"),

        [Parameter(Mandatory=$False)]
        $NewFileWithUpdatedText, # Must be full path to desired output filename

        [Parameter(Mandatory=$False)]
        $TextFormationType = $(Read-Host -Prompt "Please enter either string, line, or block"),

        [Parameter(Mandatory=$False)]
        $StringToReplace,

        [Parameter(Mandatory=$False)]
        [array]$StringLineNumber, # Which instance of $StringToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        $LineToReplace,

        [Parameter(Mandatory=$False)]
        [array]$LineLineNumber, # Which instance of $LineToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        $BlockToReplace,

        [Parameter(Mandatory=$False)]
        $ReplacementText = $(Read-Host -Prompt "Please enter the NEW text that you would like to use to replace the original text"),

        [Parameter(Mandatory=$False)]
        $ReplaceAll,

        [Parameter(Mandatory=$False)]
        $ReplaceOne,

        [Parameter(Mandatory=$False)]
        $ReplaceSome,

        [Parameter(Mandatory=$False)]
        $BeginningString,

        [Parameter(Mandatory=$False)]
        $OccurrenceOfBeginningString,

        [Parameter(Mandatory=$False)]
        $BeginningStringLineNumber,

        [Parameter(Mandatory=$False)]
        $EndingString,

        [Parameter(Mandatory=$False)]
        $OccurrenceOfEndingString,

        [Parameter(Mandatory=$False)]
        $EndingStringLineNumber,

        [Parameter(Mandatory=$False)]
        $ShowPotentialBlocksOfText

    )

    ##### BEGIN Variable/Parameter Transforms #####
    $TextFileSourceContent = Get-Content -Path $TextFileSource -Encoding Ascii

    if ($($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$StringLineNumber = $StringLineNumber.Split(",").Trim()
    }
    if (! $($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$StringLineNumber = $StringLineNumber
    }

    if ($($LineLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$LineLineNumber = $LineLineNumber.Split(",").Trim()
    }
    if (! $($LineLineNumberPrep | Select-String -Pattern ",").Matches.Success) {
        [array]$LineLineNumber = $LineLineNumber
    }

    # If either $StringLineNumber or $LineLineNumber is defined, and if they have 1 element, then $ReplaceOne should be used
    if ($StringLineNumber.Count -eq 1 -or $LineLineNumber.Count -eq 1) {
        if ($ReplaceAll -ne $null) {
            Remove-Variable -Name "ReplaceAll"
        }
        if ($ReplaceOne -ne "Yes") {
            $ReplaceOne = "Yes"
        }
        if ($ReplaceSome -ne $null) {
            Remove-Variable -Name "ReplaceSome"
        }
    }
    # If either $StringLineNumber or $LineLineNumber is defined, and if they have more than 1 element, then $ReplaceSome should be used
    if ($StringLineNumber.Count -gt 1 -or $LineLineNumber.Count -gt 1) {
        if ($ReplaceAll -ne $null) {
            Remove-Variable -Name "ReplaceAll"
        }
        if ($ReplaceOne -ne $null) {
            Remove-Variable -Name "ReplaceOne"
        }
        if ($ReplaceSome -ne "Yes") {
            $ReplaceSome = "Yes"
        }
    }

    ##### END Variable/Parameter Transforms #####

    ##### BEGIN Parameter Validation #####

    # Validate that the String exists in $TextFileSource

    if ($TextFormationType -eq "string") {
        # When attempting to replace a specific string, the parameter $StringToReplace is Required
        if ($StringLineNumber -ne $null -and $StringToReplace -eq $null) {
            Write-Host "If you intend to replace a specific string, you must use the `$StringToReplace parameter. Halting!"
            Write-Error "If you intend to replace a specific string, you must use the `$StringToReplace parameter. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Outputs $UpdatedStringLineNumbers, or fails
        if ($StringToReplace -ne $null) {
            # First, make sure that $StringToReplace is present in $TextFileSource
            if (! $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").MatchesSuccess) {
                Write-Host "The string '$StringToReplace' was not found in the file $TextFileSource"
                $StringToReplace = Read-Host -Prompt "Please enter a string that you would like to replace in the file $TextFileSource"
                if (! $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").MatchesSuccess) {
                    Write-Host "The string '$StringToReplace' was not found in the file $TextFileSource"
                    Write-Error "The string '$StringToReplace' was not found in the file $TextFileSource. Halting!"
                    return
                }
            }
            # Set some variables that can be used for later validation...
            $PossibleStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
            $StringLinesContent = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Line
            $ValidLineLinesIndexNumbers =  For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                $loop
            }
            $LineLinesChoices = For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                $($loop+1)+") "+$StringLinesContent[$loop]
            }
            $ValidLineLinesChoices = For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                $loop+1
            }

            # If $StringLineNumber is present, we can narrow down the list of $PossibleStringLineNumbers, but we also have to 
            # validate that $TextFileSourceContent[$StringLineNumber] actually contains $StringToReplace
            if ($StringLineNumber -ne $null) {
                $StringLineCheck = @()
                foreach ($LineNumber in $StringLineNumber) {
                    if ($($TextFileSourceContent[$LineNumber-1] | Select-String -Pattern "$StringToReplace").Matches.Success) {
                        Write-Host "The Line Number $LineNumber (i.e. Index $($LineNumber-1)) contains the string $StringToReplace. Continuing..."
                        $StringLineCheck += $($LineNumber-1)
                    }
                }
                if ($StringLineCheck -eq $null) {
                    Write-Host "Line Number $StringLineNumber does NOT contain '$StringToReplace'. Halting!"
                    Write-Error "Line Number $StringLineNumber does NOT contain '$StringToReplace'. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $UpdatedStringLineNumbers = $StringLineCheck
            }
            if ($StringLineNumber -eq $null) {
                $UpdatedStringLineNumbers = $PossibleStringLineNumbers
            }
        }
    }

    if ($TextFormationType -eq "line") {
        # When attempting to replace an ENTIRE Line, EITHER the $LineToReplace OR the $LineLineNumber parameter is Required
        # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace, or fails
        if ($LineToReplace -ne $null) {
            # First, Make sure that $LineToReplace is found in the $TextFileSource
            if (! $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").MatchesSuccess) {
                Write-Host "The line '$LineToReplace' was not found in the file $TextFileSource"
                $LineToReplace = Read-Host -Prompt "Please enter the entire line that you would like to replace in the file $TextFileSource"
                if (! $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").MatchesSuccess) {
                    Write-Host "The string '$LineToReplace' was not found in the file $TextFileSource"
                    Write-Error "The string '$LineToReplace' was not found in the file $TextFileSource. Halting!"
                    return
                }
            }
            # Set some variables that can be used for later validation...
            $PossibleLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
            $LineLinesContent = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Line
            $ValidLineLinesIndexNumbers =  For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                $loop
            }
            $LineLinesChoices = For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                $($loop+1)+") "+$StringLinesContent[$loop]
            }
            $ValidLineLinesChoices = For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                $loop+1
            }

            # If $LineLineNumber is present, we can ultimately define $UpdatedPossibleLineLineNumbers and $LineToReplace.
            # We do this by narrowing down the list of $PossibleStringLineNumbers AND ensuring that
            # $LineToReplace is, in fact, an ENTIRE Line (as opposed to a string within a line), AND validating
            # that $TextFileSourceContent[$LineLineNumber-1] actually matches $LineToReplace, and we have to 
            # validate that the content of each Line Number in $UpdatedPossibleStringLineNumbers is the SAME pattern.
            # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace
            if ($LineLineNumber -ne $null) {
                $LineLineCheck = @()
                foreach ($LineNumber in $LineLineNumber) {
                    if ($($TextFileSourceContent[$LineLineNumber-1] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                        Write-Host "The Line Number $LineLineNumber (i.e. Index $($LineLineNumber-1)) contains the pattern $LineToReplace. Continuing..."
                        $LineLineCheck += $($LineNumber-1)
                    }
                    if (! $($TextFileSourceContent[$LineLineNumber-1] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                        Write-Verbose "The Line Number $LineLineNumber (i.e. Index $($LineLineNumber-1)) does NOT contain the pattern $LineToReplace." -Verbose
                    }
                }
                if ($LineLineCheck -eq $null) {
                    Write-Host "`$LineToReplace is not 100% equal to the content of any of the following Line Number(s): $([string]$LineLineNumbers). Please ensure `$LineToReplace is as ENTIRE line. Halting!"
                    Write-Error "`$LineToReplace is not 100% equal to the content of any of the following Line Number(s): $([string]$LineLineNumbers). Please ensure `$LineToReplace is as ENTIRE line. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $UpdatedPossibleLineLineNumbers = $LineLineCheck
                # Check to see if every Line in $LineLineCheck is the same pattern. This also checks that $LineToRepalce is an ENITRE Line
                [System.Collections.ArrayList]$LineLineCheckContent = foreach ($obj1 in $LineLineCheck) {
                    $TextFileSourceContent[$obj1]
                }
                $LineNumberContentComparison = @()
                For ($loop=0; $loop -lt $LineLineCheckContent.Count; $loop++) {
                    [System.Collections.ArrayList]$LineLineCheckContentWithoutCurrentLoopElement = $LineLineCheckContent.RemoveAt($loop)
                    foreach ($obj1 in $LineLineCheckContentWithoutCurrentLoopElement) {
                        if ($TextFileSourceContent[$loop] -ne $obj1) {
                            $ElementToAdd = "$($TextFileSourceContent[$loop]) does not match $obj1"
                            $LineNumberContentComparison += $ElementToAdd
                        }
                    }
                }
                if ($LineNumberContentComparison -eq $null) {
                    Write-Host "The content of each `$LineLineNumber is the same. Defining `$LineToReplace. Continuing..."
                    # Arbitrarily choosing Index 0 since all of the elements in $LineLineCheckContent are the same
                    $LineToReplace = $LineLineCheckContent[0]
                }
                if ($LineNumberContentComparison -ne $null) {
                    $LineNumberContentComparison
                    Write-Host "The content of each `$LineLineNumber is NOT the same. Please ensure that there is only ONE pattern for the line/line numbers you would like to replace."
                    Write-Error "The content of each `$LineLineNumber is NOT the same. Please ensure that there is only ONE pattern for the line/line numbers you would like to replace."
                    $global:FunctionResult = "1"
                    return
                }
            }
            # If we only have $LineToReplace present, then we just have to verify that $LineToReplace is an ENTIRE Line
            # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace
            if ($LineLineNumber -eq $null) {
                $LineLineCheck = @()
                foreach ($obj1 in $PossibleLineLineNumbers) {
                    if ($TextFileSourceContent[$obj1] -eq $LineToReplace) {
                        Write-Host "Line Number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $($TextFileSourceContent[$obj1])
                    }
                    if ($TextFileSourceContent[$obj1] -ne $LineToReplace) {
                        Write-Verbose "Line Number $obj1 is NOT the same as '`$LineToReplace'. Please ensure that '`$LineToReplace' is the ENTIRE line." -Verbose
                    }
                }
                if ($LineLineCheck -eq $null) {
                    Write-Host "`$LineToReplace is not 100% equal to the content of any of the following Line Number(s): $([string]$LineLineNumbers). Please ensure `$LineToReplace is as ENTIRE line. Halting!"
                    Write-Error "`$LineToReplace is not 100% equal to the content of any of the following Line Number(s): $([string]$LineLineNumbers). Please ensure `$LineToReplace is as ENTIRE line. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $UpdatedPossibleLineLineNumbers = $LineLineCheck
            }
        }
        # If ONLY an array of $LineLineNumber is provided, we need to make sure that all of these lines are the SAME EXACT pattern
        # Outputs $UpdatedPossibleLineLineNumbers and $LineToReplace, or fails
        if ($LineLineNumber -ne $null -and $LineToReplace -eq $null) {
            # Set some variables that can be used for later validation...
            [System.Collections.ArrayList]$LineLineContent = foreach ($obj1 in $LineLineNumber) {
                $TextFileSourceContent[$obj1]
            }
            $LineNumberContentComparison = @()
            $UpdatedPossibleLineLineNumbers = @()
            For ($loop=0; $loop -lt $LineLineContent.Count; $loop++) {
                [System.Collections.ArrayList]$LineLineContentWithoutCurrentLoopElement = $LineLineContent.RemoveAt($loop)
                foreach ($obj1 in $LineLineContentWithoutCurrentLoopElement) {
                    if ($TextFileSourceContent[$loop] -eq $obj1) {
                        $UpdatedPossibleLineLineNumbers += $obj1
                    }
                    if ($TextFileSourceContent[$loop] -ne $obj1) {
                        $ElementToAdd = "$($TextFileSourceContent[$loop]) does not match $obj1"
                        $LineNumberContentComparison += $ElementToAdd
                    }
                }
            }
            if ($LineNumberContentComparison -eq $null) {
                Write-Host "The content of each `$LineLineNumber is the same. Defining `$LineToReplace. Continuing..."
                # Arbitrarily choosing Index 0 since all of the elements in $LineLineCheckContent are the same
                $LineToReplace = $LineLineCheckContent[0]
            }
            if ($LineNumberContentComparison -ne $null) {
                $LineNumberContentComparison
                Write-Host "The content of each `$LineLineNumber is NOT the same. Please ensure that there is only ONE pattern for the line/line numbers you would like to replace."
                Write-Error "The content of each `$LineLineNumber is NOT the same. Please ensure that there is only ONE pattern for the line/line numbers you would like to replace."
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($TextFormationType -eq "block") {
        if ($OccurrenceOfBeginningString -ne $null -and $BeginningStringLineNumber -ne $null) {
            Write-Host "Please use EITHER the parameter OccurrenceOfBeginningString OR the parameter BeginningStringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter OccurrenceOfBeginningString OR the parameter BeginningStringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($OccurrenceOfEndingString -ne $null -and $EndingStringLineNumber -ne $null) {
            Write-Host "Please use EITHER the parameter OccurrenceOfEndingString OR the parameter EndingStringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter OccurrenceOfEndingString OR the parameter EndingStringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####


    ##### BEGIN Helper Functions and Libraries #####

    ## BEGIN Sourced Helper Functions ##

    ## END Sourced Helper Functions ##

    ## BEGIN Native Helper Functions ##

    function Compare-Arrays {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [array]$LargerArray,

            [Parameter(Mandatory=$False)]
            [array]$SmallerArray
        )

        -not @($SmallerArray | where {$LargerArray -notcontains $_}).Count
    }
    ## END Native Helper Functions ##

    ##### END Helper Functions and Libraries #####

    ##### BEGIN Main Body #####

    # Outputs $UpdatedTextFileSourceContent
    if ($TextFormationType -eq "string") {
        # If the string is Unique in $TextFileSource or if User wants to replace ALL Occurrences...
        # Figure out if the user wants to replace ALL occurrences of the string, just one, or some of them
        if ($ReplaceAll -eq $null -and $ReplaceOne -eq $null -and $ReplaceSome -eq $null) {
            Write-Host "Defaulting to replacing ALL occurrences of $StringToReplace"
            $UpdatedTextFileSourceContent = $TextFileSourceContent -replace "$StringToReplace","$ReplacementText"
        }
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            Write-Host "Defaulting to replacing ALL occurrences of $StringToReplace"
            $UpdatedTextFileSourceContent = $TextFileSourceContent -replace "$StringToReplace","$ReplacementText"
        }
        if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
            # Begin Determine $FinalStringLineNumber #
            if ($OccurrenceOfString -eq "last" ) {
                $FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfString -eq "first") {
                $FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers -eq 1) {
                $FinalStringLineNumber = $UpdatedStringLineNumbers
            }
            if ($UpdatedStringLineNumbers.Count -gt 1 -and $OccurrenceOfString -eq $null) {
                $StringLinesContent = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Line
                $ValidStringLineIndexNumbers =  For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                    $loop
                }
                $StringLinesChoices = For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                    $($loop+1)+") "+$StringLinesContent[$loop]
                }
                $ValidStringLinesChoices = For ($loop=0; $loop -lt $StringLinesContent.Count; $loop++) {
                    $loop+1
                }
                Write-Host "The String $StringToReplace appears multiple times in $TextFileSource"
                Write-Host "Lines that contain $StringToReplace are as follows:"
                $StringLinesChoices
                $FinalStringLineNumber = Read-Host -Prompt "Please enter the line number that contains the string '$StringToReplace' that you would like to replace."
                if ($ValidStringLinesChoices -notcontains $StringLineNumber) {
                    Write-Host "$StringLineNumber is not a valid choice since it does not contain '$StringToReplace'."
                    Write-Host "Lines that contain $StringToReplace are as follows:"
                    $StringLinesChoices
                    $FinalStringLineNumber = Read-Host -Prompt "Please enter the line number that contains the string '$StringToReplace' that you would like to replace."
                    if ($ValidStringLinesChoices -notcontains $StringLineNumber) {
                        Write-Host "$StringLineNumber is not a valid choice since it does not contain '$StringToReplace'. Halting!"
                        Write-Error "$StringLineNumber is not a valid choice since it does not contain '$StringToReplace'. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # End Determine $FinalStringLineNumber #

            # Replace the String in Line Number $FinalStringLineNumber
            $UpdatedTextFileSourceContent = @()
            $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalStringLineNumber-2)]
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalStringLineNumber-1)] -replace "$StringToReplace","$ReplacementText"
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$FinalStringLineNumber..$($TextFileSourceContent.Count -1)]
        }
        if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
            # Begin Determine $FinalStringLineNumbers #
            if ($OccurrenceOfString -eq "last") {
                $FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfString -eq "first") {
                $FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers -gt 1 -and $OccurrenceOfString -eq $null) {
                $FinalStringLineNumbers = $UpdatedStringLineNumbers
            }
            # End Determine $FinalStringLineNumbers #

            # Replace the String in all Line Numbers in $StringLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalStringLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalStringLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalStringLineNumbers[$loop]-1)] -replace "$StringToReplace","$ReplacementText"
                    $NextLoopStartingPoint = $FinalStringLineNumbers[$loop]
                }
                if ($loop -gt 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($FinalStringLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalStringLineNumbers[$loop]-1)] -replace "$StringToReplace","$ReplacementText"
                    $NextLoopStartingPoint = $FinalStringLineNumbers[$loop]
                }
            }
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($TextFileSourceContent.Count -1)]
        }
    }

    # Outputs $UpdatedTextFileSourceContent
    if ($TextFormationType -eq "line") {
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            $UpdatedTextFileSourceContent = $TextFileSourceContent -replace "$LineToReplace","$ReplacementText"
        }
        if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
            # Begin Determine $FinalLineLineNumber #
            if ($OccurrenceOfLine -eq "last" ) {
                $FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfLine -eq "first") {
                $FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers -eq 1) {
                $FinalLineLineNumber = $UpdatedPossibleLineLineNumbers
            }
            if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and $OccurrenceOfLine -eq $null) {
                $LineLinesContent = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Line
                $ValidLineLineIndexNumbers =  For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                    $loop
                }
                $LineLinesChoices = For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                    $($loop+1)+") "+$LineLinesContent[$loop]
                }
                $ValidLineLinesChoices = For ($loop=0; $loop -lt $LineLinesContent.Count; $loop++) {
                    $loop+1
                }
                Write-Host "The Line `$LineToReplace appears multiple times in $TextFileSource"
                Write-Host "Lines that match `$LineToReplace are as follows:"
                $LineLinesChoices
                $FinalLineLineNumber = Read-Host -Prompt "Please enter the line number that that you would like to replace."
                if ($ValidLineLinesChoices -notcontains $LineLineNumber) {
                    Write-Host "The Line Number $FinalLineLineNumber is not a valid choice since it does not contain '$LineToReplace'."
                    Write-Host "Lines that contain $LineToReplace are as follows:"
                    $LineLinesChoices
                    $FinalLineLineNumber = Read-Host -Prompt "Please enter the line number that that you would like to replace."
                    if ($ValidLineLinesChoices -notcontains $LineLineNumber) {
                        Write-Host "The Line Number $FinalLineLineNumber is not a valid choice since it does not contain '$LineToReplace'. Halting!"
                        Write-Error "The Line Number $FinalLineLineNumber is not a valid choice since it does not contain '$LineToReplace'. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # End Determine $FinalLineLineNumber #

            # Replace the Line Number $FinalLineLineNumber
            $UpdatedTextFileSourceContent = @()
            $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalLineLineNumber-2)]
            $UpdatedTextFileSourceContent += $ReplacementText
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$FinalLineLineNumber..$($TextFileSourceContent.Count -1)]
        }
        if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
            # Begin Determine $FinalLineLineNumbers #
            if ($OccurrenceOfLine -eq "last") {
                $FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfLine -eq "first") {
                $FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers -gt 1 -and $OccurrenceOfLine -eq $null) {
                $FinalLineLineNumbers = $UpdatedPossibleLineLineNumbers
            }
            # End Determine $FinalLineLineNumbers #

            # Replace the String in all Line Numbers in $StringLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinallineLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalLineLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumbers[$loop]-1)] -replace "$LineToReplace","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumbers[$loop]
                }
                if ($loop -gt 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($FinalLineLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumbers[$loop]-1)] -replace "$LineToReplace","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumbers[$loop]
                }
            }
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($TextFileSourceContent.Count -1)]
        }
    }

    # Outputs $UpdatedTextFileSourceContent
    if ($TextFormationType -eq "block") {
        # Make sure $BeginningString and $EndingString are defined
        if ($BeginningString -eq $null) {
            Write-Host "In order to replace a block of text, you must use the `$BeginningString and `$EndingString parameters."
            Write-Host "The `$BeginningString parameter is currently not defined"
            $BeginningString = Read-Host -Prompt "Please enter the string of text that marks the beginning of the block of text you would like to replace"
        }
        if ($EndingString -eq $null) {
            Write-Host "In order to replace a block of text, you must use the `$BeginningString and `$EndingString parameters."
            Write-Host "The `$EndingString parameter is currently not defined"
            $EndingString = Read-Host -Prompt "Please enter the string of text that marks the end of the block of text you would like to replace"
        }

        # IMPORTANT NOTE: If your $TextFileSource contains the exact string ;;splithere;; then this function will break!!
        $TextFileSourceContentJoined = $TextFileSourceContent -join ";;splithere;;"

        # If both $EndingString and $BeginningString are Unique Perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -eq 1) {
            $BeginningLine = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Line
            $EndingLine = $($TextFileSourceContent | Select-String -Pattern "$EndingString").Line
            
            [array]$BlockToReplace = $($($TextFileSourceContentJoined | Select-String -Pattern "$BeginningLine[\w\W]{1,999999999}$EndingLine").Matches.Value) -split ";;splithere;;"
            Write-Host ""
            Write-Host "Writing `$BlockToReplace"
            Write-Host ""
            $BlockToReplace
        }
        # Check if $BeginningString is Unique
        # If it is, then ask the user if they want to bound the text block by the first or last occurrence of $EndingString
        if ($($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
            -and $($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -gt 1) {
            # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
            $BeginningLine = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Line
            $BeginningStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber

            # Begin Determine $EndingStringLineNumber #
            if ($OccurrenceOfEndingString -eq "last" -and $EndingStringLineNumber -eq $null) {
                $EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfEndingString -eq "first" -and $EndingStringLineNumber -eq $null) {
                $EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }

            if ($EndingStringLineNumber -eq $null) {
                Write-Host "The Ending String $EndingString appears multiple times in $TextFileSource"
                Write-Host "You must enter the line number that contains `$EndingString that will bound the block of text that you would like to replace."
                Write-Host "Line Numbers that contain `$EndingString are as follows:"
                $PossibleEndingStringLineNumbers
                $EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                    Write-Host "$EndingStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    $PossibleEndingStringLineNumbers
                    if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                        Write-Host "$EndingStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$EndingStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($BeginningStringLineNumber -gt $EndingLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource"
                    Write-Host "Please select an Ending Line Number that comes AFTER the Beginning Line Number $BeginningStringLineNumber"
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    $PossibleEndingStringLineNumbers
                    $EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($BeginningLineNumber -gt $EndingLineNumber) {
                        Write-Host "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource"
                        Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($EndingStringLineNumber -ne $null -and $OccurrenceOfEndingString -eq $null) {
                if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                    Write-Host "$EndingStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    $PossibleEndingStringLineNumbers
                    $EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                        Write-Host "$EndingStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$EndingStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # End Determine $EndingStringLineNumber #

            $BlockToReplace = $TextFileSourceContent | Select-Object -Index ($BeginningStringLineNumber..$EndingStringLineNumber)
        }
        # Check if $EndingString is Unique
        if ($($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -eq 1) {
            # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
            $EndingLine = $($TextFileSourceContent | Select-String -Pattern "$EndingString").Line
            $EndingStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber

            # Begin Determine $BeginningStringLineNumber #
            if ($OccurrenceOfBeginningString -eq "last" -and $BeginningStringLineNumber -eq $null) {
                $BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfBeginningString -eq "first" -and $EndingStringLineNumber -eq $null) {
                $BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }

            if ($BeginningStringLineNumber -eq $null) {
                Write-Host "The Beginning String $BeginningString appears multiple times in $TextFileSource"
                Write-Host "You must enter the line number that contains `$BeginningString that will bound the block of text that you would like to replace."
                Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                $PossibleBeginningStringLineNumbers
                $BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                    Write-Host "$BeginningStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    $PossibleBeginningStringLineNumbers
                    if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                        Write-Host "$BeginningStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$BeginningStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                if ($BeginningStringLineNumber -gt $EndingLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource"
                    Write-Host "Please select an Begining Line Number that comes BEFORE the Ending Line Number $EndingStringLineNumber"
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    $PossibleBeginningStringLineNumbers
                    $BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($BeginningLineNumber -gt $EndingLineNumber) {
                        Write-Host "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource"
                        Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($BeginningStringLineNumber -ne $null -and $OccurrenceOfEndingString -eq $null) {
                if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                    Write-Host "$BeginningStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    $PossibleBeginningStringLineNumbers
                    $BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                        Write-Host "$BeginningStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$BeginningStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # End Determine $BeginningStringLineNumber #

            $BlockToReplace = $TextFileSourceContent | Select-Object -Index ($BeginningStringLineNumber..$EndingStringLineNumber)
        }
        # If neither $EndingString nor $BeginningString are Unique Perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -gt 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1) {
            # Output possible results and ask the user which one they want to use
            # Create $BeginningStringIndex
            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber

            # Determine if $PossibleBeginningStringLineNumbers or $PossibleEndingStringLineNumbers has more elements
            if ($PossibleBeginningStringLineNumbers.Count -gt $PossibleEndingStringLineNumbers.Count) {
                $ComparisonLoopCount = $PossibleBeginningStringLineNumbers.Count
            }
            if ($PossibleBeginningStringLineNumbers.Count -lt $PossibleEndingStringLineNumbers.Count) {
                $ComparisonLoopCount = $PossibleEndingStringLineNumbers.Count
            }
            if ($PossibleBeginningStringLineNumbers.Count -eq $PossibleEndingStringLineNumbers.Count) {
                $ComparisonLoopCount = $PossibleBeginningStringLineNumbers.Count
            }

            $PossibleBlockToReplaceArray = @()
            $StartAndFinishLineNumbersArray = @()
            For ($loop=0; $loop -lt $ComparisonLoopCount; $loop++) {
                if ($PossibleBeginningStringLineNumbers[$loop] -lt $PossibleEndingStringLineNumbers[$loop]) {
                    Write-Host "The `$BegginningString line number $($PossibleBeginningStringLineNumbers[$loop]) comes before the `$EndingString line number $($PossibleEndingStringLineNumbers[$loop])"

                    New-Variable -Name "PossibleBlockToReplace$loop" -Value $($TextFileSourceContent | Select-Object -Index ($PossibleBeginningStringLineNumbers[$loop]..$($PossibleEndingStringLineNumbers[$loop]))) 
                    $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$loop" -ValueOnly)
                    $StartAndFinishLineNumbersArray += "Line $($PossibleBeginningStringLineNumbers[$loop]) to Line $($PossibleEndingStringLineNumbers[$loop])"
                }
                if ($PossibleBeginningStringLineNumbers[$loop] -gt $PossibleEndingStringLineNumbers[$loop]) {
                    Write-Host "The `$BegginningString line number $($PossibleBeginningStringLineNumbers[$loop]) comes after the `$EndingString line number $($PossibleEndingStringLineNumbers[$loop])"
                    Write-Host "INVALID"
                }
            }
            if ($PossibleBlockToReplaceArray -eq $null) {
                Write-Host "No valid blocks of text beginning with $BeginningString and ending with $EndingString were found."
                Write-Host "Please check to ensure that the Beginning String $BeginningString appears BEFORE the Ending String $EndingString in $TextFileSource"
                Write-Error "No valid blocks of text beginning with $BeginningString and ending with $EndingString were found. Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputPossibleBlocksToReplaceContent = For ($loop=0; $loop -lt $PossibleBlockToReplaceArray.Count; $loop++) {
                "Possible Block To Replace #$($loop+1)"+"`n"
                $PossibleBlockToReplaceArray[$loop]+"`n"
            }

            $OutputPossibleBlocksToReplaceLineNumbers = For ($loop=0; $loop -lt $StartAndFinishLineNumbersArray.Count; $loop++) {
                "Possible Block To Replace #$($loop+1)"+"`n"
                $StartAndFinishLineNumbersArray[$loop]+"`n"
            }

            Write-Host "Possible Blocks to Replace Are As Follows:"
            Write-Host ""
            $OutputPossibleBlocksToReplaceLineNumbers

            $ValidBlockToReplaceChoices = For ($loop=0; $loop -lt $PossibleBlockToReplaceArray.Count; $loop++) {$loop+1}
            [string]$PossibleBlockToReplaceChoices = For ($loop=0; $loop -lt $StartAndFinishLineNumbersArray.Count; $loop++) {"$($loop+1) = $($StartAndFinishLineNumbersArray[$loop])"}
            $SelectedBlockToReplace = Read-Host -Prompt "Please enter the number that corresponds to the range of line numbers that represent the block text that you would like to replace [$PossibleBlockToReplaceChoices]"
            # Validate $SelectedBlockToReplace
            if ($ValidBlockToReplaceChoices -notcontains $SelectedBlockToReplace) {
                Write-Host "$SelectedBlockToReplace is not a valid choice. Please select one of the following values:"
                $ValidBlockToReplaceChoices
                if ($ValidBlockToReplaceChoices -notcontains $SelectedBlockToReplace) {
                    Write-Host "$SelectedBlockToReplace is not a valid choice. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            $BlockToReplace = $PossibleBlockToReplaceArray[$($SelectedBlockToReplace-1)]
            Write-Host ""
            Write-Host "Writing `$BlockToReplace"
            Write-Host ""
            $BlockToReplace

        }

        # Define $UpdatedTextFileSourceContent
        $TextFileSourceContentJoined = $TextFileSourceContent -join ";;splithere;;"
        $BlockToReplaceJoined = $BlockToReplace -join ";;splithere;;"
        $UpdatedTextFileSourceContent = $($TextFileSourceContentJoined.Replace("$BlockToReplaceJoined","$ReplacementText")) -split ";;splithere;;"
    }

    # Update either the original $TextFileSource...
    if ($ReplacementType -eq "inplace") {
        Set-Content -Path $TextFileSource -Value $UpdatedTextFileSourceContent
        $UpdatedTextFileSourceContent
    }
    # ...or create a new file
    if ($ReplacementType -eq "newfile") {
        Set-Content -Path $NewFileWithUpdatedText -Value $UpdatedTextFileSourceContent
        $UpdatedTextFileSourceContent
    }
    ##### END Main Body #####

}

Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"



    ##### BEGIN Archived Code #####
<#
$BeginningLineIndexPositionArray = $TextFileSourceContent.LastIndexOf("$BeginningString")
$BeginningLinePositionFoundValues = $BeginningLineIndexPositionArray | Where-Object {$_ -ne "-1"} | Sort-Object | Get-Unique

$PossibleBeginningStringLineNumbers = For ($loop=0; $loop -lt $BeginningLineIndexPositionArray.Count; $loop++) {
    foreach ($obj1 in $BeginningLinePositionFoundValues) {
        if ($BeginningLineIndexPositionArray[$loop] -eq $obj1) {
            $loop
        }
    }
}

$EndingLineIndexPositionArray = $TextFileSourceContent.LastIndexOf("$EndingString")
$EndingLinePositionFoundValues = $EndingLineIndexPositionArray | Where-Object {$_ -ne "-1"} | Sort-Object | Get-Unique

$PossibleEndingStringLineNumbers = For ($loop=0; $loop -lt $EndingLineIndexPositionArray.Count; $loop++) {
    foreach ($obj1 in $EndingLinePositionFoundValues) {
        if ($EndingLineIndexPositionArray[$loop] -eq $obj1) {
            $loop
        }
    }
}

if ($OccurrenceOfEndingString -eq "last") {
    $EndingLine = $TextFileSourceContent[$([array]::lastindexof($EndingLineIndexPositionArray,$EndingLinePositionFoundValue))]

    $EndingStringIndexPosition = $TextFileSourceContentJoined.LastIndexOf("$EndingLine")
    # Grab all text before $EndingLine including $EndingLine
    $BlockToReplacePrep = $($TextFileSourceContentJoined.Substring(0, $EndingStringIndexPosition))+"$EndingLine"
    # Remove text preceding $BeginningLine
    [array]$BlockToReplace = $($($BlockToReplacePrep | Select-String -Pattern "$BeginningLine[\w\W]{1,999999999}$EndingLine").Matches.Value) -split ";;splithere;;"
    Write-Host ""
    Write-Host "Writing `$BlockToReplace"
    Write-Host ""
    $BlockToReplace
}
if ($OccurrenceOfEndingString -eq "first") {
    $EndingLine = $TextFileSourceContent[$([array]::indexof($EndingLineIndexPositionArray,$EndingLinePositionFoundValue))]

    $EndingStringIndexPosition = $TextFileSourceContentJoined.IndexOf("$EndingLine")
    # Grab all text before $EndingLine including $EndingLine
    $BlockToReplacePrep = $($TextFileSourceContentJoined.Substring(0, $EndingStringIndexPosition))+"$EndingLine"
    # Remove text preceding $BeginningLine
    [array]$BlockToReplace = $($($BlockToReplacePrep | Select-String -Pattern "$BeginningLine[\w\W]{1,999999999}$EndingLine").Matches.Value) -split ";;splithere;;"
    Write-Host ""
    Write-Host "Writing `$BlockToReplace"
    Write-Host ""
    $BlockToReplace
}
#>
    ##### END Archived Code
# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4Rc6lL++w9kooqw8nA6OBp7T
# QhCgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRogUc3B6aI
# XYHjpD4JdfEiLUmrqjANBgkqhkiG9w0BAQEFAASCAQB8/qUgrmT5cqsECIOwWMn1
# S72sLBlieErypjlH+hf2+AiyohXzbNMGmiat3q9wY8DdC9RbU1FpdypxcbQqo9+2
# +pgUphxJWLzTTc8wnvQIIca/pzPFoECnLm8A65iViN1Q2RegQSQGF3KMCPf4P7Vk
# QimtjnY6NGlf0VxJupFvsB+YxelaeQXNsUq8cCx3ZQ1X7j1imOYj2yNhRYDm7Hr8
# scnjEd1rBTizddOUadbFoFFUY2vYv9aqKjfVYdT/vUTBJ7ekpwuuQ/llF/lMqDRK
# aY35sO46k4M0swl7O4vzb38x3NNUKjb0aPo4jodC6jFij0NXWdwSNTNrkruiAtqj
# SIG # End signature block
