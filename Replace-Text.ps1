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

    ##### END Variable/Parameter Transforms #####

    ##### BEGIN Parameter Validation #####

    ## Begin Basic Validation Of Which Parameters Can/Should Be Used Together ##

    # If either $StringLineNumber or $LineLineNumber is used, then $ReplaceAll should NOT be used
    if ($StringLineNumber -ne $null) {
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            Write-Verbose "If the parameter `$LineLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            if ($StringLineNumber.Count -eq 1) {
                if ($ReplaceAll -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceAll" -Verbose
                    Remove-Variable -Name "ReplaceAll"
                }
                if ($ReplaceOne -ne "Yes") {
                    Write-Verbose "Using the parameter `$ReplaceOne"
                    $ReplaceOne = "Yes"
                }
                if ($ReplaceSome -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceSome" -Verbose
                    Remove-Variable -Name "ReplaceSome"
                }
            }
            if ($StringLineNumber.Count -gt 1) {
                if ($ReplaceAll -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceAll" -Verbose
                    Remove-Variable -Name "ReplaceAll"
                }
                if ($ReplaceOne -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceSome" -Verbose
                    Remove-Variable -Name "ReplaceOne"
                }
                if ($ReplaceSome -ne "Yes") {
                    Write-Verbose "Using the parameter `$ReplaceSome" -Verbose
                    $ReplaceSome = "Yes"
                }
            }
        }
    }
    if ($LineLineNumber -ne $null) {
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            Write-Verbose "If the parameter `$LineLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            if ($LineLineNumber.Count -eq 1) {
                if ($ReplaceAll -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceAll" -Verbose
                    Remove-Variable -Name "ReplaceAll"
                }
                if ($ReplaceOne -ne "Yes") {
                    Write-Verbose "Using the parameter `$ReplaceOne" -Verbose
                    $ReplaceOne = "Yes"
                }
                if ($ReplaceSome -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceSome" -Verbose
                    Remove-Variable -Name "ReplaceSome"
                }
            }
            if ($LineLineNumber.Count -gt 1) {
                if ($ReplaceAll -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceAll" -Verbose
                    Remove-Variable -Name "ReplaceAll"
                }
                if ($ReplaceOne -ne $null) {
                    Write-Verbose "Removing the parameter `$ReplaceSome" -Verbose
                    Remove-Variable -Name "ReplaceOne"
                }
                if ($ReplaceSome -ne "Yes") {
                    Write-Verbose "Using the parameter `$ReplaceSome" -Verbose
                    $ReplaceSome = "Yes"
                }
            }
        }
    }

    # Only one "$ReplaceX" parameter should be used
    $ReplaceParamsCheck = @()
    if ($ReplaceAll -ne $null) {
        $ReplaceParamsCheck += "`$ReplaceAll was used"
    }
    if ($ReplaceSome -ne $null) {
        $ReplaceParamsCheck += "`$ReplaceSome was used"
    }
    if ($ReplaceOne -ne $null) {
        $ReplaceParamsCheck += "`$ReplaceOne was used"
    }
    if ($ReplaceParamsCheck.Count -gt 1) {
        $ReplaceParamsCheck
        Write-Host "Only ONE of the following parameters can be used: `$ReplaceAll, `$ReplaceSome, `$ReplaceSome. Halting!"
        Write-Error "Only ONE of the following parameters can be used: `$ReplaceAll, `$ReplaceSome, `$ReplaceSome. Halting!"
        $global:FunctionResult = "1"
        return
    }

    ## End Basic Validation Of Which Parameters Can/Should Be Used Together ##

    ## Begin Working Through Specific Validation Scenarios depending on $TextFormationType ##
    if ($TextFormationType -eq "string") {
        # When attempting to replace a specific string, the parameter $StringToReplace is Required
        if ($StringToReplace -eq $null -and $StringLineNumber -ne $null) {
            Write-Host "If you intend to replace a specific string, you must use the `$StringToReplace parameter. Halting!"
            Write-Error "If you intend to replace a specific string, you must use the `$StringToReplace parameter. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Outputs $UpdatedStringLineNumbers, or fails
        if ($StringToReplace -ne $null) {
            # First, make sure that $StringToReplace is present in $TextFileSource
            if (! $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Matches.Success) {
                Write-Host "The string '$StringToReplace' was not found in the file $TextFileSource"
                $StringToReplace = Read-Host -Prompt "Please enter a string that you would like to replace in the file $TextFileSource"
                if (! $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").MatchesSuccess) {
                    Write-Host "The string '$StringToReplace' was not found in the file $TextFileSource"
                    Write-Error "The string '$StringToReplace' was not found in the file $TextFileSource. Halting!"
                    return
                }
            }

            # Second, if $ReplaceSome is used, and $StringToReplace appears multiple times in $TextFileSource, 
            # but the $StringLineNumber is not provided, prompt user to provide $StringLineNumber
            if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                if ($StringLineNumber -eq $null) {
                    if ( $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -eq 1) {
                        $StringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                    }
                    if ( $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -gt 1) {
                        Write-Host "The parameter `$ReplaceSome was used, however, no line numbers were specified using the `$StringLineNumber parameter, and more than one line contains the string:`n$StringToReplace"
                        Write-Host "Line Numbers that contain the string '$StringToReplace' are as follows:"
                        $ValidStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $ValidStringLineNumbers
                        $StringLineNumber = Read-Host -Prompt "Please enter one or more line numbers (separated by commas) that contain the string '$StringToReplace'"
                        if ($($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringLineNumber = $StringLineNumber.Split(",").Trim()
                        }
                        if (! $($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringLineNumber = $StringLineNumber
                        }
                        if (! $(Compare-Arrays -LargerArray $ValidStringLineNumbers -SmallerArray $StringLineNumber)) {
                            Write-Host "One or more of the following line numbers are not valid: $([string]$StringLineNumber -replace " ",", ")"
                            Write-Host "Valid line numbers are as follows:"
                            $ValidStringLineNumbers
                            $StringLineNumber = Read-Host -Prompt "Please enter one or more of the above line numbers (separated by commas) that contain the string '$StringToReplace' that you would like to replace"
                            if ($($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineNumber = $StringLineNumber.Split(",").Trim()
                            }
                            if (! $($StringLineNumber | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineNumber = $StringLineNumber
                            }
                            if (! $(Compare-Arrays -LargerArray $ValidStringLineNumbers -SmallerArray $StringLineNumber)) {
                                Write-Host "One or more of the following line numbers are not valid: $([string]$StringLineNumber -replace " ",", "). Halting!"
                                Write-Error "One or more of the following line numbers are not valid: $([string]$StringLineNumber -replace " ",", "). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
            }

            # Third, work on generating $UpdatedStringLineNumbers...
            # Set some variables that can be used for later validation...
            $PossibleStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
            $StringLinesContent = foreach ($obj1 in $PossibleStringLineNumbers) {
                $TextFileSourceContent[$obj1]
            }
            $ValidStringLineIndexNumbers =  foreach ($obj1 in $PossibleStringLineNumbers) {
                $obj1-1
            }
            $StringLinesChoices = foreach ($obj1 in $PossibleStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$($obj1-1)])"
            }
            $ValidStringLinesChoices = $PossibleStringLineNumbers
            

            # If $StringLineNumber is present, we can narrow down the list of $PossibleStringLineNumbers, but we also have to 
            # validate that $TextFileSourceContent[$StringLineNumber] actually contains $StringToReplace
            if ($StringLineNumber -ne $null) {
                $StringLineCheck = @()
                foreach ($LineNumber in $StringLineNumber) {
                    if ($($TextFileSourceContent[$LineNumber-1] | Select-String -Pattern "$StringToReplace").Matches.Success) {
                        Write-Host "The Line Number $LineNumber (i.e. Index $($LineNumber-1)) contains the string '$StringToReplace'. Continuing..."
                        $StringLineCheck += $LineNumber
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
        if ($LineToReplace -eq $null -and $LineLineNumber -eq $null) {
            Write-Host "If you intend to replace an entire line, you must use the `$LineToReplace parameter and/or the `$LineLineNumber parameter. Halting!"
            Write-Error "If you intend to replace an entire line, you must use the `$LineToReplace parameter and/or the `$LineLineNumber parameter. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace, or fails
        if ($LineToReplace -ne $null) {
            # First, Make sure that $LineToReplace is found in the $TextFileSource
            if (! $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Matches.Success) {
                Write-Host "The line '$LineToReplace' was not found in the file $TextFileSource"
                $LineToReplace = Read-Host -Prompt "Please enter the entire line that you would like to replace in the file $TextFileSource"
                if (! $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").MatchesSuccess) {
                    Write-Host "The string '$LineToReplace' was not found in the file $TextFileSource"
                    Write-Error "The string '$LineToReplace' was not found in the file $TextFileSource. Halting!"
                    return
                }
            }

            # Second, if $ReplaceSome is used, and $LineToReplace appears multiple times in $TextFileSource,
            # but the $LineLineNumber is not provided, prompt user to provide $LineLineNumber
            if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                if ($LineLineNumber -eq $null) {
                    if ( $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Count -eq 1) {
                        $LineLineNumber = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                    }
                    if ( $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Count -gt 1) {
                        Write-Host "The parameter `$ReplaceSome was used, however, no line numbers were specified using the `$LineLineNumber parameter, and more than one line matches the line:`n$LineToReplace"
                        Write-Host "Line Numbers that match the line '$LineToReplace' are as follows:"
                        $ValidLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $ValidLineLineNumbers
                        $LineLineNumber = Read-Host -Prompt "Please enter one or more of the above line numbers (separated by commas) that you would like to replace"
                        if ($($LineLineNumber | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineNumber = $LineLineNumber.Split(",").Trim()
                        }
                        if (! $($LineLineNumber | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineNumber = $LineLineNumber
                        }
                        if (! $(Compare-Arrays -LargerArray $ValidLineLineNumbers -SmallerArray $LineLineNumber)) {
                            Write-Host "One or more of the following line numbers are not valid: $([string]$LineLineNumber -replace " ",", ")"
                            Write-Host "Valid line numbers are as follows:"
                            $ValidLineLineNumbers
                            $LineLineNumber = Read-Host -Prompt "Please enter one or more line numbers (separated by commas) that match the line '$LineToReplace'"
                            if ($($LineLineNumber | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineNumber = $LineLineNumber.Split(",").Trim()
                            }
                            if (! $($LineLineNumber | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineNumber = $LineLineNumber
                            }
                            if (! $(Compare-Arrays -LargerArray $ValidLineLineNumbers -SmallerArray $LineLineNumber)) {
                                Write-Host "One or more of the following line numbers are not valid: $([string]$LineLineNumber -replace " ",", "). Halting!"
                                Write-Error "One or more of the following line numbers are not valid: $([string]$LineLineNumber -replace " ",", "). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
            }

            # Third, work on generating $UpdatedPossibleLineLineNumbers...
            # Set some variables that can be used for later validation...
            $PossibleLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
            $LineLinesContent = foreach ($obj1 in $PossibleLineLineNumbers) {
                $TextFileSourceContent[$obj1]
            }
            $ValidLineLineIndexNumbers =  foreach ($obj1 in $PossibleLineLineNumbers) {
                $obj1-1
            }
            $LineLinesChoices = foreach ($obj1 in $PossibleLineLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$($obj1-1)])"
            }
            $ValidLineLinesChoices = $PossibleLineLineNumbers

            # If $LineLineNumber is present, we can ultimately define $UpdatedPossibleLineLineNumbers and $LineToReplace.
            # We do this by narrowing down the list of $PossibleStringLineNumbers AND ensuring that
            # $LineToReplace is, in fact, an ENTIRE Line (as opposed to a string within a line), AND validating
            # that $TextFileSourceContent[$LineNumber-1] actually matches $LineToReplace, and we have to 
            # validate that the content of each Line Number in $UpdatedPossibleStringLineNumbers is the SAME pattern.
            # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace
            if ($LineLineNumber -ne $null) {
                $LineLineCheck = @()
                $BadMatches = @()
                foreach ($obj1 in $LineLineNumber) {
                    if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        Write-Host "The contents of the entire line number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $obj1
                    }
                    if ($TextFileSourceContent[$($obj1-1)] -ne $LineToReplace) {
                        # Check if $LineToReplace is string within the line. If so, add it to $LineLineCheck...
                        if ($($TextFileSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextFileSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', however, it DOES contain the string '$LineToReplace'. Continuing..." -Verbose
                            $LineLineCheck += $obj1
                        }
                        # If $LineToReplace is NOT a string within the line, then do NOT add anything to $LineLineCheck.
                        # The subsequent if statement will be responsible for throwing the error.
                        if (! $($TextFileSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextFileSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', and it DOES NOT contain the string '$LineToReplace'. Line number $obj1 will not be touched." -Verbose
                            $BadMatches += $obj1
                        }
                    }
                }
                if (! $($LineLineCheck -gt 0)) {
                    Write-Host "The contents of the ENTIRE lines for Line Number(s) $([string]$LineLineNumbers) do NOT 100% equal the `$LineToReplace '$LineToReplace'."
                    Write-Host "Also, these line(s) do NOT contain the string '$LineToReplace'." 
                    Write-Host "Please ensure `$LineToReplace is either equal to the entire line you would like to replace, or matches a string within the line you would like to replace. Halting!"
                    Write-Error "Please ensure `$LineToReplace is either equal to the entire line you would like to replace, or matches a string within the line you would like to replace. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                # Check to see if the content of every Line Number in $LineLineCheck is the SAME EXACT PATTERN. 
                # It might be that $LineToReplace is NOT an ENTIRE LINE, in which case the content of the referenced line numbers in $LineLineCheck,
                # while they certainly reference line numbers that contain the string $LineToReplace, the full contents of each lines may not be equal
                # If they are equal, $PotentialPatterns will remain $null, $LineToReplace will be redefined, and $UpdatedPossibleLineLineNumbers will be set
                # If they are NOT equal, ask the user which line represents the pattern of the ENTIRE LINE that he/she wants to replace 
                $PotentialPatterns = @()
                For ($loop=0; $loop -lt $LineLineCheck.Count; $loop++) {
                    $LineLineCheckWithoutCurrentLoopElement = foreach ($obj1 in $LineLineCheck) {
                        if ($obj1 -ne $($LineLineCheck[$loop])) {
                            $obj1
                        }
                    }
                    foreach ($obj1 in $LineLineCheckWithoutCurrentLoopElement) {
                        $SourceArrayElementContent = $TextFileSourceContent[$($LineLineCheck[$loop]-1)]
                        $RemainderArrayElementContent = $TextFileSourceContent[$($obj1-1)]
                        if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                            Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                            if ($PotentialPatterns -notcontains $($TextFileSourceContent[$($LineLineCheck[$loop]-1)])) {
                                $PotentialPatterns += $($TextFileSourceContent[$($LineLineCheck[$loop]-1)])
                            }
                        }
                    }
                }
                # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
                if (! $($PotentialPatterns.Count -gt 0)) {
                    Write-Host "The content of each line for lines $([string]$LineLineCheck) is the same. Defining `$LineToReplace. Continuing..."
                    # Arbitrarily choosing Index 0 since all of the elements in $LineLineCheckContent are the same
                    $LineToReplace = $TextFileSourceContent[$($LineLineCheck[0]-1)]
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck
                }
                if ($PotentialPatterns.Count -gt 0) {
                    Write-Host "The content of line numbers $([string]$LineLineNumber) are not all exactly the same."
                    Write-Host "Choices for unique patterns are as follows:"
                    Write-Host "NOTE: There is one (1) space between the ')' character and the beginning of the actual pattern"
                    For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                    }
                    $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        $loop+1
                    }
                    $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                    if ($ValidPatternChoices -notcontains $PatternChoice) {
                        Write-Host "$PatternChoice is not a valid choice. Valid choices are as follows:"
                        [string]$ValidPatternChoices -replace " ",", "
                         $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                        if ($ValidPatternChoices -notcontains $PatternChoice) {
                            Write-Host "$PatternChoice is not a valid choice. Halting!"
                            Write-Error "$PatternChoice is not a valid choice. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
                    $LineToReplace = $PotentialPatterns[$($PatternChoice-1)]
                    $LineLineCheck2 = @()
                    foreach ($obj1 in $LineLineNumber) {
                        if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                            $LineLineCheck2 += $obj1
                        }
                    }
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck2
                }
            }
            # If we only have $LineToReplace present, then we just have to verify that $LineToReplace is an ENTIRE Line
            # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace
            if ($LineLineNumber -eq $null) {
                $LineLineCheck = @()
                $BadMatches = @()
                foreach ($obj1 in $PossibleLineLineNumbers) {
                    if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        Write-Host "The contents of the entire line number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $obj1
                    }
                    if ($TextFileSourceContent[$($obj1-1)] -ne $LineToReplace) {
                        # Check if $LineToReplace is string within the line. If so, add it to $LineLineCheck...
                        if ($($TextFileSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextFileSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', however, it DOES contain the string '$LineToReplace'. Continuing..." -Verbose
                            $LineLineCheck += $obj1
                        }
                        # If $LineToReplace is NOT a string within the line, then do NOT add anything to $LineLineCheck.
                        # The subsequent if statement will be responsible for throwing the error.
                        if (! $($TextFileSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextFileSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', and it DOES NOT contain the string '$LineToReplace'. Line number $obj1 will not be touched." -Verbose
                            $BadMatches += $obj1
                        }
                    }
                }
                if (! $($LineLineCheck -gt 0)) {
                    Write-Host "The contents of the ENTIRE lines for Line Number(s) $([string]$PossibleLineLineNumbers) do NOT 100% equal the `$LineToReplace '$LineToReplace'."
                    Write-Host "Also, these line(s) do NOT contain the string '$LineToReplace'." 
                    Write-Host "Please ensure `$LineToReplace is either equal to the entire line you would like to replace, or matches a string within the line you would like to replace. Halting!"
                    Write-Error "Please ensure `$LineToReplace is either equal to the entire line you would like to replace, or matches a string within the line you would like to replace. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                # Check to see if the content of every Line Number in $LineLineCheck is the SAME EXACT PATTERN. 
                # It might be that $LineToReplace is NOT an ENTIRE LINE, in which case the content of the referenced line numbers in $LineLineCheck,
                # while they certainly reference line numbers that contain the string $LineToReplace, the full contents of each lines may not be equal
                # If they are equal, $PotentialPatterns will remain $null, $LineToReplace will be redefined, and $UpdatedPossibleLineLineNumbers will be set
                # If they are NOT equal, ask the user which line represents the pattern of the ENTIRE LINE that he/she wants to replace 
                $PotentialPatterns = @()
                For ($loop=0; $loop -lt $LineLineCheck.Count; $loop++) {
                    $LineLineCheckWithoutCurrentLoopElement = foreach ($obj1 in $LineLineCheck) {
                        if ($obj1 -ne $($LineLineCheck[$loop])) {
                            $obj1
                        }
                    }
                    foreach ($obj1 in $LineLineCheckWithoutCurrentLoopElement) {
                        $SourceArrayElementContent = $TextFileSourceContent[$($LineLineCheck[$loop]-1)]
                        $RemainderArrayElementContent = $TextFileSourceContent[$($obj1-1)]
                        if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                            Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                            if ($PotentialPatterns -notcontains $($TextFileSourceContent[$($LineLineCheck[$loop]-1)])) {
                                $PotentialPatterns += $($TextFileSourceContent[$($LineLineCheck[$loop]-1)])
                            }
                        }
                    }
                }
                # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
                if (! $($PotentialPatterns.Count -gt 0)) {
                    Write-Host "The content of each line for lines $([string]$LineLineCheck) is the same. Defining `$LineToReplace. Continuing..."
                    # Arbitrarily choosing Index 0 since all of the elements in $LineLineCheckContent are the same
                    $LineToReplace = $TextFileSourceContent[$($LineLineCheck[0]-1)]
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck
                }
                if ($PotentialPatterns.Count -gt 0) {
                    Write-Host "The content of line numbers $([string]$LineLineCheck) are not all exactly the same."
                    Write-Host "Choices for unique patterns are as follows:"
                    Write-Host "NOTE: There is one (1) space between the ')' character and the beginning of the actual pattern"
                    For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                    }
                    $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        $loop+1
                    }
                    $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                    if ($ValidPatternChoices -notcontains $PatternChoice) {
                        Write-Host "$PatternChoice is not a valid choice. Valid choices are as follows:"
                        [string]$ValidPatternChoices -replace " ",", "
                         $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                        if ($ValidPatternChoices -notcontains $PatternChoice) {
                            Write-Host "$PatternChoice is not a valid choice. Halting!"
                            Write-Error "$PatternChoice is not a valid choice. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
                    $LineToReplace = $PotentialPatterns[$($PatternChoice-1)]
                    $LineLineCheck2 = @()
                    foreach ($obj1 in $LineLineCheck) {
                        if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                            $LineLineCheck2 += $obj1
                        }
                    }
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck2
                }
            }
        }
        # If ONLY an array of $LineLineNumber is provided, we need to make sure that all of these lines are the SAME EXACT pattern
        # Outputs $UpdatedPossibleLineLineNumbers and $LineToReplace, or fails
        if ($LineToReplace -eq $null -and $LineLineNumber -ne $null) {
            # Check to see if the content of every Line Number in $LineLineCheck is the SAME EXACT PATTERN. 
            # If they are equal, $PotentialPatterns will remain $null, $LineToReplace will be redefined, and $UpdatedPossibleLineLineNumbers will be set
            # If they are NOT equal, ask the user which line represents the pattern of the ENTIRE LINE that he/she wants to replace 
            $PotentialPatterns = @()
            For ($loop=0; $loop -lt $LineLineNumber.Count; $loop++) {
                $LineLineCheckWithoutCurrentLoopElement = foreach ($obj1 in $LineLineNumber) {
                    if ($obj1 -ne $($LineLineNumber[$loop])) {
                        $obj1
                    }
                }
                foreach ($obj1 in $LineLineCheckWithoutCurrentLoopElement) {
                    $SourceArrayElementContent = $TextFileSourceContent[$($LineLineNumber[$loop]-1)]
                    $RemainderArrayElementContent = $TextFileSourceContent[$($obj1-1)]
                    if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                        Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                        if ($PotentialPatterns -notcontains $($TextFileSourceContent[$($LineLineNumber[$loop]-1)])) {
                            $PotentialPatterns += $($TextFileSourceContent[$($LineLineNumber[$loop]-1)])
                        }
                    }
                }
            }
            # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
            if (! $($PotentialPatterns.Count -gt 0)) {
                Write-Host "The content of each line for lines $([string]$LineLineNumber) is the same. Defining `$LineToReplace. Continuing..."
                # Arbitrarily choosing Index 0 since all of the elements in $LineLineCheckContent are the same
                $LineToReplace = $TextFileSourceContent[$($LineLineNumber[0]-1)]
                $UpdatedPossibleLineLineNumbers = $LineLineCheck
            }
            if ($PotentialPatterns.Count -gt 0) {
                Write-Host "The content of line numbers $([string]$LineLineNumber) are not all exactly the same."
                Write-Host "Choices for unique patterns are as follows:"
                Write-Host "NOTE: There is one (1) space between the ')' character and the beginning of the actual pattern"
                For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                    "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                }
                $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                    $loop+1
                }
                $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                if ($ValidPatternChoices -notcontains $PatternChoice) {
                    Write-Host "$PatternChoice is not a valid choice. Valid choices are as follows:"
                    [string]$ValidPatternChoices -replace " ",", "
                     $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                    if ($ValidPatternChoices -notcontains $PatternChoice) {
                        Write-Host "$PatternChoice is not a valid choice. Halting!"
                        Write-Error "$PatternChoice is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                # Redefine $LineToReplace and define $UpdatedPossibleLineLineNumbers
                $LineToReplace = $PotentialPatterns[$($PatternChoice-1)]
                $LineLineCheck2 = @()
                foreach ($obj1 in $LineLineNumber) {
                    if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        $LineLineCheck2 += $obj1
                    }
                }
                $UpdatedPossibleLineLineNumbers = $LineLineCheck2
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
    ## End Working Through Specific Validation Scenarios depending on $TextFormationType ##

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####

    # Outputs $UpdatedTextFileSourceContent
    if ($TextFormationType -eq "string") {
        # If the string is Unique in $TextFileSource or if User wants to replace ALL Occurrences...
        # Figure out if the user wants to replace ALL occurrences of the string, just one, or some of them
        if ($ReplaceAll -eq $null -and $ReplaceOne -eq $null -and $ReplaceSome -eq $null) {
            Write-Host "Defaulting to replacing ALL occurrences of '$StringToReplace'"
            Write-Host ""
            $UpdatedTextFileSourceContent = $TextFileSourceContent -replace "$StringToReplace","$ReplacementText"
        }
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            Write-Host "Defaulting to replacing ALL occurrences of '$StringToReplace'"
            Write-Host ""
            $UpdatedTextFileSourceContent = $TextFileSourceContent -replace "$StringToReplace","$ReplacementText"
        }
        if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
            # Begin Determine $FinalStringLineNumber #
            if ($OccurrenceOfString -eq "last" ) {
                [int]$FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfString -eq "first") {
                [int]$FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers.Count -eq 1) {
                [int]$FinalStringLineNumber = $UpdatedStringLineNumbers[0]
            }
            if ($UpdatedStringLineNumbers.Count -gt 1 -and $OccurrenceOfString -eq $null) {
                $StringLinesContent = foreach ($obj1 in $UpdatedStringLineNumbers) {
                    $TextFileSourceContent[$obj1]
                }
                $ValidStringLineIndexNumbers =  foreach ($obj1 in $UpdatedStringLineNumbers) {
                    $obj1-1
                }
                $StringLinesChoices = foreach ($obj1 in $UpdatedStringLineNumbers) {
                    "$obj1"+") "+"$($TextFileSourceContent[$($obj1-1)])"
                }
                $ValidStringLinesChoices = $UpdatedStringLineNumbers

                if ($StringLineNumber -ne $null) {
                    Write-Host "You used the parameter `$StringLineNumber to indicate multiple line numbers (i.e. $([string]$StringLineNumber)), but you also specified the `$ReplaceOne parameter."
                    Write-Host "Please select ONE of the lines that you specified in the `$StringLineNumber parameter"
                }
                else {
                    Write-Host "The String '$StringToReplace' appears multiple times in $TextFileSource"
                }
                Write-Host "Lines that contain $StringToReplace are as follows:"
                $StringLinesChoices
                [int]$FinalStringLineNumber = Read-Host -Prompt "Please enter the line number that contains the string '$StringToReplace' that you would like to replace."
                if ($ValidStringLinesChoices -notcontains $FinalStringLineNumber) {
                    Write-Host "$FinalStringLineNumber is not a valid choice since it does not contain '$StringToReplace'."
                    Write-Host "Lines that contain $StringToReplace are as follows:"
                    $StringLinesChoices
                    [int]$FinalStringLineNumber = Read-Host -Prompt "Please enter the line number that contains the string '$StringToReplace' that you would like to replace."
                    if ($ValidStringLinesChoices -notcontains $FinalStringLineNumber) {
                        Write-Host "$FinalStringLineNumber is not a valid choice since it does not contain '$StringToReplace'. Halting!"
                        Write-Error "$FinalStringLineNumber is not a valid choice since it does not contain '$StringToReplace'. Halting!"
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
                [int]$FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfString -eq "first") {
                [int]$FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers.Count -eq 1 -and $OccurrenceOfString -eq $null) {
                [int]$FinalStringLineNumbers = $UpdatedStringLineNumbers[0]
            }
            if ($UpdatedStringLineNumbers.Count -gt 1 -and $OccurrenceOfString -eq $null) {
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
                [int]$FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfLine -eq "first") {
                [int]$FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers.Count -eq 1) {
                [int]$FinalLineLineNumber = $UpdatedPossibleLineLineNumbers[0]
            }
            if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and $OccurrenceOfLine -eq $null) {
                $LineLinesContent = foreach ($obj1 in $UpdatedPossibleLineLineNumbers) {
                    $TextFileSourceContent[$obj1]
                }
                $ValidLineLineIndexNumbers =  foreach ($obj1 in $UpdatedPossibleLineLineNumbers) {
                    $obj1-1
                }
                $LineLinesChoices = foreach ($obj1 in $UpdatedPossibleLineLineNumbers) {
                    "$obj1"+") "+"$($TextFileSourceContent[$($obj1-1)])"
                }
                $ValidLineLinesChoices = $UpdatedPossibleLineLineNumbers

                if ($LineLineNumber -ne $null) {
                    Write-Host "You used the parameter `$LineLineNumber to indicate multiple line numbers (i.e. $([string]$LineLineNumber)), but the parameter `$ReplaceOnewas used."
                    Write-Host "Please select ONE of the following line numbers:"
                }
                else {
                    Write-Host "The Line `$LineToReplace appears multiple times in $TextFileSource, but the parameter `$ReplaceOne was used."
                    Write-Host "Please select ONE of the following line numbers:"
                }
                $LineLinesChoices
                [int]$FinalLineLineNumber = Read-Host -Prompt "Please enter the line number that that you would like to replace."
                if ($ValidLineLinesChoices -notcontains $FinalLineLineNumber) {
                    Write-Host "The Line Number $FinalLineLineNumber is not a valid choice since it does not contain '$LineToReplace'."
                    Write-Host "Lines that contain $LineToReplace are as follows:"
                    $LineLinesChoices
                    [int]$FinalLineLineNumber = Read-Host -Prompt "Please enter the line number that that you would like to replace."
                    if ($ValidLineLinesChoices -notcontains $FinalLineLineNumber) {
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
                [int]$FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfLine -eq "first") {
                [int]$FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and $OccurrenceOfString -eq $null) {
                [int]$FinalStringLineNumbers = $UpdatedPossibleLineLineNumbers[0]
            }
            if ($UpdatedPossibleLineLineNumbers -gt 1 -and $OccurrenceOfLine -eq $null) {
                $FinalLineLineNumbers = $UpdatedPossibleLineLineNumbers
            }
            # End Determine $FinalLineLineNumbers #

            # Replace the Line in all Line Numbers in $LineLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalLineLineNumbers.Count; $loop++) {
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
                Write-Host "The Ending String '$EndingString' appears multiple times in $TextFileSource"
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
                Write-Host "The Beginning String '$BeginningString' appears multiple times in $TextFileSource"
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
        Write-Host ""
        $UpdatedTextFileSourceContent
    }
    # ...or create a new file
    if ($ReplacementType -eq "newfile") {
        Set-Content -Path $NewFileWithUpdatedText -Value $UpdatedTextFileSourceContent
        Write-Host ""
        $UpdatedTextFileSourceContent
    }
    ##### END Main Body #####

}
# String, ReplaceAll = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne WITHOUT specifying $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne WITH specifying ONE $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "17" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne WITH specifying MORE THAN ONE $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8, 17" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome WITHOUT specifying $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome WITH specifying ONE $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome WITH specifying MORE THAN ONE $StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8, 17" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>






# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8, 17" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "14" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "14, 22" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8, 17" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "14" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "14, 22, 30" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>







# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8, 17" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22, 30" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8, 17" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "22" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "22, 30" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>






# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1`"" `
-LineLineNumber "8, 22" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>


# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22, 30" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>


# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "user1" `
-LineLineNumber "8, 22" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "22" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESS
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "22, 30" `
-ReplaceOne "Yes" `
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



# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtzZCw1w8Nr/gY7kAw64HCl3L
# ffugggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSF3xmaehby
# jfo63jbBVhE5W5hfJTANBgkqhkiG9w0BAQEFAASCAQB+wFrypzLkKG4B/DGQy1Mt
# h1YIE34cXxkCHs8aNIha9+qYxVjSQ5TN8ubYdzSMEwOqtJ+O3BPgTIiK1mLpooh3
# LRhC1Ck3Ya/fONEN3aNoMA02wmnBmVvZYS1vnc7skI6lvQyIw96DhkEA+9aL5rgd
# yztNo42MFLX5zQy4IwmpNcCLfqIcwGJrLSVPwYMwGzBml6M7Upgmcj5A3y7sIFgJ
# KXbztdrOaVc8PClQgpouuQR52EPOePdSrhEJUZ3asuiz57UYq3+SmjXNu89rCnTv
# AX/RDBzij0NWpm2hDjx0WyCv0X9pFNmmGhzR6gRTUhbQ7Pak8pydnoDX1aaslu6r
# SIG # End signature block
