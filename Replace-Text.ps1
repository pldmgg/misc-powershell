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
        $TextFormationType = $(Read-Host -Prompt "WOuld you like to replace a string, and entire line, or a whole block of text? [string/line/block]"),

        [Parameter(Mandatory=$False)]
        $StringToReplace,

        [Parameter(Mandatory=$False)]
        [array]$StringLineNumber, # Which instance of $StringToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        $LineOccurrenceOfString, # Refers to either the "first" line that contains $StringToReplace , or the "last" line that contains $StringToReplace

        [Parameter(Mandatory=$False)]
        $StringInLineOccurrence, # For cases where $StringToReplace appears multiple times within a single line

        [Parameter(Mandatory=$False)]
        $LineToReplace,

        [Parameter(Mandatory=$False)]
        [array]$LineLineNumber, # Which instance of $LineToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        $LineOccurrenceOfLine, # Refers to either the "first" line that matches $LineToReplace, or the "last" line that matches $LineToReplace

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
        $EndingStringLineNumber

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

    # If used, convert $BeginningStringLineNumber and/or $EndingStringLineNumber to [int] object
    # Cannnot use [int] on the parameter(s) themselves because then the variables are no longer $null, they default to 0
    # which messes up logic later in the script that looks to see if they are $null
    if (! $([System.AppDomain]::CurrentDomain.GetAssemblies() | Select-String -Pattern "VisualBasic").Matches.Success) {
        Add-Type -Assembly Microsoft.VisualBasic
    }
    if ($BeginningStringLineNumber -ne $null) {
        # Make sure $BeginningStringLineNumber / $EndingStringLineNumber is numeric before using [int]
        if ([Microsoft.VisualBasic.Information]::IsNumeric($BeginningStringLineNumber)) {
            [int]$BeginningStringLineNumber = $BeginningStringLineNumber
        }
    }
    if ($EndingStringLineNumber -ne $null) {
        # Make sure $BeginningStringLineNumber / $EndingStringLineNumber is numeric before using [int]
        if ([Microsoft.VisualBasic.Information]::IsNumeric($EndingStringLineNumber)) {
            [int]$EndingStringLineNumber = $EndingStringLineNumber
        }
    }

    ##### END Variable/Parameter Transforms #####

    ##### BEGIN Parameter Validation #####

    ## Begin Basic Validation Of Which Parameters Can/Should Be Used Together ##

    # If $TextFormationType = "string", make sure only those parameters specific to this scenario are used
    if ($TextFormationType -eq "string") {
        $ParametersForFormationTypeString = @("StringToReplace","StringLineNumber","StringInLineOccurrence","StringOccurrenceOfLine","ReplaceAll","ReplaceSome","ReplaceOne")
        if ($LineToReplace -ne $null) {
            Write-Host "The parameter `$LineToReplace is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$LineToReplace is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineLineNumber -ne $null) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ne $null) {
            Write-Host "The parameter `$LineOccurrenceOfLine is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$LineOccurrenceOfLine is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BlockToReplace -ne $null) {
            Write-Host "The parameter `$BlockToReplace is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BlockToReplace is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningString -ne $null) {
            Write-Host "The parameter `$BeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringLineNumber -ne $null) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($OccurrenceOfBeginningString -ne $null) {
            Write-Host "The parameter `$OccurrenceOfBeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$OccurrenceOfBeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingString -ne $null) {
            Write-Host "The parameter `$EndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringLineNumber -ne $null) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($OccurrenceOfEndingString -ne $null) {
            Write-Host "The parameter `$OccurrenceOfEndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$OccurrenceOfEndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ne $null -and $StringLineNumber -ne $null) {
            Write-Host "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    # If $TextFormationType = "line", make sure only those parameters specific to this scenario are used
    if ($TextFormationType -eq "line") {
        $ParametersForFormationTypeLine = @("LineToReplace","LineLineNumber","LineOccurrenceOfLine","ReplaceAll","ReplaceSome","ReplaceOne")
        if ($StringToReplace -ne $null) {
            Write-Host "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringLineNumber -ne $null) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence -ne $null) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ne $null) {
            Write-Host "The parameter `$StringOccurrenceOfLine is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringOccurrenceOfLine is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BlockToReplace -ne $null) {
            Write-Host "The parameter `$BlockToReplace is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BlockToReplace is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningString -ne $null) {
            Write-Host "The parameter `$BeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringLineNumber -ne $null) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($OccurrenceOfBeginningString -ne $null) {
            Write-Host "The parameter `$OccurrenceOfBeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$OccurrenceOfBeginningString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingString -ne $null) {
            Write-Host "The parameter `$EndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringLineNumber -ne $null) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($OccurrenceOfEndingString -ne $null) {
            Write-Host "The parameter `$OccurrenceOfEndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$OccurrenceOfEndingString is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ne $null -and $LineLineNumber -ne $null) {
            Write-Host "Please use EITHER the parameter LineOccurrenceOfLine OR the parameter LineLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter LineOccurrenceOfLine OR the parameter LineLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    # If $TextFormationType = "block", make sure only those parameters specific to this scenario are used
    if ($TextFormationType -eq "block") {
        $ParametersForFormationTypeBlock = @("BlockToReplace","BeginningString","BeginningStringLineNumber","OccurrenceOfBeginningString","EndingString","EndingStringLineNumber","OccurrenceOfEndingString")
        if ($StringToReplace -ne $null) {
            Write-Host "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringLineNumber -ne $null) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence -ne $null) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ne $null) {
            Write-Host "The parameter `$StringOccurrenceOfLine is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringOccurrenceOfLine is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineToReplace -ne $null) {
            Write-Host "The parameter `$LineToReplace is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$LineToReplace is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineLineNumber -ne $null) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ne $null) {
            Write-Host "The parameter `$LineOccurrenceOfLine is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$LineOccurrenceOfLine is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($ReplaceAll -ne $null) {
            Write-Host "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            Write-Error "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($ReplaceOne -ne $null) {
            Write-Host "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            Write-Error "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($ReplaceSome -ne $null) {
            Write-Host "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            Write-Error "When `$TextFormationType  is set to `"block`", the parameters `$ReplaceAll, `$ReplaceOne, and `$ReplaceSome should NOT be used. The `$ReplaceX parameters are meant for use with `$TextFormationType `"string`" or `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
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

    # Only one "$ReplaceX" parameter should be used, or fail
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

    # Check to make sure $ReplaceAll param is appropriate, or Fix and Continue
    if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
        if ($StringLineNumber -ne $null) {
            Write-Verbose "If the parameter `$StringLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the string `$StringToReplace in the entire file $TextFileSource" -Verbose
            Write-Verbose "`$ReplaceOne will be used if `$StringLineNumber contains one line number. `$ReplaceSome will be used if `$StringLineNumber contains multiple line numbers." -Verbose
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
        if ($LineLineNumber -ne $null) {
            Write-Verbose "If the parameter `$LineLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the line `$LineToReplace in the entire file $TextFileSource" -Verbose
            Write-Verbose "`$ReplaceOne will be used if `$LineLineNumber contains one line number. `$ReplaceSome will be used if `$LineLineNumber contains multiple line numbers." -Verbose
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
        if ($StringInLineOccurrence -ne $null) {
            Write-Verbose "The parameter `$StringInLineOccurrence is meant to be used in cases where a single line contains multiple occurrences of `$StringToReplace" -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the line `$LineToReplace in the entire file $TextFileSource" -Verbose
            Write-Verbose "Removing the parameter `$ReplaceAll" -Verbose
            Remove-Variable -Name "ReplaceAll"
            if ($ReplaceSome -ne "Yes") {
                Write-Verbose "Using the parameter `$ReplaceSome" -Verbose
                $ReplaceSome = "Yes"
            }
        }
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
                        $ValidStringLineNumbersChoices = foreach ($obj1 in $ValidStringLineNumbers) {
                            "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
                        }
                        $ValidStringLineNumbersChoices
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
                            $ValidStringLineNumbersChoices
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
            if ($LineOccurrenceOfString -eq "last" ) {
                [int]$FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($LineOccurrenceOfString -eq "first") {
                [int]$FinalStringLineNumber = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers.Count -eq 1) {
                [int]$FinalStringLineNumber = $UpdatedStringLineNumbers[0]
            }
            if ($UpdatedStringLineNumbers.Count -gt 1 -and $LineOccurrenceOfString -eq $null) {
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

            # Begin Determine if $FinalStringLineNumber has one or more instances of $StringToReplace #
            # If so, then ask user which index to replace. If not, move on to $UpdatedTextFileSourceContent
            $FinalStringLineNumberContent = $TextFileSourceContent[$FinalStringLineNumber-1]
            $StringToReplaceInLineIndexes = $($FinalStringLineNumberContent | Select-String -AllMatches "$StringToReplace").Matches.Index
            if ($StringToReplaceInLineIndexes.Count -gt 1) {
                [array]$FinalStringLineSplitPrep = $($FinalStringLineNumberContent -replace "$StringToReplace",";;;splithere;;;$StringToReplace;;;splithere;;;") -split ";;;splithere;;;"
                [System.Collections.ArrayList]$FinalStringLineSplit = $FinalStringLineSplitPrep
                $StringToReplaceInLineContext = $FinalStringLineSplit | Select-String -AllMatches "$StringToReplace" -Context 1 | foreach {
                    "$($($_.Context).PreContext)"+"$($_.Line)"+"$($($_.Context).PostContext)"
                }
                $StringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                    "$($loop+1)"+") "+"..."+"$($StringToReplaceInLineContext[$loop])"+"..."
                }
                $ValidStringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                    $loop+1
                }
                if ($StringInLineOccurrence -eq $null) {
                    Write-Host "The line number $FinalStringLineNumber contains $($StringToReplaceInLineIndexes.Count) occurrences of the string $StringToReplace"
                    Write-Host "Context for these occurrences is as follows:"
                    $StringToReplaceInLineChoices
                    $StringInLineOccurrence = Read-Host -Prompt "Please select the context for the string '$StringToReplace' in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                    if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                        Write-Host "$StringInLineOccurrence is not a valid choice. Valid choices are as follows:"
                        $StringToReplaceInLineChoices
                        $StringInLineOccurrence = Read-Host -Prompt "Please select the context for the string '$StringToReplace' in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                        if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                            Write-Host "$StringInLineOccurrence is not a valid choice. Halting!"
                            Write-Error "$StringInLineOccurrence is not a valid choice. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    $UpdatedStringToReplace = $StringToReplaceInLineContext[$StringInLineOccurrence-1]
                    $UpdatedReplacementString = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"
                }
                if ($StringInLineOccurrence -ne $null) {
                    # Validate $StringInLineOccurrence
                    if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                        Write-Host "$StringInLineOccurrence is not a valid choice. Valid choices are as follows:"
                        $StringToReplaceInLineChoices
                        $StringInLineOccurrence = Read-Host -Prompt "Please select the number that corresponds to the context of the string '$StringToReplace' in line number $FinalStringLineNumber that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                        if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                            Write-Host "$StringInLineOccurrence is not a valid choice. Halting!"
                            Write-Error "$StringInLineOccurrence is not a valid choice. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    $UpdatedStringToReplace = $StringToReplaceInLineContext[$StringInLineOccurrence-1]
                    $UpdatedReplacementString = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"
                }
            }
            if (! $StringToReplaceInLineIndexes.Count -gt 1) {
                $UpdatedStringToReplace = $StringToReplace
                $UpdatedReplacementString = $ReplacementText
            }

            # Replace the String in Line Number $FinalStringLineNumber
            $UpdatedTextFileSourceContent = @()
            $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalStringLineNumber-2)]
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalStringLineNumber-1)] -replace "$UpdatedStringToReplace","$UpdatedReplacementString"
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$FinalStringLineNumber..$($TextFileSourceContent.Count -1)]
        }
        if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
            # Begin Determine $FinalStringLineNumbers #
            if ($LineOccurrenceOfString -eq "last") {
                [int]$FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($LineOccurrenceOfString -eq "first") {
                [int]$FinalStringLineNumbers = $($UpdatedStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedStringLineNumbers.Count -eq 1 -and $LineOccurrenceOfString -eq $null) {
                [int]$FinalStringLineNumbers = $UpdatedStringLineNumbers[0]
            }
            if ($UpdatedStringLineNumbers.Count -gt 1 -and $LineOccurrenceOfString -eq $null) {
                $FinalStringLineNumbers = $UpdatedStringLineNumbers
            }
            # End Determine $FinalStringLineNumbers #

            # Begin Determine if each line in $FinalStringLineNumbers has one or more instances of $StringToReplace #
            # If so, then ask user which index to replace. If not, move on to $UpdatedTextFileSourceContent
            $UpdatedStringToReplaceObjects = @()
            foreach ($obj1 in $FinalStringLineNumbers) {
                $FinalStringLineNumberContent = $TextFileSourceContent[$obj1-1]
                $StringToReplaceInLineIndexes = $($FinalStringLineNumberContent | Select-String -AllMatches "$StringToReplace").Matches.Index
                if ($StringToReplaceInLineIndexes.Count -gt 1) {
                    [array]$FinalStringLineSplitPrep = $($FinalStringLineNumberContent -replace "$StringToReplace",";;;splithere;;;$StringToReplace;;;splithere;;;") -split ";;;splithere;;;"
                    [System.Collections.ArrayList]$FinalStringLineSplit = $FinalStringLineSplitPrep
                    $StringToReplaceInLineContext = $FinalStringLineSplit | Select-String -AllMatches "$StringToReplace" -Context 1 | foreach {
                        "$($($_.Context).PreContext)"+"$($_.Line)"+"$($($_.Context).PostContext)"
                    }
                    $StringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                        "$($loop+1)"+") "+"..."+"$($StringToReplaceInLineContext[$loop])"+"..."
                    }
                    $ValidStringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                        $loop+1
                    }
                    if ($StringInLineOccurrence -ne $null) {
                        # Validate $StringInLineOccurrence
                        if ($($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringInLineOccurrence = $StringLineNumber.Split(",").Trim()
                        }
                        if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringInLineOccurrence = $StringInLineOccurrence
                        }
                        $InLineOccurrenceValidation = @()
                        foreach ($Occurrence in $StringInLineOccurrence) {
                            if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                Write-Host "$Occurrence is not a valid choice."
                                $InLineOccurrenceValidation += $Occurrence
                            }
                        }
                        if ($InLineOccurrenceValidation -gt 0) {
                            Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                            $StringToReplaceInLineChoices
                            $StringInLineOccurrence = Read-Host -Prompt "Please select one or more numbers (separated by commas) that correspond to the context of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears in line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                            if ($($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringInLineOccurrence = $StringInLineOccurrence.Split(",").Trim()
                            }
                            if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringInLineOccurrence = $StringInLineOccurrence
                            }
                            $InLineOccurrenceValidation = @()
                            foreach ($Occurrence in $StringInLineOccurrence) {
                                if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                    Write-Host "$Occurrence is NOT a valid choice."
                                    $InLineOccurrenceValidation += $Occurrence
                                }
                            }
                            if ($InLineOccurrenceValidation -gt 0) {
                                Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        foreach ($Occurrence in $StringInLineOccurrence) {
                            $UpdatedStringToReplace = $StringToReplaceInLineContext[$Occurrence-1]
                            $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                            # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                            New-Variable -Name "UpdatedStringToReplaceLine$Occurrence" -Value $(
                                New-Object PSObject -Property @{
                                    LineNum                                         = $obj1
                                    OccurrenceInLine                                = $Occurrence
                                    OriginalLineContent                             = $FinalStringLineNumberContent
                                    UpdatedStringToReplace                          = $UpdatedStringToReplace
                                    UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                }
                            )

                            $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$Occurrence" -ValueOnly)
                        }
                    }
                    if ($StringInLineOccurrence -eq $null) {
                        Write-Host "The line number $obj1 contains $($StringToReplaceInLineIndexes.Count) occurrences of the string $StringToReplace"
                        Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                        $StringToReplaceInLineChoices
                        $StringInLineOccurrence = Read-Host -Prompt "Please select one or more numbers (separated by commas) that correspond to the context of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears in line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                        if ($($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringInLineOccurrence = $StringInLineOccurrence.Split(",").Trim()
                        }
                        if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringInLineOccurrence = $StringInLineOccurrence
                        }
                        $InLineOccurrenceValidation = @()
                        foreach ($Occurrence in $StringInLineOccurrence) {
                            if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                Write-Host "$Occurrence is NOT a valid choice."
                                $InLineOccurrenceValidation += $Occurrence
                            }
                        }
                        if ($InLineOccurrenceValidation -gt 0) {
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices."
                            Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                            $StringToReplaceInLineChoices
                            $StringInLineOccurrence = Read-Host -Prompt "Please select one or more numbers (separated by commas) that correspond to the context of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears in line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                            if ($($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringInLineOccurrence = $StringLineNumber.Split(",").Trim()
                            }
                            if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringInLineOccurrence = $StringInLineOccurrence
                            }
                            $InLineOccurrenceValidation = @()
                            foreach ($Occurrence in $StringInLineOccurrence) {
                                if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                    Write-Host "$Occurrence is NOT a valid choice."
                                    $InLineOccurrenceValidation += $Occurrence
                                }
                            }
                            if ($InLineOccurrenceValidation -gt 0) {
                                Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        foreach ($Occurrence in $StringInLineOccurrence) {
                            $UpdatedStringToReplace = $StringToReplaceInLineContext[$Occurrence-1]
                            $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                            # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                            New-Variable -Name "UpdatedStringToReplaceLine$Occurrence" -Value $(
                                New-Object PSObject -Property @{
                                    LineNum                                         = $obj1
                                    OccurrenceInLine                                = $Occurrence
                                    OriginalLineContent                             = $FinalStringLineNumberContent
                                    UpdatedStringToReplace                          = $UpdatedStringToReplace
                                    UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                }
                            )

                            $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$Occurrence" -ValueOnly)
                        }
                    }
                }
            }

            # Replace the Strings in all Line Numbers in $FinalStringLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalStringLineNumbers.Count; $loop++) {
                if ($StringToReplaceInLineIndexes -gt 0) {
                    # $ReplacementLine should be updated every time the $loop2 iterates until we're left with a fully updated line
                    For ($loop2=0; $loop2 -lt $UpdatedStringToReplaceObjects.Count; $loop2++) {
                        if ($($FinalStringLineNumbers[$loop] -eq $($UpdatedStringToReplaceObjects[$loop2]).LineNum)) {
                            if ($loop2 -eq 0) {
                                $ReplacementLine = $($UpdatedStringToReplaceObjects[$loop2]).OriginalLineContent -replace "$($($UpdatedStringToReplaceObjects[$loop2]).UpdatedStringToReplace)","$($($UpdatedStringToReplaceObjects[$loop2]).UpdatedStringToReplaceWithReplacementText)"
                            }
                            if ($loop2 -gt 0) {
                                $ReplacementLine = $ReplacementLine -replace "$($($UpdatedStringToReplaceObjects[$loop2]).UpdatedStringToReplace)","$($($UpdatedStringToReplaceObjects[$loop2]).UpdatedStringToReplaceWithReplacementText)"
                            }
                        }
                    }
                }
                if (! $UpdatedStringToReplaceObjects -gt 0) {
                    $ReplacementLine = $TextFileSourceContent[$($FinalStringLineNumbers[$loop]-1)] -replace "$StringToReplace","$ReplacementText"
                }
                if ($loop -eq 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalStringLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $ReplacementLine
                    $NextLoopStartingPoint = $FinalStringLineNumbers[$loop]
                }
                if ($loop -gt 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($FinalStringLineNumbers[$loop]-2)]
                    $UpdatedTextFileSourceContent += $ReplacementLine
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
            if ($LineOccurrenceOfLine -eq "last" ) {
                [int]$FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($LineOccurrenceOfLine -eq "first") {
                [int]$FinalLineLineNumber = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers.Count -eq 1) {
                [int]$FinalLineLineNumber = $UpdatedPossibleLineLineNumbers[0]
            }
            if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and $LineOccurrenceOfLine -eq $null) {
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
            if ($LineOccurrenceOfLine -eq "last") {
                [int]$FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($LineOccurrenceOfLine -eq "first") {
                [int]$FinalLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }
            if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and $LineOccurrenceOfLine -eq $null) {
                [int]$FinalStringLineNumbers = $UpdatedPossibleLineLineNumbers[0]
            }
            if ($UpdatedPossibleLineLineNumbers -gt 1 -and $LineOccurrenceOfLine -eq $null) {
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
            Write-Host "`$BeginningString is unique. Continuing..."
            # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
            $BeginningLine = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Line
            [int]$BeginningStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleEndingStringLineNumbersContent = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleEndingStringLineNumbersChoices = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            # Begin Determine $EndingStringLineNumber #
            if ($OccurrenceOfEndingString -eq "last" -and $EndingStringLineNumber -eq $null) {
                [int]$EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfEndingString -eq "first" -and $EndingStringLineNumber -eq $null) {
                [int]$EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }

            if ($EndingStringLineNumber -eq $null) {
                Write-Host "The Ending String '$EndingString' appears multiple times in $TextFileSource"
                Write-Host "You must enter the line number that contains `$EndingString that will bound the block of text that you would like to replace."
                Write-Host "Line Numbers that contain `$EndingString are as follows:"
                Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                $PossibleEndingStringLineNumbersChoices
                [int]$EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                    Write-Host "$EndingStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    $PossibleEndingStringLineNumbersChoices
                    if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                        Write-Host "$EndingStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$EndingStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($EndingStringLineNumber -ne $null -and $OccurrenceOfEndingString -eq $null) {
                if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                    Write-Host "$EndingStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                    $PossibleEndingStringLineNumbersChoices
                    [int]$EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($PossibleEndingStringLineNumbers -notcontains $EndingStringLineNumber) {
                        Write-Host "$EndingStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$EndingStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # Check to make sure $BeginningStringLineNumber is before $EndingStringLineNumber
            if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in $TextFileSource"
                Write-Host "Please select an Ending Line Number that comes AFTER the Beginning Line Number $BeginningStringLineNumber"
                Write-Host "Line Numbers that contain `$EndingString are as follows:"
                Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                $PossibleEndingStringLineNumbersChoices
                [int]$EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($BeginningLineNumber -gt $EndingStringLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in $TextFileSource. Halting!"
                    Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            # End Determine $EndingStringLineNumber #

            $BlockToReplace = $TextFileSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber-1))
        }
        # Check if $EndingString is Unique
        if ($($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -eq 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1) {
            Write-Host "`$EndingString is unique. Continuing..."
            # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
            $EndingLine = $($TextFileSourceContent | Select-String -Pattern "$EndingString").Line
            [int]$EndingStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleBeginningStringLineNumbersContent = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleBeginningStringLineNumbersChoices = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            # Begin Determine $BeginningStringLineNumber #
            if ($OccurrenceOfBeginningString -eq "last" -and $BeginningStringLineNumber -eq $null) {
                [int]$BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
            }
            if ($OccurrenceOfBeginningString -eq "first" -and $EndingStringLineNumber -eq $null) {
                [int]$BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
            }

            if ($BeginningStringLineNumber -eq $null) {
                Write-Host "The Beginning String '$BeginningString' appears multiple times in $TextFileSource"
                Write-Host "You must enter the line number that contains `$BeginningString that will bound the block of text that you would like to replace."
                Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                $PossibleBeginningStringLineNumbersChoices
                [int]$BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                    Write-Host "$BeginningStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    $PossibleBeginningStringLineNumbersChoices
                    if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                        Write-Host "$BeginningStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$BeginningStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($BeginningStringLineNumber -ne $null -and $OccurrenceOfEndingString -eq $null) {
                if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                    Write-Host "$BeginningStringLineNumber is not a valid choice."
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                    $PossibleBeginningStringLineNumbersChoices
                    [int]$BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($PossibleBeginningStringLineNumbers -notcontains $BeginningStringLineNumber) {
                        Write-Host "$BeginningStringLineNumber is not a valid choice. Halting!"
                        Write-Error "$BeginningStringLineNumber is not a valid choice. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            # Check to make sure $BeginningStringLineNumber is before $EndingStringLineNumber
            if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in $TextFileSource"
                Write-Host "Please select a Beginning Line Number that comes BEFORE the Ending Line Number $EndingStringLineNumber"
                Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                $PossibleBeginningStringLineNumbersChoices
                [int]$BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                if ($BeginningLineNumber -gt $EndingStringLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in $TextFileSource. Halting!"
                    Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in $TextFileSource. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            # End Determine $BeginningStringLineNumber #

            $BlockToReplace = $TextFileSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber))
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
# String, ReplaceAll = SUCCESS = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>


#### BEGIN MULTIPLE STRING MATCHES PER LINE TESTING #####
# String, ReplaceOne, WITHOUT specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne, WITH specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringInLineOccurrence "2" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne, WITH specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8" `
-StringInLineOccurrence "2" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITHOUT $StringInLineOccurrence
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"

# String, ReplaceSome, WITH specifying $StringLineNumber, WITHOUT $StringInLineOccurrence
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

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringInLineOccurrence "2" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumber "8" `
-StringInLineOccurrence "2" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

#### END MULTIPLE STRING MATCHES PER LINE TESTING #####

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
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "sudo" `
-LineLineNumber "22, 30" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>



### BEGIN TESTING FOR BLOCKS ###

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-BeginningStringLineNumber "8" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = Success
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-BeginningStringLineNumber "8" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-EndingString "shell: `"/bin/bash`"" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-BeginningStringLineNumber "8" `
-EndingString "shell: `"/bin/bash`"" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringLineNumber "16" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "user1" `
-BeginningStringLineNumber "8" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringLineNumber "16" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "- name:" `
-EndingString "shell: `"/bin/bash`"1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "- name:" `
-BeginningStringLineNumber "8" `
-EndingString "shell: `"/bin/bash`"1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "- name:" `
-EndingStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "- name:" `
-BeginningStringLineNumber "8" `
-EndingStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUEKVJIqlr8K7YzXCL6CM4M2s4
# PhugggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBS5xcIxUKhg
# J4oI9H4mrmPhqQz55jANBgkqhkiG9w0BAQEFAASCAQBE4tU5dMQdVTB2bvVKh1AF
# sqTmdaAkSBq2zdvlPUwL53ec2FEsQGJhOLu1XakWLC97AG5lGhR+8NNR7rLRi378
# 2CiNeo4cCdw3w+iNOOOTl6xbavX6A0oPUjmGY0ATK8mUPJAmKKbuFGkq03I03Z3I
# JXFaPfRO/CYeZvWxKdYRw7xvspWroZm8ETs+RMfo5EmHSi0Yzfk/tDMMi4+NUx4h
# 6eZOn6/Q66e3w8qsonPmD5i5DAbdOnj3OmA77pizE3SVuKuFJrlU9zdcb1UUxkj1
# +fG/XoXcSbkQOarw6+Hdi1isnyxUx0JAHacy6x82g6M6vAwyxKJil+FHVuVl/VEM
# SIG # End signature block
