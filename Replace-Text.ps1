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
        $TextFormationType = $(Read-Host -Prompt "Would you like to replace a string, and entire line, or a whole block of text? [string/line/block]"),

        [Parameter(Mandatory=$False)]
        $StringToReplace,

        [Parameter(Mandatory=$False)]
        [array]$StringLineNumber, # Which instance of $StringToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        [array]$StringOccurrenceOfLine, # Refers to either the "first" line that contains $StringToReplace , or the "last" line that contains $StringToReplace

        [Parameter(Mandatory=$False)]
        [array]$StringInLineOccurrence, # For cases where $StringToReplace appears multiple times within a single line

        [Parameter(Mandatory=$False)]
        $StringLineNumberVSOccurrenceHashTable, # HashTable where Key is Line Number and Value is Nth occurrence of string in line

        [Parameter(Mandatory=$False)]
        $LineToReplace,

        [Parameter(Mandatory=$False)]
        [array]$LineLineNumber, # Which instance of $LineToReplace do you want to replace if there are multiple?

        [Parameter(Mandatory=$False)]
        [array]$LineOccurrenceOfLine, # Refers to either the "first" line that matches $LineToReplace, or the "last" line that matches $LineToReplace

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
        $BeginningStringOccurrenceOfLine,

        [Parameter(Mandatory=$False)]
        $BeginningStringLineNumber,

        [Parameter(Mandatory=$False)]
        $EndingString,

        [Parameter(Mandatory=$False)]
        $EndingStringOccurrenceOfLine,

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

    if ($($StringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$StringOccurrenceOfLine = $StringOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($StringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$StringOccurrenceOfLine = $StringOccurrenceOfLine
    }

    if ($($StringOccurrenceInLine | Select-String -Pattern ",").Matches.Success) {
        [array]$StringOccurrenceInLine = $StringOccurrenceInLine.Split(",").Trim()
    }
    if (! $($StringOccurrenceInLine | Select-String -Pattern ",").Matches.Success) {
        [array]$StringOccurrenceInLine = $StringOccurrenceInLine
    }

    if ($($LineOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$LineOccurrenceOfLine = $LineOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($LineOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$LineOccurrenceOfLine = $LineOccurrenceOfLine
    }

    if ($($BeginningStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringLineNumber = $BeginningStringLineNumber.Split(",").Trim()
    }
    if (! $($BeginningStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringLineNumber = $BeginningStringLineNumber
    }

    if ($($EndingStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringLineNumber = $EndingStringLineNumber.Split(",").Trim()
    }
    if (! $($EndingStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringLineNumber = $EndingStringLineNumber
    }

    if ($($BeginningStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringOccurrenceOfLine = $BeginningStringOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($BeginningStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringOccurrenceOfLine = $BeginningStringOccurrenceOfLine
    }

    if ($($EndingStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringOccurrenceOfLine = $EndingStringOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($EndingStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringOccurrenceOfLine = $EndingStringOccurrenceOfLine
    }

    # If used, convert $BeginningStringLineNumber and/or $EndingStringLineNumber to [int] object
    # Cannnot use [int] on the parameter(s) themselves because then the variables are no longer $null, they default to 0
    # which messes up logic later in the script that looks to see if they are $null
    if (! $([System.AppDomain]::CurrentDomain.GetAssemblies() | Select-String -Pattern "VisualBasic").Matches.Success) {
        Add-Type -Assembly Microsoft.VisualBasic
    }
    if ($BeginningStringLineNumber.Count -ge 1) {
        # Make sure $BeginningStringLineNumber / $EndingStringLineNumber is numeric before using [int]
        if ([Microsoft.VisualBasic.Information]::IsNumeric($BeginningStringLineNumber)) {
            [int]$BeginningStringLineNumber = $BeginningStringLineNumber
        }
    }
    if ($EndingStringLineNumber -ge 1) {
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
        if ($LineLineNumber -ge 1) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ge 1) {
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
        if ($BeginningStringLineNumber -ge 1) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringOccurrenceOfLine -ge 1) {
            Write-Host "The parameter `$BeginningStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BeginningStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
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
        if ($EndingStringLineNumber -ge 1) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine -ge 1) {
            Write-Host "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ge 1 -and $StringLineNumber -ge 1) {
            Write-Host "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence -ge 1 -and $StringLineNumberVSOccurrenceHashTable -ne $null) {
            Write-Host "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringLineNumberVSOccurrenceHashTable. Halting!"
            Write-Error "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringLineNumberVSOccurrenceHashTable. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringLineNumberVSOccurrenceHashTable -ne $null -and $ReplaceSome -eq $null) {
            Write-Host "The parameter `$StringLineNumberVSOccurrenceHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
            Write-Error "The parameter `$StringLineNumberVSOccurrenceHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
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
        if ($StringLineNumber -ge 1) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence -ge 1) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ge 1) {
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
        if ($BeginningStringLineNumber -ge 1) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringOccurrenceOfLine -ge 1) {
            Write-Host "The parameter `$BeginningStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BeginningStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
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
        if ($EndingStringLineNumber -ge 1) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine -ge 1) {
            Write-Host "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ge 1 -and $LineLineNumber -ge 1) {
            Write-Host "Please use EITHER the parameter LineOccurrenceOfLine OR the parameter LineLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter LineOccurrenceOfLine OR the parameter LineLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    # If $TextFormationType = "block", make sure only those parameters specific to this scenario are used
    if ($TextFormationType -eq "block") {
        $ParametersForFormationTypeBlock = @("BlockToReplace","BeginningString","BeginningStringLineNumber","BeginningStringOccurrenceOfLine","EndingString","EndingStringLineNumber","EndingStringOccurrenceOfLine")
        if ($StringToReplace -ne $null) {
            Write-Host "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringToReplace is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringLineNumber -ge 1) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence -ge 1) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine -ge 1) {
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
        if ($LineLineNumber -ge 1) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine -ge 1) {
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
        if ($BeginningStringOccurrenceOfLine -ge 1 -and $BeginningStringLineNumber -ge 1) {
            Write-Host "Please use EITHER the parameter BeginningStringOccurrenceOfLine OR the parameter BeginningStringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter BeginningStringOccurrenceOfLine OR the parameter BeginningStringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine -ge 1 -and $EndingStringLineNumber -ge 1) {
            Write-Host "Please use EITHER the parameter EndingStringOccurrenceOfLine OR the parameter EndingStringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter EndingStringOccurrenceOfLine OR the parameter EndingStringLineNumber. Halting!"
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
        if ($StringLineNumber -ge 1) {
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
        if ($LineLineNumber -ge 1) {
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
        if ($StringInLineOccurrence -ge 1) {
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
        if ($StringToReplace -eq $null -and $StringLineNumber -ge 1) {
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

            # If $StringLineNumber is present, we can narrow down the list of $PossibleStringLineNumbers, but we also have to 
            # validate that $TextFileSourceContent[$StringLineNumber] actually contains $StringToReplace
            if ($StringLineNumber -ge 1) {
                $StringLineCheck = @()
                foreach ($LineNumber in $StringLineNumber) {
                    if ($($TextFileSourceContent[$LineNumber-1] | Select-String -Pattern "$StringToReplace").Matches.Success) {
                        Write-Host "The Line Number $LineNumber (i.e. Index $($LineNumber-1)) contains the string '$StringToReplace'. Continuing..."
                        $StringLineCheck += $LineNumber
                    }
                }
                # Ensure the Line Numbers in $StringLineCheck are sorted by ascending
                $StringLineCheck = $StringLineCheck | Sort-Object
                if (! $StringLineCheck.Count -gt 0) {
                    Write-Host "Line Number $StringLineNumber does NOT contain '$StringToReplace'. Halting!"
                    Write-Error "Line Number $StringLineNumber does NOT contain '$StringToReplace'. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                    if ($StringOccurrenceOfLine.Count -eq 1) {
                        if ($StringOccurrenceOfLine -eq "last") {
                            [int]$UpdatedStringLineNumbers = $($StringLineCheck | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($StringOccurrenceOfLine -eq "first") {
                            [int]$UpdatedStringLineNumbers = $($StringLineCheck | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($StringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedStringLineNumbers = @()
                            for ($loop=0; $loop -lt $StringLineCheck.Count; $loop++) {
                                foreach ($obj1 in $StringOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedStringLineNumbers += $StringLineCheck[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($StringOccurrenceOfLine.Count -gt 1) {
                        $UpdatedStringLineNumbers = for ($loop=0; $loop -lt $StringLineCheck.Count; $loop++) {
                            foreach ($obj2 in $StringOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $StringLineCheck[$loop]
                                }
                            }
                        }
                    }
                    if ($StringLineCheck.Count -eq 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                        $UpdatedStringLineNumbers = $StringLineCheck
                    }
                    if ($StringLineCheck.Count -gt 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                        $UpdatedStringLineNumbers = $StringLineCheck
                    }
                }
                if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
                    if ($StringOccurrenceOfLine.Count -eq 1) {
                        if ($StringOccurrenceOfLine -eq "last") {
                            [int]$UpdatedStringLineNumbers = $($StringLineCheck | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($StringOccurrenceOfLine -eq "first") {
                            [int]$UpdatedStringLineNumbers = $($StringLineCheck | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($StringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedStringLineNumbers = @()
                            for ($loop=0; $loop -lt $StringLineCheck.Count; $loop++) {
                                foreach ($obj1 in $StringOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedStringLineNumbers += $StringLineCheck[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($StringOccurrenceOfLine.Count -gt 1) {
                        $UpdatedStringLineNumbers = for ($loop=0; $loop -lt $StringLineCheck.Count; $loop++) {
                            foreach ($obj2 in $StringOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $StringLineCheck[$loop]
                                }
                            }
                        }
                    }
                    if ($StringLineCheck.Count -eq 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                        $UpdatedStringLineNumbers = $StringLineCheck
                    }
                    if ($StringLineCheck.Count -gt 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                        Write-Host "The parameter `$ReplaceOne was used, however, multiple line numbers were specified using the `$StringLineNumber parameter, and more than one line contains the string:`n$StringToReplace"
                        Write-Host "Lines that contain the string '$StringToReplace' are as follows:"
                        $PotentialStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
                        }
                        $ValidStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        $PotentialStringLineChoices
                        $StringLineChoices = Read-Host -Prompt "Please select one choice that corresponds to the Nth occurrence of line that contains the occurrence of '$StringToReplace' that you would like to replace. [$([string]$ValidStringLineChoices -replace " ","/")]"
                        if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                        }
                        if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$StringLineChoices = $StringLineChoices
                        }
                        # Since this is $ReplaceOne, check to make sure $LineLineChoices only has 1 element
                        if ($StringLineChoices.Count -gt 1) {
                            Write-Host "The parameter `$ReplaceOne allows for only one string in one line to be replaced, and more than one choice was selected."
                            $StringLineChoices = Read-Host -Prompt "Please select one choice that corresponds to the Nth occurrence of line that contains the occurrence of '$StringToReplace' that you would like to replace. [$([string]$ValidStringLineChoices -replace " ","/")]"
                            if ($StringLineChoices.Count -gt 1) {
                                Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                Write-Error "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        $InvalidStringLineChoices = @()
                        foreach ($obj1 in $StringLineChoices) {
                            if ($ValidStringLineChoices -notcontains $obj1) {
                                Write-Host "$obj1 is not a valid choice."
                                $InvalidStringLineChoices += $obj1
                            }
                        }
                        if ($InvalidStringLineChoices -ge 1) {
                            if ($InvalidStringLineChoices.Count -eq 1) {
                                Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Valid choices are as follows:"
                            }
                            if ($InvalidStringLineChoices.Count -gt 1) {
                                Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Valid choices are as follows:"
                            }
                            $ValidStringLineChoices
                            $StringLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '`$LineToReplace' [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                            }
                            if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices
                            }
                            $InvalidStringLineChoices = @()
                            foreach ($obj1 in $StringLineChoices) {
                                if ($ValidStringLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidStringLineChoices += $obj1
                                }
                            }
                            if ($InvalidStringLineChoices -ge 1) {
                                if ($InvalidStringLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                    Write-Error "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                }
                                if ($InvalidStringLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                    Write-Error "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                }
                                $global:FunctionResult = "1"
                                return
                            }
                        }

                        $UpdatedStringLineNumbers = foreach ($obj1 in $StringLineChoices) {
                            foreach ($obj2 in $PotentialStringLineChoices) {
                                $ChoicePosition = $obj2.IndexOf(")")
                                $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                if ($obj1 -eq $ChoiceNumber) {
                                    $LineNum
                                }
                            }
                        }
                    }
                }
            }
            if (! $StringLineNumber.Count -gt 0) {
                # If $StringToReplace appears multiple times in $TextFileSource, but the $StringLineNumber is not provided, 
                # and either $ReplaceSome or $ReplaceOne is used, prompt user to provide $StringLineNumber
                if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                    if ($StringLineNumberVSOccurrenceHashTable -ne $null) {
                        [array]$UpdatedStringLineNumbers = $StringLineNumberVSOccurrenceHashTable.Keys
                    }
                    if ( $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -eq 1) {
                        $UpdatedStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                    }
                    if ($($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -gt 1 -and $StringLineNumberVSOccurrenceHashTable -eq $null) {
                        $PotentialStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
                        }
                        $ValidStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        if ($StringOccurrenceOfLine.Count -eq 1) {
                            if ($StringOccurrenceOfLine -eq "last") {
                                [int]$UpdatedStringLineNumbers = $($PotentialStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                            }
                            if ($StringOccurrenceOfLine -eq "first") {
                                [int]$UpdatedStringLineNumbers = $($PotentialStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                            }
                            if ($StringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                                $UpdatedStringLineNumbers = @()
                                for ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                                    foreach ($obj1 in $StringOccurrenceOfLine) {
                                        if ($($loop+1) -eq $obj1) {
                                            $UpdatedStringLineNumbers += $PotentialStringLineNumbers[$loop]
                                        }
                                    }
                                    
                                }
                            }
                        }
                        if ($StringOccurrenceOfLine.Count -gt 1) {
                            $UpdatedStringLineNumbers = for ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                                foreach ($obj2 in $StringOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj2) {
                                        $PotentialStringLineNumbers[$loop]
                                    }
                                }
                            }
                        }
                        if ($PotentialStringLineNumbers.Count -eq 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                            $UpdatedStringLineNumbers = $PotentialStringLineNumbers
                        }
                        if ($PotentialStringLineNumbers.Count -gt 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                            Write-Host "The parameter `$ReplaceSome was used, however, no line numbers were specified using the `$StringLineNumber parameter, no Nth occurrence of a line that contains the string was specified using the `$StringOccurrenceOfLine parameter, and more than one line contains the string:`n$StringToReplace"
                            Write-Host "Lines that contain the string '$StringToReplace' are as follows:"
                            $PotentialStringLineChoices
                            $StringLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '$StringToReplace' [$([string]$ValidStringLineChoices -replace " ","/")]"
                            if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                            }
                            if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices
                            }
                            $InvalidStringLineChoices = @()
                            foreach ($obj1 in $StringLineChoices) {
                                if ($ValidStringLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidStringLineChoices += $obj1
                                }
                            }
                            if ($InvalidStringLineChoices -ge 1) {
                                if ($InvalidStringLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Valid choices are as follows:"
                                }
                                if ($InvalidStringLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Valid choices are as follows:"
                                }
                                $ValidStringLineChoices
                                $StringLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '$StringToReplace' [$([string]$ValidStringLineChoices -replace " ","/")]"
                                if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                    [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                                }
                                if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                    [array]$StringLineChoices = $StringLineChoices
                                }
                                $InvalidStringLineChoices = @()
                                foreach ($obj1 in $StringLineChoices) {
                                    if ($ValidStringLineChoices -notcontains $obj1) {
                                        Write-Host "$obj1 is not a valid choice."
                                        $InvalidStringLineChoices += $obj1
                                    }
                                }
                                if ($InvalidStringLineChoices -ge 1) {
                                    if ($InvalidStringLineChoices.Count -eq 1) {
                                        Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                        Write-Error "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                    }
                                    if ($InvalidStringLineChoices.Count -gt 1) {
                                        Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                        Write-Error "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                    }
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }

                            $UpdatedStringLineNumbers = foreach ($obj1 in $StringLineChoices) {
                                foreach ($obj2 in $PotentialStringLineChoices) {
                                    $ChoicePosition = $obj2.IndexOf(")")
                                    $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                    $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                    $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                    if ($obj1 -eq $ChoiceNumber) {
                                        $LineNum
                                    }
                                }
                            }
                        }
                    }
                }
                if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
                    if ( $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -eq 1) {
                        $UpdatedStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                    }
                    if ($($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Count -gt 1) {
                        $PotentialStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
                        }
                        $ValidStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        if ($StringOccurrenceOfLine.Count -eq 1) {
                            if ($StringOccurrenceOfLine -eq "last") {
                                [int]$UpdatedStringLineNumbers = $($PotentialStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                            }
                            if ($StringOccurrenceOfLine -eq "first") {
                                [int]$UpdatedStringLineNumbers = $($PotentialStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                            }
                            if ($StringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                                $UpdatedStringLineNumbers = @()
                                for ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                                    foreach ($obj1 in $StringOccurrenceOfLine) {
                                        if ($($loop+1) -eq $obj1) {
                                            $UpdatedStringLineNumbers += $PotentialStringLineNumbers[$loop]
                                        }
                                    }
                                    
                                }
                            }
                        }
                        if ($StringOccurrenceOfLine.Count -gt 1) {
                            $UpdatedStringLineNumbers = for ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                                foreach ($obj2 in $StringOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj2) {
                                        $PotentialStringLineNumbers[$loop]
                                    }
                                }
                            }
                        }
                        if ($PotentialStringLineNumbers.Count -eq 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                            $UpdatedStringLineNumbers = $PotentialStringLineNumbers
                        }
                        if ($PotentialStringLineNumbers.Count -gt 1 -and ! $StringOccurrenceOfLine.Count -gt 0) {
                            Write-Host "The parameter `$ReplaceOne was used, however, no line numbers were specified using the `$StringLineNumber parameter, and more than one line contains the string:`n$StringToReplace"
                            Write-Host "Lines that contain the string '$StringToReplace' are as follows:"
                            $PotentialStringLineChoices
                            $StringLineChoices = Read-Host -Prompt "Please select one (1) choice that corresponds to the Nth occurrence of line that contains '$StringToReplace' [$([string]$ValidStringLineChoices -replace " ","/")]"
                            if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                            }
                            if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$StringLineChoices = $StringLineChoices
                            }
                            # Since this is $ReplaceOne, check to make sure $StringLineChoices only has 1 element
                            if ($StringLineChoices.Count -gt 1) {
                                Write-Host "The parameter `$ReplaceOne allows for only one string to be replaced, and more than one choice was selected."
                                [array]$StringLineChoices = Read-Host -Prompt "Please select one (1) choice that corresponds to the Nth occurrence of line that contains '$StringToReplace' [$([string]$ValidStringLineChoices -replace " ","/")]"
                                if ($StringLineChoices.Count -gt 1) {
                                    Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                    Write-Error "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                            $InvalidStringLineChoices = @()
                            foreach ($obj1 in $StringLineChoices) {
                                if ($ValidStringLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidStringLineChoices += $obj1
                                }
                            }
                            if ($InvalidStringLineChoices -ge 1) {
                                if ($InvalidStringLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Valid choices are as follows:"
                                }
                                if ($InvalidStringLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Valid choices are as follows:"
                                }
                                $ValidStringLineChoices
                                $StringLineChoices = Read-Host -Prompt "Please select one (1) choice that corresponds to the Nth occurrence of line that contains '$StringToReplace' [$([string]$ValidStringLineChoices -replace " ","/")]"
                                if ($($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                    [array]$StringLineChoices = $StringLineChoices.Split(",").Trim()
                                }
                                if (! $($StringLineChoices | Select-String -Pattern ",").Matches.Success) {
                                    [array]$StringLineChoices = $StringLineChoices
                                }
                                $InvalidStringLineChoices = @()
                                foreach ($obj1 in $StringLineChoices) {
                                    if ($ValidStringLineChoices -notcontains $obj1) {
                                        Write-Host "$obj1 is not a valid choice."
                                        $InvalidStringLineChoices += $obj1
                                    }
                                }
                                if ($InvalidStringLineChoices -ge 1) {
                                    if ($InvalidStringLineChoices.Count -eq 1) {
                                        Write-Host "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                        Write-Error "The choice $([string]$InvalidStringLineChoices) is not a valid choice. Halting!"
                                    }
                                    if ($InvalidStringLineChoices.Count -gt 1) {
                                        Write-Host "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                        Write-Error "The choices $([string]$InvalidStringLineChoices) are not valid choices. Halting!"
                                    }
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }

                            $UpdatedStringLineNumbers = foreach ($obj1 in $StringLineChoices) {
                                foreach ($obj2 in $PotentialStringLineChoices) {
                                    $ChoicePosition = $obj2.IndexOf(")")
                                    $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                    $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                    $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                    if ($obj1 -eq $ChoiceNumber) {
                                        $LineNum
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if ($TextFormationType -eq "line") {
        # When attempting to replace an ENTIRE Line, EITHER the $LineToReplace OR the $LineLineNumber parameter is Required
        if ($LineToReplace -eq $null -and ! $LineLineNumber.Count -gt 0) {
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
            # The below variable $PossibleLineLineNumbers is used later in the if statement where ! $LineLineNumber.Count -gt 0
            $PossibleLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
            if ($LineLineNumber -ge 1) {
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
                if (! $($LineLineCheck.Count -gt 0)) {
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
                            $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextFileSourceContent[$($LineLineCheck[$loop]-1)])"
                            if ($PotentialPatterns -notcontains $PotentialPatternsObject) {
                                $PotentialPatterns += $PotentialPatternsObject
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
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck
                }
                # Make sure $UpdatedPossibleLineLineNumbers is sorted ascending
                $UpdatedPossibleLineLineNumbers = $UpdatedPossibleLineLineNumbers | Sort-Object
                # Begin checking $UpdatedPossibleLineLineNumbers against $ReplaceSome and $ReplaceOne
                if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                    if ($LineOccurrenceOfLine.Count -eq 1) {
                        if ($LineOccurrenceOfLine -eq "last") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($LineOccurrenceOfLine -eq "first") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($LineOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedLineLineNumbers = @()
                            for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                                foreach ($obj1 in $LineOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedLineLineNumbers += $UpdatedPossibleLineLineNumbers[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($LineOccurrenceOfLine.Count -gt 1) {
                        $UpdatedLineLineNumbers = for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                            foreach ($obj2 in $LineOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $UpdatedPossibleLineLineNumbers[$loop]
                                }
                            }
                        }
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        $UpdatedLineLineNumbers = $UpdatedPossibleLineLineNumbers
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        $UpdatedLineLineNumbers = $UpdatedPossibleLineLineNumbers
                    }
                }
                if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
                    if ($LineOccurrenceOfLine.Count -eq 1) {
                        if ($LineOccurrenceOfLine -eq "last") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($LineOccurrenceOfLine -eq "first") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($LineOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedLineLineNumbers = @()
                            for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                                foreach ($obj1 in $LineOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedLineLineNumbers += $UpdatedPossibleLineLineNumbers[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($LineOccurrenceOfLine.Count -gt 1) {
                        $UpdatedLineLineNumbers = for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                            foreach ($obj2 in $LineOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $UpdatedPossibleLineLineNumbers[$loop]
                                }
                            }
                        }
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        $UpdatedLineLineNumbers = $UpdatedPossibleLineLineNumbers
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        Write-Host "The parameter `$ReplaceOne was used, however, multiple line numbers were specified using the `$LineLineNumber parameter, and more than one line contains the line:`n$LineToReplace"
                        Write-Host "Lines that contain the line '$LineToReplace' are as follows:"
                        $PotentialLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
                        }
                        $ValidLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        $PotentialLineLineChoices
                        $LineLineChoices = Read-Host -Prompt "Please select one choice that correspond to the Nth occurrence of line that matches '`$LineToReplace' that you would like to replace. [$([string]$ValidLineLineChoices -replace " ","/")]"
                        if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                        }
                        if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices
                        }
                        # Since this is $ReplaceOne, check to make sure $LineLineChoices only has 1 element
                        if ($LineLineChoices.Count -gt 1) {
                            Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected."
                            $LineLineChoices = Read-Host -Prompt "Please select one choice that correspond to the Nth occurrence of line that matches '`$LineToReplace' that you would like to replace. [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($LineLineChoices.Count -gt 1) {
                                Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                Write-Error "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        $InvalidLineLineChoices = @()
                        foreach ($obj1 in $LineLineChoices) {
                            if ($ValidLineLineChoices -notcontains $obj1) {
                                Write-Host "$obj1 is not a valid choice."
                                $InvalidLineLineChoices += $obj1
                            }
                        }
                        if ($InvalidLineLineChoices -ge 1) {
                            if ($InvalidLineLineChoices.Count -eq 1) {
                                Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Valid choices are as follows:"
                            }
                            if ($InvalidLineLineChoices.Count -gt 1) {
                                Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Valid choices are as follows:"
                            }
                            $ValidLineLineChoices
                            $LineLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '`$LineToReplace' [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                            }
                            if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices
                            }
                            $InvalidLineLineChoices = @()
                            foreach ($obj1 in $LineLineChoices) {
                                if ($ValidLineLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidLineLineChoices += $obj1
                                }
                            }
                            if ($InvalidLineLineChoices -ge 1) {
                                if ($InvalidLineLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                    Write-Error "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                }
                                if ($InvalidLineLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                    Write-Error "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                }
                                $global:FunctionResult = "1"
                                return
                            }
                        }

                        $UpdatedLineLineNumbers = foreach ($obj1 in $LineLineChoices) {
                            foreach ($obj2 in $PotentialLineLineChoices) {
                                $ChoicePosition = $obj2.IndexOf(")")
                                $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                if ($obj1 -eq $ChoiceNumber) {
                                    $LineNum
                                }
                            }
                        }
                    }
                }
            }
            # If we only have $LineToReplace present, then we just have to verify that $LineToReplace is an ENTIRE Line
            # Outputs $UpdatedPossibleLineLineNumbers and verifies $LineToReplace
            if (! $LineLineNumber.Count -gt 0) {
                $LineLineCheck = @()
                $BadMatches = @()
                foreach ($obj1 in $PossibleLineLineNumbers) {
                    if ($TextFileSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        Write-Host "The contents of the entire line number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $obj1
                    }
                    if ($TextFileSourceContent[$($obj1-1)] -ne $LineToReplace) {
                        # Check if $LineToReplace is a string within the line. If so, add it to $LineLineCheck...
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
                if (! $($LineLineCheck.Count -gt 0)) {
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
                            #Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                            $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextFileSourceContent[$($LineLineCheck[$loop]-1)])"
                            if ($PotentialPatterns -notcontains $PotentialPatternsObject) {
                                $PotentialPatterns += $PotentialPatternsObject
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
                    $PotentialPatternsChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                    }
                    $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        $loop+1
                    }
                    if ($LineOccurrenceOfLine -ge 1) {
                        $PatternChoice = $LineOccurrenceOfLine
                    }
                    if (! $LineOccurrenceOfLine.Count -gt 0) {
                        Write-Host "The content of line numbers $([string]$LineLineCheck) are not all exactly the same."
                        Write-Host "Choices for unique patterns are as follows:"
                        Write-Host "NOTE: There is one (1) space between the ')' character and the beginning of the actual pattern"
                        $PotentialPatternsChoices
                        $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                    }
                    if ($($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                        [array]$PatternChoice = $PatternChoice.Split(",").Trim()
                    }
                    if (! $($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                        [array]$PatternChoice = $PatternChoice
                    }
                    $InvalidPatternChoices = @()
                    foreach ($Choice in $PatternChoice) {
                        if ($ValidPatternChoices -notcontains $Choice) {
                            Write-Host "$Choice is not a valid choice."
                            $InvalidPatternChoices += $Choice
                        }
                    }
                    if ($InvalidPatternChoices -ge 1) {
                        Write-Host "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Valid choices are as follows:"
                        [string]$ValidPatternChoices -replace " ",", "
                         $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                        if ($($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                            [array]$PatternChoice = $PatternChoice.Split(",").Trim()
                        }
                        if (! $($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                            [array]$PatternChoice = $PatternChoice
                        }
                        $InvalidPatternChoices = @()
                        foreach ($Choice in $PatternChoice) {
                            if ($ValidPatternChoices -notcontains $Choice) {
                                Write-Host "$Choice is not a valid choice."
                                $InvalidPatternChoices += $Choice
                            }
                        }
                        if ($InvalidPatternChoices -ge 1) {
                            Write-Host "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Halting!"
                            Write-Error "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    # Define $UpdatedPossibleLineLineNumbers
                    $UpdatedPossibleLineLineNumbers = @()
                    foreach ($obj1 in $PotentialPatternsChoices) {
                        foreach ($obj2 in $PatternChoice) {
                            $PotentialPatternChoiceNumber = $obj1.Split(")") | Select-Object -Index 0
                            if ($PotentialPatternChoiceNumber -eq $obj2) {
                                $PatternChoiceLineNumberPrep = $($obj1 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                $PatternChoiceLineNumber = $($PatternChoiceLineNumberPrep -split " " | Select-Object -Last 1) -replace ":",""
                                $UpdatedPossibleLineLineNumbers += $PatternChoiceLineNumber
                            }
                        }
                    }
                }
                # Make sure $UpdatedPossibleLineLineNumbers is sorted ascending
                $UpdatedPossibleLineLineNumbers = $UpdatedPossibleLineLineNumbers | Sort-Object
                # Begin checking $UpdatedPossibleLineLineNumbers against $ReplaceSome and $ReplaceOne
                if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                    if ($LineOccurrenceOfLine.Count -eq 1) {
                        if ($LineOccurrenceOfLine -eq "last") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($LineOccurrenceOfLine -eq "first") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($LineOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedLineLineNumbers = @()
                            for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                                foreach ($obj1 in $LineOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedLineLineNumbers += $UpdatedPossibleLineLineNumbers[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($LineOccurrenceOfLine.Count -gt 1) {
                        $UpdatedLineLineNumbers = for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                            foreach ($obj2 in $LineOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $UpdatedPossibleLineLineNumbers[$loop]
                                }
                            }
                        }
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        $UpdatedLineLineNumbers = $UpdatedPossibleLineLineNumbers
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        Write-Host "The parameter `$ReplaceSome was used, however, no line numbers were specified using the `$LineLineNumber parameter, and more than one line contains the line:`n$LineToReplace"
                        Write-Host "Lines that contain the line '$LineToReplace' are as follows:"
                        $PotentialLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
                        }
                        $ValidLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        $PotentialLineLineChoices
                        $LineLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that match '`$LineToReplace' [$([string]$ValidLineLineChoices -replace " ","/")]"
                        if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                        }
                        if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices
                        }
                        $InvalidLineLineChoices = @()
                        foreach ($obj1 in $LineLineChoices) {
                            if ($ValidLineLineChoices -notcontains $obj1) {
                                Write-Host "$obj1 is not a valid choice."
                                $InvalidLineLineChoices += $obj1
                            }
                        }
                        if ($InvalidLineLineChoices -ge 1) {
                            if ($InvalidLineLineChoices.Count -eq 1) {
                                Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Valid choices are as follows:"
                            }
                            if ($InvalidLineLineChoices.Count -gt 1) {
                                Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Valid choices are as follows:"
                            }
                            $ValidLineLineChoices
                            $LineLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '`$LineToReplace' [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                            }
                            if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices
                            }
                            $InvalidLineLineChoices = @()
                            foreach ($obj1 in $LineLineChoices) {
                                if ($ValidLineLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidLineLineChoices += $obj1
                                }
                            }
                            if ($InvalidLineLineChoices -ge 1) {
                                if ($InvalidLineLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                    Write-Error "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                }
                                if ($InvalidLineLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                    Write-Error "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                }
                                $global:FunctionResult = "1"
                                return
                            }
                        }

                        $UpdatedLineLineNumbers = foreach ($obj1 in $LineLineChoices) {
                            foreach ($obj2 in $PotentialLineLineChoices) {
                                $ChoicePosition = $obj2.IndexOf(")")
                                $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                if ($obj1 -eq $ChoiceNumber) {
                                    $LineNum
                                }
                            }
                        }
                    }
                }
                if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
                    if ($LineOccurrenceOfLine.Count -eq 1) {
                        if ($LineOccurrenceOfLine -eq "last") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                        }
                        if ($LineOccurrenceOfLine -eq "first") {
                            [int]$UpdatedLineLineNumbers = $($UpdatedPossibleLineLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                        }
                        if ($LineOccurrenceOfLine[0] -match "[\d]{1,10}") {
                            $UpdatedLineLineNumbers = @()
                            for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                                foreach ($obj1 in $LineOccurrenceOfLine) {
                                    if ($($loop+1) -eq $obj1) {
                                        $UpdatedLineLineNumbers += $UpdatedPossibleLineLineNumbers[$loop]
                                    }
                                }
                                
                            }
                        }
                    }
                    if ($LineOccurrenceOfLine.Count -gt 1) {
                        $UpdatedLineLineNumbers = for ($loop=0; $loop -lt $UpdatedPossibleLineLineNumbers.Count; $loop++) {
                            foreach ($obj2 in $LineOccurrenceOfLine) {
                                if ($($loop+1) -eq $obj2) {
                                    $UpdatedPossibleLineLineNumbers[$loop]
                                }
                            }
                        }
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -eq 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        $UpdatedLineLineNumbers = $UpdatedPossibleLineLineNumbers
                    }
                    if ($UpdatedPossibleLineLineNumbers.Count -gt 1 -and ! $LineOccurrenceOfLine.Count -gt 0) {
                        Write-Host "The parameter `$ReplaceOne was used, however, no line numbers were specified using the `$LineLineNumber parameter, and more than one line contains the line:`n$LineToReplace"
                        Write-Host "Lines that contain the line '$LineToReplace' are as follows:"
                        $PotentialLineLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextFileSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextFileSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
                        }
                        $ValidLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            $loop+1
                        }
                        $PotentialLineLineChoices
                        $LineLineChoices = Read-Host -Prompt "Please select one choice that correspond to the Nth occurrence of line that matches '`$LineToReplace' that you would like to replace. [$([string]$ValidLineLineChoices -replace " ","/")]"
                        if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                        }
                        if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                            [array]$LineLineChoices = $LineLineChoices
                        }
                        # Since this is $ReplaceOne, check to make sure $LineLineChoices only has 1 element
                        if ($LineLineChoices.Count -gt 1) {
                            Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected."
                            $LineLineChoices = Read-Host -Prompt "Please select one choice that correspond to the Nth occurrence of line that matches '`$LineToReplace' that you would like to replace. [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($LineLineChoices.Count -gt 1) {
                                Write-Host "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                Write-Error "The parameter `$ReplaceOne allows for only one line to be replaced, and more than one choice was selected. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        $InvalidLineLineChoices = @()
                        foreach ($obj1 in $LineLineChoices) {
                            if ($ValidLineLineChoices -notcontains $obj1) {
                                Write-Host "$obj1 is not a valid choice."
                                $InvalidLineLineChoices += $obj1
                            }
                        }
                        if ($InvalidLineLineChoices -ge 1) {
                            if ($InvalidLineLineChoices.Count -eq 1) {
                                Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Valid choices are as follows:"
                            }
                            if ($InvalidLineLineChoices.Count -gt 1) {
                                Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Valid choices are as follows:"
                            }
                            $ValidLineLineChoices
                            $LineLineChoices = Read-Host -Prompt "Please select one or more choices (separated by commas) that correspond to the Nth occurrence of lines that contain '`$LineToReplace' [$([string]$ValidLineLineChoices -replace " ","/")]"
                            if ($($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices.Split(",").Trim()
                            }
                            if (! $($LineLineChoices | Select-String -Pattern ",").Matches.Success) {
                                [array]$LineLineChoices = $LineLineChoices
                            }
                            $InvalidLineLineChoices = @()
                            foreach ($obj1 in $LineLineChoices) {
                                if ($ValidLineLineChoices -notcontains $obj1) {
                                    Write-Host "$obj1 is not a valid choice."
                                    $InvalidLineLineChoices += $obj1
                                }
                            }
                            if ($InvalidLineLineChoices -ge 1) {
                                if ($InvalidLineLineChoices.Count -eq 1) {
                                    Write-Host "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                    Write-Error "The choice $([string]$InvalidLineLineChoices) is not a valid choice. Halting!"
                                }
                                if ($InvalidLineLineChoices.Count -gt 1) {
                                    Write-Host "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                    Write-Error "The choices $([string]$InvalidLineLineChoices) are not valid choices. Halting!"
                                }
                                $global:FunctionResult = "1"
                                return
                            }
                        }

                        $UpdatedLineLineNumbers = foreach ($obj1 in $LineLineChoices) {
                            foreach ($obj2 in $PotentialLineLineChoices) {
                                $ChoicePosition = $obj2.IndexOf(")")
                                $ChoiceNumber = $obj2.Substring(0, $ChoicePosition)
                                $LineNumPrep = $($obj2 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                                $LineNum = $($LineNumPrep -split " " | Select-Object -Last 1) -replace ":",""
                                if ($obj1 -eq $ChoiceNumber) {
                                    $LineNum
                                }
                            }
                        }
                    }
                }
            }
        }
        # If ONLY an array of $LineLineNumber is provided, we need to make sure that all of these lines are the SAME EXACT pattern
        # Outputs $UpdatedPossibleLineLineNumbers and $LineToReplace, or fails
        if ($LineToReplace -eq $null -and $LineLineNumber -ge 1) {
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
                        $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextFileSourceContent[$($LineLineCheck[$loop]-1)])"
                        if ($PotentialPatterns -notcontains $PotentialPatternsObject) {
                            $PotentialPatterns += $PotentialPatternsObject
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
                $PotentialPatternsChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                    "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                }
                $PotentialPatternsChoices
                $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                    $loop+1
                }
                $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                if ($($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                    [array]$PatternChoice = $PatternChoice.Split(",").Trim()
                }
                if (! $($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                    [array]$PatternChoice = $PatternChoice
                }
                $InvalidPatternChoices = @()
                foreach ($Choice in $PatternChoice) {
                    if ($ValidPatternChoices -notcontains $Choice) {
                        Write-Host "$Choice is not a valid choice."
                        $InvalidPatternChoices += $Choice
                    }
                }
                if ($InvalidPatternChoices -ge 1) {
                    Write-Host "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Valid choices are as follows:"
                    [string]$ValidPatternChoices -replace " ",", "
                     $PatternChoice = Read-Host -Prompt "Please enter the number that corresponds to the pattern of line you would like to replace"
                    if ($($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                        [array]$PatternChoice = $PatternChoice.Split(",").Trim()
                    }
                    if (! $($PatternChoice | Select-String -Pattern ",").Matches.Success) {
                        [array]$PatternChoice = $PatternChoice
                    }
                    $InvalidPatternChoices = @()
                    foreach ($Choice in $PatternChoice) {
                        if ($ValidPatternChoices -notcontains $Choice) {
                            Write-Host "$Choice is not a valid choice."
                            $InvalidPatternChoices += $Choice
                        }
                    }
                    if ($InvalidPatternChoices -ge 1) {
                        Write-Host "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Halting!"
                        Write-Error "$($([string]$InvalidPatternChoices) -replace " ",", ") are not a valid choice(s). Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                # Define $UpdatedPossibleLineLineNumbers
                $UpdatedPossibleLineLineNumbers = @()
                foreach ($obj1 in $PotentialPatternsChoices) {
                    foreach ($obj2 in $PatternChoice) {
                        $PotentialPatternChoiceNumber = $obj1.Split(")") | Select-Object -Index 0
                        if ($PotentialPatternChoiceNumber -eq $obj2) {
                            $PatternChoiceLineNumberPrep = $($obj1 | Select-String -Pattern "Line Number [\w]{1,10}:").Matches.Value
                            $PatternChoiceLineNumber = $($PatternChoiceLineNumberPrep -split " " | Select-Object -Last 1) -replace ":",""
                            $UpdatedPossibleLineLineNumbers += $PatternChoiceLineNumber
                        }
                    }
                }
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
            if ($($UpdatedStringLineNumbers.GetType()).Name -eq "String") {
                [int]$FinalStringLineNumber = $UpdatedStringLineNumbers
            }
            if ($($UpdatedStringLineNumbers.GetType()).Name -like "*Object*" -and $($UpdatedStringLineNumbers.GetType()).BaseType -like "*Array*") {
                [int]$FinalStringLineNumber = $UpdatedStringLineNumbers[0]
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
                if (! $StringInLineOccurrence.Count -gt 0) {
                    Write-Host "The line number $FinalStringLineNumber contains $($StringToReplaceInLineIndexes.Count) occurrences of the string $StringToReplace"
                    Write-Host "Context for these occurrences is as follows:"
                    $StringToReplaceInLineChoices
                    [string]$StringInLineOccurrence = Read-Host -Prompt "Please select one (1) choice representing the Nth occurrence of the string '$StringToReplace' in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
                    if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                        Write-Host "$StringInLineOccurrence is not a valid choice. Valid choices are as follows:"
                        $ValidStringToReplaceInLineChoices
                        [string]$StringInLineOccurrence = Read-Host -Prompt "Please select the context for the string '$StringToReplace' in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
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
                if ($StringInLineOccurrence.Count -gt 0) {
                    # Validate $StringInLineOccurrence
                    if ($ValidStringToReplaceInLineChoices -notcontains $StringInLineOccurrence) {
                        Write-Host "$StringInLineOccurrence is not a valid choice. Valid choices are as follows:"
                        $StringToReplaceInLineChoices
                        [string]$StringInLineOccurrence = Read-Host -Prompt "Please select one (1) choice representing the Nth occurrence of the string '$StringToReplace' in line number $FinalStringLineNumber [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]"
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
            if ($($UpdatedStringLineNumbers.GetType()).Name -eq "String") {
                [array]$FinalStringLineNumbers = $UpdatedStringLineNumbers
            }
            if ($($UpdatedStringLineNumbers.GetType()).Name -like "*Object*" -and $($UpdatedStringLineNumbers.GetType()).BaseType -like "*Array*") {
                $FinalStringLineNumbers = $UpdatedStringLineNumbers
            }
            # End Determine $FinalStringLineNumbers #

            # Begin Determine if each line in $FinalStringLineNumbers has one or more instances of $StringToReplace #
            # If so, then ask user which index to replace. If not, move on to $UpdatedTextFileSourceContent
            $UpdatedStringToReplaceObjects = @()
            foreach ($obj1 in $FinalStringLineNumbers) {
                $FinalStringLineNumberContent = $TextFileSourceContent[$obj1-1]
                $StringToReplaceInLineIndexes = $($FinalStringLineNumberContent | Select-String -AllMatches "$StringToReplace").Matches.Index
                if ($StringToReplaceInLineIndexes.Count -eq 1) {
                    New-Variable -Name "UpdatedStringToReplaceLine$obj1`1" -Value $(
                        New-Object PSObject -Property @{
                            LineNum                                         = $obj1
                            OccurrenceInLine                                = "1"
                            OriginalLineContent                             = $FinalStringLineNumberContent
                            UpdatedStringToReplace                          = $StringToReplace
                            UpdatedStringToReplaceWithReplacementText       = $ReplacementText
                            UpdatedStringLineContent                        = $FinalStringLineNumberContent -replace "$StringToReplace","$ReplacementText"
                        }
                    )

                    $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$obj1`1" -ValueOnly)
                }
                if ($StringToReplaceInLineIndexes.Count -gt 1) {
                    [array]$StringLineSplitPrep = $($FinalStringLineNumberContent -replace "$StringToReplace",";;;splithere;;;$StringToReplace;;;splithere;;;") -split ";;;splithere;;;"
                    [System.Collections.ArrayList]$StringLineSplit = $StringLineSplitPrep
                    $StringToReplaceInLineContext = $StringLineSplit | Select-String -AllMatches "$StringToReplace" -Context 1 | foreach {
                        "$($($_.Context).PreContext)"+"$($_.Line)"+"$($($_.Context).PostContext)"
                    }
                    $StringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                        "$($loop+1)"+") "+"..."+"$($StringToReplaceInLineContext[$loop])"+"..."
                    }
                    $ValidStringToReplaceInLineChoices = For ($loop=0; $loop -lt $StringToReplaceInLineIndexes.Count; $loop++) {
                        $loop+1
                    }
                    if ($StringLineNumberVSOccurrenceHashTable -ne $null) {
                        # Validate Line Numbers (i.e. Keys in $StringLineNumberVSOccurrenceHashTable)
                        $StringLineNumberVSOccurrenceHashTable.GetEnumerator() | foreach {
                            if ($FinalStringLineNumbers -notcontains $_.Name) {
                                Write-Host "The line number $($_.Name) is not a valid line number. Line numbers that contain the string '`$StringToReplace' are $([string]$FinalStringLineNumbers).`nPlease check the contents of the hashtable passed to the parameter `$StringLineNumberVSOccurrenceHashTable and try again. Halting!"
                                Write-Error "The line number $($_.Name) is not a valid line number. Line numbers that contain the string '`$StringToReplace' are $([string]$FinalStringLineNumbers).`nPlease check the contents of the hashtable passed to the parameter `$StringLineNumberVSOccurrenceHashTable and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        # Validate Occurrences within lines, (i.e. Values in $StringLineNumberVSOccurrenceHashTable)
                        $InLineOccurrenceValidation = @()
                        $StringLineNumberVSOccurrenceHashTable.GetEnumerator() | foreach {
                            $obj3 = $_.Value
                            if ($($obj3 | Select-String -Pattern ",").Matches.Success) {
                                [array]$obj3 = $obj3.Split(",").Trim()
                            }
                            if (! $($obj3 | Select-String -Pattern ",").Matches.Success) {
                                [array]$obj3 = $obj3
                            }
                            foreach ($obj4 in $obj3) {
                                if ($ValidStringToReplaceInLineChoices -notcontains $obj4) {
                                    Write-Host "$obj4 is NOT a valid choice."
                                    $InLineOccurrenceValidation += "Occurrence $obj4 for line $($_.Name)"
                                }
                            }
                        }
                        if ($InLineOccurrenceValidation.Count -gt 0) {
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringLineNumberVSOccurrenceHashTable parameter. Halting!"
                            Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringLineNumberVSOccurrenceHashTable parameter. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        $StringLineNumberVSOccurrenceHashTable.GetEnumerator() | foreach {
                            $obj3 = $_.Value
                            foreach ($obj4 in $obj3) {
                                $UpdatedStringToReplace = $StringToReplaceInLineContext[$obj4-1]
                                $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                                # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                                New-Variable -Name "UpdatedStringToReplaceLine$($_.Name)$obj4" -Value $(
                                    New-Object PSObject -Property @{
                                        LineNum                                         = $_.Name
                                        OccurrenceInLine                                = $obj4
                                        OriginalLineContent                             = $FinalStringLineNumberContent
                                        UpdatedStringToReplace                          = $UpdatedStringToReplace
                                        UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                        UpdatedStringLineContent                        = $FinalStringLineNumberContent -replace "$UpdatedStringToReplace","$UpdatedStringToReplaceWithReplacementText"
                                    }
                                ) -Force

                                if (! $UpdatedStringToReplaceObjects.Count -gt 0) {
                                    $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$($_.Name)$obj4" -ValueOnly)
                                }
                                if ($UpdatedStringToReplaceObjects.Count -gt 0) {
                                    $NewObjLineNumPlusOccurrence = "$($_.Name)"+"$obj4"
                                    $UpdatedStringToReplaceObjectsCheck = @()
                                    foreach ($obj5 in $UpdatedStringToReplaceObjects) {
                                        $ExistingObjsLineNumPlusOccurrence = "$($obj5.LineNum)"+"$($obj5.OccurrenceInLine)"
                                        if ($ExistingObjsLineNumPlusOccurrence -eq $NewObjLineNumPlusOccurrence) {
                                            $UpdatedStringToReplaceObjectsCheck += $ExistingObjsLineNumPlusOccurrence
                                        }
                                    }
                                    if (! $UpdatedStringToReplaceObjectsCheck.Count -gt 0) {
                                        $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$($_.Name)$obj4" -ValueOnly)
                                    }
                                }
                            }
                        }
                    }
                    if ($StringInLineOccurrence -ge 1) {
                        New-Variable -Name "StringInLineOccurrence$obj1" -Value $StringInLineOccurrence
                        
                        if ($($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly).Split(",").Trim()) -Force
                        }
                        if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) -Force
                        }
                        $InLineOccurrenceValidation = @()
                        foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                            if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                Write-Host "$Occurrence is NOT a valid choice."
                                $InLineOccurrenceValidation += $Occurrence
                            }
                        }
                        if ($InLineOccurrenceValidation.Count -gt 0) {
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices."
                            Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                            $StringToReplaceInLineChoices

                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Read-Host -Prompt "Please select one or more numbers (separated by commas) that represent the Nth occurrence of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears within line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]") -Force
                            
                            if ($($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                                New-Variable -Name "StringInLineOccurrence$obj1" -Value $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly).Split(",").Trim()) -Force
                            }
                            if (! $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                                New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) -Force
                            }
                            $InLineOccurrenceValidation = @()
                            foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                                if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                    Write-Host "$Occurrence is NOT a valid choice."
                                    $InLineOccurrenceValidation += $Occurrence
                                }
                            }
                            if ($InLineOccurrenceValidation.Count -gt 0) {
                                Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                            $UpdatedStringToReplace = $StringToReplaceInLineContext[$Occurrence-1]
                            $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                            # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                            New-Variable -Name "UpdatedStringToReplaceLine$obj1$Occurrence" -Value $(
                                New-Object PSObject -Property @{
                                    LineNum                                         = $obj1
                                    OccurrenceInLine                                = $Occurrence
                                    OriginalLineContent                             = $FinalStringLineNumberContent
                                    UpdatedStringToReplace                          = $UpdatedStringToReplace
                                    UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                    UpdatedStringLineContent                        = $FinalStringLineNumberContent -replace "$UpdatedStringToReplace","$UpdatedStringToReplaceWithReplacementText"
                                }
                            )

                            $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$obj1$Occurrence" -ValueOnly)
                        }
                    }
                    if (! $StringInLineOccurrence.Count -gt 0 -and $StringLineNumberVSOccurrenceHashTable -eq $null) {
                        Write-Host "The line number $obj1 contains $($StringToReplaceInLineIndexes.Count) occurrences of the string $StringToReplace"
                        Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                        $StringToReplaceInLineChoices

                        New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Read-Host -Prompt "Please select one or more numbers (separated by commas) that represent the Nth occurrence of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears within line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]") -Force

                        if ($($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly).Split(",").Trim()) -Force
                        }
                        if (! $($StringInLineOccurrence | Select-String -Pattern ",").Matches.Success) {
                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) -Force
                        }
                        $InLineOccurrenceValidation = @()
                        foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                            if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                Write-Host "$Occurrence is NOT a valid choice."
                                $InLineOccurrenceValidation += $Occurrence
                            }
                        }
                        if ($InLineOccurrenceValidation.Count -gt 0) {
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices."
                            Write-Host "Context for occurrences of the string '$StringToReplace' are as follows:"
                            $StringToReplaceInLineChoices

                            New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Read-Host -Prompt "Please select one or more numbers (separated by commas) that represent the Nth occurrence of the string '$StringToReplace' in line number $obj1 that you would like to replace.`nNOTE: These numbers also represent the first, second, third, etc time that '$StringToReplace' appears within line number $obj1 [$($([string]$ValidStringToReplaceInLineChoices) -replace " ","/")]") -Force
                            
                            if ($($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                                New-Variable -Name "StringInLineOccurrence$obj1" -Value $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly).Split(",").Trim()) -Force
                            }
                            if (! $($(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) | Select-String -Pattern ",").Matches.Success) {
                                New-Variable -Name "StringInLineOccurrence$obj1" -Value $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly) -Force
                            }
                            $InLineOccurrenceValidation = @()
                            foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                                if ($ValidStringToReplaceInLineChoices -notcontains $Occurrence) {
                                    Write-Host "$Occurrence is NOT a valid choice."
                                    $InLineOccurrenceValidation += $Occurrence
                                }
                            }
                            if ($InLineOccurrenceValidation.Count -gt 0) {
                                Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        foreach ($Occurrence in $(Get-Variable -Name "StringInLineOccurrence$obj1" -ValueOnly)) {
                            $UpdatedStringToReplace = $StringToReplaceInLineContext[$Occurrence-1]
                            $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                            # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                            New-Variable -Name "UpdatedStringToReplaceLine$obj1$Occurrence" -Value $(
                                New-Object PSObject -Property @{
                                    LineNum                                         = $obj1
                                    OccurrenceInLine                                = $Occurrence
                                    OriginalLineContent                             = $FinalStringLineNumberContent
                                    UpdatedStringToReplace                          = $UpdatedStringToReplace
                                    UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                    UpdatedStringLineContent                        = $FinalStringLineNumberContent -replace "$UpdatedStringToReplace","$UpdatedStringToReplaceWithReplacementText"
                                }
                            )

                            $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$obj1$Occurrence" -ValueOnly)
                        }
                    }
                }
            }

            # Prep final replacement lines
            $ReplacementLinesObjects = @()
            foreach ($obj1 in $FinalStringLineNumbers) {
                foreach ($obj2 in $UpdatedStringToReplaceObjects) {
                    if ($obj2.LineNum -eq $obj1) {
                        if ($(Get-Variable -Name "ReplacementLine$($obj2.LineNum)" -ValueOnly -ErrorAction SilentlyContinue) -eq $null) {
                            New-Variable -Name "ReplacementLine$($obj2.LineNum)" -Value $(
                                $TextFileSourceContent[$obj1-1] -replace "$($obj2.UpdatedStringToReplace)","$($obj2.UpdatedStringToReplaceWithReplacementText)"
                            ) -Force
                        }
                        if ($(Get-Variable -Name "ReplacementLine$($obj2.LineNum)" -ValueOnly -ErrorAction SilentlyContinue) -ne $null) {
                            New-Variable -Name "ReplacementLine$($obj2.LineNum)" -Value $(
                                $(Get-Variable -Name "ReplacementLine$($obj2.LineNum)" -ValueOnly) -replace "$($obj2.UpdatedStringToReplace)","$($obj2.UpdatedStringToReplaceWithReplacementText)"
                            ) -Force
                        }
                    }
                }
                # Add Line Number Property to $ReplacementLineX Objects
                New-Variable -Name "FinalReplacementLine$obj1" -Value $(
                    New-Object PSObject -Property @{
                        LineNum              = [int]$obj1
                        FinalLineContent     = $(Get-Variable -Name "ReplacementLine$obj1" -ValueOnly)
                    }
                ) -Force

                $ReplacementLinesObjects += $(Get-Variable -Name "FinalReplacementLine$obj1" -ValueOnly)
            }
            # Make sure $ReplacementLineObjects is sorted by Ascending LineNum
            $ReplacementLinesObjects = $ReplacementLinesObjects | Sort-Object -Property LineNum

            # Update source content
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalStringLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($($($ReplacementLinesObjects[$loop]).LineNum)-2)]
                    $UpdatedTextFileSourceContent += $($($ReplacementLinesObjects[$loop]).FinalLineContent)
                    $NextLoopStartingPoint = $($ReplacementLinesObjects[$loop]).LineNum
                }
                if ($loop -gt 0) {
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($($($ReplacementLinesObjects[$loop]).LineNum)-2)]
                    $UpdatedTextFileSourceContent += $($($ReplacementLinesObjects[$loop]).FinalLineContent)
                    $NextLoopStartingPoint = $($ReplacementLinesObjects[$loop]).LineNum
                }
            }
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($TextFileSourceContent.Count -1)]
        }
    }

    # Outputs $UpdatedTextFileSourceContent
    if ($TextFormationType -eq "line") {
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            # Begin Determine $FinalLineLineNumbers #
            if ($($UpdatedPossibleLineLineNumbers.GetType()).Name -eq "String") {
                [array]$FinalLineLineNumbers = $UpdatedPossibleLineLineNumbers
                # Make sure $FinalLineLineNumbers is an array of intergers
                [array]$FinalLineLineNumbers = foreach ($obj1 in $FinalLineLineNumbers) {
                    [int]$obj1
                }
                # Make sure $FinalLineLineNumbers is sorted ascending
                [array]$FinalLineLineNumbers = $FinalLineLineNumbers | Sort-Object
            }
            if ($($UpdatedPossibleLineLineNumbers.GetType()).Name -like "*Object*" -and $($UpdatedPossibleLineLineNumbers.GetType()).BaseType -like "*Array*") {
                [array]$FinalLineLineNumbers = $UpdatedPossibleLineLineNumbers
                # Make sure $FinalLineLineNumbers is an array of intergers
                [array]$FinalLineLineNumbers = foreach ($obj1 in $FinalLineLineNumbers) {
                    [int]$obj1
                }
                # Make sure $FinalLineLineNumbers is sorted ascending
                [array]$FinalLineLineNumbers = $FinalLineLineNumbers | Sort-Object
            }
            # End Determine $FinalLineLineNumbers #

            # Replace the Line in all Line Numbers in $LineLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalLineLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalLineLineNumber-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextFileSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
                if ($loop -gt 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($FinalLineLineNumber-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextFileSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
            }
            $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($TextFileSourceContent.Count -1)]
        }
        if ($ReplaceOne -eq "Yes" -or $ReplaceOne -eq "y") {
            # Begin Determine $FinalLineLineNumber #
            if ($($UpdatedLineLineNumbers.GetType()).Name -eq "String") {
                [int]$FinalLineLineNumber = $UpdatedLineLineNumbers
            }
            if ($($UpdatedLineLineNumbers.GetType()).Name -like "*Object*" -and $($UpdatedLineLineNumbers.GetType()).BaseType -like "*Array*") {
                [int]$FinalLineLineNumber = $UpdatedLineLineNumbers[0]
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
            if ($($UpdatedLineLineNumbers.GetType()).Name -eq "String") {
                [array]$FinalLineLineNumbers = $UpdatedLineLineNumbers
                # Make sure $FinalLineLineNumbers is an array of intergers
                [array]$FinalLineLineNumbers = foreach ($obj1 in $FinalLineLineNumbers) {
                    [int]$obj1
                }
                # Make sure $FinalLineLineNumbers is sorted ascending
                [array]$FinalLineLineNumbers = $FinalLineLineNumbers | Sort-Object
            }
            if ($($UpdatedLineLineNumbers.GetType()).Name -like "*Object*" -and $($UpdatedLineLineNumbers.GetType()).BaseType -like "*Array*") {
                [array]$FinalLineLineNumbers = $UpdatedLineLineNumbers
                # Make sure $FinalLineLineNumbers is an array of intergers
                [array]$FinalLineLineNumbers = foreach ($obj1 in $FinalLineLineNumbers) {
                    [int]$obj1
                }
                # Make sure $FinalLineLineNumbers is sorted ascending
                [array]$FinalLineLineNumbers = $FinalLineLineNumbers | Sort-Object
            }
            # End Determine $FinalLineLineNumbers #

            # Replace the Line in all Line Numbers in $LineLineNumber
            $UpdatedTextFileSourceContent = @()
            For ($loop=0; $loop -lt $FinalLineLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[0..$($FinalLineLineNumber-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextFileSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
                if ($loop -gt 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$NextLoopStartingPoint..$($FinalLineLineNumber-2)]
                    $UpdatedTextFileSourceContent += $TextFileSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextFileSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
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

        if ($BeginningStringOccurrenceOfLine.Count -ge 1 -and ! $BeginningStringLineNumber.Count -gt 0) {
            Write-Host "HELLO THERE TOP"
            # Begin determine $BeginningStringLineNumber #
            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleBeginningStringLineNumbersContent = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleBeginningStringLineNumbersChoices = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            if ($BeginningStringOccurrenceOfLine.Count -eq 1) {
                if ($BeginningStringOccurrenceOfLine[0] -eq "last") {
                    [array]$BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                }
                if ($BeginningStringOccurrenceOfLine[0] -eq "first") {
                    [array]$BeginningStringLineNumber = $($PossibleBeginningStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                }
                if ($BeginningStringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                   $BeginningStringLineNumber = @()
                    for ($loop=0; $loop -lt $PossibleBeginningStringLineNumbers.Count; $loop++) {
                        foreach ($obj1 in $BeginningStringOccurrenceOfLine) {
                            if ($($loop+1) -eq $obj1) {
                                $BeginningStringLineNumber += $PossibleBeginningStringLineNumbers[$loop]
                            }
                        }
                        
                    }
                }
            }
            if ($BeginningStringOccurrenceOfLine.Count -gt 1) {
                $BeginningStringLineNumber = for ($loop=0; $loop -lt $PossibleBeginningStringLineNumbers.Count; $loop++) {
                    foreach ($obj2 in $BeginningStringOccurrenceOfLine) {
                        if ($($loop+1) -eq $obj2) {
                            $PossibleBeginningStringLineNumbers[$loop]
                        }
                    }
                }
            }
            if ($PossibleBeginningStringLineNumbers.Count -eq 1 -and ! $BeginningStringOccurrenceOfLine.Count -gt 0) {
                $BeginningStringLineNumber = $PossibleBeginningStringLineNumbers[0]
            }
            if ($PossibleBeginningStringLineNumbers.Count -gt 1 -and ! $BeginningStringOccurrenceOfLine.Count -gt 0) {
                Write-Host "placeholder"
            }

            # End determine $BeginningStringLineNumber #
        }
        
        if ($EndingStringOccurrenceOfLine -ge 1 -and ! $EndingStringLineNumber.Count -gt 0) {
            # Begin Determine $EndingStringLineNumber #
            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleEndingStringLineNumbersContent = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleEndingStringLineNumbersChoices = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            if ($EndingStringOccurrenceOfLine.Count -eq 1) {
                if ($EndingStringOccurrenceOfLine -eq "last") {
                    [array]$EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Maximum
                }
                if ($EndingStringOccurrenceOfLine -eq "first") {
                    [array]$EndingStringLineNumber = $($PossibleEndingStringLineNumbers | Measure-Object -Maximum -Minimum).Minimum
                }
                if ($EndingStringOccurrenceOfLine[0] -match "[\d]{1,10}") {
                   $EndingStringLineNumber = @()
                    for ($loop=0; $loop -lt $PossibleEndingStringLineNumbers.Count; $loop++) {
                        foreach ($obj1 in $EndingStringOccurrenceOfLine) {
                            if ($($loop+1) -eq $obj1) {
                                $EndingStringLineNumber += $PossibleEndingStringLineNumbers[$loop]
                            }
                        }
                        
                    }
                }
            }
            if ($EndingStringOccurrenceOfLine.Count -gt 1) {
                $EndingStringLineNumber = for ($loop=0; $loop -lt $PossibleEndingStringLineNumbers.Count; $loop++) {
                    foreach ($obj2 in $EndingStringOccurrenceOfLine) {
                        if ($($loop+1) -eq $obj2) {
                            $PossibleEndingStringLineNumbers[$loop]
                        }
                    }
                }
            }
            if ($PossibleEndingStringLineNumbers.Count -eq 1 -and ! $EndingStringOccurrenceOfLine.Count -gt 0) {
                $EndingStringLineNumber = $PossibleEndingStringLineNumbers[0]
            }
            if ($PossibleEndingStringLineNumbers.Count -gt 1 -and ! $EndingStringOccurrenceOfLine.Count -gt 0) {
                Write-Host "placeholder"
            }
            # End Determine $EndingStringLineNumber #
        }

        # If BOTH $EndingString and $BeginningString are Unique, and we haven't determined $BeginningStringLineNumber or
        # $EndingStringLineNumber using the 'OccurrenceOfLine' parameters, perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -eq 1 `
        -and ! $BeginningStringLineNumber.Count -gt 0 -and ! $EndingStringLineNumber.Count -gt 0) {
            $BeginningLine = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Line
            $EndingLine = $($TextFileSourceContent | Select-String -Pattern "$EndingString").Line
            
            [array]$BlockToReplace = $($($TextFileSourceContentJoined | Select-String -Pattern "$BeginningLine[\w\W]{1,999999999}$EndingLine").Matches.Value) -split ";;splithere;;"
            Write-Host ""
            Write-Host "Writing `$BlockToReplace"
            Write-Host ""
            $BlockToReplace
        }
        # If ONLY $BeginningString is Unique and we haven't determined $EndingStringLineNumber using the
        # $EndingOccurrenceOfLine parameter, perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -gt 1 `
        -and ! $EndingStringLineNumber.Count -gt 0 -or $BeginningStringLineNumber.Count -gt 0) {
            if (! $BeginningStringLineNumber.Count -gt 0) {
                Write-Host "`$BeginningString is unique. Continuing..."
                # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
                $BeginningLine = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Line
                [int]$BeginningStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            }
            if ($BeginningStringLineNumber.Count -eq 1) {
                [int]$BeginningStringLineNumber = $BeginningStringLineNumber[0]
            }

            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleEndingStringLineNumbersContent = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleEndingStringLineNumbersChoices = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            if (! $EndingStringLineNumber.Count -gt 0 -and ! $EndingStringOccurrenceOfLine.Count -gt 0) {
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
            if (! $EndingStringLineNumber.Count -gt 0 -and ! $EndingStringOccurrenceOfLine.Count -gt 0) {
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
        # If ONLY $EndingString is Unique and we haven't determined $BeginningStringLineNumber using the
        # $BeginningOccurrenceOfLine parameter, perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -eq 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1 `
        -and ! $BeginningStringLineNumber.Count -gt 0 -or $EndingStringLineNumber.Count -gt 0) {
            if (! $EndingStringLineNumber.Count -gt 0) {
                Write-Host "`$EndingString is unique. Continuing..."
                # Since $EndingString is unique, nothing special needs to be done to identify $EndingLine
                $EndingLine = $($TextFileSourceContent | Select-String -Pattern "$EndingString").Line
                [int]$EndingStringLineNumber = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            }
            if ($EndingStringLineNumber.Count -eq 1) {
                [int]$EndingStringLineNumber = $EndingStringLineNumber[0]
            }

            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleBeginningStringLineNumbersContent = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                $TextFileSourceContent[$obj1-1]
            }
            $PossibleBeginningStringLineNumbersChoices = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                "$obj1"+") "+"$($TextFileSourceContent[$obj1-1])"
            }

            if (! $BeginningStringLineNumber.Count -gt 0 -and ! $BeginningStringOccurrenceOfLine.Count -gt 0) {
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
            if (! $BeginningStringLineNumber.Count -gt 0 -and ! $BeginningStringOccurrenceOfLine.Count -gt 0) {
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
        # If neither $EndingString nor $BeginningString are Unique and we haven't determined $BeginningStringLineNumber
        # or $EndingStringLineNumber using the 'OccurrenceOfLine' parameters, perform the following
        if ($($TextFileSourceContent | Select-String -Pattern "$EndingString").Count -gt 1 `
        -and $($TextFileSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1 `
        -and ! $BeginningStringLineNumber.Count -gt 0 -and ! $EndingStringLineNumber.Count -gt 0) {
            Write-Host "HELLO THERE BOTTOM"
            # Output possible results and ask the user which one they want to use
            # Create $BeginningStringIndex
            $PossibleBeginningStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$BeginningString").LineNumber
            $PossibleBeginningStringLineNumbers = $PossibleBeginningStringLineNumbers | Sort-Object
            $PossibleEndingStringLineNumbers = $($TextFileSourceContent | Select-String -Pattern "$EndingString").LineNumber
            $PossibleEndingStringLineNumbers = $PossibleEndingStringLineNumbers | Sort-Object

            $UpdatedPossibleLineNumbers = $PossibleBeginningStringLineNumbers+$PossibleEndingStringLineNumbers | Sort-Object | Get-Unique

            $PossibleBlockToReplaceArray = @()
            $StartAndFinishLineNumbersArray = @()
            for ($loop=0; $loop -lt $UpdatedPossibleLineNumbers.Count; $loop++) {
                $UpdatedPossibleLineNumbersWithoutCurrentLoopElement = foreach ($obj1 in $UpdatedPossibleLineNumbers) {
                    if ($obj1 -ne $($UpdatedPossibleLineNumbers[$loop])) {
                        $obj1
                    }
                }
                foreach ($obj1 in $UpdatedPossibleLineNumbersWithoutCurrentLoopElement) {
                    if ($UpdatedPossibleLineNumbers[$loop] -lt $obj1) {
                        $PotentialBeginningStringLineNumber = $UpdatedPossibleLineNumbers[$loop]
                        $PotentialEndingStringLineNumber = $obj1
                        New-Variable -Name "PossibleBlockToReplace$PotentialBeginningStringLineNumber$PotentialEndingStringLineNumber" -Value $($TextFileSourceContent | Select-Object -Index ($PotentialBeginningStringLineNumber..$PotentialEndingStringLineNumber))
                        $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$PotentialBeginningStringLineNumber$PotentialEndingStringLineNumber" -ValueOnly)
                        $StartAndFinishLineNumbersArray += "Line $PotentialBeginningStringLineNumber to Line $PotentialEndingStringLineNumber`:`n$($TextFileSourceContent[$PotentialBeginningStringLineNumber])`n...`n$($TextFileSourceContent[$PotentialEndingStringLineNumber])"
                    }
                }
            }

            if (! $PossibleBlockToReplaceArray.Count -gt 0) {
                Write-Host "No valid blocks of text beginning with $BeginningString and ending with $EndingString were found."
                Write-Host "Please check to ensure that the Beginning String $BeginningString appears BEFORE the Ending String $EndingString in $TextFileSource"
                Write-Error "No valid blocks of text beginning with $BeginningString and ending with $EndingString were found. Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputPossibleBlocksToReplaceContent = For ($loop=0; $loop -lt $PossibleBlockToReplaceArray.Count; $loop++) {
                "Possible Block To Replace Choice #$($loop+1)"+"`n"
                $PossibleBlockToReplaceArray[$loop]+"`n"
            }

            $OutputPossibleBlocksToReplaceLineNumbers = For ($loop=0; $loop -lt $StartAndFinishLineNumbersArray.Count; $loop++) {
                "Possible Block To Replace Choice #$($loop+1)"+"`n"
                $StartAndFinishLineNumbersArray[$loop]+"`n"
            }

            Write-Host "Possible Blocks to Replace Are As Follows:"
            Write-Host ""
            $OutputPossibleBlocksToReplaceLineNumbers

            $ValidBlockToReplaceChoices = For ($loop=0; $loop -lt $PossibleBlockToReplaceArray.Count; $loop++) {$loop+1}
            [string]$PossibleBlockToReplaceChoices = For ($loop=0; $loop -lt $StartAndFinishLineNumbersArray.Count; $loop++) {"$($loop+1) = $($StartAndFinishLineNumbersArray[$loop])"}
            $SelectedBlockToReplace = Read-Host -Prompt "Please select the 'Possible Block To Replace Choice #' that represents the block text that you would like to replace [$($([string]$ValidBlockToReplaceChoices) -replace " ",", ")]"
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

        # At this point, we should have $BeginningStringLineNumber and $EndingStringLineNumber, one way or another
        # Which means that if $BlockToReplace hasn't been determined yet, we should do so now
        if ($BlockToReplace -eq $null) {
            Write-Host "Writing `$BeginningStringLineNumber"
            $BeginningStringLineNumber
            Write-Host "Writing `$EndingStringLineNumber"
            $EndingStringLineNumber
            
            if ($EndingStringLineNumber.Count -eq 1) {
                # Make sure $EndingStringLineNumber is an interger
                [int]$EndingStringLineNumber = $EndingStringLineNumber | Out-String
            }
            if ($BeginningStringLineNumber.Count -eq 1) {
                # Make sure $EndingStringLineNumber is an interger
                [int]$BeginningStringLineNumber = $BeginningStringLineNumber | Out-String
            }

            $BlockToReplace = $TextFileSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber))
            
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

#### BEGIN STRING OCCURRENCE OF LINE TESTING #####

# String, ReplaceSome, WITH $StringOccurrenceOfLine (single), WITH $StringInLineOccurrence (single), WITHOUT `$StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringOccurrenceOfLine "1" `
-StringInLineOccurrence "2" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITH $StringOccurrenceOfLine (single), WITH $StringInLineOccurrence (multiple), WITHOUT `$StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringOccurrenceOfLine "1" `
-StringInLineOccurrence "2, 3" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITH $StringOccurrenceOfLine (multiple), WITH $StringInLineOccurrence (single), WITHOUT `$StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringOccurrenceOfLine "1, 2" `
-StringInLineOccurrence "2" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITH $StringOccurrenceOfLine (multiple), WITH $StringInLineOccurrence (multiple), WITHOUT `$StringLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringOccurrenceOfLine "1, 2" `
-StringInLineOccurrence "2, 3" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

#### END STRING OCCURRENCE OF LINE TESTING #####








#### BEGIN LINE OCCURRENCE OF LINE TESTING #####
# Line, ReplaceSome, where $LineToReplace is an ENTIRE LINE (multiple), WITH $LineOccurrenceOfLine (single), WITHOUT `$LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"user1 and user1`" - name: and - name:" `
-LineOccurrenceOfLine "1" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, ReplaceSome, where $LineToReplace is an PIECE OF A LINE (multiple), WITH $LineOccurrenceOfLine (single), WITHOUT `$LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "- name" `
-LineOccurrenceOfLine "1" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, ReplaceSome, where $LineToReplace is an PIECE OF A LINE (multiple), WITH $LineOccurrenceOfLine (multiple), WITHOUT `$LineLineNumber = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "- name" `
-LineOccurrenceOfLine "1, 2" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>


#### END LINE OCCURRENCE OF LINE TESTING #####







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
# String, ReplaceOne, WITHOUT specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne, WITH specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS = SUCCESS
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

# String, ReplaceOne, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS = SUCCESS
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

# String, ReplaceOne, WITH specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS = SUCCESS
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

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITHOUT $StringInLineOccurrence, WITH $StringLineNumberVSOccurrenceHashTable = SUCCESS = SUCCESS
<#
$PassedHashTable = @{
    "8" = @("1","2")
    "17" = @("2","3")
}

Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-StringLineNumberVSOccurrenceHashTable $PassedHashTable `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome, WITH specifying $StringLineNumber, WITHOUT $StringInLineOccurrence = SUCCESS = SUCCESS
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

# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS = SUCCESS
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


# String, ReplaceSome, WITHOUT specifying $StringLineNumber, WITH $StringInLineOccurrence = SUCCESS = SUCCESS
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

# String, ReplaceOne WITHOUT specifying $StringLineNumber = SUCCESS = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceOne WITH specifying ONE $StringLineNumber = SUCCESS = SUCCESS
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

# String, ReplaceOne WITH specifying MORE THAN ONE $StringLineNumber = SUCCESS = SUCCESS
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

# String, ReplaceSome WITHOUT specifying $StringLineNumber = SUCCESS = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "string" `
-StringToReplace "- name:" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# String, ReplaceSome WITH specifying ONE $StringLineNumber = SUCCESS = SUCCESS
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

# String, ReplaceSome WITH specifying MORE THAN ONE $StringLineNumber = SUCCESS = SUCCESS
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





# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-LineLineNumber "25" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-LineLineNumber "25, 27" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-LineLineNumber "22, 30" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "32" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "17, 32" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, With ONE $LineLineNumber = SUCCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "32" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceAll, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "16, 24, 32" `
-ReplaceAll "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>







# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "17, 32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESSx3
#HERE
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESSx3
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

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESSx3
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

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "17, 32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, Without $LineLineNumber = SUCCESSx3
# HERE
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, With ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceSome, With MORE THAN ONE $LineLineNumber = SUCCESSx3
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "24, 32" `
-ReplaceSome "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>





# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-LineLineNumber "25" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "  - name: `"root`"" `
-LineLineNumber "8, 25" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>


# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "      - `"sudo`"" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESSx2
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

# Line, Where $LineToRepalce is AN ENTIRE LINE, That is NOT UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESSx2
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

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "32" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"3" `
-LineLineNumber "8, 32" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, Without $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, With ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "24" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Line, Where $LineToRepalce is PIECE OF A LINE, That is NOT UNIQUE, With ReplaceOne, With MORE THAN ONE $LineLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "line" `
-LineToReplace "`"/bin/bash`"" `
-LineLineNumber "24, 32" `
-ReplaceOne "Yes" `
-ReplacementText "Hi" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>








### BEGIN TESTING FOR BLOCKS ###


## Begin BeginningStringOccurrenceOfLine and EndingStringOccurrenceOfLine Testing


# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITHOUT $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringOccurrenceOfLine "16" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITHOUT $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringOccurrenceOfLine "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringOccurrenceOfLine "16" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringOccurrenceOfLine "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITHOUT $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"" `
-BeginningStringOccurrenceOfLine "1" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITHOUT $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringOccurrenceOfLine "1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"" `
-BeginningStringOccurrenceOfLine "1" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringOccurrenceOfLine "1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITHOUT $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringOccurrenceOfLine "1" `
-EndingString "shell: `"/bin/bash`"" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITHOUT $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringOccurrenceOfLine "2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine = SUCCESS
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringOccurrenceOfLine "1" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringOccurrenceOfLine "2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITH $BeginningStringOccurrenceOfLine, WITHOUT $EndingStringOccurrenceOfLine
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"" `
-BeginningStringOccurrenceOfLine "1" `
-EndingString "docker" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"

# Block, $BeginningString is NOT UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber,
# WITHOUT $BeginningStringOccurrenceOfLine, WITH $EndingStringOccurrenceOfLine
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"" `
-EndingString "docker" `
-EndingStringOccurrenceOfLine "1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

## End BeginningStringOccurrenceOfLine and EndingStringOccurrenceOfLine Testing





# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"2" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = Successx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"2" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is UNIQUE, $EndingString is NOT UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "`"/bin/bash`"1" `
-BeginningStringLineNumber "16" `
-EndingString "shell: `"/bin/bash`"" `
-EndingStringLineNumber "24" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
<#
Replace-Text -TextFileSource "V:\powershell\Testing\updated-phase1-template.yml" `
-TextFormationType "block" `
-BeginningString "- name:" `
-EndingString "shell: `"/bin/bash`"1" `
-ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
-ReplacementType "newfile" `
-NewFileWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"
#>

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITHOUT $EndingStringLineNumber = SUCCESSx2
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

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITHOUT $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESSx2
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

# Block, $BeginningString is NOT UNIQUE, $EndingString is UNIQUE, WITH $BeginningStringLineNumber, WITH $EndingStringLineNumber = SUCCESSx2
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
# From Line 604
<#
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
#>

<#
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
#>
<#
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

For ($loop=0; $loop -lt $ComparisonLoopCount; $loop++) {
                if ($PossibleBeginningStringLineNumbers[$loop] -lt $PossibleEndingStringLineNumbers[$loop]) {
                    Write-Host "The `$BegginningString line number $($PossibleBeginningStringLineNumbers[$loop]) comes before the `$EndingString line number $($PossibleEndingStringLineNumbers[$loop])"

                    New-Variable -Name "PossibleBlockToReplace$loop" -Value $($TextFileSourceContent | Select-Object -Index ($PossibleBeginningStringLineNumbers[$loop]..$($PossibleEndingStringLineNumbers[$loop]))) 
                    $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$loop" -ValueOnly)
                    $StartAndFinishLineNumbersArray += "Line $($PossibleBeginningStringLineNumbers[$loop]) to Line $($PossibleEndingStringLineNumbers[$loop]):`n$($TextFileSourceContent[$($($PossibleBeginningStringLineNumbers[$loop])-1)])`n...`n$($TextFileSourceContent[$($($PossibleEndingStringLineNumbers[$loop])-1)])"
                }
                if ($PossibleBeginningStringLineNumbers[$loop] -eq $PossibleEndingStringLineNumbers[$loop]) {
                    for ($loop2=0; $loop2 -lt $PossibleBeginningStringLineNumbers.Count; $loop2++) {
                        if ($PossibleBeginningStringLineNumbers[$loop] -lt $($PossibleEndingStringLineNumbers[$($loop2+1)])) {
                            New-Variable -Name "PossibleBlockToReplace$loop$loop2" -Value $($TextFileSourceContent | Select-Object -Index ($PossibleBeginningStringLineNumbers[$loop]..$($PossibleEndingStringLineNumbers[$($loop2)]))) 
                            $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$loop" -ValueOnly)
                            $StartAndFinishLineNumbersArray += "Line $($PossibleBeginningStringLineNumbers[$loop]) to Line $($PossibleEndingStringLineNumbers[$($loop2)]):`n$($TextFileSourceContent[$($($PossibleBeginningStringLineNumbers[$loop])-1)])`n...`n$($TextFileSourceContent[$($($PossibleEndingStringLineNumbers[$($loop2)])-1)])"
                        }
                    }
                    Write-Host "The `$BegginningString line number $($PossibleBeginningStringLineNumbers[$loop]) is the same as the `$EndingString line number $($PossibleEndingStringLineNumbers[$loop])"
                    Write-Host "Staggering beginning and ending line number..."
                    
                }
                if ($PossibleBeginningStringLineNumbers[$loop] -gt $PossibleEndingStringLineNumbers[$loop]) {
                    Write-Host "The `$BegginningString line number $($PossibleBeginningStringLineNumbers[$loop]) comes after the `$EndingString line number $($PossibleEndingStringLineNumbers[$loop])"
                    Write-Host "Staggering beginning and ending line number..."
                    if ($($PossibleEndingStringLineNumbers[$($loop+1)]) -ne $null) {
                        New-Variable -Name "PossibleBlockToReplace$loop" -Value $($TextFileSourceContent | Select-Object -Index ($PossibleBeginningStringLineNumbers[$loop]..$($PossibleEndingStringLineNumbers[$($loop+1)]))) 
                        $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$loop" -ValueOnly)
                        $StartAndFinishLineNumbersArray += "Line $($PossibleBeginningStringLineNumbers[$loop]) to Line $($PossibleEndingStringLineNumbers[$($loop+1)]):`n$($TextFileSourceContent[$($($PossibleBeginningStringLineNumbers[$loop])-1)])`n...`n$($TextFileSourceContent[$($($PossibleEndingStringLineNumbers[$($loop+1)])-1)])"
                    }
                }
            }
#>



# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGVrJEk8b6mVayFFXoxkK9ogz
# 1lGgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRH3p9z3kDW
# Coqt55Kuyb0/iyPvGDANBgkqhkiG9w0BAQEFAASCAQAk2Mx5FZ4x71Dy/FacZuAZ
# GQGvB9Dy/yVcHR650KPBGEt+ahDaTgb2PKVqTUSCRK0f5KsB+fzYno4YQsd2upT4
# bcLPr/0WVg6p/zz+kgexcftvft6YWkFqGJ4W6BbArO0BPl5JH6fN4S0V5uLUKsIb
# 6F9YzS/BSKZuLqgfJ1Kiv4ggligGmxgj0fb/MaikJygAm7tFcXHnyQer9H9EIfPo
# QyFWpYd5hS47Ww4dcmITUg9mBERQ+DNbrvW/CNHLwacdhHevpSCQatyGN2SNOj4P
# QVdJyFC7ClyIUuxQokoqMSFA0AxNneo5dBe/z47eUGibI/IM4DiYAUtN8xnFBC7r
# SIG # End signature block
