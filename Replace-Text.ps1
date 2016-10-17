<#
.SYNOPSIS
    The goal of this function is to make replacing text in any file or appropriate PowerShell object intuitive and easy
    while also providing flexible advanced features for more complex scenarios.

    WARNING: Be careful when using this function on larger files. The way that it is currently written, if you are attempting to
    replace text in a file that is 5GB in size, it will use ~5GB of memory beause it holds the contents of the file in memory as it
    makes changes.

.DESCRIPTION
    This function makes a distinction between three (3) types of text formations using the parameter $TextFormationType: 
    
    1) String - Specifying '-TextFormationType "String"' will result in replacing one or more occurrences of the string $StringToReplace
    with $ReplacementText. The parameter $StringToReplace is used to specify any combination of characters of any length WITHIN ONE LINE
    that can appear any number of times anywhere throughout the file (or PSObject).

    Advanced features allow for complex targeting of specific occurrences of $StringToReplace.
    
    2) Line - Specifying '-TextFormationType "Line"' will result in replacing one or more ENTIRE LINES with $Replacementtext
    depending on parameters used. The parameter $LineToReplace is used to specify either:
        A) All characters that make up an entire line
        B) Some characters that make up a line

    Advanced features allow for complex targeting of specific occurrences of lines that match $LineToReplace or lines that 
    contain $LineToReplace.

    3) Block - Specifying '-TextFormationType "Block"' will result in replacing all text between (inclusive) the line that contains
    the string $BeginningString and the line that contains $EndingString. By default, the replacement is INCLUSIVE, meaning the line that 
    contains $BeginningString and the line that contains $EndingString will ALSO BE REPLACED. Set the parameter '-Inclusive "No"' to
    avoid replacing the lines that contain $BeginningString and $EndingString.

    Currently, only one block of text can be replaced per invocation of this function, even if the boundaries $BeginningString and
    $EndingString appear multiple times throughout the file (or PSObject). Other parameters can be used to assist with targeting a
    specific block.  If it is unclear which occurrence of block the user would like to replace, the user will be prompted to choose.

    DEPENDENCIES
        None

.PARAMETER TextSource
    This parameter is MANDATORY.

    This parameter can take one of two types of inputs:
        1) A string that represents a file path

        2) An array object where BaseType = System.Array and Name = Object[]. (This is the default object type for objects created using 
        the "Get-Content" cmdlet)

.PARAMETER ReplacementType
    This parameter is MANDATORY.

    There are two (2) valid values for this parameter:
        1) Inplace - If $TextSource is a file path, then 'inplace' will overwrite the file with content reflecting the desired text 
        to be replaced. In other words, the original file content is temporarily held in memory, updated, and then written back to its
        original location.

        If $TextSource is an array object, 'inplace' will update the array object with content reflecting the desired text to be replaced.
        For example, if the function is used as follows ...

            Replace-Text -TextSource $ExampleArrayObject -ReplacementType "Inplace" ...
        
        ...then after the function completes, calling the object $ExampleArrayObject in the current scope will display the updated text.

        2) New - If $TextSource is a file path, then 'new' will cause the function to write a new file to the file path supplied in 
        the parameter $OutputWithUpdatedText with content reflecting the desired text to be replaced. In other words, the original file
        content is temporarily held in memory, updated, and then written to the location specified by the $OutputWithUpdatedText parameter.

        If $TextSource is an array object, 'new' will create a new array object using the name supplied in the parameter 
        $OutputWithUpdatedText. This new array object will be available in the current scope after the function completes.

.PARAMETER OutputWithUpdatedText
    This parameter is OPTIONAL.

    This parameter takes one of two types of inputs:
        1) A string that represents a file path

        2) A string that is/will be the name of an existing/new array object.
        For example, if the function is used as follows ...

            Replace-Text -TextSource $ExampleArrayObject -ReplacementType "New" -OutputWithUpdatedText "UpdatedExampleArrayObject" ...
        
        ...then after the function completes, calling the object $UpdatedExampleArrayObject in the current scope will display the 
        updated text.

.PARAMETER TextFormationType
    This parameter is MANDATORY.

    There are three (3) valid values for this parameter:
        1) String - Use this value in tandem with the parameter $StringToReplace and other parameters specific to string replacement
        in order to replace one or more occurrences of a string.

        2) Line - Use this value in tandem with parameters specific to replacing ENTIRE LINES to replace one or more ENTIRE LINES.

        3) Block - Use this value in tandem with parameters specific to replacing a block of text in order to replace ONE a block of text
        bounded by $BeginningString and $EndingString. Currently, only ONE block of text can be replaced per function invocation.

.PARAMETER ReplacementText
    This parameter is MANDATORY.
    
    This parameter takes a string or array of strings intended to replace the targeted text formation.

.PARAMETER StringToReplace
    This parameter is MANDATORY IF $TextFormationType = "String", and it should ONLY be used if $TextFormationType = "String".

    This parameter takes a string that is present anywhere in $TextSource. This parameter should only be used when $TextFormationType
    is "String".

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER StringLineNumber
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $StringToReplace.

    This parameter takes a string of numbers separated by commas that represent line numbers that contain the string $StringToReplace.

    IMPORTANT NOTE: Line Numbers are NOT the same as Index numbers. Line Numbers start at 1 whereas Index numbers start at 0. As a general
    rule, the line numbers you see in a text editor like Sublime, Atom, or Notepad++ are the line numbers you would use here.

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER StringOccurrenceOfLine
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $StringToReplace.

    This parameter takes a string of numbers separated by commas that represent the Nth occurrence of a line that contains the string
    $StringToReplace.

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER StringOccurrenceInLine
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $StringToReplace.

    This parameter takes a string of numbers separated by commas that represent the Nth occurrence of the string $StringToReplace within
    a sepecific line.

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER StringLineNumberVSStringOccurrenceInLineHashTable
    This parameter is OPTIONAL.

    This parameter takes a hashtable where each Key represents a Line Number that contains one or more occurrences of the string 
    $StringToReplace, and the corresponding Value is an array that contains numbers that represent the Nth occurrence of the string
    $StringToReplace within the Line Number referenced in the Key.

    For example, using the following hashtable...
    
    $SampleHashTable = @{
        "8" = @("2","3")
        "17" = @("1","2")
    }

    ...the second and third occurrence of the string $StringToReplace in line number 8 will be replaced, and the first and second
    occurrence of the string $StringToReplace in line number 17 will be replaced.

    IMPORTANT NOTE: If you intend to use this parameter, it MUST be used in tandem with the parameter $ReplaceSome = "Yes"

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER StringOccurrenceOfLineVSStringOccurrenceInLineHashTable
    This parameter is OPTIONAL.

    This parameter takes a hashtable where each Key represents an Nth occurrence of line that contains one or more occurrences of
    the string $StringToreplace, and the corresponding Value is an array that contains numbers that represent the Nth occurrence 
    of the string $StringToReplace within the Nth occurrence of line containing $StringToReplace referenced in the Key.

    For example, using the following hashtable...

    $AnotherSampleHashTable = @{
        "4" = @("2","3")
        "5" = @("1","2")
    }

    ...the second and third occurrences of the string $StringToReplace in the fourth occurrence of a line that contains $StringToReplace
    will be replaced. Also, the first and second occurrences of the string $StringToReplace in the fifth occurrence of a line that
    contains $StringToReplace will be replaced.

    IMPORTANT NOTE: If you intend to use this parameter, it MUST be used in tandem with the parameter $ReplaceSome = "Yes"

    This parameter should ONLY BE USED IF $TextFormationType = "String"

.PARAMETER LineToReplace
    This parameter is OPTIONAL.

    This parameter takes one of two types of inputs:
        1) A string of characters that make up an ENTIRE LINE
        2) A string of characters that make up PART OF A LINE

    In either case, one or more ENTIRE lines (depending on additional parameters provided) that match the string provided to this 
    parameter will be replaced.

    This parameter should ONLY BE USED IF $TextFormationType = "Line"

.PARAMETER LineLineNumber
    This parameter is OPTIONAL.

    This parameter takes a string of numbers separated by commas that represent line numbers that contain the string $LineToReplace.

    IMPORTANT NOTE: Line Numbers are NOT the same as Index numbers. Line Numbers start at 1 whereas Index numbers start at 0. As a general
    rule, the line numbers you see in a text editor like Sublime, Atom, or Notepad++ are the line numbers you would use here.

    This parameter should ONLY BE USED IF $TextFormationType = "Line"

.PARAMETER LineOccurrenceOfLine
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $LineToReplace

    This parameter takes a string of numbers separated by commas that represent the Nth occurrence of a line that contains the string
    $LineToReplace.

    This parameter should ONLY BE USED IF $TextFormationType = "Line"

.PARAMETER ReplaceAll
    This parameter is OPTIONAL.
    IMPORTANT NOTE: If none of the $ReplaceX parameters are used, the function defaults to $ReplaceAll = "Yes".

    There are two (2) valid values for this parameter:
        1) Yes / Y / y
        2) No / N / n

    This parameter acts like a switch, but is not coded as such for consistency and ease of use.

    When used with $TextFormationType = "String", $ReplaceAll has the following behavior:
        1) All instances of $StringToReplace are replaced with $ReplacementText.

    IMPORTANT NOTE: No other $StringX parameters (besided $StringToReplace) should be used when $ReplaceAll = "Yes". Parameter
    validation will throw an error if this is done.

    When used with $TextFormationType = "Line", $ReplaceAll has the following behavior when used in tandem with the following parameters:
        1) $LineToReplace - All ENTIRE LINES that contain the string $LineToReplace will be replaced with $ReplacementText
        
        2) $LineLineNumber - All ENTIRE LINES that match that pattern(s) found in the line numbers specified by $LineLineNumber
        will be replaced with $ReplacementText
        
        3) $LineToReplace and $LineOccurrenceOfLine - An index (starting at 1) of all lines that contain the string $LineToReplace
        is created. For each index number specified by $LineOccurrenceOfLine, that ENTIRE LINE will be replaced with $ReplacementText.

    In this version of the Replace-Text function, $ReplaceAll does NOT have any functionality when $TextFormationType = "Block"
    because this version of the function can only replace one (1) block of text per invocation.

.PARAMETER ReplaceOne
    This parameter is OPTIONAL.

    There are two (2) valid values for this parameter:
        1) Yes / Y / y
        2) No / N / n

    This parameter acts like a switch, but is not coded as such for consistency and ease of use.

    When used with $TextFormationType = "String", $ReplaceOne has the following behavior when used in tandem with the following parameters:
        1) $StringToReplace - If $TextSource contains ONLY ONE occurrence of $StringToReplace, then that occurrence will be
        replaced with $ReplacementText. If $TextSource contains MULTIPLE occurrences of $StringToReplace, the user will receive a 
        prompt for selection.

        2) $StringToReplace and $StringLineNumber - The parameter $StringLineNumber should only contain one line number that contains
        the string $StringToReplace. If that line number contains only one occurrence of $StringToReplace, it will be replaced with 
        $ReplacementText. If the line number contains multiple occurrences of $StringToReplace, then the user will receive a prompt 
        to select one specific occurrence.

        3) $StringToReplace and $StringLineNumber and $StringOccurrenceInLine - The parameter $StringLineNumber should only contain one 
        line number that contains the string $StringToReplace. Assuming that line number contains multiple occurrences of 
        $StringToReplace, the Nth occurrence specified by $StringOccurrenceInLine will be replaced. If the Nth occurrence of 
        $StringToReplace specified by $StringOccurrenceInLine does not exist in that $StringLineNumber, the user will receive a prompt 
        to select one Nth in-line-occurrence.

        4) $StringToReplace and $StringOccurrenceOfLine - The parameter $StringOccurrenceOfLine should only contain one number
        representing the Nth occurrence of a line that contains the string $StringToReplace. If that line contains only one
        occurrence of $StringToReplace, it will be replaced with $ReplacementText. If the line number contains multiple occurrences
        of $StringToReplace, then the user will receive a prompt to select one specific occurrence.

        5) $StringToReplace and $StringOccurrenceOfLine and $StringOccurrenceInLine - The parameter $StringOccurrenceOfLine should 
        only contain one number representing the Nth occurrence of a line that contains the string $StringToReplace. Assuming that
        the line contains multiple occurrences of $StringToReplace, the Nth occurrence specified by $StringOccurrenceInLine will
        be replaced. If the Nth occurrence of $StringToReplace specified by $StringOccurrenceInLine does not exist in that 
        $StringLineNumber, the user will receive a prompt to select one Nth in-line-occurrence.

    When used with $TextFormationType = "Line", $ReplaceOne has the following behavior when used in tandem with the following parameters:
        1) $LineToReplace - If multiple lines match or contain the string $LineToReplace, the user will be prompted to select one line to
        replace with $ReplacementText.
        
        2) $LineLineNumber - The parameter $LineLineNumber should only contain one line number. This line will be replaced 
        with $ReplacementText.

        3) $LineToReplace and $LineLineNumber - The parameter $LineLineNumber should only contain one line number. As long as this
        line number matches or contains the string $LineToReplace, then the ENTIRE LINE will be replaced with $ReplacementText.

        4) $LineToReplace and $LineOccurrenceOfLine - The parameter $LineOccurrenceOfLine should only contain one number representing
        the Nth occurrence of a line that matches or contains the string $LineToReplace. This line will be replaced with
        $ReplacementText.

    In this version of the Replace-Text function, $ReplaceOne does NOT have any functionality when $TextFormationType = "Block"
    because this version of the function is only capable of replacing one (1) block of text per invocation, making the $ReplaceOne
    parameter redundant/unnecessary.

.PARAMETER ReplaceSome
    This parameter is OPTIONAL.

    There are two (2) valid values for this parameter:
        1) Yes / Y / y
        2) No / N / n

    This parameter acts like a switch, but is not coded as such for consistency and ease of use.

    When used with $TextFormationType = "String", $ReplaceSome has the following behavior when used in tandem with the following parameters:
        1) $StringToReplace - If $TextSource contains ONLY ONE occurrence of $StringToReplace, then that occurrence will be
        replaced with $ReplacementText. If $TextSource contains MULTIPLE occurrences of $StringToReplace, the user will receive a 
        prompt for selection.

        2) $StringToReplace and $StringLineNumber - The parameter $StringLineNumber can contain one or more line numbers that contain
        the string $StringToReplace. If each line number contains only one occurrence of $StringToReplace, it will be replaced with 
        $ReplacementText. If any of the line numbers contain multiple occurrences of $StringToReplace, then the user will receive a prompt 
        to select one or more specific occurrences.

        3) $StringToReplace and $StringLineNumber and $StringOccurrenceInLine - The parameter $StringLineNumber can contain one or more 
        line numbers that contain the string $StringToReplace. The parameter $StringOccurrenceInLine can contain one or more 
        numbers that represent the Nth occurence of $StringToReplace in a line. The Nth occurrence(s) specified by $StringOccurrenceInLine
        will be replaced for each line number specified in $StringLineNumber. If the Nth occurrence of $StringToReplace specified by 
        $StringOccurrenceInLine does not exist for a particular line number, the user will receive a prompt to select one or more 
        Nth in-line-occurrence for that line.

        4) $StringToReplace and $StringOccurrenceOfLine - The parameter $StringOccurrenceOfLine can contain one or more numbers
        representing the Nth occurrence of a line that contains the string $StringToReplace. If more than one occurrence of
        $StringToReplace exists in a line, then the user will receive a prompt to select one or more Nth in-line-occurrences
        for that line.

        5) $StringToReplace and $StringOccurrenceOfLine and $StringOccurrenceInLine - The parameter $StringOccurrenceOfLine can contain 
        one or more numbers representing the Nth occurrence of a line that contains the string $StringToReplace. The parameter 
        $StringOccurrenceInLine can contain one or more numbers that represent the Nth occurence of $StringToReplace in a line. The 
        Nth occurrence(s) specified by $StringOccurrenceInLine will be replaced for each Nth line specified by $StringOccurrenceOfLine.
        If the Nth occurrence of $StringToReplace specified by $StringOccurrenceInLine does not exist for a particular line, the user 
        will receive a prompt to select one or more Nth in-line-occurrences for that line.

        6) $StringToReplace and $StringLineNumberVSStringOccurrenceInLineHashTable - The parameter 
        $StringLineNumberVSStringOccurrenceInLineHashTable takes a hashtable where each Key represents a Line Number that contains 
        one or more occurrences of the string $StringToReplace, and the corresponding Value is an array that contains numbers that 
        represent the Nth occurrence of the string $StringToReplace within the Line Number referenced in the Key.

        For example, using the following hashtable...
    
        $SampleHashTable = @{
            "8" = @("2","3")
            "17" = @("1","2")
        }

        ...the second and third occurrence of the string $StringToReplace in line number 8 will be replaced, and the first and second
        occurrence of the string $StringToReplace in line number 17 will be replaced.

        7) $StringToReplace and $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable - This parameter takes a hashtable where each 
        Key represents an Nth occurrence of line that contains one or more occurrences of the string $StringToreplace, and the 
        corresponding Value is an array that contains numbers that represent the Nth occurrence of the string $StringToReplace within 
        the Nth occurrence of line containing $StringToReplace referenced in the Key.

        For example, using the following hashtable...

        $AnotherSampleHashTable = @{
            "4" = @("2","3")
            "5" = @("1","2")
        }

        ...the second and third occurrences of the string $StringToReplace in the fourth occurrence of a line that contains $StringToReplace
        will be replaced. Also, the first and second occurrences of the string $StringToReplace in the fifth occurrence of a line that
        contains $StringToReplace will be replaced.

    When used with $TextFormationType = "Line", $ReplaceSome has the following behavior when used in tandem with the following parameters:
        1) $LineToReplace - If ONLY ONE line in $TextSource matches or contains the string $LineToReplace, then that ENTIRE LINE
        will be replaced with $ReplacementText. If MULTIPLE lines in $textSource match or contain the string $LineToReplace, then the 
        user will be prompted for selection.

        2) $LineLineNumber - The parameter $LineLineNumber can contain one or more line numbers. Each of these ENTIRE LINES will be 
        replaced with $ReplacementText.

        3) $LineToReplace and $LineLineNumber - The parameter $LineLineNumber can contain one or more line numbers. As long as each
        of these line numbers matches or contains the string $LineToReplace, these ENTIRE LINES will be replaced with $ReplacementText.

        4) $LineToReplace and $LineOccurrenceOfLine - The parameter $LineOccurrenceOfLine can contain one or more numbers representing
        the Nth occurrence of a line that matches or contains the string $LineToReplace. These line will be replaced with
        $ReplacementText.

    In this version of the Replace-Text function, $ReplaceSome does NOT have any functionality when $TextFormationType = "Block"
    because this version of the function is only capable of replacing one (1) block of text per invocation.

.PARAMETER BeginningString
    This parameter is MANDATORY IF $TextFormationType = "Block".

    This parameter takes a string the marks the upper bound of a block of text the is being targeted to be replaced. If more than
    one line contains the string $BeginningString, the user will be prompted for selection.

    The line that contains the string $BeginningString marks the upper bound of the targeted block of text to be replaced
    in $TextSource.

    The ENTIRE LINE that contains the string $BeginningString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $BeginningString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER BeginningStringLineNumber
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $BeginningString.

    This parameter takes one (1) number that represents a line number (NOT Index number) that contains the string $BeginningString.
    This line number marks the upper bound of the targeted block of text to be replaced in $TextSource.

    The ENTIRE LINE that contains the string $BeginningString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $BeginningString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER BeginningStringOccurrenceOfLine
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $BeginningString.

    This parameter takes one (1) number that represents the Nth occurrence of a line that contains the string $BeginningString.

    This line marks the upper bound of the targeted block of text to be replaced in $TextSource.

    The ENTIRE LINE that contains the string $BeginningString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $BeginningString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER EndingString
    This parameter is MANDATORY IF $TextFormationType = "Block".

    This parameter takes a string the marks the lower bound of a block of text the is being targeted to be replaced. If more than
    one line contains the string $EndingString, the user will be prompted for selection.

    The line that contains the string $EndingString marks the lower bound of the targeted block of text to be replaced
    in $TextSource.

    The ENTIRE LINE that contains the string $EndingString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $EndingString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER EndingStringLineNumber
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $EndingString.

    This parameter takes one (1) number that represents a line number (NOT Index number) that contains the string $EndingString.
    This line number marks the lower bound of the targeted block of text to be replaced in $TextSource.

    The ENTIRE LINE that contains the string $EndingString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $EndingString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER EndingStringOccurrenceOfLine
    This parameter is OPTIONAL.
    This parameter must be used in tandem with $EndingString.

    This parameter takes one (1) number that represents the Nth occurrence of a line that contains the string $EndingString.

    This line marks the upper bound of the targeted block of text to be replaced in $TextSource.

    The ENTIRE LINE that contains the string $EndingString will be replaced if $Inclusive = "Yes". The ENTIRE LINE that contains 
    the string $EndingString will NOT BE TOUCHED if $Inclusive = "No".

    This parameter should ONLY BE USED IF $TextFormationType = "Block"


.PARAMETER Inclusive
    This parameter is OPTIONAL.

    There are two (2) valid values for this parameter:
        1) Yes / Y / y
        2) No / N / n

    This parameter acts like a switch, but is not coded as such for consistency and ease of use.

    If $Inclusive = "Yes", then the lines identified by $BeginningString and $EndingString will be replaced by $ReplacementText.
    If $Inclusive = "No", then all lines BETWEEN $BeginningString and $EndingString will be replaced by $RelpacementText.

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.PARAMETER BlockToReplace
    This parameter is OPTIONAL.

    This parameter takes a string or an array object (i.e. array of lines of text). If found in $TextSource, it will be replaced
    by $ReplacementText. If the provided string/array of lines is not found in $TextSource, the function will throw an error.

    WARNING: If a string is provided to this parameter, please pay close attention to line breaks.

    This parameter should ONLY BE USED IF $TextFormationType = "Block"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains many occurrences of the string '- name:' on
    many different lines throughout the file.

    Goal: Replace all occurrences of the string '- name:' with the string 'Hi' in the file 
    V:\powershell\Testing\updated-phase1-template.yml

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "string" `
    -StringToReplace "- name:" `
    -ReplaceAll "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "inplace"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains many occurrences of the string '- name:' on
    many different lines throughout the file. Line Number 8 contains only one occurrence of the string '- name:'

    Goal: Replace the occurrence of the string '- name:' in ONLY line 8 and write the updated content to a new file.

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "string" `
    -StringToReplace "- name:" `
    -StringLineNumber "8" `
    -ReplaceOne "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "new" `
    -OutputWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains many occurrences of the string '- name:' on
    many different lines throughout the file. The file is dynamically generated, so line numbers in which the string '- name:'
    appears are not necessarily consistent. However, we do know that the third line that ends up containing '- name:' is the one
    that requires the string be replaced. The string '- name:' appears only once in that line.

    Goal: Replace the string '- name:' in the third line that contains said string and write the updated content back to the original file.

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "string" `
    -StringToReplace "- name:" `
    -StringOccurrenceOfLine "3" `
    -ReplaceOne "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "inplace"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains many occurrences of the string '- name:' on
    many different lines throughout the file. The file is dynamically generated, so line numbers in which the string '- name:'
    appears are not necessarily consistent. However, we do know that the third line that ends up containing '- name:' is the one
    that requires the string be replaced. The string '- name:' appears multiple times in that line.

    Goal: In the third line that contains the string '- name:', replace the first and second occurrences of said string and write
    the updated content to a new file.

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "string" `
    -StringToReplace "- name:" `
    -StringOccurrenceOfLine "3" `
    -StringOccurrenceInLine "1, 2"
    -ReplaceSome "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "new" `
    -OutputWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains many occurrences of the string '- name:' on
    many different lines throughout the file. The file is dynamically generated, so line numbers in which the string '- name:'
    appears are not necessarily consistent. However, we do know that the third and fifth lines that end up containing '- name:' 
    are the ones that require the string be replaced. The string '- name:' appears multiple times in each aforementioned line.

    Goal: Replace the second and fourth occurrence of '- name:' in the third line that contains the string. Replace the 
    first and third occurrence of '- name:' in the fifth line that contains the string. Write the updated content to a new
    file.

    $ReplacementMap = @{
        "3" = @("2","4")
        "5" = @("1","3")
    }

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "string" `
    -StringToReplace "- name:" `
    -StringOccurrenceOfLineVSStringOccurrenceInLineHashTable $ReplacementMap `
    -ReplaceSome "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "new" `
    -OutputWithUpdatedText "V:\powershell\Testing\newfile_with_updated_text.yml"

.EXAMPLE
    Scenario: The PowerShell array object $DocumentContent has previously been created, and each array element is a line of text.
    We are not sure exactly what the content of the object is exactly, but we know we want to replace lines 6, 10, and 15 with 
    the line "This is a new line". (NOTE: Line Numbers 6, 10, and 15 are array elements 5, 9, and 14)

    Goal: Replace lines 6, 10, and 15 with $ReplacementText and create a new PowerShell array object called $UpdatedDocumentContent.

    Replace-Text -TextSource "$DocumentContent" `
    -TextFormationType "line" `
    -LineLineNumber "6, 10, 15" `
    -ReplaceSome "Yes" `
    -ReplacementText "This is a new line" `
    -ReplacementType "new" `
    -OutputWithUpdatedText "UpdatedDocumentContent"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml contains multiple lines which contain or match the string
    'This powershell stuff is crazy'. We only want to replace the first, fifth, and tenth lines that end up matching or containing 
    this string.

    Goal: Replace the first, fifth, and tenth lines that contain the string 'This powershell stuff is crazy' and write the updated
    content back to the original file.

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "line" `
    -LineToReplace "This powershell stuff is crazy" `
    -LineOccurrenceOfLine "1, 5, 10"
    -ReplaceSome "Yes" `
    -ReplacementText "Hi" `
    -ReplacementType "inplace"

.EXAMPLE
    Scenario: The PowerShell array object $DocumentContent has previously been created, and each array element is a line of text.
    Multiple lines (i.e. array elements) contain the string 'This powershell stuff is crazy'. We want to replace the second and 
    ninth lines that end up matching or containing this string.

    Goal: Replace the second and ninth occurrences of lines that match or contain the string 'This powershell stuff is crazy'
    and updated the original PowerShell array object $DocumentContent.

    Replace-Text -TextSource "$DocumentContent" `
    -TextFormationType "line" `
    -LineOccurrenceOfLine "2, 9" `
    -ReplaceSome "Yes" `
    -ReplacementText "This is a new line" `
    -ReplacementType "inplace" `

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml is a file that contains hundreds of lines of text. There is a 
    specific block of text that you would like to replace.

    Goal: Replace that specific block of text and create a new PowerShell array object called NewContent with the updated content 
    available in the current scope.

    $SourceContent = Get-Content -Path "V:\powershell\Testing\updated-phase1-template.yml" -Encoding Ascii
    $BlockToReplace = Get-Content -Path "V:\powershell\Testing\OLD-phase1-template.yml" | Select-Object -Index (16..24)

    Replace-Text -TextSource "$SourceContent" `
    -TextFormationType "block" `
    -BlockToReplace $BlockToReplace `
    -Inclusive "No" `
    -ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
    -ReplacementType "new" `
    -OutputWithUpdatedText "NewContent"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\updated-phase1-template.yml is a file that contains hundreds of lines of text. There is a 
    specific block of text that you would like to replace that begins on line number 5 and ends on line number 9.

    Goal: Replace lines 5 through 9 INCLUSIVE and write the updated content back to the original file.

    Replace-Text -TextSource "V:\powershell\Testing\updated-phase1-template.yml" `
    -TextFormationType "block" `
    -BeginningStringLineNumber "5" `
    -EndingStringLineNumber "9" `
    -Inclusive "Yes" `
    -ReplacementText "Hi there`nThis is new stuff`nIndeed, it is" `
    -ReplacementType "inplace" `

.EXAMPLE
    Scenario: The file V:\powershell\Testing\IT-Policy.docx is a document that contains thousands of lines of text. There is a 
    block of text 100 lines long that begins with the line 'The IT Manager shall be respnsible for IT.' and ends with the line
    'So, everyone gets a new laptop.'

    Goal: Replace the 100 lines of text BETWEEN the lines 'The IT Manager shall be respnsible for IT.' and 'So, everyone gets a
    new laptop.' and write the updated content to a new file.

    Replace-Text -TextSource "V:\powershell\Testing\IT_Policy.docx" `
    -TextFormationType "block" `
    -BeginningString "The IT Manager shall be respnsible for IT." `
    -EndingString "So, everyone gets a new laptop." `
    -Inclusive "No" `
    -RepalcementText "The IT Manager is a rockstar.`nSenior leadership shall support all his/her decisions" `
    -ReplacementType "new" `
    -NewFileWithUpdatedText "V:\powershell\Testing\Updated_IT_Policy"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\IT-Policy.docx is a document that contains thousands of lines of text. There is a 
    block of text N lines long that begins with the line 'Section Summary:' and ends with the line 'Section 2: Responsibilities'. The
    The line 'Section Summary:' occurs multiple times throughout the document, but it only appears once before the line
    'Section 2: Responsibilities'. The line 'Section 2: Responsibilities' is unique and only appears once in the document.

    Goal: Replace all lines BETWEEN the first occurrence of the line 'Section Summary:' and 'Section 2: Responsibilities' and 
    update the original file.

    $UpdatedSectionParagraph = Get-Content V:\powershell\Testing\updated_paragraph.txt

    Replace-Text -TextSource "V:\powershell\Testing\IT_Policy.docx" `
    -TextFormationType "block" `
    -BeginningString "Section Summary:" `
    -EndingString "Section 2: Responsibilities" `
    -Inclusive "No" `
    -RepalcementText "$UpdatedSectionParagraph" `
    -ReplacementType "inplace"

.EXAMPLE
    Scenario: The file V:\powershell\Testing\IT-Policy.docx is a document that contains thousands of lines of text. There is a 
    block of text N lines long that begins with the line 'Section Summary:' and ends with the line 'Section 12: SLA'. The
    line 'Section Summary:' occurs multiple times throughout the document, and it appears multiple times before the line
    'Section 12: SLA'. The line 'Section 12: SLA' is unique and only appears once in the document.

    Goal: Replace all lines BETWEEN the occurrence of the line 'Section Summary:' immediately preceding the line
    'Section 12: SLA' and the line 'Section 12: SLA' and update the original file.

    $UpdatedSectionParagraph = Get-Content V:\powershell\Testing\updated_paragraph.txt

    Replace-Text -TextSource "V:\powershell\Testing\IT_Policy.docx" `
    -TextFormationType "block" `
    -BeginningString "Section Summary:" `
    -EndingString "Section 2: Responsibilities" `
    -BeginningStringOccurrencePreEndingString "1" `
    -Inclusive "No" `
    -RepalcementText "$UpdatedSectionParagraph" `
    -ReplacementType "inplace"

.OUTPUTS
    If $TextSource is a file path, and:
        A) $ReplacementType = "inplace", output will be a file written to the location provided in $TextSource.
        B) $ReplacementType = "new", output will be a file written to the file path specified by $OutputWithUpdatedText

    If $TextSource is an array object, and:
        A) $ReplacementType = "inplace", output will be the array object provided to $TextSource with updated text in Global Scope.
        B) $ReplacementType = "new", output will be a new array object named according to the string provided to $OutputWithUpdatedText
        in Global Scope.

.NOTES
    WARNING: Be careful when using this function on larger files. The way that it is currently written, if you are attempting to
    replace text in a file that is 5GB in size, it will use ~5GB of memory beause it holds the contents of the file in memory as it
    makes changes.

#>

function Replace-Text {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $TextSource = $(Read-Host -Prompt "Please enter the full path to the file containing the text you would like to replace"),

        [Parameter(Mandatory=$False)]
        $ReplacementType = $(Read-Host -Prompt "Please enter 'inplace' to replace text directly in `$TextSource or 'new' to create a new PSObject or file with the updated text [inplace/new]"),

        [Parameter(Mandatory=$True)]
        $OutputWithUpdatedText, # Either file path or string the represents the name of the new array object to be created

        [Parameter(Mandatory=$False)]
        $TextFormationType = $(Read-Host -Prompt "Would you like to replace a string, and entire line, or a whole block of text? [string/line/block]"),

        [Parameter(Mandatory=$False)]
        $ReplacementText = $(Read-Host -Prompt "Please enter the NEW text that you would like to use to replace the original text"),

        [Parameter(Mandatory=$False)]
        $StringToReplace,

        [Parameter(Mandatory=$False)]
        [array]$StringLineNumber,

        [Parameter(Mandatory=$False)]
        [array]$StringOccurrenceOfLine,

        [Parameter(Mandatory=$False)]
        [array]$StringInLineOccurrence,

        [Parameter(Mandatory=$False)]
        $StringLineNumberVSStringOccurrenceInLineHashTable,

        [Parameter(Mandatory=$False)]
        $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable,

        [Parameter(Mandatory=$False)]
        $LineToReplace,

        [Parameter(Mandatory=$False)]
        [array]$LineLineNumber,

        [Parameter(Mandatory=$False)]
        [array]$LineOccurrenceOfLine,

        [Parameter(Mandatory=$False)]
        $ReplaceAll,

        [Parameter(Mandatory=$False)]
        $ReplaceOne,

        [Parameter(Mandatory=$False)]
        $ReplaceSome,

        [Parameter(Mandatory=$False)]
        $BeginningString,

        [Parameter(Mandatory=$False)]
        $BeginningStringLineNumber,

        [Parameter(Mandatory=$False)]
        $BeginningStringOccurrenceOfLine,

        [Parameter(Mandatory=$False)]
        $EndingStringOccurrencePostBeginningString,

        [Parameter(Mandatory=$False)]
        $EndingString,

        [Parameter(Mandatory=$False)]
        $EndingStringLineNumber,

        [Parameter(Mandatory=$False)]
        $EndingStringOccurrenceOfLine,

        [Parameter(Mandatory=$False)]
        $BeginningStringOccurrencePreEndingString,

        [Parameter(Mandatory=$False)]
        $Inclusive = "Yes",

        [Parameter(Mandatory=$False)]
        $BlockToReplace

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
    if ($($TextSource.GetType()).Name -eq "String") {
        if (! $(Test-Path $TextSource)) {
            Write-Host "Since the parameter `$TextSource is a string (as opposed to an object), an assumption was made that a file path was provided. The file path provided does not exist. Please review the file path and try again. Halting!"
            Write-Error "Since the parameter `$TextSource is a string (as opposed to an object), an assumption was made that a file path was provided. The file path provided does not exist. Please review the file path and try again. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $TextSourceContent = Get-Content -Path $TextSource -Encoding Ascii

        # Since $TextSource is a file path, validate $OutputWithUpdatedText
        # But first, need to validate $ReplaementType
        $ValidReplacementTypeValues = @("inplace","new")
        if ($ValidReplacementTypeValues -notcontains $ReplacementType) {
            Write-Host "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Valid values are as follows:"
            $ValidReplacementTypeValues
            $ReplacementType = Read-Host -Prompt "Please enter 'inplace' to replace text directly in $TextSource or 'new' to create a new file with the updated text. [inplace/new]"
            if ($ValidReplacementTypeValues -notcontains $ReplacementType) {
                Write-Host "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Halting!"
                Write-Error "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ReplacementType -eq "inplace") {
            $OutputWithUpdatedText = $TextSource
        }
        if ($ReplacementType -eq "new") {
            if ($OutputWithUpdatedText -eq $null) {
                Write-Host "Since `$TextSource is a file path, and `$ReplacementType is `"new`", a new file path must be provided to the parameter `$OutputWithUpdatedText. Please try again and provide an output file path using the `$OutputWithUpdatedText parameter. Halting!"
                Write-Error "Since `$TextSource is a file path, and `$ReplacementType is `"new`", a new file path must be provided to the parameter `$OutputWithUpdatedText. Please try again and provide an output file path using the `$OutputWithUpdatedText parameter. Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($OutputWithUpdatedText -ne $null) {
                if ($($OutputWithUpdatedText | Select-String -Pattern "\\").Matches.Success -ne $true `
                -or $($OutputWithUpdatedText | Select-String -Pattern "/").Matches.Success -ne $true) {
                    Write-Host "Since `$TextSource is a file path, `$OutputWithUpdatedText must be a valid file path. Please check the path for `$OutputWithUpdatedText and try again. Halting!"
                    Write-Error "Since `$TextSource is a file path, `$OutputWithUpdatedText must be a valid file path. Please check the path for `$OutputWithUpdatedText and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                if ($($OutputWithUpdatedText | Select-String -Pattern "\\").Matches.Success -eq $true) {
                    $position = $OutputWithUpdatedText.IndexOf("\")
                }
                if ($($OutputWithUpdatedText | Select-String -Pattern "/").Matches.Success -eq $true) {
                    $position = $OutputWithUpdatedText.IndexOf("/")
                }
                $ExistingDirectory = $OutputWithUpdatedText.Substring(0, $position)
                $NewFileName = $OutputWithUpdatedText.Substring($position+1)
                if (! $(Test-Path $ExistingDirectory)) {
                    Write-Host "Since `$TextSource is a file path, `$OutputWithUpdatedText must be a valid file path. The directory $ExistingDirectory does not exist. Please check the path for `$OutputWithUpdatedText and try again. Halting!"
                    Write-Error "Since `$TextSource is a file path, `$OutputWithUpdatedText must be a valid file path. The directory $ExistingDirectory does not exist. Please check the path for `$OutputWithUpdatedText and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
    if ($($TextSource.GetType()).Name -like "*Object*" -and $($TextSource.GetType()).BaseType -like "*Array*") {
        $TextSourceContent = $TextSource

        # Since $TextSource is an array object, make the name provided in $OutputWithUpdatedText the name of the new array object
        # But first, need to validate $ReplaementType
        $ValidReplacementTypeValues = @("inplace","new")
        if ($ValidReplacementTypeValues -notcontains $ReplacementType) {
            Write-Host "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Valid values are as follows:"
            $ValidReplacementTypeValues
            $ReplacementType = Read-Host -Prompt "Please enter 'inplace' to replace text directly in the array object provided to the `$TextSource parameter, or 'new' to create a new array object with the updated text. [inplace/new]"
            if ($ValidReplacementTypeValues -notcontains $ReplacementType) {
                Write-Host "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Halting!"
                Write-Error "'$ReplacementType' is not a valid value for the parameter `$ReplacementType. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ReplacementType -eq "inplace") {
            $OutputWithUpdatedText = Get-Variable | foreach {
                if ($_.Value -match $TextSource -and $_.Name -ne "TextSource" -and $_.Name -ne "TextSourceContent") {
                    $_.Name
                }
            }
        }
        if ($ReplacementType -eq "new") {
            if ($OutputWithUpdatedText -eq $null) {
                Write-Host "Since `$TextSource is an array object, and `$ReplacementType is `"new`", a name for the new array object must be provided to the parameter`$OutputWithUpdatedText."
                $OutputWithUpdatedText = Read-Host -Prompt "Please provide a name for the new array object variable that will be available in the current scope after the Replace-Text function completes"
            }
        }
    }

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

    if ($BeginningStringLineNumber.Count -gt 1) {
        Write-Host "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$BeginningStringLineNumber, and $($BeginningStringLineNumber.Count) were provided. Halting!"
        Write-Error "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$BeginningStringLineNumber, and $($BeginningStringLineNumber.Count) were provided. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($EndingStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringLineNumber = $EndingStringLineNumber.Split(",").Trim()
    }
    if (! $($EndingStringLineNumber | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringLineNumber = $EndingStringLineNumber
    }

    if ($EndingStringLineNumber.Count -gt 1) {
        Write-Host "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$EndingStringLineNumber, and $($EndingStringLineNumber.Count) were provided. Halting!"
        Write-Error "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$EndingStringLineNumber, and $($EndingStringLineNumber.Count) were provided. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($BeginningStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringOccurrenceOfLine = $BeginningStringOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($BeginningStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$BeginningStringOccurrenceOfLine = $BeginningStringOccurrenceOfLine
    }

    if ($BeginningStringOccurrenceOfLine.Count -gt 1) {
        Write-Host "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$BeginningStringOccurrenceOfLine, and $($BeginningStringOccurrenceOfLine.Count) were provided. Halting!"
        Write-Error "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$BeginningStringOccurrenceOfLine, and $($BeginningStringOccurrenceOfLine.Count) were provided. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($($EndingStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringOccurrenceOfLine = $EndingStringOccurrenceOfLine.Split(",").Trim()
    }
    if (! $($EndingStringOccurrenceOfLine | Select-String -Pattern ",").Matches.Success) {
        [array]$EndingStringOccurrenceOfLine = $EndingStringOccurrenceOfLine
    }

    if ($EndingStringOccurrenceOfLine.Count -gt 1) {
        Write-Host "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$EndingStringOccurrenceOfLine, and $($EndingStringOccurrenceOfLine.Count) were provided. Halting!"
        Write-Error "This version of the Replace-Text function can only process one block of text at a time. As such, it can only process one (1) `$EndingStringOccurrenceOfLine, and $($EndingStringOccurrenceOfLine.Count) were provided. Halting!"
        $global:FunctionResult = "1"
        return
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
    if ($EndingStringLineNumber.Count -ge 1) {
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
        if ($LineLineNumber.Count -ge 1) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine.Count -ge 1) {
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
        if ($BeginningStringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringOccurrenceOfLine.Count -ge 1) {
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
        if ($EndingStringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine.Count -ge 1) {
            Write-Host "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"string`" are as follows:"
            $ParametersForFormationTypeString
            Write-Error "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine.Count -ge 1 -and $StringLineNumber.Count -ge 1) {
            Write-Host "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter StringOccurrenceOfLine OR the parameter StringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence.Count -ge 1 -and $StringLineNumberVSStringOccurrenceInLineHashTable -ne $null) {
            Write-Host "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringLineNumberVSStringOccurrenceInLineHashTable. Halting!"
            Write-Error "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringLineNumberVSStringOccurrenceInLineHashTable. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringLineNumberVSStringOccurrenceInLineHashTable -ne $null -and $ReplaceSome -eq $null) {
            Write-Host "The parameter `$StringLineNumberVSStringOccurrenceInLineHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
            Write-Error "The parameter `$StringLineNumberVSStringOccurrenceInLineHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence.Count -ge 1 -and $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -ne $null) {
            Write-Host "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringOccurrenceOfLineVSStringOccurrenceInLineHashTable. Halting!"
            Write-Error "Please use EITHER the parameter StringInLineOccurrence OR the parameter StringOccurrenceOfLineVSStringOccurrenceInLineHashTable. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -ne $null -and $ReplaceSome -eq $null) {
            Write-Host "The parameter `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
            Write-Error "The parameter `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable is meant to be with the `$ReplaceSome parameter (which was not used). Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -ne $null -and $StringLineNumberVSStringOccurrenceInLineHashTable -ne $null) {
            Write-Host "Please use EITHER the parameter StringOccurrenceOfLineVSStringOccurrenceInLineHashTable OR the parameter StringLineNumberVSStringOccurrenceInLineHashTable. Halting!"
            Write-Error "Please use EITHER the parameter StringOccurrenceOfLineVSStringOccurrenceInLineHashTable OR the parameter StringLineNumberVSStringOccurrenceInLineHashTable. Halting!"
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
        if ($StringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence.Count -ge 1) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine.Count -ge 1) {
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
        if ($BeginningStringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$BeginningStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($BeginningStringOccurrenceOfLine.Count -ge 1) {
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
        if ($EndingStringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingStringLineNumber is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine.Count -ge 1) {
            Write-Host "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"line`" are as follows:"
            $ParametersForFormationTypeLine
            Write-Error "The parameter `$EndingStringOccurrenceOfLine is meant for use with `$TextFormationType = `"block`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine.Count -ge 1 -and $LineLineNumber.Count -ge 1) {
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
        if ($StringLineNumber.Count -ge 1) {
            Write-Host "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringLineNumber is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringInLineOccurrence.Count -ge 1) {
            Write-Host "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$StringInLineOccurrence is meant for use with `$TextFormationType = `"string`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($StringOccurrenceOfLine.Count -ge 1) {
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
        if ($LineLineNumber.Count -ge 1) {
            Write-Host "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            Write-Host "Parameters available when `$TextFormationType = `"block`" are as follows:"
            $ParametersForFormationTypeBlock
            Write-Error "The parameter `$LineLineNumber is meant for use with `$TextFormationType = `"line`". Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($LineOccurrenceOfLine.Count -ge 1) {
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
        if ($BeginningStringOccurrenceOfLine.Count -ge 1 -and $BeginningStringLineNumber.Count -ge 1) {
            Write-Host "Please use EITHER the parameter BeginningStringOccurrenceOfLine OR the parameter BeginningStringLineNumber. Halting!"
            Write-Error "Please use EITHER the parameter BeginningStringOccurrenceOfLine OR the parameter BeginningStringLineNumber. Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($EndingStringOccurrenceOfLine.Count -ge 1 -and $EndingStringLineNumber.Count -ge 1) {
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
        if ($StringLineNumber.Count -ge 1) {
            Write-Verbose "If the parameter `$StringLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the string `$StringToReplace in `$TextSource" -Verbose
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
        if ($LineLineNumber.Count -ge 1) {
            Write-Verbose "If the parameter `$LineLineNumber is used, then the parameter `$ReplaceAll should NOT be set to 'Yes'." -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the line `$LineToReplace in `$TextSource" -Verbose
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
        if ($StringInLineOccurrence.Count -ge 1) {
            Write-Verbose "The parameter `$StringInLineOccurrence is meant to be used in cases where a single line contains multiple occurrences of `$StringToReplace" -Verbose
            Write-Verbose "The `$ReplaceAll parameter is meant to be used in cases where the goal is to replace EVERY occurrence of the line `$LineToReplace in `$TextSource" -Verbose
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
            # First, make sure that $StringToReplace is present in $TextSource
            if (! $($TextSourceContent | Select-String -Pattern "$StringToReplace").Matches.Success) {
                Write-Host "The string '$StringToReplace' was not found in `$TextSource"
                $StringToReplace = Read-Host -Prompt "Please enter a string that you would like to replace in the file `$TextSource"
                if (! $($TextSourceContent | Select-String -Pattern "$StringToReplace").MatchesSuccess) {
                    Write-Host "The string '$StringToReplace' was not found in `$TextSource"
                    Write-Error "The string '$StringToReplace' was not found in `$TextSource. Halting!"
                    return
                }
            }

            # If $StringLineNumber is present, we can narrow down the list of $PossibleStringLineNumbers, but we also have to 
            # validate that $TextSourceContent[$StringLineNumber] actually contains $StringToReplace
            if ($StringLineNumber.Count -ge 1) {
                $StringLineCheck = @()
                foreach ($LineNumber in $StringLineNumber) {
                    if ($($TextSourceContent[$LineNumber-1] | Select-String -Pattern "$StringToReplace").Matches.Success) {
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
                        $PotentialStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
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
                        if ($InvalidStringLineChoices.Count -ge 1) {
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
                            if ($InvalidStringLineChoices.Count -ge 1) {
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
                # If $StringToReplace appears multiple times in $TextSource, but the $StringLineNumber is not provided, 
                # and either $ReplaceSome or $ReplaceOne is used, prompt user to provide $StringLineNumber
                if ($ReplaceSome -eq "Yes" -or $ReplaceSome -eq "y") {
                    if ($StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -ne $null) {
                        $PotentialStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object

                        [array]$StringOccurrenceOfLineArray = $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable.Keys
                        [array]$UpdatedStringLineNumbers = for ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            foreach ($obj1 in $StringOccurrenceOfLineArray) {
                                if ($($loop+1) -eq $obj1) {
                                    $PotentialStringLineNumbers[$loop]
                                }
                            }
                            
                        }
                    }
                    if ($StringLineNumberVSStringOccurrenceInLineHashTable -ne $null) {
                        [array]$UpdatedStringLineNumbers = $StringLineNumberVSStringOccurrenceInLineHashTable.Keys
                    }
                    if ( $($TextSourceContent | Select-String -Pattern "$StringToReplace").Count -eq 1) {
                        $UpdatedStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                    }
                    if ($($TextSourceContent | Select-String -Pattern "$StringToReplace").Count -gt 1 -and $StringLineNumberVSStringOccurrenceInLineHashTable -eq $null `
                    -and $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -eq $null) {
                        $PotentialStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
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
                            if ($InvalidStringLineChoices.Count -ge 1) {
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
                                if ($InvalidStringLineChoices.Count -ge 1) {
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
                    if ( $($TextSourceContent | Select-String -Pattern "$StringToReplace").Count -eq 1) {
                        $UpdatedStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                    }
                    if ($($TextSourceContent | Select-String -Pattern "$StringToReplace").Count -gt 1) {
                        $PotentialStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$StringToReplace").LineNumber
                        $PotentialStringLineNumbers = $PotentialStringLineNumbers | Sort-Object
                        $PotentialStringLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$StringToReplace").Line
                        $PotentialStringLineChoices = For ($loop=0; $loop -lt $PotentialStringLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialStringLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialStringLineNumbers[$loop])-1])"
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
                            if ($InvalidStringLineChoices.Count -ge 1) {
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
                                if ($InvalidStringLineChoices.Count -ge 1) {
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
            # First, Make sure that $LineToReplace is found in the $TextSource
            if (! $($TextSourceContent | Select-String -Pattern "$LineToReplace").Matches.Success) {
                Write-Host "The line '$LineToReplace' was not found in `$TextSource"
                $LineToReplace = Read-Host -Prompt "Please enter the entire line that you would like to replace in `$TextSource"
                if (! $($TextSourceContent | Select-String -Pattern "$LineToReplace").MatchesSuccess) {
                    Write-Host "The string '$LineToReplace' was not found in `$TextSource"
                    Write-Error "The string '$LineToReplace' was not found in `$TextSource. Halting!"
                    return
                }
            }
            # The below variable $PossibleLineLineNumbers is used later in the if statement where ! $LineLineNumber.Count -gt 0
            $PossibleLineLineNumbers = $($TextSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
            if ($LineLineNumber.Count -ge 1) {
                $LineLineCheck = @()
                $BadMatches = @()
                foreach ($obj1 in $LineLineNumber) {
                    if ($TextSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        Write-Host "The contents of the entire line number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $obj1
                    }
                    if ($TextSourceContent[$($obj1-1)] -ne $LineToReplace) {
                        # Check if $LineToReplace is string within the line. If so, add it to $LineLineCheck...
                        if ($($TextSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', however, it DOES contain the string '$LineToReplace'. Continuing..." -Verbose
                            $LineLineCheck += $obj1
                        }
                        # If $LineToReplace is NOT a string within the line, then do NOT add anything to $LineLineCheck.
                        # The subsequent if statement will be responsible for throwing the error.
                        if (! $($TextSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', and it DOES NOT contain the string '$LineToReplace'. Line number $obj1 will not be touched." -Verbose
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
                        $SourceArrayElementContent = $TextSourceContent[$($LineLineCheck[$loop]-1)]
                        $RemainderArrayElementContent = $TextSourceContent[$($obj1-1)]
                        if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                            Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                            $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextSourceContent[$($LineLineCheck[$loop]-1)])"
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
                    $LineToReplace = $TextSourceContent[$($LineLineCheck[0]-1)]
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
                        $PotentialLineLineNumbers = $($TextSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
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
                        if ($InvalidLineLineChoices.Count -ge 1) {
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
                            if ($InvalidLineLineChoices.Count -ge 1) {
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
                    if ($TextSourceContent[$($obj1-1)] -eq $LineToReplace) {
                        Write-Host "The contents of the entire line number $obj1 is the same as '`$LineToReplace'. Continuing..."
                        $LineLineCheck += $obj1
                    }
                    if ($TextSourceContent[$($obj1-1)] -ne $LineToReplace) {
                        # Check if $LineToReplace is a string within the line. If so, add it to $LineLineCheck...
                        if ($($TextSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', however, it DOES contain the string '$LineToReplace'. Continuing..." -Verbose
                            $LineLineCheck += $obj1
                        }
                        # If $LineToReplace is NOT a string within the line, then do NOT add anything to $LineLineCheck.
                        # The subsequent if statement will be responsible for throwing the error.
                        if (! $($TextSourceContent[$($obj1-1)] | Select-String -Pattern "$LineToReplace").Matches.Success) {
                            Write-Verbose "The contents of the entire line number $obj1 (i.e. '$($TextSourceContent[$($obj1-1)])') is NOT the same as '$LineToReplace', and it DOES NOT contain the string '$LineToReplace'. Line number $obj1 will not be touched." -Verbose
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
                        $SourceArrayElementContent = $TextSourceContent[$($LineLineCheck[$loop]-1)]
                        $RemainderArrayElementContent = $TextSourceContent[$($obj1-1)]
                        if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                            #Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                            $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextSourceContent[$($LineLineCheck[$loop]-1)])"
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
                    $LineToReplace = $TextSourceContent[$($LineLineCheck[0]-1)]
                    $UpdatedPossibleLineLineNumbers = $LineLineCheck
                }
                if ($PotentialPatterns.Count -gt 0) {
                    $PotentialPatternsChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        "$($loop+1)"+") "+"$($PotentialPatterns[$loop])"
                    }
                    $ValidPatternChoices = For ($loop=0; $loop -lt $PotentialPatterns.Count; $loop++) {
                        $loop+1
                    }
                    if ($LineOccurrenceOfLine.Count -ge 1) {
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
                    if ($InvalidPatternChoices.Count -ge 1) {
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
                        if ($InvalidPatternChoices.Count -ge 1) {
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
                        $PotentialLineLineNumbers = $($TextSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
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
                        if ($InvalidLineLineChoices.Count -ge 1) {
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
                            if ($InvalidLineLineChoices.Count -ge 1) {
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
                        $PotentialLineLineNumbers = $($TextSourceContent | Select-String -Pattern "$LineToReplace").LineNumber
                        $PotentialLineLineNumbersContent = $($TextSourceContent | Select-String -Pattern "$LineToReplace").Line
                        $PotentialLineLineChoices = For ($loop=0; $loop -lt $PotentialLineLineNumbers.Count; $loop++) {
                            "$($loop+1)"+") "+"Line Number $($PotentialLineLineNumbers[$loop])`: "+"$($TextSourceContent[$($PotentialLineLineNumbers[$loop])-1])"
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
                        if ($InvalidLineLineChoices.Count -ge 1) {
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
                            if ($InvalidLineLineChoices.Count -ge 1) {
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
        if ($LineToReplace -eq $null -and $LineLineNumber.Count -ge 1) {
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
                    $SourceArrayElementContent = $TextSourceContent[$($LineLineNumber[$loop]-1)]
                    $RemainderArrayElementContent = $TextSourceContent[$($obj1-1)]
                    if ($SourceArrayElementContent -ne $RemainderArrayElementContent) {
                        Write-Host "Line number $($LineLineCheck[$loop]) (i.e. '$SourceArrayElementContent') does NOT 100% equal `nline number $obj1 (i.e. '$RemainderArrayElementContent')`n"
                        $PotentialPatternsObject = "Line Number $($LineLineCheck[$loop]):"+"$($TextSourceContent[$($LineLineCheck[$loop]-1)])"
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
                $LineToReplace = $TextSourceContent[$($LineLineNumber[0]-1)]
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
                if ($InvalidPatternChoices.Count -ge 1) {
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
                    if ($InvalidPatternChoices.Count -ge 1) {
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

    # Outputs $UpdatedTextSourceContent
    if ($TextFormationType -eq "string") {
        # If the string is Unique in $TextSource or if User wants to replace ALL Occurrences...
        # Figure out if the user wants to replace ALL occurrences of the string, just one, or some of them
        if ($ReplaceAll -eq $null -and $ReplaceOne -eq $null -and $ReplaceSome -eq $null) {
            Write-Host "Defaulting to replacing ALL occurrences of '$StringToReplace'"
            Write-Host ""
            $UpdatedTextSourceContent = $TextSourceContent -replace "$StringToReplace","$ReplacementText"
        }
        if ($ReplaceAll -eq "Yes" -or $ReplaceAll -eq "y") {
            Write-Host "Defaulting to replacing ALL occurrences of '$StringToReplace'"
            Write-Host ""
            $UpdatedTextSourceContent = $TextSourceContent -replace "$StringToReplace","$ReplacementText"
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
            # If so, then ask user which index to replace. If not, move on to $UpdatedTextSourceContent
            $FinalStringLineNumberContent = $TextSourceContent[$FinalStringLineNumber-1]
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
            $UpdatedTextSourceContent = @()
            $UpdatedTextSourceContent += $TextSourceContent[0..$($FinalStringLineNumber-2)]
            $UpdatedTextSourceContent += $TextSourceContent[$($FinalStringLineNumber-1)] -replace "$UpdatedStringToReplace","$UpdatedReplacementString"
            $UpdatedTextSourceContent += $TextSourceContent[$FinalStringLineNumber..$($TextSourceContent.Count -1)]
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
            # If so, then ask user which index to replace. If not, move on to $UpdatedTextSourceContent
            $UpdatedStringToReplaceObjects = @()
            foreach ($obj1 in $FinalStringLineNumbers) {
                $FinalStringLineNumberContent = $TextSourceContent[$obj1-1]
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
                    if ($StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -ne $null) {
                        # Validate $StringOccurrenceOfLine values (i.e. Keys in $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable) to make sure Nth Occurrence actually exists
                        $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
                            if ([int]$_.Name -gt $FinalStringLineNumbers.Count) {
                                Write-Host "The $($_.Name) occurrence of a line that contains the string $StringToReplace does not exist. Only $($FinalStringLineNumbers.Count) lines contain the string $StringToReplace.`nPlease check the contents of the hashtable passed to the parameter `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable and try again. Halting!"
                                Write-Error "The $($_.Name) occurrence of a line that contains the string $StringToReplace does not exist. Only $($FinalStringLineNumbers.Count) lines contain the string $StringToReplace.`nPlease check the contents of the hashtable passed to the parameter `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        # Validate Occurrences within lines, (i.e. Values in $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable)
                        $InLineOccurrenceValidation = @()
                        $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
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
                                    $InLineOccurrenceValidation += "Occurrence $obj4 for line $($PotentialStringLineNumbers[$($_.Name-1)])"
                                }
                            }
                        }
                        if ($InLineOccurrenceValidation.Count -gt 0) {
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable parameter. Halting!"
                            Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringOccurrenceOfLineVSStringOccurrenceInLineHashTable parameter. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
                            $obj3 = $_.Value
                            foreach ($obj4 in $obj3) {
                                $UpdatedStringToReplace = $StringToReplaceInLineContext[$obj4-1]
                                $UpdatedStringToReplaceWithReplacementText = $UpdatedStringToReplace -replace "$StringToReplace","$ReplacementText"

                                # Create PSObjects based on line number that contain properties line number and $UpdatedFinalStringLineNumberContent
                                New-Variable -Name "UpdatedStringToReplaceLine$($PotentialStringLineNumbers[$($_.Name-1)])$obj4" -Value $(
                                    New-Object PSObject -Property @{
                                        LineNum                                         = $($PotentialStringLineNumbers[$($_.Name-1)])
                                        OccurrenceInLine                                = $obj4
                                        OriginalLineContent                             = $FinalStringLineNumberContent
                                        UpdatedStringToReplace                          = $UpdatedStringToReplace
                                        UpdatedStringToReplaceWithReplacementText       = $UpdatedStringToReplaceWithReplacementText
                                        UpdatedStringLineContent                        = $FinalStringLineNumberContent -replace "$UpdatedStringToReplace","$UpdatedStringToReplaceWithReplacementText"
                                    }
                                ) -Force

                                if (! $UpdatedStringToReplaceObjects.Count -gt 0) {
                                    $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$($PotentialStringLineNumbers[$($_.Name-1)])$obj4" -ValueOnly)
                                }
                                if ($UpdatedStringToReplaceObjects.Count -gt 0) {
                                    $NewObjLineNumPlusOccurrence = "$($PotentialStringLineNumbers[$($_.Name-1)])"+"$obj4"
                                    $UpdatedStringToReplaceObjectsCheck = @()
                                    foreach ($obj5 in $UpdatedStringToReplaceObjects) {
                                        $ExistingObjsLineNumPlusOccurrence = "$($obj5.LineNum)"+"$($obj5.OccurrenceInLine)"
                                        if ($ExistingObjsLineNumPlusOccurrence -eq $NewObjLineNumPlusOccurrence) {
                                            $UpdatedStringToReplaceObjectsCheck += $ExistingObjsLineNumPlusOccurrence
                                        }
                                    }
                                    if (! $UpdatedStringToReplaceObjectsCheck.Count -gt 0) {
                                        $UpdatedStringToReplaceObjects += $(Get-Variable -Name "UpdatedStringToReplaceLine$($PotentialStringLineNumbers[$($_.Name-1)])$obj4" -ValueOnly)
                                    }
                                }
                            }
                        }
                    }
                    if ($StringLineNumberVSStringOccurrenceInLineHashTable -ne $null) {
                        # Validate Line Numbers (i.e. Keys in $StringLineNumberVSStringOccurrenceInLineHashTable)
                        $StringLineNumberVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
                            if ($FinalStringLineNumbers -notcontains $_.Name) {
                                Write-Host "The line number $($_.Name) is not a valid line number. Line numbers that contain the string '`$StringToReplace' are $([string]$FinalStringLineNumbers).`nPlease check the contents of the hashtable passed to the parameter `$StringLineNumberVSStringOccurrenceInLineHashTable and try again. Halting!"
                                Write-Error "The line number $($_.Name) is not a valid line number. Line numbers that contain the string '`$StringToReplace' are $([string]$FinalStringLineNumbers).`nPlease check the contents of the hashtable passed to the parameter `$StringLineNumberVSStringOccurrenceInLineHashTable and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        # Validate Occurrences within lines, (i.e. Values in $StringLineNumberVSStringOccurrenceInLineHashTable)
                        $InLineOccurrenceValidation = @()
                        $StringLineNumberVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
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
                            Write-Host "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringLineNumberVSStringOccurrenceInLineHashTable parameter. Halting!"
                            Write-Error "$([string]$InLineOccurrenceValidation -replace " ",", ") are NOT valid choices.`nPlease check the Values in the hashtable passed to the `$StringLineNumberVSStringOccurrenceInLineHashTable parameter. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        $StringLineNumberVSStringOccurrenceInLineHashTable.GetEnumerator() | foreach {
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
                    if ($StringInLineOccurrence.Count -ge 1) {
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
                    if (! $StringInLineOccurrence.Count -gt 0 -and $StringLineNumberVSStringOccurrenceInLineHashTable -eq $null `
                    -and $StringOccurrenceOfLineVSStringOccurrenceInLineHashTable -eq $null) {
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
                                $TextSourceContent[$obj1-1] -replace "$($obj2.UpdatedStringToReplace)","$($obj2.UpdatedStringToReplaceWithReplacementText)"
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
            $UpdatedTextSourceContent = @()
            For ($loop=0; $loop -lt $FinalStringLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    $UpdatedTextSourceContent += $TextSourceContent[0..$($($($ReplacementLinesObjects[$loop]).LineNum)-2)]
                    $UpdatedTextSourceContent += $($($ReplacementLinesObjects[$loop]).FinalLineContent)
                    $NextLoopStartingPoint = $($ReplacementLinesObjects[$loop]).LineNum
                }
                if ($loop -gt 0) {
                    $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($($($ReplacementLinesObjects[$loop]).LineNum)-2)]
                    $UpdatedTextSourceContent += $($($ReplacementLinesObjects[$loop]).FinalLineContent)
                    $NextLoopStartingPoint = $($ReplacementLinesObjects[$loop]).LineNum
                }
            }
            $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($TextSourceContent.Count -1)]
        }
    }

    # Outputs $UpdatedTextSourceContent
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
            $UpdatedTextSourceContent = @()
            For ($loop=0; $loop -lt $FinalLineLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextSourceContent += $TextSourceContent[0..$($FinalLineLineNumber-2)]
                    $UpdatedTextSourceContent += $TextSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
                if ($loop -gt 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($FinalLineLineNumber-2)]
                    $UpdatedTextSourceContent += $TextSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
            }
            $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($TextSourceContent.Count -1)]
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
            $UpdatedTextSourceContent = @()
            $UpdatedTextSourceContent += $TextSourceContent[0..$($FinalLineLineNumber-2)]
            $UpdatedTextSourceContent += $ReplacementText
            $UpdatedTextSourceContent += $TextSourceContent[$FinalLineLineNumber..$($TextSourceContent.Count -1)]
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
            $UpdatedTextSourceContent = @()
            For ($loop=0; $loop -lt $FinalLineLineNumbers.Count; $loop++) {
                if ($loop -eq 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextSourceContent += $TextSourceContent[0..$($FinalLineLineNumber-2)]
                    $UpdatedTextSourceContent += $TextSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
                if ($loop -gt 0) {
                    [int]$FinalLineLineNumber = $FinalLineLineNumbers[$loop] | Out-String
                    $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($FinalLineLineNumber-2)]
                    $UpdatedTextSourceContent += $TextSourceContent[$($FinalLineLineNumber-1)] -replace "$($TextSourceContent[$($FinalLineLineNumber-1)])","$ReplacementText"
                    $NextLoopStartingPoint = $FinalLineLineNumber
                }
            }
            $UpdatedTextSourceContent += $TextSourceContent[$NextLoopStartingPoint..$($TextSourceContent.Count -1)]
        }
    }

    # Outputs $UpdatedTextSourceContent
    if ($TextFormationType -eq "block") {
        if ($BlockToReplace -ne $null) {
            if ($($BlockToReplace.GetType()).Name -eq "String") {
                $TestTextSourceContentJoined = $TextSourceContent -join "`n"
                if (! $($TestTextSourceContentJoined | Select-String -Pattern $BlockToReplace).Matches.Success) {
                    Write-Verbose "WARNING: The block of text provided to the 'BlockToReplace' parameter is a string as opposed to an array of lines. Did you mark your line breaks properly?"
                    Write-Host "The block of text provided to the parameter `$BlockToReplace was not found in `$TextSource. Please check line breaks in the string provided and try again. Halting!"
                    Write-Error "The block of text provided to the parameter `$BlockToReplace was not found in `$TextSource. Please check line breaks in the string provided and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            if ($($BlockToReplace.GetType()).Name -like "*Object*" -and $($TextSource.GetType()).BaseType -like "*Array*") {
                if (! $(Compare-Arrays -LargerArray $TextSourceContent -SmallerArray $BlockToReplace)) {
                    Write-Host "The block of text provided to the parameter `$BlockToReplace was not found in `$TextSource. Halting!"
                    Write-Error "The block of text provided to the parameter `$BlockToReplace was not found in `$TextSource. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if ($BlockToReplace -eq $null) {
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

            # IMPORTANT NOTE: If your $TextSource contains the exact string ;;splithere;; then this function will break!!
            $TextSourceContentJoined = $TextSourceContent -join ";;splithere;;"

            if ($BeginningStringOccurrenceOfLine.Count -ge 1 -and ! $BeginningStringLineNumber.Count -gt 0) {
                Write-Host "HELLO THERE TOP"
                # Begin determine $BeginningStringLineNumber #
                $PossibleBeginningStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$BeginningString").LineNumber
                $PossibleBeginningStringLineNumbersContent = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                    $TextSourceContent[$obj1-1]
                }
                $PossibleBeginningStringLineNumbersChoices = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                    "$obj1"+") "+"$($TextSourceContent[$obj1-1])"
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
            
            if ($EndingStringOccurrenceOfLine.Count -ge 1 -and ! $EndingStringLineNumber.Count -gt 0) {
                # Begin Determine $EndingStringLineNumber #
                $PossibleEndingStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$EndingString").LineNumber
                $PossibleEndingStringLineNumbersContent = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                    $TextSourceContent[$obj1-1]
                }
                $PossibleEndingStringLineNumbersChoices = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                    "$obj1"+") "+"$($TextSourceContent[$obj1-1])"
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
            if ($($TextSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
            -and $($TextSourceContent | Select-String -Pattern "$EndingString").Count -eq 1 `
            -and ! $BeginningStringLineNumber.Count -gt 0 -and ! $EndingStringLineNumber.Count -gt 0) {
                [int]$BeginningStringLineNumber = $($TextSourceContent | Select-String -Pattern "$BeginningString").LineNumber
                [int]$EndingStringLineNumber = $($TextSourceContent | Select-String -Pattern "$EndingString").LineNumber

                if ($Inclusive -eq "Yes" -or $Inclusive -eq "y") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber-1))
                }
                if ($Inclusive -eq "No" -or $Inclusive -eq "n") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber)..$($EndingStringLineNumber-2))
                }
            }
            # If we've already determined $BeginningStringLineNumber and $EndingStringLineNumber...
            if ($BeginningStringLineNumber.Count -eq 1 -and $EndingStringLineNumber.Count -eq 1) {
                [int]$BeginningStringLineNumber = $BeginningStringLineNumber[0]
                [int]$EndingStringLineNumber = $EndingStringLineNumber[0]

                # Check to make srue $BeginningStringLineNumber comes BEFORE $EndingStringLineNumber
                if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource"
                    Write-Host "Please select an Ending Line Number that comes AFTER the Beginning Line Number $BeginningStringLineNumber"
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                    $PossibleEndingStringLineNumbersChoices
                    [int]$EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                        Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource. Halting!"
                        Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in `$TextSource. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }

                if ($Inclusive -eq "Yes" -or $Inclusive -eq "y") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber-1))
                }
                if ($Inclusive -eq "No" -or $Inclusive -eq "n") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber)..$($EndingStringLineNumber-2))
                }
            }
            # If ONLY $BeginningString is Unique and we haven't determined $EndingStringLineNumber using the
            # $EndingOccurrenceOfLine parameter, perform the following
            if ($($TextSourceContent | Select-String -Pattern "$BeginningString").Count -eq 1 `
            -and $($TextSourceContent | Select-String -Pattern "$EndingString").Count -gt 1 `
            -and ! $EndingStringLineNumber.Count -gt 0 -or $BeginningStringLineNumber.Count -gt 0 -and ! $EndingStringLineNumber.Count -gt 0) {
                if (! $BeginningStringLineNumber.Count -gt 0) {
                    Write-Host "`$BeginningString is unique. Continuing..."
                    # Since $BeginningString is unique, nothing special needs to be done to identify $BeginningLine
                    $BeginningLine = $($TextSourceContent | Select-String -Pattern "$BeginningString").Line
                    [int]$BeginningStringLineNumber = $($TextSourceContent | Select-String -Pattern "$BeginningString").LineNumber
                }
                if ($BeginningStringLineNumber.Count -eq 1) {
                    [int]$BeginningStringLineNumber = $BeginningStringLineNumber[0]
                }

                $AllPossibleEndingStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$EndingString").LineNumber
                $PossibleEndingStringLineNumbers = foreach ($obj1 in $AllPossibleEndingStringLineNumbers) {
                    if ($obj1 -gt $BeginningStringLineNumber) {
                        $obj1
                    }
                }

                if (! $PossibleEndingStringLineNumbers -gt 0) {
                    Write-Host "The Ending String '$EndingString' appears multiple times in `$TextSource, however, all occurrences appear BEFORE the first occurence of Beginning String '$BeginningString'. Please revise the boundaries of the text block you would like to replace and try again. Halting!"
                    Write-Error "The Ending String '$EndingString' appears multiple times in `$TextSource, however, all occurrences appear BEFORE the first occurence of Beginning String '$BeginningString'. Please revise the boundaries of the text block you would like to replace and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $PossibleEndingStringLineNumbersContent = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                    $TextSourceContent[$obj1-1]
                }
                $PossibleEndingStringLineNumbersChoices = foreach ($obj1 in $PossibleEndingStringLineNumbers) {
                    "$obj1"+") "+"$($TextSourceContent[$obj1-1])"
                }

                if ($PossibleEndingStringLineNumbers.Count -eq 1) {
                    [int]$EndingStringLineNumber = $PossibleEndingStringLineNumbers[0]
                }
                if (! $EndingStringLineNumber.Count -gt 0 -and ! $EndingStringOccurrenceOfLine.Count -gt 0 -and $PossibleEndingStringLineNumbers.Count -gt 1) {
                    if ($EndingStringOccurrencePostBeginningString -match "[\d]{1,100}") {
                        [int]$EndingStringLineNumber = for ($loop=0; $loop -lt $PossibleEndingStringLineNumbers.Count; $loop++) {
                            if (($loop+1) -eq $EndingStringOccurrencePostBeginningString) {
                                $PossibleEndingStringLineNumbers[$($EndingStringOccurrencePostBeginningString-1)]
                            }
                        }
                    }
                    else {
                        Write-Host "The Ending String '$EndingString' appears multiple times in `$TextSource"
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
                }
                # Check to make sure $BeginningStringLineNumber is before $EndingStringLineNumber
                if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource"
                    Write-Host "Please select an Ending Line Number that comes AFTER the Beginning Line Number $BeginningStringLineNumber"
                    Write-Host "Line Numbers that contain `$EndingString are as follows:"
                    Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                    $PossibleEndingStringLineNumbersChoices
                    [int]$EndingStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                        Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource. Halting!"
                        Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in `$TextSource. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                # End Determine $EndingStringLineNumber #

                if ($Inclusive -eq "Yes" -or $Inclusive -eq "y") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber-1))
                }
                if ($Inclusive -eq "No" -or $Inclusive -eq "n") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber)..$($EndingStringLineNumber-2))
                }
            }
            # If ONLY $EndingString is Unique and we haven't determined $BeginningStringLineNumber using the
            # $BeginningOccurrenceOfLine parameter, perform the following
            if ($($TextSourceContent | Select-String -Pattern "$EndingString").Count -eq 1 `
            -and $($TextSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1 `
            -and ! $BeginningStringLineNumber.Count -gt 0 -or $EndingStringLineNumber.Count -gt 0 -and ! $BeginningStringLineNumber.Count -gt 0) {
                if (! $EndingStringLineNumber.Count -gt 0) {
                    Write-Host "`$EndingString is unique. Continuing..."
                    # Since $EndingString is unique, nothing special needs to be done to identify $EndingLine
                    $EndingLine = $($TextSourceContent | Select-String -Pattern "$EndingString").Line
                    [int]$EndingStringLineNumber = $($TextSourceContent | Select-String -Pattern "$EndingString").LineNumber
                }
                if ($EndingStringLineNumber.Count -eq 1) {
                    [int]$EndingStringLineNumber = $EndingStringLineNumber[0]
                }

                $AllPossibleBeginningStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$BeginningString").LineNumber
                
                $PossibleBeginningStringLineNumbers = foreach ($obj1 in $AllPossibleBeginningStringLineNumbers) {
                    if ($obj1 -lt $EndingStringLineNumber) {
                        $obj1
                    }
                }

                if (! $PossibleBeginningStringLineNumbers -gt 0) {
                    Write-Host "The Beginning String '$BeginningString' appears multiple times in `$TextSource, however, all occurrences appear AFTER the last occurence of Ending String '$EndingString'. Please revise the boundaries of the text block you would like to replace and try again. Halting!"
                    Write-Error "The Beginning String '$BeginningString' appears multiple times in `$TextSource, however, all occurrences appear AFTER the last occurence of Ending String '$EndingString'. Please revise the boundaries of the text block you would like to replace and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $PossibleBeginningStringLineNumbersContent = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                    $TextSourceContent[$obj1-1]
                }
                $PossibleBeginningStringLineNumbersChoices = foreach ($obj1 in $PossibleBeginningStringLineNumbers) {
                    "$obj1"+") "+"$($TextSourceContent[$obj1-1])"
                }

                if ($PossibleBeginningStringLineNumbers.Count -eq 1) {
                    [int]$BeginningStringLineNumber = $PossibleBeginningStringLineNumbers[0]
                }
                if (! $BeginningStringLineNumber.Count -gt 0 -and ! $BeginningStringOccurrenceOfLine.Count -gt 0 -and $PossibleBeginningStringLineNumbers.Count -gt 1) {
                    if ($BeginningStringOccurrencePreEndingString -match "[\d]{1,100}") {
                        [int]$BeginningStringLineNumber = for ($loop=0; $loop -lt $PossibleBeginningStringLineNumbers.Count; $loop++) {
                            if (($loop+1) -eq $BeginningStringOccurrencePreEndingString) {
                                [array]::Reverse($PossibleBeginningStringLineNumbers)
                                $PossibleBeginningStringLineNumbers[$($BeginningStringOccurrencePreEndingString-1)]
                                [array]::Reverse($PossibleBeginningStringLineNumbers)
                            }
                        }
                    }
                    else {
                        Write-Host "The Beginning String '$BeginningString' appears multiple times in `$TextSource"
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
                }
                # Check to make sure $BeginningStringLineNumber is before $EndingStringLineNumber
                if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                    Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource"
                    Write-Host "Please select a Beginning Line Number that comes BEFORE the Ending Line Number $EndingStringLineNumber"
                    Write-Host "Line Numbers that contain `$BeginningString are as follows:"
                    Write-Host "NOTE: There is one (1) space after the ')' character in each entry below before the actual pattern begins."
                    $PossibleBeginningStringLineNumbersChoices
                    [int]$BeginningStringLineNumber = Read-Host -Prompt "Please enter the line number that will bound the block of text that you would like to replace."
                    if ($BeginningStringLineNumber -gt $EndingStringLineNumber) {
                        Write-Host "The Beginning String `"$BeginningString`" on line $BeginningStringLineNumber appears AFTER the Ending String `"$EndingString`" on line $EndingStringLineNumber in `$TextSource. Halting!"
                        Write-Error "The Beginning String `"$BeginningString`" appears AFTER the Ending String `"$EndingString`" in `$TextSource. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                # End Determine $BeginningStringLineNumber #

                if ($Inclusive -eq "Yes" -or $Inclusive -eq "y") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber-1)..$($EndingStringLineNumber-1))
                }
                if ($Inclusive -eq "No" -or $Inclusive -eq "n") {
                    $BlockToReplace = $TextSourceContent | Select-Object -Index ($($BeginningStringLineNumber)..$($EndingStringLineNumber-2))
                }
            }
            # If neither $EndingString nor $BeginningString are Unique and we haven't determined $BeginningStringLineNumber
            # or $EndingStringLineNumber using the 'OccurrenceOfLine' parameters, perform the following
            if ($($TextSourceContent | Select-String -Pattern "$EndingString").Count -gt 1 `
            -and $($TextSourceContent | Select-String -Pattern "$BeginningString").Count -gt 1 `
            -and ! $BeginningStringLineNumber.Count -gt 0 -and ! $EndingStringLineNumber.Count -gt 0) {
                # Output possible results and ask the user which one they want to use
                # Create $BeginningStringIndex
                $PossibleBeginningStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$BeginningString").LineNumber
                $PossibleBeginningStringLineNumbers = $PossibleBeginningStringLineNumbers | Sort-Object
                $PossibleEndingStringLineNumbers = $($TextSourceContent | Select-String -Pattern "$EndingString").LineNumber
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
                            if ($Inclusive -eq "Yes") {
                                New-Variable -Name "PossibleBlockToReplace$PotentialBeginningStringLineNumber$PotentialEndingStringLineNumber" -Value $($TextSourceContent | Select-Object -Index ($PotentialBeginningStringLineNumber..$PotentialEndingStringLineNumber))
                            }
                            if ($Inclusive -eq "No") {
                                New-Variable -Name "PossibleBlockToReplace$PotentialBeginningStringLineNumber$PotentialEndingStringLineNumber" -Value $($TextSourceContent | Select-Object -Index ($PotentialBeginningStringLineNumber+1..$PotentialEndingStringLineNumber-1))
                            }
                            $PossibleBlockToReplaceArray += , $(Get-Variable -Name "PossibleBlockToReplace$PotentialBeginningStringLineNumber$PotentialEndingStringLineNumber" -ValueOnly)
                            $StartAndFinishLineNumbersArray += "Line $PotentialBeginningStringLineNumber to Line $PotentialEndingStringLineNumber`:`n$($TextSourceContent[$PotentialBeginningStringLineNumber])`n...`n$($TextSourceContent[$PotentialEndingStringLineNumber])"
                        }
                    }
                }

                if (! $PossibleBlockToReplaceArray.Count -gt 0) {
                    Write-Host "No valid blocks of text beginning with $BeginningString and ending with $EndingString were found."
                    Write-Host "Please check to ensure that the Beginning String $BeginningString appears BEFORE the Ending String $EndingString in $TextSource"
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
            }
        }

        # Define $UpdatedTextSourceContent
        # If $TestTextSourceContentJoined is defined, that means $BlockToReplace was provided as a string 
        # via the -BlockToReplace parameter
        if ($TestTextSourceContentJoined -ne $null) {
            $TextSourceContentJoined = $TextSourceContent -join "`n"
            $UpdatedTextSourceContent = $($TextSourceContentJoined.Replace("$BlockToReplace","$ReplacementText"))
        }
        if ($TestTextSourceContentJoined -eq $null) {
            $TextSourceContentJoined = $TextSourceContent -join ";;splithere;;"
            $BlockToReplaceJoined = $BlockToReplace -join ";;splithere;;"
            $UpdatedTextSourceContent = $($TextSourceContentJoined.Replace("$BlockToReplaceJoined","$ReplacementText")) -split ";;splithere;;"
        }
    }

    # If $TextSource is a file path...
    if ($($TextSource.GetType()).Name -eq "String" -and $(Test-Path $TextSource)) {
        if ($ReplacementType -eq "inplace") {
            Set-Content -Path $TextSource -Value $UpdatedTextSourceContent
            Write-Host ""
            $UpdatedTextSourceContent
        }
        # ...or create a new file
        if ($ReplacementType -eq "new") {
            Set-Content -Path $OutputWithUpdatedText -Value $UpdatedTextSourceContent
            Write-Host ""
            $UpdatedTextSourceContent
        }
    }
    # If $TextSource is an array object...
    if ($($TextSource.GetType()).Name -like "*Object*" -and $($TextSource.GetType()).BaseType -like "*Array*") {
        if ($ReplacementType -eq "inplace") {
            New-Variable -Name "$OutputWithUpdatedText" -Scope Global -Value $UpdatedTextSourceContent -Force
            Write-Host "The array object $OutputWithUpdatedText has been updated with the replacement text and is now available in the current scope using `$global:$OutputWithUpdatedText"
            Write-Host ""
            $UpdatedTextSourceContent
        }
        if ($ReplacementType -eq "new") {
            New-Variable -Name "$OutputWithUpdatedText" -Scope Global -Value $UpdatedTextSourceContent -Force
            Write-Host "The array object $OutputWithUpdatedText has been created and reflects the desired replacement text. It is now available in the current scope using `$global:$OutputWithUpdatedText"
            Write-Host ""
            $UpdatedTextSourceContent
        }
    }
    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMIq67XJl/J9pLcuLqsOLCjN+
# rSCgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQ2HRW9C2v/
# XOJyrPAC+BBAViAdtTANBgkqhkiG9w0BAQEFAASCAQCN1WqiZdG6foywGNCEVV/o
# kkDga7X7xK46JlkfoPWSizjeTPog0OAM6U8e9DwmtX1/LHeB/J29ZgOwljPBITpD
# YTg0TObafRttcAuJk/7udwFjMoXTOL5zwcZPDBdT9dWaXJ+ji+6OvNqpvLro+DSi
# LVyKybwM/7XK6eX3DYqpu7X+kxf6LwXeB3U4qUNBkps7gVtP5tBmcfolOLrNZmQe
# 7b942fxmCpJmRl0EtWp1jrk8kfHiS4b2m/jkqN/8YnenehY58uELMqneVe5+OdLs
# F9a3KcweFi2yHoR7R3p9Y9UybPUkxGStScZJb8ZnAeBjyZx1b64JS5CzjMvlQ2a0
# SIG # End signature block
