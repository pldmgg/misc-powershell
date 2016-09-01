<#
.SYNOPSIS
    This script along with the Get-AllDiskInfo function (at the end) has 2 goals that can be satisfied depending on the 
    supplied parameters:
    
    1) Provide ALL disk information for the localhost in a way that ties Disk, Partition, and Volume information together 
    ***in one output***

    2) Provide a very flexible way to access any and all information about any given Disk/Partition/Volume using either an 
    Array of HashTables, or Array of PSObjects. (NOTE: Array of PSObjects provides the most flexibility for later parsing).  

    IMPORTANT NOTE: Ultimately, the output of this script is almost entirely based on diskpart. If output is not what you would 
    expect, check diskpart to make sure. For example, diskpart cuts off the Volume Label name at 11 characters. If a 
    Volume Label name is greater that 11 characters, this cutoff will be present in this script/function's output.

.DESCRIPTION
    At first glance, it may seem that more recent PowerShell cmdlets (and even just diskpart) already fulfill this need. 
    However, all newer PowerShell cmdlets that I have explored fail to tie Disk, Partition, and Volume information
    together ***in the same output***

    This script/function also provides the ability to create hashtables and PSObjects based on Disk/Partition for easier
    extensibility.
    
    This script/function is compatible with ***all*** versions of PowerShell, since, ultimately, it is all based on diskpart output.

    Dot source the script to make the Get-AllDiskInfo function available to you in your current shell.
    . "V:\powershell\Get-AllDiskInfo.ps1"

.EXAMPLE
    Example #1: 
    Get disk information for all disks on localhost as an array of strings. 
    
    PS C:\Users\testadmin> Get-AllDiskInfo
    Disk 0 / Partition 1 Type=Recovery : Volume 2                 Label=WinRE       FS=NTFS   Size=300 MB  Status=Healthy   Info=Hidden
    Disk 0 / Partition 2 Type=System   : Volume 3                 Label=SYSTEM      FS=FAT32  Size=100 MB  Status=Healthy   Info=System
    Disk 0 / Partition 3 Type=Reserved :
    Disk 0 / Partition 4 Type=Primary  : Volume 1  DriveLetter=C  Label=Windows      FS=NTFS   Size=63 GB  Status=Healthy   Info=Boot
    Disk 1 / Partition 1 Type=Reserved :
    Disk 1 / Partition 2 Type=Primary  : Volume 4  DriveLetter=E  Label=ISO_Prep     FS=NTFS   Size=127 GB  Status=Healthy
    Disk 2 / Partition 1 Type=Reserved :
    Disk 2 / Partition 2 Type=Primary  : Volume 5  DriveLetter=F  Label=WebDrive_Ca  FS=NTFS   Size=63 GB  Status=Healthy

    The above command is the same as:
    Get-AllDiskInfo -outputtype strings


    Example #2: 
    Get disk information for Disk 0 on localhost as an array of strings.

    PS C:\Users\testadmin> Get-AllDiskInfo -disknum 0
    Disk 0 / Partition 1 Type=Recovery : Volume 2                 Label=WinRE       FS=NTFS   Size=300 MB  Status=Healthy   Info=Hidden
    Disk 0 / Partition 2 Type=System   : Volume 3                 Label=SYSTEM      FS=FAT32  Size=100 MB  Status=Healthy   Info=System
    Disk 0 / Partition 3 Type=Reserved :
    Disk 0 / Partition 4 Type=Primary  : Volume 1  DriveLetter=C  Label=Windows      FS=NTFS   Size=63 GB  Status=Healthy   Info=Boot

    This above command is the same as:
    Get-AllDiskInfo -outputtype strings -disknum 0


    Example #3: 
    Get disk information for Disk 0 on localhost as an array of hashtables.
    
    PS C:\Users\testadmin> Get-AllDiskInfo -outputtype hashtables -disknum 0 | Where-Object {$_.PartitionNumber -eq 4}
    Name                           Value
    ----                           -----
    VolumeNumber                   1
    VolumeLabel                    Windows
    PartitionType                  Primary
    PartitionNumber                4
    PartitionStatus                Healthy
    DiskNumber                     0
    VolumeLetter                   C
    PartitionSize                  63 GB
    PartitionInfo                  Boot
    FileSystem                     NTFS

    
    Example #4:
    Get disk information for Disk 2 on localhost as an array of PSObjects.
    
    PS C:\Users\testadmin>  Get-AllDiskInfo -outputtype PSObjects -disknum 0 | Where-Object {$_.PartitionNumber -eq 4}
    VolumeNumber    : 1
    VolumeLabel     : Windows
    PartitionType   : Primary
    PartitionNumber : 4
    PartitionStatus : Healthy
    DiskNumber      : 0
    VolumeLetter    : C
    PartitionSize   : 63 GB
    PartitionInfo   : Boot
    FileSystem      : NTFS


    Example #5:
    Figure out the Disk Number that the Volume Labeled "Windows" is on

    PS C:\Users\testadmin>  $(Get-AllDiskInfo -outputtype PSObjects | Where-Object {$_.VolumeLabel -eq "Windows"}).DiskNumber
    0

.PARAMETERS 

    1) $outputtype - Use this parameter to specify if you want output to be an array of strings, hashtables, or PSObjects

    2) $disknum - Use this parameter to indicate that you want the output to contain array elements related to a specific disk number.

    3) $volume - Use this parameter to indicate that you want the output to contain array elements related to a specific volume number.

    4) $label - Use this parameter to indicate that you want the output to contain array elements related to a specific volume label.

.OUTPUTS
    An array of strings, or an array of hashtables, or an array of PSObjects

.NOTES
    IMPORTANT NOTE: Ultimately, the output of this script is almost entirely based on diskpart. If output is not what you would 
    expect, check diskpart to make sure. For example, diskpart cuts off the Volume Label name at 11 characters. If a 
    Volume Label name is greater that 11 characters, this cutoff will be present in this script/function's output.



#>

Function Get-AllDiskInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$outputtype = "strings",

        [Parameter(Mandatory=$False)]
        $disknum = "null",

        [Parameter(Mandatory=$False)]
        $volume = "null",

        [Parameter(Mandatory=$False)]
        $label = "null"
    )

    ##### BEGIN Helper Functions #####
    # Function to Convert a String into a Script Block
    function ConvertTo-Scriptblock  {
        Param(
            [Parameter(
                Mandatory = $true,
                ParameterSetName = '',
                ValueFromPipeline = $true)]
                [string]$string 
            )
        $scriptBlock = [scriptblock]::Create($string)
        return $scriptBlock
    }

    ##### END Helper-Functions #####
 
    ##### BEGIN Setting Up Variables to Output $everything #####
    # IMPORTANT NOTE: $everything is simply an array of strings, with each string representing information about Disk X Partition Y in a standard format
    # $everything is used for reference when creating an Array of HashTables and/or an Array of PSObjects
    # It is also the default output if you run the function without any parameters

    $disknumberarrayprep = "list disk" | diskpart | Select-String "Disk [0-9]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
    $disknumberarray = foreach ($obj in $disknumberarrayprep) {
        $obj.ToString().Split(" ") | Select-Object -Index 1
    }

    $partitionnumberarray = foreach ($disknumber in $disknumberarray) {
        $partitionnumberarrayprep = "select disk $disknumber", "list partition" | diskpart | Select-String "Partition [0-9]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        $partitionnumberarrayprep2 = foreach ($obj in $partitionnumberarrayprep) {
            $obj.ToString().Split(" ") | Select-Object -Index 1
        }
        $partitionnumberarrayprep2
    }

    $diskspartitionsandtypesarray = foreach ($disknumber in $disknumberarray) {
        $diskspartitionsandtypesarrayprep = "select disk $disknumber", "list partition" | diskpart | Select-String '(Partition [0-9]    )(\w{3,8})' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        foreach ($obj1 in $diskspartitionsandtypesarrayprep) {
            $obj2 = $obj1.Split(" ") | Select-Object -Index 5
            $obj3 = $obj1.Replace("   $obj2","Type=$obj2")
            "Disk $disknumber / $obj3"
        }
    }

    $disksandpartitionsarray = foreach ($disknumber in $disknumberarray) {
        $disksandpartitionsarrayprep = "select disk $disknumber", "list partition" | diskpart | Select-String '(Partition [0-9])' |`
        Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        foreach ($obj in $disksandpartitionsarrayprep) {
            "Disk $disknumber / $obj"
        }
    }

    $volumearrayprep = "list volume" | diskpart
    $volumenumberarray = foreach ($obj1 in $volumearrayprep) {
        $obj2 = $obj1 | Select-String "Volume [0-9]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = $obj2.Split(" ") | Select-Object -Index 1
            $obj3
        }
    }

    # Volume Letter Array Using WMI
    #$volumeletterarray = gwmi win32_volume | Select-Object DriveLetter | Select-String "[A-Z]:" | Select-Object -ExpandProperty Matches |`
    #Select-Object -ExpandProperty Value

    # Volume Letter Array Using diskpart
    $volumeletterarray = foreach ($obj1 in $volumearrayprep) {
        $obj2 = $obj1 | Select-String "Volume [0-9][\s]{2,12}[A-Z]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = $obj2.Split(" ") | Select-Object -Index 6
            if ($obj3 -match "[A-Z]") {
                $obj3+":"
            }
        }
    }

    $volumeletterarraysanscolon = foreach ($obj1 in $volumeletterarray) {
        $obj1.Replace(":","")
    }

    # Volume Label Array Using WMI
    $volumelabelarray = (gwmi win32_volume | Select-Object Label | Select-String '(Label=[\w]{1,32}[\s]{1,2}[\w]{1,32})|(Label=[\w]{1,32})' |`
    Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value) -replace 'Label=',''

    # Volume Label Array Using diskpart
    <#
    $volumelabelarray = foreach ($obj1 in $volumenumberarrayprep) {
        $obj2 = $obj1 | Select-String "Volume [0-9]     [A-Z]   [\w]{3,11}" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = $obj2.Split(" ") | Select-Object -Index 9
            $obj3
        }
    }
    #>

    $everythingprep = foreach ($diskandpartition in $disksandpartitionsarray) {
        $disknumber = ($diskandpartition | Select-String "Disk [0-9]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value).`
        Split(" ") | Select-Object -Index 1
        $partitionnumber = ($diskandpartition | Select-String "Partition [0-9]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value).`
        Split(" ") | Select-Object -Index 1

        $obj1 = "select disk $disknumber", "select partition $partitionnumber", "detail partition" | diskpart
        $obj2 = $obj1 | Sort-Object | Get-Unique | Select-String "Volume [0-9]"
        "Disk $disknumber / Partition $partitionnumber : $obj2"
    }

    $everythingprep2 = foreach ($obj in $everythingprep) {
        $obj.Replace("* ","")
    }

    $everythingprep3 = foreach ($obj1 in $everythingprep2) {
        foreach ($obj2 in $diskspartitionsandtypesarray) {
            $obj3 = $obj2 | Select-String 'Disk [0-9] / Partition [0-9]' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
            if ($obj1 -like "*$obj3*") {
                $obj1.Replace("$obj3","$obj2")
            }
        }
    }

    $everythingprep4 = foreach ($obj1 in $everythingprep3) {
        $obj2 = $obj1.IndexOf(":")
        if ($obj2 -eq 30) {
            $obj1.Replace(":","     :")
        }
        if ($obj2 -eq 31) {
            $obj1.Replace(":","    :")
        }
        if ($obj2 -eq 32) {
            $obj1.Replace(":","   :")
        }
        if ($obj2 -eq 33) {
            $obj1.Replace(":","  :")
        }
        if ($obj2 -eq 34) {
            $obj1.Replace(":"," :")
        }
        if ($obj2 -eq 35) {
            $obj1
        }
    }

    $everythingprep5 = foreach ($obj1 in $everythingprep4) {
        $obj2 = $obj1 | Select-String "Volume [0-9][\s]{2,5}[A-Z]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Last 1 | Select-Object -Index 0
        }
        if ($obj3 -ne $null) {
            $obj1.Replace("    $obj3 "," DriveLetter=$obj3")
        }
    }

    # This gets the rows that do NOT have a drive letter
    $everythingprep6 = foreach ($obj1 in $everythingprep5) {
        $obj2 = $obj1 | Select-String "Volume [0-9][\s]{3,12}[\w]{3,32}" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Last 1 | Select-Object -Index 0
        }
        if ($obj3 -ne $null) {
            $obj1.Replace(" $obj3 ","         Label=$obj3")
        }
    }

    # This gets the rows that DO have a drive letter
    $everythingprep7 = foreach ($obj1 in $everythingprep6) {
        $obj2 = $obj1 | Select-String 'DriveLetter=[A-Z][\s]{1,4}[\w]{2,32}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Index 1
        }
        if ($obj3 -ne $null) {
            $obj1.Replace(" $obj3"," Label=$obj3")
        }
    }

    # Add FS= to lines that contain Label=
    $everythingprep8 = foreach ($obj1 in $everythingprep7) {
        $obj2 = $obj1 | Select-String 'Label=[\w\s]{2,32}[\s]{2,8}[\w]{4,8}[\s]{1,4}[\w]{3,15}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Last 2 | Select-Object -Index 0
            $obj1.Replace(" $obj3"," FS=$obj3")
        }
        else {
            $obj1
        }
    }

    # Add FS= to Lines that contain DriveLetter= but not Label=
    $everythingprep85 = foreach ($obj1 in $everythingprep8) {
        $obj2 = $obj1 | Select-String 'DriveLetter=[A-Z][\s]{5,16}[\w]{3,6}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Last 1 | Select-Object -Index 0
            $obj1.Replace(" $obj3","       FS=$obj3")
        }
        else {
            $obj1
        }
    }
    # Add FS= to Lines that contain neither DriveLetter= nor Label=
    $everythingprep86 = foreach ($obj1 in $everythingprep85) {
        $obj2 = $obj1 | Select-String '[\s]{5,25}[\w]{3,6}[\s]{1,5}Partition' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = ($obj2.ToString() -replace '\s+',' ').Split(" ") | Select-Object -Last 1 | Select-Object -Index 0
            $obj1.Replace(" $obj3","               FS=$obj3")
        }
        else {
            $obj1
        }
    }

    $everythingprep9 = foreach ($obj1 in $everythingprep86) {
        $obj2 = $obj1 | Select-String 'Partition[\s]{2,6}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj1.Replace("$obj2","Size=")
        }
        if (! ($obj2 -ne $null)) {
            $obj1
        }
    }

    $everythingprep10 = foreach ($obj1 in $everythingprep9) {
        $obj2 = $obj1 | Select-String 'Removable[\s]{2,6}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj1.Replace("$obj2","Size=")
        }
        if (! ($obj2 -ne $null)) {
            $obj1
        }
    }

    $everythingprep11 = foreach ($obj1 in $everythingprep10) {
        $obj2 = $obj1 | Select-String 'B[\s]{2,2}[\w]{3,7}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = $obj2.ToString().Split(" ") | Select-Object -Index 2
        }
        if (! ($obj1 -like "*$obj3*")) {
            $obj1
        }
        if ($obj1 -like "*$obj3*") {
            $obj1.Replace("$obj3","Status=$obj3")
        }
    }

    $everything = foreach ($obj1 in $everythingprep11) {
        $obj2 = $obj1 | Select-String 'Status=[\w]{3,7}[\s]{2,4}[\w]{3,7}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        if ($obj2 -ne $null) {
            $obj3 = $obj2.Split(" ") | Select-Object -Last 1
        }
        if (! ($obj1 -like "*$obj3*")) {
            $obj1
        }
        if ($obj1 -like "*$obj3*") {
            $obj1.Replace(" $obj3","Info=$obj3")
        }
    }

    ##### END Setting Up Variables to Output $everything #####

    ##### BEGIN Generic Script Block to be used to Create Array of HashTables and Array of PSObjects #####

    $diskobjectarrayscriptblock = 
@"
`$DiskNumberValuePrep = `$obj1 | Select-String 'Disk [0-9]' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$DiskNumberValuePrep -ne `$null) {
    `$DiskNumberValue = `$DiskNumberValuePrep.Split(" ") | Select-Object -Index 1
}
else {
    `$DiskNumberValue = ""
}
    
`$PartitionNumberValuePrep = `$obj1 | Select-String 'Partition [0-9]' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$PartitionNumberValuePrep -ne `$null) {
    `$PartitionNumberValue = `$PartitionNumberValuePrep.Split(" ") | Select-Object -Index 1
}
else {
    `$PartitionNumberValue = ""
}

`$PartitionTypeValuePrep = `$obj1 | Select-String 'Type=[\w]{3,8}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$PartitionTypeValuePrep -ne `$null) {
    `$PartitionTypeValue = `$PartitionTypeValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$PartitionTypeValue = ""
}

`$VolumeNumberValuePrep = `$obj1 | Select-String 'Volume [0-9]' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$VolumeNumberValuePrep -ne `$null) {
    `$VolumeNumberValue = `$VolumeNumberValuePrep.Split(" ") | Select-Object -Index 1
}
else {
    `$VolumeNumberValue = ""
}

`$VolumeLetterValuePrep = `$obj1 | Select-String 'DriveLetter=[A-Z]' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$VolumeLetterValuePrep -ne `$null) {
    `$VolumeLetterValue = `$VolumeLetterValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$VolumeLetterValue = ""
}

`$VolumeLabelValuePrep = `$obj1 | Select-String 'Label=[\w]{3,15}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$VolumeLabelValuePrep -ne `$null) {
    `$VolumeLabelValue = `$VolumeLabelValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$VolumeLabelValue = ""
}

`$FileSystemValuePrep = `$obj1 | Select-String 'FS=[\w]{3,12}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$FileSystemValuePrep -ne `$null) {
    `$FileSystemValue = `$FileSystemValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$FileSystemValue = ""
}

`$PartitionSizeValuePrep = `$obj1 | Select-String 'Size=[\d]{1,5} [A-Z]{1,2}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$PartitionSizeValuePrep -ne `$null) {
    `$PartitionSizeValue = `$PartitionSizeValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$PartitionSizeValue = ""
}

`$PartitionStatusValuePrep = `$obj1 | Select-String 'Status=[\w]{3,7}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$PartitionStatusValuePrep -ne `$null) {
    `$PartitionStatusValue = `$PartitionStatusValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$PartitionStatusValue = ""
}

`$PartitionInfoValuePrep = `$obj1 | Select-String 'Info=[\w]{3,7}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
if (`$PartitionInfoValuePrep -ne `$null) {
    `$PartitionInfoValue = `$PartitionInfoValuePrep.Split("=") | Select-Object -Index 1
}
else {
    `$PartitionInfoValue = ""
}

`$hash = @{            
    DiskNumber       = `$DiskNumberValue
    PartitionNumber  = `$PartitionNumberValue
    PartitionType    = `$PartitionTypeValue
    VolumeNumber     = `$VolumeNumberValue
    VolumeLetter     = `$VolumeLetterValue
    VolumeLabel      = `$VolumeLabelValue
    FileSystem       = `$FileSystemValue
    PartitionSize    = `$PartitionSizeValue
    PartitionStatus  = `$PartitionStatusValue
    PartitionInfo    = `$PartitionInfoValue
}
"@

    ##### END Generic Script Block to be used to Create Array of HashTables and Array of PSObjects #####

    ##### BEGIN Creating Array of HashTables #####

    # IMPORTANT NOTE: $DiskObjectArrayOfHashes only needs to be created if $outputtype parameter -eq hashes
    if ($outputtype -eq "hashes") {
        # Add `$hash to $diskobjectarrayscriptblock so that $makescriptblockforhashes tells $scriptblockconvertedforhashes to return the final processed $hash...
        $makescriptblockforhashes = "$diskobjectarrayscriptblock"+"`r`n"+"`$hash"
        $scriptblockconvertedforhashes = ConvertTo-Scriptblock $makescriptblockforhashes

        $DiskObjectArrayOfHashes = foreach ($obj1 in $everything) {
            &$scriptblockconvertedforhashes
        }
    }

    ##### END Creating Array of HashTables #####

    ##### BEGIN Creating Array of PSObjects #####

    # IMPORTANT NOTE: $DiskObjectArrayOfPSObjects *ALWAYS* needs to be created regardless of $outputtype parameter specification
    # because $DiskObjectArrayOfPSObjects is used in Parameter Validation below

    # Add "`$DiskObject = New-Object PSObject -Property `$hash" and "`$DiskObject" to $diskobjectarrayscriptblock so that $makescriptblockforPSObjects 
    # tells $scriptblockconvertedforPSObjects to return the final processed $DiskObject...
    $makescriptblockforPSObjects = "$diskobjectarrayscriptblock"+"`r`n"+"`$DiskObject = New-Object PSObject -Property `$hash"+"`r`n"+"`$DiskObject"
    $scriptblockconvertedforPSObjects = ConvertTo-Scriptblock $makescriptblockforPSObjects

    $DiskObjectArrayOfPSObjects = foreach ($obj1 in $everything) {
        &$scriptblockconvertedforPSObjects
    }

    ##### END Creating Array of PSObjects #####

    ###### BEGIN Parameter Validation ##### 
    
    if ("strings","hashtables","PSObjects" -notcontains $outputtype) { 
        Throw "$($outputtype) is not a valid outputtype! Please use 'hashtables' or 'PSObjects' sans quotes" 
    }
    if ($disknum -ne "null") {
        if ($disknum -isnot [int]) { 
            Throw "$($disknum) is not a an integer. Please provide a number less than or equal to "+$disknumberarray.count
        } 
    }
    if ($disknum -ne "null") {
        if ($disknum -ge $disknumberarray.count) {
            Throw "$($disknum) is greater than "+($disknumberarray.count-1)+". Please provide a number less than or equal to "+$disknumberarray.count
        }
    }
    if ($volume -ne "null") {
        if ($volume -is [int]) {
            if ($volume -gt $volumenumberarray.count) {
                Throw "Volume Number "+$volume+" is greater than "+$volumenumberarray.count+". Please provide a number less than or equal to "+$volumenumberarray.count
            }
        }
        else {
            if ($volumeletterarraysanscolon -notcontains $volume) {
                Throw "Volume Letter "+$volume+" has not been found. Please verify that the volume letter exists according to diskpart."
            }
        }
    }
    if ($label -ne "null") {
        if ($volumelabelarray -notcontains $label) {
            Throw "Volume Label "+$label+" has not been found. Please verify that there is a volume labeled "+$label+" according to diskpart."
        }
    }

    # Begin Checking if certain combinations of Disk Number, Volume Number/Letter, and Volume Label are valid
    if ($disknum -ne "null" -and $label -ne "null") {
        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
            if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum -and $DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                Write-Host "Combination of DiskNumber $disknum and VolumeLabel $label exists. Continuing..."
            }
            else {
                Throw "A combination of DiskNumber $disknum and VolumeLabel $label does not exist."
            }
        }
    }
    if ($disknum -ne "null" -and $volume -ne "null") {
        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
            if ($volume -is [int]) {
                if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum -and $DiskObjectArrayOfPSObjects[$i].VolumeNumber -eq $volume) {
                    Write-Host "Combination of DiskNumber $disknum and VolumeNumber $volume exists. Continuing..."
                }
                else {
                    Throw "A combination of DiskNumber $disknum and VolumeNumber $volume does not exist."
                }
            }
            else {
                if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum -and $DiskObjectArrayOfPSObjects[$i].VolumeLetter -eq $volume) {
                    Write-Host "Combination of DiskNumber $disknum and VolumeLetter $volume exists. Continuing..."
                }
                else {
                    Throw "A combination of DiskNumber $disknum and VolumeLetter $volume does not exist."
                }
            }
            
        }
    }
    if ($disknum -ne "null" -and $label -ne "null" -and $volume -ne "null") {
        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
            if ($volume -is [int]) {
                if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum -and $DiskObjectArrayOfPSObjects[$i].VolumeNumber -eq $volume -and $DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                    Write-Host "Combination of DiskNumber $disknum, VolumeNumber $volume, and VolumeLabel $label exists. Continuing..."
                }
                else {
                    Throw "A combination of DiskNumber $disknum, VolumeNumber $volume, and VolumeLabel $label does not exist."
                }
            }
            else {
                if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum -and $DiskObjectArrayOfPSObjects[$i].VolumeLetter -eq $volume -and $DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                    Write-Host "Combination of DiskNumber $disknum, VolumeLetter $volume, and VolumeLabel $label exists. Continuing..."
                }
                else {
                    Throw "A combination of DiskNumber $disknum, VolumeLetter $volume, and VolumeLabel $label does not exist."
                }
            }
            
        }
    }
    if ($label -ne "null" -and $volume -ne "null") {
        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
            if ($volume -is [int]) {
                if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label -and $DiskObjectArrayOfPSObjects[$i].VolumeNumber -eq $volume) {
                    Write-Host "Combination of VolumeLabel $label and VolumeNumber $volume exists. Continuing..."
                }
                else {
                    Throw "A combination of VolumeLabel $label and VolumeNumber $volume does not exist."
                }
            }
            else {
                if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label -and $DiskObjectArrayOfPSObjects[$i].VolumeLetter -eq $volume) {
                    Write-Host "Combination of VolumeLabel $label and VolumeLetter $volume exists. Continuing..."
                }
                else {
                    Throw "A combination of VolumeLabel $label and VolumeLetter $volume does not exist."
                }
            }
            
        }
    }

    ###### END Parameter Validation #####

    ##### BEGIN Main Body #####

    # To output information as an Array of Strings...
    # NOTE: This takes up the least amount of real estate in STDOUT
    if ($outputtype -eq "strings") {
        if ($disknum -eq "null") {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    $everything
                }
                else {
                    foreach ($obj1 in $everything) {
                        $obj2 = $obj1 | Select-String "Label=$label"
                        if ($obj2 -ne $null) {
                            $obj1
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Volume $volume"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                    else {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Label=$label"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "DriveLetter=$volume"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                    else {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Label=$label"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                }
            }
        }
        else {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    foreach ($obj1 in $everything) {
                        $obj2 = $obj1 | Select-String "Disk $disknum" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                        if ($obj2 -ne $null) {
                            $obj1
                        }
                    }
                }
                else {
                    foreach ($obj1 in $everything) {
                        $obj2 = $obj1 | Select-String "Label=$label"
                        if ($obj2 -ne $null) {
                            $obj1
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Volume $volume"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                    else {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Label=$label"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "DriveLetter=$volume"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                    else {
                        foreach ($obj1 in $everything) {
                            $obj2 = $obj1 | Select-String "Label=$label"
                            if ($obj2 -ne $null) {
                                $obj1
                            }
                        }
                    }
                }
            }
        }
            
    }
    # To output disk information as an Array Of HashTables...
    if ($outputtype -eq "hashtables") {
        if ($disknum -eq "null") {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                        $DiskObjectArrayOfHashes[$i]
                    }
                }
                else {
                    for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                        if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                            $DiskObjectArrayOfHashes[$i]
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeNumber") -eq $volume) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLetter") -eq $volume) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                }
            }
        }
        else {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                        if ($DiskObjectArrayOfHashes[$i].Item("DiskNumber") -eq $disknum) {
                            $DiskObjectArrayOfHashes[$i]
                        }
                    }
                }
                else {
                    for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                        if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                            $DiskObjectArrayOfHashes[$i]
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeNumber") -eq $volume) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLetter") -eq $volume) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfHashes.Count; $i++) {
                            if ($DiskObjectArrayOfHashes[$i].Item("VolumeLabel") -eq $label) {
                                $DiskObjectArrayOfHashes[$i]
                            }
                        }
                    }
                }
            }
        }
    }
    # To output disk information as an Array Of PSObjects...
    if ($outputtype -eq "PSObjects") {
        if ($disknum -eq "null") {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                        $DiskObjectArrayOfPSObjects[$i]
                    }
                }
                else {
                    for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                        if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                            $DiskObjectArrayOfPSObjects[$i]
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeNumber -eq $volume) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLetter -eq $volume) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                }
            }
        }
        else {
            if ($volume -eq "null") {
                if ($label -eq "null") {
                    for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                        if ($DiskObjectArrayOfPSObjects[$i].DiskNumber -eq $disknum) {
                            $DiskObjectArrayOfPSObjects[$i]
                        }
                    }
                }
                else {
                    for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                        if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                            $DiskObjectArrayOfPSObjects[$i]
                        }
                    }
                }
            }
            else {
                if ($volume -is [int]) {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeNumber -eq $volume) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                }
                else {
                    if ($label -eq "null") {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLetter -eq $volume) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                    else {
                        for ($i = 0; $i -lt $DiskObjectArrayOfPSObjects.Count; $i++) {
                            if ($DiskObjectArrayOfPSObjects[$i].VolumeLabel -eq $label) {
                                $DiskObjectArrayOfPSObjects[$i]
                            }
                        }
                    }
                }
            }
        }
    }
}

# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUR4b4DGXQulPFbSo1ru1H5404
# khagggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSq7cX7Ls1f
# XZDOQQRJ5Gk+536bIDANBgkqhkiG9w0BAQEFAASCAQBPT8iKnpZo9h2rUWBFQ/aQ
# 2bOAIOo+484qtooXxuAhyDniDWG5TpU52jJgnSOY2yV4E7MQho41XWowgc2MVLoU
# LgQxEypssJYnrv3vtYKR221DEGvDF+eSA+ko/re6vKqEFrKNm1/nPgviIob0Z8TJ
# YgUjauwHja4Ieze31QpuLKHVjdnQ4J1ZnvesMft3Dhafl2eaybf6wjWreS765rKE
# y4yRTqWOiZ4vyphDj2X23+siqXu0MDrb3VKlRlj/lfEDb8FWWIkf1DL0aIUyP+Wa
# fT0zfTJw2SrSvVezaIpJWptbxvO8DWTlNx2gwoOclc4cgp5OwtHvhW4xihl0emaS
# SIG # End signature block
