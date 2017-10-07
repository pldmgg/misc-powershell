# USAGE EXAMPLES
<#
**** EXAMPLE 1 ****
# To get $syncHash.WPFInfoDataGrid, see V:\powershell\PowerShellDrafts\GUI_Apps\WPF\NoClutter-NetworkMonitor\NoClutter-NetworkMonitor.ps1

PS C:\Users\testadmin> $($syncHash.WPFInfoDataGrid).GetType().FullName
System.Windows.Controls.DataGrid

PS C:\Users\testadmin> [WPFUtils.DataGrids.Cells]::GetCell(1, 1, $($syncHash.WPFInfoDataGrid))

#>

function Get-Assemblies {
    [CmdletBinding(DefaultParameterSetName="AssemNameWild")]
    Param(
        [Parameter(Mandatory=$True,ParameterSetName="AssemNameWild")]
        [string]$AssemblyName,

        [Parameter(Mandatory=$True,ParameterSetName="AssemNameLoc")]
        [string]$AssemblyLocation
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $AssemblyBaseClassCount = $($AssemblyName -split "\.").Count

    [System.Collections.ArrayList]$AttemptedAssemblyPermutations = @()

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $GACDir = $CurrentlyLoadedAssemblies[0].Location | Split-Path -Parent

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($AssemblyLocation) {
        try {
            $AssemblyLocationFullPath = $(Resolve-Path $AssemblyLocation).Path
        }
        catch {
            Write-Error $Error[0]
            $global:FunctionResult = 1
            return
        }

        try {
            $AssemblyFullInfo = [System.Reflection.Assembly]::LoadFile($AssemblyLocationFullPath)
        }
        catch {
            Write-Error $Error[0]
            $global:FunctionResult = 1
            return
        }

        $AssemblyName = $($AssemblyFullInfo.FullName -split ",")[0]

        # Re-Get CurrentlyloadedAssemblies because now the .dll file has been loaded... 
        $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    }

    if ($($CurrentlyLoadedAssemblies.FullName | foreach {$($_ -split ",")[0]}) -contains $AssemblyName) {
        Write-Verbose "$AssemblyName is already loaded"
        $WorkingAssemblyReference = $CurrentlyLoadedAssemblies | Where-Object {$($_.FullName -split ",")[0] -eq $AssemblyName}
    }
    else {
        try {
            [System.Collections.ArrayList]$Failures = @()
            try {
                $AssemPartName = [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
                if (!$AssemPartName) {
                    throw
                }
                $WorkingAssemblyReference = $AssemPartName
            }
            catch {
                $null = $Failures.Add("Failed LoadWithPartialName")
            
                try {
                    $AssemTab = $(Invoke-Expression "[$AssemblyName]").Assembly
                    $WorkingAssemblyReference = $AssemTab
                }
                catch {
                    $null = $Failures.Add("Failed TabComplete Check")
                
                    try {
                        $GACChildItems = Get-ChildItem -Recurse $GACDir
                        $AssemblyFileLocation  = foreach ($childitem in $GACChildItems) {
                            if ($_.Name -like "*$AssemblyName.dll") {
                                $_.FullName
                                break
                            }
                        }
                        if ($AssemblyFileLocation) {
                            $AssemLoadFile = [System.Reflection.Assembly]::LoadFile($AssemblyFileLocation)
                            if ($AssemLoadFile) {
                                $WorkingAssemblyReference = $AssemLoadFile
                            }
                            else {
                                throw
                            }
                        }
                        else {
                            throw
                        }
                    }
                    catch {
                        $null = $Failures.Add("Failed LoadFile Check")

                        try {
                            if ($AssemblyName -eq "System.Collections.Generic") {
                                $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match "$AssemblyName.IEnumerable"}    
                            }
                            else {
                                $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match $AssemblyName}
                            }

                            if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferencePrep | Where-Object {$($_.FullName -split ",")[0] -eq $AssemblyName}
                                if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                    $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferenceCheck | Where-Object {$($_.FullName -split ",")[0] -match $AssemblyName}
                                }
                            }

                            $WorkingAssemblyReference = $WorkingAssemblyReferenceCheck
                        }
                        catch {
                            $null = $Failures.Add("CurrentlyLoaded Check")
                        }
                    }
                }
            }

            if ($Failures.Count -gt 3) {
                throw
            }
        }
        catch {
            $null = $AttemptedAssemblyPermutations.Add($AssemblyName)

            if ($AssemblyBaseClassCount -ge 3) {
                for ($i=0; $i -lt $($AssemblyBaseClassCount-2); $i++) {
                    $AssemblyName = $AssemblyName.Substring(0, $AssemblyName.LastIndexOf("."))

                    [System.Collections.ArrayList]$Failures = @()
                    try {
                        $Assem = [System.Reflection.Assembly]::LoadWithPartialName($AssemblyName)
                        if (!$Assem) {
                            throw
                        }
                        $WorkingAssemblyReference = $Assem
                        break
                    }
                    catch {
                        $null = $Failures.Add("Failed LoadWithPartialName")
                    
                        try {
                            $Assem = $(Invoke-Expression "[$AssemblyName]").Assembly
                            $WorkingAssemblyReference = $Assem
                            break
                        }
                        catch {
                            $null = $Failures.Add("Failed TabComplete Check")
                        
                            try {
                                $GACChildItems = Get-ChildItem -Recurse $GACDir
                                $AssemblyFileLocation  = foreach ($childitem in $GACChildItems) {
                                    if ($_.Name -like "*$AssemblyName.dll") {
                                        $_.FullName
                                        break
                                    }
                                }
                                if ($AssemblyFileLocation) {
                                    $AssemLoadFile = [System.Reflection.Assembly]::LoadFile($AssemblyFileLocation)
                                    if ($AssemLoadFile) {
                                        $WorkingAssemblyReference = $AssemLoadFile
                                    }
                                    else {
                                        throw
                                    }
                                }
                                else {
                                    throw
                                }
                            }
                            catch {
                                $null = $Failures.Add("Failed LoadFile Check")

                                try {
                                    if ($AssemblyName -eq "System.Collections.Generic") {
                                        $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match "$AssemblyName.IEnumerable"}    
                                    }
                                    else {
                                        $WorkingAssemblyReferenceCheck = $CurrentlyLoadedAssemblies | Where-Object {$_.ExportedTypes.FullName -match $AssemblyName}
                                    }
        
                                    if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                        $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferencePrep | Where-Object {$($_.FullName -split ",")[0] -like "$AssemblyName*"}
                                        if ($WorkingAssemblyReferenceCheck.Count -gt 1) {
                                            $WorkingAssemblyReferenceCheck = $WorkingAssemblyReferenceCheck | Where-Object {$($_.FullName -split ",")[0] -match $AssemblyName}
                                        }
                                    }
        
                                    $WorkingAssemblyReference = $WorkingAssemblyReferenceCheck
                                }
                                catch {
                                    $null = $Failures.Add("CurrentlyLoaded Check")
                                }
                            }
                        }
                    }

                    if ($Failures.Count -gt 3) {
                        $null = $AttemptedAssemblyPermutations.Add($AssemblyName)
                    }
                }
            }
        }
    }

    if (!$WorkingAssemblyReference) {
        Write-Error "The following attempts at loading the assembly $AssemblyName were made and ALL failed:`n$AttemptedAssemblyPermutations`nHalting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $WorkingAssemblyReference
    }

    ##### END Main Body #####
}


function Get-AssemblyUsingStatement {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AssemblyName,

        [Parameter(Mandatory=$True)]
        $AssemblyFullInfo,

        [Parameter(Mandatory=$False)]
        [switch]$Silent
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Make sure the $AssemblyName matches the $AssemblyFullInfo
    
    if ($AssemblyName -notlike "*$($($AssemblyFullInfo.FullName -split ",")[0])*") {
        Write-Error "The Assembly Reference '$($AssemblyFullInfo.FullName)' does not contain the Assembly Name $AssemblyName! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $UsingStatement = "using $AssemblyName;"

    $AssemblyBaseClassCount = $($AssemblyName -split "\.").Count

    [System.Collections.ArrayList]$AttemptedUsingStatements = @()

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    try {
        $WarningPreference = "SilentlyContinue"
        Add-Type -ReferencedAssemblies $AssemblyFullInfo -TypeDefinition $UsingStatement -IgnoreWarnings -ErrorAction SilentlyContinue
        $WarningPreference = "Continue"
        $UsingStatementWorks = $true
        $FinalUsingStatement = $UsingStatement
    }
    catch {
        $null = $AttemptedUsingStatements.Add($UsingStatement)
        if (!$Silent) {
            Write-Error "$($Error[1])"
        }
        if ($AssemblyBaseClassCount -ge 3) {
            for ($i=0; $i -lt $($AssemblyBaseClassCount-2); $i++) {
                $AssemblyName = $AssemblyName.Substring(0, $AssemblyName.LastIndexOf("."))
                $UsingStatement = "using $AssemblyName;"

                try {
                    Add-Type -ReferencedAssemblies $AssemblyFullInfo -TypeDefinition $UsingStatement -ErrorAction SilentlyContinue
                    $FinalUsingStatement = "using $AssemblyName;"
                    break
                }
                catch {
                    $null = $AttemptedUsingStatements.Add($UsingStatement)
                    if (!$Silent) {
                        Write-Error "$($Error[1])"
                    }
                    if ($i -eq ($AssemblyBaseClassCount-1)) {
                        $FinalUsingStatement = $null
                    }
                }
            }
        }
        else {
            $FinalUsingStatement = $null
        }
    }

    if ($FinalUsingStatement -eq $null) {
        Write-Error "The following `"using`" statements were attempted for $AssemblyName and ALL failed:`n$AttemptedUsingStatements`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalUsingStatement

    ##### END Main Body #####
}


$DefaultAssembliesToLoad = @("Microsoft.CSharp","System","System.Core","System.Linq","System.IO","System.IO.FileSystem"
"System.Console","System.Collections","System.Collections.Generic","System.Runtime","System.Runtime.Extensions")

[System.Collections.ArrayList]$AdditionalAssembliesToCheckFor = @("PresentationCore","PresentationFramework",
"WindowsBase","System.Xaml","System.Windows.Controls","System.Windows.Controls.Primitives","System.Windows.Media")

$AssembliesToCheckFor = $DefaultAssembliesToLoad + $AdditionalAssembliesToCheckFor

[System.Collections.ArrayList]$FoundAssemblies = @()
[System.Collections.ArrayList]$FinalUsingStatements = @()
foreach ($assem in $AssembliesToCheckFor) {
    $global:FunctionResult = 0
    
    $GetAssembliesResult = Get-Assemblies -AssemblyName $assem
    
    if ($global:FunctionResult -eq 1) {
        Write-Error "The Get-Assemblies function failed for $assem!"
        $global:FunctionResult = "1"
        continue
    }

    $null = $FoundAssemblies.Add($GetAssembliesResult)

    $FinalUsingStatement = Get-AssemblyUsingStatement -AssemblyName $assem -AssemblyFullInfo $GetAssembliesResult.FullName -Silent -ErrorAction SilentlyContinue
    $null = $FinalUsingStatements.Add($FinalUsingStatement)
}

if ($FoundAssemblies.Count -eq 0) {
    Write-Error "Unable to find ANY Assmeblies! Halting!"
    $global:FunctionResult = "1"
    return
}
if ($FinalUsingStatements.Count -eq 0) {
    Write-Error "Unable to create ANY 'using' statements! Halting!"
    $global:FunctionResult = "1"
    return
}

$usingStatementsAsString = $($FinalUsingStatements | Sort-Object | Get-Unique) -join "`n"

$ReferencedAssemblies = $FoundAssemblies.FullName | Sort-Object | Get-Unique

# Using Type Extensions in PowerShell see: https://powershell.org/forums/topic/how-do-i-use-extension-methods-in-zipfileextensionsclass/

$TypeDefinition = @"
$usingStatementsAsString
using System.Windows.Media;

namespace WPFUtils.DataGrids
{ 
    public class Cells
    {
        public DataGridCell GetCell(int rowIndex, int columnIndex, DataGrid dg)
        {
            DataGridRow row = dg.ItemContainerGenerator.ContainerFromIndex(rowIndex) as DataGridRow;
            DataGridCellsPresenter p = GetVisualChild<DataGridCellsPresenter>(row);
            DataGridCell cell = p.ItemContainerGenerator.ContainerFromIndex(columnIndex) as DataGridCell;
            return cell;
        }

        static T GetVisualChild<T>(Visual parent) where T : Visual
        {
            T child = default(T);
            int numVisuals = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < numVisuals; i++)
            {
                Visual v = (Visual)VisualTreeHelper.GetChild(parent, i);
                child = v as T;
                if (child == null)
                {
                    child = GetVisualChild<T>(v);
                }
                if (child != null)
                {
                    break;
                }
            }
            return child;
        }
    }
}
"@

Add-Type -ReferencedAssemblies $ReferencedAssemblies -TypeDefinition $TypeDefinition