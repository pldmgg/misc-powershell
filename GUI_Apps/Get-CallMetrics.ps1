# Create syncHash - ALL Runspaces will reference objects contained in the syncHash as well as use it
# to pass things among them
$Global:syncHash = [hashtable]::Synchronized(@{})

##### BEGIN Helper Functions ######

# The below Update-Window function is capable of reaching across runspace threads to update the GUI
# Sample Usage: Update-Window -Control TextBox -property Text -value "Here's some new text!"
Function Update-Window {
    Param (
        $Control,
        $Property,
        $Method,
        $Value,
        [switch]$AppendContent
    )

    # This is kind of a hack, there may be a better way to do this
    if ($Method) {
        $Control.Dispatcher.Invoke([action]{
            $Control.$Method($Value)
        }, "Normal")
    }

    # This updates the control based on the parameters passed to the function
    if ($Property) {
        $Control.Dispatcher.Invoke([action]{
            # This bit is only really meaningful for the TextBox control, which might be useful for logging progress steps
            If ($PSBoundParameters['AppendContent']) {
                $Control.AppendText($Value)
            } Else {
                $Control.$Property = $Value
            }
        }, "Normal")
    }
}

##### END Helper Functions #####


##### BEGIN Runspace Manager Runspace #####

$script:JobCleanup = [hashtable]::Synchronized(@{})
$script:Jobs = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$jobCleanup.Flag = $True
$RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
$RunspaceMgrRunspace.ApartmentState = "STA"
$RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
$RunspaceMgrRunspace.Open()
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobCleanup",$jobCleanup)
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$jobs)
$jobCleanup.PowerShell = [PowerShell]::Create().AddScript({
    # Routine to handle completed Runspaces
    do {
        foreach($runspace in $jobs) {
            if ($runspace.Runspace.isCompleted) {
                [void]$runspace.PowerShell.EndInvoke($runspace.Runspace)
                $runspace.PowerShell.Dispose()
                $runspace.Runspace = $null
                $runspace.PowerShell = $null
            }
        }
        # Clean Out Unused Runspace Jobs
        $temphash = $jobs.clone()
        $temphash | Where-Object {
            $_.runspace -eq $null
        } | foreach {
            $jobs.remove($_)
        }
        Start-Sleep -Seconds 1
    } while ($jobsCleanup.Flag)
})
$jobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
$jobCleanup.Thread = $jobCleanup.PowerShell.BeginInvoke()

##### END Runspace Manager Runspace #####


##### BEGIN GUI Runspace #####

$GUIRunspace =[runspacefactory]::CreateRunspace()
$GUIRunspace.ApartmentState = "STA"
$GUIRunspace.ThreadOptions = "ReuseThread"
$GUIRunspace.Open()
$GUIRunspace.SessionStateProxy.SetVariable("syncHash",$syncHash)
$GUIRunspace.SessionStateProxy.SetVariable("JobCleanup",$script:JobCleanup)
$GUIRunspace.SessionStateProxy.SetVariable("Jobs",$script:Jobs)

$GUIPSInstance = [powershell]::Create()
$GUIPSInstance.AddScript({
    $XAMLinput = @"
<Window x:Name="xamlForm" x:Class="ParseCallMetrics.MainWindow"
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
    xmlns:local="clr-namespace:ParseCallMetrics"
    mc:Ignorable="d"
    Title="Parse Call Metrics" Height="725" Width="1000" MinWidth="950" MinHeight="725" Background="#FFADEDF4" FontFamily="Microsoft Sans Serif" FontSize="14" WindowStyle="ThreeDBorderWindow" WindowStartupLocation="CenterScreen">
<Grid x:Name="xamlGrid">
    <TextBox x:Name="xamlReportDirectoryTextBox" HorizontalAlignment="Left" Height="23" Margin="15,40,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="373" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlHourTextBox" HorizontalAlignment="Left" Height="23" Margin="540,90,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlCalendarDayTextBox" HorizontalAlignment="Left" Height="23" Margin="15,90,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlTimeSpanEndHourTextBox" HorizontalAlignment="Left" Height="23" Margin="540,140,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlTimeSpanStartHourTextBox" HorizontalAlignment="Left" Height="23" Margin="15,140,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlFromWildCardTextBox" HorizontalAlignment="Left" Height="23" Margin="540,240,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlToWildCardTextBox" HorizontalAlignment="Left" Height="23" Margin="15,240,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlFromNameTextBox" HorizontalAlignment="Left" Height="23" Margin="540,290,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlToNameTextBox" HorizontalAlignment="Left" Height="23" Margin="15,290,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlFromPhoneNumberTextBox" HorizontalAlignment="Left" Height="23" Margin="540,340,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlToPhoneNumberTextBox" HorizontalAlignment="Left" Height="23" Margin="15,340,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlFromExtTextBox" HorizontalAlignment="Left" Height="23" Margin="540,390,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <TextBox x:Name="xamlToExtTextBox" HorizontalAlignment="Left" Height="23" Margin="15,390,0,0" TextWrapping="Wrap" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14"/>
    <ComboBox x:Name="xamlDayOfWeekComboBox" HorizontalAlignment="Left" Margin="540,191,0,0" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14" IsEditable="True">
        <ComboBoxItem Cursor="None" Content="Sunday"/>
        <ComboBoxItem Cursor="None" Content="Monday"/>
        <ComboBoxItem Cursor="None" Content="Tuesday"/>
        <ComboBoxItem Cursor="None" Content="Wednesday"/>
        <ComboBoxItem Cursor="None" Content="Thursday"/>
        <ComboBoxItem Cursor="None" Content="Friday"/>
        <ComboBoxItem Cursor="None" Content="Saturday"/>
    </ComboBox>
    <ComboBox x:Name="xamlCallTypeComboBox" HorizontalAlignment="Left" Margin="15,191,0,0" VerticalAlignment="Top" Width="150" IsEditable="True">
        <ComboBoxItem Cursor="None" Content="Incoming" FontSize="14" FontFamily="Microsoft Sans Serif"/>
        <ComboBoxItem Cursor="None" Content="Outgoing" FontSize="14" FontFamily="Microsoft Sans Serif"/>
        <ComboBoxItem Cursor="None" Content="Internal" FontSize="14" FontFamily="Microsoft Sans Serif"/>
    </ComboBox>
    <ProgressBar x:Name="xamlProgressBar1" HorizontalAlignment="Left" Height="30" Margin="200,442,0,0" VerticalAlignment="Top" Width="600"/>
    <Label x:Name="xamlPBarLabel" Content="Progress Bar" HorizontalAlignment="Left" Margin="440,418,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlPBarStatusLabel" Content="Status:" HorizontalAlignment="Left" Margin="358,477,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlCalendarDayLabel" Content="(OPTIONAL) Filter By Calendar Day (1-31)" HorizontalAlignment="Left" Margin="10,65,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlReportDirectoryLabel" Content="(MANDATORY) Please Enter the Directory Path Where Reports Will Be Saved:" HorizontalAlignment="Left" Margin="10,15,0,0" VerticalAlignment="Top" FontWeight="Bold"/>
    <Label x:Name="xamlReportTypeLabel" Content="(MANDATORY) Please Select/Enter the Type of Report" HorizontalAlignment="Left" Margin="535,15,0,0" VerticalAlignment="Top" FontWeight="Bold"/>
    <Label x:Name="xamlHourLabel" Content="(OPTIONAL) Filter By Time of Day (Hour 1-24)" HorizontalAlignment="Left" Margin="535,65,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlTimeSpanStartHourLabel" Content="(OPTIONAL) Filter By Starting Hour (Hour 1-24)" HorizontalAlignment="Left" Margin="10,115,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlTimeSpanEndHourLabel" Content="(OPTIONAL) Filter by Ending Hour (Hour 1-24)" HorizontalAlignment="Left" Margin="535,115,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlCallTypeLabel" Content="(OPTIONAL) Filter By Call Type" HorizontalAlignment="Left" Margin="10,165,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlDayOfWeekLabel" Content="(OPTIONAL) Filter By Day Of the Week (Sunday-Saturday)" HorizontalAlignment="Left" Margin="535,165,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlToWildCardLabel" Content="(OPTIONAL) **Filter By Any Text That Could Be in the &quot;To&quot; Field" HorizontalAlignment="Left" Margin="10,215,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlFromWildCardLabel" Content="(OPTIONAL) **Filter By Any Text That Could Be in the &quot;From&quot; Field" HorizontalAlignment="Left" Margin="535,215,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlToNameLabel" Content="(OPTIONAL) **Filter By the Name of the Party That Was Called" HorizontalAlignment="Left" Margin="10,265,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlFromNameLabel" Content="(OPTIONAL) **Filter By the Name of the Party That Made the Call" HorizontalAlignment="Left" Margin="534,265,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlToPhoneNumberLabel" Content="(OPTIONAL) Filter By Phone # of the Party That Was Called" HorizontalAlignment="Left" Margin="10,315,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlFromPhoneNumberLabel" Content="(OPTIONAL) Filter By Phone # of the Party That Made the Call" HorizontalAlignment="Left" Margin="535,315,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlToExtLabel" Content="(OPTIONAL) Filter By Phone Ext # of the Party That Was Called" HorizontalAlignment="Left" Margin="10,365,0,0" VerticalAlignment="Top"/>
    <Label x:Name="xamlFromExtLabel" Content="(OPTIONAL) Filter By Phone Ext # of the Party That Made the Call" HorizontalAlignment="Left" Margin="534,365,0,0" VerticalAlignment="Top"/>
    <Button x:Name="xamlBrowseButton" Content="Browse" HorizontalAlignment="Left" Margin="393,41,0,0" VerticalAlignment="Top" Width="75"/>
    <ListBox x:Name="xamlExcelSpreadSheetPathsListBox" HorizontalAlignment="Left" Height="80" Margin="10,545,0,0" VerticalAlignment="Top" Width="960" AllowDrop="True"/>
    <Label x:Name="xamlExcelSpreadSheetPathsListboxLabel" Content="(MANDATORY) Please Drag One Or More Excel Spreadsheet Files Here:" HorizontalAlignment="Left" Margin="10,515,0,0" VerticalAlignment="Top" FontWeight="Bold"/>
    <Button x:Name="xamlOKButton" Content="OK" HorizontalAlignment="Left" Margin="775,645,0,0" VerticalAlignment="Top" Width="75" Height="25"/>
    <ComboBox x:Name="xamlReportTypeComboBox" HorizontalAlignment="Left" Margin="540,40,0,0" VerticalAlignment="Top" Width="150" FontFamily="Microsoft Sans Serif" FontSize="14" IsEditable="True">
        <ComboBoxItem Cursor="None" Content="Call Count"/>
        <ComboBoxItem Cursor="None" Content="Call Count By Call Type"/>
        <ComboBoxItem Cursor="None" Content="Call Count By ToPhoneNumber"/>
        <ComboBoxItem Cursor="None" Content="Call Count By FromPhoneNumber"/>
    </ComboBox>
    <Button x:Name="xamlCancelButton" Content="Cancel" HorizontalAlignment="Left" Margin="855,645,0,0" VerticalAlignment="Top" Width="75" Height="25"/>
    <CheckBox x:Name="xamlFixSpreadSheetCheckBox" Content="Fix SpreadSheet Data and Export New SpreadSheet To Report Directory&#x0a;WARNING: This adds a few minutes to total processing time depending on SpreadSheet Size!" HorizontalAlignment="Left" Margin="10,638,0,0" VerticalAlignment="Top" Width="600" Height="30"/>
    <Label Content="** Indicates Wildcard Field" HorizontalAlignment="Left" Margin="10,418,0,0" VerticalAlignment="Top" FontWeight="Bold"/>
    <Label x:Name="xamlListBoxControls" Content="NOTE: To *remove* an item from the listbox below, double-click it." HorizontalAlignment="Left" Margin="547,521,0,0" VerticalAlignment="Top" FontSize="12" FontWeight="Bold"/>

</Grid>
</Window>
"@

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($XAMLInput.GetType().FullName -eq "System.String") {
        $XAMLInput = $XAMLInput -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace 'SelectionChanged="Select_Day_Of_Week_SelectionChanged" '
    }
    if ($XAMLInput.GetType().FullName -eq "System.Xml.XmlDocument") {
        $XAMLInput = $($XAMLInput.OuterXml | Out-String) -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace 'SelectionChanged="Select_Day_Of_Week_SelectionChanged" '
    }

    [void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
    [xml]$XAML = $XAMLInput

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Read XAML
    $reader = New-Object System.Xml.XmlNodeReader $XAML

    try {
        $syncHash.Window = [Windows.Markup.XamlReader]::Load($reader)
        $Form = $syncHash.Window
    }
    catch {
        Write-Verbose "Unable to load Windows.Markup.XamlReader. Double-check syntax and ensure .net is installed."
    }
    if (!$Form) {
        Write-Error $Error[0]
        $global:FunctionResult = "1"
        return
    }

    #===========================================================================
    # Load XAML Objects In PowerShell
    #===========================================================================

    $XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % {
        $syncHash.Add("WPF$($_.Name)",$syncHash.Window.FindName($_.Name))
    }

    do {
        Start-Sleep -Seconds 1
        Write-Host "Waiting for SyncHash To Populate"
    } until ($syncHash -ne $null)

    $syncHash.InitialLoad = "Complete"
    $syncHash.ParentThreadPID = $PID

    ##### BEGIN Form Control Methods #####

    ## BEGIN Report Directory Browse Button Functionality ##

    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

    $browse = New-Object System.Windows.Forms.FolderBrowserDialog 
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        $browse.RootFolder = [System.Environment+SpecialFolder]'UserProfile'
    }
    else {
        $browse.RootFolder = [System.Environment+SpecialFolder]'MyComputer'
        $browse.SelectedPath = "$HOME"
    }
    $browse.ShowNewFolderButton = $false
    $browse.Description = "Please Choose a Directory"

    $($syncHash.WPFxamlBrowseButton).Add_Click({
        $browse.ShowDialog()
        $($syncHash.WPFxamlReportDirectoryTextBox).Text = $browse.SelectedPath
    })

    ## END Report Directory Browse Button Functionality ##

    ## BEGIN Hour, TimeSpanStart, and TimeSpanEnd Field Validation ##

    $($syncHash.WPFxamlHourTextBox).Add_KeyUp({
        if ($($syncHash.WPFxamlHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlTimeSpanStartHourTextBox).Text = ""
            $($syncHash.WPFxamlTimeSpanEndHourTextBox).Text = ""
        }
    })
    $($syncHash.WPFxamlHourTextBox).Add_LostFocus({
        if ($($syncHash.WPFxamlHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlTimeSpanStartHourTextBox).Text = ""
            $($syncHash.WPFxamlTimeSpanEndHourTextBox).Text = ""
        }
    })

    $($syncHash.WPFxamlTImeSpanStartHourTextBox).Add_KeyUp({
        if ($($syncHash.WPFxamlTimeSpanStartHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlHourTextBox).Text = ""
        }
    })
    $($syncHash.WPFxamlTImeSpanStartHourTextBox).Add_LostFocus({
        if ($($syncHash.WPFxamlTimeSpanStartHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlHourTextBox).Text = ""
        }
    })

    $($syncHash.WPFxamlTimeSpanEndHourTextBox).Add_KeyUp({
        if ($($syncHash.WPFxamlTimeSpanEndHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlHourTextBox).Text = ""
        }
    })

    $($syncHash.WPFxamlTimeSpanEndHourTextBox).Add_LostFocus({
        if ($($syncHash.WPFxamlTimeSpanEndHourTextBox).Text -match "[\w]+") {
            $($syncHash.WPFxamlHourTextBox).Text = ""
        }
    })

    ## END Hour, TimeSpanStart, and TimeSpanEnd Field Validation ##

    ## BEGIN ListBox Drag and Drop Functionality ##

    $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Add_DragEnter({
        $_.Effects = [Windows.Forms.DragDropEffects]::Copy
    })
    $addhandler = {
        $_.Data.GetFileDropList() | % {
            $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Items.Add($_)
        }
    }
    $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Add_Drop($addhandler)

    <#
    $deletehandler = {
        $_.Data.GetFileDropList() | % {
            $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Items.Remove($_)
        }
    }
    #>
    $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Add_MouseDoubleClick({
        $($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Items.Remove($($syncHash.WPFxamlExcelSpreadSheetPathsListBox).SelectedItem)
    })

    ## END ListBox Drag and Drop Functionality ##


    ## BEGIN OK Button Functionality ##

    $($syncHash.WPFxamlOKButton).Add_Click({ 
        $newRunspace =[runspacefactory]::CreateRunspace()
        $newRunspace.ApartmentState = "STA"
        $newRunspace.ThreadOptions = "ReuseThread"
        $newRunspace.Open()
        $newRunspace.SessionStateProxy.SetVariable("syncHash",$syncHash)
        $newRunspace.SessionStateProxy.SetVariable("listboxRS",$($syncHash.WPFxamlExcelSpreadSheetPathsListBox).Items)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxReportDirRS",$($syncHash.WPFxamlReportDirectoryTextBox).Text)
        if ($($syncHash.WPFxamlReportTypeComboBox).SelectedItem -ne $null) {
            $newRunspace.SessionStateProxy.SetVariable("comboBoxReportTypeRS",$($($syncHash.WPFxamlReportTypeComboBox).SelectedItem).Content.ToString())
        }
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxHourRS",$($syncHash.WPFxamlHourTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxTimeSpanStartRS",$($syncHash.WPFxamlTimeSpanStartHourTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxTimeSpanEndRS",$($syncHash.WPFxamlTimeSpanEndHourTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxCDRS",$($syncHash.WPFxamlCalendarDayTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("comboBoxDoWRS",$($syncHash.WPFxamlDayOfWeekComboBox).Text)
        if ($($syncHash.WPFxamlCallTypeComboBox).SelectedItem -ne $null) {
            $newRunspace.SessionStateProxy.SetVariable("comboBoxCallTypeRS",$($($syncHash.WPFxamlCallTypeComboBox).SelectedItem).Content.ToString())
        }
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxFromRS",$($syncHash.WPFxamlFromWildCardTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxToRS",$($syncHash.WPFxamlToWildCardTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxFromPhoneRS",$($syncHash.WPFxamlFromPhoneNumberTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxFromExtRS",$($syncHash.WPFxamlFromExtTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxFromNameRS",$($syncHash.WPFxamlFromNameTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxToPhoneRS",$($syncHash.WPFxamlToPhoneNumberTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxToExtRS",$($syncHash.WPFxamlToExtTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objTextBoxToNameRS",$($syncHash.WPFxamlToNameTextBox).Text)
        $newRunspace.SessionStateProxy.SetVariable("objCheckboxRS",$($syncHash.WPFxamlFixSpreadSheetCheckBox).IsChecked)

        $PSInstance = [powershell]::Create()
        $PSInstance.AddScript({
            $syncHash.CompleteFlag = "Working"

            Function Update-Window {
                Param (
                    $Control,
                    $Property,
                    $Method,
                    $Value,
                    [switch]$AppendContent
                )

                # This is kind of a hack, there may be a better way to do this
                if ($Method) {
                    $Control.Dispatcher.Invoke([action]{
                        $Control.$Method($Value)
                    }, "Normal")
                }

                # This updates the control based on the parameters passed to the function
                if ($Property) {
                    $Control.Dispatcher.Invoke([action]{
                        # This bit is only really meaningful for the TextBox control, which might be useful for logging progress steps
                        If ($PSBoundParameters['AppendContent']) {
                            $Control.AppendText($Value)
                        } Else {
                            $Control.$Property = $Value
                        }
                    }, "Normal")
                }
            }

            ##### BEGIN MAIN Spreadsheet Parsing Function #####

            <#
            .SYNOPSIS
                Short description
            .DESCRIPTION
                Long description
            .NOTES
                DEPENDENCEIES
                    Helper scripts/functions and/or binaries needed for the function to work.

                Run PowerShell as a non-admin:
                    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

            .PARAMETER
                N parameter
            .PARAMETER
                N+1 parameter
            .EXAMPLE
                Get-CallMetrics -ExcelSpreadSheetPaths "$HOME\Downloads\call_activity_2016 December.xlsx" -ReportDirectory "C:\Users\pddomain" -CalendarDay 31
            .EXAMPLE
                Another example of how to use this cmdlet
            .INPUTS
                Inputs to this cmdlet (if any)
            .OUTPUTS
                Output from this cmdlet (if any)
            #>
            function Get-CallMetrics {
                [CmdletBinding()]
                Param( 
                    [Parameter(Mandatory=$False)]
                    #[string[]]$ExcelSpreadSheetPaths = $(Write-Error "Whoops - No spreadsheets"),
                    [string[]]$ExcelSpreadSheetPaths = $(Read-Host -Prompt "Please enter a file path to a .xlsx file, OR a comma separated list of file paths to .xlsx files, OR a directory/folder path that contains .xlsx files, OR a comma separated list of directory/folder paths that contain .xlsx files"),

                    [Parameter(Mandatory=$False)]
                    #[string]$ReportDirectory = $(Write-Error "Whoops - No Report Directory"),
                    [string]$ReportDirectory = $(Read-Host -Prompt "Please enter a path to a directory/folder that will contain the Report(s)"),

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,24)]
                    [int]$TimeSpanStartHour,

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,24)]
                    [int]$TimeSpanEndHour,

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,24)]
                    [int]$Hour,

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,60)]
                    [int]$Minute,

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,60)]
                    [int]$Second,

                    [Parameter(Mandatory=$False)]
                    [ValidateRange(0,31)]
                    [int]$CalendarDay,

                    [Parameter(Mandatory=$False)]
                    [ValidateSet("Sunday", "Monday","Tuesday","Wednesday","Thursday","Friday","Saturday")]
                    $DayOfWeek,  

                    [Parameter(Mandatory=$False)]
                    [ValidateSet("Incoming", "Outgoing","Internal")]
                    $CallType,

                    # Below regex is from: http://stackoverflow.com/questions/8318236/regex-pattern-for-hhmmss-time-string
                    [Parameter(Mandatory=$False)]
                    [ValidatePattern('^(?:(?:([01]?\d|2[0-3]):)?([0-5]?\d):)?([0-5]?\d)$')]
                    [string]$Duration,

                    [Parameter(Mandatory=$False)]
                    $FromWildCard,

                    [Parameter(Mandatory=$False)]
                    $FromPhoneNumber,

                    [Parameter(Mandatory=$False)]
                    $FromExt,

                    [Parameter(Mandatory=$False)]
                    $FromName,

                    [Parameter(Mandatory=$False)]
                    $ToWildCard,

                    [Parameter(Mandatory=$False)]
                    $ToPhoneNumber,

                    [Parameter(Mandatory=$False)]
                    $ToExt,

                    [Parameter(Mandatory=$False)]
                    $ToName,

                    [Parameter(Mandatory=$False)]
                    [switch]$FixSpreadsheet,

                    [Parameter(Mandatory=$False)]
                    [ValidateSet("Call Count", "Call Count By Call Type","Call Count By ToPhoneNumber","Call Count By FromPhoneNumber")]
                    $ReportType
                )

                ##### BEGIN Native Helper Functions #####

                function Convert-Size {
                    [cmdletbinding()]
                    param(
                        [Parameter(Mandatory=$True)]
                        [validateset("Bytes","KB","MB","GB","TB")]
                        [string]$From,

                        [Parameter(Mandatory=$True)]
                        [validateset("Bytes","KB","MB","GB","TB")]
                        [string]$To,

                        [Parameter(Mandatory=$True)]
                        [double]$Value,

                        [Parameter(Mandatory=$False)]
                        [int]$Precision = 4
                    )

                    switch($From) {
                        "Bytes" {$Value = $Value }
                        "KB" {$Value = $Value * 1024 }
                        "MB" {$Value = $Value * 1024 * 1024}
                        "GB" {$Value = $Value * 1024 * 1024 * 1024}
                        "TB" {$Value = $Value * 1024 * 1024 * 1024 * 1024}
                    }            
                                
                    switch ($To) {
                        "Bytes" {return $value}
                        "KB" {$Value = $Value/1KB}
                        "MB" {$Value = $Value/1MB}
                        "GB" {$Value = $Value/1GB}
                        "TB" {$Value = $Value/1TB}
                    }

                    return [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)
                }


                # Function for unzipping file in PowerShell 2.0
                function Expand-ZIPFile {
                    [cmdletbinding()]
                    param(
                        [Parameter(Mandatory=$False)]
                        [string]$ZipFile,

                        [Parameter(Mandatory=$False)]
                        [string]$Destination
                    )

                    if (! $(Test-Path $ZipFIle)) {
                        Write-Verbose "The file path $ZipFile was not found! Halting!"
                        Write-Error "The file path $ZipFile was not found! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    if (! $(Test-Path $Destination)) {
                        Write-Verbose "The directory path $Destination was not found! Halting!"
                        Write-Error "The directory path $Destination was not found! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }

                    $Shell = New-Object -COM Shell.Application
                    $Zip = $Shell.NameSpace($ZipFile)

                    foreach($Item in $Zip.items()) {
                        $Shell.Namespace($Destination).copyhere($Item)
                    }
                }


                ## Function for Unzipping File / Extracting a particular file/files from a zip for PowerShell 3.0 and higher
                <#
                .Synopsis
                   Extract specific files from a compressed archive.

                   Credit to /u/skuchoochum: https://www.reddit.com/r/PowerShell/comments/5uaquy/extracting_specific_files_from_a_zip_archive/

                .DESCRIPTION
                   If no argument is given to File then each archive will be extracted normally to the DestinationPath.

                   File names can be given as a comma-separated array to the File parameter. Expand-CompressedFile will then search in each
                   archive for every file specified.

                .EXAMPLE
                   Get-ChildItem | Where Extension -eq ".zip" | Expand-CompressedFile -DestinationPath UnzipHere -File FileOne, SecondFileIwant.txt

                   DESCRIPTION
                   -----------
                   Get-ChildItem sends every item in the current directory through the Where-Object cmdlet which filters away files that do not have
                   the extension ".zip". After filtering, the result is piped to the Expand-CompressedFile function which opens the archive and searches
                   for items that matches 'FileOne' and 'SecondFileIwant.txt'. If any of these files are found they are then placed in the UnzipHere
                   folder with the name of the zip archive and the internal name.

                .EXAMPLE
                   Get-Item ZippedFolder.zip | ecf

                   DESCRIPTION
                   -----------
                   Extracts the contents of ZippedFolder.zip to the folder ZippedFolder in the current directory.
                #>
                function Expand-CompressedFile {
                    [CmdletBinding(
                        SupportsShouldProcess=$true,
                        DefaultParameterSetName='ExpandArchive'
                    )]
                    [Alias('ecf')]
                    Param(
                        # Specifies a path to one or more locations. Wildcards are permitted.
                        [Parameter(
                            Mandatory=$true,
                            ValueFromPipeline=$true,
                            ValueFromPipelineByPropertyName=$true,
                            Position=1
                        )]
                        [Alias('FullName')]
                        [string[]]$Path,

                        # Specifies the path to the folder in which you want the command to save extracted files.
                        # Enter the path to a folder, but do not specify a file name or file name extension.
                        [Parameter(
                            Mandatory=$false,
                            ParameterSetName='ExpandArchive'
                        )]
                        [Parameter(
                            Mandatory=$true,
                            ParameterSetName='ExpandFile'
                        )]
                        [Alias('dp')]
                        [string]$DestinationPath = (Get-Location),

                        # Specify file names within a compressed archive.
                        [Parameter(
                            Mandatory=$true,
                            ParameterSetName='ExpandFile'
                        )] 
                        [string[]]$File,

                        # Overwrites existing files. If Force is not used an error is produced if the file exists.
                        [Parameter(Mandatory=$false)]
                        [switch]$Force,

                        # Passes an object that represents the item to the pipeline. By default, this cmdlet does not generate any output.
                        [Parameter(Mandatory=$false)]
                        [switch]$Passthru
                    )
                    BEGIN {
                        if( -not (Test-Path $DestinationPath)) {
                            New-Item -ItemType Directory -Path $DestinationPath -ErrorAction Stop | Out-Null
                        }
                        $DestinationDirectory = (Resolve-Path $DestinationPath -ErrorAction Stop).ProviderPath

                        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
                        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

                        $ZipFile = [System.IO.Compression.ZipFile]
                        $ZipExtensions = [System.IO.Compression.ZipFileExtensions]
                    }
                    PROCESS {
                        foreach($Zip in $Path) {
                            try {
                                $ResolvedPath = (Resolve-Path $Zip -ErrorAction Stop).ProviderPath
                                $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($ResolvedPath)

                                # if([System.IO.Path]::GetExtension($ResolvedPath) -ne ".zip") { continue }
                                <#
                                    User choice dilemma: assume they only want to process .zip files?
                                    Filtering with Get-ChildItem is not difficult and something they should be doing before using this command.
                                #>

                                if($PSCmdlet.ShouldProcess("$ResolvedPath", "Expanding files")) {
                                    if($File) {
                                        $ZipArchive = $ZipFile::OpenRead($ResolvedPath)
                                        foreach($FileName in $File) {
                                            try {
                                                # Get compressed files. IO.Path.GetExtension excludes folders.
                                                $Entries = $ZipArchive.Entries |
                                                    Where-Object { $_.Name -match $FileName -and [System.IO.Path]::GetExtension($_.Name)}
                                                foreach($Entry in $Entries) {
                                                    # Destination name: "DestinationDirectory\ZipBaseName InternalFileName.extension"
                                                    $ExtractToFile = ("{0}\{1} {2}" -f $DestinationDirectory, $BaseName, $Entry.Name)
                                                    if($Force) {
                                                        # Overwrite existing file.
                                                        $ZipExtensions::ExtractToFile($Entry, $ExtractToFile, $true)
                                                    }
                                                    else {
                                                        $ZipExtensions::ExtractToFile($Entry, $ExtractToFile, $false)
                                                    }
                                                    if($Passthru) {
                                                        Write-Output (Get-Item $ExtractToFile)
                                                    }
                                                }
                                            }
                                            catch {
                                                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                                            }
                                        }
                                    } # If File
                                    else {
                                        # No files specified, extract the entire archive
                                        $ZipFile::ExtractToDirectory($ResolvedPath, $DestinationDirectory)
                                        if($Passthru) {
                                            Write-Output (Get-Item "$DestinationDirectory\$BaseName")
                                        }
                                    } # If File Else
                                }
                            }
                            catch {
                                Write-Error -Exception $_.Exception -Message $_.Exception.Message
                            }
                        }
                    }
                    END {
                    }
                }


                Function Convert-ExcelXLSXtoCSV {
                    [CmdletBinding()]
                    Param( 
                        [Parameter(Mandatory=$False)]
                        $InXLSXFile = $(Read-Host -Prompt "Please enter the full path to the .xlsx file."),
                
                        [Parameter(Mandatory=$False)]
                        $OutCSVFile = $(Read-Host -Prompt "Please enter the full path to the NEW output file with .csv extension")
                    )

                    if (!$(Test-Path $InXLSXFile)) {
                        Write-Verbose "The path $InXLSXFile was not found! Halting!"
                        Write-Error "The path $InXLSXFile was not found! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    if ($(Get-ChildItem $InXLSXFile).Extension -ne ".xlsx") {
                        Write-Verbose "The file $InXLSXFile is not a .xlsx file! Halting!"
                        Write-Error "The file $InXLSXFile is not a .xlsx file! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }

                    $OutCSVFileFileName = $($OutCSVFile | Split-Path -Leaf).Split("\.")[0]

                    $Excel = New-Object -ComObject Excel.Application
                    $Excel.Visible = $false
                    $Excel.DisplayAlerts = $false
                    $wb = $Excel.Workbooks.Open($InXLSXFile)
                    $($wb.Worksheets)[0].SaveAs($OutCSVFile, 6)
                    <#
                    for ($i=0; $i -lt $($wb.Worksheets).Count; $i++) {
                        $($wb.Worksheets)[$i].SaveAs("$OutCSVFileFileName$i", 6)
                    }
                    #>
                    $Excel.Quit()
                }

                ##### END Native Helper Functions #####


                ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
                if ($FromPhoneNumber) {
                    $FromPhoneNumber = $($FromPhoneNumber | Select-String -AllMatches -Pattern "[0-9]").Matches.Value -join ""
                }
                if ($ToPhoneNumber) {
                    $ToPhoneNumber = $($ToPhoneNumber | Select-String -AllMatches -Pattern "[0-9]").Matches.Value -join ""
                }
                if ($FromExt) {
                    $FromExt = $($FromExt | Select-String -AllMatches -Pattern "[0-9]").Matches.Value -join ""
                }
                if ($ToExt) {
                    $ToExt = $($ToExt | Select-String -AllMatches -Pattern "[0-9]").Matches.Value -join ""
                }

                try {
                    $UpdatedReportDirectory = Resolve-Path $ReportDirectory
                }
                catch {
                    Write-Verbose "Unable to resolve path to $ReportDirectory! Halting!" 
                }
                if (!$UpdatedReportDirectory) {
                    Write-Verbose "The directory path $UpdatedReportDirectory was not found! Halting!"
                    Write-Error "The directory path $UpdatedReportDirectory was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                # Test $ExcelSpreadSheetPaths
                $VariablesToRemoveAtEndOfForEachLoop = @("UpdatedItemPath","DirectoryXLSXContents","GCIObject","DateTimeObject")
                $FinalExcelSpreadSheetFiles = @()
                foreach ($ItemPath in $ExcelSpreadSheetPaths) {
                    try {
                        $UpdatedItemPath = Resolve-Path $ItemPath
                    }
                    catch {
                        Write-Verbose "The path $ItemPath was not found! Skipping..."
                    }
                    if (!$UpdatedItemPath) {
                        Write-Warning "The path $ItemPath was not found! Skipping..."
                        continue
                    }
                    if (Test-Path -PathType Container -Path $UpdatedItemPath) {
                        $DirectoryXLSXContents = Get-ChildItem $UpdatedItemPath | Where-Object {$_.Extension -eq ".xlsx"}
                        if (!$DirectoryXLSXContents) {
                            Write-Warning "No .xlsx files found in the directory $UpdatedItemPath. Skipping..."
                            continue
                        }
                        if ($DirectoryXLSXContents) {
                            foreach ($SubItem in $DirectoryXLSXContents) {
                                New-Variable -Name "$($($SubItem.Name).Split("\.")[0])" -Value $(
                                    New-Object PSObject -Property @{
                                        FullPath          = $SubItem.FullName
                                        FileName          = $SubItem.Name
                                        FileSizeInBytes   = $SubItem.Length
                                    }
                                )
                                
                                $FinalExcelSpreadSheetFiles +=, $(Get-Variable -Name "$($($SubItem.Name).Split("\.")[0])" -ValueOnly)
                            }
                        }
                    }
                    if (Test-Path -PathType Leaf -Path $UpdatedItemPath) {
                        if ($(Get-ChildItem $UpdatedItemPath).Extension -ne ".xlsx") {
                            Write-Warning "The file $UpdatedItemPath is NOT a .xlsx file. Skipping..."
                            continue
                        }
                        if ($(Get-ChildItem $UpdatedItemPath).Extension -eq ".xlsx") {
                            $GCIObject = Get-ChildItem $UpdatedItemPath
                            New-Variable -Name "$($($GCIObject.Name).Split("\.")[0])" -Value $(
                                New-Object PSObject -Property @{
                                    FullPath          = $GCIObject.FullName
                                    FileName          = $GCIObject.Name
                                    FileSizeInBytes   = $GCIObject.Length
                                }
                            )

                            $FinalExcelSpreadSheetFiles +=, $(Get-Variable -Name "$($($GCIObject.Name).Split("\.")[0])" -ValueOnly)
                        }
                    }

                    # Cleanup
                    foreach ($VarName in $VariablesToRemoveAtEndOfForEachLoop) {
                        Remove-Variable -Name "$VarName" -Force -ErrorAction SilentlyContinue
                    }
                }
                if ($FinalExcelSpreadSheetFiles.Count -lt 1) {
                    Write-Verbose "No .xlsx files were found at any of the specified paths! Halting!"
                    Write-Error "No .xlsx files were found at any of the specified paths! Halting!"
                    $global:FunctionResult = "1"
                    return
                }

                $TotalSizeInGBOfExcelSpreadSheets = Convert-Size -From Bytes -To GB -Value $($($FinalExcelSpreadSheetFiles | foreach {$_.FileSizeInBytes} | Measure-Object -Sum).Sum)

                if ($TotalSizeInGBOfExcelSpreadSheets -gt 2) {
                    Write-Warning "Processing these Excel spreadsheets could take up to $TotalSizeInGBOfExcelSpreadSheets GB in Memory."
                    $ShouldWeContinue = Read-Host -Prompt "Would you like to continue? [Yes/No]"
                    while ($ShouldWeContinue -notmatch "Yes|Y|No|N") {
                        Write-Warning "$ShouldWeContinue is not a valid option. Please enter 'Yes','Y','No', or 'n'"
                        $ShouldWeContinue = Read-Host -Prompt "Would you like to continue? [Yes/No]"
                    } 
                    if ($ShouldWeContinue -match "No|N") {
                        Write-Host "Halting!"
                        return
                    }
                }

                # Get PSExcel PowerShell Module
                if ($(Get-Module -ListAvailable | % {$_.Name}) -notcontains "PSExcel") {
                    $PSExcelURL = "https://github.com/RamblingCookieMonster/PSExcel/archive/master.zip"
                    $PSExcelDestination = "$HOME\Downloads\PSExcelMaster.zip"
                    if ($PSVerstionTable.PSVersion.Major -lt 3) {
                        $WebClient = new-object System.Net.WebClient 
                        $WebClient.DownloadFile($PSExcelURL, $PSExcelDestination) 
                    }
                    if ($PSVerstionTable.PSVersion.Major -ge 3) {
                        Invoke-WebRequest -Uri "https://github.com/RamblingCookieMonster/PSExcel/archive/master.zip" -OutFile "$HOME\Downloads\PSExcelMaster.zip"
                    }
                    if (!$(Test-Path "$Home\Documents\WindowsPowerShell")) {
                        New-Item -Type Directory -Path "$Home\Documents\WindowsPowerShell"
                    }
                    if (!$(Test-Path "$Home\Documents\WindowsPowerShell\Modules")) {
                        New-Item -Type Directory -Path "$Home\Documents\WindowsPowerShell\Modules"
                    }
                    if ($PSVerstionTable.PSVersion.Major -lt 3) {
                        Expand-ZIPFile -ZipFile $PSExcelDestination -Destination "$HOME\Downloads"
                        Copy-Item -Recurse -Path "$HOME\Downloads\PSExcel-master\PSExcel" -Destination "$Home\Documents\WindowsPowerShell\Modules\PSExcel"
                        Remove-Item -Recurse -Path "$HOME\Downloads\PSExcel-master" -Force
                    }
                    if ($PSVerstionTable.PSVersion.Major -ge 3) {
                        Expand-CompressedFile -Path "$HOME\Downloads\PSExcelMaster.zip" -DestinationPath "$HOME\Downloads"
                        Copy-Item -Recurse -Path "$HOME\Downloads\PSExcelMaster\PSExcel" -Destination "$Home\Documents\WindowsPowerShell\Modules\PSExcel"
                        Remove-Item -Recurse -Path "$HOME\Downloads\PSExcelMaster" -Force
                    }
                    
                    Import-Module PSExcel
                }
                if ($(Get-Module).Name -notcontains "PSExcel") {
                    Import-Module PSExcel
                }

                # Sort out the Parameters
                $AllParams = $($PSBoundParameters.GetEnumerator())
                $AllFilterableParams = $($PSBoundParameters.GetEnumerator()) | Where-Object {$_.Key -ne "ExcelSpreadSheetPaths" -and $_.Key -ne "ReportDirectory"}
                
                $WildCardParams = @("ToWildCard","FromWildCard","ToName","FromName")
                $ReadilyFilterableWildCardParams = foreach ($Param in $WildCardParams) {if ($PSBoundParameters.Keys -contains $Param) {$Param}}
                
                $PreciseParams = @("CallType","ToPhoneNumber","ToExt","FromPhoneNumber","FromExt")
                $ReadilyFilterablePreciseParams = foreach ($Param in $PreciseParams) {if ($PSBoundParameters.Keys -contains $Param) {$Param}}

                $DateTimeParams = @("CalendarDay","DayOfWeek","Hour","Minute","Second")
                $ReadilyFilterableDateTimeParams = foreach ($Param in $DateTimeParams) {if ($PSBoundParameters.Keys -contains $Param) {$Param}}


                $syncHashCollection = @()
                $PSInstanceCollection = @()
                $RunSpaceCollection = @()
                $AsyncHandleCollection = @()
                # Prepare and Create Runspaces for each Excel SpreadSheet
                for ($i=0; $i -lt $FinalExcelSpreadSheetFiles.Count; $i++)
                {
                    New-Variable -Name "syncHash$i" -Scope Global -Value $([hashtable]::Synchronized(@{}))
                    $syncHashCollection +=, $(Get-Variable -Name "syncHash$i" -ValueOnly)

                    New-Variable -Name "Runspace$i" -Value $([runspacefactory]::CreateRunspace())
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).ApartmentState = "STA"
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).ThreadOptions = "ReuseThread"
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).Open()
                    # Pass all function Parameters to Runspace
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("AllParams",$AllParams)
                    foreach ($ParamKVP in $AllParams) {
                        $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("$($ParamKVP.Key)",$(Get-Variable -Name "$($ParamKVP.Key)" -ValueOnly))
                    }
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("syncHash",$(Get-Variable -Name "syncHash$i" -ValueOnly))
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("SpreadSheetFileItem",$FinalExcelSpreadSheetFiles[$i])
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("UpdatedReportDirectory",$UpdatedReportDirectory)
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("ReadilyFilterableWildCardParams",$ReadilyFilterableWildCardParams)
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("ReadilyFilterablePreciseParams",$ReadilyFilterablePreciseParams)
                    $(Get-Variable -Name "Runspace$i" -ValueOnly).SessionStateProxy.SetVariable("ReadilyFilterableDateTimeParams",$ReadilyFilterableDateTimeParams)

                    New-Variable -Name "PSInstance$i" -Value $([System.Management.Automation.PowerShell]::Create())
                    $(Get-Variable -Name "PSInstance$i" -ValueOnly).AddScript({
                        $syncHash.CompleteFlag = "Working"
                        
                        # Reset some things within the Runspace
                        Import-Module PSExcel
                        $FileItem = $SpreadSheetFileItem

                        $DataSet = Import-XLSX -Path $FileItem.FullPath -Sheet 1
                        # Make Sure To, Account Code, and Column 7 are Strings, not doubles
                        $DataSet = $DataSet | foreach {
                            if ($_.To -match "[\w\W]+") {
                                if ($_.To.GetType().FullName -eq "System.Double") {
                                    $_.To = $_.To.ToString()
                                }
                            }
                            if ($_.'Acct. Code' -match "[\w\W]+") {
                                if ($_.'Acct. Code'.GetType().FullName -eq "System.Double") {
                                    $_.'Acct. Code' = $_.'Acct. Code'.ToString()
                                }
                            }
                            if ($_.'<Column 7>' -match "[\w\W]+") {
                                if ($_.'<Column 7>'.GetType().FullName -eq "System.Double") {
                                    $_.'<Column 7>' = $_.'<Column 7>'.ToString()
                                }
                            }

                            $_
                        }

                        # Fix Duration Column
                        if ($DataSet[0].Duration.GetType().FullName -ne "System.TimeSpan") {
                            $DataSet = $DataSet | foreach {
                                $DurationCheck = $_.Duration -match "[\w\W]+"
                                if ($DurationCheck -and $_.Duration.GetType().FullName -ne "System.TimeSpan") {
                                    [string]$DurationPropertyAsString = $($($_.Duration | Out-String).Trim() -split " ")[-2]
                                    $HHMMSSArray = $DurationPropertyAsString.Split(":")
                                    if ($HHMMSSArray[0] -eq "12") {
                                        $HHMMSSArray[0] = "00"
                                        $_.Duration = [timespan]$($HHMMSSArray -join ":")
                                        $_
                                    }
                                    if ($HHMMSSArray[0] -eq "1" -or $HHMMSSArray[0] -eq "01") {
                                        $HHMMSSArray[0] = "01"
                                        $_.Duration = [timespan]$($HHMMSSArray -join ":")
                                        $_
                                    }
                                    if ($HHMMSSArray[0] -eq "2" -or $HHMMSSArray[0] -eq "02") {
                                        $HHMMSSArray[0] = "02"
                                        $_.Duration = [timespan]$($HHMMSSArray -join ":")
                                        $_
                                    }
                                    if ($HHMMSSArray[0] -eq "3" -or $HHMMSSArray[0] -eq "03") {
                                        $HHMMSSArray[0] = "03"
                                        $_.Duration = [timespan]$($HHMMSSArray -join ":")
                                        $_
                                    }
                                }
                            }
                        }
                        # Fix Date/Time Column
                        if ($DataSet[0].'Date/Time'.GetType().FullName -ne "System.DateTime") {
                            $DataSet = $DataSet | foreach {
                                $DateTimeCheck = $_.'Date/Time' -match "[\w\W]+"
                                if ($DateTimeCheck -and $_.'Date/Time'.GetType().FullName -ne "System.DateTime") {
                                    [DateTime]$DateTimeFixed = $($_.'Date/Time').Trim() -replace '"',''
                                    $_.'Date/Time' = $DateTimeFixed
                                    $_
                                }
                            }
                        }

                        # Add Properties FromPhoneNumber and FromName and FromExt
                        if ($($($DataSet[0] | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"}).Name -join ", ") -notmatch "FromPhoneNumber|FromName|FromExt") {
                            $DataSet = $DataSet | foreach {
                                $FromPhoneNumberRegex = '((^\d{3}|\(\d{3}\))(-|\s)\d{3}-\d{4})|([0-9]{10})'
                                # Below $FromPhoneNumber should be just 10 digits - not other characters or spaces
                                $FromPhoneNumber = if ($($_.From | Select-String -Pattern $FromPhoneNumberRegex).Matches.Success) {
                                    $($($_.From | Select-String -Pattern $FromPhoneNumberRegex).Matches.Value | Select-String -AllMatches "[0-9]+").Matches.Value -join ""
                                }
                                $FromNameRegex = '([a-zA-Z]+(\s|[a-zA-Z])+)'
                                $FromName = if ($($_.From | Select-String -Pattern $FromNameRegex).Matches.Success) {
                                    $($_.From | Select-String -AllMatches -Pattern $FromNameRegex).Matches.Value | Where-Object {$_.Trim() -ne "Extension"}
                                }
                                $FromExtRegex = '(\s[0-9]{3}\s)|(\<[0-9]{3}\>)|(\s[0-9]{3}\])'
                                $FromExt = if ($($_.From | Select-String -Pattern $FromExtRegex).Matches.Success) {
                                    $($($_.From | Select-String -Pattern $FromExtRegex).Matches.Value).Trim() -replace "\W",""
                                }

                                $_ | Add-Member -MemberType NoteProperty -Name "FromPhoneNumber" -Value "$FromPhoneNumber"
                                $_ | Add-Member -MemberType NoteProperty -Name "FromName" -Value "$FromName"
                                $_ | Add-Member -MemberType NoteProperty -Name "FromExt" -Value "$FromExt"
                                $_
                            }
                        }

                        # Add Properties ToPhoneNumber and ToName and ToExt and ToVoiceMail and ToGroup
                        if ($($($DataSet[0] | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty"}).Name -join ", ") -notmatch "ToPhoneNumber|ToName|ToExt") {
                            $DataSet = $DataSet | foreach {
                                $ToPhoneNumberRegex = '((^\d{3}|\(\d{3}\))(-|\s)\d{3}-\d{4})|([0-9]{10})'
                                # Below $ToPhoneNumber should be just 10 digits - not other characters or spaces
                                $ToPhoneNumber = if ($($_.To | Select-String -Pattern $ToPhoneNumberRegex).Matches.Success) {
                                    $($($_.To | Select-String -Pattern $ToPhoneNumberRegex).Matches.Value | Select-String -AllMatches "[0-9]+").Matches.Value -join ""
                                }
                                $ToNameRegex = "([a-zA-Z]+(\s|[a-zA-Z]|'$)+)"
                                $ToName = if ($($_.To | Select-String -Pattern $ToNameRegex).Matches.Success) {
                                    $($_.To | Select-String -AllMatches -Pattern $ToNameRegex).Matches.Value | Where-Object {
                                        $_.Trim() -ne "Extension" -and 
                                        $_.Trim() -ne "Group" -and
                                        $_.Trim() -ne "Voicemail" -and
                                        $_.Trim() -ne "Forwarded Call" -and
                                        $_.Trim() -notmatch "(.*?)'"
                                    }
                                }
                                if ($($_.To | Select-String -Pattern "(Extension [0-9]{3})").Matches.Success) {
                                    $ToExt = $($($($_.To | Select-String -Pattern "(Extension [0-9]{3})").Matches.Value).Trim() -split " ")[-1]
                                }
                                if ($($_.To | Select-String -Pattern "(^[0-9]{3}$)").Matches.Success) {
                                    $ToExt = $($($_.To | Select-String -Pattern "(^[0-9]{3}$)").Matches.Value).Trim()
                                }
                                if ($($_.To | Select-String -Pattern "(^[0-9]{10}$)").Matches.Success) {
                                    $ToExt = $($($_.To | Select-String -Pattern "(^[0-9]{10}$)").Matches.Value).Trim()
                                }
                                $ToGroupCriteria = if ($($_.To | Select-String -Pattern "Group '(.*?)'").Matches.Success) {
                                    if ($($($($_.To | Select-String -Pattern "Group '(.*?)'").Matches.Value).Trim() | Select-String -Pattern "'(.*?)'").Matches.Success) {
                                        $True
                                    }
                                }
                                $ToGroup = if ($ToGroupCriteria) {
                                    $($($($($($_.To | Select-String -Pattern "Group '(.*?)'").Matches.Value).Trim()) | Select-String -Pattern "'(.*?)'").Matches.Value -replace "'","").Trim()
                                }
                                $ToVoicemail = if ($($_.To | Select-String -Pattern "Box [0-9]{3}").Matches.Success) {
                                    $($($_.To | Select-String -Pattern "Box [0-9]{3}").Matches.Value).Split(" ")[-1]
                                }
                                $ToForwardedCallCriteria = if ($($_.To | Select-String -Pattern "Forwarded Call: $ToPhoneNumberRegex").Matches.Success) {
                                    if ($($($_.To | Select-String -Pattern "Forwarded Call: $ToPhoneNumberRegex").Matches.Value | Select-String -AllMatches "[0-9]+").Matches.Success) {
                                        $True
                                    }
                                }
                                $ToForwardedCall = if ($ToForwardedCallCriteria) {
                                    $($($_.To | Select-String -Pattern "Forwarded Call: $ToPhoneNumberRegex").Matches.Value | Select-String -AllMatches "[0-9]+").Matches.Value -join ""
                                }

                                $_ | Add-Member -MemberType NoteProperty -Name "ToPhoneNumber" -Value "$ToPhoneNumber"
                                $_ | Add-Member -MemberType NoteProperty -Name "ToName" -Value "$ToName"
                                $_ | Add-Member -MemberType NoteProperty -Name "ToExt" -Value "$ToExt"
                                $_ | Add-Member -MemberType NoteProperty -Name "ToGroup" -Value "$ToGroup"
                                $_ | Add-Member -MemberType NoteProperty -Name "ToVoicemail" -Value "$ToVoicemail"
                                $_ | Add-Member -MemberType NoteProperty -Name "ToForwardedCall" -Value "$ToForwardedCall"
                                $_                       
                            }
                        }
                        
                        $MonthNumber = $($DataSet[0].'Date/Time').Month
                        $MonthName = (Get-Culture).DateTimeFormat.GetMonthName($MonthNumber)

                        if ($FixSpreadSheet) {
                            $PathToFixedXLSX = "$UpdatedReportDirectory\Call_Activity_ORIGINAL_FIXED_$($($DataSet[0].'Date/Time').Year)_$MonthName.xlsx"
                            Export-XLSX -InputObject $DataSet -Path $PathToFixedXLSX -Force
                        }

                        New-Variable -Name "CallsFor$MonthName" -Value $(
                            New-Object PSObject -Property @{
                                Month       = $MonthName
                                DataSet     = $DataSet
                            }
                        )

                        # Begin Phase 2 #
                        $UpdatedXLSXObjectSet = $(Get-Variable -Name "CallsFor$MonthName" -ValueOnly).DataSet

                        if ($ReadilyFilterableWildCardParams) {
                            foreach ($Param in $ReadilyFilterableWildCardParams) {
                                if ($Param -eq "ToWildCard") {
                                    $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | Where-Object {$_.To -like "*$ToWildCard*"}
                                }
                                if ($Param -eq "FromWildCard") {
                                    $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | Where-Object {$_.From -like "*$FromWildCard*"}
                                }
                                if ($Param -ne "FromWildCard" -and $Param -ne "ToWildCard") {
                                    $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | Where-Object {$_.$Param -like "*$(Get-Variable -Name "$Param" -ValueOnly)*"}
                                }
                            }
                        }
                        if ($ReadilyFilterablePreciseParams) {
                            foreach ($Param in $ReadilyFilterablePreciseParams) {
                                if ($Param -eq "CallType") {
                                    $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | Where-Object {$_.'Call Type' -eq "$CallType"}
                                }
                                else {
                                    $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | Where-Object {$_.$Param -eq "$(Get-Variable -Name "$Param" -ValueOnly)"}
                                }
                            }
                        }
                        if ($ReadilyFilterableDateTimeParams) {
                            foreach ($Param in $ReadilyFilterableDateTimeParams) {
                                if ($Param -eq "CalendarDay") {
                                    $TranslatedParam = "Day"
                                }
                                if ($Param -match "Hour|Minute|Second") {
                                    $TranslatedParam = $Param
                                }
                                $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                    if ($_.'Date/Time'.$TranslatedParam -eq $(Get-Variable -Name $Param -ValueOnly)) {
                                        $_
                                    }
                                }
                            }
                        }
                        if ($TimeSpanStartHour -and $TimeSpanEndHour) {
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                if ($_.'Date/Time'.Hour -ge $TimeSpanStartHour -and $_.'Date/Time'.Hour -lt $TimeSpanEndHour) {
                                    $_
                                }
                            }
                        }
                        if ($TimeSpanStartHour -and !$TimeSpanEndHour) {
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                if ($_.'Date/Time'.Hour -ge $TimeSpanStartHour) {
                                    $_
                                }
                            }
                        }
                        if (!$TimeSpanStartHour -and $TimeSpanEndHour) {
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                if ($_.'Date/Time'.Hour -lt $TimeSpanEndHour) {
                                    $_
                                }
                            }
                        }

                        # Group By CallType, Gives Us Total Count for Incoming, Internal, and Outgoing
                        $GroupedByCallType = $UpdatedXLSXObjectSet | Group-Object -Property 'Call Type' | Select-Object Name,Count
                        # Grouped By ToPhoneNumber gives us 1000s of Entries
                        $GroupedByToPhoneNumberPrep = $UpdatedXLSXObjectSet | Group-Object -Property 'ToPhoneNumber','ToExt'
                        $GroupedByToPhoneNumberPrep2 = $GroupedByToPhoneNumberPrep | foreach {
                            $GroupNameToPhoneNumber = $($_.Name -split ", ")[0].Trim()
                            $GroupNameToExt = $($_.Name -split ", ")[-1].Trim()
                            if ($GroupNameToPhoneNumber -eq $GroupNameToExt) {
                                $_ | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value "$GroupNameToPhoneNumber"
                            }
                            if ($GroupNameToPhoneNumber -notmatch "[\w]+") {
                                $_ | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value "$GroupNameToExt"
                            }
                            $_
                        }
                        $GroupedByToPhoneNumber = $GroupedByToPhoneNumberPrep2 | Select-Object UpdatedName,Count
                        # Grouped By FromPhoneNumber gives us 1000s of Entries
                        $GroupedByFromPhoneNumberPrep = $UpdatedXLSXObjectSet | Group-Object -Property 'FromPhoneNumber','FromExt'
                        $GroupedByFromPhoneNumberPrep2 = $GroupedByFromPhoneNumberPrep | foreach {
                            $GroupNameFromPhoneNumber = $($_.Name -split ", ")[0].Trim()
                            $GroupNameFromExt = $($_.Name -split ", ")[-1].Trim()
                            if ($GroupNameFromPhoneNumber -eq $GroupNameFromExt) {
                                $_ | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value "$GroupNameFromPhoneNumber"
                            }
                            if ($GroupNameFromPhoneNumber -notmatch "[\w]+") {
                                $_ | Add-Member -MemberType NoteProperty -Name "UpdatedName" -Value "$GroupNameFromExt"
                            }
                            $_
                        }
                        $GroupedByFromPhoneNumber = $GroupedByFromPhoneNumberPrep2 | Select-Object UpdatedName,Count

                        New-Variable -Name "UpdatedCallsFor$MonthName" -Value $(
                            New-Object PSObject -Property @{
                                Month                       = $MonthName
                                UpdatedDataSet              = $UpdatedXLSXObjectSet
                                GroupedByCallType           = $GroupedByCallType
                                GroupedByToPhoneNumber      = $GroupedByToPhoneNumber
                                GroupedByFromPhoneNumber    = $GroupedByFromPhoneNumber
                                TotalCalls                  = $UpdatedXLSXObjectSet.Count
                            }
                        ) -Force


                        if ($FixSpreadSheet) {
                            # If ToPhoneNumber and FromPhoneNumber are blank, add 0000000000 so that Add-PivotTable works
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                if ($_.ToPhoneNumber -notmatch "[\w]+") {
                                    $_.ToPhoneNumber = "0000000000"
                                }
                                $_
                            }
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                if ($_.FromPhoneNumber -notmatch "[\w]+") {
                                    $_.FromPhoneNumber = "0000000000"
                                }
                                $_
                            }
                            $UpdatedXLSXObjectSet = $UpdatedXLSXObjectSet | foreach {
                                $_.PSObject.Properties.Remove('<Column 7>')
                                $_
                            }

                            $FilteredFixedSpreadSheetFileName = "FILTERED_FIXED_"+"$($($DataSet[0].'Date/Time').Year)_$MonthName"+"$ReadilyFilterableWildCardParams"+"$ReadilyFilterablePreciseParams"+"$ReadilyFilterableDateTimeParams"+"$ReportType"

                            $PathToFixedFilteredXLSX = "$UpdatedReportDirectory\Call_Activity_$FilteredFixedSpreadSheetFileName.xlsx"
                            Export-XLSX -InputObject $UpdatedXLSXObjectSet -Path $PathToFixedFilteredXLSX -Force

                            $SpecialExcelObject = New-Excel -Path $PathToFixedFilteredXLSX
                            $CurrentWorksheets = $SpecialExcelObject | Get-WorkSheet
                            $SourceWorkSheet = $($SpecialExcelObject | Get-WorkSheet)[0].Name
                            $ToPhoneNumberPTName = "PivotTable ToPhoneNumber"
                            $FromPhoneNumberPTName = "PivotTable FromPhoneNumber"
                            if ($CurrentWorksheets.Name -contains $ToPhoneNumberPTName) {
                                $ToPhoneNumberPTName = "$ToPhoneNumberPTName"+"$(Get-Date -Format hhmss)"
                            }
                            if ($CurrentWorksheets.Name -contains $FromPhoneNumberPTName) {
                                $FromPhoneNumberPTName = "$FromPhoneNumberPTName"+"$(Get-Date -Format hhmss)"
                            }

                            Add-PivotTable -PivotTableWorksheetName "PivotTable ToPhoneNumber" -WorkSheetName $SourceWorkSheet -Path $PathToFixedFilteredXLSX -PivotRows ToPhoneNumber -PivotValues ToPhoneNumber
                            Add-PivotTable -PivotTableWorksheetName "PivotTable FromPhoneNumber" -WorkSheetName $SourceWorkSheet -Path $PathToFixedFilteredXLSX -PivotRows FromPhoneNumber -PivotValues FromPhoneNumber
                        }

                        # Begin Phase 3 #
                        $ReportObject = Get-Variable -Name "UpdatedCallsFor$MonthName" -ValueOnly

                        $Header = @"
                            <style>
                            TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
                            TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
                            TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;}
                            .odd  { background-color:#ffffff; }
                            .even { background-color:#dddddd; }
                            TR:Nth-Child(Even) {Background-Color: #dddddd;}
                            TR:Hover TD {Background-Color: #C1D5F8;}
                            </style>
                            <h2>
                            $ReportType For $($ReportObject.Month)
                            </h2>
                            <h4>
                            This Report Has Been Saved To "$UpdatedReportDirectory\CallActivityReport$($ReportObject.Month).html"
                            </h4>
"@
                        
                        foreach ($ParamKVP in $AllParams) {
                            if ($ParamKVP.Key -ne "ReportDirectory" -and
                            $ParamKVP.Key -ne "ExcelSpreadSheetPaths" -and
                            $ParamKVP.Key -ne "ReportType" -and
                            $ParamKVP.Key -ne "FixSpreadsheet") {
                                $SummaryPrep = "`"$($ParamKVP.Key) = $($ParamKVP.Value)`""
                            }
                        }
                        if (!$SummaryPrep) {
                            $Summary = "`"No Filters Applied`""
                        }
                        else {
                            $Summary = $SummaryPrep -join ", and "
                        }
                        
                        $Pre = "<h3>Total Number of Calls for filter $Summary is $($($ReportObject.UpdatedDataSet).Count)</h3>"
                        $Post = "<h3>Report Run on $(Get-Date)</h3>"

                        $ReportFileName = "$($($DataSet[0].'Date/Time').Year)"+"_$($ReportObject.Month)"+"$ReadilyFilterableWildCardParams"+"$ReadilyFilterablePreciseParams"+"$ReadilyFilterableDateTimeParams"+"$ReportType"

                        if ($ReportType -eq "Call Count") {
                            $ReportObject.UpdatedDataSet | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File "$UpdatedReportDirectory\Call_Activity_Report_$ReportFileName.html"
                        }
                        if ($ReportType -eq "Call Count By Call Type") {
                            $ReportObject.GroupedByCallType | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File "$UpdatedReportDirectory\Call_Activity_Report_$ReportFileName.html"
                        }
                        if ($ReportType -eq "Call Count By ToPhoneNumber") {
                            $ReportObject.GroupedByToPhoneNumber | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File "$UpdatedReportDirectory\Call_Activity_Report_$ReportFileName.html"
                        }
                        if ($ReportType -eq "Call Count By FromPhoneNumber") {
                            $ReportObject.GroupedByFromPhoneNumber | ConvertTo-HTML -Head $Header -PreContent $Pre -PostContent $Post | Out-File "$UpdatedReportDirectory\Call_Activity_Report_$ReportFileName.html"
                        }
                        
                        Start-Process -FilePath iexplore -ArgumentList "$UpdatedReportDirectory\Call_Activity_Report_$ReportFileName.html"

                        $syncHash.CompleteFlag = "Complete"
                    })

                    # Start the Runspace in the PSInstance
                    $(Get-Variable -Name "PSInstance$i" -ValueOnly).Runspace = $(Get-Variable -Name "Runspace$i" -ValueOnly)
                    New-Variable -Name "AsyncHandle$i" -Value $($(Get-Variable -Name "PSInstance$i" -ValueOnly).BeginInvoke())

                    $RunSpaceCollection +=, $(Get-Variable -Name "Runspace$i" -ValueOnly)
                    $PSInstanceCollection +=, $(Get-Variable -Name "PSInstance$i" -ValueOnly)
                    $AsyncHandleCollection +=, $(Get-Variable -Name "AsyncHandle$i" -ValueOnly)
                }

                do {
                    Write-Host "Working..."
                    Start-Sleep -Seconds 10

                    $CheckAllSyncHashesStatus = for ($i=0; $i -lt $syncHashCollection.Count; $i++)
                    {
                        $(Get-Variable -Name "syncHash$i" -ValueOnly).CompleteFlag
                    }
                    $CheckSyncHashCollection = $($CheckAllSyncHashesStatus | Sort-Object | Get-Unique) -eq "Complete"
                } until ($CheckSyncHashCollection -or $pct -ge 100)

                # Cleanup PSInstances and Runspaces
                for ($i=0; $i -lt $PSInstanceCollection.Count; $i++)
                {
                    $PSInstanceCollection[$i].EndInvoke($AsyncHandleCollection[$i])
                    $PSInstanceCollection[$i].Dispose()
                    $RunSpaceCollection[$i].Close()
                }

                ##### END Main Body #####

            }

            ##### END MAIN Spreadsheet Parsing Function #####


            ###### BEGIN Setup Get-CallMetrics Params Using Form Inputs ######
            
            ## BEGIN Helper Functions ##
            function ConvertTo-HashtableFromPsCustomObject {
                param (
                    [Parameter(
                        Position = 0,
                        Mandatory = $true,
                        ValueFromPipeline = $true,
                        ValueFromPipelineByPropertyName = $true
                    )] [object[]]$psCustomObject
                ); 
                
                process { 
                    foreach ($myPsObject in $psCustomObject) {
                        $output = @{};
                        $myPsObject | Get-Member -MemberType *Property | % {
                            $output.($_.name) = $myPsObject.($_.name);
                        }
                        $output;
                    }
                }
            }

            ## END Helper Functions ##

            # Need to copy the spreadsheets temporarily because $listbox creates a file lock, so PSExcel's Import-XLSX won't work
            $tmpFilePaths = @()
            foreach ($SpreadsheetPath in $listboxRS) {
                $tmpFile = [IO.Path]::GetTempFileName()
                Rename-Item -Path $tmpFile -NewName ([io.path]::ChangeExtension($tmpFile, '.xlsx')) -Force
                $tmpFile = $tmpFile -replace "\.tmp",".xlsx"
                Copy-Item -Path $SpreadsheetPath -Destination $tmpFile -Force
                $tmpFilePaths += $tmpFile
            }

            #$listboxRS | Export-Clixml "C:\Users\pddomain\listboxPaths.xml"
            #$objTextBoxReportDirRS | Export-Clixml "C:\Users\pddomain\ReportDir.xml"
            #$objTextBoxCDRS | Export-Clixml "C:\Users\pddomain\CalendarDay.xml"

            $DayOfTheWeekArray = @("Sunday", "Monday","Tuesday","Wednesday","Thursday","Friday","Saturday")
            $CallTypeArray = @("Incoming","Outgoing","Internal")

            try {
                New-Variable -Name "GetCallMetricsParamsPSObject" -Value $(
                    New-Object PSObject -Property @{
                        ExcelSpreadSheetPaths   = $tmpFilePaths
                        ReportDirectory         = $objTextBoxReportDirRS
                        ReportType              = $comboBoxReportTypeRS
                        Hour                    = $objTextBoxHourRS
                        TimeSpanStartHour       = $objTextBoxTimeSpanStartRS
                        TimeSpanEndHour         = $objTextBoxTimeSpanEndRS
                        CalendarDay             = $objTextBoxCDRS
                        DayOfWeek               = $comboBoxDoWRS
                        CallType                = $comboBoxCallTypeRS
                        FromWildCard            = $objTextBoxFromRS
                        ToWildCard              = $objTextBoxToRS
                        FromPhoneNumber         = $objTextBoxFromPhoneRS
                        FromExt                 = $objTextBoxFromExtRS
                        FromName                = $objTextBoxFromNameRS
                        ToPhoneNumber           = $objTextBoxToPhoneRS
                        ToExt                   = $objTextBoxToExtRS
                        ToName                  = $objTextBoxToNameRS
                    }
                )

                # $GetCallMetricsParamsPSObject | Export-Clixml "C:\Users\pddomain\GetCallMetricsParamsPSObject.xml"

                $NullProperties = $GetCallMetricsParamsPSObject.PSObject.Properties | Where-Object {$_.Value -notmatch "[\w\W]+"}
                foreach ($Property in $NullProperties) {
                    $GetCallMetricsParamsPSObject.PSObject.Properties.Remove("$($Property.Name)")
                }

                # $NullProperties | Export-Clixml "C:\Users\pddomain\Nulproperties.xml"

                $GetCallMetricsParamsHashTable = ConvertTo-HashtableFromPsCustomObject -psCustomObject $GetCallMetricsParamsPSObject

                # $GetCallMetricsParamsHashTable | Out-File "C:\Users\pddomain\GetCallMetricsParamsHashTable.txt"

                if ($objCheckboxRS) {
                    Get-CallMetrics @GetCallMetricsParamsHashTable -FixSpreadsheet
                }
                else {
                    Get-CallMetrics @GetCallMetricsParamsHashTable
                }

                # Cleanup
                $CleanUpScriptBlock = {
                    foreach ($tempFile in $tmpFilePaths) {
                        Remove-Item -Path $tempFile -Force
                    }
                }
                Register-EngineEvent PowerShell.Exiting -Action $CleanUpScriptBlock | Out-Null
                
            }
            catch {
                $wshell = New-Object -ComObject Wscript.Shell
                $wshell.Popup("$($Error[0].Exception)",0,"Friendly Error Message",0x1) | Out-Null
            }

            $syncHash.CompleteFlag = "Complete"
        })
        $PSInstance.Runspace = $newRunspace
        $AsyncHandle = $PSInstance.BeginInvoke()

        $Jobs +=, $PSInstance

        $PBarRunspace =[runspacefactory]::CreateRunspace()
        $PBarRunspace.ApartmentState = "STA"
        $PBarRunspace.ThreadOptions = "ReuseThread"
        $PBarRunspace.Open()
        $PBarRunspace.SessionStateProxy.SetVariable("syncHash",$syncHash)

        $PBarPSInstance = [powershell]::Create()
        $PBarPSInstance.AddScript({
            Function Update-Window {
                Param (
                    $Control,
                    $Property,
                    $Method,
                    $Value,
                    [switch]$AppendContent
                )

                # This is kind of a hack, there may be a better way to do this
                if ($Method) {
                    $Control.Dispatcher.Invoke([action]{
                        $Control.$Method($Value)
                    }, "Normal")
                }

                # This updates the control based on the parameters passed to the function
                if ($Property) {
                    $Control.Dispatcher.Invoke([action]{
                        # This bit is only really meaningful for the TextBox control, which might be useful for logging progress steps
                        If ($PSBoundParameters['AppendContent']) {
                            $Control.AppendText($Value)
                        } Else {
                            $Control.$Property = $Value
                        }
                    }, "Normal")
                }
            }

            $i = 0
            do {
                Start-Sleep -Milliseconds 500

                # Calculate percentage
                $i++
                [int]$pct = ($i/125)*100
                # Update the progress bar
                Update-Window -Control $syncHash.WPFxamlProgressBar1 -Property Value -Value $pct

                if ($pct -gt 0 -and $pct -lt 20) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(360,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "       Status: Fixing SpreadSheet Data..."
                }
                if ($pct -gt 20 -and $pct -lt 40) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(330,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Exporting Fixed SpreadSheet To ReportDirectory..."
                }
                if ($pct -gt 40 -and $pct -lt 60) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(350,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value " Status: Filtering Data For Report Generation..."
                }
                if ($pct -gt 60 -and $pct -lt 100) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(400,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "         Status: Generating Report..."
                }

                if ($syncHash.CompleteFlag -eq "Complete") {
                    [int]$pct = 100
                    # Update the progress bar
                    Update-Window -Control $syncHash.WPFxamlProgressBar1 -Property Value -Value $pct
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "             Status: COMPLETE"
                }

                # Thank God for this solution to actually force UI updates in a WPF Application
                # See: http://stackoverflow.com/questions/5504244/how-do-i-refresh-visual-control-properties-textblock-text-set-inside-a-loop
                # [System.Windows.Forms.Application]::DoEvents()

            } until ($syncHash.CompleteFlag -eq "Complete" -or $pct -ge 100)

            do {
                Start-Sleep -Seconds 1
            } until ($syncHash.CompleteFlag -eq "Complete")
        })
        $PBarPSInstance.Runspace = $PBarRunspace
        $PBarAsyncHandle = $PBarPSInstance.BeginInvoke()

        $Jobs +=, $PBarPSInstance

        <#
        do {
            Start-Sleep -Milliseconds 500

            # Calculate percentage
            $i++
            [int]$pct = ($i/640)*100
            # Update the progress bar
            $($syncHash.WPFxamlProgressBar1).Value = $pct
            if ($pct -gt 0 -and $pct -lt 20) {
                #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(360,470)
                $($syncHash.WPFxamlPBarStatusLabel).Content = "Status: Fixing SpreadSheet Data..."
            }
            if ($pct -gt 20 -and $pct -lt 40) {
                #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(330,470)
                $($syncHash.WPFxamlPBarStatusLabel).Content = "Status: Exporting Fixed SpreadSheet To ReportDirectory..."
            }
            if ($pct -gt 40 -and $pct -lt 60) {
                #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(350,470)
                $($syncHash.WPFxamlPBarStatusLabel).Content = "Status: Filtering Data For Report Generation..."
            }
            if ($pct -gt 60 -and $pct -lt 100) {
                #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(400,470)
                $($syncHash.WPFxamlPBarStatusLabel).Content = "Status: Generating Report..."
            }

            if ($syncHash.CompleteFlag -eq "Complete") {
                [int]$pct = 100
                # Update the progress bar
                $($syncHash.WPFxamlProgressBar1).Value = $pct
                $($syncHash.WPFxamlPBarStatusLabel).Content = "COMPLETE"
            }

            # Thank God for this solution to actually force UI updates in a WPF Application
            # See: http://stackoverflow.com/questions/5504244/how-do-i-refresh-visual-control-properties-textblock-text-set-inside-a-loop
            # [System.Windows.Forms.Application]::DoEvents()

        } until ($syncHash.CompleteFlag -eq "Complete" -or $pct -ge 100)
        #>
    })

    ## END OK Button Functionality ##


    ## BEGIN Cancel Button Functionality ##

    #$WPFxamlCancelButton.Add_Click({[System.Environment]::Exit(0)})
    $($syncHash.WPFxamlCancelButton).Add_Click({
        $($syncHash.Window).Close()
        
        Write-Verbose 'Halt RunSpaceMgr Runspace cleanup job processing'
        $jobCleanup.Flag = $False

        Write-Verbose 'Stopping All Runspaces'
        $jobCleanup.PowerShell.Dispose()

        Stop-Process -Id $($syncHash.ParentThreadPID)
    })

    ## END Cancel Button Functionality ##

    ## BEGIN Form Keyboard Functionality ##

    # Get All KeyCode Names
    # See: https://msdn.microsoft.com/en-us/library/system.windows.forms.keys(v=vs.110).aspx
    $AllKeyCodeNames = [System.Windows.Forms.Keys].GetMembers().Name
    <#
    $KeysThatTriggerFormRefresh = $AllKeyCodeNames | Where-Object {
        $_ -like "[A-Z]" -or 
        $_ -like "D[0-9]" -or 
        $_ -eq "Back"
        $_ -eq "Delete"
        $_ -eq "Tab"
    }
    #>

    $($syncHash.Window).Add_GotFocus({
        $($syncHash.Window).PreviewKeyUp = $True
        $($syncHash.Window).Add_KeyUp({
            if ($_.KeyCode -eq "Enter") {
                $($syncHash.WPFxamlOKButton).PerformClick()
            }
            if ($_.KeyCode -eq "Escape") {
                $($syncHash.Window).Close()
            }
        })
    })
    

    ## END Form Keyboard Functionality ##

    ##### END Form Control Methods #####

    $syncHash.Window.ShowDialog()

    Start-Sleep -Seconds 2

    while ($($syncHash.Window).IsVisible) {
        Write-Verbose "Holding Pattern..."
        Start-Sleep -Seconds 5
    }
    if (!$($syncHash.Window).IsVisible) {
        Write-Verbose 'Halt RunSpaceMgr Runspace cleanup job processing'
        $jobCleanup.Flag = $False

        Write-Verbose 'Stopping All Runspaces'
        $jobCleanup.PowerShell.Dispose()

        Stop-Process -Id $($syncHash.ParentThreadPID)
    }
})
$GUIPSInstance.Runspace = $GUIRunspace
$GUIAsyncHandle = $GUIPSInstance.BeginInvoke()

##### END GUI Runspace #####

# Add the $GUIInstance Job (with its accompanying $GUIRunspace) and the $PSInstance Job (with its accompanying $newRunspace)
# To the array of jobs (i.e. $script.Jobs) that the $RunspaceMgrRunspace is handling
$script:Jobs +=, $GUIPSInstance


do {
    Start-Sleep -Seconds 1
    Write-Host "Waiting for SyncHash To Populate"
} until ($syncHash.InitialLoad -eq "Complete")

##### BEGIN Form Controls Initial Property Settings #####

# Update-Window -Control $syncHash.WPFxamlBrowseButton -Property Content -Value "Doof"

Update-Window -Control $syncHash.WPFxamlExcelSpreadSheetPathsListBox -Property AllowDrop -Value $True

##### END Form Controls Initial Property Settings #####



