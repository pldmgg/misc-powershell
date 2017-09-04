##### BEGIN Helper Functions ######

function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

[System.Collections.ArrayList]$TestIsValidIPAddressDefinitionArray = $(Get-Command Test-IsValidIPAddress).Definition -split "`n"
$TestIsValidIPAddressDefinitionArray.Insert(0, "function Test-IsValidIPAddress {")
$TestIsValidIPAddressDefinitionArray.Insert($TestIsValidIPAddressDefinitionArray.Count, "}")
$TestIsValidIPAddressFunctionAsString = $TestIsValidIPAddressDefinitionArray -join "`n"
$TestIsValidIPAddressFunctionAsScriptBlock = [scriptblock]::Create($TestIsValidIPAddressFunctionAsString)

# The below Update-Window function is capable of reaching across runspace threads to update the GUI
# Sample Usage: Update-Window -Control TextBox -property Text -value "Here's some new text!"
# Original Author: Boe Prox
Function Update-Window {
    [CmdletBinding(DefaultParameterSetName='PropertyOrMethod')]
    Param (
        [Parameter(Mandatory=$True)]
        $Control,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'PropertyOrMethod'
        )]
        $Property,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'PropertyOrMethod'
        )]
        [string]$Method,

        [Parameter(Mandatory=$False)]
        $Value,

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'CustomAction'
        )]
        [action]$Action,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'PropertyOrMethod'
        )]
        [switch]$AppendContent
    )

    if ($Action) {
        $Control.Dispatcher.Invoke($Action, "Normal")
    }

    if ($Method) {
        if ($Value) {
            $Control.Dispatcher.Invoke([action]{$Control.$Method($Value)}, "Normal")
        }
        else {
            $Control.Dispatcher.Invoke([action]{$Control.$Method()}, "Normal")
        }
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

# Below "ConvertTo" Functions from: http://www.indented.co.uk/2010/01/23/powershell-subnet-math/
[System.Collections.ArrayList]$UpdateWindowDefinitionArray = $(Get-Command Update-Window).Definition -split "`n"
$UpdateWindowDefinitionArray.Insert(0, "function Update-Window {")
$UpdateWindowDefinitionArray.Insert($UpdateWindowDefinitionArray.Count, "}")
$UpdateWindowFunctionAsString = $UpdateWindowDefinitionArray -join "`n"
$UpdateWindowFunctionAsScriptBlock = [scriptblock]::Create($UpdateWindowFunctionAsString)

function ConvertTo-Mask {
    <#
    .Synopsis
      Returns a dotted decimal subnet mask from a mask length.
    .Description
      ConvertTo-Mask returns a subnet mask in dotted decimal format from an integer value ranging 
      between 0 and 32. ConvertTo-Mask first creates a binary string from the length, converts 
      that to an unsigned 32-bit integer then calls ConvertTo-DottedDecimalIP to complete the operation.
    .Parameter MaskLength
      The number of bits which must be masked.
    #>

    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Alias("Length")]
        [ValidateRange(0, 32)]
        $MaskLength
    )
      
    Process {
        return ConvertTo-DottedDecimalIP ([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
    }
}

[System.Collections.ArrayList]$ConvertToMaskDefinitionArray = $(Get-Command ConvertTo-Mask).Definition -split "`n"
$ConvertToMaskDefinitionArray.Insert(0, "function ConvertTo-Mask {")
$ConvertToMaskDefinitionArray.Insert($ConvertToMaskDefinitionArray.Count, "}")
$ConvertToMaskFunctionAsString = $ConvertToMaskDefinitionArray -join "`n"
$ConvertToMaskFunctionAsScriptBlock = [scriptblock]::Create($ConvertToMaskFunctionAsString)

function ConvertTo-DottedDecimalIP {
    <#
    .Synopsis
      Returns a dotted decimal IP address from either an unsigned 32-bit integer or a dotted binary string.
    .Description
      ConvertTo-DottedDecimalIP uses a regular expression match on the input string to convert to an IP address.
    .Parameter IPAddress
      A string representation of an IP address from either UInt32 or dotted binary.
    #>

    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]$IPAddress
    )

    process {
        Switch -RegEx ($IPAddress) {
            "([01]{8}.){3}[01]{8}" {
                return [String]::Join('.', $( $IPAddress.Split('.') | ForEach-Object { [Convert]::ToUInt32($_, 2) } ))
            }

            "\d" {
                $IPAddress = [UInt32]$IPAddress
                $DottedIP = $(For ($i = 3; $i -gt -1; $i--) {
                    $Remainder = $IPAddress % [Math]::Pow(256, $i)
                    ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
                    $IPAddress = $Remainder
                })

                return [String]::Join('.', $DottedIP)
            }

            default {
                Write-Error "Cannot convert this format"
            }
        }
    }
}

[System.Collections.ArrayList]$ConvertToDottedDecimalIPDefinitionArray = $(Get-Command ConvertTo-DottedDecimalIP).Definition -split "`n"
$ConvertToDottedDecimalIPDefinitionArray.Insert(0, "function ConvertTo-DottedDecimalIP {")
$ConvertToDottedDecimalIPDefinitionArray.Insert($ConvertToDottedDecimalIPDefinitionArray.Count, "}")
$ConvertToDottedDecimalIPFunctionAsString = $ConvertToDottedDecimalIPDefinitionArray -join "`n"
$ConvertToDottedDecimalIPFunctionAsScriptBlock = [scriptblock]::Create($ConvertToDottedDecimalIPFunctionAsString)

function ConvertTo-DecimalIP {
    <#
    .Synopsis
      Converts a Decimal IP address into a 32-bit unsigned integer.
    .Description
      ConvertTo-DecimalIP takes a decimal IP, uses a shift-like operation on each octet and returns a single UInt32 value.
    .Parameter IPAddress
      An IP Address to convert.
    #>

    [CmdLetBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Net.IPAddress]$IPAddress
    )

    process {
    $i = 3; $DecimalIP = 0;
    $IPAddress.GetAddressBytes() | ForEach-Object { $DecimalIP += $_ * [Math]::Pow(256, $i); $i-- }

    return [UInt32]$DecimalIP
    }
}

[System.Collections.ArrayList]$ConvertToDecimalIPDefinitionArray = $(Get-Command ConvertTo-DecimalIP).Definition -split "`n"
$ConvertToDecimalIPDefinitionArray.Insert(0, "function ConvertTo-DecimalIP {")
$ConvertToDecimalIPDefinitionArray.Insert($ConvertToDecimalIPDefinitionArray.Count, "}")
$ConvertToDecimalIPFunctionAsString = $ConvertToDecimalIPDefinitionArray -join "`n"
$ConvertToDecimalIPFunctionAsScriptBlock = [scriptblock]::Create($ConvertToDecimalIPFunctionAsString)

function Get-NetworkRange {
    <#
    .Synopsis
      Generates IP addresses within the specified network.
    .Description
      Get-NetworkRange finds the network and broadcast address as decimal values then starts a 
      counter between the two, returning Net.IPAddress for each.
    .Parameter IPAddress
      Any IP address within the network range.
    .Parameter Network
      A network description in the format 1.2.3.4/24
    .Parameter SubnetMask
      The subnet mask for the network.
    #>

    [CmdLetBinding(DefaultParameterSetName = "IPAndMask")]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "IPAndMask", ValueFromPipeline = $true)]
        [Net.IPAddress]$IPAddress, 
        
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "IPAndMask")]
        [Alias("Mask")]
        $SubnetMask,
        
        [Parameter(Mandatory = $true, ParameterSetName = "CIDRNotation", ValueFromPipeline = $true)]
        [String]$CIDRNetwork
    )

    process {
        if ($SubnetMask -match [regex]'^[\d]{1,2}$') {
            $SubnetMask = ConvertTo-Mask $SubnetMask
        }

        if ($CIDRNetwork) {
            $CIDRRegex = '^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
            if ($CIDRNetwork -notmatch $CIDRRegex) {
                Write-Error "$CIDRNetwork is not in a valid format! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $Temp = $CIDRNetwork.Split("/")
            $IPAddress = $Temp[0]
            $SubnetMask = ConvertTo-Mask $Temp[1]
        }

        $DecimalIP = ConvertTo-DecimalIP $IPAddress
        $DecimalMask = ConvertTo-DecimalIP $SubnetMask

        $DecimalNetwork = $DecimalIP -band $DecimalMask
        $DecimalBroadcast = $DecimalIP -bor ((-BNot $DecimalMask) -band [UInt32]::MaxValue)

        for ($i = $($DecimalNetwork + 1); $i -lt $DecimalBroadcast; $i++) {
            ConvertTo-DottedDecimalIP $i
        }
    }
}
[System.Collections.ArrayList]$GetNetworkRangeDefinitionArray = $(Get-Command Get-NetworkRange).Definition -split "`n"
$GetNetworkRangeDefinitionArray.Insert(0, "function Get-NetworkRange {")
$GetNetworkRangeDefinitionArray.Insert($GetNetworkRangeDefinitionArray.Count, "}")
$GetNetworkRangeFunctionAsString = $GetNetworkRangeDefinitionArray -join "`n"
$GetNetworkRangeFunctionAsScriptBlock = [scriptblock]::Create($GetNetworkRangeFunctionAsString)

$ScriptBlockCollection = @($TestIsValidIPAddressFunctionAsScriptBlock,$UpdateWindowFunctionAsScriptBlock,
$ConvertToMaskFunctionAsScriptBlock,$ConvertToDottedDecimalIPFunctionAsScriptBlock,
$ConvertToDecimalIPFunctionAsScriptBlock,$GetNetworkRangeFunctionAsScriptBlock)

##### END Helper Functions #####

# Create syncHash - ALL Runspaces will reference objects contained in the syncHash as well as use it
# to pass things among them
$global:syncHash = [hashtable]::Synchronized(@{})

##### BEGIN Runspace Manager Runspace #####

$global:JobCleanup = [hashtable]::Synchronized(@{})
$global:jobs = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
#$global:jobs = [System.Collections.Concurrent.ConcurrentBag[System.Object]]::new()
$global:JobCleanup.Flag = $True

$RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
$RunspaceMgrRunspace.ApartmentState = "STA"
$RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
$RunspaceMgrRunspace.Open()

# Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
# NOTE: We're only going to collect Child Runspaces that are created if number of IPs to Check > 20
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$global:jobs)
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("synchash",$global:syncHash)
# Pass Update-Window function to Runspace
$RunspaceMgrRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)

$global:JobCleanup.PowerShell = [PowerShell]::Create().AddScript({

    ##### BEGIN Runspace Manager Runspace Helper Functions #####

    . $UpdateWindowFunctionAsScriptBlock

    ##### END Runspace Manager Runspace Helper Functions #####

    # Routine to handle completed Runspaces
    do {
        foreach($job in $jobs) {
            if ($job.AsyncHandle.IsCompleted -or $job.SyncHash.CompleteFlag -eq "Complete") {
                [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                $job.Runspace.Dispose()
                $job.PSInstance.Dispose()
                $job.AsyncHandle = $null
                $job.PSInstance = $null
            }
        }

        # Clean out unused runspace jobs
        $temphash = $jobs.clone()
        $temphash | Where {
            $_.AsyncHandle -eq $null -or $_.SyncHash.CompleteFlag -eq "Complete"
        } | foreach {
            $jobs.remove($_)
        }

        Start-Sleep -Seconds 2

        if ($syncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($synchash.IPArray.Count -ne 0 -or $synchash.IPArray -ne $null)) {
            if ($syncHash.WPFInfoDatagrid.Items.Count -ge $synchash.IPArray.Count) {
                Update-Window -Control $syncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
            }
        }
        
    } while ($global:JobCleanup.Flag)
})
# NOTE: Below code to start the Runspace Manager Runspace is moved to the scenario
# where more that 20 IPs are going to be checked. See ~line 740
# Start the RunspaceManagerRunspace
$global:JobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
$global:JobCleanup.Thread = $global:JobCleanup.PowerShell.BeginInvoke()

[System.Collections.ArrayList]$DontTouchTheseRunspaces = @()
Get-Runspace | foreach {$null = $DontTouchTheseRunspaces.Add($_)}

##### END Runspace Manager Runspace #####


##### BEGIN GUI Runspace #####

$GUIRunspace =[runspacefactory]::CreateRunspace()
$GUIRunspace.ApartmentState = "STA"
$GUIRunspace.ThreadOptions = "ReuseThread"
$GUIRunspace.Open()
$GUIRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)
$GUIRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
$GUIRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)

$GUIRunspace.SessionStateProxy.SetVariable("TestIsValidIPAddressFunctionAsScriptBlock",$TestIsValidIPAddressFunctionAsScriptBlock)
$GUIRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
$GUIRunspace.SessionStateProxy.SetVariable("ConvertToMaskFunctionAsScriptBlock",$ConvertToMaskFunctionAsScriptBlock)
$GUIRunspace.SessionStateProxy.SetVariable("ConvertToDottedDecimalIPFunctionAsScriptBlock",$ConvertToDottedDecimalIPFunctionAsScriptBlock)
$GUIRunspace.SessionStateProxy.SetVariable("ConvertToDecimalIPFunctionAsScriptBlock",$ConvertToDecimalIPFunctionAsScriptBlock)
$GUIRunspace.SessionStateProxy.SetVariable("GetNetworkRangeFunctionAsScriptBlock",$GetNetworkRangeFunctionAsScriptBlock)

$GUIPSInstance = [powershell]::Create()
$GUIPSInstance.AddScript({
    ##### BEGIN GUI Runspace Helper Functions #####

    [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
    [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Xaml')
    [void][System.Reflection.Assembly]::LoadWithPartialName('WindowsBase')

    . $TestIsValidIPAddressFunctionAsScriptBlock
    . $UpdateWindowFunctionAsScriptBlock
    . $ConvertToMaskFunctionAsScriptBlock
    . $ConvertToDottedDecimalIPFunctionAsScriptBlock
    . $ConvertToDecimalIPFunctionAsScriptBlock
    . $GetNetworkRangeFunctionAsScriptBlock

    ##### END GUI Runspace Helper Functions #####

    # Reference fo XAML DataGrid Styles:
    # https://stackoverflow.com/questions/18053281/how-to-set-datagrids-row-background-based-on-a-property-value-using-data-bindi
    # https://stackoverflow.com/questions/36485313/wpf-datagrid-cell-style-from-different-property-in-xaml
    $XAMLInput = @"
<Window x:Name="XamlMainWindow" x:Class="NoClutter_NetworkMonitorForXMLOnly.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
        xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
        xmlns:local="clr-namespace:NoClutter_NetworkMonitorForXMLOnly"
        mc:Ignorable="d"
        Title="NoClutter-NetworkMonitor" Height="525" Width="525" WindowStartupLocation="CenterScreen" SizeToContent="Height" MinHeight="600" MinWidth="625" MaxHeight="800">
    <Grid x:Name="XAMLGrid">
        <Label x:Name="SubnetsLabel" Content="Enter one or more IPs, and/or one or more Subnets separated by semicolons" HorizontalAlignment="Left" Margin="10,5,0,0" VerticalAlignment="Top"/>
        <Label x:Name="SubnetsLabelExample" Content="Example #1: 192.168.2.55; 10.0.2.3; 172.16.2.5" HorizontalAlignment="Left" Margin="10,26,0,0" VerticalAlignment="Top"/>
        <Label x:Name="SubnetsLabelExample2" Content="Example #2: 192.68.2.0/24; 10.0.1.0/30" HorizontalAlignment="Left" Margin="274,26,0,0" VerticalAlignment="Top"/>
        <TextBox x:Name="SubnetsTextBox" Margin="10,55,10,0" VerticalAlignment="Top"/>
        <Label x:Name="SubnetsLabelValidation" Content="ERROR: One or more subnets listed above are not in the correct format!" HorizontalAlignment="Left" Margin="10,73,0,0" VerticalAlignment="Top" FontSize="10" FontWeight="Bold" Visibility="Hidden"/>
        <CheckBox x:Name="FilterUnresolvableCheckBox" Content="Filter Out Unresolved FQDN" HorizontalAlignment="Right" Margin="0,79,27,0" VerticalAlignment="Top" HorizontalContentAlignment="Right" IsChecked="False"/>
        <Label x:Name="InfoLabel" Content="Info:" HorizontalAlignment="Left" Margin="10,99,0,0" VerticalAlignment="Top"/>
        <Label x:Name="InfoScanStatusLabel" Content="Currently Running Continuous Scan (45 second intervals)..." HorizontalAlignment="Left" Margin="135,101,0,0" VerticalAlignment="Top" FontSize="12" FontWeight="Bold" Visibility="Hidden"/>
        <Label x:Name="InfoPleaseWaitLabel" Content="Populating..." HorizontalAlignment="Left" Margin="481,101,0,0" VerticalAlignment="Top" FontSize="12" FontWeight="Bold" Visibility="Hidden"/>
        <DataGrid x:Name="InfoDataGrid" Margin="11,127,10,0" VerticalAlignment="Top" AlternationCount="1" HorizontalContentAlignment="Center" Padding="10,0" MinHeight="215" MaxHeight="300">
            <DataGrid.Columns>
                <DataGridTextColumn x:Name="StatusDataGridTextColumn" Header="Status" Binding="{Binding Status}" Width="*">
                    <DataGridTextColumn.CellStyle>
                        <Style TargetType="{x:Type DataGridCell}">
                            <Style.Triggers>
                                <DataTrigger Binding="{Binding Status, UpdateSourceTrigger=PropertyChanged, IsAsync=True}" Value="Red">
                                    <Setter Property="Background" Value="Red"></Setter>
                                </DataTrigger>
                                <DataTrigger Binding="{Binding Status, UpdateSourceTrigger=PropertyChanged, IsAsync=True}" Value="Green">
                                    <Setter Property="Background" Value="Green"></Setter>
                                </DataTrigger>
                            </Style.Triggers>
                        </Style>
                    </DataGridTextColumn.CellStyle>
                </DataGridTextColumn>
                <DataGridTextColumn x:Name="HostNameDataGridTextColumn" Header="HostName / IP" Binding="{Binding HostName}" Width="*"></DataGridTextColumn>
                <DataGridTextColumn x:Name="FQDNDataGridTextColumn" Header="FQDN" Binding="{Binding FQDN}" Width="*"></DataGridTextColumn>
                <DataGridTextColumn x:Name="LastCheckedDataGridTextColumn" Header="Last Checked" Binding="{Binding LastChecked}" Width="*"></DataGridTextColumn>
            </DataGrid.Columns>
        </DataGrid>
        <Button x:Name="ScanButton" Content="Single Scan" Margin="0,0,390,74.95" VerticalAlignment="Bottom" Padding="1" UseLayoutRounding="False" MinWidth="31" MinHeight="20" Width="150"/>
        <Button x:Name="ContinuousScanButton" Content="Continuous Scan" Margin="218,0,224,75" VerticalAlignment="Bottom" Padding="1" UseLayoutRounding="False" MinWidth="31" MinHeight="20" Width="150"/>
        <Button x:Name="ExportToCSVButton" Content="Export To CSV" Margin="218,0,224,36.95" VerticalAlignment="Bottom" Padding="1" UseLayoutRounding="False" MinWidth="31" MinHeight="20" Width="150"/>
        <Button x:Name="StopButton" Content="Stop" Margin="415,0,27,74.95" VerticalAlignment="Bottom" Padding="1" UseLayoutRounding="False" MinWidth="31" MinHeight="20" Width="150"/>
        <Label x:Name="StopButtonMsg" Content="Finishing items currently in pipeline..." HorizontalAlignment="Right" Margin="0,0,27,52" VerticalAlignment="Bottom" FontSize="10" Visibility="Hidden"/>
        <Label x:Name="ContinuousScanError" Content="Continuous Scan can only be used with less than 11 targets!" HorizontalAlignment="Right" Margin="0,0,164,95" VerticalAlignment="Bottom" FontSize="10" Visibility="Hidden" FontWeight="Bold"/>
    </Grid>
</Window>
"@

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # "Fix" $XAMLInput so that Windows.Markup.XamlReader doesn't choke
    if ($XAMLInput.GetType().FullName -eq "System.String") {
        $XAMLInput = $XAMLInput -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace "DataGridTextColumn Name=`".+?`"","DataGridTextColumn"
    }
    if ($XAMLInput.GetType().FullName -eq "System.Xml.XmlDocument") {
        $XAMLInput = $($XAMLInput.OuterXml | Out-String) -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace "DataGridTextColumn Name=`".+?`"","DataGridTextColumn"
    }

    [xml]$XAML = $XAMLInput

    # Read XAML
    $reader = New-Object System.Xml.XmlNodeReader $XAML

    try {
        # Adds the MainWIndow XAML Object to the $syncHash as key/value pairs
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


    # Adds the rest XAML Objects to the $syncHash as key/value pairs
    $XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % {
        $syncHash.Add("WPF$($_.Name)",$syncHash.Window.FindName($_.Name))
    }

    do {
        Start-Sleep -Seconds 1
        Write-Host "Waiting for SyncHash To Populate"
    } until ($syncHash -ne $null)

    $syncHash.XAMLInitialLoad = "Complete"
    $syncHash.ParentThreadPID = $PID


    ##### BEGIN Form Control Methods #####

    # The below is needed because the "IsChecked" property of the checkbox never gets updated.
    # Also the Add_Checked event never fires either...
    $syncHash.WPFFilterUnresolvableCheckBox.Add_Click({
        if ($syncHash.WPFFilterAlternateIsChecked) {
            $syncHash.WPFFilterAlternateIsChecked = $false
        }
        else {
            $syncHash.WPFFilterAlternateIsChecked = $true
        }
    })

    $syncHash.WPFSubnetsTextBox.Add_TextChanged({
        $IPsAndOrSubnetsAsString = $syncHash.WPFSubnetsTextBox.Text
        $IPsAndOrSubnetsArray = $($IPsAndOrSubnetsAsString -split ";").Trim() | Where-Object {$_ -match "[\w]"}

        $CIDRRegex = '^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$'
        $IPAddrRegex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        $IPAddrDashIPAddrRegex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)-(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

        foreach ($IpOrSub in $IPsAndOrSubnetsArray) {
            if (!$(Test-IsValidIPAddress $IpOrSub)) {
                if (!$($IpOrSub -match $CIDRRegex)) {
                    if (!$($IpOrSub -match $IPAddrDashIPAddrRegex)) {
                        if ($syncHash.WPFSubnetsLabelValidation.Visibility -ne "Visible") {
                            $syncHash.WPFSubnetsLabelValidation.Visibility = "Visible"
                        }
                    }
                    else {
                        if ($syncHash.WPFSubnetsLabelValidation.Visibility -eq "Visible") {
                            $syncHash.WPFSubnetsLabelValidation.Visibility = "Hidden"
                        }
                    }
                }
                else {
                    if ($syncHash.WPFSubnetsLabelValidation.Visibility -eq "Visible") {
                        $syncHash.WPFSubnetsLabelValidation.Visibility = "Hidden"
                    }
                }
            }
            else {
                if ($syncHash.WPFSubnetsLabelValidation.Visibility -eq "Visible") {
                    $syncHash.WPFSubnetsLabelValidation.Visibility = "Hidden"
                }
            }
        }

        [System.Collections.ArrayList]$IndividualIPs = @()
        [System.Collections.ArrayList]$Subnets = @()
        foreach ($IPString in $IPsAndOrSubnetsArray) {
            if ($IPString -match "/") {
                $null = $Subnets.Add($IPString)
            }
            if ($IPString -match $IPAddrDashIPAddrRegex) {
                $RangeStart = $($($IPString -split "-")[0] -split "\.")[-1]
                $RangeEnd = $($($IPString -split "-")[-1] -split "\.")[-1]
                $IPFirst3Octets = $($IPString -split "\.")[0..2] -join "."
                $IndivIPArray = ($RangeStart..$RangeEnd) | foreach {"$IPFirst3Octets`.$_"}
                foreach ($IndivIP in $IndivIPArray) {
                    $null = $IndividualIPs.Add($IndivIP)
                }
            }
            else {
                $null = $IndividualIPs.Add($IPString)
            }
        }

        $syncHash.IPArray = $IndividualIPs
        $syncHash.SubnetsArray = $Subnets
    })

    $syncHash.WPFScanButton.Add_Click({
        if ($syncHash.WPFContinuousScanError.Visibility -eq "Visible") {
            $syncHash.WPFContinuousScanError.Visibility = "Hidden"
        }
        
        [System.Collections.ArrayList]$ContinueChecks = @()
        if ($syncHash.WPFSubnetsLabelValidation.Visibility -eq "Visible") {
            $null = $ContinueChecks.Add("False")
        }
        else {
            $null = $ContinueChecks.Add("True")
        }
        if ($ContinueChecks -contains "False") {
            $Continue = $false
        }
        else {
            $Continue = $true
        }

        if ($Continue) {
            $syncHash.Stop = $false
            $synchash.WPFInfoDataGrid.Items.Clear()
            $synchash.WPFInfoDataGrid.Items.Refresh()
            $syncHash.WPFInfoPleaseWaitLabel.Visibility = "Visible"

            $SingleScanRunspace =[runspacefactory]::CreateRunspace()
            $SingleScanRunspace.ApartmentState = "STA"
            $SingleScanRunspace.ThreadOptions = "ReuseThread"
            $SingleScanRunspace.Open()
            $SingleScanRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)
            $SingleScanRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
            $SingleScanRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)

            $SingleScanRunspace.SessionStateProxy.SetVariable("TestIsValidIPAddressFunctionAsScriptBlock",$TestIsValidIPAddressFunctionAsScriptBlock)
            $SingleScanRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
            $SingleScanRunspace.SessionStateProxy.SetVariable("ConvertToMaskFunctionAsScriptBlock",$ConvertToMaskFunctionAsScriptBlock)
            $SingleScanRunspace.SessionStateProxy.SetVariable("ConvertToDottedDecimalIPFunctionAsScriptBlock",$ConvertToDottedDecimalIPFunctionAsScriptBlock)
            $SingleScanRunspace.SessionStateProxy.SetVariable("ConvertToDecimalIPFunctionAsScriptBlock",$ConvertToDecimalIPFunctionAsScriptBlock)
            $SingleScanRunspace.SessionStateProxy.SetVariable("GetNetworkRangeFunctionAsScriptBlock",$GetNetworkRangeFunctionAsScriptBlock)

            $SingleScanPSInstance = [powershell]::Create()
            $SingleScanPSInstance.AddScript({

                ##### BEGIN Single Scan Runspace Helper Functions #####

                . $TestIsValidIPAddressFunctionAsScriptBlock
                . $UpdateWindowFunctionAsScriptBlock
                . $ConvertToMaskFunctionAsScriptBlock
                . $ConvertToDottedDecimalIPFunctionAsScriptBlock
                . $ConvertToDecimalIPFunctionAsScriptBlock
                . $GetNetworkRangeFunctionAsScriptBlock

                ##### END Single Scan Runspace Helper Functions #####

                foreach ($SubnetRange in $syncHash.SubnetsArray) {
                    $IPAddressesToScan = Get-NetworkRange -CIDRNetwork $SubnetRange
                    foreach ($IPAddr in $IPAddressesToScan) {
                        if ($syncHash.IPArray -notcontains $IPAddr) {
                            $null = $syncHash.IPArray.Add($IPAddr)
                        }
                    }
                }

                $syncHash.IPArray = $syncHash.IPArray | foreach {if ($_ -notmatch "/") {$_}}

                ### If we have a lot of IPs to test, create more Runspaces
                if ($syncHash.IPArray.Count -gt 20) {
                    $LoopBreakIterationNumber = 20
                    $NumberOfIterations = [int][Math]::Ceiling($($syncHash.IPArray.Count / $LoopBreakIterationNumber))
                    $Remainder = $syncHash.IPArray.Count % $LoopBreakIterationNumber

                    for ($i=0; $i -lt $NumberOfIterations; $i++) {
                        if ($syncHash.Stop -eq $true) {
                            break
                        }

                        Write-Host "For Loop iteration is $i"
                        Write-Host "For Loop NumberOfIterations-1 is $($NumberOfIterations-1)"
                        Write-Host "For Loop Remainder is $Remainder"
                        $CreateRunspaceLoopStartingPoint = $i * $LoopBreakIterationNumber
                        if ($i -eq $($NumberOfIterations-1)) {
                            Write-Host "Changing LoopBreakIterationNumber $LoopBreakIterationNumber to Remainder $Remainder"
                            $script:LoopBreakIterationNumber = $Remainder
                        }
                        $CreateRunspaceLoopEndingPoint = $CreateRunspaceLoopStartingPoint + $LoopBreakIterationNumber
                        Write-Host "For Loop LoopBreakIterationNumber is $LoopBreakIterationNumber"

                        Write-Host "CreateRunspaceLoopEndingPoint is $CreateRunspaceLoopEndingPoint"
                        Write-Host "Starting chunk of $LoopBreakIterationNumber..."

                        $IPChunk = $syncHash.IPArray[$CreateRunspaceLoopStartingPoint..$CreateRunspaceLoopEndingPoint]

                        # Create Runspace for the Chunk
                        New-Variable -Name "syncHashRSLoop$i" -Value $([hashtable]::Synchronized(@{}))

                        New-Variable -Name "RSLoopRunspace$i" -Value $([runspacefactory]::CreateRunspace())
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).ApartmentState = "STA"
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).ThreadOptions = "ReuseThread"
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).Open()
                        # Pass $global:syncHash to Runspace (which is actually refered to as just $syncHash because we're already in a Runspace)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("syncHash",$syncHash)
                        # Pass loop iteration indicator to Runspace
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("iteration",$i)
                        # Pass syncHashRSLoop$i to the Runspace
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("syncHashRSLoop",$(Get-Variable -Name "syncHashRSLoop$i" -ValueOnly))
                        # Pass $global:jobs to Runspace 
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("jobs",$global:jobs)
                        # Pass $IPChunk to Runspace 
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("IPChunk",$IPChunk)

                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("TestIsValidIPAddressFunctionAsScriptBlock",$TestIsValidIPAddressFunctionAsScriptBlock)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("ConvertToMaskFunctionAsScriptBlock",$ConvertToMaskFunctionAsScriptBlock)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("ConvertToDottedDecimalIPFunctionAsScriptBlock",$ConvertToDottedDecimalIPFunctionAsScriptBlock)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("ConvertToDecimalIPFunctionAsScriptBlock",$ConvertToDecimalIPFunctionAsScriptBlock)
                        $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly).SessionStateProxy.SetVariable("GetNetworkRangeFunctionAsScriptBlock",$GetNetworkRangeFunctionAsScriptBlock)

                        New-Variable -Name "RSLoopPSInstance$i" -Value $([System.Management.Automation.PowerShell]::Create())
                        $(Get-Variable -Name "RSLoopPSInstance$i" -ValueOnly).AddScript({
                            ## BEGIN Main Code to run in Runspace ##

                            $syncHashRSLoop.CompleteFlag = "Working"

                            ##### BEGIN Runspace Loop Helper Functions #####

                            . $TestIsValidIPAddressFunctionAsScriptBlock
                            . $UpdateWindowFunctionAsScriptBlock
                            . $ConvertToMaskFunctionAsScriptBlock
                            . $ConvertToDottedDecimalIPFunctionAsScriptBlock
                            . $ConvertToDecimalIPFunctionAsScriptBlock
                            . $GetNetworkRangeFunctionAsScriptBlock

                            ##### END Runspace Loop Helper Functions #####

                            foreach ($IndividualIP in $IPChunk) {
                                if ($syncHash.Stop -eq $true) {
                                    break
                                }

                                try {
                                    $FQDN = $(Resolve-DNSName -Name $IndividualIP).NameHost
                                }
                                catch {
                                    Write-Verbose "Unable to resolve FQDN via DNS..."
                                }
                                if (!$FQDN) {
                                    if ($syncHash.WPFFilterAlternateIsChecked) {
                                        continue
                                    }
                                    $FQDN = "Unable to Resolve"
                                }

                                if (Test-Connection -Computer $IndividualIP -Count 1 -Quiet) {
                                    $Status = "Green"
                                }
                                else {
                                    $Status = "Red"
                                }

                                $LastChecked = Get-Date -Format "MM/dd/yy hh:mm:ss"

                                [System.Windows.RoutedEventHandler]$CheckNowEvent = {
                                    param ($sender,$e)
                                    $HostNameValueOfRowInWhichCheckNowButtonWasClicked = $synchash.WPFInfoDataGrid.SelectedCells[1].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[1].Item).Text
                                    
                                    if (Test-Connection -Computer $HostNameValueOfRowInWhichCheckNowButtonWasClicked -Count 1 -Quiet) {
                                        $Status = "Green"
                                    }
                                    else {
                                        $Status = "Red"
                                    }

                                    $LastChecked = Get-Date -Format "MM/dd/yy hh:mm:ss"

                                    # Below Text Change Solution from: https://stackoverflow.com/questions/7902826/delete-selected-cells-content-in-wpf-datagrid?rq=1
                                    $synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Text = $Status
                                    $synchash.WPFInfoDataGrid.SelectedCells[3].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[3].Item).Text = $LastChecked

                                    # Below Color Solution from: https://stackoverflow.com/questions/16167755/c-sharp-wpf-change-datagrid-cell-background-after-celleditending-event
                                    $ColorBrush = [System.Windows.Media.SolidColorBrush]::new()
                                    $ColorBrush.Color = $Status
                                    $([System.Windows.Controls.DataGridCell]$synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Parent).Background = $ColorBrush
                                }

                                # From: https://stackoverflow.com/questions/42288974/add-click-event-to-wpf-datagrid-button-column-in-powershell
                                $buttonFactory = New-Object System.Windows.FrameworkElementFactory([System.Windows.Controls.Button])
                                $buttonFactory.SetValue([System.Windows.Controls.Button]::ContentProperty, "Launch")
                                $buttonFactory.AddHandler([System.Windows.Controls.Button]::ClickEvent,$CheckNowEvent)
                                $dataTemplate = New-Object System.Windows.DataTemplate
                                $dataTemplate.VisualTree = $buttonFactory

                                $NewRow = [pscustomobject]@{
                                    Status          = $Status
                                    HostName        = $IndividualIP
                                    FQDN            = $FQDN
                                    LastChecked     = $LastChecked
                                    CheckNow        = $dataTemplate
                                }

                                if ($syncHash.Stop -eq $false) {
                                    Update-Window -Control $syncHash.WPFInfoDataGrid -Method AddChild -Value $NewRow
                                }
                            }

                            $syncHashRSLoop.CompleteFlag = "Complete"

                            ## END Main Code to run in Runspace ##
                        })

                        # Start the Runspace in the PSInstance...
                        $(Get-Variable -Name "RSLoopPSInstance$i" -ValueOnly).Runspace = $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly)

                        # For PSDataCollection below see https://learn-powershell.net/2016/02/14/another-way-to-get-output-from-a-powershell-runspace/
                        #$RunspaceDataCollection = New-Object 'System.Management.Automation.PSDataCollection[psobject]'                
                        #New-Variable -Name "AsyncHandle$i" -Value $($(Get-Variable -Name "PSInstance$i" -ValueOnly).BeginInvoke($RunspaceDataCollection,$RunspaceDataCollection))
                        New-Variable -Name "RSLoopAsyncHandle$i" -Value $($(Get-Variable -Name "RSLoopPSInstance$i" -ValueOnly).BeginInvoke())

                        # IMPORTANT NOTE: The values in the below PSInstance and Runspace properties will disappear
                        # once the RunspaceManagerRunspace Closes and Disposes of them. AsyncHandle will still be there though.
                        # NOTE, however, that the corresponding System.Collections.Arraylist will still have all of the info.
                        New-Variable -Name "JobInfo$i" -Value $(
                            [pscustomobject][ordered]@{
                                PSInstance      = $(Get-Variable -Name "RSLoopPSInstance$i" -ValueOnly)
                                Runspace        = $(Get-Variable -Name "RSLoopRunspace$i" -ValueOnly)
                                AsyncHandle     = $(Get-Variable -Name "RSLoopAsyncHandle$i" -ValueOnly)
                                SyncHash        = $(Get-Variable -Name "syncHashRSLoop$i" -ValueOnly)
                            }
                        ) -Force

                        # Add to $global:jobs so that the Runspace Manager Runspace can clean up...
                        $global:jobs.Add($(Get-Variable -Name "JobInfo$i" -ValueOnly))
                    }
                }
                else {
                    foreach ($IndividualIP in $syncHash.IPArray) {
                        if ($syncHash.Stop -eq $true) {
                            break
                        }
                        
                        try {
                            $FQDN = $(Resolve-DNSName -Name $IndividualIP).NameHost
                        }
                        catch {
                            Write-Verbose "Unable to resolve FQDN via DNS..."
                        }
                        if (!$FQDN) {
                            if ($syncHash.WPFFilterAlternateIsChecked) {
                                continue
                            }
                            $FQDN = "Unable to Resolve"
                        }

                        if (Test-Connection -Computer $IndividualIP -Count 1 -Quiet) {
                            $Status = "Green"
                        }
                        else {
                            $Status = "Red"
                        }

                        $LastChecked = Get-Date -Format "MM/dd/yy hh:mm:ss"

                        [System.Windows.RoutedEventHandler]$CheckNowEvent = {
                            param ($sender,$e)
                            $HostNameValueOfRowInWhichCheckNowButtonWasClicked = $synchash.WPFInfoDataGrid.SelectedCells[1].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[1].Item).Text
                            
                            if (Test-Connection -Computer $HostNameValueOfRowInWhichCheckNowButtonWasClicked -Count 1 -Quiet) {
                                $Status = "Green"
                            }
                            else {
                                $Status = "Red"
                            }

                            $LastChecked = Get-Date -Format "MM/dd/yy hh:mm:ss"

                            # Below Text Change Solution from: https://stackoverflow.com/questions/7902826/delete-selected-cells-content-in-wpf-datagrid?rq=1
                            $synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Text = $Status
                            $synchash.WPFInfoDataGrid.SelectedCells[3].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[3].Item).Text = $LastChecked

                            # Below Color Solution from: https://stackoverflow.com/questions/16167755/c-sharp-wpf-change-datagrid-cell-background-after-celleditending-event
                            $ColorBrush = [System.Windows.Media.SolidColorBrush]::new()
                            $ColorBrush.Color = $Status
                            $([System.Windows.Controls.DataGridCell]$synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Parent).Background = $ColorBrush
                        }

                        # From: https://stackoverflow.com/questions/42288974/add-click-event-to-wpf-datagrid-button-column-in-powershell
                        $buttonFactory = New-Object System.Windows.FrameworkElementFactory([System.Windows.Controls.Button])
                        $buttonFactory.SetValue([System.Windows.Controls.Button]::ContentProperty, "Launch")
                        $buttonFactory.AddHandler([System.Windows.Controls.Button]::ClickEvent,$CheckNowEvent)
                        $dataTemplate = New-Object System.Windows.DataTemplate
                        $dataTemplate.VisualTree = $buttonFactory

                        $NewRow = [pscustomobject]@{
                            Status          = $Status
                            HostName        = $IndividualIP
                            FQDN            = $FQDN
                            LastChecked     = $LastChecked
                            CheckNow        = $dataTemplate
                        }

                        Update-Window -Control $syncHash.WPFInfoDataGrid -Method AddChild -Value $NewRow
                    }

                    Update-Window -Control $syncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                }
            })

            $SingleScanPSInstance.Runspace = $SingleScanRunspace
            $SingleScanAsyncHandle = $SingleScanPSInstance.BeginInvoke()

            New-Variable -Name "JobInfoSS" -Value $(
                [pscustomobject][ordered]@{
                    PSInstance      = $SingleScanPSInstance
                    Runspace        = $SingleScanRunspace
                    AsyncHandle     = $SingleScanAsyncHandle
                }
            ) -Force

            # Add to $global:jobs so that the Runspace Manager Runspace can clean up...
            $global:jobs.Add($(Get-Variable -Name "JobInfoSS" -ValueOnly))
        }
    })

    $syncHash.WPFContinuousScanButton.Add_Click({
        . $TestIsValidIPAddressFunctionAsScriptBlock
        . $UpdateWindowFunctionAsScriptBlock
        . $ConvertToMaskFunctionAsScriptBlock
        . $ConvertToDottedDecimalIPFunctionAsScriptBlock
        . $ConvertToDecimalIPFunctionAsScriptBlock
        . $GetNetworkRangeFunctionAsScriptBlock
        
        if ($syncHash.SubnetsArray.Count -gt 0) {
            foreach ($SubnetRange in $syncHash.SubnetsArray) {
                $IPAddressesToScan = Get-NetworkRange -CIDRNetwork $SubnetRange
                foreach ($IPAddr in $IPAddressesToScan) {
                    if ($syncHash.IPArray -notcontains $IPAddr) {
                        $null = $syncHash.IPArray.Add($IPAddr)
                    }
                }
            }
        }

        [System.Collections.ArrayList]$ContinueChecks = @()
        if ($syncHash.IPArray.Count -gt 10) {
            $syncHash.WPFContinuousScanError.Visibility = "Visible"
            $null = $ContinueChecks.Add("False")
        }
        if ($syncHash.IPArray.Count -le 10) {
            if ($syncHash.WPFContinuousScanError.Visibility -eq "Visible") {
                $syncHash.WPFContinuousScanError.Visibility = "Hidden"
            }
            $null = $ContinueChecks.Add("True")
        }
        if ($syncHash.WPFSubnetsLabelValidation.Visibility -eq "Visible") {
            $null = $ContinueChecks.Add("False")
        }
        else {
            $null = $ContinueChecks.Add("True")
        }
        if ($ContinueChecks -contains "False") {
            $Continue = $false
        }
        else {
            $Continue = $true
        }

        if ($Continue) {
            $syncHash.Stop = $false

            if ($syncHash.WPFInfoScanStatusLabel.Visibility -ne "Visible") {
                $syncHash.WPFInfoScanStatusLabel.Visibility = "Visible"
            }

            $ContinuousScanRunspace =[runspacefactory]::CreateRunspace()
            $ContinuousScanRunspace.ApartmentState = "STA"
            $ContinuousScanRunspace.ThreadOptions = "ReuseThread"
            $ContinuousScanRunspace.Open()
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)

            $ContinuousScanRunspace.SessionStateProxy.SetVariable("TestIsValidIPAddressFunctionAsScriptBlock",$TestIsValidIPAddressFunctionAsScriptBlock)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("ConvertToMaskFunctionAsScriptBlock",$ConvertToMaskFunctionAsScriptBlock)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("ConvertToDottedDecimalIPFunctionAsScriptBlock",$ConvertToDottedDecimalIPFunctionAsScriptBlock)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("ConvertToDecimalIPFunctionAsScriptBlock",$ConvertToDecimalIPFunctionAsScriptBlock)
            $ContinuousScanRunspace.SessionStateProxy.SetVariable("GetNetworkRangeFunctionAsScriptBlock",$GetNetworkRangeFunctionAsScriptBlock)

            $ContinuousScanPSInstance = [powershell]::Create()
            $ContinuousScanPSInstance.AddScript({
                ##### BEGIN Continuous Scan Helper Functions ######
                
                . $TestIsValidIPAddressFunctionAsScriptBlock
                . $UpdateWindowFunctionAsScriptBlock
                . $ConvertToMaskFunctionAsScriptBlock
                . $ConvertToDottedDecimalIPFunctionAsScriptBlock
                . $ConvertToDecimalIPFunctionAsScriptBlock
                . $GetNetworkRangeFunctionAsScriptBlock

                ##### END Continuous Scan Helper Functions ######

                while ($syncHash.Stop -eq $false) {
                    # From: https://stackoverflow.com/questions/728432/how-to-programmatically-click-a-button-in-wpf
                    $ButtonClickEvent = [System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)
                    #$syncHash.WPFScanButton.RaiseEvent($ButtonClickEvent)

                    Update-Window -Control $syncHash.WPFScanButton -Method RaiseEvent -Value $ButtonClickEvent

                    #Invoke-Command -ScriptBlock $ScanButtonScriptBlock
                    Start-Sleep -Seconds 45
                }
            })

            $ContinuousScanPSInstance.Runspace = $ContinuousScanRunspace
            $ContinuousScanAsyncHandle = $ContinuousScanPSInstance.BeginInvoke()

            New-Variable -Name "JobInfoCS" -Value $(
                [pscustomobject][ordered]@{
                    PSInstance      = $ContinuousScanPSInstance
                    Runspace        = $ContinuousScanRunspace
                    AsyncHandle     = $ContinuousScanAsyncHandle
                }
            ) -Force

            # Add to $global:jobs so that the Runspace Manager Runspace can clean up...
            $global:jobs.Add($(Get-Variable -Name "JobInfoCS" -ValueOnly))
        }
    })

    $syncHash.WPFStopButton.Add_Click({
        $syncHash.Stop = $true
        $syncHash.WPFInfoScanStatusLabel.Visibility = "Hidden"
        $syncHash.WPFInfoPleaseWaitLabel.Visibility = "Hidden"
        $syncHash.WPFStopButtonMsg.Visibility = "Visible"

        $StopButtonRunspace =[runspacefactory]::CreateRunspace()
        $StopButtonRunspace.ApartmentState = "STA"
        $StopButtonRunspace.ThreadOptions = "ReuseThread"
        $StopButtonRunspace.Open()
        $StopButtonRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)
        $StopButtonRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
        $StopButtonRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)

        $StopButtonRunspace.SessionStateProxy.SetVariable("TestIsValidIPAddressFunctionAsScriptBlock",$TestIsValidIPAddressFunctionAsScriptBlock)
        $StopButtonRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
        $StopButtonRunspace.SessionStateProxy.SetVariable("ConvertToMaskFunctionAsScriptBlock",$ConvertToMaskFunctionAsScriptBlock)
        $StopButtonRunspace.SessionStateProxy.SetVariable("ConvertToDottedDecimalIPFunctionAsScriptBlock",$ConvertToDottedDecimalIPFunctionAsScriptBlock)
        $StopButtonRunspace.SessionStateProxy.SetVariable("ConvertToDecimalIPFunctionAsScriptBlock",$ConvertToDecimalIPFunctionAsScriptBlock)
        $StopButtonRunspace.SessionStateProxy.SetVariable("GetNetworkRangeFunctionAsScriptBlock",$GetNetworkRangeFunctionAsScriptBlock)

        $StopButtonPSInstance = [powershell]::Create()
        $StopButtonPSInstance.AddScript({
            ##### BEGIN StopButton Runspace Helper Functions #####

            . $TestIsValidIPAddressFunctionAsScriptBlock
            . $UpdateWindowFunctionAsScriptBlock
            . $ConvertToMaskFunctionAsScriptBlock
            . $ConvertToDottedDecimalIPFunctionAsScriptBlock
            . $ConvertToDecimalIPFunctionAsScriptBlock
            . $GetNetworkRangeFunctionAsScriptBlock

            ##### END StopButton Runspace Helper Functions #####

            $Monitor = $true
            while ($Monitor) {
                if ($syncHash.WPFStopButtonMsg.Visibility -eq "Visible") {
                    Start-Sleep -Seconds 10
                    Update-Window -Control $syncHash.WPFStopButtonMsg -Property Visibility -Value "Hidden"
                    $Monitor = $false
                }
            }
        })

        $StopButtonPSInstance.Runspace = $StopButtonRunspace
        $StopButtonAsyncHandle = $StopButtonPSInstance.BeginInvoke()

        New-Variable -Name "JobInfoStop" -Value $(
            [pscustomobject][ordered]@{
                PSInstance      = $StopButtonPSInstance
                Runspace        = $StopButtonRunspace
                AsyncHandle     = $StopButtonAsyncHandle
            }
        ) -Force

        # Add to $global:jobs so that the Runspace Manager Runspace can clean up...
        $global:jobs.Add($(Get-Variable -Name "JobInfoStop" -ValueOnly))
    })

    $syncHash.WPFExportToCSVButton.Add_Click({
        $syncHash.Stop = $true

        $syncHash.WPFInfoScanStatusLabel.Visibility = "Hidden"
        $syncHash.WPFInfoPleaseWaitLabel.Visibility = "Hidden"

        $syncHash.WPFInfoDataGrid.Items | Export-Csv -Path "$HOME\Downloads\DataGrid.csv"
    })

    [System.Windows.RoutedEventHandler]$CheckNowEvent = {
        param ($sender,$e)
        $HostNameValueOfRowInWhichCheckNowButtonWasClicked = $synchash.WPFInfoDataGrid.SelectedCells[1].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[1].Item).Text

        if (Test-Connection -Computer $HostNameValueOfRowInWhichCheckNowButtonWasClicked -Count 1 -Quiet) {
            $Status = "Green"
        }
        else {
            $Status = "Red"
        }

        $LastChecked = Get-Date -Format "MM/dd/yy hh:mm:ss"

        # Below Text Change Solution from: https://stackoverflow.com/questions/7902826/delete-selected-cells-content-in-wpf-datagrid?rq=1
        $synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Text = $Status
        $synchash.WPFInfoDataGrid.SelectedCells[3].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[3].Item).Text = $LastChecked

        # Below Color Solution from: https://stackoverflow.com/questions/16167755/c-sharp-wpf-change-datagrid-cell-background-after-celleditending-event
        $ColorBrush = [System.Windows.Media.SolidColorBrush]::new()
        $ColorBrush.Color = $Status
        $([System.Windows.Controls.DataGridCell]$synchash.WPFInfoDataGrid.SelectedCells[0].Column.GetCellContent($synchash.WPFInfoDataGrid.SelectedCells[0].Item).Parent).Background = $ColorBrush
    }
    $buttonColumn = New-Object System.Windows.Controls.DataGridTemplateColumn
    $buttonFactory = New-Object System.Windows.FrameworkElementFactory([System.Windows.Controls.Button])
    $buttonFactory.SetValue([System.Windows.Controls.Button]::ContentProperty, "CheckNow")
    $buttonFactory.AddHandler([System.Windows.Controls.Button]::ClickEvent,$CheckNowEvent)
    $dataTemplate = New-Object System.Windows.DataTemplate
    $dataTemplate.VisualTree = $buttonFactory
    $buttonColumn.Header = "CheckNow"
    $buttonColumn.CellTemplate = $dataTemplate
    $syncHash.WPFInfoDatagrid.Columns.Add($buttonColumn)


    ##### END Form Control Methods #####

    $syncHash.Window.ShowDialog()
})

$GUIPSInstance.Runspace = $GUIRunspace
$GUIAsyncHandle = $GUIPSInstance.BeginInvoke()
$null = $DontTouchTheseRunspaces.Add($(Get-Runspace)[-1])

##### END GUI Runspace 






















# SIG # Begin signature block
# MIIMLAYJKoZIhvcNAQcCoIIMHTCCDBkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgTUP2jBxrO9VTGrobFWdbDdF
# 39WgggmhMIID/jCCAuagAwIBAgITawAAAAQpgJFit9ZYVQAAAAAABDANBgkqhkiG
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSC78yV0IJT
# R4vImbVF4AA18CZdsDANBgkqhkiG9w0BAQEFAASCAQBdb1JtB1eisiYegp77McB4
# O7bK69Te8Tp+AhcpR36uwwzvaOC7UKRjrVAzmI95qle/RWkOiV1nduAN3ApBtZ7z
# sckclXqfRm3jJvi6GiwbrD9c5nvdWJwveJYsOC0OjFeg5/vcBCEOLUJAleHDycDo
# LV9QxGkFJiqgShRD+RDz3kBXZRiX3Uk3YEuETzVE5WRZ3f9z/1ENMVwVMHP38/cN
# 9U1yjYNSxE9W4QgEJEd/KaJnX0QESbZFL1rwibZJMq6j+QW19LKF0ciG+ZpkVaU2
# Zw0ocvQquC7jcvaA9YxN5/KWMiJTKTNwQbN0W80T5F8aSZwVnLLFtqnW+1ThvJlc
# SIG # End signature block
