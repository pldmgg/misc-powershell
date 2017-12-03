##### BEGIN Helper Functions ######

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

# Prep the Update-Window function to be used WITHIN a Runspace
[System.Collections.ArrayList]$UpdateWindowDefinitionArray = $(Get-Command Update-Window).Definition -split "`n"
$UpdateWindowDefinitionArray.Insert(0, "function Update-Window {")
$UpdateWindowDefinitionArray.Insert($UpdateWindowDefinitionArray.Count, "}")
$UpdateWindowFunctionAsString = $UpdateWindowDefinitionArray -join "`n"
$UpdateWindowFunctionAsScriptBlock = [scriptblock]::Create($UpdateWindowFunctionAsString)

##### END Helper Functions #####


##### BEGIN Global SyncHash Creation #####

# Create syncHash - ALL Runspaces will reference objects contained in the syncHash as well as use it
# to pass things among them
$global:syncHash = [hashtable]::Synchronized(@{})

##### END Global SyncHash Creation #####


##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

$global:JobCleanup = [hashtable]::Synchronized(@{})
$global:jobs = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
#$global:jobs = [System.Collections.Concurrent.ConcurrentBag[System.Object]]::new()
$global:JobCleanup.Flag = $True

$RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
$RunspaceMgrRunspace.ApartmentState = "STA"
$RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
$RunspaceMgrRunspace.Open()

# Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
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

        # Optional -
        # For realtime updates to the GUI depending on changes in data within the $global:syncHash, use
        # a something like the following (replace with $syncHash properties germane to your project)
        <#
        if ($syncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($synchash.IPArray.Count -ne 0 -or $synchash.IPArray -ne $null)) {
            if ($syncHash.WPFInfoDatagrid.Items.Count -ge $synchash.IPArray.Count) {
                Update-Window -Control $syncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
            }
        }
        #>
        
    } while ($global:JobCleanup.Flag)
})

# Start the RunspaceManagerRunspace
$global:JobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
$global:JobCleanup.Thread = $global:JobCleanup.PowerShell.BeginInvoke()

##### END Runspace Manager Runspace #####


##### BEGIN GUI Runspace #####

$GUIRunspace =[runspacefactory]::CreateRunspace()
$GUIRunspace.ApartmentState = "STA"
$GUIRunspace.ThreadOptions = "ReuseThread"
$GUIRunspace.Open()

# Pass the $global:syncHash to the GUI Runspace so it read/write properties to it
$GUIRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)

# Pass $global:JobCleanup and $global:jobs to the GUI Runspace so that the Runspace Manager Runspace can manage it
$GUIRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
$GUIRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)

# Pass any helper functions to the GUI Runspace
$GUIRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)

$GUIPSInstance = [powershell]::Create()

# Define the main PowerShell Script that will define the GUI look/feel as well as overall functionality
$GUIPSInstance.AddScript({
    ##### BEGIN Load Required WPF Assemblies #####

    [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationFramework')
    [void][System.Reflection.Assembly]::LoadWithPartialName('PresentationCore')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Xaml')
    [void][System.Reflection.Assembly]::LoadWithPartialName('WindowsBase')

    ##### END Load Required WPF Assemblies #####


    ##### BEGIN GUI Runspace Helper Functions #####

    # Dot source any helper functions within the GUI Runspace so that they become available in that context
    . $UpdateWindowFunctionAsScriptBlock

    ##### END GUI Runspace Helper Functions #####


    ##### BEGIN Use XAML to Create the GUI #####
    # The below is just an example of a GUI's look/feel as defined by XAML. Change as needed.

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

    ##### END Use XAML to Create the GUI #####


    ##### BEGIN Slice Up the XAML Into Properties That We Can Reference in the $global:syncHash #####

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
        Write-Error $_
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

    ##### END Slice Up the XAML Into Properties That We Can Reference in the $global:syncHash #####


    ##### BEGIN WPF Form Controls #####

    # This is where you assign functionality to all of the elements on your WPF Form
    # The below is just an example of creating functionality for the Continuous Scan Button defined
    # in the above XAML.
    #
    # Since we don't want the button-press functionality to freeze the GUI, any action taken by the
    # button-press scriptblock should be handled within its own Runspace
    $syncHash.WPFContinuousScanButton.Add_Click({
        # Pass Helper Functions to this Add_Click scriptblock
        . $UpdateWindowFunctionAsScriptBlock

        # Update any properties you'd like in the $global:syncHash and consequently, the GUI
        $syncHash.Stop = $false

        if ($syncHash.WPFInfoScanStatusLabel.Visibility -ne "Visible") {
            $syncHash.WPFInfoScanStatusLabel.Visibility = "Visible"
        }

        # Create a Runspace specifically for the Continuous Scan button
        $ContinuousScanRunspace =[runspacefactory]::CreateRunspace()
        $ContinuousScanRunspace.ApartmentState = "STA"
        $ContinuousScanRunspace.ThreadOptions = "ReuseThread"
        $ContinuousScanRunspace.Open()
        $ContinuousScanRunspace.SessionStateProxy.SetVariable("syncHash",$global:syncHash)
        $ContinuousScanRunspace.SessionStateProxy.SetVariable("JobCleanup",$global:JobCleanup)
        $ContinuousScanRunspace.SessionStateProxy.SetVariable("Jobs",$global:jobs)
        $ContinuousScanRunspace.SessionStateProxy.SetVariable("UpdateWindowFunctionAsScriptBlock",$UpdateWindowFunctionAsScriptBlock)
        
        $ContinuousScanPSInstance = [powershell]::Create()
        $ContinuousScanPSInstance.AddScript({
            ##### BEGIN Continuous Scan Runspace Helper Functions ######
            
            . $UpdateWindowFunctionAsScriptBlock

            ##### END Continuous Scan Runspace Helper Functions ######

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

        # Add the Continuous Scan Runspace to $global:jobs so that the Runspace Manager Runspace can clean
        # it up when it's finished ...
        $global:jobs.Add($(Get-Variable -Name "JobInfoCS" -ValueOnly))
    })

    ##### END WPF Form Controls #####

    # Makes the GUI visible when the GUI Runspace is started
    $syncHash.Window.ShowDialog()
})

# Start the GUI Runspace
$GUIPSInstance.Runspace = $GUIRunspace
$GUIAsyncHandle = $GUIPSInstance.BeginInvoke()


##### END GUI Runspace




















# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnrSH4EigxQl4+H39gM/CImNg
# M7qgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCXnw5Yv6BoLQ44R
# pzjzyuO/i0/IMA0GCSqGSIb3DQEBAQUABIIBAFP6zh64xQcDEXTnWYDUEtLMd+Bn
# FNTxFujCVHba2/MjzGyUAuDHnEqBgH0IoC3ufMm+8JzwLvB1XVoxvGXfdjoH6EMy
# lNnoMWWn3oaltiTtKzl/kIzVIvvsuSMW2nlawlOCKrJgJvE9Ar8IyP+nvTy+JJEA
# iGeQ9XjG1DhpsSFuphBYldueUn1txg5BXEv1OaVGziA7lIIYeopUKpZIviseArKc
# jkUJ+ntQ1wvgManRNvC9jqrTqyNqKaUFfN7Yl2Q0epkSd85J7+n5IeUQsPcgonso
# bZtO0/3owrm0Ea6v6dS7U00J0KSncOWp3xCzWIifaMWUoBVZrErASN699ug=
# SIG # End signature block
