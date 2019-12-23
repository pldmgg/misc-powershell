#region >> Helper Functions

function Update-Window {
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

<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ScriptBeingRun -Value $ScriptBlock
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            Invoke-Expression -Command $ScriptBlock.ToString() -OutVariable Result
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}

function New-FileScan {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        $DirectoryToScan = "C:\"
    )

    Write-Host "This is a placeholder function to illustrate OK Button functionality"
    
    Get-ChildItem $DirectoryToScan
}

#endregion >> Helper Functions


#region >> The Main SyncHash

# Create $syncHash - ALL Runspaces will reference objects contained in the properties of this syncHash.
# These runspaces will update the objects contained in the syncHash properties as the GUI is interacted with
$global:syncHash = [hashtable]::Synchronized(@{})

# Add the helper functions as strings into the sycnHash so it is easy to load them with form control scriptblocks
$syncHash.Add("FuncUpdateWindow",${Function:Update-Window}.Ast.Extent.Text)
$syncHash.Add("FuncNewRunspace",${Function:New-Runspace}.Ast.Extent.Text)
$syncHash.Add("FuncGetCallMetrics",${Function:New-Runspace}.Ast.Extent.Text)

#endregion >> The Main SyncHash


#region >> Create and Scrub the XAML

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

if ($XAMLInput.GetType().FullName -eq "System.String") {
    $XAMLInput = $XAMLInput -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace 'SelectionChanged="Select_Day_Of_Week_SelectionChanged" '
}
if ($XAMLInput.GetType().FullName -eq "System.Xml.XmlDocument") {
    $XAMLInput = $($XAMLInput.OuterXml | Out-String) -replace 'mc:Ignorable="d"','' -replace "x:N",'N' -replace '^<Win.*', '<Window' -replace 'TextChanged="TextBox_TextChanged" ','' -replace 'SelectionChanged="Select_Day_Of_Week_SelectionChanged" '
}

[void][System.Reflection.Assembly]::LoadWithPartialName('presentationframework')
[xml]$XAML = $XAMLInput

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

#endrgion >> Create and Scrub the XAML


#region >> Add the XAML Objects to the $syncHash

$XAML.SelectNodes("//*[@*[contains(translate(name(.),'n','N'),'Name')]]") | % {
    $syncHash.Add("WPF$($_.Name)",$syncHash.Window.FindName($_.Name))
}

do {
    Start-Sleep -Seconds 1
    Write-Host "Waiting for SyncHash To Populate"
} until ($syncHash -ne $null)

$syncHash.InitialLoad = "Complete"
$syncHash.ParentThreadPID = $PID

#endregion >> Add the XAML Objects to the $syncHash


#region >> Create Form Controls

#region >> Browse Button Functionality

[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

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

#endregion >> Browse Button Functionality

#region >> Hour, TimeSpanStart, and TimeSpanEnd Field Validation

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

#endregion >> Hour, TimeSpanStart, and TimeSpanEnd Field Validation


#region >> ListBox Drag and Drop Functionality

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

#endregion >> ListBox Drag and Drop Functionality


#region >> OK Button Functionality

$($syncHash.WPFxamlOKButton).Add_Click({
    # Load Helper Functions within the Add_Click scriptblock
    $FunctionsToLoad = @(
        $syncHash.FuncUpdateWindow
        $syncHash.FuncNewRunspace
        $syncHash.FuncGetCallMetrics
    )
    $FunctionsToLoad | foreach { Invoke-Expression $_ }

    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Please Wait..."

    $RunspaceName = $([System.IO.Path]::GetRandomFileName() -split "\.")[0]
    New-RunSpace -RunSpaceName $RunspaceName -ScriptBlock {
        $syncHash.CompleteFlag = "Working"

        try {
            $ScanItems = New-FileScan -DirectoryToScan "C:\"
        }
        catch {
            # Need to see the error message visually in a GUI, so just use a pop-up
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup("$($Error[0].Exception)",0,"Friendly Error Message",0x1) | Out-Null
            return
        }

        try {
            for ($i=1; $i -le $ScanItems.Count; $i++) {
                Start-Sleep -Milliseconds 500

                [int]$pct = ($i/$ScanItems.Count)*100

                # Update the progress bar
                Update-Window -Control $syncHash.WPFxamlProgressBar1 -Property Value -Value $pct

                if ($pct -gt 0 -and $pct -lt 20) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(360,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Doing Things Part A..."
                }
                if ($pct -gt 20 -and $pct -lt 40) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(330,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Doing Things Part B..."
                }
                if ($pct -gt 40 -and $pct -lt 60) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(350,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Doing Things Part C..."
                }
                if ($pct -gt 60 -and $pct -lt 80) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(400,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Doing Things Part D..."
                }
                if ($pct -gt 80 -and $pct -lt 99) {
                    #$WPFxamlPBarStatusLabel.Location = New-Object System.Drawing.Size(400,470)
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "Status: Doing Things Part E..."
                }
                if ($pct -ge 99) {
                    Update-Window -Control $syncHash.WPFxamlProgressBar1 -Property Value -Value $pct
                    Update-Window -Control $syncHash.WPFxamlPBarStatusLabel -Property Content -Value "        Status: COMPLETE"
                }
            }
        }
        catch {
            # Need to see the error message visually in a GUI, so just use a pop-up
            $wshell = New-Object -ComObject Wscript.Shell
            $wshell.Popup("$($Error[0].Exception)",0,"Friendly Error Message",0x1) | Out-Null
            return
        }

        $syncHash.CompleteFlag = "Complete"
    }
})

#endregion >> OK Button Functionality


#region >> Cancel Button Functionality

#$WPFxamlCancelButton.Add_Click({[System.Environment]::Exit(0)})
$($syncHash.WPFxamlCancelButton).Add_Click({
    $($syncHash.Window).Close()
    Stop-Process -Id $($syncHash.ParentThreadPID)
})

#endregion >> Cancel Button Functionality


#region >> Form Keyboard Functionality

$($syncHash.Window).Add_GotFocus({
    #$($syncHash.Window).Add_PreviewKeyUp({$True})
    $($syncHash.Window).Add_KeyUp({
        # Pressing Enter on the keyboard is the same as clicking the OK button
        if ($_.KeyCode -eq "Enter") {
            $($syncHash.WPFxamlOKButton).PerformClick()
        }

        # Pressing Esc on the keyboard is the same as clicking the Cancel button
        if ($_.KeyCode -eq "Escape") {
            $($syncHash.WPFxamlCancelButton).PerformClick()
        }
    })
})

#endregion >> Form Keyboard Functionality


#endregion >> Create Form Controls


# Actually Show the GUI
$syncHash.Window.ShowDialog()
Start-Sleep -Seconds 2

# Keep Checking the synchHash to see if the GUI is visible
while ($($syncHash.Window).IsVisible) {
    Write-Host "Holding Pattern..."
    Start-Sleep -Seconds 5
}

# If the GUI isn't visible anymore, make sure you kill the PowerShell Parent Process
if (!$($syncHash.Window).IsVisible) {
    Stop-Process -Id $($syncHash.ParentThreadPID)
}

