## If the module is removed, stop any await sessions that are active
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    if($SCRIPT:awaitHost)
    {
        Stop-AwaitSession
    }
}

<#

.SYNOPSIS

Creates a new Await Session, which is a virtual console that can invoke console-based
applications, interact with them, retrieve their responses, and view their (textual)
user interfaces.

.EXAMPLE

PS> Start-AwaitSession
PS> Send-AwaitCommand '123*456'
PS> $output = Wait-AwaitResponse '56088'
PS> $output

Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS> 123*456
56088

PS> Stop-AwaitSession

#>
function Start-AwaitSession
{
    [Alias("spawn", "saas")]
    [CmdletBinding(DefaultParameterSetName = "ByText")]
    param(
        [Parameter(ParameterSetName = "ByCommand", Position = 0)]
        [ScriptBlock] $Command,

        [Parameter(ParameterSetName = "ByText", Position = 0)]
        [AllowEmptyString()]
        [String] $Text
    )

    ## Ensure there's not already an await session running
    if($SCRIPT:awaitHost)
    {
        throw "Cannot start await session. A session is already started. Use the Send and Receive cmdlets to interact with it."
    }

    
    $SCRIPT:separatorLine = "="*20 + " " + [GUID]::NewGuid() + " " + "="*20
    $SCRIPT:pipeName = "AwaitServer_$([Guid]::NewGuid())"

    $script = @"
    `$namedPipeServer = New-Object System.IO.Pipes.NamedPipeServerStream '$pipename'
    `$pipeInput = New-Object System.IO.StreamReader `$namedPipeServer
    `$pipeOutput = New-Object System.IO.StreamWriter `$namedPipeServer

    `$namedPipeServer.WaitForConnection()
    `$pipeOutput.AutoFlush = `$true

    while(`$true) ``
    {
        `$command = `$pipeInput.ReadLine()
        try
        {
            `$result = Invoke-Expression `$command | Out-String
        }
        catch
        {
            `$result = `$_ | Out-String
        }

        `$pipeOutput.WriteLine(`$result + '$separatorLine')
    }
"@

    $SCRIPT:awaitHost = Start-Process "$pshome\powershell.exe" -ArgumentList "-NoProfile -Command $script" -PassThru -WindowStyle Hidden

    $SCRIPT:namedPipeClient = New-Object System.IO.Pipes.NamedPipeClientStream $pipename
    $SCRIPT:pipeInput = New-Object System.IO.StreamReader $namedPipeClient
    $SCRIPT:pipeOutput = New-Object System.IO.StreamWriter $namedPipeClient

    $namedPipeClient.Connect()

    $pipeOutput.AutoFlush = $true

    Invoke-AwaitHostCommand "Add-Type -Path '$psscriptRoot\AwaitDriver.cs'"
    Invoke-AwaitHostCommand '$awaitDriver = New-Object AwaitDriver.AwaitDriver'

    if($Command)
    {
        Send-AwaitCommand -Command $Command
    }
    
    if($Text)
    {
        ## If they just gave us text, assume it is a command name.
        
        ## If it has spaces (but no ampersand or single quotes), quote it
        ## Which precludes: "spawn 'c:\bin\program with arguments", but that can
        ## be accomplished with the script block parameter set.
        if(($Text -match " ") -and
           (-not ($Text -match "&|'")))
        {
            $Text = "& '$Text'"
        }

        Send-AwaitCommand -Text $Text
    }
}

function Stop-AwaitSession
{
    [Alias("spas")]
    [CmdletBinding()]
    param()

    Invoke-AwaitHostCommand '$awaitDriver.Close()'
    $SCRIPT:awaitHost.Kill()
    $SCRIPT:awaitHost = $null
}

function Send-AwaitCommand
{
    [Alias("sendac", "sdac")]
    [CmdletBinding(DefaultParameterSetName = 'ByText')]
	param(
        [Parameter(Mandatory, ParameterSetName = "ByCommand", Position = 0)]
        [ScriptBlock] $Command,

        [Parameter(Mandatory, ParameterSetName = "ByText", Position = 0)]
        [AllowEmptyString()]
        [String] $Text,

        [Switch] $NoNewLine
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    ## If they specified a script block, get its string representation.
    ## This saves the user from having to escape syntax and quoting rules.
    if($Command)
    {
        $Text = $Command.ToString().Trim()
        $Text = $Text -replace '{','{{'
        $Text = $Text -replace '}','}}'
    }

    $escapedText = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $driverCommand = "`$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$escapedText')); "

    if($NonewLine)
    {
	    $driverCommand += "`$awaitDriver.Send(`$text)"
    }
    else
    {
        $driverCommand += "`$awaitDriver.SendLine(`$text)"
    }

    Invoke-AwaitHostCommand $driverCommand
}

function Wait-AwaitResponse
{
    [Alias("expect", "war")]
    [CmdletBinding()]
	param(
        [Parameter(Mandatory)]
        $Text,

        [Parameter()]
        [Switch]
        $All,

        [Parameter()]
        [Switch]
        $Stream
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    
    $escapedText = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $command = "`$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$escapedText')); "

    if($All)
    {
	    $command += "`$awaitDriver.AwaitOutput(`$text, `$true)"
    }
    else
    {
        $command += "`$awaitDriver.AwaitOutput(`$text)"
    }

    $output = Invoke-AwaitHostCommand $command

    if($Stream)
    {
        $output
    }
    else
    {
        $output -join "`r`n"
    }
}

function Receive-AwaitResponse
{
    [Alias("expect?", "rcar")]
    [CmdletBinding()]
    param(
        [Parameter()]
        [Switch]
        $All,

        [Parameter()]
        [Switch]
        $Stream
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    if($All)
    {
    	$output = Invoke-AwaitHostCommand '$awaitDriver.ReadOutput($true)'
    }
    else
    {
        $output = Invoke-AwaitHostCommand '$awaitDriver.ReadOutput()'
    }

    if($Stream)
    {
        $output
    }
    else
    {
        $output -join "`r`n"
    }
}

function Invoke-AwaitHostCommand
{
    param(
        [Parameter(Mandatory)]
        $Command
    )

    $SCRIPT:pipeOutput.WriteLine($Command)

    while($true)
    {
        $content = $pipeInput.ReadLine()
        if($content -and $content.EndsWith($SCRIPT:separatorLine))
        {
            break
        }

        $content
    }
}