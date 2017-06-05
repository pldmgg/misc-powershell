$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Describe "Basics" {
    It "Doesn't leak processes" {

        $beforeProcesses = Get-Process -Name PowerShell
        Start-AwaitSession

        do
        {
            $midProcesses =  Get-Process -Name PowerShell
        } while($midProcesses.Count -eq $beforeProcesses.Count)

        Stop-AwaitSession
        
        do
        {
            $endProcesses =  Get-Process -Name PowerShell
        }
        while($endProcesses.Count -gt $beforeProcesses.Count)

        $midProcesses.Count - $beforeProcesses.Count | Should be 2
        $midProcesses.Count - $endProcesses.Count | Should be 2
    }

    It "Doesn't leave processes behind" {

        $beforeProcesses = Get-Process -Name PowerShell

        PowerShell -NoProfile -Command 'Start-AwaitSession; Remove-Module Await'

        do
        {
            $endProcesses =  Get-Process -Name PowerShell
        }
        while($endProcesses.Count -gt $beforeProcesses.Count)

        $beforeProcesses.Count | Should be $endProcesses.Count
    }
}

Describe "FullScreenOutput" {

    Start-AwaitSession

    try
    {
        It "Captures initial logo" {
        
            $output = Wait-AwaitResponse 'All rights reserved.' -All
            $output -match 'PowerShell'| Should be $true
	    }

        It "Evaluates simple command" {
        
            Send-AwaitCommand '111+222'
            
            do
            {
                $output = Receive-AwaitResponse -All
            } while(-not ($output -match '333'))

            $output -match '333'| Should be $true
	    }

        It "Supports Stream parameter" {
        
            $null = Receive-AwaitResponse
            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand '"`n"*5; "AAA"*2'           
            $output = Wait-AwaitResponse "AAAAAA" -Stream
            ($output.Count) -gt 1 | Should be $true

            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand '"`n"*5; "AAA"*2'
            Start-Sleep -m 500
            $output = Receive-AwaitResponse -Stream
            ($output.Count) -gt 1 | Should be $true
	    }

        It "Retains previous output" {
        
            Send-AwaitCommand '333+444'
            
            do
            {
                $output = Wait-AwaitResponse 777 -All
            } while(-not ($output -match '777'))

            $output -match '333'| Should be $true
            $output -match '777'| Should be $true
	    }

        It "Produces identical output for multiple invocations" {
        
            $output1 = Receive-AwaitResponse -All
            $output2 = Receive-AwaitResponse -All
            
            $output1 -eq $output2 | Should be $true
	    }

        It "Captures cleared screens" {
        
            Send-AwaitCommand cls
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand "'1234567'"
            $output = Wait-AwaitResponse '1234567' -All
            $output -match 1234567 | Should be $true

            Send-AwaitCommand cls
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand "'12121212'"
            $output = Wait-AwaitResponse 12121212 -All
            $output -match 1234567 | Should be $false
            $output -match 12121212 | Should be $true
	    }
    }
    finally
    {
        Stop-AwaitSession
    }
}

Describe "IncrementalOutput" {

    It "Captures initial logo" {
        Start-AwaitSession
        $output = Wait-AwaitResponse 'All rights reserved.'
        $output -match 'PowerShell'| Should be $true
        Stop-AwaitSession
	}

    Start-AwaitSession

    try
    {
        It "Clears output on multiple invocations" {
            Send-AwaitCommand '11*11'
            $output = Wait-AwaitResponse 121

            $output -match 121 | Should be $true
            $output2 = Receive-AwaitResponse
            $output2 | Should be ""
        }

        It "Captures secondary invocation" {
            Send-AwaitCommand '5*5'
            $output = Wait-AwaitResponse 25
            $output -match 25 | Should be $true

            Send-AwaitCommand '6*6'
            $output = Wait-AwaitResponse 36
            $output -match 36 | Should be $true
        }

        It "Handles cleared screens" {
            Send-AwaitCommand '"`n"*50'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"

            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse BBBBBB
            $output -match 'BBBBBB' | Should be $true
        }

        It "Captures output at the end of the buffer" {
            Send-AwaitCommand 'cls'
            $null = Receive-AwaitResponse

            Send-AwaitCommand '[Console]::BufferHeight = [Console]::WindowHeight'
            Send-AwaitCommand '"`n" * [Console]::BufferHeight * 2'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse BBBBBB
            $output -match 'BBBBBB' | Should be $true

            Send-AwaitCommand '"CCC"*2'
            $output = Wait-AwaitResponse CCCCCC
            $output -match 'CCCCCC' | Should be $true
        }

        It "Captures input at the end of the buffer" {
            Send-AwaitCommand 'cls'
            $null = Receive-AwaitResponse

            Send-AwaitCommand '[Console]::BufferHeight = [Console]::WindowHeight'
            Send-AwaitCommand '"`n" * [Console]::BufferHeight * 2'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            ## Should have original input line
            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse '"BBB"*2' -All
            $output -match ([Regex]::Escape('"BBB"*2')) | Should be $true
        }
    }
    finally
    {
        Stop-AwaitSession
    }
}

Describe "Scenarios" {

    Start-AwaitSession

    try
    {
        It "Does Something" {
        }
    }
    finally
    {
        Stop-AwaitSession
    }
}