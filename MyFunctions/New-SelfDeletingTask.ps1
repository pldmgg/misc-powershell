<# 
    .SYNOPSIS
        Create a self-deleting Scheduled Task.

    .DESCRIPTION 
        See .SYNOPSIS

    .NOTES

    .PARAMETER AdminUserAccount
        This parameter is MANDATORY.

        This parameter takes a string that represents the admin user that the Scheduled Task run as. It must be in format
        $env:ComputerName\<UserName> or <DomainShort>\<UserName>.

    .PARAMETER InMemory
        This parameter is MANDATORY.

        This parameter takes a securestring that represents the password for -AdminuserAccount.

    .PARAMETER Scriptblock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that the Scheduled Task will execute.

    .PARAMETER ScriptTimeLimitInMinutes
        This parameter is MANDATORY.

        This parameter takes an integer that represents the number of minutes that the Scheduled Task will be allowed to run
        before it is forcibly killed.

    .PARAMETER WhenToExecute
        This parameter is MANDATORY.

        This parameter takes either a string (valid values 'Immediately','AtLogon','AtStartup') or a System.DateTime object
        that represent when the Scheduled Task will run.

    .PARAMETER TranscriptPath
        This parameter is OPTIONAL, however, a default value of "$HOME\SelfDelTask_$(Get-Date -f ddMMyy_hhmmss).txt" is set.

        This parameter takes a string that represents the full path to a file that will contain a transcript of what the
        -Scriptblock does.

    .PARAMETER TaskName
        This parameter is OPTIONAL, however, a default value of "selfdeltask" is set.

        This parameter takes a string that represents the name of the new self-deleting Scheduled Task.

    .EXAMPLE
        # Launch powershell and...

        PS C:\Users\zeroadmin> $SB = {$null = New-Item -ItemType Directory -Path "C:\SelfDelTaskTestA"}
        PS C:\Users\zeroadmin> $UserAcct = 'zero\zeroadmin'
        PS C:\Users\zeroadmin> $PwdSS = Read-Host -Prompt "Enter passsword for $UserAcct" -AsSecureString
        PS C:\Users\zeroadmin> New-SelfDeletingTask -AdminUserAccount $UserAcct -PasswordSS $PwdSS -Scriptblock $SB -ScriptTimeLimitInMinutes 1 -WhenToExecute 'Immediately'
#>
function New-SelfDeletingTask {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        $AdminUserAccount, # Should be in format $env:ComputerName\<UserName> or <DomainShort>\<UserName>

        [Parameter(Mandatory=$True)]
        [securestring]$PasswordSS,

        [Parameter(Mandatory=$True)]
        [scriptblock]$Scriptblock,

        [Parameter(Mandatory=$True)]
        [int]$ScriptTimeLimitInMinutes, # Put a time limit on how long the script should take before killing it

        [Parameter(Mandatory=$True)]
        [ValidateScript({
            $ObjType = $_.GetType().FullName
            switch ($_) {
                'Immediately'                       {$True}
                'AtLogon'                           {$True}
                'AtStartup'                         {$True}
                {$ObjType -eq "System.DateTime"}    {$True}
                Default                             {$False}
            }
        })]
        $WhenToExecute,

        [Parameter(Mandatory=$False)]
        [string]$TranscriptPath = "$HOME\SelfDelTask_$(Get-Date -f ddMMyy_hhmmss).txt",

        [Parameter(Mandatory=$False)]
        [string]$TaskName = 'selfdeltask'
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

    #region >> Prep

    if ($AdminUserAccount -notmatch "\\") {
        Write-Error "The format of -AdminUserAccount should be '$env:ComputerName\<UserName>' or '<DomainShort>\<UserName>'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $tmpDir = [IO.Path]::GetTempPath()
    $SchTaskScriptPath = "$tmpdir\selfdeletingtask.ps1"
    $TaskDonePath = "$tmpdir\TaskDone_$(Get-Date -f ddMMyy+hhmmss)"
    $PlainTextPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PasswordSS))
    $TaskName = NewUniqueString -ArrayOfStrings $(Get-ScheduledTask).TaskName -PossibleNewUniqueString $TaskName

    #endregion >> Prep

    #region >> Main

    try {
        # Create selfdeletingtask.ps1 that your Scheduled Task will run and then delete
        [System.Collections.Generic.List[string]]$SBAsArrayOfStrings = $ScriptBlock.ToString() -split "`n"
        if ($SBAsArrayOfStrings -notmatch "Start-Transcript") {
            $null = $SBAsArrayOfStrings.Insert(0,"Start-Transcript -Path '$TranscriptPath' -Append")
        }
        if ($SBAsArrayOfStrings -notmatch "Stop-Transcript") {
            $null = $SBAsArrayOfStrings.Add('Stop-Transcript')
        }
        if ($SBAsArrayOfStrings -notmatch [regex]::Escape("Set-Content -Path '$TaskDonePath' -Value 'TaskDone'")) {
            $null = $SBAsArrayOfStrings.Add("Set-Content -Path '$TaskDonePath' -Value 'TaskDone'")
        }
        if ($SBAsArrayOfStrings -notmatch "Unregister-ScheduledTask") {
            $null = $SBAsArrayOfStrings.Add("`$null = Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$False")
        }
        if ($SBAsArrayOfStrings -notmatch [regex]::Escape('Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force')) {
            $null = $SBAsArrayOfStrings.Add('Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force')
        }
        #$FinalSB = [scriptblock]::Create($($SBAsArrayOfStrings -join "`n"))
        Set-Content -Path $SchTaskScriptPath -Value $SBAsArrayOfStrings
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    try {
        switch ($WhenToExecute) {
            'Immediately'                                   {$Trigger = New-ScheduledTaskTrigger -Once -At $(Get-Date).AddSeconds(10)}
            'AtLogon'                                       {$Trigger = New-ScheduledTaskTrigger -AtLogon -User $AdminUserAccount}
            'AtStartup'                                     {$Trigger = New-ScheduledTaskTrigger -AtStartup}
            {$_.GetType().FullName -eq "System.DateTime"}   {$Trigger = New-ScheduledTaskTrigger -Once -At $WhenToExecute}
        }
        if (!$Trigger) {
            throw "Problem defining `$Trigger (i.e. New-ScheduledTaskTrigger)! Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    
    try {
        # Put a time limit on how long the script should/can take before killing it
        $Trigger.EndBoundary = $(Get-Date).AddMinutes($ScriptTimeLimitInMinutes).ToString('s')
        
        # IMPORTANT NOTE: The double quotes around the -File value are MANDATORY. They CANNOT be single quotes or without quote or the Scheduled Task will error out!
        $null = Register-ScheduledTask -Force -TaskName $TaskName -User $AdminUserAccount -Password $PlainTextPwd -Action $(
            New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File `"$SchTaskScriptPath`""
        ) -Trigger $Trigger -Settings $(New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01)

        $PlainTextPwd = $null
    }
    catch {
        $PlainTextPwd = $null
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $Counter = 0
    while ($(Get-ScheduledTask -TaskName $TaskName).State -ne "Ready" -and $Counter -lt 6) {
        Write-Verbose "Waiting for new Scheduled Task '$TaskName' to be 'Ready'..."
        Start-Sleep -Seconds 1
        $Counter++
    }
    if ($(Get-ScheduledTask -TaskName $TaskName).State -ne "Ready") {
        Write-Error "The new Scheduled Task '$TaskName' did not report 'Ready' within 30 seconds! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($WhenToExecute -eq 'Immediately') {
        try {
            Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Wait for $ScriptTimeLimitInMinutes + 1 minutes or halt if the task fails
        $LastRunResultHT = @{
            '0'             = 'The operation completed successfully.'
            '1'             = 'Incorrect function called or unknown function called. 2 File not found.'
            '10'            = 'The environment is incorrect.'
            '267008'        = 'Task is ready to run at its next scheduled time.'
            '267009'        = 'Task is currently running. '
            '267010'        = 'The task will not run at the scheduled times because it has been disabled.'
            '267011'        = 'Task has not yet run.'
            '267012'        = 'There are no more runs scheduled for this task.'
            '267013'        = 'One or more of the properties that are needed to run this task on a schedule have not been set.'
            '267014'        = 'The last run of the task was terminated by the user.'
            '267015'        = 'Either the task has no triggers or the existing triggers are disabled or not set.'
            '2147750671'    = 'Credentials became corrupted.'
            '2147750687'    = 'An instance of this task is already running.'
            '2147943645'    = 'The service is not available (is "Run only when an user is logged on" checked?).'
            '3221225786'    = 'The application terminated as a result of a CTRL+C.'
            '3228369022'    = 'Unknown software exception.'
        }
        $LastRunResultRegex = $($LastRunResultHT.Keys | Where-Object {$_ -ne '0' -and $_ -ne '267009'} | foreach {'^' + $_ + '$'}) -join '|'

        $Counter = 0
        $ScriptTimeLimitInSeconds = $ScriptTimeLimitInMinutes/60
        while (!$(Test-Path $TaskDonePath) -and $LastRunResult -notmatch $LastRunResultRegex -and $Counter -le $($ScriptTimeLimitInSeconds+1)) {
            $Task = Get-ScheduledTask -TaskName $TaskName
            $TaskState = $Task.State
            $LastRunResult = $($Task | Get-ScheduledTaskInfo).LastRunResult

            $PercentComplete = [Math]::Round(($Counter/$ScriptTimeLimitInSeconds)*100)
            Write-Progress -Activity "Running Scheduled Task '$TaskName'" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
            Start-Sleep -Seconds 1
            $Counter++
        }

        if ($LastRunResult -match $LastRunResultRegex) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False -ErrorAction SilentlyContinue

            [System.Collections.Generic.List[string]]$ErrMsg = @("The Scheduled Task '$TaskName' failed with the result code $LastRunResult, meaning '$($LastRunResultHT.$LastRunResult)'.")
            if (Test-Path $TranscriptPath) {
                $TranscriptContent = Get-Content $TranscriptPath
                $null = $ErrMsg.Add("Transcript output is as follows`n`n###BEGIN Transcript###`n`n$TranscriptContent`n`n###END Transcript###`n")
            }
            Write-Error $($ErrMsg -join "`n")
            $global:FunctionResult = "1"
            return
        }
        if ($Counter -gt $($ScriptTimeLimitInMinutes+1)) {
            Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$False -ErrorAction SilentlyContinue

            Write-Error "The Scheduled Task '$TaskName' did not complete within the alotted time (i.e. $ScriptTimeLimitInMinutes minutes)! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (Test-Path $TaskDonePath) {
            Remove-Item $TaskDonePath -Force
        }

        Write-Host "The Scheduled Task '$TaskName' completed successfully!" -ForegroundColor Green
    }

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgS9qcKLXhPpdumu4Ar8yU23u
# aXGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLcfntgJ0Jj+zkBA
# EeSr2bS3yHJnMA0GCSqGSIb3DQEBAQUABIIBAJ/fOduOo0R1xW7wjFb+MQ2+7whL
# oTWFoPmsRhnEwJKC0n1i+kROafOyuHnq9+7Jq5qOdB2Ot8kSpG0TaiAGuB9PD265
# gEqXCVidOjTr7oMZygRyOn1T/93L8TIhgvqnayvpWIEOsekOgaTh70sjtplNl5ro
# e+OsVL+y3Cw4dFgTdnxmOnIY5yObnvkS0DbGQvX3cwQ7IInp3Nvr7MFpwAZQKSHW
# pdqH7JD4GK4OITuPBAKzpetRsvApGyUw1IizuayO5in44uF4lupOG43keAx4E0xz
# jatFzZReTWdL3LMraiD0WMT3J83E/6VWXGNhdV48TH5qcs4hIJSyMYsJZqU=
# SIG # End signature block
