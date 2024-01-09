function Process-ICM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.Runspaces.PSSession]$PSSession,

        [Parameter(Mandatory=$True)]
        [string]$Command,

        [Parameter(Mandatory=$False)]
        [ValidateSet('String','Other')]
        [string]$OutputType = 'Other'
    )

    if ($OutputType -eq 'String') {
        # Validate [string]$Command has a line in it that indicates $OutputThatICareAbout is below here...
        $OutputIndicatorLine = ($Command -split "`n") -match 'SuccessOutput'
        if (!$OutputIndicatorLine) {
            Write-Error "The Command you provided does not have a line with the string 'SuccessOutput' (including single quotes)`
            that indicates where the output you care about is. Halting!"
            return
        }

        Invoke-Command -Session $PSSession {Invoke-Expression -Command $using:Command} -ErrorVariable icmErrs 2>&1 | Tee-Object -Variable icmAllOutput *>$null

        $ErrsThatICareAbout = $icmErrs.Exception.Message -notmatch '^NotSpecified'
        #if ($ErrsThatICareAbout.Count -gt 0) {$ErrsThatICareAbout | foreach {Write-Error $_}}
        $OutputThatICareAbout = $icmAllOutput[($icmAllOutput.IndexOf('SuccessOutput') + 1)..$icmAllOutput.Count]
        #if ($OutputThatICareAbout.Count -gt 0) {$OutputThatICareAbout | foreach {$_}}

        [pscustomobject]@{
            Errors = $icmErrs
            Output = $icmAllOutput
            RealErrors = $ErrsThatICareAbout
            RealOutput = $OutputThatICareAbout
        }

        Write-Host '$_.RealOutput is [string[]]'
    } else {
        Invoke-Command -Session $PSSession {Invoke-Expression -Command $using:Command} -ErrorVariable icmErrs 2>&1 | Tee-Object -Variable icmAllOutput *>$null

        $ErrsThatICareAbout = $icmErrs.Exception.Message -notmatch '^NotSpecified'
        #if ($ErrsThatICareAbout.Count -gt 0) {$ErrsThatICareAbout | foreach {Write-Error $_}}
        $OutputThatICareAbout = @($icmAllOutput) | Where-Object {$_ -isnot [System.Management.Automation.ErrorRecord]}
        #if ($OutputThatICareAbout.Count -gt 0) {$OutputThatICareAbout | foreach {$_}}
        if ($OutputThatICareAbout -match 'SuccessOutput') {
            $LineContent = $OutputThatICareAbout | Where-Object {$_ -match 'SuccessOutput'}
            $OutputThatICareAbout = $OutputThatICareAbout[($OutputThatICareAbout.IndexOf($LineContent) + 1)..$OutputThatICareAbout.Count]
        }

        [pscustomobject]@{
            Errors = $icmErrs
            Output = $icmAllOutput
            RealErrors = $ErrsThatICareAbout
            RealOutput = $OutputThatICareAbout
        }

        if ($OutputThatICareAbout.Count -gt 0) {
            $objectTypes = $OutputThatICareAbout | foreach {$_.GetType().FullName}
            Write-Host "`$_.RealOutput.Count is $($OutputThatICareAbout.Count) and it contains these types of objects (in order): $($objectTypes -join ', ')`n"
        } elseif (!$icmAllOutput) {
            Write-Host "You received *no* output at all...including no errors. This might be okay."
        } else {
            Write-Host "You received *no* relevant output. Check the contents of `$_.RealErrors and `$_.Output to see what happened."
        }
    }
}
