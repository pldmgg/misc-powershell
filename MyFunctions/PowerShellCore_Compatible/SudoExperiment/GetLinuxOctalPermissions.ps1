function GetLinuxOctalPermissions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$FullPath,

        [Parameter(Mandatory=$False)]
        [switch]$Children
    )

    # If $FullPath ends with '/', remove it
    if ($FullPath[-1] -eq "/") {
        $FullPath = $FullPath.Substring(0,$VaultSSHHostSigningUrl.Length-1)
    }

    if (!$(Test-Path $FullPath)) {
        Write-Error "The path $FullPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalFullPath = if (!$Children) {$FullPath -replace "[\s]","\ "} else {$($FullPath -replace "[\s]","\ ") + '/*'}
    $ResultPrep = [scriptblock]::Create($('stat -c "%a %n" {0}' -f $FinalFullPath)).InvokeReturnAsIs()

    if (!$ResultPrep) {
        Write-Error $Error[0]
        $global:FunctionResult = "1"
        return
    }

    $Result = $ResultPrep | foreach {
        $Octal = $($_ -split "[\s]")[0]
        $ItemPath = $($_ -split "[\s]")[-1]
        [pscustomobject]@{
            ItemInfo        = Get-Item $ItemPath
            Permissions     = $Octal
        }
    }

    $Result
}