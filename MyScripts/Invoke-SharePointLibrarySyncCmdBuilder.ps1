# SUMMARY: Generate a PowerShell command that should connect a SharePoint Document Library to a Windows User Profile

[string]$LogFileDirectory = 'C:\Scripts\logs'
if (!$(Test-Path $LogFileDirectory)) {$null = New-Item -Path $LogFileDirectory -ItemType Directory -Force}
[string]$ConnectionUri = 'https://contoso.sharepoint.com/'
[string]$SiteAdminUserName = 'contoso_admin@contoso.com'
[string]$UserToSyncWithLibrary = 'contoso_user@contoso.com'
#[pscredential]$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $SiteAdminUserName, (Read-Host -Prompt 'Enter password' -AsSecureString)
[bool]$UseMFA = $True

if ($PSVersionTable.PSEdition -ne 'Core') {
    Write-Error "You must run this in PowerShell Core (version 7 or higher)! Halting!"
    return
}

$ModuleName = 'PnP.PowerShell'
if (!$(Get-Module -ListAvailable $ModuleName -ErrorAction SilentlyContinue)) {
    try {
        $InstallModuleResult = Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module $ModuleName -ErrorAction Stop
    } catch {
        Write-Warning $_.Exception.Message
        Write-Error "Unable to install $ModuleName module! Halting!"
        $global:FunctionResult = "1"
        return
    }
}

$ConnectPnPOnlineSplat = @{
    Url = $ConnectionUri
}
if ($UseMFA) {
    $ConnectPnPOnlineSplat.Add('Interactive', $True)
}
#Connect-PnPOnline -Interactive -Url $ConnectionUri

try {
    $null = Connect-PnPOnline @ConnectPnPOnlineSplat -ErrorAction Stop
    $Session = Get-PnPConnection -ErrorAction Stop
    $TenantId = Get-PnPTenantId -Connection $Session -ErrorAction Stop
    $ConnectionData = Get-PnPSite -ErrorAction Stop
}
catch {
    Write-Warning $_.Exception.Message
    Write-Error "Unable to connect to SharePoint Online via Connect-PNPOnline cmdlet! Is -ConnectionUri in the correct format (for example, 'https://contoso.sharepoint.com/')? Halting!"
    $global:FunctionResult = "1"
    return
}

try {
    # We are looking for the "Documents" Document library found at url: https://contoso.sharepoint.com/Shared%20Documents/Forms/AllItems.aspx
    $AllLists = Get-PnPList -Includes ID
    $ListName = "Documents"
    $ListId = $($AllLists | Where-Object {$_.Title -eq $ListName}).Id.Guid
    $SiteContext = $Session.Context
    $Site = Get-PnPSite -Includes ID
    $SiteId = $Site.Id.Guid
    $Web = Get-PnPWeb -Includes ID
    $WebId = $Web.Id.Guid
    $Title = $Web.Title
    $WebUrl = $ConnectionData.Url
} catch {
    Write-Warning $_.Exception.Message
    Write-Error "Unable to explore $ConnectionUri! Halting!"
    $global:FunctionResult = "1"
    return
}

$CmdStringAttributes = [pscustomobject]@{
    WebUrl      = $WebUrl
    TenantId    = $TenantId
    SiteId      = $SiteId
    WebId       = $WebId
    ListId      = $ListId
    Title       = $Title
}

$CmdStringBase = @'
cmd /c 'start "C:\windows\explorer.exe" "odopen://sync?
'@

$TransformedCurrentUserUPN = $($UserToSyncWithLibrary -replace [regex]::Escape('@'),'%40') -replace [regex]::Escape('.'),'%2E'
$TransformedTenantId = '%7B' + $($TenantId -replace [regex]::Escape('-'),'%2D') + '%7D'
$TransformedSiteId = '%7B' + $($SiteId -replace [regex]::Escape('-'),'%2D') + '%7D'
$TransformedWebId = '%7B' + $($WebId -replace [regex]::Escape('-'),'%2D') + '%7D'
$TransformedListId = '%7B' + $($ListId -replace [regex]::Escape('-'),'%2D') + '%7D'
$TransformedRelevantSite = $($($($($($WebUrl -replace [regex]::Escape(':'),'%3A') -replace [regex]::Escape('/'),'%2F') -replace [regex]::Escape('.'),'%2E') -replace [regex]::Escape('-'),'%2D') -replace '[\s]','%20') -replace [regex]::Escape("'"),'%27'
$TransformedWebTitle = $($($($Title -replace '[\s]','%20') -replace [regex]::Escape('-'),'%2D') -replace '[\s]','%20') -replace [regex]::Escape("'"),'%27'

$OneDriveSyncObj = [ordered]@{
    userEmail   = $TransformedCurrentUserUPN
    tenantId    = $TransformedTenantId
    isSiteAdmin = '0'
    siteId      = $TransformedSiteId
    webId       = $TransformedWebId
    webTitle    = $TransformedWebTitle
    webTemplate = '7'
    webUrl      = $TransformedRelevantSite
    onPrem      = '0'
    libraryType = '4'
    listId      = $TransformedListId
    listTitle   = 'Documents'
    scope       = 'OPENLIST'
}

$Iteration = 0
$CmdStringPrep = $OneDriveSyncObj.Keys | foreach {
    if ($Iteration -eq 0) {
        $_ + '=' + $OneDriveSyncObj.$_
    }
    else {
        '&' + $_ + '=' + $OneDriveSyncObj.$_
    }

    $Iteration++
}
$FinalCmdString = $CmdStringBase + $($CmdStringPrep -join '') + '"' + "'"

# Ouput $FinalCmdString to a file named after the Site and User
$DateTime = Get-Date -Format mmddyy_hhmmss
$OutputFilePath = $LogFileDirectory + '\' + ($UserToSyncWithLibrary -split '@')[0] + "_onedrive_cmd_" + $DateTime +'.txt'
$FinalCmdString >> $OutputFilePath
$OneDriveSyncObj | Export-Clixml -Path ($OutputFilePath -replace '.txt','.xml')
$FinalCmdString