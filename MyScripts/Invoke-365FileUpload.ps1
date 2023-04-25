##### BEGIN Reference Links #####
# Create OneDriveAPI App Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online
# Redirect URI should look like: https://login.microsoftonline.com/common/oauth2/nativeclient
# Set API Delegated Permissions Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/concepts/permissions_reference?view=odsp-graph-online
# How to Authenticate Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online
# About Authentication Scopes (subset of above link): https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online
# Expose an API, Define Scope(s) and Authorize the Application: https://stackoverflow.com/questions/62438643/azure-expose-an-api-vs-api-permissions
# AND https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/ProtectAnAPI/quickStartType~/null/sourceType/Microsoft_AAD_IAM/appId/{GUID}/objectId/{GUID}/isMSAApp~/false/defaultBlade/Overview/appSignInAudience/AzureADMyOrg/servicePrincipalCreated~/true
# More on Authentication: https://stackoverflow.com/a/67806539
#
# Required PowerShell Module: https://morgantechspace.com/2022/03/azure-ad-get-access-token-for-delegated-permissions-using-powershell.html
# Creating an upload session: https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession?view=graph-rest-1.0
##### END Reference Links #####

##### BEGIN Azure App Instructions #####
# In Azure Dashboard, follow these steps:
<#
1) Navigate to https://portal.azure.com/
2) Hamburger menu -> Azure Active Directory -> App registrations -> New registration
3) Fill out "Name" field -> Under "Supported account types" select "Accounts in this organizational directory only (Rosner Title only - Single tenant)"
4) Under "Redirect URI (optional)" use the "Select a platform" dropdown and choose "Single-page Application (SPA)" and URI field should be "https://login.live.com/oauth20_desktop.srf"
5) Take note: "Application (client) ID" = $AppClientID | "Directory (tenant)" = $TenantID
6) In the left-hand menu, click "API Permissions" -> Click "Add a permission" -> Click "Microsoft Graph" -> Click "Delegated permissions" ->
In the "Select permissions" Search field search for and add the following permissions:
- Files.Read
- Files.Read.All
- Files.Read.Selected
- Files.ReadWrite
- Files.ReadWrite.All
- Files.ReadWrite.AppFolder
- Files.ReadWrite.Selected
- Sites.ReadWrite.All
- User.Read
- User.ReadWrite
7) In the left-hand menu, click on "Manifest" -> Ctrl + F for "oauth2AllowIdTokenImplicitFlow" and set to "true ->
Ctrl + F for "oauth2AllowImplicitFlow" and set to "true" so that it looks like the following:

    "oauth2AllowIdTokenImplicitFlow": true,
    "oauth2AllowImplicitFlow": true,
8) In the left-hand menu, click on "Authentication" -> Delete the SPA Platform entry -> Click "Add a platform" ->
Select "Mobile and desktop applications" -> Check the checkbox for URI "https://login.live.com/oauth20_desktop.srf" -> Click Save
9) If you want the App itself (as opposed to the logged-in user) to have the ability to upload files to SharePoint do the following:
- On the left-hand menu, click on "Certificates & secrets" -> Click "New client secret" ->
Take not that "Value" = $AppClientSecretValue
- On the left-hand menu, click "API Permissions" -> Click "Add a permission" -> Click "Microsoft Graph" ->
Click "Application permissions" -> Search for "Site.ReadWrite.All" -> Select the checkbox and click "Add permissions"

##### END Azure App Instructions #####

#### BEGIN Right-Click SendTo Menu Config #####

1) Create a .lnk file under C:\Users\ttadmin\AppData\Roaming\Microsoft\Windows\SendTo called 'SyncWithOneDrive'
2) Open the properties of SyncWithOneDrive.lnk and configure the following:
    - The "Target" Field should read: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoExit -NoProfile -File C:\Scripts\powershell\Invoke-365FileUpload.ps1
    - The "Start In" Field should read: C:\Scripts\powershell

#### BEGIN Right-Click SendTo Menu Config #####
#>

function Get-365AccessToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AppClientID,
        
        [Parameter(Mandatory=$True)]
        [string]$TenantID
    )

    # Get the user-specific access token via MSAL.PS Module
    try {
        if ($(Get-Module -ListAvailable).Name -notcontains 'MSAL.PS') {
            Install-PackageProvider NuGet -Force -ErrorAction Stop
            Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            #Install-Module -Name MSAL.PS -AllowClobber -Force -Confirm:$False -ErrorAction Stop
            # Install Module for all users on this machine...
            Save-Module -Name "MSAL.PS" -Path "$env:ProgramFiles\WindowsPowerShell\Modules" -Force -Confirm:$False -ErrorAction Stop
        }
        $null = Import-Module -Name 'MSAL.PS' -Force -ErrorAction Stop
    } catch {
        Write-Error $_
        $global:FunctionResult = 1
        return
    }

    # Specify user credentials (only works if 2-Factor is *not* enabled)
    #$username = "user@domain"
    #$password = "MyPassword"
    #$securePwd = ConvertTo-SecureString $password -AsPlainText -Force
    #$Cred = New-Object System.Management.Automation.PSCredential ($username, $securePwd)

    $MsalParams = @{
        ClientId        = $AppClientId
        TenantId        = $TenantId
        #ClientSecret   = $AppClientSecretValue # Use EITHER ClientSecret OR below UserCredential parameter
        #UserCredential = $Cred # Use EITHER UserCredential OR above ClientSecret parameter
        RedirectUri     = 'https://login.live.com/oauth20_desktop.srf'
        ErrorAction     = "Stop"
    }

    # WARNING: The below will most likely be INTERACTIVE
    # Acquire token via interactive prompt
    try {
        $MsalResponse = Get-MsalToken @MsalParams
        $AccessToken  = $MsalResponse.AccessToken
    } catch {
        Write-Error $_
        $global:FunctionResult = 1
        return
    }

    # Output
    $AccessToken
}

function Invoke-365FileUpload {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AppClientID,
        
        [Parameter(Mandatory=$True)]
        [string]$TenantID,

        [Parameter(Mandatory=$True)]
        [string]$AccessToken,

        [Parameter(Mandatory=$True)]
        [string]$SharePointDomain,

        [Parameter(Mandatory=$True)]
        [string[]]$LocalFilesToUpload,

        [Parameter(Mandatory=$True)]
        [string]$PathToDocumentLibrary,

        [Parameter(Mandatory=$True)]
        [string]$DestinationDirectoryPath
    )

    #region >> Prep

    $PathToTeamSite = $PathToDocumentLibrary | Split-Path -Parent

    # Validate all paths in $LocalFilesToUpload
    [System.Collections.Generic.List[string]]$ValidatedLocalFilesToUpload = @()
    foreach ($FilePath in $LocalFilesToUpload) {
        # Make sure $FilePath actually exists
        if (!$(Test-Path -Path $FilePath)) {
            Write-Error "$FilePath does not exist! Check the path and try again. Halting!"
            $global:FunctionResult = 1
            return
        }

        # Make sure $FilePath is a Full Path   
        $FilePath = $(Get-Item -Path $FilePath).FullName

        # Add the Validated Full Path to the $ValidatedLocalFilesToUpload array
        $null = $ValidatedLocalFilesToUpload.Add($FilePath)
    }

    #endregion >> Prep


    #region >> Main

    # Get the DriveID
    $UrlForDriveID = "https://graph.microsoft.com/v1.0/sites/{0}:{1}:\drive" -f $SharePointDomain,$PathToTeamSite

    $SmallIRMParams = @{
        Uri         = $UrlForDriveID
        Headers     = @{Authorization  = "Bearer $AccessToken"}
        ContentType = 'application/json'
        ErrorAction = "Stop"
    }

    try {
        $driveID = $(Invoke-RestMethod @SmallIRMParams).ID
    } catch {
        Write-Error $_
        $global:FunctionResult = 1
        return
    }

    if (!$driveID) {
        Write-Error "Unable to get `$driveID! Halting!"
        $global:FunctionResult = 1
        return
    }

    # Loop through all files in $ValidatedLocalFilesToUpload and upload each one at a time
    foreach ($LocalFile in $ValidatedLocalFilesToUpload) {
        $FileName = $LocalFile | Split-Path -Leaf
        $DestinationPath = $DestinationDirectoryPath + '/' + $FileName

        $UrlForFileDestination = "https://graph.microsoft.com/v1.0/drives/{0}/items/root:{1}:/content" -f $driveID,$DestinationPath
        #$UrlToCreateUploadSession = "https://graph.microsoft.com/v1.0/drives/root:{0}:/createUploadSession" -f $PathToDocumentLibrary
        $UrlToCreateUploadSession = "https://graph.microsoft.com/v1.0/drives/{0}/items/root:{1}:/createUploadSession" -f $driveID,$DestinationPath

        #Write-Host "UrlForFileDestination is $UrlForFileDestination"
        #Write-Host "UrlToCreateUploadSession is $UrlToCreateUploadSession"

        ### For files less than 4MB, you can use the below: ###
        # Do the upload
        #$UploadResponse = Invoke-RestMethod -Uri $UrlForFileDestination @SmallIRMParams -Method Put -InFile $LocalFile

        ### For files larger than 4MB, you must use the below: ###
        # Create the session
        $SessionIRMParams = @{
            Method      = "Post"
            Uri         = $UrlToCreateUploadSession
            Headers     = @{"Authorization" = "Bearer $AccessToken"}
            ContentType = 'application/json'
            Body        = "{'@microsoft.graph.conflictBehavior': 'replace', 'name': '$FileName'}"
        }
        $SessionInfo = Invoke-RestMethod @SessionIRMParams

        # Do the Upload
        # NOTE: This was tested for files up to 100MB in size
        $FileInBytes = [System.IO.File]::ReadAllBytes($LocalFile)
        $FileLength = $FileInBytes.Length

        $LargeIRMParams = @{
            Uri     = $SessionInfo.uploadUrl
            Method  = "PUT"
            Body    = $FileInBytes
            Headers = @{
                'Content-Range' = "bytes 0-$($FileLength-1)/$FileLength"
            }
        }
        $UploadResponse = Invoke-RestMethod @LargeIRMParams

        $itemID = $UploadResponse.id
        $UrlForFileItemCheck = "https://graph.microsoft.com/v1.0/drives/{0}/items/{1}" -f $driveID,$itemID
        $FileCheckIRMParams = @{
            Uri         = $UrlForFileItemCheck
            Headers     = @{Authorization  = "Bearer $AccessToken"}
            ContentType = 'application/json'
            ErrorAction = "Stop"
        }
        $SharePointFileItem = Invoke-RestMethod @FileCheckIRMParams

        # Output
        $SharePointFileItem
    }

    #endregion >> Main
}


function Invoke-Upload {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AppClientID,
        
        [Parameter(Mandatory=$True)]
        [string]$TenantID,

        [Parameter(Mandatory=$True)]
        [string[]]$LocalFilesToUpload,

        [Parameter(Mandatory=$True)]
        [string]$LocalPathEquivalentForSharePointLocation,

        [Parameter(Mandatory=$True)]
        [string]$SharePointDomain,

        [Parameter(Mandatory=$True)]
        [string]$PathToDocumentLibrary,

        [Parameter(Mandatory=$True)]
        [switch]$LocalToSharePointPathCheck
    )

    #Write-Host $("args0 is {0}" -f $args[0])
    #Write-Host $("args1 is {0}" -f $args[1])
    Write-Host "Uploading the following files: $($LocalFilesToUpload | Split-Path -Leaf)"

    # Make sure the user is trying to upload file(s) that *SHOULD IN FACT* be uploaded to SharePoint
    if ($LocalToSharePointPathCheck) {
        $LocalPathRegexString = $LocalPathEquivalentForSharePointLocation -replace '\\','\\'
        foreach ($FilePath in $args) {
            $DataLocationCheck = $(Get-Item $FilePath).FullName -match $LocalPathRegexString
            if (-not $DataLocationCheck) {
                $ErrMsg = "Only files under '$LocalPathEquivalentForSharePointLocation' can use this function. Halting!"
                Write-Error $ErrMsg
                return
            }
        }
    }

    # Figure out Destination Directory/Folder Path
    $DestinationDirPathPrep1 = $LocalPathEquivalentForSharePointLocation | Split-Path -Leaf
    $DestinationDirPathPrep2 =  $($args[0] -split $DestinationDirPathPrep1)[-1]
    $DestinationDirPath = $DestinationDirPathPrep2 -replace '\\','/'
    $DestinationDirPathCheck = $($DestinationDirPath | Select-String -Pattern '\/' -AllMatches).Matches.Count
    if ($DestinationDirPathCheck -eq 1) {
        $DestinationDirPath = '/'
    }
    Write-Host "DestinationDirPath is $DestinationDirPath"

    try {
        $AccessToken = Get-365AccessToken -AppClientID $AppClientID -TenantID $TenantID -ErrorAction Stop
        if (!$AccessToken) {throw "Unable to get AccessToken! Halting!"}
    } catch {
        Write-Error $_
        $global:FunctionResult = 1
        return
    }

    $Invoke365Params = @{
        AppClientID                 = $AppClientID
        TenantID                    = $TenantID
        AccessToken                 = $AccessToken
        SharePointDomain            = $SharePointDomain
        LocalFilesToUpload          = $LocalFilesToUpload
        PathToDocumentLibrary       = $PathToDocumentLibrary
        DestinationDirectoryPath    = $DestinationDirPath
    }
    Invoke-365FileUpload @Invoke365Params
}


$InvokeUploadParams = @{
    AppClientID                                 = '{placeholder}' # Some GUID from your Azure App
    TenantID                                    = '{placeholder}' # Some GUID from Azure Tenant Properties
    SharePointDomain                            = '{placeholder}' # Your Org's SharePoint Domain, for example: contoso.sharepoint.com
    LocalFilesToUpload                          = $args
    LocalPathEquivalentForSharePointLocation    = '{placeholder}' # Usually something like: "$HOME\{OrgName}\{TeamsiteName} - {DocumentLibraryName}", for example "$HOME\Contoso\Contoso Data - Documents"
    PathToDocumentLibrary                       = '{placeholder}' # For example: "/sites/ContosoData/Documents"
    LocalToSharePointPathCheck                  = $False
    #DestinationDirectoryPath                    = '{placeholder}' # For example "/IT Department/Subfolder" or, if you just want it in the root of the Document Library "/"
}
Invoke-Upload @InvokeUploadParams
