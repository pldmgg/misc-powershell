##### BEGIN Reference Links #####
# Create OneDriveAPI App Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/app-registration?view=odsp-graph-online
# Redirect URI should look like: https://login.microsoftonline.com/common/oauth2/nativeclient
# Set API Delegated Permissions Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/concepts/permissions_reference?view=odsp-graph-online
# How to Authenticate Reference: https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online
# About Authentication Scopes (subset of above link): https://learn.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online
# Expose an API, Define Scope(s) and Authorize the Application: https://stackoverflow.com/questions/62438643/azure-expose-an-api-vs-api-permissions
# AND https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/ProtectAnAPI/quickStartType~/null/sourceType/Microsoft_AAD_IAM/appId/e3707594-e16e-40e9-835f-51457df5f3c5/objectId/ba3989d5-4af4-4b25-b427-41808d851fde/isMSAApp~/false/defaultBlade/Overview/appSignInAudience/AzureADMyOrg/servicePrincipalCreated~/true
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
#>
function Invoke-365FileUpload {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$AppClientID,
        
        [Parameter(Mandatory=$True)]
        [string]$TenantID,

        [Parameter(Mandatory=$True)]
        [string]$SharePointDomain,

        [Parameter(Mandatory=$True)]
        [string]$LocalFilePathToUpload,

        [Parameter(Mandatory=$True)]
        [string]$PathToDocumentLibrary,

        [Parameter(Mandatory=$True)]
        [string]$DestinationPath
    )

    #region >> Prep

    $PathToTeamSite = $PathToDocumentLibrary | Split-Path -Parent
    $FileName = $LocalFilePathToUpload | Split-Path -Leaf

    # Make sure $LocalFilePathToUpload actually exists
    if (!$(Test-Path -Path $LocalFilePathToUpload)) {
        Write-Error "$LocalFilePathToUpload does not exist! Check the path and try again. Halting!"
        $global:FunctionResult = 1
        return
    }

    # Make sure $LocalFilePathToUpload is a Full Path
    $LocalFilePathToUpload = $(Get-Item -Path $LocalFilePathToUpload).FullName

    #endregion >> Prep


    #region >> Main

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


    ##### Upload File to SharePoint Document Library #####

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

    $UrlForFileDestination = "https://graph.microsoft.com/v1.0/drives/{0}/items/root:{1}:/content" -f $driveID,$DestinationPath
    #$UrlToCreateUploadSession = "https://graph.microsoft.com/v1.0/drives/root:{0}:/createUploadSession" -f $PathToDocumentLibrary
    $UrlToCreateUploadSession = "https://graph.microsoft.com/v1.0/drives/{0}/items/root:{1}:/createUploadSession" -f $driveID,$DestinationPath

    ### For files less than 4MB, you can use the below: ###
    # Do the upload
    #$UploadResponse = Invoke-RestMethod -Uri $UrlForFileDestination @SmallIRMParams -Method Put -InFile $LocalFilePathToUpload

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
    $FileInBytes = [System.IO.File]::ReadAllBytes($LocalFilePathToUpload)
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

    #endregion >> Main
}

#Write-Host $("args0 is {0}" -f $args[0])
# NOTE: The below $LocalPathEquivalentForSharePointLocation is usually something like...
# ... "$HOME\{OrgName}\{TeamsiteName} - {DocumentLibraryName}", for example "$HOME\Contoso\Contoso Data - Documents"
$LocalPathEquivalentForSharePointLocation = "{placeholder}"
$LocalPathRegexString = $LocalPathEquivalentForSharePointLocation -replace '\\','\\'  
$DataLocationCheck = $(Get-Item $args[0]).FullName -match $LocalPathRegexString
if (-not $DataLocationCheck) {
    $ErrMsg = "Only files under '$LocalPathEquivalentForSharePointLocation' can use this function. Halting!"
    Write-Error $ErrMsg
    return
}

$DestinationPathPrep1 = $LocalPathEquivalentForSharePointLocation | Split-Path -Leaf
$DestinationPathPrep2 =  $($args[0] -split $DestinationPathPrep1)[-1]
$DestinationPath = $DestinationPathPrep2 -replace '\\','/'
$Invoke365Params = @{
    AppClientID             = "{placeholder}" # Some GUID from your Azure App
    TenantID                = "{placeholder}" # Some GUID from Azure Tenant Properties
    SharePointDomain        = "{placeholder}" # Your Org's SharePoint Domain, for example: contoso.sharepoint.com
    LocalFilePathToUpload   = $args[0]
    PathToDocumentLibrary   = "{placeholder}" # Something like "/sites/{TeamSiteName}/{DocumentLibraryName}", for example: "/sites/Contoso Data/Documents"
    DestinationPath         = $DestinationPath # Should end up being something like "/{FolderWithinDocumentLibrary}/{FileName}"
}
Invoke-365FileUpload @Invoke365Params