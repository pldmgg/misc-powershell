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

function Install-DotNetScript {
    [CmdletBinding()]
    Param ()

    if (!$(Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find the 'dotnet' binary! Halting!"
        $global:FunctionResult = "1"
        return
    }

    dotnet tool install -g dotnet-script

    # $HOME/.dotnet/tools
    $DirSep = [System.IO.Path]::DirectorySeparatorChar
    $DotNetToolsDir = $HOME + $DirSep + '.dotnet' + $DirSep + 'tools'
    $PathSeparatorChar = if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {':'} else {';'}

    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:PATH -split $PathSeparatorChar | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
    if ($CurrentEnvPathArray -notcontains $DotNetToolsDir) {
        $CurrentEnvPathArray.Insert(0,$DotNetToolsDir)
        $env:PATH = $CurrentEnvPathArray -join $PathSeparatorChar
    }

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        $PathCheckforProfile = @"
[[ ":`$PATH:" != *":$DotNetToolsDir`:"* ]] && PATH="$DotNetToolsDir`:`${PATH}"
"@
        $ProfileContent = Get-Content "$HOME/.profile"
        if (!$($ProfileContent -match 'dotnet/tools')) {
            Add-Content -Path "$HOME/.profile" -Value $PathCheckforProfile
        }
    }

    if (!$(Get-Command dotnet-script -ErrorAction SilentlyContinue)) {
        Write-Error "Something went wrong during installation of 'dotnet-script' via the dotnet cli. Please review the above output. Halting!"
        $global:FunctionResult = "1"
        return
    }
}

function Get-SiteAsJson {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [uri]$Url,

        [Parameter(Mandatory=$False)]
        [uri]$SplashServerUri = "http://localhost:8050",

        [Parameter(Mandatory=$False)]
        [string]$XPathJsonConfigString,

        [Parameter(Mandatory=$False)]
        [string]$XPathJsonConfigFile,

        [Parameter(Mandatory=$False)]
        [string]$LuaScript,
        
        [Parameter(Mandatory=$False)]
        [switch]$HandleInfiniteScrolling,

        [Parameter(Mandatory=$False)]
        [string]$NewProjectDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveFileOutputs
    )

    # Make sure we have dotnet and dotnet-script in our $env:PATH
    $DirSep = [IO.Path]::DirectorySeparatorChar

    if (!$(Get-Command dotnet-script -ErrorAction SilentlyContinue)) {
        $DotNetToolsDir = $HOME + $DirSep + '.dotnet' + $DirSep + 'tools'

        if (!$(Test-Path $DotNetToolsDir)) {
            Write-Error "Unable to find '$DotNetToolsDir'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:PATH -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
        if ($CurrentEnvPathArray -notcontains $DotNetToolsDir) {
            $CurrentEnvPathArray.Insert(0,$DotNetToolsDir)
            $env:PATH = $CurrentEnvPathArray -join ';'
        }
    }
    if (!$(Get-Command dotnet-script -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'dotnet-script' binary! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        if (!$(Get-Command dotnet -ErrorAction SilentlyContinue)) {
            $DotNetDir = "C:\Program Files\dotnet"

            if (!$(Test-Path $DotNetDir)) {
                Write-Error "Unable to find '$DotNetDir'! Halting!"
                $global:FunctionResult = "1"
                return
            }

            [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:PATH -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
            if ($CurrentEnvPathArray -notcontains $DotNetDir) {
                $CurrentEnvPathArray.Insert(0,$DotNetDir)
                $env:PATH = $CurrentEnvPathArray -join ';'
            }
        }
        if (!$(Get-Command dotnet -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find 'dotnet' binary! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        if (!$(Get-Command dotnet -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find 'dotnet' binary! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$XPathJsonConfigFile -and !$XPathJsonConfigString) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -XPathJsonConfigString or the -XPathJsonConfigFile parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($HandleInfiniteScrolling -and $LuaScript) {
        Write-Error "Please use *either* the -HandleInfiniteScrolling *or* the -LuaScript parameter. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $UrlString = $Url.OriginalString
    if ($UrlString[-1] -ne '/') {
        $UrlString = $UrlString + '/'
    }

    $SplashServerUriString = $SplashServerUri.OriginalString
    
    $SiteNamePrep = @($($Url.OriginalString -split '/' | Where-Object {$_ -notmatch 'http' -and ![System.String]::IsNullOrWhiteSpace($_)}))[0]
    $SiteNamePrepA = $($SiteNamePrep -split '\.') -split ':'
    $SiteName = @($($SiteNamePrepA | Where-Object {$_ -notmatch 'www' -and ![System.String]::IsNullOrWhiteSpace($_)}))[0]

    if (!$SiteName) {
        Write-Error "Unable to parse site domain name from the value provided to the -Url parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($XPathJsonConfigFile) {
        try {
            $XPathJsonConfigFile = $(Resolve-Path $XPathJsonConfigFile -ErrorAction Stop).Path
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure the file is valid Json
        try {
            $JsonContent = Get-Content $XPathJsonConfigFile
            $JsonAsPSObject = $JsonContent | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($XPathJsonConfigString) {
        # Make sure the string is valid Json
        try {
            $JsonAsPSObject = $XPathJsonConfigString | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Check to see if a Project folder of the same name as $SiteName exists in either the current directory or the Parent Directory of $NewProjectDirectory
    if (!$NewProjectDirectory) {
        $PotentialProjectDirectories = @($(Get-ChildItem -Directory))
        if ($PotentialProjectDirectories.Name -contains $SiteName) {
            $DirItem = $PotentialProjectDirectories | Where-Object {$_.Name -eq $SiteName}
            
            # Make sure the existing project directory actually has a .csproj file in it to confirm it's a real project
            $DirItemContents = Get-ChildItem -Path $DirItem.FullName -File -Filter "*.csproj"
            if ($DirItemContents) {
                $ProjectDirectoryItem = $DirItem
            }
        }
    }
    else {
        $PotentialProjectDirParentDir = $NewProjectDirectory | Split-Path -Parent
        $PotentialProjectDirName = $NewProjectDirectory | Split-Path -Leaf

        $PotentialProjectDirectories = @($(Get-ChildItem -Path $PotentialProjectDirParentDir -Directory).Name)
        if ($PotentialProjectDirectories -contains $PotentialProjectDirName) {
            $DirItem = $PotentialProjectDirectories | Where-Object {$_.Name -eq $PotentialProjectDirName}

            # Make sure the existing project directory actually has a .csproj file in it to confirm it's a real project
            $DirItemContents = Get-ChildItem -Path $DirItem.FullName -File -Filter "*.csproj"
            if ($DirItemContents) {
                $ProjectName = $PotentialProjectDirName
            }

            $ProjectDirectoryItem = $DirItem
        }
    }

    # If an appropriate Project Folder doesn't already exist, create one
    if (!$ProjectDirectoryItem) {
        if (!$NewProjectDirectory) {
            $CurrentProjectDirectories = @($(Get-ChildItem -Directory).Name)
            if ($CurrentProjectDirectories.Count -gt 0) {
                $DirectoryName = NewUniqueString -ArrayOfStrings $CurrentProjectDirectories -PossibleNewUniqueString $SiteName
            }
            else {
                $DirectoryName = $SiteName
            }
            $NewProjectDirectory = $(Get-Location).Path + $DirSep + $DirectoryName
        }
        else {
            $NewProjectParentDir = $NewProjectDirectory | Split-Path -Parent
            if (!$(Test-Path $NewProjectParentDir)) {
                Write-Error "Unable to find the path $NewProjectParentDir! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $CurrentProjectDirectories = @($(Get-ChildItem -Path $NewProjectParentDir -Directory).Name)
            if ($CurrentProjectDirectories.Count -gt 0) {
                $DirectoryName = NewUniqueString -ArrayOfStrings $CurrentProjectDirectories -PossibleNewUniqueString $SiteName
            }
            else {
                $DirectoryName = $SiteName
            }
            $NewProjectDirectory = $NewProjectParentDir + $DirSep + $DirectoryName
        }

        if (!$(Test-Path $NewProjectDirectory)) {
            try {
                $ProjectDirectoryItem = New-Item -ItemType Directory -Path $NewProjectDirectory -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Error "A directory with the name $NewProjectDirectory already exists! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Push-Location $ProjectDirectoryItem.FullName

        $null = dotnet new console
        $null = dotnet restore
        $null = dotnet build
        $TestRun = dotnet run
        if ($TestRun -ne "Hello World!") {
            Write-Error "There was an issue creating a new dotnet console app in '$($(Get-Location).Path)'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        Push-Location $ProjectDirectoryItem.FullName
    }

    # Install any NuGetPackage dependencies
    # These packages will be found under $HOME/.nuget/packages/ after install, so they're not project specific
    # However, first make sure the project doesn't already include these packages
    $CSProjFileItem = Get-ChildItem -File -Filter "*.csproj"
    [xml]$CSProjParsedXml = Get-Content $CSProjFileItem
    $CurrentPackages = $CSProjParsedXml.Project.ItemGroup.PackageReference.Include

    $PackagesToInstall = @("Newtonsoft.Json","OpenScraping")
    foreach ($PackageName in $PackagesToInstall) {
        if ($CurrentPackages -notcontains $PackageName) {
            $null = dotnet add package $PackageName
        }
    }

    # Create Directory that will contain our .csx script and html parsing json config file (for example, dotnetapis.com.json)
    $WorkingDir = $ProjectDirectoryItem.FullName + $DirSep + "ScriptsConfigsAndOutput"
    if (!$(Test-Path $WorkingDir)) {
        try {
            $null = New-Item -ItemType Directory -Path $WorkingDir -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    Push-Location $WorkingDir

    # NOTE: OpenScraping 1.3.0 also installs System.Net.Http 4.3.2, System.Xml.XPath.XmlDocument 4.3.0, and HtmlAgilityPack 1.8.10

    $CSharpScriptPath = $WorkingDir + $DirSep + "$SiteName.csx"
    $HtmlParsingJsonConfigPath = $WorkingDir + $DirSep + "$SiteName.json"

    if ($HandleInfiniteScrolling) {
        # Get the InfiniteScrolling Lua Script and double-up on the double quotes
        $LuaScriptPSObjs = $(Get-Module HTMLToJson).Invoke({$LuaScriptPSObjects})
        $LuaScriptPrep = $($LuaScriptPSObjs | Where-Object {$_.LuaScriptName -eq 'InfiniteScrolling'}).LuaScriptContent
        $LuaScript = $LuaScriptPrep -replace '"','""'
    }

    if ($LuaScript) {
        $SplashEndPointString = 'string splashEndpoint = @"execute";'
        $PostDataString = 'var postData = JsonConvert.SerializeObject(new { url = url, timeout = 30, wait = 3, lua_source = luaScript });'
        $FinalLuaScript = $LuaScript -join "`n"
    }
    else {
        $SplashEndPointString = 'string splashEndpoint = @"render.html";'
        $PostDataString = 'var postData = JsonConvert.SerializeObject(new { url = url, timeout = 10, wait = 3 });'
        $FinalLuaScript = 'null'
    }

    # Write the CSharp Script
    $CSharpScript = @"
#r "nuget:Newtonsoft.Json,12.0.1"
#r "nuget:OpenScraping,1.3.0"

using System;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenScraping;
using OpenScraping.Config;

// XPath Cheat Sheet: http://ricostacruz.com/cheatsheets/xpath.html

string currDir = Directory.GetCurrentDirectory();
//string currDir = @"C:\Users\pddomain\Documents\LINQPad Queries";
string dirSeparator = System.IO.Path.DirectorySeparatorChar.ToString();

bool scrapeJavaScript = true;
if (scrapeJavaScript)
{
    string url = @"$UrlString";
    // Get Splash here: https://splash.readthedocs.io/en/stable/install.html
    string splashServer = @"$SplashServerUriString/";
    $SplashEndPointString
    string splashFinalUrl = splashServer + splashEndpoint;
    var request = (HttpWebRequest)WebRequest.Create(splashFinalUrl);
    request.Method = "POST";

    // For available Splash EndPoint Args (such as "timeout" and "wait" below), see: 
    // https://splash.readthedocs.io/en/stable/api.html
    string luaScript = @"
$FinalLuaScript";

    $PostDataString

    //Console.WriteLine(postData);
    var data = Encoding.ASCII.GetBytes(postData);
    // List of available content types here: https://en.wikipedia.org/wiki/Media_type
    request.ContentType = "application/json; charset=utf-8";
    //request.ContentType = "application/x-www-form-urlencoded; charset=utf-8";
    request.ContentLength = data.Length;

    using (var stream = request.GetRequestStream())
    {
        stream.Write(data, 0, data.Length);
    }
    var response = (HttpWebResponse)request.GetResponse();

    using (StreamReader sr = new StreamReader(response.GetResponseStream()))
    {
        var responseString = sr.ReadToEnd();
        using (StreamWriter sw = new StreamWriter(currDir + dirSeparator + "$SiteName.html"))
        {
            sw.Write(responseString);
        }
        //Console.WriteLine(responseString);
    }
}

// $SiteName.json contains the JSON configuration file pasted above
var jsonConfig = File.ReadAllText(currDir + dirSeparator + "$SiteName.json");
var config = StructuredDataConfig.ParseJsonString(jsonConfig);

var html = File.ReadAllText(currDir + dirSeparator + "$SiteName.html", Encoding.UTF8);

var openScraping = new StructuredDataExtractor(config);
var scrapingResults = openScraping.Extract(html);

Console.WriteLine(JsonConvert.SerializeObject(scrapingResults, Newtonsoft.Json.Formatting.Indented));
"@

    Set-Content -Path $CSharpScriptPath -Value $CSharpScript

    if ($XPathJsonConfigFile) {
        $HtmlParsingJsonConfig = Get-Content $XPathJsonConfigFile
    }
    if ($XPathJsonConfigString) {
        $HtmlParsingJsonConfig = $XPathJsonConfigString
    }

    Set-Content -Path $HtmlParsingJsonConfigPath -Value $HtmlParsingJsonConfig

    # Json Output
    dotnet-script $CSharpScriptPath

    # Cleanup
    if ($RemoveFileOutputs) {
        $HtmlFile = $WorkingDir + $DirSep + "$SiteName.html"
        $FilesToRemove = @($HtmlFile,$CSharpScriptPath,$HtmlParsingJsonConfigPath)
        foreach ($FilePath in $FilesToRemove) {
            if (Test-Path $FilePath) {
                $null = Remove-Item -Path $FilePath -Force
            }
        }
    }

    Pop-Location
    Pop-Location

}