<#=============================================================================================
Script by    : Leo Nguyen
Website      : www.bonguides.com
Telegram     : https://t.me/bonguides
Discord      : https://discord.gg/fUVjuqexJg
YouTube      : https://www.youtube.com/@BonGuides

Script Highlights:
~~~~~~~~~~~~~~~~~
#. Install Windows Package Manager (winget).
============================================================================================#>

if (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You need to have Administrator rights to run this script!`nPlease re-run this script as an Administrator in an elevated powershell prompt!"
    break
}


# Install Windows Package Manager on Windows Sandbox
if (Test-Path 'C:\Users\WDAGUtilityAccount') {
    Write-Host "`nYou're using Windows Sandbox." -ForegroundColor Yellow
    irm bonguides.com/wsb/winget | iex
} else {

    # Create temporary directory
    $null = New-Item -Path $env:temp\temp -ItemType Directory -Force
    Set-Location $env:temp\temp
    $path = "$env:temp\temp"

    # Install C++ Runtime framework packages for Desktop Bridge
        $ProgressPreference='Silent'
        $url = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
        (New-Object Net.WebClient).DownloadFile($url, "$env:temp\temp\Microsoft.VCLibs.x64.14.00.Desktop.appx")
        Add-AppxPackage -Path Microsoft.VCLibs.x64.14.00.Desktop.appx -ErrorAction SilentlyContinue | Out-Null
    
    # Install Microsoft.UI.Xaml through Nuget.
        Write-Host "Downloading Windows Package Manager..." -ForegroundColor Green
        $ProgressPreference='Silent'
        Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx' -OutFile 'Microsoft.UI.Xaml.2.7.x64.appx'
        # Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.5/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile 'Microsoft.UI.Xaml.2.8.x64.appx'
    
        Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
        # Add-AppxPackage Microsoft.UI.Xaml.2.8.x64.appx
    
    # Download winget and license file the install it
        Write-Host "Installing Windows Package Manager..." -ForegroundColor Green
        function getLink($match) {
            $uri = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
            $get = Invoke-RestMethod -uri $uri -Method Get -ErrorAction stop
            $data = $get[0].assets | Where-Object name -Match $match
            return $data.browser_download_url
        }
    
        $url = getLink("msixbundle")
        $licenseUrl = getLink("License1.xml")
    
        # Finally, install winget
        $fileName = 'winget.msixbundle'
        $licenseName = 'license1.xml'
    
        (New-Object Net.WebClient).DownloadFile($url, "$env:temp\temp\$fileName")
        (New-Object Net.WebClient).DownloadFile($licenseUrl, "$env:temp\temp\$licenseName")
    
        Add-AppxProvisionedPackage -Online -PackagePath $fileName -LicensePath $licenseName | Out-Null
        Write-Host "The Windows Package Manager has been installed." -ForegroundColor Green
    
    # Cleanup
        Remove-Item $path\* -Recurse -Force
}