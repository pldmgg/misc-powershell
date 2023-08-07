# Miniserve ideal command parameters
miniserve -i 192.168.2.203 -i 127.0.0.1 -p 8080 --qrcode --upload-files --mkdir --media-type image --overwrite-files --enable-tar --enable-tar-gz --enable-zip --dirs-first --show-symlink-info --show-wget-footer C:/test_folder
# NOTE: In this example, within $HOME/test_folder are files and directories, one of which is a directory called "temp"
# If we want to recursively download the contents of "temp"...

# On Linux:
wget -rcnHp -R 'index.html*' --cut-dirs=2 -P $HOME/Downloads/temp 'http://192.168.2.203:8080/temp/?raw=true'

# Windows Equivalent:
# Just install and use wget via:
winget install GNU.Wget2
$destinationDir = "$HOME/Downloads/temp"
if (!(Test-Path -Path $destinationDir)) {$null = New-Item -Path $destinationDir -ItemType Directory -Force}
Push-Location $destinationdir
wget2 -rcnHp -R 'index.html*' --cut-dirs=2 'http://192.168.2.203:8080/temp/?raw=true'
# For some reason winget2 doesn't honor -R parameter, so we need to cleanup after...
Get-ChildItem -Path $destinationDir -Recurse -File -Filter 'index.html*' | Remove-Item -Force
Pop-Location
# ...OR if you want pure PowerShell:
$OSSeparator = [System.IO.Path]::DirectorySeparatorChar
$baseUrl = 'http://localhost:8080'
$sourceUrl = $baseUrl + '/' + 'temp/?raw=true'
$destinationDir = $HOME + $OSSeparator + 'Downloads' + $OSSeparator + 'temp'
if (!(Test-Path -Path $destinationDir)) {$null = New-Item -Path $destinationDir -ItemType Directory -Force}
function Download-FilesRecursively {
    param (
        [string]$Url,
        [string]$DirPath
    )

    $OSSeparator = [System.IO.Path]::DirectorySeparatorChar
    $baseUrl = ($Url -split '/')[0..2] -join '/'
    $IWRResult = Invoke-WebRequest $Url
    $FolderLinks = $IWRResult.links | Where-Object {$_.outerHTML -match [regex]::Escape('class="directory"')}
    $FileLinks = $IWRResult.links | Where-Object {$_.outerHTML -match [regex]::Escape('class="file"')}

    foreach ($folderLink in $FolderLinks) {
        $folderUrl = $baseUrl + [System.Uri]::new($folderLink.href, [System.UriKind]::RelativeOrAbsolute).OriginalString
        $folderPath = $DirPath + $OSSeparator + ($folderLink.outerHTML -split '/')[-4]
        Write-Host "Creating directory $folderPath ..."
        $null = New-Item -Path $folderPath -ItemType Directory -ErrorAction SilentlyContinue
        Download-FilesRecursively -Url $folderUrl -DirPath $folderPath
    }

    foreach ($fileLink in $FileLinks) {
        $fileUrl = $baseUrl + [System.Uri]::new($fileLink.href, [System.UriKind]::RelativeOrAbsolute).OriginalString
        $filePath = $DirPath + $OSSeparator + ($fileLink.href -split '/')[-1]
        Write-Host "Downloading $fileUrl to $filePath ..."
        Invoke-WebRequest -Uri $fileUrl -OutFile $filePath
    }
}
Download-FilesRecursively -Url $sourceUrl -DirPath $destinationDir