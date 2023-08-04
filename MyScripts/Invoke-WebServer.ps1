param (
    [Parameter(Mandatory=$true)]
    [string]$DirectoryPath,

    [Parameter(Mandatory=$false)]
    [int]$Port = '8888'
)

# Example Usage: .\Invoke-WebServer.ps1 -DirectoryPath "C:\MyFiles" -Port 8080

function Get-ContentTypeFromExtension {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$extension
    )

    switch ($extension) {
        ".aac" { return "audio/aac" }
        ".abw" { return "application/x-abiword" }
        ".arc" { return "application/x-freearc" }
        ".avif" { return "image/avif" }
        ".avi" { return "video/x-msvideo" }
        ".azw" { return "application/vnd.amazon.ebook" }
        ".bin" { return "application/octet-stream" }
        ".bmp" { return "image/bmp" }
        ".bz" { return "application/x-bzip" }
        ".bz2" { return "application/x-bzip2" }
        ".cda" { return "application/x-cdf" }
        ".csh" { return "application/x-csh" }
        ".css" { return "text/css" }
        ".csv" { return "text/csv" }
        ".doc" { return "application/msword" }
        ".docx" { return "application/vnd.openxmlformats-officedocument.wordprocessingml.document" }
        ".eot" { return "application/vnd.ms-fontobject" }
        ".epub" { return "application/epub+zip" }
        ".gz" { return "application/gzip" }
        ".gif" { return "image/gif" }
        ".htm" { return "text/html" }
        ".html" { return "text/html" }
        ".ico" { return "image/vnd.microsoft.icon" }
        ".ics" { return "text/calendar" }
        ".jar" { return "application/java-archive" }
        ".jpeg" { return "image/jpeg" }
        ".jpg" { return "image/jpeg" }
        ".js" { return "text/javascript (Specifications: HTML and RFC 9239)" }
        ".json" { return "application/json" }
        ".jsonld" { return "application/ld+json" }
        ".md" { return "text/markdown" }
        ".mid" { return "audio/midi" }
        ".midi" { return "audio/midi" }
        ".mjs" { return "text/javascript" }
        ".mp3" { return "audio/mpeg" }
        ".mp4" { return "video/mp4" }
        ".mpeg" { return "video/mpeg" }
        ".mpkg" { return "application/vnd.apple.installer+xml" }
        ".odp" { return "application/vnd.oasis.opendocument.presentation" }
        ".ods" { return "application/vnd.oasis.opendocument.spreadsheet" }
        ".odt" { return "application/vnd.oasis.opendocument.text" }
        ".oga" { return "audio/ogg" }
        ".ogv" { return "video/ogg" }
        ".ogx" { return "application/ogg" }
        ".opus" { return "audio/opus" }
        ".otf" { return "font/otf" }
        ".png" { return "image/png" }
        ".pdf" { return "application/pdf" }
        ".php" { return "application/x-httpd-php" }
        ".ppt" { return "application/vnd.ms-powerpoint" }
        ".pptx" { return "application/vnd.openxmlformats-officedocument.presentationml.presentation" }
        ".rar" { return "application/vnd.rar" }
        ".rtf" { return "application/rtf" }
        ".sh" { return "application/x-sh" }
        ".svg" { return "image/svg+xml" }
        ".tar" { return "application/x-tar" }
        ".tif" { return "image/tiff" }
        ".tiff" { return "image/tiff" }
        ".ts" { return "video/mp2t" }
        ".ttf" { return "font/ttf" }
        ".txt" { return "text/plain" }
        ".vsd" { return "application/vnd.visio" }
        ".wav" { return "audio/wav" }
        ".weba" { return "audio/webm" }
        ".webm" { return "video/webm" }
        ".webp" { return "image/webp" }
        ".woff" { return "font/woff" }
        ".woff2" { return "font/woff2" }
        ".xhtml" { return "application/xhtml+xml" }
        ".xls" { return "application/vnd.ms-excel" }
        ".xlsx" { return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" }
        ".xml" { return "application/xml (recommended) or text/xml" }
        ".xul" { return "application/vnd.mozilla.xul+xml" }
        ".zip" { return "application/zip" }
        ".3gp" { return "video/3gpp; audio/3gpp if it doesn't contain video" }
        ".3g2" { return "video/3gpp2; audio/3gpp2 if it doesn't contain video" }
        ".7z" { return "application/x-7z-compressed" }
        default { return "application/octet-stream" }
    } else {
        return "application/octet-stream"
    }
}

$listener = New-Object System.Net.HttpListener

# Specify the desired InterfaceAliases where this webserver will be reachable
$allowedInterfaceAliases = @("ZeroTier One [8bkp1rxn07zvy5tfh]", "Ethernet", "Wi-Fi", "Loopback Pseudo-Interface 1")

# Get the network interfaces
$networkInterfaceIPs = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $allowedInterfaceAliases -contains $_.InterfaceAlias }).IPAddress
$netshOutput = netsh http show iplisten
$IPsThatAreListening = $netshOutput.Trim() | foreach { try {([ipaddress]$_).IPAddressToString} catch {} }

# Add prefixes for the allowed network interfaces
foreach ($IPAddr in $networkInterfaceIPs) {
    if ($IPAddr -notmatch '^169') {
        if ($IPsThatAreListening -notcontains $IPAddr) {
            $null = netsh http add iplisten $IPAddr
        }
        $listener.Prefixes.Add("http://$IPAddr`:$Port/")
        $listener.Prefixes.Add("http://$IPAddr`:$Port/upload/")
        $listener.Prefixes.Add("http://$IPAddr`:$Port/delete/")
    }
}

$listener.Start()


Write-Host "Web server started. Listening on the allowed network interfaces."
Write-Host "PowerShell process ID: $PID"

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
    } catch {
        Write-Host "Error occurred: $($_.Exception.Message)"
        continue
    }

    if ($request.HttpMethod -eq "POST" -and $request.Url.LocalPath -eq "/upload/") {
        $fileBuffer = New-Object byte[] $request.ContentLength64
        $request.InputStream.Read($fileBuffer, 0, $request.ContentLength64)
        $bytes = [System.Collections.Generic.List[byte]]$fileBuffer
        $fileName = [System.Text.Encoding]::UTF8.GetString($bytes).Split("`r`n")[1].Split("filename=")[1].Replace('"', '')
        $currentDirectory = ($request.UrlReferrer.AbsoluteUri -split $Port)[-1] -replace [regex]::Escape('/'),'\'
        $filePath = $directoryPath + '\' + $currentDirectory + '\' + $fileName

        $stringBuffer = [System.Text.Encoding]::UTF8.GetString($fileBuffer)
        $splitString = $stringBuffer.Split("`n")
        $lengthOfFourLines = $splitString[0].Length + $splitString[1].Length + $splitString[2].Length + $splitString[3].Length + 4
        $bytes.RemoveRange(0, $lengthOfFourLines)
        $lengthOfLastLine = $splitString[-2].Length+2
        $bytes.RemoveRange($bytes.Count - $lengthOfLastLine, $lengthOfLastLine)
        $fileBuffer = $bytes.ToArray()

        $fileStream = [System.IO.File]::Create($filePath)
        $fileStream.Write($fileBuffer)
        $fileStream.Close()

        $response.StatusCode = 200
        $response.StatusDescription = "File uploaded successfully"
        $response.ContentType = "text/html"
        $response.Redirect($request.UrlReferrer.AbsoluteUri)
        $response.Close()
    }
    elseif ($request.HttpMethod -eq "POST" -and $request.Url.LocalPath -eq "/delete") {
        $body = $request.InputStream
        $encoding = $request.ContentEncoding
        $reader = New-Object System.IO.StreamReader($body, $encoding)
        $requestBody = $reader.ReadToEnd()
        $body.Close()
        $reader.Close()
        [System.Collections.ArrayList]$filesToDelete = @($requestBody | ConvertFrom-Json)

        $currentDirectory = ($request.UrlReferrer.AbsoluteUri -split $Port)[-1] -replace [regex]::Escape('/'),'\'
        Write-Host "Absolute URI: $($request.UrlReferrer.AbsoluteUri)"
        Write-Host "Current directory: $currentDirectory"
        

        foreach ($fileName in $filesToDelete) {
            if ($currentDirectory -eq '\') {
                $filePathToDelete = $directoryPath + '\' + $fileName
            } else {
                $filePathToDelete = $directoryPath + $currentDirectory + '\' + $fileName
            }
            Write-Host "Deleting $filePathToDelete"
            if (Test-Path $filePathToDelete) {
                Remove-Item -Path $filePathToDelete -Force
            }
        }
        $response.StatusCode = 200
        $response.StatusDescription = "Files deleted successfully"
        $response.ContentType = "text/html"
        $response.Redirect($request.UrlReferrer.AbsoluteUri)
        $response.Close()
    }
    else {
        try {
            $filePath = Join-Path $directoryPath $request.Url.LocalPath.TrimStart('/')

            if (Test-Path $filePath) {
                if ($request.HttpMethod -eq "GET") {
                    if (Test-Path -PathType Container $filePath) {
                        $files = Get-ChildItem -Path $filePath -File
                        $directories = Get-ChildItem -Path $filePath -Directory
                        $html = "<html><head><style>"
                        $html += "body { font-family: Arial, sans-serif; }"
                        $html += "h1 { color: #333; }"
                        $html += "table { border-collapse: collapse; width: 100%; }"
                        $html += "th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }"
                        $html += "tr:hover { background-color: #f5f5f5; }"
                        $html += "a { text-decoration: none; color: #333; }"
                        $html += "</style>"

                        #$html += "<h1>Directory: $($request.Url.LocalPath)</h1>"
                        $html += "<h1>Directory: "
                        $html += "<a href='/'>Home</a>"
                        $currentPath = $request.Url.LocalPath.TrimStart('/')
                        $directories1 = $currentPath.Split('/')
                        $currentDirectory1 = ""
                        foreach ($directory1 in $directories1) {
                            if ($directory1 -ne "") {
                                $currentDirectory1 += "/" + $directory1
                                $html += " / <a href='$currentDirectory1'>$directory1</a>"
                            }
                        }
                        $html += "</h1>"
                        
                        $html += "<script>"
                        $html += "function toggleCheckbox(checkbox) {"
                        $html += "    var selectedFiles = document.querySelectorAll('input[name=`"selectedFiles[]`"]');"
                        $html += "    for (var i = 0; i < selectedFiles.length; i++) {"
                        $html += "        selectedFiles[i].checked = checkbox.checked;"
                        $html += "    }"
                        $html += "}"
                        $html += "function deleteSelectedFiles() {"
                        $html += "    var checkboxes = document.querySelectorAll('input[name=`"selectedFiles[]`"]:checked');"
                        $html += "    var filesToDelete = Array.from(checkboxes).map(function(checkbox) {"
                        $html += "        return checkbox.value;"
                        $html += "    });"
                        $html += "    if (filesToDelete.length > 0) {"
                        $html += "        var confirmation = confirm('Are you sure you want to delete the following files?\n' + filesToDelete.join('\n'));"
                        $html += "        if (confirmation) {"
                        $html += "            var data = JSON.stringify(filesToDelete);"
                        $html += "            var xhr = new XMLHttpRequest();"
                        $html += "            xhr.open('POST', '/delete', true);"
                        $html += "            xhr.setRequestHeader('Content-Type', 'application/json;charset=utf-8');"
                        $html += "            xhr.onload = function() {"
                        $html += "                if (xhr.status === 200) {"
                        $html += "                    location.reload();"
                        $html += "                } else {"
                        $html += "                    console.error('Error deleting files:', xhr.statusText);"
                        $html += "                }"
                        $html += "            };"
                        $html += "            xhr.onerror = function() {"
                        $html += "                console.error('Error deleting files:', xhr.statusText);"
                        $html += "            };"
                        $html += "            xhr.send(data);"
                        $html += "        }"
                        $html += "    }"
                        $html += "}"
                        $html += "</script>"
                        #$html += "<button onclick='deleteSelectedFiles()'>Delete</button>"
                        
                        # Add the upload button
                        #$html += "<tr><td colspan='6'><form action='/upload/' method='post' enctype='multipart/form-data'><input type='file' name='file' /><input type='submit' value='Upload' /></form></td></tr>"
                        $html += "<table>"
                        $html += "<tr><td colspan='6'><form name='form1' method='post' enctype='multipart/form-data' action='/upload/'><input name='file' type='file' /><input type='submit' value='Upload' /></form></td><td><button onclick='deleteSelectedFiles()'>Delete Selected</button></td></tr>"
                        $html += "</table>"
                        $html += "<table>"
                        $html += "<tr><th>Select</th><th>Icon</th><th>Name</th><th>Date Modified</th><th>Created</th><th>Size</th><th>Preview</th></tr>"
                        foreach ($directory in $directories) {
                            $directoryUrl = "http://" + $request.Url.Authority + $request.Url.LocalPath.TrimEnd('/') + "/" + $directory.Name
                            $html += "<tr><td><input type='checkbox' name='selectedFiles[]' value='$($directory.Name)'></td><td><img src='https://upload.wikimedia.org/wikipedia/commons/5/59/OneDrive_Folder_Icon.svg' alt='Folder' style='max-width: 25px; max-height: 25px;'></td><td><a href='$directoryUrl'>$($directory.Name)</a></td><td>$($directory.LastWriteTime)</td><td>$($directory.CreationTime)</td><td></td></tr>"
                        }
                        foreach ($fileItem in $files) {
                            $fileUrl = "http://" + $request.Url.Authority + $request.Url.LocalPath.TrimEnd('/') + "/" + $fileItem.Name
                            $fileExtension = [System.IO.Path]::GetExtension($fileItem.Name)
                            $contentType = Get-ContentTypeFromExtension $fileExtension

                            if ($contentType -match '^image') {
                                $html += "<tr><td><input type='checkbox' name='selectedFiles[]' value='$($fileItem.Name)'></td><td><img src='https://upload.wikimedia.org/wikipedia/commons/5/52/WLA_icon_image_gallery.svg' alt='Image' style='max-width: 25px; max-height: 25px;'></td><td><a href='$fileUrl'>$($fileItem.Name)</a></td><td>$($fileItem.LastWriteTime)</td><td>$($fileItem.CreationTime)</td><td>$($fileItem.Length)</td>"
                                $html += "<td><a href='$fileUrl'><img src='$fileUrl' alt='$($fileItem.Name)' style='max-width: 100px; max-height: 100px;'></a></td></tr>"
                            } elseif ($contentType -match '^video') {
                                $html += "<tr><td><input type='checkbox' name='selectedFiles[]' value='$($fileitem.Name)'></td><td><img src='https://upload.wikimedia.org/wikipedia/commons/6/68/Video_camera_icon.svg' alt='Image' style='max-width: 25px; max-height: 25px;'></td><td><a href='$fileUrl'>$($fileItem.Name)</a></td><td>$($fileItem.LastWriteTime)</td><td>$($fileItem.CreationTime)</td><td>$($fileItem.Length)</td>"
                                $html += "<td><a href='$fileUrl'><img src='$fileUrl' alt='$($fileItem.Name)' style='max-width: 100px; max-height: 100px;'></a></td></tr>"
                            } elseif ($contentType -match '^audio') {
                                $html += "<tr><td><input type='checkbox' name='selectedFiles[]' value='$($fileItem.Name)'></td><td><img src='https://upload.wikimedia.org/wikipedia/commons/c/c9/Antu_audio-volume-high.svg' alt='Image' style='max-width: 25px; max-height: 25px;'></td><td><a href='$fileUrl'>$($fileItem.Name)</a></td><td>$($fileItem.LastWriteTime)</td><td>$($fileItem.CreationTime)</td><td>$($fileItem.Length)</td>"
                            } else {
                                $html += "<tr><td><input type='checkbox' name='selectedFiles[]' value='$($fileItem.Name)'></td><td><img src='https://upload.wikimedia.org/wikipedia/commons/1/17/Noun_Project_new_file_icon_863190.svg' alt='File' style='max-width: 25px; max-height: 25px;'></td><td><a href='$fileUrl'>$($fileItem.Name)</a></td><td>$($fileItem.LastWriteTime)</td><td>$($fileItem.CreationTime)</td><td>$($fileItem.Length)</td><td></td></tr>"
                            }
                        }

                        $html += "</table></body></html>"
                        $fileBytes = [System.Text.Encoding]::UTF8.GetBytes($html)
                        $response.ContentLength64 = $fileBytes.Length
                        $response.OutputStream.Write($fileBytes, 0, $fileBytes.Length)
                    }
                    else {
                        $fileItem = Get-Item -Path $filePath
                        $fileExtension = [System.IO.Path]::GetExtension($fileItem.Name)
                        $contentType = Get-ContentTypeFromExtension $fileExtension

                        if ($contentType -notmatch '^text') {
                            # Handle non-text files
                            $response.ContentType = Get-ContentTypeFromExtension $fileExtension
                            $response.ContentLength64 = $fileItem.Length
                            $response.Headers.Add("Accept-Ranges", "bytes") # Allows for video playback skipping
                            $response.Headers.Add("Content-Disposition", "inline") # Allows images to load in browser automatically
                            $fileStream = [System.IO.File]::OpenRead($filePath)
                            $copyToTask = $fileStream.CopyToAsync($response.OutputStream, 8192)

                            try {
                                $copyToTask.Wait(5000)
                                if ($copyToTask.IsCompleted) {
                                    $fileStream.Close()
                                } else {
                                    $fileStream.Close()
                                    throw "CopyTo operation timed out"
                                }
                            } catch {
                                Write-Host "Error occurred during CopyTo: $($_.Exception.Message)"
                                $fileStream.Close()
                                continue
                            }
                        }
                        else {
                            $fileContent = Get-Content -Path $filePath -Raw
                            $fileContentBytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)
                            $contentType = Get-ContentTypeFromExtension $fileExtension
                            $response.ContentType = $contentType
                            $response.ContentLength64 = $fileContentBytes.Length
                            $response.OutputStream.Write($fileContentBytes, 0, $fileContentBytes.Length)
                        }
                    }
                }
            }
        } catch {
            Write-Host "Error occurred: $($_.Exception.Message)"
            continue
        }
    }
}

$listener.Stop()
$listener.Close()

