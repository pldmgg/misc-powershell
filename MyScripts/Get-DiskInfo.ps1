# It's ugly...

# Make sure NTFSSecurity module is loaded
$ModuleName = "NTFSSecurity"
if (!$(Get-Module -ListAvailable $ModuleName -ErrorAction SilentlyContinue)) {
    try {
        Install-Module $ModuleName -AllowClobber -Force -AcceptLicense -ErrorAction Stop
    } catch {
        Write-Error $_
        Write-Error "Unable to install $ModuleName Module! Halting!"
        return
    }
}
try {
    Import-Module $ModuleName -ErrorAction Stop
} catch {
    Write-Error $_
    Write-Error "Unable to import $ModuleName Module! Halting!"
    return
}

# Gather all disk, partition, and volume information
$diskInfo = Get-Disk
$partitionInfo = Get-Partition
$volumeInfo = Get-Volume
$ntfsDiskInfo = Get-DiskSpace

# Combine and display the information in a custom object
$storageInfo = $diskInfo | ForEach-Object {
    $disk = $_
    $partitions = $partitionInfo | Where-Object DiskNumber -eq $disk.Number
    $partitions | ForEach-Object {
        $partition = $_
        $volume = $volumeInfo | Where-Object { $_.DriveLetter -eq $partition.DriveLetter } | Select-Object -First 1
        [PSCustomObject]@{
            DiskNumber = $disk.Number
            DiskModel = $disk.Model
            DiskSizeGB = "{0:N3}" -f [math]::Round($disk.Size / 1GB, 3)
            PartitionNumber = $partition.PartitionNumber
            PartitionSizeGB = "{0:N3}" -f [math]::Round($partition.Size / 1GB, 3)
            VolumeDriveLetter = $volume.DriveLetter
            VolumeLabel = $volume.FileSystemLabel
            FileSystem = $volume.FileSystem
            UsedSpaceGB = if ($volume) {
                "{0:N3}" -f [math]::Round(($volume.Size - $volume.SizeRemaining) / 1GB, 3)
            } else {
                $relevantNTFSDiskInfoObj = $ntfsDiskInfo | Where-Object {$partition.AccessPaths -match [regex]::Escape($_.DriveName)}
                if ($relevantNTFSDiskInfoObj) {
                    $sizeString = $relevantNTFSDiskInfoObj.UsedSpaceUnitSize
                    $sizeStringNoUnits = [double]($sizeString -replace '[^\d.]')
                    if ($sizeString -match "GB") {
                        "{0:N3}" -f $sizeStringNoUnits
                    } elseif ($sizeString -match "MB"){
                        "{0:N3}" -f ($sizeStringNoUnits / 1024)
                    } else {
                        "Units are not GB or MB"
                    }
                } else {
                    "Unable to find matching object from NTFSSecurity Module's Get-DiskSpace output"
                }
            }
            FreeSpaceGB = if ($volume) {
                "{0:N3}" -f [math]::Round($volume.SizeRemaining / 1GB, 3)
            } else {
                $relevantNTFSDiskInfoObj = $ntfsDiskInfo | Where-Object {$partition.AccessPaths -match [regex]::Escape($_.DriveName)}
                if ($relevantNTFSDiskInfoObj) {
                    $sizeString = $relevantNTFSDiskInfoObj.AvailableFreeSpaceUnitSize
                    $sizeStringNoUnits = [double]($sizeString -replace '[^\d.]')
                    if ($sizeString -match "GB") {
                        "{0:N3}" -f $sizeStringNoUnits
                    } elseif ($sizeString -match "MB"){
                        "{0:N3}" -f ($sizeStringNoUnits / 1024)
                    } else {
                        "Units are not GB or MB"
                    }
                } else {
                    "Unable to find matching object from NTFSSecurity Module's Get-DiskSpace output"
                }
            }
            FreeSpacePercent = if ($volume) {
                "{0:N3}" -f [math]::Round($volume.SizeRemaining / $volume.Size * 100, 3)
            } else {
                $relevantNTFSDiskInfoObj = $ntfsDiskInfo | Where-Object {$partition.AccessPaths -match [regex]::Escape($_.DriveName)}
                if ($relevantNTFSDiskInfoObj) {
                    "{0:N3}" -f [double]($relevantNTFSDiskInfoObj.AvailableFreeSpacePercent -replace '%','')
                } else {
                    "Unable to find matching object from NTFSSecurity Module's Get-DiskSpace output"
                }
            }
        }
    }
}
$storageInfo