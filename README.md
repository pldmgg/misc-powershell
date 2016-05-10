# misc-powershell
Miscellaneous PowerShell Scripts

Contents:

1) Get-AllDiskInfo.ps1
SYNOPSIS
    This script along with the Get-AllDiskInfo function (at the end) attempts to provide all disk information for the localhost in a way that ties Disk, Partition, and Volume information together ***in one output***.
DESCRIPTION
    At first glance, it may seem that more recent PowerShell cmdlets (and even just diskpart) already fulfill this need.  However, all newer PowerShell cmdlets that I have explored fail to tie Disk, Partition, and Volume information together ***in the same output***
    
    This script/function also provides the ability to create hashtables and PSObjects based on Disk/Partition for easier extensibility.
    
    This script/function is compatible with ***all*** versions of PowerShell, since, ultimately, it is all based on diskpart output.
    
2) XXXXXXXX

