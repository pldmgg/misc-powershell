# 1) Temporarily allow scripts for this PowerShell window
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Unrestricted -Force

# 2) Install RSAT Active Directory module (Windows 10/11, build 1809+)
Add-WindowsCapability -Online -Name RSAT:ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# 3) Load the module (safe to run even if it auto-loads)
Import-Module ActiveDirectory -ErrorAction Stop

# 4) Show the Domain Controller that authenticated the current user
$env:LOGONSERVER

# 5) (Optional) Show additional DC details for your domain
try {
    $domain = (Get-ADDomain).DNSRoot
    Get-ADDomain
    Write-Host "`nRunning nltest..." -ForegroundColor Cyan
    nltest /dsgetdc:$domain
} catch {
    Write-Host "`n(Optional details skipped—couldn't read domain info.)"
}
