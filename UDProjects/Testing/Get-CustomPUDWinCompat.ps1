function Get-CustomPUD {
    Param (
        [Parameter(Mandatory=$True)]
        [string]$DomainName,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True
    )

    ### BEGIN Helper Functions ###

    # The below AddwinRMTrustLocalHost function is needed for PSCore Compatibility with the Resolve-DNSName cmdlet
    function AddWinRMTrustLocalHost {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$False)]
            [string]$NewRemoteHost = "localhost"
        )
    
        # Make sure WinRM in Enabled and Running on $env:ComputerName
        try {
            $null = Enable-PSRemoting -Force -ErrorAction Stop
        }
        catch {
            if ($PSVersionTable.PSEdition -eq "Core") {
                Import-WinModule NetConnection
            }
    
            $NICsWPublicProfile = @(Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 0})
            if ($NICsWPublicProfile.Count -gt 0) {
                foreach ($Nic in $NICsWPublicProfile) {
                    Set-NetConnectionProfile -InterfaceIndex $Nic.InterfaceIndex -NetworkCategory 'Private'
                }
            }
    
            try {
                $null = Enable-PSRemoting -Force
            }
            catch {
                Write-Error $_
                Write-Error "Problem with Enable-PSRemoting WinRM Quick Config! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
        if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
            $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
        }
    
        # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
        $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','
    
        $HostsToAddToWSMANTrustedHosts = @($NewRemoteHost)
        foreach ($HostItem in $HostsToAddToWSMANTrustedHosts) {
            if ($CurrentTrustedHostsAsArray -notcontains $HostItem) {
                $null = $CurrentTrustedHostsAsArray.Add($HostItem)
            }
            else {
                Write-Warning "Current WinRM Trusted Hosts Config already includes $HostItem"
                return
            }
        }
        $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
    }

    ### END Helper FUnctions ###

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Make sure we can resolve the $DomainName
    try {
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {Install-Module WindowsCompatibility}
        if (![bool]$(Get-Module WindowsCompatibility)) {Import-Module WindowsCompatibility}
        AddWinRMTrustLocalHost -WarningAction SilentlyContinue
        Import-WinModule DnsClient
    }

    # Get all Computers in Active Directory without the ActiveDirectory Module
    $LDAPRootEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$DomainName")
    $LDAPSearcher = [System.DirectoryServices.DirectorySearcher]::new($LDAPRootEntry)
    $LDAPSearcher.Filter = "(objectClass=computer)"
    $LDAPSearcher.SizeLimit = 0
    $LDAPSearcher.PageSize = 250
    $null = $LDAPSearcher.PropertiesToLoad.Add("name")
    [System.Collections.ArrayList]$ServerList = $($LDAPSearcher.FindAll().Properties.GetEnumerator()).name

    # Create some Pages
    $HomePageContent = New-UDLayout -Columns 3 -Content {
        New-UDCard -Title "Server Reports" -Id "SRCard" -Text "Get Basic Info About Servers" -Links @(
            New-UDLink -Text "Server Reports" -Url "/ServerReports" -Icon book
        )

        New-UDCard -Title "Employee Contacts" -Id "ECCard" -Text "Get Contact Info" -Links @(
            New-UDLink -Text "Employee Contacts" -Url "/ContactInfo" -Icon address_book
        )

        New-UDCard -Title "Metrics" -Id "MCard" -Text "Metrics" -Links @(
            New-UDLink -Text "Metrics" -Url "/Metrics" -Icon bullseye
        )
    }
    $HomePage = New-UDPage -Name "Home" -Icon home -Content {$HomePageContent}

    $ServerReportingPage = New-UDPage -Name "ServerReports" -Icon book -Content {
        New-UDInput -Title "Server Report Form" -Id "Form" -Content {
            $ServerList.Insert(0,"Please Select a Server")
            New-UDInputField -Type 'select' -Name 'Server' -Placeholder 'Select Server For Report' -Values $ServerList
        } -Endpoint {
            param($Server)

            [System.Collections.ArrayList]$SubmitButtonActions = @()

            # Output a Grid with the data from Resolve-DNSName
            $DNSInfoProperties = @("Name","Type","TTL","Section","IPAddress")
            $ResolveDNSGrid = New-UdGrid -Title "DNSInfo" -Headers $DNSInfoProperties -Properties $DNSInfoProperties -Endpoint {
                $ResultPrep = Resolve-DNSName $Server | Select-Object -Property $DNSInfoProperties -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
                $ResultPrep | Out-UDGridData
            }
            $SubmitButtonActions.Add($ResolveDNSGrid)

            # Output a Grid with data from Get-Process
            $ProcessInfoProperties = @("Name","Id","UserName","SessionId","StartTime","CPU","PagedMemorySize")
            $GetProcessGrid = New-UdGrid -Title "ProcessInfo" -Headers $ProcessInfoProperties -Properties $ProcessInfoProperties -Endpoint {
                $ResultPrep = Invoke-Command -ComputerName $Server -ScriptBlock {
                    Get-Process -IncludeUserName
                } -HideComputerName | Select-Object -Property $ProcessInfoProperties -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
                $ResultPrep | Out-UDGridData
            }
            $SubmitButtonActions.Add($GetProcessGrid)

            # Output a Chart Displaying Drive Space Info
            $DiskSpaceChart = New-UdChart -Title "DiskInfo" -Type Bar -Endpoint {
                $ResultPrep = Get-CimInstance -ComputerName $Server -ClassName Win32_LogicalDisk | foreach {
                    $Size = [Math]::Round($_.Size / 1GB, 2)
                    $FreeSpace = [Math]::Round($_.FreeSpace / 1GB, 2)
                    $UsedSpace = $Size - $FreeSpace

                    [PSCustomObject]@{
                        DeviceId = $_.DeviceID
                        Size = $Size
                        FreeSpace = $FreeSpace
                        UsedSpace = $UsedSpace
                    }
                } | Select-Object -Property DeviceId,Size,FreeSpace,UsedSpace -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
                
                $ResultPrep | Out-UDChartData -LabelProperty "DeviceID" -Dataset @(
                    New-UdChartDataset -DataProperty "Size" -Label "Size" -BackgroundColor "#80962F23" -HoverBackgroundColor "#80962F23"
                    New-UdChartDataset -DataProperty "FreeSpace" -Label "Free Space" -BackgroundColor "#8014558C" -HoverBackgroundColor "#8014558C"
                    New-UdChartDataset -DataProperty "UsedSpace" -Label "Used Space" -BackgroundColor "#85f29c" -HoverBackgroundColor "#35f45e"
                )             
            }
            $SubmitButtonActions.Add($DiskSpaceChart)

            New-UDInputAction -Content $SubmitButtonActions
        }
    }

    $ContactsPage = New-UDPage -Name "ContactInfo" -Icon home -Content {
        New-UDCard -Title "Employee Contacts" -Id "ECCard" -Text "Get Contact Info"
    }

    $MetricsPage = New-UDPage -Name "Metrics" -Icon home -Content {
        New-UDCard -Title "Metrics" -Id "MCard" -Text "Metrics"
    }
    
    # Finalize the Site
    $MyDashboard = New-UDDashboard -Pages @($HomePage,$ServerReportingPage,$ContactsPage,$MetricsPage)

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUV3V7vnFjA+TrMuQ5qYZdtfND
# wtOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMIdh03cFtwbkXwb
# sMnBsV+zZ8wpMA0GCSqGSIb3DQEBAQUABIIBAGUzUA5huHKon6RzUuaPlruwyrwS
# XeKQQ4UwXmVCIBTI8yqlvaPCBw4BddyiClJiGI05BQ1qoyjW2yZohMG4OcV3YZyq
# cLL5R4Xf4KVUXXKYR1hXdKE0DYT/wXKcytwDGOHF2MbjQHpLAVs9pJHHRdFaQ4NV
# sR64DSFIVCDKwsxvQ5qSY2v7pWo3YOGLio29W3nuhraDl65dxBYgN3w9pCSXc2SX
# 1RyTDCSfGZuW84WlsFyC2+VU47Nx8Xt6jOvHy7WVORHOqpF3sNo78BaIquzU05Jc
# Tek19txLuY6i4a2uXBBnK9hP7Msc1dPY4kncgWmZHE4584rc9t1HdkbPGsM=
# SIG # End signature block
