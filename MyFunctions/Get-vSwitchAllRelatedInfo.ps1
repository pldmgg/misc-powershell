function Get-vSwitchAllRelatedInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$vSwitchName,

        [Parameter(Mandatory=$False)]
        [string]$InterfaceAlias,

        [Parameter(Mandatory=$False)]
        [string]$IPAddress,

        [Parameter(Mandatory=$False)]
        [string]$MacAddress,

        [Parameter(Mandatory=$False)]
        [string]$DeviceId
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters

    if (!$vSwitchName -and !$InterfaceAlias -and !$IPAddress -and !$MacAddress -and !$DeviceId) {
        Write-Error "The Get-vSwitchRelationship function requires at least one of the following parameters: -vSwitchName, -InterfaceAlias, -IPAddress, -MacAddress, -DeviceId or any combination thereof! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($IPAddress) {
        if (![bool]$(Test-IsValidIPAddress -IPAddress $IPAddress)) {
            Write-Error "$IPAddress is NOT a valid IPv4 IP Address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($DeviceId) {
        # The $DeviceId might have prefix '{' and trailing '}', so get rid of them
        if ($DeviceId.Substring(0,1) -eq '{') {
            $DeviceId = $DeviceId.TrimStart('{')
        }
        if ($DeviceId[-1] -eq '}') {
            $DeviceId = $DeviceId.TrimEnd('}')
        }
    }

    if ($MacAddress) {
        # Standardize MacAddress string format with dashes
        if ($MacAddress -notmatch "-") {
            $MacAddress = $($MacAddress -split "([\w]{2})" | Where-Object {$_ -match "[\w]"}) -join '-'
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Try to get $DetailedvSwitchInfo...

    [System.Collections.ArrayList]$DetailedvSwitchInfoPSObjects = @()

    if ($BoundParametersDictionary["vSwitchName"]) {
        try {
            $DetailedvSwitchInfoViavSwitchName = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.SwitchName -eq $vSwitchName}
            if (!$DetailedvSwitchInfoViavSwitchName) {
                throw "Unable to find a vSwitch with the name $vSwitchName! Halting!"
            }
            if ($DetailedvSwitchInfoViavSwitchName.Count -gt 1) {
                throw "Multiple vSwitches with the same name (i.e. $vSwitchName)! Halting!"
            }

            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViavSwitchName.SwitchName
            $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViavSwitchName.MacAddress}
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $vSwitchNamePSObject = @{
                ParameterUsed           = "vSwitchName"
                DetailedvSwitchInfo     = $DetailedvSwitchInfoViavSwitchName
            }

            $null = $DetailedvSwitchInfoPSObjects.Add($vSwitchNamePSObject)
        }
        catch {
            if (!$DetailedvSwitchInfoViavSwitchName -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a vSwitch with the name $vSwitchName!"
                $BadvSwitchNameProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["InterfaceAlias"]) {
        try {
            $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $InterfaceAlias -ErrorAction Stop
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS
            $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''
            $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

            if (!$DetailedvSwitchInfoViaIPAddress) {
                throw
            }
            else {
                $InterfaceAliasPSObject = @{
                    ParameterUsed           = "InterfaceAlias"
                    DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                }

                $null = $DetailedvSwitchInfoPSObjects.Add($InterfaceAliasPSObject)
            }
        }
        catch {
            if (!$DetailedvSwitchInfoViaIPAddress -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a Network Adapter with the InterfaceAlias name $InterfaceAlias!"
                $BadvInterfaceAliasProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["IPAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS

                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $IPAddress -ErrorAction SilentlyContinue -ErrorVariable GNIPErr
                if (!$IPAddressInfo -or $GNIPErr) {throw}
                $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $IPAddressInfo.InterfaceAlias
                $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''

                $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

                if (!$DetailedvSwitchInfoViaIPAddress) {
                    throw
                }
                else {
                    $IPAddressPSObject = @{
                        ParameterUsed           = "IPAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($IPAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a vSwitch with the IP Address $IPAddress!"
                    $BadIPAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a vSwitch with the IP Address $IPAddress! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["DeviceId"]) {
        if(!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaDeviceId = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.DeviceId -eq "{$DeviceId}"}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaDeviceId.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaDeviceId.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaDeviceId) {
                    throw
                }
                else {
                    $DeviceIdPSObject = @{
                        ParameterUsed           = "DeviceId"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaDeviceId
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($DeviceIdPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId!"
                    $BadDeviceIdProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["MacAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaMacAddress = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.MacAddress -eq $($MacAddress -replace '-','')}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaMacAddress.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaMacAddress.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaMacAddress) {
                    throw
                }
                else {
                    $MacAddressPSObject = @{
                        ParameterUsed           = "MacAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaMacAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($MacAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $BadMacAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    # If we still DO NOT have $DetailedvSwitchInfoViaXXXXX one way or another, then halt
    if ($DetailedvSwitchInfoPSObjects.Count -eq 0) {
        Write-Error "Unable to find a Device using any of the parameters provided! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Start comparing each of the $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo objects to see
    # which $DetailedvSwitchInfoPSObjects.ParameterUsed get consensus for the the proper target Device.
    # Group by MacAddress and select the highest Count
    $GroupByMacAddress = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Group-Object -Property MacAddress
    # It's possible that the number of parameters referencing one device equal the number of parameters that
    # reference another device. If that happens, we need to ask the user which one they want.
    if ($GroupByMacAddress.Count -gt 1) {
        if ($($GroupByMacAddress | Select-Object -ExpandProperty Count | Sort-Object | Get-Unique).Count -eq 1) {
            Write-Warning "Unable to get consensus on which Device should be targeted!"
            
            [System.Collections.ArrayList]$DeviceOptionsPSObjects = @()
            foreach ($item in $($GroupByMacAddress.Group | Sort-Object | Get-Unique)) {
                $SwitchName = $item.SwitchName
                $NetAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $item.MacAddress}
                $IPInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapterInfo.InterfaceAlias

                $OptionPSObject = [pscustomobject]@{
                    SwitchName         = $SwitchName
                    InterfaceAlias     = $NetAdapterInfo.InterfaceAlias
                    IPAddress          = $IPInfo.IPAddress
                    MacAddress         = $item.MacAddress
                }

                $null = $DeviceOptionsPSObjects.Add($OptionPSObject)
            }

            Write-Host "`nPotential matching Devices are as follows:`n"
            for ($i=0; $i -lt $DeviceOptionsPSObjects.Count; $i++) {
                $WriteHostString = "$i) vSwitchName: $($DeviceOptionsPSObjects[$i].SwitchName); " +
                "NetworkAdapterAlias: $($DeviceOptionsPSObjects[$i].InterfaceAlias); " +
                "IPAddress: $($DeviceOptionsPSObjects[$i].IPAddress); " +
                "MacAddress: $($DeviceOptionsPSObjects[$i].MacAddress)"
                Write-Host $WriteHostString
            }
            
            $ValidChoiceNumbers = 0..$($DeviceOptionsPSObjects.Count-1)
            Write-Host ""
            $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            while ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
                Write-Host "$ChoiceNumber is NOT a valid choice number! Valid options are: $($ValidChoiceNumbers -join ', ')"
                $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            }

            $MacAddressThatAppearsMostOften = $DeviceOptionsPSObjects[$ChoiceNumber].MacAddress
        }
    }
    else {
        $MacAddressThatAppearsMostOften = $($GroupByMacAddress | Sort-Object -Property Count)[-1].Name
    }

    [Array]$FinalDetailedvSwitchInfoPrep = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Where-Object {$_.MacAddress -eq $MacAddressThatAppearsMostOften}
    # Just choose one to use since they're all the same...
    $FinalDetailedvSwitchInfo = $FinalDetailedvSwitchInfoPrep[0]
    $FinalBasicvSwitchInfo = Get-VMSwitch -Name $FinalDetailedvSwitchInfo.SwitchName
    $FinalNetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $FinalDetailedvSwitchInfo.MacAddress}
    $FinalIPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $FinalNetworkAdapterInfo.InterfaceAlias

    # Describe Parameters that WERE used in Final Output and Parameters that were IGNORED in Final Output
    [System.Collections.ArrayList][Array]$ParametersUsedToGenerateOutput = $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -eq $MacAddressThatAppearsMostOften}).ParameterUsed
    [System.Collections.ArrayList]$ParametersIgnoredToGenerateOutput = @()
    $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -ne $MacAddressThatAppearsMostOften}).ParameterUsed | foreach {
        if ($_ -ne $null) {
            $null = $ParametersIgnoredToGenerateOutput.Add($_)
        }
    }
    
    if ($BadvSwitchNameProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("vSwitchName")
    }
    if ($BadvInterfaceAliasProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("InterfaceAlias")
    }
    if ($BadIPAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("IPAddress")
    }
    if ($BadDeviceIdProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("DeviceId")
    }
    if ($BadMacAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("MacAddress")
    }

    [pscustomobject]@{
        MacAddress                          = $FinalDetailedvSwitchInfo.MacAddress
        BasicvSwitchInfo                    = $FinalBasicvSwitchInfo
        DetailedvSwitchInfo                 = $FinalDetailedvSwitchInfo
        NetworkAdapterInfo                  = $FinalNetworkAdapterInfo
        IPAddressInfo                       = $FinalIPAddressInfo
        ParametersUsedToGenerateOutput      = $ParametersUsedToGenerateOutput
        ParametersIgnoredToGenerateOutput   = $ParametersIgnoredToGenerateOutput
        NonExistentvSwitchNameProvided      = if ($BadvSwitchNameProvided) {$True} else {$False}
        NonExistentIPAddressProvided        = if ($BadIPAddressProvided) {$True} else {$False}
        NonExistentMacAddressProvided       = if ($BadMacAddressProvided) {$True} else {$False}
        NonExistentDeviceIdProvided         = if ($BadDeviceIdProvided) {$True} else {$False}
    }

    ##### END Main Body #####
    #>
}













# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgeTgMsr1N2j2YGLlikjvoDpY
# CsOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLFNh5eDKO32Ajm9
# 5t9f4U4Nz8DwMA0GCSqGSIb3DQEBAQUABIIBAHEXjdKfvhHSUHjjrh+rLnet6gpz
# F5KkJnUWrf/GAlMyNykaqOs1YRF8pFbuiXxBgG3vJgHoq5AZRkAXGbP3Xg9+HryC
# OroTnfCPve/KsXt1SAOZucd20qjbdXqFOhNVSOFb/1Ob/ohDuin0GAfRG5PW8SZu
# d31BAc/BNeh7d610ZcuGt3/NX5nBM0PzP2y4TC8drLMr6vxekBF3H/YZN+3rwrhO
# S82BKCMfT3J0zOTjtqXXqM4HfD1LwQBmyNO6txa+78jGKURwGh2d7bXg8G4dajcc
# NxM/XLNqzvZ5l9Y+cJ7hwFdDtzX8gJqhbk9oLPCl2mnU4BpSRBzTBkNseJA=
# SIG # End signature block
