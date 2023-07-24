# Bootstrap new Windows Workstation
# You Just need to have SSHD installed and running on the remote host and default shell must be powershell.exe
# To get SSHD installed, on the new Windows 11 machine, lauch Powershell as admin and run the following command:
# Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyScripts/Install-SSHD.ps1'))

# Next, from your local workstation, run:
$ScriptsDir = "C:\Scripts"
@("$ScriptsDir\temp", "$ScriptsDir\logs", "$ScriptsDir\bin", "$ScriptsDir\powershell") | foreach {
    if (!(Test-Path $_)) {
        $null = New-Item -Path $_ -ItemType Directory -Force
    }
}

$ModuleBaseUri = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyModules"
$ScriptsBaseUri = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyScripts"
@(
  "$ModuleBaseUri/BootstrapRemoteHost.psm1"
  "$ModuleBaseUri/MiniServeModule.psm1"
  "$ModuleBaseUri/TTYDModule.psm1"
  "$ScriptsBaseUri/Install-ZeroTier.ps1"
  ) | foreach {
    if (!(Test-Path "$ScriptsDir\powershell\$(Split-Path $_ -Leaf)")) {
        $null = Invoke-WebRequest -Uri $_ -OutFile "$ScriptsDir\powershell\$(Split-Path $_ -Leaf)"
    }
}

Import-Module "$ScriptsDir\powershell\BootstrapRemoteHost.psm1"
$RemoteIPAddress = "192.168.2.44"
$RemoteUserName = "adminuser"
$SSHUserAndHost = $RemoteUserName + "@" + $RemoteIPAddress
$SSHPrivateKeyPath = "C:\Users\adminuser\.ssh\id_rsa_for_remote_commands"
$SSHPublicKeyPath = $SSHPrivateKeyPath + ".pub"
Invoke-ScaffoldingOnRemoteHost -RemoteUserName $RemoteUserName -RemoteIPAddress $RemoteIPAddress

$SendKeyParams = @{
    RemoteUserName = $RemoteUserName
    RemoteIPAddress = $RemoteIPAddress
    SSHPrivateKeyPath = $SSHPrivateKeyPath
    SSHPublicKeyPath = $SSHPublicKeyPath
}
Send-SSHKeyToRemoteHost @SendKeyParams

# Install ZeroTier
$ZTScriptPath = "$ScriptsDir\powershell\Install-ZeroTier.ps1"
$ZTNetworkID = '8bkp1rxn07zvy5tfh'
$ZTToken = 'aB8jG4uWxP5yDc2rL3FqV6ZtH7E9sK1M'
$SCPRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress + ':' + $ZTScriptPath
scp.exe -i $SSHPrivateKeyPath $ZTScriptPath $SCPRemoteLocationString
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"& $ZTScriptPath -NetworkID $ZTNetworkID -Token $ZTToken`""

# Disable Bitlocker and Decrypt on ALL Volumes
#Disable-BitLocker -MountPoint (Get-BitLockerVolume) -Confirm:$false
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Disable-BitLocker -MountPoint (Get-BitLockerVolume) -Confirm:```$false`""

# Use winget to install pwsh, chrome, nomachine, vmware player, and hyper-v
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install Microsoft.PowerShell`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install Google.Chrome`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install NoMachine.NoMachine`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install VMware.WorkstationPlayer`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`""

# Install Chocolatey
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`""
# Update Environment Variables to access Chocolatey bin path
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\ProgramData\chocolatey\bin'), 'Machine')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\ProgramData\chocolatey\bin'), 'Machine')`""
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'User') + ';C:\ProgramData\chocolatey\bin'), 'User')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'User') + ';C:\ProgramData\chocolatey\bin'), 'User')`""

# Use Chocolatey to install VSCode, nano and veeam-agent
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install vscode`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install nano`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install veeam-agent`""

# Restart the machine because a few of the above installs require a reboot
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Restart-Computer -Force`""

# Use NoMachine to login to the remote host and install Canonical.Ubuntu.2204 (wsl2 environment) via winget
# IMPORTANT NOTE: For some reason the installer fails unless it thinks you're logged into console session
winget install -e --id Canonical.Ubuntu.2204

# Optionally Install Windows Subsystem for Android
# DOESN'T WORK: ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install --silent --exact --id=9P3395VX91NR -e --accept-package-agreements --accept-source-agreements`""
#Invoke-WebRequest -uri 'http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/862fe146-d265-4305-9951-f8c5983f427d?P1=1689726418&P2=404&P3=2&P4=mHD%2fatoZ49xCdHZMGnivAxQwc0j86RlROyiL2pMGxg0%2fb6ezs9lPQYFHzQTTPcA9XkalD6focoDkR1%2bkSgKp2Q%3d%3d' -OutFile 'C:\Users\ttadmin\Downloads\windows_subsystem_for_android.msixbundle'
#dism.exe /Online /Add-ProvisionedAppxPackage /PackagePath:C:\Users\ttadmin\Downloads\windows_subsystem_for_android.msixbundle /SkipLicense
# NOTE: If the below $AppxUri doesn't work, you can get the latest version by navigating to https://store.rg-adguard.net/ and in the URL box, input: www.microsoft.com/en-us/p/windows-subsystem-for-android/9p3395vx91nr 
$AppxUri = 'http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/862fe146-d265-4305-9951-f8c5983f427d?P1=1689726418&P2=404&P3=2&P4=mHD%2fatoZ49xCdHZMGnivAxQwc0j86RlROyiL2pMGxg0%2fb6ezs9lPQYFHzQTTPcA9XkalD6focoDkR1%2bkSgKp2Q%3d%3d'
$OutFilePath = 'C:\Users\ttadmin\Downloads\windows_subsystem_for_android.msixbundle'
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "pwsh.exe -ExecutionPolicy Bypass -Command `"Invoke-WebRequest -uri '$AppxUri' -OutFile '$OutFilePath'; dism.exe /Online /Add-ProvisionedAppxPackage /PackagePath:$OutFilePath /SkipLicense`""

# Install TTYD and create scheduled task to run it as a specific user (i.e. the person who uses the PC most often)
$CreateRemoteSchdTaskParams = @{
  RemoteUserName = $RemoteUserName
  RemoteIPAddress = $RemoteIPAddress
  ModuleDir = "$ScriptsDir\powershell"
  SSHPrivateKeyPath = $SSHPrivateKeyPath
  NetworkInterfaceAlias = "ZeroTier One [8bkp1rxn07zvy5tfh]"
  TaskUser = "otheruser"
  TTYDWebUser = "ttydadmin"
  TTYDWebPassword = "ttydadmin_P@ssword123!"
}
Create-RemoteTTYDScheduledTask @CreateRemoteSchdTaskParams