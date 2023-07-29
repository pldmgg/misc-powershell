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

# Set Execution Policy to RemoteSigned so that scripts created locally can run
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`""

# Set profle.ps1
# The below line at the top of profile.ps1 ensures that $env:Path does not have any repeated entries
#The final line within profile.ps1 looks like - $env:Path = ($env:Path -split ';' | Sort-Object | Get-Unique) -join ';'
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "cmd /c echo `"```$env:Path = (```$env:Path -split ';' | Sort-Object | Get-Unique) -join ';'`" > C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1; (Get-Content C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1).Trim('`"') | Out-File C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"

# Enable ICMP Ping
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -Enabled True`""

# Set Timezone
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Get-TimeZone -Id 'Eastern Standard Time' | Set-TimeZone`""

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

# Since we are using winget below, we need to login manually and run winget to accept the EULA
ssh -i $SSHPrivateKeyPath $SSHUserAndHost
winget search Microsoft.PowerShell

# Use winget to install pwsh, chrome, nomachine, vmware player, and hyper-v
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install Microsoft.PowerShell`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install Google.Chrome`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install NoMachine.NoMachine`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"winget install VMware.WorkstationPlayer`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart; Restart-Computer -Force`""

# Get LastBootTime to ensure that the machine has rebooted after enabling Hyper-V
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`""

# Install Chocolatey
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))`""
# Update Environment Variables to access Chocolatey bin path
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\ProgramData\chocolatey\bin'), 'Machine')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'Machine')).Trim(';') + ';C:\ProgramData\chocolatey\bin'), 'Machine'); [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'Machine')).Trim(';') + ';C:\ProgramData\chocolatey\lib'), 'Machine')`""
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'User') + ';C:\ProgramData\chocolatey\bin'), 'User')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'User')).Trim(';') + ';C:\ProgramData\chocolatey\bin'), 'User'); [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'User')).Trim(';') + ';C:\ProgramData\chocolatey\lib'), 'User')`""

# Use Chocolatey to install VSCode, nano and veeam-agent
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install lockhunter -y`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install vscode -y`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install nano -y`""
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"choco install veeam-agent -y`""

# Restart the machine because a few of the above installs require a reboot
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Restart-Computer -Force`""

# Get LastBootTime to ensure that the machine has rebooted after installing veeam-agent
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"(Get-CimInstance Win32_OperatingSystem).LastBootUpTime`""

# Enable RDP
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0`""
# Disable RDP via
# ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1`""

# IMPORTANT NOTE: For some reason the installer fails unless it thinks you're logged into a GUI session
mstsc /v:$RemoteIPAddress
wsl --install
Restart-Computer -Force
#winget install -e --id Canonical.Ubuntu.2204
mstsc /v:$RemoteIPAddress
# Just wait for wsl to pop open a window to finish the install
wsl
sudo apt update && sudo apt upgrade -y
sudo apt install openssh-server -y
sudo sed -i -E 's,^#?Port.*$,Port 2222,' /etc/ssh/sshd_config
sudo service ssh restart
sudo sh -c "echo '${USER} ALL=(root) NOPASSWD: /usr/sbin/service ssh start' >/etc/sudoers.d/service-ssh-start"
exit
# Now you should be back in powershell on the remote host within an RDP session
# Allow ssh traffic on port 2222
New-NetFirewallRule -Name wsl_sshd -DisplayName 'OpenSSH Server (sshd) for WSL' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 2222
# Now we want to create a scheduled task that will start WSL AND ssh within WSL on boot
$ScriptOutputPath = "C:\Scripts\bin\wsl_sshd.ps1"
$ScriptContentAsString = @'
# Start SSH service in WSL
bash.exe -c "sudo /usr/sbin/service ssh start"

# Remove port proxy rule
netsh.exe interface portproxy delete v4tov4 listenport=2222 listenaddress=0.0.0.0 protocol=tcp

# Get IP address from WSL
$IP = (wsl.exe hostname -I).Trim()

# Add port proxy rule with the obtained IP address
netsh.exe interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=2222 connectaddress=$IP

'@
$TaskName = "Start WSL SSHD on Boot"
$TaskUser = "ttadmin"
$ScriptContentAsString | Out-File -FilePath $ScriptOutputPath -Encoding ascii -Force
$TenSecondsFromNow = $(Get-Date).Add($(New-TimeSpan -Seconds 10))
$TaskTrigger = New-ScheduledTaskTrigger -AtStartup
$Options = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -WakeToRun -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit $(New-TimeSpan -Hours 1)
$Passwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt "Enter password" -AsSecureString)))
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& $ScriptOutputPath`""
Register-ScheduledTask -TaskName $TaskName -Trigger $TaskTrigger -Settings $Options -User $TaskUser -Password $Passwd -Action $Action -ErrorAction Stop


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
  ModuleDir = "C:\Scripts\powershell"
  SSHPrivateKeyPath = $SSHPrivateKeyPath
  NetworkInterfaceAlias = "ZeroTier One [$ZTNetworkID]"
  TaskUser = "ttadminbackup"
  TTYDWebUser = "ttydadmin"
  TTYDWebPassword = "MyP@ssword123!"
}
Create-RemoteTTYDScheduledTask @CreateRemoteSchdTaskParams

Import-Module "$ScriptsDir\powershell\MiniServeModule.psm1"
# Make sure you have miniserve.exe on the local workstation
$NetworkInterfaceAlias = "ZeroTier One [$ZTNetworkID]"
Install-MiniServe -NetworkInterfaceAlias $NetworkInterfaceAlias
$PromptSSParams = @{
    RemoteUserName = $RemoteUserName
    RemoteIPAddress = $RemoteIPAddress
    SSHPrivateKeyPath = $SSHPrivateKeyPath
    MiniServeNetworkInterfaceAlias = $NetworkInterfaceAlias
    RemovePwdFile = $False
}
$UserString = Prompt-ActiveUserForSecureString @PromptSSParams
