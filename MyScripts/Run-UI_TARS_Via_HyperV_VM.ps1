<# 
.SYNOPSIS
  Enable Hyper-V, ensure Vagrant is installed, and deploy a ready-to-use Windows 11 VM
  from HashiCorp Vagrant Cloud (Hyper-V provider). Creates an extra local admin account
  inside the guest so it’s ready to RDP.

.NOTES
  - Fix: Vagrantfile provisioning block now uses a single-quoted heredoc to avoid Ruby escape issues.
  - Defaults: project folder C:\Vagrant\win11, switch "Default Switch", 4 vCPUs, 8 GB RAM.
#>

[CmdletBinding()]
param(
  [string]$ProjectRoot = "C:\Vagrant\win11",
  [string]$VmUser = "devuser",
  [string]$VmPassword,
  [string]$SwitchName = "Default Switch",
  [int]$MemoryGB = 8,
  [int]$CPUs = 4
)

#-------------------- Helpers --------------------
function Assert-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) { throw "Run this script in an elevated PowerShell (Run as Administrator)." }
}

function Assert-Edition {
  $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
  if ($edition -match 'Core') {
    throw "Hyper-V isn’t supported on Windows Home (EditionID=$edition). Use Pro/Enterprise/Education."
  }
}

function Enable-HyperV {
  Write-Host "Enabling Hyper-V (this may require a reboot)..." -ForegroundColor Cyan
  $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
  if ($feature.State -ne 'Enabled') {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Tools-All -All -NoRestart | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell -All -NoRestart | Out-Null
    Write-Warning "Hyper-V enabled. Restarting..."
    Restart-Computer -Force
  } else {
    Write-Host "Hyper-V already enabled." -ForegroundColor Green
  }
}

function Ensure-Choco {
  if (Get-Command choco -ErrorAction SilentlyContinue) { return }
  Write-Host "Installing Chocolatey..." -ForegroundColor Cyan
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'Machine')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'Machine')
  [Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'User')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'User')
}

function Install-VagrantIfMissing {
  if (Get-Command vagrant -ErrorAction SilentlyContinue) { return }

  # Try winget first
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "Installing Vagrant via winget..." -ForegroundColor Cyan
    try {
      winget install --id HashiCorp.Vagrant --accept-source-agreements
    } catch { }
  }

  Ensure-Choco
  refreshenv # provided by Chocolatey; otherwise open a new shell

  <#
  if (-not (Get-Command vagrant -ErrorAction SilentlyContinue)) {
    # Fallback to MSI direct install
    $ver = "2.4.9"
    $msiUrl = "https://releases.hashicorp.com/vagrant/$ver/vagrant_${ver}_windows_amd64.msi"
    $msi = Join-Path $env:TEMP "vagrant_${ver}_windows_amd64.msi"
    Write-Host "Downloading Vagrant $ver MSI..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $msiUrl -OutFile $msi -UseBasicParsing
    Start-Process msiexec.exe -Wait -ArgumentList "/i `"$msi`" /qn /norestart"
    # Make sure current process can see it
    $vagrantBin = "C:\HashiCorp\Vagrant\bin"
    if (Test-Path $vagrantBin) { $env:PATH = "$env:PATH;$vagrantBin" }
  }
#>

  if (-not (Get-Command vagrant -ErrorAction SilentlyContinue)) {
    throw "Vagrant not found after install. Open a new elevated PowerShell and try again."
  }
}

function Get-VagrantBoxWithHyperV {
  # Prefer reputable Windows 11 boxes with Hyper-V provider
  $candidates = @(
    "rgl/windows-11-24h2",
    "rgl/windows-11",
    "gusztavvargadr/windows-11",
    "peru/windows-11-enterprise-x64-eval"
  )

  foreach ($slug in $candidates) {
    try {
      $info = Invoke-RestMethod -Method GET -Uri ("https://app.vagrantup.com/api/v2/box/$slug") -ErrorAction Stop
      foreach ($ver in $info.versions) {
        if ($ver.providers.name -contains "hyperv") { return $slug }
      }
    } catch { }
  }
  return $null
}

function New-RandomPassword {
  param([int]$Length = 18)
  $charsUpper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
  $charsLower = "abcdefghijkmnopqrstuvwxyz"
  $digits = "23456789"
  $symbols = "!@#$%^&*()-_=+[]{}"
  $all = ($charsUpper + $charsLower + $digits + $symbols).ToCharArray()
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $bytes = New-Object byte[] ($Length)
  $rng.GetBytes($bytes)
  $pwd = -join ($bytes | ForEach-Object { $all[ $_ % $all.Length ] })
  $pwdChars = $pwd.ToCharArray()
  $pwdChars[0] = $charsUpper[(Get-Random -Min 0 -Max $charsUpper.Length)]
  $pwdChars[1] = $charsLower[(Get-Random -Min 0 -Max $charsLower.Length)]
  $pwdChars[2] = $digits[(Get-Random -Min 0 -Max $digits.Length)]
  $pwdChars[3] = $symbols[(Get-Random -Min 0 -Max $symbols.Length)]
  -join $pwdChars
}


function Invoke-HfEndpointTools {
<#
.SYNOPSIS
  Hugging Face Inference Endpoints helper (list/get/export) as a reusable function.

.DESCRIPTION
  Wraps the Hugging Face control-plane API:
    - list   : list endpoints in a namespace
    - get    : get one endpoint (pretty or raw JSON/object)
    - export : save raw endpoint JSON to a file

.PARAMETER Command
  One of: list, get, export

.PARAMETER Namespace
  HF owner/namespace (e.g., pldmgg)

.PARAMETER Name
  Endpoint name (required for get/export)

.PARAMETER Token
  HF token. Falls back to $env:HF_TOKEN if omitted.

.PARAMETER Json
  For list/get: return raw JSON (string). By default returns objects; with -Pretty prints human-readable text.

.PARAMETER Pretty
  For list/get: print a friendly, human-readable summary.

.PARAMETER Out
  For export: path to write endpoint JSON.

.EXAMPLES
  Invoke-HfEndpointTools -Command list -Namespace pldmgg
  Invoke-HfEndpointTools -Command get -Namespace pldmgg -Name ui-tars-1-5-7b-clt -Pretty
  Invoke-HfEndpointTools -Command get -Namespace pldmgg -Name ui-tars-1-5-7b-clt -Json
  Invoke-HfEndpointTools -Command export -Namespace pldmgg -Name ui-tars-1-5-7b-clt -Out .\endpoint.json

.NOTES
  Control plane base URL: https://api.endpoints.huggingface.cloud/v2
#>
  [CmdletBinding(DefaultParameterSetName='list')]
  param(
    [Parameter(Mandatory=$true, Position=0, ParameterSetName='list')]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName='get')]
    [Parameter(Mandatory=$true, Position=0, ParameterSetName='export')]
    [ValidateSet('list','get','export')]
    [string]$Command,

    [Parameter(Mandatory=$true)]
    [string]$Namespace,

    [Parameter(Mandatory=$false, ParameterSetName='get')]
    [Parameter(Mandatory=$false, ParameterSetName='export')]
    [string]$Name,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$false, ParameterSetName='list')]
    [Parameter(Mandatory=$false, ParameterSetName='get')]
    [switch]$Json,

    [Parameter(Mandatory=$false, ParameterSetName='list')]
    [Parameter(Mandatory=$false, ParameterSetName='get')]
    [switch]$Pretty,

    [Parameter(Mandatory=$true, ParameterSetName='export')]
    [string]$Out
  )

  $ErrorActionPreference = 'Stop'
  $Base  = 'https://api.endpoints.huggingface.cloud/v2'
  $Token = if ($Token) { $Token } elseif ($env:HF_TOKEN) { $env:HF_TOKEN } else {
    throw "No token provided. Set -Token or `$env:HF_TOKEN`."
  }

  function _Invoke-HfApi {
    param(
      [Parameter(Mandatory=$true)][ValidateSet('GET','POST','PUT','DELETE','PATCH')][string]$Method,
      [Parameter(Mandatory=$true)][string]$Path,   # e.g. "/endpoints?namespace=pldmgg"
      [Parameter()][hashtable]$Body
    )
    $uri = "$Base$Path"
    $headers = @{ 'Authorization' = "Bearer $Token" }
    if ($Body) {
      return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Depth 50)
    } else {
      return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
    }
  }

  switch ($Command) {
    'list' {
      $resp = _Invoke-HfApi -Method GET -Path "/endpoints?namespace=$Namespace"

      if ($Json) {
        # return raw JSON string (no console noise)
        return ($resp | ConvertTo-Json -Depth 50)
      }
      if ($Pretty) {
        if (-not $resp -or $resp.Count -eq 0) {
          Write-Host "(no endpoints found in namespace '$Namespace')"
          return
        }
        $resp | ForEach-Object {
          $name  = $_.name
          $state = $_.status.state
          $url   = $_.status.url
          if ([string]::IsNullOrWhiteSpace($url)) { $url = '—' }
          "{0,-30}  state={1,-10}  url={2}" -f $name, $state, $url
        } | Write-Output
        return
      }
      # Default: return objects (pipeline-friendly)
      return $resp
    }

    'get' {
      if (-not $Name) { throw "-Name is required for 'get'." }
      $resp = _Invoke-HfApi -Method GET -Path "/endpoints/$Namespace/$Name"

      if ($Json) {
        return ($resp | ConvertTo-Json -Depth 100)
      }
      if ($Pretty) {
        $model   = $resp.model
        $compute = $resp.compute
        $scale   = $compute.scaling
        Write-Host "Name:        $($resp.name)"
        Write-Host "Namespace:   $Namespace"
        Write-Host "State:       $($resp.status.state)"
        Write-Host "URL:         $($resp.status.url)"
        Write-Host ""
        Write-Host "Model"
        Write-Host ("  repository: {0}" -f $model.repository)
        Write-Host ("  revision:   {0}" -f $model.revision)
        Write-Host ("  task:       {0}" -f $model.task)
        Write-Host ""
        Write-Host "Compute"
        Write-Host ("  id:         {0}" -f $compute.id)
        Write-Host ("  accelerator:{0}" -f $compute.accelerator)
        Write-Host ("  instance:   {0} {1}" -f $compute.instanceType, $compute.instanceSize)
        Write-Host ""
        Write-Host "Scaling"
        Write-Host ("  min/max:    {0}/{1}" -f $scale.minReplica, $scale.maxReplica)
        Write-Host ("  scaleToZero:{0}s" -f $scale.scaleToZeroTimeout)
        return
      }
      # Default: return object
      return $resp
    }

    'export' {
      if (-not $Name) { throw "-Name is required for 'export'." }
      if (-not $Out)  { throw "-Out is required for 'export'." }

      $resp = _Invoke-HfApi -Method GET -Path "/endpoints/$Namespace/$Name"
      $json = $resp | ConvertTo-Json -Depth 100
      $dir  = Split-Path -Parent $Out
      if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
      Set-Content -Path $Out -Value $json -Encoding UTF8
      Write-Output "Wrote $Out"
      return
    }
  }
}


#-------------------- Main --------------------

# Gather Hugging Face info for UI-TARS
$powershellDir = "C:\Scripts\powershell"
$hfInfoPath = "$powershellDir\hf_info.xml"
if (-not (Test-Path $powershellDir)) {New-Item -ItemType Directory -Path $powershellDir -Force | Out-Null}
if (Test-Path $hfInfoPath) {
  try {
    $hf = Import-Clixml -Path $hfInfoPath
    if (-not $hf.HF_TOKEN -or -not $hf.HF_BaseURL -or -not $hf.HF_Username) {throw "Missing fields"}
    $HF_TOKEN    = $hf.HF_TOKEN
    $HF_BaseURL  = $hf.HF_BaseURL
    $HF_Username = $hf.HF_Username
  } catch {
    Write-Warning $_.Exception.Message
    $hf = $null
  }
}
if (-not $hf) {
  Write-Host @"
To use the HuggingFace endpoint for UI-TARS-1.5, you need to create a HuggingFace account
(if you don't have one)and set up an Inference Endpoint for the UI-TARS-1.5-7B model.

1. Sign up or log in to your HuggingFace account at https://huggingface.co/join

2. Go to the Inference Endpoints page: https://endpoints.huggingface.co/

3. Click on "+ New".

4. In the "Model" field, enter "ByteDance-Seed/UI-TARS-1.5-7B", select it from the dropdown, and click Configure

5. In the right-hand pane, select "Amazon Web Services" -> GPU -> East US us-east -> Nvidia A100 -> Scroll down and expand the Container Configuration section -> Max Input Length (per Query): 65536 -> Max Batch Prefill Tokens: 65536 -> Max Number of Tokens (per Query): 65537 -> Scroll down and expand the Environment Variable section -> Under Default Env add these 2 variables: CUDA_GRAPHS = 0 -> PAYLOAD_LIMIT = 8000000

6. Click "Create Endpoint" at the bottom of the page.

7. Once the endpoint is created, go to the "Settings" tab of your endpoint and make sure Container URI says something like: ghcr.io/huggingface/text-generation-inference:3.3.4

8. Go to your endpoint's Overview tab -> Look at the "Playground" section towards the bottom of the page -> Click on the "API" tab -> take note of the value for "base_url" which should look like https://{unique-id}.us-east-1.aws.endpoints.huggingface.cloud/v1/

9. Go to https://huggingface.co/settings/tokens -> Create new token -> Token type = Read -> Give it an arbitrary name -> click Create token -> take note of the value
"@ -ForegroundColor Yellow

  $HF_TOKEN = Read-Host "Enter your huggingface.co API Token (see https://huggingface.co/settings/tokens)"
  $HF_BaseURL = Read-Host "Enter your huggingface.co base_url (see https://endpoints.huggingface.co/)"
  $HF_Username = Read-Host "Enter your huggingface.co username (see https://huggingface.co/settings/account)"
  $hf = [pscustomobject]@{
    HF_TOKEN    = $HF_TOKEN
    HF_BaseURL  = $HF_BaseURL
    HF_Username = $HF_Username
  }
  $hf | Export-Clixml -Path $hfInfoPath -Force
}

Assert-Admin
Assert-Edition
Enable-HyperV
Install-VagrantIfMissing

Write-Host "Searching for a Windows 11 Vagrant box with Hyper-V provider..." -ForegroundColor Cyan
$boxSlug = Get-VagrantBoxWithHyperV
if (-not $boxSlug) {
  Write-Warning "Could not auto-discover a Windows 11 Hyper-V box; defaulting to 'rgl/windows-11-24h2'."
  $boxSlug = "rgl/windows-11-24h2"
} else {
  Write-Host "Selected box: $boxSlug" -ForegroundColor Green
}

# Pre-add the box (optional, speeds first 'vagrant up')
try {
  Write-Host "Adding Vagrant box $boxSlug (provider=hyperv)..." -ForegroundColor Cyan
  vagrant box add $boxSlug --provider hyperv --clean -c | Out-Null
} catch {
  Write-Warning "Pre-add failed; proceeding (Vagrant will download on 'vagrant up')."
}

# Ensure project folder
New-Item -ItemType Directory -Path $ProjectRoot -Force | Out-Null
Push-Location $ProjectRoot

# Decide password for extra admin
if (-not $VmPassword) {
  $VmPassword = New-RandomPassword
  "VM username: $VmUser`r`nVM password: $VmPassword" | Out-File -FilePath (Join-Path $ProjectRoot "vm-user.txt") -Encoding utf8 -Force
  Write-Host "Generated VM password saved to $ProjectRoot\vm-user.txt" -ForegroundColor Yellow
}

# Export env for Vagrantfile use
$env:VM_USER = $VmUser
$env:VM_PASS = $VmPassword
$env:HYPERV_SWITCH = $SwitchName
$env:VAGRANT_MEMORY_MB = ($MemoryGB * 1024)
$env:VAGRANT_CPUS = $CPUs
$env:BOX_SLUG = $boxSlug

# Write fixed Vagrantfile (no variable expansion in this PowerShell here-string)
$vagrantfile = @'
Vagrant.configure("2") do |config|
  # Box & Windows guest settings
  config.vm.box = ENV.fetch("BOX_SLUG", "rgl/windows-11-24h2")
  config.vm.guest = :windows
  config.vm.communicator = "winrm"
  config.winrm.username = "vagrant"
  config.winrm.password = "vagrant"
  config.vm.boot_timeout = 1800

  # Avoid SMB prompts on Windows hosts
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Hyper-V resources
  config.vm.provider "hyperv" do |h|
    h.vmname = "Win11-Dev"
    h.cpus   = (ENV["VAGRANT_CPUS"] || "4").to_i
    h.memory = (ENV["VAGRANT_MEMORY_MB"] || "8192").to_i
  end

  # Attach to a specific switch if provided (Default Switch is OK)
  if ENV["HYPERV_SWITCH"] && !ENV["HYPERV_SWITCH"].empty?
    config.vm.network "public_network", bridge: ENV["HYPERV_SWITCH"]
  end

  # Provision: create ready-to-use local admin and enable RDP
  user = ENV["VM_USER"] || "devuser"
  pass = ENV["VM_PASS"] || "TempP@ss321!"

  config.vm.provision "shell",
    name: "Create local admin",
    privileged: true,
    reboot: false,
    env: { "VM_USER" => user, "VM_PASS" => pass },
    inline: <<-'POWERSHELL'
      $ErrorActionPreference = 'Stop'
      $user = $env:VM_USER
      $pass = $env:VM_PASS | ConvertTo-SecureString -AsPlainText -Force

      if (-not (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $user -Password $pass -PasswordNeverExpires:$true
        Add-LocalGroupMember -Group 'Administrators' -Member $user
      }

      # Enable RDP for convenience
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
      netsh advfirewall firewall set rule group='remote desktop' new enable=Yes

      # Fix broken OpenSSH Server install in Windows guests
      Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Where-Object State -eq 'Installed' | Remove-WindowsCapability -Online
      Stop-Service sshd -ErrorAction SilentlyContinue
      Set-Service sshd -StartupType Disabled -ErrorAction SilentlyContinue
      Get-NetFirewallRule -DisplayName 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
      Remove-Item -Recurse -Force "$env:ProgramData\ssh" -ErrorAction SilentlyContinue

      Set-ExecutionPolicy Bypass -Scope Process -Force
      [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
      iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyScripts/Install-SSHD.ps1'))

      Set-NetFirewallRule -DisplayName "OpenSSH SSH Server (sshd)" -Profile Domain,Private,Public
    POWERSHELL
end
'@

Set-Content -Path (Join-Path $ProjectRoot "Vagrantfile") -Value $vagrantfile -Encoding UTF8

Write-Host "`nVagrantfile written to $ProjectRoot" -ForegroundColor Green
Write-Host "Bringing the VM up (first download is large; initial boot can be slow)..." -ForegroundColor Cyan

vagrant up --provider hyperv

Write-Host "`n✅ Done. Built-in: vagrant/vagrant. Extra admin: '$VmUser' (see vm-user.txt for the password)." -ForegroundColor Green
Write-Host "To connect: use Hyper-V Manager or run 'vagrant rdp' from $ProjectRoot." -ForegroundColor Green


#-------------------- Post-setup: SSH into the VM --------------------

# Now, get the VM's IP address and test SSH
$vm = "Win11-Dev"
$RemoteIPAddress = (Get-VMNetworkAdapter -VMName $vm).IPAddresses | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.*' } | Select-Object -First 1
$ScriptsDir = "C:\Scripts"
$powershellDir = Join-Path $ScriptsDir "powershell"
if (-not (Test-Path $powershellDir)) {New-Item -ItemType Directory -Path $powershellDir -Force | Out-Null}
$ModuleFile = "BootstrapRemoteHost.psm1"
$ModuleURL = "https://raw.githubusercontent.com/pldmgg/misc-powershell/refs/heads/master/MyModules/$ModuleFile"
$OutputPath = "$env:USERPROFILE\Downloads\$ModuleFile"
Invoke-WebRequest -Uri $ModuleURL -OutFile $OutputPath
Import-Module $OutputPath
$NewComputerName = "testpc2"
$RemoteUserName = "vagrant"
$SSHUserAndHost = $RemoteUserName + "@" + $RemoteIPAddress
$SSHPrivateKeyPath = "C:\Users\$($($HOME -split '\\')[-1])\.ssh\id_$($env:ComputerName)_to_$NewComputerName"
$SSHPublicKeyPath = $SSHPrivateKeyPath + ".pub"
$sshDir = Split-Path -Parent $SSHPrivateKeyPath
if (!(Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
if (Test-Path $SSHPrivateKeyPath) { Remove-Item $SSHPrivateKeyPath, $SSHPublicKeyPath -Force }
# Generate a new SSH key pair (no passphrase)
#ssh-keygen -t rsa -b 4096 -o -a 100 -f $SSHPrivateKeyPath -N "" -q
ssh-keygen -t ed25519 -a 100 -f $SSHPrivateKeyPath -N `"`" -q
$RemoteHostDotSSHDir = "C:\Users\$RemoteUserName\.ssh"
$SSHAuthorizedKeysPath = "$RemoteHostDotSSHDir\authorized_keys"
$SSHAuthorizedKeysPath2 = "C:\ProgramData\ssh\administrators_authorized_keys"
$SSHPublicKey = Get-Content -Raw $SSHPublicKeyPath
$script = @"
`$RemotePaths = @(
    "$ScriptsDir\bin"
    "$ScriptsDir\logs"
    "$ScriptsDir\powershell"
    "$ScriptsDir\configs"
    "$ScriptsDir\temp"
    "$ScriptsDir\certs"
    "C:\Users\$RemoteUserName\Documents\WindowsPowerShell"
    "C:\Users\$RemoteUserName\Documents\PowerShell"
)
foreach (`$path in `$RemotePaths) {
    if (!(Test-Path `$path)) { New-Item -ItemType Directory -Path `$path -Force | Out-Null }
}

if (!(Test-Path '$RemoteHostDotSSHDir')) {
  New-Item -Path '$RemoteHostDotSSHDir' -ItemType Directory -Force
}
[System.IO.File]::AppendAllLines([string]'$SSHAuthorizedKeysPath', [string[]]'$SSHPublicKey', [System.Text.UTF8Encoding]::new())
[System.IO.File]::AppendAllLines([string]'$SSHAuthorizedKeysPath2', [string[]]'$SSHPublicKey', [System.Text.UTF8Encoding]::new())
"@
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
vagrant winrm -c "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $b64"

# Test Key Authentication - This should return the name of the remote host
ssh -i $SSHPrivateKeyPath -o StrictHostKeyChecking=accept-new $SSHUserAndHost "powershell.exe -ExecutionPolicy Bypass -Command `"'`$env:ComputerName'`""

# The below should now work:
#ssh -i $SSHPrivateKeyPath $SSHUserAndHost

##### Do normal bootstrap stuff via ssh #####
$tempFileForProfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
$null = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyScripts/profile_2023.ps1" -OutFile $tempFileForProfile
# Set profile.ps1 for Windows PowerShell
$PSProfilePath = "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
$PSProfilePath1 = "C:\Users\$RemoteUserName\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
$SCPRemoteLocationStringPSProfile = $RemoteUserName + '@' + $RemoteIPAddress + ':' + $PSProfilePath
$SCPRemoteLocationStringPSProfile1 = $RemoteUserName + '@' + $RemoteIPAddress + ':' + $PSProfilePath1
scp.exe -i $SSHPrivateKeyPath $tempFileForProfile $SCPRemoteLocationStringPSProfile
scp.exe -i $SSHPrivateKeyPath $tempFileForProfile $SCPRemoteLocationStringPSProfile1
# Enable ICMP Ping
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Set-NetFirewallRule -DisplayName 'File and Printer Sharing (Echo Request - ICMPv4-In)' -Enabled True"
# Set Timezone
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Get-TimeZone -Id 'Eastern Standard Time' | Set-TimeZone"
# Rename Computer and restart
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Rename-Computer -NewName '$NewComputerName' -Restart"
Write-Host "Waiting 60 seconds for the remote machine to reboot after renaming..."
Start-Sleep -Seconds 60
# Get LastBootTime to ensure that the machine has rebooted after renaming
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"
# Install Chocolatey
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
# Update Environment Variables to access Chocolatey bin path
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'Machine') + ';C:\ProgramData\chocolatey\bin'), 'Machine')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'Machine')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'Machine')"
#[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'User') + ';C:\ProgramData\chocolatey\bin'), 'User')
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path', 'User')).Trim(';') + ';C:\ProgramData\chocolatey\bin;C:\ProgramData\chocolatey\lib'), 'User')"
# Install Pwsh
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "choco install powershell-core -y"
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "pwsh -Command `$PSVersionTable.PSVersion"
# Set Pwsh profile.ps1
$Pwsh7ProfilePath = 'C:\Program Files\PowerShell\7\profile.ps1'
$Pwsh7ProfilePath1 = "C:\Users\$RemoteUserName\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
$SCPRemoteLocationStringPwshProfile = $RemoteUserName + '@' + $RemoteIPAddress + ':' + $Pwsh7ProfilePath
$SCPRemoteLocationStringPwshProfile1 = $RemoteUserName + '@' + $RemoteIPAddress + ':' + $Pwsh7ProfilePath1
scp.exe -i $SSHPrivateKeyPath $tempFileForProfile $SCPRemoteLocationStringPwshProfile
scp.exe -i $SSHPrivateKeyPath $tempFileForProfile $SCPRemoteLocationStringPwshProfile1
# Set the default sshd shell to pwsh in the registry.
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Set-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value ((Get-Command pwsh).Source); Restart-Service sshd"
# NOTE: If you're going to use Invoke-Command/New-PSSession over ssh, then the below sshd_config subsystem changes are required
$SSHDConfigPath = "C:\ProgramData\ssh\sshd_config"
$PwshSubsystemString = "Subsystem powershell c:/progra~1/powershell/7/pwsh.exe -sshs -nologo"
$OverrideSubsystemsString = "# override default of no subsystems"
$RemoteSSHDConfig = ssh -i $SSHPrivateKeyPath $SSHUserAndHost "Stop-Service sshd; if ((Get-Content '$SSHDConfigPath') -notcontains '$PwshSubsystemString') {(Get-Content '$SSHDConfigPath') -replace [Regex]::Escape('$OverrideSubsystemsString'), ('$OverrideSubsystemsString' + [Environment]::NewLine + '$PwshSubsystemString') | Set-Content '$SSHDConfigPath'}; Start-Service sshd; Get-Content '$SSHDConfigPath'"
# Remove the tempfile
$null = Remove-item -Path $tempFileForProfile -Force
# Now you can use pwsh remoting commands like:
#$PSSession = New-PSSession -HostName $RemoteIPAddress -UserName $RemoteUserName -IdentityFilePath $SSHPrivateKeyPath
# Build a credential object (plain text username + password)
$Password = ConvertTo-SecureString "vagrant" -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($RemoteUserName, $Password)
Enable-PSRemoting -SkipNetworkProfileCheck -Force
$curr = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
Set-Item WSMan:\localhost\Client\TrustedHosts -Value ($(if($curr){$curr+","}) + $RemoteIPAddress) -Force
$PSSession = New-PSSession -ComputerName $RemoteIPAddress -Credential $Cred -Authentication Negotiate
$ArrayOfCimInstances = Invoke-Command $PSSession -ScriptBlock {Get-NetIPAddress -AddressFamily IPv4}
# Disable Bitlocker and Decrypt on ALL Volumes
try {ssh -i $SSHPrivateKeyPath $SSHUserAndHost 'Disable-BitLocker -MountPoint (Get-BitLockerVolume) -Confirm:$false'} catch {}
# Install other programs
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "choco install nano -y"
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "choco install vscode -y"
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "choco install googlechrome -y"
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "choco install rustdesk.install -y"
# Get RustDesk ID in terminal on remote host
#(& "C:\Program Files\RustDesk\rustdesk.exe" --get-id | Out-String).Trim()
$rustDeskID = ssh -i $SSHPrivateKeyPath $SSHUserAndHost "(& 'C:\Program Files\RustDesk\rustdesk.exe' --get-id | Out-String).Trim()"
Write-Host "RustDesk ID is $rustDeskID" -ForegroundColor Green
# Set RustDesk Password in terminal on remote host
#& "C:\Program Files\RustDesk\rustdesk.exe" --password $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt "Password" -AsSecureString))))
#Invoke-Command $PSSession {& "C:\Program Files\RustDesk\rustdesk.exe" --password $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Read-Host -Prompt "Password" -AsSecureString))))}
Invoke-Command $PSSession {& "C:\Program Files\RustDesk\rustdesk.exe" --password "RustDesk321!"}

# Finally launch RDP connection
Add-Type -AssemblyName System.Windows.Forms
$bounds  = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$screenW = $bounds.Width
$screenH = $bounds.Height
# Start window size (70% of screen) at 100,100
$winW = [math]::Round($screenW * 0.9)
$winH = [math]::Round($screenH * 0.9)
$left = 100
$top  = 100
$RdpFile = "$env:TEMP\vm.rdp"
@"
full address:s:$RemoteIPAddress
username:s:$RemoteUserName
authentication level:i:0
screen mode id:i:1
desktopwidth:i:$screenW
desktopheight:i:$screenH
session bpp:i:32
smart sizing:i:1
use multimon:i:0
span monitors:i:0
winposstr:s:0,1,$left,$top,$winW,$winH
"@ | Out-File -Encoding ASCII $RdpFile
Unblock-File $RdpFile
Start-Process mstsc.exe $RdpFile

Read-host -Prompt "Press Enter when you have started the RDP session in order to continue. Password is: vagrant"

### RUN THE BELOW IN THE RDP GUI SESSION ###

# Install-TARS.ps1
# Purpose: Install agent-tars, set up HF endpoint, and install UI-TARS Desktop (latest stable)
@"
`$ErrorActionPreference = 'Stop'

`$HF_TOKEN = '$HF_TOKEN'
`$HF_BaseURL = '$HF_BaseURL'
`$HF_Username = '$HF_Username'

"@ + @'
# --- Prereqs ---
Write-Host "Installing prerequisites via Chocolatey..." -ForegroundColor Cyan
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  throw "Chocolatey is required. Install from https://chocolatey.org/install then re-run."
}
choco install python -y
refreshenv
# Ensure python.exe/python3.exe dual names under C:\Python313
$ChocoPythonPath = "C:\Python313"
if ((Test-Path "$ChocoPythonPath\python3.exe") -and -not (Test-Path "$ChocoPythonPath\python.exe")) {
  New-Item -ItemType HardLink -Path "$ChocoPythonPath\python.exe" -Target "$ChocoPythonPath\python3.exe" | Out-Null
} elseif (-not (Test-Path "$ChocoPythonPath\python3.exe") -and (Test-Path "$ChocoPythonPath\python.exe")) {
  New-Item -ItemType HardLink -Path "$ChocoPythonPath\python3.exe" -Target "$ChocoPythonPath\python.exe" | Out-Null
}
choco upgrade nodejs-lts -y

# uv via pipx
Write-Host "Installing uv via pipx..." -ForegroundColor Cyan
python -m pip install --user pipx
python -m pipx ensurepath
python -m pipx install uv
# Make sure ~/.local/bin is on PATH for both user and machine
[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path','Machine')).Trim(';') + ";$HOME\.local\bin"), 'Machine')
[Environment]::SetEnvironmentVariable('Path', (([Environment]::GetEnvironmentVariable('Path','User')).Trim(';') + ";$HOME\.local\bin"), 'User')
refreshenv
Get-Command uv -ErrorAction SilentlyContinue | Out-Null
Get-Command uvx -ErrorAction SilentlyContinue | Out-Null

# agent-tars CLI
Write-Host "Installing @agent-tars/cli..." -ForegroundColor Cyan
npm i -g @agent-tars/cli@latest
agent-tars --version

# Use system Chrome for Puppeteer
[System.Environment]::SetEnvironmentVariable(
  "PUPPETEER_EXECUTABLE_PATH",
  "C:\Program Files\Google\Chrome\Application\chrome.exe",
  "User"
)

# --- Hugging Face Endpoint config prompts ---

if ([string]::IsNullOrWhiteSpace($HF_TOKEN)) {
    Write-Error "HUGGINGFACE_API_KEY is required for the HF endpoint. Halting!"
    return
}
if ([string]::IsNullOrWhiteSpace($HF_BaseURL)) {
    Write-Error "HUGGINGFACE_BASEURL is required for the HF endpoint. Halting!"
    return
}
if ([string]::IsNullOrWhiteSpace($HF_Username)) {
    Write-Error "HUGGINGFACE_USERNAME is required for the HF endpoint. Halting!"
    return
}

# Open firewall (optional: allow remote hits to agent-tars)
if (-not (Get-NetFirewallRule -DisplayName "TARS 8888" -ErrorAction SilentlyContinue)) {
  New-NetFirewallRule -DisplayName "TARS 8888" -Direction Inbound -Protocol TCP -LocalPort 8888 -Action Allow | Out-Null
}

# --- Run agent-tars pointing to HF endpoint (OpenAI-compatible) in background ---
Write-Host "Starting agent-tars on port 8888 in background..." -ForegroundColor Cyan
Write-Host "Model: ui-tars-1-5-7b-clt  | Base URL: $HF_BaseURL" -ForegroundColor DarkCyan
$agentArgs = @(
  "--model.provider","openai-compatible",
  "--model.id","ui-tars-1-5-7b-clt",
  "--model.apiKey",$HF_TOKEN,
  "--model.baseUrl",$HF_BaseURL,
  "--port","8888"
)

# 1) Try to find agent-tars on PATH
$cmdCheck = Get-Command 'agent-tars' -ErrorAction SilentlyContinue

# 2) If not found, try the common npm global location (Windows)
if (-not $cmdCheck) {
  $npmBin = Join-Path $env:APPDATA 'npm'
  $candidates = @(
    (Join-Path $npmBin 'agent-tars.cmd'),
    (Join-Path $npmBin 'agent-tars.ps1')
  )
  foreach ($c in $candidates) {
    if (Test-Path $c) { $cmdCheck = [pscustomobject]@{ Source = $c }; break }
  }
} else {
  $cmdPath = $cmdCheck.Source
}
if (-not $cmdCheck) {Write-Error "agent-tars command not found."; return}
if (-not $cmdPath) {$cmdPath = $cmdCheck.Source}

Write-Host "agent-tars found at $cmdPath" -ForegroundColor Green

# Launch minimized in a separate process, don't block
# NOTE: We have to run it like this because agent-tars is ultimately an alias for agent-tars.ps1
$args = @('-NoProfile','-ExecutionPolicy','Bypass','-File', $cmdPath) + $agentArgs
$proc = Start-Process -FilePath (Get-Command 'powershell.exe').Source -ArgumentList $args -WindowStyle Minimized -PassThru
#$proc = Start-Process -FilePath $cmdPath -ArgumentList $agentArgs -WindowStyle Minimized -PassThru # THIS DOES NOT WORK
#agent-tars --model.provider openai-compatible --model.id ui-tars-1-5-7b-clt --model.apiKey $HF_TOKEN --model.baseUrl $HF_BaseURL --port 8888 # THIS BLOCKS
Write-Host "agent-tars launched with PID $($proc.Id)" -ForegroundColor Green
Start-Sleep -Seconds 10
# Kill it
Write-Host "Stopping node process running agent-tars (PID $($proc.Id) to allow for UI-TARS Desktop run)."
try {
  Stop-Process -Id $proc.Id -Force
  Get-Process node | Stop-Process -Force
} catch {
  try {Get-Process node | Stop-Process -Force} catch {}
}

# --- UI-TARS Desktop (latest stable) ---
Write-Host "Downloading UI-TARS Desktop (latest stable)..." -ForegroundColor Cyan
# GitHub API requires a UA
$Headers = @{ 'User-Agent' = 'UI-TARS-Setup-Script' }
$releases = Invoke-RestMethod -Uri "https://api.github.com/repos/bytedance/UI-TARS-desktop/releases" -Headers $Headers
$stable = $releases | Where-Object { -not $_.prerelease -and $_.tag_name -notmatch 'beta' -and $_.name -notmatch 'beta' } |
          Sort-Object {[datetime]$_.published_at} -Descending | Select-Object -First 1
if (-not $stable) { throw "No stable release found." }
$asset = $stable.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1
if (-not $asset) { throw "No Windows .exe asset found in the latest stable release." }

$installerPath = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installerPath -Headers $Headers
Write-Host "Downloaded $($stable.tag_name): $($asset.name) to $installerPath" -ForegroundColor Green

Write-Host "Running the UI installer (silent)..." -ForegroundColor Cyan
Start-Process -FilePath $installerPath -ArgumentList '/SILENT'

Write-Host "Waiting 20 seconds for installation to complete..." -ForegroundColor Cyan
Start-Sleep -Seconds 20

# Desktop shortcut
$TargetPath   = "$HOME\AppData\Local\UiTars\UI-TARS.exe"
$ShortcutPath = "$HOME\Desktop\UI-TARS.lnk"
if (-not (Test-Path $ShortcutPath)) {
  Write-Host "Creating Desktop shortcut to UI-TARS at $ShortcutPath" -ForegroundColor Cyan  
  $WshShell = New-Object -ComObject WScript.Shell
  $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
  $Shortcut.TargetPath = $TargetPath
  $Shortcut.WorkingDirectory = Split-Path $TargetPath
  $Shortcut.IconLocation = $TargetPath
  $Shortcut.Save()
}

Write-Host "`nDone. Launching UI-TARS Desktop..." -ForegroundColor Green
#Start-Process -FilePath $TargetPath
Write-Host @"
When UI-TARS opens, click the "Local Computer" button and then set...

  VLM Provider:     Hugging Face for UI-TARS-1.5
  VLM Base URL:     $HF_BaseURL
  VLM API Key:      $HF_TOKEN
  VLM Model Name:   ByteDance-Seed/UI-TARS-1.5-7B

...and then click the "Check Model Availability" button. It may throw an error the first time, but wait a minute and try again. Once it returns green, you can start chatting with the AI to control your Computer.
"@ -ForegroundColor Yellow

'@ | Set-Content -Path (Join-Path $powershellDir "Install-TARS.ps1") -Encoding UTF8 -Force

# scp Install-TARS.ps1 to remote host
$SCPRemoteLocationString = $RemoteUserName + '@' + $RemoteIPAddress + ':' + (Join-Path $ScriptsDir "powershell\Install-TARS.ps1")
scp.exe -i $SSHPrivateKeyPath (Join-Path $powershellDir "Install-TARS.ps1") $SCPRemoteLocationString
Write-Host "`nInstall-TARS.ps1 copied to $SCPRemoteLocationString" -ForegroundColor Green

@'
# --- Run it interactively in the current active RDP session ---

# Path on the remote to run
$RemoteScriptPath = "C:\Scripts\powershell\Install-TARS.ps1"

# Helper: find the active RDP user (uses 'quser' output)
function Get-ActiveRdpUser {
  $lines = (quser) 2>$null
  if (-not $lines) { return $null }
  # Skip header; parse rows: USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME
  $id = ((($lines -match 'rdp') -split ' ') -match "^[0-9]")[0]
  $user = 'vagrant'
  $session = [string]$session = (($lines -match 'rdp') -split ' ') -match "rdp"
  return [PSCustomObject]@{
    User    = $user
    Session = $session
    Id      = $id
  }
}

$rdp = Get-ActiveRdpUser
if (-not $rdp) {
  $rdp = [PSCustomObject]@{
    User    = "vagramt"
    Session = "rdp-tcp#0"
    Id      = "2"
  }
}
Write-Host "Active RDP session: User='$($rdp.User)' Session='$($rdp.Session)' ID=$($rdp.Id)" -ForegroundColor Cyan

# Create a Scheduled Task that runs as the *interactive* logged-on user (no password prompt)
$taskName  = "Run-Install-TARS-" + ([guid]::NewGuid().ToString('N'))
$exe       = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $exe) { $exe = (Get-Command powershell).Source }  # fallback to Windows PowerShell if pwsh not found
$args      = "-NoExit -ExecutionPolicy Bypass -File `"$RemoteScriptPath`""

$action    = New-ScheduledTaskAction -Execute $exe -Argument $args
$principal = New-ScheduledTaskPrincipal -UserId $rdp.User -LogonType Interactive -RunLevel Highest
# Use an "already due" one-time trigger; weâ€™ll start it immediately
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(-5)

Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Trigger $trigger -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Host "Launched interactive task '$taskName' in $($rdp.User)'s session. A terminal window should appear on their desktop." -ForegroundColor Green

# Optional: clean up the task later (uncomment if you want auto-clean after 2 minutes)
# Start-Sleep -Seconds 120
# Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
'@ | Set-Content -Path (Join-Path $powershellDir "Run-Install-TARS-Interactively.ps1") -Encoding UTF8 -Force

# scp Run-Install-TARS-Interactively.ps1 to remote host
$SCPRemoteLocationString2 = $RemoteUserName + '@' + $RemoteIPAddress + ':' + (Join-Path $ScriptsDir "powershell\Run-Install-TARS-Interactively.ps1")
scp.exe -i $SSHPrivateKeyPath (Join-Path $powershellDir "Run-Install-TARS-Interactively.ps1") $SCPRemoteLocationString2
Write-Host "`nRun-Install-TARS-Interactively.ps1 copied to $SCPRemoteLocationString2" -ForegroundColor Green

# Run it interactively in the current active RDP session
ssh -i $SSHPrivateKeyPath $SSHUserAndHost "powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Scripts\powershell\Run-Install-TARS-Interactively.ps1'"
Write-Host "`nRun-Install-TARS-Interactively.ps1 launched. Switch to the RDP session and wait for the TARS installation to finish. Follow any additional instructions in the RDP session." -ForegroundColor Green
