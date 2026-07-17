$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$virtio = Get-CimInstance Win32_LogicalDisk | Where-Object {
    Test-Path ($_.DeviceID + '\virtio-win-guest-tools.exe')
} | Select-Object -First 1
if (-not $virtio) { throw 'VirtIO guest-tools media not found' }

$installer = $virtio.DeviceID + '\virtio-win-guest-tools.exe'
$process = Start-Process -FilePath $installer -ArgumentList '/quiet', '/norestart' -Wait -PassThru
if ($process.ExitCode -notin 0, 3010) { throw "VirtIO guest tools failed: $($process.ExitCode)" }

Set-Service -Name QEMU-GA -StartupType Automatic
Start-Service -Name QEMU-GA -ErrorAction SilentlyContinue

$ssh = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($ssh.State -ne 'Installed') { Add-WindowsCapability -Online -Name $ssh.Name | Out-Null }
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Type String -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShellCommandOption -Type String -Value '-c'
if (-not (Get-NetFirewallRule -Name 'BOFBench-OpenSSH' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'BOFBench-OpenSSH' -DisplayName 'BOFBench OpenSSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}

$keyMedia = Get-CimInstance Win32_LogicalDisk | Where-Object {
    Test-Path ($_.DeviceID + '\bofbench-authorized-key.pub')
} | Select-Object -First 1
if (-not $keyMedia) { throw 'BOFBench SSH public key media not found' }
$sshRoot = Join-Path $env:ProgramData 'ssh'
New-Item -ItemType Directory -Path $sshRoot -Force | Out-Null
$authorizedKeys = Join-Path $sshRoot 'administrators_authorized_keys'
$key = (Get-Content -LiteralPath ($keyMedia.DeviceID + '\bofbench-authorized-key.pub') -Raw).Trim()
if ($key -notmatch '^ssh-[a-z0-9-]+\s+[A-Za-z0-9+/=]+') { throw 'BOFBench SSH public key is malformed' }
[IO.File]::WriteAllText($authorizedKeys, $key + [Environment]::NewLine, (New-Object Text.ASCIIEncoding))
icacls.exe $authorizedKeys /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null
Restart-Service sshd

Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Service -Name WinRM -StartupType Automatic
powercfg.exe /change standby-timeout-ac 0 | Out-Null
powercfg.exe /change hibernate-timeout-ac 0 | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name LongPathsEnabled -Type DWord -Value 1

$root = 'C:\ProgramData\BOFBench'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$record = [ordered]@{
    schema = 'bofbench.proxmox-template'
    schema_version = 1
    template = 'windows-11-clean'
    computer_name = $env:COMPUTERNAME
    architecture = $env:PROCESSOR_ARCHITECTURE
	ssh_key_installed = (Test-Path $authorizedKeys)
    completed_at = [DateTime]::UtcNow.ToString('o')
}
[IO.File]::WriteAllText((Join-Path $root 'template-ready.json'), ($record | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))

# Setup copies may contain the one-time answer. Remove them before shutdown;
# the provider removes the detached answer ISO after template acceptance.
foreach ($path in @(
    'C:\Windows\Panther\unattend.xml',
    'C:\Windows\Panther\Unattend\unattend.xml',
    'C:\Windows\System32\Sysprep\unattend.xml'
)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }

shutdown.exe /s /t 5 /f /d p:4:1 /c 'BOFBench template provisioning complete'
