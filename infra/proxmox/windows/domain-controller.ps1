[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][string]$NetBIOSName,
    [Parameter(Mandatory)][securestring]$SafeModeAdministratorPassword,
    [string]$MarkerPath = 'C:\ProgramData\BOFBench\domain-controller-ready.json'
)

$ErrorActionPreference = 'Stop'
$feature = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
if (-not $feature.Success) { throw 'AD Domain Services feature installation failed' }

Import-Module ADDSDeployment
$forest = @{
    DomainName = $DomainName
    DomainNetbiosName = $NetBIOSName
    SafeModeAdministratorPassword = $SafeModeAdministratorPassword
    InstallDNS = $true
    NoRebootOnCompletion = $true
    Force = $true
}
Install-ADDSForest @forest

New-Item -ItemType Directory -Path (Split-Path $MarkerPath) -Force | Out-Null
$record = [ordered]@{
    schema = 'bofbench.proxmox-domain-controller'
    schema_version = 1
    domain_name = $DomainName
    netbios_name = $NetBIOSName
    completed_at = [DateTime]::UtcNow.ToString('o')
    reboot_required = $true
}
[IO.File]::WriteAllText($MarkerPath, ($record | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
Write-Output ($record | ConvertTo-Json -Compress)
