[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [Parameter(Mandatory)][pscredential]$Credential,
    [string]$ComputerName = $env:COMPUTERNAME,
    [string]$MarkerPath = 'C:\ProgramData\BOFBench\domain-member-ready.json'
)

$ErrorActionPreference = 'Stop'
if ($ComputerName -ne $env:COMPUTERNAME) {
    Rename-Computer -NewName $ComputerName -Force
}
Add-Computer -DomainName $DomainName -Credential $Credential -Force

New-Item -ItemType Directory -Path (Split-Path $MarkerPath) -Force | Out-Null
$record = [ordered]@{
    schema = 'bofbench.proxmox-domain-member'
    schema_version = 1
    domain_name = $DomainName
    computer_name = $ComputerName
    completed_at = [DateTime]::UtcNow.ToString('o')
    reboot_required = $true
}
[IO.File]::WriteAllText($MarkerPath, ($record | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
Write-Output ($record | ConvertTo-Json -Compress)
