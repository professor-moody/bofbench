[CmdletBinding()]
param(
    [string]$MarkerPath = 'C:\ProgramData\BOFBench\dev-template-ready.json'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-OfficialFile {
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$OutFile)
    Write-Output "download $Uri"
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile
    if (-not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -eq 0) { throw "download produced no data: $Uri" }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$downloads = Join-Path $env:TEMP 'bofbench-dev-tools'
New-Item -ItemType Directory -Path $downloads -Force | Out-Null

if (-not (Get-ChildItem 'C:\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe' -ErrorAction SilentlyContinue | Select-Object -First 1)) {
    $vsBootstrapper = Join-Path $downloads 'vs_BuildTools.exe'
    Get-OfficialFile -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $vsBootstrapper
    $vsArguments = @(
        '--wait', '--passive', '--norestart', '--installPath', 'C:\BuildTools',
        '--add', 'Microsoft.VisualStudio.Workload.VCTools',
        '--add', 'Microsoft.VisualStudio.Component.Windows11SDK.26100',
        '--includeRecommended'
    )
    $vs = Start-Process -FilePath $vsBootstrapper -ArgumentList $vsArguments -Wait -PassThru
    if ($vs.ExitCode -notin 0, 3010) { throw "Visual Studio Build Tools failed with exit code $($vs.ExitCode)" }
}

if (-not (Test-Path 'C:\Program Files\Go\bin\go.exe')) {
    $goRelease = Invoke-RestMethod -UseBasicParsing -Uri 'https://go.dev/dl/?mode=json'
    $goFile = $goRelease | Where-Object { $_.stable } | ForEach-Object { $_.files } | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'installer' } | Select-Object -First 1
    if (-not $goFile) { throw 'official Go release feed contains no stable Windows amd64 installer' }
    $goMSI = Join-Path $downloads $goFile.filename
    Get-OfficialFile -Uri ('https://go.dev/dl/' + $goFile.filename) -OutFile $goMSI
    $go = Start-Process -FilePath msiexec.exe -ArgumentList @('/i', $goMSI, '/qn', '/norestart') -Wait -PassThru
    if ($go.ExitCode -notin 0, 3010) { throw "Go MSI failed with exit code $($go.ExitCode)" }
}

if (-not (Test-Path 'C:\msys64\usr\bin\bash.exe')) {
    $msysInstaller = Join-Path $downloads 'msys2-base-x86_64-latest.sfx.exe'
    Get-OfficialFile -Uri 'https://github.com/msys2/msys2-installer/releases/latest/download/msys2-base-x86_64-latest.sfx.exe' -OutFile $msysInstaller
    $msys = Start-Process -FilePath $msysInstaller -ArgumentList @('-y', '-oC:\') -Wait -PassThru
    if ($msys.ExitCode -ne 0) { throw "MSYS2 extraction failed with exit code $($msys.ExitCode)" }
}

$bash = 'C:\msys64\usr\bin\bash.exe'
if (-not (Test-Path $bash)) { throw 'MSYS2 installation did not create the expected bash executable' }
& $bash -lc 'pacman -Syu --noconfirm || true; pacman -S --needed --noconfirm make mingw-w64-ucrt-x86_64-gcc mingw-w64-i686-gcc'
if ($LASTEXITCODE -ne 0) { throw "MSYS2 compiler installation failed with exit code $LASTEXITCODE" }

$debuggerPath = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
if (-not (Test-Path $debuggerPath)) {
    $sdkSetup = Join-Path $downloads 'winsdksetup.exe'
    Get-OfficialFile -Uri 'https://go.microsoft.com/fwlink/?linkid=2370315' -OutFile $sdkSetup
    $sdk = Start-Process -FilePath $sdkSetup -ArgumentList @('/features', 'OptionId.WindowsDesktopDebuggers', '/quiet', '/norestart', '/ceip', 'off') -Wait -PassThru
    if ($sdk.ExitCode -notin 0, 3010) { throw "Windows Debugging Tools failed with exit code $($sdk.ExitCode)" }
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$additions = @('C:\Program Files\Go\bin', 'C:\msys64\ucrt64\bin', 'C:\msys64\mingw32\bin', 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64')
foreach ($entry in $additions) {
    if ($machinePath -notlike "*$entry*") { $machinePath += ";$entry" }
}
[Environment]::SetEnvironmentVariable('Path', $machinePath, 'Machine')

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$vsInstall = if (Test-Path $vswhere) { (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim() } else { '' }
$debugger = Get-Item $debuggerPath -ErrorAction SilentlyContinue
$record = [ordered]@{
    schema = 'bofbench.proxmox-dev-template'
    schema_version = 1
    completed_at = [DateTime]::UtcNow.ToString('o')
    visual_studio = $vsInstall
    go = (& 'C:\Program Files\Go\bin\go.exe' version)
    mingw_x64 = (Test-Path 'C:\msys64\ucrt64\bin\gcc.exe')
    mingw_x86 = (Test-Path 'C:\msys64\mingw32\bin\gcc.exe')
    debugger = if ($debugger) { $debugger.FullName } else { '' }
}
New-Item -ItemType Directory -Path (Split-Path $MarkerPath) -Force | Out-Null
[IO.File]::WriteAllText($MarkerPath, ($record | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
Write-Output ($record | ConvertTo-Json -Compress)
