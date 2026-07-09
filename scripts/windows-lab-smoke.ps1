param(
    [string]$RepoRoot = "C:\bofbench",
    [string]$Select = "whoami,ipconfig,env",
    [int]$TimeoutMS = 5000,
    [string]$BofbenchExe = "work\bin\bofbench.exe",
    [switch]$SkipFetch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $true

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Script
    )
    $started = Get-Date
    Write-Host "[lab] $Name"
    try {
        & $Script 2>&1 | ForEach-Object { Write-Host $_ }
        [pscustomobject]@{
            name = $Name
            status = "pass"
            started_at = $started.ToUniversalTime().ToString("o")
            duration_ms = [int]((Get-Date) - $started).TotalMilliseconds
            error = $null
        }
    } catch {
        [pscustomobject]@{
            name = $Name
            status = "fail"
            started_at = $started.ToUniversalTime().ToString("o")
            duration_ms = [int]((Get-Date) - $started).TotalMilliseconds
            error = $_.Exception.Message
        }
    }
}

if (!(Test-Path $RepoRoot)) {
    throw "RepoRoot does not exist: $RepoRoot"
}

$Select = ($Select -replace "\s+", ",")

Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path "bofs", "runs", "work\bin", "dist", "stage", "arsenal" | Out-Null

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$runDir = Join-Path "runs" "$runId-lab-smoke"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

$steps = New-Object System.Collections.Generic.List[object]

$steps.Add((Invoke-Step "generated capability contract" {
    go run ./cmd/capgen -check -out native/loader/capabilities.generated.h
}))

$steps.Add((Invoke-Step "native loader build" {
    $msvc = Get-Command cl -ErrorAction SilentlyContinue
    $mingw = Get-Command x86_64-w64-mingw32-gcc -ErrorAction SilentlyContinue
    if ($msvc) {
        & $msvc.Source /nologo /O2 /W4 /Fe:native\loader\bofbench-loader.exe native\loader\loader.c
    } elseif ($mingw) {
        & $mingw.Source -O2 -Wall -Wextra -o native\loader\bofbench-loader.exe native\loader\loader.c
    } else {
        throw "no compiler is available to build the native loader"
    }
}))

$steps.Add((Invoke-Step "go test" {
    go test ./...
}))

$steps.Add((Invoke-Step "native loader malformed corpus" {
    go test ./internal/loader -run 'TestNativeLoader|TestLoaderRun' -v -count=1
}))

$steps.Add((Invoke-Step "build cli" {
    go build -o $BofbenchExe .\cmd\bofbench
}))

$steps.Add((Invoke-Step "doctor" {
    & $BofbenchExe doctor
}))

$steps.Add((Invoke-Step "MSVC reproducible build evidence" {
    $buildEvidence = & $BofbenchExe build .\testdata\bofs\hello --compiler msvc --verify-reproducible | ConvertFrom-Json
    if ($buildEvidence.compiler.profile -ne "msvc") {
        throw "expected msvc compiler profile, got $($buildEvidence.compiler.profile)"
    }
    if (!$buildEvidence.compiler.path -or !$buildEvidence.compiler.version -or !$buildEvidence.compiler.sha256) {
        throw "MSVC compiler provenance is incomplete"
    }
    if (!$buildEvidence.reproducibility.checked -or !$buildEvidence.reproducibility.reproducible) {
        throw "MSVC object did not pass reproducibility verification"
    }
    if (!(($buildEvidence.command -contains "/experimental:deterministic") -and ($buildEvidence.command | Where-Object { $_ -like "/pathmap:*" }))) {
        throw "MSVC deterministic path-mapping flags are missing"
    }
    $buildEvidence | ConvertTo-Json -Depth 8
}))

$steps.Add((Invoke-Step "fixture build" {
    Remove-Item -Force .\dist\*.x64.o -ErrorAction SilentlyContinue
    & $BofbenchExe build .\testdata\bofs\hello
    & $BofbenchExe build .\testdata\bofs\arg_echo
    & $BofbenchExe build .\testdata\bofs\winapi_call
    & $BofbenchExe build .\testdata\bofs\data_reloc
    & $BofbenchExe build .\testdata\bofs\bss_reloc
    & $BofbenchExe build .\testdata\bofs\callback_ptr
    & $BofbenchExe build .\testdata\bofs\parser_all
    & $BofbenchExe build .\testdata\bofs\import_resolver
    & $BofbenchExe build .\testdata\bofs\unresolved
    & $BofbenchExe build .\testdata\bofs\crash
    & $BofbenchExe build .\testdata\bofs\timeout
}))

$steps.Add((Invoke-Step "fixture run hello" {
    $helloEvidence = & $BofbenchExe run .\dist\hello.x64.o --runtime windows-coff | ConvertFrom-Json
    if ($helloEvidence.status -ne "pass" -or $helloEvidence.exit_state -ne "success") {
        throw "hello fixture did not complete successfully"
    }
    if ($helloEvidence.loader_memory.initial_protection -ne "readwrite") {
        throw "hello fixture did not record a read/write relocation phase"
    }
    if ($helloEvidence.loader_memory.stub_region.protection -ne "execute_read") {
        throw "hello fixture stub region is not execute/read"
    }
    if ($helloEvidence.loader_memory.writable_executable_sections -ne 0) {
        throw "hello fixture contains a writable/executable section"
    }
    $sectionProtections = @($helloEvidence.loader_memory.sections | ForEach-Object { $_.protection })
    if ($sectionProtections -notcontains "execute_read") {
        throw "hello fixture has no execute/read code section"
    }
    if ($sectionProtections -contains "execute_readwrite") {
        throw "hello fixture retained an execute/read/write section"
    }
    $helloEvidence | ConvertTo-Json -Depth 10
}))

$steps.Add((Invoke-Step "fixture run arg_echo" {
    & $BofbenchExe run .\dist\arg_echo.x64.o --runtime windows-coff --args z:lab-message i:42
}))

$steps.Add((Invoke-Step "fixture run winapi_call" {
    & $BofbenchExe run .\dist\winapi_call.x64.o --runtime windows-coff
}))

$steps.Add((Invoke-Step "fixture test data_reloc" {
    & $BofbenchExe test .\testdata\bofs\data_reloc --runtime windows-coff
}))

$steps.Add((Invoke-Step "fixture test bss_reloc" {
    & $BofbenchExe test .\testdata\bofs\bss_reloc --runtime windows-coff
}))

$steps.Add((Invoke-Step "fixture test callback_ptr" {
    & $BofbenchExe test .\testdata\bofs\callback_ptr --runtime windows-coff
}))

$steps.Add((Invoke-Step "fixture test parser_all" {
    & $BofbenchExe test .\testdata\bofs\parser_all --runtime windows-coff
}))

$steps.Add((Invoke-Step "fixture test import_resolver" {
    & $BofbenchExe test .\testdata\bofs\import_resolver --runtime windows-coff
}))

$steps.Add((Invoke-Step "negative fixture unresolved" {
    & $BofbenchExe test .\testdata\bofs\unresolved --runtime windows-coff
}))

$steps.Add((Invoke-Step "negative fixture crash" {
    $crashEvidence = & $BofbenchExe test .\testdata\bofs\crash --runtime windows-coff | ConvertFrom-Json
    if ($crashEvidence.exit_state -ne "crash" -or $crashEvidence.loader_error_code -ne "windows_exception") {
        throw "crash fixture was not classified as a Windows exception"
    }
    if (!$crashEvidence.loader_process.exception_code) {
        throw "crash fixture is missing its exception code"
    }
    if (!$crashEvidence.loader_memory -or $crashEvidence.loader_memory.initial_protection -ne "readwrite") {
        throw "crash fixture is missing pre-entry memory-protection evidence"
    }
    $crashEvidence | ConvertTo-Json -Depth 10
}))

$steps.Add((Invoke-Step "negative fixture timeout" {
    & $BofbenchExe test .\testdata\bofs\timeout --runtime windows-coff
}))

$steps.Add((Invoke-Step "stage package verify" {
    & $BofbenchExe stage .\dist\hello.x64.o --target raw
    & $BofbenchExe stage verify .\stage\hello-raw
    & $BofbenchExe stage verify .\stage\hello-raw.zip --format json
}))

if (!$SkipFetch -and !(Test-Path "arsenal\trustedsec-sa")) {
    $steps.Add((Invoke-Step "fetch trustedsec-sa" {
        & $BofbenchExe fetch trustedsec-sa
    }))
}

$steps.Add((Invoke-Step "trustedsec real-object import resolution" {
    $previousNativePreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    try {
        $nativeOutput = & .\native\loader\bofbench-loader.exe --object .\arsenal\trustedsec-sa\SA\nslookup\nslookup.x64.o --entry __bofbench_missing_probe --arg-hex ""
        $nativeExitCode = $LASTEXITCODE
    } finally {
        $PSNativeCommandUseErrorActionPreference = $previousNativePreference
    }
    $nativeEvidence = $nativeOutput | ConvertFrom-Json
    if ($nativeExitCode -eq 0 -or $nativeEvidence.exit_state -ne "entry_missing" -or $nativeEvidence.error_code -ne "entrypoint_missing") {
        throw "real nslookup object did not resolve all imports before the missing-entry probe"
    }
    if (@($nativeEvidence.errors | Where-Object { $_ -like "unresolved symbol*" }).Count -ne 0) {
        throw "real nslookup object retained an unresolved import"
    }
    $nativeEvidence | ConvertTo-Json -Depth 8
}))

$steps.Add((Invoke-Step "trustedsec loader preflight" {
    & $BofbenchExe preflight .\arsenal\trustedsec-sa --select $Select
}))

$steps.Add((Invoke-Step "trustedsec architecture matrix" {
    & $BofbenchExe preflight .\arsenal\trustedsec-sa --select $Select --arch all --report-only
}))

$steps.Add((Invoke-Step "trustedsec arsenal smoke" {
    & $BofbenchExe test .\arsenal\trustedsec-sa --select $Select --runtime windows-coff --timeout $TimeoutMS
}))

$failed = @($steps | Where-Object { $_.status -ne "pass" })
$versionInfo = & $BofbenchExe version --format json | ConvertFrom-Json
$bofbenchResolved = (Resolve-Path $BofbenchExe).Path
$loaderItem = Resolve-Path "native\loader\bofbench-loader.exe" -ErrorAction SilentlyContinue
$loaderResolved = if ($loaderItem) { $loaderItem.Path } else { $null }
$compilerCommand = Get-Command cl -ErrorAction SilentlyContinue
$labEnvironment = [pscustomobject]@{
    computer_name = $env:COMPUTERNAME
    os_version = [Environment]::OSVersion.VersionString
    os_architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    powershell = $PSVersionTable.PSVersion.ToString()
    go_version = (go version)
    compiler = if ($compilerCommand) { $compilerCommand.Source } else { $null }
    bofbench_sha256 = (Get-FileHash -Algorithm SHA256 $bofbenchResolved).Hash.ToLowerInvariant()
    loader_sha256 = if ($loaderResolved) { (Get-FileHash -Algorithm SHA256 $loaderResolved).Hash.ToLowerInvariant() } else { $null }
}
$summary = [pscustomobject]@{
    schema = "bofbench.lab-smoke"
    schema_version = 1
    run_id = "$runId-lab-smoke"
    tool = $versionInfo.tool
    host = $versionInfo.host
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    repo_root = (Resolve-Path $RepoRoot).Path
    selection = $Select
    timeout_ms = $TimeoutMS
    status = if ($failed.Count -eq 0) { "pass" } else { "fail" }
    steps = $steps
    environment = $labEnvironment
}

$summaryPath = Join-Path $runDir "lab-smoke.json"
$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $summaryPath

Write-Host "[lab] summary: $summaryPath"
Write-Host "[lab] status: $($summary.status)"

if ($failed.Count -gt 0) {
    exit 1
}
