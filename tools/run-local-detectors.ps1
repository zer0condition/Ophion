[CmdletBinding()]
param(
    [ValidateRange(2, 60)]
    [int]$Seconds = 6,
    [ValidateRange(10, 100000)]
    [int]$ProbeSamples = 1000,
    [switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$source = 'E:\Tools\git\momo5502\ept-hook-detection'
if (-not (Test-Path -LiteralPath (Join-Path $source 'main.cpp'))) {
    throw "Local EPT detector source not found: $source"
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere.exe not found' }
$vsOutput = @(& $vswhere -latest -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath)
$vsExit = $LASTEXITCODE
$vs = $vsOutput | Where-Object { $_ } | Select-Object -First 1
if ($vsExit -ne 0 -or -not $vs) { throw 'Visual Studio C++ tools not found' }
$vsDevCmd = Join-Path $vs.Trim() 'Common7\Tools\VsDevCmd.bat'

$outRoot = Join-Path $repo 'build\detectors'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$generatedMain = Join-Path $outRoot 'ept_check_main.cpp'
$detector = Join-Path $outRoot 'ept_check.exe'

# The upstream source relied on VS2019 transitive chrono includes. Generate a
# build-only compatibility copy without modifying E:\Tools.
$main = Get-Content -LiteralPath (Join-Path $source 'main.cpp') -Raw
$main = "#include <chrono>`r`n" + $main
$main = $main.Replace('using namespace std::literals;', '')
$main = $main.Replace('1s', 'std::chrono::seconds(1)')
$main = $main.Replace('printf("\n");', 'printf("\n"); fflush(stdout);')
Set-Content -LiteralPath $generatedMain -Value $main -Encoding utf8

$sources = @(
    $generatedMain,
    (Join-Path $source 'thread_check.cpp'),
    (Join-Path $source 'timing_check.cpp'),
    (Join-Path $source 'write_check.cpp')
)
$quotedSources = $sources | ForEach-Object { '"' + $_ + '"' }
$command = 'call "' + $vsDevCmd + '" -no_logo -arch=x64 -host_arch=x64 && cl /nologo /EHsc /std:c++17 /O2 /I"' +
    $source + '" ' + ($quotedSources -join ' ') + ' /Fe:"' + $detector + '"'
& $env:ComSpec /d /s /c $command
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $detector)) {
    throw "EPT detector build failed: $LASTEXITCODE"
}
Write-Host "Built $detector"

$hvSolution = 'E:\Tools\git\xeroxz\Hypervisor-Detection\Hypervisor-Detection.sln'
$hvDetector = 'E:\Tools\git\xeroxz\Hypervisor-Detection\x64\Release\Hypervisor-Detection.exe'
if (-not (Test-Path -LiteralPath $hvSolution)) {
    throw "Local CPUID detector source not found: $hvSolution"
}
$msbuildOutput = @(& $vswhere -latest -products '*' `
    -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\MSBuild.exe')
$msbuild = $msbuildOutput | Where-Object { $_ } | Select-Object -First 1
if (-not $msbuild) { throw 'MSBuild.exe not found' }
& $msbuild $hvSolution /nologo /m `
    /p:Configuration=Release /p:Platform=x64
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hvDetector)) {
    throw "CPUID detector build failed: $LASTEXITCODE"
}
Write-Host "Built $hvDetector"

if ($BuildOnly) { return }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultDir = Join-Path $repo "build\detector-results\$stamp"
New-Item -ItemType Directory -Force -Path $resultDir | Out-Null
$eptOut = Join-Path $resultDir 'ept-hook-detection.txt'
$eptErr = Join-Path $resultDir 'ept-hook-detection.err.txt'

$process = Start-Process -FilePath $detector -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $eptOut -RedirectStandardError $eptErr
try {
    if (-not $process.WaitForExit($Seconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit()
    }
} finally {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}

$hvOut = Join-Path $resultDir 'hypervisor-detection.txt'
$hvErr = Join-Path $resultDir 'hypervisor-detection.err.txt'
$psi = [Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $hvDetector
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$hvProcess = [Diagnostics.Process]::new()
$hvProcess.StartInfo = $psi
[void]$hvProcess.Start()
$hvProcess.StandardInput.WriteLine()
$hvProcess.StandardInput.Close()
if (-not $hvProcess.WaitForExit(30000)) {
    $hvProcess.Kill()
    throw 'CPUID detector timed out'
}
$hvProcess.StandardOutput.ReadToEnd() |
    Set-Content -LiteralPath $hvOut -Encoding utf8
$hvProcess.StandardError.ReadToEnd() |
    Set-Content -LiteralPath $hvErr -Encoding utf8
$hvProcess.Dispose()


$probe = Join-Path $repo 'build\bin\Release\OphionProbe.exe'
$probeOut = Join-Path $resultDir 'ophion-probe.json'
$probeError = $null
if (Test-Path -LiteralPath $probe) {
    & $probe --samples $ProbeSamples 2>$null |
        Set-Content -LiteralPath $probeOut -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        $probeError = "OphionProbe exit $LASTEXITCODE (driver not loaded is expected)"
        Remove-Item -LiteralPath $probeOut -Force -ErrorAction SilentlyContinue
    }
} else {
    $probeError = 'OphionProbe.exe not built'
}

$vbs = $null
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbs = [int]$dg.VirtualizationBasedSecurityStatus
} catch {}

$summary = [ordered]@{
    Schema = 'ophion.detector-run.v1'
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    Seconds = $Seconds
    HypervisorPresent = [bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    VbsStatus = $vbs
    EptDetector = $eptOut
    EptDetectorErrors = $eptErr
    CpuidDetector = $hvOut
    CpuidDetectorErrors = $hvErr
    Probe = if (Test-Path -LiteralPath $probeOut) { $probeOut } else { $null }
    ProbeError = $probeError
}
$summaryPath = Join-Path $resultDir 'summary.json'
[pscustomobject]$summary | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $summaryPath -Encoding utf8

Write-Host "Detector artifacts: $resultDir"
Get-Content -LiteralPath $eptOut -Tail 24
