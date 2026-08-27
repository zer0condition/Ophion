[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Edk2Root,
    [Parameter(Mandatory)]
    [string]$NasmPrefix,
    [Parameter(Mandatory)]
    [string]$IaslPrefix,
    [Parameter(Mandatory)]
    [string]$QemuPath,
    [string]$Target = 'RELEASE',
    [string]$DriveImage,
    [string]$SerialLog = (Join-Path $PSScriptRoot 'ovmf-serial.log')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$packageSource = Join-Path $PSScriptRoot 'OphionBootPkg'
$packageDestination = Join-Path $Edk2Root 'OphionBootPkg'
$baseDsc = Join-Path $Edk2Root 'OvmfPkg\OvmfPkgX64.dsc'
$labDsc = Join-Path $Edk2Root 'OvmfPkg\OphionOvmfPkgX64.dsc'
$varsTemplate = Join-Path $Edk2Root "Build\OvmfX64\${Target}_VS2022\FV\OVMF_VARS.fd"
$codeImage = Join-Path $Edk2Root "Build\OvmfX64\${Target}_VS2022\FV\OVMF_CODE.fd"
$varsImage = Join-Path $PSScriptRoot 'OVMF_VARS.lab.fd'

foreach ($path in @($packageSource, $baseDsc, $QemuPath, (Join-Path $Edk2Root 'edksetup.bat'))) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Required path is missing: $path" }
}

$NasmPrefix = $NasmPrefix.TrimEnd('\', '/') + '\'
$IaslPrefix = $IaslPrefix.TrimEnd('\', '/') + '\'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'vswhere.exe was not found.' }
$vs = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
Remove-Item -LiteralPath $packageDestination -Recurse -Force -ErrorAction SilentlyContinue
if (-not $vs -or -not (Test-Path -LiteralPath $vcvars)) { throw 'Visual Studio x64 C++ tools were not found.' }

Copy-Item -LiteralPath $packageSource -Destination $packageDestination -Recurse -Force
$lines = Get-Content -LiteralPath $baseDsc
$component = '  OphionBootPkg/Application/OphionBoot.inf'
if ($lines -notcontains $component) {
    $componentIndex = [Array]::FindIndex([string[]]$lines, [Predicate[string]]{ param($line) $line -eq '[Components]' })
    if ($componentIndex -lt 0) { throw "[Components] was not found in $baseDsc" }
    $lines = @($lines[0..$componentIndex] + $component + $lines[($componentIndex + 1)..($lines.Length - 1)])
}
Set-Content -LiteralPath $labDsc -Value $lines -Encoding ascii
Set-Content -LiteralPath $SerialLog -Value '' -Encoding ascii

$cmd = @"
@echo off
set NASM_PREFIX=$NasmPrefix
set IASL_PREFIX=$IaslPrefix
set PATH=%IASL_PREFIX%;%NASM_PREFIX%;%PATH%
call "$vcvars" >nul 2>&1
if errorlevel 1 exit /b 1
call edksetup.bat >nul 2>&1
if errorlevel 1 exit /b 1
build -t VS2022 -a X64 -p OvmfPkg\OphionOvmfPkgX64.dsc -b $Target
"@
$wrapper = Join-Path $Edk2Root 'build-ophion-ovmf.cmd'
try {
    Set-Content -LiteralPath $wrapper -Value $cmd -Encoding ascii
    Push-Location $Edk2Root
    & cmd.exe /d /c $wrapper
    if ($LASTEXITCODE -ne 0) { throw "OVMF build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $labDsc -Force -ErrorAction SilentlyContinue
}

foreach ($path in @($codeImage, $varsTemplate)) {
    if (-not (Test-Path -LiteralPath $path)) { throw "OVMF build output is missing: $path" }
}
Copy-Item -LiteralPath $varsTemplate -Destination $varsImage -Force
$args = @(
    '-machine', 'q35,accel=tcg',
    '-cpu', 'max,+vmx',
    '-m', '2048', '-smp', '2', '-nographic',
    '-drive', "if=pflash,format=raw,readonly=on,file=$codeImage",
    '-drive', "if=pflash,format=raw,file=$varsImage",
    '-serial', "file:$SerialLog"
)
if ($DriveImage) { $args += @('-drive', "format=raw,file=$DriveImage") }
& $QemuPath @args
Write-Host "Serial artifact: $SerialLog"
