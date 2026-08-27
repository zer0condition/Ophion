[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Edk2Root,
    [Parameter(Mandatory)]
    [string]$NasmPrefix,
    [Parameter(Mandatory)]
    [string]$IaslPrefix,
    [ValidateSet('NOOPT', 'DEBUG', 'RELEASE')]
    [string]$Target = 'RELEASE'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$NasmPrefix = $NasmPrefix.TrimEnd('\', '/') + '\'
$IaslPrefix = $IaslPrefix.TrimEnd('\', '/') + '\'

$packageRoot = Join-Path $PSScriptRoot 'OphionBootPkg'
if (-not (Test-Path (Join-Path $Edk2Root 'edksetup.bat'))) {
    throw "Edk2Root does not contain edksetup.bat: $Edk2Root"
}
if (-not (Test-Path (Join-Path $NasmPrefix 'nasm.exe'))) {
    throw "NasmPrefix does not contain nasm.exe: $NasmPrefix"
}
if (-not (Test-Path (Join-Path $IaslPrefix 'iasl.exe'))) {
    throw "IaslPrefix does not contain iasl.exe: $IaslPrefix"
}

$destination = Join-Path $Edk2Root 'OphionBootPkg'
Remove-Item -LiteralPath $destination -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item -LiteralPath $packageRoot -Destination $destination -Recurse -Force

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'vswhere.exe was not found.' }
$vs = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath).Trim()
if (-not $vs) { throw 'Visual Studio C++ tools were not found.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat was not found: $vcvars" }

$cmd = @"
@echo off
set NASM_PREFIX=$NasmPrefix
set IASL_PREFIX=$IaslPrefix
set PATH=%IASL_PREFIX%;%NASM_PREFIX%;%PATH%
call "$vcvars" >nul 2>&1
if errorlevel 1 exit /b 1
call edksetup.bat >nul 2>&1
if errorlevel 1 exit /b 1
build -t VS2022 -a X64 -p OphionBootPkg\OphionBootPkg.dsc -b $Target
"@

$wrapper = Join-Path $Edk2Root 'build-ophionboot.cmd'
Set-Content -LiteralPath $wrapper -Value $cmd -Encoding ascii
try {
    Push-Location $Edk2Root
    & cmd.exe /d /c $wrapper
    if ($LASTEXITCODE -ne 0) { throw "EDK2 build failed with exit code $LASTEXITCODE." }
} finally {
    Pop-Location
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
}

$output = Join-Path $Edk2Root "Build\OphionBoot\${Target}_VS2022\X64\OphionBoot.efi"
if (-not (Test-Path $output)) { throw "Build completed but output is missing: $output" }
Get-FileHash -LiteralPath $output -Algorithm SHA256
Write-Host "Built $output"
