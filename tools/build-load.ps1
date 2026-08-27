<#
.SYNOPSIS
    Build the guarded x64 Ophion loader.

.DESCRIPTION
    Compiles tools\OphionLoad.cpp into build\bin\<Config>\OphionLoad.exe.
    Supported x64 backends:
      - DirectIo64_legacy (PassMark)
      - LnvMSRIO.sys (Lenovo Dispatcher)
    pstrip64 is intentionally rejected on x64 because its mapping result
    truncates the user VA to 32 bits.

.PARAMETER Configuration
    Debug or Release (default: Release)

.PARAMETER Clean
    Delete existing output before building.

.PARAMETER WarningsAsErrors
    Treat compiler warnings as errors.

.EXAMPLE
    .\build-load.ps1

.EXAMPLE
    # Smoke test with the LnvMSRIO backend (run as administrator):
    .\build-load.ps1
    build\bin\Release\OphionLoad.exe --driver lnvmsrio `
        --vuln LnvMSRIO.sys --smoke --walk

.EXAMPLE
    # Prefer an already-loaded OEM driver to avoid a new file/service event:
    OphionLoad.exe --driver lnvmsrio --existing `
        --device \\.\WinMsrDev --smoke
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$Clean,
    [switch]$WarningsAsErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repo "build\bin\$Configuration"
$output = Join-Path $outDir 'OphionLoad.exe'

if ($Clean) { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue }

# ----------------------------------------------------------------
# Locate MSVC toolset
# ----------------------------------------------------------------
$vswhere = if (${env:ProgramFiles(x86)}) {
    Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
}
if (-not $vswhere -or -not (Test-Path $vswhere)) {
    $cmd = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($cmd) { $vswhere = $cmd.Source }
}
if (-not $vswhere -or -not (Test-Path $vswhere)) { throw 'vswhere.exe was not found.' }

$vsOutput = @(& $vswhere -latest -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath)
$vswhereExit = $LASTEXITCODE
$vs = $vsOutput | Where-Object { $_ } | Select-Object -First 1
if ($vswhereExit -ne 0 -or -not $vs) {
    throw 'No Visual Studio installation with x64 C++ tools was found.'
}

$toolset = Get-ChildItem -LiteralPath (Join-Path $vs.Trim() 'VC\Tools\MSVC') -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe') } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $toolset) { throw 'No x64 MSVC toolset was found.' }

$cl       = Join-Path $toolset.FullName 'bin\Hostx64\x64\cl.exe'
$vsDevCmd = Join-Path $vs.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsDevCmd)) { throw "VsDevCmd.bat not found: $vsDevCmd" }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# ----------------------------------------------------------------
# Compiler flags
# ----------------------------------------------------------------
$compileFlags = @(
    '/nologo', '/EHsc', '/std:c++17', '/W4', '/utf-8',
    '/DUNICODE', '/D_UNICODE',
    (Join-Path $PSScriptRoot 'OphionLoad.cpp'),
    "/Fe$output",
    '/link', '/INCREMENTAL:NO', 'ntdll.lib', 'advapi32.lib'
)

if ($Configuration -eq 'Release') {
    $compileFlags = @('/O2', '/DNDEBUG') + $compileFlags
} else {
    $compileFlags = @('/Od', '/Zi', '/D_DEBUG') + $compileFlags
}
if ($WarningsAsErrors) {
    $compileFlags = @('/WX') + $compileFlags
}

$quotedArgs   = $compileFlags | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }
$commandLine  = 'call "' + $vsDevCmd + '" -no_logo -arch=x64 -host_arch=x64 && "' +
                $cl + '" ' + ($quotedArgs -join ' ')

Write-Host "Building OphionLoad ($Configuration)..."
& $env:ComSpec /d /s /c $commandLine
if ($LASTEXITCODE -ne 0) {
    throw "OphionLoad compilation failed with exit code $LASTEXITCODE."
}
if (-not (Test-Path $output)) {
    throw "Compiler did not produce $output."
}
Write-Host "Built: $output"
Write-Host ""
Write-Host "Usage examples:"
Write-Host "  # LnvMSRIO smoke + CR3 walk (run as Admin, HVCI off):"
Write-Host "  $output --driver lnvmsrio --vuln LnvMSRIO.sys --smoke --walk"
Write-Host ""
Write-Host "  # Prefer an already-loaded driver (no file/service creation):"
Write-Host "  $output --driver lnvmsrio --existing --device \\.\WinMsrDev --smoke"
Write-Host ""
Write-Host "  # DirectIo diagnostic load:"
Write-Host "  $output --driver directio --vuln DirectIo64_legacy.sys --load-image Ophion.sys"
