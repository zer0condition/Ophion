<#
.SYNOPSIS
    Build OphionInternal.lib (stack-spoof thunk) for in-game modules.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repo "build\bin\$Configuration"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$vswhere = if (${env:ProgramFiles(x86)}) {
    Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
}
if (-not $vswhere -or -not (Test-Path $vswhere)) {
    $candidate = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($candidate) { $vswhere = $candidate.Source }
}
if (-not $vswhere -or -not (Test-Path $vswhere)) {
    throw 'vswhere.exe was not found.'
}
$vsOutput = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
$vswhereExit = $LASTEXITCODE
$vs = $vsOutput | Where-Object { $_ } | Select-Object -First 1
if ($vswhereExit -ne 0 -or -not $vs) {
    throw 'No Visual Studio installation with x64 C++ tools was found.'
}
$vsDevCmd = Join-Path $vs.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsDevCmd)) { throw "VsDevCmd.bat not found: $vsDevCmd" }
$ml = 'ml64.exe'
$lib = 'lib.exe'
$obj = Join-Path $outDir 'ophion_spoof.obj'
$out = Join-Path $outDir 'OphionInternal.lib'

$cmd = "call `"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 && $ml /nologo /c /Fo`"$obj`" `"$PSScriptRoot\ophion_spoof.asm`" && $lib /nologo /out:`"$out`" `"$obj`""
& $env:ComSpec /d /s /c $cmd
if ($LASTEXITCODE -ne 0) { throw "OphionInternal.lib failed: $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $out)) { throw "Library was not produced: $out" }
Write-Host "Built $out"
Write-Host "Link this lib + include OphionInternal.h; call ophion::harden_image(base, size)."
