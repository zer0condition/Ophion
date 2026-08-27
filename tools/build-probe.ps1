[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$Clean,
    [switch]$WarningsAsErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $repo "build\bin\$Configuration"
$output = Join-Path $outDir 'OphionProbe.exe'
if ($Clean) { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue }

$vswhere = if (${env:ProgramFiles(x86)}) {
    Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
}
if (-not $vswhere -or -not (Test-Path $vswhere)) {
    $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($command) { $vswhere = $command.Source }
}
if (-not $vswhere -or -not (Test-Path $vswhere)) { throw 'vswhere.exe was not found.' }

$vsOutput = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
$vswhereExit = $LASTEXITCODE
$vs = $vsOutput | Where-Object { $_ } | Select-Object -First 1
if ($vswhereExit -ne 0 -or -not $vs) { throw 'No Visual Studio installation with x64 C++ tools was found.' }
$toolset = Get-ChildItem -LiteralPath (Join-Path $vs.Trim() 'VC\Tools\MSVC') -Directory | Where-Object {
    Test-Path (Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe')
} | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $toolset) { throw 'No x64 MSVC toolset was found.' }
$cl = Join-Path $toolset.FullName 'bin\Hostx64\x64\cl.exe'
$vsDevCmd = Join-Path $vs.Trim() 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsDevCmd)) { throw "VsDevCmd.bat was not found: $vsDevCmd" }

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$args = @(
    '/nologo', '/EHsc', '/std:c++17', '/W4', '/utf-8', '/DUNICODE', '/D_UNICODE',
    "/I$(Join-Path $repo 'include')", (Join-Path $PSScriptRoot 'OphionProbe.cpp'),
    "/Fe$output", '/link', '/INCREMENTAL:NO'
)
if ($Configuration -eq 'Release') { $args = @('/O2', '/DNDEBUG') + $args } else { $args = @('/Od', '/Zi', '/D_DEBUG') + $args }
if ($WarningsAsErrors) { $args = @('/WX') + $args }
$quotedArgs = $args | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }
$commandLine = 'call "' + $vsDevCmd + '" -no_logo -arch=x64 -host_arch=x64 && "' +
    $cl + '" ' + ($quotedArgs -join ' ')
& $env:ComSpec /d /s /c $commandLine
if ($LASTEXITCODE -ne 0) { throw "Probe compilation failed with exit code $LASTEXITCODE." }
if (-not (Test-Path $output)) { throw "Probe compiler did not create $output." }
Write-Host "Built $output"
