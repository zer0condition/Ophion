[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'tools\verify-production-boundary.ps1'
$dumpbin = Get-ChildItem 'C:\Program Files (x86)\Microsoft Visual Studio\2022' `
    -Filter dumpbin.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'Hostx64\\x64' } |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $dumpbin) { throw 'x64 dumpbin.exe was not found.' }

function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    if (-not $rejected) { throw "production-boundary test failed: $Message" }
}

$image = Join-Path $repo 'build\bin\Release\Ophion-production.sys'
$manifest = Join-Path $repo 'build\bin\Release\Ophion-production.objects.json'
if (-not (Test-Path $image) -or -not (Test-Path $manifest)) {
    throw 'Build the production driver before running this test.'
}

$result = & $tool -Path $image -DumpbinPath $dumpbin.FullName `
    -ObjectManifestPath $manifest | ConvertFrom-Json
if ($result.Schema -ne 'ophion.production-boundary.v1' -or
    $result.ForbiddenMarkers -ne 0 -or $result.ForbiddenImports -ne 0) {
    throw 'production-boundary positive control failed.'
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('ophion-boundary-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $badManifest = Join-Path $temp 'bad.objects.json'
    $bad = Get-Content $manifest -Raw | ConvertFrom-Json
    $bad.Sources = @($bad.Sources) + 'tracewipe.c'
    $bad | ConvertTo-Json -Depth 4 | Set-Content $badManifest -Encoding UTF8
    Assert-Rejected {
        & $tool -Path $image -DumpbinPath $dumpbin.FullName `
            -ObjectManifestPath $badManifest | Out-Null
    } 'experiment source manifest must be rejected'

    $wrongProfile = Join-Path $temp 'diagnostic.objects.json'
    $bad.Profile = 'Diagnostic'
    $bad.Sources = @($bad.Sources | Where-Object { $_ -ne 'tracewipe.c' })
    $bad | ConvertTo-Json -Depth 4 | Set-Content $wrongProfile -Encoding UTF8
    Assert-Rejected {
        & $tool -Path $image -DumpbinPath $dumpbin.FullName `
            -ObjectManifestPath $wrongProfile | Out-Null
    } 'diagnostic manifest must be rejected'
} finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Production boundary tests passed: positive image, source exclusion, profile rejection'