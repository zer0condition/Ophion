[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'tools\new-research-case.ps1'
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "research-case test failed: $Message" }
}

$temp = Join-Path ([IO.Path]::GetTempPath()) ('ophion-case-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $sample = Join-Path $temp 'sample.sys'
    [IO.File]::WriteAllBytes($sample, [byte[]](0..255))
    $case = & $tool -Product BattlEye -BinaryPath $sample -GameBuild build_1 -OutputRoot $temp
    Assert ($case.Schema -eq 'ophion.research-case.v1') 'schema'
    Assert ($case.Product -eq 'BattlEye') 'product'
    Assert ($case.EvidenceState -eq 'intake-only') 'evidence state'
    Assert (-not $case.RuntimeExecuted) 'runtime must remain false'
    Assert (-not $case.ProductVerdictObserved) 'verdict must remain false'
    Assert ($case.Binary.Sha256 -eq (Get-FileHash $sample -Algorithm SHA256).Hash) 'hash'
    $manifest = Join-Path $temp "$($case.CaseId)\manifest.json"
    Assert (Test-Path -LiteralPath $manifest) 'manifest written'

    $duplicateRejected = $false
    try {
        [void](& $tool -Product BattlEye -BinaryPath $sample -GameBuild build_1 -OutputRoot $temp)
    } catch { $duplicateRejected = $true }
    Assert $duplicateRejected 'duplicate case must fail closed'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host 'Research case tests passed: provenance, evidence boundary, duplicate rejection'