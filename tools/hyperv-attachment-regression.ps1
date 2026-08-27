[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BaselinePath,
    [Parameter(Mandatory)]
    [string]$OutputPath,
    [string]$ProbePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $ProbePath) {
    $ProbePath = Join-Path $PSScriptRoot '..\build\bin\Release\OphionProbe.exe'
}
if (-not (Test-Path $BaselinePath)) { throw "Baseline is missing: $BaselinePath" }
if (-not (Test-Path $ProbePath)) { throw "Probe is missing: $ProbePath" }

$baseline = Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
$current = ((& $ProbePath) -join "`n") | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Probe failed with exit code $LASTEXITCODE." }

function Get-Min([object[]]$Values) {
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    return ($Values | Measure-Object -Property tscDelta -Minimum).Minimum
}

$baselineFirst = $baseline.processors[0]
$currentFirst = $current.processors[0]
$result = [ordered]@{
    schema = 'ophion.hyperv-regression.v1'
    timestampUtc = [DateTime]::UtcNow.ToString('o')
    baseline = $BaselinePath
    cpuidVendorBaseline = if ($baselineFirst) { $baselineFirst.cpuid.hypervisorBase } else { $null }
    cpuidVendorCurrent = if ($currentFirst) { $currentFirst.cpuid.hypervisorBase } else { $null }
    processorCountBaseline = @($baseline.processors).Count
    processorCountCurrent = @($current.processors).Count
    minCpuidTscBaseline = if ($baselineFirst) { Get-Min @($baselineFirst.timing) } else { $null }
    minCpuidTscCurrent = if ($currentFirst) { Get-Min @($currentFirst.timing) } else { $null }
    identicalProcessorTopology = (@($baseline.processors).Count -eq @($current.processors).Count)
    classification = 'capture-only'
    boundary = 'This tool records raw attachment-stratum deltas. It does not execute detector binaries, alter Hyper-V, load drivers, or determine stealth.'
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Get-Content -LiteralPath $OutputPath -Raw
