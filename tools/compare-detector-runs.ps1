[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Baseline,

    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$Current,

    [string]$OutputPath = (
        'C:\Users\Admin\Documents\Ophion\build\detector-differential.json'),

    [ValidateRange(1, 100)]
    [double]$MedianTimingTolerancePercent = 25
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Json([string]$Path) {
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-EptResult([string]$Path) {
    $text = Get-Content -LiteralPath $Path -Raw
    $result = [ordered]@{}
    foreach ($name in @('Hooked', 'Timing', 'Thread', 'Writing')) {
        $prefix = '(?im)^' + [regex]::Escape($name) + ':\s*'
        $yes = ([regex]::Matches(
            $text, $prefix + 'Yes\s*$')).Count
        $no = ([regex]::Matches(
            $text, $prefix + 'No\s*$')).Count
        if (($yes + $no) -eq 0) {
            throw "EPT detector output did not contain $name samples: $Path"
        }
        $result[$name] = [pscustomobject]@{
            Yes = $yes
            No = $no
            Total = $yes + $no
        }
    }
    [pscustomobject]$result
}

function Get-CpuidDetectorResult([string]$Path) {
    $checks = [Collections.Generic.List[object]]::new()
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -match '^\*\s*(?<check>.+?)\s*~\s*(?<result>Passed|Detected)') {
            $checks.Add([pscustomobject][ordered]@{
                Check = $Matches.check.Trim()
                Result = $Matches.result
            })
        }
    }
    @($checks)
}

function Get-Percentile([object[]]$Values, [double]$Percentile) {
    if (-not $Values.Count) { return $null }
    $sorted = @($Values | Sort-Object)
    $index = [Math]::Ceiling(($sorted.Count - 1) * $Percentile)
    [uint64]$sorted[[int]$index]
}

function Get-ProbeResult([string]$Path) {
    $probe = Read-Json $Path
    if ($probe.schema -ne 'ophion.probe.v1') {
        throw "Unsupported probe schema in $Path"
    }
    $timing = @(
        $probe.processors | ForEach-Object {
            $_.timing | ForEach-Object { [uint64]$_.tscDelta }
        })
    $hypervisorProcessors = @(
        $probe.processors | Where-Object {
            ([uint32]$_.cpuid.leaf1.ecx -band [uint32]2147483648) -ne 0
        }).Count
    $persona = [pscustomobject][ordered]@{
        ProcessorCount = @($probe.processors).Count
        HypervisorProcessors = $hypervisorProcessors
        DriverFormat = [string]$probe.status.format
        HypervisorBaseMax = @(
            $probe.processors |
            ForEach-Object { [uint32]$_.cpuid.hypervisorBase.eax } |
            Sort-Object -Unique)
        HypervisorInterface = @(
            $probe.processors |
            ForEach-Object { [uint32]$_.cpuid.hypervisorInterface.eax } |
            Sort-Object -Unique)
        InvalidFixed = @(
            $probe.processors |
            ForEach-Object {
                '{0:X8}:{1:X8}:{2:X8}:{3:X8}' -f
                    [uint32]$_.cpuid.invalidFixed.eax,
                    [uint32]$_.cpuid.invalidFixed.ebx,
                    [uint32]$_.cpuid.invalidFixed.ecx,
                    [uint32]$_.cpuid.invalidFixed.edx
            } | Sort-Object -Unique)
    }
    [pscustomobject][ordered]@{
        Persona = $persona
        Timing = [pscustomobject][ordered]@{
            Samples = $timing.Count
            Minimum = if ($timing.Count) {
                [uint64]($timing | Measure-Object -Minimum).Minimum
            } else { $null }
            Median = Get-Percentile $timing 0.50
            P95 = Get-Percentile $timing 0.95
            P99 = Get-Percentile $timing 0.99
            Maximum = if ($timing.Count) {
                [uint64]($timing | Measure-Object -Maximum).Maximum
            } else { $null }
        }
    }
}

function Test-ErrorText([string]$Path) {
    $text = Get-Content -LiteralPath $Path -Raw
    if ($null -eq $text) { return $false }
    return $text.Trim(
        [char]0xFEFF,
        [char]0xEF,
        [char]0xBB,
        [char]0xBF,
        [char]0x20,
        [char]0x09,
        [char]0x0D,
        [char]0x0A).Length -ne 0
}

function Read-Run([string]$Directory) {
    $summary = Read-Json (Join-Path $Directory 'summary.json')
    if ($summary.Schema -ne 'ophion.detector-run.v1') {
        throw "Unsupported detector run schema in $Directory"
    }
    $probePath = Join-Path $Directory 'ophion-probe.json'
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
        throw "Detector run has no probe output: $Directory"
    }
    [pscustomobject][ordered]@{
        Directory = (Resolve-Path -LiteralPath $Directory).Path
        Summary = $summary
        Ept = Get-EptResult (
            Join-Path $Directory 'ept-hook-detection.txt')
        Cpuid = Get-CpuidDetectorResult (
            Join-Path $Directory 'hypervisor-detection.txt')
        Probe = Get-ProbeResult $probePath
        ErrorTextPresent = [pscustomobject]@{
            Ept = Test-ErrorText (
                Join-Path $Directory 'ept-hook-detection.err.txt')
            Cpuid = Test-ErrorText (
                Join-Path $Directory 'hypervisor-detection.err.txt')
        }
    }
}

$baselineRun = Read-Run $Baseline
$currentRun = Read-Run $Current
$baselinePersona = $baselineRun.Probe.Persona |
    ConvertTo-Json -Compress -Depth 5
$currentPersona = $currentRun.Probe.Persona |
    ConvertTo-Json -Compress -Depth 5
$baselineCpuid = $baselineRun.Cpuid |
    ConvertTo-Json -Compress -Depth 4
$currentCpuid = $currentRun.Cpuid |
    ConvertTo-Json -Compress -Depth 4

$eptCurrentPositive = 0
foreach ($name in @('Hooked','Timing','Thread','Writing')) {
    $eptCurrentPositive += $currentRun.Ept.$name.Yes
}
$medianDeltaPercent = if ($baselineRun.Probe.Timing.Median) {
    [Math]::Round(
        100.0 * (
            [double]$currentRun.Probe.Timing.Median -
            [double]$baselineRun.Probe.Timing.Median) /
        [double]$baselineRun.Probe.Timing.Median,
        3)
} else { $null }
$timingExceeded = (
    $null -ne $medianDeltaPercent -and
    [Math]::Abs($medianDeltaPercent) -gt
        $MedianTimingTolerancePercent)
$hardDrift = (
    [bool]$baselineRun.Summary.HypervisorPresent -ne
        [bool]$currentRun.Summary.HypervisorPresent -or
    [int]$baselineRun.Summary.VbsStatus -ne
        [int]$currentRun.Summary.VbsStatus -or
    $baselinePersona -ne $currentPersona -or
    $baselineCpuid -ne $currentCpuid -or
    $eptCurrentPositive -ne 0 -or
    $currentRun.ErrorTextPresent.Ept -or
    $currentRun.ErrorTextPresent.Cpuid)
$runtimeExercised = (
    [bool]$currentRun.Summary.HypervisorPresent -or
    $currentRun.Probe.Persona.DriverFormat -ne 'unavailable')
$verdict = if ($hardDrift) {
    'hard-drift'
} elseif ($timingExceeded) {
    'timing-drift'
} elseif (-not $runtimeExercised) {
    'host-baseline-unchanged-runtime-not-exercised'
} else {
    'no-detector-drift'
}

$result = [pscustomobject][ordered]@{
    Schema = 'ophion.detector-differential.v1'
    GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    Baseline = $baselineRun
    Current = $currentRun
    Differential = [pscustomobject][ordered]@{
        HypervisorPresentChanged = (
            [bool]$baselineRun.Summary.HypervisorPresent -ne
            [bool]$currentRun.Summary.HypervisorPresent)
        VbsStatusChanged = (
            [int]$baselineRun.Summary.VbsStatus -ne
            [int]$currentRun.Summary.VbsStatus)
        EptPositiveCount = $eptCurrentPositive
        CpuidChecksChanged = ($baselineCpuid -ne $currentCpuid)
        ProbePersonaChanged = ($baselinePersona -ne $currentPersona)
        MedianTscDeltaPercent = $medianDeltaPercent
        MedianTimingTolerancePercent = $MedianTimingTolerancePercent
        TimingThresholdExceeded = $timingExceeded
        HardDrift = $hardDrift
        RuntimeExercised = $runtimeExercised
    }
    Verdict = $verdict
    KnownBaselineFinding = (
        'The xeroxz CPUID/FYL2XP1 timing heuristic reports Detected ' +
        'on both clean-host runs; it is not new drift.')
    Limitation = (
        'Code Integrity blocked the available bootstrap. Ophion did not ' +
        'enter VMX, so this differential measures host/tool stability only.')
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
$result | ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
$result | ConvertTo-Json -Depth 10
