[CmdletBinding()]
param(
    [string]$Root,
    [switch]$Fetch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = Join-Path $repo 'build\detectors' }
$manifestPath = Join-Path $PSScriptRoot 'detectors.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1) { throw "Unsupported detector manifest version: $($manifest.schemaVersion)" }

$git = $null
function Get-Git {
    if (-not $script:git) {
        $command = Get-Command git.exe -ErrorAction SilentlyContinue
        if (-not $command) { $command = Get-Command git -ErrorAction SilentlyContinue }
        if (-not $command) { throw 'git is required to inspect or fetch detector sources.' }
        $script:git = $command.Source
    }
    return $script:git
}
function Invoke-Git([string[]]$Arguments) {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & (Get-Git) @Arguments 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($exitCode -ne 0) { throw "git failed: $($output -join [Environment]::NewLine)" }
    return ($output -join [Environment]::NewLine).Trim()
}

if ($Fetch) { New-Item -ItemType Directory -Force -Path $Root | Out-Null }
$results = foreach ($detector in $manifest.detectors) {
    if ($detector.revision -notmatch '^[0-9a-f]{40}$') { throw "Invalid pinned revision for $($detector.name)." }
    $sourcePath = Join-Path $Root $detector.directory

    if ($Fetch) {
        if (-not (Test-Path (Join-Path $sourcePath '.git'))) {
            if (Test-Path $sourcePath) { throw "Fetch target exists but is not a git checkout: $sourcePath" }
            Invoke-Git @('clone', '--filter=blob:none', '--no-checkout', $detector.repository, $sourcePath) | Out-Null
        }
        Invoke-Git @('-C', $sourcePath, 'fetch', '--depth', '1', 'origin', $detector.revision) | Out-Null
        Invoke-Git @('-C', $sourcePath, 'checkout', '--detach', 'FETCH_HEAD') | Out-Null
    }

    $present = Test-Path (Join-Path $sourcePath '.git')
    $actualRevision = $null
    if ($present) { $actualRevision = Invoke-Git @('-C', $sourcePath, 'rev-parse', 'HEAD') }
    $revisionMatch = $present -and ($actualRevision -eq $detector.revision)
    $state = if (-not $present) { 'missing' } elseif ($revisionMatch) { 'ready' } else { 'revision-mismatch' }

    [ordered]@{
        name = $detector.name
        repository = $detector.repository
        expectedRevision = $detector.revision
        actualRevision = $actualRevision
        revisionMatch = $revisionMatch
        state = $state
        sourcePath = $sourcePath
        expectedCommand = $detector.expectedCommand
        resultArtifact = Join-Path $repo $detector.resultArtifact
    }
}

[ordered]@{
    schema = 'ophion.detectors.v1'
    fetchPerformed = [bool]$Fetch
    detectors = @($results)
} | ConvertTo-Json -Depth 5
