param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [string]$ImagePath,
    [string]$MapperPath,
    [string]$MappedBase = '0xFFFFF80200000000',
    [string]$NtosBase = '0xFFFFF80000000000'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
if (-not $ImagePath) {
    $ImagePath = Join-Path $repo "build\bin\$Configuration\Ophion-production.sys"
}
if (-not $MapperPath) {
    $MapperPath = Join-Path $repo "build\bin\$Configuration\OphionMap.exe"
}
$ntos = Join-Path $env:SystemRoot 'System32\ntoskrnl.exe'
$outDir = Join-Path $repo 'build\mapper-artifact-test'

function Convert-Base([string]$Value) {
    if ($Value -match '^0[xX](?<Hex>[0-9a-fA-F]+)$') {
        return [Convert]::ToUInt64($Matches.Hex, 16)
    }
    return [UInt64]::Parse($Value)
}

$mappedBaseValue = Convert-Base $MappedBase
$ntosBaseValue = Convert-Base $NtosBase

function Invoke-Mapper([string[]]$Arguments, [int]$ExpectedExit) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $MapperPath @Arguments 2>&1 | Out-String
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($exit -ne $ExpectedExit) {
        throw "OphionMap exit mismatch: expected=$ExpectedExit actual=$exit`n$output"
    }
    return $output
}

foreach ($path in @($MapperPath, $ImagePath, $ntos)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required artifact missing: $path"
    }
}

$help = Invoke-Mapper @('--help') 0
if ($help -notmatch 'ophion\.exec\.bin' -or
    $help -notmatch '\-\-base <hex kernel VA>') {
    throw 'Mapper help does not describe the launchable v2 artifact.'
}
$macSelfTest = Invoke-Mapper @('--mac-self-test') 0
if ($macSelfTest -notmatch 'Transport MAC self-test passed') {
    throw 'Shared transport MAC self-test failed.'
}

$bad = Invoke-Mapper @('--image', $ImagePath, '--out', $outDir) 1
if ($bad -notmatch '--base is required for a launchable artifact') {
    throw 'Mapper did not fail closed without a relocation base.'
}

function Assert-PlacementRejected(
    [string]$Base,
    [string]$KernelBase,
    [string]$Pattern
) {
    $output = Invoke-Mapper @(
        '--image', $ImagePath,
        '--out', $outDir,
        '--base', $Base,
        '--ntos', $ntos,
        '--ntos-base', $KernelBase
    ) 1
    if ($output -notmatch $Pattern) {
        throw "Mapper accepted or misclassified invalid placement: $Base"
    }
}

function Write-EntryRvaFixture(
    [string]$SourcePath,
    [string]$DestinationPath,
    [uint32]$EntryRva
) {
    [byte[]]$bytes = [IO.File]::ReadAllBytes($SourcePath)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    $entryOffset = $peOffset + 4 + 20 + 16
    [Array]::Copy([BitConverter]::GetBytes($EntryRva), 0, $bytes, $entryOffset, 4)
    [IO.File]::WriteAllBytes($DestinationPath, $bytes)
}

function Assert-EntryRejected(
    [uint32]$EntryRva,
    [string]$ExpectedError,
    [string]$Label
) {
    $fixturePath = Join-Path $outDir "$Label.sys"
    $fixtureOut = Join-Path $outDir "$Label-out"
    Write-EntryRvaFixture $ImagePath $fixturePath $EntryRva
    $output = Invoke-Mapper @(
        '--image', $fixturePath,
        '--out', $fixtureOut,
        '--base', ('0x{0:X}' -f $mappedBaseValue),
        '--ntos', $ntos,
        '--ntos-base', ('0x{0:X}' -f $ntosBaseValue)
    ) 1
    if ($output -notmatch [regex]::Escape($ExpectedError)) {
        throw "Mapper accepted or misclassified invalid entry point: $Label"
    }
}

Assert-PlacementRejected '0xfffff80200000000junk' `
    '0xfffff80000000000' 'invalid numeric value'
Assert-PlacementRejected '0x1000' `
    '0xfffff80000000000' 'canonical kernel'
Assert-PlacementRejected '0xfffff80200000001' `
    '0xfffff80000000000' 'aligned'
Assert-PlacementRejected '0xfffffffffffff000' `
    '0xfffff80000000000' 'range overflows'
Assert-PlacementRejected '0xfffff80200000000' `
    '0x1000' 'ntos base must be a canonical kernel'

Remove-Item -LiteralPath $outDir -Recurse -Force -ErrorAction SilentlyContinue
[void](Invoke-Mapper @(
    '--image', $ImagePath,
    '--out', $outDir,
    '--base', ('0x{0:X}' -f $mappedBaseValue),
    '--ntos', $ntos,
    '--ntos-base', ('0x{0:X}' -f $ntosBaseValue)
) 0)

$jsonPath = Join-Path $outDir 'ophion.map.json'
$mapPath = Join-Path $outDir 'ophion.map.bin'
$thunkPath = Join-Path $outDir 'ophion.exec.bin'
$bootstrapPath = Join-Path $outDir 'ophion.bootstrap.bin'
$sealPath = Join-Path $outDir 'ophion.seal.bin'
$stopPath = Join-Path $outDir 'ophion.stop.bin'
$cleanupPath = Join-Path $outDir 'ophion.cleanup.bin'
$manifestText = Get-Content -LiteralPath $jsonPath -Raw
$manifest = $manifestText | ConvertFrom-Json
$image = [IO.File]::ReadAllBytes($mapPath)
$thunk = [IO.File]::ReadAllBytes($thunkPath)
$bootstrapThunk = [IO.File]::ReadAllBytes($bootstrapPath)
$sealThunk = [IO.File]::ReadAllBytes($sealPath)
$stopThunk = [IO.File]::ReadAllBytes($stopPath)
$cleanupThunk = [IO.File]::ReadAllBytes($cleanupPath)

if ($manifest.schema -ne 'ophion.map.v2' -or
    $manifest.commandMagic -ne '0x7a6d94c13b52e807' -or
    $manifest.commandVersion -ne 1 -or
    $manifest.commandHeaderBytes -ne 72 -or
    $manifest.commandPageBytes -ne 4096 -or
    $manifest.macAlgorithm -ne 'siphash-2-4x2-128' -or
    $manifest.recordMacOffset -ne 56 -or
    $manifest.recordMacBytes -ne 16 -or
    $manifest.sharedPageRva -le 0 -or
    ($manifest.sharedPageRva % 4096) -ne 0 -or
    $manifest.bootstrapState -ne 1 -or
    $manifest.bootstrapRequestBytes -ne 16 -or
    $manifest.capabilityPayloadOffset -ne 72 -or
    $manifest.initialSequence -ne 1 -or
    $manifest.sealVmcallStep -ne 5 -or
    $manifest.stopVmcallStep -ne 6 -or
    $manifest.bootstrapVmcallStep -ne 7 -or
    $manifest.rootCommandVmcall -ne 0x100 -or
    -not $manifest.requiresRootBootstrap -or
    -not $manifest.bootstrapAfterEntry -or
    -not $manifest.requiresAllCoreSeal -or
    -not $manifest.requiresAllCoreStop -or
    $manifest.stopCapabilityLowOffset -ne 39 -or
    $manifest.stopCapabilityHighOffset -ne 49 -or
    $manifest.stopEpochOffset -ne 59 -or
    $manifest.bootstrapCapabilityLowOffset -ne 39 -or
    $manifest.bootstrapCapabilityHighOffset -ne 49 -or
    $manifest.bootstrapEpochOffset -ne 59 -or
    $manifest.sealThunk -ne 'ophion.seal.bin' -or
    $manifest.sealThunkSize -ne $sealThunk.Length -or
    $manifest.sealCapabilityLowOffset -ne 39 -or
    $manifest.sealCapabilityHighOffset -ne 49 -or
    $manifest.sealEpochOffset -ne 59 -or
    -not $manifest.importsResolved) {
    throw 'Mapper transport manifest invariant failed.'
}
if ($image.Length -ne $manifest.size) {
    throw 'Mapped image size differs from the manifest.'
}
Assert-EntryRejected ([uint32]$manifest.size) `
    'entry point is outside the mapped image' `
    'entry-outside-image'
Assert-EntryRejected ([uint32]$manifest.sharedPageRva) `
    'entry point is not in an executable section' `
    'entry-non-executable'
if ($thunk.Length -ne 25 -or
    $thunk[0] -ne 0x48 -or $thunk[1] -ne 0x83 -or
    $thunk[2] -ne 0xEC -or $thunk[3] -ne 0x28 -or
    $thunk[18] -ne 0xFF -or $thunk[19] -ne 0xD0 -or
    $thunk[24] -ne 0xC3) {
    throw 'Execution thunk ABI bytes changed.'
}
$entryVa = [Convert]::ToUInt64(
    ($manifest.entryVa -replace '^0x', ''), 16)
if ([BitConverter]::ToUInt64($thunk, 10) -ne $entryVa) {
    throw 'Execution thunk does not target the manifest entry VA.'
}
if ($cleanupThunk.Length -ne 25 -or
    [BitConverter]::ToUInt64($cleanupThunk, 10) -ne
        [Convert]::ToUInt64(
            ($manifest.cleanupVa -replace '^0x', ''), 16)) {
    throw 'Cleanup thunk does not target OphionCleanup.'
}
if ($stopThunk.Length -ne 73 -or
    [BitConverter]::ToUInt64($stopThunk, 4) -ne
        [Convert]::ToUInt64('48564653', 16) -or
    [BitConverter]::ToUInt64($stopThunk, 14) -ne
        [Convert]::ToUInt64('564D43414C4C', 16) -or
    [BitConverter]::ToUInt64($stopThunk, 24) -ne
        [Convert]::ToUInt64('4E4F485950455256', 16) -or
    [BitConverter]::ToUInt32($stopThunk, 33) -ne 6 -or
    [BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopCapabilityLowOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopCapabilityHighOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopEpochOffset) -ne 0) {
    throw 'Authenticated stop thunk ABI changed.'
}
if ($bootstrapThunk.Length -ne 73 -or
    [BitConverter]::ToUInt64($bootstrapThunk, 4) -ne
        [Convert]::ToUInt64('48564653', 16) -or
    [BitConverter]::ToUInt64($bootstrapThunk, 14) -ne
        [Convert]::ToUInt64('564D43414C4C', 16) -or
    [BitConverter]::ToUInt64($bootstrapThunk, 24) -ne
        [Convert]::ToUInt64('4E4F485950455256', 16) -or
    [BitConverter]::ToUInt32($bootstrapThunk, 33) -ne 7 -or
    [BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapCapabilityLowOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapCapabilityHighOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapEpochOffset) -ne 0) {
    throw 'VMX-root bootstrap thunk ABI changed.'
}
if ($sealThunk.Length -ne 73 -or
    [BitConverter]::ToUInt64($sealThunk, 4) -ne
        [Convert]::ToUInt64('48564653', 16) -or
    [BitConverter]::ToUInt64($sealThunk, 14) -ne
        [Convert]::ToUInt64('564D43414C4C', 16) -or
    [BitConverter]::ToUInt64($sealThunk, 24) -ne
        [Convert]::ToUInt64('4E4F485950455256', 16) -or
    [BitConverter]::ToUInt32($sealThunk, 33) -ne 5 -or
    [BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealCapabilityLowOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealCapabilityHighOffset) -ne 0 -or
    [BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealEpochOffset) -ne 0) {
    throw 'VMX-root all-core seal thunk ABI changed.'
}

$shared = [int]$manifest.sharedPageRva
for ($i = 0; $i -lt 4096; $i++) {
    if ($image[$shared + $i] -ne 0) {
        throw 'Shared command page is not zero initialized.'
    }
}

# Model the external runtime's one-time bootstrap patch using manifest offsets.
$capLow = [Convert]::ToUInt64('0123456789ABCDEF', 16)
$capHigh = [Convert]::ToUInt64('FEDCBA9876543210', 16)
[BitConverter]::GetBytes([UInt64]0x7A6D94C13B52E807).CopyTo($image, $shared)
[BitConverter]::GetBytes([UInt16]1).CopyTo($image, $shared + 8)
[BitConverter]::GetBytes(
    [UInt16]$manifest.commandHeaderBytes).CopyTo($image, $shared + 10)
[BitConverter]::GetBytes([UInt32]4096).CopyTo($image, $shared + 12)
[BitConverter]::GetBytes([UInt32]1).CopyTo($image, $shared + 16)
[BitConverter]::GetBytes([UInt32]16).CopyTo($image, $shared + 32)
[BitConverter]::GetBytes([UInt64]1).CopyTo($image, $shared + 48)
[BitConverter]::GetBytes($capLow).CopyTo(
    $image, $shared + $manifest.capabilityPayloadOffset)
[BitConverter]::GetBytes($capHigh).CopyTo(
    $image, $shared + $manifest.capabilityPayloadOffset + 8)
[BitConverter]::GetBytes($capLow).CopyTo(
    $stopThunk, $manifest.stopCapabilityLowOffset)
[BitConverter]::GetBytes($capHigh).CopyTo(
    $stopThunk, $manifest.stopCapabilityHighOffset)
[BitConverter]::GetBytes([UInt64]1).CopyTo(
    $stopThunk, $manifest.stopEpochOffset)
[BitConverter]::GetBytes($capLow).CopyTo(
    $bootstrapThunk, $manifest.bootstrapCapabilityLowOffset)
[BitConverter]::GetBytes($capHigh).CopyTo(
    $bootstrapThunk, $manifest.bootstrapCapabilityHighOffset)
[BitConverter]::GetBytes([UInt64]1).CopyTo(
    $bootstrapThunk, $manifest.bootstrapEpochOffset)
[BitConverter]::GetBytes($capLow).CopyTo(
    $sealThunk, $manifest.sealCapabilityLowOffset)
[BitConverter]::GetBytes($capHigh).CopyTo(
    $sealThunk, $manifest.sealCapabilityHighOffset)
[BitConverter]::GetBytes([UInt64]1).CopyTo(
    $sealThunk, $manifest.sealEpochOffset)

if ([BitConverter]::ToUInt64($image, $shared) -ne
        [UInt64]0x7A6D94C13B52E807 -or
    [BitConverter]::ToUInt32($image, $shared + 16) -ne 1 -or
    [BitConverter]::ToUInt64(
        $image, $shared + $manifest.capabilityPayloadOffset) -ne $capLow -or
    [BitConverter]::ToUInt64(
        $image, $shared + $manifest.capabilityPayloadOffset + 8) -ne $capHigh) {
    throw 'Runtime bootstrap record does not match the public page ABI.'
}
if ([BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopCapabilityLowOffset) -ne $capLow -or
    [BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopCapabilityHighOffset) -ne $capHigh -or
    [BitConverter]::ToUInt64(
        $stopThunk, $manifest.stopEpochOffset) -ne 1) {
    throw 'Runtime stop-thunk patch does not match manifest offsets.'
}
if ([BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapCapabilityLowOffset) -ne $capLow -or
    [BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapCapabilityHighOffset) -ne $capHigh -or
    [BitConverter]::ToUInt64(
        $bootstrapThunk, $manifest.bootstrapEpochOffset) -ne 1) {
    throw 'Runtime bootstrap-thunk patch does not match manifest offsets.'
}
if ([BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealCapabilityLowOffset) -ne $capLow -or
    [BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealCapabilityHighOffset) -ne $capHigh -or
    [BitConverter]::ToUInt64(
        $sealThunk, $manifest.sealEpochOffset) -ne 1) {
    throw 'Runtime seal-thunk patch does not match manifest offsets.'
}
if ($manifestText -match '0123456789abcdef|fedcba9876543210') {
    throw 'Capability material leaked into mapper metadata.'
}

Write-Host (
    'Mapper artifact tests passed: image={0} entry={1} bootstrap={2} seal={3} stop={4} cleanup={5} sharedRva=0x{6:X}' -f
    $image.Length, $thunk.Length, $bootstrapThunk.Length,
    $sealThunk.Length, $stopThunk.Length, $cleanupThunk.Length, $shared)
