[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Path,
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$DumpbinPath
    ,
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ObjectManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolved = (Resolve-Path -LiteralPath $Path).Path
$objectManifest = Get-Content -LiteralPath $ObjectManifestPath -Raw | ConvertFrom-Json
if ($objectManifest.Schema -ne 'ophion.driver-object-manifest.v1' -or
    $objectManifest.Profile -ne 'Production') {
    throw 'Object manifest is not a production driver manifest.'
}
$forbiddenSources = @('eac_stealth.c', 'tracewipe.c', 'byovd_conceal.c')
$presentSources = @($objectManifest.Sources | ForEach-Object { [string]$_ })
$badSources = @($forbiddenSources | Where-Object { $presentSources -contains $_ })
if ($badSources.Count) {
    throw "Production object manifest contains experiment sources: $($badSources -join ', ')"
}
if ($presentSources -notcontains 'production_safe_profile.c') {
    throw 'Production object manifest is missing production_safe_profile.c.'
}
$bytes = [IO.File]::ReadAllBytes($resolved)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$utf16 = [Text.Encoding]::Unicode.GetString($bytes)
$forbidden = @(
    'PiDDBCacheTable', 'MmUnloadedDrivers', 'PsLoadedModuleList',
    'KdDebuggerEnabled', 'KdEnteredDebugger', 'VslGetSecurePciEnabled',
    'HvlQueryConnection', 'PSTRIP64', 'WinMsrDev', 'DirectIo64',
    'conceal-byovd', 'Tracewipe verified clean')
$found = @($forbidden | Where-Object {
    $ascii.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
    $utf16.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0
})
if ($found.Count) {
    throw "Production image contains forbidden experiment markers: $($found -join ', ')"
}

$imports = (& $DumpbinPath /nologo /imports $resolved 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'dumpbin /imports failed.' }
$forbiddenImports = @(
    'IoCreateDevice', 'IoCreateSymbolicLink', 'ZwLoadDriver',
    'PsLoadedModuleList')
$badImports = @($forbiddenImports | Where-Object {
    $imports -match ('(?im)^\s*' + [regex]::Escape($_) + '\s*$')
})
if ($badImports.Count) {
    throw "Production image imports forbidden experiment surface: $($badImports -join ', ')"
}

[pscustomobject][ordered]@{
    Schema = 'ophion.production-boundary.v1'
    Path = $resolved
    Sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
    ForbiddenMarkers = 0
    ForbiddenImports = 0
    SourceManifest = (Resolve-Path -LiteralPath $ObjectManifestPath).Path
    SourceCount = $presentSources.Count
    VerifiedUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 3