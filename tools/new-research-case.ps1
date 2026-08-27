[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('EAC', 'EAC-EOS', 'BattlEye', 'KEVLAR')]
    [string]$Product,
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BinaryPath,
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$GameBuild,
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputRoot) { $OutputRoot = Join-Path $repo 'build\research-cases' }

$binary = Get-Item -LiteralPath (Resolve-Path -LiteralPath $BinaryPath)
$hash = (Get-FileHash -LiteralPath $binary.FullName -Algorithm SHA256).Hash
$version = $binary.VersionInfo
$signature = Get-AuthenticodeSignature -LiteralPath $binary.FullName
$caseId = '{0}-{1}-{2}' -f $Product.ToLowerInvariant(), $GameBuild, $hash.Substring(0, 12).ToLowerInvariant()
$caseDir = Join-Path $OutputRoot $caseId
if (Test-Path -LiteralPath $caseDir) {
    throw "Research case already exists: $caseDir"
}
[void][IO.Directory]::CreateDirectory((Join-Path $caseDir 'raw'))
[void][IO.Directory]::CreateDirectory((Join-Path $caseDir 'observations'))
[void][IO.Directory]::CreateDirectory((Join-Path $caseDir 'analysis'))

$manifest = [pscustomobject][ordered]@{
    Schema = 'ophion.research-case.v1'
    CaseId = $caseId
    Product = $Product
    GameBuild = $GameBuild
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
    Binary = [pscustomobject][ordered]@{
        OriginalPath = $binary.FullName
        FileName = $binary.Name
        Bytes = $binary.Length
        Sha256 = $hash
        FileVersion = $version.FileVersion
        ProductVersion = $version.ProductVersion
        CompanyName = $version.CompanyName
        AuthenticodeStatus = [string]$signature.Status
        SignerThumbprint = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Thumbprint
        } else { $null }
        SignerSubject = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        } else { $null }
    }
    EvidenceState = 'intake-only'
    RuntimeExecuted = $false
    ProductVerdictObserved = $false
    RequiredIndependentViews = 2
}
$manifest | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $caseDir 'manifest.json') -Encoding UTF8

@"
# $caseId

This case is an intake record, not evidence of detection resilience.

## Required gates

- Preserve the original SHA-256 and signature metadata.
- Record static and runtime observations separately.
- Confirm important claims through two independent views.
- Pin every offset/signature to this binary hash.
- Keep immediate kick, telemetry anomaly, delayed verdict, and account/device action separate.
"@ | Set-Content -LiteralPath (Join-Path $caseDir 'README.md') -Encoding UTF8

$manifest