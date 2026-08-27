[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'tools\tpm-audit.ps1'
function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "TPM audit test failed: $Message" }
}
function Write-Evidence(
    [string]$Path,
    [string]$SecureBoot,
    [int]$TpmVersion,
    [bool]$PcrRead,
    [int]$PcrCount,
    [int]$LogCount) {
    [ordered]@{
        Schema = 'ophion.tpm-evidence.v1'
        SecureBoot = $SecureBoot
        TpmVersion = $TpmVersion
        PcrSha256Read = $PcrRead
        PcrCount = $PcrCount
        MeasuredBootLogCount = $LogCount
        TcgLogReplay = if ($LogCount) { 'matched' } else { 'unknown' }
        AttestationHealth = if ($LogCount) { 'Attestable' } else { 'unknown' }
        MutationPerformed = $false
    } | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
}

$temp = Join-Path ([IO.Path]::GetTempPath()) (
    'ophion-tpm-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $good = Join-Path $temp 'good.json'
    Write-Evidence $good 'enabled' 2 $true 5 1
    $compatible = & $tool -EvidencePath $good -AsObject
    Assert ($compatible.Schema -eq 'ophion.tpm-audit.v2') 'schema'
    Assert ($compatible.AttachmentPolicy -eq 'compatible') 'compatible classification'
    Assert ($compatible.ReadyForMeasuredBootNeutralProvider -eq $true) 'compatible readiness'
    Assert ($compatible.PreservationValidated -eq $false) 'provider preservation must remain unclaimed'

    $unknown = Join-Path $temp 'unknown.json'
    Write-Evidence $unknown 'unknown' 2 $true 5 1
    $inconclusive = & $tool -EvidencePath $unknown -AsObject
    Assert ($inconclusive.AttachmentPolicy -eq 'inconclusive') 'unknown classification'
    Assert ($inconclusive.Reasons -contains 'Secure Boot state is unknown') 'unknown reason'

    $disabled = Join-Path $temp 'disabled.json'
    Write-Evidence $disabled 'disabled' 2 $true 5 1
    $incompatible = & $tool -EvidencePath $disabled -AsObject
    Assert ($incompatible.AttachmentPolicy -eq 'incompatible') 'disabled classification'
    Assert ($incompatible.ReadyForMeasuredBootNeutralProvider -eq $false) 'disabled readiness'

    $malformed = Join-Path $temp 'malformed.json'
    '{"Schema":"wrong"}' | Set-Content -LiteralPath $malformed -Encoding UTF8
    $threw = $false
    try {
        [void](& $tool -EvidencePath $malformed -AsObject)
    } catch {
        $threw = $true
    }
    Assert $threw 'malformed evidence must throw'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'TPM audit tests passed: compatible, inconclusive, incompatible, malformed'
