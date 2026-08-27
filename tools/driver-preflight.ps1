[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Path,

    [ValidateSet('directio', 'lnvmsrio')]
    [string]$Backend,

    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [IO.File]::ReadAllBytes($resolved)
if ($bytes.Length -lt 0x100) { throw 'File is too small to be a PE image.' }
$peOffset = [BitConverter]::ToUInt32($bytes, 0x3C)
if ($peOffset + 6 -gt $bytes.Length -or
    [BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
    throw 'File is not a valid PE image.'
}
$machineValue = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
$machine = switch ($machineValue) {
    0x8664 { 'x64' }
    0x014C { 'x86' }
    0xAA64 { 'arm64' }
    default { '0x{0:X4}' -f $machineValue }
}

$signature = Get-AuthenticodeSignature -LiteralPath $resolved
$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($resolved)
$sha256 = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
$osBuild = [Environment]::OSVersion.Version.Build

$provider = switch ($Backend) {
    'directio' {
        [ordered]@{
            Name = 'DirectIo64_legacy'
            ExpectedDevice = 'dynamic service/device name'
            MinNtBuild = $null
            MaxNtBuild = $null
            HvciSupport = 'unknown'
            UnloadSupport = 'unknown'
            RequiresCompanion = $false
            AdvisoryIds = @()
        }
    }
    'lnvmsrio' {
        [ordered]@{
            Name = 'LnvMSRIO'
            ExpectedDevice = '\\.\WinMsrDev'
            MinNtBuild = $null
            MaxNtBuild = $null
            HvciSupport = 'unknown'
            UnloadSupport = 'unknown'
            RequiresCompanion = $false
            AdvisoryIds = @('CVE-2025-8061')
        }
    }
    default {
        [ordered]@{
            Name = 'unknown'
            ExpectedDevice = $null
            MinNtBuild = $null
            MaxNtBuild = $null
            HvciSupport = 'unknown'
            UnloadSupport = 'unknown'
            RequiresCompanion = 'unknown'
            AdvisoryIds = @()
        }
    }
}

$vbsStatus = $null
$hvciConfigured = $null
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName Win32_DeviceGuard -ErrorAction Stop
    $vbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
    $hvciConfigured = @(2) | Where-Object {
        [int[]]$dg.SecurityServicesConfigured -contains $_
    } | ForEach-Object { $true } | Select-Object -First 1
    if ($null -eq $hvciConfigured) { $hvciConfigured = $false }
} catch {}

$policies = @()
$ciTool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
if (Test-Path -LiteralPath $ciTool) {
    try {
        $ci = (& $ciTool --list-policies --json | ConvertFrom-Json)
        $policies = @($ci.Policies | Where-Object IsEnforced | ForEach-Object {
            [ordered]@{
                PolicyId = $_.PolicyID
                FriendlyName = $_.FriendlyName
                Version = $_.VersionString
                Authorized = [bool]$_.IsAuthorized
            }
        })
    } catch {}
}

$signatureValid =
    $signature.Status -eq [Management.Automation.SignatureStatus]::Valid
$architectureValid = $machine -eq 'x64'
$ready = $signatureValid -and $architectureValid -and $Backend
$reasons = @()
if (-not $signatureValid) { $reasons += "Authenticode=$($signature.Status)" }
if (-not $architectureValid) { $reasons += "Machine=$machine" }
if (-not $Backend) { $reasons += 'Backend metadata not selected' }
if ($provider.HvciSupport -eq 'unknown') { $reasons += 'HVCI compatibility unknown' }
$reasons += 'Exact vulnerable-driver deny-list snapshot not configured'

$report = [pscustomobject][ordered]@{
    Schema = 'ophion.driver-preflight.v1'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('o')
    Path = $resolved
    Sha256 = $sha256
    Authentihash = $null
    Machine = $machine
    OriginalFilename = $version.OriginalFilename
    FileVersion = $version.FileVersion
    ProductVersion = $version.ProductVersion
    CompanyName = $version.CompanyName
    Trust = [ordered]@{
        Status = [string]$signature.Status
        IsValid = $signatureValid
        SignerSubject = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Subject
        } else { $null }
        SignerThumbprint = if ($signature.SignerCertificate) {
            $signature.SignerCertificate.Thumbprint
        } else { $null }
        StatusMessage = $signature.StatusMessage
    }
    Provider = $provider
    Platform = [ordered]@{
        OsBuild = $osBuild
        VbsStatus = $vbsStatus
        HvciConfigured = $hvciConfigured
        EnforcedCodeIntegrityPolicies = $policies
    }
    ExactHashDenyList = [ordered]@{
        Configured = $false
        Match = $null
        SourceRevision = $null
    }
    ReadyToAttemptLoad = [bool]$ready
    Reasons = $reasons
}

if ($AsObject) {
    return $report
}
$report | ConvertTo-Json -Depth 8
