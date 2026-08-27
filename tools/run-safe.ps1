[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [ValidateSet('directio', 'lnvmsrio')]
    [string]$Backend = 'lnvmsrio',

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$VulnerableDriver,

    [Parameter(Mandatory, ParameterSetName = 'Existing')]
    [switch]$Existing,

    [Parameter(Mandatory, ParameterSetName = 'Existing')]
    [string]$DevicePath,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$OphionImage,

    [switch]$Smoke,
    [switch]$Walk,
    [switch]$Build,
    [switch]$TpmAudit,
    [switch]$SkipMmioApertureCheck,
    [switch]$AllowInvalidSignature
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator elevation is required.'
}

$repo = Split-Path -Parent $PSScriptRoot
$loader = Join-Path $repo 'build\bin\Release\OphionLoad.exe'
if ($Build -or -not (Test-Path -LiteralPath $loader)) {
    & (Join-Path $PSScriptRoot 'build-load.ps1') -Configuration Release -WarningsAsErrors
}
if (-not (Test-Path -LiteralPath $loader)) {
    throw "Loader not found: $loader"
}

if (-not $Existing) {
    $driverPath = (Resolve-Path -LiteralPath $VulnerableDriver).Path
    $preflight = & (Join-Path $PSScriptRoot 'driver-preflight.ps1') `
        -Path $driverPath -Backend $Backend -AsObject
    if (-not $AllowInvalidSignature -and -not $preflight.Trust.IsValid) {
        throw "Driver Authenticode status is $($preflight.Trust.Status): $driverPath"
    }
    if ($preflight.Machine -ne 'x64') {
        throw "Driver machine type is $($preflight.Machine), expected x64"
    }
    $preflightPath = Join-Path $repo 'build\driver-preflight-latest.json'
    $preflight | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $preflightPath -Encoding utf8
    Write-Host "Driver SHA256: $($preflight.Sha256)"
    Write-Host "Driver signer: $($preflight.Trust.SignerSubject)"
    Write-Host "Driver version: $($preflight.FileVersion)"
    Write-Host "Preflight report: $preflightPath"
}

if ($OphionImage) {
    $vbs = $false
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbs = [int]$dg.VirtualizationBasedSecurityStatus -ne 0
    } catch {
        $vbs = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    }
    if ($vbs) {
        throw 'Hyper-V/VBS is active. Nested hypercall pass-through is unsupported; refusing VMX launch.'
    }

    if (-not $SkipMmioApertureCheck) {
        try {
            $limit = [uint64]1 -shl 39
            $high = @(Get-CimInstance Win32_DeviceMemoryAddress -ErrorAction Stop |
                Where-Object {
                    [uint64]$_.StartingAddress -ge $limit -or
                    [uint64]$_.EndingAddress -ge $limit
                })
            if ($high.Count) {
                $sample = $high | Select-Object -First 1
                throw ('A device MMIO range exceeds Ophion''s 512-GiB EPT aperture: ' +
                    $sample.StartingAddress + '-' + $sample.EndingAddress)
            }
        } catch {
            throw ('MMIO aperture preflight failed closed: ' + $_.Exception.Message)
        }
    }
}

if ($TpmAudit) {
    & (Join-Path $PSScriptRoot 'tpm-audit.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "TPM audit failed with exit code $LASTEXITCODE"
    }
}

$argsList = @('--driver', $Backend)
if ($Existing) {
    $argsList += @('--existing', '--device', $DevicePath)
} else {
    $argsList += @('--vuln', (Resolve-Path -LiteralPath $VulnerableDriver).Path)
}
if ($OphionImage) {
    $argsList += @('--load-image', (Resolve-Path -LiteralPath $OphionImage).Path)
}
if ($Smoke) { $argsList += '--smoke' }
if ($Walk)  { $argsList += '--walk' }

Write-Host ('> ' + $loader + ' ' + ($argsList -join ' '))
& $loader @argsList
if ($LASTEXITCODE -ne 0) {
    throw "OphionLoad failed with exit code $LASTEXITCODE"
}
