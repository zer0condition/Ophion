[CmdletBinding()]
param(
    [ValidateRange(1, 168)]
    [int]$Hours = 24,
    [switch]$IncludeSystemEvtx
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $repo "build\crash-artifacts\$stamp"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$since = (Get-Date).AddHours(-$Hours)

$summary = [ordered]@{
    Schema = 'ophion.crash-artifacts.v1'
    CollectedUtc = (Get-Date).ToUniversalTime().ToString('o')
    SinceUtc = $since.ToUniversalTime().ToString('o')
    Computer = $env:COMPUTERNAME
    OsBuild = [Environment]::OSVersion.Version.ToString()
    HypervisorPresent = $null
    VbsStatus = $null
    MemoryDump = $null
    MiniDumps = @()
}

try {
    $summary.HypervisorPresent =
        [bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
} catch {}
try {
    $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
        -ClassName Win32_DeviceGuard -ErrorAction Stop
    $summary.VbsStatus = [int]$dg.VirtualizationBasedSecurityStatus
} catch {}

$memoryDump = Join-Path $env:SystemRoot 'MEMORY.DMP'
if (Test-Path -LiteralPath $memoryDump) {
    $item = Get-Item -LiteralPath $memoryDump
    $summary.MemoryDump = [ordered]@{
        Path = $item.FullName
        Length = $item.Length
        LastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
        Sha256 = if ($item.Length -le 2GB) {
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        } else { $null }
    }
}

$miniRoot = Join-Path $env:SystemRoot 'Minidump'
if (Test-Path -LiteralPath $miniRoot) {
    foreach ($dump in Get-ChildItem -LiteralPath $miniRoot -Filter '*.dmp' -File |
        Where-Object LastWriteTime -ge $since |
        Sort-Object LastWriteTime) {
        $dest = Join-Path $out $dump.Name
        Copy-Item -LiteralPath $dump.FullName -Destination $dest -Force
        $summary.MiniDumps += [ordered]@{
            Source = $dump.FullName
            Copy = $dest
            Length = $dump.Length
            LastWriteUtc = $dump.LastWriteTimeUtc.ToString('o')
            Sha256 = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
        }
    }
}

$providers = @(
    'Microsoft-Windows-WER-SystemErrorReporting',
    'Microsoft-Windows-Kernel-Power',
    'Microsoft-Windows-WHEA-Logger',
    'BugCheck'
)
$events = foreach ($provider in $providers) {
    try {
        Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since; ProviderName=$provider } `
            -ErrorAction Stop |
            Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message
    } catch {}
}
$events | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'system-events.json') -Encoding utf8

try {
    Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since; Id=41,1001 } `
        -ErrorAction Stop |
        Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $out 'bugcheck-power-events.json') -Encoding utf8
} catch {}

if ($IncludeSystemEvtx) {
    & wevtutil.exe epl System (Join-Path $out 'System.evtx') /ow:true
}

$driverFiles = @(
    (Join-Path $repo 'build\bin\Release\Ophion.sys'),
    (Join-Path $repo 'build\bin\Release\Ophion-production.sys'),
    (Join-Path $repo 'build\bin\Release\Ophion.pdb')
)
$driverInfo = foreach ($file in $driverFiles) {
    if (Test-Path -LiteralPath $file) {
        $item = Get-Item -LiteralPath $file
        [ordered]@{
            Path = $item.FullName
            Length = $item.Length
            LastWriteUtc = $item.LastWriteTimeUtc.ToString('o')
            Sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
        }
    }
}
$driverInfo | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $out 'build-artifacts.json') -Encoding utf8

[pscustomobject]$summary | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath (Join-Path $out 'summary.json') -Encoding utf8

Write-Host "Crash artifacts: $out"
