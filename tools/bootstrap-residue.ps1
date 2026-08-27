[CmdletBinding()]
param(
    [ValidateSet('Capture', 'Compare')]
    [string]$Mode = 'Capture',
    [Parameter(Mandatory)]
    [string]$SnapshotPath,
    [string]$OutputPath,
    [switch]$FailOnResidue,
    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ObjectDirectoryNames([string]$Path) {
    try {
        Import-Module NtObjectManager -ErrorAction Stop
        $directory = Get-NtDirectory -Path $Path
        try {
            return @(
                Get-NtDirectoryEntry $directory |
                    ForEach-Object { [string]$_.Name } |
                    Sort-Object -Unique
            )
        } finally {
            $directory.Dispose()
        }
    } catch {
        return @()
    }
}

function Get-ServiceSnapshot {
    $services = @()
    foreach ($key in Get-ChildItem `
            -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services' `
            -ErrorAction SilentlyContinue) {
        try {
            $value = Get-ItemProperty -LiteralPath $key.PSPath `
                -ErrorAction Stop
            $services += [pscustomobject][ordered]@{
                Name = [string]$key.PSChildName
                ImagePath = [string]$value.ImagePath
                Type = if ($null -ne $value.Type) {
                    [uint32]$value.Type
                } else { $null }
                Start = if ($null -ne $value.Start) {
                    [uint32]$value.Start
                } else { $null }
            }
        } catch {}
    }
    return @($services | Sort-Object Name)
}

function Get-DriverSnapshot {
    return @(
        Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Name = [string]$_.Name
                    State = [string]$_.State
                    StartMode = [string]$_.StartMode
                    PathName = [string]$_.PathName
                }
            } |
            Sort-Object Name
    )
}

function Get-TempDriverFiles {
    $roots = @($env:TEMP, (Join-Path $env:SystemRoot 'Temp')) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Sort-Object -Unique
    return @(
        foreach ($root in $roots) {
            Get-ChildItem -LiteralPath $root -Filter '*.sys' -File `
                -ErrorAction SilentlyContinue |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        Path = $_.FullName
                        Length = [uint64]$_.Length
                        LastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
                    }
                }
        }
    )
}

function Get-LastRecordId([string]$LogName) {
    try {
        $event = Get-WinEvent -LogName $LogName -MaxEvents 1 `
            -ErrorAction Stop
        return [uint64]$event.RecordId
    } catch {
        return [uint64]0
    }
}

function Get-Snapshot {
    $module = Get-Module -ListAvailable NtObjectManager |
        Select-Object -First 1
    return [pscustomobject][ordered]@{
        Schema = 'ophion.bootstrap-residue.snapshot.v1'
        CapturedUtc = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName = $env:COMPUTERNAME
        Services = @(Get-ServiceSnapshot)
        SystemDrivers = @(Get-DriverSnapshot)
        DriverObjects = @(Get-ObjectDirectoryNames '\Driver')
        DeviceObjects = @(Get-ObjectDirectoryNames '\Device')
        GlobalLinks = @(Get-ObjectDirectoryNames '\GLOBAL??')
        TempDriverFiles = @(Get-TempDriverFiles)
        EventHighWater = [ordered]@{
            System = Get-LastRecordId 'System'
            CodeIntegrity = Get-LastRecordId `
                'Microsoft-Windows-CodeIntegrity/Operational'
        }
        Coverage = [ordered]@{
            ServiceRegistry = $true
            SystemDriverProvider = $true
            ObjectManager = [bool]$module
            TempDriverFiles = $true
            SystemEventLog = $true
            CodeIntegrityEventLog = $true
            PiDDBCacheTable = $false
            MmUnloadedDrivers = $false
            ImageLoadEtwHistory = $false
        }
    }
}

function Get-AddedByName($Before, $After, [string]$Property) {
    $known = @{}
    foreach ($item in @($Before)) {
        $known[[string]$item.$Property] = $true
    }
    return @(
        foreach ($item in @($After)) {
            if (-not $known.ContainsKey([string]$item.$Property)) {
                $item
            }
        }
    )
}

function Get-ChangedServices($Before, $After) {
    $known = @{}
    foreach ($item in @($Before)) {
        $known[[string]$item.Name] = $item
    }
    return @(
        foreach ($item in @($After)) {
            if ($known.ContainsKey([string]$item.Name)) {
                $old = $known[[string]$item.Name]
                if ([string]$old.ImagePath -ne [string]$item.ImagePath -or
                    $old.Type -ne $item.Type -or
                    $old.Start -ne $item.Start) {
                    [pscustomobject][ordered]@{
                        Name = $item.Name
                        Before = $old
                        After = $item
                    }
                }
            }
        }
    )
}

function Get-NewEvents(
    [string]$LogName,
    [uint64]$AfterRecordId,
    [int[]]$Ids
) {
    try {
        $filter = @{ LogName = $LogName }
        if (@($Ids).Count) { $filter.Id = $Ids }
        return @(
            Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 `
                -ErrorAction Stop |
                Where-Object { [uint64]$_.RecordId -gt $AfterRecordId } |
                Sort-Object RecordId |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        RecordId = [uint64]$_.RecordId
                        TimeCreatedUtc = $_.TimeCreated.ToUniversalTime().
                            ToString('o')
                        Provider = $_.ProviderName
                        Id = [int]$_.Id
                        Level = $_.LevelDisplayName
                        Message = $_.Message
                    }
                }
        )
    } catch {
        return @()
    }
}

$snapshotDirectory = Split-Path -Parent $SnapshotPath
if ($snapshotDirectory) {
    New-Item -ItemType Directory -Force -Path $snapshotDirectory |
        Out-Null
}

if ($Mode -eq 'Capture') {
    $snapshot = Get-Snapshot
    $snapshot | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $SnapshotPath -Encoding UTF8
    if ($AsObject) { return $snapshot }
    Write-Host "Bootstrap residue baseline captured: $SnapshotPath"
    return
}

if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
    throw "Baseline snapshot missing: $SnapshotPath"
}
$before = Get-Content -LiteralPath $SnapshotPath -Raw |
    ConvertFrom-Json
$after = Get-Snapshot

$addedServices = @(Get-AddedByName `
    $before.Services $after.Services 'Name')
$changedServices = @(Get-ChangedServices `
    $before.Services $after.Services)
$addedDrivers = @(Get-AddedByName `
    $before.SystemDrivers $after.SystemDrivers 'Name')
$addedTempFiles = @(Get-AddedByName `
    $before.TempDriverFiles $after.TempDriverFiles 'Path')

$addedDriverObjects = @(
    $after.DriverObjects | Where-Object {
        $_ -notin @($before.DriverObjects)
    }
)
$addedDeviceObjects = @(
    $after.DeviceObjects | Where-Object {
        $_ -notin @($before.DeviceObjects)
    }
)
$addedGlobalLinks = @(
    $after.GlobalLinks | Where-Object {
        $_ -notin @($before.GlobalLinks)
    }
)

$systemEvents = @(Get-NewEvents 'System' `
    ([uint64]$before.EventHighWater.System) `
    @(7000, 7001, 7009, 7011, 7026, 7045))
$codeIntegrityEvents = @(Get-NewEvents `
    'Microsoft-Windows-CodeIntegrity/Operational' `
    ([uint64]$before.EventHighWater.CodeIntegrity) @())

$residueDetected =
    $addedServices.Count -ne 0 -or
    $changedServices.Count -ne 0 -or
    $addedDrivers.Count -ne 0 -or
    $addedDriverObjects.Count -ne 0 -or
    $addedDeviceObjects.Count -ne 0 -or
    $addedGlobalLinks.Count -ne 0 -or
    $addedTempFiles.Count -ne 0

$report = [pscustomobject][ordered]@{
    Schema = 'ophion.bootstrap-residue.report.v1'
    BaselineUtc = $before.CapturedUtc
    ComparedUtc = $after.CapturedUtc
    ResidueDetected = $residueDetected
    Added = [ordered]@{
        Services = @($addedServices)
        ChangedServices = @($changedServices)
        SystemDrivers = @($addedDrivers)
        DriverObjects = @($addedDriverObjects)
        DeviceObjects = @($addedDeviceObjects)
        GlobalLinks = @($addedGlobalLinks)
        TempDriverFiles = @($addedTempFiles)
    }
    Events = [ordered]@{
        SystemDriverService = @($systemEvents)
        CodeIntegrity = @($codeIntegrityEvents)
    }
    Coverage = $after.Coverage
    Uncovered = @(
        'PiDDBCacheTable structural state'
        'MmUnloadedDrivers structural state'
        'historical ImageLoad ETW not captured before baseline'
    )
}

if ($OutputPath) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ($outputDirectory) {
        New-Item -ItemType Directory -Force -Path $outputDirectory |
            Out-Null
    }
    $report | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
if ($FailOnResidue -and $residueDetected) {
    throw 'Bootstrap residue detected; inspect the comparison report.'
}
if ($AsObject) { return $report }
$report | ConvertTo-Json -Depth 10
