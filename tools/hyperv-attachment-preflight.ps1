[CmdletBinding()]
param(
    [ValidateSet('probe', 'root', 'nested')]
    [string]$Mode = 'probe',

    [string]$ProbePath,

    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$SnapshotPath,

    [string]$OutputPath,

    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schema = 'ophion.hyperv-attachment-preflight.v1'
$hv1 = [uint32]824407624       # 0x31237648, "Hv#1"
$minimumLeaf = [uint32]1073741829 # 0x40000005
$maximumLeaf = [uint32]1073742079 # 0x400000FF
$rootPrivileges = [uint64]12884901920 # bits 5, 32, 33
$modeCodes = @{ probe = 0; root = 1; nested = 2 }
$failureCodes = @{
    'none' = 0
    'no-hypervisor' = 2
    'interface-mismatch' = 3
    'cpuid-truncated' = 4
    'privilege-missing' = 5
    'nested-unavailable' = 6
    'cpuid-incoherent' = 17
}
$transitions = [Collections.Generic.List[string]]::new()
$transitions.Add('empty')

function Convert-ToUInt32($Value, [string]$Name) {
    if ($null -eq $Value) { throw "$Name is missing." }
    if ($Value -is [string]) {
        if ($Value -match '^0[xX][0-9a-fA-F]+$') {
            return [Convert]::ToUInt32($Value.Substring(2), 16)
        }
        if ($Value -notmatch '^[0-9]+$') {
            throw "$Name is not an unsigned integer."
        }
    }
    try {
        return [Convert]::ToUInt32($Value)
    } catch {
        throw "$Name is outside the UInt32 range."
    }
}

function Convert-CpuidRecord($Record, [string]$Name) {
    [pscustomobject][ordered]@{
        Leaf = Convert-ToUInt32 $Record.Leaf "$Name.Leaf"
        Eax = Convert-ToUInt32 $Record.Eax "$Name.Eax"
        Ebx = Convert-ToUInt32 $Record.Ebx "$Name.Ebx"
        Ecx = Convert-ToUInt32 $Record.Ecx "$Name.Ecx"
        Edx = Convert-ToUInt32 $Record.Edx "$Name.Edx"
    }
}

function New-LeafMap($Records, [string]$Name) {
    $map = @{}
    $index = 0
    foreach ($record in @($Records)) {
        $normalized = Convert-CpuidRecord $record "$Name[$index]"
        if ($map.ContainsKey($normalized.Leaf)) {
            throw "$Name contains duplicate leaf 0x$($normalized.Leaf.ToString('X8'))."
        }
        $map[$normalized.Leaf] = $normalized
        $index++
    }
    return $map
}

function Convert-ProbeProcessor($Processor, [int]$Index) {
    if (-not $Processor.cpuid) {
        throw "Probe processor $Index has no cpuid record."
    }
    $records = [Collections.Generic.List[object]]::new()
    $leaf1 = $Processor.cpuid.leaf1
    $records.Add([pscustomobject]@{
        Leaf = 1
        Eax = $leaf1.eax
        Ebx = $leaf1.ebx
        Ecx = $leaf1.ecx
        Edx = $leaf1.edx
    })
    if ($Processor.cpuid.hypervisorLeaves) {
        foreach ($leaf in @($Processor.cpuid.hypervisorLeaves)) {
            $records.Add($leaf)
        }
    } else {
        $base = $Processor.cpuid.hypervisorBase
        $interface = $Processor.cpuid.hypervisorInterface
        $records.Add([pscustomobject]@{
            Leaf = [uint32]1073741824
            Eax = $base.eax
            Ebx = $base.ebx
            Ecx = $base.ecx
            Edx = $base.edx
        })
        $records.Add([pscustomobject]@{
            Leaf = [uint32]1073741825
            Eax = $interface.eax
            Ebx = $interface.ebx
            Ecx = $interface.ecx
            Edx = $interface.edx
        })
    }
    return New-LeafMap $records "probe.processors[$Index].cpuid"
}

function Invoke-Probe([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "CPUID probe was not found: $Path"
    }
    $lines = @(& $Path --samples 1)
    if ($LASTEXITCODE -ne 0) {
        throw "CPUID probe failed with exit code $LASTEXITCODE."
    }
    $probe = ($lines -join "`n") | ConvertFrom-Json
    if ($probe.schema -ne 'ophion.probe.v1' -or
        -not $probe.processors -or
        @($probe.processors).Count -eq 0) {
        throw 'CPUID probe output has an unsupported schema or no processors.'
    }
    $maps = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt @($probe.processors).Count; $index++) {
        $maps.Add((Convert-ProbeProcessor $probe.processors[$index] $index))
    }
    return [pscustomobject]@{
        Source = 'live-probe'
        OsBuild = [Environment]::OSVersion.Version.Build
        Maps = $maps
    }
}

function Read-Snapshot([string]$Path) {
    $snapshot = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($snapshot.Schema -ne 'ophion.hyperv-cpuid.v1') {
        throw 'Snapshot schema must be ophion.hyperv-cpuid.v1.'
    }
    if ($snapshot.Architecture -ne 'x64') {
        throw 'Snapshot architecture must be x64.'
    }
    if (-not $snapshot.Leaves) {
        throw 'Snapshot contains no CPUID leaves.'
    }
    return [pscustomobject]@{
        Source = 'snapshot'
        OsBuild = Convert-ToUInt32 $snapshot.OsBuild 'snapshot.OsBuild'
        Maps = @((New-LeafMap $snapshot.Leaves 'snapshot.Leaves'))
    }
}

function Get-Leaf($Map, [uint32]$Leaf) {
    if ($Map.ContainsKey($Leaf)) { return $Map[$Leaf] }
    return $null
}

function Get-Vendor([object]$BaseLeaf) {
    $bytes = [Collections.Generic.List[byte]]::new()
    foreach ($word in @($BaseLeaf.Ebx, $BaseLeaf.Ecx, $BaseLeaf.Edx)) {
        $bytes.AddRange([BitConverter]::GetBytes([uint32]$word))
    }
    return [Text.Encoding]::ASCII.GetString($bytes.ToArray()).Trim([char]0)
}

function Get-DeviceGuard {
    $result = [ordered]@{
        VbsStatus = 0
        Configured = 0
        Running = 0
    }
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop
        $result.VbsStatus = [uint32]$dg.VirtualizationBasedSecurityStatus
        foreach ($service in @($dg.SecurityServicesConfigured)) {
            if ([int]$service -gt 0 -and [int]$service -lt 32) {
                $result.Configured = $result.Configured -bor (1 -shl [int]$service)
            }
        }
        foreach ($service in @($dg.SecurityServicesRunning)) {
            if ([int]$service -gt 0 -and [int]$service -lt 32) {
                $result.Running = $result.Running -bor (1 -shl [int]$service)
            }
        }
    } catch {}
    return [pscustomobject]$result
}

function Complete-Failure(
    [string]$Failure,
    [hashtable]$Platform,
    [string]$Source) {
    $transitions.Add('failed')
    return [pscustomobject][ordered]@{
        Schema = $schema
        GeneratedUtc = [DateTime]::UtcNow.ToString('o')
        ReadOnly = $true
        Mode = $Mode
        ModeCode = [uint32]$modeCodes[$Mode]
        State = 'failed'
        StateCode = 5
        Failure = $Failure
        FailureCode = [uint32]$failureCodes[$Failure]
        ReadyForProvider = $false
        TransitionLog = @($transitions)
        Source = $Source
        Platform = [pscustomobject]$Platform
        Boundary = 'Read-only discovery only; no MSR, hypercall, boot, TPM, policy, or driver mutation.'
    }
}

$inputData = if ($SnapshotPath) {
    Read-Snapshot $SnapshotPath
} else {
    if (-not $ProbePath) {
        $ProbePath = Join-Path $PSScriptRoot '..\build\bin\Release\OphionProbe.exe'
    }
    Invoke-Probe $ProbePath
}

$maps = @($inputData.Maps)
$first = $maps[0]
$leaf1 = Get-Leaf $first 1
$base = Get-Leaf $first ([uint32]1073741824)
$interface = Get-Leaf $first ([uint32]1073741825)
$feature = Get-Leaf $first ([uint32]1073741827)
$recommendation = Get-Leaf $first ([uint32]1073741828)
$hardware = Get-Leaf $first ([uint32]1073741830)
$nested = Get-Leaf $first ([uint32]1073741834)
$dg = if ($SnapshotPath) {
    [pscustomobject]@{ VbsStatus = 0; Configured = 0; Running = 0 }
} else {
    Get-DeviceGuard
}

$platform = [ordered]@{
    Architecture = 'x64'
    OsBuild = [uint32]$inputData.OsBuild
    HypervisorPresent = $false
    MaximumHypervisorLeaf = 0
    HypervisorVendor = $null
    InterfaceSignature = 0
    PartitionPrivileges = [uint64]0
    PartitionType = 'unknown'
    Recommendations = 0
    HardwareFeatures = 0
    NestedFeatures = 0
    VbsStatus = [uint32]$dg.VbsStatus
    SecurityServicesConfigured = [uint32]$dg.Configured
    SecurityServicesRunning = [uint32]$dg.Running
    FeatureFlags = @()
}

if (-not $leaf1 -or -not $base -or -not $interface) {
    $result = Complete-Failure 'cpuid-truncated' $platform $inputData.Source
} else {
    $platform.HypervisorPresent =
        (([uint32]$leaf1.Ecx -band [uint32]2147483648) -ne 0)
    $platform.MaximumHypervisorLeaf = [uint32]$base.Eax
    $platform.HypervisorVendor = if ($platform.HypervisorPresent) {
        Get-Vendor $base
    } else {
        $null
    }
    $platform.InterfaceSignature = [uint32]$interface.Eax
    $transitions.Add('discovered')

    $incoherent = $false
    foreach ($map in $maps) {
        $otherLeaf1 = Get-Leaf $map 1
        $otherBase = Get-Leaf $map ([uint32]1073741824)
        $otherInterface = Get-Leaf $map ([uint32]1073741825)
        if (-not $otherLeaf1 -or -not $otherBase -or -not $otherInterface -or
            [uint32]$otherLeaf1.Ecx -ne [uint32]$leaf1.Ecx -or
            [uint32]$otherBase.Eax -ne [uint32]$base.Eax -or
            [uint32]$otherBase.Ebx -ne [uint32]$base.Ebx -or
            [uint32]$otherBase.Ecx -ne [uint32]$base.Ecx -or
            [uint32]$otherBase.Edx -ne [uint32]$base.Edx -or
            [uint32]$otherInterface.Eax -ne [uint32]$interface.Eax) {
            $incoherent = $true
            break
        }
    }

    if ($incoherent) {
        $result = Complete-Failure 'cpuid-incoherent' $platform $inputData.Source
    } elseif (-not $platform.HypervisorPresent) {
        $result = Complete-Failure 'no-hypervisor' $platform $inputData.Source
    } elseif ($platform.MaximumHypervisorLeaf -lt $minimumLeaf -or
              $platform.MaximumHypervisorLeaf -gt $maximumLeaf) {
        $result = Complete-Failure 'cpuid-truncated' $platform $inputData.Source
    } elseif ($platform.InterfaceSignature -ne $hv1) {
        $result = Complete-Failure 'interface-mismatch' $platform $inputData.Source
    } elseif ($Mode -ne 'probe' -and
              (-not $feature -or -not $recommendation)) {
        $result = Complete-Failure 'cpuid-truncated' $platform $inputData.Source
    } else {
        if ($feature) {
            $privileges = [uint64]$feature.Eax -bor (
                [uint64]$feature.Ebx -shl 32)
            $platform.PartitionPrivileges = $privileges
            if (($privileges -band [uint64]32) -ne 0) {
                $platform.FeatureFlags += 'hypercall-msr'
            }
            if (($privileges -band [uint64]8589934592) -ne 0) {
                $platform.FeatureFlags += 'partition-id'
            }
            if (($privileges -band [uint64]4294967296) -ne 0) {
                $platform.FeatureFlags += 'create-partitions'
            }
            if (($privileges -band ([uint64]1 -shl 49)) -ne 0) {
                $platform.FeatureFlags += 'vp-registers'
            }
            if (($privileges -band ([uint64]1 -shl 52)) -ne 0) {
                $platform.FeatureFlags += 'extended-hypercalls'
            }
            if (($privileges -band ([uint64]1 -shl 53)) -ne 0) {
                $platform.FeatureFlags += 'start-vp'
            }
            if (($privileges -band $rootPrivileges) -eq $rootPrivileges) {
                $platform.PartitionType = 'root'
            }
        }
        if ($recommendation) {
            $platform.Recommendations = [uint32]$recommendation.Eax
            if (([uint32]$recommendation.Eax -band 0x1000) -ne 0) {
                $platform.PartitionType = 'nested'
            }
            if (([uint32]$recommendation.Eax -band 0x4000) -ne 0) {
                $platform.FeatureFlags += 'enlightened-vmcs-recommended'
            }
        }
        if ($hardware) {
            $platform.HardwareFeatures = [uint32]$hardware.Eax
        }
        if ($nested) {
            $platform.NestedFeatures = [uint32]$nested.Eax
            if (([uint32]$nested.Eax -band 0xFFFF) -ne 0) {
                $platform.FeatureFlags += 'enlightened-vmcs'
            }
        }

        if ($Mode -eq 'root' -and
            ($platform.PartitionPrivileges -band $rootPrivileges) -ne
                $rootPrivileges) {
            $result = Complete-Failure 'privilege-missing' $platform $inputData.Source
        } elseif ($Mode -eq 'nested' -and (
            $platform.PartitionType -ne 'nested' -or
            -not $nested -or
            ([uint32]$nested.Eax -band 0xFFFF) -eq 0)) {
            $result = Complete-Failure 'nested-unavailable' $platform $inputData.Source
        } else {
            $transitions.Add('eligible')
            $result = [pscustomobject][ordered]@{
                Schema = $schema
                GeneratedUtc = [DateTime]::UtcNow.ToString('o')
                ReadOnly = $true
                Mode = $Mode
                ModeCode = [uint32]$modeCodes[$Mode]
                State = 'eligible'
                StateCode = 2
                Failure = 'none'
                FailureCode = 0
                ReadyForProvider = ($Mode -ne 'probe')
                TransitionLog = @($transitions)
                Source = $inputData.Source
                Platform = [pscustomobject]$platform
                Boundary = 'Eligibility only; no Hyper-V attachment provider was invoked.'
            }
        }
    }
}

if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        [void][IO.Directory]::CreateDirectory($parent)
    }
    $result | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
if ($AsObject) {
    return $result
}
$result | ConvertTo-Json -Depth 8
