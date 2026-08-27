Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:assertions = 0

function Assert([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw "contract assertion failed: $Message" }
}
function Assert-Equal($Actual, $Expected, [string]$Message) {
    Assert ($Actual -eq $Expected) "$Message (expected=$Expected actual=$Actual)"
}
function Align([int]$Offset, [int]$Alignment) {
    return [int]([Math]::Floor(($Offset + $Alignment - 1) / [double]$Alignment) * $Alignment)
}

$repo = Split-Path -Parent $PSScriptRoot
$publicHeader = Get-Content -LiteralPath (Join-Path $repo 'include\hv_public.h') -Raw
$vmexit = Get-Content -LiteralPath (Join-Path $repo 'src\vmexit.c') -Raw
$ept = Get-Content -LiteralPath (Join-Path $repo 'src\ept.c') -Raw
$bootVmxCore = Get-Content -LiteralPath (Join-Path $repo 'boot\OphionBootPkg\Application\VmxCore.c') -Raw

# Public ABI constants and pack-8 layout.
Assert ($publicHeader -match '#pragma\s+pack\s*\(\s*push\s*,\s*8\s*\)') 'public status structures must use pack(8)'
Assert ($publicHeader -match '#define\s+HV_IOCTL_BASE\s+0x800\b') 'HV IOCTL base changed'
Assert ($publicHeader -match '#define\s+HV_STATUS_VERSION_1\s+1U?\b') 'status version changed'
Assert ($publicHeader -match '#define\s+HV_STATUS_MAX_VCPUS\s+256U?\b') 'maximum VCPU count changed'
Assert ($publicHeader -match '#define\s+HV_STATUS_EXIT_REASON_COUNT\s+128U?\b') 'exit counter count changed'
Assert ($publicHeader -match '#define\s+HV_IOCTL_ACCESS\s+\(FILE_READ_ACCESS\s*\|\s*FILE_WRITE_ACCESS\)' -and
        $publicHeader -match '#define\s+IOCTL_HV_STATUS\s+CTL_CODE\s*\(\s*FILE_DEVICE_UNKNOWN\s*,\s*HV_IOCTL_BASE\s*,\s*METHOD_BUFFERED\s*,\s*HV_IOCTL_ACCESS\s*\)') 'status IOCTL definition changed'
$ioctl = (0x22 -shl 16) -bor (3 -shl 14) -bor (0x800 -shl 2)
Assert-Equal $ioctl 0x22E000 'IOCTL_HV_STATUS numeric value changed'

function Get-Fields([string]$TypeName) {
    $match = [regex]::Match($publicHeader, "(?s)typedef\s+struct\s+_$TypeName\s*\{(?<body>.*?)\}\s*$TypeName\s*;")
    Assert $match.Success "$TypeName declaration missing"
    $fields = foreach ($field in [regex]::Matches($match.Groups['body'].Value, '(?m)^\s*(?<type>HV_UINT(?:8|16|32|64)|char|HV_STATUS_VCPU_V1)\s+(?<name>\w+)(?:\[(?<count>\w+)\])?\s*;')) {
        [pscustomobject]@{ Type = $field.Groups['type'].Value; Name = $field.Groups['name'].Value; Count = $field.Groups['count'].Value }
    }
    return @($fields)
}
function Assert-FieldSequence($Fields, [string[]]$Expected, [string]$TypeName) {
    $actual = @($Fields | ForEach-Object { if ($_.Count) { "$($_.Type) $($_.Name)[$($_.Count)]" } else { "$($_.Type) $($_.Name)" } })
    Assert-Equal ($actual -join '|') ($Expected -join '|') "$TypeName field sequence changed"
}
function Get-Layout($Fields, [hashtable]$KnownSizes) {
    $sizes = @{ HV_UINT8 = 1; HV_UINT16 = 2; HV_UINT32 = 4; HV_UINT64 = 8; char = 1 }
    foreach ($key in $KnownSizes.Keys) { $sizes[$key] = $KnownSizes[$key] }
    $counts = @{ HV_STATUS_EXIT_REASON_COUNT = 128; HV_STATUS_MAX_VCPUS = 256 }
    $offset = 0
    $maxAlign = 1
    $offsets = @{}
    foreach ($field in $Fields) {
        $size = [int]$sizes[$field.Type]
        $alignment = [Math]::Min($size, 8)
        $maxAlign = [Math]::Max($maxAlign, $alignment)
        $offset = Align $offset $alignment
        $offsets[$field.Name] = $offset
        $count = if (-not $field.Count) { 1 } elseif ($counts.ContainsKey($field.Count)) { $counts[$field.Count] } else { [int]$field.Count }
        $offset += $size * $count
    }
    return [pscustomobject]@{ Size = (Align $offset $maxAlign); Offsets = $offsets }
}

$vcpuFields = Get-Fields 'HV_STATUS_VCPU_V1'
Assert-FieldSequence $vcpuFields @(
    'HV_UINT32 Size', 'HV_UINT32 Index', 'HV_UINT16 Group', 'HV_UINT8 Number', 'HV_UINT8 Reserved0',
    'HV_UINT32 StateFlags', 'HV_UINT32 LastExitReason', 'HV_UINT32 LastFailure',
    'HV_UINT32 LastVmInstructionError', 'HV_UINT64 LastExitQualification', 'HV_UINT64 TotalExits',
    'HV_UINT64 CpuidExits', 'HV_UINT64 EptViolationExits', 'HV_UINT64 MonitorTrapExits',
    'HV_UINT64 RdtscExits', 'HV_UINT64 RdtscpExits', 'HV_UINT64 VmcallExits',
    'HV_UINT64 MsrReadExits', 'HV_UINT64 MsrWriteExits'
) 'HV_STATUS_VCPU_V1'
$vcpuLayout = Get-Layout $vcpuFields @{}
Assert-Equal $vcpuLayout.Size 112 'HV_STATUS_VCPU_V1 size changed'
Assert-Equal $vcpuLayout.Offsets.Group 8 'HV_STATUS_VCPU_V1 Group offset changed'
Assert-Equal $vcpuLayout.Offsets.LastExitQualification 32 'HV_STATUS_VCPU_V1 qualification offset changed'
Assert-Equal $vcpuLayout.Offsets.TotalExits 40 'HV_STATUS_VCPU_V1 TotalExits offset changed'

$statusFields = Get-Fields 'HV_STATUS_V1'
Assert-FieldSequence $statusFields @(
    'HV_UINT32 Size', 'HV_UINT32 Version', 'HV_UINT32 HeaderSize', 'HV_UINT32 Flags',
    'HV_UINT32 TotalProcessors', 'HV_UINT32 LaunchedProcessors', 'HV_UINT32 DetachedProcessors',
    'HV_UINT32 FailedProcessors', 'HV_UINT32 TerminalProcessors', 'HV_UINT32 ParentFlags',
    'HV_UINT32 ParentFeatures', 'HV_UINT32 CapabilityFlags', 'HV_UINT32 PreflightFailure',
    'HV_UINT32 LastFailure', 'HV_UINT32 LastVmInstructionError', 'HV_UINT32 PhysicalAddressBits',
    'HV_UINT64 MaximumGuestPhysicalAddress', 'char ParentVendor[16]',
    'HV_UINT64 AggregateExitCounters[HV_STATUS_EXIT_REASON_COUNT]',
    'HV_STATUS_VCPU_V1 Vcpu[HV_STATUS_MAX_VCPUS]'
) 'HV_STATUS_V1'
$statusLayout = Get-Layout $statusFields @{ HV_STATUS_VCPU_V1 = $vcpuLayout.Size }
Assert-Equal $statusLayout.Offsets.MaximumGuestPhysicalAddress 64 'maximum GPA offset changed'
Assert-Equal $statusLayout.Offsets.ParentVendor 72 'parent vendor offset changed'
Assert-Equal $statusLayout.Offsets.AggregateExitCounters 88 'aggregate exit counter offset changed'
Assert-Equal $statusLayout.Offsets.Vcpu 1112 'VCPU array/header size changed'
Assert-Equal $statusLayout.Size 29784 'HV_STATUS_V1 size changed'

# Root-only shared command page ABI.
Assert ($publicHeader -match '#define\s+HV_ROOT_COMMAND_MAGIC\s+0x7A6D94C13B52E807ULL' -and
        $publicHeader -match '#define\s+HV_ROOT_COMMAND_VERSION_1\s+1U' -and
        $publicHeader -match '#define\s+HV_ROOT_COMMAND_PAGE_BYTES\s+4096U' -and
        $publicHeader -match '#define\s+HV_ROOT_COMMAND_HEADER_BYTES\s+72U' -and
        $publicHeader -match '#define\s+HV_ROOT_VMCALL_SEAL_STEP\s+5U' -and
        $publicHeader -match '#define\s+HV_ROOT_VMCALL_STOP_STEP\s+6U' -and
        $publicHeader -match '#define\s+HV_ROOT_VMCALL_BOOTSTRAP_STEP\s+7U' -and
        $publicHeader -match '#define\s+HV_ROOT_VMCALL_COMMAND\s+0x100U' -and
        $publicHeader -match '#define\s+HV_VMCALL_FRAME_R10\s+0x0000000048564653ULL' -and
        $publicHeader -match '#define\s+HV_VMCALL_FRAME_R11\s+0x0000564D43414C4CULL' -and
        $publicHeader -match '#define\s+HV_VMCALL_FRAME_R12\s+0x4E4F485950455256ULL') 'root command ABI constants drifted'
$rootPageFields = Get-Fields 'HV_ROOT_COMMAND_PAGE_V1'
Assert-FieldSequence $rootPageFields @(
    'HV_UINT64 Magic', 'HV_UINT16 Version', 'HV_UINT16 HeaderBytes',
    'HV_UINT32 PageBytes', 'HV_UINT32 State', 'HV_UINT32 Command',
    'HV_UINT64 Sequence', 'HV_UINT32 RequestBytes',
    'HV_UINT32 ResponseCapacity', 'HV_UINT32 ResponseBytes',
    'HV_UINT32 Status', 'HV_UINT64 Epoch', 'HV_UINT64 RecordMacLow',
    'HV_UINT64 RecordMacHigh', 'HV_UINT8 Payload[4024]'
) 'HV_ROOT_COMMAND_PAGE_V1'
$rootPageLayout = Get-Layout $rootPageFields @{}
Assert-Equal $rootPageLayout.Size 4096 'root command page size changed'
Assert-Equal $rootPageLayout.Offsets.State 16 'root command state offset changed'
Assert-Equal $rootPageLayout.Offsets.Payload 72 'root command payload offset changed'
$rootBootstrapFields = Get-Fields 'HV_ROOT_BOOTSTRAP_V1'
Assert-FieldSequence $rootBootstrapFields @(
    'HV_UINT64 CapabilityLow', 'HV_UINT64 CapabilityHigh'
) 'HV_ROOT_BOOTSTRAP_V1'
Assert-Equal (Get-Layout $rootBootstrapFields @{}).Size 16 'root bootstrap size changed'
$rootQueryFields = Get-Fields 'HV_ROOT_QUERY_VCPU_V1'
Assert-FieldSequence $rootQueryFields @(
    'HV_UINT32 Size', 'HV_UINT32 Index'
) 'HV_ROOT_QUERY_VCPU_V1'
Assert-Equal (Get-Layout $rootQueryFields @{}).Size 8 'root VCPU query size changed'
$rootStatusFields = Get-Fields 'HV_ROOT_TRANSPORT_STATUS_V1'
Assert-FieldSequence $rootStatusFields @(
    'HV_UINT32 Size', 'HV_UINT32 Version', 'HV_UINT32 Phase',
    'HV_UINT32 ProcessorCount', 'HV_UINT32 SealedProcessors',
    'HV_UINT32 LastFailure', 'HV_UINT32 Flags', 'HV_UINT32 Reserved0',
    'HV_UINT64 Epoch', 'HV_UINT64 ExpectedSequence',
    'HV_UINT64 CompletedCommands', 'HV_UINT64 Reserved1'
) 'HV_ROOT_TRANSPORT_STATUS_V1'
Assert-Equal (Get-Layout $rootStatusFields @{}).Size 64 'root transport status size changed'
Assert ($publicHeader -match '#define\s+HV_ROOT_PHASE_EMPTY\s+0U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_PREPARED\s+1U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_ACTIVE\s+2U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_FAILED\s+3U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_STOPPING\s+4U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_STOPPED\s+5U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_INITIALIZING\s+6U' -and
        $publicHeader -match '#define\s+HV_ROOT_PHASE_AWAITING_BOOTSTRAP\s+7U' -and
        $publicHeader -match '#define\s+HV_ROOT_COMMAND_QUERY_TRANSPORT\s+1U' -and
        $publicHeader -match '#define\s+HV_ROOT_COMMAND_QUERY_VCPU\s+2U') 'root transport phases or command IDs drifted'

# PMU widths are defined over an unsigned 64-bit mask.
function Pmu-WidthMask([int]$Width) {
    if ($Width -ge 64) { return [uint64]::MaxValue }
    if ($Width -le 0) { return [uint64]0 }
    [uint64]$mask = 0
    for ($i = 0; $i -lt $Width; $i++) { $mask = [uint64](($mask -shl 1) -bor 1) }
    return $mask
}
Assert-Equal (Pmu-WidthMask 0) ([uint64]0) 'zero-width PMU mask'
Assert-Equal (Pmu-WidthMask 1) ([uint64]1) 'one-bit PMU mask'
Assert-Equal (Pmu-WidthMask 48) ([uint64]0x0000FFFFFFFFFFFF) '48-bit PMU mask'
Assert-Equal (Pmu-WidthMask 63) ([uint64]0x7FFFFFFFFFFFFFFF) '63-bit PMU mask'
Assert-Equal (Pmu-WidthMask 64) ([uint64]::MaxValue) '64-bit PMU mask'
Assert-Equal (Pmu-WidthMask 65) ([uint64]::MaxValue) 'oversized PMU mask'
Assert ($vmexit -match '(?s)if\s*\(width\s*>=\s*64\).*?MAXULONG64.*?if\s*\(!width\).*?return\s+0.*?\(1ULL\s*<<\s*width\)\s*-\s*1') 'source PMU mask rules drifted'

# MTRR descriptors are half-open [base,end); check every edge and adjacency.
function In-Mtrr([uint64]$Address, [uint64]$Base, [uint64]$End) { return $Address -ge $Base -and $Address -lt $End }
Assert (-not (In-Mtrr 0x0FFF 0x1000 0x2000)) 'MTRR address below base matched'
Assert (In-Mtrr 0x1000 0x1000 0x2000) 'MTRR base must match'
Assert (In-Mtrr 0x1FFF 0x1000 0x2000) 'MTRR final byte must match'
Assert (-not (In-Mtrr 0x2000 0x1000 0x2000)) 'MTRR exclusive end matched'
Assert (In-Mtrr 0x2000 0x2000 0x3000) 'adjacent MTRR base must match exactly once'
Assert (-not (In-Mtrr 0x1000 0x1000 0x1000)) 'empty MTRR interval matched'
Assert ($ept -match 'page_addr\s*>=\s*range->phys_base\s*&&\s*page_addr\s*<\s*range->phys_end') 'source MTRR lookup is not half-open'

# Processor-group flattening: prefix sum + group-relative number is bijective.
$groupCounts = @(64, 3, 1)
$flattened = @()
$prefix = 0
for ($group = 0; $group -lt $groupCounts.Count; $group++) {
    for ($number = 0; $number -lt $groupCounts[$group]; $number++) {
        $flattened += [pscustomobject]@{ Group = $group; Number = $number; Index = $prefix + $number }
    }
    $prefix += $groupCounts[$group]
}
Assert-Equal $flattened.Count 68 'flattened processor count'
Assert-Equal (@($flattened.Index | Sort-Object -Unique).Count) $flattened.Count 'flattened indices must be unique'
Assert-Equal $flattened[63].Index 63 'last processor in group zero'
Assert-Equal $flattened[64].Index 64 'first processor in group one'
Assert-Equal $flattened[-1].Index 67 'last flattened processor'
foreach ($cpu in $flattened) { Assert ($cpu.Number -lt $groupCounts[$cpu.Group]) 'flattened processor inverse is invalid' }

# Hyper-V synthetic MSRs have an explicit feature and direction whitelist.
function HyperV-MsrAllowed([uint32]$Msr, [bool]$Write, [uint32]$Features = [uint32]::MaxValue, [bool]$ParentHyperV = $true) {
    if (-not $ParentHyperV) { return $false }
    switch ($Msr) {
        0x40000000 { return ($Features -band (1 -shl 5)) -ne 0 }
        0x40000001 { return ($Features -band (1 -shl 5)) -ne 0 }
        0x40000002 { return (-not $Write) -and (($Features -band (1 -shl 6)) -ne 0) }
        0x40000003 { return $Write -and (($Features -band (1 -shl 7)) -ne 0) }
        0x40000010 { return (-not $Write) -and (($Features -band 1) -ne 0) }
        0x40000020 { return (-not $Write) -and (($Features -band (1 -shl 1)) -ne 0) }
        0x40000021 { return ($Features -band (1 -shl 9)) -ne 0 }
        0x40000022 { return (-not $Write) -and (($Features -band (1 -shl 11)) -ne 0) }
        0x40000023 { return (-not $Write) -and (($Features -band (1 -shl 11)) -ne 0) }
        0x40000070 { return $Write -and (($Features -band (1 -shl 4)) -ne 0) }
        0x40000071 { return ($Features -band (1 -shl 4)) -ne 0 }
        0x40000072 { return ($Features -band (1 -shl 4)) -ne 0 }
        0x40000073 { return ($Features -band (1 -shl 4)) -ne 0 }
        0x40000080 { return ($Features -band (1 -shl 2)) -ne 0 }
        0x40000081 { return (-not $Write) -and (($Features -band (1 -shl 2)) -ne 0) }
        0x40000082 { return ($Features -band (1 -shl 2)) -ne 0 }
        0x40000083 { return ($Features -band (1 -shl 2)) -ne 0 }
        0x40000084 { return $Write -and (($Features -band (1 -shl 2)) -ne 0) }
        0x400000F0 { return $Write -and (($Features -band (1 -shl 10)) -ne 0) }
        default {
            if ($Msr -ge 0x40000090 -and $Msr -le 0x4000009F) { return ($Features -band (1 -shl 2)) -ne 0 }
            if ($Msr -ge 0x400000B0 -and $Msr -le 0x400000B7) { return ($Features -band (1 -shl 3)) -ne 0 }
            return $false
        }
    }
}
Assert (HyperV-MsrAllowed 0x40000000 $false) 'guest OS ID MSR read must be allowed'
Assert (HyperV-MsrAllowed 0x40000000 $true) 'guest OS ID MSR write must be allowed'
Assert (HyperV-MsrAllowed 0x40000002 $false) 'VP index read must be allowed'
Assert (-not (HyperV-MsrAllowed 0x40000002 $true)) 'VP index write must be rejected'
Assert (-not (HyperV-MsrAllowed 0x40000003 $false)) 'reset read must be rejected'
Assert (HyperV-MsrAllowed 0x40000003 $true) 'reset write must be allowed'
Assert (HyperV-MsrAllowed 0x40000081 $false) 'SINT read-only member must be readable'
Assert (-not (HyperV-MsrAllowed 0x40000081 $true)) 'SINT read-only member must reject writes'
Assert (-not (HyperV-MsrAllowed 0x40000084 $false)) 'EOI write-only member must reject reads'
Assert (HyperV-MsrAllowed 0x40000084 $true) 'EOI write-only member must accept writes'
Assert (-not (HyperV-MsrAllowed 0x400000FF $false)) 'unknown synthetic MSR must be rejected'
Assert (-not (HyperV-MsrAllowed 0x40000000 $false ([uint32]::MaxValue) $false)) 'synthetic MSR must be rejected without Hyper-V parent'
Assert ($vmexit -match 'parent_hyperv_msr_supported' -and $vmexit -match '(?s)case\s+0x40000002:.*?return\s+!write' -and $vmexit -match '(?s)case\s+0x40000003:.*?return\s+write') 'source Hyper-V direction whitelist drifted'

# Integer timer conversion must be saturating, monotonic, and division-safe.
function MulDiv-U64([uint64]$Value, [uint64]$Multiplier, [uint64]$Divisor) {
    if ($Divisor -eq 0 -or $Multiplier -eq 0) { return [uint64]0 }
    $wide = [System.Numerics.BigInteger]$Value * [System.Numerics.BigInteger]$Multiplier / [System.Numerics.BigInteger]$Divisor
    if ($wide -gt [System.Numerics.BigInteger][uint64]::MaxValue) { return [uint64]::MaxValue }
    return [uint64]$wide
}
Assert-Equal (MulDiv-U64 123 456 0) ([uint64]0) 'zero-divisor timer conversion'
Assert-Equal (MulDiv-U64 123 0 456) ([uint64]0) 'zero-multiplier timer conversion'
Assert-Equal (MulDiv-U64 3000000000 1000000 3000000000) ([uint64]1000000) 'exact timer conversion'
Assert-Equal (MulDiv-U64 1 3 2) ([uint64]1) 'timer conversion truncates toward zero'
Assert-Equal (MulDiv-U64 ([uint64]::MaxValue) 2 1) ([uint64]::MaxValue) 'timer conversion saturation'
$previous = [uint64]0
foreach ($value in 0, 1, 2, 3, 10, 1000, 1000000) {
    $converted = MulDiv-U64 $value 1000000000 3000000000
    Assert ($converted -ge $previous) 'timer conversion must be monotonic'
    $previous = $converted
}
Assert ($ept -match 'ept_mul_div_u64' -and $ept -match 'if\s*\(!divisor\s*\|\|\s*!multiplier\)' -and $ept -match 'quotient\s*>\s*MAXULONG64\s*/\s*multiplier') 'source timer conversion safeguards drifted'

# Unknown VM exits are terminal/error paths and must not skip an arbitrary guest instruction.
Assert ($vmexit -match '(?s)vmexit_enter_terminal\s*\([^)]*\)\s*\{.*?vcpu->advance_rip\s*=\s*FALSE;') 'terminal helper must suppress RIP advancement'
Assert ($vmexit -match '(?s)default:\s*vmexit_enter_terminal\s*\(\s*vcpu\s*,\s*HV_FAILURE_UNKNOWN_EXIT\s*\);\s*break;') 'unknown VM exits must enter the terminal path'

# Production stealth profile: logging, status device, and identifiable pool
# tags must compile out; VM-exit state sampling must be reason-conditional.
$hvHeader = Get-Content -LiteralPath (Join-Path $repo 'include\hv.h') -Raw
$hvTypes = Get-Content -LiteralPath (Join-Path $repo 'include\hv_types.h') -Raw
Assert ($hvHeader -match '(?s)#if\s+OPHION_PRODUCTION\s*#define\s+HV_LOG\(\.\.\.\)\s+\(\(void\)0\)') 'production logging must compile to nothing'
$buildScript = Get-Content -LiteralPath (Join-Path $repo 'build.ps1') -Raw
$vcxproj = Get-Content -LiteralPath (Join-Path $repo 'Ophion.vcxproj') -Raw
$driverSource = Get-Content -LiteralPath (Join-Path $repo 'src\driver.c') -Raw
Assert ($hvHeader -match '#ifndef\s+OPHION_PRODUCTION' -and $hvHeader -match '#define\s+HV_LOG') 'production profile macro must exist'
Assert ($hvTypes -match "(?s)#if\s+OPHION_PRODUCTION.*#define\s+HV_POOL_TAG\s+'DptS'.*#else.*#define\s+HV_POOL_TAG\s+'nhpO'") 'pool tag profile split drifted'
Assert ('DptS' -notmatch 'Ophn' -and 'DptS' -notmatch 'Ophi') 'production pool tag must not identify the project'
Assert ($vmexit -match 'vmexit_exit_sample_plan' -and $vmexit -match 'VMEXIT_SAMPLE_DR' -and $vmexit -match 'VMEXIT_SAMPLE_APERF_MPERF') 'conditional exit sampling plan drifted'
Assert ($vmexit -match 'sample_plan\s*&\s*VMEXIT_SAMPLE_DR\)\)' -and $vmexit -match 'sample_plan\s*&\s*VMEXIT_SAMPLE_CR8\)\)') 'exit epilogue must restore only sampled state'
Assert ($vmexit -match 'VMCS_GUEST_DR7,\s*&dr7_raw' -and $vmexit -match 'RFLAGS_TF' ) 'DR sampling must stay live for TF/DR7 debugging probes'
$productionEntry = [regex]::Match($driverSource, '(?s)#else\s*//\s*OPHION_PRODUCTION\s*(?<body>.*?)#endif\s*//\s*OPHION_PRODUCTION').Groups['body'].Value
Assert ($productionEntry -match 'vmx_init\(\)' -and $productionEntry -notmatch 'IoCreateDevice' -and $productionEntry -notmatch 'IoCreateSymbolicLink') 'production entry must create no device objects'
Assert ($driverSource -match '(?s)#if\s+!OPHION_PRODUCTION\s*.*IoCreateDevice') 'default entry must keep the status device'
Assert ($buildScript -match '\[switch\]\$Production' -and $buildScript -match '/DOPHION_PRODUCTION=1') 'build pipeline must expose the production switch'
Assert ($vcxproj -match 'src\\root_transport\.c' -and
        $vcxproj -match 'src\\tracewipe\.c') 'Visual Studio project must link transport and trace-wipe objects'
Assert ($buildScript -match "productionExcluded\s*=\s*@\('byovd_conceal\.c',\s*'eac_stealth\.c',\s*'tracewipe\.c'\)" -and
        $buildScript -match 'production_safe_profile\.c' -and
        $buildScript -match 'verify-production-boundary\.ps1' -and
        $buildScript -match 'driver-object-manifest\.v1') 'authoritative production source boundary drifted'
Assert ($vmexit -match 'vmexit_advance_rip\s*\(\s*vcpu\s*\)' -and ($vmexit | Select-String -Pattern 'vmexit_advance_rip' -AllMatches).Matches.Count -ge 2) 'exit epilogue must call the RIP advance path'

# Host-page concealment: dummy GPA hide, not an execute/read EPT hook.
$stealthHeader = Get-Content -LiteralPath (Join-Path $repo 'include\stealth.h') -Raw
$conceal = Get-Content -LiteralPath (Join-Path $repo 'src\conceal.c') -Raw
$bootHeader = Get-Content -LiteralPath (Join-Path $repo 'boot\OphionBootPkg\Application\OphionBoot.h') -Raw
$bootDec = Get-Content -LiteralPath (Join-Path $repo 'boot\OphionBootPkg\OphionBootPkg.dec') -Raw
Assert ($stealthHeader -match '#define\s+STEALTH_CONCEAL_HOST_PAGES\s+1') 'host-page concealment must be on'
Assert ($conceal -match 'ept_conceal_prepare' -and
        $conceal -match 'ept_conceal_commit_local' -and
        $conceal -match 'ept_conceal_register_runtime') 'concealment registry drifted'
Assert ($conceal -match 'conceal_find_image' -and
        $conceal -match 'conceal_register_self_image' -and
        $conceal -match 'g_root_command_page' -and
        $conceal -match 'shared_page \+ PAGE_SIZE') 'production mapped image concealment must preserve only .hvshare'
Assert ($conceal -notmatch 'ept_conceal_register_va\(g_vcpu') 'live vCPU metadata must use the bounded root transport snapshot'
Assert ($conceal -match '(?s)#if\s+OPHION_PRODUCTION.*ept_conceal_register_va\s*\(\s*g_ept\s*,\s*sizeof\(EPT_STATE\)' -and
        $conceal -match 'VMM_EPT_DYNAMIC_SPLIT' -and
        $conceal -match 'g_ept->hooked_pages') 'production concealment must include EPT metadata and dynamic split tables'
Assert ($conceal -match 'replacement\.ExecuteAccess\s*=\s*0' -and
        $conceal -match 'replacement\.ReadAccess\s*=\s*1' -and
        $conceal -match 'replacement\.WriteAccess\s*=\s*0') 'concealed pages must be read-only dummy, execute-clear'
Assert ($vmexit -match 'ept_conceal_is_hidden' -and
        $vmexit -match 'VMCS_GUEST_LINEAR_ADDRESS' -and
        $vmexit -match 'root_tsc_entry') 'EPT hide, fault address, and TSC compensation drifted'
Assert ($vmexit -match 'tsc\s*=\s*\(UINT64\)\(\(INT64\)vcpu->root_tsc_entry') 'unarmed RDTSC must use root entry TSC'
Assert ($bootHeader -match '#define\s+OPB_ENABLE_RUNTIME_CONCEALMENT\s+1') 'boot concealment switch must default on'
Assert ($bootHeader -match '#define\s+OPB_ENABLE_HYPERV_PERSONA\s+0') 'incomplete boot Hyper-V persona must default off'
Assert ($bootDec -match 'OphionBootConcealRuntime\|TRUE') 'boot PCD must default concealment on'
$wipe = Get-Content -LiteralPath (Join-Path $repo 'src\tracewipe.c') -Raw
$mapSource = Get-Content -LiteralPath (Join-Path $repo 'tools\OphionMap.cpp') -Raw
$rootTransportPath = Join-Path $repo 'src\root_transport.c'
$transportMacPath = Join-Path $repo 'include\hv_transport_mac.h'
Assert (Test-Path -LiteralPath $rootTransportPath) 'root transport implementation missing'
Assert (Test-Path -LiteralPath $transportMacPath) 'shared transport MAC implementation missing'
$rootTransport = if (Test-Path -LiteralPath $rootTransportPath) {
    Get-Content -LiteralPath $rootTransportPath -Raw
} else {
    ''
}
$readme = Get-Content -LiteralPath (Join-Path $repo 'README.md') -Raw
Assert ($stealthHeader -match '#define\s+STEALTH_WIPE_LOADER_TRACES\s+0') 'loader-trace wipe must default off'
Assert ($wipe -match 'wipe_loaded_module' -and $wipe -match 'wipe_piddb' -and $wipe -match 'wipe_unloaded') 'opt-in trace-wipe implementation drifted'
Assert ($mapSource -match 'none-sc-none-ntloaddriver' -and
        $mapSource -match 'ophion\.map\.v2' -and
        $mapSource -match 'buildEntryThunk' -and
        $mapSource -match 'ophion\.exec\.bin' -and
        $mapSource -match 'ophion\.bootstrap\.bin' -and
        $mapSource -match 'ophion\.seal\.bin' -and
        $mapSource -match 'findSharedPageRva' -and
        $mapSource -match 'commandMagic' -and
        $mapSource -match '\-\-mac-self-test' -and
        $mapSource -match 'macAlgorithm' -and
        $mapSource -match 'capabilityPayloadOffset' -and
        $mapSource -match 'vmcallFrameR10' -and
        $mapSource -match 'requiresAllCoreSeal' -and
        $mapSource -match 'requiresRootBootstrap' -and
        $mapSource -match 'parseHexStrict' -and
        $mapSource -match 'isCanonicalKernelVa' -and
        $mapSource -match 'SectionAlignment' -and
        $mapSource -match 'numeric_limits' -and
        $mapSource -match '--base is required for a launchable artifact' -and
        $mapSource -match '--ntos and --ntos-base are required for a launchable artifact') 'launchable mapper/trampoline contract drifted'
Assert ($rootTransport -match '\.hvshare' -and
        $rootTransport -match '\.hvroot' -and
        $rootTransport -match 'InterlockedCompareExchange' -and
        $rootTransport -match 'InterlockedOr64' -and
        $rootTransport -match 'ExpectedSequence' -and
        $rootTransport -match 'RtlSecureZeroMemory' -and
        $rootTransport -match 'root_transport_register_conceal') 'root transport state/concealment contract drifted'
Assert ($rootTransport -match '(?s)ExpectedSequence\+\+.*root_transport_complete' -and
        $rootTransport -match '(?s)capability_low\s*\^\s*state->CapabilityLow.*capability_high\s*\^\s*state->CapabilityHigh') 'root transport sequence publication or capability comparison drifted'
Assert ($rootTransport -match 'hv_transport_mac_request' -and
        $rootTransport -match 'hv_transport_mac_response' -and
        $rootTransport -match 'RecordMacLow' -and
        $rootTransport -match 'RecordMacHigh') 'shared command records must carry keyed request and response MACs'
Assert ($rootTransport -match 'root_transport_bootstrap' -and
        $rootTransport -match 'root_transport_mark_awaiting_bootstrap' -and
        $rootTransport -match 'HV_ROOT_PHASE_AWAITING_BOOTSTRAP' -and
        $rootTransport -match 'root_transport_conceal_ack' -and
        $rootTransport -match 'ConcealReady' -and
        $rootTransport -notmatch 'root_transport_get_bootstrap_auth' -and
        $rootTransport -match '(?s)root_transport_bootstrap.*CapabilityLow.*CapabilityHigh.*RtlSecureZeroMemory') 'capability must be established and erased in VMX root'
$bootstrapBody = [regex]::Match(
    $rootTransport,
    '(?s)NTSTATUS\s+root_transport_bootstrap\s*\(.*?\)\s*\{(?<body>.*?)\n\}')
Assert ($bootstrapBody.Success -and
        $bootstrapBody.Groups['body'].Value -notmatch 'ConcealReady') 'external bootstrap must complete before all-core concealment seals the image'
$sealStep = [regex]::Match(
    $rootTransport,
    '(?s)NTSTATUS\s+root_transport_seal_step\s*\(.*?\)\s*\{(?<body>.*?)\n\}')
Assert ($sealStep.Success -and
        $sealStep.Groups['body'].Value -match 'ept_conceal_commit_local' -and
        $sealStep.Groups['body'].Value -match 'root_transport_conceal_ack' -and
        $sealStep.Groups['body'].Value.IndexOf('root_transport_authorized') -lt
            $sealStep.Groups['body'].Value.IndexOf('ept_conceal_commit_local') -and
        $sealStep.Groups['body'].Value.IndexOf('ept_conceal_commit_local') -lt
            $sealStep.Groups['body'].Value.IndexOf('SealedBitmap')) 'authenticated all-core seal must commit concealment before publishing the local sealed bit'
$vmxConcealFlow = Get-Content -LiteralPath (Join-Path $repo 'src\vmx.c') -Raw
Assert ($vmxConcealFlow -match '(?s)#if\s*!OPHION_PRODUCTION.*broadcast_conceal_invept\(\).*?#endif') 'production must not conceal the return path from an in-image DPC'
Assert ($rootTransport -match 'root_transport_stop_begin' -and
        $rootTransport -match 'root_transport_stop_complete' -and
        $rootTransport -match 'StoppedBitmap' -and
        $rootTransport -match 'HV_ROOT_PHASE_STOPPING' -and
        $rootTransport -match 'HV_ROOT_PHASE_STOPPED') 'authenticated teardown state machine drifted'
Assert ($rootTransport -match 'MAXULONG64' -and
        $rootTransport -match 'STATUS_INTEGER_OVERFLOW' -and
        $rootTransport -match 'address\s*-\s*base\s*>=\s*bytes' -and
        $rootTransport -match 'offset\s*%\s*sizeof\(VIRTUAL_MACHINE_STATE\)') 'root transport sequence exhaustion or checked vCPU indexing drifted'
Assert ($conceal -match 'HV_CONCEAL_STATE_COLLECTING' -and
        $conceal -match 'HV_CONCEAL_STATE_PREPARING' -and
        $conceal -match 'HV_CONCEAL_STATE_PUBLISHED' -and
        $conceal -match 'HV_CONCEAL_STATE_FAILED' -and
        $conceal -match 'ExAcquirePushLockExclusive' -and
        $conceal -match 'conceal_add_interval' -and
        $conceal -match 'staged_ranges' -and
        $conceal -match 'UINT32 middle = low \+ \(high - low\) / 2') 'conceal serialization, transactional normalization, or binary lookup drifted'
$attachmentManager = Get-Content -LiteralPath (Join-Path $repo 'src\attachment.c') -Raw
$persona = Get-Content -LiteralPath (Join-Path $repo 'boot\OphionBootPkg\Application\Persona.c') -Raw
Assert ($attachmentManager -match 'attachment_valid' -and
        $attachmentManager -match 'HV_ATTACH_KNOWN_REQUEST_FLAGS' -and
        $attachmentManager -match 'HV_ATTACH_KNOWN_OWNERSHIP' -and
        $attachmentManager -match 'HV_ATTACH_STATE_ELIGIBLE' -and
        $attachmentManager -match 'HV_ATTACH_FAILURE_ROLLBACK' -and
        $attachmentManager -match 'session->OwnershipMask') 'attachment lifecycle validation or rollback contract drifted'
Assert ($persona -match '#define\s+HV_MAX_LEAF\s+0x40000001' -and
        $persona -notmatch 'return\s+0;\s*/\*\s*HV_STATUS_SUCCESS' -and
        $persona -notmatch 'mHypercallStub' -and
        $persona -match '(?s)OpbPersonaReadMsr.*return EFI_UNSUPPORTED' -and
        $persona -match '(?s)OpbPersonaWriteMsr.*return EFI_UNSUPPORTED' -and
        $persona -match '(?s)OpbPersonaHypercall.*return 0x0002') 'boot persona must remain identity-only and fail unsupported effects closed'
$rootFillStatus = [regex]::Match(
    $rootTransport,
    '(?s)root_transport_fill_status\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
$rootFillVcpu = [regex]::Match(
    $rootTransport,
    '(?s)root_transport_fill_vcpu\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($rootTransport -match 'root_transport_snapshot_metadata' -and
        $rootTransport -match 'VcpuBase' -and
        $rootTransport -match 'ProcessorCount' -and
        $rootTransport -match 'Topology' -and
        $rootTransport -match 'Capabilities' -and
        $rootTransport -match 'MetadataReady') 'root-owned metadata snapshot missing'
Assert ($rootFillStatus.Success -and $rootFillVcpu.Success -and
        $rootFillStatus.Groups['body'].Value -notmatch 'g_vcpu|g_cpu_count|g_processor_topology|g_hv_capabilities' -and
        $rootFillVcpu.Groups['body'].Value -notmatch 'g_vcpu|g_cpu_count|g_processor_topology|g_hv_capabilities') 'root status paths must not trust guest-writable metadata'
$broadcastTransport = Get-Content -LiteralPath (Join-Path $repo 'src\broadcast.c') -Raw
$vmxTransport = Get-Content -LiteralPath (Join-Path $repo 'src\vmx.c') -Raw
$hostGdt = Get-Content -LiteralPath (Join-Path $repo 'src\hostgdt.c') -Raw
Assert ($conceal -match '(?s)root_transport_vcpu_base.*root_transport_processor_count.*ept_conceal_register_va' -and
        $conceal -match '(?s)conceal_snapshot_page_tables.*conceal_prepare_splits\s*\(\s*page_tables\s*,\s*processor_count\s*\)' -and
        $broadcastTransport -match 'HV_BROADCAST_RESULT' -and
        $broadcastTransport -match 'VMCALL_CONCEAL_COMMIT' -and
        $broadcastTransport -match 'VMCALL_INIT_ROLLBACK' -and
        $vmxTransport -match 'root_transport_snapshot_metadata' -and
        $vmxTransport -match '(?s)ept_conceal_prepare\(\).*broadcast_virtualize_all\(\)' -and
        $vmxTransport -match 'root_transport_mark_awaiting_bootstrap' -and
        $vmxTransport -match 'broadcast_terminate_initializing' -and
        $vmxTransport -match 'broadcast_conceal_invept\(\)' -and
        $vmxTransport -notmatch 'ept_conceal_apply\(\)') 'vCPU concealment or root snapshot launch gate drifted'
$rootCommit = [regex]::Match(
    $conceal,
    '(?s)ept_conceal_commit_local\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($conceal -match 'HV_CONCEAL_MANIFEST' -and
        $conceal -match 'g_conceal_generation' -and
        $conceal -match 'g_conceal_frozen' -and
        $conceal -match 'root_transport_set_conceal_manifest' -and
        $conceal -match '(?s)ept_conceal_register_runtime\(\).*ept_conceal_register_va\s*\(\s*g_conceal_manifest.*conceal_prepare_splits.*root_transport_set_conceal_manifest.*InterlockedExchange\s*\(\s*&g_conceal_frozen,\s*1\s*\).*RtlSecureZeroMemory' -and
        $conceal -match 'root_transport_snapshot_conceal' -and
        $rootCommit.Success -and
        $rootCommit.Groups['body'].Value -notmatch 'MmAllocate|ExAllocate|ept_split_large_page') 'conceal commit must consume a frozen allocation-free root manifest'
Assert ($conceal -match '(?s)g_dummy_pa\s*=\s*va_to_pa\(g_dummy_va\).*ept_conceal_register_pa\s*\(\s*g_dummy_pa' -and
        $conceal -match 'InterlockedExchange64' -and
        $conceal -match 'ept_invept_single_initializing') 'conceal dummy identity, atomic leaf, or initialization INVEPT safety drifted'
Assert ($ept -match '(?s)ept_split_large_page.*ept_conceal_is_frozen.*return\s+FALSE') 'post-prepare production EPT splits must fail closed'
Assert ($ept -match '(?s)ept_invept_single_initializing.*vcpu->failed\s*=\s*TRUE.*vcpu->last_failure\s*=\s*HV_FAILURE_INVEPT.*return\s+FALSE' -and
        [regex]::Match($ept, '(?s)ept_invept_single_initializing\s*\([^)]*\)\s*\{(?<body>.*?)\n\}').Groups['body'].Value -notmatch 'vcpu->terminal') 'initialization INVEPT failure must preserve VMX for coordinated rollback'
Assert ($rootTransport -match '(?s)root_transport_conceal_commit_allowed.*HV_ROOT_PHASE_AWAITING_BOOTSTRAP' -and
        $vmexit -match '(?s)case\s+VMCALL_CONCEAL_COMMIT:.*root_transport_conceal_commit_allowed.*ept_conceal_commit_local.*root_transport_conceal_ack') 'conceal root commit phase gate drifted'
Assert ($broadcastTransport -match 'broadcast_prepare_host_state' -and
        $broadcastTransport -match '(?s)dpc_prepare_host_state.*hostgdt_build_for_vcpu' -and
        $hostGdt -match '(?s)if\s*\(\s*vcpu->host_gdt\s*\)\s*return\s+TRUE' -and
        $vmxTransport -match '(?s)broadcast_prepare_host_state\(\).*hostcr3_build\(\).*ept_conceal_prepare\(\).*broadcast_virtualize_all\(\)') 'private host GDT must be allocated before host CR3 and conceal freeze'
Assert ($vmexit -match 'VMCS_GUEST_CS_SELECTOR' -and
        $vmexit -match 'VMCALL_BOOTSTRAP_STEP' -and
        $vmexit -match 'VMCALL_CONCEAL_COMMIT' -and
        $vmexit -match 'ept_conceal_commit_local' -and
        $vmexit -match 'VMCALL_INIT_ROLLBACK' -and
        $vmexit -match 'root_transport_seal_step' -and
        $vmexit -match 'root_transport_command' -and
        $vmexit -match 'VMCALL_STOP_STEP' -and
        $vmexit -match 'VMCALL_ROOT_COMMAND' -and
        $vmexit -match 'vmexit_inject_ud') 'root-only VMCALL dispatch contract drifted'
Assert ($driverSource -match 'OphionCleanup' -and
        $driverSource -match '(?s)OphionCleanup.*vmx_all_stopped.*vmx_terminate.*root_transport_destroy') 'mapped-image cleanup entry drifted'
Assert ($mapSource -match 'buildStopThunk' -and
        $mapSource -match 'buildBootstrapThunk' -and
        $mapSource -match 'ophion\.stop\.bin' -and
        $mapSource -match 'ophion\.cleanup\.bin' -and
        $mapSource -match 'stopCapabilityLowOffset') 'authenticated teardown artifact contract drifted'
Assert ($readme -match 'sc\.exe create/start' -and $readme -match 'Do not') 'README must not recommend sc start for AC'
Assert ($readme -match 'OphionMap.exe') 'README must document the no-service mapper'
$loadSource = Get-Content -LiteralPath (Join-Path $repo 'tools\OphionLoad.cpp') -Raw
Assert ($loadSource -match '0x8011E044' -and $loadSource -match 'DirectIoPhysMem' -and $loadSource -match 'randomStem') 'DirectIo random-stem loader drifted'
Assert ($readme -match 'DirectIo64_legacy' -and $readme -match 'OphionLoad.exe') 'README must rank DirectIo64_legacy as the write primitive'




$protect = Get-Content -LiteralPath (Join-Path $repo 'src\protect.c') -Raw
$vmxSource = Get-Content -LiteralPath (Join-Path $repo 'src\vmx.c') -Raw
$hostCr3 = Get-Content -LiteralPath (Join-Path $repo 'src\hostcr3.c') -Raw
$broadcast = Get-Content -LiteralPath (Join-Path $repo 'src\broadcast.c') -Raw
$byovdConceal = Get-Content -LiteralPath (Join-Path $repo 'src\byovd_conceal.c') -Raw
$eacStealth = Get-Content -LiteralPath (Join-Path $repo 'src\eac_stealth.c') -Raw
$internal = Get-Content -LiteralPath (Join-Path $repo 'tools\OphionInternal.h') -Raw
$spoofAsm = Get-Content -LiteralPath (Join-Path $repo 'tools\ophion_spoof.asm') -Raw
Assert ($broadcast -match 'asm_vmx_vmcall\s*\(\s*VMCALL_CONCEAL_COMMIT' -and
        $broadcast -notmatch 'ept_invept_single') 'guest DPC must request INVEPT through VMCALL'
Assert ($protect -match 'MmProbeAndLockPages' -and
        $protect -match 'MmUnlockPages' -and
        $protect -match 'g_prot_owners\[owner\]\.mdl' -and
        $protect -match 'prot_process_notify') 'protected pages need per-owner pinning and exit cleanup'
Assert ($protect -match 'InterlockedExchange64' -and
        $protect -match 'protect_mtf_pending') 'EPT permission updates and MTF preemption contract drifted'
Assert ($protect -match 'owner_cr3.*STATUS_NOT_SUPPORTED' -or
        $protect -match 'prot_cr3_key\(owner_cr3\)\s*!=\s*current_cr3') 'foreign CR3 registration must fail closed'
Assert ($stealthHeader -match '#define\s+STEALTH_EAC_STACK_SCRUB\s+0') 'heuristic stack rewriting must default off'
Assert ($byovdConceal -match '#define\s+STEALTH_CONCEAL_BYOVD\s+0') 'live BYOVD conceal must default off'
Assert ($eacStealth -match '#define\s+STEALTH_EAC_PATCH_KD\s+0' -and
        $eacStealth -match '#define\s+STEALTH_EAC_PATCH_KSD\s+0' -and
        $eacStealth -match '#define\s+STEALTH_EAC_SPOOF_SMBIOS\s+0') 'destructive AC patches must default off'
Assert ($loadSource -match 'pstrip64 returns a truncated 32-bit map VA' -and
        $loadSource -match 'bool Read\(ULONGLONG pa, void\* out, ULONG size\) override') 'x64 pstrip gate or Lnv read-only path drifted'
Assert ($internal -match 'HardenNone' -and
        $internal -match '(?s)protect_remote.*ERROR_NOT_SUPPORTED' -and
        $internal -notmatch 'Tbsi_GetDeviceInfo') 'internal safe defaults drifted'
Assert ($spoofAsm -match 'sub\s+rsp,\s*20h' -and
        $spoofAsm -match 'push\s+r11') 'spoof thunk shadow-space contract drifted'
Assert ($protect -match 'MmGetMdlPfnArray' -and
        $protect -match 'prot_find_user_cr3' -and
        $protect -match 'prot_kva_shadow_enabled') 'MDL PFN and KPTI ownership contract drifted'
Assert ($protect -match 'HV_PROTECT_MAX_MTF_PAGES' -and
        $protect -match 'g_prot_mtf_count' -and
        $protect -match 'broadcast_protect_refresh') 'cross-page MTF or per-vCPU refresh contract drifted'
$initialPrimaryControls = [regex]::Match(
    $vmxSource,
    '(?s)pri_proc\s*=\s*vmx_adjust_controls\s*\((?<body>.*?)IA32_VMX_PROCBASED_CTLS\s*\);')
Assert ($initialPrimaryControls.Success -and
        $initialPrimaryControls.Groups['body'].Value -notmatch 'CPU_BASED_VM_EXEC_CTRL_(CR3_LOAD|RDTSC)_EXITING') 'dynamic CR3/RDTSC exits must not be requested before demand'
Assert ($protect -match 'protect_requires_cr3_exiting' -and
        $hvTypes -match 'primary_dynamic_forced' -and
        $hvTypes -match 'protect_cr3_exiting' -and
        $vmexit -match 'vmexit_sync_dynamic_exiting' -and
        $vmexit -notmatch 'vmexit_set_(cr3_load|rdtsc)_exiting') 'CR3/RDTSC demand must share one per-vCPU control synchronizer'
$dynamicSync = [regex]::Match(
    $vmexit,
    '(?s)vmexit_sync_dynamic_exiting\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($dynamicSync.Success -and
        $dynamicSync.Groups['body'].Value -match 'vmx_vmread_checked' -and
        $dynamicSync.Groups['body'].Value -match 'vmx_vmwrite_checked' -and
        $dynamicSync.Groups['body'].Value -match 'primary_dynamic_forced' -and
        $dynamicSync.Groups['body'].Value -match 'protect_cr3_exiting' -and
        $dynamicSync.Groups['body'].Value -match 'tsc_rdtsc_armed' -and
        $dynamicSync.Groups['body'].Value -notmatch 'g_stealth_cpuid_cache') 'dynamic exit synchronizer must preserve forced bits and use local demand'
Assert ($vmexit -match 'regs->rax\s*=\s*\(UINT64\)\(UINT32\)cpu_info\[0\]' -and
        $vmexit -match 'regs->rbx\s*=\s*\(UINT64\)\(UINT32\)cpu_info\[1\]' -and
        $vmexit -match 'regs->rcx\s*=\s*\(UINT64\)\(UINT32\)cpu_info\[2\]' -and
        $vmexit -match 'regs->rdx\s*=\s*\(UINT64\)\(UINT32\)cpu_info\[3\]') 'CPUID results must zero-extend into 64-bit guest registers'
Assert ($bootVmxCore -notmatch 'EXECCTRL_CPUID_EXIT') 'CPUID is an unconditional VM exit; primary control bit 21 must not be requested as CPUID exiting'
$movCr4 = [regex]::Match(
    $vmexit,
    '(?s)case\s+4:\s*\{(?<body>.*?MOV to CR4.*?)\n\s*break;')
Assert ($movCr4.Success -and
        $movCr4.Groups['body'].Value -match 'actual\s*=\s*desired\s*\|\s*CR4_VMX_ENABLE_FLAG' -and
        $movCr4.Groups['body'].Value -match 'VMCS_CTRL_CR4_READ_SHADOW,\s*desired' -and
        $movCr4.Groups['body'].Value -notmatch 'VMCS_CTRL_CR4_READ_SHADOW,\s*desired\s*&\s*~CR4_VMX_ENABLE_FLAG') 'CR4.VMXE writes must update the read shadow while the actual guest CR4 keeps VMXE set'
Assert ($vmxSource -match 'VMCS_CTRL_CR4_READ_SHADOW,\s*__readcr4\(\)\s*&\s*~CR4_VMX_ENABLE_FLAG') 'initial CR4 shadow must hide host VMXE before any guest write'
Assert ($stealthHeader -match '#define\s+STEALTH_VIRTUALIZE_PMU\s+1' -and
        $vmxSource -match 'VM_EXIT_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL' -and
        $vmxSource -match 'VM_EXIT_CTRL_SAVE_IA32_PERF_GLOBAL_CTRL' -and
        $vmxSource -match 'VM_ENTRY_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL' -and
        $vmexit -match 'aperf_root_bias' -and
        $vmexit -match 'mperf_root_bias') 'PMU isolation and APERF/MPERF compensation contract drifted'
$pmuIsolation = [regex]::Match(
    $vmxSource,
    '(?s)vcpu->pmu_isolated\s*=(?<body>.*?);')
Assert ($pmuIsolation.Success -and
        $pmuIsolation.Groups['body'].Value -match 'VM_EXIT_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL' -and
        $pmuIsolation.Groups['body'].Value -match 'VM_ENTRY_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL' -and
        $vmexit -match '(?s)case\s+IA32_PERF_GLOBAL_CTRL:.*vcpu->perf_global_ctrl\s*=\s*msr.Flags.*VMCS_GUEST_PERF_GLOBAL_CTRL') 'PMU isolation requires host/guest load controls and an intercepted guest control shadow'
Assert ($vmxSource -match '(?s)vcpu->pmu_version\s*&&\s*!vcpu->pmu_isolated.*HV_FAILURE_REQUIRED_CONTROLS.*return\s+FALSE') 'advertised PMU must fail closed when VMCS PERF_GLOBAL_CTRL isolation is unavailable'
$samplePlan = [regex]::Match(
    $vmexit,
    '(?s)vmexit_exit_sample_plan\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($samplePlan.Success -and
        $samplePlan.Groups['body'].Value -match 'plan\s*=\s*VMEXIT_SAMPLE_APERF_MPERF' -and
        $samplePlan.Groups['body'].Value -notmatch 'default:\s*return\s+0') 'APERF/MPERF root residency must be sampled for every VM-exit reason'
Assert ($stealthHeader -match '#define\s+STEALTH_VIRTUALIZE_TIMERS\s+1' -and
        $ept -match 'ept_create_mmio_hook' -and
        $ept -match 'EptMmioHpet' -and
        $ept -match 'EptMmioLapic' -and
        $ept -match 'ept_handle_mmio_violation' -and
        $ept -match 'CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG') 'HPET/xAPIC EPT timer virtualization contract drifted'
$timerViolation = [regex]::Match(
    $ept,
    '(?s)BOOLEAN\s+ept_handle_mmio_violation\s*\(.*?\)\s*\{(?<body>.*?)\n\}')
Assert ($timerViolation.Success -and
        $timerViolation.Groups['body'].Value -match 'qual\.ExecuteAccess\s*\|\|' -and
        $timerViolation.Groups['body'].Value -match 'qual\.ReadAccess\s*&&\s*qual\.WriteAccess' -and
        $timerViolation.Groups['body'].Value -match 'return\s+FALSE') 'timer hooks must reject execute and mixed RMW accesses instead of livelocking or exposing the real counter'
$timerSetup = [regex]::Match(
    $ept,
    '(?s)ept_setup_timer_hooks\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($timerSetup.Success -and
        $timerSetup.Groups['body'].Value -notmatch 'continuing without MMIO timing hooks' -and
        $timerSetup.Groups['body'].Value -match '(?s)hpet_physical\s*&&\s*!g_ept->tsc_frequency.*return\s+FALSE' -and
        $timerSetup.Groups['body'].Value -match '(?s)!g_ept->mtf_supported.*return\s+FALSE' -and
        $timerSetup.Groups['body'].Value -match '(?s)!vcpu->hpet_va.*ept_destroy_timer_hooks\(\);\s*return\s+FALSE' -and
        $timerSetup.Groups['body'].Value -match '(?s)!vcpu->lapic_va.*ept_destroy_timer_hooks\(\);\s*return\s+FALSE') 'enabled timer virtualization must fail closed when required EPT/MTF hooks cannot be installed'
$tscFrequency = [regex]::Match(
    $ept,
    '(?s)ept_query_tsc_frequency\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($tscFrequency.Success -and
        $tscFrequency.Groups['body'].Value -match '0x15' -and
        $tscFrequency.Groups['body'].Value -notmatch '0x16') 'HPET conversion must use an architectural TSC-frequency source, not CPUID.16H base frequency'
Assert ($timerSetup.Groups['body'].Value -match 'if\s*\(\s*apic_enabled\s*\)' -and
        $timerSetup.Groups['body'].Value -notmatch 'if\s*\(\s*apic_enabled\s*&&\s*!x2apic\s*\)' -and
        $vmexit -match '(?s)case\s+IA32_X2APIC_CUR_COUNT:.*__readmsr\(IA32_APIC_BASE\).*x2apic_enabled') 'LAPIC hook state must survive xAPIC/x2APIC mode transitions after launch'
$lapicSample = [regex]::Match(
    $vmexit,
    '(?s)if\s*\(\s*sample_plan\s*&\s*VMEXIT_SAMPLE_LAPIC\s*\)\s*\{(?<body>.*?)\n\s*\}')
Assert ($lapicSample.Success -and
        $lapicSample.Groups['body'].Value -match '__readmsr\(IA32_APIC_BASE\)' -and
        $lapicSample.Groups['body'].Value -match 'x2apic_enabled') 'per-exit LAPIC sampling must refresh APIC mode before touching the x2APIC current-count MSR'
Assert ($ept -match 'if\s*\(\s*raw\s*&&\s*vcpu->timer_bias_pending\s*\)' -and
        $vmexit -match '(?s)case\s+IA32_X2APIC_CUR_COUNT:.*if\s*\(\s*raw\s*&&\s*vcpu->timer_bias_pending\s*\)') 'expired one-shot LAPIC timers must remain visibly expired after compensation'
Assert ($stealthHeader -match '#define\s+USE_PRIVATE_HOST_CR3\s+0') 'private host CR3 must remain disabled until a race-safe live refresh protocol exists'
Assert ($hostCr3 -match '(?s)if\s*\(!orig_pt\)\s*return\s+NULL;.*if\s*\(!our_pt\)\s*return\s+NULL;' -and
        $hostCr3 -match '(?s)if\s*\(!orig_pd\)\s*return\s+NULL;.*if\s*\(!our_pd\)\s*return\s+NULL;' -and
        $hostCr3 -match '(?s)if\s*\(!orig_pdpt\)\s*return\s+FALSE;.*if\s*\(!our_pdpt\)\s*return\s+FALSE;' -and
        $hostCr3 -match 'g_host_pt_count\s*>=\s*MAX_HOST_PT_PAGES') 'private host CR3 cloning must fail instead of sharing guest-modifiable page-table branches'
function Sync-DynamicControls(
    [uint64]$Controls,
    [uint64]$Forced,
    [bool]$Protect,
    [bool]$Timing) {
    [uint64]$cr3 = 0x8000
    [uint64]$rdtsc = 0x1000
    [uint64]$mask = $cr3 -bor $rdtsc
    [uint64]$next = ($Controls -band (-bnot $mask)) -bor ($Forced -band $mask)
    if ($Protect -or $Timing) { $next = $next -bor $cr3 }
    if ($Timing) { $next = $next -bor $rdtsc }
    return $next
}
Assert-Equal (Sync-DynamicControls 0 0 $false $false) 0 'no dynamic-exit demand'
Assert-Equal (Sync-DynamicControls 0 0 $true $false) 0x8000 'protection requests CR3 only'
Assert-Equal (Sync-DynamicControls 0 0 $false $true) 0x9000 'timing requests CR3 and RDTSC'
Assert-Equal (Sync-DynamicControls 0x20000000 0x1000 $false $false) 0x20001000 'forced and unrelated controls survive'
Assert ($vmexit -match '(?s)VMCALL_PROTECT_REFRESH.*vmx_vmread_checked.*protect_on_cr3_load.*protect_requires_cr3_exiting.*vmexit_sync_dynamic_exiting') 'protection refresh must apply the local EPT view before syncing exits'
Assert ($protect -match '(?s)prot_vcpus_ready.*g_vcpu.*launched' -and
        $protect -match '(?s)protect_add_range.*!prot_vcpus_ready\(\).*STATUS_DEVICE_NOT_READY' -and
        $protect -match '(?s)active\s*=\s*TRUE.*MemoryBarrier\(\).*broadcast_protect_refresh') 'protection publication and rollback must require and restore live vCPUs'
Assert ($vmxSource -match '(?s)pin_ctrl\s*=\s*vmx_adjust_controls\s*\(\s*PIN_BASED_VM_EXEC_CTRL_NMI_EXITING\s*\|\s*PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI' -and
        $vmxSource -notmatch '(?s)pin_ctrl\s*=\s*vmx_adjust_controls\s*\([^;]*PIN_BASED_VM_EXEC_CTRL_EXTERNAL_INTERRUPT_EXITING') 'normal operation must not request external-interrupt exiting'
Assert ($vmxSource -match '(?s)\(\s*pin_ctrl\s*&\s*PIN_BASED_VM_EXEC_CTRL_EXTERNAL_INTERRUPT_EXITING\s*\)\s*\?\s*VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT\s*:\s*0') 'ACK-on-exit must be requested only when external-interrupt exiting is active'
Assert ($driverSource -match 'IoCreateDeviceSecure' -and
        $driverSource -match 'OPHION_CONTROL_SDDL') 'control device ACL drifted'
Assert ($stealthHeader -match '#define\s+OPHION_ALLOW_UNLOAD\s+0' -and
        $stealthHeader -match '#define\s+OPHION_ALLOW_NESTED\s+0') 'unsafe unload/nested modes must default off'
Assert ($vmxSource -match 'PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI' -and
        $vmxSource -match 'HV_FAILURE_NESTED_RESTRICTION') 'virtual-NMI or nested fail-closed gate drifted'
Assert ($ept -match 'execute_only_supported' -and
        $ept -match 'invept_single_context' -and
        $ept -match 'Undefined overlap combinations are conservatively UC') 'EPT capability/MTRR safety drifted'
Assert ($publicHeader -match 'IOCTL_HV_PROTECT_STATUS' -and
        $publicHeader -match 'HV_PROTECT_STATUS_AVAILABLE' -and
        $publicHeader -match 'HV_PROTECT_STATUS_V1') 'protect-status ABI drifted'
Assert ($protect -match 'protect_query_status' -and
        $driverSource -match 'IOCTL_HV_PROTECT_STATUS' -and
        $internal -match 'OPHION_IOCTL_PROTECT_STATUS') 'protect-status plumbing drifted'
$protectLeaf = [regex]::Match(
    $protect,
    '(?s)prot_set_leaf\s*\([^)]*\)\s*\{(?<body>.*?)\n\}')
Assert ($protectLeaf.Success -and
        $protectLeaf.Groups['body'].Value -notmatch 'ept_split_large_page|MmAllocate|ExAllocate|MmMapIoSpace') 'VMX-root leaf mutation must be allocation-free'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\run-local-detectors.ps1')) 'local detector runner missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\collect-crash-artifacts.ps1')) 'crash artifact collector missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\tpm-audit.ps1')) 'TPM auditor missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tests\tpm-audit.ps1')) 'TPM policy tests missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\driver-preflight.ps1')) 'driver preflight tool missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\hyperv-attachment-preflight.ps1')) 'Hyper-V attachment preflight tool missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tests\attachment-preflight.ps1')) 'Hyper-V attachment preflight tests missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\bootstrap-residue.ps1')) 'bootstrap residue auditor missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\artifact-manifest.ps1')) 'artifact manifest tool missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tools\compare-detector-runs.ps1')) 'detector differential tool missing'
Assert (Test-Path -LiteralPath (Join-Path $repo 'tests\mapper-artifact.ps1')) 'mapper artifact test missing'
$attachmentHeaderPath = Join-Path $repo 'include\hv_attachment.h'
$attachmentDocPath = Join-Path $repo 'lab\HYPERV_ATTACHMENT_ABI.md'
Assert (Test-Path -LiteralPath $attachmentHeaderPath) 'clean-room Hyper-V attachment ABI header missing'
Assert (Test-Path -LiteralPath $attachmentDocPath) 'clean-room Hyper-V attachment ABI specification missing'
$attachmentHeader = if (Test-Path -LiteralPath $attachmentHeaderPath) {
    Get-Content -LiteralPath $attachmentHeaderPath -Raw
} else { '' }
$attachmentDoc = if (Test-Path -LiteralPath $attachmentDocPath) {
    Get-Content -LiteralPath $attachmentDocPath -Raw
} else { '' }
Assert ($publicHeader -match 'HV_ATTACH_PLATFORM_V1' -and
        $publicHeader -match 'HV_ATTACH_REQUEST_V1' -and
        $publicHeader -match 'HV_ATTACH_RESULT_V1' -and
        $publicHeader -match 'HV_ATTACH_INTERFACE_HV1' -and
        $publicHeader -match 'HV_ATTACH_ROOT_REQUIRED_PRIVILEGES') 'attachment wire ABI drifted'
Assert ($attachmentHeader -match 'HV_ATTACHMENT_PROVIDER_V1' -and
        $attachmentHeader -match 'HV_ATTACHMENT_SESSION' -and
        $attachmentHeader -match 'Probe' -and
        $attachmentHeader -match 'Prepare' -and
        $attachmentHeader -match 'Commit' -and
        $attachmentHeader -match 'Rollback' -and
        $attachmentHeader -match 'Release') 'attachment provider lifecycle ABI drifted'
Assert ($attachmentDoc -match 'TLFS' -and
        $attachmentDoc -match 'Hv#1' -and
        $attachmentDoc -match 'no private symbols' -and
        $attachmentDoc -match 'VMXON' -and
        $attachmentDoc -match 'measured boot' -and
        $attachmentDoc -match 'rollback') 'attachment clean-room invariants drifted'
$attachmentPreflight = Get-Content -LiteralPath (Join-Path $repo 'tools\hyperv-attachment-preflight.ps1') -Raw
$attachmentTests = Get-Content -LiteralPath (Join-Path $repo 'tests\attachment-preflight.ps1') -Raw
$probeSource = Get-Content -LiteralPath (Join-Path $repo 'tools\OphionProbe.cpp') -Raw
Assert ($attachmentPreflight -match 'ophion\.hyperv-attachment-preflight\.v1' -and
        $attachmentPreflight -match "ValidateSet\('probe', 'root', 'nested'\)" -and
        $attachmentPreflight -match 'TransitionLog' -and
        $attachmentPreflight -match 'cpuid-incoherent' -and
        $attachmentPreflight -match 'privilege-missing' -and
        $attachmentPreflight -match 'nested-unavailable' -and
        $attachmentPreflight -match 'ReadOnly\s*=\s*\$true') 'attachment preflight state machine drifted'
Assert ($attachmentTests -match 'eligible, incompatible, malformed' -and
        $probeSource -match 'hypervisorLeaves' -and
        $probeSource -match '0x4000000au' -and
        $probeSource -match '\-\-help') 'attachment preflight coverage or CPUID leaf cap drifted'
$tpmAudit = Get-Content -LiteralPath (Join-Path $repo 'tools\tpm-audit.ps1') -Raw
$tpmTests = Get-Content -LiteralPath (Join-Path $repo 'tests\tpm-audit.ps1') -Raw
Assert ($tpmAudit -match 'ophion\.tpm-audit\.v2' -and
        $tpmAudit -match 'New-PcrReadSha256' -and
        $tpmAudit -match '0x95,0x08,0x00' -and
        $tpmAudit -match 'Confirm-SecureBootUEFI' -and
        $tpmAudit -match 'PcrsMatchTcgLog' -and
        $tpmAudit -match 'AttestationHealth' -and
        $tpmAudit -match 'PreservationValidated\s*=\s*\$false') 'TPM/PCR/measured-boot audit contract drifted'
Assert ($tpmTests -match 'compatible, inconclusive, incompatible, malformed' -and
        $tpmTests -match 'PreservationValidated') 'TPM policy classification coverage drifted'
$artifactManifest = Get-Content -LiteralPath (Join-Path $repo 'tools\artifact-manifest.ps1') -Raw
Assert ($artifactManifest -match 'ophion\.artifact-manifest\.v1' -and
        $artifactManifest -match 'production-driver' -and
        $artifactManifest -match 'diagnostic-driver' -and
        $artifactManifest -match 'mapper' -and
        $artifactManifest -match 'loader' -and
        $artifactManifest -match 'probe' -and
        $artifactManifest -match 'internal-library' -and
        $artifactManifest -match 'platform-library' -and
        $artifactManifest -match 'platform-tests' -and
        $artifactManifest -match 'mock-client' -and
        $artifactManifest -match 'BootImagePath' -and
        $artifactManifest -match "0x8664") 'artifact inventory or architecture gate drifted'
$detectorDiff = Get-Content -LiteralPath (Join-Path $repo 'tools\compare-detector-runs.ps1') -Raw
Assert ($detectorDiff -match 'ophion\.detector-differential\.v1' -and
        $detectorDiff -match 'HardDrift' -and
        $detectorDiff -match 'RuntimeExercised' -and
        $detectorDiff -match 'host-baseline-unchanged-runtime-not-exercised' -and
        $detectorDiff -match 'KnownBaselineFinding' -and
        $detectorDiff -match 'MedianTimingTolerancePercent') 'detector differential evidence gate drifted'
Assert ($vmxSource -match 'vmx_all_stopped' -and
        $driverSource -match 'if\s*\(\s*!vmx_all_stopped\(\)\s*\)' -and
        $vmexit -match 'asm_vmxoff_checked') 'VMXOFF acknowledgement/free gate drifted'
$asmPrototypes = Get-Content -LiteralPath (Join-Path $repo 'include\asm_prototypes.h') -Raw
Assert ($asmPrototypes -match 'asm_vmxoff_checked') 'checked VMXOFF ABI missing'
Write-Host "Contract assertions passed: $script:assertions"
