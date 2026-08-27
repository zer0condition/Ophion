[CmdletBinding()]
param(
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$EvidencePath,

    [string]$OutputPath,

    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Complete-Audit($Evidence, $Details) {
    $required = @(
        'Schema', 'SecureBoot', 'TpmVersion', 'PcrSha256Read',
        'PcrCount', 'MeasuredBootLogCount', 'TcgLogReplay',
        'AttestationHealth', 'MutationPerformed')
    foreach ($name in $required) {
        if ($Evidence.PSObject.Properties.Name -notcontains $name) {
            throw "TPM evidence is missing $name."
        }
    }
    if ($Evidence.Schema -ne 'ophion.tpm-evidence.v1') {
        throw 'TPM evidence schema must be ophion.tpm-evidence.v1.'
    }
    if ([bool]$Evidence.MutationPerformed) {
        throw 'TPM compatibility evidence must be read-only.'
    }
    if ($Evidence.SecureBoot -notin @('enabled', 'disabled', 'unknown')) {
        throw 'SecureBoot must be enabled, disabled, or unknown.'
    }

    $incompatible = [Collections.Generic.List[string]]::new()
    $unknown = [Collections.Generic.List[string]]::new()
    if ([int]$Evidence.TpmVersion -ne 2) {
        if ([int]$Evidence.TpmVersion -eq 0) {
            $unknown.Add('TPM 2.0 device state is unknown')
        } else {
            $incompatible.Add('TPM 2.0 is not available')
        }
    }
    if ($Evidence.SecureBoot -eq 'disabled') {
        $incompatible.Add('Secure Boot is disabled')
    } elseif ($Evidence.SecureBoot -eq 'unknown') {
        $unknown.Add('Secure Boot state is unknown')
    }
    if (-not [bool]$Evidence.PcrSha256Read) {
        $unknown.Add('SHA-256 PCR read was not successful')
    } elseif ([int]$Evidence.PcrCount -lt 5) {
        $unknown.Add('Required PCR set 0,2,4,7,11 is incomplete')
    }
    if ([int]$Evidence.MeasuredBootLogCount -lt 1) {
        $unknown.Add('Measured boot event log was not found')
    }
    if ($Evidence.TcgLogReplay -eq 'mismatch') {
        $incompatible.Add('PCR values do not match the TCG log')
    } elseif ($Evidence.TcgLogReplay -ne 'matched') {
        $unknown.Add('TCG log replay state is unknown')
    }
    if ($Evidence.AttestationHealth -eq 'NotAttestable') {
        $incompatible.Add('Windows measured boot health is not attestable')
    } elseif ($Evidence.AttestationHealth -ne 'Attestable') {
        $unknown.Add('Windows measured boot health is unknown')
    }

    $policy = if ($incompatible.Count) {
        'incompatible'
    } elseif ($unknown.Count) {
        'inconclusive'
    } else {
        'compatible'
    }
    $reasons = @($incompatible) + @($unknown)
    [pscustomobject][ordered]@{
        Schema = 'ophion.tpm-audit.v2'
        GeneratedUtc = [DateTime]::UtcNow.ToString('o')
        ReadOnly = $true
        MutationPerformed = $false
        AttachmentProviderInvoked = $false
        PreservationValidated = $false
        AttachmentPolicy = $policy
        ReadyForMeasuredBootNeutralProvider = ($policy -eq 'compatible')
        Reasons = $reasons
        Evidence = $Evidence
        Details = $Details
        Boundary = 'Current-state compatibility only; no attachment provider ran, so PCR preservation is not validated.'
    }
}

function Write-Result($Result) {
    if ($OutputPath) {
        $parent = Split-Path -Parent $OutputPath
        if ($parent) {
            [void][IO.Directory]::CreateDirectory($parent)
        }
        $Result | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $OutputPath -Encoding UTF8
    }
    if ($AsObject) { return $Result }
    $Result | ConvertTo-Json -Depth 10
}

if ($EvidencePath) {
    $evidence = Get-Content -LiteralPath $EvidencePath -Raw |
        ConvertFrom-Json
    $result = Complete-Audit $evidence ([pscustomobject]@{
        Source = 'fixture'
        EvidencePath = (Resolve-Path -LiteralPath $EvidencePath).Path
    })
    Write-Result $result
    return
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class OphionTbsV2 {
    [StructLayout(LayoutKind.Sequential)]
    public struct ContextParams2 {
        public UInt32 Version;
        public UInt32 Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DeviceInfo {
        public UInt32 StructVersion;
        public UInt32 TpmVersion;
        public UInt32 TpmInterfaceType;
        public UInt32 TpmImpRevision;
    }

    [DllImport("tbs.dll")]
    public static extern UInt32 Tbsi_Context_Create(
        ref ContextParams2 parameters, out IntPtr context);

    [DllImport("tbs.dll")]
    public static extern UInt32 Tbsi_GetDeviceInfo(
        UInt32 size, ref DeviceInfo info);

    [DllImport("tbs.dll")]
    public static extern UInt32 Tbsip_Submit_Command(
        IntPtr context, UInt32 locality, UInt32 priority,
        byte[] input, UInt32 inputLength,
        byte[] output, ref UInt32 outputLength);

    [DllImport("tbs.dll")]
    public static extern UInt32 Tbsip_Context_Close(IntPtr context);
}
'@

function Read-Be16([byte[]]$Buffer, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 2 -gt $Buffer.Length) { return $null }
    [uint16](
        ([uint16]$Buffer[$Offset] -shl 8) -bor
        [uint16]$Buffer[$Offset + 1])
}

function Read-Be32([byte[]]$Buffer, [int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $Buffer.Length) { return $null }
    [uint32](
        ([uint32]$Buffer[$Offset] -shl 24) -bor
        ([uint32]$Buffer[$Offset + 1] -shl 16) -bor
        ([uint32]$Buffer[$Offset + 2] -shl 8) -bor
        [uint32]$Buffer[$Offset + 3])
}

function Get-ByteHash([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        -join ($sha.ComputeHash($Bytes) |
            ForEach-Object { $_.ToString('X2') })
    } finally {
        $sha.Dispose()
    }
}

function Read-JsonTextFile([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and
        $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return [Text.Encoding]::Unicode.GetString(
            $bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and
        $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return [Text.Encoding]::BigEndianUnicode.GetString(
            $bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[1] -eq 0) {
        return [Text.Encoding]::Unicode.GetString($bytes)
    }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

function New-ReadPublic([uint32]$Handle) {
    [byte[]]@(
        0x80,0x01, 0x00,0x00,0x00,0x0E, 0x00,0x00,0x01,0x73,
        [byte](($Handle -shr 24) -band 0xFF),
        [byte](($Handle -shr 16) -band 0xFF),
        [byte](($Handle -shr 8) -band 0xFF),
        [byte]($Handle -band 0xFF))
}

function New-GetHandleCapability([uint32]$Handle) {
    [byte[]]@(
        0x80,0x01, 0x00,0x00,0x00,0x16, 0x00,0x00,0x01,0x7A,
        0x00,0x00,0x00,0x01,
        [byte](($Handle -shr 24) -band 0xFF),
        [byte](($Handle -shr 16) -band 0xFF),
        [byte](($Handle -shr 8) -band 0xFF),
        [byte]($Handle -band 0xFF),
        0x00,0x00,0x00,0x01)
}

function New-PcrReadSha256 {
    # SHA-256 bank; PCR 0,2,4,7 and 11.
    [byte[]]@(
        0x80,0x01, 0x00,0x00,0x00,0x14, 0x00,0x00,0x01,0x7E,
        0x00,0x00,0x00,0x01, 0x00,0x0B, 0x03, 0x95,0x08,0x00)
}

function Invoke-Tpm([IntPtr]$Context, [byte[]]$Command) {
    $output = New-Object byte[] 4096
    $length = [uint32]$output.Length
    $tbsResult = [OphionTbsV2]::Tbsip_Submit_Command(
        $Context, 0, 200, $Command, [uint32]$Command.Length,
        $output, [ref]$length)
    $response = if ($length) {
        [byte[]]$output[0..($length - 1)]
    } else {
        [byte[]]@()
    }
    [pscustomobject]@{
        TbsResult = ('0x{0:X8}' -f $tbsResult)
        ResponseCode = if ($response.Length -ge 10) {
            '0x{0:X8}' -f (Read-Be32 $response 6)
        } else { $null }
        Length = [int]$length
        Sha256 = if ($response.Length) {
            Get-ByteHash $response
        } else { $null }
        Bytes = $response
    }
}

function Read-PcrResponse([byte[]]$Response) {
    if ($Response.Length -lt 22 -or
        (Read-Be32 $Response 6) -ne 0) {
        return $null
    }
    $offset = 10
    $updateCounter = Read-Be32 $Response $offset
    $offset += 4
    $selectionCount = Read-Be32 $Response $offset
    $offset += 4
    $selected = [Collections.Generic.List[int]]::new()
    for ($selection = 0; $selection -lt $selectionCount; $selection++) {
        if ($offset + 3 -gt $Response.Length) { return $null }
        $algorithm = Read-Be16 $Response $offset
        $offset += 2
        $selectBytes = [int]$Response[$offset]
        $offset++
        if ($selectBytes -lt 1 -or
            $offset + $selectBytes -gt $Response.Length) {
            return $null
        }
        if ($algorithm -eq 0x000B) {
            for ($byteIndex = 0; $byteIndex -lt $selectBytes; $byteIndex++) {
                for ($bit = 0; $bit -lt 8; $bit++) {
                    if (($Response[$offset + $byteIndex] -band
                        (1 -shl $bit)) -ne 0) {
                        $selected.Add(($byteIndex * 8) + $bit)
                    }
                }
            }
        }
        $offset += $selectBytes
    }
    if ($offset + 4 -gt $Response.Length) { return $null }
    $digestCount = Read-Be32 $Response $offset
    $offset += 4
    if ($digestCount -ne $selected.Count) { return $null }
    $digests = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $digestCount; $index++) {
        if ($offset + 2 -gt $Response.Length) { return $null }
        $digestSize = [int](Read-Be16 $Response $offset)
        $offset += 2
        if ($digestSize -ne 32 -or
            $offset + $digestSize -gt $Response.Length) {
            return $null
        }
        $digest = [byte[]]$Response[
            $offset..($offset + $digestSize - 1)]
        $offset += $digestSize
        $digests.Add([pscustomobject][ordered]@{
            Index = $selected[$index]
            Sha256 = -join ($digest |
                ForEach-Object { $_.ToString('X2') })
        })
    }
    [pscustomobject][ordered]@{
        UpdateCounter = $updateCounter
        Digests = @($digests)
    }
}

$secureBoot = 'unknown'
$secureBootError = $null
try {
    $secureBoot = if (Confirm-SecureBootUEFI -ErrorAction Stop) {
        'enabled'
    } else {
        'disabled'
    }
} catch {
    $secureBootError = $_.Exception.Message
}

$tpmCmdlet = $null
try {
    $tpmCmdlet = Get-Tpm -ErrorAction Stop |
        Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,
            TpmOwned,ManufacturerIdTxt,ManufacturerVersion,
            ManagedAuthLevel,OwnerClearDisabled,AutoProvisioning
} catch {}

$measuredBootLogs = @()
$measuredBootSummary = $null
$measuredBootPath = Join-Path $env:SystemRoot 'Logs\MeasuredBoot'
if (Test-Path -LiteralPath $measuredBootPath -PathType Container) {
    $measuredBootLogs = @(
        Get-ChildItem -LiteralPath $measuredBootPath -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 16 |
        ForEach-Object {
            [pscustomobject][ordered]@{
                Path = $_.FullName
                Bytes = $_.Length
                LastWriteUtc = $_.LastWriteTimeUtc.ToString('o')
                Sha256 = (Get-FileHash -LiteralPath $_.FullName `
                    -Algorithm SHA256).Hash
            }
        })
    $summaryFile = @(
        Get-ChildItem -LiteralPath $measuredBootPath -File -Filter '*.json' |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1)
    if ($summaryFile.Count) {
        try {
            $summary = Read-JsonTextFile $summaryFile[0].FullName |
                ConvertFrom-Json
            $pcrMatch = @($summary.Expected | Where-Object {
                $_.Field -eq 'PcrsMatchTcgLog'
            } | Select-Object -First 1)
            $measuredBootSummary = [pscustomobject][ordered]@{
                Path = $summaryFile[0].FullName
                Version = $summary.Version
                HealthStatus = [string]$summary.HealthStatus
                PcrsMatchTcgLog = if ($pcrMatch.Count) {
                    [bool]$pcrMatch[0].Value
                } else { $null }
            }
        } catch {}
    }
}

$parameters = [OphionTbsV2+ContextParams2]::new()
$parameters.Version = 2
$parameters.Flags = 4
$context = [IntPtr]::Zero
$contextResult = [OphionTbsV2]::Tbsi_Context_Create(
    [ref]$parameters, [ref]$context)
$deviceA = [OphionTbsV2+DeviceInfo]::new()
$deviceB = [OphionTbsV2+DeviceInfo]::new()
$deviceResultA = [OphionTbsV2]::Tbsi_GetDeviceInfo(16, [ref]$deviceA)
$deviceResultB = [OphionTbsV2]::Tbsi_GetDeviceInfo(16, [ref]$deviceB)

$srk = $null
$aik1 = $null
$aik2 = $null
$handles = $null
$pcr = $null
$parsedPcr = $null
if ($contextResult -eq 0 -and $context -ne [IntPtr]::Zero) {
    try {
        $srkHandle = [Convert]::ToUInt32('81000001', 16)
        $eacHandle = [Convert]::ToUInt32('810EAC00', 16)
        $srk = Invoke-Tpm $context (New-ReadPublic $srkHandle)
        $aik1 = Invoke-Tpm $context (New-ReadPublic $eacHandle)
        $aik2 = Invoke-Tpm $context (New-ReadPublic $eacHandle)
        $handles = Invoke-Tpm $context (
            New-GetHandleCapability $eacHandle)
        $pcr = Invoke-Tpm $context (New-PcrReadSha256)
        $parsedPcr = Read-PcrResponse $pcr.Bytes
    } finally {
        [void][OphionTbsV2]::Tbsip_Context_Close($context)
    }
}

$tpmVersion = if (
    $deviceResultA -eq 0 -and
    $deviceResultB -eq 0 -and
    $deviceA.TpmVersion -eq $deviceB.TpmVersion) {
    [int]$deviceA.TpmVersion
} else { 0 }
$requiredPcrs = @(0,2,4,7,11)
$pcrIndices = if ($parsedPcr) {
    @($parsedPcr.Digests | ForEach-Object Index)
} else { @() }
$pcrComplete = (
    $pcr -and
    $pcr.TbsResult -eq '0x00000000' -and
    $pcr.ResponseCode -eq '0x00000000' -and
    $parsedPcr -and
    @($requiredPcrs | Where-Object {
        $pcrIndices -notcontains $_
    }).Count -eq 0)

$evidence = [pscustomobject][ordered]@{
    Schema = 'ophion.tpm-evidence.v1'
    SecureBoot = $secureBoot
    TpmVersion = $tpmVersion
    PcrSha256Read = [bool]$pcrComplete
    PcrCount = $pcrIndices.Count
    MeasuredBootLogCount = $measuredBootLogs.Count
    TcgLogReplay = if (
        $measuredBootSummary -and
        $null -ne $measuredBootSummary.PcrsMatchTcgLog) {
        if ($measuredBootSummary.PcrsMatchTcgLog) {
            'matched'
        } else {
            'mismatch'
        }
    } else { 'unknown' }
    AttestationHealth = if ($measuredBootSummary) {
        $measuredBootSummary.HealthStatus
    } else { 'unknown' }
    MutationPerformed = $false
}
$details = [pscustomobject][ordered]@{
    Source = 'live'
    ContextResult = ('0x{0:X8}' -f $contextResult)
    DeviceProbeA = [pscustomobject][ordered]@{
        Result = ('0x{0:X8}' -f $deviceResultA)
        Version = $deviceA.TpmVersion
        Interface = $deviceA.TpmInterfaceType
        Revision = $deviceA.TpmImpRevision
    }
    DeviceProbeB = [pscustomobject][ordered]@{
        Result = ('0x{0:X8}' -f $deviceResultB)
        Version = $deviceB.TpmVersion
        Interface = $deviceB.TpmInterfaceType
        Revision = $deviceB.TpmImpRevision
    }
    GetTpm = $tpmCmdlet
    SecureBoot = [pscustomobject]@{
        State = $secureBoot
        Error = $secureBootError
    }
    MeasuredBootLogs = $measuredBootLogs
    MeasuredBootSummary = $measuredBootSummary
    PcrRead = if ($pcr) {
        [pscustomobject][ordered]@{
            TbsResult = $pcr.TbsResult
            ResponseCode = $pcr.ResponseCode
            Length = $pcr.Length
            Sha256 = $pcr.Sha256
            Parsed = $parsedPcr
        }
    } else { $null }
    Srk = if ($srk) {
        $srk | Select-Object TbsResult,ResponseCode,Length,Sha256
    } else { $null }
    EacAikFirst = if ($aik1) {
        $aik1 | Select-Object TbsResult,ResponseCode,Length,Sha256
    } else { $null }
    EacAikSecond = if ($aik2) {
        $aik2 | Select-Object TbsResult,ResponseCode,Length,Sha256
    } else { $null }
    EacAikDeterministic = if ($aik1 -and $aik2) {
        $aik1.Length -eq $aik2.Length -and
        $aik1.Sha256 -eq $aik2.Sha256
    } else { $false }
    EacAikHandlePresent = (
        $handles -and
        $handles.ResponseCode -eq '0x00000000' -and
        $handles.Bytes.Length -ge 23 -and
        (Read-Be32 $handles.Bytes 19) -eq
            [Convert]::ToUInt32('810EAC00', 16))
}

$result = Complete-Audit $evidence $details
Write-Result $result
