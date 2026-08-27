[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'tools\hyperv-attachment-preflight.ps1'
if (-not (Test-Path -LiteralPath $tool)) {
    throw 'Hyper-V attachment preflight tool is missing.'
}

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "attachment preflight test failed: $Message" }
}

function Write-Snapshot(
    [string]$Path,
    [uint32]$Interface,
    [uint32]$PrivilegeLow,
    [uint32]$PrivilegeHigh,
    [bool]$HypervisorPresent = $true) {
    $leaves = @(
        [ordered]@{
            Leaf = '0x00000001'
            Eax = 0
            Ebx = 0
            Ecx = if ($HypervisorPresent) { [uint32]2147483648 } else { 0 }
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000000'
            Eax = [uint32]0x4000000A
            Ebx = [uint32]0x7263694D
            Ecx = [uint32]0x666F736F
            Edx = [uint32]0x76482074
        },
        [ordered]@{
            Leaf = '0x40000001'
            Eax = $Interface
            Ebx = 0
            Ecx = 0
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000002'
            Eax = 26200
            Ebx = [uint32]0x000A0000
            Ecx = 0
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000003'
            Eax = $PrivilegeLow
            Ebx = $PrivilegeHigh
            Ecx = 0
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000004'
            Eax = 0
            Ebx = 0
            Ecx = 48
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000005'
            Eax = 256
            Ebx = 256
            Ecx = 0
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x40000006'
            Eax = 0x3F
            Ebx = 0
            Ecx = 0
            Edx = 0
        },
        [ordered]@{
            Leaf = '0x4000000A'
            Eax = 0x00000101
            Ebx = 0
            Ecx = 0
            Edx = 0
        }
    )
    [ordered]@{
        Schema = 'ophion.hyperv-cpuid.v1'
        Architecture = 'x64'
        OsBuild = 26200
        Leaves = $leaves
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Path -Encoding UTF8
}

$temp = Join-Path ([IO.Path]::GetTempPath()) (
    'ophion-attachment-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $root = Join-Path $temp 'root.json'
    Write-Snapshot $root 0x31237648 0x20 0x3
    $eligible = & $tool -Mode root -SnapshotPath $root -AsObject
    Assert ($eligible.Schema -eq 'ophion.hyperv-attachment-preflight.v1') 'schema'
    Assert ($eligible.State -eq 'eligible') 'root state'
    Assert ($eligible.StateCode -eq 2) 'root state code'
    Assert ($eligible.Failure -eq 'none') 'root failure'
    Assert ($eligible.FailureCode -eq 0) 'root failure code'
    Assert ($eligible.ReadOnly -eq $true) 'read-only marker'
    Assert (($eligible.TransitionLog -join ',') -eq 'empty,discovered,eligible') 'root transitions'
    Assert (($eligible.Platform.PartitionPrivileges -band 0x300000020) -eq 0x300000020) 'root privileges'

    $wrongInterface = Join-Path $temp 'wrong-interface.json'
    Write-Snapshot $wrongInterface ([uint32]3735928559) 0x20 0x3
    $incompatible = & $tool -Mode root -SnapshotPath $wrongInterface -AsObject
    Assert ($incompatible.State -eq 'failed') 'wrong-interface state'
    Assert ($incompatible.Failure -eq 'interface-mismatch') 'wrong-interface failure'
    Assert ($incompatible.FailureCode -eq 3) 'wrong-interface failure code'
    Assert (($incompatible.TransitionLog -join ',') -eq 'empty,discovered,failed') 'wrong-interface transitions'

    $missingPrivilege = Join-Path $temp 'missing-privilege.json'
    Write-Snapshot $missingPrivilege 0x31237648 0x20 0
    $denied = & $tool -Mode root -SnapshotPath $missingPrivilege -AsObject
    Assert ($denied.State -eq 'failed') 'privilege state'
    Assert ($denied.Failure -eq 'privilege-missing') 'privilege failure'

    $malformed = Join-Path $temp 'malformed.json'
    '{"Schema":"wrong","Leaves":[]}' | Set-Content -LiteralPath $malformed -Encoding UTF8
    $threw = $false
    try {
        [void](& $tool -Mode probe -SnapshotPath $malformed -AsObject)
    } catch {
        $threw = $true
    }
    Assert $threw 'malformed snapshot must throw'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Attachment preflight tests passed: eligible, incompatible, malformed'
