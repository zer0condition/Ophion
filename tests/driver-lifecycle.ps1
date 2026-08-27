[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Match(
    [string]$Text,
    [string]$Pattern,
    [string]$Message
) {
    if (-not [regex]::IsMatch($Text, $Pattern)) {
        throw "driver lifecycle assertion failed: $Message"
    }
}

$repo = Split-Path -Parent $PSScriptRoot
$driver = Get-Content -LiteralPath (Join-Path $repo 'src\driver.c') -Raw

# IoCreateDevice leaves DO_DEVICE_INITIALIZING set. The device must only be
# published after its dispatch table and hypervisor state are initialized.
Assert-Match $driver `
    '(?s)if\s*\(!vmx_init\(\)\).*?return\s+STATUS_HV_OPERATION_FAILED\s*;\s*\}\s*device_obj->Flags\s*&=\s*~DO_DEVICE_INITIALIZING\s*;.*?return\s+STATUS_SUCCESS\s*;' `
    'successful DriverEntry must clear DO_DEVICE_INITIALIZING'

# Every IOCTL starts with a zero byte count so errors cannot return stale
# information initialized by a caller, verifier fixture, or reused IRP.
Assert-Match $driver `
    '(?s)DriverIoControl\s*\(.*?UNREFERENCED_PARAMETER\s*\(\s*device_obj\s*\)\s*;\s*irp->IoStatus.Information\s*=\s*0\s*;\s*io_stack\s*=\s*IoGetCurrentIrpStackLocation' `
    'DriverIoControl must reset IoStatus.Information before dispatch'

Write-Host 'Driver lifecycle tests passed: device publication and IOCTL byte count'