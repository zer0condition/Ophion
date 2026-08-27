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
$project = Get-Content -LiteralPath (Join-Path $repo 'Ophion.vcxproj') -Raw
$targets = Get-Content -LiteralPath (Join-Path $repo 'Directory.Build.targets') -Raw

# A device created by IoCreateDeviceSecure is not available for opens until
# the driver clears DO_DEVICE_INITIALIZING. Both success paths that keep the
# image resident must publish the diagnostic control device before returning.
Assert-Match $driver `
    '(?s)if\s*\(!vmx_all_stopped\(\)\).*?driver_obj->DriverUnload\s*=\s*NULL\s*;\s*device_obj->Flags\s*&=\s*~DO_DEVICE_INITIALIZING\s*;\s*return\s+STATUS_SUCCESS\s*;' `
    'the pinned partial-initialization path must publish its status device'
Assert-Match $driver `
    '(?s)tracewipe_apply\s*\(\s*driver_obj\s*,\s*TRUE\s*\)\s*;\s*device_obj->Flags\s*&=\s*~DO_DEVICE_INITIALIZING\s*;.*?return\s+STATUS_SUCCESS\s*;' `
    'the successful diagnostic path must publish its control device'

# Every IOCTL starts with a zero byte count so error paths cannot return stale
# information from an IRP that a lower layer or verifier fixture initialized.
Assert-Match $driver `
    '(?s)DriverIoControl\s*\(.*?UNREFERENCED_PARAMETER\s*\(\s*device_obj\s*\)\s*;\s*irp->IoStatus.Information\s*=\s*0\s*;\s*io_stack\s*=\s*IoGetCurrentIrpStackLocation' `
    'DriverIoControl must reset IoStatus.Information before dispatch'

# Signing identity is an explicit build input. Never commit a machine-specific
# certificate thumbprint in Directory.Build.targets.
if ($targets -match '(?is)<TestCertificate>\s*[0-9a-f]{40}\s*</TestCertificate>') {
    throw 'driver lifecycle assertion failed: Directory.Build.targets pins a certificate thumbprint'
}
Assert-Match $project `
    '(?s)<TestCertificate\s+Condition="[^\"]*OphionCertificateThumbprint[^\"]*">\$\(OphionCertificateThumbprint\)</TestCertificate>' `
    'the project must accept the signing certificate only through OphionCertificateThumbprint'

Write-Host 'Driver lifecycle tests passed: device publication, IOCTL byte count, explicit signing input'