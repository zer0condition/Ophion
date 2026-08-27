[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$Clean,
    [switch]$CleanOnly,
    [switch]$WarningsAsErrors,
    [switch]$Production,
    [switch]$CodeAnalysis,
    [string]$WdkVersion,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Native([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath"
    }
}

function Get-VsInstallation {
    if ($env:VSINSTALLDIR -and (Test-Path (Join-Path $env:VSINSTALLDIR 'VC\Tools\MSVC'))) {
        return $env:VSINSTALLDIR
    }

    $vswhere = $null
    if (${env:ProgramFiles(x86)}) {
        $candidate = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path $candidate) { $vswhere = $candidate }
    }
    if (-not $vswhere) {
        $command = Get-Command vswhere.exe -ErrorAction SilentlyContinue
        if ($command) { $vswhere = $command.Source }
    }
    if (-not $vswhere) {
        throw 'Visual Studio discovery failed: vswhere.exe was not found.'
    }

    $installation = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $installation) {
        throw 'No Visual Studio installation with the x64 C++ tools was found.'
    }
    return $installation.Trim()
}

function Get-MsvcTools([string]$VsInstallation) {
    $root = Join-Path $VsInstallation 'VC\Tools\MSVC'
    $toolset = Get-ChildItem -LiteralPath $root -Directory | Where-Object {
        Test-Path (Join-Path $_.FullName 'bin\Hostx64\x64\cl.exe')
    } | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if (-not $toolset) { throw "No x64 MSVC toolset was found under $root." }
    return $toolset.FullName
}

function Get-KitsRoot {
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'
    )) {
        if (Test-Path $key) {
            $value = (Get-ItemProperty -LiteralPath $key -Name KitsRoot10 -ErrorAction SilentlyContinue).KitsRoot10
            if ($value -and (Test-Path $value)) { return $value }
        }
    }
    throw 'Windows Kits 10 root was not found in the Installed Roots registry keys.'
}

function Get-Wdk([string]$KitsRoot, [string]$RequestedVersion) {
    $includeRoot = Join-Path $KitsRoot 'Include'
    if ($RequestedVersion) {
        $version = $RequestedVersion.TrimEnd('\', '/')
        $candidates = @(Get-Item -LiteralPath (Join-Path $includeRoot $version) -ErrorAction SilentlyContinue)
    } else {
        $candidates = @(
            Get-ChildItem -LiteralPath $includeRoot -Directory |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending
        )
    }

    foreach ($candidate in $candidates) {
        $version = $candidate.Name
        $kmHeader = Join-Path $candidate.FullName 'km\ntddk.h'
        $sharedHeader = Join-Path $candidate.FullName 'shared\ntdef.h'
        $ntoskrnl = Join-Path $KitsRoot "Lib\$version\km\x64\ntoskrnl.lib"
        if ((Test-Path $kmHeader) -and
            (Test-Path $sharedHeader) -and
            (Test-Path $ntoskrnl)) {
            return [pscustomobject]@{
                Root = $KitsRoot
                Version = $version
                Include = $candidate.FullName
                Library = Join-Path $KitsRoot "Lib\$version\km\x64"
                Bin = Join-Path $KitsRoot "bin\$version"
            }
        }
    }

    $requested = if ($RequestedVersion) { " version $RequestedVersion" } else { '' }
    throw "No installed WDK$requested contains both kernel headers and x64 kernel libraries."
}

$repo = $PSScriptRoot
$profile = if ($Production) { 'Production' } else { 'Diagnostic' }
$objDir = Join-Path $repo "build\obj\$Configuration-$profile"
$binDir = Join-Path $repo "build\bin\$Configuration"
$output = Join-Path $binDir 'Ophion.sys'
if ($Production) { $output = Join-Path $binDir 'Ophion-production.sys' }

if ($Clean -or $CleanOnly) {
    Remove-Item -LiteralPath $objDir, $binDir -Recurse -Force -ErrorAction SilentlyContinue
}
if ($CleanOnly) { return }

$vs = Get-VsInstallation
$msvc = Get-MsvcTools $vs
$wdk = Get-Wdk (Get-KitsRoot) $WdkVersion
$tools = Join-Path $msvc 'bin\Hostx64\x64'
$cl = Join-Path $tools 'cl.exe'
$ml64 = Join-Path $tools 'ml64.exe'
$link = Join-Path $tools 'link.exe'
$dumpbin = Join-Path $tools 'dumpbin.exe'
foreach ($tool in @($cl, $ml64, $link, $dumpbin)) {
    if (-not (Test-Path $tool)) { throw "Required MSVC tool not found: $tool" }
}

New-Item -ItemType Directory -Force -Path $objDir, $binDir | Out-Null

$compile = @(
    '/nologo', '/c', '/kernel', '/W4', '/Zp8', '/GS', '/Gy', '/Zi', '/FC',
    "/Fd$(Join-Path $objDir 'compiler.pdb')",
    '/diagnostics:caret', '/volatile:iso', '/std:c17',
    '/D_AMD64_', '/DAMD64', '/DWINNT=1', '/DUNICODE', '/D_UNICODE',
    "/I$(Join-Path $repo 'include')",
    "/I$(Join-Path $wdk.Include 'shared')",
    "/I$(Join-Path $wdk.Include 'km')",
    "/I$(Join-Path $wdk.Include 'ucrt')",
    "/I$(Join-Path $msvc 'include')"
)
if ($Configuration -eq 'Release') {
    $compile += @('/O2', '/Ob2', '/Oi', '/DNDEBUG')
} else {
    $compile += @('/Od', '/Ob0', '/D_DEBUG', '/DDBG=1')
}
if ($WarningsAsErrors) { $compile += '/WX' }
if ($Production) {
    $compile += @(
        '/DOPHION_PRODUCTION=1',
        '/DOPHION_EXPERIMENTAL_MUTATIONS=0',
        '/DSTEALTH_WIPE_LOADER_TRACES=0',
        '/DSTEALTH_EAC_STACK_SCRUB=0',
        '/DSTEALTH_CONCEAL_BYOVD=0',
        '/DSTEALTH_EAC_PATCH_KD=0',
        '/DSTEALTH_EAC_PATCH_KSD=0',
        '/DSTEALTH_EAC_CONCEAL_DMAR=0',
        '/DSTEALTH_EAC_ZERO_HVL=0',
        '/DSTEALTH_EAC_SPOOF_SMBIOS=0',
        '/DSTEALTH_EAC_PATCH_VSL=0')
}
if ($CodeAnalysis) { $compile += '/analyze' }

$productionExcluded = @('byovd_conceal.c', 'eac_stealth.c', 'tracewipe.c')
$sources = @(Get-ChildItem -LiteralPath (Join-Path $repo 'src') -Filter '*.c' -File |
    Where-Object { $_.Name -ne 'production_safe_profile.c' } |
    Sort-Object Name)
if ($Production) {
    $sources = @($sources | Where-Object { $productionExcluded -notcontains $_.Name })
    $safeProfile = Get-Item -LiteralPath (Join-Path $repo 'src\production_safe_profile.c')
    if ($sources.FullName -notcontains $safeProfile.FullName) { $sources += $safeProfile }
}
$objects = [System.Collections.Generic.List[string]]::new()
foreach ($source in $sources) {
    $object = Join-Path $objDir ($source.BaseName + '.obj')
    Invoke-Native $cl ($compile + @("/Fo$object", $source.FullName))
    $objects.Add($object)
}
foreach ($source in Get-ChildItem -LiteralPath (Join-Path $repo 'asm') -Filter '*.asm' -File | Sort-Object Name) {
    $object = Join-Path $objDir ($source.BaseName + '.obj')
    $masm = @('/nologo', '/c', '/W3', '/Zi', '/D_AMD64_', "/Fo$object", $source.FullName)
    if ($WarningsAsErrors) { $masm = @('/WX') + $masm }
    Invoke-Native $ml64 $masm
    $objects.Add($object)
}
if ($objects.Count -eq 0) { throw 'No C or MASM source files were found.' }

$libraryNames = @('ntoskrnl.lib', 'hal.lib', 'wmilib.lib', 'aux_klib.lib', 'wdmsec.lib', 'BufferOverflowFastFailK.lib')
$libraries = foreach ($name in $libraryNames) {
    $path = Join-Path $wdk.Library $name
    if (-not (Test-Path $path)) { throw "Required WDK library not found: $path" }
    $path
}
$pdbPath = [System.IO.Path]::ChangeExtension($output, '.pdb')
$linkArgs = @(
    '/NOLOGO', "/OUT:$output", '/MACHINE:X64', '/SUBSYSTEM:NATIVE', '/DRIVER',
    '/KERNEL', '/ENTRY:DriverEntry', '/NODEFAULTLIB', '/INCREMENTAL:NO',
    '/MANIFEST:NO', '/DYNAMICBASE', '/NXCOMPAT', '/DEBUG',
    "/PDB:$pdbPath", "/MAP:$([IO.Path]::ChangeExtension($output, '.map'))"
)
if ($Production) {
    # keep symbols locally but never embed the build machine's path or the
    # project name in the shipped binary
    $linkArgs += '/PDBALTPATH:driver.pdb'
}
if ($Configuration -eq 'Release') {
    $linkArgs += @('/OPT:REF', '/OPT:ICF')
} else {
    $linkArgs += @('/OPT:NOREF', '/OPT:NOICF')
}
Invoke-Native $link ($linkArgs + $objects.ToArray() + $libraries)
$objectManifest = [pscustomobject][ordered]@{
    Schema = 'ophion.driver-object-manifest.v1'
    Profile = $profile
    Configuration = $Configuration
    Sources = @($sources | ForEach-Object { $_.Name })
    Objects = @($objects | ForEach-Object { [IO.Path]::GetFileName($_) })
}
$objectManifest | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath ([IO.Path]::ChangeExtension($output, '.objects.json')) -Encoding UTF8

$headers = (& $dumpbin /nologo /headers $output 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'dumpbin failed while verifying the output PE headers.' }
if ($headers -notmatch '(?im)^\s*8664\s+machine\s+\(x64\)') { throw 'Output verification failed: PE machine is not x64.' }
if ($headers -notmatch '(?im)^\s*1\s+subsystem\s+\(Native\)') { throw 'Output verification failed: PE subsystem is not Native.' }
if ($Production) {
    & (Join-Path $repo 'tools\verify-production-boundary.ps1') `
        -Path $output `
        -DumpbinPath $dumpbin `
        -ObjectManifestPath ([IO.Path]::ChangeExtension($output, '.objects.json'))
    if ($LASTEXITCODE -ne 0) { throw 'Production boundary verification failed.' }
}

if ($CertificateThumbprint) {
    $thumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw 'CertificateThumbprint must be a 40-digit SHA1 thumbprint.' }
    $signtool = @(
        (Join-Path $wdk.Bin 'x64\signtool.exe'),
        (Join-Path $wdk.Bin 'x86\signtool.exe')
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe was not found under $($wdk.Bin)." }

    $signArgs = @('sign', '/s', 'My', '/sha1', $thumbprint, '/fd', 'SHA256')
    if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
    $signArgs += $output
    Invoke-Native $signtool $signArgs
    Invoke-Native $signtool @('verify', '/pa', '/v', $output)

    $signature = Get-AuthenticodeSignature -LiteralPath $output
    if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Thumbprint -ne $thumbprint) {
        throw 'Output signature does not match CertificateThumbprint.'
    }
} else {
    $signature = Get-AuthenticodeSignature -LiteralPath $output
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned) {
        throw "Unsigned build verification failed: output signature status is $($signature.Status)."
    }
}

Write-Host "Built $output (WDK $($wdk.Version), unsigned=$(-not [bool]$CertificateThumbprint))."
