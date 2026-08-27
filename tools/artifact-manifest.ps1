[CmdletBinding()]
param(
    [string]$OutputPath,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$BootImagePath,
    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $repo 'build\artifact-manifest.json'
}

$targets = @(
    @{ Name='production-driver'; Path='build\bin\Release\Ophion-production.sys'; Kind='pe'; Required=$true },
    @{ Name='diagnostic-driver'; Path='build\bin\Debug\Ophion.sys'; Kind='pe'; Required=$true },
    @{ Name='mapper'; Path='build\bin\Release\OphionMap.exe'; Kind='pe'; Required=$true },
    @{ Name='loader'; Path='build\bin\Release\OphionLoad.exe'; Kind='pe'; Required=$true },
    @{ Name='probe'; Path='build\bin\Release\OphionProbe.exe'; Kind='pe'; Required=$true },
    @{ Name='internal-library'; Path='build\bin\Release\OphionInternal.lib'; Kind='archive'; Required=$true },
    @{ Name='platform-library'; Path='build\cmake\vs2022-x64\platform\Release\ophion_platform.lib'; Kind='archive'; Required=$true },
    @{ Name='platform-tests'; Path='build\cmake\vs2022-x64\platform\Release\ophion_platform_tests.exe'; Kind='pe'; Required=$true },
    @{ Name='mock-client'; Path='build\cmake\vs2022-x64\client\Release\ophion_mock_client.exe'; Kind='pe'; Required=$true }
)

function Get-PeMachine([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 0x100) { return $null }
    $offset = [BitConverter]::ToUInt32($bytes, 0x3C)
    if ($offset + 6 -gt $bytes.Length -or
        [BitConverter]::ToUInt32($bytes, $offset) -ne 0x00004550) {
        return $null
    }
    '0x{0:X4}' -f [BitConverter]::ToUInt16($bytes, $offset + 4)
}

$artifacts = [Collections.Generic.List[object]]::new()
$missing = [Collections.Generic.List[string]]::new()
foreach ($target in $targets) {
    $path = Join-Path $repo $target.Path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ($target.Required) { $missing.Add($target.Name) }
        continue
    }
    $file = Get-Item -LiteralPath $path
    $machine = if ($target.Kind -eq 'pe') {
        Get-PeMachine $path
    } else { $null }
    if ($target.Kind -eq 'pe' -and $machine -ne '0x8664') {
        throw "$($target.Name) is not an x64 PE image."
    }
    $artifacts.Add([pscustomobject][ordered]@{
        Name = $target.Name
        Path = $file.FullName
        Kind = $target.Kind
        Bytes = $file.Length
        Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        Machine = $machine
    })
}

$result = [pscustomobject][ordered]@{
    Schema = 'ophion.artifact-manifest.v1'
    GeneratedUtc = [DateTime]::UtcNow.ToString('o')
    RequiredArtifacts = $targets.Count
    PresentArtifacts = $artifacts.Count
    MissingRequired = @($missing)
    BootImage = if ($BootImagePath) {
        $boot = Get-Item -LiteralPath $BootImagePath
        $bootMachine = Get-PeMachine $boot.FullName
        if ($bootMachine -ne '0x8664') {
            throw 'OphionBoot.efi is not an x64 PE image.'
        }
        [pscustomobject][ordered]@{
            RequiredForRuntimeProfile = $false
            BuiltThisRun = $true
            Path = $boot.FullName
            Bytes = $boot.Length
            Sha256 = (
                Get-FileHash -LiteralPath $boot.FullName `
                    -Algorithm SHA256).Hash
            Machine = $bootMachine
        }
    } else {
        [pscustomobject]@{
            RequiredForRuntimeProfile = $false
            BuiltThisRun = $false
            Reason = 'EDK2 boot image path was not supplied.'
        }
    }
    Artifacts = @($artifacts)
}
if ($missing.Count) {
    throw "Required artifacts are missing: $($missing -join ', ')"
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { [void][IO.Directory]::CreateDirectory($parent) }
$result | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $OutputPath -Encoding UTF8
if ($AsObject) { return $result }
$result | ConvertTo-Json -Depth 6
