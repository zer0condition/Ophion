param([ValidateSet('Debug', 'Release')][string]$Configuration = 'Debug')

$ErrorActionPreference = 'Stop'
$build = Join-Path $PSScriptRoot 'build'
cmake -S $PSScriptRoot -B $build
cmake --build $build --config $Configuration --target ophion_mock_client
