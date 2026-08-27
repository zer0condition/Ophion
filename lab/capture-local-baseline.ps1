<#
.SYNOPSIS
Writes local, self-process baseline observations as versioned JSONL.

.DESCRIPTION
This script performs no network operation, anti-cheat or game attachment,
driver operation, kernel-memory access, or system configuration change. It only
reads local machine and the script's own process metadata, then writes the
requested JSONL file. Output events use source=local_baseline and are rejected
by the fixture-only emulator until independently reviewed and converted into a
recorded fixture.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$schema = 'ophion.eac.startup-observation'
$schemaVersion = '1.0'
$sequence = 0
$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory) {
    [void][System.IO.Directory]::CreateDirectory($outputDirectory)
}

$writer = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.UTF8Encoding]::new($false))
try {
    function Write-Observation([string]$EventType, [hashtable]$Payload) {
        $event = [ordered]@{
            schema = $schema
            schema_version = $schemaVersion
            source = 'local_baseline'
            sequence = $script:sequence
            event_type = $EventType
            captured_at = [DateTime]::UtcNow.ToString('o')
            raw_artifact_path = $OutputPath
            payload = $Payload
        }
        $script:sequence++
        $writer.WriteLine(($event | ConvertTo-Json -Compress -Depth 6))
    }

    Write-Observation 'fixture_metadata' ([ordered]@{
        collection_scope = 'local machine and capture-script process only'
        anti_cheat_attachment = 'not-performed'
        network = 'not-used'
        driver_changes = 'not-performed'
        fixture_compatible = $false
    })

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    Write-Observation 'system_hypervisor_detail' ([ordered]@{
        system_information_class = '0xC5'
        collection_method = 'Win32_ComputerSystem.HypervisorPresent proxy; NtQuerySystemInformation not invoked'
        hypervisor_present = [bool]$computer.HypervisorPresent
    })

    Write-Observation 'cpuid' ([ordered]@{
        collection_state = 'not-collected'
        reason = 'The capture script uses no native CPUID probe; this is a local baseline collector, not an anti-cheat emulator.'
    })

    for ($sample = 0; $sample -lt 2; $sample++) {
        Write-Observation 'kuser_qpc_sample' ([ordered]@{
            kuser_tick_100ns = [DateTime]::UtcNow.Ticks
            qpc_ticks = [System.Diagnostics.Stopwatch]::GetTimestamp()
            qpc_frequency = [System.Diagnostics.Stopwatch]::Frequency
            collection_method = 'managed local clock APIs'
        })
        Start-Sleep -Milliseconds 1
    }

    Write-Observation 'synthetic_msr_access' ([ordered]@{
        collection_state = 'not-collected'
        reason = 'Reading synthetic MSRs requires privileged access and is outside this read-only collector.'
    })

    $self = [System.Diagnostics.Process]::GetCurrentProcess()
    Write-Observation 'process_inventory' ([ordered]@{
        scope = 'self'
        process_id = $self.Id
        process_name = $self.ProcessName
        started_at = $self.StartTime.ToUniversalTime().ToString('o')
    })

    foreach ($thread in $self.Threads) {
        $threadState = [string]$thread.ThreadState
        $waitReason = $null
        if ($threadState -eq 'Wait') {
            $waitReason = [string]$thread.WaitReason
        }
        Write-Observation 'thread_inventory' ([ordered]@{
            scope = 'self'
            process_id = $self.Id
            thread_id = $thread.Id
            state = $threadState
            wait_reason = $waitReason
        })
    }

    foreach ($module in $self.Modules) {
        $certificateState = 'unsigned-or-unavailable'
        $certificateSubject = $null
        try {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($module.FileName)
            $certificateState = 'embedded-certificate-present'
            $certificateSubject = $certificate.Subject
        } catch {
            # No trust or revocation validation is performed, so this stays local and offline.
        }
        Write-Observation 'module_inventory' ([ordered]@{
            scope = 'self'
            module_id = $module.ModuleName
            image_path = $module.FileName
            base_address = ('0x{0:X}' -f $module.BaseAddress.ToInt64())
            image_size = $module.ModuleMemorySize
            certificate_state = $certificateState
            certificate_subject = $certificateSubject
        })
    }

    Write-Observation 'memory_inventory' ([ordered]@{
        scope = 'self-summary'
        working_set_bytes = $self.WorkingSet64
        private_memory_bytes = $self.PrivateMemorySize64
        virtual_memory_bytes = $self.VirtualMemorySize64
        image_backed = 'mixed-or-not-classified'
        collection_method = 'Process memory counters; no virtual-address scan'
    })

    Write-Observation 'nmi_sample_metadata' ([ordered]@{
        collection_state = 'not-collected'
        reason = 'NMI sampling is privileged and outside this read-only collector.'
    })
    Write-Observation 'tpm_measured_boot_result' ([ordered]@{
        state = 'not-collected'
        reason = 'No TPM quote or measured-boot log is collected by this baseline script.'
    })
} finally {
    $writer.Dispose()
}

Write-Host "Wrote local baseline JSONL: $OutputPath"
