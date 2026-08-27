/*
 * root_transport.c - production-only authenticated VMX-root command page
 *
 * The guest-visible .hvshare page is a fixed doorbell record.  Capability,
 * sequence, concurrency, and seal state live in the EPT-concealed .hvroot
 * page.  VMX-root never follows a guest pointer and never allocates.
 */
#include "hv.h"
#include "hv_transport_mac.h"

#define HV_ROOT_REQUEST_MAX 64U
#define HV_ROOT_SEAL_WORDS  4U

typedef struct _HV_ROOT_TRANSPORT_STATE {
    volatile LONG   Phase;
    volatile LONG   InFlight;
    volatile LONG   SealedCount;
    volatile LONG   StopCount;
    volatile LONG   LastFailure;
    volatile LONG   MetadataReady;
    volatile LONG   ConcealCount;
    volatile LONG   ConcealReady;
    volatile LONG64 ConcealBitmap[HV_ROOT_SEAL_WORDS];
    volatile LONG64 SealedBitmap[HV_ROOT_SEAL_WORDS];
    volatile LONG64 StoppingBitmap[HV_ROOT_SEAL_WORDS];
    volatile LONG64 StoppedBitmap[HV_ROOT_SEAL_WORDS];
    UINT64          CapabilityLow;
    UINT64          CapabilityHigh;
    UINT64          Epoch;
    UINT64          ExpectedSequence;
    UINT64          CompletedCommands;
    VIRTUAL_MACHINE_STATE * VcpuBase;
    UINT32          ProcessorCount;
    HV_PROCESSOR_TOPOLOGY_ENTRY Topology[MAX_PROCESSORS];
    HV_CAPABILITY_RECORD Capabilities;
    volatile LONG   ConcealManifestReady;
    PVOID           ConcealManifest;
    UINT32          ConcealRangeCount;
    UINT64          ConcealGeneration;
    UINT64          ConcealDummyPa;
} HV_ROOT_TRANSPORT_STATE;

typedef union _HV_ROOT_TRANSPORT_STORAGE {
    HV_ROOT_TRANSPORT_STATE State;
    UCHAR                   Page[PAGE_SIZE];
} HV_ROOT_TRANSPORT_STORAGE;

typedef union _HV_ROOT_RESPONSE {
    HV_ROOT_TRANSPORT_STATUS_V1 Transport;
    HV_STATUS_VCPU_V1           Vcpu;
} HV_ROOT_RESPONSE;

C_ASSERT(sizeof(HV_ROOT_COMMAND_PAGE_V1) == PAGE_SIZE);
C_ASSERT(FIELD_OFFSET(HV_ROOT_COMMAND_PAGE_V1, Payload) ==
         HV_ROOT_COMMAND_HEADER_BYTES);
C_ASSERT(sizeof(HV_ROOT_TRANSPORT_STORAGE) == PAGE_SIZE);
C_ASSERT(sizeof(HV_ROOT_TRANSPORT_STATUS_V1) == 64);

#pragma section(".hvshare", read, write)
__declspec(allocate(".hvshare")) DECLSPEC_ALIGN(PAGE_SIZE)
volatile HV_ROOT_COMMAND_PAGE_V1 g_root_command_page = {0};

#pragma section(".hvroot", read, write)
__declspec(allocate(".hvroot")) DECLSPEC_ALIGN(PAGE_SIZE)
static HV_ROOT_TRANSPORT_STORAGE g_root_transport_storage = {0};

static HV_ROOT_TRANSPORT_STATE *
root_transport_state(VOID)
{
    return &g_root_transport_storage.State;
}

static LONG
root_transport_phase(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(&state->Phase, 0, 0);
}

static BOOLEAN
root_transport_authorized(UINT64 capability_low, UINT64 capability_high)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT64 difference =
        (capability_low ^ state->CapabilityLow) |
        (capability_high ^ state->CapabilityHigh);

    return difference == 0 &&
           (capability_low || capability_high);
}

static BOOLEAN
root_transport_vcpu_index(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT32 * index)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT_PTR base;
    UINT_PTR address;
    SIZE_T bytes;
    SIZE_T offset;

    if (!vcpu || !index ||
        InterlockedCompareExchange(&state->MetadataReady, 0, 0) == 0 ||
        !state->VcpuBase || !state->ProcessorCount)
        return FALSE;
    if (state->ProcessorCount >
        MAXULONG_PTR / sizeof(VIRTUAL_MACHINE_STATE))
        return FALSE;
    base = (UINT_PTR)state->VcpuBase;
    address = (UINT_PTR)vcpu;
    bytes = (SIZE_T)state->ProcessorCount *
        sizeof(VIRTUAL_MACHINE_STATE);
    if (address < base || address - base >= bytes)
        return FALSE;
    offset = (SIZE_T)(address - base);
    if (offset % sizeof(VIRTUAL_MACHINE_STATE) != 0)
        return FALSE;
    offset /= sizeof(VIRTUAL_MACHINE_STATE);
    if (offset >= HV_STATUS_MAX_VCPUS)
        return FALSE;
    *index = (UINT32)offset;
    return TRUE;
}

static VOID
root_transport_fill_vcpu(
    HV_STATUS_VCPU_V1 * out,
    UINT32 index)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    VIRTUAL_MACHINE_STATE * vcpu = &state->VcpuBase[index];

    RtlZeroMemory(out, sizeof(*out));
    out->Size = sizeof(*out);
    out->Index = index;
    out->Group = state->Topology[index].Processor.Group;
    out->Number = state->Topology[index].Processor.Number;
    out->LastExitReason = vcpu->exit_reason;
    out->LastExitQualification = vcpu->exit_qual;
    out->LastFailure = vcpu->last_failure;
    out->LastVmInstructionError = vcpu->last_vm_instruction_error;
    out->TotalExits = vcpu->total_exits;
    out->CpuidExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_CPUID];
    out->EptViolationExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EPT_VIOLATION];
    out->MonitorTrapExits =
        vcpu->exit_counters[VMX_EXIT_REASON_MONITOR_TRAP_FLAG];
    out->RdtscExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDTSC];
    out->RdtscpExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDTSCP];
    out->VmcallExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_VMCALL];
    out->MsrReadExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDMSR];
    out->MsrWriteExits =
        vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_WRMSR];

    if (vcpu->launched)
        out->StateFlags |= HV_VCPU_LAUNCHED;
    if (vcpu->detached)
        out->StateFlags |= HV_VCPU_DETACHED;
    if (vcpu->failed)
        out->StateFlags |= HV_VCPU_FAILED;
    if (vcpu->terminal)
        out->StateFlags |= HV_VCPU_TERMINAL;
}

static VOID
root_transport_fill_status(HV_ROOT_TRANSPORT_STATUS_V1 * out)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    RtlZeroMemory(out, sizeof(*out));
    out->Size = sizeof(*out);
    out->Version = HV_ROOT_TRANSPORT_VERSION_1;
    out->Phase = (UINT32)root_transport_phase();
    out->ProcessorCount = state->ProcessorCount;
    out->SealedProcessors =
        (UINT32)InterlockedCompareExchange(&state->SealedCount, 0, 0);
    out->LastFailure =
        (UINT32)InterlockedCompareExchange(&state->LastFailure, 0, 0);
    out->Flags = state->Capabilities.CapabilityFlags;
    out->Epoch = state->Epoch;
    out->ExpectedSequence = state->ExpectedSequence;
    out->CompletedCommands = state->CompletedCommands;
}

static VOID
root_transport_complete(
    UINT32 command,
    UINT64 sequence,
    UINT64 epoch,
    NTSTATUS status,
    const VOID * response,
    UINT32 response_bytes)
{
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT64 mac_low = 0;
    UINT64 mac_high = 0;

    RtlSecureZeroMemory((PVOID)page->Payload, sizeof(page->Payload));
    if (response && response_bytes)
        RtlCopyMemory((PVOID)page->Payload, response, response_bytes);
    page->ResponseBytes = response_bytes;
    page->Status = (UINT32)status;
    hv_transport_mac_response(
        state->CapabilityLow,
        state->CapabilityHigh,
        command,
        epoch,
        sequence,
        (UINT32)status,
        response_bytes,
        response,
        &mac_low,
        &mac_high);
    page->RecordMacLow = mac_low;
    page->RecordMacHigh = mac_high;
    MemoryBarrier();
    InterlockedExchange((volatile LONG *)&page->State,
                        HV_ROOT_STATE_COMPLETE);
}

NTSTATUS
root_transport_prepare(VOID)
{
#if OPHION_PRODUCTION
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    RtlZeroMemory(&g_root_transport_storage,
                  sizeof(g_root_transport_storage));
    RtlZeroMemory((PVOID)page, sizeof(*page));
    page->Magic = HV_ROOT_COMMAND_MAGIC;
    page->Version = HV_ROOT_COMMAND_VERSION_1;
    page->HeaderBytes = HV_ROOT_COMMAND_HEADER_BYTES;
    page->PageBytes = HV_ROOT_COMMAND_PAGE_BYTES;
    page->Status = (UINT32)STATUS_PENDING;
    MemoryBarrier();
    InterlockedExchange(
        &state->Phase, HV_ROOT_PHASE_INITIALIZING);
    InterlockedExchange((volatile LONG *)&page->State,
                        HV_ROOT_STATE_IDLE);
    return STATUS_SUCCESS;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

BOOLEAN
root_transport_mark_awaiting_bootstrap(VOID)
{
#if OPHION_PRODUCTION
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    if (root_transport_phase() != HV_ROOT_PHASE_INITIALIZING)
        return FALSE;

    RtlZeroMemory((PVOID)page, sizeof(*page));
    page->Magic = HV_ROOT_COMMAND_MAGIC;
    page->Version = HV_ROOT_COMMAND_VERSION_1;
    page->HeaderBytes = HV_ROOT_COMMAND_HEADER_BYTES;
    page->PageBytes = HV_ROOT_COMMAND_PAGE_BYTES;
    page->Status = (UINT32)STATUS_PENDING;
    MemoryBarrier();
    InterlockedExchange(
        &state->Phase,
        HV_ROOT_PHASE_AWAITING_BOOTSTRAP);
    InterlockedExchange(
        (volatile LONG *)&page->State,
        HV_ROOT_STATE_IDLE);
    return TRUE;
#else
    return TRUE;
#endif
}

BOOLEAN
root_transport_conceal_ack(
    VIRTUAL_MACHINE_STATE * vcpu)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT32 index;
    UINT32 word;
    LONG64 mask;
    LONG64 previous;
    LONG count;

    if ((root_transport_phase() !=
            HV_ROOT_PHASE_AWAITING_BOOTSTRAP &&
         root_transport_phase() !=
            HV_ROOT_PHASE_PREPARED) ||
        !root_transport_vcpu_index(vcpu, &index))
        return FALSE;

    word = index / 64;
    mask = (LONG64)(1ULL << (index % 64));
    previous = InterlockedOr64(
        &state->ConcealBitmap[word], mask);
    if (!(previous & mask))
    {
        count = InterlockedIncrement(&state->ConcealCount);
        if ((UINT32)count == state->ProcessorCount)
            InterlockedExchange(&state->ConcealReady, 1);
    }
    return TRUE;
#else
    UNREFERENCED_PARAMETER(vcpu);
    return TRUE;
#endif
}

NTSTATUS
root_transport_bootstrap(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch)
{
#if OPHION_PRODUCTION
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    HV_ROOT_BOOTSTRAP_V1 bootstrap = {0};
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UINT64 difference;

    if (!vcpu || !vcpu->launched ||
        (!capability_low && !capability_high) ||
        !epoch ||
        root_transport_phase() !=
            HV_ROOT_PHASE_AWAITING_BOOTSTRAP)
        return STATUS_DEVICE_NOT_READY;
    if (InterlockedCompareExchange(&state->InFlight, 1, 0) != 0)
        return STATUS_DEVICE_BUSY;

    if (InterlockedCompareExchange(
            (volatile LONG *)&page->State,
            HV_ROOT_STATE_BUSY,
            HV_ROOT_STATE_WRITING) != HV_ROOT_STATE_WRITING)
    {
        status = STATUS_DEVICE_BUSY;
        goto Release;
    }

    MemoryBarrier();
    if (page->Magic != HV_ROOT_COMMAND_MAGIC ||
        page->Version != HV_ROOT_COMMAND_VERSION_1 ||
        page->HeaderBytes != HV_ROOT_COMMAND_HEADER_BYTES ||
        page->PageBytes != HV_ROOT_COMMAND_PAGE_BYTES ||
        page->Command != 0 ||
        page->Sequence != 0 ||
        page->RequestBytes != sizeof(bootstrap) ||
        page->Epoch != epoch ||
        page->RecordMacLow != 0 ||
        page->RecordMacHigh != 0)
        goto Complete;

    RtlCopyMemory(
        &bootstrap,
        (const VOID *)page->Payload,
        sizeof(bootstrap));
    MemoryBarrier();
    difference =
        (bootstrap.CapabilityLow ^ capability_low) |
        (bootstrap.CapabilityHigh ^ capability_high);
    if (difference != 0)
        goto Complete;

    state->CapabilityLow = capability_low;
    state->CapabilityHigh = capability_high;
    state->Epoch = epoch;
    state->ExpectedSequence = 1;
    state->CompletedCommands = 0;
    status = STATUS_SUCCESS;

Complete:
    (VOID)RtlSecureZeroMemory(&bootstrap, sizeof(bootstrap));
    (VOID)RtlSecureZeroMemory(
        (PVOID)page->Payload,
        sizeof(page->Payload));
    page->Command = 0;
    page->Sequence = 0;
    page->RequestBytes = 0;
    page->ResponseCapacity = 0;
    page->ResponseBytes = 0;
    page->Status = (UINT32)status;
    page->Epoch = status == STATUS_SUCCESS ? epoch : 0;
    page->RecordMacLow = 0;
    page->RecordMacHigh = 0;
    MemoryBarrier();
    if (status == STATUS_SUCCESS)
    {
        InterlockedExchange(
            &state->Phase, HV_ROOT_PHASE_PREPARED);
        InterlockedExchange(
            (volatile LONG *)&page->State,
            HV_ROOT_STATE_IDLE);
    }
    else
    {
        InterlockedExchange(
            (volatile LONG *)&page->State,
            HV_ROOT_STATE_COMPLETE);
    }

Release:
    InterlockedExchange(&state->InFlight, 0);
    return status;
#else
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(capability_low);
    UNREFERENCED_PARAMETER(capability_high);
    UNREFERENCED_PARAMETER(epoch);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
root_transport_destroy(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    if (InterlockedCompareExchange(&state->InFlight, 0, 0) != 0)
    {
        root_transport_mark_failed(HV_FAILURE_UNKNOWN_EXIT);
        return;
    }
    if (root_transport_phase() != HV_ROOT_PHASE_STOPPED &&
        root_transport_phase() != HV_ROOT_PHASE_INITIALIZING &&
        root_transport_phase() != HV_ROOT_PHASE_FAILED)
    {
        root_transport_mark_failed(HV_FAILURE_UNKNOWN_EXIT);
        return;
    }
    (VOID)RtlSecureZeroMemory(&g_root_transport_storage,
                             sizeof(g_root_transport_storage));
    (VOID)RtlSecureZeroMemory((PVOID)&g_root_command_page,
                             sizeof(g_root_command_page));
}

VOID
root_transport_mark_failed(UINT32 failure)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    InterlockedExchange(&state->LastFailure, (LONG)failure);
    InterlockedExchange(&state->Phase, HV_ROOT_PHASE_FAILED);
}

VOID
root_transport_publish_failure(UINT32 failure)
{
#if OPHION_PRODUCTION
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    HV_ROOT_TRANSPORT_STATUS_V1 response;

    root_transport_mark_failed(failure);
    root_transport_fill_status(&response);
    if (state->CapabilityLow || state->CapabilityHigh)
    {
        root_transport_complete(
            0,
            0,
            state->Epoch,
            STATUS_HV_OPERATION_FAILED,
            &response,
            sizeof(response));
    }
    else
    {
        RtlCopyMemory(
            (PVOID)page->Payload,
            &response,
            sizeof(response));
        page->ResponseBytes = sizeof(response);
        page->Status = (UINT32)STATUS_HV_OPERATION_FAILED;
        page->RecordMacLow = 0;
        page->RecordMacHigh = 0;
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG *)&page->State,
            HV_ROOT_STATE_COMPLETE);
    }
#else
    UNREFERENCED_PARAMETER(failure);
#endif
}

VOID
root_transport_register_conceal(VOID)
{
#if OPHION_PRODUCTION
    if (root_transport_phase() != HV_ROOT_PHASE_EMPTY)
        ept_conceal_register_va(&g_root_transport_storage,
                                sizeof(g_root_transport_storage));
#endif
}

BOOLEAN
root_transport_snapshot_metadata(VOID)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    if (!g_vcpu || !g_cpu_count ||
        g_cpu_count > MAX_PROCESSORS ||
        g_cpu_count > HV_STATUS_MAX_VCPUS)
        return FALSE;

    state->VcpuBase = g_vcpu;
    state->ProcessorCount = g_cpu_count;
    RtlCopyMemory(
        state->Topology,
        g_processor_topology,
        sizeof(HV_PROCESSOR_TOPOLOGY_ENTRY) * g_cpu_count);
    RtlCopyMemory(
        &state->Capabilities,
        &g_hv_capabilities,
        sizeof(state->Capabilities));
    MemoryBarrier();
    InterlockedExchange(&state->MetadataReady, 1);
    return TRUE;
#else
    return TRUE;
#endif
}

VOID
root_transport_release_metadata(VOID)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    InterlockedExchange(&state->MetadataReady, 0);
    MemoryBarrier();
    state->VcpuBase = NULL;
    state->ProcessorCount = 0;
    RtlZeroMemory(state->Topology, sizeof(state->Topology));
    RtlZeroMemory(&state->Capabilities, sizeof(state->Capabilities));
#endif
}

VIRTUAL_MACHINE_STATE *
root_transport_vcpu_base(VOID)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->MetadataReady, 0, 0)
        ? state->VcpuBase
        : NULL;
#else
    return g_vcpu;
#endif
}

UINT32
root_transport_processor_count(VOID)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->MetadataReady, 0, 0)
        ? state->ProcessorCount
        : 0;
#else
    return g_cpu_count;
#endif
}

UINT32
root_transport_physical_address_bits(VOID)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->MetadataReady, 0, 0)
        ? state->Capabilities.PhysicalAddressBits
        : 0;
#else
    return g_hv_capabilities.PhysicalAddressBits;
#endif
}

BOOLEAN
root_transport_set_conceal_manifest(
    PVOID manifest,
    UINT32 range_count,
    UINT64 generation,
    UINT64 dummy_pa)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    if (!manifest || !range_count || !generation || !dummy_pa ||
        InterlockedCompareExchange(
            &state->ConcealManifestReady, 0, 0) != 0)
        return FALSE;
    state->ConcealManifest = manifest;
    state->ConcealRangeCount = range_count;
    state->ConcealGeneration = generation;
    state->ConcealDummyPa = dummy_pa;
    MemoryBarrier();
    InterlockedExchange(&state->ConcealManifestReady, 1);
    return TRUE;
}

BOOLEAN
root_transport_snapshot_conceal(HV_CONCEAL_SNAPSHOT * snapshot)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    if (!snapshot)
        return FALSE;
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    if (InterlockedCompareExchange(
            &state->ConcealManifestReady, 0, 0) == 0)
        return FALSE;
    MemoryBarrier();
    snapshot->Manifest = state->ConcealManifest;
    snapshot->RangeCount = state->ConcealRangeCount;
    snapshot->Generation = state->ConcealGeneration;
    snapshot->DummyPa = state->ConcealDummyPa;
    MemoryBarrier();
    if (InterlockedCompareExchange(
            &state->ConcealManifestReady, 0, 0) == 0)
    {
        RtlZeroMemory(snapshot, sizeof(*snapshot));
        return FALSE;
    }
    return snapshot->Manifest && snapshot->RangeCount &&
           snapshot->Generation && snapshot->DummyPa;
}

PVOID
root_transport_conceal_manifest(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->ConcealManifestReady, 0, 0)
        ? state->ConcealManifest
        : NULL;
}

UINT32
root_transport_conceal_range_count(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->ConcealManifestReady, 0, 0)
        ? state->ConcealRangeCount
        : 0;
}

UINT64
root_transport_conceal_generation(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->ConcealManifestReady, 0, 0)
        ? state->ConcealGeneration
        : 0;
}

UINT64
root_transport_conceal_dummy_pa(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    return InterlockedCompareExchange(
               &state->ConcealManifestReady, 0, 0)
        ? state->ConcealDummyPa
        : 0;
}

VOID
root_transport_release_conceal_manifest(VOID)
{
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();

    InterlockedExchange(&state->ConcealManifestReady, 0);
    MemoryBarrier();
    state->ConcealManifest = NULL;
    state->ConcealRangeCount = 0;
    state->ConcealGeneration = 0;
    state->ConcealDummyPa = 0;
}

BOOLEAN
root_transport_conceal_commit_allowed(VOID)
{
#if OPHION_PRODUCTION
    return root_transport_phase() ==
        HV_ROOT_PHASE_AWAITING_BOOTSTRAP;
#else
    return TRUE;
#endif
}

BOOLEAN
root_transport_legacy_allowed(UINT64 vmcall_number)
{
#if OPHION_PRODUCTION
    LONG phase = root_transport_phase();

    if (phase != HV_ROOT_PHASE_INITIALIZING &&
        phase != HV_ROOT_PHASE_AWAITING_BOOTSTRAP)
        return FALSE;
    return vmcall_number == VMCALL_INVEPT ||
           vmcall_number == VMCALL_PROTECT_REFRESH;
#else
    UNREFERENCED_PARAMETER(vmcall_number);
    return TRUE;
#endif
}

BOOLEAN
root_transport_initializing_rollback_allowed(VOID)
{
#if OPHION_PRODUCTION
    LONG phase = root_transport_phase();
    return phase == HV_ROOT_PHASE_INITIALIZING ||
           phase == HV_ROOT_PHASE_AWAITING_BOOTSTRAP;
#else
    return TRUE;
#endif
}

NTSTATUS
root_transport_seal_step(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT32 index;
    UINT32 word;
    LONG64 mask;
    LONG64 previous;
    LONG sealed;
    LONG phase;

    if (!root_transport_authorized(capability_low, capability_high))
        return STATUS_ACCESS_DENIED;

    phase = root_transport_phase();
    if (phase != HV_ROOT_PHASE_PREPARED &&
        phase != HV_ROOT_PHASE_ACTIVE)
        return STATUS_DEVICE_NOT_READY;
    if (epoch != state->Epoch || !vcpu || !vcpu->launched)
        return STATUS_INVALID_PARAMETER;

    if (!root_transport_vcpu_index(vcpu, &index))
        return STATUS_INVALID_PARAMETER;
    if (phase == HV_ROOT_PHASE_ACTIVE)
        return STATUS_SUCCESS;

    /*
     * Commit self-concealment from the external all-core seal thunk, after
     * DriverEntry and vmx_init returned outside the mapped image.  An in-image
     * DPC would make its own post-VMCALL return path non-executable.
     */
    if (!ept_conceal_commit_local(vcpu) ||
        !root_transport_conceal_ack(vcpu))
    {
        root_transport_mark_failed(
            HV_FAILURE_EPT_MISCONFIGURATION);
        return STATUS_HV_OPERATION_FAILED;
    }

    word = index / 64;
    mask = (LONG64)(1ULL << (index % 64));
    previous = InterlockedOr64(&state->SealedBitmap[word], mask);
    if (!(previous & mask))
    {
        sealed = InterlockedIncrement(&state->SealedCount);
        if ((UINT32)sealed == state->ProcessorCount &&
            InterlockedCompareExchange(
                &state->ConcealReady, 0, 0) != 0)
            InterlockedExchange(&state->Phase, HV_ROOT_PHASE_ACTIVE);
    }

    return root_transport_phase() == HV_ROOT_PHASE_ACTIVE
        ? STATUS_SUCCESS
        : STATUS_MORE_ENTRIES;
#else
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(capability_low);
    UNREFERENCED_PARAMETER(capability_high);
    UNREFERENCED_PARAMETER(epoch);
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS
root_transport_command(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 sequence)
{
#if OPHION_PRODUCTION
    volatile HV_ROOT_COMMAND_PAGE_V1 * page = &g_root_command_page;
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UCHAR request[HV_ROOT_REQUEST_MAX] = {0};
    HV_ROOT_RESPONSE response;
    UINT32 request_bytes;
    UINT32 response_capacity;
    UINT32 command;
    UINT32 response_bytes = 0;
    UINT64 record_sequence;
    UINT64 record_epoch;
    UINT64 record_mac_low;
    UINT64 record_mac_high;
    UINT64 expected_mac_low = 0;
    UINT64 expected_mac_high = 0;
    UINT64 mac_difference;
    UINT64 magic;
    UINT16 version;
    UINT16 header_bytes;
    UINT32 page_bytes;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(vcpu);

    if (!root_transport_authorized(capability_low, capability_high))
        return STATUS_ACCESS_DENIED;
    if (root_transport_phase() != HV_ROOT_PHASE_ACTIVE)
        return STATUS_DEVICE_NOT_READY;
    if (InterlockedCompareExchange(&state->InFlight, 1, 0) != 0)
        return STATUS_DEVICE_BUSY;

    if (InterlockedCompareExchange(
            (volatile LONG *)&page->State,
            HV_ROOT_STATE_BUSY,
            HV_ROOT_STATE_READY) != HV_ROOT_STATE_READY)
    {
        status = STATUS_DEVICE_BUSY;
        goto Release;
    }

    MemoryBarrier();
    request_bytes = page->RequestBytes;
    response_capacity = page->ResponseCapacity;
    command = page->Command;
    record_sequence = page->Sequence;
    record_epoch = page->Epoch;
    record_mac_low = page->RecordMacLow;
    record_mac_high = page->RecordMacHigh;
    magic = page->Magic;
    version = page->Version;
    header_bytes = page->HeaderBytes;
    page_bytes = page->PageBytes;

    if (magic != HV_ROOT_COMMAND_MAGIC ||
        version != HV_ROOT_COMMAND_VERSION_1 ||
        header_bytes != HV_ROOT_COMMAND_HEADER_BYTES ||
        page_bytes != HV_ROOT_COMMAND_PAGE_BYTES ||
        request_bytes > sizeof(request) ||
        response_capacity > sizeof(page->Payload) ||
        sequence != state->ExpectedSequence ||
        record_sequence != sequence ||
        record_epoch != state->Epoch)
    {
        status = STATUS_INVALID_PARAMETER;
        root_transport_complete(
            command, sequence, state->Epoch,
            status, NULL, 0);
        goto Release;
    }

    if (request_bytes)
        RtlCopyMemory(request, (const VOID *)page->Payload,
                      request_bytes);
    MemoryBarrier();
    hv_transport_mac_request(
        state->CapabilityLow,
        state->CapabilityHigh,
        command,
        record_epoch,
        record_sequence,
        request_bytes,
        response_capacity,
        request,
        &expected_mac_low,
        &expected_mac_high);
    mac_difference =
        (record_mac_low ^ expected_mac_low) |
        (record_mac_high ^ expected_mac_high);
    if (mac_difference != 0)
    {
        status = STATUS_DATA_ERROR;
        root_transport_complete(
            command, record_sequence, record_epoch,
            status, NULL, 0);
        goto Release;
    }

    if (state->ExpectedSequence == MAXULONG64)
    {
        status = STATUS_INTEGER_OVERFLOW;
        root_transport_mark_failed(HV_FAILURE_UNKNOWN_EXIT);
        root_transport_complete(
            command, record_sequence, record_epoch,
            status, NULL, 0);
        goto Release;
    }
    state->ExpectedSequence++;
    state->CompletedCommands++;
    RtlZeroMemory(&response, sizeof(response));

    switch (command)
    {
    case HV_ROOT_COMMAND_QUERY_TRANSPORT:
        if (request_bytes != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        root_transport_fill_status(&response.Transport);
        response_bytes = sizeof(response.Transport);
        break;

    case HV_ROOT_COMMAND_QUERY_VCPU:
    {
        HV_ROOT_QUERY_VCPU_V1 query;

        if (request_bytes != sizeof(query))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RtlCopyMemory(&query, request, sizeof(query));
        if (query.Size != sizeof(query) ||
            query.Index >= state->ProcessorCount ||
            query.Index >= HV_STATUS_MAX_VCPUS)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        root_transport_fill_vcpu(&response.Vcpu, query.Index);
        response_bytes = sizeof(response.Vcpu);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    if (response_bytes > response_capacity)
    {
        status = STATUS_BUFFER_TOO_SMALL;
        response_bytes = 0;
    }
    root_transport_complete(
        command,
        record_sequence,
        record_epoch,
        status,
        response_bytes ? &response : NULL,
        response_bytes);

Release:
    InterlockedExchange(&state->InFlight, 0);
    return status;
#else
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(capability_low);
    UNREFERENCED_PARAMETER(capability_high);
    UNREFERENCED_PARAMETER(sequence);
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS
root_transport_stop_begin(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT32 index;
    UINT32 word;
    LONG64 mask;
    LONG phase;

    if (!root_transport_authorized(capability_low, capability_high))
        return STATUS_ACCESS_DENIED;

    phase = root_transport_phase();
    if (phase != HV_ROOT_PHASE_PREPARED &&
        phase != HV_ROOT_PHASE_ACTIVE &&
        phase != HV_ROOT_PHASE_FAILED &&
        phase != HV_ROOT_PHASE_STOPPING)
        return STATUS_DEVICE_NOT_READY;
    if (!vcpu || epoch != state->Epoch)
        return STATUS_INVALID_PARAMETER;

    if (!root_transport_vcpu_index(vcpu, &index))
        return STATUS_INVALID_PARAMETER;
    word = index / 64;
    mask = (LONG64)(1ULL << (index % 64));

    if (InterlockedOr64(&state->StoppedBitmap[word], 0) & mask)
        return STATUS_SUCCESS;
    if (InterlockedOr64(&state->StoppingBitmap[word], mask) & mask)
        return STATUS_DEVICE_BUSY;

    InterlockedExchange(&state->Phase, HV_ROOT_PHASE_STOPPING);
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(capability_low);
    UNREFERENCED_PARAMETER(capability_high);
    UNREFERENCED_PARAMETER(epoch);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
root_transport_stop_complete(
    VIRTUAL_MACHINE_STATE * vcpu,
    BOOLEAN success)
{
#if OPHION_PRODUCTION
    HV_ROOT_TRANSPORT_STATE * state = root_transport_state();
    UINT32 index;
    UINT32 word;
    LONG64 mask;
    LONG64 previous;
    LONG stopped;

    if (!vcpu)
        return;
    if (!root_transport_vcpu_index(vcpu, &index))
        return;
    word = index / 64;
    mask = (LONG64)(1ULL << (index % 64));
    InterlockedAnd64(&state->StoppingBitmap[word], ~mask);

    if (!success)
    {
        InterlockedExchange(
            &state->LastFailure, HV_FAILURE_VM_ENTRY);
        InterlockedExchange(&state->Phase, HV_ROOT_PHASE_FAILED);
        return;
    }

    InterlockedAnd64(&state->SealedBitmap[word], ~mask);
    previous = InterlockedOr64(&state->StoppedBitmap[word], mask);
    if (!(previous & mask))
    {
        stopped = InterlockedIncrement(&state->StopCount);
        if ((UINT32)stopped == state->ProcessorCount)
            InterlockedExchange(
                &state->Phase, HV_ROOT_PHASE_STOPPED);
    }
#else
    UNREFERENCED_PARAMETER(vcpu);
    UNREFERENCED_PARAMETER(success);
#endif
}
