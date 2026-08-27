/*
*   broadcast.c - dpc-based broadcast for multi-processor vmx operations
*   uses KeGenericCallDpc to execute code on all logical processors
*/
#include "hv.h"

// KeGenericCallDpc, KeSignalCallDpcDone, KeSignalCallDpcSynchronize
// are not in the standard wdk headers
NTKERNELAPI
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID          Context);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1);

NTKERNELAPI
_IRQL_requires_(DISPATCH_LEVEL)
_IRQL_requires_same_
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2);

typedef struct _HV_TERMINATE_CONTEXT {
    BOOLEAN AllCoresLaunched;
} HV_TERMINATE_CONTEXT;

typedef struct _HV_BROADCAST_RESULT {
    volatile LONG Failures;
} HV_BROADCAST_RESULT;

#if USE_PRIVATE_HOST_GDT
static VOID
dpc_prepare_host_state(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    HV_BROADCAST_RESULT * result =
        (HV_BROADCAST_RESULT *)DeferredContext;
    PROCESSOR_NUMBER processor;
    UINT32 core;

    UNREFERENCED_PARAMETER(Dpc);

    KeGetCurrentProcessorNumberEx(&processor);
    core = vmx_topology_index(&processor);
    if (!g_vcpu || core >= g_cpu_count ||
        !hostgdt_build_for_vcpu(&g_vcpu[core]))
    {
        if (result)
            InterlockedIncrement(&result->Failures);
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}
#endif

static VOID
dpc_init_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    // saves gprs + rflags, calls vmx_virtualize_cpu(rsp)
    // on successful vmlaunch, returns via asm_vmx_restore_state
    asm_vmx_save_state();

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
dpc_terminate_guest(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    HV_TERMINATE_CONTEXT * context =
        (HV_TERMINATE_CONTEXT *)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);

#if OPHION_PRODUCTION
    if (context)
    {
        BOOLEAN should_stop = context->AllCoresLaunched;

        if (!should_stop)
        {
            PROCESSOR_NUMBER processor;
            UINT32 core;

            KeGetCurrentProcessorNumberEx(&processor);
            core = vmx_topology_index(&processor);
            should_stop =
                g_vcpu && core < g_cpu_count &&
                g_vcpu[core].launched &&
                !g_vcpu[core].detached;
        }
        if (should_stop)
        {
            (VOID)asm_vmx_vmcall(
                VMCALL_INIT_ROLLBACK, 0, 0, 0);
        }
    }
#else
    {
        PROCESSOR_NUMBER processor;
        UINT32 core;

        KeGetCurrentProcessorNumberEx(&processor);
        core = vmx_topology_index(&processor);
        if (g_vcpu && core < g_cpu_count &&
            g_vcpu[core].launched && !g_vcpu[core].detached)
        {
            UNREFERENCED_PARAMETER(context);
            asm_vmx_vmcall(VMCALL_VMXOFF, 0, 0, 0);
        }
    }
#endif

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
dpc_conceal_invept(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    HV_BROADCAST_RESULT * result =
        (HV_BROADCAST_RESULT *)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);

    if (!NT_SUCCESS(asm_vmx_vmcall(
            VMCALL_CONCEAL_COMMIT, 0, 0, 0)) &&
        result)
        InterlockedIncrement(&result->Failures);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static VOID
dpc_protect_refresh(
    _In_ PKDPC  Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    PROCESSOR_NUMBER processor;
    UINT32 core;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    KeGetCurrentProcessorNumberEx(&processor);
    core = vmx_topology_index(&processor);
    if (g_vcpu && core < g_cpu_count &&
        g_vcpu[core].launched && !g_vcpu[core].detached)
    {
        (VOID)asm_vmx_vmcall(
            VMCALL_PROTECT_REFRESH, 0, 0, 0);
    }

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}



VOID
broadcast_virtualize_all(VOID)
{
    KeGenericCallDpc(dpc_init_guest, NULL);
}

BOOLEAN
broadcast_prepare_host_state(VOID)
{
#if USE_PRIVATE_HOST_GDT
    HV_BROADCAST_RESULT result = {0};

    KeGenericCallDpc(dpc_prepare_host_state, &result);
    return InterlockedCompareExchange(
               &result.Failures, 0, 0) == 0;
#else
    return TRUE;
#endif
}

VOID
broadcast_terminate_all(VOID)
{
#if OPHION_PRODUCTION
    broadcast_terminate_initializing(FALSE);
#else
    KeGenericCallDpc(dpc_terminate_guest, NULL);
#endif
}

VOID
broadcast_terminate_initializing(
    BOOLEAN all_cores_launched)
{
    HV_TERMINATE_CONTEXT context;

    context.AllCoresLaunched = all_cores_launched;
    KeGenericCallDpc(dpc_terminate_guest, &context);
}

BOOLEAN
broadcast_conceal_invept(VOID)
{
    HV_BROADCAST_RESULT result = {0};

    KeGenericCallDpc(dpc_conceal_invept, &result);
    return InterlockedCompareExchange(
               &result.Failures, 0, 0) == 0;
}

VOID
broadcast_protect_refresh(VOID)
{
    KeGenericCallDpc(dpc_protect_refresh, NULL);
}
