/*
*   driver.c - windows kernel driver entry point for the hypervisor
*   creates a device object, symbolic link, and initializes vmx
*   provides ioctl interface for usermode loader communication
*
*   production builds create no device object, no symbolic link, and no
*   dispatch table: nothing for module/device enumeration to fingerprint.
*/
#include "hv.h"
#include <wdmsec.h>
#pragma comment(lib, "Wdmsec.lib")

static const GUID GUID_DEVCLASS_OPHION_CONTROL =
    {0x9772eb3e,0x6371,0x42f1,{0xa9,0x0b,0x8e,0x81,0x9d,0xa8,0x15,0xd4}};
static const WCHAR OPHION_CONTROL_SDDL[] =
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";


#if !OPHION_PRODUCTION

#define DEVICE_NAME     L"\\Device\\Ophion"
#define SYMLINK_NAME    L"\\DosDevices\\Ophion"


static NTSTATUS DriverCreateClose(PDEVICE_OBJECT device_obj, PIRP irp);
static NTSTATUS DriverIoControl(PDEVICE_OBJECT device_obj, PIRP irp);

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNICODE_STRING symlink;

    HV_LOG(0, 0, "[hv] Unloading hypervisor driver...\n");

    broadcast_terminate_all();
    vmx_terminate();

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);

    if (driver_obj->DeviceObject)
    {
        IoDeleteDevice(driver_obj->DeviceObject);
    }

    HV_LOG(0, 0, "[hv] Driver unloaded.\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS       status;
    PDEVICE_OBJECT device_obj = NULL;
    UNICODE_STRING device_name;
    UNICODE_STRING symlink;
    UNICODE_STRING sddl;

    UNREFERENCED_PARAMETER(registry_path);

    HV_LOG(0, 0, "[hv] Ophion initializing...\n");

    RtlInitUnicodeString(&device_name, DEVICE_NAME);
    RtlInitUnicodeString(&sddl, OPHION_CONTROL_SDDL);
    status = IoCreateDeviceSecure(
        driver_obj,
        0,
        &device_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        &GUID_DEVCLASS_OPHION_CONTROL,
        &device_obj);

    if (!NT_SUCCESS(status))
    {
        HV_LOG(0, 0, "[hv] IoCreateDeviceSecure failed: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&symlink, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &device_name);

    if (!NT_SUCCESS(status))
    {
        HV_LOG(0, 0, "[hv] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(device_obj);
        return status;
    }

#if OPHION_ALLOW_UNLOAD
    driver_obj->DriverUnload = DriverUnload;
#else
    driver_obj->DriverUnload = NULL;
#endif
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = DriverCreateClose;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

    if (!vmx_init())
    {
        HV_LOG(0, 0, "[hv] VMX initialization FAILED!\n");
        if (!vmx_all_stopped())
        {
            /*
            * Returning failure would unload this image while a vCPU may
            * still own VMX/root resources.  Stay resident and expose the
            * failure through IOCTL_HV_STATUS instead.
            */
            driver_obj->DriverUnload = NULL;
            device_obj->Flags &= ~DO_DEVICE_INITIALIZING;
            return STATUS_SUCCESS;
        }
        vmx_terminate();
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(device_obj);
        return STATUS_HV_OPERATION_FAILED;
    }

    tracewipe_apply(driver_obj, TRUE);
    device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    HV_LOG(0, 0, "[hv] Hypervisor loaded and active on all cores!\n");
    return STATUS_SUCCESS;
}

static NTSTATUS
DriverCreateClose(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID
DriverFillStatusV1(HV_STATUS_V1 * status)
{
    RtlZeroMemory(status, sizeof(*status));
    status->Size = sizeof(*status);
    status->Version = HV_STATUS_VERSION_1;
    status->HeaderSize = FIELD_OFFSET(HV_STATUS_V1, Vcpu);
    status->TotalProcessors = g_cpu_count;
    status->ParentFlags = g_hv_capabilities.ParentFlags;
    status->ParentFeatures = g_hv_capabilities.ParentFeatures;
    status->CapabilityFlags = g_hv_capabilities.CapabilityFlags;
    status->PreflightFailure = g_hv_capabilities.Failure;
    status->PhysicalAddressBits = g_hv_capabilities.PhysicalAddressBits;
    if (g_vmxoff_nmi_deferred)
        status->Flags |= HV_STATUS_FLAG_VMXOFF_NMI_DEFERRED;
    status->MaximumGuestPhysicalAddress =
        g_hv_capabilities.MaximumGuestPhysicalAddress;
    RtlCopyMemory(status->ParentVendor, g_hv_capabilities.ParentVendor,
                  sizeof(status->ParentVendor));

    for (UINT32 i = 0; i < g_cpu_count && i < HV_STATUS_MAX_VCPUS; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];
        HV_STATUS_VCPU_V1 * out = &status->Vcpu[i];

        out->Size = sizeof(*out);
        out->Index = i;
        out->Group = g_processor_topology[i].Processor.Group;
        out->Number = g_processor_topology[i].Processor.Number;
        out->LastExitReason = vcpu->exit_reason;
        out->LastExitQualification = vcpu->exit_qual;
        out->LastFailure = vcpu->last_failure;
        out->LastVmInstructionError = vcpu->last_vm_instruction_error;
        out->TotalExits = vcpu->total_exits;
        out->CpuidExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_CPUID];
        out->EptViolationExits = vcpu->exit_counters[VMX_EXIT_REASON_EPT_VIOLATION];
        out->MonitorTrapExits = vcpu->exit_counters[VMX_EXIT_REASON_MONITOR_TRAP_FLAG];
        out->RdtscExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDTSC];
        out->RdtscpExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDTSCP];
        out->VmcallExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_VMCALL];
        out->MsrReadExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_RDMSR];
        out->MsrWriteExits = vcpu->exit_counters[VMX_EXIT_REASON_EXECUTE_WRMSR];

        if (vcpu->launched) {
            out->StateFlags |= HV_VCPU_LAUNCHED;
            status->LaunchedProcessors++;
        }
        if (vcpu->detached) {
            out->StateFlags |= HV_VCPU_DETACHED;
            status->DetachedProcessors++;
        }
        if (vcpu->failed) {
            out->StateFlags |= HV_VCPU_FAILED;
            status->FailedProcessors++;
        }
        if (vcpu->terminal) {
            out->StateFlags |= HV_VCPU_TERMINAL;
            status->TerminalProcessors++;
        }
        if (vcpu->last_failure)
            status->LastFailure = vcpu->last_failure;
        if (vcpu->last_vm_instruction_error)
            status->LastVmInstructionError = vcpu->last_vm_instruction_error;

        for (UINT32 reason = 0;
             reason < HV_STATUS_EXIT_REASON_COUNT;
             reason++)
            status->AggregateExitCounters[reason] +=
                vcpu->exit_counters[reason];
    }
}

static NTSTATUS
DriverIoControl(
    _In_ PDEVICE_OBJECT device_obj,
    _In_ PIRP           irp)
{
    NTSTATUS           status = STATUS_SUCCESS;
    PIO_STACK_LOCATION io_stack;
    ULONG              ioctl_code;

    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Information = 0;
    io_stack       = IoGetCurrentIrpStackLocation(irp);
    ioctl_code = io_stack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioctl_code)
    {
    case IOCTL_HV_STATUS:
    {
        ULONG output_length =
            io_stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (output_length >= sizeof(HV_STATUS_V1))
        {
            DriverFillStatusV1(
                (HV_STATUS_V1 *)irp->AssociatedIrp.SystemBuffer);
            irp->IoStatus.Information = sizeof(HV_STATUS_V1);
        }
        else if (output_length >= sizeof(UINT32))
        {
            *(UINT32 *)irp->AssociatedIrp.SystemBuffer = g_cpu_count;
            irp->IoStatus.Information = sizeof(UINT32);
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    }

    case IOCTL_HV_CONCEAL_BYOVD:
    {
        status = byovd_handle_ioctl(irp, io_stack);
        break;
    }

    case IOCTL_HV_EAC_STEALTH:
    {
        ULONG in_len  = io_stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io_stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG action  = (in_len >= sizeof(ULONG))
                        ? *(ULONG *)irp->AssociatedIrp.SystemBuffer : 0;

        if (action == HV_EAC_ACTION_SCRUB)
        {
#if STEALTH_EAC_STACK_SCRUB
            eac_stack_scrub();
            status = STATUS_SUCCESS;
#else
            status = STATUS_NOT_SUPPORTED;
#endif
        }
        else if (action == HV_EAC_ACTION_QUERY && out_len >= 4 * sizeof(ULONG))
        {
            ULONG * out = (ULONG *)irp->AssociatedIrp.SystemBuffer;
            eac_stealth_query(&out[0], &out[1]);
            irp->IoStatus.Information = 4 * sizeof(ULONG);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    }

    case IOCTL_HV_PROTECT_RANGE:
    {
        status = protect_handle_ioctl(irp, io_stack);
        break;
    }

    case IOCTL_HV_PROTECT_STATUS:
    {
        ULONG out_len =
            io_stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (out_len < sizeof(HV_PROTECT_STATUS_V1))
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            protect_query_status(
                (HV_PROTECT_STATUS_V1 *)irp->AssociatedIrp.SystemBuffer);
            irp->IoStatus.Information =
                sizeof(HV_PROTECT_STATUS_V1);
            status = STATUS_SUCCESS;
        }
        break;
    }



    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

#else // OPHION_PRODUCTION

//
// production entry: virtualize and leave. no device object, no symlink, no
// dispatch table — module/device/service enumerators see nothing to query.
// teardown for a mapped image is driven by VMCALL_VMXOFF per core.
//
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(registry_path);

    status = root_transport_prepare();
    if (!NT_SUCCESS(status))
        return status;

    if (!vmx_init())
    {
        if (!vmx_all_stopped())
        {
            /* Pin the image rather than unload code still owned by VMX. */
            root_transport_publish_failure(
                g_hv_capabilities.Failure
                    ? g_hv_capabilities.Failure
                    : HV_FAILURE_VM_ENTRY);
            return STATUS_SUCCESS;
        }
        vmx_terminate();
        root_transport_destroy();
        return STATUS_HV_OPERATION_FAILED;
    }

    tracewipe_apply(driver_obj, FALSE);
    return STATUS_SUCCESS;
}

__declspec(dllexport)
NTSTATUS
NTAPI
OphionCleanup(VOID)
{
    if (!vmx_all_stopped())
        return STATUS_DEVICE_BUSY;

    vmx_terminate();
    root_transport_destroy();
    return STATUS_SUCCESS;
}

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNREFERENCED_PARAMETER(driver_obj);

    (VOID)OphionCleanup();
}

#endif // OPHION_PRODUCTION
