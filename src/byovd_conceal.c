/*
 * byovd_conceal.c — Post-launch EPT concealment of BYOVD loader driver pages
 *
 * After Ophion is live (HV running on all cores), the BYOVD driver that was
 * used to load us is still present in the guest's physical/virtual address
 * space.  EAC/BE kernel scans walk PsLoadedModuleList and can find it.
 *
 * This module:
 *   1. Receives the BYOVD driver's LDR entry VA from usermode via IOCTL.
 *   2. Registers all physical pages of the BYOVD driver image with the EPT
 *      conceal subsystem (the same one that hides VMXON/VMCS/EPT tables).
 *   3. Applies a conceal pass: those GPA ranges are EPT-remapped to the
 *      shared zero dummy page.  Guest reads see zeroes; execute faults #VE.
 *   4. Optionally wipes the BYOVD driver's LDR entry from PsLoadedModuleList
 *      by locating it via the provided base VA and NULLing the name fields —
 *      this is the same logic as tracewipe.c's wipe_loaded_module but driven
 *      from an IOCTL rather than from DriverEntry.
 *
 * Disabled by default: hiding an active driver image before its unload path
 * executes can fault that path, and unlinking live loader state is not a
 * BSOD-safe operation.  Prefer an already-loaded OEM driver or UEFI bring-up.
 *
 * IOCTL: IOCTL_HV_CONCEAL_BYOVD (defined in hv_public.h)
 *   Input:  HV_CONCEAL_BYOVD_REQUEST
 *   Output: none (STATUS_SUCCESS or error)
 */
#include "hv.h"
#include <aux_klib.h>

#pragma comment(lib, "Aux_Klib.lib")

#ifndef STEALTH_CONCEAL_BYOVD
#define STEALTH_CONCEAL_BYOVD 0
#endif

#if STEALTH_CONCEAL_BYOVD

/*
 * Locate a loaded module by name suffix (basename only) and return its
 * base address and size.  Uses AuxKlibQueryModuleInformation so we do
 * not touch PsLoadedModuleList directly from this path.
 */
static BOOLEAN
byovd_find_module(
    const UNICODE_STRING * name,
    UINT64               * out_base,
    ULONG                * out_size)
{
    ULONG bufSize = 0;
    NTSTATUS st;

    st = AuxKlibQueryModuleInformation(&bufSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (st != STATUS_BUFFER_TOO_SMALL || !bufSize)
        return FALSE;

    PAUX_MODULE_EXTENDED_INFO modules =
        (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(
            NonPagedPool, bufSize, 'DVOB');
    if (!modules)
        return FALSE;

    st = AuxKlibQueryModuleInformation(&bufSize,
                                       sizeof(AUX_MODULE_EXTENDED_INFO),
                                       modules);
    if (!NT_SUCCESS(st))
    {
        ExFreePoolWithTag(modules, 'DVOB');
        return FALSE;
    }

    ULONG count = bufSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    BOOLEAN found = FALSE;

    for (ULONG i = 0; i < count; i++)
    {
        // FullPathName is an ASCII string in AUX_MODULE_EXTENDED_INFO
        CHAR  fullPath[256] = {0};
        ULONG pathLen = (ULONG)strnlen(
            (const char*)modules[i].FullPathName,
            sizeof(modules[i].FullPathName));
        if (pathLen >= sizeof(fullPath))
            pathLen = sizeof(fullPath) - 1;
        RtlCopyMemory(fullPath, modules[i].FullPathName, pathLen);

        // Convert basename to UNICODE for comparison
        const CHAR* lastSlash = fullPath;
        for (ULONG j = 0; j < pathLen; j++)
            if (fullPath[j] == '\\' || fullPath[j] == '/')
                lastSlash = fullPath + j + 1;

        // Convert the caller's UNICODE name to ANSI for comparison
        ANSI_STRING ansiName;
        if (!NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansiName, name, TRUE)))
            continue;

        BOOLEAN match = (_stricmp(lastSlash, ansiName.Buffer) == 0);
        RtlFreeAnsiString(&ansiName);

        if (match)
        {
            *out_base = (UINT64)(ULONG_PTR)modules[i].BasicInfo.ImageBase;
            *out_size = modules[i].ImageSize;
            found = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'DVOB');
    return found;
}

/*
 * Conceal all physical pages belonging to the BYOVD driver image.
 * The immutable production conceal manifest cannot be reopened after launch.
 */
NTSTATUS
byovd_conceal_driver(
    const UNICODE_STRING * driver_name,
    BOOLEAN                wipe_ldr)
{
    UINT64 base = 0;
    ULONG  size = 0;

    if (!byovd_find_module(driver_name, &base, &size))
    {
        HV_LOG(0, 0, "[byovd] module '%wZ' not found in loaded list\n",
               driver_name);
        return STATUS_NOT_FOUND;
    }

    HV_LOG(0, 0, "[byovd] concealing %wZ base=0x%016llX size=0x%X\n",
           driver_name, base, size);

    if (ept_conceal_is_frozen())
    {
        HV_LOG(
            0, 0,
            "[byovd] conceal manifest is sealed; late ranges rejected\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Register the image VA range with the EPT conceal subsystem.
    // ept_conceal_register_va walks page-by-page and calls
    // ept_conceal_register_pa for each physical page.
    ept_conceal_register_va((PVOID)(ULONG_PTR)base, size);

    if (!ept_conceal_prepare())
    {
        HV_LOG(0, 0, "[byovd] conceal preparation failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Flush EPT TLBs on all cores so the new mappings take effect.
    broadcast_conceal_invept();

    // Optionally wipe the driver's LDR list entry name so enumeration
    // via PsLoadedModuleList does not reveal it.
//
// PsLoadedModuleList is not declared in the WDK public headers for
// arbitrary drivers; declare it ourselves (ntoskrnl export).
//
extern PLIST_ENTRY PsLoadedModuleList;

//
// Loader entry layout used by the kernel (same as tracewipe.c's
// HV_KLDR_DATA_TABLE_ENTRY — the WDK's LDR_DATA_TABLE_ENTRY is not
// exposed to kernel consumers with these offsets).
//
typedef struct _HV_BYOVD_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    PVOID          ExceptionTable;
    ULONG          ExceptionTableSize;
    PVOID          GpValue;
    PVOID          NonPagedDebugInfo;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} HV_BYOVD_LDR_ENTRY, *PHV_BYOVD_LDR_ENTRY;

    if (wipe_ldr)
    {
        // Walk PsLoadedModuleList and zero the BaseDllName / FullDllName
        // for any entry whose DllBase matches our target.
        // We locate PsLoadedModuleList via the kernel's own AUX_MODULE list
        // (which we already queried), so we avoid pattern scanning here.
        // The actual wipe is the same as tracewipe.c wipe_loaded_module().
        PLIST_ENTRY head = PsLoadedModuleList;
        if (head)
        {
            PLIST_ENTRY entry = head->Flink;
            while (entry && entry != head)
            {
                PHV_BYOVD_LDR_ENTRY ldr =
                    CONTAINING_RECORD(entry, HV_BYOVD_LDR_ENTRY, InLoadOrderLinks);
                entry = entry->Flink;

                if ((UINT64)(ULONG_PTR)ldr->DllBase != base)
                    continue;

                // Zero the name buffers
                if (ldr->BaseDllName.Buffer)
                {
                    RtlZeroMemory(ldr->BaseDllName.Buffer,
                                  ldr->BaseDllName.MaximumLength);
                    ldr->BaseDllName.Length        = 0;
                    ldr->BaseDllName.MaximumLength = 0;
                    ldr->BaseDllName.Buffer        = NULL;
                }
                if (ldr->FullDllName.Buffer)
                {
                    RtlZeroMemory(ldr->FullDllName.Buffer,
                                  ldr->FullDllName.MaximumLength);
                    ldr->FullDllName.Length        = 0;
                    ldr->FullDllName.MaximumLength = 0;
                    ldr->FullDllName.Buffer        = NULL;
                }

                // Remove from list
                RemoveEntryList(&ldr->InLoadOrderLinks);
                ldr->InLoadOrderLinks.Flink = NULL;
                ldr->InLoadOrderLinks.Blink = NULL;
                HV_LOG(0, 0, "[byovd] LDR entry wiped for base=0x%016llX\n", base);
                break;
            }
        }
    }

    HV_LOG(0, 0, "[byovd] conceal complete for %wZ\n", driver_name);
    return STATUS_SUCCESS;
}

/*
 * IOCTL handler entry point — called from DriverIoControl in driver.c.
 * Input buffer: HV_CONCEAL_BYOVD_REQUEST
 */
NTSTATUS
byovd_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io_stack)
{
    ULONG inLen = io_stack->Parameters.DeviceIoControl.InputBufferLength;

    if (inLen < sizeof(HV_CONCEAL_BYOVD_REQUEST))
        return STATUS_BUFFER_TOO_SMALL;

    HV_CONCEAL_BYOVD_REQUEST* req =
        (HV_CONCEAL_BYOVD_REQUEST*)irp->AssociatedIrp.SystemBuffer;

    // Ensure driver name is null-terminated within the request
    req->DriverName[sizeof(req->DriverName)/sizeof(WCHAR) - 1] = L'\0';

    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, req->DriverName);

    NTSTATUS st = byovd_conceal_driver(&uName, req->WipeLdrEntry != 0);

    irp->IoStatus.Information = 0;
    return st;
}

#else // !STEALTH_CONCEAL_BYOVD

NTSTATUS
byovd_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io_stack)
{
    UNREFERENCED_PARAMETER(irp);
    UNREFERENCED_PARAMETER(io_stack);
    return STATUS_NOT_SUPPORTED;
}

#endif // STEALTH_CONCEAL_BYOVD
