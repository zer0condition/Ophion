/*
*   tracewipe.c - erase Windows-loader fingerprints after any bring-up
*
*   sc.exe create/start, NtLoadDriver, and most signed-driver loads publish
*   a KLDR_DATA_TABLE_ENTRY, a \Driver object name, a PiDDB cache row, and
*   later an MmUnloadedDrivers slot. Guest AC inventories those. A mapped
*   image with a NULL/dummy DriverSection is a no-op here.
*
*   This cannot unsay an ImageLoad ETW event that already left the box.
*   The AC load path is still boot-time or an external kernel map.
*/
#include "hv.h"
#include <ntimage.h>
#include <aux_klib.h>

#pragma comment(lib, "Aux_Klib.lib")



#ifndef STEALTH_WIPE_LOADER_TRACES
#define STEALTH_WIPE_LOADER_TRACES 1
#endif

#if STEALTH_WIPE_LOADER_TRACES

typedef struct _HV_KLDR_DATA_TABLE_ENTRY {
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
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         Unused5;
    PVOID          SectionPointer;
    ULONG          CheckSum;
    ULONG          TimeDateStamp;
} HV_KLDR_DATA_TABLE_ENTRY, *PHV_KLDR_DATA_TABLE_ENTRY;

typedef struct _HV_PIDDB_CACHE_ENTRY {
    LIST_ENTRY     List;
    UNICODE_STRING DriverName;
    ULONG          TimeDateStamp;
    NTSTATUS       LoadStatus;
    char           _pad[16];
} HV_PIDDB_CACHE_ENTRY, *PHV_PIDDB_CACHE_ENTRY;

typedef struct _HV_MM_UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID          ModuleStart;
    PVOID          ModuleEnd;
    ULONG64        UnloadTime;
} HV_MM_UNLOADED_DRIVER, *PHV_MM_UNLOADED_DRIVER;

#define HV_MM_UNLOADED_DRIVERS 50

static VOID
wipe_unicode(PUNICODE_STRING string)
{
    if (!string)
        return;
    if (string->Buffer && string->MaximumLength)
        RtlZeroMemory(string->Buffer, string->MaximumLength);
    string->Length = 0;
    string->MaximumLength = 0;
    string->Buffer = NULL;
}

static PVOID
ntos_base(PSIZE_T size)
{
    ULONG needed = 0;
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    PVOID base = NULL;

    if (!NT_SUCCESS(AuxKlibInitialize()))
        goto done;
    (VOID)AuxKlibQueryModuleInformation(
        &needed, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
    if (!needed)
        goto done;
    modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, needed, HV_POOL_TAG);
    if (!modules)
        goto done;
    if (!NT_SUCCESS(AuxKlibQueryModuleInformation(
            &needed, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
        goto done;
    if (needed >= sizeof(AUX_MODULE_EXTENDED_INFO))
    {
        base = modules[0].BasicInfo.ImageBase;
        if (size)
            *size = modules[0].ImageSize;
    }

done:
    if (modules)
        ExFreePoolWithTag(modules, HV_POOL_TAG);
    if (!base && size)
        *size = 0;
    return base;
}

static SIZE_T
mask_length(const char * mask)
{
    SIZE_T length = 0;
    if (!mask)
        return 0;
    while (mask[length])
        length++;
    return length;
}

static PVOID
find_pattern(PVOID base, SIZE_T size, const UCHAR * needle, const char * mask)
{
    SIZE_T needle_len;
    SIZE_T i;
    SIZE_T j;

    if (!base || !size || !needle || !mask)
        return NULL;
    needle_len = mask_length(mask);
    if (!needle_len || size < needle_len)
        return NULL;

    for (i = 0; i + needle_len <= size; i++)
    {
        const UCHAR * candidate = (const UCHAR *)base + i;
        BOOLEAN matched = TRUE;
        for (j = 0; j < needle_len; j++)
        {
            if (mask[j] != '?' && candidate[j] != needle[j])
            {
                matched = FALSE;
                break;
            }
        }
        if (matched)
            return (PVOID)candidate;
    }
    return NULL;
}

static PVOID
resolve_lea_target(PVOID insn)
{
    INT32 rel;

    if (!insn)
        return NULL;
    RtlCopyMemory(&rel, (PUCHAR)insn + 3, sizeof(rel));
    return (PUCHAR)insn + 7 + rel;
}

static VOID
wipe_loaded_module(PDRIVER_OBJECT driver_obj)
{
    PHV_KLDR_DATA_TABLE_ENTRY entry;
    KIRQL old_irql;

    if (!driver_obj || !driver_obj->DriverSection)
        return;

    entry = (PHV_KLDR_DATA_TABLE_ENTRY)driver_obj->DriverSection;
    if (!entry->InLoadOrderLinks.Flink || !entry->InLoadOrderLinks.Blink)
        return;

    old_irql = KeRaiseIrqlToDpcLevel();
    RemoveEntryList(&entry->InLoadOrderLinks);
    InitializeListHead(&entry->InLoadOrderLinks);
    KeLowerIrql(old_irql);

    wipe_unicode(&entry->FullDllName);
    wipe_unicode(&entry->BaseDllName);
}

static VOID
wipe_driver_object(PDRIVER_OBJECT driver_obj)
{
    if (!driver_obj)
        return;

    driver_obj->DriverUnload = NULL;
    driver_obj->DriverStart = NULL;
    driver_obj->DriverSize = 0;
    driver_obj->DriverSection = NULL;
    driver_obj->DriverInit = NULL;
    RtlZeroMemory(driver_obj->MajorFunction, sizeof(driver_obj->MajorFunction));
    wipe_unicode(&driver_obj->DriverName);
    if (driver_obj->HardwareDatabase)
        wipe_unicode(driver_obj->HardwareDatabase);
}

static VOID
wipe_piddb(const UNICODE_STRING * name, ULONG time_date_stamp)
{
    static const UCHAR lock_needle[] = {
        0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8,
        0x00, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0x8C
    };
    static const UCHAR table_needle[] = {
        0x66, 0x03, 0xD2, 0x48, 0x8D, 0x0D
    };
    SIZE_T ntos_size = 0;
    PVOID ntos = ntos_base(&ntos_size);
    PVOID lock_hit;
    PVOID table_hit;
    PERESOURCE lock;
    PRTL_AVL_TABLE table;
    PHV_PIDDB_CACHE_ENTRY found = NULL;

    if (!ntos || !name || !name->Buffer)
        return;

    lock_hit = find_pattern(ntos, ntos_size, lock_needle, "xxx????x????xxx");
    table_hit = find_pattern(ntos, ntos_size, table_needle, "xxxxxx");
    if (!lock_hit || !table_hit)
        return;

    lock = (PERESOURCE)resolve_lea_target(lock_hit);
    table = (PRTL_AVL_TABLE)resolve_lea_target((PUCHAR)table_hit + 3);
    if (!lock || !table || !MmIsAddressValid(lock) || !MmIsAddressValid(table))
        return;

    ExAcquireResourceExclusiveLite(lock, TRUE);
    if (table->NumberGenericTableElements)
    {
        PVOID element;

        for (element = RtlEnumerateGenericTableAvl(table, TRUE);
             element;
             element = RtlEnumerateGenericTableAvl(table, FALSE))
        {
            PHV_PIDDB_CACHE_ENTRY row = (PHV_PIDDB_CACHE_ENTRY)element;
            if (row->TimeDateStamp == time_date_stamp &&
                row->DriverName.Buffer &&
                RtlEqualUnicodeString(&row->DriverName, name, TRUE))
            {
                found = row;
                break;
            }
        }
    }
    if (found)
    {
        RemoveEntryList(&found->List);
        RtlDeleteElementGenericTableAvl(table, found);
    }
    ExReleaseResourceLite(lock);
}

static VOID
wipe_unloaded(PVOID image_base)
{
    static const UCHAR needle[] = {
        0x4C, 0x8B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x4C,
        0x8B, 0xC9
    };
    SIZE_T ntos_size = 0;
    PVOID ntos = ntos_base(&ntos_size);
    PVOID hit;
    PHV_MM_UNLOADED_DRIVER * table_ptr;
    PHV_MM_UNLOADED_DRIVER table;
    UINT32 i;

    if (!ntos || !image_base)
        return;

    hit = find_pattern(ntos, ntos_size, needle, "xxx????xxx");
    if (!hit)
        return;
    table_ptr = (PHV_MM_UNLOADED_DRIVER *)resolve_lea_target(hit);
    if (!table_ptr || !MmIsAddressValid(table_ptr) || !(*table_ptr))
        return;
    table = *table_ptr;
    if (!MmIsAddressValid(table))
        return;

    for (i = 0; i < HV_MM_UNLOADED_DRIVERS; i++)
    {
        if (!MmIsAddressValid(&table[i]))
            break;
        if (table[i].ModuleStart == image_base ||
            (table[i].ModuleStart && table[i].ModuleEnd &&
             image_base >= table[i].ModuleStart &&
             image_base < table[i].ModuleEnd))
        {
            wipe_unicode(&table[i].Name);
            table[i].ModuleStart = NULL;
            table[i].ModuleEnd = NULL;
            table[i].UnloadTime = 0;
        }
    }
}

VOID
tracewipe_apply(PDRIVER_OBJECT driver_obj, BOOLEAN preserve_dispatch)
{
    UNICODE_STRING name = {0};
    ULONG stamp = 0;
    PVOID image = NULL;
    PHV_KLDR_DATA_TABLE_ENTRY entry;

    if (!g_stealth_enabled || !driver_obj)
        return;

    entry = (PHV_KLDR_DATA_TABLE_ENTRY)driver_obj->DriverSection;
    if (entry)
    {
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length)
        {
            name.Length = entry->BaseDllName.Length;
            name.MaximumLength = entry->BaseDllName.MaximumLength;
            name.Buffer = entry->BaseDllName.Buffer;
        }
        stamp = entry->TimeDateStamp;
        image = entry->DllBase ? entry->DllBase : driver_obj->DriverStart;
    }
    if (!image)
        image = driver_obj->DriverStart;

    wipe_piddb(&name, stamp);
    wipe_loaded_module(driver_obj);
    wipe_unloaded(image);
    if (!preserve_dispatch)
        wipe_driver_object(driver_obj);
}

#else

VOID
tracewipe_apply(PDRIVER_OBJECT driver_obj, BOOLEAN preserve_dispatch)
{
    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(preserve_dispatch);
}

#endif
