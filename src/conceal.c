/*
*   conceal.c - guest-physical hide for host-only allocations
*
*   Before VMX launch, every conceal GPA is frozen into a root-owned manifest
*   and all required 2 MiB mappings are split to 4 KiB leaves.  After launch,
*   each vCPU consumes that manifest in VMX root without allocating, remaps its
*   own EPT leaves to a read-only zero page (R=1 W=0 X=0), and executes INVEPT.
*   Production also hides its fixed EPT allocation, vCPU metadata, and mapped
*   image after initialization.  The sole guest-visible exception is .hvshare:
*   an external bootstrap thunk must execute VMCALL while that command page
*   remains readable and writable.  Diagnostic builds leave mutable EPT
*   controls and their device path visible.
*/
#include "hv.h"
#include <ntimage.h>

#ifndef STEALTH_CONCEAL_HOST_PAGES
#define STEALTH_CONCEAL_HOST_PAGES 1
#endif

#define HV_CONCEAL_MAX_RANGES 8192

typedef struct _HV_CONCEAL_RANGE {
    UINT64 pa;
    UINT64 size;
} HV_CONCEAL_RANGE;

typedef struct _HV_CONCEAL_MANIFEST {
    UINT32 Version;
    UINT32 RangeCount;
    UINT64 Generation;
    HV_CONCEAL_RANGE Ranges[HV_CONCEAL_MAX_RANGES];
} HV_CONCEAL_MANIFEST;

static HV_CONCEAL_RANGE g_conceal_ranges[HV_CONCEAL_MAX_RANGES];
static UINT32           g_conceal_count;
static UINT64           g_conceal_generation;
static volatile LONG    g_conceal_frozen;
static HV_CONCEAL_MANIFEST * g_conceal_manifest;
static PVOID            g_dummy_va;
static UINT64           g_dummy_pa;
static BOOLEAN          g_conceal_prepared;
static BOOLEAN          g_conceal_overflow;

#define HV_CONCEAL_STATE_COLLECTING 0
#define HV_CONCEAL_STATE_PREPARING  1
#define HV_CONCEAL_STATE_PUBLISHED  2
#define HV_CONCEAL_STATE_FAILED     3
static volatile LONG    g_conceal_state = HV_CONCEAL_STATE_COLLECTING;
static EX_PUSH_LOCK     g_conceal_lock;
static volatile LONG    g_conceal_prepare_busy;

#if STEALTH_CONCEAL_HOST_PAGES

#if OPHION_PRODUCTION
extern volatile HV_ROOT_COMMAND_PAGE_V1 g_root_command_page;
#endif

static UINT64
conceal_page_align(UINT64 value)
{
    return value & ~(UINT64)(PAGE_SIZE - 1);
}

static BOOLEAN
conceal_add_interval(
    HV_CONCEAL_RANGE * ranges,
    UINT32 * count,
    UINT64 start,
    UINT64 end)
{
    UINT32 first = 0;
    UINT32 last;
    UINT32 remove_count;

    if (!ranges || !count || end <= start)
        return FALSE;
    while (first < *count &&
           ranges[first].pa + ranges[first].size < start)
        first++;
    last = first;
    while (last < *count && ranges[last].pa <= end)
    {
        UINT64 range_end = ranges[last].pa + ranges[last].size;
        if (ranges[last].pa < start)
            start = ranges[last].pa;
        if (range_end > end)
            end = range_end;
        last++;
    }
    remove_count = last - first;
    if (!remove_count && *count >= HV_CONCEAL_MAX_RANGES)
        return FALSE;
    if (remove_count != 1)
    {
        RtlMoveMemory(
            &ranges[first + 1],
            &ranges[last],
            (*count - last) * sizeof(*ranges));
        *count = *count - remove_count + 1;
    }
    ranges[first].pa = start;
    ranges[first].size = end - start;
    return TRUE;
}

#if OPHION_PRODUCTION
static BOOLEAN
conceal_find_image(PVOID address, PUCHAR * image_base, SIZE_T * image_size)
{
    PUCHAR page = (PUCHAR)conceal_page_align((UINT64)address);
    UINT32 pages;

    if (!address || !image_base || !image_size)
        return FALSE;

    /* A production mapper preserves the PE headers; bound the search so a
     * corrupt callback address cannot walk arbitrary kernel memory. */
    for (pages = 0; pages != 0x2000; pages++, page -= PAGE_SIZE)
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)page;
        PIMAGE_NT_HEADERS64 nt;

        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew <= 0 || dos->e_lfanew > PAGE_SIZE - sizeof(*nt))
            continue;
        nt = (PIMAGE_NT_HEADERS64)(page + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            !nt->OptionalHeader.SizeOfImage ||
            nt->OptionalHeader.SizeOfImage > 0x02000000 ||
            nt->OptionalHeader.SizeOfImage > MAXULONG64 - (UINT64)page)
            continue;

        *image_base = page;
        *image_size = nt->OptionalHeader.SizeOfImage;
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN
conceal_register_self_image(VOID)
{
    PUCHAR image_base;
    SIZE_T image_size;
    PUCHAR image_end;
    PUCHAR shared_page = (PUCHAR)conceal_page_align(
        (UINT64)&g_root_command_page);

    if (!conceal_find_image((PVOID)DriverEntry, &image_base, &image_size))
        return FALSE;
    image_end = image_base + image_size;
    if (image_end <= image_base)
        return FALSE;

    /* Keep the authenticated bootstrap doorbell available to guest VMCALL
     * thunks.  VMX-root accesses the concealed image through host CR3. */
    if (shared_page >= image_base && shared_page < image_end)
    {
        if (shared_page > image_base)
            ept_conceal_register_va(image_base, shared_page - image_base);
        if (shared_page + PAGE_SIZE < image_end)
            ept_conceal_register_va(shared_page + PAGE_SIZE,
                image_end - (shared_page + PAGE_SIZE));
    }
    else
    {
        ept_conceal_register_va(image_base, image_size);
    }
    return TRUE;
}
#endif

BOOLEAN
ept_conceal_is_hidden(UINT64 guest_phys)
{
    HV_CONCEAL_SNAPSHOT snapshot;
    HV_CONCEAL_MANIFEST * manifest;
    UINT64 pa = conceal_page_align(guest_phys);

    if (!root_transport_snapshot_conceal(&snapshot))
        return FALSE;
    manifest = (HV_CONCEAL_MANIFEST *)snapshot.Manifest;
    if (!manifest ||
        manifest->Version != 1 ||
        manifest->RangeCount != snapshot.RangeCount ||
        manifest->Generation != snapshot.Generation ||
        manifest->RangeCount >
            HV_CONCEAL_MAX_RANGES)
        return FALSE;
    {
        UINT32 low = 0;
        UINT32 high = manifest->RangeCount;
        while (low < high)
        {
            UINT32 middle = low + (high - low) / 2;
            UINT64 start = manifest->Ranges[middle].pa;
            UINT64 end = start + manifest->Ranges[middle].size;

            if (pa < start)
                high = middle;
            else if (pa >= end)
                low = middle + 1;
            else
                return TRUE;
        }
    }
    return FALSE;
}

VOID
ept_conceal_register_pa(UINT64 pa, SIZE_T size)
{
    UINT64 start;
    UINT64 end;

    if (!pa || !size)
        return;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_conceal_lock);
    if (InterlockedCompareExchange(
            &g_conceal_state, 0, 0) != HV_CONCEAL_STATE_COLLECTING ||
        InterlockedCompareExchange(&g_conceal_frozen, 0, 0) != 0)
    {
        g_conceal_overflow = TRUE;
        goto Done;
    }
    if ((UINT64)size > MAXULONG64 - pa ||
        pa + (UINT64)size >
            MAXULONG64 - (PAGE_SIZE - 1))
    {
        g_conceal_overflow = TRUE;
        goto Done;
    }

    start = conceal_page_align(pa);
    end = (pa + (UINT64)size + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1);
    if (end <= start)
        goto Done;
    if (!conceal_add_interval(
            g_conceal_ranges, &g_conceal_count, start, end))
    {
        g_conceal_overflow = TRUE;
        goto Done;
    }
    g_conceal_generation++;
Done:
    ExReleasePushLockExclusive(&g_conceal_lock);
    KeLeaveCriticalRegion();
}

VOID
ept_conceal_register_va(PVOID va, SIZE_T size)
{
    PUCHAR page;
    PUCHAR end;
    UINT64 * physical_pages = NULL;
    HV_CONCEAL_RANGE * staged_ranges = NULL;
    UINT32 staged_count;
    UINT64 staged_generation;
    SIZE_T page_count;
    SIZE_T page_index = 0;

    if (!va || !size ||
        (UINT64)size > MAXULONG64 - (UINT64)va ||
        InterlockedCompareExchange(
            &g_conceal_state, 0, 0) != HV_CONCEAL_STATE_COLLECTING)
    {
        g_conceal_overflow = TRUE;
        return;
    }

    page = (PUCHAR)conceal_page_align((UINT64)va);
    end = (PUCHAR)va + size;
    page_count = ((SIZE_T)(end - page) + PAGE_SIZE - 1) / PAGE_SIZE;
    if (!page_count || page_count > MAXULONG / sizeof(*physical_pages))
    {
        g_conceal_overflow = TRUE;
        return;
    }
    physical_pages = (UINT64 *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        page_count * sizeof(*physical_pages),
        HV_POOL_TAG);
    if (!physical_pages)
    {
        g_conceal_overflow = TRUE;
        return;
    }
    staged_ranges = (HV_CONCEAL_RANGE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(g_conceal_ranges),
        HV_POOL_TAG);
    if (!staged_ranges)
    {
        g_conceal_overflow = TRUE;
        goto Done;
    }
    while (page < end)
    {
        UINT64 pa = va_to_pa(page);
        if (!pa)
        {
            g_conceal_overflow = TRUE;
            goto Done;
        }
        physical_pages[page_index++] = pa;
        page += PAGE_SIZE;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_conceal_lock);
    if (InterlockedCompareExchange(
            &g_conceal_state, 0, 0) != HV_CONCEAL_STATE_COLLECTING)
    {
        g_conceal_overflow = TRUE;
        ExReleasePushLockExclusive(&g_conceal_lock);
        KeLeaveCriticalRegion();
        goto Done;
    }
    RtlCopyMemory(
        staged_ranges, g_conceal_ranges, sizeof(g_conceal_ranges));
    staged_count = g_conceal_count;
    staged_generation = g_conceal_generation;
    for (page_index = 0; page_index < page_count; page_index++)
    {
        UINT64 start = conceal_page_align(physical_pages[page_index]);
        if (!conceal_add_interval(
                staged_ranges,
                &staged_count,
                start,
                start + PAGE_SIZE))
        {
            g_conceal_overflow = TRUE;
            break;
        }
        staged_generation++;
    }
    if (!g_conceal_overflow)
    {
        RtlCopyMemory(
            g_conceal_ranges, staged_ranges, sizeof(g_conceal_ranges));
        g_conceal_count = staged_count;
        g_conceal_generation = staged_generation;
    }
    ExReleasePushLockExclusive(&g_conceal_lock);
    KeLeaveCriticalRegion();
Done:
    if (staged_ranges)
    {
        RtlSecureZeroMemory(staged_ranges, sizeof(g_conceal_ranges));
        ExFreePoolWithTag(staged_ranges, HV_POOL_TAG);
    }
    RtlSecureZeroMemory(
        physical_pages, page_count * sizeof(*physical_pages));
    ExFreePoolWithTag(physical_pages, HV_POOL_TAG);
}



VOID
ept_conceal_register_runtime(VOID)
{
    UINT32 i;

    if (!g_stealth_enabled)
        return;

#if OPHION_PRODUCTION
    {
        VIRTUAL_MACHINE_STATE * vcpu_base =
            root_transport_vcpu_base();
        UINT32 processor_count =
            root_transport_processor_count();

        if (vcpu_base && processor_count)
            ept_conceal_register_va(
                vcpu_base,
                sizeof(VIRTUAL_MACHINE_STATE) * processor_count);
    }

    root_transport_register_conceal();

    /* Once DriverEntry has entered VMX, no production guest path executes
     * this mapped image until all vCPUs have stopped and EPT is gone. */
    if (!conceal_register_self_image())
        g_conceal_overflow = TRUE;

    if (g_ept)
    {
        PLIST_ENTRY link;

        ept_conceal_register_va(g_ept, sizeof(EPT_STATE));
        for (link = g_ept->hooked_pages.Flink;
             link != &g_ept->hooked_pages;
             link = link->Flink)
        {
            PVMM_EPT_DYNAMIC_SPLIT split =
                CONTAINING_RECORD(
                    link,
                    VMM_EPT_DYNAMIC_SPLIT,
                    SplitList);
            ept_conceal_register_va(split, sizeof(*split));
        }
    }
#endif

    for (i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        if (vcpu->vmxon_va)
            ept_conceal_register_va((PVOID)vcpu->vmxon_va,
                                    2 * VMXON_SIZE + ALIGNMENT_PAGE_SIZE);
        if (vcpu->vmcs_va)
            ept_conceal_register_va((PVOID)vcpu->vmcs_va,
                                    2 * VMCS_SIZE + ALIGNMENT_PAGE_SIZE);
        if (vcpu->vmm_stack)
            ept_conceal_register_va((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE);
        if (vcpu->msr_bitmap_va)
            ept_conceal_register_va((PVOID)vcpu->msr_bitmap_va, PAGE_SIZE);
        if (vcpu->io_bitmap_va_a)
            ept_conceal_register_va((PVOID)vcpu->io_bitmap_va_a, PAGE_SIZE);
        if (vcpu->io_bitmap_va_b)
            ept_conceal_register_va((PVOID)vcpu->io_bitmap_va_b, PAGE_SIZE);
#if OPHION_PRODUCTION
        /*
        * Production has no post-launch protection IOCTL, so the fixed EPT
        * allocation is host-only.  Diagnostic protection mutates it from
        * guest context and must keep it visible until that path is moved
        * entirely into VMX-root hypercalls.
        */
        if (vcpu->ept_page_table)
            ept_conceal_register_va(
                vcpu->ept_page_table,
                sizeof(VMM_EPT_PAGE_TABLE));
#endif
        if (vcpu->host_gdt)
            ept_conceal_register_va(vcpu->host_gdt, PAGE_SIZE);
        if (vcpu->hpet_hook.shadow_va)
            ept_conceal_register_va((PVOID)vcpu->hpet_hook.shadow_va, PAGE_SIZE);
        if (vcpu->lapic_hook.shadow_va)
            ept_conceal_register_va((PVOID)vcpu->lapic_hook.shadow_va, PAGE_SIZE);
    }

#if USE_PRIVATE_HOST_CR3
    hostcr3_register_conceal();
#endif

}

static BOOLEAN
conceal_snapshot_page_tables(
    PVMM_EPT_PAGE_TABLE * page_tables,
    UINT32 * processor_count)
{
    VIRTUAL_MACHINE_STATE * vcpu_base =
        root_transport_vcpu_base();
    UINT32 count =
        root_transport_processor_count();
    UINT32 cpu;

    if (!page_tables || !processor_count ||
        !vcpu_base || !count || count > MAX_PROCESSORS)
        return FALSE;
    for (cpu = 0; cpu < count; cpu++)
        page_tables[cpu] = vcpu_base[cpu].ept_page_table;
    *processor_count = count;
    return TRUE;
}

static BOOLEAN
conceal_prepare_splits(
    PVMM_EPT_PAGE_TABLE * page_tables,
    UINT32 processor_count)
{
    UINT32 cpu;
    UINT32 range_index;

    for (cpu = 0; cpu < processor_count; cpu++)
    {
        VIRTUAL_MACHINE_STATE local_vcpu = {0};

        if (!page_tables[cpu])
            continue;
        local_vcpu.ept_page_table = page_tables[cpu];

        for (range_index = 0; range_index < g_conceal_count; range_index++)
        {
            UINT64 pa = g_conceal_ranges[range_index].pa;
            UINT64 end = pa + g_conceal_ranges[range_index].size;

            while (pa < end)
            {
                if (!ept_split_large_page(&local_vcpu, pa))
                    return FALSE;
                pa += PAGE_SIZE;
            }
        }
    }
    return TRUE;
}

BOOLEAN
ept_conceal_is_frozen(VOID)
{
    return InterlockedCompareExchange(
               &g_conceal_frozen, 0, 0) != 0;
}

BOOLEAN
ept_conceal_prepare(VOID)
{
    PHYSICAL_ADDRESS max_phys;
    PVMM_EPT_PAGE_TABLE page_tables[MAX_PROCESSORS] = {0};
    UINT32 processor_count = 0;
    UINT64 before_generation;
    UINT32 passes;
    BOOLEAN converged = FALSE;

    if (!g_stealth_enabled)
        return TRUE;
    if (g_conceal_prepared)
        return !g_conceal_overflow;
    if (InterlockedCompareExchange(
            &g_conceal_prepare_busy, 1, 0) != 0)
        return FALSE;
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_conceal_lock);
    if (InterlockedCompareExchange(
            &g_conceal_state, 0, 0) != HV_CONCEAL_STATE_COLLECTING)
    {
        ExReleasePushLockExclusive(&g_conceal_lock);
        KeLeaveCriticalRegion();
        InterlockedExchange(&g_conceal_prepare_busy, 0);
        return FALSE;
    }
    ExReleasePushLockExclusive(&g_conceal_lock);
    KeLeaveCriticalRegion();

    max_phys.QuadPart = MAXULONG64;
    g_dummy_va = MmAllocateContiguousMemory(PAGE_SIZE, max_phys);
    if (!g_dummy_va)
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        goto Failed;
    }
    RtlZeroMemory(g_dummy_va, PAGE_SIZE);
    g_dummy_pa = va_to_pa(g_dummy_va);
    if (!g_dummy_pa)
    {
        g_hv_capabilities.Failure = HV_FAILURE_GPA_COVERAGE;
        goto Failed;
    }
    ept_conceal_register_pa(
        g_dummy_pa,
        PAGE_SIZE);

    g_conceal_manifest =
        (HV_CONCEAL_MANIFEST *)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(HV_CONCEAL_MANIFEST),
            HV_POOL_TAG);
    if (!g_conceal_manifest)
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        goto Failed;
    }
    RtlZeroMemory(
        g_conceal_manifest,
        sizeof(HV_CONCEAL_MANIFEST));

    ept_conceal_register_runtime();
    ept_conceal_register_va(
        g_conceal_manifest,
        sizeof(HV_CONCEAL_MANIFEST));
    if (g_conceal_overflow || g_conceal_count == 0)
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        goto Failed;
    }
    if (!conceal_snapshot_page_tables(
            page_tables, &processor_count))
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        goto Failed;
    }

    for (passes = 0; passes < 16; passes++)
    {
        before_generation = g_conceal_generation;
        if (!conceal_prepare_splits(
                page_tables, processor_count))
        {
            g_hv_capabilities.Failure = HV_FAILURE_GPA_COVERAGE;
            goto Failed;
        }
        if (g_conceal_overflow)
        {
            g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
            goto Failed;
        }
        if (g_conceal_generation == before_generation)
        {
            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&g_conceal_lock);
            if (g_conceal_generation == before_generation &&
                InterlockedCompareExchange(
                    &g_conceal_state,
                    HV_CONCEAL_STATE_PREPARING,
                    HV_CONCEAL_STATE_COLLECTING) ==
                        HV_CONCEAL_STATE_COLLECTING)
                converged = TRUE;
            ExReleasePushLockExclusive(&g_conceal_lock);
            KeLeaveCriticalRegion();
        }
        if (converged)
            break;
    }
    if (!converged)
    {
        g_hv_capabilities.Failure = HV_FAILURE_GPA_COVERAGE;
        goto Failed;
    }

    g_conceal_manifest->Version = 1;
    g_conceal_manifest->RangeCount = g_conceal_count;
    g_conceal_manifest->Generation = g_conceal_generation;
    RtlCopyMemory(
        g_conceal_manifest->Ranges,
        g_conceal_ranges,
        sizeof(HV_CONCEAL_RANGE) * g_conceal_count);
    if (!root_transport_set_conceal_manifest(
            g_conceal_manifest,
            g_conceal_count,
            g_conceal_generation,
            g_dummy_pa))
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        goto Failed;
    }
    MemoryBarrier();
    InterlockedExchange(&g_conceal_frozen, 1);
    InterlockedExchange(&g_conceal_state, HV_CONCEAL_STATE_PUBLISHED);

    RtlSecureZeroMemory(
        g_conceal_ranges,
        sizeof(g_conceal_ranges));
    g_conceal_count = 0;
    g_conceal_prepared = TRUE;
    InterlockedExchange(&g_conceal_prepare_busy, 0);
    HV_LOG(
        0, 0,
        "[hv] Prepared immutable conceal manifest generation %llu\n",
        g_conceal_generation);
    return TRUE;

Failed:
    InterlockedExchange(&g_conceal_state, HV_CONCEAL_STATE_FAILED);
    InterlockedExchange(&g_conceal_frozen, 0);
    root_transport_release_conceal_manifest();
    if (g_conceal_manifest)
    {
        RtlSecureZeroMemory(
            g_conceal_manifest, sizeof(HV_CONCEAL_MANIFEST));
        ExFreePoolWithTag(g_conceal_manifest, HV_POOL_TAG);
        g_conceal_manifest = NULL;
    }
    if (g_dummy_va)
    {
        RtlSecureZeroMemory(g_dummy_va, PAGE_SIZE);
        MmFreeContiguousMemory(g_dummy_va);
        g_dummy_va = NULL;
    }
    g_dummy_pa = 0;
    g_conceal_prepared = FALSE;
    InterlockedExchange(&g_conceal_prepare_busy, 0);
    return FALSE;
}

BOOLEAN
ept_conceal_commit_local(
    VIRTUAL_MACHINE_STATE * vcpu)
{
    HV_CONCEAL_SNAPSHOT snapshot;
    HV_CONCEAL_MANIFEST * manifest;
    UINT32 range_count;
    UINT64 generation;
    UINT64 dummy_pa;
    UINT32 range_index;

#if !OPHION_PRODUCTION
    if (!g_stealth_enabled)
        return ept_invept_single(vcpu);
#endif
    if (!root_transport_snapshot_conceal(&snapshot))
        return FALSE;
    manifest = (HV_CONCEAL_MANIFEST *)snapshot.Manifest;
    range_count = snapshot.RangeCount;
    generation = snapshot.Generation;
    dummy_pa = snapshot.DummyPa;
    if (!vcpu || !vcpu->ept_page_table ||
        !manifest || !dummy_pa ||
        manifest->Version != 1 ||
        !generation ||
        generation != manifest->Generation ||
        !range_count ||
        range_count != manifest->RangeCount ||
        range_count > HV_CONCEAL_MAX_RANGES ||
        (dummy_pa & (PAGE_SIZE - 1)) != 0)
        return FALSE;

    /*
     * Validate the complete immutable plan before changing the first leaf.
     * With topology frozen, the second pass cannot legitimately lose a leaf.
     */
    for (range_index = 0;
         range_index < range_count;
         range_index++)
    {
        UINT64 pa = manifest->Ranges[range_index].pa;
        UINT64 size = manifest->Ranges[range_index].size;
        UINT64 end;

        if (!pa || !size ||
            (pa & (PAGE_SIZE - 1)) != 0 ||
            (size & (PAGE_SIZE - 1)) != 0 ||
            size > MAXULONG64 - pa)
            return FALSE;
        end = pa + size;
        while (pa < end)
        {
            if (!ept_get_pml1(
                    vcpu->ept_page_table, pa))
                return FALSE;
            pa += PAGE_SIZE;
        }
    }

    for (range_index = 0;
         range_index < range_count;
         range_index++)
    {
        UINT64 pa = manifest->Ranges[range_index].pa;
        UINT64 end = pa +
            manifest->Ranges[range_index].size;

        if (end <= pa)
            return FALSE;
        while (pa < end)
        {
            PEPT_PML1_ENTRY leaf =
                ept_get_pml1(vcpu->ept_page_table, pa);
            EPT_PML1_ENTRY replacement;

            if (!leaf)
                return FALSE;
            replacement.AsUInt = leaf->AsUInt;
            replacement.PageFrameNumber =
                dummy_pa / PAGE_SIZE;
            replacement.ReadAccess = 1;
            replacement.WriteAccess = 0;
            replacement.ExecuteAccess = 0;
            replacement.MemoryType =
                MEMORY_TYPE_WRITE_BACK;
            InterlockedExchange64(
                (volatile LONG64 *)&leaf->AsUInt,
                (LONG64)replacement.AsUInt);
            pa += PAGE_SIZE;
        }
    }
    return ept_invept_single_initializing(vcpu);
}

VOID
ept_conceal_destroy(VOID)
{
    HV_CONCEAL_SNAPSHOT snapshot;
    HV_CONCEAL_MANIFEST * manifest = NULL;

    if (root_transport_snapshot_conceal(&snapshot))
        manifest = (HV_CONCEAL_MANIFEST *)snapshot.Manifest;
    if (!manifest)
        manifest = g_conceal_manifest;
    root_transport_release_conceal_manifest();
    if (manifest)
    {
        RtlSecureZeroMemory(
            manifest,
            sizeof(HV_CONCEAL_MANIFEST));
        ExFreePoolWithTag(manifest, HV_POOL_TAG);
    }
    g_conceal_manifest = NULL;
    if (g_dummy_va)
    {
        MmFreeContiguousMemory(g_dummy_va);
        g_dummy_va = NULL;
    }
    g_dummy_pa = 0;
    g_conceal_count = 0;
    g_conceal_generation = 0;
    InterlockedExchange(&g_conceal_frozen, 0);
    g_conceal_prepared = FALSE;
    g_conceal_overflow = FALSE;
    InterlockedExchange(&g_conceal_prepare_busy, 0);
    InterlockedExchange(
        &g_conceal_state, HV_CONCEAL_STATE_COLLECTING);
    RtlSecureZeroMemory(
        g_conceal_ranges,
        sizeof(g_conceal_ranges));
}

#else // STEALTH_CONCEAL_HOST_PAGES

BOOLEAN
ept_conceal_is_hidden(UINT64 guest_phys)
{
    UNREFERENCED_PARAMETER(guest_phys);
    return FALSE;
}

VOID
ept_conceal_register_pa(UINT64 pa, SIZE_T size)
{
    UNREFERENCED_PARAMETER(pa);
    UNREFERENCED_PARAMETER(size);
}

VOID
ept_conceal_register_va(PVOID va, SIZE_T size)
{
    UNREFERENCED_PARAMETER(va);
    UNREFERENCED_PARAMETER(size);
}

VOID
ept_conceal_register_runtime(VOID)
{
}

BOOLEAN
ept_conceal_prepare(VOID)
{
    return TRUE;
}

BOOLEAN
ept_conceal_commit_local(
    VIRTUAL_MACHINE_STATE * vcpu)
{
    return ept_invept_single(vcpu);
}

BOOLEAN
ept_conceal_is_frozen(VOID)
{
    return FALSE;
}

VOID
ept_conceal_destroy(VOID)
{
}

#endif
