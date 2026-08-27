/*
*   ept.c - extended page table (ept) initialization and management
*   identity-mapped ept with 2mb large pages, mtrr-aware memory typing
*   architecture: pml4 -> pml3 -> pml2 (2mb large pages)
*/
#include "hv.h"
#include <aux_klib.h>

#pragma comment(lib, "Aux_Klib.lib")

#define ACPI_PROVIDER_SIGNATURE 'IPCA'
#define ACPI_HPET_SIGNATURE     'TEPH'

#pragma pack(push, 1)
typedef struct _HV_ACPI_TABLE_HEADER {
    UINT32 Signature;
    UINT32 Length;
    UINT8  Revision;
    UINT8  Checksum;
    UINT8  OemId[6];
    UINT8  OemTableId[8];
    UINT32 OemRevision;
    UINT32 AslCompilerId;
    UINT32 AslCompilerRevision;
} HV_ACPI_TABLE_HEADER;

typedef struct _HV_ACPI_GAS {
    UINT8  AddressSpaceId;
    UINT8  RegisterBitWidth;
    UINT8  RegisterBitOffset;
    UINT8  AccessSize;
    UINT64 Address;
} HV_ACPI_GAS;

typedef struct _HV_ACPI_HPET {
    HV_ACPI_TABLE_HEADER Header;
    UINT32               EventTimerBlockId;
    HV_ACPI_GAS          BaseAddress;
    UINT8                Sequence;
    UINT16               MinimumTick;
    UINT8                Flags;
} HV_ACPI_HPET;
#pragma pack(pop)

static UINT64
ept_query_tsc_frequency(VOID)
{
    INT32 cpu_info[4] = {0};
    UINT64 frequency = 0;

    __cpuidex(cpu_info, 0x15, 0);
    if (cpu_info[0] && cpu_info[1] && cpu_info[2])
        frequency = ((UINT64)(UINT32)cpu_info[2] * (UINT32)cpu_info[1]) /
                    (UINT32)cpu_info[0];

    return frequency;
}

static UINT64
ept_query_hpet(VOID)
{
    NTSTATUS status;
    ULONG size = 0;
    HV_ACPI_HPET * table;
    UINT64 address = 0;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
        return 0;

    status = AuxKlibGetSystemFirmwareTable(
        ACPI_PROVIDER_SIGNATURE, ACPI_HPET_SIGNATURE, NULL, 0, &size);
    if (status != STATUS_BUFFER_TOO_SMALL || size < sizeof(HV_ACPI_HPET))
        return 0;

    table = (HV_ACPI_HPET *)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, HV_POOL_TAG);
    if (!table)
        return 0;

    status = AuxKlibGetSystemFirmwareTable(
        ACPI_PROVIDER_SIGNATURE, ACPI_HPET_SIGNATURE, table, size, &size);
    if (NT_SUCCESS(status) &&
        table->Header.Signature == ACPI_HPET_SIGNATURE &&
        table->BaseAddress.AddressSpaceId == 0)
    {
        address = table->BaseAddress.Address;
    }

    ExFreePoolWithTag(table, HV_POOL_TAG);
    return address;
}

BOOLEAN
ept_check_features(VOID)
{
    IA32_VMX_EPT_VPID_CAP_REGISTER vpid_reg;
    IA32_MTRR_DEF_TYPE_REGISTER    mtrr_def;
    IA32_VMX_BASIC_REGISTER        vmx_basic;
    MSR                            proc_controls;

    vpid_reg.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);
    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);
    proc_controls.Flags = __readmsr(
        vmx_basic.VmxControls
            ? IA32_VMX_TRUE_PROCBASED_CTLS
            : IA32_VMX_PROCBASED_CTLS);
    g_ept->mtf_supported =
        (proc_controls.Fields.High &
         CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG) != 0;
    g_ept->execute_only_supported =
        vpid_reg.ExecuteOnlyPages ? TRUE : FALSE;
    if (g_ept->execute_only_supported)
        g_hv_capabilities.CapabilityFlags |= HV_CAP_EPT_EXEC_ONLY;
    g_ept->invept_supported = vpid_reg.Invept ? TRUE : FALSE;
    g_ept->invept_single_context =
        vpid_reg.InveptSingleContext ? TRUE : FALSE;
    g_ept->invept_all_contexts =
        vpid_reg.InveptAllContexts ? TRUE : FALSE;

    if (!vpid_reg.PageWalkLength4 ||
        !vpid_reg.MemoryTypeWriteBack ||
        !vpid_reg.Pde2MbPages ||
        !g_ept->invept_supported ||
        !g_ept->invept_single_context)
    {
        HV_LOG(0, 0,
            "[hv] EPT: Missing required features "
            "(PW4=%d WB=%d 2MB=%d INVEPT=%d SINGLE=%d)\n",
            (int)vpid_reg.PageWalkLength4,
            (int)vpid_reg.MemoryTypeWriteBack,
            (int)vpid_reg.Pde2MbPages,
            (int)g_ept->invept_supported,
            (int)g_ept->invept_single_context);
        return FALSE;
    }

    g_ept->ad_supported = vpid_reg.EptAccessedAndDirtyFlags ? TRUE : FALSE;

    g_ept->invvpid_supported              = vpid_reg.Invvpid ? TRUE : FALSE;
    g_ept->invvpid_individual_addr        = vpid_reg.InvvpidIndividualAddress ? TRUE : FALSE;
    g_ept->invvpid_single_context         = vpid_reg.InvvpidSingleContext ? TRUE : FALSE;
    g_ept->invvpid_all_contexts           = vpid_reg.InvvpidAllContexts ? TRUE : FALSE;
    g_ept->invvpid_single_retaining_globals = vpid_reg.InvvpidSingleContextRetainingGlobals ? TRUE : FALSE;

    HV_LOG(0, 0, "[hv] INVVPID caps: supported=%d individual=%d single=%d all=%d retaining_globals=%d\n",
             g_ept->invvpid_supported,
             g_ept->invvpid_individual_addr,
             g_ept->invvpid_single_context,
             g_ept->invvpid_all_contexts,
             g_ept->invvpid_single_retaining_globals);

    if (!mtrr_def.MtrrEnable)
    {
        HV_LOG(0, 0, "[hv] EPT: MTRR not enabled\n");
        return FALSE;
    }

    return TRUE;
}

UINT8
ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page)
{
    SIZE_T page_addr = is_large_page ? pfn * SIZE_2_MB : pfn * PAGE_SIZE;
    UINT8  target_type    = (UINT8)-1;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if (page_addr >= range->phys_base &&
            page_addr < range->phys_end)
        {
            if (range->fixed)
            {
                target_type = range->mem_type;
                break;
            }

            if (target_type == (UINT8)-1)
            {
                target_type = range->mem_type;
                continue;
            }
            if (target_type == range->mem_type)
                continue;
            if (target_type == MEMORY_TYPE_UNCACHEABLE ||
                range->mem_type == MEMORY_TYPE_UNCACHEABLE)
            {
                target_type = MEMORY_TYPE_UNCACHEABLE;
                break;
            }
            if ((target_type == MEMORY_TYPE_WRITE_BACK &&
                 range->mem_type == MEMORY_TYPE_WRITE_THROUGH) ||
                (target_type == MEMORY_TYPE_WRITE_THROUGH &&
                 range->mem_type == MEMORY_TYPE_WRITE_BACK))
            {
                target_type = MEMORY_TYPE_WRITE_THROUGH;
                continue;
            }

            /* Undefined overlap combinations are conservatively UC. */
            target_type = MEMORY_TYPE_UNCACHEABLE;
            break;
        }
    }

    if (target_type == (UINT8)-1)
        target_type = g_ept->default_type;

    return target_type;
}

BOOLEAN
ept_build_mtrr_map(VOID)
{
    IA32_MTRR_CAPABILITIES_REGISTER mtrr_cap;
    IA32_MTRR_DEF_TYPE_REGISTER     mtrr_def;
    IA32_MTRR_PHYSBASE_REGISTER     cur_base;
    IA32_MTRR_PHYSMASK_REGISTER     cur_mask;
    MTRR_RANGE_DESCRIPTOR *         desc;

    mtrr_cap.AsUInt     = __readmsr(IA32_MTRR_CAPABILITIES);
    mtrr_def.AsUInt = __readmsr(IA32_MTRR_DEF_TYPE);

    if (!mtrr_def.MtrrEnable)
    {
        g_ept->default_type = MEMORY_TYPE_UNCACHEABLE;
        return TRUE;
    }

    g_ept->default_type = (UINT8)mtrr_def.DefaultMemoryType;

    //
    // fixed-range mtrrs (64K, 16K, 4K regions)
    //
    if (mtrr_cap.FixedRangeSupported && mtrr_def.FixedRangeMtrrEnable)
    {
        //
        // IA32_MTRR_FIX64K_00000: 8 x 64KB regions from 0x00000 to 0x7FFFF
        //
        IA32_MTRR_FIXED_RANGE_TYPE k64_types = { __readmsr(IA32_MTRR_FIX64K_00000) };
        for (UINT32 i = 0; i < 8; i++)
        {
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->mem_type          = k64_types.s.Types[i];
            desc->phys_base = 0x10000 * i;
            desc->phys_end  = desc->phys_base + 0x10000;
            desc->fixed          = TRUE;
        }

        //
        // IA32_MTRR_FIX16K_80000/A0000: 16 x 16KB regions
        //
        for (UINT32 i = 0; i < 2; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k16_types = { __readmsr(IA32_MTRR_FIX16K_80000 + i) };
            for (UINT32 j = 0; j < 8; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type          = k16_types.s.Types[j];
                desc->phys_base = 0x80000 + (i * 0x20000) + (j * 0x4000);
                desc->phys_end  = desc->phys_base + 0x4000;
                desc->fixed          = TRUE;
            }
        }

        //
        // IA32_MTRR_FIX4K_C0000 through FIX4K_F8000: 64 x 4KB regions
        //
        for (UINT32 i = 0; i < 8; i++)
        {
            IA32_MTRR_FIXED_RANGE_TYPE k4_types = { __readmsr(IA32_MTRR_FIX4K_C0000 + i) };
            for (UINT32 j = 0; j < 8; j++)
            {
                desc = &g_ept->mem_ranges[g_ept->num_ranges++];
                desc->mem_type          = k4_types.s.Types[j];
                desc->phys_base = 0xC0000 + (i * 0x8000) + (j * 0x1000);
                desc->phys_end  = desc->phys_base + 0x1000;
                desc->fixed          = TRUE;
            }
        }
    }

    //
    // variable-range mtrrs
    //
    for (UINT32 i = 0; i < mtrr_cap.VariableRangeCount; i++)
    {
        cur_base.AsUInt = __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2));
        cur_mask.AsUInt = __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2));

        if (cur_mask.Valid)
        {
            ULONG mask_bits;

            if (g_ept->num_ranges >= MAX_MTRR_RANGES)
                return FALSE;
            desc = &g_ept->mem_ranges[g_ept->num_ranges++];
            desc->phys_base = cur_base.PageFrameNumber * PAGE_SIZE;
            _BitScanForward64(&mask_bits,
                              cur_mask.PageFrameNumber * PAGE_SIZE);
            desc->phys_end = desc->phys_base + (1ULL << mask_bits);
            desc->mem_type = (UINT8)cur_base.Type;
            desc->fixed = FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_valid_for_large_page(SIZE_T pfn)
{
    SIZE_T start_addr = pfn * SIZE_2_MB;
    SIZE_T end_addr   = start_addr + SIZE_2_MB;

    for (UINT32 i = 0; i < g_ept->num_ranges; i++)
    {
        MTRR_RANGE_DESCRIPTOR * range = &g_ept->mem_ranges[i];

        if ((range->phys_base > start_addr &&
             range->phys_base < end_addr) ||
            (range->phys_end > start_addr &&
             range->phys_end < end_addr))
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
ept_setup_pml2(PVMM_EPT_PAGE_TABLE page_table, PEPT_PML2_ENTRY new_entry, SIZE_T pfn)
{
    UNREFERENCED_PARAMETER(page_table);
    new_entry->PageFrameNumber = pfn;

    new_entry->MemoryType = ept_get_memory_type(pfn, TRUE);
    return TRUE;
}

/*
*   allocate and create identity-mapped ept page table
*   maps all physical memory 1:1 (guest physical = host physical)
*   pml4 (512 entries) -> pml3 (512 entries) -> pml2 (512 x 512 = 262144 entries)
*/
PVMM_EPT_PAGE_TABLE
ept_alloc_identity_map(VOID)
{
    PHYSICAL_ADDRESS    max_phys;
    PVMM_EPT_PAGE_TABLE page_table;
    EPT_PML2_ENTRY      pml2_tmpl;

    max_phys.QuadPart = MAXULONG64;

    page_table = (PVMM_EPT_PAGE_TABLE)MmAllocateContiguousMemory(
        sizeof(VMM_EPT_PAGE_TABLE), max_phys);
    if (!page_table)
        return NULL;

    RtlZeroMemory(page_table, sizeof(VMM_EPT_PAGE_TABLE));

    page_table->PML4[0].ReadAccess    = 1;
    page_table->PML4[0].WriteAccess   = 1;
    page_table->PML4[0].ExecuteAccess = 1;
    page_table->PML4[0].PageFrameNumber = va_to_pa(&page_table->PML3[0]) / PAGE_SIZE;

    for (SIZE_T i = 0; i < VMM_EPT_PML3E_COUNT; i++)
    {
        page_table->PML3[i].ReadAccess    = 1;
        page_table->PML3[i].WriteAccess   = 1;
        page_table->PML3[i].ExecuteAccess = 1;
        page_table->PML3[i].PageFrameNumber = va_to_pa(&page_table->PML2[i][0]) / PAGE_SIZE;
    }

    pml2_tmpl.AsUInt        = 0;
    pml2_tmpl.ReadAccess    = 1;
    pml2_tmpl.WriteAccess   = 1;
    pml2_tmpl.ExecuteAccess = 1;
    pml2_tmpl.LargePage     = 1;

    __stosq((SIZE_T *)&page_table->PML2[0], pml2_tmpl.AsUInt,
            VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    for (SIZE_T group = 0; group < VMM_EPT_PML3E_COUNT; group++)
    {
        for (SIZE_T entry_idx = 0; entry_idx < VMM_EPT_PML2E_COUNT; entry_idx++)
        {
            ept_setup_pml2(page_table,
                              &page_table->PML2[group][entry_idx],
                              (group * VMM_EPT_PML2E_COUNT) + entry_idx);
        }
    }

    return page_table;
}

BOOLEAN
ept_init(VOID)
{
    EPT_POINTER eptp = {0};
    PHYSICAL_ADDRESS max_phys;

    max_phys.QuadPart = MAXULONG64;
    g_ept = (EPT_STATE *)MmAllocateContiguousMemory(
        sizeof(EPT_STATE), max_phys);
    if (!g_ept)
        return FALSE;

    RtlZeroMemory(g_ept, sizeof(EPT_STATE));
    InitializeListHead(&g_ept->hooked_pages);

    g_ept->tsc_frequency = ept_query_tsc_frequency();
    g_ept->hpet_physical = ept_query_hpet();
    if (g_ept->hpet_physical)
    {
        PHYSICAL_ADDRESS hpet_pa;
        volatile UINT64 * hpet;

        hpet_pa.QuadPart = g_ept->hpet_physical & ~(UINT64)(PAGE_SIZE - 1);
        hpet = (volatile UINT64 *)MmMapIoSpaceEx(
            hpet_pa, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
        if (hpet)
        {
            UINT64 capabilities =
                hpet[HPET_GENERAL_CAPABILITIES / sizeof(UINT64)];
            UINT64 period_fs = capabilities >> 32;

            if ((capabilities & 0xFF) &&
                period_fs && period_fs <= 0x05F5E100ULL)
            {
                g_ept->hpet_period_fs = period_fs;
                g_ept->hpet_counter_64bit =
                    (capabilities & (1ULL << 13)) != 0;
            }
            MmUnmapIoSpace((PVOID)hpet, PAGE_SIZE);
        }
        if (!g_ept->hpet_period_fs)
            g_ept->hpet_physical = 0;
        else
            g_hv_capabilities.CapabilityFlags |= HV_CAP_HPET;
    }

    if (!ept_check_features() || !ept_build_mtrr_map())
        return FALSE;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        PVMM_EPT_PAGE_TABLE page_table = ept_alloc_identity_map();
        if (!page_table)
        {
            HV_LOG(0, 0, "[hv] EPT: Failed to allocate page table for core %u\n", i);
            return FALSE;
        }

        g_vcpu[i].ept_page_table = page_table;
        for (UINT32 range_index = 0;
             range_index < g_ept->num_ranges;
             range_index++)
        {
            MTRR_RANGE_DESCRIPTOR * range =
                &g_ept->mem_ranges[range_index];

            if ((range->phys_base & (SIZE_2_MB - 1)) &&
                !ept_split_large_page(&g_vcpu[i], range->phys_base))
                return FALSE;
            if ((range->phys_end & (SIZE_2_MB - 1)) &&
                !ept_split_large_page(&g_vcpu[i], range->phys_end - 1))
                return FALSE;
        }


        eptp.MemoryType = MEMORY_TYPE_WRITE_BACK;
        eptp.EnableAccessAndDirtyFlags = g_ept->ad_supported;
        eptp.PageWalkLength = 3;
        eptp.PageFrameNumber = va_to_pa(&page_table->PML4) / PAGE_SIZE;
        g_vcpu[i].ept_pointer = eptp;
    }

    HV_LOG(0, 0, "[hv] EPT initialized for %u processors\n", g_cpu_count);
    return TRUE;
}

BOOLEAN
ept_split_large_page(VIRTUAL_MACHINE_STATE * vcpu, SIZE_T phys_addr)
{
    PHYSICAL_ADDRESS max_phys;
    PEPT_PML2_ENTRY target;
    PVMM_EPT_DYNAMIC_SPLIT new_split;
    EPT_PML1_ENTRY entry_tmpl;
    EPT_PML2_POINTER new_ptr;

    target = ept_get_pml2(vcpu->ept_page_table, phys_addr);
    if (!target)
        return FALSE;
    if (!target->LargePage)
        return TRUE;
#if OPHION_PRODUCTION
    if (ept_conceal_is_frozen())
        return FALSE;
#endif

    max_phys.QuadPart = MAXULONG64;
    new_split = (PVMM_EPT_DYNAMIC_SPLIT)MmAllocateContiguousMemory(
        sizeof(VMM_EPT_DYNAMIC_SPLIT), max_phys);
    if (!new_split)
        return FALSE;

    RtlZeroMemory(new_split, sizeof(VMM_EPT_DYNAMIC_SPLIT));
    new_split->u.Entry = target;
    new_split->OriginalEntry = target->AsUInt;

    entry_tmpl.AsUInt = 0;
    entry_tmpl.ReadAccess = 1;
    entry_tmpl.WriteAccess = 1;
    entry_tmpl.ExecuteAccess = 1;
    __stosq((SIZE_T *)&new_split->PML1[0], entry_tmpl.AsUInt, VMM_EPT_PML1E_COUNT);

    for (SIZE_T i = 0; i < VMM_EPT_PML1E_COUNT; i++)
    {
        new_split->PML1[i].PageFrameNumber =
            ((target->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + i;
        new_split->PML1[i].MemoryType =
            ept_get_memory_type(new_split->PML1[i].PageFrameNumber, FALSE);
    }

    new_ptr.AsUInt = 0;
    new_ptr.ReadAccess = 1;
    new_ptr.WriteAccess = 1;
    new_ptr.ExecuteAccess = 1;
    new_ptr.PageFrameNumber = va_to_pa(&new_split->PML1[0]) / PAGE_SIZE;
    RtlCopyMemory(target, &new_ptr, sizeof(new_ptr));
    InsertTailList(&g_ept->hooked_pages, &new_split->SplitList);
#if OPHION_PRODUCTION
    ept_conceal_register_va(new_split, sizeof(*new_split));
#endif
    return TRUE;
}

PEPT_PML2_ENTRY
ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir  = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4 = ADDRMASK_EPT_PML4_INDEX(phys_addr);

    if (pml4 > 0)
        return NULL;

    return &page_table->PML2[dir_p][dir];
}

/*
*   get pml1 entry for a physical address (only if page is split)
*/
PEPT_PML1_ENTRY
ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    SIZE_T dir   = ADDRMASK_EPT_PML2_INDEX(phys_addr);
    SIZE_T dir_p = ADDRMASK_EPT_PML3_INDEX(phys_addr);
    SIZE_T pml4  = ADDRMASK_EPT_PML4_INDEX(phys_addr);
    PEPT_PML2_ENTRY pml2;

    if (pml4 > 0 || !g_ept)
        return NULL;
    pml2 = &page_table->PML2[dir_p][dir];
    if (pml2->LargePage || !g_ept)
        return NULL;

    for (PLIST_ENTRY link = g_ept->hooked_pages.Flink;
         link != &g_ept->hooked_pages;
         link = link->Flink)
    {
        PVMM_EPT_DYNAMIC_SPLIT split =
            CONTAINING_RECORD(link, VMM_EPT_DYNAMIC_SPLIT, SplitList);
        if (split->u.Entry == pml2)
            return &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
    }
    return NULL;
}

BOOLEAN
ept_invept_single(VIRTUAL_MACHINE_STATE * vcpu)
{
    INVEPT_DESCRIPTOR desc = {0};
    desc.EptPointer = vcpu->ept_pointer;
    if (asm_invept(InveptSingleContext, &desc) == 0)
        return TRUE;
    vcpu->failed = TRUE;
    vcpu->terminal = TRUE;
    vcpu->last_failure = HV_FAILURE_INVEPT;
    return FALSE;
}

BOOLEAN
ept_invept_single_initializing(
    VIRTUAL_MACHINE_STATE * vcpu)
{
    INVEPT_DESCRIPTOR desc = {0};

    desc.EptPointer = vcpu->ept_pointer;
    if (asm_invept(
            InveptSingleContext, &desc) == 0)
        return TRUE;
    /*
     * Keep VMX active so the all-core initialization rollback can issue its
     * teardown VMCALL on every processor.  The normal runtime helper marks a
     * failed vCPU terminal immediately.
     */
    vcpu->failed = TRUE;
    vcpu->last_failure = HV_FAILURE_INVEPT;
    return FALSE;
}

BOOLEAN
ept_invept_all(VIRTUAL_MACHINE_STATE * vcpu)
{
    INVEPT_DESCRIPTOR desc = {0};
    if (asm_invept(InveptAllContexts, &desc) == 0)
        return TRUE;
    if (vcpu)
    {
        vcpu->failed = TRUE;
        vcpu->terminal = TRUE;
        vcpu->last_failure = HV_FAILURE_INVEPT;
    }
    return FALSE;
}

BOOLEAN
vpid_invvpid_single(VIRTUAL_MACHINE_STATE * vcpu, UINT16 vpid)
{
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = vpid;
    if (asm_invvpid(InvvpidSingleContext, &desc) == 0)
        return TRUE;
    if (vcpu)
    {
        vcpu->failed = TRUE;
        vcpu->terminal = TRUE;
        vcpu->last_failure = HV_FAILURE_INVVPID;
    }
    return FALSE;
}


static UINT64
ept_mul_div_u64(UINT64 value, UINT64 multiplier, UINT64 divisor)
{
    UINT64 quotient;
    UINT64 remainder;

    if (!divisor || !multiplier)
        return 0;

    quotient = value / divisor;
    remainder = value % divisor;
    if (quotient > MAXULONG64 / multiplier)
        return MAXULONG64;
    return quotient * multiplier + (remainder * multiplier) / divisor;
}

static BOOLEAN
ept_create_mmio_hook(
    VIRTUAL_MACHINE_STATE * vcpu,
    PEPT_MMIO_HOOK hook,
    EPT_MMIO_KIND kind,
    UINT64 physical,
    UINT16 target_offset,
    UINT16 target_size)
{
    PHYSICAL_ADDRESS max_phys;

    if (!ept_split_large_page(vcpu, physical))
        return FALSE;

    hook->entry = ept_get_pml1(vcpu->ept_page_table, physical);
    if (!hook->entry)
        return FALSE;

    max_phys.QuadPart = MAXULONG64;
    hook->shadow_va = (UINT64)MmAllocateContiguousMemory(PAGE_SIZE, max_phys);
    if (!hook->shadow_va)
        return FALSE;

    RtlZeroMemory((PVOID)hook->shadow_va, PAGE_SIZE);
    hook->kind = kind;
    hook->physical_page = physical & ~(UINT64)(PAGE_SIZE - 1);
    hook->target_offset = target_offset;
    hook->target_size = target_size;
    hook->shadow_pa = va_to_pa((PVOID)hook->shadow_va);
    hook->original_entry = hook->entry->AsUInt;
    hook->entry->ReadAccess = 0;
    hook->entry->WriteAccess = 0;
    hook->entry->ExecuteAccess = 0;
    hook->active = TRUE;
    return TRUE;
}

BOOLEAN
ept_setup_timer_hooks(VOID)
{
#if STEALTH_VIRTUALIZE_TIMERS
    UINT64 apic_base = __readmsr(IA32_APIC_BASE);
    BOOLEAN apic_enabled = (apic_base & IA32_APIC_BASE_ENABLE) != 0;
    BOOLEAN x2apic = (apic_base & IA32_APIC_BASE_X2APIC) != 0;
    UINT64 apic_physical = apic_base & IA32_APIC_BASE_ADDRESS_MASK;

    for (UINT32 i = 0; i < g_cpu_count; i++)
        g_vcpu[i].x2apic_enabled = apic_enabled && x2apic;

    if (g_ept->hpet_physical && !g_ept->tsc_frequency)
    {
        HV_LOG(0, 0,
            "[hv] HPET virtualization failed: TSC frequency unavailable\n");
        return FALSE;
    }

    if ((g_ept->hpet_physical || apic_enabled) &&
        !g_ept->mtf_supported)
    {
        HV_LOG(0, 0,
            "[hv] Timer MMIO virtualization failed: MTF unavailable\n");
        return FALSE;
    }

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];
        vcpu->x2apic_enabled = apic_enabled && x2apic;

        if (g_ept->hpet_physical)
        {
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = g_ept->hpet_physical & ~(UINT64)(PAGE_SIZE - 1);
            vcpu->hpet_va = MmMapIoSpaceEx(
                pa, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
            if (!vcpu->hpet_va ||
                !ept_create_mmio_hook(
                    vcpu, &vcpu->hpet_hook, EptMmioHpet,
                    g_ept->hpet_physical,
                    (UINT16)((g_ept->hpet_physical & (PAGE_SIZE - 1)) +
                             HPET_MAIN_COUNTER),
                    g_ept->hpet_counter_64bit
                        ? sizeof(UINT64) : sizeof(UINT32)))
            {
                HV_LOG(0, 0,
                    "[hv] HPET virtualization failed\n");
                ept_destroy_timer_hooks();
                return FALSE;
            }
        }

        if (apic_enabled)
        {
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = apic_physical;
            vcpu->lapic_va = MmMapIoSpaceEx(
                pa, PAGE_SIZE, PAGE_READWRITE | PAGE_NOCACHE);
            if (!vcpu->lapic_va ||
                !ept_create_mmio_hook(
                    vcpu, &vcpu->lapic_hook, EptMmioLapic,
                    apic_physical, XAPIC_CURRENT_COUNT_OFFSET, sizeof(UINT32)))
            {
                HV_LOG(0, 0,
                    "[hv] xAPIC virtualization failed\n");
                ept_destroy_timer_hooks();
                return FALSE;
            }
            g_hv_capabilities.CapabilityFlags |= HV_CAP_XAPIC;
        }
    }
#endif
    return TRUE;
}

BOOLEAN
ept_handle_mmio_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys)
{
    PEPT_MMIO_HOOK hook = NULL;
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
    UINT16 offset = (UINT16)(guest_phys & (PAGE_SIZE - 1));
    BOOLEAN target_read;

    if (vcpu->hpet_hook.active &&
        (guest_phys & ~(UINT64)(PAGE_SIZE - 1)) == vcpu->hpet_hook.physical_page)
        hook = &vcpu->hpet_hook;
    else if (vcpu->lapic_hook.active &&
             (guest_phys & ~(UINT64)(PAGE_SIZE - 1)) == vcpu->lapic_hook.physical_page)
        hook = &vcpu->lapic_hook;
    else
        return FALSE;

    qual.AsUInt = vcpu->exit_qual;
    if (qual.ExecuteAccess ||
        (qual.ReadAccess && qual.WriteAccess))
        return FALSE;
    target_read = qual.ReadAccess &&
        !qual.WriteAccess &&
        offset == hook->target_offset;

    hook->entry->AsUInt = hook->original_entry;
    if (target_read)
    {
        if (hook->kind == EptMmioHpet)
        {
            UINT64 raw = *(volatile UINT64 *)((PUCHAR)vcpu->hpet_va +
                                              hook->target_offset);
            UINT64 total_bias = vcpu->timer_bias_pending
                ? vcpu->root_tsc_bias +
                  (__rdtsc() - vcpu->root_tsc_entry)
                : 0;
            BOOLEAN enabled =
                (*(volatile UINT64 *)(
                    (PUCHAR)vcpu->hpet_va + HPET_GENERAL_CONFIGURATION) & 1) != 0;

            if (!g_ept->hpet_counter_64bit)
                raw = (UINT32)raw;

            if (enabled)
            {
                UINT64 root_ticks = 0;


                if (g_ept->tsc_frequency && g_ept->hpet_period_fs)
                {
                    UINT64 root_ns = ept_mul_div_u64(
                        total_bias,
                        1000000000ULL, g_ept->tsc_frequency);
                    root_ticks = ept_mul_div_u64(
                        root_ns, 1000000ULL, g_ept->hpet_period_fs);
                }

                if (g_ept->hpet_counter_64bit)
                {
                    raw = raw > root_ticks ? raw - root_ticks : 0;
                    if (raw < vcpu->hpet_last_value)
                        raw = vcpu->hpet_last_value;
                }
                else
                {
                    raw = (UINT32)((UINT32)raw - (UINT32)root_ticks);
                }
            }

            vcpu->hpet_last_value = raw;
            if (hook->target_size == sizeof(UINT64))
                *(UINT64 *)((PUCHAR)hook->shadow_va + hook->target_offset) = raw;
            else
                *(UINT32 *)((PUCHAR)hook->shadow_va + hook->target_offset) =
                    (UINT32)raw;
        }
        else
        {
            UINT32 raw = *(volatile UINT32 *)((PUCHAR)vcpu->lapic_va +
                                              XAPIC_CURRENT_COUNT_OFFSET);
            UINT32 initial = *(volatile UINT32 *)((PUCHAR)vcpu->lapic_va +
                                                  XAPIC_INITIAL_COUNT_OFFSET);
            UINT64 adjusted;

            if (initial != vcpu->lapic_initial_count)
            {
                vcpu->lapic_initial_count = initial;
                vcpu->lapic_root_bias = 0;
            }
            adjusted = raw;
            if (raw && vcpu->timer_bias_pending)
            {
                adjusted += vcpu->lapic_root_bias;
                if (vcpu->lapic_root_entry >= raw)
                    adjusted += vcpu->lapic_root_entry - raw;
            }
            if (adjusted > initial)
                adjusted = initial;
            vcpu->lapic_last_value = (UINT32)adjusted;
            *(UINT32 *)((PUCHAR)hook->shadow_va + hook->target_offset) =
                (UINT32)adjusted;
        }
        vcpu->timer_bias_pending = FALSE;
        hook->entry->PageFrameNumber = hook->shadow_pa / PAGE_SIZE;
    }

    if (!target_read && qual.WriteAccess &&
        hook->kind == EptMmioHpet &&
        offset >= hook->target_offset &&
        offset < hook->target_offset + hook->target_size)
    {
        vcpu->hpet_last_value = 0;
    }

    hook->entry->ReadAccess = 1;
    hook->entry->WriteAccess = target_read ? 0 : 1;
    hook->entry->ExecuteAccess = 0;
    vcpu->mtf_hook = hook;

    {
        UINT64 controls = 0;
        if (!vmx_vmread_checked(
                vcpu,
                VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                &controls) ||
            !vmx_vmwrite_checked(
                vcpu,
                VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                controls | CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG))
        {
            hook->entry->AsUInt = hook->original_entry;
            hook->entry->ReadAccess = 0;
            hook->entry->WriteAccess = 0;
            hook->entry->ExecuteAccess = 0;
            vcpu->mtf_hook = NULL;
            ept_invept_single(vcpu);
            vcpu->terminal = TRUE;
            return FALSE;
        }
    }
    if (!ept_invept_single(vcpu))
        return FALSE;
    return TRUE;
}

VOID
ept_handle_monitor_trap(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 controls = 0;


    protect_on_mtf(vcpu);

    if (vcpu->mtf_hook)
    {
        vcpu->mtf_hook->entry->AsUInt = vcpu->mtf_hook->original_entry;
        vcpu->mtf_hook->entry->ReadAccess = 0;
        vcpu->mtf_hook->entry->WriteAccess = 0;
        vcpu->mtf_hook->entry->ExecuteAccess = 0;
        vcpu->mtf_hook = NULL;
        if (!ept_invept_single(vcpu))
            vcpu->terminal = TRUE;
    }

    if (!vmx_vmread_checked(
            vcpu,
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &controls) ||
        !vmx_vmwrite_checked(
            vcpu,
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            controls & ~(UINT64)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG))
        vcpu->terminal = TRUE;
}

VOID
ept_destroy_timer_hooks(VOID)
{
    if (!g_ept)
        return;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];
        if (vcpu->hpet_hook.entry)
            vcpu->hpet_hook.entry->AsUInt =
                vcpu->hpet_hook.original_entry;
        if (vcpu->lapic_hook.entry)
            vcpu->lapic_hook.entry->AsUInt =
                vcpu->lapic_hook.original_entry;
        if (vcpu->hpet_hook.shadow_va)
            MmFreeContiguousMemory((PVOID)vcpu->hpet_hook.shadow_va);
        if (vcpu->lapic_hook.shadow_va)
            MmFreeContiguousMemory((PVOID)vcpu->lapic_hook.shadow_va);
        if (vcpu->hpet_va)
            MmUnmapIoSpace(vcpu->hpet_va, PAGE_SIZE);
        if (vcpu->lapic_va)
            MmUnmapIoSpace(vcpu->lapic_va, PAGE_SIZE);
        RtlZeroMemory(&vcpu->hpet_hook, sizeof(vcpu->hpet_hook));
        RtlZeroMemory(&vcpu->lapic_hook, sizeof(vcpu->lapic_hook));
        vcpu->hpet_va = NULL;
        vcpu->lapic_va = NULL;
    }
}

VOID
ept_destroy_splits(VOID)
{
    if (!g_ept)
        return;

    while (!IsListEmpty(&g_ept->hooked_pages))
    {
        PLIST_ENTRY entry = RemoveHeadList(&g_ept->hooked_pages);
        PVMM_EPT_DYNAMIC_SPLIT split =
            CONTAINING_RECORD(entry, VMM_EPT_DYNAMIC_SPLIT, SplitList);
        split->u.Entry->AsUInt = split->OriginalEntry;
        MmFreeContiguousMemory(split);
    }
}
