/*
*   vmx.c - vmx initialization, vmcs setup, and vmx lifecycle management
*   this is the core of the hypervisor. handles vmxon, vmcs allocation,
*   full vmcs field programming, and vmlaunch
*/
#include "hv.h"

UINT32
vmx_topology_index(const PROCESSOR_NUMBER * processor)
{
    if (!processor)
        return MAX_PROCESSORS;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (g_processor_topology[i].Processor.Group == processor->Group &&
            g_processor_topology[i].Processor.Number == processor->Number)
            return g_processor_topology[i].Index;
    }
    return MAX_PROCESSORS;
}

BOOLEAN
vmx_build_topology(VOID)
{
    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    if (!count || count > MAX_PROCESSORS)
    {
        g_hv_capabilities.Failure = HV_FAILURE_PROCESSOR_CAPACITY;
        return FALSE;
    }

    RtlZeroMemory(g_processor_topology, sizeof(g_processor_topology));
    g_cpu_count = count;
    for (ULONG i = 0; i < count; i++)
    {
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(
                i, &g_processor_topology[i].Processor)))
        {
            g_hv_capabilities.Failure = HV_FAILURE_PROCESSOR_CAPACITY;
            g_cpu_count = 0;
            return FALSE;
        }
        g_processor_topology[i].Index = i;
    }
    g_hv_capabilities.CpuCount = count;
    return TRUE;
}

BOOLEAN
vmx_preflight(VOID)
{
    CPUID data = {0};
    INT32 cpu_info[4] = {0};
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    IA32_VMX_EPT_VPID_CAP_REGISTER ept_vpid = {0};
    MSR primary = {0};
    MSR secondary = {0};
    PPHYSICAL_MEMORY_RANGE ranges;

    RtlZeroMemory(&g_hv_capabilities, sizeof(g_hv_capabilities));
    if (!vmx_build_topology())
        return FALSE;

    __cpuid((int *)&data, CPUID_PROCESSOR_FEATURES);
    if (data.ecx & HYPERV_HYPERVISOR_PRESENT_BIT)
    {
        g_hv_capabilities.ParentFlags |= HV_PARENT_PRESENT;
        __cpuidex(cpu_info, 0x40000000, 0);
        RtlCopyMemory(&g_hv_capabilities.ParentVendor[0], &cpu_info[1], 12);
        if ((UINT32)cpu_info[1] == 0x7263694D &&
            (UINT32)cpu_info[2] == 0x666F736F &&
            (UINT32)cpu_info[3] == 0x76482074)
        {
            g_hv_capabilities.ParentFlags |= HV_PARENT_HYPERV;
            if ((UINT32)cpu_info[0] >= 0x40000003)
            {
                __cpuidex(cpu_info, 0x40000003, 0);
                g_hv_capabilities.ParentFeatures = (UINT32)cpu_info[0];
            }
        }
#if !OPHION_ALLOW_NESTED
        g_hv_capabilities.ParentFlags |= HV_PARENT_NESTED_RESTRICTED;
        g_hv_capabilities.Failure = HV_FAILURE_NESTED_RESTRICTION;
        return FALSE;
#endif
    }

    if (!(data.ecx & (1U << CPUID_VMX_BIT)) ||
        !vmx_check_support())
    {
        g_hv_capabilities.Failure = HV_FAILURE_VMX_UNAVAILABLE;
        return FALSE;
    }

    __cpuidex(cpu_info, (INT32)0x80000000, 0);
    if ((UINT32)cpu_info[0] >= 0x80000008)
    {
        __cpuidex(cpu_info, (INT32)0x80000008, 0);
        g_hv_capabilities.PhysicalAddressBits = (UINT32)cpu_info[0] & 0xFF;
    }

    ranges = MmGetPhysicalMemoryRanges();
    if (!ranges)
    {
        g_hv_capabilities.Failure = HV_FAILURE_GPA_COVERAGE;
        return FALSE;
    }
    for (PPHYSICAL_MEMORY_RANGE range = ranges; range->NumberOfBytes.QuadPart; range++)
    {
        UINT64 end = (UINT64)range->BaseAddress.QuadPart +
                     (UINT64)range->NumberOfBytes.QuadPart;
        if (end > g_hv_capabilities.MaximumGuestPhysicalAddress)
            g_hv_capabilities.MaximumGuestPhysicalAddress = end;
    }
    ExFreePool(ranges);

    if (g_hv_capabilities.MaximumGuestPhysicalAddress >
        (1ULL << 39))
    {
        g_hv_capabilities.Failure = HV_FAILURE_GPA_COVERAGE;
        return FALSE;
    }

    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);
    primary.Flags = __readmsr(vmx_basic.VmxControls
        ? IA32_VMX_TRUE_PROCBASED_CTLS
        : IA32_VMX_PROCBASED_CTLS);
    secondary.Flags = __readmsr(IA32_VMX_PROCBASED_CTLS2);
    ept_vpid.AsUInt = __readmsr(IA32_VMX_EPT_VPID_CAP);

    if (!(primary.Fields.High &
          CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS) ||
        !(secondary.Fields.High & CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT))
    {
        g_hv_capabilities.Failure = HV_FAILURE_REQUIRED_CONTROLS;
        if (g_hv_capabilities.ParentFlags & HV_PARENT_PRESENT)
            g_hv_capabilities.ParentFlags |= HV_PARENT_NESTED_RESTRICTED;
        return FALSE;
    }
    if (!ept_vpid.PageWalkLength4 || !ept_vpid.MemoryTypeWriteBack ||
        !ept_vpid.Pde2MbPages)
    {
        g_hv_capabilities.Failure = HV_FAILURE_EPT_UNAVAILABLE;
        if (g_hv_capabilities.ParentFlags & HV_PARENT_PRESENT)
            g_hv_capabilities.ParentFlags |= HV_PARENT_NESTED_RESTRICTED;
        return FALSE;
    }

    g_hv_capabilities.CapabilityFlags =
        HV_CAP_EPT | HV_CAP_EPT_2MB;
    if (ept_vpid.EptAccessedAndDirtyFlags)
        g_hv_capabilities.CapabilityFlags |= HV_CAP_EPT_AD;
    if (primary.Fields.High & CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG)
        g_hv_capabilities.CapabilityFlags |= HV_CAP_MTF;
    if (ept_vpid.Invvpid)
        g_hv_capabilities.CapabilityFlags |= HV_CAP_INVVPID;
    __cpuidex(cpu_info, 7, 0);
    if (((UINT32)cpu_info[2] & (1U << 5)) &&
        (secondary.Fields.High &
         CPU_BASED_VM_EXEC_CTRL2_ENABLE_USER_WAIT_PAUSE))
        g_hv_capabilities.CapabilityFlags |= HV_CAP_WAITPKG;
    __cpuidex(cpu_info, 0x0A, 0);
    if ((cpu_info[0] & 0xFF) != 0)
        g_hv_capabilities.CapabilityFlags |= HV_CAP_PMU;

    return TRUE;
}

BOOLEAN
vmx_vmread_checked(
    VIRTUAL_MACHINE_STATE * vcpu,
    SIZE_T field,
    UINT64 * value)
{
    if (__vmx_vmread(field, value) == 0)
        return TRUE;
    if (vcpu)
    {
        UINT64 error = 0;
        vcpu->failed = TRUE;
        vcpu->last_failure = HV_FAILURE_VMCS_READ;
        if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error) == 0)
            vcpu->last_vm_instruction_error = (UINT32)error;
    }
    return FALSE;
}

BOOLEAN
vmx_vmwrite_checked(
    VIRTUAL_MACHINE_STATE * vcpu,
    SIZE_T field,
    UINT64 value)
{
    if (__vmx_vmwrite(field, value) == 0)
        return TRUE;
    if (vcpu)
    {
        UINT64 error = 0;
        vcpu->failed = TRUE;
        vcpu->last_failure = HV_FAILURE_VMCS_WRITE;
        if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error) == 0)
            vcpu->last_vm_instruction_error = (UINT32)error;
    }
    return FALSE;
}

VOID
vmx_mark_host_nmi_pending(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (vcpu)
        InterlockedExchange(&vcpu->host_nmi_pending, 1);
}


static VOID
vmx_calibrate_cpuid(VIRTUAL_MACHINE_STATE * vcpu)
{
    static const UINT32 leaves[HvCpuidLeafClassCount] = {
        0, 7, 0x80000000U
    };
    INT32 cpu_info[4];

    for (UINT32 leaf_class = 0;
         leaf_class < HvCpuidLeafClassCount;
         leaf_class++)
    {
        UINT64 minimum = MAXULONG64;
        UINT64 maximum = 0;

        for (UINT32 sample = 0; sample < 32; sample++)
        {
            UINT32 aux;
            UINT64 start = __rdtsc();
            __cpuidex(cpu_info, (INT32)leaves[leaf_class], 0);
            UINT64 elapsed = __rdtscp(&aux) - start;
            if (elapsed < minimum)
                minimum = elapsed;
            if (elapsed > maximum)
                maximum = elapsed;
        }

        vcpu->cpuid_cost[leaf_class] = minimum;
        vcpu->cpuid_jitter[leaf_class] =
            maximum > minimum ? maximum - minimum : 0;
        if (vcpu->cpuid_jitter[leaf_class] > minimum / 4)
            vcpu->cpuid_jitter[leaf_class] = minimum / 4;
    }
}
BOOLEAN
vmx_check_support(VOID)
{
    CPUID                         data              = {0};
    IA32_FEATURE_CONTROL_REGISTER feat_ctrl = {0};

    //
    // CPUID.1:ECX[5] = VMX support
    //
    __cpuid((int *)&data, 1);
    if (!_bittest((const LONG *)&data.ecx, CPUID_VMX_BIT))
    {
        return FALSE;
    }

    feat_ctrl.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

    if (feat_ctrl.EnableVmxOutsideSmx == FALSE)
    {
        return FALSE;
    }

    return TRUE;
}

UINT32
vmx_adjust_controls(UINT32 requested, UINT32 capability_msr)
{
    MSR msr_val = {0};
    msr_val.Flags = __readmsr(capability_msr);

    //
    // bit == 0 in high word -> must be zero
    // bit == 1 in low word  -> must be one
    //
    requested &= msr_val.Fields.High;
    requested |= msr_val.Fields.Low;
    return requested;
}

VOID
vmx_set_fixed_bits(VOID)
{
    CR_FIXED fixed = {0};
    CR4      cr4   = {0};
    CR0      cr0   = {0};

    fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    cr0.AsUInt  = __readcr0();
    cr0.AsUInt |= fixed.Fields.Low;
    fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    cr0.AsUInt &= fixed.Fields.Low;
    __writecr0(cr0.AsUInt);

    fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    cr4.AsUInt  = __readcr4();
    cr4.AsUInt |= fixed.Fields.Low;
    fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    cr4.AsUInt &= fixed.Fields.Low;
    __writecr4(cr4.AsUInt);
}

/*
*   allocate vmxon region (memory only — vmxon runs per-core later)
*/
BOOLEAN
vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE * vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    PHYSICAL_ADDRESS        max_phys;
    UINT8 *                 vmxon_region;
    UINT64                  phys_addr;
    UINT64                  aligned_va;
    UINT64                  aligned_pa;

    max_phys.QuadPart = MAXULONG64;

    vmxon_region = (UINT8 *)MmAllocateContiguousMemory(2 * VMXON_SIZE + ALIGNMENT_PAGE_SIZE, max_phys);
    if (!vmxon_region)
        return FALSE;

    RtlZeroMemory(vmxon_region, 2 * VMXON_SIZE + ALIGNMENT_PAGE_SIZE);

    phys_addr  = va_to_pa(vmxon_region);
    aligned_va = (UINT64)((ULONG_PTR)(vmxon_region + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
    aligned_pa = (UINT64)((ULONG_PTR)(phys_addr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    vmx_basic.AsUInt          = __readmsr(IA32_VMX_BASIC);
    *(UINT64 *)aligned_va        = vmx_basic.VmcsRevisionId;

    vcpu->vmxon_pa = aligned_pa;
    vcpu->vmxon_va  = (UINT64)vmxon_region;
    return TRUE;
}

BOOLEAN
vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    PHYSICAL_ADDRESS        max_phys;
    UINT8 *                 vmcs_region;
    UINT64                  phys_addr;
    UINT64                  aligned_va;
    UINT64                  aligned_pa;

    max_phys.QuadPart = MAXULONG64;

    vmcs_region = (UINT8 *)MmAllocateContiguousMemory(2 * VMCS_SIZE + ALIGNMENT_PAGE_SIZE, max_phys);
    if (!vmcs_region)
        return FALSE;

    RtlZeroMemory(vmcs_region, 2 * VMCS_SIZE + ALIGNMENT_PAGE_SIZE);

    phys_addr  = va_to_pa(vmcs_region);
    aligned_va = (UINT64)((ULONG_PTR)(vmcs_region + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
    aligned_pa = (UINT64)((ULONG_PTR)(phys_addr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

    vmx_basic.AsUInt          = __readmsr(IA32_VMX_BASIC);
    *(UINT64 *)aligned_va        = vmx_basic.VmcsRevisionId;

    vcpu->vmcs_pa = aligned_pa;
    vcpu->vmcs_va  = (UINT64)vmcs_region;
    return TRUE;
}

BOOLEAN
vmx_clear_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    return __vmx_vmclear(&vcpu->vmcs_pa) == 0;
}

BOOLEAN
vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (__vmx_vmptrld(&vcpu->vmcs_pa))
        return FALSE;
    return TRUE;
}

#define __vmx_vmwrite(Field, Value) \
    vmx_vmwrite_checked(vcpu, (Field), (UINT64)(Value))

BOOLEAN
vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack)
{
    UINT32                  pri_proc;
    UINT32                  sec_proc;
    UINT32                  pin_ctrl;
    UINT32                  exit_ctrl;
    UINT32                  entry_ctrl;
    UINT64                  gdt_base;
    INT32                   cpu_info[4] = {0};
    IA32_VMX_BASIC_REGISTER vmx_basic = {0};
    VMX_SEGMENT_SELECTOR    seg_sel = {0};

    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);
#if STEALTH_VIRTUALIZE_PMU
    __cpuidex(cpu_info, 0x0A, 0);
    vcpu->pmu_version = (UINT8)(cpu_info[0] & 0xFF);
    if (vcpu->pmu_version)
    {
        UINT64 valid_global_mask;

        vcpu->pmu_gp_count = (UINT8)((cpu_info[0] >> 8) & 0xFF);
        vcpu->pmu_gp_width = (UINT8)((cpu_info[0] >> 16) & 0xFF);
        vcpu->pmu_fixed_bitmap = (UINT32)cpu_info[2];
        vcpu->pmu_fixed_count = (UINT8)(cpu_info[3] & 0x1F);
        vcpu->pmu_fixed_width = (UINT8)((cpu_info[3] >> 5) & 0xFF);

        valid_global_mask = vcpu->pmu_gp_count >= 32
            ? 0xFFFFFFFFULL
            : ((1ULL << vcpu->pmu_gp_count) - 1);
        valid_global_mask |= ((vcpu->pmu_fixed_count >= 32
            ? 0xFFFFFFFFULL
            : ((1ULL << vcpu->pmu_fixed_count) - 1)) |
            vcpu->pmu_fixed_bitmap) << 32;
        vcpu->perf_global_ctrl =
            __readmsr(IA32_PERF_GLOBAL_CTRL) & valid_global_mask;
    }

    __cpuidex(cpu_info, 6, 0);
    vcpu->aperf_mperf_supported = ((UINT32)cpu_info[2] & 1U) != 0;
#endif

    //
    // mask RPL and TI bits (bits 0-2) per Intel SDM
    //
    __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, asm_get_es() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, asm_get_cs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, asm_get_ss() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, asm_get_ds() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, asm_get_fs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, asm_get_gs() & 0xF8);
    __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, asm_get_tr() & 0xF8);

    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_POINTER, ~0ULL);

    __vmx_vmwrite(VMCS_GUEST_DEBUGCTL, __readmsr(IA32_DEBUGCTL));

    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);

    gdt_base = asm_get_gdt_base();

#if USE_PRIVATE_HOST_GDT
    if (!hostgdt_build_for_vcpu(vcpu))
        return FALSE;
#else
    vcpu->original_gdt_base    = gdt_base;
    vcpu->original_gdt_limit   = asm_get_gdt_limit();
    vcpu->original_tr_selector = asm_get_tr();
#endif

    if (!segment_fill_vmcs(vcpu, (PVOID)gdt_base, ES, asm_get_es()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, CS, asm_get_cs()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, SS, asm_get_ss()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, DS, asm_get_ds()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, FS, asm_get_fs()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, GS, asm_get_gs()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, LDTR, asm_get_ldtr()) ||
        !segment_fill_vmcs(vcpu, (PVOID)gdt_base, TR, asm_get_tr()))
        return FALSE;

    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

    pri_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING |
        (STEALTH_VIRTUALIZE_PMU
            ? CPU_BASED_VM_EXEC_CTRL_RDPMC_EXITING : 0) |
        CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pri_proc);

    vcpu->primary_dynamic_forced =
        pri_proc &
        (CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING |
         CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING);
    vcpu->mov_dr_exiting = !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING);
    vcpu->guest_cr8 = (UINT8)__readcr8();

    HV_LOG(0, 0, "[hv] Primary proc controls: 0x%08X (CR3load=%d CR3store=%d INVLPG=%d HLT=%d RDTSC=%d MOVDR=%d TSCoff=%d)\n",
             pri_proc,
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_CR3_STORE_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_INVLPG_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_HLT_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING));

    __cpuidex(cpu_info, 7, 0);
    sec_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID |
        CPU_BASED_VM_EXEC_CTRL2_RDTSCP |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_INVPCID |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES |
        (((UINT32)cpu_info[2] & (1U << 5))
            ? CPU_BASED_VM_EXEC_CTRL2_ENABLE_USER_WAIT_PAUSE : 0),
        IA32_VMX_PROCBASED_CTLS2);
    if (!(sec_proc & CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT))
        return FALSE;
    vcpu->vpid_enabled =
        (sec_proc & CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID) != 0;
    if (vcpu->vpid_enabled &&
        (!g_ept->invvpid_supported ||
         !g_ept->invvpid_single_context))
        return FALSE;
    vcpu->waitpkg_enabled =
        ((sec_proc & CPU_BASED_VM_EXEC_CTRL2_ENABLE_USER_WAIT_PAUSE) != 0);
    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, sec_proc);

    pin_ctrl = vmx_adjust_controls(
        PIN_BASED_VM_EXEC_CTRL_NMI_EXITING |
        PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI,
        vmx_basic.VmxControls
            ? IA32_VMX_TRUE_PINBASED_CTLS
            : IA32_VMX_PINBASED_CTLS);
    if (!(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_NMI_EXITING) ||
        !(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI))
        return FALSE;
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin_ctrl);

    HV_LOG(0, 0, "[hv] Pin controls: 0x%08X (ExtInt=%d NMI=%d VirtNMI=%d Preempt=%d)\n",
             pin_ctrl,
             !!(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_EXTERNAL_INTERRUPT_EXITING),
             !!(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_NMI_EXITING),
             !!(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI),
             !!(pin_ctrl & PIN_BASED_VM_EXEC_CTRL_VMX_PREEMPTION_TIMER));

    //
    // 64-bit host, save/load debug controls
    // SAVE_DEBUG_CONTROLS: saves DR7 + IA32_DEBUGCTL on VM-exit
    // Required for correct guest debug register state (DR7, pending #DB)
    //
    //
    // ack interrupt on exit: on vm-exit due to external interrupt, the cpu
    // acknowledges the interrupt at the lapic and stores the vector in
    // VMCS_VMEXIT_INTERRUPTION_INFORMATION. without this, pending interrupts
    // cause an infinite vm-exit loop -> TDR -> black blink
    //
    exit_ctrl = vmx_adjust_controls(
        VM_EXIT_CTRL_HOST_ADDRESS_SPACE_SIZE |
        VM_EXIT_CTRL_SAVE_DEBUG_CONTROLS |
        ((pin_ctrl & PIN_BASED_VM_EXEC_CTRL_EXTERNAL_INTERRUPT_EXITING)
            ? VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT
            : 0) |
        (vcpu->pmu_gp_count
            ? VM_EXIT_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL |
              VM_EXIT_CTRL_SAVE_IA32_PERF_GLOBAL_CTRL
            : 0),
        vmx_basic.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, exit_ctrl);

    HV_LOG(0, 0, "[hv] Exit controls: 0x%08X (AckInt=%d)\n",
             exit_ctrl, !!(exit_ctrl & VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT));

    //
    // IA-32e mode guest, load debug controls
    // required so guest sees its own DR7 after VM-exit/entry cycle
    //
    entry_ctrl = vmx_adjust_controls(
        VM_ENTRY_CTRL_IA32E_MODE_GUEST |
        VM_ENTRY_CTRL_LOAD_DEBUG_CONTROLS |
        (vcpu->pmu_gp_count ? VM_ENTRY_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL : 0),
        vmx_basic.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entry_ctrl);

    vcpu->pmu_isolated =
        vcpu->pmu_gp_count &&
        (exit_ctrl & VM_EXIT_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL) &&
        (entry_ctrl & VM_ENTRY_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL);
    if (vcpu->pmu_isolated)
    {
        __vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, vcpu->perf_global_ctrl);
        __vmx_vmwrite(VMCS_HOST_PERF_GLOBAL_CTRL, 0);
    }
#if STEALTH_VIRTUALIZE_PMU
    if (vcpu->pmu_version && !vcpu->pmu_isolated)
    {
        g_hv_capabilities.Failure = HV_FAILURE_REQUIRED_CONTROLS;
        return FALSE;
    }
#endif

    //
    // CR0: 0 = don't cause VM-exit on CR0 modifications (pass-through)
    //
    __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
    __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, 0);

    //
    // CR4: stealth mode masks bit 13 (VMXE) so guest reads see VMXE=0
    //
    // when bit 13 in the mask is set:
    //   - guest reads CR4: bit 13 comes from shadow (=0) -> VMXE hidden
    //   - guest writes CR4 with bit 13 matching shadow: no VM-exit, host bits preserved
    //   - guest writes CR4 with bit 13 != shadow: VM-exit, we handle it
    //
    // defeats: hvdetecc vm.vmxe
    //
#if STEALTH_HIDE_CR4_VMXE
    if (g_stealth_enabled)
    {
        __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMX_ENABLE_FLAG);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, __readcr4() & ~CR4_VMX_ENABLE_FLAG);
    }
    else
#endif
    {
        __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, 0);
    }

    __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
    __vmx_vmwrite(VMCS_GUEST_DR7, 0x400);

    //
    // must be programmed or VMLAUNCH will fail VM-entry checks.
    //
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);          // Active
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, 0);  // No blocking
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

    __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
    __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());

    //
    // HOST_CR3 = private host page tables (immune to guest pt trashing)
    //
#if USE_PRIVATE_HOST_CR3
    __vmx_vmwrite(VMCS_HOST_CR3, hostcr3_get());
#else
    __vmx_vmwrite(VMCS_HOST_CR3, g_system_cr3 ? g_system_cr3 : __readcr3());
#endif

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,  asm_get_gdt_base());
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, asm_get_gdt_limit());
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,  asm_get_idt_base());
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, asm_get_idt_limit());
    __vmx_vmwrite(VMCS_GUEST_RFLAGS,     asm_get_rflags());

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

#if USE_PRIVATE_HOST_GDT
    if (vcpu->host_gdt)
    {
        segment_get_descriptor((PUCHAR)vcpu->host_gdt, asm_get_tr(), &seg_sel);
        __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_sel.Base);
        __vmx_vmwrite(VMCS_HOST_GDTR_BASE, (UINT64)vcpu->host_gdt);
    }
    else
#endif
    {
        segment_get_descriptor((PUCHAR)asm_get_gdt_base(), asm_get_tr(), &seg_sel);
        __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_sel.Base);
        __vmx_vmwrite(VMCS_HOST_GDTR_BASE, asm_get_gdt_base());
    }

    //
    // private host IDT prevents NMI hijacking (guest corrupts OS IDT vector 2,
    // triggers NMI while in VMX-root -> attacker code runs in ring 0)
    //
#if USE_PRIVATE_HOST_IDT
    if (g_host_idt.initialized)
        __vmx_vmwrite(VMCS_HOST_IDTR_BASE, hostidt_get_base());
    else
#endif
        __vmx_vmwrite(VMCS_HOST_IDTR_BASE, asm_get_idt_base());

    __vmx_vmwrite(VMCS_HOST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_HOST_GS_BASE, __readmsr(IA32_GS_BASE));

    __vmx_vmwrite(VMCS_HOST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, vcpu->msr_bitmap_pa);

    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_A_ADDRESS, vcpu->io_bitmap_pa_a);
    __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_B_ADDRESS, vcpu->io_bitmap_pa_b);

    __vmx_vmwrite(VMCS_CTRL_EPT_POINTER, vcpu->ept_pointer.AsUInt);

    __vmx_vmwrite(VIRTUAL_PROCESSOR_ID, VPID_TAG);

    //
    // RSP = current stack (saved by asm_vmx_save_state)
    // RIP = asm_vmx_restore_state (returns to caller after VMLAUNCH succeeds)
    //
    __vmx_vmwrite(VMCS_GUEST_RSP, (UINT64)guest_stack);
    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)asm_vmx_restore_state);

    //
    // store vcpu pointer at top of VMM stack so assembly can retrieve it
    // without calling any Windows API in VMX-root mode.
    //
    // stack layout:
    //   [vmm_stack + VMM_STACK_SIZE - 8]  = vcpu pointer
    //   [vmm_stack + VMM_STACK_SIZE - 16] = HOST_RSP (16-byte aligned)
    //
    *(PVIRTUAL_MACHINE_STATE *)((UINT64)vcpu->vmm_stack + VMM_STACK_SIZE - VMM_STACK_VCPU_OFFSET) = vcpu;

    __vmx_vmwrite(VMCS_HOST_RSP, (UINT64)vcpu->vmm_stack + VMM_STACK_SIZE - 16);
    __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)asm_vmexit_handler);

    if (vcpu->failed)
        return FALSE;

    return TRUE;
}
#undef __vmx_vmwrite

/*
*   called per-core via dpc — sets up vmx, enters vmx operation, launches
*   memory for vmxon/vmcs regions is pre-allocated in vmx_init
*   this function runs at dispatch_level and performs the vmx instructions
*/
BOOLEAN
vmx_virtualize_cpu(PVOID guest_stack)
{
    PROCESSOR_NUMBER processor;
    UINT32 core;
    VIRTUAL_MACHINE_STATE * vcpu;
    UINT64 error_code = 0;

    KeGetCurrentProcessorNumberEx(&processor);
    core = vmx_topology_index(&processor);
    if (!g_vcpu || core >= g_cpu_count)
        return FALSE;
    vcpu = &g_vcpu[core];
    vcpu->core_id = core;
    vmx_calibrate_cpuid(vcpu);
    vcpu->original_cr0 = __readcr0();
    vcpu->original_cr4 = __readcr4();


    asm_enable_vmx();
    vmx_set_fixed_bits();

    if (__vmx_on(&vcpu->vmxon_pa))
    {
        vcpu->failed = TRUE;
        vcpu->last_failure = HV_FAILURE_VM_ENTRY;
        __writecr0(vcpu->original_cr0);
        __writecr4(vcpu->original_cr4 & ~CR4_VMX_ENABLE_FLAG);
        HV_LOG(0, 0, "[hv] VMXON failed on core %u\n", core);
        return FALSE;
    }
    vcpu->vmxon_active = TRUE;

    if (!vmx_clear_vmcs(vcpu) ||
        !vmx_load_vmcs(vcpu) ||
        !vmx_setup_vmcs(vcpu, guest_stack))
    {
        vcpu->failed = TRUE;
        if (!vcpu->last_failure)
            vcpu->last_failure = HV_FAILURE_VMCS_WRITE;
        if (asm_vmxoff_checked() == 0)
        {
            __writecr0(vcpu->original_cr0);
            __writecr4(vcpu->original_cr4 & ~CR4_VMX_ENABLE_FLAG);
        }
        return FALSE;
    }

    vcpu->launched = TRUE;
    __vmx_vmlaunch();

    vcpu->launched = FALSE;
    vcpu->failed = TRUE;
    vcpu->last_failure = HV_FAILURE_VM_ENTRY;
    if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code) == 0)
        vcpu->last_vm_instruction_error = (UINT32)error_code;
    if (asm_vmxoff_checked() == 0)
    {
        __writecr0(vcpu->original_cr0);
        __writecr4(vcpu->original_cr4 & ~CR4_VMX_ENABLE_FLAG);
    }

    HV_LOG(0, 0, "[hv] VMLAUNCH failed on core %u, error: 0x%llx\n", core, error_code);
    return FALSE;
}

VOID
vmx_vmresume(VOID)
{
    __vmx_vmresume();

    //
    // should never reach here
    //
    UINT64 error_code = 0;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code);
    if (asm_vmxoff_checked() == 0)
        __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);
    HV_LOG(0, 0, "[hv] VMRESUME failed! Error: 0x%llx\n", error_code);
    __debugbreak();
    for (;;)
        __halt();
}

BOOLEAN
vmx_init(VOID)
{
    if (!vmx_preflight())
    {
        HV_LOG(0, 0, "[hv] VMX preflight failed: %u\n",
                   g_hv_capabilities.Failure);
        return FALSE;
    }

#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();
#endif

    g_vcpu = (VIRTUAL_MACHINE_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count, HV_POOL_TAG);

    if (!g_vcpu)
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        return FALSE;
    }

    RtlZeroMemory(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count);


    {
        KAPC_STATE apc_state;
        KeStackAttachProcess(PsInitialSystemProcess, &apc_state);
        g_system_cr3 = __readcr3();
        KeUnstackDetachProcess(&apc_state);
    }

    if (!ept_init())
    {
        HV_LOG(0, 0, "[hv] EPT initialization failed!\n");
        return FALSE;
    }

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

        vcpu->vmm_stack = (UINT64)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, HV_POOL_TAG);
        if (!vcpu->vmm_stack)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->vmm_stack, VMM_STACK_SIZE);

        //
        // MSR Bitmap (1 page, all zeros = no MSR VM-exits)
        //
        vcpu->msr_bitmap_va = (UINT64)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_POOL_TAG);
        if (!vcpu->msr_bitmap_va)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->msr_bitmap_va, PAGE_SIZE);

        //
        // intercept RDMSR(0x10) — IA32_TIME_STAMP_COUNTER
        // per SDM 27.6.5, "use TSC offsetting" applies the offset to RDMSR(0x10)
        // automatically. interception is only needed so the TSC compensation path
        // can cover RDMSR-based timing attacks alongside RDTSC.
        //
        ((PUCHAR)vcpu->msr_bitmap_va)[0x10 / 8] |= (UCHAR)(1 << (0x10 % 8));

        // IA32_FEATURE_CONTROL read+write
        ((PUCHAR)vcpu->msr_bitmap_va)[0x3A / 8] |= (UCHAR)(1 << (0x3A % 8));
        ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + 0x3A / 8] |= (UCHAR)(1 << (0x3A % 8));

        // VMX capability MSRs (0x480-0x493) read+write
        for (UINT32 msr_idx = 0x480; msr_idx <= 0x493; msr_idx++)
        {
            ((PUCHAR)vcpu->msr_bitmap_va)[msr_idx / 8] |= (UCHAR)(1 << (msr_idx % 8));
            ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + msr_idx / 8] |= (UCHAR)(1 << (msr_idx % 8));
        }

#if STEALTH_VIRTUALIZE_PMU
        {
            const UINT32 read_write_msrs[] = {
                IA32_MPERF, IA32_APERF, IA32_PERF_GLOBAL_CTRL
            };
            for (UINT32 bitmap_idx = 0;
                 bitmap_idx < RTL_NUMBER_OF(read_write_msrs);
                 bitmap_idx++)
            {
                UINT32 msr_idx = read_write_msrs[bitmap_idx];
                ((PUCHAR)vcpu->msr_bitmap_va)[msr_idx / 8] |=
                    (UCHAR)(1 << (msr_idx % 8));
                ((PUCHAR)vcpu->msr_bitmap_va)[0x800 + msr_idx / 8] |=
                    (UCHAR)(1 << (msr_idx % 8));
            }
        }
#endif
#if STEALTH_VIRTUALIZE_TIMERS
        ((PUCHAR)vcpu->msr_bitmap_va)[IA32_X2APIC_CUR_COUNT / 8] |=
            (UCHAR)(1 << (IA32_X2APIC_CUR_COUNT % 8));
#endif

        vcpu->msr_bitmap_pa = va_to_pa(
            (PVOID)vcpu->msr_bitmap_va);

        //
        // I/O Bitmap A (ports 0x0000 - 0x7FFF)
        //
        vcpu->io_bitmap_va_a = (UINT64)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_POOL_TAG);
        if (!vcpu->io_bitmap_va_a)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->io_bitmap_va_a, PAGE_SIZE);
        vcpu->io_bitmap_pa_a = va_to_pa(
            (PVOID)vcpu->io_bitmap_va_a);

        //
        // I/O Bitmap B (ports 0x8000 - 0xFFFF)
        //
        vcpu->io_bitmap_va_b = (UINT64)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_POOL_TAG);
        if (!vcpu->io_bitmap_va_b)
            return FALSE;
        RtlZeroMemory((PVOID)vcpu->io_bitmap_va_b, PAGE_SIZE);
        vcpu->io_bitmap_pa_b = va_to_pa(
            (PVOID)vcpu->io_bitmap_va_b);

        //
        // VMXON Region (pre-allocate at PASSIVE_LEVEL; VMXON runs per-core in DPC)
        //
        if (!vmx_alloc_vmxon(vcpu))
            return FALSE;

        //
        // VMCS Region (pre-allocate at PASSIVE_LEVEL; VMCLEAR/VMPTRLD in DPC)
        //
        if (!vmx_alloc_vmcs(vcpu))
            return FALSE;
    }

    if (!ept_setup_timer_hooks())
    {
        HV_LOG(0, 0, "[hv] Timer virtualization setup failed!\n");
        return FALSE;
    }

    protect_init();

    /*
     * Capture and allocate every per-core host GDT before cloning the host
     * page tables or freezing the conceal manifest.  vmx_setup_vmcs() runs
     * on the same core later and only validates/reuses this allocation.
     */
    if (!broadcast_prepare_host_state())
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        HV_LOG(0, 0, "[hv] Per-core host GDT preparation failed!\n");
        return FALSE;
    }

    //
    // build private host page tables AFTER all allocations are done.
    // The snapshot must include PTEs for VMM stacks, bitmaps, and all
    // other structures accessed in host mode. Building before allocations
    // would leave those VAs unmapped in host CR3 -> #PF -> double fault.
    //
#if USE_PRIVATE_HOST_CR3
    if (!hostcr3_build())
    {
        HV_LOG(0, 0, "[hv] Host CR3 build failed!\n");
        return FALSE;
    }
#endif

    //
    // private host IDT to prevent NMI hijacking. must be built before
    // broadcast_virtualize_all() so HOST_IDTR points to valid handlers.
    //
#if USE_PRIVATE_HOST_IDT
    if (!hostidt_build())
    {
        HV_LOG(0, 0, "[hv] Host IDT build failed!\n");
        return FALSE;
    }
#endif

    if (!root_transport_snapshot_metadata())
    {
        g_hv_capabilities.Failure = HV_FAILURE_ALLOCATION;
        return FALSE;
    }

#if STEALTH_CONCEAL_HOST_PAGES
    if (g_stealth_enabled &&
        !ept_conceal_prepare())
    {
        HV_LOG(
            0, 0,
            "[hv] Conceal manifest preparation failed: %u\n",
            g_hv_capabilities.Failure);
        return FALSE;
    }
#endif

    broadcast_virtualize_all();

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].launched)
        {
            HV_LOG(0, 0, "[hv] Core %u failed to launch; rolling back launched cores.\n", i);
            broadcast_terminate_initializing(FALSE);
            return FALSE;
        }
    }

    HV_LOG(0, 0, "[hv] All %u cores virtualized successfully!\n", g_cpu_count);
    if (!root_transport_mark_awaiting_bootstrap())
    {
        g_hv_capabilities.Failure =
            HV_FAILURE_REQUIRED_CONTROLS;
        broadcast_terminate_initializing(TRUE);
        return FALSE;
    }
#if STEALTH_CONCEAL_HOST_PAGES
#if !OPHION_PRODUCTION
    if (g_stealth_enabled)
    {
        if (!broadcast_conceal_invept())
        {
            HV_LOG(0, 0, "[hv] Conceal INVEPT failed\n");
            broadcast_terminate_initializing(TRUE);
            return FALSE;
        }
    }
#endif

    eac_stealth_apply();
#endif

    return TRUE;
}

BOOLEAN
vmx_all_stopped(VOID)
{
    VIRTUAL_MACHINE_STATE * vcpu_base =
        root_transport_vcpu_base();
    UINT32 processor_count =
        root_transport_processor_count();
    UINT32 i;

    if (!vcpu_base)
    {
        vcpu_base = g_vcpu;
        processor_count = g_cpu_count;
    }
    if (!vcpu_base)
        return TRUE;
    for (i = 0; i < processor_count; i++)
    {
        if (vcpu_base[i].vmxon_active ||
            vcpu_base[i].launched ||
            vcpu_base[i].in_root)
            return FALSE;
    }
    return TRUE;
}

VOID
vmx_terminate(VOID)
{
    VIRTUAL_MACHINE_STATE * vcpu_base =
        root_transport_vcpu_base();
    UINT32 processor_count =
        root_transport_processor_count();

    if (!vcpu_base)
    {
        vcpu_base = g_vcpu;
        processor_count = g_cpu_count;
    }
    if (!vcpu_base)
        return;
    if (!vmx_all_stopped())
    {
        HV_LOG(0, 0,
            "[hv] Refusing to free live VMX resources; a vCPU is still active\n");
        return;
    }


    ept_destroy_timer_hooks();
    ept_conceal_destroy();

    ept_destroy_splits();

    for (UINT32 i = 0; i < processor_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &vcpu_base[i];

        //
        // free per-VCPU resources.
        // note: broadcast_terminate_all() must be called before this
        // to VMCALL(VMXOFF) on each core and exit VMX operation.
        //

        if (vcpu->vmxon_va)
            MmFreeContiguousMemory((PVOID)vcpu->vmxon_va);
        if (vcpu->vmcs_va)
            MmFreeContiguousMemory((PVOID)vcpu->vmcs_va);
        if (vcpu->vmm_stack)
            ExFreePoolWithTag((PVOID)vcpu->vmm_stack, HV_POOL_TAG);
        if (vcpu->msr_bitmap_va)
            ExFreePoolWithTag((PVOID)vcpu->msr_bitmap_va, HV_POOL_TAG);
        if (vcpu->io_bitmap_va_a)
            ExFreePoolWithTag((PVOID)vcpu->io_bitmap_va_a, HV_POOL_TAG);
        if (vcpu->io_bitmap_va_b)
            ExFreePoolWithTag((PVOID)vcpu->io_bitmap_va_b, HV_POOL_TAG);
    }

    protect_destroy();

    if (g_ept)
    {
        for (UINT32 i = 0; i < processor_count; i++)
        {
            if (vcpu_base[i].ept_page_table)
                MmFreeContiguousMemory(vcpu_base[i].ept_page_table);
        }
        MmFreeContiguousMemory(g_ept);
        g_ept = NULL;
    }

#if USE_PRIVATE_HOST_CR3
    hostcr3_destroy();
#endif

#if USE_PRIVATE_HOST_IDT
    hostidt_destroy();
#endif

#if USE_PRIVATE_HOST_GDT
    for (UINT32 i = 0; i < processor_count; i++)
    {
        hostgdt_destroy_for_vcpu(&vcpu_base[i]);
    }
#endif

    ExFreePoolWithTag(vcpu_base, HV_POOL_TAG);
    g_vcpu = NULL;
    root_transport_release_metadata();

    HV_LOG(0, 0, "[hv] VMX terminated on all cores.\n");
}
