/*
*   vmx.c - vmx initialization, vmcs setup, and vmx lifecycle management
*   this is the core of the hypervisor. handles vmxon, vmcs allocation,
*   full vmcs field programming, and vmlaunch
*/
#include "hv.h"

/*
*   get current processor id without windows apis
*   ia32_tsc_aux (0xc0000103) is set by the os to the processor number
*   safe to call in vmx-root mode. lower 12 bits = processor number
*/
static __forceinline UINT32
vmx_get_cpu_id(VOID)
{
    return (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
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
    if (__vmx_vmclear(&vcpu->vmcs_pa))
    {
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (__vmx_vmptrld(&vcpu->vmcs_pa))
        return FALSE;
    return TRUE;
}

BOOLEAN
vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack)
{
    UINT32                  pri_proc;
    UINT32                  sec_proc;
    UINT64                  gdt_base;
    IA32_VMX_BASIC_REGISTER vmx_basic     = {0};
    VMX_SEGMENT_SELECTOR    seg_sel = {0};

    vmx_basic.AsUInt = __readmsr(IA32_VMX_BASIC);

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

    segment_fill_vmcs((PVOID)gdt_base, ES,   asm_get_es());
    segment_fill_vmcs((PVOID)gdt_base, CS,   asm_get_cs());
    segment_fill_vmcs((PVOID)gdt_base, SS,   asm_get_ss());
    segment_fill_vmcs((PVOID)gdt_base, DS,   asm_get_ds());
    segment_fill_vmcs((PVOID)gdt_base, FS,   asm_get_fs());
    segment_fill_vmcs((PVOID)gdt_base, GS,   asm_get_gs());
    segment_fill_vmcs((PVOID)gdt_base, LDTR, asm_get_ldtr());
    segment_fill_vmcs((PVOID)gdt_base, TR,   asm_get_tr());

    __vmx_vmwrite(VMCS_GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
    __vmx_vmwrite(VMCS_GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

    pri_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING |
        CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS |
        CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pri_proc);

    vcpu->mov_dr_exiting = !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING);

    DbgPrintEx(0, 0, "[hv] Primary proc controls: 0x%08X (CR3load=%d CR3store=%d INVLPG=%d HLT=%d RDTSC=%d MOVDR=%d TSCoff=%d)\n",
             pri_proc,
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_CR3_STORE_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_INVLPG_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_HLT_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING),
             !!(pri_proc & CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING));

    sec_proc = vmx_adjust_controls(
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID |
        CPU_BASED_VM_EXEC_CTRL2_RDTSCP |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_INVPCID |
        CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES,
        IA32_VMX_PROCBASED_CTLS2);

    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, sec_proc);

    UINT32 pin_ctrl = vmx_adjust_controls(
        PIN_BASED_VM_EXEC_CTRL_NMI_EXITING |
        PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS);

    //
    // SDM: "virtual NMIs" requires "NMI exiting" — some nested VMX
    // implementations (Hyper-V) don't advertise NMI exiting in the
    // capability MSR's allowed-1 set despite supporting it.
    // Force the constraint; if truly unsupported, VMLAUNCH will fail
    // with a clear error rather than the cryptic VirtNMI-without-NMI.
    //
    if (pin_ctrl & PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI)
        pin_ctrl |= PIN_BASED_VM_EXEC_CTRL_NMI_EXITING;

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin_ctrl);

    DbgPrintEx(0, 0, "[hv] Pin controls: 0x%08X (ExtInt=%d NMI=%d VirtNMI=%d Preempt=%d)\n",
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
    UINT32 exit_ctrl = vmx_adjust_controls(
        VM_EXIT_CTRL_HOST_ADDRESS_SPACE_SIZE |
        VM_EXIT_CTRL_SAVE_DEBUG_CONTROLS |
        VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT,
        vmx_basic.VmxControls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS);

    __vmx_vmwrite(VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS, exit_ctrl);

    DbgPrintEx(0, 0, "[hv] Exit controls: 0x%08X (AckInt=%d)\n",
             exit_ctrl, !!(exit_ctrl & VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT));

    //
    // IA-32e mode guest, load debug controls
    // required so guest sees its own DR7 after VM-exit/entry cycle
    //
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS,
                  vmx_adjust_controls(
                      VM_ENTRY_CTRL_IA32E_MODE_GUEST |
                      VM_ENTRY_CTRL_LOAD_DEBUG_CONTROLS,
                      vmx_basic.VmxControls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS));

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
    __vmx_vmwrite(VMCS_HOST_CR3, get_system_cr3());
#endif

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,  asm_get_gdt_base());
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, asm_get_gdt_limit());
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,  asm_get_idt_base());
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, asm_get_idt_limit());
    __vmx_vmwrite(VMCS_GUEST_RFLAGS,     asm_get_rflags());

    __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS,  __readmsr(IA32_SYSENTER_CS));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));

    //
    // host GDT and IDT — use current OS ones (simplest approach)
    //
    segment_get_descriptor((PUCHAR)asm_get_gdt_base(), asm_get_tr(), &seg_sel);
    __vmx_vmwrite(VMCS_HOST_TR_BASE,    seg_sel.Base);
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE,  asm_get_gdt_base());
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE,  asm_get_idt_base());

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

    return TRUE;
}

/*
*   called per-core via dpc — sets up vmx, enters vmx operation, launches
*   memory for vmxon/vmcs regions is pre-allocated in vmx_init
*   this function runs at dispatch_level and performs the vmx instructions
*/
BOOLEAN
vmx_virtualize_cpu(PVOID guest_stack)
{
    ULONG                   core = KeGetCurrentProcessorNumberEx(NULL);
    VIRTUAL_MACHINE_STATE * vcpu        = &g_vcpu[core];
    UINT64                  error_code   = 0;

    vcpu->core_id = core;

    asm_enable_vmx();
    vmx_set_fixed_bits();

    if (__vmx_on(&vcpu->vmxon_pa))
    {
        DbgPrintEx(0, 0, "[hv] VMXON failed on core %u\n", core);
        return FALSE;
    }

    if (!vmx_clear_vmcs(vcpu))
        return FALSE;

    if (!vmx_load_vmcs(vcpu))
        return FALSE;

    vmx_setup_vmcs(vcpu, guest_stack);

    vcpu->launched = TRUE;

    __vmx_vmlaunch();

    //
    // if we reach here, VMLAUNCH failed
    //
    vcpu->launched = FALSE;
    __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code);
    __vmx_off();

    DbgPrintEx(0, 0, "[hv] VMLAUNCH failed on core %u, error: 0x%llx\n", core, error_code);
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
    __vmx_off();

    DbgPrintEx(0, 0, "[hv] VMRESUME failed! Error: 0x%llx\n", error_code);
}

BOOLEAN
vmx_init(VOID)
{
    g_cpu_count = KeQueryActiveProcessorCount(0);

    g_vcpu = (VIRTUAL_MACHINE_STATE *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count, HV_POOL_TAG);

    if (!g_vcpu)
        return FALSE;

    RtlZeroMemory(g_vcpu, sizeof(VIRTUAL_MACHINE_STATE) * g_cpu_count);

    if (!vmx_check_support())
    {
        DbgPrintEx(0, 0, "[hv] VMX not supported!\n");
        return FALSE;
    }

    //
    // initialize stealth CPUID cache — MUST be before VMXON
    // this captures bare-metal CPUID responses for invalid leaves
    // so we can return consistent values when virtualizing.
    //
#if STEALTH_CPUID_CACHING
    stealth_init_cpuid_cache();
#endif

    if (!ept_init())
    {
        DbgPrintEx(0, 0, "[hv] EPT initialization failed!\n");
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

    //
    // build private host page tables AFTER all allocations are done.
    // The snapshot must include PTEs for VMM stacks, bitmaps, and all
    // other structures accessed in host mode. Building before allocations
    // would leave those VAs unmapped in host CR3 -> #PF -> double fault.
    //
#if USE_PRIVATE_HOST_CR3
    if (!hostcr3_build())
    {
        DbgPrintEx(0, 0, "[hv] Host CR3 build failed!\n");
        return FALSE;
    }
#endif

    broadcast_virtualize_all();

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].launched)
        {
            DbgPrintEx(0, 0, "[hv] Core %u failed to launch!\n", i);
            return FALSE;
        }
    }

    DbgPrintEx(0, 0, "[hv] All %u cores virtualized successfully!\n", g_cpu_count);
    return TRUE;
}

VOID
vmx_terminate(VOID)
{
    if (!g_vcpu)
        return;

    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        VIRTUAL_MACHINE_STATE * vcpu = &g_vcpu[i];

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

    if (g_ept)
    {
        for (UINT32 i = 0; i < g_cpu_count; i++)
        {
            if (g_vcpu[i].ept_page_table)
                MmFreeContiguousMemory(g_vcpu[i].ept_page_table);
        }
        ExFreePoolWithTag(g_ept, HV_POOL_TAG);
        g_ept = NULL;
    }

#if USE_PRIVATE_HOST_CR3
    hostcr3_destroy();
#endif

    ExFreePoolWithTag(g_vcpu, HV_POOL_TAG);
    g_vcpu = NULL;

    DbgPrintEx(0, 0, "[hv] VMX terminated on all cores.\n");
}
