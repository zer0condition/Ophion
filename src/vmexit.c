/*
*   vmexit.c - vm-exit handler dispatches exits to sub-handlers
*/
#include "hv.h"
static VOID vmexit_enter_terminal(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT32 failure);


static __forceinline VOID
vmexit_advance_rip(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 instr_len = 0;
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

    UINT64 new_rip = vcpu->vmexit_rip + instr_len;

    //
    // truncate RIP for non-64-bit segments (compatibility mode)
    // CS.L=0 CS.D=1 -> 32-bit, CS.L=0 CS.D=0 -> 16-bit
    //
    size_t cs_ar_raw = 0;
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar_raw);
    if (!((cs_ar_raw >> 13) & 1))
    {
        if ((cs_ar_raw >> 14) & 1)
            new_rip = (UINT32)new_rip;
        else
            new_rip = (UINT16)new_rip;
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, new_rip);

    // clear STI/MOV-SS blocking
    size_t intr_state = 0;
    __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
    if (intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS))
    {
        intr_state &= ~(size_t)(GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS);
        __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
    }

    // single-step + hardware breakpoint handling
    size_t rflags_raw = 0;
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);

    UINT64 pending = 0;
    __vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pending);

    BOOLEAN need_bs = FALSE;
    if (rflags_raw & RFLAGS_TF)
    {
        size_t debugctl_raw = 0;
        __vmx_vmread(VMCS_GUEST_DEBUGCTL, &debugctl_raw);
        if (!(debugctl_raw & DEBUGCTL_BTF))
            need_bs = TRUE;
    }

    UINT64 dr7 = 0;
    __vmx_vmread(VMCS_GUEST_DR7, &dr7);

    static const UINT64 ln_bits[] = { DR7_L0, DR7_L1, DR7_L2, DR7_L3 };
    static const UINT64 gn_bits[] = { DR7_G0, DR7_G1, DR7_G2, DR7_G3 };
    static const UINT64 bn_bits[] = { PENDING_DEBUG_B0, PENDING_DEBUG_B1, PENDING_DEBUG_B2, PENDING_DEBUG_B3 };

    UINT64 bp_matched = 0;
    for (int i = 0; i < 4; i++)
    {
        if (!(dr7 & (ln_bits[i] | gn_bits[i])))
            continue;
        if ((dr7 & DR7_RW_MASK(i)) != 0)
            continue;

        UINT64 drn;
        switch (i)
        {
        case 0: drn = vcpu->guest_dr0; break;
        case 1: drn = vcpu->guest_dr1; break;
        case 2: drn = vcpu->guest_dr2; break;
        case 3: drn = vcpu->guest_dr3; break;
        default: continue;
        }

        if (drn == new_rip)
            bp_matched |= bn_bits[i];
    }

    if (need_bs || bp_matched)
    {
        if (need_bs)
            pending |= PENDING_DEBUG_BS;
        if (bp_matched)
            pending |= bp_matched | PENDING_DEBUG_ENABLED_BP;
        __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, pending);
    }
}

//
// exception classification for double-fault generation (SDM Vol 3 Table 6-5)
//
// contributory: #DE(0), #TS(10), #NP(11), #SS(12), #GP(13)
// page fault:   #PF(14)
// double fault: #DF(8)
// everything else: benign
//

typedef enum {
    EXCEPTION_CLASS_BENIGN,
    EXCEPTION_CLASS_CONTRIBUTORY,
    EXCEPTION_CLASS_PAGE_FAULT,
    EXCEPTION_CLASS_DOUBLE_FAULT
} EXCEPTION_CLASS;

static __forceinline EXCEPTION_CLASS
classify_exception(UINT32 vector)
{
    switch (vector)
    {
    case EXCEPTION_VECTOR_DIVIDE_ERROR:
    case EXCEPTION_VECTOR_INVALID_TSS:
    case EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case EXCEPTION_VECTOR_GENERAL_PROTECTION:
        return EXCEPTION_CLASS_CONTRIBUTORY;
    case EXCEPTION_VECTOR_PAGE_FAULT:
        return EXCEPTION_CLASS_PAGE_FAULT;
    case EXCEPTION_VECTOR_DOUBLE_FAULT:
        return EXCEPTION_CLASS_DOUBLE_FAULT;
    default:
        return EXCEPTION_CLASS_BENIGN;
    }
}

static __forceinline BOOLEAN
should_generate_df(UINT32 first_vector, UINT32 second_vector)
{
    EXCEPTION_CLASS first  = classify_exception(first_vector);
    EXCEPTION_CLASS second = classify_exception(second_vector);

    // contributory + contributory = #DF
    if (first == EXCEPTION_CLASS_CONTRIBUTORY && second == EXCEPTION_CLASS_CONTRIBUTORY)
        return TRUE;

    // PF + contributory or PF + PF = #DF
    if (first == EXCEPTION_CLASS_PAGE_FAULT &&
        (second == EXCEPTION_CLASS_CONTRIBUTORY || second == EXCEPTION_CLASS_PAGE_FAULT))
        return TRUE;

    return FALSE;
}

static __forceinline UINT64
pmu_width_mask(UINT8 width)
{
    if (width >= 64)
        return MAXULONG64;
    if (!width)
        return 0;
    return (1ULL << width) - 1;
}

static __forceinline UINT64
pmu_global_control_mask(const VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 gp_mask = vcpu->pmu_gp_count >= 32
        ? 0xFFFFFFFFULL
        : ((1ULL << vcpu->pmu_gp_count) - 1);
    UINT64 fixed_mask = (vcpu->pmu_fixed_count >= 32
        ? 0xFFFFFFFFULL
        : ((1ULL << vcpu->pmu_fixed_count) - 1)) |
        vcpu->pmu_fixed_bitmap;

    return gp_mask | (fixed_mask << 32);
}

static BOOLEAN
pmu_guest_can_read(VOID)
{
    size_t guest_cr0 = 0;
    size_t guest_cr4 = 0;
    size_t guest_cs_ar = 0;

    __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
    if (!(guest_cr0 & 1))
        return TRUE;

    __vmx_vmread(VMCS_GUEST_CR4, &guest_cr4);
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &guest_cs_ar);
    return (((guest_cs_ar >> 5) & 3) == 0) ||
           ((guest_cr4 & CR4_PERFORMANCE_MONITOR_COUNTER_ENABLE) != 0);
}

static BOOLEAN
parent_hyperv_msr_supported(UINT32 msr, BOOLEAN write)
{
    UINT32 features = g_stealth_cpuid_cache.parent_hyperv_features;

    if (!g_stealth_cpuid_cache.parent_is_hyperv)
        return FALSE;

    switch (msr)
    {
    case 0x40000000:
    case 0x40000001:
        return (features & (1U << 5)) != 0;
    case 0x40000002:
        return !write && (features & (1U << 6));
    case 0x40000003:
        return write && (features & (1U << 7));
    case 0x40000010:
        return !write && (features & (1U << 0));
    case 0x40000020:
        return !write && (features & (1U << 1));
    case 0x40000021:
        return (features & (1U << 9)) != 0;
    case 0x40000022:
    case 0x40000023:
        return !write && (features & (1U << 11));
    case 0x40000070:
        return write && (features & (1U << 4));
    case 0x40000071:
    case 0x40000072:
    case 0x40000073:
        return (features & (1U << 4)) != 0;
    case 0x40000080:
    case 0x40000082:
    case 0x40000083:
        return (features & (1U << 2)) != 0;
    case 0x40000081:
        return !write && (features & (1U << 2));
    case 0x40000084:
        return write && (features & (1U << 2));
    case 0x400000F0:
        return write && (features & (1U << 10));
    default:
        if (msr >= 0x40000090 && msr <= 0x4000009F)
            return (features & (1U << 2)) != 0;
        if (msr >= 0x400000B0 && msr <= 0x400000B7)
            return (features & (1U << 3)) != 0;
        return FALSE;
    }
}

static BOOLEAN
vmexit_sync_dynamic_exiting(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 controls = 0;
    UINT64 next;
    const UINT64 mask =
        CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING |
        CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;

    if (!vmx_vmread_checked(
            vcpu,
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &controls))
        return FALSE;

    next = (controls & ~mask) |
           (vcpu->primary_dynamic_forced & mask);

    if (vcpu->protect_cr3_exiting || vcpu->tsc_rdtsc_armed)
        next |= CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING;
    if (vcpu->tsc_rdtsc_armed)
        next |= CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;

    return next == controls ||
           vmx_vmwrite_checked(
               vcpu,
               VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
               next);
}


#define VMXOFF_SAVED_RFLAGS_OFFSET 0x190
#define VMXOFF_RETURN_RSP_OFFSET   0x1A0

static BOOLEAN
vmexit_leave_vmx(VIRTUAL_MACHINE_STATE * vcpu, UINT64 return_rip, BOOLEAN handoff)
{
    UINT64 guest_rsp = 0;
    UINT64 guest_rflags = 0;
    UINT64 guest_cr0 = 0;
    UINT64 guest_cr3 = 0;
    UINT64 guest_cr4 = 0;
    UINT64 guest_dr7 = 0;
    UINT64 guest_debugctl = 0;
    UINT64 guest_fs_base = 0;
    UINT64 guest_gs_base = 0;
    UINT64 guest_perf = 0;

    __vmx_vmread(VMCS_GUEST_RSP, &guest_rsp);
    __vmx_vmread(VMCS_GUEST_RFLAGS, &guest_rflags);
    __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
    __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
    __vmx_vmread(VMCS_GUEST_CR4, &guest_cr4);
    __vmx_vmread(VMCS_GUEST_DR7, &guest_dr7);
    __vmx_vmread(VMCS_GUEST_DEBUGCTL, &guest_debugctl);
    __vmx_vmread(VMCS_GUEST_FS_BASE, &guest_fs_base);
    __vmx_vmread(VMCS_GUEST_GS_BASE, &guest_gs_base);
    if (vcpu->pmu_isolated)
        __vmx_vmread(VMCS_GUEST_PERF_GLOBAL_CTRL, &guest_perf);

    vcpu->vmxoff.guest_rip = return_rip;
    vcpu->vmxoff.guest_rsp = guest_rsp;
    vcpu->vmxoff.guest_cr3 = guest_cr3;
    vcpu->vmxoff.handoff = handoff;

    *(UINT64 *)(guest_rsp - sizeof(UINT64)) = return_rip;
    *(UINT64 *)((PUCHAR)vcpu->regs + VMXOFF_SAVED_RFLAGS_OFFSET) = guest_rflags;
    *(UINT64 *)((PUCHAR)vcpu->regs + VMXOFF_RETURN_RSP_OFFSET) =
        guest_rsp - sizeof(UINT64);

    _InterlockedIncrement(&g_vmxoff_transition_count);
    if (asm_vmxoff_checked() != 0)
    {
        _InterlockedDecrement(&g_vmxoff_transition_count);
        vcpu->failed = TRUE;
        vcpu->last_failure = HV_FAILURE_VM_ENTRY;
        return FALSE;
    }
    vcpu->vmxon_active = FALSE;
    vcpu->launched = FALSE;
    vcpu->detached = handoff;

    __writecr3(guest_cr3);

#if USE_PRIVATE_HOST_IDT
    if (g_host_idt.initialized)
        asm_reload_idtr((PVOID)g_host_idt.original_idt_base,
                        IDT_NUM_ENTRIES * sizeof(IDT_GATE_DESCRIPTOR_64) - 1);
#endif
    _InterlockedDecrement(&g_vmxoff_transition_count);

#if USE_PRIVATE_HOST_GDT
    if (vcpu->host_gdt)
    {
        PSEGMENT_DESCRIPTOR_64 tss_desc = (PSEGMENT_DESCRIPTOR_64)(
            vcpu->original_gdt_base + (vcpu->original_tr_selector & ~0x7));
        tss_desc->Type = TSS_TYPE_AVAILABLE_64;
        asm_reload_gdtr((PVOID)vcpu->original_gdt_base,
                        (UINT32)vcpu->original_gdt_limit);
        asm_reload_tr(vcpu->original_tr_selector);
    }
#endif

    if (vcpu->pmu_isolated)
        __writemsr(IA32_PERF_GLOBAL_CTRL, guest_perf);
    __writemsr(IA32_DEBUGCTL, guest_debugctl);
    __writemsr(IA32_FS_BASE, guest_fs_base);
    __writemsr(IA32_GS_BASE, guest_gs_base);
    __writedr(7, guest_dr7);
    __writecr0(guest_cr0);
    if (handoff)
        guest_cr4 |= CR4_VMX_ENABLE_FLAG;
    else
        guest_cr4 &= ~CR4_VMX_ENABLE_FLAG;
    __writecr4(guest_cr4);

    vcpu->vmxoff.executed = TRUE;
    return TRUE;
}

//
// Defeats:
//   - compare CPUID(0x04201337) vs CPUID(0x40000000)
//   - CPUID(max_leaf) vs CPUID(0x40000000)
//   - CPUID.1.ECX[31] hypervisor present bit
//   - CPUID subleaf handling
//   - some more
//
// Strategy:
//   before VMXON, we cache what the real CPU returns for an out-of-range leaf.
//   during VM-exit, if the guest queries an invalid/hypervisor leaf, we return
//   the cached response — identical to what bare metal would return.
//   for leaf 1, we clear ECX[31] (hypervisor present bit).
//

VOID
vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu)
{
    INT32       cpu_info[4] = {0};
    PGUEST_REGS regs       = vcpu->regs;
    UINT32      leaf       = (UINT32)regs->rax;
    UINT32      subleaf    = (UINT32)regs->rcx;

#if STEALTH_CPUID_CACHING
    //
    // if stealth is enabled and this leaf is invalid/out-of-range,
    // return the cached bare-metal response for perfect consistency.
    // on real hardware, CPUID(0x40000000) == CPUID(0x04201337) == CPUID(max+1)
    //
    if (g_stealth_enabled &&
        !g_stealth_cpuid_cache.parent_hypervisor_present &&
        stealth_is_leaf_invalid(leaf))
    {
        cpu_info[0] = g_stealth_cpuid_cache.invalid_leaf[0];
        cpu_info[1] = g_stealth_cpuid_cache.invalid_leaf[1];
        cpu_info[2] = g_stealth_cpuid_cache.invalid_leaf[2];
        cpu_info[3] = g_stealth_cpuid_cache.invalid_leaf[3];
    }
    else
#endif
    {
        __cpuidex(cpu_info, (int)leaf, (int)subleaf);

        //
        // On bare metal Ophion hides only the hypervisor-present bit. VMX and
        // every unrelated hardware feature remain native and coherent with
        // IA32_FEATURE_CONTROL/IA32_VMX_* reporting.
        if (leaf == CPUID_PROCESSOR_FEATURES && g_stealth_enabled &&
            !g_stealth_cpuid_cache.parent_hypervisor_present)
        {
            cpu_info[2] &= ~(INT32)HYPERV_HYPERVISOR_PRESENT_BIT;
        }

        // If nested VMX does not expose the user-wait control, do not let
        // Windows select WAITPKG instructions that cannot execute in-guest.
        if (leaf == 7 && !vcpu->waitpkg_enabled)
            cpu_info[2] &= ~(1 << 5);
    }

    regs->rax = (UINT64)(UINT32)cpu_info[0];
    regs->rbx = (UINT64)(UINT32)cpu_info[1];
    regs->rcx = (UINT64)(UINT32)cpu_info[2];
    regs->rdx = (UINT64)(UINT32)cpu_info[3];
}

//
// Defeats:
//   - MSRs 0x40000000+ must #GP like bare metal
//   - IA32_FEATURE_CONTROL must hide VMX/SMX enables
//

VOID
vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    //
    // hypervisor synthetic MSRs (0x40000000+) — inject #GP on bare metal
    // this includes Hyper-V (0x40000000-0x400000FF) and KVM (0x4b564d00-02) MSRs
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        if (parent_hyperv_msr_supported(target_msr, FALSE))
        {
            msr.Flags = __readmsr(target_msr);
            regs->rax = msr.Fields.Low;
            regs->rdx = msr.Fields.High;
        }
        else
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        return;
    }

    //
    // only service MSRs in valid architectural ranges
    //
    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmread(VMCS_GUEST_SYSENTER_CS, &msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_ESP, &msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_EIP, &msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmread(VMCS_GUEST_GS_BASE, &msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmread(VMCS_GUEST_FS_BASE, &msr.Flags);
            break;

        //
        // IA32_TIME_STAMP_COUNTER (MSR 0x10)
        //
        // intercepted via MSR bitmap. in the handler, __rdtsc() returns raw
        // hardware TSC (no offset in VMX root), so we apply TSC_OFFSET manually.
        // per SDM 27.6.5, "use TSC offsetting" applies the same offset to RDTSC,
        // RDTSCP, and RDMSR of this MSR — interception is only needed so the
        // TSC compensation path can also cover RDMSR-based timing attacks.
        //
        case 0x10:
        {
            if (g_stealth_enabled)
            {
                size_t tsc_offset_raw = 0;
                __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_offset_raw);
                msr.Flags = (UINT64)(
                    (INT64)vcpu->root_tsc_entry + (INT64)tsc_offset_raw);
            }
            else
            {
                msr.Flags = __rdtsc();
            }
            break;
        }

        case IA32_FEATURE_CONTROL:
            msr.Flags = __readmsr(IA32_FEATURE_CONTROL);
            break;

        case IA32_APERF:
            if (!vcpu->aperf_mperf_supported)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            msr.Flags = vcpu->aperf_root_entry -
                        vcpu->aperf_root_bias +
                        vcpu->aperf_guest_offset;
            break;

        case IA32_MPERF:
            if (!vcpu->aperf_mperf_supported)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            msr.Flags = vcpu->mperf_root_entry -
                        vcpu->mperf_root_bias +
                        vcpu->mperf_guest_offset;
            break;

        case IA32_PERF_GLOBAL_CTRL:
            if (!vcpu->pmu_gp_count)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            msr.Flags = vcpu->perf_global_ctrl;
            break;

        case IA32_X2APIC_CUR_COUNT:
        {
            UINT64 apic_base = __readmsr(IA32_APIC_BASE);
            vcpu->x2apic_enabled =
                (apic_base & IA32_APIC_BASE_ENABLE) != 0 &&
                (apic_base & IA32_APIC_BASE_X2APIC) != 0;
            if (vcpu->x2apic_enabled)
            {
                UINT32 raw = (UINT32)__readmsr(IA32_X2APIC_CUR_COUNT);
                UINT32 initial = (UINT32)__readmsr(IA32_X2APIC_INIT_COUNT);
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
                    vcpu->timer_bias_pending = FALSE;
                }
                msr.Flags = adjusted > initial ? initial : adjusted;
                break;
            }
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }

        default:
            //
            // VMX capability MSRs (0x480-0x493) — always readable on VMX-capable
            // CPUs regardless of FEATURE_CONTROL lock state. return real values
            // to match bare-metal behavior for stealth.
            //
            if (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493)
            {
                msr.Flags = __readmsr(target_msr);
                break;
            }

            //
            // unhandled — never forward to hardware in VMX-root, would #GP
            // and hit our private IDT halt handler. inject #GP(0) to guest.
            //
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }

        regs->rax = (UINT64)msr.Fields.Low;
        regs->rdx = (UINT64)msr.Fields.High;
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

VOID
vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    msr.Fields.Low  = (ULONG)regs->rax;
    msr.Fields.High = (ULONG)regs->rdx;

    //
    // hypervisor synthetic MSRs — inject #GP
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        if (parent_hyperv_msr_supported(target_msr, TRUE))
        {
            __writemsr(target_msr, msr.Flags);
        }
        else
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        return;
    }

    // IA32_FEATURE_CONTROL (locked) + VMX capability MSRs (read-only)
    if (target_msr == IA32_FEATURE_CONTROL ||
        (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmwrite(VMCS_GUEST_GS_BASE, msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmwrite(VMCS_GUEST_FS_BASE, msr.Flags);
            break;

        case IA32_APERF:
            if (!vcpu->aperf_mperf_supported)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            vcpu->aperf_guest_offset =
                msr.Flags - (vcpu->aperf_root_entry - vcpu->aperf_root_bias);
            break;

        case IA32_MPERF:
            if (!vcpu->aperf_mperf_supported)
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            vcpu->mperf_guest_offset =
                msr.Flags - (vcpu->mperf_root_entry - vcpu->mperf_root_bias);
            break;

        case IA32_PERF_GLOBAL_CTRL:
            if (!vcpu->pmu_version ||
                (msr.Flags & ~pmu_global_control_mask(vcpu)))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                return;
            }
            vcpu->perf_global_ctrl = msr.Flags;
            if (vcpu->pmu_isolated)
                __vmx_vmwrite(VMCS_GUEST_PERF_GLOBAL_CTRL, msr.Flags);
            break;

        default:
            //
            // unhandled — never forward to hardware in VMX-root, would #GP
            // and hit our private IDT halt handler. inject #GP(0) to guest.
            //
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

//
// Defeats: hvdetecc vm.vmxe (checks if CR4 bit 13 is set)
//
//   CR4 guest/host mask has bit 13 set, so guest reads CR4 with VMXE
//   from the read shadow (where it's 0). Guest writes to CR4 that change
//   masked bits cause a VM-exit, which we handle here by keeping VMXE=1
//   in the actual VMCS guest CR4 while the shadow shows VMXE=0.
//

VOID
vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu)
{
    VMX_EXIT_QUALIFICATION_MOV_CR cr_qual;
    PGUEST_REGS                   regs = vcpu->regs;
    UINT64 *                      reg_ptr;

    cr_qual.AsUInt = vcpu->exit_qual;

    switch (cr_qual.GeneralPurposeRegister)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    switch (cr_qual.AccessType)
    {
    case 0: // MOV to CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 0:
        {
            //
            // MOV to CR0: enforce VMX fixed bits to prevent VM-entry failure.
            // shadow gets the guest's requested value so reads return what the
            // guest wrote (host-owned bits come from shadow, not actual CR0).
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;
            UINT64  actual = desired;

            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
            actual |= fixed.Fields.Low;
            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
            actual &= fixed.Fields.Low;

            __vmx_vmwrite(VMCS_GUEST_CR0, actual);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, desired);
            break;
        }

        case 3:
        {
            UINT64 new_cr3 = *reg_ptr;
            UINT64 guest_cr4 = 0;
            UINT64 addr;
            UINT64 high_mask;
            UINT64 pcid = new_cr3 & 0xFFFULL;
            UINT32 phys_bits =
                root_transport_physical_address_bits();
            BOOLEAN pcide;
            BOOLEAN no_flush = (new_cr3 >> 63) & 1;

            if (!phys_bits)
                phys_bits = 52;

            __vmx_vmread(VMCS_GUEST_CR4, &guest_cr4);
            pcide = (guest_cr4 & (1ULL << 17)) != 0;
            addr = new_cr3 & 0x7FFFFFFFFFFFF000ULL;
            high_mask = phys_bits < 63
                ? (~((1ULL << phys_bits) - 1ULL) &
                   0x7FFFFFFFFFFFF000ULL)
                : 0;

            if ((addr & high_mask) ||
                (!pcide && (no_flush || (pcid & ~0x18ULL))) ||
                (pcide && no_flush && pcid == 0))
            {
                vmexit_inject_gp();
                vcpu->advance_rip = FALSE;
                break;
            }

            __vmx_vmwrite(
                VMCS_GUEST_CR3,
                new_cr3 & ~(1ULL << 63));
            protect_on_cr3_load(
                vcpu,
                new_cr3 & ~(1ULL << 63));
            if (vcpu->terminal)
                break;

            if (!no_flush && vcpu->vpid_enabled)
            {
                INVVPID_DESCRIPTOR desc = {0};
                UINT8 ret = 1;
                desc.Vpid = VPID_TAG;

                if (g_ept->invvpid_single_retaining_globals)
                    ret = asm_invvpid(
                        InvvpidSingleContextRetainingGlobals,
                        &desc);
                if (ret != 0 &&
                    g_ept->invvpid_single_context)
                    ret = asm_invvpid(
                        InvvpidSingleContext,
                        &desc);
                if (ret != 0 &&
                    g_ept->invvpid_all_contexts)
                    ret = asm_invvpid(
                        InvvpidAllContexts,
                        &desc);
                if (ret != 0)
                {
                    vcpu->failed = TRUE;
                    vcpu->terminal = TRUE;
                    vcpu->last_failure = HV_FAILURE_INVVPID;
                    vcpu->advance_rip = FALSE;
                }
            }
            break;
        }

        case 8:
            //
            // MOV to CR8 (TPR): pass through directly
            // only bits [3:0] are valid. required when cr8-load exiting
            // is forced by must-be-1 bits
            //
            vcpu->guest_cr8 = (UINT8)(*reg_ptr & 0xF);
            __writecr8(vcpu->guest_cr8);
            break;

        case 4:
        {
            //
            // MOV to CR4: enforce VMX fixed bits + stealth VMXE hiding.
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;

#if STEALTH_HIDE_CR4_VMXE
            if (g_stealth_enabled)
            {
                UINT64 actual = desired | CR4_VMX_ENABLE_FLAG;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired);
            }
            else
#endif
            {
                UINT64 actual = desired;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired);
            }
            break;
        }

        default:
            break;
        }
        break;
    }
    case 1: // MOV from CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 3:
            __vmx_vmread(VMCS_GUEST_CR3, reg_ptr);
            break;

        case 8:
            *reg_ptr = vcpu->guest_cr8;
            break;

        default:
            break;
        }
        break;
    }
    case 2: // CLTS — clear CR0.TS (bit 3)
    {
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        guest_cr0 &= ~(1ULL << 3);
        shadow    &= ~(1ULL << 3);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    case 3: // LMSW — load machine status word (bits 0-3 of CR0)
    {
        //
        // LMSW loads PE, MP, EM, TS from source data in exit qualification.
        // PE (bit 0) can be set but NOT cleared by LMSW (Intel SDM Vol 2).
        //
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;
        UINT64  src       = (UINT64)(UINT16)cr_qual.LmswSourceData & 0xFULL;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        //
        // Bits 1-3 (MP, EM, TS): loaded from source
        // Bit 0 (PE): can be set, never cleared — OR with current value
        //
        guest_cr0 = (guest_cr0 & ~0xEULL) | (src & 0xEULL) | ((guest_cr0 | src) & 1ULL);
        shadow    = (shadow    & ~0xEULL) | (src & 0xEULL) | ((shadow    | src) & 1ULL);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    default:
        break;
    }
}

VOID
vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 guest_phys = 0;
    if (!vmx_vmread_checked(
            vcpu, VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys))
    {
        vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
        return;
    }


    if (protect_handle_violation(vcpu, guest_phys))
    {
        if (vcpu->terminal)
            vmexit_enter_terminal(
                vcpu,
                vcpu->last_failure
                    ? vcpu->last_failure
                    : HV_FAILURE_EPT_MISCONFIGURATION);
        vcpu->advance_rip = FALSE;
        return;
    }
    if (ept_handle_mmio_violation(vcpu, guest_phys))
    {
        vcpu->advance_rip = FALSE;
        return;
    }
    if (ept_conceal_is_hidden(guest_phys))
    {
        VMX_EXIT_QUALIFICATION_EPT_VIOLATION qual;
        UINT64 guest_linear = guest_phys;
        UINT32 error_code = 0;

        qual.AsUInt = vcpu->exit_qual;
        if (qual.ValidGuestLinearAddress)
            __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &guest_linear);
        if (qual.WriteAccess)
            error_code |= 0x2;
        if (qual.UserModeLinearAddress)
            error_code |= 0x4;
        if (qual.ExecuteAccess)
            error_code |= 0x10;
        vmexit_inject_pf(error_code, guest_linear);
        vcpu->advance_rip = FALSE;
        return;
    }

    if (vcpu->terminal)
    {
        vmexit_enter_terminal(
            vcpu,
            vcpu->last_failure
                ? vcpu->last_failure
                : HV_FAILURE_INVEPT);
        return;
    }

    vmexit_inject_gp();
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;
    UINT64 guest_cs_selector = 0;
    UINT64 guest_cs_ar = 0;
    UINT64 vmcall_num;
    NTSTATUS status;

    //
    // Both selector RPL and descriptor DPL must identify ring 0.
    //
    if (!vmx_vmread_checked(
            vcpu, VMCS_GUEST_CS_SELECTOR, &guest_cs_selector) ||
        !vmx_vmread_checked(
            vcpu, VMCS_GUEST_CS_ACCESS_RIGHTS, &guest_cs_ar) ||
        (guest_cs_selector & 3) != 0 ||
        ((guest_cs_ar >> 5) & 3) != 0)
    {
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        return;
    }

    if (regs->r10 != HV_VMCALL_FRAME_R10 ||
        regs->r11 != HV_VMCALL_FRAME_R11 ||
        regs->r12 != HV_VMCALL_FRAME_R12)
    {
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        return;
    }

    vmcall_num = regs->rcx;

#if OPHION_PRODUCTION
    if (vmcall_num != VMCALL_BOOTSTRAP_STEP &&
        vmcall_num != VMCALL_SEAL_STEP &&
        vmcall_num != VMCALL_STOP_STEP &&
        vmcall_num != VMCALL_INIT_ROLLBACK &&
        vmcall_num != VMCALL_ROOT_COMMAND &&
        !root_transport_legacy_allowed(vmcall_num))
    {
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        return;
    }
#endif

    switch (vmcall_num)
    {
    case VMCALL_BOOTSTRAP_STEP:
        status = root_transport_bootstrap(
            vcpu, regs->rdx, regs->r8, regs->r9);
        regs->rax = (UINT64)status;
        break;

    case VMCALL_SEAL_STEP:
        status = root_transport_seal_step(
            vcpu, regs->rdx, regs->r8, regs->r9);
        if (status == STATUS_ACCESS_DENIED)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        regs->rax = (UINT64)status;
        break;

    case VMCALL_ROOT_COMMAND:
        status = root_transport_command(
            vcpu, regs->rdx, regs->r8, regs->r9);
        if (status == STATUS_ACCESS_DENIED)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        regs->rax = (UINT64)status;
        break;

    case VMCALL_STOP_STEP:
    {
        UINT64 instr_len = 0;

        status = root_transport_stop_begin(
            vcpu, regs->rdx, regs->r8, regs->r9);
        if (status == STATUS_ACCESS_DENIED)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        if (!NT_SUCCESS(status))
        {
            regs->rax = (UINT64)status;
            break;
        }
        if (!vmx_vmread_checked(
                vcpu,
                VMCS_VMEXIT_INSTRUCTION_LENGTH,
                &instr_len))
        {
            root_transport_stop_complete(vcpu, FALSE);
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }

        regs->rax = (UINT64)STATUS_SUCCESS;
        if (vmexit_leave_vmx(
                vcpu,
                vcpu->vmexit_rip + instr_len,
                FALSE))
        {
            root_transport_stop_complete(vcpu, TRUE);
        }
        else
        {
            root_transport_stop_complete(vcpu, FALSE);
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        }
        break;
    }

    case VMCALL_INIT_ROLLBACK:
    {
        UINT64 instr_len = 0;

        if (!root_transport_initializing_rollback_allowed())
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        if (!vmx_vmread_checked(
                vcpu,
                VMCS_VMEXIT_INSTRUCTION_LENGTH,
                &instr_len))
        {
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }
        regs->rax = (UINT64)STATUS_SUCCESS;
        if (!vmexit_leave_vmx(
                vcpu,
                vcpu->vmexit_rip + instr_len,
                FALSE))
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }

    case VMCALL_TEST:
        regs->rax = (UINT64)STATUS_SUCCESS;
        break;

    case VMCALL_INVEPT:
        regs->rax = ept_invept_single(vcpu)
            ? (UINT64)STATUS_SUCCESS
            : (UINT64)STATUS_UNSUCCESSFUL;
        break;

    case VMCALL_CONCEAL_COMMIT:
        if (root_transport_conceal_commit_allowed() &&
            ept_conceal_commit_local(vcpu) &&
            root_transport_conceal_ack(vcpu))
            regs->rax = (UINT64)STATUS_SUCCESS;
        else
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;

    case VMCALL_PROTECT_REFRESH:
    {
        UINT64 cr3 = 0;
        if (!vmx_vmread_checked(vcpu, VMCS_GUEST_CR3, &cr3))
        {
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }
        protect_on_cr3_load(vcpu, cr3);
        vcpu->protect_cr3_exiting =
            protect_requires_cr3_exiting();
        if (!vcpu->terminal && !vmexit_sync_dynamic_exiting(vcpu))
            vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_WRITE);
        regs->rax = vcpu->terminal
            ? (UINT64)STATUS_UNSUCCESSFUL
            : (UINT64)STATUS_SUCCESS;
        break;
    }

    case VMCALL_VMXOFF:
    {
        UINT64 instr_len = 0;
        __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
        regs->rax = vmexit_leave_vmx(
            vcpu,
            vcpu->vmexit_rip + instr_len,
            FALSE)
            ? (UINT64)STATUS_SUCCESS
            : (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }

    default:
        regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
        break;
    }
}

static VOID
vmexit_enter_terminal(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT32 failure)
{
    UINT64 cs_ar = 0;

    vcpu->failed = TRUE;
    vcpu->terminal = TRUE;
    vcpu->last_failure = failure;
    vcpu->advance_rip = FALSE;

    /*
    * Kernel-mode terminal exits can fall back to bare metal on the existing
    * kernel stack.  A failed internal VMCALL must be skipped after VMXOFF;
    * retrying VMCALL with VMXE cleared would raise #UD in the DPC.
    */
    if (vcpu->vmxon_active &&
        vmx_vmread_checked(
            vcpu, VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar) &&
        (((cs_ar >> 5) & 3) == 0))
    {
        UINT64 return_rip = vcpu->vmexit_rip;
        if (vcpu->exit_reason ==
            VMX_EXIT_REASON_EXECUTE_VMCALL)
        {
            UINT64 length = 0;
            __vmx_vmread(
                VMCS_VMEXIT_INSTRUCTION_LENGTH,
                &length);
            return_rip += length;
        }
        vmexit_leave_vmx(vcpu, return_rip, FALSE);
        return;
    }

    vmx_vmwrite_checked(
        vcpu,
        VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD,
        0);
    vmx_vmwrite_checked(
        vcpu,
        VMCS_GUEST_ACTIVITY_STATE,
        GUEST_ACTIVITY_STATE_SHUTDOWN);
}
static __forceinline HV_CPUID_LEAF_CLASS
vmexit_cpuid_leaf_class(UINT32 leaf)
{
    if (leaf >= 0x80000000U)
        return HvCpuidLeafExtended;
    if (leaf == 7 || leaf == 0x0D || leaf == 0x14 || leaf == 0x1F)
        return HvCpuidLeafStructured;
    return HvCpuidLeafBasic;
}


VOID
vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu)
{
    vmexit_enter_terminal(vcpu, HV_FAILURE_TRIPLE_FAULT);
}

//
// MOV DR pass-through when MOV-DR exiting is forced by must-be-1 bits.
// DR0-DR3, DR6: read/write hardware directly (no VMCS save/load)
// DR7: use VMCS field, __writedr(7) writes host DR7
//
VOID
vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;
    UINT64      exit_qual = vcpu->exit_qual;

    UINT32 dr_num  = (UINT32)(exit_qual & 7);
    UINT32 dir     = (UINT32)((exit_qual >> 4) & 1);   // 0=to DR, 1=from DR
    UINT32 gpr_idx = (UINT32)((exit_qual >> 8) & 0xF);

    UINT64 * reg_ptr;
    switch (gpr_idx)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    //
    // DR4/DR5 alias DR6/DR7 when CR4.DE=0, #UD when CR4.DE=1
    //
    if (dr_num == 4 || dr_num == 5)
    {
        UINT64 cr4 = 0;
        __vmx_vmread(VMCS_GUEST_CR4, &cr4);
        if (cr4 & (1ULL << 3))
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        dr_num = (dr_num == 4) ? 6 : 7;
    }

    if (dir == 0)
    {
        UINT64 val = *reg_ptr;
        switch (dr_num)
        {
        case 0: vcpu->guest_dr0 = val; break;
        case 1: vcpu->guest_dr1 = val; break;
        case 2: vcpu->guest_dr2 = val; break;
        case 3: vcpu->guest_dr3 = val; break;
        case 6: vcpu->guest_dr6 = val; break;
        case 7:
            __vmx_vmwrite(VMCS_GUEST_DR7, val);
            break;
        }
    }
    else
    {
        UINT64 val = 0;
        switch (dr_num)
        {
        case 0: val = vcpu->guest_dr0; break;
        case 1: val = vcpu->guest_dr1; break;
        case 2: val = vcpu->guest_dr2; break;
        case 3: val = vcpu->guest_dr3; break;
        case 6: val = vcpu->guest_dr6; break;
        case 7:
            __vmx_vmread(VMCS_GUEST_DR7, &val);
            break;
        default: break;
        }
        *reg_ptr = val;
    }
}

//
// Per-exit state sampling plan. APERF/MPERF must bracket every exit because
// both counters advance during any root-mode residency. DR, CR8, and LAPIC
// state remain conditional so unrelated exits do not pay for unused reads.
//
#define VMEXIT_SAMPLE_APERF_MPERF   0x1u
#define VMEXIT_SAMPLE_LAPIC         0x2u
#define VMEXIT_SAMPLE_DR            0x4u
#define VMEXIT_SAMPLE_CR8           0x8u

static __forceinline UINT32
vmexit_exit_sample_plan(UINT32 exit_reason)
{
    UINT32 plan = VMEXIT_SAMPLE_APERF_MPERF;

    switch (exit_reason)
    {
    case VMX_EXIT_REASON_EXECUTE_RDMSR:
    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        return plan | VMEXIT_SAMPLE_LAPIC;

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    case VMX_EXIT_REASON_EPT_VIOLATION:
    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
        return plan | VMEXIT_SAMPLE_LAPIC;

    case VMX_EXIT_REASON_MOV_DR:
        return plan | VMEXIT_SAMPLE_DR;

    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    case VMX_EXIT_REASON_MOV_CR:
        return plan | VMEXIT_SAMPLE_CR8;

    default:
        return plan;
    }
}

BOOLEAN
vmexit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    size_t  exit_raw = 0;
    UINT32  exit_reason    = 0;
    UINT32  sample_plan    = 0;
    BOOLEAN result        = FALSE;

#if STEALTH_COMPENSATE_TIMING
    //
    // capture TSC as early as possible — used by TSC compensation to measure
    // handler overhead. Must be before any other work.
    //
    UINT64 exit_tsc_start = __rdtsc();
#endif

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->advance_rip = TRUE;

    vcpu->root_tsc_entry = __rdtsc();

    // __vmx_vmread writes size_t
    if (!vmx_vmread_checked(vcpu, VMCS_EXIT_REASON, &exit_raw))
    {
        vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
        return FALSE;
    }
    exit_reason = (UINT32)(exit_raw & 0xFFFF);
    vcpu->exit_reason = exit_reason;
    vcpu->total_exits++;
    if (exit_reason < HV_STATUS_EXIT_REASON_COUNT)
        vcpu->exit_counters[exit_reason]++;

    if (!vmx_vmread_checked(vcpu, VMCS_GUEST_RIP, &vcpu->vmexit_rip) ||
        !vmx_vmread_checked(vcpu, VMCS_GUEST_RSP, &vcpu->regs->rsp) ||
        !vmx_vmread_checked(vcpu, VMCS_EXIT_QUALIFICATION, &vcpu->exit_qual))
    {
        vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
        return FALSE;
    }

    //
    // conditional per-exit sampling (see vmexit_exit_sample_plan). the DR
    // shadow is additionally sampled whenever guest debugging is live —
    // advance_rip's pending-debug merge needs an exact DR0-DR3 image when
    // TF or any DR7 local/global breakpoint enable is set (VMAware-class
    // TF+DR0 collision probes), but normal execution skips all five reads.
    //
    sample_plan = vmexit_exit_sample_plan(exit_reason);
    if (!(sample_plan & VMEXIT_SAMPLE_DR))
    {
        UINT64 dr7_raw = 0;
        UINT64 rflags_raw = 0;
        __vmx_vmread(VMCS_GUEST_DR7, &dr7_raw);
        __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);
        if ((dr7_raw & 0xFF) != 0 || (rflags_raw & RFLAGS_TF) != 0)
            sample_plan |= VMEXIT_SAMPLE_DR;
    }

    if ((sample_plan & VMEXIT_SAMPLE_APERF_MPERF) &&
        vcpu->aperf_mperf_supported)
    {
        vcpu->aperf_root_entry = __readmsr(IA32_APERF);
        vcpu->mperf_root_entry = __readmsr(IA32_MPERF);
    }
    if (sample_plan & VMEXIT_SAMPLE_LAPIC)
    {
        UINT64 apic_base = __readmsr(IA32_APIC_BASE);
        BOOLEAN apic_enabled =
            (apic_base & IA32_APIC_BASE_ENABLE) != 0;

        vcpu->x2apic_enabled =
            apic_enabled &&
            (apic_base & IA32_APIC_BASE_X2APIC) != 0;
        if (!apic_enabled)
        {
            sample_plan &= ~VMEXIT_SAMPLE_LAPIC;
        }
        else if (vcpu->x2apic_enabled)
        {
            vcpu->lapic_root_entry =
                (UINT32)__readmsr(IA32_X2APIC_CUR_COUNT);
        }
        else if (vcpu->lapic_va &&
                 vcpu->lapic_hook.physical_page ==
                     (apic_base & IA32_APIC_BASE_ADDRESS_MASK))
        {
            vcpu->lapic_root_entry =
                *(volatile UINT32 *)((PUCHAR)vcpu->lapic_va +
                                     XAPIC_CURRENT_COUNT_OFFSET);
        }
        else
        {
            vmexit_enter_terminal(
                vcpu, HV_FAILURE_REQUIRED_CONTROLS);
            vcpu->in_root = FALSE;
            return FALSE;
        }
    }
    if (sample_plan & VMEXIT_SAMPLE_CR8)
        vcpu->guest_cr8 = (UINT8)__readcr8();
    if (sample_plan & VMEXIT_SAMPLE_DR)
    {
        vcpu->guest_dr0 = __readdr(0);
        vcpu->guest_dr1 = __readdr(1);
        vcpu->guest_dr2 = __readdr(2);
        vcpu->guest_dr3 = __readdr(3);
        vcpu->guest_dr6 = __readdr(6);
    }
    // Keep prior grants across additional protected-page EPT violations from
    // the same instruction; MTF restores the complete bounded set only after
    // the instruction retires.  Other exits fail closed and restore now.
    if ((vcpu->mtf_hook || protect_mtf_pending(vcpu)) &&
        exit_reason != VMX_EXIT_REASON_MONITOR_TRAP_FLAG &&
        !(protect_mtf_pending(vcpu) &&
          !vcpu->mtf_hook &&
          exit_reason == VMX_EXIT_REASON_EPT_VIOLATION))
    {
        ept_handle_monitor_trap(vcpu);
        if (vcpu->terminal)
        {
            vmexit_enter_terminal(
                vcpu,
                vcpu->last_failure
                    ? vcpu->last_failure
                    : HV_FAILURE_INVEPT);
            vcpu->in_root = FALSE;
            return FALSE;
        }
    }

    //
    // TSC compensation: if RDTSC exiting was armed for compensation and this
    // exit is NOT an RDTSC/RDTSCP, the attack pattern was broken (e.g. an
    // external interrupt fired between CPUID and RDTSC). Disarm and disable
    // RDTSC exiting to avoid trapping unrelated RDTSCs.
    //
#if STEALTH_COMPENSATE_TIMING
    if (vcpu->tsc_rdtsc_armed &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSC &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSCP)
    {
        vcpu->tsc_rdtsc_armed = FALSE;
        vcpu->timer_bias_pending = FALSE;
        vcpu->root_tsc_bias = 0;
        vcpu->lapic_root_bias = 0;

        if (!vmexit_sync_dynamic_exiting(vcpu))
        {
            vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_WRITE);
            vcpu->in_root = FALSE;
            return vcpu->vmxoff.executed;
        }
    }
#endif

    if (vcpu->timer_bias_pending &&
        !vcpu->tsc_rdtsc_armed &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSC &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSCP &&
        exit_reason != VMX_EXIT_REASON_EPT_VIOLATION &&
        exit_reason != VMX_EXIT_REASON_MONITOR_TRAP_FLAG)
    {
        vcpu->timer_bias_pending = FALSE;
        vcpu->root_tsc_bias = 0;
        vcpu->lapic_root_bias = 0;
    }

    switch (exit_reason)
    {
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        vmexit_handle_triple_fault(vcpu);
        break;
    case VMX_EXIT_REASON_VMENTRY_FAILURE_GUEST_STATE:
    case VMX_EXIT_REASON_VMENTRY_FAILURE_MSR_LOADING:
    case VMX_EXIT_REASON_VMENTRY_FAILURE_MACHINE_CHECK:
        vmexit_enter_terminal(vcpu, HV_FAILURE_VM_ENTRY);
        break;


    //
    // VMX instructions in guest — inject #UD (bare metal behavior)
    //
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
    case VMX_EXIT_REASON_EXECUTE_GETSEC:
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_EXECUTE_INVD:
        // INVD would discard dirty cache lines — use WBINVD instead
        __wbinvd();
        break;

    case VMX_EXIT_REASON_EXECUTE_INVLPG:
    {
        INVVPID_DESCRIPTOR desc = {0};
        BOOLEAN invalidated = FALSE;

        desc.Vpid = VPID_TAG;
        desc.LinearAddress = vcpu->exit_qual;
        if (g_ept->invvpid_individual_addr)
            invalidated =
                asm_invvpid(InvvpidIndividualAddress, &desc) == 0;

        if (!invalidated && g_ept->invvpid_all_contexts)
        {
            INVVPID_DESCRIPTOR all_contexts = {0};
            invalidated =
                asm_invvpid(InvvpidAllContexts, &all_contexts) == 0;
        }
        if (!invalidated)
            vmexit_enter_terminal(vcpu, HV_FAILURE_INVVPID);
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    {
        UINT32 selector = (UINT32)vcpu->regs->rcx;
        UINT16 type = (UINT16)(selector >> 16);
        UINT16 index = (UINT16)selector;
        UINT8 width = 0;
        BOOLEAN valid = FALSE;

        if (vcpu->pmu_version && pmu_guest_can_read())
        {
            if (type == 0 && index < vcpu->pmu_gp_count)
            {
                width = vcpu->pmu_gp_width;
                valid = width != 0;
            }
            else if (type == 0x4000 &&
                     (index < vcpu->pmu_fixed_count ||
                      (index < 32 &&
                       (vcpu->pmu_fixed_bitmap & (1U << index)))))
            {
                width = vcpu->pmu_fixed_width;
                valid = width != 0;
            }
        }

        if (!valid)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        {
            UINT64 val = __readpmc(selector) & pmu_width_mask(width);
            vcpu->regs->rax = (UINT32)val;
            vcpu->regs->rdx = (UINT32)(val >> 32);
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    {
        UINT64 tsc = __rdtsc();
        UINT64 offset_raw = 0;
        if (!vmx_vmread_checked(vcpu, VMCS_CTRL_TSC_OFFSET, &offset_raw))
        {
            vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
            break;
        }

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            //
            // tsc_cpuid_entry is already offset-adjusted; expose only the
            // native CPUID instruction cost above that timestamp.
            //
            tsc = vcpu->tsc_cpuid_entry + vcpu->tsc_cpuid_cost;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!vmexit_sync_dynamic_exiting(vcpu))
                vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_WRITE);
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)vcpu->root_tsc_entry + (INT64)offset_raw);
        }

        if (tsc <= vcpu->tsc_last_value)
            tsc = vcpu->tsc_last_value + 1;
        vcpu->tsc_last_value = tsc;

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        UINT32 leaf = (UINT32)vcpu->regs->rax;
        HV_CPUID_LEAF_CLASS leaf_class = vmexit_cpuid_leaf_class(leaf);
        UINT64 jitter = vcpu->cpuid_jitter[leaf_class];

        vcpu->tsc_cpuid_cost = vcpu->cpuid_cost[leaf_class];
        if (jitter)
            vcpu->tsc_cpuid_cost +=
                vcpu->tsc_variance_sequence++ % (jitter + 1);
        vmexit_handle_cpuid(vcpu);

#if STEALTH_COMPENSATE_TIMING
        //
        // Arm one following RDTSC/RDTSCP and retain the guest-visible CPUID
        // entry timestamp. A separate one-shot bias is mirrored into the next
        // HPET/LAPIC read without creating persistent per-core TSC domains.
        //
        if (g_stealth_enabled)
        {
            UINT64 offset_raw = 0;
            if (!vmx_vmread_checked(vcpu, VMCS_CTRL_TSC_OFFSET, &offset_raw))
            {
                vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
                break;
            }
            vcpu->tsc_cpuid_entry =
                (UINT64)((INT64)exit_tsc_start + (INT64)offset_raw);
            vcpu->tsc_rdtsc_armed = TRUE;
            vcpu->root_tsc_bias = 0;
            vcpu->lapic_root_bias = 0;
            vcpu->timer_bias_pending = TRUE;

            if (!vmexit_sync_dynamic_exiting(vcpu))
                vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_WRITE);
        }
#endif
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
        vmexit_handle_msr_read(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        vmexit_handle_msr_write(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_CR:
        vmexit_handle_mov_cr(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_DR:
        vmexit_handle_mov_dr(vcpu);
        break;

    case VMX_EXIT_REASON_EPT_VIOLATION:
        vmexit_handle_ept_violation(vcpu);
        break;

    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
        ept_handle_monitor_trap(vcpu);
        if (vcpu->terminal)
        {
            vmexit_enter_terminal(
                vcpu,
                vcpu->last_failure
                    ? vcpu->last_failure
                    : HV_FAILURE_INVEPT);
        }
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
        vmexit_enter_terminal(vcpu, HV_FAILURE_EPT_MISCONFIGURATION);
        break;

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
        vmexit_handle_vmcall(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_XSETBV:
    {
        //
        // XSETBV — stealth: proper validation per Intel SDM
        //
        // Defeats:
        //   - XSETBV with high bits in ECX should #GP
        //   - XSETBV with valid ECX should NOT fault
        //   - XSETBV with invalid XCR0 value should #GP
        //
        UINT64 rcx_val   = vcpu->regs->rcx;
        UINT64 value  = (vcpu->regs->rdx << 32) | (vcpu->regs->rax & 0xFFFFFFFF);

        if (rcx_val & 0xFFFFFFFF00000000ULL)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        //
        // check 2: only XCR0 (index 0) is valid
        //
        if ((UINT32)rcx_val != 0)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        if (!stealth_is_xcr0_valid(value))
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        _xsetbv(0, value);
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_HLT:
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_HLT);
        break;

    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        //
        // with ack-interrupt-on-exit, the CPU stores the acknowledged
        // vector in VMCS exit info. re-inject or defer if guest can't
        // accept it (IF=0, STI/MOV-SS blocking, or CR8 priority masking).
        //
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            UINT32 vector = int_info.Vector;

            size_t rflags_raw = 0;
            size_t intr_state = 0;
            __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);
            __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);

            BOOLEAN guest_interruptible =
                (rflags_raw & (1ULL << 9)) &&
                !(intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI |
                                GUEST_INTR_STATE_BLOCKING_BY_MOV_SS));

            if (guest_interruptible)
            {
                UINT8 vector_priority = (UINT8)(vector >> 4);
                if (vector_priority <= vcpu->guest_cr8)
                    guest_interruptible = FALSE;
            }

            if (guest_interruptible)
            {
                vmexit_inject_interrupt(vector);
            }
            else
            {
                //
                // guest can't take it now — defer and enable
                // interrupt-window exiting to inject later
                //
                vcpu->pending_ext_vector = (UINT8)vector;
                vcpu->has_pending_ext_interrupt = TRUE;

                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            if (int_info.InterruptionType == INTERRUPT_TYPE_NMI)
            {
                //
                // with virtual NMIs, the NMI exit sets blocking-by-NMI.
                // clear it before reinjecting — the NMI was intercepted
                // before guest delivery, and VM-entry re-sets blocking
                // when it delivers the injected NMI (SDM 26.6.1.2).
                //
                size_t intr_state = 0;
                __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
                intr_state &= ~(size_t)GUEST_INTR_STATE_BLOCKING_BY_NMI;
                __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
            }

            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, int_info.AsUInt);

            if (int_info.DeliverErrorCode)
            {
                size_t error_code = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error_code);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
            }

            if (int_info.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION)
            {
                size_t instr_len = 0;
                __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    {
        if (vcpu->has_pending_ext_interrupt)
        {
            UINT8 vector_priority = (UINT8)(vcpu->pending_ext_vector >> 4);

            if (vector_priority > vcpu->guest_cr8)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

                vmexit_inject_interrupt(vcpu->pending_ext_vector);
                vcpu->has_pending_ext_interrupt = FALSE;
            }
        }
        else
        {
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_NMI_WINDOW:
    {
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        if (vcpu->has_pending_nmi)
        {
            VMENTRY_INTERRUPT_INFORMATION nmi_info = {0};
            nmi_info.Vector           = EXCEPTION_VECTOR_NMI;
            nmi_info.InterruptionType = INTERRUPT_TYPE_NMI;
            nmi_info.Valid            = 1;
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, nmi_info.AsUInt);
            vcpu->has_pending_nmi = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_MWAIT:
        break;

    case VMX_EXIT_REASON_EXECUTE_MONITOR:
        break;

    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        break;

    case VMX_EXIT_REASON_EXECUTE_UMWAIT:
    case VMX_EXIT_REASON_EXECUTE_TPAUSE:
        // A nested VMM may elect to exit these hints despite advertising the
        // WAITPKG control. Consume the one exiting instruction exactly once.
        _mm_pause();
        break;

    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
    {
        unsigned int aux = 0;
        UINT64 tsc = __rdtscp(&aux);
        UINT64 offset_raw = 0;
        if (!vmx_vmread_checked(vcpu, VMCS_CTRL_TSC_OFFSET, &offset_raw))
        {
            vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_READ);
            break;
        }

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            tsc = vcpu->tsc_cpuid_entry + vcpu->tsc_cpuid_cost;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!vmexit_sync_dynamic_exiting(vcpu))
                vmexit_enter_terminal(vcpu, HV_FAILURE_VMCS_WRITE);
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)vcpu->root_tsc_entry + (INT64)offset_raw);
        }

        if (tsc <= vcpu->tsc_last_value)
            tsc = vcpu->tsc_last_value + 1;
        vcpu->tsc_last_value = tsc;

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        vcpu->regs->rcx = (UINT64)aux;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WBINVD:
        __wbinvd();
        break;

    default:
        vmexit_enter_terminal(vcpu, HV_FAILURE_UNKNOWN_EXIT);
        break;
    }

    if (vcpu->terminal && !vcpu->vmxoff.executed)
        vmexit_enter_terminal(
            vcpu,
            vcpu->last_failure
                ? vcpu->last_failure
                : HV_FAILURE_UNKNOWN_EXIT);

    //
    // re-inject IDT vectoring event if one was in progress during this VM-exit.
    // skip when vmxoff has been executed — vmread would #UD outside VMX.
    //
    if (!vcpu->vmxoff.executed && !vcpu->terminal)
    {
        size_t idt_vec_raw = 0;
        __vmx_vmread(VMCS_IDT_VECTORING_INFORMATION, &idt_vec_raw);

        VMENTRY_INTERRUPT_INFORMATION idt_vec;
        idt_vec.AsUInt = (UINT32)idt_vec_raw;

        if (idt_vec.Valid)
        {
            BOOLEAN reinject_idt = TRUE;

            //
            // exception combining (SDM Vol 3 Table 6-5):
            // when a hardware exception occurs during delivery of another
            // hardware exception, certain combinations produce #DF or
            // triple fault instead of serial delivery.
            //
            if (exit_reason == VMX_EXIT_REASON_EXCEPTION_OR_NMI)
            {
                size_t exit_int_raw = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &exit_int_raw);

                VMENTRY_INTERRUPT_INFORMATION exit_int;
                exit_int.AsUInt = (UINT32)exit_int_raw;

                if (exit_int.Valid &&
                    idt_vec.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION &&
                    exit_int.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION)
                {
                    if (classify_exception(idt_vec.Vector) == EXCEPTION_CLASS_DOUBLE_FAULT)
                    {
                        // #DF + any exception = triple fault
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
                        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
                        reinject_idt = FALSE;
                    }
                    else if (should_generate_df(idt_vec.Vector, exit_int.Vector))
                    {
                        // contributory+contributory, PF+contributory, PF+PF → #DF
                        vmexit_inject_df();
                        reinject_idt = FALSE;
                    }
                    // else: benign combination — reinject IDT event,
                    // exit exception regenerates during delivery
                }
            }

            if (reinject_idt)
            {
                // if the handler already queued an NMI injection, defer it —
                // IDT vectoring event takes priority
                size_t entry_info_raw = 0;
                __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, &entry_info_raw);

                VMENTRY_INTERRUPT_INFORMATION entry_info;
                entry_info.AsUInt = (UINT32)entry_info_raw;

                if (entry_info.Valid && entry_info.InterruptionType == INTERRUPT_TYPE_NMI)
                {
                    vcpu->has_pending_nmi = TRUE;

                    size_t proc_ctrl = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                    proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
                }

                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, idt_vec.AsUInt);

                if (idt_vec.DeliverErrorCode)
                {
                    size_t idt_err = 0;
                    __vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE, &idt_err);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, idt_err);
                }

                if (idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
                    idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_INTERRUPT)
                {
                    size_t instr_len = 0;
                    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
                }
            }

            vcpu->advance_rip = FALSE;
        }
    }

    // check for NMI that fired while in host mode (via private host IDT)
#if USE_PRIVATE_HOST_IDT
    if (!vcpu->vmxoff.executed && !vcpu->terminal &&
        _InterlockedExchange(&vcpu->host_nmi_pending, 0))
    {
        if (!vcpu->has_pending_nmi)
        {
            vcpu->has_pending_nmi = TRUE;
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }
    }
#endif
    if (!vcpu->vmxoff.executed && vcpu->advance_rip)
    {
        vmexit_advance_rip(vcpu);
    }

    if (!vcpu->vmxoff.executed && (sample_plan & VMEXIT_SAMPLE_DR))
    {
        __writedr(0, vcpu->guest_dr0);
        __writedr(1, vcpu->guest_dr1);
        __writedr(2, vcpu->guest_dr2);
        __writedr(3, vcpu->guest_dr3);
        __writedr(6, vcpu->guest_dr6);
    }
    if (!vcpu->vmxoff.executed && (sample_plan & VMEXIT_SAMPLE_CR8))
        __writecr8(vcpu->guest_cr8);

    if (vcpu->vmxoff.executed)
        result = TRUE;

    if (!vcpu->vmxoff.executed)
    {
        UINT64 root_delta = __rdtsc() - vcpu->root_tsc_entry;

#if STEALTH_COMPENSATE_TIMING
        if (g_stealth_enabled && vcpu->timer_bias_pending)
        {
            UINT64 hidden_delta = root_delta;

            if (exit_reason == VMX_EXIT_REASON_EXECUTE_CPUID)
            {
                UINT64 native_cost = vcpu->tsc_cpuid_cost;
                hidden_delta = root_delta > native_cost
                    ? root_delta - native_cost
                    : 0;
            }
            vcpu->root_tsc_bias += hidden_delta;
        }
#else
        UNREFERENCED_PARAMETER(root_delta);
#endif
        if ((sample_plan & VMEXIT_SAMPLE_APERF_MPERF) &&
            vcpu->aperf_mperf_supported)
        {
            vcpu->aperf_root_bias +=
                __readmsr(IA32_APERF) - vcpu->aperf_root_entry;
            vcpu->mperf_root_bias +=
                __readmsr(IA32_MPERF) - vcpu->mperf_root_entry;
        }
        if ((sample_plan & VMEXIT_SAMPLE_LAPIC) &&
            vcpu->timer_bias_pending)
        {
            if (vcpu->x2apic_enabled)
            {
                UINT32 current = (UINT32)__readmsr(IA32_X2APIC_CUR_COUNT);
                if (vcpu->lapic_root_entry >= current)
                    vcpu->lapic_root_bias +=
                        vcpu->lapic_root_entry - current;
            }
            else if (vcpu->lapic_va)
            {
                UINT32 current = *(volatile UINT32 *)(
                    (PUCHAR)vcpu->lapic_va + XAPIC_CURRENT_COUNT_OFFSET);
                if (vcpu->lapic_root_entry >= current)
                    vcpu->lapic_root_bias +=
                        vcpu->lapic_root_entry - current;
            }
        }
    }

    vcpu->in_root = FALSE;
    return result;
}
