/*
*   hv_types.h - core hypervisor type definitions — per-vcpu state, ept structures, configs
*   zero windows api dependency in vmx-root mode by design
*/
#pragma once

#include "ia32.h"

#ifndef MAXULONG64
#define MAXULONG64              ((ULONG64)~((ULONG64)0))
#endif

#define VMM_STACK_SIZE          0x8000      // 32 KB per-VCPU VMM stack
#define VMM_STACK_VCPU_OFFSET   8           // vcpu ptr stored at top-8 of stack
#define VMXON_SIZE              0x1000
#define VMCS_SIZE               0x1000
#define MAX_PROCESSORS          256
#define MAX_MTRR_RANGES         256

#if OPHION_PRODUCTION
// benign production tag: must not identify the project (pool-tag scanners
// flag rare tags with no owning module). allocated and freed consistently.
#define HV_POOL_TAG             'DptS'
#else
#define HV_POOL_TAG             'nhpO'
#endif

typedef struct _GUEST_REGS {
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;    // placeholder — real RSP read from VMCS
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef struct _VMX_VMXOFF_STATE {
    BOOLEAN executed;
    BOOLEAN handoff;
    UINT64  guest_rip;
    UINT64  guest_rsp;
    UINT64  guest_cr3;
} VMX_VMXOFF_STATE;

typedef struct _MTRR_RANGE_DESCRIPTOR {
    UINT64  phys_base;
    UINT64  phys_end;
    UINT8   mem_type;
    BOOLEAN fixed;
} MTRR_RANGE_DESCRIPTOR;

typedef struct _VMM_EPT_PAGE_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_ENTRY   PML4[VMM_EPT_PML4E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY   PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];
} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

//
// dynamic split: when we split a 2MB page into 512 4KB pages
//
typedef struct _VMM_EPT_DYNAMIC_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];
    union {
        PEPT_PML2_ENTRY   Entry;
        PEPT_PML2_POINTER Pointer;
    } u;
    UINT64 OriginalEntry;
    LIST_ENTRY SplitList;
} VMM_EPT_DYNAMIC_SPLIT, *PVMM_EPT_DYNAMIC_SPLIT;

typedef enum _EPT_MMIO_KIND {
    EptMmioNone,
    EptMmioHpet,
    EptMmioLapic
} EPT_MMIO_KIND;

typedef struct _EPT_MMIO_HOOK {
    BOOLEAN        active;
    EPT_MMIO_KIND  kind;
    UINT16         target_offset;
    UINT16         target_size;
    UINT64         physical_page;
    UINT64         shadow_va;
    UINT64         shadow_pa;
    UINT64         original_entry;
    PEPT_PML1_ENTRY entry;
} EPT_MMIO_HOOK, *PEPT_MMIO_HOOK;

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    LIST_ENTRY            hooked_pages;    // owns dynamic EPT split allocations

    //
    // INVVPID capability bits (cached from IA32_VMX_EPT_VPID_CAP)
    //
    BOOLEAN               invvpid_supported;
    BOOLEAN               invvpid_individual_addr;
    BOOLEAN               invvpid_single_context;
    BOOLEAN               invvpid_all_contexts;
    BOOLEAN               invvpid_single_retaining_globals;
    BOOLEAN               mtf_supported;
    BOOLEAN               execute_only_supported;
    BOOLEAN               invept_supported;
    BOOLEAN               invept_single_context;
    BOOLEAN               invept_all_contexts;
    BOOLEAN               hpet_counter_64bit;
    UINT64                hpet_physical;
    UINT64                hpet_period_fs;
    UINT64                tsc_frequency;
} EPT_STATE, *PEPT_STATE;

typedef struct _HV_PROCESSOR_TOPOLOGY_ENTRY {
    PROCESSOR_NUMBER Processor;
    UINT32           Index;
} HV_PROCESSOR_TOPOLOGY_ENTRY, *PHV_PROCESSOR_TOPOLOGY_ENTRY;

typedef struct _HV_CAPABILITY_RECORD {
    UINT32 CpuCount;
    UINT32 PhysicalAddressBits;
    UINT64 MaximumGuestPhysicalAddress;
    UINT32 ParentFlags;
    UINT32 ParentFeatures;
    UINT32 CapabilityFlags;
    UINT32 Failure;
    CHAR   ParentVendor[16];
} HV_CAPABILITY_RECORD, *PHV_CAPABILITY_RECORD;

typedef enum _HV_CPUID_LEAF_CLASS {
    HvCpuidLeafBasic,
    HvCpuidLeafStructured,
    HvCpuidLeafExtended,
    HvCpuidLeafClassCount
} HV_CPUID_LEAF_CLASS;


typedef struct _VIRTUAL_MACHINE_STATE {

    // Kept first so the root NMI stub can set it without C/Windows calls.
    volatile LONG host_nmi_pending;

    UINT64 original_cr0;
    UINT64 original_cr4;
    UINT64 vmxon_va;
    UINT64 vmxon_pa;
    UINT64 vmcs_va;
    UINT64 vmcs_pa;

    //
    // VMM stack (HOST_RSP points near top of this)
    //
    UINT64 vmm_stack;

    UINT64 msr_bitmap_va;
    UINT64 msr_bitmap_pa;
    UINT64 io_bitmap_va_a;
    UINT64 io_bitmap_pa_a;
    UINT64 io_bitmap_va_b;
    UINT64 io_bitmap_pa_b;

    PVMM_EPT_PAGE_TABLE ept_page_table;
    EPT_POINTER         ept_pointer;

    PGUEST_REGS regs;
    UINT32      core_id;
    UINT32      exit_reason;
    UINT64      exit_qual;
    UINT64      vmexit_rip;
    BOOLEAN     in_root;
    BOOLEAN     launched;
    BOOLEAN     vmxon_active;
    BOOLEAN     detached;
    BOOLEAN     waitpkg_enabled;
    BOOLEAN     vpid_enabled;
    UINT32      primary_dynamic_forced;
    BOOLEAN     protect_cr3_exiting;
    BOOLEAN     advance_rip;
    BOOLEAN     failed;
    BOOLEAN     terminal;
    UINT32      last_failure;
    UINT32      last_vm_instruction_error;
    UINT64      total_exits;
    UINT64      exit_counters[HV_STATUS_EXIT_REASON_COUNT];


    VMX_VMXOFF_STATE vmxoff;

    //
    // stealth: per-VCPU TSC compensation state for "trap next RDTSC" approach.
    // after CPUID exit, RDTSC exiting is armed for one instruction.
    // the trapped RDTSC returns a compensated value hiding VM-exit overhead.
    // TSC_OFFSET is never modified — zero drift, zero monotonicity issues.
    //
    UINT64  tsc_cpuid_entry;        // TSC recorded at start of CPUID VM-exit handler
    BOOLEAN tsc_rdtsc_armed;        // TRUE = next RDTSC/RDTSCP should be compensated
    UINT64  cpuid_cost[HvCpuidLeafClassCount];
    UINT64  cpuid_jitter[HvCpuidLeafClassCount];
    UINT64  tsc_cpuid_cost;
    UINT64  tsc_last_value;
    UINT32  tsc_variance_sequence;


    //
    // PMU virtualization. PERF_GLOBAL_CTRL is loaded as zero on VM-exit and
    // restored from the guest VMCS field on entry. APERF/MPERF biases remove
    // the exact root-mode deltas sampled at handler entry/exit.
    //
    BOOLEAN pmu_isolated;
    BOOLEAN aperf_mperf_supported;
    UINT8   pmu_version;
    UINT8   pmu_gp_count;
    UINT8   pmu_gp_width;
    UINT8   pmu_fixed_count;
    UINT8   pmu_fixed_width;
    UINT32  pmu_fixed_bitmap;
    UINT64  perf_global_ctrl;
    UINT64  aperf_root_entry;
    UINT64  mperf_root_entry;
    UINT64  aperf_root_bias;
    UINT64  mperf_root_bias;
    UINT64  aperf_guest_offset;
    UINT64  mperf_guest_offset;

    //
    // Per-vCPU timer MMIO state. A permission fault temporarily maps either
    // the shadow page or the real MMIO page; MTF restores the trap after the
    // retried instruction.
    //
    EPT_MMIO_HOOK hpet_hook;
    EPT_MMIO_HOOK lapic_hook;
    PVOID   hpet_va;
    UINT64  root_tsc_entry;
    UINT64  root_tsc_bias;
    BOOLEAN timer_bias_pending;
    UINT64  hpet_last_value;
    PEPT_MMIO_HOOK mtf_hook;
    PVOID   lapic_va;
    BOOLEAN x2apic_enabled;
    UINT32  lapic_root_entry;
    UINT64  lapic_root_bias;
    UINT32  lapic_initial_count;
    UINT32  lapic_last_value;

    //
    // pending external interrupt for deferred re-injection
    // used when external-interrupt exiting is active but the guest
    // can't accept an interrupt right now (IF=0 or STI/MOV-SS blocking)
    //
    UINT8   pending_ext_vector;
    BOOLEAN has_pending_ext_interrupt;

    //
    // pending NMI for deferred delivery via NMI-window exiting
    // set when an NMI VM-exit interrupts IDT delivery of another event
    //
    BOOLEAN has_pending_nmi;

    // guest DR0-DR3/DR6 saved on vm-exit, restored before vmresume
    UINT64  guest_dr0;
    UINT64  guest_dr1;
    UINT64  guest_dr2;
    UINT64  guest_dr3;
    UINT64  guest_dr6;
    BOOLEAN mov_dr_exiting;

    // shadowed guest CR8 (TPR) for interrupt priority checks
    UINT8   guest_cr8;

    // per-core private host GDT for VMXOFF restore
    PVOID   host_gdt;
    UINT64  original_gdt_base;
    UINT16  original_gdt_limit;
    UINT16  original_tr_selector;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002
#define VMCALL_INVEPT           0x00000003
#define VMCALL_PROTECT_REFRESH  0x00000004
#define VMCALL_SEAL_STEP        HV_ROOT_VMCALL_SEAL_STEP
#define VMCALL_STOP_STEP        HV_ROOT_VMCALL_STOP_STEP
#define VMCALL_BOOTSTRAP_STEP   HV_ROOT_VMCALL_BOOTSTRAP_STEP
#define VMCALL_ROOT_COMMAND     HV_ROOT_VMCALL_COMMAND
#define VMCALL_CONCEAL_COMMIT   0x00007FFD
#define VMCALL_INIT_ROLLBACK    0x00007FFE


typedef struct _HOST_IDT_STATE {
    DECLSPEC_ALIGN(16) IDT_GATE_DESCRIPTOR_64 idt[IDT_NUM_ENTRIES];
    UINT64  original_idt_base;
    BOOLEAN initialized;
} HOST_IDT_STATE, *PHOST_IDT_STATE;

extern VIRTUAL_MACHINE_STATE * g_vcpu;
extern EPT_STATE *             g_ept;
extern UINT32                  g_cpu_count;
extern HV_PROCESSOR_TOPOLOGY_ENTRY g_processor_topology[MAX_PROCESSORS];
extern HV_CAPABILITY_RECORD        g_hv_capabilities;
extern UINT64                  g_system_cr3;
extern UINT64 *                g_msr_bitmap_invalid;
extern HOST_IDT_STATE          g_host_idt;
extern volatile LONG           g_vmxoff_nmi_deferred;
extern volatile LONG           g_vmxoff_transition_count;
