/*
*   hv.h - master hypervisor header — includes everything needed
*/
#pragma once

//
// windows kernel headers (used only at PASSIVE/DPC level in non-root)
//
#include <ntifs.h>
#include <intrin.h>

//
// production stealth profile: defined via /DOPHION_PRODUCTION=1 at build
// time. removes diagnostic logging and the status device entirely; default
// (0) keeps the diagnosable, probe-friendly build unchanged.
//
#ifndef OPHION_PRODUCTION
#define OPHION_PRODUCTION 0
#endif

#if OPHION_PRODUCTION
#define HV_LOG(...) ((void)0)
#else
#define HV_LOG(...) DbgPrintEx(__VA_ARGS__)
#endif

#include "ia32.h"
#include "hv_public.h"
#include "hv_types.h"
#include "hv_attachment.h"
#include "asm_prototypes.h"
#include "stealth.h"

UINT64 va_to_pa(PVOID va);
PVOID  pa_to_va(UINT64 pa);
UINT64 get_system_cr3(VOID);

//
// private host page tables (hostcr3.c)
//
BOOLEAN hostcr3_build(VOID);
UINT64  hostcr3_get(VOID);
VOID    hostcr3_destroy(VOID);
VOID    hostcr3_register_conceal(VOID);
VOID    tracewipe_apply(PDRIVER_OBJECT driver_obj, BOOLEAN preserve_dispatch);



//
// private host IDT (hostidt.c)
//
BOOLEAN hostidt_build(VOID);
UINT64  hostidt_get_base(VOID);
VOID    hostidt_destroy(VOID);

//
// per-core private host GDT (hostgdt.c)
//
BOOLEAN hostgdt_build_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);
VOID    hostgdt_destroy_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);

//
// segment helpers (segment.c)
//
VOID segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR * result);
BOOLEAN segment_fill_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID gdt_base, UINT32 seg_reg, UINT16 selector);

BOOLEAN vmx_preflight(VOID);
BOOLEAN vmx_build_topology(VOID);
UINT32  vmx_topology_index(const PROCESSOR_NUMBER * processor);
BOOLEAN vmx_vmread_checked(VIRTUAL_MACHINE_STATE * vcpu, SIZE_T field, UINT64 * value);
BOOLEAN vmx_vmwrite_checked(VIRTUAL_MACHINE_STATE * vcpu, SIZE_T field, UINT64 value);
VOID    vmx_mark_host_nmi_pending(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_check_support(VOID);
BOOLEAN vmx_init(VOID);
VOID    vmx_terminate(VOID);
BOOLEAN vmx_all_stopped(VOID);

BOOLEAN vmx_virtualize_cpu(PVOID guest_stack);
BOOLEAN vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack);

BOOLEAN vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_clear_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu);

UINT32  vmx_adjust_controls(UINT32 requested, UINT32 capability_msr);
VOID    vmx_set_fixed_bits(VOID);
VOID    vmx_vmresume(VOID);

BOOLEAN ept_check_features(VOID);
BOOLEAN ept_build_mtrr_map(VOID);
BOOLEAN ept_init(VOID);
PVMM_EPT_PAGE_TABLE ept_alloc_identity_map(VOID);
UINT8   ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page);
BOOLEAN ept_valid_for_large_page(SIZE_T pfn);
BOOLEAN ept_setup_pml2(PVMM_EPT_PAGE_TABLE page_table, PEPT_PML2_ENTRY new_entry, SIZE_T pfn);

PEPT_PML1_ENTRY ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
PEPT_PML2_ENTRY ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
BOOLEAN ept_split_large_page(VIRTUAL_MACHINE_STATE * vcpu, SIZE_T phys_addr);
BOOLEAN ept_setup_timer_hooks(VOID);
VOID    ept_destroy_timer_hooks(VOID);
VOID    ept_destroy_splits(VOID);
BOOLEAN ept_handle_mmio_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys);
VOID    ept_handle_monitor_trap(VIRTUAL_MACHINE_STATE * vcpu);

BOOLEAN ept_invept_single(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_invept_single_initializing(
    VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_invept_all(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vpid_invvpid_single(VIRTUAL_MACHINE_STATE * vcpu, UINT16 vpid);
VOID    ept_conceal_register_pa(UINT64 pa, SIZE_T size);
VOID    ept_conceal_register_va(PVOID va, SIZE_T size);
VOID    ept_conceal_register_runtime(VOID);
BOOLEAN ept_conceal_prepare(VOID);
BOOLEAN ept_conceal_commit_local(
    VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_conceal_is_frozen(VOID);
BOOLEAN ept_conceal_is_hidden(UINT64 guest_phys);
VOID    ept_conceal_destroy(VOID);
BOOLEAN broadcast_conceal_invept(VOID);

NTSTATUS root_transport_prepare(VOID);
VOID     root_transport_destroy(VOID);
VOID     root_transport_mark_failed(UINT32 failure);
VOID     root_transport_publish_failure(UINT32 failure);
BOOLEAN  root_transport_mark_awaiting_bootstrap(VOID);
BOOLEAN  root_transport_conceal_ack(
    VIRTUAL_MACHINE_STATE * vcpu);
VOID     root_transport_register_conceal(VOID);
BOOLEAN  root_transport_snapshot_metadata(VOID);
VOID     root_transport_release_metadata(VOID);
VIRTUAL_MACHINE_STATE * root_transport_vcpu_base(VOID);
UINT32   root_transport_processor_count(VOID);
UINT32   root_transport_physical_address_bits(VOID);
BOOLEAN  root_transport_set_conceal_manifest(
    PVOID manifest,
    UINT32 range_count,
    UINT64 generation,
    UINT64 dummy_pa);
typedef struct _HV_CONCEAL_SNAPSHOT {
    PVOID  Manifest;
    UINT32 RangeCount;
    UINT32 Reserved;
    UINT64 Generation;
    UINT64 DummyPa;
} HV_CONCEAL_SNAPSHOT;
BOOLEAN  root_transport_snapshot_conceal(
    HV_CONCEAL_SNAPSHOT * snapshot);
PVOID    root_transport_conceal_manifest(VOID);
UINT32   root_transport_conceal_range_count(VOID);
UINT64   root_transport_conceal_generation(VOID);
UINT64   root_transport_conceal_dummy_pa(VOID);
VOID     root_transport_release_conceal_manifest(VOID);
BOOLEAN  root_transport_conceal_commit_allowed(VOID);
BOOLEAN  root_transport_legacy_allowed(UINT64 vmcall_number);
BOOLEAN  root_transport_initializing_rollback_allowed(VOID);
NTSTATUS root_transport_bootstrap(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch);
NTSTATUS root_transport_seal_step(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch);
NTSTATUS root_transport_command(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 sequence);
NTSTATUS root_transport_stop_begin(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 capability_low,
    UINT64 capability_high,
    UINT64 epoch);
VOID     root_transport_stop_complete(
    VIRTUAL_MACHINE_STATE * vcpu,
    BOOLEAN success);

BOOLEAN vmexit_handler(PGUEST_REGS regs, VIRTUAL_MACHINE_STATE * vcpu);

//
// exit sub-handlers
//
VOID vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu);

//
// event injection helpers (events.c)
//
VOID vmexit_inject_gp(VOID);
VOID vmexit_inject_ud(VOID);
VOID vmexit_inject_df(VOID);
VOID vmexit_inject_interrupt(UINT32 vector);
VOID vmexit_inject_bp(VOID);
VOID vmexit_inject_pf(UINT32 error_code, UINT64 fault_addr);

VOID broadcast_virtualize_all(VOID);
BOOLEAN broadcast_prepare_host_state(VOID);
VOID broadcast_terminate_all(VOID);
VOID broadcast_terminate_initializing(
    BOOLEAN all_cores_launched);
VOID broadcast_protect_refresh(VOID);

//
// BYOVD post-launch EPT concealment (byovd_conceal.c)
// Hides the BYOVD loader driver's physical pages via EPT after the HV is live.
//
NTSTATUS byovd_conceal_driver(const UNICODE_STRING* driver_name, BOOLEAN wipe_ldr);
NTSTATUS byovd_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io_stack);
//
// EAC-specific stealth (eac_stealth.c)
//
VOID eac_stealth_apply(VOID);
VOID eac_stack_scrub(VOID);
VOID eac_stealth_query(PULONG flags, PULONG counters);
//
// per-CR3 EPT split-view (protect.c)
//
VOID     protect_init(VOID);
VOID     protect_destroy(VOID);
BOOLEAN  protect_requires_cr3_exiting(VOID);
VOID     protect_on_cr3_load(VIRTUAL_MACHINE_STATE * vcpu, UINT64 new_cr3);
BOOLEAN  protect_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 gpa);
VOID     protect_on_mtf(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN  protect_mtf_pending(VIRTUAL_MACHINE_STATE * vcpu);

NTSTATUS protect_add_range(UINT64 owner_cr3, UINT64 gva, UINT64 size);
VOID     protect_query_status(HV_PROTECT_STATUS_V1 * status);

NTSTATUS protect_add_whitelist(UINT64 owner_cr3, UINT64 gva, UINT64 size);
NTSTATUS protect_handle_ioctl(PIRP irp, PIO_STACK_LOCATION io);



NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path);
VOID     DriverUnload(PDRIVER_OBJECT driver_obj);
