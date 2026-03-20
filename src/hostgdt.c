/*
*   hostgdt.c - per-core private host GDT for VMX-root mode
*   each core has its own GDT/TSS, so private GDT must be per-core
*/
#include "hv.h"

BOOLEAN
hostgdt_build_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 orig_base  = asm_get_gdt_base();
    UINT16 orig_limit = asm_get_gdt_limit();

    PVOID gdt_copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_POOL_TAG);
    if (!gdt_copy)
        return FALSE;

    RtlZeroMemory(gdt_copy, PAGE_SIZE);
    RtlCopyMemory(gdt_copy, (PVOID)orig_base, (SIZE_T)orig_limit + 1);

    vcpu->host_gdt           = gdt_copy;
    vcpu->original_gdt_base  = orig_base;
    vcpu->original_gdt_limit = orig_limit;
    vcpu->original_tr_selector = asm_get_tr();

    return TRUE;
}

VOID
hostgdt_destroy_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (vcpu->host_gdt)
    {
        ExFreePoolWithTag(vcpu->host_gdt, HV_POOL_TAG);
        vcpu->host_gdt = NULL;
    }
}
