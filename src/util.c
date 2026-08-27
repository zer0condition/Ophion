/*
*   util.c - utility functions — address conversion, segment descriptor parsing
*   these are our own implementations to avoid relying on undocumented
*   windows internals wherever possible
*/
#include "hv.h"

/*
*   convert virtual address to physical using mmgetphysicaladdress
*   this is one of the few windows apis we must use (no safe alternative)
*   only call from non-root or at dispatch_level
*/
UINT64
va_to_pa(PVOID va)
{
    return MmGetPhysicalAddress(va).QuadPart;
}

PVOID
pa_to_va(UINT64 pa)
{
    PHYSICAL_ADDRESS phys_addr;
    phys_addr.QuadPart = pa;
    return MmGetVirtualForPhysical(phys_addr);
}

/*
*   get the system (kernel) directory table base (cr3 of system process)
*   we read it from the eprocess of pid 4 (system). this is needed because
*   when we set host_cr3 in vmcs we need a valid kernel-space cr3 that won't
*/
UINT64
get_system_cr3(VOID)
{

    // the safest portable way: just read __readcr3() from DPC context
    // since DPC runs in system process context.
    // for maximum safety and portability, we use the sytem eprocess cr3:
    //
    PEPROCESS sys_proc = PsInitialSystemProcess;
    if (sys_proc)
    {
        return *(UINT64 *)((UINT8 *)sys_proc + 0x28);
    }

    //
    // fallback: use current CR3 (may be user-mode process page tables)
    //
    return __readcr3();
}

VOID
segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR * result)
{
    PSEGMENT_DESCRIPTOR_32 desc;
    UINT16                 index;

    if (!result)
        return;

    //
    // the index into the GDT is the upper 13 bits of the selector
    //
    index = (selector >> 3) & 0x1FFF;

    if (selector == 0 || index == 0)
    {
        result->Selector   = 0;
        result->Base       = 0;
        result->Limit      = 0;
        result->Attributes.AsUInt = 0;
        result->Attributes.Unusable = TRUE;
        return;
    }

    desc = (PSEGMENT_DESCRIPTOR_32)(gdt_base + index * 8);

    result->Selector = selector;

    result->Base = (UINT64)desc->BaseLow |
                   ((UINT64)desc->BaseMid << 16) |
                   ((UINT64)desc->BaseHigh << 24);

    //
    // for system segments (TSS, LDT) in 64-bit mode, the base is 8 bytes
    // (the next descriptor entry holds the high 32 bits of the base)
    //
    if (!desc->System)
    {
        UINT64 base_high = *(UINT64 *)(gdt_base + index * 8 + 8);
        result->Base |= (base_high & 0xFFFFFFFF) << 32;
    }

    result->Limit = (UINT32)desc->LimitLow |
                    ((UINT32)desc->LimitHigh << 16);

    if (desc->Granularity)
    {
        result->Limit = (result->Limit << 12) | 0xFFF;
    }

    result->Attributes.AsUInt = 0;
    result->Attributes.Type        = desc->Type;
    result->Attributes.System      = desc->System;
    result->Attributes.Dpl         = desc->Dpl;
    result->Attributes.Present     = desc->Present;
    result->Attributes.Avl         = desc->Avl;
    result->Attributes.LongMode    = desc->LongMode;
    result->Attributes.DefaultBig  = desc->DefaultBig;
    result->Attributes.Granularity = desc->Granularity;
    result->Attributes.Unusable    = 0;
}

BOOLEAN
segment_fill_vmcs(
    VIRTUAL_MACHINE_STATE * vcpu,
    PVOID gdt_base,
    UINT32 seg_reg,
    UINT16 selector)
{
    VMX_SEGMENT_SELECTOR seg = {0};

    segment_get_descriptor((PUCHAR)gdt_base, selector, &seg);

    if (selector == 0)
    {
        seg.Attributes.Unusable = TRUE;
    }

    //
    // clear reserved bits that VMCS checks reject
    //
    seg.Attributes.Reserved1 = 0;
    seg.Attributes.Reserved2 = 0;

    //
    // write to VMCS — each segment field is offset by seg_reg * 2
    //
    return
        vmx_vmwrite_checked(vcpu, VMCS_GUEST_ES_SELECTOR + seg_reg * 2, selector) &&
        vmx_vmwrite_checked(vcpu, VMCS_GUEST_ES_LIMIT + seg_reg * 2, seg.Limit) &&
        vmx_vmwrite_checked(vcpu, VMCS_GUEST_ES_ACCESS_RIGHTS + seg_reg * 2,
                            seg.Attributes.AsUInt) &&
        vmx_vmwrite_checked(vcpu, VMCS_GUEST_ES_BASE + seg_reg * 2, seg.Base);
}
