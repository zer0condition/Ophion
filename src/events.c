/*
*   events.c - exception/interrupt injection into guest via vmcs
*/
#include "hv.h"

/*
*   inject #gp (general protection) exception
*   error code 0 for most software-triggered cases
*/
VOID
vmexit_inject_gp(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    info.Vector           = EXCEPTION_VECTOR_GENERAL_PROTECTION;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 1;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
}

VOID
vmexit_inject_ud(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    info.Vector           = EXCEPTION_VECTOR_UNDEFINED_OPCODE;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 0;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
}

VOID
vmexit_inject_df(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    info.Vector           = EXCEPTION_VECTOR_DOUBLE_FAULT;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 1;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
}

VOID
vmexit_inject_interrupt(UINT32 vector)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    info.Vector           = (UINT8)vector;
    info.InterruptionType = INTERRUPT_TYPE_EXTERNAL_INTERRUPT;
    info.DeliverErrorCode = 0;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
}

VOID
vmexit_inject_bp(VOID)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    info.Vector           = EXCEPTION_VECTOR_BREAKPOINT;
    info.InterruptionType = INTERRUPT_TYPE_SOFTWARE_EXCEPTION;
    info.DeliverErrorCode = 0;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);

    // software exceptions need instruction length field
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 1);
}

/*
*   inject #pf (page fault) exception
*   sets cr2 to faulting address before injection
*/
VOID
vmexit_inject_pf(UINT32 error_code, UINT64 fault_addr)
{
    VMENTRY_INTERRUPT_INFORMATION info = {0};

    asm_write_cr2(fault_addr);

    info.Vector           = EXCEPTION_VECTOR_PAGE_FAULT;
    info.InterruptionType = INTERRUPT_TYPE_HARDWARE_EXCEPTION;
    info.DeliverErrorCode = 1;
    info.Valid            = 1;

    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, info.AsUInt);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
    __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, 0);
}
