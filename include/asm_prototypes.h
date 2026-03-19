/*
*   asm_prototypes.h - prototypes for all masm assembly routines
*/
#pragma once

#include <ntddk.h>

//
// segment register accessors (AsmSegmentRegs.asm)
//
extern UINT16 asm_get_cs(VOID);
extern UINT16 asm_get_ds(VOID);
extern UINT16 asm_get_es(VOID);
extern UINT16 asm_get_ss(VOID);
extern UINT16 asm_get_fs(VOID);
extern UINT16 asm_get_gs(VOID);
extern UINT16 asm_get_ldtr(VOID);
extern UINT16 asm_get_tr(VOID);
extern UINT64 asm_get_gdt_base(VOID);
extern UINT64 asm_get_idt_base(VOID);
extern UINT16 asm_get_gdt_limit(VOID);
extern UINT16 asm_get_idt_limit(VOID);
extern UINT64 asm_get_rflags(VOID);

extern VOID asm_set_ds(UINT16 selector);
extern VOID asm_set_es(UINT16 selector);
extern VOID asm_set_ss(UINT16 selector);
extern VOID asm_set_fs(UINT16 selector);

//
// common routines (AsmCommon.asm)
//
extern VOID asm_reload_gdtr(PVOID gdt_base, UINT32 gdt_limit);
extern VOID asm_reload_idtr(PVOID idt_base, UINT32 idt_limit);
extern VOID asm_write_cr2(UINT64 value);

//
// VMX operation (AsmVmxOperation.asm)
//
extern VOID asm_enable_vmx(VOID);
extern NTSTATUS asm_vmx_vmcall(UINT64 vmcall_num, UINT64 param1, UINT64 param2, UINT64 param3);

//
// VMX save/restore context (AsmVmxContext.asm)
//
extern VOID asm_vmx_save_state(VOID);
extern VOID asm_vmx_restore_state(VOID);

//
// VM-exit handler entry point (asm_vmexit_handler.asm)
//
extern VOID asm_vmexit_handler(VOID);

//
// INVEPT / INVVPID (AsmVmxIntrinsics.asm)
//
extern UINT8 asm_invept(UINT32 type, PVOID descriptor);
extern UINT8 asm_invvpid(UINT32 type, PVOID descriptor);

//
// host IDT handlers (AsmHostIdt.asm)
//
extern VOID asm_host_nmi_handler(VOID);
extern VOID asm_host_df_handler(VOID);
extern VOID asm_host_gp_handler(VOID);
extern VOID asm_host_default_handler(VOID);
