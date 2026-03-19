/*
*   hostidt.c - private host IDT for VMX-root mode
*   prevents NMI hijacking where guest corrupts OS IDT and triggers
*   NMI while in host mode to execute attacker code in ring 0
*/
#include "hv.h"

extern VOID asm_host_nmi_handler(VOID);
extern VOID asm_host_df_handler(VOID);
extern VOID asm_host_gp_handler(VOID);
extern VOID asm_host_default_handler(VOID);

static VOID
hostidt_set_gate(
    PIDT_GATE_DESCRIPTOR_64 gate,
    UINT64                  handler,
    UINT16                  selector,
    UINT8                   type,
    UINT8                   ist
)
{
    gate->OffsetLow  = (UINT16)(handler & 0xFFFF);
    gate->OffsetMid  = (UINT16)((handler >> 16) & 0xFFFF);
    gate->OffsetHigh = (UINT32)(handler >> 32);
    gate->Selector   = selector;
    gate->Ist        = ist;
    gate->Reserved0  = 0;
    gate->Type       = type;
    gate->Zero       = 0;
    gate->Dpl        = 0;
    gate->Present    = 1;
    gate->Reserved1  = 0;
}

BOOLEAN
hostidt_build(VOID)
{
    UINT16 cs;

    if (g_host_idt.initialized)
        return TRUE;

    cs = asm_get_cs() & 0xF8;

    g_host_idt.original_idt_base = asm_get_idt_base();

    //
    // default handler halts cpu — anything unexpected is a bug
    //
    for (UINT32 i = 0; i < IDT_NUM_ENTRIES; i++)
        hostidt_set_gate(&g_host_idt.idt[i], (UINT64)asm_host_default_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // NMI: sets pending flag, vmexit handler injects to guest
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_NMI], (UINT64)asm_host_nmi_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // #DF/#GP: unrecoverable in host mode, halt
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_DF], (UINT64)asm_host_df_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_GP], (UINT64)asm_host_gp_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    g_host_idt.initialized = TRUE;
    return TRUE;
}

UINT64
hostidt_get_base(VOID)
{
    return (UINT64)&g_host_idt.idt[0];
}

VOID
hostidt_destroy(VOID)
{
    g_host_idt.initialized = FALSE;
}
