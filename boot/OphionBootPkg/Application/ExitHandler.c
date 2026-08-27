/*
 * ExitHandler.c - architecturally conservative DXE VM-exit dispatcher.
 *
 * The handler either emulates a deliberately intercepted instruction,
 * reinjects the event that caused the exit, or terminalizes the VCPU. It
 * never lets a VMX-root fault escape into firmware.
 */
#include "OphionBoot.h"
#include <intrin.h>

#define EXIT_EXCEPTION_OR_NMI  0
#define EXIT_EXTERNAL_INTERRUPT 1
#define EXIT_INTERRUPT_WINDOW   7
#define EXIT_NMI_WINDOW         8
#define EXIT_CPUID             10
#define EXIT_HLT               12
#define EXIT_INVD              13
#define EXIT_INVLPG            14
#define EXIT_VMCALL            18
#define EXIT_VMCLEAR           19
#define EXIT_VMLAUNCH          20
#define EXIT_VMPTRLD           21
#define EXIT_VMPTRST           22
#define EXIT_VMREAD            23
#define EXIT_VMRESUME          24
#define EXIT_VMWRITE           25
#define EXIT_VMXOFF            26
#define EXIT_VMXON             27
#define EXIT_MOV_CR            28
#define EXIT_MOV_DR            29
#define EXIT_RDMSR             31
#define EXIT_WRMSR             32
#define EXIT_VMENTRY_GUEST     33
#define EXIT_VMENTRY_MSR       34
#define EXIT_EPT_VIOLATION     48
#define EXIT_EPT_MISCONFIG     49
#define EXIT_WBINVD            54
#define EXIT_XSETBV            55
#define EXIT_VMENTRY_MACHINE   41

#define VMCS_EXEC_PROC_CONTROLS       0x00004002
#define VMCS_GUEST_CR0                0x00006800
#define VMCS_GUEST_CR3                0x00006802
#define VMCS_GUEST_CR4                0x00006804
#define VMCS_GUEST_DR7                0x0000681A
#define VMCS_GUEST_RIP                0x0000681E
#define VMCS_GUEST_RSP                0x0000681C
#define VMCS_GUEST_RFLAGS             0x00006820
#define VMCS_GUEST_INTERRUPTIBILITY   0x00004824
#define VMCS_GUEST_ACTIVITY           0x00004826
#define VMCS_CR0_READ_SHADOW          0x00006004
#define VMCS_CR4_READ_SHADOW          0x00006006
#define VMCS_EXIT_REASON              0x00004402
#define VMCS_EXIT_QUALIFICATION       0x00006400
#define VMCS_EXIT_INTERRUPTION_INFO   0x00004404
#define VMCS_EXIT_INTERRUPTION_ERROR  0x00004406
#define VMCS_INSTR_LENGTH             0x0000440C
#define VMCS_ENTRY_INTERRUPTION_INFO  0x00004016
#define VMCS_ENTRY_EXCEPTION_ERROR    0x00004018
#define VMCS_ENTRY_INSTR_LENGTH       0x0000401A

#define EXECCTRL_INT_WINDOW_EXIT      BIT2
#define EXECCTRL_NMI_WINDOW_EXIT      BIT22
#define GUEST_INTR_BLOCK_STI          BIT0
#define GUEST_INTR_BLOCK_MOV_SS       BIT1
#define GUEST_INTR_BLOCK_NMI          BIT3
#define GUEST_ACTIVITY_HLT            1
#define INTERRUPTION_TYPE_EXTERNAL    0
#define INTERRUPTION_TYPE_NMI         2
#define INTERRUPTION_TYPE_HARDWARE    3
#define INTERRUPTION_TYPE_SOFTWARE_EXCEPTION 6
#define INTERRUPTION_INFO_VALID        BIT31
#define INTERRUPTION_INFO_ERROR        BIT11
#define VMCALL_SHUTDOWN_KEY 0x4E4F485950455256ULL

#define OPB_TERMINAL_VMCS             1
#define OPB_TERMINAL_VM_ENTRY         2
#define OPB_TERMINAL_EPT              3
#define OPB_TERMINAL_CONCEAL          4
#define OPB_TERMINAL_UNEXPECTED_EXIT  5

STATIC
BOOLEAN
VmRead (
    OPB_VCPU *Vcpu,
    UINT64 Field,
    UINT64 *Value
    )
{
    if (EFI_ERROR (OpbVmread (Field, Value))) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_VMCS, Field);
        return FALSE;
    }
    return TRUE;
}

STATIC
BOOLEAN
VmWrite (
    OPB_VCPU *Vcpu,
    UINT64 Field,
    UINT64 Value
    )
{
    if (EFI_ERROR (OpbVmwrite (Field, Value))) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_VMCS, Field);
        return FALSE;
    }
    return TRUE;
}

STATIC
BOOLEAN
AdvanceRip (
    OPB_VCPU *Vcpu
    )
{
    UINT64 Rip;
    UINT64 Length;

    return VmRead (Vcpu, VMCS_GUEST_RIP, &Rip) &&
           VmRead (Vcpu, VMCS_INSTR_LENGTH, &Length) &&
           VmWrite (Vcpu, VMCS_GUEST_RIP, Rip + Length);
}

STATIC
UINT64 *
GuestRegister (
    OPB_GUEST_REGS *Regs,
    UINT32 Index
    )
{
    switch (Index) {
    case 0: return &Regs->rax;
    case 1: return &Regs->rcx;
    case 2: return &Regs->rdx;
    case 3: return &Regs->rbx;
    case 4: return &Regs->rsp;
    case 5: return &Regs->rbp;
    case 6: return &Regs->rsi;
    case 7: return &Regs->rdi;
    case 8: return &Regs->r8;
    case 9: return &Regs->r9;
    case 10: return &Regs->r10;
    case 11: return &Regs->r11;
    case 12: return &Regs->r12;
    case 13: return &Regs->r13;
    case 14: return &Regs->r14;
    default: return &Regs->r15;
    }
}

STATIC
BOOLEAN
SetWindowExiting (
    OPB_VCPU *Vcpu,
    UINT32 Bit,
    BOOLEAN Enable
    )
{
    UINT64 Controls;

    if (!VmRead (Vcpu, VMCS_EXEC_PROC_CONTROLS, &Controls)) {
        return FALSE;
    }
    if (Enable) {
        Controls |= Bit;
    } else {
        Controls &= ~((UINT64)Bit);
    }
    return VmWrite (Vcpu, VMCS_EXEC_PROC_CONTROLS, Controls);
}

STATIC
BOOLEAN
Inject (
    OPB_VCPU *Vcpu,
    UINT8 Vector,
    UINT8 Type,
    BOOLEAN HasError,
    UINT32 Error
    )
{
    UINT32 Info;

    Info = Vector | ((UINT32)Type << 8) | INTERRUPTION_INFO_VALID;
    if (HasError) {
        Info |= INTERRUPTION_INFO_ERROR;
    }
    if (!VmWrite (Vcpu, VMCS_ENTRY_INTERRUPTION_INFO, Info)) {
        return FALSE;
    }
    return !HasError || VmWrite (Vcpu, VMCS_ENTRY_EXCEPTION_ERROR, Error);
}

STATIC
VOID
InjectGp (
    OPB_VCPU *Vcpu
    )
{
    (VOID)Inject (Vcpu, 13, INTERRUPTION_TYPE_HARDWARE, TRUE, 0);
}

STATIC
VOID
InjectUd (
    OPB_VCPU *Vcpu
    )
{
    (VOID)Inject (Vcpu, 6, INTERRUPTION_TYPE_HARDWARE, FALSE, 0);
}

STATIC
BOOLEAN
GuestCanTakeInterrupt (
    OPB_VCPU *Vcpu,
    UINT8 Vector
    )
{
    UINT64 Rflags;
    UINT64 Interruptibility;

    return VmRead (Vcpu, VMCS_GUEST_RFLAGS, &Rflags) &&
           VmRead (Vcpu, VMCS_GUEST_INTERRUPTIBILITY, &Interruptibility) &&
           (Rflags & BIT9) != 0 &&
           (Interruptibility & (GUEST_INTR_BLOCK_STI | GUEST_INTR_BLOCK_MOV_SS)) == 0 &&
           (Vector >> 4) > Vcpu->guest_cr8;
}

STATIC
BOOLEAN
QueueExternalInterrupt (
    OPB_VCPU *Vcpu,
    UINT8 Vector
    )
{
    if (Vcpu->pending_ext_count == OPB_PENDING_EXT_INTERRUPTS) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_UNEXPECTED_EXIT, EXIT_EXTERNAL_INTERRUPT);
        return FALSE;
    }
    Vcpu->pending_ext_vectors[Vcpu->pending_ext_tail] = Vector;
    Vcpu->pending_ext_tail =
        (UINT8)((Vcpu->pending_ext_tail + 1) % OPB_PENDING_EXT_INTERRUPTS);
    Vcpu->pending_ext_count++;
    return SetWindowExiting (Vcpu, EXECCTRL_INT_WINDOW_EXIT, TRUE);
}

STATIC
VOID
HandleExternalInterrupt (
    OPB_VCPU *Vcpu
    )
{
    UINT64 ExitInfo;
    UINT8 Vector;

    if (!VmRead (Vcpu, VMCS_EXIT_INTERRUPTION_INFO, &ExitInfo) ||
        (ExitInfo & INTERRUPTION_INFO_VALID) == 0) {
        return;
    }
    Vector = (UINT8)ExitInfo;
    if (Vcpu->pending_ext_count == 0 && GuestCanTakeInterrupt (Vcpu, Vector)) {
        (VOID)Inject (Vcpu, Vector, INTERRUPTION_TYPE_EXTERNAL, FALSE, 0);
    } else {
        (VOID)QueueExternalInterrupt (Vcpu, Vector);
    }
}

STATIC
VOID
HandleInterruptWindow (
    OPB_VCPU *Vcpu
    )
{
    UINT8 Vector;

    if (Vcpu->pending_ext_count == 0) {
        (VOID)SetWindowExiting (Vcpu, EXECCTRL_INT_WINDOW_EXIT, FALSE);
        return;
    }
    Vector = Vcpu->pending_ext_vectors[Vcpu->pending_ext_head];
    if (!GuestCanTakeInterrupt (Vcpu, Vector)) {
        return;
    }
    Vcpu->pending_ext_head =
        (UINT8)((Vcpu->pending_ext_head + 1) % OPB_PENDING_EXT_INTERRUPTS);
    Vcpu->pending_ext_count--;
    (VOID)Inject (Vcpu, Vector, INTERRUPTION_TYPE_EXTERNAL, FALSE, 0);
    if (Vcpu->pending_ext_count == 0) {
        (VOID)SetWindowExiting (Vcpu, EXECCTRL_INT_WINDOW_EXIT, FALSE);
    }
}

STATIC
VOID
HandleExceptionOrNmi (
    OPB_VCPU *Vcpu
    )
{
    UINT64 ExitInfo;
    UINT64 Interruptibility;
    UINT8 Type;

    if (!VmRead (Vcpu, VMCS_EXIT_INTERRUPTION_INFO, &ExitInfo) ||
        (ExitInfo & INTERRUPTION_INFO_VALID) == 0) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_UNEXPECTED_EXIT, EXIT_EXCEPTION_OR_NMI);
        return;
    }
    Type = (UINT8)((ExitInfo >> 8) & 7);
    if (Type == INTERRUPTION_TYPE_NMI) {
        if (!VmRead (Vcpu, VMCS_GUEST_INTERRUPTIBILITY, &Interruptibility)) {
            return;
        }
        if ((Interruptibility & GUEST_INTR_BLOCK_NMI) != 0) {
            _InterlockedIncrement ((volatile long *)&Vcpu->nmi_pending);
            (VOID)SetWindowExiting (Vcpu, EXECCTRL_NMI_WINDOW_EXIT, TRUE);
        } else {
            (VOID)Inject (Vcpu, 2, INTERRUPTION_TYPE_NMI, FALSE, 0);
        }
        return;
    }

    if (!VmWrite (Vcpu, VMCS_ENTRY_INTERRUPTION_INFO, ExitInfo)) {
        return;
    }
    if ((ExitInfo & INTERRUPTION_INFO_ERROR) != 0) {
        UINT64 Error;
        if (VmRead (Vcpu, VMCS_EXIT_INTERRUPTION_ERROR, &Error)) {
            (VOID)VmWrite (Vcpu, VMCS_ENTRY_EXCEPTION_ERROR, Error);
        }
    }
    if (Type == INTERRUPTION_TYPE_SOFTWARE_EXCEPTION) {
        UINT64 Length;
        if (VmRead (Vcpu, VMCS_INSTR_LENGTH, &Length)) {
            (VOID)VmWrite (Vcpu, VMCS_ENTRY_INSTR_LENGTH, Length);
        }
    }
}

STATIC
VOID
HandleNmiWindow (
    OPB_VCPU *Vcpu
    )
{
    if (Vcpu->nmi_pending <= 0) {
        (VOID)SetWindowExiting (Vcpu, EXECCTRL_NMI_WINDOW_EXIT, FALSE);
        return;
    }
    Vcpu->nmi_pending--;
    (VOID)Inject (Vcpu, 2, INTERRUPTION_TYPE_NMI, FALSE, 0);
    if (Vcpu->nmi_pending == 0) {
        (VOID)SetWindowExiting (Vcpu, EXECCTRL_NMI_WINDOW_EXIT, FALSE);
    }
}

STATIC
VOID
HandleMovCr (
    OPB_VCPU *Vcpu,
    OPB_GUEST_REGS *Regs
    )
{
    UINT64 Qualification;
    UINT64 *Value;
    UINT64 Actual;
    UINT64 Fixed0;
    UINT64 Fixed1;
    UINT32 Cr;
    UINT32 Access;

    if (!VmRead (Vcpu, VMCS_EXIT_QUALIFICATION, &Qualification)) {
        return;
    }
    Cr = (UINT32)(Qualification & 0xF);
    Access = (UINT32)((Qualification >> 4) & 3);
    Value = GuestRegister (Regs, (UINT32)((Qualification >> 8) & 0xF));
    if (Access == 0) {
        switch (Cr) {
        case 0:
            Fixed0 = AsmReadMsr64 (0x486);
            Fixed1 = AsmReadMsr64 (0x487);
            Actual = (*Value | Fixed0) & Fixed1;
            (VOID)VmWrite (Vcpu, VMCS_GUEST_CR0, Actual);
            (VOID)VmWrite (Vcpu, VMCS_CR0_READ_SHADOW, *Value);
            (VOID)AdvanceRip (Vcpu);
            return;
        case 3:
            (VOID)VmWrite (Vcpu, VMCS_GUEST_CR3, *Value & ~BIT63);
            (VOID)AdvanceRip (Vcpu); /* no VPID: VM entry invalidates guest TLB */
            return;
        case 4:
            Fixed0 = AsmReadMsr64 (0x488);
            Fixed1 = AsmReadMsr64 (0x489);
            Actual = ((*Value | BIT13) | Fixed0) & Fixed1;
            (VOID)VmWrite (Vcpu, VMCS_GUEST_CR4, Actual);
            (VOID)VmWrite (Vcpu, VMCS_CR4_READ_SHADOW, *Value & ~BIT13);
            (VOID)AdvanceRip (Vcpu);
            return;
        case 8:
            if ((*Value & ~0xFULL) != 0) {
                InjectGp (Vcpu);
            } else {
                Vcpu->guest_cr8 = (UINT8)*Value;
                (VOID)AdvanceRip (Vcpu);
            }
            return;
        default:
            InjectGp (Vcpu);
            return;
        }
    }
    if (Access == 1) {
        switch (Cr) {
        case 0: (VOID)VmRead (Vcpu, VMCS_CR0_READ_SHADOW, Value); break;
        case 3: (VOID)VmRead (Vcpu, VMCS_GUEST_CR3, Value); break;
        case 4: (VOID)VmRead (Vcpu, VMCS_CR4_READ_SHADOW, Value); break;
        case 8: *Value = Vcpu->guest_cr8; break;
        default: InjectGp (Vcpu); return;
        }
        (VOID)AdvanceRip (Vcpu);
        return;
    }
    if (Access == 2 && Cr == 0) {
        (VOID)VmRead (Vcpu, VMCS_GUEST_CR0, &Actual);
        Actual &= ~BIT3;
        Actual = (Actual | AsmReadMsr64 (0x486)) & AsmReadMsr64 (0x487);
        (VOID)VmWrite (Vcpu, VMCS_GUEST_CR0, Actual);
        (VOID)VmRead (Vcpu, VMCS_CR0_READ_SHADOW, &Actual);
        (VOID)VmWrite (Vcpu, VMCS_CR0_READ_SHADOW, Actual & ~BIT3);
        (VOID)AdvanceRip (Vcpu);
        return;
    }
    if (Access == 3 && Cr == 0) {
        UINT64 Source = (Qualification >> 16) & 0xF;
        (VOID)VmRead (Vcpu, VMCS_GUEST_CR0, &Actual);
        Actual = (Actual & ~0xEULL) | (Source & 0xEULL) |
                 ((Actual | Source) & BIT0);
        Actual = (Actual | AsmReadMsr64 (0x486)) & AsmReadMsr64 (0x487);
        (VOID)VmWrite (Vcpu, VMCS_GUEST_CR0, Actual);
        (VOID)VmRead (Vcpu, VMCS_CR0_READ_SHADOW, &Actual);
        Actual = (Actual & ~0xEULL) | (Source & 0xEULL) |
                 ((Actual | Source) & BIT0);
        (VOID)VmWrite (Vcpu, VMCS_CR0_READ_SHADOW, Actual);
        (VOID)AdvanceRip (Vcpu);
        return;
    }
    InjectGp (Vcpu);
}

STATIC
VOID
HandleMovDr (
    OPB_VCPU *Vcpu,
    OPB_GUEST_REGS *Regs
    )
{
    UINT64 Qualification;
    UINT64 Cr4;
    UINT64 *Value;
    UINT32 Dr;
    UINT32 Direction;

    if (!VmRead (Vcpu, VMCS_EXIT_QUALIFICATION, &Qualification)) {
        return;
    }
    Dr = (UINT32)(Qualification & 7);
    Direction = (UINT32)((Qualification >> 4) & 1);
    Value = GuestRegister (Regs, (UINT32)((Qualification >> 8) & 0xF));
    if (Dr == 4 || Dr == 5) {
        if (!VmRead (Vcpu, VMCS_GUEST_CR4, &Cr4)) {
            return;
        }
        if ((Cr4 & BIT3) != 0) {
            InjectUd (Vcpu);
            return;
        }
        Dr = Dr == 4 ? 6 : 7;
    }
    if (Direction == 0) {
        switch (Dr) {
        case 0: Vcpu->guest_dr0 = *Value; break;
        case 1: Vcpu->guest_dr1 = *Value; break;
        case 2: Vcpu->guest_dr2 = *Value; break;
        case 3: Vcpu->guest_dr3 = *Value; break;
        case 6: Vcpu->guest_dr6 = *Value; break;
        case 7: (VOID)VmWrite (Vcpu, VMCS_GUEST_DR7, *Value); break;
        default: InjectUd (Vcpu); return;
        }
    } else {
        switch (Dr) {
        case 0: *Value = Vcpu->guest_dr0; break;
        case 1: *Value = Vcpu->guest_dr1; break;
        case 2: *Value = Vcpu->guest_dr2; break;
        case 3: *Value = Vcpu->guest_dr3; break;
        case 6: *Value = Vcpu->guest_dr6; break;
        case 7: (VOID)VmRead (Vcpu, VMCS_GUEST_DR7, Value); break;
        default: InjectUd (Vcpu); return;
        }
    }
    (VOID)AdvanceRip (Vcpu);
}

STATIC
VOID
HandleXsetbv (
    OPB_VCPU *Vcpu,
    OPB_GUEST_REGS *Regs
    )
{
    UINT32 Eax;
    UINT32 Ebx;
    UINT32 Ecx;
    UINT32 Edx;
    UINT64 Supported;
    UINT64 Value;
    UINT64 Avx512;

    if ((Regs->rcx & 0xFFFFFFFF00000000ULL) != 0 ||
        (UINT32)Regs->rcx != 0) {
        InjectGp (Vcpu);
        return;
    }
    AsmCpuidEx (0xD, 0, &Eax, &Ebx, &Ecx, &Edx);
    Supported = (UINT64)Eax | ((UINT64)Edx << 32);
    Value = (Regs->rax & MAX_UINT32) | (Regs->rdx << 32);
    Avx512 = BIT5 | BIT6 | BIT7;
    if ((Value & BIT0) == 0 || (Value & ~Supported) != 0 ||
        ((Value & BIT2) != 0 && (Value & BIT1) == 0) ||
        ((Value & Avx512) != 0 &&
         ((Value & Avx512) != Avx512 || (Value & (BIT1 | BIT2)) != (BIT1 | BIT2)))) {
        InjectGp (Vcpu);
        return;
    }
    AsmXSetBv (0, Value);
    Vcpu->xcr0 = Value;
    (VOID)AdvanceRip (Vcpu);
}

BOOLEAN
EFIAPI
OpbVmExitHandler (
    OPB_GUEST_REGS *Regs,
    OPB_VCPU *Vcpu
    )
{
    UINT64 Reason;
    UINT32 ExitReason;
    UINT32 Leaf;
    UINT32 SubLeaf;
    UINT32 Eax;
    UINT32 Ebx;
    UINT32 Ecx;
    UINT32 Edx;
    UINT32 Msr;
    UINT64 Value;
    EFI_STATUS Status;

    if (Regs == NULL || Vcpu == NULL || Vcpu->terminal) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_UNEXPECTED_EXIT, 0);
    }
    if (!VmRead (Vcpu, VMCS_EXIT_REASON, &Reason)) {
        return FALSE;
    }
    ExitReason = (UINT32)Reason & 0xFFFF;
    Vcpu->last_exit_reason = ExitReason;
    Vcpu->exit_count++;
    if (Vcpu->exit_count == 1) {
        OpbTelemetryRecord (OpbTelemetryFirstExit, Vcpu, ExitReason, 0, Reason);
    }

#if OPB_ENABLE_RUNTIME_CONCEALMENT
    if (EFI_ERROR (OpbConcealPoll (Vcpu))) {
        OpbTerminalize (Vcpu, OPB_TERMINAL_CONCEAL, ExitReason);
    }
    if (Vcpu->core_index == 0 && Vcpu->exit_count == 128) {
        if (EFI_ERROR (OpbConcealRuntimeAllocations (Vcpu))) {
            OpbTerminalize (Vcpu, OPB_TERMINAL_CONCEAL, ExitReason);
        }
    }
#endif

    switch (ExitReason) {
    case EXIT_CPUID:
        Leaf = (UINT32)Regs->rax;
        SubLeaf = (UINT32)Regs->rcx;
        OpbPersonaCpuid (Leaf, SubLeaf, &Eax, &Ebx, &Ecx, &Edx);
        Regs->rax = Eax;
        Regs->rbx = Ebx;
        Regs->rcx = Ecx;
        Regs->rdx = Edx;
        OpbTelemetryRecord (OpbTelemetryCpuid, Vcpu, Leaf, SubLeaf, Eax);
        (VOID)AdvanceRip (Vcpu);
        break;
    case EXIT_RDMSR:
        Msr = (UINT32)Regs->rcx;
        Status = OpbPersonaReadMsr (Vcpu, Msr, &Value);
        if (EFI_ERROR (Status)) {
            InjectGp (Vcpu);
        } else {
            Regs->rax = (UINT32)Value;
            Regs->rdx = (UINT32)(Value >> 32);
            OpbTelemetryRecord (OpbTelemetryMsrRead, Vcpu, Msr, 0, Value);
            (VOID)AdvanceRip (Vcpu);
        }
        break;
    case EXIT_WRMSR:
        Msr = (UINT32)Regs->rcx;
        Value = (Regs->rax & MAX_UINT32) | (Regs->rdx << 32);
        Status = OpbPersonaWriteMsr (Vcpu, Msr, Value);
        if (EFI_ERROR (Status)) {
            InjectGp (Vcpu);
        } else {
            OpbTelemetryRecord (OpbTelemetryMsrWrite, Vcpu, Msr, 0, Value);
            (VOID)AdvanceRip (Vcpu);
        }
        break;
    case EXIT_VMCALL:
        if (Regs->r12 == VMCALL_SHUTDOWN_KEY) {
            Vcpu->launched = FALSE;
            Regs->rax = 0;
            return TRUE;
        }
        Regs->rax = OpbPersonaHypercall (Vcpu, Regs);
        (VOID)AdvanceRip (Vcpu);
        break;
    case EXIT_INVD:
    case EXIT_WBINVD:
        AsmWbinvd ();
        (VOID)AdvanceRip (Vcpu);
        break;
    case EXIT_INVLPG:
        /* VPID is deliberately disabled; VM exit/entry flushes guest TLB state. */
        (VOID)AdvanceRip (Vcpu);
        break;
    case EXIT_HLT:
        (VOID)VmWrite (Vcpu, VMCS_GUEST_ACTIVITY, GUEST_ACTIVITY_HLT);
        (VOID)AdvanceRip (Vcpu);
        break;
    case EXIT_MOV_CR:
        HandleMovCr (Vcpu, Regs);
        break;
    case EXIT_MOV_DR:
        HandleMovDr (Vcpu, Regs);
        break;
    case EXIT_XSETBV:
        HandleXsetbv (Vcpu, Regs);
        break;
    case EXIT_EXTERNAL_INTERRUPT:
        HandleExternalInterrupt (Vcpu);
        break;
    case EXIT_INTERRUPT_WINDOW:
        HandleInterruptWindow (Vcpu);
        break;
    case EXIT_EXCEPTION_OR_NMI:
        HandleExceptionOrNmi (Vcpu);
        break;
    case EXIT_NMI_WINDOW:
        HandleNmiWindow (Vcpu);
        break;
    case EXIT_VMCLEAR:
    case EXIT_VMLAUNCH:
    case EXIT_VMPTRLD:
    case EXIT_VMPTRST:
    case EXIT_VMREAD:
    case EXIT_VMRESUME:
    case EXIT_VMWRITE:
    case EXIT_VMXOFF:
    case EXIT_VMXON:
        InjectUd (Vcpu);
        break;
    case EXIT_VMENTRY_GUEST:
    case EXIT_VMENTRY_MSR:
    case EXIT_VMENTRY_MACHINE:
        OpbTerminalize (Vcpu, OPB_TERMINAL_VM_ENTRY, ExitReason);
        break;
    case EXIT_EPT_VIOLATION:
    case EXIT_EPT_MISCONFIG:
        OpbTerminalize (Vcpu, OPB_TERMINAL_EPT, ExitReason);
        break;
    default:
        OpbTerminalize (Vcpu, OPB_TERMINAL_UNEXPECTED_EXIT, ExitReason);
        break;
    }
    return FALSE;
}
