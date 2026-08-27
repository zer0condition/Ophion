/*
 * Persona.c - Microsoft Hyper-V guest persona for the boot hypervisor.
 *
 * Experimental identity-only surface. It is disabled by default and does not
 * advertise or implement synthetic MSRs, hypercalls, partition privileges, or
 * enlightenment leaves. Enabling it exposes only vendor/interface identity.
 *
 * Persona invariants:
 *   CPUID.1: ECX[31]=1 (hypervisor present), ECX[5]=0 (VMX hidden)
 *   CPUID.0x40000000: vendor "Microsoft Hv", max hypervisor leaf
 *   CPUID.0x40000001: interface signature "Hv#1" (0x31237648)
 *   every persona MSR and hypercall is rejected as unsupported
 */

#include "OphionBoot.h"

#define HV_MAX_LEAF             0x40000001

/* "Microsoft Hv" little-endian */
#define HV_VENDOR_EBX 0x7263694D
#define HV_VENDOR_ECX 0x666F736F
#define HV_VENDOR_EDX 0x76482074

STATIC
VOID
OpbNativeCpuid (
    UINT32 Leaf,
    UINT32 SubLeaf,
    UINT32 *Eax,
    UINT32 *Ebx,
    UINT32 *Ecx,
    UINT32 *Edx
    )
{
    AsmCpuidEx (Leaf, SubLeaf, Eax, Ebx, Ecx, Edx);
}

VOID
OpbPersonaCpuid (
    UINT32 Leaf,
    UINT32 SubLeaf,
    UINT32 *Eax,
    UINT32 *Ebx,
    UINT32 *Ecx,
    UINT32 *Edx
    )
{
    /* everything the firmware/hardware answers stays native except the
     * hypervisor window and the VMX capability bit Hyper-V hides from a
     * root partition. */
    OpbNativeCpuid (Leaf, SubLeaf, Eax, Ebx, Ecx, Edx);

#if !OPB_ENABLE_HYPERV_PERSONA
    return;
#else

    switch (Leaf) {
    case 1:
        if (Ecx != NULL) {
            *Ecx |= BIT31;          /* hypervisor present bit            */
            *Ecx &= ~(UINT32)BIT5;  /* VMX hidden, root partition view   */
            *Ecx &= ~(UINT32)BIT6;  /* SMX hidden                         */
        }
        return;

    case 0x40000000:
        if (Eax != NULL) { *Eax = HV_MAX_LEAF; }
        if (Ebx != NULL) { *Ebx = HV_VENDOR_EBX; }
        if (Ecx != NULL) { *Ecx = HV_VENDOR_ECX; }
        if (Edx != NULL) { *Edx = HV_VENDOR_EDX; }
        return;

    case 0x40000001:
        if (Eax != NULL) { *Eax = 0x31237648; } /* "Hv#1" */
        if (Ebx != NULL) { *Ebx = 0; }
        if (Ecx != NULL) { *Ecx = 0; }
        if (Edx != NULL) { *Edx = 0; }
        return;

    default:
        if (Leaf >= 0x40000000 && Leaf <= 0x4FFFFFFF) {
            if (Eax != NULL) { *Eax = 0; }
            if (Ebx != NULL) { *Ebx = 0; }
            if (Ecx != NULL) { *Ecx = 0; }
            if (Edx != NULL) { *Edx = 0; }
        }
        return;
    }
#endif
}

EFI_STATUS
OpbPersonaReadMsr (
    OPB_VCPU *Vcpu,
    UINT32 Msr,
    UINT64 *Value
    )
{
#if !OPB_ENABLE_HYPERV_PERSONA
    (VOID)Vcpu;
    (VOID)Msr;
    (VOID)Value;
    return EFI_UNSUPPORTED;
#else
    (VOID)Vcpu;
    (VOID)Msr;
    (VOID)Value;
    return EFI_UNSUPPORTED;
#endif
}

EFI_STATUS
OpbPersonaWriteMsr (
    OPB_VCPU *Vcpu,
    UINT32 Msr,
    UINT64 Value
    )
{
#if !OPB_ENABLE_HYPERV_PERSONA
    (VOID)Vcpu;
    (VOID)Msr;
    (VOID)Value;
    return EFI_UNSUPPORTED;
#else
    (VOID)Vcpu;
    (VOID)Msr;
    (VOID)Value;
    return EFI_UNSUPPORTED;
#endif
}

/* No hypercall is advertised; reject every call without side effects. */
UINT64
OpbPersonaHypercall (
    OPB_VCPU *Vcpu,
    OPB_GUEST_REGS *Regs
    )
{
#if !OPB_ENABLE_HYPERV_PERSONA
    (VOID)Vcpu;
    Regs->rdx = 0;
    return 0x0002; /* HV_STATUS_INVALID_HYPERCALL_CODE */
#else
    (VOID)Vcpu;
    Regs->rdx = 0;
    return 0x0002; /* HV_STATUS_INVALID_HYPERCALL_CODE */
#endif
}
