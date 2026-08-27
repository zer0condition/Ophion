/*
 * OphionBoot.h - shared definitions for the boot-time hypervisor.
 *
 * UEFI firmware identity-maps installed RAM, so virtual == physical for
 * every allocation made here. All per-core state lives in one structure
 * addressed from the fixed HOST_RSP slot, exactly like the runtime core.
 */
#ifndef OPHION_BOOT_H_
#define OPHION_BOOT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Register/Intel/Cpuid.h>
#include <Register/Intel/Msr.h>

#define OPB_MAX_PROCESSORS  64
#define OPB_VMM_STACK_SIZE  0x8000
#define OPB_POOL_ALIGNMENT  0x1000

#ifndef OPB_ENABLE_RUNTIME_CONCEALMENT
#define OPB_ENABLE_RUNTIME_CONCEALMENT 1
#endif

/*
 * The partial Microsoft Hv persona is a laboratory model, not a coherent
 * TLFS implementation. Keep it fail-closed until every advertised CPUID bit,
 * synthetic MSR, and successful hypercall has an effect-conformance test.
 */
#ifndef OPB_ENABLE_HYPERV_PERSONA
#define OPB_ENABLE_HYPERV_PERSONA 0
#endif

#define OPB_MAX_RUNTIME_ALLOCS  256
#define OPB_TELEMETRY_CAPACITY  128
#define OPB_PENDING_EXT_INTERRUPTS 16

typedef enum {
    OpbTelemetryVmEntryFailure = 1,
    OpbTelemetryFirstExit,
    OpbTelemetryCpuid,
    OpbTelemetryMsrRead,
    OpbTelemetryMsrWrite,
    OpbTelemetryConcealPublish,
    OpbTelemetryConcealPrepareAck,
    OpbTelemetryConcealInvalidateAck,
    OpbTelemetryTerminal
} OPB_TELEMETRY_EVENT;

typedef struct {
    UINT64 Sequence;
    UINT64 Tsc;
    UINT32 Event;
    UINT32 Core;
    UINT32 Arg0;
    UINT32 Arg1;
    UINT64 Value;
} OPB_TELEMETRY_RECORD;

typedef struct {
    UINT32 Magic;
    UINT32 Capacity;
    volatile UINT32 WriteIndex;
    volatile UINT32 Sequence;
    OPB_TELEMETRY_RECORD Records[OPB_TELEMETRY_CAPACITY];
} OPB_TELEMETRY_RING;

typedef enum {
    OpbConcealIdle,
    OpbConcealPublishing,
    OpbConcealPrepare,
    OpbConcealInvalidate,
    OpbConcealRelease,
    OpbConcealAbort
} OPB_CONCEAL_STATE;

typedef struct {
    volatile UINT32 Generation;
    volatile UINT32 State;
    volatile UINT32 Participants;
    volatile UINT32 PrepareAcks;
    volatile UINT32 InvalidateAcks;
    UINT32 Leader;
} OPB_CONCEAL_EPOCH;

typedef enum {
    OpbAllocVmxon,
    OpbAllocVmcs,
    OpbAllocMsrBitmap,
    OpbAllocHostStack,
    OpbAllocEptTable,
    OpbAllocHostCr3,
    OpbAllocDummyPage,
    OpbAllocTelemetry
} OPB_ALLOC_KIND;

typedef struct {
    EFI_PHYSICAL_ADDRESS Base;
    UINTN                Pages;
    OPB_ALLOC_KIND        Kind;
    BOOLEAN              Conceal;
} OPB_RUNTIME_ALLOCATION;

typedef struct {
    UINT64 rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    UINT64 r8, r9, r10, r11, r12, r13, r14, r15;
} OPB_GUEST_REGS;

typedef struct {
    /* must stay first: assembly locates the VCPU from HOST_RSP. */
    volatile INT32 nmi_pending;
    volatile UINT32 active;

    UINT64 vmxon_pa;
    UINT64 vmcs_pa;
    UINT64 vmm_stack;             /* top of private host stack */
    UINT64 msr_bitmap;            /* 4KB, physical == virtual */

    UINT32 core_index;
    BOOLEAN launched;
    BOOLEAN terminal;
    UINT32 last_exit_reason;
    UINT32 terminal_reason;
    UINT64 terminal_detail;

    /* Persona and architecturally virtualized state. */
    UINT64 hv_guest_os_id;
    UINT64 hv_hypercall_gpa;
    UINT64 exit_count;
    UINT64 xcr0;
    UINT64 guest_dr0;
    UINT64 guest_dr1;
    UINT64 guest_dr2;
    UINT64 guest_dr3;
    UINT64 guest_dr6;
    UINT8 guest_cr8;
    UINT8 pending_ext_head;
    UINT8 pending_ext_tail;
    UINT8 pending_ext_count;
    UINT8 pending_ext_vectors[OPB_PENDING_EXT_INTERRUPTS];
    UINT32 conceal_prepare_generation;
    UINT32 conceal_invalidate_generation;

    OPB_GUEST_REGS regs;
} OPB_VCPU;

#pragma pack(push, 1)
typedef struct {
    UINT16 Limit;
    UINT64 Base;
} OPB_DTR;
#pragma pack(pop)
extern OPB_VCPU g_opb_vcpu[OPB_MAX_PROCESSORS];
extern UINT32 g_opb_cpu_count;
extern OPB_RUNTIME_ALLOCATION g_opb_runtime_allocs[OPB_MAX_RUNTIME_ALLOCS];
extern UINTN g_opb_runtime_alloc_count;
extern EFI_PHYSICAL_ADDRESS g_opb_host_cr3;
extern EFI_PHYSICAL_ADDRESS g_opb_dummy_page;
extern OPB_TELEMETRY_RING *g_opb_telemetry;
extern OPB_CONCEAL_EPOCH g_opb_conceal_epoch;

EFI_STATUS
OpbAllocateRuntimePages (
    OPB_ALLOC_KIND Kind,
    UINTN Pages,
    UINT64 MaxAddress,
    BOOLEAN Conceal,
    VOID **Address
    );

EFI_STATUS
OpbBuildHostIdentityCr3 (VOID);

EFI_STATUS
OpbConcealRuntimeAllocations (
    OPB_VCPU *Leader
    );

EFI_STATUS
OpbConcealPoll (
    OPB_VCPU *Vcpu
    );

VOID
OpbTelemetryInitialize (
    VOID
    );

VOID
OpbTelemetryRecord (
    OPB_TELEMETRY_EVENT Event,
    OPB_VCPU *Vcpu,
    UINT32 Arg0,
    UINT32 Arg1,
    UINT64 Value
    );

VOID
OpbTerminalize (
    OPB_VCPU *Vcpu,
    UINT32 Reason,
    UINT64 Detail
    );

VOID
EFIAPI
OpbVmxEntryFailure (
    UINT32 CoreIndex,
    UINT32 Reason
    );

/* Assembly.nasm */
extern EFI_STATUS
EFIAPI
AsmEnableVmxAndVmxon (
    UINT64 VmxonPhysicalAddress
    );

extern UINT64
EFIAPI
AsmReadCr0 (VOID);
extern UINT64
EFIAPI
AsmReadCr3 (VOID);
extern UINT64
EFIAPI
AsmReadCr4 (VOID);
/* AsmWriteCr0/AsmWriteCr4/AsmReadMsr64/AsmWriteMsr64 come from BaseLib */

extern EFI_STATUS
EFIAPI
OpbVmclear (
    UINT64 *VmcsPhysicalAddress
    );

extern EFI_STATUS
EFIAPI
OpbVmptrld (
    UINT64 *VmcsPhysicalAddress
    );

extern EFI_STATUS
EFIAPI
OpbVmread (
    UINT64 Field,
    UINT64 *Value
    );

extern EFI_STATUS
EFIAPI
OpbVmwrite (
    UINT64 Field,
    UINT64 Value
    );

extern VOID
EFIAPI
AsmVmExitStub (VOID);

extern EFI_STATUS
EFIAPI
AsmInveptSingleContext (
    UINT64 EptPointer
    );

extern VOID OpbAsmSgdt (OPB_DTR *Gdtr);
extern VOID OpbAsmSidt (OPB_DTR *Idtr);
extern UINT64 OpbAsmReadRflags (VOID);
extern UINT64 OpbAsmReadRsp (VOID);
extern UINT64 OpbGetLaunchRip (VOID);
extern UINT64 OpbGetLaunchRsp (VOID);
extern VOID OpbSetHostStackTop (VOID *StackTop);
extern VOID OpbGdtSetTr (UINT16 Selector);
extern VOID OpbGdtReadTrBase (UINT64 *TrBase);
extern VOID OpbAsmLaunchResume (VOID);

/* VmxCore.c */
EFI_STATUS
OpbSetupCurrentCore (
    UINT32 CoreIndex,
    VOID *GuestStack
    );

EFI_STATUS
EFIAPI
OpbAsmSaveAndVirtualize (
    UINT32 CoreIndex
    );

/* ExitHandler.c */
BOOLEAN
EFIAPI
OpbVmExitHandler (
    OPB_GUEST_REGS *Regs,
    OPB_VCPU *Vcpu
    );

/* Persona.c */
VOID
OpbPersonaCpuid (
    UINT32 Leaf,
    UINT32 SubLeaf,
    UINT32 *Eax,
    UINT32 *Ebx,
    UINT32 *Ecx,
    UINT32 *Edx
    );

EFI_STATUS
OpbPersonaReadMsr (
    OPB_VCPU *Vcpu,
    UINT32 Msr,
    UINT64 *Value
    );

EFI_STATUS
OpbPersonaWriteMsr (
    OPB_VCPU *Vcpu,
    UINT32 Msr,
    UINT64 Value
    );

UINT64
OpbPersonaHypercall (
    OPB_VCPU *Vcpu,
    OPB_GUEST_REGS *Regs
    );

#endif /* OPHION_BOOT_H_ */
