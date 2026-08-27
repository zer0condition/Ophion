/*
 * VmxCore.c - per-processor VMX bring-up for the boot hypervisor.
 *
 * Bring-up model (Bluepill-style): capture the running UEFI state as the
 * guest state, switch to a private host stack, and VMLAUCH so execution
 * continues non-root at the instruction after the launch helper. From that
 * point the firmware, boot manager, and Windows all run as our guest.
 */

#include "OphionBoot.h"
#include <Library/PcdLib.h>
#include <intrin.h>

/* VMCS field encodings (Intel SDM Appendix B) */
#define VMCS_VPID                       0x00000000
#define VMCS_GUEST_ES_SELECTOR          0x00000800
#define VMCS_GUEST_CS_SELECTOR          0x00000802
#define VMCS_GUEST_SS_SELECTOR          0x00000804
#define VMCS_GUEST_DS_SELECTOR          0x00000806
#define VMCS_GUEST_FS_SELECTOR          0x00000808
#define VMCS_GUEST_GS_SELECTOR          0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR        0x0000080C
#define VMCS_GUEST_TR_SELECTOR          0x0000080E
#define VMCS_HOST_ES_SELECTOR           0x00000C00
#define VMCS_HOST_CS_SELECTOR           0x00000C02
#define VMCS_HOST_SS_SELECTOR           0x00000C04
#define VMCS_HOST_DS_SELECTOR           0x00000C06
#define VMCS_HOST_FS_SELECTOR           0x00000C08
#define VMCS_HOST_GS_SELECTOR           0x00000C0A
#define VMCS_HOST_TR_SELECTOR           0x00000C0C
#define VMCS_IO_BITMAP_A                0x00002000
#define VMCS_IO_BITMAP_B                0x00002002
#define VMCS_MSR_BITMAP                 0x00002004
#define VMCS_TSC_OFFSET                 0x00002010
#define VMCS_EXIT_MSR_STORE_COUNT       0x0000400E
#define VMCS_EXIT_MSR_LOAD_COUNT        0x00004010
#define VMCS_ENTRY_MSR_LOAD_COUNT       0x00004014
#define VMCS_EXEC_PIN_CONTROLS          0x00004000
#define VMCS_EXEC_PROC_CONTROLS         0x00004002
#define VMCS_EXEC_PROC2_CONTROLS        0x0000401E
#define VMCS_EXIT_CONTROLS              0x0000400C
#define VMCS_ENTRY_CONTROLS             0x00004012
#define VMCS_CR0_GUEST_HOST_MASK         0x00006000
#define VMCS_CR4_GUEST_HOST_MASK         0x00006002
#define VMCS_CR0_READ_SHADOW             0x00006004
#define VMCS_CR4_READ_SHADOW             0x00006006
#define VMCS_EXEC_VMCS_PTR              0x0000200A
#define VMCS_GUEST_PHYSICAL             0x00002400
#define VMCS_VMEXIT_INSTR_LENGTH        0x0000440C
#define VMCS_VMEXIT_INSTRUCTION_ERROR   0x00004400
#define VMCS_EXIT_REASON                0x00004402
#define VMCS_GUEST_LINEAR_ADDRESS       0x0000640A

#define VMCS_GUEST_CR0                  0x00006800
#define VMCS_GUEST_CR3                  0x00006802
#define VMCS_GUEST_CR4                  0x00006804
#define VMCS_GUEST_DR7                  0x0000681A
#define VMCS_GUEST_EFER                 0x00002806
#define VMCS_GUEST_RSP                  0x0000681C
#define VMCS_GUEST_RIP                  0x0000681E
#define VMCS_GUEST_RFLAGS               0x00006820
#define VMCS_GUEST_ES_BASE              0x00006806
#define VMCS_GUEST_CS_BASE              0x00006808
#define VMCS_GUEST_SS_BASE              0x0000680A
#define VMCS_GUEST_DS_BASE              0x0000680C
#define VMCS_GUEST_FS_BASE              0x0000680E
#define VMCS_GUEST_GS_BASE              0x00006810
#define VMCS_GUEST_ES_LIMIT             0x00004800
#define VMCS_GUEST_CS_LIMIT             0x00004802
#define VMCS_GUEST_SS_LIMIT             0x00004804
#define VMCS_GUEST_DS_LIMIT             0x00004806
#define VMCS_GUEST_FS_LIMIT             0x00004808
#define VMCS_GUEST_GS_LIMIT             0x0000480A
#define VMCS_GUEST_LDTR_LIMIT           0x0000480C
#define VMCS_GUEST_TR_LIMIT             0x0000480E
#define VMCS_GUEST_ES_AR                0x00004814
#define VMCS_GUEST_CS_AR                0x00004816
#define VMCS_GUEST_SS_AR                0x00004818
#define VMCS_GUEST_DS_AR                0x0000481A
#define VMCS_GUEST_FS_AR                0x0000481C
#define VMCS_GUEST_GS_AR                0x0000481E
#define VMCS_GUEST_LDTR_AR              0x00004820
#define VMCS_GUEST_TR_AR                0x00004822
#define VMCS_GUEST_IDTR_BASE            0x00006818
#define VMCS_GUEST_IDTR_LIMIT           0x00004812
#define VMCS_GUEST_GDTR_BASE            0x00006816
#define VMCS_GUEST_GDTR_LIMIT           0x00004810
#define VMCS_GUEST_SYSENTER_CS          0x0000482A
#define VMCS_GUEST_SYSENTER_ESP         0x00006824
#define VMCS_GUEST_SYSENTER_EIP         0x00006826
#define VMCS_GUEST_INTERRUPTIBILITY     0x00004824
#define VMCS_GUEST_ACTIVITY             0x00004826
#define VMCS_GUEST_PENDING_DEBUG        0x00006822

#define VMCS_HOST_CR0                   0x00006C00
#define VMCS_HOST_CR3                   0x00006C02
#define VMCS_HOST_CR4                   0x00006C04
#define VMCS_HOST_FS_BASE               0x00006C06
#define VMCS_HOST_GS_BASE               0x00006C08
#define VMCS_HOST_TR_BASE               0x00006C0A
#define VMCS_HOST_GDTR_BASE             0x00006C0C
#define VMCS_HOST_IDTR_BASE             0x00006C0E
#define VMCS_HOST_SYSENTER_CS           0x00004C00
#define VMCS_HOST_SYSENTER_ESP          0x00006C10
#define VMCS_HOST_SYSENTER_EIP          0x00006C12
#define VMCS_HOST_RSP                   0x00006C14
#define VMCS_HOST_RIP                   0x00006C16

#define PINCTRL_EXTINT_EXIT            BIT0
#define PINCTRL_NMI_EXIT               BIT3
#define PINCTRL_VIRTUAL_NMI            BIT5
#define EXECCTRL_INT_WINDOW_EXIT       BIT2
#define EXECCTRL_HLT_EXIT              BIT7
#define EXECCTRL_INVLPG_EXIT           BIT9
#define EXECCTRL_CR3_LOAD_EXIT         BIT15
#define EXECCTRL_CR3_STORE_EXIT        BIT16
#define EXECCTRL_CR8_LOAD_EXIT         BIT19
#define EXECCTRL_CR8_STORE_EXIT        BIT20
#define EXECCTRL_NMI_WINDOW_EXIT       BIT22
#define EXECCTRL_MOV_DR_EXIT           BIT23
#define EXECCTRL_USE_MSR_BITMAP        BIT28
#define EXECCTRL_USE_IO_BITMAPS        BIT25
#define EXECCTRL_ACTIVATE_SECONDARY    BIT31
#define PROC2_ENABLE_EPT               BIT1
#define EXITCTRL_HOST_64BIT            BIT9
#define EXITCTRL_ACK_INTERRUPT         BIT15
#define ENTRYCTRL_LONG_MODE_GUEST      BIT9

/* MSRs */
#define IA32_VMX_BASIC_MSR              0x480
#define IA32_FEATURE_CONTROL_MSR        0x03A
#define IA32_EFER_MSR                   0xC0000080
#define IA32_FS_BASE_MSR                0xC0000100
#define IA32_GS_BASE_MSR                0xC0000101
#define IA32_SYSENTER_CS_MSR            0x174
#define IA32_SYSENTER_ESP_MSR           0x175
#define IA32_SYSENTER_EIP_MSR           0x176

#define EXIT_REASON_CPUID               10
#define EXIT_REASON_RDMSR               31
#define EXIT_REASON_WRMSR               32

extern UINT64 AsmVmread64 (UINT64 Field);
extern UINT64 AsmVmwrite64 (UINT64 Field, UINT64 Value);
extern UINT64 OpbAsmVmlaunch (VOID);

/* raw helpers with failure capture into the vcpu */
STATIC OPB_VCPU *m_CurrentVcpu;

STATIC
UINT64
VmRead64 (
    UINT64 Field
    )
{
    return AsmVmread64 (Field);
}

STATIC
VOID
VmWrite64 (
    UINT64 Field,
    UINT64 Value
    )
{
    AsmVmwrite64 (Field, Value);
}

/* Descriptor/segment helper declarations live in OphionBoot.h. */

#define MAX_PHYS_4GB 0xFFFFFFFFULL
#define OPB_HOST_CR3_LIMIT (512ULL * 1024 * 1024 * 1024)

OPB_RUNTIME_ALLOCATION g_opb_runtime_allocs[OPB_MAX_RUNTIME_ALLOCS];
UINTN g_opb_runtime_alloc_count = 0;
EFI_PHYSICAL_ADDRESS g_opb_host_cr3 = 0;
EFI_PHYSICAL_ADDRESS g_opb_dummy_page = 0;

OPB_TELEMETRY_RING *g_opb_telemetry = NULL;
OPB_CONCEAL_EPOCH g_opb_conceal_epoch;

VOID
OpbTelemetryInitialize (
    VOID
    )
{
    VOID *Page;

    if (g_opb_telemetry != NULL) {
        return;
    }
    Page = NULL;
    if (EFI_ERROR (OpbAllocateRuntimePages (
                       OpbAllocTelemetry,
                       EFI_SIZE_TO_PAGES (sizeof (OPB_TELEMETRY_RING)),
                       MAX_PHYS_4GB,
                       TRUE,
                       &Page))) {
        return;
    }
    g_opb_telemetry = Page;
    g_opb_telemetry->Magic = SIGNATURE_32 ('O', 'P', 'B', 'T');
    g_opb_telemetry->Capacity = OPB_TELEMETRY_CAPACITY;
}

VOID
OpbTelemetryRecord (
    OPB_TELEMETRY_EVENT Event,
    OPB_VCPU *Vcpu,
    UINT32 Arg0,
    UINT32 Arg1,
    UINT64 Value
    )
{
    UINT32 Sequence;
    UINT32 Slot;
    OPB_TELEMETRY_RECORD *Record;

    if (g_opb_telemetry == NULL) {
        return;
    }
    Sequence = (UINT32)_InterlockedIncrement (
                         (volatile long *)&g_opb_telemetry->Sequence);
    Slot = (UINT32)_InterlockedIncrement (
                       (volatile long *)&g_opb_telemetry->WriteIndex) %
           OPB_TELEMETRY_CAPACITY;
    Record = &g_opb_telemetry->Records[Slot];
    Record->Tsc = AsmReadTsc ();
    Record->Event = Event;
    Record->Core = Vcpu == NULL ? MAX_UINT32 : Vcpu->core_index;
    Record->Arg0 = Arg0;
    Record->Arg1 = Arg1;
    Record->Value = Value;
    MemoryFence ();
    Record->Sequence = Sequence;
}

VOID
OpbTerminalize (
    OPB_VCPU *Vcpu,
    UINT32 Reason,
    UINT64 Detail
    )
{
    if (Vcpu != NULL) {
        Vcpu->terminal = TRUE;
        Vcpu->terminal_reason = Reason;
        Vcpu->terminal_detail = Detail;
    }
    if (g_opb_conceal_epoch.State != OpbConcealIdle &&
        g_opb_conceal_epoch.State != OpbConcealRelease) {
        g_opb_conceal_epoch.State = OpbConcealAbort;
        MemoryFence ();
    }
    OpbTelemetryRecord (OpbTelemetryTerminal, Vcpu, Reason, 0, Detail);
    CpuDeadLoop ();
}

VOID
EFIAPI
OpbVmxEntryFailure (
    UINT32 CoreIndex,
    UINT32 Reason
    )
{
    OPB_VCPU *Vcpu;

    Vcpu = CoreIndex < OPB_MAX_PROCESSORS ? &g_opb_vcpu[CoreIndex] : NULL;
    OpbTelemetryRecord (OpbTelemetryVmEntryFailure, Vcpu, Reason, 0, 0);
    OpbTerminalize (Vcpu, Reason, 0);
}

EFI_STATUS
OpbAllocateRuntimePages (
    OPB_ALLOC_KIND Kind,
    UINTN Pages,
    UINT64 MaxAddress,
    BOOLEAN Conceal,
    VOID **Address
    )
{
    EFI_PHYSICAL_ADDRESS Base;
    EFI_STATUS Status;

    if (Address == NULL || Pages == 0 ||
        g_opb_runtime_alloc_count >= OPB_MAX_RUNTIME_ALLOCS) {
        return EFI_OUT_OF_RESOURCES;
    }

    Base = MaxAddress & ~(UINT64)0xFFF;
    Status = gBS->AllocatePages (
                    MaxAddress == MAX_UINT64
                        ? AllocateAnyPages
                        : AllocateMaxAddress,
                    EfiRuntimeServicesData,
                    Pages,
                    &Base
                    );
    if (EFI_ERROR (Status)) {
        return Status;
    }

    SetMem ((VOID *)(UINTN)Base, EFI_PAGES_TO_SIZE (Pages), 0);
    g_opb_runtime_allocs[g_opb_runtime_alloc_count].Base = Base;
    g_opb_runtime_allocs[g_opb_runtime_alloc_count].Pages = Pages;
    g_opb_runtime_allocs[g_opb_runtime_alloc_count].Kind = Kind;
    g_opb_runtime_allocs[g_opb_runtime_alloc_count].Conceal = Conceal;
    g_opb_runtime_alloc_count++;
    *Address = (VOID *)(UINTN)Base;
    return EFI_SUCCESS;
}

STATIC
VOID *
OpbAllocatePage (
    OPB_ALLOC_KIND Kind,
    UINT64 MaxAddress,
    BOOLEAN Conceal
    )
{
    VOID *Page = NULL;

    if (EFI_ERROR (OpbAllocateRuntimePages (
                        Kind, 1, MaxAddress, Conceal, &Page))) {
        return NULL;
    }
    return Page;
}

EFI_STATUS
OpbBuildHostIdentityCr3 (VOID)
{
    UINT64 *Pml4;
    UINT64 *Pdpt;
    UINTN Index;
    EFI_STATUS Status;

    if (g_opb_host_cr3 != 0) {
        return EFI_SUCCESS;
    }

    Status = OpbAllocateRuntimePages (
                 OpbAllocHostCr3, 1, MAX_PHYS_4GB, TRUE, (VOID **)&Pml4);
    if (EFI_ERROR (Status)) {
        return Status;
    }
    Status = OpbAllocateRuntimePages (
                 OpbAllocHostCr3, 1, MAX_PHYS_4GB, TRUE, (VOID **)&Pdpt);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    Pml4[0] = ((UINT64)(UINTN)Pdpt & 0x000FFFFFFFFFF000ULL) | 0x3;
    for (Index = 0; Index < 512; Index++) {
        Pdpt[Index] = ((UINT64)Index << 30) | 0x83; /* 1GB RW identity */
    }
    g_opb_host_cr3 = (EFI_PHYSICAL_ADDRESS)(UINTN)Pml4;
    return EFI_SUCCESS;
}

/* segment access rights expansion for a raw selector in the current GDT */
typedef union {
    UINT64 Uint64;
    struct {
        UINT32 Lo;
        UINT32 Hi;
    };
} OPB_SEG_DESC64;

STATIC
UINT32
OpbSegmentAr (
    UINT16 Selector,
    BOOLEAN IsSystem
    )
{
    OPB_DTR Gdtr;
    OPB_SEG_DESC64 *Desc;
    UINT32 Ar;

    OpbAsmSgdt (&Gdtr);
    if (Selector == 0 || Gdtr.Base == 0) {
        return IsSystem ? 0x008B : 0x0093; /* sane TSS/data defaults */
    }
    Desc = (OPB_SEG_DESC64 *)(UINTN)(Gdtr.Base + (Selector & ~0x7));
    Ar = (Desc->Uint64 >> 40) & 0xFF;
    Ar |= (Desc->Uint64 >> 4) & 0xF00;
    if (!(Desc->Uint64 & (1ULL << 47))) {  /* present bit */
        return IsSystem ? 0x008B : 0x0093;
    }
    if (Desc->Uint64 & (1ULL << 54)) {     /* L bit - long mode CS */
        Ar |= 1ULL << 13;
    }
    return Ar;
}

STATIC
UINT32
OpbSegmentLimit (
    UINT16 Selector
    )
{
    OPB_DTR Gdtr;
    OPB_SEG_DESC64 *Desc;
    UINT32 Limit;

    OpbAsmSgdt (&Gdtr);
    if (Selector == 0 || Gdtr.Base == 0) {
        return 0xFFFFFFFF;
    }
    Desc = (OPB_SEG_DESC64 *)(UINTN)(Gdtr.Base + (Selector & ~0x7));
    Limit = (UINT32)((Desc->Uint64 & 0xFFFF) | ((Desc->Uint64 >> 32) & 0x000F0000));
    if (Desc->Uint64 & (1ULL << 55)) {     /* G bit */
        Limit = (Limit << 12) | 0xFFF;
    }
    return Limit;
}

/* EPT construction: identity map all RAM WB using 1GB leaves, honor nothing
 * else - firmware MTRRs default WB for RAM and UC for MMIO holes; EPT 1GB
 * WB across MMIO holes would be wrong, so we use the firmware memory map to
 * type RAM WB and everything else UC via 2MB entries where required. For
 * bring-up v1 we map all RAM reported by the EFI memory map as WB with 2MB
 * pages and leave every other physical range UC 2MB pages. */

typedef union {
    UINT64 Uint64;
    struct {
        UINT64 Read       : 1;  /* 0 */
        UINT64 Write      : 1;  /* 1 */
        UINT64 Execute    : 1;  /* 2 */
        UINT64 Type       : 3;  /* 3..5, leaf memory type */
        UINT64 IgnorePat  : 1;  /* 6 */
        UINT64 LargePage  : 1;  /* 7, PDE 2MB leaf */
        UINT64 Accessed   : 1;  /* 8 */
        UINT64 Dirty      : 1;  /* 9 */
        UINT64 UserExec   : 1;  /* 10 */
        UINT64 Reserved   : 1;  /* 11 */
        UINT64 PageFrame  : 40; /* 12..51 */
        UINT64 ReservedHi : 12;
    };
} OPB_EPT_ENTRY;

#define EPT_LEVELS 4

typedef struct {
    OPB_EPT_ENTRY *Pml4;
    OPB_EPT_ENTRY *Pdpt[512];
    OPB_EPT_ENTRY *Pd[512][512];      /* lazily allocated 2MB leaf tables */
} OPB_EPT_STATE;

STATIC OPB_EPT_STATE m_Ept;
STATIC UINT64 m_EptPointer = 0;
STATIC BOOLEAN m_RuntimeConcealed = FALSE;

STATIC
OPB_EPT_ENTRY *
OpbEptAllocateTable (
    VOID
    )
{
    VOID *Table = OpbAllocatePage (OpbAllocEptTable, MAX_PHYS_4GB, TRUE);
    if (Table != NULL) {
        SetMem (Table, 0x1000, 0);
    }
    return (OPB_EPT_ENTRY *)Table;
}

STATIC
EFI_STATUS
OpbEptBuildEntry (
    UINT64 GuestPhys,
    UINT64 HostPhys,
    BOOLEAN WriteBack
    )
{
    OPB_EPT_ENTRY *Pml4Entry;
    OPB_EPT_ENTRY *PdptEntry;
    OPB_EPT_ENTRY *PdEntry;
    UINT64 Pml4Index;
    UINT64 PdptIndex;
    UINT64 PdIndex;

    if (GuestPhys >= (1ULL << 46)) {
        return EFI_UNSUPPORTED;
    }

    Pml4Index = (GuestPhys >> 39) & 0x1FF;
    PdptIndex = (GuestPhys >> 30) & 0x1FF;
    PdIndex   = (GuestPhys >> 21) & 0x1FF;

    if (m_Ept.Pml4 == NULL) {
        m_Ept.Pml4 = OpbEptAllocateTable ();
        if (m_Ept.Pml4 == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
    }

    Pml4Entry = &m_Ept.Pml4[Pml4Index];
    if (!(Pml4Entry->Uint64 & 1)) {
        m_Ept.Pdpt[Pml4Index] = OpbEptAllocateTable ();
        if (m_Ept.Pdpt[Pml4Index] == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
        Pml4Entry->Uint64 = 0;
        Pml4Entry->Read = 1;
        Pml4Entry->Write = 1;
        Pml4Entry->Execute = 1;
        Pml4Entry->PageFrame = (UINT64)(UINTN)m_Ept.Pdpt[Pml4Index] >> 12;
    }

    PdptEntry = &m_Ept.Pdpt[Pml4Index][PdptIndex];
    if (!(PdptEntry->Uint64 & 1)) {
        m_Ept.Pd[Pml4Index][PdptIndex] = OpbEptAllocateTable ();
        if (m_Ept.Pd[Pml4Index][PdptIndex] == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
        PdptEntry->Uint64 = 0;
        PdptEntry->Read = 1;
        PdptEntry->Write = 1;
        PdptEntry->Execute = 1;
        PdptEntry->PageFrame = (UINT64)(UINTN)m_Ept.Pd[Pml4Index][PdptIndex] >> 12;
    }

    PdEntry = &m_Ept.Pd[Pml4Index][PdptIndex][PdIndex];
    PdEntry->Uint64 = 0;
    PdEntry->Read = 1;
    PdEntry->Write = 1;
    PdEntry->Execute = 1;
    PdEntry->LargePage = 1;
    PdEntry->Type = WriteBack ? 6 : 0;    /* WB=6, UC=0 */
    PdEntry->PageFrame = HostPhys >> 12;
    return EFI_SUCCESS;
}

/* build identity EPT: WB for every EFI runtime/conventional RAM range,
 * UC for everything else in 2MB steps covering physical address space
 * reported by CPUID.80000008. */
STATIC
EFI_STATUS
OpbEptIdentityMap (
    VOID
    )
{
    EFI_STATUS Status;
    UINTN MemoryMapSize;
    EFI_MEMORY_DESCRIPTOR *Map;
    UINTN MapKey, DescriptorSize;
    UINT32 DescriptorVersion;
    EFI_MEMORY_DESCRIPTOR *Desc;
    UINT64 Addr;
    UINT8 *MapBuffer;

    MemoryMapSize = 0;
    Map = NULL;
    Status = gBS->GetMemoryMap (&MemoryMapSize, Map, &MapKey, &DescriptorSize,
                                &DescriptorVersion);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        return Status;
    }
    MapBuffer = AllocatePool (MemoryMapSize + 2 * DescriptorSize);
    if (MapBuffer == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    Map = (EFI_MEMORY_DESCRIPTOR *)MapBuffer;
    Status = gBS->GetMemoryMap (&MemoryMapSize, Map, &MapKey, &DescriptorSize,
                                &DescriptorVersion);
    if (EFI_ERROR (Status)) {
        FreePool (MapBuffer);
        return Status;
    }

    /*
     * Map only ranges the firmware reports. This covers RAM, boot-service
     * allocations, runtime regions, and EFI memory-mapped I/O without
     * allocating a catastrophic 2MB table for every address up to CPUID's
     * physical-width ceiling. RAM is WB; firmware-declared MMIO stays UC.
     */
    Status = EFI_SUCCESS;
    for (Desc = Map;
         (UINT8 *)Desc < MapBuffer + MemoryMapSize;
         Desc = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Desc + DescriptorSize)) {
        UINT64 Start = Desc->PhysicalStart & ~(UINT64)0x1FFFFF;
        UINT64 End = (Desc->PhysicalStart +
                      (UINT64)Desc->NumberOfPages * 0x1000 + 0x1FFFFF) &
                     ~(UINT64)0x1FFFFF;
        BOOLEAN WriteBack = Desc->Type != EfiMemoryMappedIO &&
                            Desc->Type != EfiMemoryMappedIOPortSpace;

        for (Addr = Start; Addr < End; Addr += 0x200000) {
            Status = OpbEptBuildEntry (Addr, Addr, WriteBack);
            if (EFI_ERROR (Status)) {
                break;
            }
        }
        if (EFI_ERROR (Status)) {
            break;
        }
    }

    FreePool (MapBuffer);
    return Status;
}

EFI_STATUS
OpbEptSplit2Mb (
    UINT64 GuestPhysical,
    OPB_EPT_ENTRY **Leaf
    )
{
    UINTN Pml4Index = (GuestPhysical >> 39) & 0x1FF;
    UINTN PdptIndex = (GuestPhysical >> 30) & 0x1FF;
    UINTN PdIndex = (GuestPhysical >> 21) & 0x1FF;
    UINTN PtIndex = (GuestPhysical >> 12) & 0x1FF;
    OPB_EPT_ENTRY *Pde;
    OPB_EPT_ENTRY *Pt;
    UINT64 Original;
    UINT64 Base;
    UINTN Index;

    if (Pml4Index >= 512 || m_Ept.Pd[Pml4Index][PdptIndex] == NULL) {
        return EFI_NOT_FOUND;
    }

    Pde = &m_Ept.Pd[Pml4Index][PdptIndex][PdIndex];
    if (Pde->LargePage) {
        Pt = OpbEptAllocateTable ();
        if (Pt == NULL) {
            return EFI_OUT_OF_RESOURCES;
        }
        Original = Pde->Uint64;
        Base = Original & 0x000FFFFFFFE00000ULL;
        for (Index = 0; Index < 512; Index++) {
            Pt[Index].Uint64 = (Original & ~((UINT64)BIT7 |
                                0x000FFFFFFFFFF000ULL)) |
                               (Base + ((UINT64)Index << 12));
        }
        Pde->Uint64 = 0;
        Pde->Read = 1;
        Pde->Write = 1;
        Pde->Execute = 1;
        Pde->PageFrame = (UINT64)(UINTN)Pt >> 12;
    }

    Pt = (OPB_EPT_ENTRY *)(UINTN)(Pde->PageFrame << 12);
    *Leaf = &Pt[PtIndex];
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
OpbApplyConcealment (
    VOID
    )
{
    EFI_STATUS Status;
    UINTN AllocationIndex;

    if (g_opb_dummy_page == 0) {
        return EFI_NOT_READY;
    }

    for (AllocationIndex = 0;
         AllocationIndex < g_opb_runtime_alloc_count;
         AllocationIndex++) {
        OPB_RUNTIME_ALLOCATION *Allocation;
        UINTN Page;

        Allocation = &g_opb_runtime_allocs[AllocationIndex];
        if (!Allocation->Conceal || Allocation->Kind == OpbAllocDummyPage) {
            continue;
        }
        for (Page = 0; Page < Allocation->Pages; Page++) {
            OPB_EPT_ENTRY *Leaf;

            Status = OpbEptSplit2Mb (
                         Allocation->Base + EFI_PAGES_TO_SIZE (Page), &Leaf);
            if (EFI_ERROR (Status)) {
                return Status;
            }
            Leaf->PageFrame = g_opb_dummy_page >> 12;
            Leaf->Read = 1;
            Leaf->Write = 1;
            Leaf->Execute = 0;
            Leaf->Type = 6;
        }
    }
    return EFI_SUCCESS;
}

STATIC
EFI_STATUS
OpbConcealAcknowledge (
    OPB_VCPU *Vcpu,
    BOOLEAN Invalidate
    )
{
    EFI_STATUS Status;
    UINT32 Generation;

    Generation = g_opb_conceal_epoch.Generation;
    if (Invalidate) {
        if (Vcpu->conceal_invalidate_generation == Generation) {
            return EFI_SUCCESS;
        }
    } else if (Vcpu->conceal_prepare_generation == Generation) {
        return EFI_SUCCESS;
    }

    Status = AsmInveptSingleContext (m_EptPointer);
    if (EFI_ERROR (Status)) {
        g_opb_conceal_epoch.State = OpbConcealAbort;
        MemoryFence ();
        return Status;
    }

    if (Invalidate) {
        Vcpu->conceal_invalidate_generation = Generation;
        (VOID)_InterlockedIncrement (
            (volatile long *)&g_opb_conceal_epoch.InvalidateAcks);
        OpbTelemetryRecord (
            OpbTelemetryConcealInvalidateAck, Vcpu, Generation,
            g_opb_conceal_epoch.InvalidateAcks, m_EptPointer);
    } else {
        Vcpu->conceal_prepare_generation = Generation;
        (VOID)_InterlockedIncrement (
            (volatile long *)&g_opb_conceal_epoch.PrepareAcks);
        OpbTelemetryRecord (
            OpbTelemetryConcealPrepareAck, Vcpu, Generation,
            g_opb_conceal_epoch.PrepareAcks, m_EptPointer);
    }
    MemoryFence ();
    return EFI_SUCCESS;
}

EFI_STATUS
OpbConcealPoll (
    OPB_VCPU *Vcpu
    )
{
    EFI_STATUS Status;
    UINT32 State;

    if (Vcpu == NULL || !Vcpu->launched) {
        return EFI_SUCCESS;
    }
    for (;;) {
        State = g_opb_conceal_epoch.State;
        if (State == OpbConcealIdle || State == OpbConcealRelease) {
            return EFI_SUCCESS;
        }
        if (State == OpbConcealAbort) {
            return EFI_DEVICE_ERROR;
        }
        if (State == OpbConcealPublishing) {
            CpuPause ();
            continue;
        }
        if (State == OpbConcealPrepare) {
            Status = OpbConcealAcknowledge (Vcpu, FALSE);
        } else {
            Status = OpbConcealAcknowledge (Vcpu, TRUE);
        }
        if (EFI_ERROR (Status)) {
            return Status;
        }
        CpuPause ();
    }
}

EFI_STATUS
OpbConcealRuntimeAllocations (
    OPB_VCPU *Leader
    )
{
    EFI_STATUS Status;
    UINT32 Participants;
    UINTN Index;

    if (Leader == NULL || m_RuntimeConcealed) {
        return Leader == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
    }
    if ((UINT32)_InterlockedCompareExchange (
            (volatile long *)&g_opb_conceal_epoch.State,
            (long)OpbConcealPublishing,
            (long)OpbConcealIdle) != OpbConcealIdle) {
        return OpbConcealPoll (Leader);
    }

    Participants = 0;
    for (Index = 0; Index < g_opb_cpu_count; Index++) {
        if (g_opb_vcpu[Index].launched && !g_opb_vcpu[Index].terminal) {
            Participants++;
        }
    }
    if (Participants == 0) {
        g_opb_conceal_epoch.State = OpbConcealAbort;
        return EFI_NOT_READY;
    }
    g_opb_conceal_epoch.Leader = Leader->core_index;
    g_opb_conceal_epoch.Participants = Participants;
    g_opb_conceal_epoch.PrepareAcks = 0;
    g_opb_conceal_epoch.InvalidateAcks = 0;
    g_opb_conceal_epoch.Generation++;
    MemoryFence ();
    g_opb_conceal_epoch.State = OpbConcealPrepare;
    OpbTelemetryRecord (
        OpbTelemetryConcealPublish, Leader, g_opb_conceal_epoch.Generation,
        Participants, m_EptPointer);

    Status = OpbConcealAcknowledge (Leader, FALSE);
    if (EFI_ERROR (Status)) {
        return Status;
    }
    while (g_opb_conceal_epoch.PrepareAcks != Participants) {
        if (g_opb_conceal_epoch.State == OpbConcealAbort) {
            return EFI_DEVICE_ERROR;
        }
        CpuPause ();
    }

    /*
     * Every launched VCPU is now held in VMX root. No mapping changes before
     * this barrier, and no guest resumes until the post-change INVEPT barrier.
     */
    Status = OpbApplyConcealment ();
    if (EFI_ERROR (Status)) {
        g_opb_conceal_epoch.State = OpbConcealAbort;
        MemoryFence ();
        return Status;
    }
    m_RuntimeConcealed = TRUE;
    MemoryFence ();
    g_opb_conceal_epoch.State = OpbConcealInvalidate;
    Status = OpbConcealAcknowledge (Leader, TRUE);
    if (EFI_ERROR (Status)) {
        return Status;
    }
    while (g_opb_conceal_epoch.InvalidateAcks != Participants) {
        if (g_opb_conceal_epoch.State == OpbConcealAbort) {
            return EFI_DEVICE_ERROR;
        }
        CpuPause ();
    }
    MemoryFence ();
    g_opb_conceal_epoch.State = OpbConcealRelease;
    return EFI_SUCCESS;
}

/* update CR0/CR4 to satisfy VMX fixed bits and enable VMXE */
STATIC
EFI_STATUS
OpbEnableVmx (
    VOID
    )
{
    UINT64 FeatureControl;
    UINT64 Cr0;
    UINT64 Cr4;
    UINT64 Fixed0;
    UINT64 Fixed1;

    FeatureControl = AsmReadMsr64 (IA32_FEATURE_CONTROL_MSR);
    if ((FeatureControl & (1ULL << 0)) == 0) {
        /* unlocked: lock with VMX outside SMX enabled - boot context duty */
        FeatureControl |= (1ULL << 0) | (1ULL << 2);
        AsmWriteMsr64 (IA32_FEATURE_CONTROL_MSR, FeatureControl);
    } else if ((FeatureControl & (1ULL << 2)) == 0) {
        return EFI_UNSUPPORTED;
    }

    Fixed0 = AsmReadMsr64 (0x486);
    Fixed1 = AsmReadMsr64 (0x487);
    Cr0 = AsmReadCr0 ();
    Cr0 |= Fixed0;
    Cr0 &= Fixed1;
    AsmWriteCr0 (Cr0);

    Fixed0 = AsmReadMsr64 (0x488);
    Fixed1 = AsmReadMsr64 (0x489);
    Cr4 = AsmReadCr4 ();
    Cr4 |= Fixed0;
    Cr4 &= Fixed1;
    AsmWriteCr4 (Cr4);
    return EFI_SUCCESS;
}

STATIC
UINT32
OpbAdjustControls (
    UINT32 Requested,
    UINT32 CapabilityMsr
    )
{
    UINT64 Capability = AsmReadMsr64 (CapabilityMsr);

    return (Requested | (UINT32)Capability) &
           (UINT32)(Capability >> 32);
}


/* Per-core VMCS setup. The assembly wrapper captures every guest GPR and
 * calls this routine with GuestStack pointing at that saved frame; VMLAUNCH
 * happens only after this routine returns successfully. */
EFI_STATUS
OpbSetupCurrentCore (
    UINT32 CoreIndex,
    VOID *GuestStack
    )
{
    OPB_VCPU *Vcpu;
    VOID *VmxonRegion;
    VOID *VmcsRegion;
    UINT8 *MsrBitmap;
    VOID *HostStack;
    UINT64 RevisionId;
    EFI_STATUS Status;
    UINT64 EptPointer;
    OPB_DTR Gdtr, Idtr;
    UINT64 TrBase;
    UINT32 PinControls, ProcControls, Proc2Controls, ExitControls;
    UINT32 EntryControls;

    if (CoreIndex >= OPB_MAX_PROCESSORS) {
        return EFI_UNSUPPORTED;
    }
    Vcpu = &g_opb_vcpu[CoreIndex];
    m_CurrentVcpu = Vcpu;
    Vcpu->core_index = CoreIndex;

    Status = OpbEnableVmx ();
    if (EFI_ERROR (Status)) {
        return Status;
    }

    VmxonRegion = OpbAllocatePage (OpbAllocVmxon, MAX_PHYS_4GB, TRUE);
    VmcsRegion = OpbAllocatePage (OpbAllocVmcs, MAX_PHYS_4GB, TRUE);
    MsrBitmap = OpbAllocatePage (OpbAllocMsrBitmap, MAX_PHYS_4GB, TRUE);
    Status = OpbAllocateRuntimePages (
                 OpbAllocHostStack,
                 EFI_SIZE_TO_PAGES (OPB_VMM_STACK_SIZE),
                 MAX_PHYS_4GB,
                 TRUE,
                 &HostStack
                 );
    if (VmxonRegion == NULL || VmcsRegion == NULL || MsrBitmap == NULL ||
        EFI_ERROR (Status) || HostStack == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    SetMem (VmxonRegion, 0x1000, 0);
    SetMem (VmcsRegion, 0x1000, 0);
    SetMem (MsrBitmap, 0x1000, 0);
    SetMem (HostStack, OPB_VMM_STACK_SIZE, 0);

#if OPB_ENABLE_RUNTIME_CONCEALMENT
    /*
     * Concealment cannot allocate after ExitBootServices. Allocate its dummy
     * page before the shared EPT snapshot so it is a valid, non-concealed GPA.
     */
    if (g_opb_dummy_page == 0) {
        VOID *Dummy;

        Dummy = NULL;
        Status = OpbAllocateRuntimePages (
                     OpbAllocDummyPage, 1, MAX_PHYS_4GB, FALSE, &Dummy);
        if (EFI_ERROR (Status)) {
            return Status;
        }
        SetMem (Dummy, 0x1000, 0xFF);
        g_opb_dummy_page = (EFI_PHYSICAL_ADDRESS)(UINTN)Dummy;
    }
#endif

    /*
     * The Intel MSR bitmap explicitly covers only low (0x0000-0x1FFF)
     * and high (0xC0000000-0xC0001FFF) architectural ranges. Hyper-V
     * synthetic MSRs sit outside both and therefore exit unconditionally
     * while USE_MSR_BITMAPS is set; do not index them into this 4KB bitmap.
     */

    /* CPUID exiting is requested through the primary controls below; all
     * CPUID leaves route through the persona. */

    RevisionId = AsmReadMsr64 (IA32_VMX_BASIC_MSR) & 0x7FFFFFFF;
    *(UINT64 *)VmxonRegion = RevisionId;
    *(UINT64 *)VmcsRegion = RevisionId;

    Vcpu->vmxon_pa = (UINT64)(UINTN)VmxonRegion;
    Vcpu->vmcs_pa = (UINT64)(UINTN)VmcsRegion;
    Vcpu->msr_bitmap = (UINT64)(UINTN)MsrBitmap;
    Vcpu->vmm_stack = (UINT64)(UINTN)((UINT8 *)HostStack + OPB_VMM_STACK_SIZE);

    /* EPT is shared across cores: build once from BSP before AP bring-up. */
    if (m_Ept.Pml4 == NULL) {
        Status = OpbEptIdentityMap ();
        if (EFI_ERROR (Status)) {
            return Status;
        }
    }
    Status = OpbBuildHostIdentityCr3 ();
    if (EFI_ERROR (Status)) {
        return Status;
    }

    /* EPTP: WB memory type (bits 2:0), 4-level walk (bits 5:3=3),
     * page-table PFN at bit 12. */
    EptPointer = 6 |
                 ((UINT64)(EPT_LEVELS - 1) << 3) |
                 (((UINT64)(UINTN)m_Ept.Pml4 >> 12) << 12);

    Status = AsmEnableVmxAndVmxon ((UINT64)(UINTN)VmxonRegion);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    /* VMCLEAR + VMPTRLD via NASM helpers */
    Status = OpbVmclear (&Vcpu->vmcs_pa);
    if (EFI_ERROR (Status)) {
        return Status;
    }
    Status = OpbVmptrld (&Vcpu->vmcs_pa);
    m_EptPointer = EptPointer;
    if (EFI_ERROR (Status)) {
        return Status;
    }

    /* program the VMCS: guest = current firmware state */
    OpbAsmSgdt (&Gdtr);
    OpbAsmSidt (&Idtr);

    VmWrite64 (VMCS_HOST_CS_SELECTOR, AsmReadCs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_SS_SELECTOR, AsmReadSs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_DS_SELECTOR, AsmReadDs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_ES_SELECTOR, AsmReadEs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_FS_SELECTOR, AsmReadFs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_GS_SELECTOR, AsmReadGs () & 0xFFF8);
    VmWrite64 (VMCS_HOST_TR_SELECTOR, AsmReadTr () & 0xFFF8);

    VmWrite64 (VMCS_GUEST_CS_SELECTOR, AsmReadCs ());
    VmWrite64 (VMCS_GUEST_SS_SELECTOR, AsmReadSs ());
    VmWrite64 (VMCS_GUEST_DS_SELECTOR, AsmReadDs ());
    VmWrite64 (VMCS_GUEST_ES_SELECTOR, AsmReadEs ());
    VmWrite64 (VMCS_GUEST_FS_SELECTOR, AsmReadFs ());
    VmWrite64 (VMCS_GUEST_GS_SELECTOR, AsmReadGs ());
    VmWrite64 (VMCS_GUEST_LDTR_SELECTOR, 0);
    VmWrite64 (VMCS_GUEST_TR_SELECTOR, AsmReadTr ());

    VmWrite64 (VMCS_GUEST_CS_AR, OpbSegmentAr (AsmReadCs (), FALSE));
    VmWrite64 (VMCS_GUEST_SS_AR, OpbSegmentAr (AsmReadSs (), FALSE));
    VmWrite64 (VMCS_GUEST_DS_AR, OpbSegmentAr (AsmReadDs (), FALSE));
    VmWrite64 (VMCS_GUEST_ES_AR, OpbSegmentAr (AsmReadEs (), FALSE));
    VmWrite64 (VMCS_GUEST_FS_AR, OpbSegmentAr (AsmReadFs (), FALSE));
    VmWrite64 (VMCS_GUEST_GS_AR, OpbSegmentAr (AsmReadGs (), FALSE));
    VmWrite64 (VMCS_GUEST_LDTR_AR, 0x10000);   /* unusable */
    VmWrite64 (VMCS_GUEST_TR_AR, OpbSegmentAr (AsmReadTr (), TRUE));

    VmWrite64 (VMCS_GUEST_CS_LIMIT, OpbSegmentLimit (AsmReadCs ()));
    VmWrite64 (VMCS_GUEST_SS_LIMIT, OpbSegmentLimit (AsmReadSs ()));
    VmWrite64 (VMCS_GUEST_DS_LIMIT, OpbSegmentLimit (AsmReadDs ()));
    VmWrite64 (VMCS_GUEST_ES_LIMIT, OpbSegmentLimit (AsmReadEs ()));
    VmWrite64 (VMCS_GUEST_FS_LIMIT, OpbSegmentLimit (AsmReadFs ()));
    VmWrite64 (VMCS_GUEST_GS_LIMIT, OpbSegmentLimit (AsmReadGs ()));
    VmWrite64 (VMCS_GUEST_TR_LIMIT, OpbSegmentLimit (AsmReadTr ()));

    VmWrite64 (VMCS_GUEST_IDTR_BASE, Idtr.Base);
    VmWrite64 (VMCS_GUEST_IDTR_LIMIT, Idtr.Limit);
    VmWrite64 (VMCS_GUEST_GDTR_BASE, Gdtr.Base);
    VmWrite64 (VMCS_GUEST_GDTR_LIMIT, Gdtr.Limit);

    /* host TR base from the GDT */
    OpbGdtReadTrBase (&TrBase);
    VmWrite64 (VMCS_HOST_TR_BASE, TrBase);
    VmWrite64 (VMCS_HOST_GDTR_BASE, Gdtr.Base);
    VmWrite64 (VMCS_HOST_IDTR_BASE, Idtr.Base);

    VmWrite64 (VMCS_GUEST_ES_BASE, 0);
    VmWrite64 (VMCS_GUEST_CS_BASE, 0);
    VmWrite64 (VMCS_GUEST_SS_BASE, 0);
    VmWrite64 (VMCS_GUEST_DS_BASE, 0);
    VmWrite64 (VMCS_GUEST_FS_BASE, AsmReadMsr64 (IA32_FS_BASE_MSR));
    VmWrite64 (VMCS_GUEST_GS_BASE, AsmReadMsr64 (IA32_GS_BASE_MSR));
    VmWrite64 (0x00006812, 0);      /* GUEST_LDTR_BASE */
    VmWrite64 (0x00006814, TrBase); /* GUEST_TR_BASE */
    VmWrite64 (VMCS_GUEST_CR0, AsmReadCr0 ());
    VmWrite64 (VMCS_GUEST_CR3, AsmReadCr3 ());
    VmWrite64 (VMCS_GUEST_CR4, AsmReadCr4 () | 0x2000);
    VmWrite64 (VMCS_GUEST_DR7, 0x400);
    VmWrite64 (VMCS_GUEST_EFER, AsmReadMsr64 (IA32_EFER_MSR));
    /*
     * Intercept CR0/CR4 through read shadows so the guest's requested state
     * is preserved while VMX fixed bits and CR4.VMXE remain host-owned.
     */
    VmWrite64 (VMCS_CR0_GUEST_HOST_MASK, MAX_UINT64);
    VmWrite64 (VMCS_CR0_READ_SHADOW, AsmReadCr0 ());
    VmWrite64 (VMCS_CR4_GUEST_HOST_MASK, MAX_UINT64);
    VmWrite64 (VMCS_CR4_READ_SHADOW, AsmReadCr4 () & ~0x2000ULL);

    VmWrite64 (VMCS_HOST_CR0, AsmReadCr0 ());
    VmWrite64 (VMCS_HOST_CR3, g_opb_host_cr3);
    VmWrite64 (VMCS_HOST_FS_BASE, AsmReadMsr64 (IA32_FS_BASE_MSR));
    VmWrite64 (VMCS_HOST_GS_BASE, AsmReadMsr64 (IA32_GS_BASE_MSR));
    VmWrite64 (VMCS_HOST_SYSENTER_CS, AsmReadMsr64 (IA32_SYSENTER_CS_MSR));
    VmWrite64 (VMCS_HOST_SYSENTER_ESP, AsmReadMsr64 (IA32_SYSENTER_ESP_MSR));
    VmWrite64 (VMCS_HOST_SYSENTER_EIP, AsmReadMsr64 (IA32_SYSENTER_EIP_MSR));

    /* Capability-correct controls: (requested | allowed-0) & allowed-1. */
    RevisionId = AsmReadMsr64 (IA32_VMX_BASIC_MSR);
    if (RevisionId & (1ULL << 55)) {
        PinControls = OpbAdjustControls (
                          PINCTRL_EXTINT_EXIT | PINCTRL_NMI_EXIT |
                          PINCTRL_VIRTUAL_NMI, 0x48D);
        ProcControls = OpbAdjustControls (
                         EXECCTRL_HLT_EXIT |
                         EXECCTRL_INVLPG_EXIT |
                         EXECCTRL_CR3_LOAD_EXIT |
                         EXECCTRL_CR3_STORE_EXIT |
                         EXECCTRL_CR8_LOAD_EXIT |
                         EXECCTRL_CR8_STORE_EXIT |
                         EXECCTRL_MOV_DR_EXIT |
                         EXECCTRL_USE_MSR_BITMAP |
                         EXECCTRL_USE_IO_BITMAPS |
                         EXECCTRL_ACTIVATE_SECONDARY,
                         0x48E);
        ExitControls = OpbAdjustControls (
                          EXITCTRL_HOST_64BIT | EXITCTRL_ACK_INTERRUPT, 0x48F);
        EntryControls = OpbAdjustControls (ENTRYCTRL_LONG_MODE_GUEST, 0x490);
    } else {
        PinControls = OpbAdjustControls (
                          PINCTRL_EXTINT_EXIT | PINCTRL_NMI_EXIT |
                          PINCTRL_VIRTUAL_NMI, 0x481);
        ProcControls = OpbAdjustControls (
                         EXECCTRL_HLT_EXIT |
                         EXECCTRL_INVLPG_EXIT |
                         EXECCTRL_CR3_LOAD_EXIT |
                         EXECCTRL_CR3_STORE_EXIT |
                         EXECCTRL_CR8_LOAD_EXIT |
                         EXECCTRL_CR8_STORE_EXIT |
                         EXECCTRL_MOV_DR_EXIT |
                         EXECCTRL_USE_MSR_BITMAP |
                         EXECCTRL_USE_IO_BITMAPS |
                         EXECCTRL_ACTIVATE_SECONDARY,
                         0x482);
        ExitControls = OpbAdjustControls (
                          EXITCTRL_HOST_64BIT | EXITCTRL_ACK_INTERRUPT, 0x483);
        EntryControls = OpbAdjustControls (ENTRYCTRL_LONG_MODE_GUEST, 0x484);
    }
    Proc2Controls = OpbAdjustControls (PROC2_ENABLE_EPT, 0x48B);
    if (!(PinControls & PINCTRL_EXTINT_EXIT) ||
        !(PinControls & PINCTRL_NMI_EXIT) ||
        !(ProcControls & EXECCTRL_ACTIVATE_SECONDARY) ||
        !(Proc2Controls & PROC2_ENABLE_EPT) ||
        !(ExitControls & EXITCTRL_ACK_INTERRUPT)) {
        return EFI_UNSUPPORTED;
    }

    VmWrite64 (VMCS_EXEC_PIN_CONTROLS, PinControls);
    VmWrite64 (VMCS_EXEC_PROC_CONTROLS, ProcControls);
    VmWrite64 (VMCS_EXEC_PROC2_CONTROLS, Proc2Controls);
    VmWrite64 (VMCS_EXIT_CONTROLS, ExitControls);
    VmWrite64 (VMCS_ENTRY_CONTROLS, EntryControls);
    VmWrite64 (VMCS_TSC_OFFSET, 0);
    VmWrite64 (VMCS_EXIT_MSR_STORE_COUNT, 0);
    VmWrite64 (VMCS_EXIT_MSR_LOAD_COUNT, 0);
    VmWrite64 (VMCS_ENTRY_MSR_LOAD_COUNT, 0);
    VmWrite64 (VMCS_IO_BITMAP_A, 0);
    VmWrite64 (VMCS_IO_BITMAP_B, 0);
    VmWrite64 (VMCS_MSR_BITMAP, Vcpu->msr_bitmap);
    VmWrite64 (VMCS_EXEC_VMCS_PTR, 0xFFFFFFFFFFFFFFFFULL);

    /* EPTP lives in the secondary-control-linked field 0x0000201A */
    VmWrite64 (0x0000201A, EptPointer);

    VmWrite64 (VMCS_GUEST_INTERRUPTIBILITY, 0);
    VmWrite64 (VMCS_GUEST_ACTIVITY, 0);
    VmWrite64 (VMCS_GUEST_PENDING_DEBUG, 0);
    VmWrite64 (VMCS_GUEST_SYSENTER_CS, AsmReadMsr64 (IA32_SYSENTER_CS_MSR));
    VmWrite64 (VMCS_GUEST_SYSENTER_ESP, AsmReadMsr64 (IA32_SYSENTER_ESP_MSR));
    VmWrite64 (VMCS_GUEST_SYSENTER_EIP, AsmReadMsr64 (IA32_SYSENTER_EIP_MSR));

    /* host stack layout: [top-8]=vcpu, [top-16]=HOST_RSP */
    *(OPB_VCPU **)(UINTN)(Vcpu->vmm_stack - 8) = Vcpu;
    VmWrite64 (VMCS_HOST_RSP, Vcpu->vmm_stack - 16);
    VmWrite64 (VMCS_HOST_RIP, (UINT64)(UINTN)AsmVmExitStub);

    /*
     * Resume through the assembly frame unwinder so the guest receives the
     * exact GPR/RFLAGS state it had before C setup executed. The saved
     * RFLAGS is at GuestStack+0x98 (0x20 shadow + 15 pushed GPRs).
     */
    VmWrite64 (VMCS_GUEST_RIP, (UINT64)(UINTN)OpbAsmLaunchResume);
    VmWrite64 (VMCS_GUEST_RSP, (UINT64)(UINTN)GuestStack);
    VmWrite64 (VMCS_GUEST_RFLAGS,
                *(UINT64 *)((UINT8 *)GuestStack + 0x98));

    Vcpu->guest_cr8 = 0;
    Vcpu->active = TRUE;
    Vcpu->launched = TRUE;
    return EFI_SUCCESS;
}
