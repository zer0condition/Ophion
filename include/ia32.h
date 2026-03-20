/**
 * @file ia32.h
 * @brief Minimal Intel IA-32/64 architecture definitions for VMX hypervisor
 * @details Self-contained — no dependency on external ia32-doc or Windows headers
 *          for architecture constants. Based on Intel SDM Vol 3.
 */
#pragma once

#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable : 4201)


#define NULL64_ZERO            0ULL

#ifndef PAGE_SIZE
#define PAGE_SIZE              0x1000
#endif

#ifndef ALIGNMENT_PAGE_SIZE
#define ALIGNMENT_PAGE_SIZE    PAGE_SIZE
#endif
#define SIZE_2_MB              (512ULL * PAGE_SIZE)
#define SIZE_1_GB              (512ULL * SIZE_2_MB)
#define SIZE_512_GB            (512ULL * SIZE_1_GB)

//
// MSR Indices (Intel SDM Appendix B)
//

#define IA32_FEATURE_CONTROL           0x0000003A
#define IA32_DEBUGCTL                  0x000001D9
#define IA32_SYSENTER_CS               0x00000174
#define IA32_SYSENTER_ESP              0x00000175
#define IA32_SYSENTER_EIP              0x00000176
#define IA32_FS_BASE                   0xC0000100
#define IA32_GS_BASE                   0xC0000101
#define IA32_KERNEL_GS_BASE            0xC0000102
#define IA32_TSC_AUX                   0xC0000103
#define IA32_EFER                      0xC0000080
#define IA32_LSTAR                     0xC0000082
#define IA32_DS_AREA                   0x00000600

//
// VMX-specific MSRs
//
#define IA32_VMX_BASIC                 0x00000480
#define IA32_VMX_PINBASED_CTLS         0x00000481
#define IA32_VMX_PROCBASED_CTLS        0x00000482
#define IA32_VMX_EXIT_CTLS             0x00000483
#define IA32_VMX_ENTRY_CTLS            0x00000484
#define IA32_VMX_MISC                  0x00000485
#define IA32_VMX_CR0_FIXED0            0x00000486
#define IA32_VMX_CR0_FIXED1            0x00000487
#define IA32_VMX_CR4_FIXED0            0x00000488
#define IA32_VMX_CR4_FIXED1            0x00000489
#define IA32_VMX_PROCBASED_CTLS2       0x0000048B
#define IA32_VMX_EPT_VPID_CAP          0x0000048C
#define IA32_VMX_TRUE_PINBASED_CTLS    0x0000048D
#define IA32_VMX_TRUE_PROCBASED_CTLS   0x0000048E
#define IA32_VMX_TRUE_EXIT_CTLS        0x0000048F
#define IA32_VMX_TRUE_ENTRY_CTLS       0x00000490
#define IA32_VMX_VMCS_ENUM             0x0000048A
#define IA32_VMX_VMFUNC                0x00000491
#define IA32_VMX_PROCBASED_CTLS3       0x00000492
#define IA32_VMX_EXIT_CTLS2            0x00000493

//
// MTRR MSRs
//
#define IA32_MTRR_CAPABILITIES         0x000000FE
#define IA32_MTRR_DEF_TYPE             0x000002FF
#define IA32_MTRR_PHYSBASE0            0x00000200
#define IA32_MTRR_PHYSMASK0            0x00000201
#define IA32_MTRR_FIX64K_00000        0x00000250
#define IA32_MTRR_FIX16K_80000        0x00000258
#define IA32_MTRR_FIX4K_C0000         0x00000268

//
// IA32_FEATURE_CONTROL MSR
//

typedef union _IA32_FEATURE_CONTROL_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 Lock                    : 1;
        UINT64 EnableVmxInsideSmx      : 1;
        UINT64 EnableVmxOutsideSmx     : 1;
        UINT64 Reserved1               : 5;
        UINT64 SenterLocalFunctionEnables : 7;
        UINT64 SenterGlobalEnable      : 1;
        UINT64 Reserved2               : 1;
        UINT64 SgxLaunchControlEnable  : 1;
        UINT64 SgxGlobalEnable         : 1;
        UINT64 Reserved3               : 1;
        UINT64 LmceOn                  : 1;
        UINT64 Reserved4               : 43;
    };
} IA32_FEATURE_CONTROL_REGISTER;

//
// IA32_VMX_BASIC MSR
//

typedef union _IA32_VMX_BASIC_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 VmcsRevisionId        : 31;
        UINT64 MustBeZero            : 1;
        UINT64 VmcsSize              : 13;
        UINT64 Reserved1             : 3;
        UINT64 VmcsAddressWidth      : 1;
        UINT64 DualMonitor           : 1;
        UINT64 MemoryType            : 4;
        UINT64 InsOutsReporting      : 1;
        UINT64 VmxControls           : 1;
        UINT64 VmEntryHwException    : 1;
        UINT64 Reserved2             : 7;
    };
} IA32_VMX_BASIC_REGISTER;

//
// IA32_VMX_EPT_VPID_CAP MSR
//

typedef union _IA32_VMX_EPT_VPID_CAP_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 ExecuteOnlyPages                     : 1;
        UINT64 Reserved1                            : 5;
        UINT64 PageWalkLength4                      : 1;
        UINT64 Reserved2                            : 1;
        UINT64 MemoryTypeUncacheable                : 1;
        UINT64 Reserved3                            : 5;
        UINT64 MemoryTypeWriteBack                  : 1;
        UINT64 Reserved4                            : 1;
        UINT64 Pde2MbPages                          : 1;
        UINT64 Pdpte1GbPages                        : 1;
        UINT64 Reserved5                            : 2;
        UINT64 Invept                               : 1;
        UINT64 EptAccessedAndDirtyFlags             : 1;
        UINT64 AdvancedVmexitEptViolationsInformation : 1;
        UINT64 SupervisorShadowStack                : 1;
        UINT64 Reserved6                            : 1;
        UINT64 InveptSingleContext                   : 1;
        UINT64 InveptAllContexts                     : 1;
        UINT64 Reserved7                            : 5;
        UINT64 Invvpid                              : 1;
        UINT64 Reserved8                            : 7;
        UINT64 InvvpidIndividualAddress              : 1;
        UINT64 InvvpidSingleContext                  : 1;
        UINT64 InvvpidAllContexts                    : 1;
        UINT64 InvvpidSingleContextRetainingGlobals  : 1;
        UINT64 Reserved9                            : 20;
    };
} IA32_VMX_EPT_VPID_CAP_REGISTER;

//
// MTRR Structures
//

typedef union _IA32_MTRR_CAPABILITIES_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 VariableRangeCount : 8;
        UINT64 FixedRangeSupported : 1;
        UINT64 Reserved1          : 1;
        UINT64 WcSupported        : 1;
        UINT64 SmrrSupported      : 1;
        UINT64 Reserved2          : 52;
    };
} IA32_MTRR_CAPABILITIES_REGISTER;

typedef union _IA32_MTRR_DEF_TYPE_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 DefaultMemoryType : 3;
        UINT64 Reserved1         : 7;
        UINT64 FixedRangeMtrrEnable : 1;
        UINT64 MtrrEnable        : 1;
        UINT64 Reserved2         : 52;
    };
} IA32_MTRR_DEF_TYPE_REGISTER;

typedef union _IA32_MTRR_PHYSBASE_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 Type             : 8;
        UINT64 Reserved1        : 4;
        UINT64 PageFrameNumber  : 36;
        UINT64 Reserved2        : 16;
    };
} IA32_MTRR_PHYSBASE_REGISTER;

typedef union _IA32_MTRR_PHYSMASK_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 Reserved1        : 11;
        UINT64 Valid            : 1;
        UINT64 PageFrameNumber  : 36;
        UINT64 Reserved2        : 16;
    };
} IA32_MTRR_PHYSMASK_REGISTER;

typedef union _IA32_MTRR_FIXED_RANGE_TYPE {
    UINT64 AsUInt;
    struct {
        UINT8 Types[8];
    } s;
} IA32_MTRR_FIXED_RANGE_TYPE;

//
// EFER MSR
//

typedef union _IA32_EFER_REGISTER {
    UINT64 AsUInt;
    struct {
        UINT64 SyscallEnable : 1;
        UINT64 Reserved1     : 7;
        UINT64 Ia32eModeEnable : 1;
        UINT64 Reserved2     : 1;
        UINT64 Ia32eModeActive : 1;
        UINT64 ExecuteDisableBitEnable : 1;
        UINT64 Reserved3     : 52;
    };
} IA32_EFER_REGISTER;

typedef struct _CPUID {
    INT32 eax;
    INT32 ebx;
    INT32 ecx;
    INT32 edx;
} CPUID;

#define CPUID_VMX_BIT                       5
#define CPUID_PROCESSOR_FEATURES            1
#define HYPERV_HYPERVISOR_PRESENT_BIT       (1U << 31)

typedef union _CR0 {
    UINT64 AsUInt;
    struct {
        UINT64 ProtectionEnable    : 1;
        UINT64 MonitorCoprocessor  : 1;
        UINT64 EmulateFpu          : 1;
        UINT64 TaskSwitched        : 1;
        UINT64 ExtensionType       : 1;
        UINT64 NumericError        : 1;
        UINT64 Reserved1           : 10;
        UINT64 WriteProtect        : 1;
        UINT64 Reserved2           : 1;
        UINT64 AlignmentMask       : 1;
        UINT64 Reserved3           : 10;
        UINT64 NotWriteThrough     : 1;
        UINT64 CacheDisable        : 1;
        UINT64 Paging              : 1;
        UINT64 Reserved4           : 32;
    };
} CR0;

typedef union _CR4 {
    UINT64 AsUInt;
    struct {
        UINT64 VirtualModeExtensions    : 1;
        UINT64 ProtectedVirtualInts     : 1;
        UINT64 TimestampDisable         : 1;
        UINT64 DebuggingExtensions      : 1;
        UINT64 PageSizeExtensions       : 1;
        UINT64 PhysicalAddressExtension : 1;
        UINT64 MachineCheckEnable       : 1;
        UINT64 PageGlobalEnable         : 1;
        UINT64 PerformanceCounterEnable : 1;
        UINT64 OsFxsaveFxrstor          : 1;
        UINT64 OsXmmExcept              : 1;
        UINT64 UserModeInstructionPrev  : 1;
        UINT64 Reserved1                : 1;
        UINT64 VmxEnable                : 1;
        UINT64 SmxEnable                : 1;
        UINT64 Reserved2                : 1;
        UINT64 FsGsBaseEnable           : 1;
        UINT64 PcidEnable               : 1;
        UINT64 OsXsave                  : 1;
        UINT64 Reserved3                : 1;
        UINT64 SupervisorExecPrevention : 1;
        UINT64 SupervisorAccessPrevention : 1;
        UINT64 ProtectionKeyEnable      : 1;
        UINT64 ControlFlowEnforcement   : 1;
        UINT64 ProtectionKeySupervisor  : 1;
        UINT64 Reserved4                : 39;
    };
} CR4;

#define CR4_VMX_ENABLE_FLAG (1ULL << 13)

typedef union _CR_FIXED {
    UINT64 Flags;
    struct {
        ULONG Low;
        LONG  High;
    } Fields;
} CR_FIXED;

typedef union _RFLAGS {
    UINT64 AsUInt;
    struct {
        UINT64 CarryFlag       : 1;
        UINT64 Reserved1       : 1;
        UINT64 ParityFlag      : 1;
        UINT64 Reserved2       : 1;
        UINT64 AuxCarryFlag    : 1;
        UINT64 Reserved3       : 1;
        UINT64 ZeroFlag        : 1;
        UINT64 SignFlag        : 1;
        UINT64 TrapFlag        : 1;
        UINT64 InterruptEnable : 1;
        UINT64 DirectionFlag   : 1;
        UINT64 OverflowFlag    : 1;
        UINT64 IoPrivilegeLevel : 2;
        UINT64 NestedTask      : 1;
        UINT64 Reserved4       : 1;
        UINT64 ResumeFlag      : 1;
        UINT64 Virtual8086     : 1;
        UINT64 AlignmentCheck  : 1;
        UINT64 VirtualInterrupt : 1;
        UINT64 VirtualInterruptPending : 1;
        UINT64 CpuidAllowed    : 1;
        UINT64 Reserved5       : 42;
    };
} RFLAGS;

typedef union _MSR {
    UINT64 Flags;
    struct {
        ULONG Low;
        ULONG High;
    } Fields;
} MSR;

//
// Memory Types (MTRR)
//

#define MEMORY_TYPE_UNCACHEABLE    0x00
#define MEMORY_TYPE_WRITE_COMBINING 0x01
#define MEMORY_TYPE_WRITE_THROUGH  0x04
#define MEMORY_TYPE_WRITE_PROTECTED 0x05
#define MEMORY_TYPE_WRITE_BACK     0x06

//
// VMCS Field Encodings (Intel SDM Vol 3, Appendix B)
//

//
// 16-Bit Control Fields
//
#define VIRTUAL_PROCESSOR_ID                         0x00000000

//
// 16-Bit Guest-State Fields
//
#define VMCS_GUEST_ES_SELECTOR                       0x00000800
#define VMCS_GUEST_CS_SELECTOR                       0x00000802
#define VMCS_GUEST_SS_SELECTOR                       0x00000804
#define VMCS_GUEST_DS_SELECTOR                       0x00000806
#define VMCS_GUEST_FS_SELECTOR                       0x00000808
#define VMCS_GUEST_GS_SELECTOR                       0x0000080A
#define VMCS_GUEST_LDTR_SELECTOR                     0x0000080C
#define VMCS_GUEST_TR_SELECTOR                       0x0000080E

//
// 16-Bit Host-State Fields
//
#define VMCS_HOST_ES_SELECTOR                        0x00000C00
#define VMCS_HOST_CS_SELECTOR                        0x00000C02
#define VMCS_HOST_SS_SELECTOR                        0x00000C04
#define VMCS_HOST_DS_SELECTOR                        0x00000C06
#define VMCS_HOST_FS_SELECTOR                        0x00000C08
#define VMCS_HOST_GS_SELECTOR                        0x00000C0A
#define VMCS_HOST_TR_SELECTOR                        0x00000C0C

//
// 64-Bit Control Fields
//
#define VMCS_CTRL_IO_BITMAP_A_ADDRESS                0x00002000
#define VMCS_CTRL_IO_BITMAP_B_ADDRESS                0x00002002
#define VMCS_CTRL_MSR_BITMAP_ADDRESS                 0x00002004
#define VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS           0x00002006
#define VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS            0x00002008
#define VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS           0x0000200A
#define VMCS_CTRL_TSC_OFFSET                         0x00002010
#define VMCS_CTRL_EPT_POINTER                        0x0000201A
#define VMCS_CTRL_PML_ADDRESS                        0x0000200E

//
// 64-Bit Read-Only Data Field
//
#define VMCS_GUEST_PHYSICAL_ADDRESS                  0x00002400

//
// 64-Bit Guest-State Fields
//
#define VMCS_GUEST_VMCS_LINK_POINTER                 0x00002800
#define VMCS_GUEST_DEBUGCTL                          0x00002802
#define VMCS_GUEST_DEBUGCTL_HIGH                     0x00002803
#define VMCS_GUEST_PAT                               0x00002804
#define VMCS_GUEST_EFER                              0x00002806

//
// 64-Bit Host-State Fields
//
#define VMCS_HOST_PAT                                0x00002C00
#define VMCS_HOST_EFER                               0x00002C02

//
// 32-Bit Control Fields
//
#define VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS    0x00004000
#define VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS 0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP                   0x00004004
#define VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK          0x00004006
#define VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH         0x00004008
#define VMCS_CTRL_CR3_TARGET_COUNT                   0x0000400A
#define VMCS_CTRL_PRIMARY_VMEXIT_CONTROLS            0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT             0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT              0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS                   0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT             0x00004014
#define VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD 0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE       0x00004018
#define VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH         0x0000401A
#define VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS 0x0000401E
#define VMCS_CTRL_PLE_GAP                            0x00004020
#define VMCS_CTRL_PLE_WINDOW                         0x00004022

//
// 32-Bit Read-Only Data Fields
//
#define VMCS_VM_INSTRUCTION_ERROR                    0x00004400
#define VMCS_EXIT_REASON                             0x00004402
#define VMCS_VMEXIT_INTERRUPTION_INFORMATION         0x00004404
#define VMCS_VMEXIT_INTERRUPTION_ERROR_CODE          0x00004406
#define VMCS_IDT_VECTORING_INFORMATION               0x00004408
#define VMCS_IDT_VECTORING_ERROR_CODE                0x0000440A
#define VMCS_VMEXIT_INSTRUCTION_LENGTH               0x0000440C
#define VMCS_VMEXIT_INSTRUCTION_INFORMATION          0x0000440E

//
// 32-Bit Guest-State Fields
//
#define VMCS_GUEST_ES_LIMIT                          0x00004800
#define VMCS_GUEST_CS_LIMIT                          0x00004802
#define VMCS_GUEST_SS_LIMIT                          0x00004804
#define VMCS_GUEST_DS_LIMIT                          0x00004806
#define VMCS_GUEST_FS_LIMIT                          0x00004808
#define VMCS_GUEST_GS_LIMIT                          0x0000480A
#define VMCS_GUEST_LDTR_LIMIT                        0x0000480C
#define VMCS_GUEST_TR_LIMIT                          0x0000480E
#define VMCS_GUEST_GDTR_LIMIT                        0x00004810
#define VMCS_GUEST_IDTR_LIMIT                        0x00004812
#define VMCS_GUEST_ES_ACCESS_RIGHTS                  0x00004814
#define VMCS_GUEST_CS_ACCESS_RIGHTS                  0x00004816
#define VMCS_GUEST_SS_ACCESS_RIGHTS                  0x00004818
#define VMCS_GUEST_DS_ACCESS_RIGHTS                  0x0000481A
#define VMCS_GUEST_FS_ACCESS_RIGHTS                  0x0000481C
#define VMCS_GUEST_GS_ACCESS_RIGHTS                  0x0000481E
#define VMCS_GUEST_LDTR_ACCESS_RIGHTS                0x00004820
#define VMCS_GUEST_TR_ACCESS_RIGHTS                  0x00004822
#define VMCS_GUEST_INTERRUPTIBILITY_STATE            0x00004824
#define VMCS_GUEST_ACTIVITY_STATE                    0x00004826
#define VMCS_GUEST_SMBASE                            0x00004828
#define VMCS_GUEST_SYSENTER_CS                       0x0000482A
#define VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE        0x0000482E

//
// 32-Bit Host-State Field
//
#define VMCS_HOST_SYSENTER_CS                        0x00004C00

//
// Natural-Width Control Fields
//
#define VMCS_CTRL_CR0_GUEST_HOST_MASK                0x00006000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK                0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW                    0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW                    0x00006006
#define VMCS_EXIT_QUALIFICATION                      0x00006400

//
// Natural-Width Guest-State Fields
//
#define VMCS_GUEST_CR0                               0x00006800
#define VMCS_GUEST_CR3                               0x00006802
#define VMCS_GUEST_CR4                               0x00006804
#define VMCS_GUEST_ES_BASE                           0x00006806
#define VMCS_GUEST_CS_BASE                           0x00006808
#define VMCS_GUEST_SS_BASE                           0x0000680A
#define VMCS_GUEST_DS_BASE                           0x0000680C
#define VMCS_GUEST_FS_BASE                           0x0000680E
#define VMCS_GUEST_GS_BASE                           0x00006810
#define VMCS_GUEST_LDTR_BASE                         0x00006812
#define VMCS_GUEST_TR_BASE                           0x00006814
#define VMCS_GUEST_GDTR_BASE                         0x00006816
#define VMCS_GUEST_IDTR_BASE                         0x00006818
#define VMCS_GUEST_DR7                               0x0000681A
#define VMCS_GUEST_RSP                               0x0000681C
#define VMCS_GUEST_RIP                               0x0000681E
#define VMCS_GUEST_RFLAGS                            0x00006820
#define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS          0x00006822
#define VMCS_GUEST_SYSENTER_ESP                      0x00006824
#define VMCS_GUEST_SYSENTER_EIP                      0x00006826

//
// Natural-Width Host-State Fields
//
#define VMCS_HOST_CR0                                0x00006C00
#define VMCS_HOST_CR3                                0x00006C02
#define VMCS_HOST_CR4                                0x00006C04
#define VMCS_HOST_FS_BASE                            0x00006C06
#define VMCS_HOST_GS_BASE                            0x00006C08
#define VMCS_HOST_TR_BASE                            0x00006C0A
#define VMCS_HOST_GDTR_BASE                          0x00006C0C
#define VMCS_HOST_IDTR_BASE                          0x00006C0E
#define VMCS_HOST_SYSENTER_ESP                       0x00006C10
#define VMCS_HOST_SYSENTER_EIP                       0x00006C12
#define VMCS_HOST_RSP                                0x00006C14
#define VMCS_HOST_RIP                                0x00006C16

//
// VM-Exit Reasons (Intel SDM Vol 3, Appendix C)
//

#define VMX_EXIT_REASON_EXCEPTION_OR_NMI             0
#define VMX_EXIT_REASON_EXTERNAL_INTERRUPT            1
#define VMX_EXIT_REASON_TRIPLE_FAULT                  2
#define VMX_EXIT_REASON_INIT_SIGNAL                   3
#define VMX_EXIT_REASON_SIPI                          4
#define VMX_EXIT_REASON_IO_SMI                        5
#define VMX_EXIT_REASON_SMI                           6
#define VMX_EXIT_REASON_INTERRUPT_WINDOW              7
#define VMX_EXIT_REASON_NMI_WINDOW                    8
#define VMX_EXIT_REASON_TASK_SWITCH                   9
#define VMX_EXIT_REASON_EXECUTE_CPUID                 10
#define VMX_EXIT_REASON_EXECUTE_GETSEC                11
#define VMX_EXIT_REASON_EXECUTE_HLT                   12
#define VMX_EXIT_REASON_EXECUTE_INVD                  13
#define VMX_EXIT_REASON_EXECUTE_INVLPG                14
#define VMX_EXIT_REASON_EXECUTE_RDPMC                 15
#define VMX_EXIT_REASON_EXECUTE_RDTSC                 16
#define VMX_EXIT_REASON_EXECUTE_RSM                   17
#define VMX_EXIT_REASON_EXECUTE_VMCALL                18
#define VMX_EXIT_REASON_EXECUTE_VMCLEAR               19
#define VMX_EXIT_REASON_EXECUTE_VMLAUNCH              20
#define VMX_EXIT_REASON_EXECUTE_VMPTRLD               21
#define VMX_EXIT_REASON_EXECUTE_VMPTRST               22
#define VMX_EXIT_REASON_EXECUTE_VMREAD                23
#define VMX_EXIT_REASON_EXECUTE_VMRESUME              24
#define VMX_EXIT_REASON_EXECUTE_VMWRITE               25
#define VMX_EXIT_REASON_EXECUTE_VMXOFF                26
#define VMX_EXIT_REASON_EXECUTE_VMXON                 27
#define VMX_EXIT_REASON_MOV_CR                        28
#define VMX_EXIT_REASON_MOV_DR                        29
#define VMX_EXIT_REASON_EXECUTE_IO_INSTRUCTION        30
#define VMX_EXIT_REASON_EXECUTE_RDMSR                 31
#define VMX_EXIT_REASON_EXECUTE_WRMSR                 32
#define VMX_EXIT_REASON_VMENTRY_FAILURE_GUEST_STATE   33
#define VMX_EXIT_REASON_VMENTRY_FAILURE_MSR_LOADING   34
#define VMX_EXIT_REASON_EXECUTE_MWAIT                 36
#define VMX_EXIT_REASON_MONITOR_TRAP_FLAG             37
#define VMX_EXIT_REASON_EXECUTE_MONITOR               39
#define VMX_EXIT_REASON_EXECUTE_PAUSE                 40
#define VMX_EXIT_REASON_VMENTRY_FAILURE_MACHINE_CHECK 41
#define VMX_EXIT_REASON_TPR_BELOW_THRESHOLD           43
#define VMX_EXIT_REASON_APIC_ACCESS                   44
#define VMX_EXIT_REASON_VIRTUALIZED_EOI               45
#define VMX_EXIT_REASON_GDTR_IDTR_ACCESS              46
#define VMX_EXIT_REASON_LDTR_TR_ACCESS                47
#define VMX_EXIT_REASON_EPT_VIOLATION                 48
#define VMX_EXIT_REASON_EPT_MISCONFIGURATION          49
#define VMX_EXIT_REASON_EXECUTE_INVEPT                50
#define VMX_EXIT_REASON_EXECUTE_RDTSCP                51
#define VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED  52
#define VMX_EXIT_REASON_EXECUTE_INVVPID               53
#define VMX_EXIT_REASON_EXECUTE_WBINVD                54
#define VMX_EXIT_REASON_EXECUTE_XSETBV                55
#define VMX_EXIT_REASON_APIC_WRITE                    56
#define VMX_EXIT_REASON_EXECUTE_RDRAND                57
#define VMX_EXIT_REASON_EXECUTE_INVPCID               58
#define VMX_EXIT_REASON_EXECUTE_VMFUNC                59
#define VMX_EXIT_REASON_EXECUTE_ENCLS                 60
#define VMX_EXIT_REASON_EXECUTE_RDSEED                61
#define VMX_EXIT_REASON_PAGE_MODIFICATION_LOG_FULL    62
#define VMX_EXIT_REASON_EXECUTE_XSAVES                63
#define VMX_EXIT_REASON_EXECUTE_XRSTORS               64

//
// VMX Pin-Based Controls
//

#define PIN_BASED_VM_EXEC_CTRL_EXTERNAL_INTERRUPT_EXITING   (1U << 0)
#define PIN_BASED_VM_EXEC_CTRL_NMI_EXITING                  (1U << 3)
#define PIN_BASED_VM_EXEC_CTRL_VIRTUAL_NMI                  (1U << 5)
#define PIN_BASED_VM_EXEC_CTRL_VMX_PREEMPTION_TIMER         (1U << 6)

//
// VMX Processor-Based Controls (Primary)
//

#define CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING     (1U << 2)
#define CPU_BASED_VM_EXEC_CTRL_USE_TSC_OFFSETTING           (1U << 3)
#define CPU_BASED_VM_EXEC_CTRL_HLT_EXITING                  (1U << 7)
#define CPU_BASED_VM_EXEC_CTRL_INVLPG_EXITING               (1U << 9)
#define CPU_BASED_VM_EXEC_CTRL_MWAIT_EXITING                (1U << 10)
#define CPU_BASED_VM_EXEC_CTRL_RDPMC_EXITING                (1U << 11)
#define CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING                (1U << 12)
#define CPU_BASED_VM_EXEC_CTRL_CR3_LOAD_EXITING             (1U << 15)
#define CPU_BASED_VM_EXEC_CTRL_CR3_STORE_EXITING            (1U << 16)
#define CPU_BASED_VM_EXEC_CTRL_CR8_LOAD_EXITING             (1U << 19)
#define CPU_BASED_VM_EXEC_CTRL_CR8_STORE_EXITING            (1U << 20)
#define CPU_BASED_VM_EXEC_CTRL_USE_TPR_SHADOW               (1U << 21)
#define CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING           (1U << 22)
#define CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING               (1U << 23)
#define CPU_BASED_VM_EXEC_CTRL_UNCONDITIONAL_IO_EXITING     (1U << 24)
#define CPU_BASED_VM_EXEC_CTRL_USE_IO_BITMAPS               (1U << 25)
#define CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG            (1U << 27)
#define CPU_BASED_VM_EXEC_CTRL_USE_MSR_BITMAPS              (1U << 28)
#define CPU_BASED_VM_EXEC_CTRL_MONITOR_EXITING              (1U << 29)
#define CPU_BASED_VM_EXEC_CTRL_PAUSE_EXITING                (1U << 30)
#define CPU_BASED_VM_EXEC_CTRL_ACTIVATE_SECONDARY_CONTROLS  (1U << 31)

//
// VMX Processor-Based Controls (Secondary)
//

#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_EPT                  (1U << 1)
#define CPU_BASED_VM_EXEC_CTRL2_RDTSCP                      (1U << 3)
#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_VPID                 (1U << 5)
#define CPU_BASED_VM_EXEC_CTRL2_UNRESTRICTED_GUEST          (1U << 7)
#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_INVPCID              (1U << 12)
#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_VMFUNC               (1U << 13)
#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_XSAVES               (1U << 20)
#define CPU_BASED_VM_EXEC_CTRL2_ENABLE_USER_WAIT_PAUSE      (1U << 26)

//
// VM-Exit Controls
//

#define VM_EXIT_CTRL_SAVE_DEBUG_CONTROLS                    (1U << 2)
#define VM_EXIT_CTRL_HOST_ADDRESS_SPACE_SIZE                (1U << 9)
#define VM_EXIT_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL             (1U << 12)
#define VM_EXIT_CTRL_ACK_INTERRUPT_ON_EXIT                  (1U << 15)
#define VM_EXIT_CTRL_SAVE_IA32_PAT                          (1U << 18)
#define VM_EXIT_CTRL_LOAD_IA32_PAT                          (1U << 19)
#define VM_EXIT_CTRL_SAVE_IA32_EFER                         (1U << 20)
#define VM_EXIT_CTRL_LOAD_IA32_EFER                         (1U << 21)

//
// VM-Entry Controls
//

#define VM_ENTRY_CTRL_LOAD_DEBUG_CONTROLS                   (1U << 2)
#define VM_ENTRY_CTRL_IA32E_MODE_GUEST                      (1U << 9)
#define VM_ENTRY_CTRL_LOAD_IA32_PERF_GLOBAL_CTRL            (1U << 13)
#define VM_ENTRY_CTRL_LOAD_IA32_PAT                         (1U << 14)
#define VM_ENTRY_CTRL_LOAD_IA32_EFER                        (1U << 15)

//
// Segment Register Indices (matching VMCS segment field encoding offsets)
//

#define ES   0
#define CS   1
#define SS   2
#define DS   3
#define FS   4
#define GS   5
#define LDTR 6
#define TR   7

//
// Segment Descriptor / Selector Structures
//

typedef union _VMX_SEGMENT_ACCESS_RIGHTS {
    UINT32 AsUInt;
    struct {
        UINT32 Type          : 4;
        UINT32 System        : 1;
        UINT32 Dpl           : 2;
        UINT32 Present       : 1;
        UINT32 Reserved1     : 4;
        UINT32 Avl           : 1;
        UINT32 LongMode      : 1;
        UINT32 DefaultBig    : 1;
        UINT32 Granularity   : 1;
        UINT32 Unusable      : 1;
        UINT32 Reserved2     : 15;
    };
} VMX_SEGMENT_ACCESS_RIGHTS;

typedef struct _VMX_SEGMENT_SELECTOR {
    UINT16                    Selector;
    VMX_SEGMENT_ACCESS_RIGHTS Attributes;
    UINT32                    Limit;
    UINT64                    Base;
} VMX_SEGMENT_SELECTOR;

#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR_32 {
    UINT16 LimitLow;
    UINT16 BaseLow;
    union {
        struct {
            UINT32 BaseMid       : 8;
            UINT32 Type          : 4;
            UINT32 System        : 1;
            UINT32 Dpl           : 2;
            UINT32 Present       : 1;
            UINT32 LimitHigh     : 4;
            UINT32 Avl           : 1;
            UINT32 LongMode      : 1;
            UINT32 DefaultBig    : 1;
            UINT32 Granularity   : 1;
            UINT32 BaseHigh      : 8;
        };
        UINT32 Flags;
    };
} SEGMENT_DESCRIPTOR_32, *PSEGMENT_DESCRIPTOR_32;
#pragma pack(pop)

//
// 64-bit system segment descriptor (16 bytes for TSS/LDT in long mode)
//
#pragma pack(push, 1)
typedef struct _SEGMENT_DESCRIPTOR_64 {
    UINT16 LimitLow;
    UINT16 BaseLow;
    union {
        struct {
            UINT32 BaseMid       : 8;
            UINT32 Type          : 4;
            UINT32 System        : 1;
            UINT32 Dpl           : 2;
            UINT32 Present       : 1;
            UINT32 LimitHigh     : 4;
            UINT32 Avl           : 1;
            UINT32 Reserved0     : 2;
            UINT32 Granularity   : 1;
            UINT32 BaseHigh      : 8;
        };
        UINT32 Flags;
    };
    UINT32 BaseUpper;
    UINT32 Reserved1;
} SEGMENT_DESCRIPTOR_64, *PSEGMENT_DESCRIPTOR_64;
#pragma pack(pop)

// TSS type field values (64-bit mode)
#define TSS_TYPE_AVAILABLE_64   0x9
#define TSS_TYPE_BUSY_64        0xB

//
// IDT Gate Descriptor (64-bit long mode)
//
// In long mode, interrupt/trap gates are 16 bytes.
// Type field values:
//   0xE = 64-bit interrupt gate (IF cleared on entry)
//   0xF = 64-bit trap gate (IF unchanged)
//
#pragma pack(push, 1)
typedef struct _IDT_GATE_DESCRIPTOR_64 {
    UINT16 OffsetLow;           // bits 0-15 of handler address
    UINT16 Selector;            // code segment selector
    UINT8  Ist : 3;             // interrupt stack table index (0 = legacy stack)
    UINT8  Reserved0 : 5;
    UINT8  Type : 4;            // gate type (0xE = interrupt, 0xF = trap)
    UINT8  Zero : 1;            // must be 0
    UINT8  Dpl : 2;             // descriptor privilege level
    UINT8  Present : 1;         // segment present
    UINT16 OffsetMid;           // bits 16-31 of handler address
    UINT32 OffsetHigh;          // bits 32-63 of handler address
    UINT32 Reserved1;           // reserved, must be 0
} IDT_GATE_DESCRIPTOR_64, *PIDT_GATE_DESCRIPTOR_64;
#pragma pack(pop)

#define IDT_TYPE_INTERRUPT_GATE     0xE
#define IDT_TYPE_TRAP_GATE          0xF
#define IDT_VECTOR_NMI              2
#define IDT_VECTOR_DF               8
#define IDT_VECTOR_GP              13
#define IDT_VECTOR_PF              14
#define IDT_NUM_ENTRIES           256

//
// EPT Structures (Intel SDM Vol 3, Chapter 28)
//

typedef union _EPT_POINTER {
    UINT64 AsUInt;
    struct {
        UINT64 MemoryType             : 3;
        UINT64 PageWalkLength         : 3;
        UINT64 EnableAccessAndDirtyFlags : 1;
        UINT64 EnforcementOfAccessRights : 1;
        UINT64 Reserved1              : 4;
        UINT64 PageFrameNumber        : 36;
        UINT64 Reserved2              : 16;
    };
} EPT_POINTER, *PEPT_POINTER;

typedef union _EPT_PML4_ENTRY {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 Reserved1       : 5;
        UINT64 Accessed        : 1;
        UINT64 Ignored1        : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored2        : 1;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2       : 4;
        UINT64 Ignored3        : 12;
    };
} EPT_PML4_ENTRY, *PEPT_PML4_ENTRY;

typedef union _EPT_PML3_POINTER {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 Reserved1       : 5;
        UINT64 Accessed        : 1;
        UINT64 Ignored1        : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored2        : 1;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2       : 4;
        UINT64 Ignored3        : 12;
    };
} EPT_PML3_POINTER;

typedef union _EPT_PML3_ENTRY {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 MemoryType      : 3;
        UINT64 IgnorePat       : 1;
        UINT64 LargePage       : 1;
        UINT64 Accessed        : 1;
        UINT64 Dirty           : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored1        : 1;
        UINT64 Reserved1       : 18;
        UINT64 PageFrameNumber : 18;
        UINT64 Reserved2       : 4;
        UINT64 Ignored2        : 7;
        UINT64 VerifyGuestPaging : 1;
        UINT64 PagingWriteAccess : 1;
        UINT64 Ignored3        : 1;
        UINT64 SuppressVe      : 1;
        UINT64 Ignored4        : 1;
    };
} EPT_PML3_ENTRY;

typedef union _EPT_PML2_ENTRY {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 MemoryType      : 3;
        UINT64 IgnorePat       : 1;
        UINT64 LargePage       : 1;
        UINT64 Accessed        : 1;
        UINT64 Dirty           : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored1        : 10;
        UINT64 PageFrameNumber : 27;
        UINT64 Reserved1       : 4;
        UINT64 Ignored2        : 7;
        UINT64 VerifyGuestPaging : 1;
        UINT64 PagingWriteAccess : 1;
        UINT64 Ignored3        : 1;
        UINT64 SuppressVe      : 1;
        UINT64 Ignored4        : 1;
    };
} EPT_PML2_ENTRY, *PEPT_PML2_ENTRY;

typedef union _EPT_PML2_POINTER {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 Reserved1       : 5;
        UINT64 Accessed        : 1;
        UINT64 Ignored1        : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored2        : 1;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved2       : 4;
        UINT64 Ignored3        : 12;
    };
} EPT_PML2_POINTER, *PEPT_PML2_POINTER;

typedef union _EPT_PML1_ENTRY {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 MemoryType      : 3;
        UINT64 IgnorePat       : 1;
        UINT64 Ignored1        : 1;
        UINT64 Accessed        : 1;
        UINT64 Dirty           : 1;
        UINT64 UserModeExecute : 1;
        UINT64 Ignored2        : 1;
        UINT64 PageFrameNumber : 36;
        UINT64 Reserved1       : 4;
        UINT64 Ignored3        : 7;
        UINT64 VerifyGuestPaging : 1;
        UINT64 PagingWriteAccess : 1;
        UINT64 Ignored4        : 1;
        UINT64 SuppressVe      : 1;
        UINT64 Ignored5        : 1;
    };
} EPT_PML1_ENTRY, *PEPT_PML1_ENTRY;

//
// EPT Violation Exit Qualification
//

typedef union _VMX_EXIT_QUALIFICATION_EPT_VIOLATION {
    UINT64 AsUInt;
    struct {
        UINT64 ReadAccess      : 1;
        UINT64 WriteAccess     : 1;
        UINT64 ExecuteAccess   : 1;
        UINT64 EptReadable     : 1;
        UINT64 EptWriteable    : 1;
        UINT64 EptExecutable   : 1;
        UINT64 EptExecutableForUserMode : 1;
        UINT64 ValidGuestLinearAddress  : 1;
        UINT64 CausedByTranslation      : 1;
        UINT64 UserModeLinearAddress    : 1;
        UINT64 ReadableWritablePage     : 1;
        UINT64 ExecuteDisablePage       : 1;
        UINT64 NmiUnblocking            : 1;
        UINT64 Reserved1                : 51;
    };
} VMX_EXIT_QUALIFICATION_EPT_VIOLATION;

//
// MOV CR Exit Qualification
//

typedef union _VMX_EXIT_QUALIFICATION_MOV_CR {
    UINT64 AsUInt;
    struct {
        UINT64 ControlRegister          : 4;
        UINT64 AccessType               : 2;
        UINT64 LmswOperandType          : 1;
        UINT64 Reserved1                : 1;
        UINT64 GeneralPurposeRegister   : 4;
        UINT64 Reserved2                : 4;
        UINT64 LmswSourceData           : 16;
        UINT64 Reserved3                : 32;
    };
} VMX_EXIT_QUALIFICATION_MOV_CR;

#define VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR     0
#define VMX_EXIT_QUALIFICATION_ACCESS_MOV_FROM_CR   1
#define VMX_EXIT_QUALIFICATION_REGISTER_CR0         0
#define VMX_EXIT_QUALIFICATION_REGISTER_CR3         3
#define VMX_EXIT_QUALIFICATION_REGISTER_CR4         4

//
// INVEPT / INVVPID
//

typedef enum _INVEPT_TYPE {
    InveptSingleContext = 1,
    InveptAllContexts   = 2
} INVEPT_TYPE;

typedef enum _INVVPID_TYPE {
    InvvpidIndividualAddress                = 0,
    InvvpidSingleContext                    = 1,
    InvvpidAllContexts                      = 2,
    InvvpidSingleContextRetainingGlobals    = 3
} INVVPID_TYPE;

typedef struct _INVEPT_DESCRIPTOR {
    EPT_POINTER EptPointer;
    UINT64      Reserved;
} INVEPT_DESCRIPTOR;

typedef struct _INVVPID_DESCRIPTOR {
    UINT16 Vpid;
    UINT16 Reserved1;
    UINT32 Reserved2;
    UINT64 LinearAddress;
} INVVPID_DESCRIPTOR;

//
// VM-Entry Interruption Information Field
//

typedef union _VMENTRY_INTERRUPT_INFORMATION {
    UINT32 AsUInt;
    struct {
        UINT32 Vector              : 8;
        UINT32 InterruptionType    : 3;
        UINT32 DeliverErrorCode    : 1;
        UINT32 Reserved            : 19;
        UINT32 Valid               : 1;
    };
} VMENTRY_INTERRUPT_INFORMATION;

#define INTERRUPT_TYPE_EXTERNAL_INTERRUPT    0
#define INTERRUPT_TYPE_NMI                   2
#define INTERRUPT_TYPE_HARDWARE_EXCEPTION    3
#define INTERRUPT_TYPE_SOFTWARE_INTERRUPT    4
#define INTERRUPT_TYPE_SOFTWARE_EXCEPTION    6

//
// Exception vectors
//
#define EXCEPTION_VECTOR_DIVIDE_ERROR            0
#define EXCEPTION_VECTOR_DEBUG                   1
#define EXCEPTION_VECTOR_NMI                     2
#define EXCEPTION_VECTOR_BREAKPOINT              3
#define EXCEPTION_VECTOR_OVERFLOW                4
#define EXCEPTION_VECTOR_BOUND_RANGE             5
#define EXCEPTION_VECTOR_UNDEFINED_OPCODE        6
#define EXCEPTION_VECTOR_DEVICE_NOT_AVAILABLE    7
#define EXCEPTION_VECTOR_DOUBLE_FAULT            8
#define EXCEPTION_VECTOR_INVALID_TSS             10
#define EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT     11
#define EXCEPTION_VECTOR_STACK_SEGMENT_FAULT     12
#define EXCEPTION_VECTOR_GENERAL_PROTECTION      13
#define EXCEPTION_VECTOR_PAGE_FAULT              14
#define EXCEPTION_VECTOR_MACHINE_CHECK           18

//
// EPT Table Constants
//

#define VMM_EPT_PML4E_COUNT 512
#define VMM_EPT_PML3E_COUNT 512
#define VMM_EPT_PML2E_COUNT 512
#define VMM_EPT_PML1E_COUNT 512

//
// EPT address mask helpers
//
#define ADDRMASK_EPT_PML1_INDEX(_VAR_) ((_VAR_ & 0x1FF000ULL) >> 12)
#define ADDRMASK_EPT_PML2_INDEX(_VAR_) ((_VAR_ & 0x3FE00000ULL) >> 21)
#define ADDRMASK_EPT_PML3_INDEX(_VAR_) ((_VAR_ & 0x7FC0000000ULL) >> 30)
#define ADDRMASK_EPT_PML4_INDEX(_VAR_) ((_VAR_ & 0xFF8000000000ULL) >> 39)

//
// DR7 — Debug Register 7 (Intel SDM Vol 3, 17.2.4)
//

#define DR7_L0                  (1ULL << 0)   // Local enable DR0
#define DR7_G0                  (1ULL << 1)   // Global enable DR0
#define DR7_L1                  (1ULL << 2)   // Local enable DR1
#define DR7_G1                  (1ULL << 3)   // Global enable DR1
#define DR7_L2                  (1ULL << 4)   // Local enable DR2
#define DR7_G2                  (1ULL << 5)   // Global enable DR2
#define DR7_L3                  (1ULL << 6)   // Local enable DR3
#define DR7_G3                  (1ULL << 7)   // Global enable DR3

// R/W and LEN fields for each DR (2 bits each, starting at bit 16)
#define DR7_RW_SHIFT(n)         (16 + (n) * 4)     // R/W0 at 16, R/W1 at 20, ...
#define DR7_LEN_SHIFT(n)        (18 + (n) * 4)     // LEN0 at 18, LEN1 at 22, ...
#define DR7_RW_MASK(n)          (3ULL << DR7_RW_SHIFT(n))
#define DR7_RW_EXEC             0   // Break on execution only

//
// Pending Debug Exceptions (VMCS 0x6822 — Intel SDM Vol 3, 24.4.2)
//

#define PENDING_DEBUG_B0        (1ULL << 0)   // DR0 breakpoint matched
#define PENDING_DEBUG_B1        (1ULL << 1)   // DR1 breakpoint matched
#define PENDING_DEBUG_B2        (1ULL << 2)
#define PENDING_DEBUG_B3        (1ULL << 3)
#define PENDING_DEBUG_ENABLED_BP (1ULL << 12)
#define PENDING_DEBUG_BS        (1ULL << 14)

#define RFLAGS_TF               (1ULL << 8)
#define DEBUGCTL_BTF            (1ULL << 1)

//
// Guest Interruptibility State (VMCS 0x4824 bits)
//
#define GUEST_INTR_STATE_BLOCKING_BY_STI    (1U << 0)
#define GUEST_INTR_STATE_BLOCKING_BY_MOV_SS (1U << 1)
#define GUEST_INTR_STATE_BLOCKING_BY_SMI    (1U << 2)
#define GUEST_INTR_STATE_BLOCKING_BY_NMI    (1U << 3)

//
// Guest Activity State values (VMCS 0x4826)
//
#define GUEST_ACTIVITY_STATE_ACTIVE         0
#define GUEST_ACTIVITY_STATE_HLT            1
#define GUEST_ACTIVITY_STATE_SHUTDOWN       2
#define GUEST_ACTIVITY_STATE_WAIT_FOR_SIPI  3

//
// VPID Tag
//
#define VPID_TAG 1

#pragma warning(pop)
