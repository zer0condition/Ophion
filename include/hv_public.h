/*
 * Stable user/kernel ABI for Ophion status queries.
 */
#pragma once

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif
#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS 0x0001
#endif
#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif


typedef unsigned __int8  HV_UINT8;
typedef unsigned __int16 HV_UINT16;
typedef unsigned __int32 HV_UINT32;
typedef unsigned __int64 HV_UINT64;

/*
 * Clean-room attachment wire ABI.  Discovery is grounded only in the public
 * Microsoft TLFS CPUID/hypercall contract; private Hyper-V symbols and
 * build-specific structure layouts are outside this interface.
 */
#define HV_ATTACH_ABI_VERSION_1       1U
#define HV_ATTACH_INTERFACE_HV1       0x31237648U
#define HV_ATTACH_CPUID_MIN_LEAF      0x40000005U

#define HV_ATTACH_PRIV_ACCESS_HYPERCALL_MSRS (1ULL << 5)
#define HV_ATTACH_PRIV_CREATE_PARTITIONS     (1ULL << 32)
#define HV_ATTACH_PRIV_ACCESS_PARTITION_ID   (1ULL << 33)
#define HV_ATTACH_PRIV_ACCESS_VP_REGISTERS   (1ULL << 49)
#define HV_ATTACH_PRIV_EXTENDED_HYPERCALLS   (1ULL << 52)
#define HV_ATTACH_PRIV_START_VP              (1ULL << 53)
#define HV_ATTACH_ROOT_REQUIRED_PRIVILEGES \
    (HV_ATTACH_PRIV_ACCESS_HYPERCALL_MSRS | \
     HV_ATTACH_PRIV_CREATE_PARTITIONS | \
     HV_ATTACH_PRIV_ACCESS_PARTITION_ID)

#define HV_ATTACH_ARCH_X64                    1U

#define HV_ATTACH_PARTITION_UNKNOWN           0U
#define HV_ATTACH_PARTITION_ROOT              1U
#define HV_ATTACH_PARTITION_CHILD             2U
#define HV_ATTACH_PARTITION_NESTED            3U

#define HV_ATTACH_MODE_PROBE_ONLY             0U
#define HV_ATTACH_MODE_HYPERV_ROOT_TLFS       1U
#define HV_ATTACH_MODE_HYPERV_NESTED_TLFS     2U

#define HV_ATTACH_STATE_EMPTY                 0U
#define HV_ATTACH_STATE_DISCOVERED            1U
#define HV_ATTACH_STATE_ELIGIBLE              2U
#define HV_ATTACH_STATE_PREPARED              3U
#define HV_ATTACH_STATE_ATTACHED              4U
#define HV_ATTACH_STATE_FAILED                5U
#define HV_ATTACH_STATE_DETACHED              6U

#define HV_ATTACH_FAILURE_NONE                0U
#define HV_ATTACH_FAILURE_UNSUPPORTED_ARCH    1U
#define HV_ATTACH_FAILURE_NO_HYPERVISOR       2U
#define HV_ATTACH_FAILURE_INTERFACE_MISMATCH  3U
#define HV_ATTACH_FAILURE_CPUID_TRUNCATED     4U
#define HV_ATTACH_FAILURE_PRIVILEGE_MISSING   5U
#define HV_ATTACH_FAILURE_NESTED_UNAVAILABLE  6U
#define HV_ATTACH_FAILURE_VBS_POLICY          7U
#define HV_ATTACH_FAILURE_PROVIDER_UNAVAILABLE 8U
#define HV_ATTACH_FAILURE_ABI_MISMATCH        9U
#define HV_ATTACH_FAILURE_INVALID_STATE      10U
#define HV_ATTACH_FAILURE_ALLOCATION         11U
#define HV_ATTACH_FAILURE_PROVIDER_PROBE     12U
#define HV_ATTACH_FAILURE_PROVIDER_PREPARE   13U
#define HV_ATTACH_FAILURE_PROVIDER_COMMIT    14U
#define HV_ATTACH_FAILURE_ROLLBACK           15U
#define HV_ATTACH_FAILURE_MEASURED_BOOT_UNKNOWN 16U
#define HV_ATTACH_FAILURE_CPUID_INCOHERENT   17U

#define HV_ATTACH_PLATFORM_HYPERVISOR_PRESENT 0x00000001U
#define HV_ATTACH_PLATFORM_HV1                0x00000002U
#define HV_ATTACH_PLATFORM_ROOT_PRIVILEGES    0x00000004U
#define HV_ATTACH_PLATFORM_NESTED             0x00000008U
#define HV_ATTACH_PLATFORM_VBS_CONFIGURED     0x00000010U
#define HV_ATTACH_PLATFORM_VBS_RUNNING        0x00000020U
#define HV_ATTACH_PLATFORM_HVCI_CONFIGURED    0x00000040U
#define HV_ATTACH_PLATFORM_HVCI_RUNNING       0x00000080U
#define HV_ATTACH_PLATFORM_SECURE_BOOT        0x00000100U
#define HV_ATTACH_PLATFORM_TPM20              0x00000200U
#define HV_ATTACH_PLATFORM_MEASURED_BOOT      0x00000400U

#define HV_ATTACH_FEATURE_CPUID_DISCOVERY     (1ULL << 0)
#define HV_ATTACH_FEATURE_HYPERCALL_MSR       (1ULL << 1)
#define HV_ATTACH_FEATURE_PARTITION_ID        (1ULL << 2)
#define HV_ATTACH_FEATURE_CREATE_PARTITIONS   (1ULL << 3)
#define HV_ATTACH_FEATURE_VP_REGISTERS        (1ULL << 4)
#define HV_ATTACH_FEATURE_EXTENDED_HYPERCALLS (1ULL << 5)
#define HV_ATTACH_FEATURE_START_VP            (1ULL << 6)
#define HV_ATTACH_FEATURE_ENLIGHTENED_VMCS    (1ULL << 7)
#define HV_ATTACH_FEATURE_DIRECT_FLUSH        (1ULL << 8)
#define HV_ATTACH_FEATURE_GPA_FLUSH           (1ULL << 9)
#define HV_ATTACH_FEATURE_VSM_AWARE           (1ULL << 10)
#define HV_ATTACH_FEATURE_ROLLBACK            (1ULL << 11)

#define HV_ATTACH_REQUEST_REQUIRE_MEASURED_BOOT 0x00000001U
#define HV_ATTACH_REQUEST_REQUIRE_HVCI_SAFE     0x00000002U
#define HV_ATTACH_REQUEST_NO_PRIVATE_SYMBOLS    0x00000004U
#define HV_ATTACH_REQUEST_NO_BOOT_MUTATION      0x00000008U

#define HV_ATTACH_PROVIDER_NONE               0U
#define HV_ATTACH_PROVIDER_HYPERV_TLFS        1U

#pragma pack(push, 8)
typedef struct _HV_ATTACH_PLATFORM_V1 {
    HV_UINT32 Size;
    HV_UINT16 Version;
    HV_UINT16 Architecture;
    HV_UINT32 State;
    HV_UINT32 PartitionType;
    HV_UINT32 Flags;
    HV_UINT32 Failure;
    HV_UINT32 OsBuild;
    HV_UINT32 MaximumHypervisorLeaf;
    HV_UINT32 InterfaceSignature;
    HV_UINT32 HypervisorBuild;
    HV_UINT16 HypervisorMajor;
    HV_UINT16 HypervisorMinor;
    HV_UINT32 Recommendations;
    HV_UINT32 HardwareFeatures;
    HV_UINT32 NestedFeaturesLow;
    HV_UINT32 NestedFeaturesHigh;
    HV_UINT32 VbsStatus;
    HV_UINT32 SecurityServicesConfigured;
    HV_UINT32 SecurityServicesRunning;
    HV_UINT32 Reserved0;
    HV_UINT64 PartitionPrivileges;
    HV_UINT64 FeatureFlags;
    HV_UINT8  HypervisorVendor[12];
    HV_UINT32 Reserved1;
} HV_ATTACH_PLATFORM_V1;

typedef struct _HV_ATTACH_REQUEST_V1 {
    HV_UINT32 Size;
    HV_UINT16 Version;
    HV_UINT16 HeaderBytes;
    HV_UINT32 Mode;
    HV_UINT32 Flags;
    HV_UINT64 RequiredFeatures;
    HV_UINT64 OptionalFeatures;
    HV_UINT64 NonceLow;
    HV_UINT64 NonceHigh;
} HV_ATTACH_REQUEST_V1;

typedef struct _HV_ATTACH_RESULT_V1 {
    HV_UINT32 Size;
    HV_UINT16 Version;
    HV_UINT16 HeaderBytes;
    HV_UINT32 State;
    HV_UINT32 Failure;
    HV_UINT32 Mode;
    HV_UINT32 Provider;
    HV_UINT64 NegotiatedFeatures;
    HV_UINT64 OwnershipMask;
    HV_UINT64 SessionId;
    HV_UINT64 Reserved;
} HV_ATTACH_RESULT_V1;
#pragma pack(pop)

#define HV_IOCTL_BASE               0x800
#define HV_IOCTL_ACCESS             (FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_HV_STATUS             CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE,     METHOD_BUFFERED, HV_IOCTL_ACCESS)
#define IOCTL_HV_CONCEAL_BYOVD      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 1, METHOD_BUFFERED, HV_IOCTL_ACCESS)
#define IOCTL_HV_EAC_STEALTH        CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 2, METHOD_BUFFERED, HV_IOCTL_ACCESS)
#define IOCTL_HV_PROTECT_RANGE      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 3, METHOD_BUFFERED, HV_IOCTL_ACCESS)
#define IOCTL_HV_PROTECT_STATUS     CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 4, METHOD_BUFFERED, HV_IOCTL_ACCESS)


#define HV_EAC_ACTION_SCRUB 1U
#define HV_EAC_ACTION_QUERY 2U

#pragma pack(push, 1)
typedef struct _HV_PROTECT_RANGE_REQUEST {
    HV_UINT64 OwnerCr3;   /* 0 = caller's current CR3 */
    HV_UINT64 GuestVa;
    HV_UINT64 Size;
    HV_UINT32 Flags;
    HV_UINT32 Reserved;
} HV_PROTECT_RANGE_REQUEST;

#define HV_PROTECT_FLAG_WHITELIST 0x1U

#pragma pack(pop)
#define HV_PROTECT_STATUS_VERSION_1 1U
#define HV_PROTECT_STATUS_AVAILABLE       0x00000001U
#define HV_PROTECT_STATUS_MTF             0x00000002U
#define HV_PROTECT_STATUS_EXECUTE_ONLY    0x00000004U
#define HV_PROTECT_STATUS_PROCESS_NOTIFY  0x00000008U
#define HV_PROTECT_STATUS_ACTIVE          0x00000010U
#define HV_PROTECT_STATUS_KPTI_DUAL_ROOT  0x00000020U

#pragma pack(push, 8)
typedef struct _HV_PROTECT_STATUS_V1 {
    HV_UINT32 Size;
    HV_UINT32 Version;
    HV_UINT32 Flags;
    HV_UINT32 MaximumPages;
    HV_UINT32 ActiveOwners;
    HV_UINT32 ProtectedPages;
    HV_UINT32 WhitelistRanges;
    HV_UINT32 Reserved;
} HV_PROTECT_STATUS_V1;
#pragma pack(pop)

/*
 * Production root-command transport.  The .hvshare page is the only
 * guest-visible command surface; capability material is copied into
 * concealed root state during bootstrap and erased from Payload.
 */
#define HV_ROOT_COMMAND_MAGIC        0x7A6D94C13B52E807ULL
#define HV_ROOT_COMMAND_VERSION_1    1U
#define HV_ROOT_COMMAND_PAGE_BYTES   4096U
#define HV_ROOT_COMMAND_HEADER_BYTES 72U
#define HV_ROOT_COMMAND_PAYLOAD_BYTES \
    (HV_ROOT_COMMAND_PAGE_BYTES - HV_ROOT_COMMAND_HEADER_BYTES)

#define HV_ROOT_STATE_IDLE     0U
#define HV_ROOT_STATE_WRITING  1U
#define HV_ROOT_STATE_READY    2U
#define HV_ROOT_STATE_BUSY     3U
#define HV_ROOT_STATE_COMPLETE 4U

#define HV_ROOT_PHASE_EMPTY    0U
#define HV_ROOT_PHASE_PREPARED 1U
#define HV_ROOT_PHASE_ACTIVE   2U
#define HV_ROOT_PHASE_FAILED   3U
#define HV_ROOT_PHASE_STOPPING 4U
#define HV_ROOT_PHASE_STOPPED  5U
#define HV_ROOT_PHASE_INITIALIZING 6U
#define HV_ROOT_PHASE_AWAITING_BOOTSTRAP 7U

#define HV_ROOT_COMMAND_QUERY_TRANSPORT 1U
#define HV_ROOT_COMMAND_QUERY_VCPU      2U

#define HV_ROOT_TRANSPORT_VERSION_1 1U
#define HV_ROOT_VMCALL_SEAL_STEP    5U
#define HV_ROOT_VMCALL_STOP_STEP    6U
#define HV_ROOT_VMCALL_BOOTSTRAP_STEP 7U
#define HV_ROOT_VMCALL_COMMAND      0x100U
#define HV_VMCALL_FRAME_R10 0x0000000048564653ULL
#define HV_VMCALL_FRAME_R11 0x0000564D43414C4CULL
#define HV_VMCALL_FRAME_R12 0x4E4F485950455256ULL

#pragma pack(push, 8)
typedef struct _HV_ROOT_COMMAND_PAGE_V1 {
    HV_UINT64 Magic;
    HV_UINT16 Version;
    HV_UINT16 HeaderBytes;
    HV_UINT32 PageBytes;
    HV_UINT32 State;
    HV_UINT32 Command;
    HV_UINT64 Sequence;
    HV_UINT32 RequestBytes;
    HV_UINT32 ResponseCapacity;
    HV_UINT32 ResponseBytes;
    HV_UINT32 Status;
    HV_UINT64 Epoch;
    HV_UINT64 RecordMacLow;
    HV_UINT64 RecordMacHigh;
    HV_UINT8  Payload[4024];
} HV_ROOT_COMMAND_PAGE_V1;

typedef struct _HV_ROOT_BOOTSTRAP_V1 {
    HV_UINT64 CapabilityLow;
    HV_UINT64 CapabilityHigh;
} HV_ROOT_BOOTSTRAP_V1;

typedef struct _HV_ROOT_QUERY_VCPU_V1 {
    HV_UINT32 Size;
    HV_UINT32 Index;
} HV_ROOT_QUERY_VCPU_V1;

typedef struct _HV_ROOT_TRANSPORT_STATUS_V1 {
    HV_UINT32 Size;
    HV_UINT32 Version;
    HV_UINT32 Phase;
    HV_UINT32 ProcessorCount;
    HV_UINT32 SealedProcessors;
    HV_UINT32 LastFailure;
    HV_UINT32 Flags;
    HV_UINT32 Reserved0;
    HV_UINT64 Epoch;
    HV_UINT64 ExpectedSequence;
    HV_UINT64 CompletedCommands;
    HV_UINT64 Reserved1;
} HV_ROOT_TRANSPORT_STATUS_V1;
#pragma pack(pop)


#define HV_STATUS_VERSION_1         1U
#define HV_STATUS_MAX_VCPUS         256U
#define HV_STATUS_EXIT_REASON_COUNT 128U

#define HV_PARENT_PRESENT           0x00000001U
#define HV_PARENT_HYPERV            0x00000002U
#define HV_PARENT_NESTED_RESTRICTED 0x00000004U
#define HV_STATUS_FLAG_VMXOFF_NMI_DEFERRED 0x00000001U

#define HV_CAP_EPT                  0x00000001U
#define HV_CAP_EPT_EXEC_ONLY        0x00000200U
#define HV_CAP_EPT_2MB              0x00000002U
#define HV_CAP_EPT_AD               0x00000004U
#define HV_CAP_MTF                  0x00000008U
#define HV_CAP_INVVPID              0x00000010U
#define HV_CAP_WAITPKG              0x00000020U
#define HV_CAP_PMU                  0x00000040U
#define HV_CAP_HPET                 0x00000080U
#define HV_CAP_XAPIC                0x00000100U

#define HV_VCPU_LAUNCHED            0x00000001U
#define HV_VCPU_DETACHED            0x00000002U
#define HV_VCPU_FAILED              0x00000004U
#define HV_VCPU_TERMINAL            0x00000008U

#define HV_FAILURE_NONE                         0U
#define HV_FAILURE_PROCESSOR_CAPACITY           1U
#define HV_FAILURE_VMX_UNAVAILABLE              2U
#define HV_FAILURE_EPT_UNAVAILABLE              3U
#define HV_FAILURE_GPA_COVERAGE                 4U
#define HV_FAILURE_REQUIRED_CONTROLS            5U
#define HV_FAILURE_NESTED_RESTRICTION           6U
#define HV_FAILURE_ALLOCATION                   7U
#define HV_FAILURE_VMCS_WRITE                   8U
#define HV_FAILURE_VMCS_READ                    9U
#define HV_FAILURE_INVEPT                      10U
#define HV_FAILURE_INVVPID                     11U
#define HV_FAILURE_VM_ENTRY                    12U
#define HV_FAILURE_TRIPLE_FAULT                13U
#define HV_FAILURE_UNKNOWN_EXIT                14U
#define HV_FAILURE_EPT_MISCONFIGURATION        15U

#pragma pack(push, 8)
typedef struct _HV_STATUS_VCPU_V1 {
    HV_UINT32 Size;
    HV_UINT32 Index;
    HV_UINT16 Group;
    HV_UINT8  Number;
    HV_UINT8  Reserved0;
    HV_UINT32 StateFlags;
    HV_UINT32 LastExitReason;
    HV_UINT32 LastFailure;
    HV_UINT32 LastVmInstructionError;
    HV_UINT64 LastExitQualification;
    HV_UINT64 TotalExits;
    HV_UINT64 CpuidExits;
    HV_UINT64 EptViolationExits;
    HV_UINT64 MonitorTrapExits;
    HV_UINT64 RdtscExits;
    HV_UINT64 RdtscpExits;
    HV_UINT64 VmcallExits;
    HV_UINT64 MsrReadExits;
    HV_UINT64 MsrWriteExits;
} HV_STATUS_VCPU_V1;

typedef struct _HV_STATUS_V1 {
    HV_UINT32 Size;
    HV_UINT32 Version;
    HV_UINT32 HeaderSize;
    HV_UINT32 Flags;
    HV_UINT32 TotalProcessors;
    HV_UINT32 LaunchedProcessors;
    HV_UINT32 DetachedProcessors;
    HV_UINT32 FailedProcessors;
    HV_UINT32 TerminalProcessors;
    HV_UINT32 ParentFlags;
    HV_UINT32 ParentFeatures;
    HV_UINT32 CapabilityFlags;
    HV_UINT32 PreflightFailure;
    HV_UINT32 LastFailure;
    HV_UINT32 LastVmInstructionError;
    HV_UINT32 PhysicalAddressBits;
    HV_UINT64 MaximumGuestPhysicalAddress;
    char      ParentVendor[16];
    HV_UINT64 AggregateExitCounters[HV_STATUS_EXIT_REASON_COUNT];
    HV_STATUS_VCPU_V1 Vcpu[HV_STATUS_MAX_VCPUS];
} HV_STATUS_V1;
#pragma pack(pop)

/* Input structure for IOCTL_HV_CONCEAL_BYOVD */
#pragma pack(push, 8)
typedef struct _HV_CONCEAL_BYOVD_REQUEST {
    /* Basename of the BYOVD driver to conceal, e.g. L"pstrip64.sys" */
    /* (the random stem copy name is fine — match is on DllBase, not name) */
    HV_UINT16 DriverName[128];
    /* If non-zero, also wipe the driver's LDR_DATA_TABLE_ENTRY name fields */
    HV_UINT32 WipeLdrEntry;
    HV_UINT32 Reserved;
} HV_CONCEAL_BYOVD_REQUEST;
#pragma pack(pop)
