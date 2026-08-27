/*
 * Clean-room Hyper-V attachment provider ABI.
 *
 * Providers are restricted to documented TLFS interfaces.  Probe is
 * read-only; Prepare owns reversible resources; Commit publishes the
 * attachment; Rollback is idempotent; Release runs only after detach or a
 * completed rollback.
 */
#pragma once

#include <ntddk.h>
#include "hv_public.h"

#define HV_ATTACHMENT_PROVIDER_VERSION_1 1U

#define HV_ATTACHMENT_PROVIDER_READ_ONLY_PROBE      0x00000001U
#define HV_ATTACHMENT_PROVIDER_IDEMPOTENT_ROLLBACK  0x00000002U
#define HV_ATTACHMENT_PROVIDER_DOCUMENTED_TLFS_ONLY 0x00000004U
#define HV_ATTACHMENT_PROVIDER_MEASURED_BOOT_NEUTRAL 0x00000008U

#define HV_ATTACHMENT_OWN_HYPERCALL_PAGE (1ULL << 0)
#define HV_ATTACHMENT_OWN_INPUT_PAGE     (1ULL << 1)
#define HV_ATTACHMENT_OWN_OUTPUT_PAGE    (1ULL << 2)
#define HV_ATTACHMENT_OWN_PARTITION      (1ULL << 3)
#define HV_ATTACHMENT_OWN_VP             (1ULL << 4)
#define HV_ATTACHMENT_OWN_PORT           (1ULL << 5)
#define HV_ATTACHMENT_OWN_GPA_MAPPING    (1ULL << 6)

typedef struct _HV_ATTACHMENT_SESSION {
    UINT32 Size;
    UINT16 Version;
    UINT16 HeaderBytes;
    volatile LONG State;
    UINT32 Failure;
    UINT64 NegotiatedFeatures;
    UINT64 OwnershipMask;
    UINT64 SessionId;
    PVOID  ProviderContext;
    volatile LONG Transition;
    UINT32 Reserved;
} HV_ATTACHMENT_SESSION;

typedef NTSTATUS
(*HV_ATTACHMENT_PROBE_FN)(
    PVOID provider_context,
    const HV_ATTACH_PLATFORM_V1 * platform,
    UINT64 * available_features);

typedef NTSTATUS
(*HV_ATTACHMENT_PREPARE_FN)(
    PVOID provider_context,
    const HV_ATTACH_PLATFORM_V1 * platform,
    const HV_ATTACH_REQUEST_V1 * request,
    HV_ATTACHMENT_SESSION * session);

typedef NTSTATUS
(*HV_ATTACHMENT_COMMIT_FN)(
    PVOID provider_context,
    HV_ATTACHMENT_SESSION * session);

typedef NTSTATUS
(*HV_ATTACHMENT_ROLLBACK_FN)(
    PVOID provider_context,
    HV_ATTACHMENT_SESSION * session);

typedef VOID
(*HV_ATTACHMENT_RELEASE_FN)(
    PVOID provider_context,
    HV_ATTACHMENT_SESSION * session);

typedef struct _HV_ATTACHMENT_PROVIDER_V1 {
    UINT32 Size;
    UINT16 Version;
    UINT16 HeaderBytes;
    UINT32 ProviderId;
    UINT32 Flags;
    UINT64 AvailableFeatures;
    PVOID  Context;
    HV_ATTACHMENT_PROBE_FN Probe;
    HV_ATTACHMENT_PREPARE_FN Prepare;
    HV_ATTACHMENT_COMMIT_FN Commit;
    HV_ATTACHMENT_ROLLBACK_FN Rollback;
    HV_ATTACHMENT_RELEASE_FN Release;
} HV_ATTACHMENT_PROVIDER_V1;

C_ASSERT(sizeof(HV_ATTACH_PLATFORM_V1) == 112);
C_ASSERT(sizeof(HV_ATTACH_REQUEST_V1) == 48);
C_ASSERT(sizeof(HV_ATTACH_RESULT_V1) == 56);
C_ASSERT(sizeof(HV_ATTACHMENT_SESSION) == 56);
C_ASSERT(sizeof(HV_ATTACHMENT_PROVIDER_V1) == 72);

NTSTATUS
hv_attachment_execute(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    const HV_ATTACH_PLATFORM_V1 * platform,
    const HV_ATTACH_REQUEST_V1 * request,
    HV_ATTACHMENT_SESSION * session,
    HV_ATTACH_RESULT_V1 * result);

NTSTATUS
hv_attachment_rollback(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    HV_ATTACHMENT_SESSION * session);

VOID
hv_attachment_release(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    HV_ATTACHMENT_SESSION * session);
