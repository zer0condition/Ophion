/*
 * attachment.c - strict generic lifecycle for documented attachment providers.
 * The bundled boundary supports probe-only eligibility. A provider must supply
 * real documented primitives before Prepare or Commit can advance state.
 */
#include "hv.h"

#define HV_ATTACH_KNOWN_REQUEST_FLAGS \
    (HV_ATTACH_REQUEST_REQUIRE_MEASURED_BOOT | \
     HV_ATTACH_REQUEST_REQUIRE_HVCI_SAFE | \
     HV_ATTACH_REQUEST_NO_PRIVATE_SYMBOLS | \
     HV_ATTACH_REQUEST_NO_BOOT_MUTATION)
#define HV_ATTACH_KNOWN_FEATURES \
    ((HV_ATTACH_FEATURE_ROLLBACK << 1) - 1)
#define HV_ATTACH_KNOWN_OWNERSHIP \
    ((HV_ATTACHMENT_OWN_GPA_MAPPING << 1) - 1)

static VOID
attachment_result(
    HV_ATTACH_RESULT_V1 * result,
    const HV_ATTACH_REQUEST_V1 * request,
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    const HV_ATTACHMENT_SESSION * session)
{
    RtlZeroMemory(result, sizeof(*result));
    result->Size = sizeof(*result);
    result->Version = HV_ATTACH_ABI_VERSION_1;
    result->HeaderBytes = sizeof(*result);
    result->Mode = request ? request->Mode : HV_ATTACH_MODE_PROBE_ONLY;
    result->Provider = provider ? provider->ProviderId : HV_ATTACH_PROVIDER_NONE;
    if (session)
    {
        result->State = (UINT32)session->State;
        result->Failure = session->Failure;
        result->NegotiatedFeatures = session->NegotiatedFeatures;
        result->OwnershipMask = session->OwnershipMask;
        result->SessionId = session->SessionId;
    }
}

static BOOLEAN
attachment_valid(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    const HV_ATTACH_PLATFORM_V1 * platform,
    const HV_ATTACH_REQUEST_V1 * request)
{
    if (!provider || !platform || !request ||
        provider->Size != sizeof(*provider) ||
        provider->Version != HV_ATTACHMENT_PROVIDER_VERSION_1 ||
        provider->HeaderBytes != sizeof(*provider) ||
        !provider->Probe || !provider->Rollback || !provider->Release ||
        platform->Size < sizeof(*platform) ||
        platform->Version != HV_ATTACH_ABI_VERSION_1 ||
        platform->Reserved0 || platform->Reserved1 ||
        request->Size != sizeof(*request) ||
        request->Version != HV_ATTACH_ABI_VERSION_1 ||
        request->HeaderBytes != sizeof(*request) ||
        request->Flags & ~HV_ATTACH_KNOWN_REQUEST_FLAGS ||
        request->RequiredFeatures & ~HV_ATTACH_KNOWN_FEATURES ||
        request->OptionalFeatures & ~HV_ATTACH_KNOWN_FEATURES ||
        (!request->NonceLow && !request->NonceHigh))
        return FALSE;
    return request->Mode == HV_ATTACH_MODE_PROBE_ONLY ||
           request->Mode == HV_ATTACH_MODE_HYPERV_ROOT_TLFS ||
           request->Mode == HV_ATTACH_MODE_HYPERV_NESTED_TLFS;
}

NTSTATUS
hv_attachment_execute(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    const HV_ATTACH_PLATFORM_V1 * platform,
    const HV_ATTACH_REQUEST_V1 * request,
    HV_ATTACHMENT_SESSION * session,
    HV_ATTACH_RESULT_V1 * result)
{
    NTSTATUS status;
    UINT64 available = 0;

    if (!session || !result)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(session, sizeof(*session));
    session->Size = sizeof(*session);
    session->Version = HV_ATTACHMENT_PROVIDER_VERSION_1;
    session->HeaderBytes = sizeof(*session);
    session->State = HV_ATTACH_STATE_EMPTY;
    if (!attachment_valid(provider, platform, request))
    {
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = HV_ATTACH_FAILURE_ABI_MISMATCH;
        attachment_result(result, request, provider, session);
        return STATUS_INVALID_PARAMETER;
    }
    session->State = HV_ATTACH_STATE_DISCOVERED;
    status = provider->Probe(provider->Context, platform, &available);
    if (!NT_SUCCESS(status))
    {
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = HV_ATTACH_FAILURE_PROVIDER_PROBE;
        attachment_result(result, request, provider, session);
        return status;
    }
    available &= provider->AvailableFeatures & HV_ATTACH_KNOWN_FEATURES;
    if (request->RequiredFeatures & ~available)
    {
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = HV_ATTACH_FAILURE_PROVIDER_UNAVAILABLE;
        attachment_result(result, request, provider, session);
        return STATUS_NOT_SUPPORTED;
    }
    session->NegotiatedFeatures = request->RequiredFeatures |
        (request->OptionalFeatures & available);
    session->SessionId = request->NonceLow ^ _rotl64(request->NonceHigh, 29);
    session->State = HV_ATTACH_STATE_ELIGIBLE;
    if (request->Mode == HV_ATTACH_MODE_PROBE_ONLY)
    {
        attachment_result(result, request, provider, session);
        return STATUS_SUCCESS;
    }
    if (!provider->Prepare || !provider->Commit)
    {
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = HV_ATTACH_FAILURE_PROVIDER_UNAVAILABLE;
        attachment_result(result, request, provider, session);
        return STATUS_NOT_SUPPORTED;
    }
    status = provider->Prepare(
        provider->Context, platform, request, session);
    if (!NT_SUCCESS(status) ||
        session->OwnershipMask & ~HV_ATTACH_KNOWN_OWNERSHIP)
    {
        UINT32 failure = HV_ATTACH_FAILURE_PROVIDER_PREPARE;
        NTSTATUS rollback_status = hv_attachment_rollback(provider, session);
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = NT_SUCCESS(rollback_status)
            ? failure
            : HV_ATTACH_FAILURE_ROLLBACK;
        attachment_result(result, request, provider, session);
        if (!NT_SUCCESS(rollback_status))
            return rollback_status;
        return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
    }
    session->State = HV_ATTACH_STATE_PREPARED;
    status = provider->Commit(provider->Context, session);
    if (!NT_SUCCESS(status))
    {
        NTSTATUS commit_status = status;
        NTSTATUS rollback_status = hv_attachment_rollback(provider, session);
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = NT_SUCCESS(rollback_status)
            ? HV_ATTACH_FAILURE_PROVIDER_COMMIT
            : HV_ATTACH_FAILURE_ROLLBACK;
        attachment_result(result, request, provider, session);
        return NT_SUCCESS(rollback_status) ? commit_status : rollback_status;
    }
    session->State = HV_ATTACH_STATE_ATTACHED;
    attachment_result(result, request, provider, session);
    return STATUS_SUCCESS;
}

NTSTATUS
hv_attachment_rollback(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    HV_ATTACHMENT_SESSION * session)
{
    NTSTATUS status;

    if (!provider || !session || !provider->Rollback)
        return STATUS_INVALID_PARAMETER;
    if (!session->OwnershipMask)
    {
        session->State = HV_ATTACH_STATE_DETACHED;
        return STATUS_SUCCESS;
    }
    status = provider->Rollback(provider->Context, session);
    if (!NT_SUCCESS(status) || session->OwnershipMask)
    {
        session->State = HV_ATTACH_STATE_FAILED;
        session->Failure = HV_ATTACH_FAILURE_ROLLBACK;
        return NT_SUCCESS(status) ? STATUS_DEVICE_BUSY : status;
    }
    session->State = HV_ATTACH_STATE_DETACHED;
    return STATUS_SUCCESS;
}

VOID
hv_attachment_release(
    const HV_ATTACHMENT_PROVIDER_V1 * provider,
    HV_ATTACHMENT_SESSION * session)
{
    if (!provider || !session || !provider->Release ||
        session->State != HV_ATTACH_STATE_DETACHED ||
        session->OwnershipMask)
        return;
    provider->Release(provider->Context, session);
    session->ProviderContext = NULL;
}