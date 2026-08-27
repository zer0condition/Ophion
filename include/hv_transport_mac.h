/*
 * Shared allocation-free command-record authenticator.
 *
 * Two domain-separated SipHash-2-4 results form a 128-bit tag.  The same
 * implementation is compiled into VMX-root and OphionMap's self-test.
 */
#pragma once

#include "hv_public.h"

#define HV_TRANSPORT_MAC_ALGORITHM "siphash-2-4x2-128"
#define HV_TRANSPORT_MAC_REQUEST_DOMAIN  0x315145525F56484FULL
#define HV_TRANSPORT_MAC_RESPONSE_DOMAIN 0x315053525F56484FULL
#define HV_TRANSPORT_MAC_SECOND_DOMAIN   0xA5A5A5A5A5A5A5A5ULL

typedef struct _HV_TRANSPORT_SIPHASH {
    HV_UINT64 V0;
    HV_UINT64 V1;
    HV_UINT64 V2;
    HV_UINT64 V3;
    HV_UINT64 Tail;
    HV_UINT64 TotalBytes;
    HV_UINT32 TailBytes;
} HV_TRANSPORT_SIPHASH;

static inline HV_UINT64
hv_transport_rotl64(HV_UINT64 value, HV_UINT32 bits)
{
    return (value << bits) | (value >> (64U - bits));
}

static inline void
hv_transport_sip_round(HV_TRANSPORT_SIPHASH * state)
{
    state->V0 += state->V1;
    state->V1 = hv_transport_rotl64(state->V1, 13);
    state->V1 ^= state->V0;
    state->V0 = hv_transport_rotl64(state->V0, 32);
    state->V2 += state->V3;
    state->V3 = hv_transport_rotl64(state->V3, 16);
    state->V3 ^= state->V2;
    state->V0 += state->V3;
    state->V3 = hv_transport_rotl64(state->V3, 21);
    state->V3 ^= state->V0;
    state->V2 += state->V1;
    state->V1 = hv_transport_rotl64(state->V1, 17);
    state->V1 ^= state->V2;
    state->V2 = hv_transport_rotl64(state->V2, 32);
}

static inline void
hv_transport_sip_compress(
    HV_TRANSPORT_SIPHASH * state,
    HV_UINT64 word)
{
    state->V3 ^= word;
    hv_transport_sip_round(state);
    hv_transport_sip_round(state);
    state->V0 ^= word;
}

static inline void
hv_transport_sip_init(
    HV_TRANSPORT_SIPHASH * state,
    HV_UINT64 key_low,
    HV_UINT64 key_high)
{
    state->V0 = 0x736F6D6570736575ULL ^ key_low;
    state->V1 = 0x646F72616E646F6DULL ^ key_high;
    state->V2 = 0x6C7967656E657261ULL ^ key_low;
    state->V3 = 0x7465646279746573ULL ^ key_high;
    state->Tail = 0;
    state->TotalBytes = 0;
    state->TailBytes = 0;
}

static inline void
hv_transport_sip_update(
    HV_TRANSPORT_SIPHASH * state,
    const void * data,
    HV_UINT32 data_bytes)
{
    const HV_UINT8 * bytes = (const HV_UINT8 *)data;
    HV_UINT32 index;

    for (index = 0; index < data_bytes; index++)
    {
        state->Tail |=
            (HV_UINT64)bytes[index] << (state->TailBytes * 8U);
        state->TailBytes++;
        state->TotalBytes++;
        if (state->TailBytes == 8U)
        {
            hv_transport_sip_compress(state, state->Tail);
            state->Tail = 0;
            state->TailBytes = 0;
        }
    }
}

static inline HV_UINT64
hv_transport_sip_finish(HV_TRANSPORT_SIPHASH * state)
{
    HV_UINT64 final_word =
        state->Tail | ((state->TotalBytes & 0xFFULL) << 56);

    hv_transport_sip_compress(state, final_word);
    state->V2 ^= 0xFFULL;
    hv_transport_sip_round(state);
    hv_transport_sip_round(state);
    hv_transport_sip_round(state);
    hv_transport_sip_round(state);
    return state->V0 ^ state->V1 ^ state->V2 ^ state->V3;
}

static inline HV_UINT64
hv_transport_mac64(
    HV_UINT64 key_low,
    HV_UINT64 key_high,
    HV_UINT64 domain,
    HV_UINT32 command,
    HV_UINT64 epoch,
    HV_UINT64 sequence,
    HV_UINT32 value_bytes,
    HV_UINT32 capacity_or_status,
    const void * payload,
    HV_UINT32 payload_bytes)
{
    HV_TRANSPORT_SIPHASH state;

    hv_transport_sip_init(&state, key_low, key_high);
    hv_transport_sip_update(&state, &domain, sizeof(domain));
    hv_transport_sip_update(&state, &command, sizeof(command));
    hv_transport_sip_update(&state, &epoch, sizeof(epoch));
    hv_transport_sip_update(&state, &sequence, sizeof(sequence));
    hv_transport_sip_update(&state, &value_bytes, sizeof(value_bytes));
    hv_transport_sip_update(
        &state, &capacity_or_status, sizeof(capacity_or_status));
    if (payload_bytes)
        hv_transport_sip_update(&state, payload, payload_bytes);
    return hv_transport_sip_finish(&state);
}

static inline void
hv_transport_mac_request(
    HV_UINT64 key_low,
    HV_UINT64 key_high,
    HV_UINT32 command,
    HV_UINT64 epoch,
    HV_UINT64 sequence,
    HV_UINT32 request_bytes,
    HV_UINT32 response_capacity,
    const void * payload,
    HV_UINT64 * mac_low,
    HV_UINT64 * mac_high)
{
    *mac_low = hv_transport_mac64(
        key_low, key_high,
        HV_TRANSPORT_MAC_REQUEST_DOMAIN,
        command, epoch, sequence,
        request_bytes, response_capacity,
        payload, request_bytes);
    *mac_high = hv_transport_mac64(
        key_low, key_high,
        HV_TRANSPORT_MAC_REQUEST_DOMAIN ^
            HV_TRANSPORT_MAC_SECOND_DOMAIN,
        command, epoch, sequence,
        request_bytes, response_capacity,
        payload, request_bytes);
}

static inline void
hv_transport_mac_response(
    HV_UINT64 key_low,
    HV_UINT64 key_high,
    HV_UINT32 command,
    HV_UINT64 epoch,
    HV_UINT64 sequence,
    HV_UINT32 status,
    HV_UINT32 response_bytes,
    const void * payload,
    HV_UINT64 * mac_low,
    HV_UINT64 * mac_high)
{
    *mac_low = hv_transport_mac64(
        key_low, key_high,
        HV_TRANSPORT_MAC_RESPONSE_DOMAIN,
        command, epoch, sequence,
        response_bytes, status,
        payload, response_bytes);
    *mac_high = hv_transport_mac64(
        key_low, key_high,
        HV_TRANSPORT_MAC_RESPONSE_DOMAIN ^
            HV_TRANSPORT_MAC_SECOND_DOMAIN,
        command, epoch, sequence,
        response_bytes, status,
        payload, response_bytes);
}
