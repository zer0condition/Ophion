# Clean-room Hyper-V attachment ABI v1

## Scope

This ABI is the boundary between Ophion and a future Hyper-V attachment
provider. Attachment means using public Microsoft Hyper-V TLFS discovery,
synthetic-register, and hypercall contracts from the current partition. It
does not mean patching `hvix64.exe`/`hvax64.exe`, resolving private symbols, or
reusing build-specific Hyper-V structures.

Version 1 is x64-only and defines negotiation plus lifecycle ownership. It
does not claim that a production Hyper-V provider exists or that attachment is
compatible with EAC or BattlEye.

`ELIGIBLE` means only that documented parent-partition operations may be
attempted. Public TLFS discovery and hypercalls do not expose ownership of the
existing Hyper-V SLAT root, arbitrary VTL0 VM-exit interception, a Hyper-V host
CR3, private partition objects, or `hvix64.exe`/`hvax64.exe` handoff state.
Those are unsupported by this provider boundary. A provider must return
`HV_ATTACH_FAILURE_PROVIDER_UNAVAILABLE` rather than advancing to `PREPARED`
when the requested Ophion data plane depends on any such primitive.

## Clean-room invariants

1. Probe uses CPUID only and has no side effects.
2. Compatibility is based on the `Hv#1` interface and advertised features,
   not vendor text or Windows version heuristics.
3. Reserved TLFS bits are zero and no synthetic MSR or hypercall is used until
   its privilege bit is present.
4. There are no private symbols, hypervisor patches, VTL transitions, or
   undocumented partition layouts in the provider boundary.
5. When a conformant hypervisor is already present, the bare-metal path must
   not execute `VMXON`. It selects a validated provider or fails closed.
6. Prepare may create only reversible, provider-owned resources. Commit is the
   first publication point.
7. Rollback is idempotent, records every remaining ownership bit, and runs in
   reverse ownership order. Release is valid only after detach or completed
   rollback.
8. Attachment is measured boot neutral: it does not change Secure Boot,
   BCD/hypervisor launch policy, TPM NV state, PCR banks, VBS policy, HVCI
   policy, or boot files.
9. One session transition may be in flight. Implementations use an atomic
   compare/exchange on `HV_ATTACHMENT_SESSION.Transition`.

## Discovery contract

The platform record is filled from these public facts:

- `CPUID.01h:ECX[31]` reports a hypervisor.
- `CPUID.40000000h` reports the maximum leaf and diagnostic vendor string.
- `CPUID.40000001h:EAX` must equal `0x31237648` (`Hv#1`).
- `CPUID.40000002h` supplies Hyper-V build/major/minor reporting data.
- `CPUID.40000003h:EAX:EBX` is the 64-bit partition privilege mask.
- `CPUID.40000004h` supplies recommendations; bit 12 reports nested
  placement and bit 14 recommends enlightened VMCS.
- `CPUID.40000005h` supplies implementation limits.
- Leaves `0x40000009` and `0x4000000A`, when present, supply nested
  synthetic-register and enlightened-VMCS capabilities.

The root-provider baseline is:

```text
AccessHypercallMsrs | CreatePartitions | AccessPartitionId
```

That mask means root-provider operations are eligible; it is not by itself an
identity or security decision. The provider still performs a documented
read-only probe and records the returned status.

## Wire records

`include/hv_public.h` defines fixed-width, pack-8 records:

- `HV_ATTACH_PLATFORM_V1` - immutable discovery snapshot.
- `HV_ATTACH_REQUEST_V1` - requested mode, required/optional features, policy,
  and caller nonce.
- `HV_ATTACH_RESULT_V1` - negotiated provider, state, failure, ownership, and
  session identity.

Every record begins with `Size` and `Version`. Unknown trailing fields are
ignored only when `Size` is at least the v1 size. Reserved fields must be zero.
Inputs with unknown modes, flags, required features, or nonzero reserved
fields fail with `HV_ATTACH_FAILURE_ABI_MISMATCH`.

## Provider ABI

`include/hv_attachment.h` defines `HV_ATTACHMENT_PROVIDER_V1`:

1. `Probe` is read-only and returns advertised features.
2. `Prepare` allocates reversible resources and moves
   `ELIGIBLE -> PREPARED`.
3. `Commit` publishes the attachment and moves `PREPARED -> ATTACHED`.
4. `Rollback` unwinds owned resources and is safe to call repeatedly.
5. `Release` clears provider-private session storage after detach/rollback.

The generic layer owns state transitions and failure publication. Providers
own only resources represented by `OwnershipMask`; they set each bit before
the corresponding resource becomes externally reachable.

## State machine

```text
EMPTY
  -> DISCOVERED
  -> ELIGIBLE
  -> PREPARED
  -> ATTACHED
  -> DETACHED

DISCOVERED | ELIGIBLE | PREPARED | ATTACHED
  -> FAILED
  -> rollback until OwnershipMask == 0
  -> DETACHED
```

Probe-only requests stop at `ELIGIBLE`. Any missing required feature fails
before `Prepare`. A commit failure enters `FAILED`; it never retries commit
implicitly.

## Policy gates

- `REQUIRE_MEASURED_BOOT` requires captured Secure Boot, TPM 2.0, and measured
  boot evidence; unknown is failure, not false.
- `REQUIRE_HVCI_SAFE` requires a provider that does not allocate executable
  VTL0 pages or depend on writable executable mappings.
- `NO_PRIVATE_SYMBOLS` and `NO_BOOT_MUTATION` are mandatory for the
  `HV_ATTACH_PROVIDER_HYPERV_TLFS` provider.
- Nested mode requires the nested recommendation and advertised leaf
  `0x4000000A` features needed by the selected implementation.

## Explicit non-goals

- No live Hyper-V patching, private object traversal, or VTL1 access.
- No bypass of Secure Boot, HVCI, Code Integrity, or TPM attestation.
- No assumption that root-partition eligibility makes a provider stealthy.
- No inference that privilege bits identify the current partition as root.
- No arbitrary VTL0 interception or existing-SLAT ownership through public TLFS.
- No fallback to bare-metal `VMXON` after Hyper-V discovery.

## References

- Microsoft Hyper-V TLFS:
  https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs
- Feature and interface discovery:
  https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
- Hypercall interface:
  https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/hypercall-interface
- Partition privilege mask:
  https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask
- Hyper-V architecture:
  https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/architecture
