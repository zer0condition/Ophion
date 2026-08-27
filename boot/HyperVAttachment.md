# Clean-room Hyper-V attachment mode

This document is an implementation boundary for Ophion's future `HyperVAttachment` mode. It derives requirements from public Hyper-V architecture and independently written design notes; no GPLv3 source from `hyper-reV` is copied into Ophion.

## Objective

Replace the current minimal synthetic Hyper-V persona with an attachment that runs inside an already launched Microsoft Hyper-V instance. Windows then sees genuine Hyper-V CPUID leaves, synthetic MSRs, hypercalls, timing behavior, and VBS/HVCI policy, while Ophion owns a narrowly scoped attachment context.

## Preconditions

- Microsoft Hyper-V must be active before Windows begins loading.
- The preflight tool must report `Microsoft Hv` from CPUID leaf `0x40000000` and Hyper-V detail information from the matching boot stratum.
- The attachment is a lab/OVMF feature until the runtime matrix is green.
- This mode must not patch or replace `bootmgfw.efi`, SPI flash, Secure Boot databases, TPM state, or the Windows Hyper-V image outside a disposable OVMF lab.

## Clean-room state machine

```text
DXE runtime driver
  -> capture loaded-image and allocation registry
  -> observe boot-manager/winload/hvloader state
  -> capture only public launch handoff facts
  -> wait for genuine Hyper-V first exit
  -> initialize attachment heap, per-core state, and SLAT context
  -> validate host CPUID/MSR/hypercall behavior
  -> expose read-only telemetry
```

Each transition is guarded by a versioned handoff record. Failure always returns to the unmodified Hyper-V path; it never falls back to a synthetic VMX path in the same boot.

## Required interfaces

1. **Launch handoff ABI:** Hyper-V image base/size, host CR3, guest CR3, attachment physical range, CPU topology, and a generation counter.
2. **SLAT ABI:** immutable original context, optional copy-on-write context, all-core invalidation epoch, and a dummy-page registry. Code hooks stay disabled for anti-cheat test boots.
3. **Hypercall ABI:** pass through genuine Microsoft hypercalls; attachment commands use a separate versioned page and must not overload undocumented synthetic MSRs.
4. **Telemetry ABI:** CPUID/MSR identity, first-exit count, per-core state, SLAT epoch, and failure reason. No device object/IOCTL exists in production mode.

## Gates before implementation

1. OVMF DXE path reaches the Windows loader with a valid `Microsoft Hv` persona.
2. The preflight output records matching CPUID, system hypervisor detail, QPC, and KUSER state.
3. Hyper-V baseline runs VMAware, hvdetecc, the Ophion probe, and the existing detector manifest with no attachment.
4. An attachment build may first add **read-only** first-exit telemetry. SLAT redirection, page hiding, and command transport are separate gated changes.

## License boundary

`noahware/hyper-reV` is GPLv3 and is reference-only. Ophion may use public architecture facts and independently derived test evidence, but it must not copy source, headers, comments, ABI layouts, or boot-hook implementations from that repository.
