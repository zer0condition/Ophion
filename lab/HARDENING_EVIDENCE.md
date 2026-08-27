# Ophion hardening evidence

This ledger records only observations reproduced on the current host. It is not
evidence that Ophion is compatible with, undetected by, or safe to use against
EAC or BattlEye.

## Vulnerable-driver bootstrap residue

Observed on Windows build `26200` on 2026-08-26.

- Candidate:
  `C:\Users\Admin\Desktop\Sec-Research\VulnDrivers\12-DirectIo64_legacy\DirectIo64_legacy.sys`
- SHA-256:
  `AC63C26CA43701DDDAA7FB1AEA535D42190F88752900A03040FD5AAA24991E25`
- Authenticode: valid PassMark Software signature, thumbprint
  `99484BEBCE6A522785F748107F227A257B3AB119`.
- Device Guard query: VBS status `0`; HVCI not configured.
- Load result: `NtLoadDriver` returned `0xC0000603`. Code Integrity event
  `3023` states that the randomized copy was revoked by Microsoft; event
  `3077` records rejection by the enforced Microsoft Windows Driver Policy.
- Stateful post-attempt comparison found no additions or changes in:
  service registry keys, `Win32_SystemDriver`, Object Manager `\Driver`,
  `\Device`, or `\GLOBAL??`, and temporary `.sys` files.
- Durable observability remains: Code Integrity records `214` through `219`
  preserved the randomized temporary path and the blocked-load decision.

Evidence artifacts:

- `build/bootstrap-residue/baseline.json`
- `build/bootstrap-residue/failed-load-report.json`
- `tools/bootstrap-residue.ps1`

Conclusion: this DirectIo build is not a viable bootstrap on the current code
integrity policy. The loader's failed-load cleanup removed the state surfaces
covered by the comparison, but it cannot erase the Code Integrity audit trail.

Uncovered surfaces:

- `PiDDBCacheTable` structural state
- `MmUnloadedDrivers` structural state
- historical ImageLoad ETW that was not captured before the baseline

Those surfaces must not be described as clean without a build-pinned kernel
structural collector or a trace started before the load attempt.

## Clean-room Hyper-V attachment foundation

- `include/hv_public.h` defines fixed-width v1 platform, request, and result
  records plus the public `Hv#1` interface and partition-privilege constants.
- `include/hv_attachment.h` defines a probe/prepare/commit/rollback/release
  provider lifecycle with explicit ownership and compile-time ABI sizes.
- `lab/HYPERV_ATTACHMENT_ABI.md` pins the design to public Microsoft TLFS
  feature discovery and hypercalls. It forbids private symbols, live
  hypervisor patches, boot-policy changes, and bare-metal `VMXON` fallback
  after Hyper-V discovery.
- `OphionProbe.exe` now captures Hyper-V leaves `0x40000000` through the
  advertised maximum, capped at `0x4000000A`, on every active processor.
  `tools/hyperv-attachment-preflight.ps1` rejects cross-processor drift,
  truncated leaves, non-`Hv#1` interfaces, missing root privileges, and
  unavailable nested enlightenment before a provider can run.
- Fixture tests passed eligible-root, incompatible-interface/privilege, and
  malformed-input paths. The live read-only report at
  `build/hyperv-attachment-preflight.json` ended
  `empty -> discovered -> failed` with `no-hypervisor` on Windows build
  `26200`; this host is not an attachment-provider test target.
- The ABI compiles in production and diagnostic WDK builds. It is a
  foundation only; no Hyper-V provider or live attachment is claimed.

## TPM and measured-boot compatibility

Observed read-only on Windows build `26200`:

- Secure Boot is enabled.
- TBS reported TPM 2.0 twice with identical device metadata; `Get-Tpm`
  reported an enabled, activated, ready, owned Intel TPM.
- A TPM2 `PCR_Read` of SHA-256 PCRs `0,2,4,7,11` succeeded and returned five
  32-byte digests.
- The newest Windows measured-boot summary reported `HealthStatus=Attestable`
  and `PcrsMatchTcgLog=true`. The raw log and summary were hashed in the
  report.
- The `0x810EAC00` public object was present, and two `ReadPublic` responses
  were byte-hash identical.
- `tests/tpm-audit.ps1` passed compatible, inconclusive, incompatible, and
  malformed evidence classifications.

Evidence: `build/tpm-measured-boot-audit.json`.

The current-state measured-boot policy is compatible with a provider that
performs no boot or TPM mutation. No provider ran, so PCR preservation across
an attachment transition remains unvalidated and must not be claimed.

## Artifact build gate

- Clean production and diagnostic WDK builds completed with compiler/MASM
  warnings fatal.
- Release `OphionMap.exe`, `OphionLoad.exe`, `OphionProbe.exe`, and
  `OphionInternal.lib` builds completed.
- The Visual Studio CMake preset produced `ophion_platform.lib`,
  `ophion_platform_tests.exe`, and `ophion_mock_client.exe`.
- The local EDK2/VS2022/NASM/IASL toolchain produced the x64
  `OphionBoot.efi` at
  `C:\Users\Admin\Tools\edk2\Build\OphionBoot\RELEASE_VS2022\X64`.
  EDK2 emitted two package-level `DevicePathLib` library-class warnings; C
  compilation and linking used `/WX` and succeeded.
- `build/artifact-manifest.json` records SHA-256, size, and x64 PE validation
  for nine required runtime/support artifacts plus the boot image. No required
  artifact is missing.

## Verification matrix

- `tests/contracts.ps1`: 252 assertions passed.
- `tests/attachment-preflight.ps1`: eligible, incompatible, and malformed
  state-machine paths passed.
- `tests/tpm-audit.ps1`: compatible, inconclusive, incompatible, and malformed
  policy paths passed.
- `tests/mapper-artifact.ps1`: 311296-byte image, 25-byte entry/cleanup,
  73-byte bootstrap/stop, and shared RVA `0x46000` passed.
- `tests/eac_startup_harness_test.py`: 10 fixture-emulator tests passed.
- CTest: `ophion_platform_tests` passed.
- Mapper transport-MAC self-test passed.
- The live probe parsed all 16 processors with one timing sample each; help
  returns success and invalid sample input fails with structured JSON.
- The mock client completed with `{"transport":"mock","epoch":1,"error":"Ok"}`.
- Mapper and loader help paths rendered; malformed numeric/backend input was
  rejected without side effects.
- `git diff --check` passed; Git reported only expected LF-to-CRLF working-copy
  conversion warnings.

## Detector differential

Baseline:
`build/detector-results/20260826-182658`

Current:
`build/detector-results/20260826-202522`

- Both runs reported `HypervisorPresent=false` and VBS status `0`.
- The pinned EPT detector completed six samples per check in each run. Hook,
  timing, thread, and write-reflection checks were `No` in all samples.
- The pinned xeroxz detector produced the same four classifications in both
  runs. Its CPUID-vs-FYL2XP1 timing heuristic reported `Detected` on the clean
  baseline and current host; this is a known baseline positive, not new drift.
- The all-core probe persona was unchanged across 16 processors and 16000
  samples. Aggregate median CPUID timing moved from `81` to `80` cycles
  (`-1.235%`), below the recorded 25% noise threshold; P95 remained `256`.
- Detector stderr contained no text. There was no persona, VBS, hypervisor,
  EPT, or detector-classification drift.

`build/detector-differential.json` records verdict
`host-baseline-unchanged-runtime-not-exercised`.

This is not an Ophion detector pass: Code Integrity prevented launch, so both
runs measured the non-virtualized host. It proves detector/tool stability and
no host-state regression, not EAC/BattlEye or live-VMX compatibility.

## Production command and teardown transport

- `.hvshare` is a dedicated 4 KiB RW/NX command page at mapped RVA `0x46000`.
- `.hvroot` is a separate 4 KiB RW/NX page registered for EPT concealment.
- Production snapshots the vCPU base, processor count, topology, and
  capability record into `.hvroot`; VMX-root status, seal, stop, and CR3
  validation paths no longer consume the guest-writable globals.
- The complete `g_vcpu` allocation is registered for concealment. EPT table
  pointers are snapshotted before launch.
- Concealment now allocates its dummy page and manifest before VMX launch,
  pre-splits every covered GPA in every vCPU EPT to a fixed point, freezes
  range registration, copies the final ranges into the manifest held by
  `.hvroot`, and securely erases the mutable collector.
- An all-core pre-launch DPC captures and allocates each private host GDT
  before host-CR3 construction and manifest freeze, so the default private-GDT
  pages are present in both the host mapping snapshot and conceal manifest.
- Each vCPU consumes the frozen manifest in `VMCALL_CONCEAL_COMMIT`, changes
  only its own EPT leaves with atomic 64-bit exchanges in VMX root, and
  executes single-context INVEPT before resuming guest execution. The dummy
  page's identity GPA is included in the read-only/execute-clear manifest, so
  guest physical writes cannot poison concealed reads. The commit path
  performs no allocation or large-page split. New production splits fail
  closed after manifest freeze.
- An initialization-only INVEPT helper records failure without making the
  vCPU terminal, preserving the all-core rollback VMCALL invariant if one
  local conceal commit cannot flush.
- `ophion.stop.bin` is a 73-byte per-CPU VMCALL thunk whose capability and
  epoch patch offsets are frozen in `ophion.map.json`.
- `ophion.cleanup.bin` targets exported `OphionCleanup`, which refuses cleanup
  until `vmx_all_stopped()` succeeds.
- READY requests and COMPLETE responses carry domain-separated 128-bit
  `siphash-2-4x2-128` tags over command/status, epoch, sequence, lengths, and
  payload. The mapper self-test passed the standard empty-message SipHash
  vector and mutation checks for both key words and every authenticated field.
- `DriverEntry` now launches and conceals first. The capability remains absent
  from `.hvroot` until every vCPU acknowledges the concealment INVEPT and the
  external runtime invokes the 73-byte `ophion.bootstrap.bin` VMCALL thunk.
  VMX-root then copies the capability and securely zeros both temporary copies.
- Production and diagnostic WDK builds passed with warnings as errors.
- `tests/contracts.ps1` passed 252 assertions.
- `tests/mapper-artifact.ps1` validated the 311296-byte mapped image, 25-byte
  entry thunk, 73-byte bootstrap thunk, 73-byte stop thunk, 25-byte cleanup
  thunk, shared page, patch offsets, and capability omission from metadata.
- Mapper placement tests reject trailing-junk numbers, user/noncanonical VAs,
  one-byte misalignment, image-range overflow, and a noncanonical ntoskrnl
  base. Accepted bases must be whole numeric values, canonical kernel
  addresses, and aligned to at least the PE `SectionAlignment`/4 KiB.

Live all-core VMX teardown was not exercised: the available DirectIo bootstrap
was rejected by Code Integrity before driver initialization. Current evidence
therefore proves build and artifact contracts, not a successful hardware
teardown cycle.

The manifest and `.hvroot` become guest-inaccessible only when each vCPU
executes its local root commit. They remain readable during the bounded
launch-to-commit interval, and the mapped driver image remains guest-visible.
Those are residual integrity and discovery surfaces, not evidence of EAC or
BattlEye compatibility.

## Residual risk

- The available DirectIo bootstrap is revoked, so no current artifact entered
  VMX and no all-core launch, conceal, command, stop, or cleanup cycle ran on
  hardware.
- No EAC or BattlEye binary was launched or attached. Fixture emulation and
  public detector suites cannot substitute for those products.
- The mapped image remains guest-visible. `.hvroot` and the manifest are
  readable during the bounded launch-to-local-commit interval.
- The private host-CR3 snapshot remains disabled; enabling it is incompatible
  with allocations created after its clone.
- Late BYOVD concealment and optional SMBIOS/DMAR mutation remain disabled
  because the immutable manifest intentionally rejects post-freeze ranges.
- The clean-room Hyper-V work is an ABI and preflight foundation; no provider
  exists and no attachment transition was exercised.
- TPM, Secure Boot, PCR, and TCG-log current state is compatible, but PCR
  preservation across a provider transition is untested.
- `OphionBoot.efi` is compile-verified only; it was not run in OVMF or on this
  Secure Boot chain.
- Conceal preparation fails closed after 16 fixed-point passes, and root leaf
  lookup remains linear in tracked EPT splits.
- The clean baseline itself trips the xeroxz FYL2XP1 timing heuristic.

The strongest defensible conclusion is therefore: source, lifecycle,
transport, artifact, and read-only platform gates are materially hardened and
green; runtime anti-cheat resilience remains unverified until a permitted
bootstrap and isolated hardware/Hyper-V/OVMF matrix can exercise the actual
artifacts.

## 2026-08-27 production-boundary and coherence pass

- A pre-edit safety checkpoint was written outside the repository at
  `C:\Users\Admin\Documents\Ophion-safety-20260827-025543`. It contains a
  repository bundle, binary working-tree patch, untracked-file archive, status
  record, and SHA-256 manifest.
- `build.ps1 -Production` now uses a profile-specific object directory and an
  explicit source graph. `eac_stealth.c`, `tracewipe.c`, and
  `byovd_conceal.c` are not compiled or linked into the production driver.
  `production_safe_profile.c` supplies inert fail-closed replacements.
- Every production mutation macro is forced to zero. A generated object
  manifest and post-link PE inspection reject experiment sources, forbidden
  markers, and control-device/loader imports.
- The fresh unsigned production artifact is 66,048 bytes with SHA-256
  `4AB3369A26AD1286A41A6E82673F69AF50FA154DF5E886F1AB0BAA898BB0CC7B`.
  The boundary report found zero forbidden markers and zero forbidden imports.
- The diagnostic driver remains separate and includes the research modules.
  Its SHA-256 is
  `F0BC114E390C703A118AFE63DDEF40BED0BDFDDAAD5BA13AE1A338FE19223E0E`.
- The incomplete boot `Microsoft Hv` persona now defaults off. Native CPUID is
  retained; synthetic Hyper-V MSRs are unsupported and unimplemented
  hypercalls return `HV_STATUS_INVALID_HYPERCALL_CODE`.
- The attachment ABI documentation now states that public TLFS eligibility
  does not provide arbitrary VTL0 VM-exit interception, ownership of the
  existing Hyper-V SLAT root, private partition objects, or a Hyper-V image
  handoff. Providers must fail with `PROVIDER_UNAVAILABLE` when those
  primitives are required.
- Root transport completion clears the complete payload before publishing a
  response, command sequence wrap fails closed, and conceal readers consume a
  coherent manifest/count/generation/dummy-PA snapshot.
- Conceal registration is serialized, VA translation and range-capacity
  changes are transactional, intervals are normalized into sorted disjoint
  ranges, root lookup uses binary search, and preparation has explicit
  collecting/preparing/published/failed states with unpublished allocation
  rollback.
- `attachment.c` now implements the generic v1 provider lifecycle: strict ABI
  and reserved-field validation, probe-only eligibility, required-feature
  negotiation, explicit rejection when no data-plane provider exists,
  ownership-mask validation, rollback failure propagation, and release only
  after a detached zero-ownership session. This is not a Hyper-V attachment
  provider and does not add undocumented interception primitives.
- `new-research-case.ps1` creates immutable, version-pinned EAC, EAC-EOS,
  BattlEye, or KEVLAR intake records without copying or executing the supplied
  binary. Intake state cannot be confused with a runtime product verdict.
- Host validation passed 259 source contracts, eight lifecycle model tests,
  attachment preflight tests,
  TPM policy tests, research-case tests, production-boundary positive and
  negative tests, 10 startup-harness fixture tests, the CMake platform test, diagnostic
  and production WDK builds with warnings as errors, mapper artifact tests,
  and the nine-artifact manifest.

Still not exercised: VMX launch/stop on hardware, an EDK2 boot build/run,
Hyper-V provider commit, measured-boot preservation across a transition, and
any EAC/BattlEye client or backend verdict path.

## 2026-08-27 WebSec limitations follow-up

- CR4.VMXE read-shadow semantics are preserved across guest writes while the
  actual VMCS CR4 retains the VMXE bit required by VMX.
- APERF/MPERF root residency is accounted on every VM exit. Programmable PMU
  isolation now fails launch when host/guest PERF_GLOBAL_CTRL loading is
  unavailable.
- HPET/xAPIC hooks, x2APIC current-count interception, live APIC-mode refresh,
  architectural CPUID.15H frequency gating, and one-shot expiry preservation
  are source-contract covered. Timer hook setup, execute access, and mixed
  RMW access fail closed.
- Private host CR3 remains disabled. The dormant clone now fails on capacity,
  mapping, and subtree-copy errors; safe enablement requires two complete
  pre-conceal arenas and a two-pass all-core VMCS switch/observation protocol.
- A production-critical EPT ordering defect was fixed: self-concealment no
  longer commits from code that must return into the mapped image. Bootstrap
  completes first, then `ophion.seal.bin` commits and acknowledges each EPTP
  from an external authenticated all-core thunk.
- `tests/contracts.ps1` passed 279 assertions. Mapper QA exercised `--help`,
  MAC self-test, malformed placements/entry points, a valid production image,
  and the 73-byte bootstrap, seal, and stop thunks.
- Diagnostic and production WDK Release builds passed with warnings as errors.
  SHA-256:
  - `Ophion.sys`:
    `9776BB4F085B73877D52FA9D63B27AA0200685A9983B1CF3A012FE4109EE6DF1`
  - `Ophion-production.sys`:
    `E791EDBA9584E27B4E2714FDBF8612518D94536C517B8E2185CA333AA72E6F91`
  - `OphionMap.exe`:
    `E8B87C9054B7C3DE4DC1A8B374E110F0F939B1439A025917A00B7C8FB1753064`
- The full PowerShell/Python/CMake matrix passed: attachment preflight, driver
  lifecycle, production boundary, mapper artifact, research case, TPM audit,
  eight lifecycle-model tests, ten EAC-startup fixture tests, and CTest 1/1.
- Not exercised: bare-metal VMX launch/return through the external seal path,
  timer MMIO on hardware, live EAC/BattlEye behavior, or the full EDK2 build.
