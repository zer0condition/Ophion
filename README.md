# Ophion
<div align="center"> <img src="logo.png" alt="Demo" width="800"/> </div>

Intel VT-x Type-2 hypervisor research code for virtualizing an already running Windows system. The feature list below describes implemented code paths; detector compatibility and production stability are not implied. Current evidence is tracked explicitly in the evidence matrix.

> **Build boundary:** Visual Studio `Debug` and `Release` configurations are
> diagnostic artifacts. The only production driver path is
> `.\build.ps1 -Configuration Release -Production -WarningsAsErrors`, which
> uses an explicit source profile and runs the post-link production-boundary
> verifier.


***

## Blog

> **[Ophion — Building a Stealth Intel VT-x Hypervisor for Windows](https://websec.net/blog/ophion-building-a-stealth-intel-vt-x-hypervisor-for-windows-69b62daa7462693131828c97)**
>
> A detailed technical writeup covering the internals of Ophion — VMX bring-up, EPT construction, stealth mechanisms, and the lessons learned along the way. Thanks to [WebSec](https://websec.net) for the motivation and for hosting it.

***

## Features

- **Per-core VMX** — Virtualizes all logical processors via DPC broadcast. Clean VMXOFF on unload with guest CR3 restoration.
- **Host-page concealment** — Before launch, host-owned GPAs (VMXON, VMCS, EPT tables, bitmaps, stacks, GDT, root state, and the dummy identity page) are frozen into an immutable manifest. Each vCPU atomically retargets its own EPT leaves to the read-only/execute-clear dummy page in VMX root and executes INVEPT before acknowledging. The mapped driver image remains guest-visible.
- **EPT with 2MB large pages** — Identity-mapped, MTRR-aware memory typing (fixed + variable ranges). Per-processor page tables with dynamic 2MB-to-4KB splitting for hooks.
- **VPID** — Capability-aware INVVPID (prefers type 3 retaining-globals, falls back gracefully).
- **System host CR3** — Uses a build-independent system-process CR3 by default. The stale private page-table snapshot path is retained but disabled.
- **Private host IDT** — Isolated IDT for VMX-root mode prevents NMI hijacking (guest corrupts OS IDT, triggers NMI while in host mode). NMIs are flagged and injected to guest on next VM-exit.
- **Private host GDT** — Per-core isolated GDT for VMX-root mode. Each core has its own TSS, so the private GDT is per-VCPU. On VMXOFF, clears TSS busy bit and reloads original GDTR/TR.
- **CPUID coherence** — Caches bare-metal CPUID at init, hides ECX[31] and invalid hypervisor leaves only on bare metal, and preserves an existing parent-hypervisor persona when running nested.
- **CR4.VMXE coherence** — VMXE is hidden initially, but guest writes update the read shadow exactly as bare metal does. A guest VMXON triggers a clean per-vCPU handoff so VMware can acquire VMX without a #UD/crash.
- **TSC compensation** — One-shot CPUID/RDTSC compensation preserves native CPUID cost without persistent per-core TSC offsets; unarmed RDTSC/RDTSCP returns the VM-exit entry TSC so forced RDTSC-exiting does not leak root residency.
- **MSR emulation** — Intercepts TSC, APERF/MPERF, PERF_GLOBAL_CTRL, x2APIC current count, feature-control, and VMX capability surfaces. Only CPUID-advertised Hyper-V synthetic MSRs are forwarded to a parent; unsupported probes get guest #GP.
- **External interrupt re-injection** — ACK-on-exit with deferred delivery via interrupt-window exiting when guest is not interruptible. TPR priority masking via shadowed CR8.
- **IDT vectoring** — Re-injects interrupted IDT events with priority. NMI deferral via NMI-window exiting on collision. Exception combining per SDM Table 6-5 (#DF generation, triple fault on #DF+exception).
- **Debug register passthrough** — Full DR0-DR7, CR8 save/restore on vmexit/vmentry. DR4/DR5 aliasing. Hardware BP matching merged into pending debug exceptions on RIP advance.
- **XSETBV validation** — SDM-compliant XCR0 validation using hardware capability mask from CPUID.0Dh.
- **MOV CR handling** — CR3 writes strip PCID bit 63 and flush through capability-gated INVVPID; CR4 writes preserve a coherent guest shadow while enforcing VMX fixed bits.
- **VMCALL gate** — Signature-verified (R10/R11/R12), CPL-checked (ring 0 only). User-mode VMCALL gets #UD.

***

## VMCS Configuration

| Field | Value |
|-------|-------|
| **Pin-based** | External-interrupt exiting, NMI exiting, virtual NMIs |
| **Primary proc** | TSC offsetting, RDPMC exiting, MSR bitmaps, I/O bitmaps, activate secondary. CR3/HLT/MOV-DR/RDTSC/INVLPG exiting may be forced by must-be-1 bits. MTF is enabled only for an active timer-MMIO retry. |
| **Secondary proc** | Required EPT; capability-gated VPID, RDTSCP, INVPCID, XSAVES/XRSTORS, and WAITPKG |
| **Exit** | 64-bit host, save debug controls, ACK interrupt on exit; capability-gated save/load of `IA32_PERF_GLOBAL_CTRL` |
| **Entry** | IA-32e mode guest, load debug controls; capability-gated guest `IA32_PERF_GLOBAL_CTRL` load |
| **PFEC mask/match** | Both 0 — all #PFs go to guest |
| **CR0 mask** | 0 (full pass-through) |
| **CR4 mask** | Bit 13 (VMXE) when stealth enabled; initial shadow is 0 and later guest writes persist |
| **MSR bitmap** | TSC, APERF/MPERF, PERF_GLOBAL_CTRL, x2APIC current count, IA32_FEATURE_CONTROL, and VMX capability MSRs |
| **I/O bitmaps** | All zeros |
| **EPT pointer** | WB cache, 4-level walk; per-vCPU 4KB HPET/xAPIC timer traps when available |
| **VPID** | Tag 1 |
| **HOST_CR3** | System CR3 by default; optional private snapshot remains disabled until its physical-page walker/coherency model is redesigned |
| **HOST_IDTR** | Private IDT with controlled handlers (or system IDT if disabled) |
| **HOST_GDTR** | Per-core private GDT copy (or system GDT if disabled) |

***

## Architecture

```
include/
    hv.h                Master header, function prototypes
    hv_attachment.h     Clean-room Hyper-V provider lifecycle ABI
    hv_public.h         Stable wire records and attachment negotiation ABI
    hv_types.h          Per-VCPU state, EPT structures, VMCALL numbers
    ia32.h              Intel architecture defines (MSRs, VMCS fields, EPT, control bits)
    stealth.h           Anti-detection feature toggles and types
    asm_prototypes.h    C prototypes for MASM routines

src/
    driver.c            DriverEntry, IOCTL dispatch, device setup
    vmx.c               VMX lifecycle (VMXON/VMCS alloc, VMCS programming, launch)
    vmexit.c            VM-exit handler (CPUID, CR, MSR, EPT, interrupts, etc.)
    ept.c               EPT init, MTRR map, identity mapping, tracked splits, HPET/xAPIC shadow hooks
    events.c            Exception/interrupt injection (#GP, #UD, #DF, #BP, #PF, external)
    broadcast.c         Multi-processor DPC broadcast for virtualize/terminate
    hostcr3.c           Private host page table deep-copy
    hostidt.c           Private host IDT for VMX-root mode
    hostgdt.c           Per-core private host GDT for VMX-root mode
    stealth.c           CPUID cache init, bare-metal cost calibration, XCR0 validation
    globals.c           Global variable definitions
    util.c              VA/PA translation, GDT/segment helpers

asm/
    AsmVmexitHandler.asm    VM-exit entry point (save/restore GPRs + XMM + MXCSR)
    AsmVmxContext.asm       Guest state save/restore for VMLAUNCH
    AsmVmxOperation.asm     CR4.VMXE enable, VMCALL with signature
    AsmVmxIntrinsics.asm    INVEPT/INVVPID wrappers
    AsmSegmentRegs.asm      Segment register getters/setters, GDT/IDT
    AsmCommon.asm           RFLAGS, GDTR/IDTR/TR reload, CR2 write
    AsmHostIdt.asm          Private host IDT handlers (NMI, #DF, #GP)
```

***

## Building

The portable build requires Visual Studio 2022 C++ tools and an installed Windows Driver Kit containing x64 kernel headers and libraries. It discovers `vswhere`, the newest x64 MSVC toolset, and the newest suitable WDK; it does not require the WDK Visual Studio extension.

```powershell
# Unsigned Release build, clean first, with compiler and MASM warnings fatal
pwsh -NoProfile -File .\build.ps1 -Configuration Release -Clean -WarningsAsErrors

# Debug plus MSVC code analysis
pwsh -NoProfile -File .\build.ps1 -Configuration Debug -CodeAnalysis

# Select an installed WDK explicitly
pwsh -NoProfile -File .\build.ps1 -WdkVersion $env:OPHION_WDK_VERSION
```

### Production stealth profile

`-Production` compiles `OPHION_PRODUCTION=1`: the status device, symbolic link, IOCTL dispatch, and every diagnostic log string are compiled out, the pool tag is replaced with a non-identifying one, and the embedded PDB reference is neutralized to `driver.pdb`. Debug-register, CR8, and LAPIC sampling is reason-conditional; APERF/MPERF bracket every exit because those counters advance during all root residency. The binary contains no device path, log text, build-machine path, or project-name string:

```powershell
pwsh -NoProfile -File .\build.ps1 -Configuration Release -Clean -WarningsAsErrors -Production
# -> build\bin\Release\Ophion-production.sys
```

The output is `build\bin\<Configuration>\Ophion.sys`. The script verifies that it is an x64 Native PE. Default output is unsigned. Signing is opt-in and the SHA1 certificate thumbprint is injected at invocation time:

```powershell
pwsh -NoProfile -File .\build.ps1 -Configuration Release `
  -CertificateThumbprint $env:OPHION_CERT_SHA1 `
  -TimestampUrl $env:OPHION_TIMESTAMP_URL
```

The signing path checks the resulting signer thumbprint and runs kernel-policy signature verification. For a Visual Studio WDK-integrated build, the project remains usable directly:

```powershell
msbuild .\Ophion.sln /m /p:Configuration=Release /p:Platform=x64

# Optional project-level WDK selection and signing
msbuild .\Ophion.sln /m /p:Configuration=Release /p:Platform=x64 `
  /p:OphionWdkVersion=$env:OPHION_WDK_VERSION `
  /p:OphionCertificateThumbprint=$env:OPHION_CERT_SHA1
```

Run the dependency-free contract assertions separately:

```powershell
pwsh -NoProfile -File .\tests\contracts.ps1
```

GitHub-hosted Windows CI runs the contract assertions and builds the user-mode probe. It does not compile the driver because the hosted image does not guarantee WDK kernel headers and libraries.

***

## Hyper-V attachment foundation

[`lab/HYPERV_ATTACHMENT_ABI.md`](lab/HYPERV_ATTACHMENT_ABI.md) defines the
versioned clean-room provider boundary. It uses public Microsoft TLFS
discovery/privilege contracts only, never private Hyper-V symbols or patches,
forbids a bare-metal `VMXON` fallback after Hyper-V discovery, requires
idempotent rollback, and treats Secure Boot/TPM/measured-boot state as
immutable policy inputs. This is an ABI foundation, not a completed provider
or an anti-cheat compatibility claim.

Read-only platform gates:

```powershell
pwsh -NoProfile -File .\tools\hyperv-attachment-preflight.ps1 -Mode probe
pwsh -NoProfile -File .\tools\tpm-audit.ps1 `
  -OutputPath .\build\tpm-measured-boot-audit.json
```

***

## Boot-time mode

[`boot/OphionBootPkg`](boot/README.md) is the EDK2 boot-time build: a resident DXE driver starts the VMX layer before the Windows loader and establishes a coherent `Microsoft Hv` persona from the first Windows instruction. This is the only architecture that removes the post-boot hypervisor-transition discontinuity; it is compile-verified as a `RELEASE` EFI driver and must first be exercised with OVMF, not a production ESP or firmware flash.

```powershell
pwsh -NoProfile -File .\boot\build.ps1 `
  -Edk2Root $env:OPHION_EDK2 `
  -NasmPrefix $env:NASM_PREFIX `
  -IaslPrefix $env:IASL_PREFIX `
  -Target RELEASE
```

## Game data-plane foundation

`platform/` and `client/` provide a dependency-free C++20 foundation for
read-only externals. The protocol is versioned and bounded; it supports only
status, discovery, module enumeration, VA translation, coherent snapshots,
and scatter reads. Its page walker handles 4-/5-level paging and large pages,
Unreal, Unity IL2CPP, and Source2 adapters refuse to run until a build
fingerprint validates the supplied offset profile. A renderer-neutral external
overlay emits draw commands through a caller-owned projector; the PE planner
only validates image layout into an immutable plan and never maps or executes
an image.

`GuestMemoryReader` consumes only the bounded page-table walker and caller
supplied CR3. The in-process transport now covers discovery, module catalog,
translation, scatter reads, status, and snapshot epochs, each with capability
and session-nonce validation. Adapter profiles must match a module fingerprint
and provide engine-specific array/count/root/transform offsets; malformed,
stale, or oversized snapshots fail closed.

The root `CMakePresets.json` generates one Visual Studio solution for the
platform library, deterministic tests, and mock client. Open the repository
folder in Visual Studio's CMake view, or run:

```powershell
cmake --preset vs2022-x64
cmake --build --preset vs2022-x64-release
ctest --preset vs2022-x64-release
.\build\cmake\vs2022-x64\client\Release\ophion_mock_client.exe
```

The current bridge is deliberately mock-only. Production Ophion creates no
device or IOCTL endpoint; a real VMM command page is an attachment-mode gate,
not an implicit kernel client.

## EAC and BattlEye lab harness

`lab/eac_harness.py` consumes recorded JSONL fixtures only. It models the
public EAC/EOS startup observations—SystemHypervisorDetailInformation/CPUID,
KUSER/QPC, synthetic MSR direction, stack/image/module records, NMI metadata,
and TPM/measured-boot state—without shipping or attaching to an anti-cheat
binary. `lab/be_eac_test_matrix.json` records the required bare-metal,
Hyper-V/VBS, runtime, DXE, and attachment strata.

```powershell
python .\tests\eac_startup_harness_test.py
pwsh -NoProfile -File .\lab\capture-local-baseline.ps1 -OutputPath .\build\eac-local-baseline.jsonl
pwsh -NoProfile -File .\tools\hyperv-attachment-preflight.ps1
```
## Loading

Do not `sc.exe create/start` for an anti-cheat boot. That publishes a service,
a `\Driver` object, a `PsLoadedModuleList` row, PiDDB, and ImageLoad ETW.
`tracewipe_apply` unlinks those after `DriverEntry`; it cannot unsay ETW.

AC bring-up, in order:

1. **Boot** — `boot/OphionBoot.efi` owns VMX before `winload`. No Windows `.sys`.
2. **Map** — build `Ophion-production.sys`, then emit a relocated blob and copy it with an external kernel write. Never `NtLoadDriver`.

```powershell
pwsh -NoProfile -File .\build.ps1 -Configuration Release -Clean -WarningsAsErrors -Production
pwsh -NoProfile -File .\tools\build-map.ps1 -Configuration Release -WarningsAsErrors
$mappedBase = Read-Host 'Mapped image kernel VA'
$ntBase = Read-Host 'Live ntoskrnl base'
.\build\bin\Release\OphionMap.exe --image .\build\bin\Release\Ophion-production.sys --out .\build\map --base $mappedBase --ntos $env:SystemRoot\System32\ntoskrnl.exe --ntos-base $ntBase
```

`ophion.map.json` v2 carries the relocated entry VA, image size, import/relocation
state, and seal protocol metadata. `ophion.exec.bin` is the 25-byte Microsoft x64
ABI adapter that calls the relocated production entry with null driver arguments.
The mapper still does not allocate kernel memory or trigger execution; the external
write/execute primitive owns placement, invocation, and recovery.

The runtime invokes `ophion.exec.bin` first, with the mapped `.hvshare` page
still zeroed. `DriverEntry` launches VMX, snapshots root metadata, freezes the
concealment manifest, and returns without changing the guest EPT view. The
runtime then generates a nonzero 128-bit capability with its OS CSPRNG,
initializes `sharedPageRva` as state `WRITING`, patches
`ophion.bootstrap.bin`, and invokes bootstrap VMCALL `7` on one virtualized
processor. VMX-root copies the capability and securely erases both the shared
payload and its local copy.

The runtime retains the capability, patches `ophion.seal.bin`, and schedules
seal VMCALL `5` synchronously on every logical processor. Each authenticated
seal call commits the immutable concealment plan to that vCPU's EPTP before
publishing its sealed bit. The final vCPU activates the transport only after
all EPTPs acknowledge concealment. These calls return into the external seal
thunk, not the now-hidden image: committing from an in-image DPC would make
its own post-VMCALL return path NX. After sealing, EPT maps host-only
allocations, `.hvroot`, and the mapped production image to the dummy page;
only `.hvshare` remains guest-visible. The runtime then uses VMCALL `0x100`
with strictly increasing sequences.
Every READY command carries the manifest-declared `siphash-2-4x2-128` tag over
command, epoch, sequence, lengths, and payload. VMX-root authenticates one local
snapshot and signs every COMPLETE response over status, length, and payload;
callers must reject a response whose 128-bit tag does not verify.
For teardown it patches the capability and epoch slots in `ophion.stop.bin`,
runs that thunk synchronously on every logical processor, verifies every return
status, then invokes `ophion.cleanup.bin`. `OphionCleanup` refuses to free any
allocation until `vmx_all_stopped()` proves that no vCPU still owns VMX state.

Lab-only (probe / status device): a test-signed non-production image may still be registered locally. `tracewipe_apply` still unlinks the module list after launch.
VulnDrivers ranking for a no-`sc` kernel write (this box):

| Image | Use for Ophion map? |
|---|---|
| `12-DirectIo64_legacy` | **No on this host** — unrestricted DRAM R/W, but enforced Code Integrity rejects this hash as revoked (`0xC0000603`) and records the randomized path. |
| `01-HWiNFO_x64` | No — WHQL/HVCI-clean but SENS-gated, cannot hit kernel PA. |
| `11-AsIO3` / `09-AsIO3` | No — live test returns `ACCESS_DENIED` off the HAL/PnP windows. |
| `13-DirectIo64-WHQL` | Read-only DRAM. |
| `14-Eneio64` | Full phys R/W, loldrivers-famous. Worse name hit than a random-stem DirectIo. |
| `06-cpuz` / `10-IOMap64` / `07-kerneld-x64` | Name-listed or hardcoded `\Device\AIDA64Driver`. |

```powershell
pwsh -NoProfile -File .\tools\build-load.ps1 -Configuration Release -WarningsAsErrors
.\build\bin\Release\OphionLoad.exe --vuln C:\Users\Admin\Desktop\VulnDrivers\12-DirectIo64_legacy\DirectIo64_legacy.sys --smoke
```

Guarded wrapper (administrator check, backend validation, and fail-closed
Hyper-V/VBS preflight):

```powershell
.\tools\run-safe.ps1 -Backend lnvmsrio -Existing `
  -DevicePath \\.\WinMsrDev -Smoke -Walk
```

For a deterministic signature/hash/version/CI-policy report without loading
anything:

```powershell
.\tools\driver-preflight.ps1 -Path .\LnvMSRIO.sys -Backend lnvmsrio
```

The schema (`ophion.driver-preflight.v1`) follows an Ophion-owned,
fail-closed subset of KDU provider metadata and LOLDrivers sample metadata.
It does not import mapper code, driver binaries, or service commands.




***
## Stealth Toggles

Defined in `include/stealth.h`:

| Toggle | Default | Description |
|--------|---------|-------------|
| `STEALTH_ENABLED` | 1 | Master stealth switch |
| `STEALTH_HIDE_CR4_VMXE` | 1 | Hide CR4.VMXE from guest via CR4 shadow |
| `STEALTH_COMPENSATE_TIMING` | 1 | Compensate selected CPUID/timer VM-exit residency |
| `STEALTH_CPUID_CACHING` | 1 | Cache native CPUID responses for invalid/hypervisor leaves |
| `STEALTH_VIRTUALIZE_PMU` | 1 | Exclude VMX-root PMCs and compensate APERF/MPERF |
| `STEALTH_VIRTUALIZE_TIMERS` | 1 | Virtualize HPET and LAPIC current-count reads |
| `STEALTH_CONCEAL_HOST_PAGES` | 1 | Hide VMXON/VMCS/bitmap/root-stack allocations behind a read-only zero page; production also hides fixed EPT controls and the mapped image after initialization, while `.hvshare` remains visible for authenticated VMCALLs |
| `STEALTH_WIPE_LOADER_TRACES` | 0 | Experimental only: loader-list/cache edits can violate PatchGuard or live loader invariants |
| `STEALTH_EAC_STACK_SCRUB` | 0 | Unsafe heuristic stack rewriting is disabled |
| `USE_PRIVATE_HOST_CR3` | 0 | Disabled until a bounded two-generation, all-core switch and observation protocol exists |
| `USE_PRIVATE_HOST_IDT` | 1 | Isolated host IDT (prevents NMI hijacking in VMX-root) |
| `USE_PRIVATE_HOST_GDT` | 1 | Per-core isolated host GDT |
| `OPHION_ALLOW_UNLOAD` | 0 | Unload disabled until all vCPUs can prove VMXOFF completion |
| `OPHION_ALLOW_NESTED` | 0 | Parent Hyper-V/VBS rejected because genuine hypercall pass-through is unavailable |

### WebSec known-limitations status

The March 2026
[WebSec article](https://websec.net/blog/ophion-building-a-stealth-intel-vt-x-hypervisor-for-windows-69b62daa7462693131828c97)
describes an older tree. The current branch has the following status:

| Published limitation | Current status |
|---|---|
| CR4.VMXE write then read | Resolved. Initial reads hide host VMXE, but a guest write updates the CR4 read shadow with the guest-requested bit while the actual VMCS CR4 retains VMXE. |
| RDPMC and APERF/MPERF | Resolved with a fail-closed ceiling. Root residency is excluded from APERF/MPERF on every VM exit, programmable counters load a zero host control, and launch fails if the required host/guest PERF_GLOBAL_CTRL controls are unavailable. |
| HPET and LAPIC wall clocks | Partially resolved. HPET and xAPIC use EPT/MTF shadows, x2APIC current-count reads are intercepted, APIC mode transitions are re-evaluated, and hook setup fails closed. Full timer-interrupt deadline virtualization is not implemented. |
| Private host CR3 staleness | Not active: `USE_PRIVATE_HOST_CR3` remains off. The dormant clone now rejects incomplete/shared branches. Enabling it requires a preallocated two-generation snapshot plus authenticated all-core VMCS switch; allocating replacement tables after conceal freeze is unsafe. |
| No EPT hooks | Superseded. Timer MMIO, host-page concealment, and diagnostic execute-only/dummy protection all install 4 KB EPT leaf policies with MTF/INVEPT restoration. A general production inline-hook API is intentionally not exposed. |

These are implementation properties, not EAC/BattlEye verdicts. The runtime
evidence gate remains a version-pinned baseline, positive control, one changed
variable, rollback, and backend outcome.


***

## Read-only TPM audit

`tools\tpm-audit.ps1` reproduces the observed EAC startup probes without
creating, evicting, or changing TPM objects: two device-info calls,
`ReadPublic(0x81000001)`, two deterministic
`ReadPublic(0x810EAC00)` calls, and a handle-capability query.

```powershell
pwsh -NoProfile -File .\tools\tpm-audit.ps1
```

The output is local JSON (`ophion.tpm-audit.v1`). It is evidence only:
Ophion does not forge TPM public objects, AIK signatures, PCR quotes, or
remote-attestation responses.

## Runtime probe

The x64 user-mode probe is read-only: it opens `\\.\Ophion`, requests `HV_STATUS_V1` with a legacy `UINT32` fallback, pins its thread to every active group-aware logical processor, and emits CPUID and timing samples as JSON. It does not load a driver, write an MSR, or change system configuration.

```powershell
pwsh -NoProfile -File .\tools\build-probe.ps1 -Configuration Release -WarningsAsErrors
.\build\bin\Release\OphionProbe.exe --samples 1000 |
  Set-Content .\build\probe.json -Encoding utf8
```

The stable top-level schema identifier is `ophion.probe.v1`. Each processor record contains the processor group/number, CPUID leaf 1, Hyper-V base/interface leaves, two invalid-leaf responses, and paired `RDTSC-CPUID-RDTSC`/QPC deltas.


Local source in `E:\Tools` can be built and sampled without modifying the
upstream checkout:

```powershell
.\tools\run-local-detectors.ps1 -Seconds 6 -ProbeSamples 1000
```

Raw output and a run manifest are stored under
`build\detector-results\<timestamp>`.

For a failed bare-metal launch or bugcheck, collect reproducible event,
minidump, and build hashes with:

```powershell
.\tools\collect-crash-artifacts.ps1 -Hours 24
```
## Pinned detector sources

`tools\detectors.json` pins public detector repositories and records their expected build command and result artifact. The management script never executes detector binaries. Without `-Fetch` it performs no network activity:

```powershell
# Inspect already-present checkouts only
pwsh -NoProfile -File .\tools\detectors.ps1

# Explicitly clone/fetch and detach each checkout at its pinned revision
pwsh -NoProfile -File .\tools\detectors.ps1 -Fetch
```

The manifest covers VMAware, hvdetecc, checkhv_um, void-stack Hypervisor-Detection, and momo5502 EPT hook detection.

## Evidence matrix

Evidence status as of **2026-08-25**:

| Scope or claim | Compile-verified | Runtime-verified | Evidence / limit |
|---|---:|---:|---|
| Portable unsigned driver build | Yes | No | Release and Debug x64 built with WDK 10.0.26100.0 and `/WX`; Native x64 PE headers verified by `build.ps1`. |
| Optional test-signed driver build | Yes | No | Release signing and Authenticode verification passed with an injected local certificate thumbprint; kernel trust/loading was not exercised. |
| Contract assertion script | Yes | N/A | `tests\contracts.ps1` validates safe-default, EPT, MTF, loader, and teardown invariants; assertion count is emitted by the script. |
| Platform data plane and mock client | Yes | Mock only | Unified VS2022 CMake preset builds the C++20 library, adapter/guest-reader/command-path tests, and client. No production VMM bridge exists yet. |
| EAC/EOS fixture harness | Yes | Mock only | Python stdlib harness uses recorded fixtures; no anti-cheat binary was executed. |
| Production stealth profile | Yes | No | Production build removes the diagnostic device/log surface; runtime trust/loading still requires validation. |
| `OphionBoot.efi` boot-time DXE driver | Yes | OVMF shell only | OVMF/TCG cannot validate VMX launch; nested/bare-metal validation remains pending. |
| VMX launch, unload, and all-core status | N/A | No | Requires a compatible Intel host, a loadable signed/test-signed driver, and captured status/crash artifacts. |
| Detector compatibility | N/A | No | Public detectors are pinned, but no current live detector run is claimed. |
| Host-page concealment | Yes | No | Compile/contracts only. Safe default hides host-only allocations and, in production, the initialized mapped image except `.hvshare`; it uses a read-only dummy page and performs INVEPT through a root-mode VMCALL. |
| Internal page protection | Yes | No | Current-process pages are pinned and execute-only for the owner CR3; foreign-CR3 registration fails closed. No live game/AC run is claimed. |
| EAC, EOS, Ricochet, BattlEye | N/A | No | No build is “100% safe.” Vendor-specific and server-side verdict paths remain unvalidated. |

***

## Disclaimer

This project has not been thoroughly tested for long-term usage or stability. It is intended primarily as a learning resource and a foundation for further development. Use at your own risk.

***

## Credits

- [HyperDbg](https://github.com/HyperDbg/HyperDbg) — Referenced for VMX architecture and VM-exit handling patterns
- [humzak711](https://github.com/humzak711) — Stealth feedback: MSR feature hiding (IA32_FEATURE_CONTROL, VMX MSRs), CPUID SMX masking
- [VMAware](https://github.com/kernelwernel/VMAware) — Hypervisor detection testing
- [hvdetecc](https://github.com/can1357/hvdetecc) — Hypervisor detection testing
- [Claude](https://claude.ai) — Debugging assistance and IA-32 architecture research

## License

MIT
