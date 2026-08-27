# OphionBoot — boot-time Hyper-V persona

`OphionBoot.efi` is an EDK2 x64 resident DXE research driver that brings up Ophion before the Windows loader continues. It captures the UEFI caller's complete register frame, virtualizes every logical processor through `EFI_MP_SERVICES_PROTOCOL`, and identity-maps firmware-declared RAM/MMIO with EPT. The incomplete Microsoft Hyper-V persona is compile-gated off by default; production claims require effect-conformance tests for every advertised TLFS facility.

With the safe default, CPUID remains native and synthetic Hyper-V MSRs and hypercalls are unsupported. The laboratory persona must not be enabled merely to obtain a `Microsoft Hv` vendor string.

## Build

Prerequisites: an EDK2 checkout with Windows BaseTools, NASM, iasl, and Visual Studio C++ x64 tools.

```powershell
pwsh -NoProfile -File .\boot\build.ps1 `
  -Edk2Root $env:OPHION_EDK2 `
  -NasmPrefix $env:NASM_PREFIX `
  -IaslPrefix $env:IASL_PREFIX `
  -Target RELEASE
```

Expected output:

```text
<Edk2Root>\Build\OphionBoot\RELEASE_VS2022\X64\OphionBoot.efi
```

Latest fully compiled DXE artifact (after full event/NMI/CR/DR handling) SHA-256:

```text
e051c6aafe092b6c348c0d276d8fcfa0bee14fb1778df29b4839c568d98ec823
```

## Hyper-V attachment preflight

The clean-room attachment path is designed to use a genuine Microsoft Hyper-V
host rather than fabricate its full runtime. Run the read-only preflight
before any OVMF attachment experiment:

```powershell
pwsh -NoProfile -File .\tools\build-probe.ps1 -Configuration Release -WarningsAsErrors
pwsh -NoProfile -File .\tools\hyperv-attachment-preflight.ps1
```

`readyForAttachmentLab` is true only when both Windows and CPUID report a
real `Microsoft Hv` stratum. The attachment design and license boundary are
in [`HyperVAttachment.md`](HyperVAttachment.md).

## OVMF lab path

The lab runner is intentionally manual; it is never called by a build or test:

```powershell
pwsh -NoProfile -File .\boot\run-ovmf-lab.ps1 `
  -Edk2Root $env:OPHION_EDK2 `
  -NasmPrefix $env:NASM_PREFIX `
  -IaslPrefix $env:IASL_PREFIX `
  -QemuPath C:\path\to\qemu-system-x86_64.exe `
  -DriveImage C:\lab\disposable.img
```

It creates a temporary OVMF DSC with the resident DXE component, builds that
OVMF image, and writes `boot\ovmf-serial.log`. It uses TCG plus `max,+vmx`
only as a controlled smoke path; a host must expose working nested VMX for
`VMLAUNCH` to succeed.

Expected observations, in order:

1. The OVMF serial log reaches the DXE/ReadyToBoot phase without a VMX entry
   failure; `OphionBoot: <n> cores virtualized, 0 failed` is the required
   driver diagnostic when OVMF debug is routed to serial.
2. The runtime telemetry page has magic `OPBT`, capacity 128, and records the
   first exit followed by CPUID and Hyper-V MSR persona records. It is runtime
   allocated, so it remains readable from the host mapping after
   `ExitBootServices`.
3. The guest exposes CPUID.1.ECX[31] and `CPUID(0x40000000) = Microsoft Hv`;
   the synthetic MSRs 0x40000000–0x40000002 complete without a VMX-root
   exception.
4. With the compile-time concealment lab switch enabled, telemetry shows one
   publish record, one prepare-INVEPT acknowledgement per launched VCPU, then
   one post-change INVEPT acknowledgement per launched VCPU before release.
   The EPT redirect is not changed before the first barrier and no VCPU is
   resumed before the second barrier.

Failure signatures:

| Signature | Meaning |
| --- | --- |
| `OpbTelemetryVmEntryFailure` / terminal reason 2 | VM entry or resume failed; inspect the current VMCS instruction error and nested-VMX exposure. |
| terminal reason 1 | VMREAD/VMWRITE failed; the VMCS was not current or control state was invalid. |
| terminal reason 3 | EPT violation/misconfiguration was not an allowed lab mapping transition. |
| terminal reason 4 or `OpbConcealAbort` | A local INVEPT or concealment rendezvous failed; do not continue the guest. |
| OVMF resets or no serial progression after ReadyToBoot | Nested VMX is unavailable or the OVMF/QEMU CPU configuration cannot execute VMX. |

`OphionBootConcealRuntime` and `OPB_ENABLE_RUNTIME_CONCEALMENT` default on.
Concealment is a dummy-page GPA redirect with execute stripped. It is not an
EPT code hook. A failed two-barrier INVEPT epoch terminalizes the guest.

## Current boundary

This is a boot-time VMX/HV-persona foundation, not a firmware flasher or a finished Hyper-V implementation. It provides the boot-critical Hyper-V MSR/hypercall floor: guest OS ID, hypercall-page registration, VP index, and no-op success for selected flush/post-message/spin-wait calls. The allocation registry and dummy-page redirector run after the first 128 exits.


Do not modify `bootmgfw.efi`, SPI flash, measured-boot state, TPM state, or a production ESP until the OVMF boot matrix is green.
