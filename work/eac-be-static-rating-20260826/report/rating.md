# EAC / BattlEye static rating

## Verdict

| Product | Evidence-based resilience rating | Basis |
|---|---:|---|
| Easy Anti-Cheat / EOS | **2/10** | Generic VMX fingerprint-reduction paths exist, but vendor validation is fixture-only and the only recorded bootstrap is rejected before VMX launch. |
| BattlEye | **1/10** | The same generic paths apply, but there is no BattlEye-specific implementation or live product test. |

These are deployability/detection-resilience scores, not source quality scores. The design is more mature than the score: the source has coherent CPUID/CR4/MSR/timer handling, EPT host-page concealment, a bounded root transport, and static contract coverage. Those properties do not establish an anti-cheat bypass.

## Evidence -> finding -> path

### E-01: static verification passed
- Commands: `tests/contracts.ps1`, `tests/attachment-preflight.ps1`, `tests/tpm-audit.ps1`, `tests/mapper-artifact.ps1`, `tests/eac_startup_harness_test.py`, `git diff --check`.
- Observed: 252 contract assertions, four preflight/audit test classifications, mapper artifacts, and 10 fixture-harness tests passed. See `../evidence/static-validation.txt`.
- Finding: build and source-contract integrity are supported only at static/fixture scope.

### E-02: no live anti-cheat or live VMX evidence
- Observed: `lab/HARDENING_EVIDENCE.md` records that the available DirectIo bootstrap was Code-Integrity-blocked before driver initialization, and that no EAC or BattlEye binary was launched or attached.
- Finding: there is no evidence for VMX launch, concealment commit, teardown, EAC/EOS verdict path, or BattlEye verdict path.
- Path: the effective rating cannot exceed low confidence until the actual artifact runs in a version-pinned isolated lab with healthy telemetry.

### E-03: EAC-specific code is largely disabled by default
- Observed: `include/stealth.h` defaults loader trace wiping and stack scrubbing to `0`; `src/eac_stealth.c` defaults KD/KUSER/DMAR/HVL/SMBIOS/VSL modifications to `0`; `src/byovd_conceal.c` defaults late BYOVD concealment to `0`.
- Finding: default production behavior leaves several intended EAC-facing controls inactive. Enabling them would introduce PatchGuard, kernel-layout, and platform-state consistency risk.
- Path: only the generic CPUID/CR4/timer/PMU and pre-launch EPT concealment paths contribute to the EAC score.

### E-04: residual observables remain
- Observed: the production concealment manifest now covers the initialized manually mapped image while preserving only `.hvshare` for authenticated VMCALL thunks. `lab/HARDENING_EVIDENCE.md` still records launch-to-conceal exposure, an unvalidated boot/TPM transition, unavailable nested Hyper-V/VBS support, and historic loader/CI observability.
- Finding: the guest-visible image surface is reduced after the all-core conceal commit, but kernel image provenance before/during launch, attestation, and server-side enforcement remain unproven.
- Path: these residuals still materially lower both scores; BattlEye remains lower because the tree has no product-specific validation beyond generic public detectors.

## What would move the rating

1. Prove all-core launch, conceal commit, command, VMXOFF, and cleanup on a pinned test host.
2. Run clean/positive-control/modified/rollback experiments against each exact anti-cheat and game build, with local and backend telemetry health evidenced.
3. Independently validate module/image provenance, page-table/EPT views, timing/PMU distributions, device/loader history, and measured-boot/attestation behavior.
4. Treat kicks, telemetry, delayed verdicts, and bans as distinct outcomes.

## Limit

This review performed no EAC, EOS, BattlEye, protected-game, driver-load, or network interaction.
