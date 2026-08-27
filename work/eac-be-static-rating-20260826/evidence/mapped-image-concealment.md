# Production mapped-image concealment change

## Change

`src/conceal.c` now locates the mapped production image from `DriverEntry`'s PE headers during pre-launch manifest assembly and registers the image's physical pages for EPT dummy-page remapping. The page holding `g_root_command_page` (`.hvshare`) is deliberately excluded so external bootstrap, seal, command, and stop VMCALL thunks retain their guest-visible doorbell.

The mapped image is executed only through host mappings after VMX launch. It becomes guest-visible again only after all vCPUs have left VMX operation and the cleanup thunk invokes `OphionCleanup`, at which point EPT no longer controls guest translation.

## Safety properties

- Bound PE-header backward search (32 MiB) and fail-closed manifest preparation.
- No global kernel-data or kernel-text patching enabled.
- `.hvshare` remains readable/writable; `.hvroot` and image pages remain concealed after the all-core commit.
- Diagnostic builds remain unchanged because the image conceal path is compiled only under `OPHION_PRODUCTION`.

## Verification

- `tests/contracts.ps1`: 253 assertions passed.
- `tests/attachment-preflight.ps1`: passed.
- `tests/tpm-audit.ps1`: passed.
- `tests/mapper-artifact.ps1`: passed; rebuilt image `315392` bytes, `.hvshare` RVA `0x47000`.
- `build.ps1 -Configuration Release -WarningsAsErrors -Production`: passed with WDK `10.0.26100.0`.
- `build.ps1 -Configuration Release -WarningsAsErrors`: passed with WDK `10.0.26100.0`.

This is static/build evidence only; no protected process, EAC/EOS, BattlEye, live driver load, or game was run.
