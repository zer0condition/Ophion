# EAC/EOS startup-emulation lab report

## Scope

This lab is a **fixture-only emulator** for a bounded set of startup-observation
schemas. It models observations commonly discussed around hypervisor coherence,
clock samples, synthetic MSR directions, inventory records, stack/image
provenance, NMI metadata, and TPM/measured-boot state.

It does **not** include, ship, invoke, attach to, or validate EAC, EOS,
BattlEye, a protected game, a target-game process, a driver, an NMI source, or
a TPM attestation service. Passing the fixture tests establishes only the
emulator's deterministic handling of its hand-authored fixtures.

## Versioned artifacts

- `eac_observation.schema.json` — JSONL observation envelope, version `1.0`.
- `be_eac_test_matrix.schema.json` and `be_eac_test_matrix.json` — matrix and
  fixture expectations, version `1.0`.
- `eac_harness.py` — stdlib-only fixture loader and bounded invariant emulator.
- `fixtures/` — recorded mock fixtures consumed by the tests.
- `capture-local-baseline.ps1` — local/self-process baseline writer. Its output
  is marked `local_baseline`, which the emulator deliberately rejects.

## Deferred bridges

`real-binary` and `KEVLAR` integration are explicitly deferred. They require a
separate, version-pinned laboratory plan, raw-artifact provenance, and an
independent validation contract; nothing in this lab is evidence for either
bridge.

## Local capture boundary

`capture-local-baseline.ps1 -OutputPath <path>` performs local reads only and
writes JSONL to the supplied path. It does not make network requests, attach to
EAC/BE or any game, change a driver, query synthetic MSRs, sample NMI state, or
collect a TPM quote.
