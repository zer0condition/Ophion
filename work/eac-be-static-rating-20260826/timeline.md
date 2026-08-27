# Timeline (append-only)

## 2026-08-26T21:07:27.4821705+02:00 | lead | init
- action: case-init
- command_or_ref: skills/scripts/case-init.ps1
- result_summary: case directory created; scope ready_for_act=true
- artifacts: [scope.md, workitems.md]
- evidence_ids: []
- next: open PRIMARY SKILL.md and ACT within scope

## 2026-08-26 | lead | static EAC/BE rating
- action: static source and evidence review
- command_or_ref: tests/contracts.ps1; tests/attachment-preflight.ps1; tests/tpm-audit.ps1; tests/mapper-artifact.ps1; tests/eac_startup_harness_test.py; git diff --check
- result_summary: static contracts and fixture tests passed; live VMX/EAC/BattlEye validation remains absent
- artifacts: [evidence/static-validation.txt, report/rating.md]
- evidence_ids: [E-01, E-02, E-03, E-04]
- next: run a version-pinned isolated live baseline/positive-control/modified/rollback matrix

## 2026-08-26 | lead | production mapped-image concealment
- action: implementation and dual-profile build verification
- command_or_ref: build.ps1 -Configuration Release -WarningsAsErrors -Production; build.ps1 -Configuration Release -WarningsAsErrors
- result_summary: production concealment now registers the manually mapped image while excluding .hvshare; production and diagnostic WDK builds passed
- artifacts: [evidence/mapped-image-concealment.md]
- evidence_ids: [E-04]
- next: validate all-core launch, conceal commit, stop, and cleanup on an isolated version-pinned host
