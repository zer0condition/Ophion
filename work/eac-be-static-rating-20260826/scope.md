# Case Scope

## meta
- case_id: eac-be-static-rating-20260826
- created: 2026-08-26T21:07:27.4821705+02:00
- operator: local
- project_root: C:\Users\Admin\Documents\Ophion
- primary_skill: reverse-engineering/SKILL.md
- primary_id: R0
- lead_role: lead
- specialist_roles: []
- hint: Rate a local Intel VT-x game anti-cheat hypervisor source project against EAC and BattlEye through static analysis and existing offline test evidence
- preset: none

## auth
- status: granted
- basis: own_system
- evidence_of_auth: operator-owned local source repository
- MUST NOT proceed if status != granted

## in_scope
- assets:
  - C:\Users\Admin\Documents\Ophion
- surfaces: []
- activities: []

## out_of_scope
- assets: []
- activities: [dos, phishing_real_users, unrestricted_exfil]

## network_profile
- mode: lab_only
- notes: |
    offline | lab_only | authorized_target_only | unrestricted_lab
    Change mode only after auth.status = granted.

## deliverables
- report: true
- field_journal: true
- diagrams: true
- timeline: true

## constraints
- timebox: {}
- stealth: low
- data_handling: anonymize

## signoff
- ready_for_act: true
- checklist:
  - [x] auth.status = granted
  - [x] in_scope.assets non-empty OR offline sample path set
  - [x] network_profile.mode chosen
  - [ ] out_of_scope reviewed
  - [ ] roles assigned (see skills/ops/role-map.md)

## ops_refs
- skills/ops/scope-contract.md
- skills/ops/evidence-finding-path.md
- skills/ops/role-map.md
- skills/ops/timeline-workitem.md
- skills/ops/IDENTITY.md