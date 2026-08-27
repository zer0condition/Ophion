# Ophion hardening research scope

## Authorization

The operator explicitly requested analysis and improvement of the local
`C:\Users\Admin\Documents\Ophion` repository against EAC and BattlEye
detection surfaces. The repository, attached tools, local corpora, and supplied
public research URLs are in scope.

## In scope

- Compare the local worktree with `zer0condition/Ophion`.
- Review the supplied UnknownCheats threads and three author histories.
- Review `E:\Tools`, `C:\Users\Admin\Desktop\Sec-Research`, the operator's
  GitHub stars/repositories, and the drof Labs book.
- Implement only findings supported by source or reproducible local evidence.
- Add regression tests, reusable skill guidance, build evidence, and
  closest-surface manual QA.

## Out of scope

- Running a live EAC or BattlEye protected session.
- Claiming undetected, compatible, bypassed, or backend-accepted behavior.
- Importing target-specific offsets, unverified spoof values, or community
  detection-duration claims as portable facts.
- Overwriting unrelated pre-existing worktree changes.

## Network profile

Public read-only research access to GitHub, UnknownCheats, Intel, Microsoft,
and the supplied book. No secrets were transmitted to an unrequested network.

## Completion evidence

The task is complete only when the selected changes have failing regression
tests before implementation, green builds/tests afterward, a real mapper
happy path and rejection path, a source-to-change audit, and explicit
documentation of validation gaps.
