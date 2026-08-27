# Version-pinned EAC and BattlEye research cases

Create one immutable intake record per anti-cheat binary and game build:

```powershell
.\tools\new-research-case.ps1 `
  -Product EAC-EOS `
  -BinaryPath C:\lab\pinned\EasyAntiCheat_EOS.sys `
  -GameBuild game-branch-build
```

The generated `build\research-cases\<case-id>` directory records the binary
hash, version, Authenticode identity, and evidence state. It deliberately does
not copy or execute the supplied binary. Raw artifacts, observations, and
analysis remain separate. A claim is promoted only after two independent
views agree for the exact SHA-256.

KEVLAR traces are one observation view. They do not establish SMP, NMI,
PatchGuard, deferred-work, network, or backend behavior. BattlEye and EAC cases
remain separate even when they exercise similar Windows surfaces.