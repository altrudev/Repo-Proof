# RepoProof

**Executable repository claims, boundaries, invariants, and transition proofs.**

RepoProof answers a question normal CI does not: **what important properties changed even when the tests still pass?**

## v0.1 primitives

- **CLAIM** — a statement the repository makes that can be checked against evidence.
- **BOUNDARY** — capabilities the repository declares, such as allowed outbound domains or process spawning.
- **INVARIANT** — properties that must remain unchanged across a transition.
- **DIFF** — a proof-oriented comparison of two git revisions.

## Try it

    python -m pip install .
    repoproof check
    repoproof baseline
    repoproof diff HEAD~1 HEAD
    repoproof --json repoproof.json diff HEAD~1 HEAD

A violating transition returns exit code `2`, making RepoProof usable directly as a CI gate.

## Configuration

RepoProof reads `repoproof.toml`. v0.1 supports path/text claims, network and process boundaries, and dependency/workflow/path invariants.

The engine is intentionally deterministic. `UNPROVEN` is preserved as a first-class result rather than converted into a guess.

## Scope and limitations

RepoProof v0.1 performs static evidence checks. A detected URL or process-spawn primitive is evidence of capability, not proof that it executes at runtime. Conversely, dynamic or obfuscated behavior may not be visible statically. RepoProof reports evidence and bounded conclusions rather than claiming complete behavioral verification.

## Authorship and use

Created by **Valentyn Rukhaylo / Altru.dev**.

No open-source license is granted by this repository. Commercial use, redistribution, or incorporation into commercial products requires permission from the copyright holder.
