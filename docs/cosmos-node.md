# Aethelred Cosmos Node (Authority Notice)

Status: Canonical chain repository (interim enforced authority designation; final Foundation ratification pending).

This repository currently overlaps with `aethelred-core` and uses the same Go module path (`github.com/aethelred/aethelred`).

Enforced interim controls now in place:
- Treat this repo as the implementation-focused chain codebase under active development.
- Confirm release provenance and security patch authority against the published repo authority policy and registry.
- Do not rely on module-path duplication as evidence of synchronization.
- `repo-authority.json` and repo-local authority CI guard define and verify this repo's canonical status.

See:
- `docs/security/threat-model.md`
- `docs/governance/adr-0001-chain-repo-authority-canonicalization.md`
- `SECURITY.md`
- `repo-authority.json`
