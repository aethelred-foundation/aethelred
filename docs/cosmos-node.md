# Aethelred Cosmos Node (Authority Notice)

Status: Canonical public chain repository (Foundation ratification pending).

This repository is the canonical public source of truth for the Aethelred chain
implementation and uses the Go module path `github.com/aethelred/aethelred`.

Controls in place:
- Confirm release provenance and security patch authority against the published
  repo authority policy and registries.
- Treat standalone repos as scoped distribution surfaces, not competing chain
  authorities.
- `repo-authority.json`, `repo-role.json`, and repo-local CI define and verify
  canonical status.

See:
- `docs/security/threat-model.md`
- `docs/governance/adr-0001-chain-repo-authority-canonicalization.md`
- `SECURITY.md`
- `repo-authority.json`
