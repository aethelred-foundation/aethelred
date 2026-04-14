# Repo Authority

This repository is the canonical public source of truth for the Aethelred
protocol.

Status:

- Operationally canonical public chain repo: `aethelred-foundation/aethelred`
- Formal Foundation ratification record: pending in
  `docs/governance/adr-0001-chain-repo-authority-canonicalization.md`

Summary:

- Canonical public chain repo: `aethelred-foundation/aethelred`
- Canonical Go module path: `github.com/aethelred/aethelred`
- Standalone public repos are governed distribution surfaces, not competing
  canonical chain repos

Enforcement:

- `repo-authority.json` declares this repo as `canonical-chain`.
- `repo-role.json` declares this repo as the canonical public monorepo.
- Repo-local CI validates manifest and README authority claims.
- Release provenance and protected-branch controls govern `main`.
- Foundation governance docs define the approved public repo inventory.
