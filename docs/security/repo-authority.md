# Repo Authority

This repository is the canonical public source of truth for the Aethelred
protocol.

Summary:

- Canonical public chain repo: `AethelredFoundation/aethelred`
- Canonical Go module path: `github.com/aethelred/aethelred`
- Standalone public repos are governed distribution surfaces, not competing
  canonical chain repos

Enforcement:

- `repo-authority.json` declares this repo as `canonical-chain`.
- `repo-role.json` declares this repo as the canonical public monorepo.
- Repo-local CI validates manifest and README authority claims.
- Foundation governance docs define the approved public repo inventory.
