# Repo Authority (Enforced Interim)

This repository is subject to the interim authority policy for the Aethelred protocol multi-repo set.

See the Foundation-level repo authority policy (interim, published in the Aethelred governance docs).

Summary:
- Canonical chain implementation (interim): `aethelred-cosmos-node`
- Transitional mirror / duplicate module path repo: `aethelred-core`
- Alternative implementation track (buildable/testable, non-canonical chain): `aethelred-rust-node`

Enforcement:
- `repo-authority.json` declares this repo as `canonical-chain`.
- Repo-local CI (`repo-authority-guard.yml`) validates manifest ↔ `go.mod` consistency and canonical release authority.
