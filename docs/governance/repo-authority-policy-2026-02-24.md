# Repository Authority Policy (Enforced Interim) — 2026-02-24

Status: Enforced interim policy (registry + CI guardrails implemented locally); Foundation ratification package prepared; final org-level ratification pending approval.

## Purpose

Resolve ambiguity where multiple public repositories appear to represent the same protocol surface or module path.

## Canonical Source Rules (Interim)

### 1. Chain Implementation (Cosmos SDK / Go)

Canonical implementation repo (interim): `AethelredFoundation/aethelred-cosmos-node`

Transitional / mirror repo (interim): `AethelredFoundation/aethelred-core`

Rationale:
- `aethelred-cosmos-node` is the implementation-focused codebase currently carrying the active PoUW / validator / attestation hardening work in this workspace.
- Duplicate Go module path (`github.com/aethelred/aethelred`) across both repos creates patch-drift and audit confusion.

Interim controls:
- Security fixes MUST land in `aethelred-cosmos-node` first.
- `aethelred-core` MUST carry a repository authority notice (README + SECURITY.md) until deprecation or mirror automation is finalized.
- A machine-readable authority registry MUST define canonical and transitional roles.
- Each chain repo MUST ship `repo-authority.json` matching its `go.mod` module path.
- `aethelred-core` MUST block release publishing in CI while designated `transitional-mirror`.
- No release tags should be cut from both repos for the same version identifier.

### 2. Rust Implementation Track Repository

`AethelredFoundation/aethelred-rust-node` is designated a **Rust implementation track repository** (buildable/testable crate baseline), but it is **not** the canonical chain implementation.

Rust implementation track requirements:
- MUST remain buildable/testable (`Cargo.toml`, CI, tests)
- MUST include `SECURITY.md` and threat model scope
- MUST NOT be used to support production deployment claims without a separate validator/runtime hardening review

## Public Communication Requirements

When describing the protocol externally (auditors, partners, investors):
- Name the canonical chain repo explicitly.
- Distinguish canonical chain repos from alternative implementation tracks and research/spec repos.
- Link to repo-local CI/security artifacts when making security claims.

## Deprecation / Consolidation Next Steps

1. Decide whether `aethelred-core` will be archived, mirrored, or repurposed.
2. If mirrored, implement automated sync and mark the repo read-only for direct feature work.
3. Publish a signed decision record in the Foundation governance documentation (ratification template prepared in `adr-0001-chain-repo-authority-canonicalization.md`).
4. Push and enable repo-local authority guard workflows in both `aethelred-cosmos-node` and `aethelred-core`.
