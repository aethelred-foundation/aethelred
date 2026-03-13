# Repository Authority Policy

Status: Active interim policy. Last updated: 2026-03-13.

## Purpose

Make the public GitHub organization unambiguous for developers, auditors,
partners, and maintainers.

## Canonical Source Rules

### 1. Chain Implementation

Canonical public chain repository:

- `AethelredFoundation/aethelred`

Canonical Go module path:

- `github.com/aethelred/aethelred`

Controls:

- Security fixes for the public chain implementation must land in
  `AethelredFoundation/aethelred`.
- `repo-authority.json` and `repo-role.json` must remain consistent with the
  Foundation registries.
- Public chain releases must be cut from `AethelredFoundation/aethelred`.
- Any future mirror or split repo using the same module path must be explicitly
  declared in the authority registry before publication.

### 2. Standalone Repositories

The following public repos are approved standalone surfaces:

- `AethelredFoundation/contracts`
- `AethelredFoundation/aethelred-sdk-ts`
- `AethelredFoundation/aethelred-sdk-py`
- `AethelredFoundation/aethelred-sdk-go`
- `AethelredFoundation/aethelred-sdk-rs`
- `AethelredFoundation/aethelred-cli`
- `AethelredFoundation/vscode-aethelred`
- `AethelredFoundation/aethelred-docs`
- `AethelredFoundation/AIPs`
- `AethelredFoundation/cruzible`

Controls:

- Each standalone repo must declare its role in `repo-role.json`.
- Each standalone repo must state whether it is exported from a monorepo source
  path or independently maintained.
- Standalone repos may publish releases for their own surface area, but they do
  not supersede the canonical chain authority model.

### 3. Foundation Control Plane

`AethelredFoundation/.github` is the organization control plane for:

- Community health defaults
- Org profile assets
- Shared issue and support intake defaults

It is not a release-authoritative repo.

## Public Communication Requirements

When describing the protocol externally:

- Name `AethelredFoundation/aethelred` as the canonical public repo.
- Link to the relevant standalone repo only when discussing that surface area.
- Link to repo-local CI, security, and release provenance artifacts when making
  security or release claims.

## Change Control

Before creating, archiving, or repurposing a public repo:

1. Update the authority registry and GitHub standards manifest.
2. Update the public org profile and pinned repo strategy if needed.
3. Update `repo-role.json` and README authority notes for the affected repo.
4. Record the change in Foundation governance documentation.
