# Release Provenance

This document defines how Aethelred publishes release-authoritative source code
and artifacts from GitHub.

## Canonical Source

- Canonical public source repo: `aethelred-foundation/aethelred`
- Canonical default branch: `main`
- Canonical chain module path: `github.com/aethelred/aethelred`

Standalone repositories such as `contracts`, `aethelred-sdk-ts`, and `cruzible`
exist to improve developer ergonomics and package distribution. They do not
replace the canonical repo-authority model documented in:

- [repo-authority.json](../../repo-authority.json)
- [docs/governance/repo-authority-registry.json](../governance/repo-authority-registry.json)

## Release Rules

- Every release must originate from a reviewed pull request merged into `main`.
- Canonical `main` releases require the protected-branch policy in force at the
  time of merge, including required status checks, conversation resolution, and
  two approving reviews.
- Version tags use semantic versioning: `vMAJOR.MINOR.PATCH`.
- GitHub Releases must reference the exact tag and commit SHA they were built from.
- Release notes must link to the changelog, upgrade notes, and any relevant AIPs.
- Security-sensitive releases must reference the applicable advisory or incident note.
- External audit and regulatory evidence packs must record the exact release or
  audit snapshot commit SHA they rely on.

## Artifact Expectations

Each release should publish or link:

- Source tag and GitHub Release
- SBOM artifact when available
- Checksums for binaries or packaged artifacts
- Package registry publication references when applicable
- Any migration, upgrade, or rollback notes

## Standalone Repo Expectations

Standalone repos must clearly state one of the following:

- They are the source of truth for that surface, or
- They are exported from the canonical monorepo source path

Each standalone repo must include a `repo-role.json` manifest and a README note
describing its provenance.

## Verification Checklist

Before announcing a release:

1. Confirm the release tag resolves to the intended commit.
2. Confirm the commit is traceable to the reviewed pull request and protected-branch evidence.
3. Confirm `SECURITY.md`, support links, and changelog references are current.
4. Confirm the correct repo is publishing the release for that surface.
5. Confirm generated artifacts match the committed source tree.
6. Confirm audit or advisory references do not overstate the current status.
