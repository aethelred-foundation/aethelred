# GitHub Operating Standard

This document defines the minimum public GitHub standard for all
`aethelred-foundation` repositories.

## Objectives

- Make the canonical source of truth obvious within 30 seconds.
- Ensure every public repo is legally, operationally, and security complete.
- Keep standalone repos consistent with the monorepo and Foundation defaults.
- Make releases verifiable by auditors, partners, and developers.

## Required Public Repo Baseline

Every public repo must ship:

- `README.md` with repo role and source-of-truth statement
- `LICENSE`
- `SECURITY.md`
- `SUPPORT.md`
- `CODE_OF_CONDUCT.md`
- `repo-role.json`
- `CODEOWNERS`
- Issue templates and a PR template
- At least one CI or baseline workflow

## Authority Rules

- `aethelred-foundation/aethelred` is the canonical public monorepo.
- Standalone repos may optimize packaging and discoverability, but they must not
  conflict with the canonical authority model.
- Any future mirror, archive, or split repo must clearly declare its role in
  both the README and `repo-role.json`.

## Release Rules

- Publish semantic version tags and GitHub Releases.
- Link every release to changelog and upgrade notes.
- Publish or attach provenance artifacts and SBOMs when available.
- Do not overstate audit status in badges, release notes, or READMEs.

## Org Defaults

The Foundation `.github` repo should provide:

- Community health defaults for repos that do not override them
- The public org profile README and banner assets
- Shared issue intake defaults
- Shared support and conduct policies

## Metadata Rules

- Every repo must have a precise description, homepage, and topics.
- Pinned repos must reflect the current developer journey, not simply the newest repos.
- Discussions should only be enabled where maintainers have a clear response model.

## Source Of Truth

The machine-readable source of truth for public repo setup lives in:

- [github-repo-standards.json](github-repo-standards.json)
- [github-labels.json](github-labels.json)
- [repo-authority-registry.json](repo-authority-registry.json)
