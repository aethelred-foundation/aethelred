# Audit Readiness Snapshot — 2026-04-14

This document records the canonical repository control baseline prepared for
external audit and regulatory evidence review.

## Canonical Repository

- Repository: `aethelred-foundation/aethelred`
- Canonical branch: `main`
- Baseline snapshot at hardening start: `6423bc59b8f3341e514ef5058d2fa84c73b53ad0`
- Hardening branch: `ramesh/audit-readiness-hardening-20260414`

## Change-Control Baseline

The intended protected-branch baseline for `main` is:

1. `Contracts Required Gate`
2. `Docker Required Gate`
3. `E2E Required Gate`
4. `Fuzzing Required Gate`
5. `Load Test Required Gate`
6. `Rust Required Gate`
7. `Sandbox Required Gate`
8. `Security Required Gate`
9. Two approving reviews required
10. Conversation resolution enabled
11. Linear history enabled
12. Administrator enforcement enabled
13. Direct pushes restricted to release-authority actors

## Traceable Security Hardening

The current mainline includes the recent hardening chain:

- PR `#121` merged at commit `c4f0f7b7147415e06fa2abcf4973c7ffb915c381`
- PR `#122` merged at commit `6423bc59b8f3341e514ef5058d2fa84c73b53ad0`

## Provenance Notes

- Release provenance policy: `docs/security/release-provenance.md`
- Authority manifest: `repo-authority.json`
- Authority narrative: `docs/security/repo-authority.md`
- Branch protection automation: `scripts/setup_required_github_checks.sh`
- Required-check mapping: `.github/branch-protection/required-checks.json`

## Residual Governance Notes

- `repo-authority.json` still records `pending-foundation-ratification`; this
  is a governance status item, not a code-integrity blocker.
- External audit and regulatory packs should cite the exact commit SHA used for
  review and not rely on moving branch names alone.
