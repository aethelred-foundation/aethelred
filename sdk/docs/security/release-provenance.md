# SDK Release Provenance (Enforced Local Controls, Publication Pending)

Status: Partially enforced in `aethelred-sdks` (machine checks + CI workflows + provenance bundle generation); public registry publication/signing still pending

## Objectives

- Reproducible builds for Python / TypeScript / Rust / Go SDK artifacts
- Signed release tags and published checksums
- CI-generated provenance metadata linked to Git commit and version matrix
- Public verification instructions for downstream integrators

## Minimum Requirements

1. Build all SDK artifacts in CI from a tagged commit.
2. Generate checksums (`SHA256SUMS`) for published artifacts.
3. Publish SBOMs per SDK artifact set.
4. Attach provenance attestations (e.g., Sigstore/GitHub attestations).
5. Keep `version-matrix.json` synchronized with published package versions.

## Machine-Enforced Controls (Now Present)

- Provenance requirements registry:
  - `docs/security/release-provenance-registry.json`
- Provenance validator + status generator:
  - `scripts/validate_release_provenance.py`
  - `docs/security/release-provenance-status.md`
- Repo-local provenance guard CI:
  - `.github/workflows/sdk-release-provenance-guard.yml`
- Repo-local provenance bundle generation CI:
  - `.github/workflows/sdk-release-provenance-local.yml`
- Repo-local release-readiness CI (build/package checks):
  - `.github/workflows/sdk-release-readiness.yml`

## Verification Steps (Public Consumers)

See the full consumer checklist in:

- `docs/security/release-verification-guide.md`

Minimum public verification:

1. Verify release tag signature
2. Verify artifact checksums
3. Verify provenance/attestation subject digest matches artifact
4. Verify package version matches `version-matrix.json`

## Current Gap

The SDK suite is source-first in parts; registry publication and signed provenance rollout must be completed before claiming final installability across all ecosystems.

Operationally open items:

1. Publish canonical artifacts to PyPI / npm / crates.io / Go module path
2. Publish signed release tags and checksums for those artifacts
3. Enable and use attestation outputs in public releases (workflow support is present)
4. Update `version-matrix.json` `published` flags from `false` to `true` only after registry verification succeeds
