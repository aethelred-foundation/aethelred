# SDK Release Verification Guide

Status: Draft (required for public registry releases)

This guide defines how downstream integrators should verify Aethelred SDK releases across Python, TypeScript, Rust, and Go.

## What to Verify (Every Release)

1. **Release tag** maps to the expected Git commit.
2. **Artifact checksums** match `SHA256SUMS.txt`.
3. **Release provenance bundle** includes:
   - `MANIFEST.json`
   - `build-metadata.json`
   - `version-matrix.sdk.json`
   - `sdk-release-status.json`
4. **SDK version** matches `sdk/version-matrix.json`.
5. **Attestation/provenance** (when enabled) references the same artifact digests.

## Per-Ecosystem Checks

### Python (PyPI)

- Download wheel and sdist
- Verify `sha256sum -c SHA256SUMS.txt`
- Confirm package version in wheel metadata matches `version-matrix.sdk.json`

### TypeScript / JavaScript (npm)

- Download `.tgz`
- Verify `sha256sum -c SHA256SUMS.txt`
- Confirm `package.json` version inside tarball matches `version-matrix.sdk.json`

### Rust (crates.io)

- Download `.crate`
- Verify `sha256sum -c SHA256SUMS.txt`
- Confirm `Cargo.toml` package version matches `version-matrix.sdk.json`

### Go (module proxy)

- Verify module version and pseudo-content against release metadata:
  - `.mod`
  - `.info`
  - `.zip`
- Confirm module path and version match `version-matrix.sdk.json`

## Current Status

Before registry publication is complete, the SDKs remain source-first for some ecosystems. See:

- `docs/security/release-provenance.md`
- `docs/security/release-provenance-status.md`
- `version-matrix.json`
