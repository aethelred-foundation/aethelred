# SDK Versioning Strategy

## Objective
Provide a deterministic, auditable versioning policy across all Aethelred SDKs and API artifacts.

## Source of Truth
1. Version matrix: `$AETHELRED_REPO_ROOT/version-matrix.json`
2. OpenAPI schema:
- `$AETHELRED_REPO_ROOT/sdk/spec/openapi.yaml`
- `$AETHELRED_REPO_ROOT/sdk/spec/openapi.json`

## Policy
1. All packages follow Semantic Versioning (`MAJOR.MINOR.PATCH`).
2. API compatibility is governed by the OpenAPI version and REST path version.
3. Any `MAJOR` change requires:
- Version matrix update.
- Migration notes in release docs.
- Regeneration of OpenAPI artifacts.
4. Lifecycle support window:
- `N` (current): full support.
- `N-1`: maintenance/security fixes.
- `N-2`: end-of-life.

## Validation Gate
Run:

```bash
python3 $AETHELRED_REPO_ROOT/scripts/check_sdk_versions.py
```

This validates:
1. Package versions in manifests match `version-matrix.json`.
2. OpenAPI `info.version` matches the matrix.
3. All versions are valid semver strings.

## Release Checklist (SDK)
1. Update package versions.
2. Update `$AETHELRED_REPO_ROOT/version-matrix.json` (and mirror `sdk/version-matrix.json`).
3. Run version check gate.
4. Run OpenAPI generation:
```bash
make openapi
```
5. Publish release notes with compatibility statement.
6. Use package-scoped semantic tags (validated by `scripts/validate_sdk_release_tag.py`):
- `sdk-python-vX.Y.Z`
- `sdk-typescript-vX.Y.Z`
- `sdk-rust-vX.Y.Z`
- `sdk-go-vX.Y.Z`
