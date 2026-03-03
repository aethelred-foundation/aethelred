# SDK Safe Publish Playbook

This playbook defines the controlled path for publishing SDK artifacts to registries.

## 1. Required GitHub Environments and Secrets

Create protected environments:

1. `sdk-pypi`
2. `sdk-npm`
3. `sdk-crates`

Store secrets at environment scope:

1. `PYPI_API_TOKEN` in `sdk-pypi`
2. `NPM_TOKEN` in `sdk-npm`
3. `CARGO_REGISTRY_TOKEN` in `sdk-crates`

The workflow `$AETHELRED_REPO_ROOT/.github/workflows/sdk-publish.yml` fails fast when a required secret is missing.
Baseline branch/environment hardening checklist:
`$AETHELRED_REPO_ROOT/docs/operations/ci-cd-gates.md`.

## 2. Version-Driven Tag Rules

Publishing is tag-driven and strictly validated against `$AETHELRED_REPO_ROOT/version-matrix.json`.

Allowed tags:

1. `sdk-python-v<semver>`
2. `sdk-typescript-v<semver>`
3. `sdk-rust-v<semver>`
4. `sdk-go-v<semver>`

Validation is enforced by:

1. `$AETHELRED_REPO_ROOT/scripts/validate_sdk_release_tag.py`
2. `$AETHELRED_REPO_ROOT/.github/workflows/sdk-publish.yml`

## 3. Release Readiness Checklist

1. Update versions in manifests.
2. Update `$AETHELRED_REPO_ROOT/version-matrix.json` and mirror `$AETHELRED_REPO_ROOT/sdk/version-matrix.json`.
3. Confirm `packages.<target>.published=true` for the package being published.
4. Run local dry-run:

```bash
cd $AETHELRED_REPO_ROOT
make sdk-publish-dry-run
```

## 4. Publish Procedure

1. Merge release PR to `main`.
2. Create and push an annotated tag:

```bash
git tag -a sdk-python-v1.0.0 -m "SDK Python v1.0.0"
git push origin sdk-python-v1.0.0
```

3. Approve environment deployment gates when prompted in GitHub Actions.
4. Verify published artifact and record release notes.

## 5. Dry-Run in GitHub (No Publish)

Run workflow manually:

1. Workflow: `SDK Publish`
2. Inputs:
3. `target`: package target
4. `version`: exact semver from matrix
5. `publish`: `false`

This executes full preflight build/package checks without publishing.

## 6. Rollback Procedure

1. Do not delete/overwrite published versions.
2. Cut a new patch version in matrix/manifests.
3. Tag and publish the patch version.
4. Document remediation in release notes.
