# CI/CD Branch Protection and Environment Hardening

This document is the source of truth for protected-branch required checks and
GitHub Environment protection settings.

## 1. Required Check Mapping

Branch mappings are codified in:
`.github/branch-protection/required-checks.json`.

Current mapping:

1. `main`
2. `Audit Signoff Required Gate`
3. `Core Required Gate`
4. `Contracts Required Gate`
5. `Rust Required Gate`
6. `Security Required Gate`
7. `Sandbox Required Gate`
8. `Load Test Required Gate`

1. `develop`
2. `Core Required Gate`
3. `Contracts Required Gate`
4. `Rust Required Gate`
5. `Security Required Gate`
6. `Sandbox Required Gate`

1. `release/*`
2. `Audit Signoff Required Gate`
3. `Core Required Gate`
4. `Contracts Required Gate`
5. `Rust Required Gate`
6. `Security Required Gate`
7. `Sandbox Required Gate`
8. `Load Test Required Gate`

Apply branch protection:

```bash
cd .
scripts/setup_required_github_checks.sh <owner/repo> main develop
```

## 2. PR Protection Baseline

Set these on protected branches:

1. Require pull request before merge.
2. Require status checks to pass.
3. Require branches to be up to date before merging.
4. Require 1+ approving review (2 for `main` recommended).
5. Require CODEOWNERS review.
6. Require conversation resolution.
7. Enforce for administrators.
8. Disallow force pushes and branch deletion.
9. Require linear history.

## 3. Environment Protection Checklist

Configure the following GitHub Environments:

1. Runtime deploy: `staging`, `canary`, `production`
2. SDK publish: `sdk-pypi`, `sdk-npm`, `sdk-crates`

Set protection rules:

1. Require reviewers:
2. `staging`: at least 1 reviewer
3. `canary`: at least 2 reviewers
4. `production`: at least 2 reviewers
5. `sdk-pypi`: at least 1 reviewer
6. `sdk-npm`: at least 1 reviewer
7. `sdk-crates`: at least 1 reviewer

1. Prevent self-review for all six environments.
2. Restrict deployment branches:
3. `staging`: `main` only
4. `canary`: `main` only
5. `production`: `main` only
6. `sdk-*`: tags matching `sdk-*-v*` only

Required environment secrets:

1. `staging`: `KUBE_CONFIG_STAGING`
2. `production`: `KUBE_CONFIG_PRODUCTION`
3. `sdk-pypi`: `PYPI_API_TOKEN`
4. `sdk-npm`: `NPM_TOKEN`
5. `sdk-crates`: `CARGO_REGISTRY_TOKEN`

## 4. Release Tag Rules (SDK)

SDK releases are version-driven and validated against
`version-matrix.json`.

Allowed tags:

1. `sdk-python-v<semver>`
2. `sdk-typescript-v<semver>`
3. `sdk-rust-v<semver>`
4. `sdk-go-v<semver>`

Validator:
`scripts/validate_sdk_release_tag.py`.

## 5. Local Dry-Run Gate

Run before tagging:

```bash
cd .
make sdk-publish-dry-run
```

This executes full preflight build/package checks without publishing.
