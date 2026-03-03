# SDK Repo Split Playbook (TypeScript + Rust)

Last updated: **February 23, 2026**

## Why this exists

Two package managers have practical GitHub-install limitations with the current monorepo layout:

1. `npm` cannot reliably install a package from a monorepo subdirectory over Git.
2. `cargo` is better than npm here, but a standalone repo still simplifies direct consumption, publishing, and external contribution workflows.

## Recommended dedicated repos

1. `AethelredFoundation/aethelred-sdk-js` (from `sdk/typescript`)
2. `AethelredFoundation/aethelred-sdk-rust` (from `sdk/rust`)

## Export scripts (standalone repo materialization)

These scripts create a clean standalone repo directory with package files + a minimal CI workflow:

```bash
# TypeScript SDK
$AETHELRED_REPO_ROOT/scripts/export-sdk-typescript-repo.sh /tmp/aethelred-sdk-js

# Rust SDK
$AETHELRED_REPO_ROOT/scripts/export-sdk-rust-repo.sh /tmp/aethelred-sdk-rust
```

Generic form:

```bash
$AETHELRED_REPO_ROOT/scripts/export-sdk-standalone-repo.sh typescript /tmp/aethelred-sdk-js
$AETHELRED_REPO_ROOT/scripts/export-sdk-standalone-repo.sh rust /tmp/aethelred-sdk-rust
```

## Push to GitHub (after export)

```bash
cd /tmp/aethelred-sdk-js
git init
git add .
git commit -m "Initial split from AethelredMVP sdk/typescript"
git branch -M main
git remote add origin git@github.com:AethelredFoundation/aethelred-sdk-js.git
git push -u origin main
```

```bash
cd /tmp/aethelred-sdk-rust
git init
git add .
git commit -m "Initial split from AethelredMVP sdk/rust"
git branch -M main
git remote add origin git@github.com:AethelredFoundation/aethelred-sdk-rust.git
git push -u origin main
```

## Post-split package install examples

### TypeScript / JavaScript

```bash
npm install github:AethelredFoundation/aethelred-sdk-js
```

### Rust (Cargo)

```toml
[dependencies]
aethelred-sdk = { git = "https://github.com/AethelredFoundation/aethelred-sdk-rust.git" }
```

## Operational note

The monorepo remains the source of truth until you formally switch ownership/process. If you use dedicated repos, add a sync policy (manual, subtree, or release-branch export) and document it in both repos.

## Sync Automation (GitHub Actions)

Monorepo workflow:

- `$AETHELRED_REPO_ROOT/.github/workflows/sdk-standalone-sync.yml`

Helper script used by the workflow:

- `$AETHELRED_REPO_ROOT/scripts/sync-standalone-sdk.sh`

### Required GitHub configuration (for branch push / PR mode)

Repository variables:

- `SDK_TYPESCRIPT_STANDALONE_REPO` = `AethelredFoundation/aethelred-sdk-js`
- `SDK_RUST_STANDALONE_REPO` = `AethelredFoundation/aethelred-sdk-rust`
- `SDK_STANDALONE_AUTO_PUSH` = `false` (recommended initially)
- `SDK_STANDALONE_AUTO_PR` = `true`

Repository secret:

- `SDK_STANDALONE_SYNC_TOKEN` = GitHub token with `repo` scope for the target repos

### Operating modes

1. **Validation-only (safe default)**:
   - Runs on pushes to `main` touching `sdk/typescript` or `sdk/rust`
   - Exports standalone repos and validates packaging/builds
   - Does not push unless auto-push is enabled

2. **Manual sync + PR (recommended)**
   - Run `SDK Standalone Sync` via `workflow_dispatch`
   - Choose `target=typescript|rust|all`
   - Set `push=true`
   - Keep `create_pr=true`
