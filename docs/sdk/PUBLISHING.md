# SDK Publishing Status

As of **February 23, 2026**, SDK registries are **not published yet**. Use source-path or supported GitHub-source installs from this repository.

## Current Status

| SDK | Registry Package | Published |
|-----|------------------|-----------|
| Python | `aethelred-sdk` (PyPI) | No |
| TypeScript | `@aethelred/sdk` (npm) | No |
| Rust | `aethelred-sdk` (crates.io) | No |
| Go | `github.com/aethelred/sdk-go` (module proxy) | No |

## Source Install Commands

```bash
# Python
pip install -e $AETHELRED_REPO_ROOT/sdk/python

# TypeScript
npm install $AETHELRED_REPO_ROOT/sdk/typescript

# Rust (Cargo.toml)
# aethelred-sdk = { path = "$AETHELRED_REPO_ROOT/sdk/rust" }

# Go (source-first, current module path)
go mod edit -replace github.com/aethelred/sdk-go=$AETHELRED_REPO_ROOT/sdk/go
go get github.com/aethelred/sdk-go@v1.0.0
```

## Release Flow

1. Run `make sdk-release-check`.
2. Run `make sdk-publish-dry-run`.
3. Trigger `$AETHELRED_REPO_ROOT/.github/workflows/sdk-publish.yml` with `publish=false` for CI dry-run if needed.
4. Publish with package-scoped tags:
5. `sdk-python-vX.Y.Z`
6. `sdk-typescript-vX.Y.Z`
7. `sdk-rust-vX.Y.Z`
8. `sdk-go-vX.Y.Z`
9. Verify each registry artifact and update this document + `version-matrix.json`.

See full controls: `$AETHELRED_REPO_ROOT/docs/sdk/PUBLISH_PLAYBOOK.md`.

## Important Go Note

The Go module path is currently `github.com/aethelred/sdk-go` (without `/v2`), so public releases must remain `v1.x` until a module-path migration is executed.
