# Official SDKs (Release Readiness)

Last updated: **February 23, 2026**

This document tracks installability, feature coverage, and release readiness for the official Aethelred SDKs:

- Python SDK
- TypeScript / JavaScript SDK
- Rust SDK
- Go SDK

## Current Release Matrix

| SDK | Package / Module | Version | Registry Publish Status |
|---|---|---:|---|
| Python | `aethelred-sdk` | `1.0.0` | Pending public PyPI release |
| TypeScript | `@aethelred/sdk` | `1.0.0` | Pending public npm release |
| Rust | `aethelred-sdk` | `1.0.0` | Pending public crates.io release |
| Go | `github.com/aethelred/sdk-go` | `1.0.0` | Pending public module publication |

Version source of truth:
- `$AETHELRED_REPO_ROOT/version-matrix.json`
- `$AETHELRED_REPO_ROOT/sdk/version-matrix.json`

## Install Status (Today)

### Python

Direct install from GitHub subdirectory is supported:

```bash
pip install "git+https://github.com/AethelredFoundation/AethelredMVP.git#subdirectory=sdk/python"
```

### TypeScript / JavaScript

Current monorepo layout supports local path install, but npm Git installs do not support subdirectory packages directly:

```bash
npm install $AETHELRED_REPO_ROOT/sdk/typescript
```

### Rust

Current monorepo layout supports local path dependency:

```toml
[dependencies]
aethelred-sdk = { path = "$AETHELRED_REPO_ROOT/sdk/rust" }
```

### Go

Current monorepo layout supports local replace + `go get`:

```bash
go mod edit -replace github.com/aethelred/sdk-go=$AETHELRED_REPO_ROOT/sdk/go
go get github.com/aethelred/sdk-go@v1.0.0
```

## Feature Coverage Highlights

### Python SDK

- Async + sync clients
- Type hints + `py.typed`
- Automatic retries and connection pooling (`httpx`, `tenacity`)
- ML/framework integrations: PyTorch, TensorFlow/Keras, Hugging Face, LangChain, FastAPI

### TypeScript SDK

- TypeScript-first client (`AethelredClient`)
- Retry/error handling and WebSocket support
- Offline seal verifier (`devtools`)
- Next.js route wrappers + middleware wrapper
- React hooks (`@aethelred/sdk/react`)
- Publish-safe `.d.ts` declarations from `dist/`

### Rust SDK

- Async client with `tokio` runtime support
- Typed modules for jobs/seals/models/validators/verification
- Borrowed (zero-copy-oriented) seal JSON parsing helpers for hot paths

### Go SDK

- Idiomatic context-first APIs
- Configurable HTTP connection pooling
- Pluggable transport interface and gRPC adapter hook (`WithGRPCTransport`)
- Typed modules for jobs/seals/models/validators/verification

## CI / Validation

- Python tests + coverage: `$AETHELRED_REPO_ROOT/.github/workflows/sdk-python-tests.yml`
- TypeScript tests + coverage: `$AETHELRED_REPO_ROOT/.github/workflows/sdk-typescript-tests.yml`
- Rust tests + coverage: `$AETHELRED_REPO_ROOT/.github/workflows/sdk-rust-tests.yml`
- Go tests + coverage: `$AETHELRED_REPO_ROOT/.github/workflows/sdk-go-tests.yml`
- Go `pkg/nn` focused coverage: `$AETHELRED_REPO_ROOT/.github/workflows/sdk-go-nn-coverage.yml`
- SDK release-readiness gate (packaging/install checks): `$AETHELRED_REPO_ROOT/.github/workflows/sdk-release-readiness.yml`
- SDK release provenance guard (SDK repo-local): `$AETHELRED_REPO_ROOT/sdk/.github/workflows/sdk-release-provenance-guard.yml`
- SDK release provenance bundle generator (SDK repo-local): `$AETHELRED_REPO_ROOT/sdk/.github/workflows/sdk-release-provenance-local.yml`
- SDK release provenance status (machine-generated): `$AETHELRED_REPO_ROOT/sdk/docs/security/release-provenance-status.md`
- SDK release verification guide: `$AETHELRED_REPO_ROOT/sdk/docs/security/release-verification-guide.md`

## Publishing Workflow

Publishing/dry-run workflow:
- `$AETHELRED_REPO_ROOT/.github/workflows/sdk-publish.yml`

Supporting docs:
- `$AETHELRED_REPO_ROOT/docs/sdk/PUBLISHING.md`
- `$AETHELRED_REPO_ROOT/docs/sdk/PUBLISH_PLAYBOOK.md`
- `$AETHELRED_REPO_ROOT/docs/sdk/VERSIONING.md`

## Remaining Steps Before Public Registry Release

1. Publish registry artifacts (PyPI / npm / crates.io / Go module path) using the SDK publish workflow.
2. Decide final Go major-version strategy (`v1.x` now vs `/v2` module path migration).
3. If direct GitHub install is required for npm/cargo, use the standalone export playbook and publish dedicated repos for `sdk/typescript` and `sdk/rust`: `$AETHELRED_REPO_ROOT/docs/sdk/REPO_SPLIT_PLAYBOOK.md`.
4. Sync public docs URLs (`docs.aethelred.org`) to the current SDK README content after first registry release.
5. Keep the vendored Python build backend in sync with `pyproject.toml` metadata when packaging fields change: `$AETHELRED_REPO_ROOT/sdk/python/build_backend/README.md`.
