# Aethelred Official SDKs

Aethelred provides official SDKs for **Python**, **TypeScript/JavaScript**, **Rust**, and **Go** for interacting with the verifiable AI protocol (jobs, seals, model registry, validators, verification).

This monorepo is currently **source-first**. Registry publishing workflows and dry-runs exist, but public registry releases are still marked pending in `version-matrix.json`.

## Current Versions (Release Matrix)

| SDK | Package / Module | Version | Install Status |
|---|---|---:|---|
| [`aethelred-sdk`](./python) | `aethelred-sdk` | `1.0.0` | Source-ready, PyPI publish workflow ready |
| [`@aethelred/sdk`](./typescript) | `@aethelred/sdk` | `1.0.0` | Source-ready, npm publish workflow ready |
| [`aethelred-sdk`](./rust) | `aethelred-sdk` | `1.0.0` | Source-ready, crates.io publish workflow ready |
| [`sdk-go`](./go) | `github.com/aethelred/sdk-go` | 1.0.0 | Source-ready, module proxy publish pending |

Notes:
- Go remains on `v1.x` until the module path is migrated to `/v2`.
- Version source of truth: `$AETHELRED_REPO_ROOT/version-matrix.json` and `$AETHELRED_REPO_ROOT/sdk/version-matrix.json`.

## Install (Current Monorepo Source-First)

### Python (supported direct from GitHub subdirectory)

```bash
pip install "git+https://github.com/AethelredFoundation/AethelredMVP.git#subdirectory=sdk/python"
# or local editable install
pip install -e $AETHELRED_REPO_ROOT/sdk/python
```

### TypeScript / JavaScript

```bash
# local path install (current monorepo layout)
npm install $AETHELRED_REPO_ROOT/sdk/typescript
```

Notes:
- npm Git installs do not support this monorepo subdirectory layout directly.
- Use npm registry (`@aethelred/sdk`) once published, or split/package this SDK repo separately.

### Rust

```toml
# Cargo.toml (current monorepo source install)
[dependencies]
aethelred-sdk = { path = "$AETHELRED_REPO_ROOT/sdk/rust" }
```

Notes:
- Direct Git dependency from this monorepo subdirectory requires a repo/workspace layout change.
- Use crates.io once published.

### Go

```bash
# inside your Go project (source-first local replace)
go mod edit -replace github.com/aethelred/sdk-go=$AETHELRED_REPO_ROOT/sdk/go
go get github.com/aethelred/sdk-go@v1.0.0
```

Notes:
- Public `go get github.com/aethelred/sdk-go@v1.0.0` requires the module to be published at the canonical module path.

## Feature Coverage (Current Implementation)

| Capability | Python | TypeScript | Rust | Go |
|---|---|---|---|---|
| Async client support | Yes | Yes (Promises) | Yes (`tokio`) | Yes (`context.Context`) |
| Automatic retries | Yes | Yes | Basic HTTP error mapping | Basic retry-ready config |
| Type safety | Type hints + `py.typed` | TypeScript + published `.d.ts` in dist | Strong types + serde | Strong types + compile-time interfaces |
| WebSocket / realtime | Yes | Yes | Planned parity | Planned parity |
| Framework integrations | PyTorch / TF(Keras) / HF / LangChain / FastAPI | Next.js API routes / route handlers / middleware + React hooks | Envelope parity + zero-copy parsing helpers | Transport + middleware/interceptor parity docs |
| Offline seal verification | Via modules/tools | Yes (`@aethelred/sdk/devtools`) | Borrowed parser + verify modules | Yes via seals/verification modules |

## Documentation

- SDK publishing and registry status: `$AETHELRED_REPO_ROOT/docs/sdk/PUBLISHING.md`
- SDK versioning policy: `$AETHELRED_REPO_ROOT/docs/sdk/VERSIONING.md`
- Framework integrations matrix: `$AETHELRED_REPO_ROOT/docs/sdk/framework-integrations.md`
- Official SDK install/readiness guide: `$AETHELRED_REPO_ROOT/docs/sdk/official-sdks.md`
- SDK release provenance policy: `docs/security/release-provenance.md`
- SDK release provenance verification guide: `docs/security/release-verification-guide.md`
- SDK release provenance machine status: `docs/security/release-provenance-status.md`

## CLI Tools (Version Matrix Compatibility)

| Tool | Version | Notes |
|---|---:|---|
| [`aeth`](./cli/aeth) | 2.0.0 | Developer CLI / local testnet / diagnostics |

## Per-SDK READMEs

- Python: `$AETHELRED_REPO_ROOT/sdk/python/README.md`
- TypeScript: `$AETHELRED_REPO_ROOT/sdk/typescript/README.md`
- Rust: `$AETHELRED_REPO_ROOT/sdk/rust/README.md`
- Go: `$AETHELRED_REPO_ROOT/sdk/go/README.md`
