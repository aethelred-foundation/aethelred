# Contributing to Aethelred

Thank you for contributing! This document explains how to participate in the Aethelred project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Commit Format](#commit-format)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [DCO Sign-Off](#dco-sign-off)

---

## Code of Conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md). Be kind, constructive, and inclusive.

---

## Ways to Contribute

- **Bug reports**: [Open an issue](https://github.com/aethelred-foundation/aethelred/issues/new?template=bug_report.md)
- **Feature proposals**: [Open a feature request](https://github.com/aethelred-foundation/aethelred/issues/new?template=feature_request.md) or [write an AIP](https://github.com/aethelred-foundation/AIPs)
- **Code**: Fork → branch → PR
- **Documentation**: PRs to [aethelred-docs](https://github.com/aethelred-foundation/aethelred-docs)
- **Discussion**: [Discord](https://discord.gg/aethelred)

---

## Development Setup

**Requirements**: Go 1.22+, Rust 1.75+, Docker, `buf` (protobuf), `golangci-lint`

```bash
# Clone
git clone https://github.com/aethelred-foundation/aethelred.git
cd aethelred

# Install Go tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install Rust tools
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Start local testnet
make local-testnet-up

# Run all tests
make test
cargo test --workspace --manifest-path crates/Cargo.toml
```

---

## Commit Format

We use **Conventional Commits**:

```
<type>(<scope>): <description>

[optional body]

[optional footer: Closes #N, Signed-off-by: ...]
```

**Types**: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`, `ci`, `security`

**Scopes**: `pouw`, `seal`, `verify`, `abci`, `bridge`, `sdk`, `cli`, `infra`, `proto`

**Examples**:
```
feat(pouw): add reputation-scaled reward distribution
fix(verify): reject simulated TEE platform in strict mode
security(abci): bind TEE user_data to block height and chain ID
```

---

## Pull Request Process

1. **Fork** and create a branch: `git checkout -b feat/my-feature`
2. **Write tests** - new code must have unit tests; consensus changes need integration tests
3. **Run locally**: `make test && cargo test --workspace --manifest-path crates/Cargo.toml`
4. **Update CHANGELOG.md** under `[Unreleased]`
5. **Sign your commits** (DCO, see below)
6. **Open PR** against `main` - fill in the PR template completely
7. **Respond to review** - address all comments before requesting re-review

PRs require:
- CI passing (all jobs)
- At least 1 approving review from a core maintainer
- No unresolved conversations

---

## Coding Standards

### Go
- Follow `gofmt` formatting (enforced by CI)
- Use `sdkmath.Int` everywhere - **no `float64` in consensus-critical code**
- All errors must be handled - no `_ = err` in production paths
- Write table-driven tests using `t.Run`
- Use `ctx sdk.Context` - never mock consensus state

### Rust
- Follow `rustfmt` (enforced by CI)
- `clippy` warnings are errors in CI (`-D warnings`)
- Use `thiserror` for error types
- Document public APIs with `///`

### Protobuf
- All new message types go in `proto/aethelred/<module>/v1/`
- Run `make proto-gen` after changes
- Never change existing field numbers

---

## DCO Sign-Off

All commits must include a DCO (Developer Certificate of Origin) sign-off:

```bash
git commit -s -m "feat(pouw): add my feature"
```

This adds `Signed-off-by: Your Name <email@example.com>` to the commit message, indicating you agree to the [DCO](https://developercertificate.org/).

---

## Security Vulnerabilities

Please do NOT open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure.
