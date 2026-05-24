# Audit Readiness Snapshot — 2026-05-24

This note records the local audit-readiness sweep completed on
`ramesh/audit-readiness-20260524` before the branch is merged back to
`main`.

## Local Baseline

- Repository: `aethelred-foundation/aethelred`
- Working branch: `ramesh/audit-readiness-20260524`
- Sweep start baseline: `b91128405d`
- Current local head: `272efd294a`
- Working tree status at closeout: `clean`

## What This Sweep Changed

### Security and Dependency Remediation

- Replaced literal development nonce buffers in
  `crates/core/src/pillars/secret_mempool.rs` with randomized development-only
  byte generation to close the active nonce finding.
- Refreshed audit-facing dependency lines in:
  - root `go.mod` / `go.sum`
  - `sdk/typescript`
  - `integrations/apps/nextjs-verifier`
  - `tools/cli/aethel`
  - `contracts`
  - Rust lockfiles in `crates`, `sdk/rust`, `tools/testnet`, and
    `crates/bridge/fuzz`
- Restored the declared `tools/testnet` CLI entrypoint so the package matches
  its Cargo manifest again.

### Repository Hygiene

- Removed the tracked `sdk/go/.cache/go-build` cache tree from version control.
- Removed the stray tracked archive
  `contracts/contracts/AethelredToken.sol.zip`.
- Aligned `.gitignore` with the actual repo contract:
  - committed TypeChain bindings are no longer treated as ignored build output
  - committed `test-results/` and `loadtest-results/` evidence is no longer
    hidden behind local-output ignore rules
  - tracked `.cargo/config.toml` is no longer masked by the Cargo ignore rule
  - `cmd/aethelredd/...` source is no longer shadowed by the binary ignore rule

### Contracts Toolchain Consistency

- Refreshed the Hardhat toolchain and related contract dev dependencies in
  `contracts/package.json`.
- Regenerated the committed TypeChain binding surface under
  `contracts/typechain-types` so the repository matches the refreshed local
  contracts toolchain.

## Local Validation Completed

The following checks were run successfully during this sweep:

- `go test ./...`
- `go test ./...` from `sdk/go`
- `cargo test --manifest-path crates/Cargo.toml -p aethelred-core secret_mempool -- --nocapture`
- `cargo check --manifest-path sdk/rust/Cargo.toml`
- `cargo check --manifest-path tools/testnet/Cargo.toml`
- `cargo check --manifest-path crates/bridge/fuzz/Cargo.toml`
- `npm audit --omit=dev --json` in `sdk/typescript`
- `npm audit --omit=dev --json` in `integrations/apps/nextjs-verifier`
- `npm audit --omit=dev --json` in `tools/cli/aethel`
- `npm audit --json` in `contracts`
- `npx hardhat build` in `contracts`
- `npx hardhat test mocha test/bridge.emergency.test.ts` in `contracts`

## Remaining Blockers

This branch is materially cleaner and closer to audit-ready, but two blockers
still remain outside the local code changes themselves:

1. GitHub Actions / CodeQL validation for PR `#149` is blocked by the current
   GitHub billing lock, so the branch cannot yet prove itself through remote
   checks.
2. The default branch cannot reflect the local dependency and code-scanning
   improvements until this branch is merged.

## Commit Trail For This Sweep

- `74086c8da2` `hygiene: remove tracked sdk cache artifacts`
- `272efd294a` `contracts: refresh hardhat toolchain and regenerate bindings`

These commits are additive to the earlier audit-readiness work already present
on this branch.
