## Description

<!-- Explain the what and why of this PR. Link the relevant issue with "Closes #N" -->

Closes #

## Related AIP / Issue / Project

- AIP: <!-- e.g. AIP-003, or N/A -->
- Issue: <!-- e.g. #123 -->
- Project: <!-- e.g. Core Protocol, SDK, Ecosystem Apps -->
- Target Release: <!-- e.g. Testnet, Mainnet v1.1, N/A -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (consensus / API / storage)
- [ ] Performance improvement
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor / chore
- [ ] Release preparation

## Scope

<!-- Which area(s) does this PR affect? -->
- [ ] Protocol (consensus, ABCI++, modules)
- [ ] Contracts (Solidity, bridge)
- [ ] CLI
- [ ] SDK (TS / Python / Go / Rust)
- [ ] VS Code Extension
- [ ] Docs
- [ ] DevOps / CI
- [ ] Infrastructure (Helm / Terraform / Docker)
- [ ] Ecosystem App (Shiora / NoblePay / ZeroID / Cruzible / TerraQura)

## Risk Level

<!-- What is the risk if this change has a defect? -->
- [ ] Low (cosmetic, internal tooling, tests)
- [ ] Medium (non-consensus feature, single SDK)
- [ ] High (cross-module, multi-SDK, operator-facing)
- [ ] Critical (consensus, state transitions, bridge, key management)

## Testing

- [ ] I have added unit tests covering the changed code
- [ ] I have added integration / E2E tests where applicable
- [ ] All existing tests pass (`make test`, `cargo test --workspace`)
- [ ] I have run the local testnet and verified the behaviour (`make local-testnet-up`)

## Security Checklist

- [ ] No floating-point arithmetic in consensus-critical paths
- [ ] All integer arithmetic uses `sdkmath.Int` (no overflow possible)
- [ ] No new `allowSimulated=true` paths in production code
- [ ] No new secrets or keys committed (check with `git secret scan`)
- [ ] TEE attestation binding (BlockHeight + ChainID) preserved where applicable

## Changelog

<!-- Add an entry to CHANGELOG.md under [Unreleased] -->
- [ ] CHANGELOG.md updated

## Documentation

- [ ] In-code comments updated
- [ ] Public API / ABI changes reflected in `proto/` or type definitions
- [ ] Docs site updated (if user-facing change)

## Breaking Change Assessment

- [ ] No breaking change
- [ ] Breaking change to consensus (requires AIP + governance vote)
- [ ] Breaking change to API / SDK (requires major version bump)
- [ ] Breaking change to contract interfaces
- [ ] Migration required

<!-- If breaking, describe the migration path: -->

## Reviewer Notes

<!-- Anything the reviewer should pay special attention to -->
