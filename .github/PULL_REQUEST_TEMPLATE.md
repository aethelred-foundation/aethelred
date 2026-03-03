## Description

<!-- Explain the what and why of this PR. Link the relevant issue with "Closes #N" -->

Closes #

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (consensus / API / storage)
- [ ] Documentation
- [ ] Refactor / chore

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

## Reviewer Notes

<!-- Anything the reviewer should pay special attention to -->
