# Verification Pipeline Modes

Date: 2026-03-27
Owner: SQ05

## Mode Summary

| Mode | TEE | zkML | Vote Extensions | Use Case |
|------|-----|------|-----------------|----------|
| Production | Real TEE (SGX/Nitro) | Real proofs | Signed, validated | Mainnet |
| Testnet | Simulated TEE | Simulated proofs | Signed, validated | Public testnet |
| Development | Mock TEE | Mock proofs | Optional | Local dev |

## Fail-Closed Behavior

Production mode (`AllowSimulated=false`) enforces:

1. `app/readiness.go`: `RunProductionReadinessChecks` panics on:
   - Missing verification endpoints
   - Unreachable verification dependencies
   - Missing PQC configuration

2. `app/abci.go`: Strict mode rejects:
   - Unsigned vote extensions
   - Simulated TEE attestations
   - Missing proof hashes

3. `app/allow_simulated_prod.go`: Compile-time assertion that production builds never allow simulated mode.

## Testnet Configuration

Testnet uses:
- `TEE_MODE=simulated` or `TEE_MODE=mock-tee`
- `AllowSimulated=true` on both `x/pouw` and `x/verify` params
- Vote extensions are still signed and validated (same as production)
- Consensus thresholds are the same as production

## Verification Pipeline Flow

1. Job submitted -> `x/pouw` schedules via VRF
2. Validator executes in TEE (or simulated TEE)
3. Validator generates vote extension with proof hash
4. `ExtendVote` signs the extension
5. `VerifyVoteExtension` validates signature and proof
6. `PrepareProposal` aggregates extensions
7. `ProcessProposal` verifies aggregated proofs
8. `x/verify` stores verification result on-chain
9. `x/seal` creates attestation seal

## Test Coverage

- `x/verify/keeper`: negative paths for malformed proofs, replayed proofs, expired attestations
- `x/seal/keeper`: seal creation, verification, revocation
- `app/process_proposal_integration_test.go`: full pipeline integration
- `app/vote_extension_test.go`: vote extension signing and validation
