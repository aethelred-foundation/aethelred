# Release Branch Test Failures -- Requires SQ03/SQ05 Immediate Attention

Date: 2026-03-27
Branch: release/testnet-v1.0 (after merge from feat/dapps-protocol-updates)

## Fixed Issues

### 1. Proto typeURL conflict (FIXED)
- **File**: `x/ibc/types/msgs.go`
- **Root cause**: Hand-written proto messages (`MsgRelayProof`, `MsgRequestProof`, `MsgSubscribeProofs`) lacked `XXX_MessageName()`, causing typeURL collision at `/`
- **Fix**: Added `XXX_MessageName()` returning unique FQN (`aethelred.ibc.v1.MsgRelayProof`, etc.)
- **Result**: `TestNewApp_NoPanic` now PASS

### 2. TEE attestation missing BlockHeight (FIXED)
- **File**: `app/vote_extension_test.go`
- **Root cause**: `makeValidTEEAttestationWithUserData` did not set `BlockHeight` or `ChainID`, which `ValidateStrict` now requires
- **Fix**: Added `BlockHeight: 100`, `ChainID: "aethelred-testnet-1"`, and bound UserData computation
- **Result**: `TestVoteExtension_ValidateStrict_AcceptsSignedExtension` now PASS

## Remaining Failures -- SQ03/SQ05 Must Fix

### 3. Process proposal integration tests (4 failures)
- **Tests**: `TestProcessProposal_FinalityAcceptsValidInjectedTx`, `FinalityRejectsMissingInjectedTx`, `FinalityRejectsTamperedConsensusPower`, `FinalityRejectsInjectedTxWhenCacheMissing`
- **Root cause**: `consensusHandler.AggregateVoteExtensions()` returns empty results. The security hardening in `x/pouw/keeper/consensus.go` added mandatory signing enforcement (lines 782-791) and production mode checks. Test vote extensions lack signatures and may fail the `productionVerificationMode` check.
- **Fix needed**: Update `makeVoteExtensionForJob()` in `process_proposal_integration_test.go` to produce properly signed vote extensions with valid TEE attestations, or ensure test mode flags are set correctly.
- **Owner**: SQ03 Lead (E011) + SQ05 Lead (E021)
- **Severity**: BLOCKER for Gate 2 (Go Test Suite)

### 4. PoUW keeper test failures (3 failures)
- **Tests**: `TestCB7_NoDuplicateValidatorCapabilitiesInvariant`, `TestCB7_QueryServer_ValidatorStats_NotFound`, `TestCB7_MsgServer_SubmitJob_NilRequest`
- **Root cause**: CB7 (Circuit Breaker 7) tests likely depend on new keeper state initialization that changed in the merge
- **Owner**: SQ03 Lead (E011)
- **Severity**: HIGH for Gate 5 (PoUW E2E)

### 5. Verify keeper test failures (4 failures)
- **Tests**: `TestZKVerifierPrecompileAndSystemVerifier`, `TestZKVerifierVerifyProofErrors`, `TestZKVerifierFailsClosedWithoutSystemVerifier`, `TestZKVerifierValidProofs/groth16`
- **Root cause**: ZK verifier tests may reference updated proof types or system verifier initialization
- **Owner**: SQ05 Lead (E021)
- **Severity**: HIGH for Gate 2 (Go Test Suite)

## Summary

| Package | Total Failures | Fixed | Remaining | Owner |
|---------|---------------|-------|-----------|-------|
| app/ | 6 | 2 | 4 | SQ03 |
| x/pouw/keeper | 3 | 0 | 3 | SQ03 |
| x/verify/keeper | 4 | 0 | 4 | SQ05 |
| **Total** | **13** | **2** | **11** | |

## What Passed on Release Branch

- Go build: PASS
- Rust workspace compile: PASS (16 binaries, 25 warnings)
- Fuzz check: PASS (all 4 crates, 10 targets)
- Exploit simulations: PASS (7/7 scenarios)
- SDK version check: (running)
- IBC keeper tests: PASS
- Seal tests: PASS
- Validator tests: PASS
