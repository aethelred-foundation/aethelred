# Formal Verification Proof Inventory

This document tracks all formal verification proofs across the Aethelred codebase.
It maps each Certora spec rule and Kani harness to its current status.

**Workflow:** `.github/workflows/formal-verification.yml`
**Last updated:** 2026-03-25

## Status Key

| Status | Meaning |
|--------|---------|
| Active | Proof harness/rule exists and is executed in CI |
| Gated | Proof exists but CI job uses `continue-on-error: true` |
| Blocked | Proof exists but cannot run (missing secret, tooling issue) |
| Planned | Proof target identified but harness not yet written |

---

## Certora Proofs (Solidity Contracts)

Certora proofs require the `CERTORAKEY` secret. When the secret is not provisioned,
proof runs are skipped but structure validation still executes.

### AethelredToken (`contracts/certora/specs/AethelredToken.spec`)

| Property | Type | Rule/Invariant Name | Status | Owner |
|----------|------|---------------------|--------|-------|
| Supply cap invariant | invariant | `totalSupplyBounded` | Gated | contracts |
| Remaining mintable consistent | invariant | `remainingMintableConsistent` | Gated | contracts |
| Circulating supply consistent | invariant | `circulatingSupplyConsistent` | Gated | contracts |
| Mint exact amount | rule | `mintExactAmount` | Gated | contracts |
| Mint cannot exceed cap | rule | `mintCannotExceedCap` | Gated | contracts |
| Bridge mint cannot exceed cap | rule | `bridgeMintCannotExceedCap` | Gated | contracts |
| Blacklisted sender cannot transfer | rule | `blacklistedSenderCannotTransfer` | Gated | contracts |
| Blacklisted recipient cannot receive | rule | `blacklistedRecipientCannotReceive` | Gated | contracts |
| Blacklisted cannot transferFrom | rule | `blacklistedCannotTransferFrom` | Gated | contracts |
| Cannot mint to blacklisted | rule | `cannotMintToBlacklisted` | Gated | contracts |
| Cannot bridge-mint to blacklisted | rule | `cannotBridgeMintToBlacklisted` | Gated | contracts |
| Burn tracks amount | rule | `burnTracksAmount` | Gated | contracts |
| BurnFrom tracks amount | rule | `burnFromTracksAmount` | Gated | contracts |
| Compliance burn tracks amount | rule | `complianceBurnTracksAmount` | Gated | contracts |
| Compliance burn requires reason | rule | `complianceBurnRequiresReason` | Gated | contracts |
| Paused blocks transfer | rule | `pausedBlocksTransfer` | Gated | contracts |
| Paused blocks transferFrom | rule | `pausedBlocksTransferFrom` | Gated | contracts |
| Transfer restrictions enforced | rule | `transferRestrictionsEnforced` | Gated | contracts |
| Transfer preserves total supply | rule | `transferPreservesTotalSupply` | Gated | contracts |
| Transfer conserves balance | rule | `transferConservesBalance` | Gated | contracts |

### AethelredBridge (`contracts/certora/specs/AethelredBridge.spec`)

| Property | Type | Rule/Invariant Name | Status | Owner |
|----------|------|---------------------|--------|-------|
| Processed withdrawals never unset | rule | `processedWithdrawalsNeverUnset` | Gated | contracts |
| Cannot replay processed burn tx | rule | `cannotReplayProcessedBurnTx` | Gated | contracts |
| Cannot double-process withdrawal | rule | `cannotDoubleProcessWithdrawal` | Gated | contracts |
| Withdrawal blocked during challenge | rule | `withdrawalBlockedDuringChallengePeriod` | Gated | contracts |
| Challenged withdrawal cannot process | rule | `challengedWithdrawalCannotProcess` | Gated | contracts |
| Relayer cannot double vote | rule | `relayerCannotDoubleVote` | Gated | contracts |
| Mint ceiling is positive | rule | `mintCeilingIsPositive` | Gated | contracts |
| Default mint ceiling correct | rule | `defaultMintCeilingCorrect` | Gated | contracts |
| Deposit nonce increases | rule | `depositNonceIncreases` | Gated | contracts |
| Deposit increases locked ETH | rule | `depositIncreasesLockedETH` | Gated | contracts |
| Blocked address cannot receive | rule | `blockedAddressCannotReceiveWithdrawal` | Gated | contracts |
| Deposits revert when paused | rule | `depositsRevertWhenPaused` | Gated | contracts |
| Process withdrawal reverts when paused | rule | `processWithdrawalRevertsWhenPaused` | Gated | contracts |
| Emergency withdrawal requires approvals | rule | `emergencyWithdrawalRequiresGuardianApprovals` | Gated | contracts |
| Emergency withdrawal bounded | rule | `emergencyWithdrawalBounded` | Gated | contracts |
| Emergency timelock bounds | rule | `emergencyTimelockBounds` | Gated | contracts |
| Process withdrawal decreases locked | rule | `processWithdrawalDecreasesLocked` | Gated | contracts |

### AethelredVesting (`contracts/certora/specs/AethelredVesting.spec`)

| Property | Type | Rule/Invariant Name | Status | Owner |
|----------|------|---------------------|--------|-------|
| Category caps enforced | invariant | `categoryCapsEnforced` | Gated | contracts |
| Category released bounded | invariant | `categoryReleasedBounded` | Gated | contracts |
| Total released bounded | invariant | `totalReleasedBounded` | Gated | contracts |
| Vested amount monotonically increases | rule | `vestedAmountMonotonicallyIncreases` | Gated | contracts |
| Released amount only increases | rule | `releasedAmountOnlyIncreases` | Gated | contracts |
| No release before TGE | rule | `noReleaseBeforeTGE` | Gated | contracts |
| No release-all before TGE | rule | `noReleaseAllBeforeTGE` | Gated | contracts |
| Vested is zero before TGE | rule | `vestedIsZeroBeforeTGE` | Gated | contracts |
| Cliff blocks linear vesting | rule | `cliffBlocksLinearVesting` | Gated | contracts |
| Release exact amount | rule | `releaseExactAmount` | Gated | contracts |
| Release reverts when nothing releasable | rule | `releaseRevertsWhenNothingReleasable` | Gated | contracts |
| Only beneficiary can release | rule | `onlyBeneficiaryCanRelease` | Gated | contracts |
| Revocation preserves vested tokens | rule | `revocationPreservesVestedTokens` | Gated | contracts |
| Cannot release revoked schedule | rule | `cannotReleaseRevokedSchedule` | Gated | contracts |
| Release reverts when paused | rule | `releaseRevertsWhenPaused` | Gated | contracts |

### SovereignGovernanceTimelock (`contracts/certora/specs/SovereignGovernanceTimelock.spec`)

| Property | Type | Rule/Invariant Name | Status | Owner |
|----------|------|---------------------|--------|-------|
| Minimum delay enforced | invariant | `minimumDelayEnforced` | Gated | contracts |
| Min delay is 7 days | rule | `minDelayIs7Days` | Gated | contracts |
| Min delay preserved across operations | rule | `minDelayPreservedAcrossOperations` | Gated | contracts |
| Cannot execute before ready | rule | `cannotExecuteBeforeReady` | Gated | contracts |
| Cannot execute unqueued operation | rule | `cannotExecuteUnqueuedOperation` | Gated | contracts |
| Done operation stays done | rule | `doneOperationStaysDone` | Gated | contracts |
| Cannot double-execute rotation | rule | `cannotDoubleExecuteRotation` | Gated | contracts |
| Cannot double-queue rotation | rule | `cannotDoubleQueueRotation` | Gated | contracts |
| Rotation requires dual signatures | rule | `rotationRequiresDualSignatures` | Gated | contracts |
| Cannot rotate to zero address | rule | `cannotRotateToZeroAddress` | Gated | contracts |
| Cannot rotate with zero bridge | rule | `cannotRotateWithZeroBridge` | Gated | contracts |
| Cannot rotate with expired deadline | rule | `cannotRotateWithExpiredDeadline` | Gated | contracts |
| Rotation rejects insufficient delay | rule | `rotationRejectsInsufficientDelay` | Gated | contracts |

---

## Kani Proofs (Rust Crates)

Kani proofs run via `cargo kani` in CI. Each crate has a `kani_proofs.rs` module
gated behind `#[cfg(kani)]`.

### crates/core (`crates/core/src/kani_proofs.rs`)

| Property | Harness Name | Status | Owner |
|----------|-------------|--------|-------|
| SignatureAlgorithm byte roundtrip | `verify_signature_algorithm_roundtrip` | Gated | core |
| Signature/pubkey sizes always positive | `verify_signature_and_pubkey_sizes_positive` | Gated | core |
| Quantum safety classification correct | `verify_quantum_safety_classification` | Gated | core |
| QuantumThreatLevel monotonicity | `verify_quantum_threat_level_monotonicity` | Gated | core |
| Hash256::from_slice length check | `verify_hash256_from_slice_length_check` | Gated | core |

### crates/consensus (`crates/consensus/src/kani_proofs.rs`)

| Property | Harness Name | Status | Owner |
|----------|-------------|--------|-------|
| compute_multiplier bounded [1.0, 5.0] | `verify_compute_multiplier_bounded` | Gated | consensus |
| compute_multiplier(0) == 1.0 | `verify_compute_multiplier_zero_is_unity` | Gated | consensus |
| Slot/epoch roundtrip consistency | `verify_slot_epoch_roundtrip` | Gated | consensus |
| Epoch boundary iff divisible | `verify_epoch_boundary_consistency` | Gated | consensus |
| Validator jail eligibility logic | `verify_validator_eligibility_jail_logic` | Gated | consensus |

### crates/vm (`crates/vm/src/kani_proofs.rs`)

| Property | Harness Name | Status | Owner |
|----------|-------------|--------|-------|
| Gas meter never exceeds limit | `verify_gas_meter_limit_never_exceeded` | Gated | vm |
| Failed consume preserves state | `verify_gas_meter_reject_preserves_state` | Gated | vm |
| remaining() + used() == limit | `verify_gas_meter_remaining_invariant` | Gated | vm |
| MemoryConfig rejects initial > max | `verify_memory_config_validation_initial_le_max` | Gated | vm |
| initial_bytes <= max_bytes | `verify_memory_config_bytes_ordering` | Gated | vm |
| Memory cost monotonic with bytes | `verify_gas_memory_cost_monotonic` | Gated | vm |

---

## Planned Proof Targets

| Crate/Contract | Property | Tool | Priority |
|----------------|----------|------|----------|
| crates/core | Dilithium3 sign/verify roundtrip | Kani | P2 |
| crates/core | Kyber encaps/decaps roundtrip | Kani | P2 |
| crates/consensus | VRF output uniqueness | Kani | P2 |
| crates/mempool | Priority ordering consistency | Kani | P2 |
| crates/mempool | Capacity invariant | Kani | P2 |
| crates/vm | WASM memory bounds safety | Kani | P3 |

---

## Frequency

| Trigger | Tier 1 (Structure) | Tier 2 (Proofs) |
|---------|-------------------|-----------------|
| Nightly (03:00 UTC) | Yes | Yes |
| PR (relevant paths) | Yes | Yes |
| Manual dispatch | Yes | Yes |
