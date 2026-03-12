# Formal Verification Plan

**Version**: 1.0
**Status**: Active
**Last Updated**: 2026-02-28
**Owner**: Security Engineering

---

## 1. Overview

This document defines the formal verification strategy for the Aethelred Protocol.
Formal verification provides mathematical proof that code satisfies its specification,
eliminating entire classes of bugs that testing alone cannot catch.

---

## 2. Scope & Priority

### 2.1 Tier 1 - Must Verify Before Mainnet

| Component | Tool | Properties to Verify |
|-----------|------|----------------------|
| **AethelredToken.sol** | Certora / Halmos | Total supply invariant, blacklist correctness, transfer safety |
| **AethelredVesting.sol** | Certora | Vesting monotonicity, cliff/TGE unlock correctness, no early withdrawal |
| **AethelredBridge.sol** | Certora | Replay protection completeness, rate limit correctness, mint <= deposit |
| **SovereignGovernanceTimelock.sol** | Certora | Dual-signature enforcement, delay bounds, execution-after-timelock |

### 2.2 Tier 2 - Should Verify Before Mainnet v2

| Component | Tool | Properties to Verify |
|-----------|------|----------------------|
| VRF (Rust) | Kani / Creusot | Prove/verify consistency, constant-time execution paths |
| Tokenomics (Go) | Dafny / TLA+ | Emission schedule determinism, supply cap invariant |
| Bridge Processor (Rust) | Kani | State machine transitions, no stuck states |

### 2.3 Tier 3 - Long-term

| Component | Tool | Properties to Verify |
|-----------|------|----------------------|
| Consensus protocol | TLA+ | Safety (no two conflicting blocks finalized), liveness |
| VM runtime | Kani | Memory safety, WASM execution bounds |
| P2P networking | Spin / TLA+ | Message delivery guarantees, partition tolerance |

---

## 3. Solidity Verification (Certora / Halmos)

### 3.1 AethelredToken.sol - Key Invariants

```
// INV-1: Total supply is constant after deployment (no mint function)
invariant totalSupplyConstant()
    totalSupply() == INITIAL_SUPPLY
    { preserved { ... } }

// INV-2: Blacklisted addresses cannot send or receive
rule blacklistedCannotTransfer(address from, address to, uint256 amount) {
    require blacklisted[from] || blacklisted[to];
    transfer@withrevert(from, to, amount);
    assert lastReverted;
}

// INV-3: circulatingSupply() <= totalSupply()
invariant circulatingSupplyBounded()
    circulatingSupply() <= totalSupply()

// INV-4: Only COMPLIANCE_ROLE can blacklist
rule onlyComplianceCanBlacklist(address account, bool status) {
    env e;
    require !hasRole(COMPLIANCE_ROLE, e.msg.sender);
    setBlacklisted@withrevert(e, account, status);
    assert lastReverted;
}

// INV-5: Batch blacklist bounded by MAX_BATCH_BLACKLIST_SIZE
rule batchBlacklistBounded(address[] accounts) {
    require accounts.length > MAX_BATCH_BLACKLIST_SIZE;
    batchSetBlacklisted@withrevert(accounts, true);
    assert lastReverted;
}
```

### 3.2 AethelredVesting.sol - Key Invariants

```
// INV-1: Vested amount is monotonically non-decreasing
rule vestedMonotonicity(bytes32 scheduleId, uint256 t1, uint256 t2) {
    require t1 <= t2;
    uint256 v1 = computeVestedAmount(scheduleId, t1);
    uint256 v2 = computeVestedAmount(scheduleId, t2);
    assert v2 >= v1;
}

// INV-2: Released amount never exceeds vested amount
invariant releasedBoundedByVested(bytes32 scheduleId)
    schedule[scheduleId].released <= computeVestedAmount(scheduleId, block.timestamp)

// INV-3: Total vested across all schedules <= token balance of contract
invariant contractSolvency()
    sumOfAllVested() <= token.balanceOf(address(this))

// INV-4: TGE unlock happens at schedule start, cliff at start + cliffDuration
rule tgeUnlockAtStart(bytes32 scheduleId) {
    VestingSchedule s = schedule[scheduleId];
    uint256 vested = computeVestedAmount(scheduleId, s.start);
    assert vested == s.totalAmount * s.tgeUnlockBps / BPS_BASE;
}
```

### 3.3 AethelredBridge.sol - Key Invariants

```
// INV-1: No withdrawal can be processed twice (replay protection)
rule noDoubleWithdrawal(bytes32 burnTxHash) {
    require processedWithdrawals[burnTxHash];
    processWithdrawal@withrevert(..., burnTxHash, ...);
    assert lastReverted;
}

// INV-2: Total minted in a window <= rate limit
invariant rateLimitEnforced()
    currentWindowMinted <= maxMintPerWindow

// INV-3: Per-block mint ceiling enforced
rule perBlockCeilingEnforced(uint256 amount) {
    require amount > maxMintPerBlock;
    mintTokens@withrevert(amount);
    assert lastReverted;
}
```

---

## 4. Rust Verification (Kani)

### 4.1 VRF Module

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn vrf_prove_verify_consistency() {
        let seed: [u8; 32] = kani::any();
        kani::assume(seed != [0u8; 32]);

        let keys = VrfKeys::from_seed(&seed).unwrap();
        let engine = VrfEngine::new();
        let input: [u8; 64] = kani::any();

        let (proof, output) = engine.prove(&keys, &input).unwrap();
        let verified = engine.verify(keys.public_key(), &input, &proof).unwrap();

        assert_eq!(output, verified);
    }

    #[kani::proof]
    fn vrf_deterministic() {
        let seed: [u8; 32] = kani::any();
        kani::assume(seed != [0u8; 32]);

        let keys = VrfKeys::from_seed(&seed).unwrap();
        let engine = VrfEngine::new();
        let input: [u8; 32] = kani::any();

        let (_, out1) = engine.prove(&keys, &input).unwrap();
        let (_, out2) = engine.prove(&keys, &input).unwrap();

        assert_eq!(out1, out2);
    }
}
```

### 4.2 Tokenomics Module

```rust
#[cfg(kani)]
mod verification {
    #[kani::proof]
    fn vested_amount_bounded() {
        let total: u128 = kani::any();
        let elapsed: u64 = kani::any();
        let duration: u64 = kani::any();
        kani::assume(duration > 0);
        kani::assume(total <= 10_000_000_000 * 1_000_000_000_000_000_000u128);

        let vested = compute_vested(total, elapsed, duration);
        assert!(vested <= total);
    }
}
```

---

## 5. Protocol Verification (TLA+)

### 5.1 Consensus Safety

```tla
---- MODULE AethelredConsensus ----
\* Safety: No two conflicting blocks are finalized at the same height
Safety == \A h \in Heights:
    Cardinality({b \in FinalizedBlocks : b.height = h}) <= 1

\* Liveness: If a transaction is submitted, it is eventually included
Liveness == \A tx \in SubmittedTxs:
    <>(tx \in IncludedTxs)

\* VRF Fairness: Over time, each validator is elected proportional to stake
VRFFairness == \A v \in Validators:
    eventually(ElectionCount(v) / TotalElections ~= Stake(v) / TotalStake)
====
```

---

## 6. Execution Plan

| Phase | Timeline | Deliverable |
|-------|----------|-------------|
| Phase 1: Certora specs for Token + Vesting | Testnet launch | Verified invariants, CI integration |
| Phase 2: Certora specs for Bridge + Governance | Pre-mainnet | Full Solidity coverage |
| Phase 3: Kani proofs for VRF + Tokenomics | Pre-mainnet | Rust verification harness |
| Phase 4: TLA+ consensus model | Mainnet v2 | Protocol safety proof |

---

## 7. CI Integration

Formal verification runs will be integrated into CI:

```yaml
# .github/workflows/formal-verification.yml
formal-verification:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run Certora Prover
      run: certoraRun contracts/certora/*.conf
    - name: Run Kani (Rust)
      run: cargo kani --harness vrf_prove_verify_consistency
    - name: Run Halmos (Symbolic)
      run: halmos --contract AethelredToken --function check_
```

---

## 8. References

- [Certora Prover Documentation](https://docs.certora.com/)
- [Kani Rust Model Checker](https://model-checking.github.io/kani/)
- [Halmos Symbolic Testing](https://github.com/a16z/halmos)
- [TLA+ Specification Language](https://lamport.azurewebsites.net/tla/tla.html)
