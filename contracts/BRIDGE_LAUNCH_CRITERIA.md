# Bridge Launch Criteria

Status: Pre-launch | Last updated: 2026-03-27

This document defines the gate conditions for unpausing the AethelredBridge and
InstitutionalStablecoinBridge on testnet, the conditions under which they must be
re-paused, and the ongoing monitoring requirements. It also documents vault
solvency invariants and share-accounting rules for the Cruzible liquid staking vault.

---

## Part 1: Bridge Opening Criteria

The AethelredBridge deploys in a **PAUSED** state. It may only be unpaused after
all four gate categories pass.

### Gate 1: Replay Protection Test Pass

| Test | Acceptance Criteria |
|------|-------------------|
| Duplicate burnTxHash rejection | `processedWithdrawals[burnTxHash]` prevents second proposal for same burn |
| Cross-chain replay | EIP-712 domain separator includes `chainId` and `verifyingContract`; forked-chain proposals rejected |
| Nonce monotonicity | `depositNonce` increments strictly; invariant test `invariant_depositNonceMonotonic` passes |
| Withdrawal proposal deduplication | Same burnTxHash with different proposalId reverts |
| Forge invariant suite | `BridgeInvariant.t.sol::invariant_processedNoncesNeverReused` passes on 10K+ runs |

### Gate 2: Rate-Limit Test Pass

| Test | Acceptance Criteria |
|------|-------------------|
| Deposit cap enforcement | Deposits exceeding `maxDepositPerPeriod` revert within each `RATE_LIMIT_PERIOD` (1 hour) |
| Withdrawal cap enforcement | Withdrawals exceeding `maxWithdrawalPerPeriod` revert within each period |
| Per-block mint ceiling | Cumulative mints within a single block cannot exceed `mintCeilingPerBlock` (default 10 ETH) |
| Deposit bounds | Amounts below `MIN_DEPOSIT` (0.01 ETH) or above `MAX_SINGLE_DEPOSIT` (100 ETH) revert |
| Period rollover | Limits reset correctly at period boundaries |
| Forge invariant suite | `invariant_depositsWithinPeriodLimit`, `invariant_withdrawalsWithinPeriodLimit`, `invariant_mintCeilingPerBlock` pass |

### Gate 3: Accounting Test Pass

| Test | Acceptance Criteria |
|------|-------------------|
| ETH balance conservation | `address(bridge).balance >= totalLockedETH` at all times |
| ERC20 balance conservation | `token.balanceOf(bridge) >= totalLockedERC20[token]` for every supported token |
| Deposit-withdrawal balance | Net deposits minus net withdrawals equals locked balance |
| Emergency withdrawal cap | Single emergency withdrawal cannot exceed `MAX_EMERGENCY_WITHDRAWAL` (50 ETH) |
| Forge invariant suite | `invariant_bridgeBalanceSolvent`, `invariant_lockedETHConsistency`, `invariant_emergencyWithdrawalCapped` pass |

### Gate 4: Operator Drill Pass

| Drill | Acceptance Criteria |
|-------|-------------------|
| Pause drill | Operator can pause bridge within 5 minutes of alert |
| Emergency withdrawal drill | Guardian 2-of-N multisig can queue and execute emergency withdrawal |
| Relayer rotation drill | Admin can add/remove relayers without affecting in-flight proposals (requiredVotesSnapshot) |
| Challenge period drill | Withdrawal waits full 7-day challenge period before execution |
| Rate limit adjustment drill | Admin can increase/decrease rate limits while bridge is live |
| Upgrade drill | UPGRADER_ROLE (via timelock) can schedule and execute proxy upgrade |

---

## Part 2: Bridge Pause Criteria

The bridge MUST be paused immediately if any of the following occur:

### Automatic Pause Triggers
- Circuit breaker module detects reserve anomaly (supply > oracle reserve by > MAX_DEVIATION_BPS)
- Oracle feed returns stale data (> 24 hours since last update)
- Oracle feed returns zero or negative reserve balance

### Manual Pause Triggers (operator override)
- Any accounting discrepancy: `address(bridge).balance < totalLockedETH` or ERC20 equivalent
- Any replay detected: duplicate burnTxHash processed (should be impossible; indicates logic bypass)
- Relayer consensus failure: fewer than `minVotesRequired` relayers available
- Relayer key compromise: suspected or confirmed compromise of any relayer key
- Upstream dependency failure: Ethereum RPC provider outage, Aethelred L1 halt
- Governance emergency: any governance key suspected compromised

### Unpause Process
- **AethelredBridge**: `DEFAULT_ADMIN_ROLE` unpauses after root cause resolved and post-mortem documented
- **InstitutionalStablecoinBridge**: `jointUnpause()` requires signatures from Issuer + Foundation + Auditor (3-of-3); prevents unilateral unpause

---

## Part 3: Monitoring Requirements

### Event Log Alerts

| Event | Alert Level | Response SLA |
|-------|------------|-------------|
| `DepositInitiated` with amount > 50 ETH | WARNING | Review within 1 hour |
| `WithdrawalProposed` | INFO | Log and track |
| `WithdrawalProcessed` | INFO | Verify against Aethelred L1 burn tx |
| `EmergencyWithdrawalQueued` | CRITICAL | Immediate review; verify guardian approvals |
| `EmergencyWithdrawalExecuted` | CRITICAL | Immediate post-mortem |
| `Paused` | CRITICAL | Confirm intentional; begin incident response if unexpected |
| `Unpaused` | WARNING | Verify authorization |
| `DepositCancelled` | WARNING | Review cancellation reason |
| `RateLimitExceeded` (reverted tx) | WARNING | Monitor for sustained pressure |
| `CircuitBreakerTriggered` | CRITICAL | Immediate investigation; do not unpause until resolved |
| `AnomalyDetected` | CRITICAL | Check reserve oracle; verify on-chain supply |
| `MintingPaused` | CRITICAL | Verify circuit breaker triggered correctly |

### Balance Reconciliation

| Check | Frequency | Method |
|-------|-----------|--------|
| ETH balance vs `totalLockedETH` | Every block | Off-chain monitor compares `address(bridge).balance` to `totalLockedETH()` |
| ERC20 balance vs `totalLockedERC20` | Every block | Off-chain monitor compares `token.balanceOf(bridge)` to `totalLockedERC20(token)` for each supported token |
| Cross-chain supply reconciliation | Every hour | Compare total minted on Aethelred L1 to total locked on Ethereum |
| Rate-limit utilization | Every period | Track `rateLimitState[period].totalDeposited` and `totalWithdrawn` as percentage of caps |

### Rate-Limit Utilization Dashboard

| Metric | Threshold | Action |
|--------|-----------|--------|
| Deposit utilization > 80% of period cap | WARNING | Alert ops; consider increasing cap |
| Withdrawal utilization > 80% of period cap | WARNING | Alert ops; consider increasing cap |
| Per-block mint utilization > 50% of ceiling | WARNING | Monitor for batched exploitation attempts |
| Emergency withdrawal queued | CRITICAL | Full team notification; verify guardian legitimacy |

---

## Part 4: InstitutionalStablecoinBridge-Specific Criteria

In addition to the general bridge criteria above, the InstitutionalStablecoinBridge
has additional requirements before per-asset routing is enabled.

### Per-Asset Activation Checklist

For each stablecoin asset (USDC, USDT, etc.):

| Gate | Criteria |
|------|----------|
| Token contract verified | Token address confirmed on target chain; decimals checked |
| Routing type configured | CCTP_V2 or TEE_ISSUER_MINT selected and tested |
| Issuer signers configured | Signer addresses set with threshold (multi-sig) |
| Enclave measurement approved | TEE measurement hash whitelisted (for TEE_ISSUER_MINT) |
| Mint ceiling set | `mintCeilingPerEpoch` configured per risk assessment |
| Daily tx limit set | `dailyTxLimit` configured |
| Outflow caps set | `hourlyOutflowBps` and `dailyOutflowBps` configured |
| PoR feed connected | Chainlink Proof-of-Reserve feed address set and returning valid data |
| PoR deviation threshold set | `porDeviationBps` configured (recommended: 500 bps / 5%) |
| PoR heartbeat configured | `porHeartbeatSeconds` set (recommended: 86400 / 24 hours) |
| Circuit breaker module attached | `circuitBreakerModule` set for the asset |
| Integration test pass | End-to-end mint and redeem tested on testnet |
| Relayer bond posted | All relayers have posted `relayerBondRequirement` |

---

## Part 5: Vault Solvency Invariants

The Cruzible liquid staking vault maintains the following solvency invariants,
enforced on-chain and verified by the `VaultInvariant.t.sol` Foundry test suite.

### Core Invariants

**INV-1: Share Conservation**
```
sum(shares[staker] for all stakers) == _totalShares (StAETHEL)
```
The XOR-based `stakerRegistryRoot` in StAETHEL provides a cryptographic
commitment to the per-staker share distribution, verified against TEE attestation
at reward distribution time.

**INV-2: Exchange Rate Floor**
```
exchangeRate = totalPooledAethel / _totalShares >= 1e18
```
The exchange rate between AETHEL and stAETHEL only increases over time as
rewards accrue. It never decreases below the initial 1:1 peg. Any slash event
reduces `totalPooledAethel` proportionally across all stakers, but the protocol
compensates from the insurance fund to maintain the floor.

**INV-3: Vault Solvency**
```
totalPooledAethel >= sum(pending_withdrawal_amounts)
```
The vault always holds sufficient AETHEL to cover all pending withdrawal requests.
Withdrawals enter a 14-day unbonding queue and are processed FIFO.

**INV-4: Withdrawal Queue Ordering**
```
for all i < j: withdrawalQueue[i].requestTime <= withdrawalQueue[j].requestTime
```
Withdrawal requests are processed in strict FIFO order. No withdrawal can
jump the queue regardless of size or staker identity.

**INV-5: Epoch Monotonicity**
```
currentEpoch only increases; never decreases or skips
```
Epoch numbers are strictly monotonic. Reward distribution is tied to epoch
boundaries (24-hour periods).

**INV-6: Ghost Share Accounting**
```
totalSharesMinted - totalSharesBurned == _totalShares
```
The cumulative mint and burn operations produce a consistent total. Tracked
by ghost variables in the invariant test suite.

**INV-7: Pending Withdrawals Consistency**
```
pendingWithdrawals == sum(active_withdrawal_request_amounts)
```
The aggregate pending withdrawal counter matches the sum of individual
unfulfilled withdrawal requests.

### Share-Accounting Rules

1. **Minting shares**: When a user stakes AETHEL, shares are minted proportionally:
   ```
   shares = (amount * _totalShares) / totalPooledAethel
   ```
   If `_totalShares == 0` (first deposit), `shares = amount`.

2. **Burning shares**: When a user unstakes, shares are burned and an equivalent
   AETHEL amount is queued for withdrawal:
   ```
   aethelAmount = (shares * totalPooledAethel) / _totalShares
   ```

3. **Reward accrual**: The oracle reports new rewards by increasing `totalPooledAethel`.
   This increases the exchange rate for all existing share holders without changing
   share counts.

4. **Protocol fee**: 5% of rewards are taken as protocol fee before distribution.
   MEV redistribution allocates 90% to stakers and 10% to protocol.

5. **Slashing**: If a validator is slashed, `totalPooledAethel` decreases. The
   exchange rate drops proportionally for all stakers delegated to that validator
   (via delegation-weighted distribution). Insurance fund may compensate.

6. **Precision**: Share calculations use `SHARES_PRECISION = 1e27` to minimize
   rounding errors. Maximum total shares capped at `MAX_TOTAL_SHARES = 10B * 1e18`.

### TEE Verification in Reward Distribution

Reward distribution requires:
1. Keeper commits delegation snapshot (via `commitDelegationSnapshot()`)
2. TEE attestation verifies staker registry root matches on-chain `stakerRegistryRoot`
3. Challenge period (1 hour) elapses without fraud flags
4. Delegation commitment is not stale (< 6 hours old)
5. Multi-attestor quorum (2 independent attestors agree on same root)
6. `distributeRewards()` consumes the verified delegation root and distributes
   rewards proportionally to each validator's delegated stake

This pipeline ensures no single party can manipulate reward distribution. The
keeper provides delegation state, the TEE verifies it against the on-chain staker
set, challengers can flag fraud, and the guardian can slash fraudulent keepers.
