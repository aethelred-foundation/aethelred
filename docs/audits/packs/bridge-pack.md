# Auditor Pack: Bridge Subsystem

**Squad:** SQ9 (Bridge) + SQ13 (Rust Bridge/VM)
**Last Updated:** 2026-03-25
**Classification:** CONFIDENTIAL - For Auditors Only

---

## 1. Subsystem Overview

- **Name:** Ethereum Bridge (Lock-and-Mint)
- **Squad:** SQ9 (Solidity contracts), SQ13 (Rust relayer)
- **Scope:** Bidirectional asset transfer between Ethereum and Aethelred L1. Includes deposit locking, withdrawal processing with multi-sig relayer consensus, fraud proofs with challenge period, rate limiting, per-block mint ceiling, guardian emergency withdrawals, and EIP-712 typed data signing.
- **Key Source Paths:**
  - `contracts/contracts/AethelredBridge.sol` -- Ethereum-side bridge contract (UUPS upgradeable)
  - `contracts/contracts/AethelredToken.sol` -- Token contract with `bridgeMint`/`bridgeBurn` via `authorizedBridges`
  - `contracts/contracts/SovereignGovernanceTimelock.sol` -- Timelock controlling UPGRADER_ROLE
  - `contracts/contracts/SovereignCircuitBreakerModule.sol` -- Optional external anomaly detection
  - `crates/bridge/` -- Rust relayer service (watches Ethereum events, votes on deposits/withdrawals)
  - `x/ibc/` -- IBC module for cross-chain proof relay (related, owned by SQ3)
- **Language/Stack:** Solidity 0.8.20 (Foundry + Hardhat), Rust 1.75+
- **External Dependencies:** OpenZeppelin Contracts Upgradeable (v5), Ethereum RPC providers, CometBFT event subscriptions

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   ETHEREUM MAINNET                       │
│                                                          │
│  User ──► deposit() ──► Lock ETH/ERC20                  │
│                          │                               │
│                    Emit DepositEvent                     │
│                          │                               │
│  Relayers ──► processWithdrawal()                       │
│                (67% relayer votes + EIP-712 typed data)  │
│                                                          │
│  Guardians ──► emergencyWithdraw()                      │
│                 (2-of-N guardian multi-sig)              │
│                                                          │
│  Controls:                                               │
│   • Rate limiting (max deposit/withdrawal per period)   │
│   • Per-block mint ceiling (defense-in-depth)           │
│   • 7-day fraud proof challenge period                  │
│   • Emergency pause by admin                            │
│   • UUPS upgradeable (timelock-gated)                   │
│   • Chain-fork safe EIP-712 domain separator            │
│                                                          │
│  AethelredBridge.sol ←→ AethelredToken.sol              │
│         │                    (bridgeMint/bridgeBurn)     │
│         └──→ SovereignGovernanceTimelock                │
│         └──→ SovereignCircuitBreakerModule (optional)   │
└──────────────────────────┬──────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │    RELAYER NETWORK       │
              │  (Top 20 Aethelred       │
              │   Validators)            │
              │  crates/bridge/          │
              └────────────┬────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│                   AETHELRED L1                            │
│                                                          │
│  Watch Ethereum Events ──► Vote on Deposits ──► Mint    │
│  Watch Burn Events ──► Vote on Withdrawals ──► Signal   │
│                                                          │
│  crates/bridge/ (Rust relayer service)                   │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Trust Boundaries

| Boundary | From | To | Trust Assumption | Verification Mechanism |
|----------|------|----|------------------|----------------------|
| User to Bridge contract | External user | `AethelredBridge.deposit()` | User provides valid ETH/ERC20 | Contract validates token allowance, deposit limits |
| Relayer consensus | Individual relayer | Bridge contract | Relayers may be Byzantine | 67% vote threshold required for withdrawal processing |
| Bridge to Token | `AethelredBridge` | `AethelredToken.bridgeMint()` | Only authorized bridges can mint | `authorizedBridges` mapping in Token contract |
| Upgrade authority | `SovereignGovernanceTimelock` | `AethelredBridge` (UUPS proxy) | Upgrades are governance-approved | Timelock delay + UPGRADER_ROLE restricted to timelock |
| Ethereum event watching | Ethereum RPC | `crates/bridge/` relayer | Ethereum node provides accurate events | Relayer validates event proofs; consensus among multiple relayers |
| Fraud proof challenge | Anyone (challenger) | Bridge contract | Fraudulent withdrawals can be challenged | 7-day challenge period before withdrawal finalization |
| Guardian emergency | Guardian multi-sig | Bridge contract | Guardians act in good faith | 2-of-N multi-sig requirement |
| Circuit breaker | `SovereignCircuitBreakerModule` | Bridge contract | Anomaly detection may be imperfect | Optional additional defense; does not replace primary controls |
| Rust relayer to L1 | `crates/bridge/` | Aethelred L1 consensus | HTTP/gRPC only (no FFI/CGo) | Protobuf-defined contract (`proto/`) |

---

## 4. Access Control Matrix

| Role | Permissions | Assignment Mechanism | Revocation Mechanism |
|------|-------------|---------------------|---------------------|
| `DEFAULT_ADMIN_ROLE` | Grant/revoke other roles, set rate limits | `initialize()` assigns to deployer | Governance vote or self-renounce |
| `RELAYER_ROLE` | Vote on withdrawals, submit deposit confirmations | Admin grants to top 20 validators | Admin revokes; automatic on validator exit |
| `GUARDIAN_ROLE` | Emergency withdrawal (2-of-N multi-sig) | Admin grants | Admin revokes |
| `PAUSER_ROLE` | Pause/unpause bridge operations | Admin grants | Admin revokes |
| `UPGRADER_ROLE` | Upgrade bridge implementation (UUPS) | `initializeWithTimelock()` assigns to timelock | Only via timelock governance |
| Depositor (any user) | Deposit ETH/ERC20 into bridge | Permissionless | N/A |
| Challenger (any user) | Submit fraud proofs during challenge period | Permissionless | N/A |

---

## 5. Key State Transitions

| State | Trigger | Next State | Validation | Reversible? |
|-------|---------|------------|------------|-------------|
| No Deposit | User calls `deposit()` | Deposit Locked | Token transferred to contract, amount within rate limit, not paused | No (but refundable via withdrawal) |
| Deposit Locked | Relayers observe Ethereum event | Deposit Confirmed on L1 | 67% relayer vote on deposit event | No |
| Deposit Confirmed | L1 mints wrapped token | Tokens Minted | `bridgeMint` called via authorized bridge | No |
| Withdrawal Requested | User burns wrapped token on L1 | Withdrawal Pending | Burn event emitted on L1 | No |
| Withdrawal Pending | Relayers vote on withdrawal | Withdrawal Proposed | 67% relayer threshold + EIP-712 typed data | No |
| Withdrawal Proposed | 7-day challenge period elapses | Withdrawal Finalized | No valid fraud proof submitted | No |
| Withdrawal Proposed | Valid fraud proof submitted | Withdrawal Challenged | Fraud proof verified on-chain | Yes (withdrawal cancelled) |
| Withdrawal Finalized | User claims on Ethereum | Withdrawal Complete | Tokens/ETH released to recipient, per-block mint ceiling check | No |
| Any operational state | Guardian emergency | Emergency Withdrawal | 2-of-N guardian multi-sig | No |
| Any state | Pauser pauses | Bridge Paused | PAUSER_ROLE check | Yes (unpause) |

---

## 6. Known Risks and Mitigations

| Risk ID | Description | Severity | Mitigation | Status |
|---------|-------------|----------|------------|--------|
| B-001 | Bridge drain via compromised relayer majority | Critical | 67% threshold, 7-day fraud proof window, rate limiting, per-block mint ceiling | Mitigated |
| B-002 | UUPS upgrade to malicious implementation | Critical | UPGRADER_ROLE restricted to governance timelock with mandatory delay | Mitigated |
| B-003 | Reentrancy on withdrawal processing | Critical | `ReentrancyGuardUpgradeable`, `SafeERC20` for token transfers | Mitigated |
| B-004 | Rate limit bypass via multiple accounts | Medium | Per-period global rate limit (not per-account) | Mitigated |
| B-005 | EIP-712 domain separator invalid after chain fork | Medium | Domain separator recomputed on chain ID change (chain-fork safe caching) | Mitigated |
| B-006 | Relayer liveness failure (fewer than 67% online) | High | Guardian emergency withdrawal as fallback; relayer rotation from top 20 validators | Mitigated |
| B-007 | Ethereum RPC provider manipulation | Medium | Multiple relayers use independent RPC providers; consensus required | Mitigated |
| B-008 | Per-block mint ceiling too permissive or too restrictive | Medium | Configurable via governance; defense-in-depth (not sole control) | Accepted |
| B-009 | Rust relayer <-> Go chain integration mismatch | Medium | Protobuf-defined contract in `proto/`; HTTP/gRPC only (no FFI) | Mitigated |

---

## 7. Test Evidence

| Evidence Type | Location | Coverage/Result |
|---------------|----------|-----------------|
| Foundry unit tests | `cd contracts && forge test` | Pass (Solidity 0.8.20, optimizer on) |
| Foundry fuzz tests | `forge test` (256 runs default, 100 CI) | Pass |
| Hardhat tests | `cd contracts && npx hardhat test` | Pass |
| Rust relayer tests | `cargo test --workspace --manifest-path crates/Cargo.toml` | Pass |
| Static analysis (Solidity) | `forge build` (compiler warnings = errors) | Zero warnings |
| Static analysis (Rust) | `cargo clippy` | Zero warnings |
| E2E smoke tests | `test-results/e2e-network-smoke-*.txt` | Pass |
| Dynamic exploit simulations | `test-results/dynamic-exploit-simulations.json` | Pass |
| Load tests | `loadtest-results/` via `make loadtest` | See results |
| Go integration tests | `make test-integration` (bridge-related paths) | Pass |

---

## 8. Previous Audit Findings and Remediation

| Finding ID | Auditor | Severity | Description | Status | Remediation |
|------------|---------|----------|-------------|--------|-------------|
| I-06 | Internal review | Informational | Cross-contract dependency documentation incomplete | Fixed | Architecture docs and dependency graph added to contract NatSpec header |
| (27 findings) | External audit (2026-02-28) | Various | All 27 findings addressed per `@custom:audit-status` annotation | Fixed | See `contracts/contracts/AethelredBridge.sol` header: "Remediated - all 27 findings addressed (2026-02-28)" |

*Note: The bridge contract header (`@custom:audit-status`) confirms all 27 external audit findings have been remediated as of 2026-02-28. Detailed finding-by-finding breakdown should be obtained from the external auditor's report.*

---

## Appendix: Rate Limits and Thresholds

These values are configurable via governance. Current defaults should be verified against deployed contract state.

| Parameter | Description | Default |
|-----------|-------------|---------|
| Relayer vote threshold | Percentage of relayers that must agree | 67% |
| Fraud proof challenge period | Time window for fraud proof submission | 7 days |
| Guardian multi-sig threshold | Guardians required for emergency withdrawal | 2-of-N |
| Rate limit period | Rolling window for deposit/withdrawal caps | Configurable |
| Per-block mint ceiling | Maximum tokens mintable in a single block | Configurable |
