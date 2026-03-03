# Aethelred Testnet: Institutional Stablecoin Integration (TRD V2)

## Document Metadata

| Attribute | Value |
|-----------|-------|
| **Target Team** | Smart Contract & Protocol Engineering |
| **Network Scope** | Aethelred Testnet |
| **Version** | TRD V2 |
| **Status** | Engineering Implementation Baseline |
| **Date** | February 2026 |

## Objective

Deploy institutional stablecoin infrastructure for **USDC, USDT, USDU, and DDSC** with:

- Zero-liquidity-pool routing
- Attested reserve verification
- Multi-party circuit breakers
- Explicit issuer-sovereign mint authority controls

---

## 1. Bridge Architecture & Minting Authority

### 1.1 USDC Integration (Circle CCTP V2)

- Integrate Circle CCTP V2 path using `TokenMessengerV2` + `MessageTransmitterV2`.
- Use native burn-and-mint routing (no wrapped USDC representation on Aethelred).
- Preserve direct domain-based transfer semantics for CCTP burn messages.
- Support fast-transfer relays via Iris-attester signature verification (`relayCCTPFastMessage`) before message execution.

### 1.2 DDSC & USDU Integration (TEE Relayers + Issuer Multi-Sig)

- Operate relayer workflow on AWS Nitro Enclave-attested infrastructure.
- **Critical authority model**:
  - TEE relayers are execution conduits only.
  - Mint authorization is issuer sovereign control (e.g., issuer-controlled 3-of-5).
  - Contract must reject mint attempts without valid issuer signature quorum.
  - Oracle/monitoring data cannot bypass issuer signature requirements.
- Composition wiring: map sovereign assets to external circuit-breaker modules via `setCircuitBreakerModule(assetId, module)` so mint flow checks module pause state before finalizing.
- Signer governance is issuer-exclusive: signer set updates are accepted only from the issuer governance key and constrained to fixed 3-of-5 threshold sets.

---

## 2. Reserve Verification (PoR & Attested Feeds)

### 2.1 Chainlink Proof of Reserve (Attested Feeds)

- Integrate Chainlink PoR attested feeds as reserve telemetry source.
- Model standard reconciliation lag using heartbeat-aware checks.
- Do not require millisecond parity against off-chain banking systems.

### 2.2 Anomaly Pause Behavior (Not Per-Tx Auto-Revert)

- Remove mint-time strict oracle `revert()` gating.
- Implement monitor-driven anomaly logic:
  - If deviation exceeds configured threshold (e.g., 0.5%), trigger `pause()` on further mint operations.
  - Current transaction flow is not automatically reverted solely due to feed lag/anomaly.
  - Resume requires governed investigation + joint unpause flow.

### 2.3 Merkle Audit Supplement

- Record Merkle-root audit artifacts as supplementary cryptographic trail.
- Expose on-chain proof verification (`verifyReserveMerkleProof`) so auditors can validate inclusion proofs against the latest recorded root.
- Treat this as additive to legally mandated external audit confirmations (e.g., Big 4 / ADGM workflows).

---

## 3. Institutional Risk Parameters & Circuit Breakers

### 3.1 Fractional Mint Quotas

- Enforce per-asset mint ceilings over 24-hour epochs.
- Govern risk-limit changes through governance-controlled config updates (can be routed through external timelock governance).
- Ensure no single automated pathway can bypass quota constraints.
- Mint attempts above ceiling hard-revert even with valid issuer signatures.

### 3.2 Velocity Limits (Time-Weighted Outflows)

- Enforce rolling outflow controls per stablecoin:
  - Hourly outflow thresholds in the 3% to 5% range
  - Daily outflow threshold around 10%
- Trigger protective controls when thresholds are breached.

### 3.3 Multi-Party Circuit Breakers

- Trigger automated global `pause()` on:
  - PoR anomalies
  - Velocity limit breaches
  - Daily transaction/volume limit breaches

### 3.4 Joint Unpause Governance (Critical Update)

- Aethelred governance cannot unilaterally unpause.
- `unpause()` enforces sovereign 3-of-5 quorum:
  - FAB Treasury (Issuer anchor)
  - FAB Compliance / Board (Issuer redundancy)
  - Aethelred Foundation
  - Independent auditor / custody key
  - ADQ / regulator guardian key
- Golden rule enforced on-chain:
  - Minimum 3 valid signatures required
  - At least one signer must be an issuer key (Treasury or Compliance)
- Key wiring:
  - `setSovereignUnpauseKeys(issuerRecoveryKey, guardianKey)` configures keys 2 and 5.
  - `unpauseWithJointSignatures(actionId, deadline, signatures[])` evaluates the 3-of-5 anchored quorum.

### 3.5 Governance Timelock for Key Rotation

- Governance key rotation is implemented through an OpenZeppelin `TimelockController` contract.
- Rotation delay is hard-floor constrained to 48 hours.
- Queueing a rotation requires issuer + foundation signatures over the rotation payload before scheduling.

---

## 4. DDSC Context (Program Assumption)

For TRD V2 implementation scope, DDSC is treated as:

- A UAE Central Bank-approved, 1:1 AED-backed stablecoin
- Launched in February 2026 by IHC, Sirius International Holding, and FAB
- Operating on ADI Chain as a compliance-ready sovereign L2
- Focused on institutional payments and trade finance workflows

---

## 5. Reference Implementation (This Repository)

- Contract: `contracts/ethereum/contracts/InstitutionalStablecoinBridge.sol`
- Circuit-breaker interface: `contracts/ethereum/contracts/interfaces/ISovereignCircuitBreaker.sol`
- Drop-in circuit-breaker module: `contracts/ethereum/contracts/SovereignCircuitBreakerModule.sol`
- Governance timelock: `contracts/ethereum/contracts/SovereignGovernanceTimelock.sol`
- Mocks:
  - `contracts/ethereum/contracts/mocks/MockMintableBurnableERC20.sol`
  - `contracts/ethereum/contracts/mocks/MockTokenMessengerV2.sol`
  - `contracts/ethereum/contracts/mocks/MockMessageTransmitterV2.sol`
  - `contracts/ethereum/contracts/mocks/MockAggregatorV3.sol`
- Tests: `contracts/ethereum/test/institutional.stablecoin.integration.test.ts`

---

## 6. Acceptance Criteria (Testnet)

1. USDC CCTP outflow path executes burn-routing without LP custody assumptions.
2. USDU/DDSC minting fails without issuer quorum signatures.
3. USDC fast-transfer relay path validates Iris attester signatures before `receiveMessage`.
4. PoR monitor triggers mint pause and global pause on threshold breach.
5. Velocity breach triggers circuit-breaker pause.
6. Unpause succeeds only with valid 3-of-5 sovereign signatures including at least one issuer key.
7. Issuer signer set management is issuer-exclusive and fixed to 3-of-5.
8. Merkle reserve proofs verify against recorded audit roots.
9. Mint attempts above daily ceiling revert.
10. Oracle feed silence beyond 24 hours triggers circuit-breaker pause via anomaly checks.
11. Governance key rotation is timelocked for at least 48 hours and requires issuer + foundation proposal consent.
