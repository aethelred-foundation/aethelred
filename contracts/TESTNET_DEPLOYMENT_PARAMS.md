# Testnet Deployment Parameters

Status: Pre-launch | Last updated: 2026-03-27

This document specifies which contracts deploy at testnet launch, their constructor
and initialization parameters, and which controls are active day one versus gated
behind drill passes.

---

## Deployment Order

Contracts must be deployed in dependency order:

1. **SovereignGovernanceTimelock** (no dependencies)
2. **AethelredToken** (UUPS proxy; admin = timelock)
3. **AethelredVesting** (UUPS proxy; depends on token address)
4. **SovereignCircuitBreakerModule** (depends on stablecoin + oracle addresses)
5. **AethelredBridge** (UUPS proxy; depends on token address + timelock)
6. **InstitutionalStablecoinBridge** (UUPS proxy; depends on timelock + governance keys)
7. **StAETHEL** (UUPS proxy; depends on Cruzible address)
8. **VaultTEEVerifier** (depends on Cruzible address)
9. **Cruzible** (UUPS proxy; depends on token + StAETHEL + VaultTEEVerifier)

Post-deployment wiring:
- Grant `MINTER_ROLE` on AethelredToken to AethelredVesting
- Register AethelredBridge as an authorized bridge on AethelredToken
- Grant `VAULT_ROLE` on StAETHEL to Cruzible

---

## 1. SovereignGovernanceTimelock

**Deploys at testnet launch: YES**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `minDelay` | 604800 (7 days) | Matches `MIN_KEY_ROTATION_DELAY` |
| `proposers` | [testnet-ops-multisig] | Addresses with PROPOSER_ROLE |
| `executors` | [testnet-ops-multisig] | Addresses with EXECUTOR_ROLE |
| `admin` | testnet-ops-multisig | Must be a contract on non-local chains |

---

## 2. AethelredToken (AETHEL)

**Deploys at testnet launch: YES**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `admin` | testnet-ops-multisig | Receives DEFAULT_ADMIN_ROLE, PAUSER_ROLE, BURNER_ROLE, COMPLIANCE_ROLE, UPGRADER_ROLE |
| `minter` | AethelredVesting address | Receives MINTER_ROLE |
| `initialRecipient` | testnet treasury address | Receives initial mint |
| `initialAmount` | TBD (testnet allocation) | Must be <= TOTAL_SUPPLY_CAP |

### Day-one active controls
- Transfer restrictions: **ENABLED** (pre-TGE default)
- Pause capability: **ACTIVE** (not paused)
- Blacklist: **ACTIVE** (empty list)
- Supply cap enforcement: **ACTIVE**

### Gated until drill passes
- Bridge authorization: **NOT CONFIGURED** until bridge deployment drill passes
- COMPLIANCE_BURN_ROLE: **NOT GRANTED** until compliance drill passes

---

## 3. AethelredVesting

**Deploys at testnet launch: YES**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `admin` | testnet-ops-multisig | DEFAULT_ADMIN_ROLE |
| `token` | AethelredToken proxy address | AETHEL token |
| `tgeTime` | 0 (set later via triggerTGE) | TGE not triggered at deploy |

### Day-one active controls
- Category caps: **CONFIGURED** per tokenomics table
- Schedule creation: **ACTIVE** via VESTING_ADMIN_ROLE
- Revocation: **ACTIVE** via REVOKER_ROLE
- Pause: **ACTIVE** (not paused)

### Gated until drill passes
- TGE trigger: **BLOCKED** until tokenomics verification drill passes
- Milestone attestation: **BLOCKED** until attestor key ceremony drill passes

---

## 4. SovereignCircuitBreakerModule

**Deploys at testnet launch: YES (for InstitutionalStablecoinBridge)**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `owner_` | testnet-ops-multisig | Contract owner |
| `stablecoin_` | Test stablecoin address | ERC20 monitored for supply |
| `reserveOracle_` | Testnet Chainlink PoR feed (or mock) | Reserve data source |
| `multiSigWallet_` | testnet-ops-multisig | Can unpause minting |
| `maxDeviationBps_` | 500 (5%) | Trigger threshold |

### Day-one active controls
- Reserve anomaly detection: **ACTIVE**
- Auto-pause on deviation: **ACTIVE**
- Oracle staleness check (24h): **ACTIVE**

---

## 5. AethelredBridge

**Deploys at testnet launch: YES (paused until bridge drill passes)**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `admin` | testnet-ops-multisig | DEFAULT_ADMIN_ROLE |
| `relayerAddresses` | [testnet validator relayer addresses] | Initial relayer set |
| `consensusThresholdBps` | 6700 (67%) | Relayer consensus threshold |
| `rateLimitConfig.maxDepositPerPeriod` | 1000 ETH | Per-hour deposit cap |
| `rateLimitConfig.maxWithdrawalPerPeriod` | 1000 ETH | Per-hour withdrawal cap |
| `rateLimitConfig.enabled` | true | Rate limiting on |
| `mintCeilingPerBlock` | 10 ETH (default) | Per-block mint ceiling |
| `emergencyWithdrawalDelay` | 172800 (48 hours) | Default emergency timelock |

### Day-one active controls
- Rate limiting: **ACTIVE**
- Per-block mint ceiling: **ACTIVE**
- Replay protection: **ACTIVE**
- EIP-712 domain separation: **ACTIVE**
- Challenge period (7 days): **ACTIVE**
- Emergency withdrawal timelock: **ACTIVE**

### Paused until drill passes
- **Contract is PAUSED at deployment** -- deposits and withdrawals disabled
- Unpaused only after ALL bridge launch criteria pass (see BRIDGE_LAUNCH_CRITERIA.md):
  - Replay test pass
  - Rate-limit test pass
  - Accounting test pass
  - Operator drill pass

---

## 6. InstitutionalStablecoinBridge

**Deploys at testnet launch: YES (paused until stablecoin partner onboarding)**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| `admin` | testnet-ops-multisig | DEFAULT_ADMIN_ROLE |
| `issuerGovernanceKey` | Issuer testnet key | Joint unpause signer |
| `foundationGovernanceKey` | Foundation testnet key | Joint unpause signer |
| `auditorGovernanceKey` | Auditor testnet key | Joint unpause signer |
| `guardianGovernanceKey` | Guardian testnet key | Sovereign unpause signer |
| `governanceTimelock` | SovereignGovernanceTimelock address | Key rotation controller |
| `governanceActionDelaySeconds` | 604800 (7 days) | Min delay for config changes |
| `relayerBondRequirement` | 500000 AETHEL (default) | Relayer bond amount |

### Day-one active controls
- Governance key rotation via timelock: **ACTIVE**
- Joint unpause requirement: **ACTIVE**
- Relayer bonding: **ACTIVE**
- EIP-712 typed data: **ACTIVE**

### Paused until drill passes
- Per-asset configurations: **NOT CONFIGURED** until stablecoin partner integration tests pass
- CCTP routing: **DISABLED** until Circle testnet integration verified
- TEE mint flow: **DISABLED** until enclave measurement approved

---

## 7-9. Cruzible, StAETHEL, VaultTEEVerifier

**Deploy at testnet launch: YES**

| Parameter | Testnet Value | Notes |
|-----------|---------------|-------|
| StAETHEL `admin` | testnet-ops-multisig | DEFAULT_ADMIN_ROLE |
| StAETHEL `vaultAddress` | Cruzible proxy address | VAULT_ROLE recipient |
| Cruzible `admin` | testnet-ops-multisig | DEFAULT_ADMIN_ROLE |
| Cruzible `token` | AethelredToken proxy address | Staking token |
| Cruzible `stAETHEL` | StAETHEL proxy address | Share token |

### Day-one active controls
- Minimum stake (32 AETHEL): **ACTIVE**
- Unbonding period (14 days): **ACTIVE**
- Max validators (200): **ACTIVE**
- Delegation challenge period (1 hour): **ACTIVE**
- Keeper bond requirement (100K AETHEL): **ACTIVE**
- Rate limiting (500M AETHEL/epoch): **ACTIVE**
- Pause capability: **ACTIVE**

### Gated until drill passes
- Reward distribution: **BLOCKED** until TEE attestation pipeline verified
- Delegation quorum enforcement: **BLOCKED** until multi-attestor infrastructure deployed
- MEV redistribution: **BLOCKED** until MEV detection pipeline validated

---

## Network-Specific Overrides

| Setting | DevNet (31337) | Testnet (Sepolia) | Mainnet |
|---------|---------------|-------------------|---------|
| Admin must be contract | Bypassed | Enforced | Enforced |
| Consensus threshold | 67% | 67% | 67% |
| Upgrader timelock delay | 27 days | 27 days | 27 days |
| Key rotation delay | 7 days | 7 days | 7 days |
| Bridge challenge period | 7 days | 7 days | 7 days |
| Emergency withdrawal delay | 48 hours | 48 hours | 48 hours |
