# Threat Matrix

**Version:** 1.0
**Status:** Active
**Owner:** Security Engineering
**Classification:** Internal -- Share with auditors and security partners
**Last Updated:** 2026-03-25
**Companion Document:** [threat-model.md](threat-model.md)

---

## 1. Purpose

This threat matrix catalogs known attack vectors against the Aethelred Protocol, their assessed impact and likelihood, existing mitigations, and the test artifacts that validate each mitigation. It is organized by attack category and is intended to be maintained as a living document alongside the threat model.

Every entry in this matrix must have an associated test owner and a test artifact that can be executed to verify the mitigation is effective.

---

## 2. Risk Rating Key

| Rating | Impact Description | Likelihood Description |
|--------|-------------------|----------------------|
| **H** (High) | Fund loss, consensus break, or chain halt | Actively exploited in similar systems or trivially achievable |
| **M** (Medium) | Service degradation, partial data loss, or economic distortion | Requires moderate effort or insider access |
| **L** (Low) | Minor inconvenience, informational disclosure | Requires significant effort, unlikely conditions |

---

## 3. Consensus Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| CON-01 | **Long-Range Attack** | Attacker acquires old validator keys and forks the chain from a historical block, presenting an alternative (longer) chain history. | H | L | Weak subjectivity checkpoints enforced at epoch boundaries; light clients require recent trusted headers; bonding period exceeds checkpoint interval. | Consensus Team | `x/lightclient/keeper/checkpoint_test.go` |
| CON-02 | **Grinding Attack** | Proposer manipulates block contents (transaction ordering, timestamps) to bias VRF output for favorable future leader elections. | H | M | VRF output is bound to the full block hash including vote extensions; grinding resistance via epoch-locked seed chain; detection via `aethelred_vrf_verification_failures` metric. | Consensus Team | `x/pouw/keeper/vrf_grinding_test.go`, `scripts/chaos/validator-loss.sh` |
| CON-03 | **Nothing-at-Stake** | Validators sign multiple conflicting blocks at the same height since there is no inherent cost (in pure PoS). | H | M | Slashing for equivocation (double-signing) enforced by CometBFT evidence reactor; tombstoning prevents re-entry; evidence submitted within unbonding period. | Consensus Team | `x/validator/keeper/slashing_test.go` |
| CON-04 | **Validator Collusion (>1/3)** | Colluding validators withhold votes or produce conflicting blocks to halt or manipulate consensus. | H | L | Economic security model requires supermajority (2/3+1); on-chain liveness slashing for prolonged downtime; geographic and entity diversity requirements for genesis set. | Consensus Team | `scripts/chaos/network-partition.sh` |
| CON-05 | **Eclipse Attack** | Attacker isolates a validator by controlling all its P2P connections, feeding it a false view of the network. | M | M | Sentry node architecture with multiple ISPs; persistent peer list with authenticated identities; peer scoring and rotation; minimum peer count alert (`cometbft_p2p_peers < 3`). | SRE / Consensus | `internal/consensus/peer_scoring_test.go` |
| CON-06 | **Time Manipulation** | Attacker manipulates block timestamps to affect VRF seeds, epoch transitions, or vesting schedules. | M | L | BFT time (median of validator timestamps); maximum clock skew enforced by CometBFT; NTP monitoring on validators. | Consensus Team | `app/abci_test.go` (timestamp validation) |

---

## 4. Bridge Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| BRG-01 | **Deposit Replay** | Attacker replays a legitimate deposit proof to mint tokens multiple times on Aethelred. | H | M | Deposit nonce tracking with uniqueness constraint; each deposit indexed by `(srcChainId, txHash, logIndex)` tuple; duplicate check in `x/ibc` bridge module. | Bridge Team | `x/ibc/keeper/replay_test.go` |
| BRG-02 | **Double-Spend via Reorg** | Attacker deposits ETH, waits for Aethelred mint, then causes an Ethereum reorg to reverse the deposit while keeping minted tokens. | H | M | 64-block confirmation depth (>12 minutes); reorg detection in bridge relayer; automatic bridge pause on reorg event; rate limiting per window. | Bridge Team | `crates/bridge/src/reorg_test.rs`, `scripts/drills/bridge-pause-drill.sh` |
| BRG-03 | **Relay Manipulation** | Compromised bridge relayer submits fraudulent mint/burn messages. | H | L | Multi-relayer quorum (k-of-n signatures required); relayer bond with slashing; on-chain verification of Ethereum state proofs (MPT proof against block header). | Bridge Team | `crates/bridge/src/relay_verification_test.rs` |
| BRG-04 | **Rate Limit Exhaustion** | Attacker exhausts bridge rate limits with many small deposits to DoS legitimate users. | M | M | Per-address and global rate limits in `AethelredBridge.sol`; minimum deposit threshold; rate limit utilization monitoring > 80% triggers P2 alert. | Bridge Team | `contracts/test/AethelredBridge.rateLimit.t.sol` |
| BRG-05 | **Withdrawal Front-Running** | Attacker observes a pending withdrawal and front-runs it to extract MEV or manipulate the withdrawal queue. | M | M | Encrypted mempool for bridge transactions; time-locked withdrawal processing; withdrawal queue is FIFO with no reordering. | Bridge Team | `crates/mempool/src/encrypted_test.rs` |

---

## 5. Governance Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| GOV-01 | **Timelock Bypass** | Attacker finds a way to execute governance actions without waiting for the mandatory delay period. | H | L | `SovereignGovernanceTimelock.sol` enforces minimum 7-day delay on all key rotations; delay is immutable in constructor; monitoring alert if `getMinDelay() < 7 days`. | Security Team | `contracts/test/SovereignGovernanceTimelock.t.sol` |
| GOV-02 | **Guardian Key Compromise** | Attacker obtains guardian private key and can pause/unpause contracts, rotate keys, or blacklist addresses. | H | L | 3-of-5 multisig for guardian actions; HSM-stored keys with FIPS 140-3 Level 3; key rotation drill quarterly; emergency key revocation procedure. | Security Team | `scripts/hsm/preflight-check.sh`, `contracts/test/GovernanceTimelock.guardian.t.sol` |
| GOV-03 | **Malicious Governance Proposal** | Attacker submits a governance proposal that appears benign but contains malicious parameter changes. | M | M | 7-day timelock for all parameter changes; mandatory audit review for code-changing proposals; proposal simulation in fork environment before execution. | Governance Team | `contracts/test/SovereignGovernanceTimelock.proposal.t.sol` |
| GOV-04 | **Governance Takeover** | Attacker acquires enough voting power to pass arbitrary proposals. | H | L | Token-weighted voting with delegation caps; Foundation veto power during initial governance bootstrap; quorum requirements; time-locked execution. | Governance Team | Protocol economic analysis (off-chain) |

---

## 6. Verifier Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| VER-01 | **Proof Forgery (zkML)** | Attacker generates a valid-looking but fraudulent zero-knowledge proof that passes on-chain verification. | H | L | Multiple proof system support (EZKL, RISC Zero, Groth16, Halo2, Plonky2) with cross-verification; verification key pinned on-chain and rotated via governance; trusted setup ceremony for Groth16. | Verification Team | `x/verify/keeper/proof_verification_test.go` |
| VER-02 | **TEE Escape** | Attacker breaks out of the TEE enclave to execute arbitrary code, forge attestations, or extract secrets. | H | L | Defense in depth: TEE attestation verified on-chain + zkML proof required; multiple TEE vendor support (SGX + Nitro); attestation freshness check (< 10 min); measurement hash pinned on-chain. | Verification Team | `services/tee-worker/attestation_test.rs`, `internal/tee/attestation_test.go` |
| VER-03 | **Attestation Replay** | Attacker replays a valid but stale TEE attestation to bypass verification for a different computation. | M | M | Attestation nonce binding to specific job ID; freshness window (600s max age); attestation age monitored via `aethelred_attestation_age_seconds`. | Verification Team | `x/verify/keeper/attestation_freshness_test.go` |
| VER-04 | **Simulated Verification Bypass** | Simulated (non-real) verification accepted on production chain, bypassing the entire verification pipeline. | H | L | `aethelred_simulated_verification_total` metric fires P0 alert on any non-dev chain; chain ID check in verification pipeline; compile-time feature flag for simulation mode. | Security Team | `app/verification_pipeline_test.go` |
| VER-05 | **Model Poisoning** | Attacker submits a poisoned AI model that produces subtly incorrect results while passing verification. | M | M | Model hash pinned at job submission; deterministic execution in TEE; output validation against reference dataset for registered models; reputation scoring for model submitters. | Verification Team | `crates/vm/src/model_integrity_test.rs` |

---

## 7. Economic Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| ECON-01 | **MEV Extraction** | Validators or searchers extract maximal extractable value by reordering, inserting, or censoring transactions. | M | H | Encrypted mempool (threshold encryption); proposer-builder separation roadmap; MEV-share mechanism for fair redistribution; monitoring of abnormal proposer revenue. | Protocol Team | `crates/mempool/src/encrypted_test.rs` |
| ECON-02 | **Token Inflation Attack** | Attacker exploits a minting bug or bridge flaw to inflate token supply beyond the 10B cap. | H | L | Fixed supply enforced in `AethelredToken.sol` with `totalSupply` invariant; P0 alert on any deviation from 10B * 1e18; bridge minting rate-limited per window. | Security Team | `contracts/test/AethelredToken.supply.t.sol` |
| ECON-03 | **Vesting Schedule Manipulation** | Attacker accelerates or redirects vesting schedules to unlock tokens prematurely. | H | L | `AethelredVesting.sol` schedules are immutable after creation; revocation only by governance with timelock; cliff enforcement in smart contract. | Token Team | `contracts/test/AethelredVesting.t.sol` |
| ECON-04 | **PoUW Reward Gaming** | Validator submits trivial or fake AI jobs to collect PoUW rewards without performing useful computation. | M | M | Minimum job complexity requirements; TEE attestation proving actual execution; reward scaling based on model registry and job difficulty; reputation scoring for repeated trivial submissions. | Consensus Team | `x/pouw/keeper/reward_validation_test.go` |
| ECON-05 | **Validator Stake Concentration** | Single entity accumulates excessive stake, approaching or exceeding the Byzantine threshold. | H | M | Maximum stake cap per validator (configurable via governance); delegation diversity requirements; Nakamoto coefficient monitoring; foundation delegation strategy to maintain decentralization. | Protocol Team | `x/validator/keeper/stake_cap_test.go` |
| ECON-06 | **Fee Market Manipulation** | Attacker floods the mempool with high-fee transactions to crowd out legitimate users (economic DoS). | M | M | EIP-1559-style dynamic fee mechanism; per-account transaction limits; priority mempool with fair ordering; gas price floor and ceiling. | Protocol Team | `crates/mempool/src/fee_market_test.rs` |

---

## 8. Infrastructure Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| INFRA-01 | **DDoS on RPC Endpoints** | Volumetric or application-layer DDoS targeting public RPC nodes. | M | H | Cloudflare/CDN in front of public RPCs; rate limiting per IP; sentry node architecture isolates validators from public traffic; geographic redundancy. | SRE Team | Load test (`make loadtest-scenarios`) |
| INFRA-02 | **Supply Chain Attack** | Compromised dependency or build tooling injects malicious code. | H | M | Dependabot with auto-merge disabled; SLSA Level 3 build provenance; reproducible builds; dependency pinning with hash verification; `go.sum` and `Cargo.lock` committed. | Security Team | `scripts/validate-repo-auditability.py` |
| INFRA-03 | **Secret Exfiltration** | Attacker extracts HSM PINs, API keys, or private keys from infrastructure. | H | L | HSM-stored keys (FIPS 140-3); no secrets in environment variables (use secret manager); TLS everywhere; audit logging on all key access; regular secret rotation. | SRE / Security | `scripts/hsm/preflight-check.sh`, `scripts/validate-compose-security.sh` |
| INFRA-04 | **DNS Hijacking** | Attacker redirects DNS for RPC endpoints, explorer, or bridge UI to phishing infrastructure. | M | M | DNSSEC enabled; certificate transparency monitoring; HSTS preload; multiple DNS providers; monitoring for unexpected DNS changes. | SRE Team | Certificate monitoring (external) |

---

## 9. Validator Set Attacks

| ID | Threat | Description | Impact | Likelihood | Mitigation | Test Owner | Test Artifact |
|----|--------|-------------|--------|------------|------------|------------|---------------|
| VAL-01 | **Validator Jailing Cascade** | Coordinated attack or software bug causes mass jailing, dropping active set below 2/3 quorum, halting the chain. | H | M | Jailing rate limits (max validators jailed per epoch); automatic unjailing after downtime window; `x/crisis` module for emergency parameter adjustments; consensus halt recovery drill. | SRE Team | `scripts/drills/consensus-halt-drill.sh`, `scripts/chaos/validator-loss.sh` |
| VAL-02 | **Validator Centralization / Cartel** | Small number of entities control majority of validators via Sybil identities, enabling censorship or MEV extraction. | H | M | Validator set cap; delegation concentration limits; encrypted mempool prevents front-running; geographic and jurisdictional diversity requirements; Nakamoto coefficient monitoring. | Governance Team | `x/validator/keeper/stake_cap_test.go`, monitoring dashboards |
| VAL-03 | **HSM Failure / Key Loss** | Hardware failure in a validator's HSM causes signing key loss, taking the validator offline. Correlated failures across same HSM vendor amplify impact. | M | M | HSM preflight checks with failover testing; key backup ceremonies with wrapping keys; firmware version compatibility validation; dual-HSM deployment for critical validators. | SRE Team | `scripts/hsm/preflight-check.sh --failover` |
| VAL-04 | **Validator Key Exfiltration** | Attacker extracts consensus signing key from compromised validator infrastructure. | H | L | HSM-backed signing (non-extractable keys); CKA_SENSITIVE and CKA_EXTRACTABLE flags enforced; signer failover path; double-sign evidence auto-jailing; key rotation procedures. | SRE / Security | `scripts/hsm/preflight-check.sh` (key attribute validation) |
| VAL-05 | **Coordinated Validator Downtime** | Attacker targets validator infrastructure (DDoS, power, network) to bring multiple validators offline simultaneously. | H | M | Geographic and provider diversity; sentry node architecture; auto-restart with staggered recovery; circuit breaker for cascade detection. | SRE Team | `scripts/drills/consensus-halt-drill.sh` (staggered restart validation) |

---

## 10. High-Risk Abuse Paths

The following paths represent the highest-priority exploit scenarios with assigned test or drill ownership:

| # | Abuse Path | Attack Chain | Severity | Test/Drill Coverage | Owner | Status |
|---|-----------|-------------|----------|-------------------|-------|--------|
| 1 | Bridge fund drain | Relayer key compromise -> forge withdrawal proof -> drain escrow | H | `scripts/drills/bridge-pause-drill.sh`, Foundry fuzz tests, CircuitBreaker rate limit tests | Bridge Team | Drilled |
| 2 | Consensus halt via upgrade | Push malicious upgrade -> vote extensions break -> chain halts | H | `scripts/drills/consensus-halt-drill.sh`, `make test-consensus`, upgrade simulation | Consensus Team | Drilled |
| 3 | zkML proof forgery | Exploit verifier bug -> submit false proof -> wrong inference accepted | H | Fuzzing campaign, multi-prover cross-check, formal verification | Cryptography Team | In progress |
| 4 | Validator mass jailing | Trigger software bug -> mass downtime -> quorum loss -> halt | H | `scripts/chaos/validator-loss.sh`, `scripts/drills/consensus-halt-drill.sh` | SRE Team | Drilled |
| 5 | TEE attestation bypass | Forge attestation -> run unverified compute -> poison results | H | Attestation verification tests, enclave measurement allowlist | Verification Team | Tested |
| 6 | Governance takeover | Accumulate voting power -> pass malicious proposal -> exploit chain | H | Governance parameter tests, timelock enforcement, `SovereignGovernanceTimelock.t.sol` | Governance Team | Tested |
| 7 | Bridge reorg double-spend | Deep ETH reorg -> deposit on abandoned fork -> withdraw on Aethelred | H | Foundry reorg simulation, finality depth tests, `scripts/drills/bridge-pause-drill.sh` | Bridge Team | Tested |
| 8 | Encrypted mempool bypass | Extract pending tx content -> front-run via MEV | M | Encrypted mempool integration tests, `crates/mempool/src/encrypted_test.rs` | Consensus Team | Tested |
| 9 | HSM correlated failure | Same-vendor HSM bug -> multiple validators lose signing keys -> quorum loss | H | `scripts/hsm/preflight-check.sh --failover`, firmware version checks | SRE Team | Drilled |

---

## 11. Exploit Scenario Backlog

Scenarios queued for future drill development or testing:

| # | Scenario | Priority | Target Quarter | Assigned To |
|---|----------|----------|---------------|-------------|
| 1 | Multi-validator coordinated equivocation attack | High | Q2 2026 | Consensus Team |
| 2 | Cross-chain replay attack via IBC proof manipulation | High | Q2 2026 | Bridge Team |
| 3 | PQC (Dilithium3/Kyber) key recovery under quantum simulation | Medium | Q3 2026 | Cryptography Team |
| 4 | TEE side-channel data extraction under controlled conditions | Medium | Q3 2026 | Verification Team |
| 5 | Governance proposal with time-delayed malicious execution | Medium | Q2 2026 | Governance Team |
| 6 | WASM VM escape via crafted precompile input | High | Q2 2026 | VM Team |
| 7 | Sustained economic attack on PoUW reward distribution | Medium | Q3 2026 | Protocol Team |
| 8 | Network-level eclipse attack on new validator syncing | Medium | Q3 2026 | SRE Team |
| 9 | Bridge griefing via dust deposits consuming rate limit budget | Low | Q3 2026 | Bridge Team |
| 10 | Validator set manipulation via strategic unbonding timing | Medium | Q2 2026 | Consensus Team |

---

## 12. Maintenance

### 12.1 Adding a New Threat

1. Assign an ID following the category prefix pattern (e.g., `CON-07`, `BRG-06`).
2. Fill in all columns including test owner and test artifact.
3. If no test artifact exists, create one before merging the threat entry.
4. Update the companion [threat-model.md](threat-model.md) if the threat affects the trust boundary diagram.

### 12.2 Quarterly Review

- Review all threat entries for accuracy of impact/likelihood ratings.
- Verify test artifacts still pass.
- Add new threats discovered during audits, bug bounty, or incident response.
- Archive threats that are no longer applicable (do not delete).

---

## 13. Related Documents

- [threat-model.md](threat-model.md) -- Detailed threat model with trust boundaries and asset inventory
- [MONITORING.md](MONITORING.md) -- Alert thresholds referenced in mitigations
- [SECURITY_RUNBOOKS.md](SECURITY_RUNBOOKS.md) -- Incident response procedures
- [FUZZING.md](FUZZING.md) -- Fuzz testing coverage
- [FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md) -- Formal verification status
- [hsm-requirements.md](hsm-requirements.md) -- HSM requirements for key management
