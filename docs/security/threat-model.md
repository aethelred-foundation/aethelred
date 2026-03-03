# Aethelred Protocol — Threat Model

**Version**: 2.0
**Status**: Active (Reviewed 2026-02-28)
**Owner**: Security Engineering
**Classification**: Internal — Share with auditors and security partners
**Last Updated**: 2026-02-28

---

## 1. System Scope

### 1.1 In Scope

The Aethelred Protocol is a sovereign Layer-1 blockchain purpose-built for
verifiable AI compute (Proof of Useful Work). This threat model covers:

| Component | Repository Path | Language | Description |
|-----------|-----------------|----------|-------------|
| Cosmos SDK Node | `app/`, `x/pouw/`, `x/verify/`, `x/seal/` | Go | L1 blockchain: consensus, state machine, ABCI handlers |
| Smart Contracts | `contracts/` | Solidity | ERC-20 token, vesting, bridge, governance timelock, circuit breaker |
| Bridge Relayer | `crates/bridge/` | Rust | Bi-directional Ethereum <-> Aethelred asset bridge |
| Consensus Engine | `crates/consensus/` | Rust | VRF leader election, PoUW validation, epoch management |
| VM Runtime | `crates/vm/` | Rust | WASM VM for AI model execution, system contract precompiles |
| Core Crypto | `crates/core/` | Rust | Hybrid ECDSA + Dilithium3, key management, hash primitives |
| TEE Worker | `services/tee-worker/` | Rust | SGX/Nitro enclave attestation and AI execution |
| SDK | `sdk/` | TS/Py/Go | Client libraries for developers |

### 1.2 Out of Scope

- Third-party infrastructure (AWS, GCP, Cloudflare)
- End-user application logic built on top of the SDK
- Social engineering attacks against personnel
- Physical security of data centers

---

## 2. Assets (Ranked by Impact)

### 2.1 Critical Assets

| Asset | Location | Impact of Compromise |
|-------|----------|----------------------|
| **Validator consensus keys** | HSM / TEE-sealed storage | Byzantine fault: can forge blocks, halt consensus |
| **Bridge treasury** | AethelredBridge.sol custody | Direct fund theft of all bridged ETH/ERC-20 |
| **Governance keys** (Issuer, Foundation, Auditor) | SovereignGovernanceTimelock.sol | Can blacklist addresses, rotate all keys, seize funds |
| **Token supply integrity** | AethelredToken.sol `totalSupply` | Inflation attack, economic collapse |
| **VRF secret keys** | Validator memory (zeroized on drop) | Leader election manipulation, MEV extraction |

### 2.2 High Assets

| Asset | Location | Impact of Compromise |
|-------|----------|----------------------|
| Bridge relayer keys | `crates/bridge/` config | Can propose fraudulent mint/withdrawal |
| TEE measurement hashes | `x/verify` on-chain params | Accept forged attestations |
| Vesting schedules | AethelredVesting.sol | Premature token unlock, schedule manipulation |
| Digital Seal integrity | `x/seal` module | Forge verifiable AI compute certificates |
| Epoch seed randomness | Consensus VRF output chain | Predictable leader election |

### 2.3 Medium Assets

| Asset | Location | Impact of Compromise |
|-------|----------|----------------------|
| Rate limit state | AethelredBridge.sol | DoS via rate limit exhaustion |
| Compliance blacklist | AethelredToken.sol | Block legitimate users or unblock sanctioned |
| Node P2P identities | CometBFT config | Eclipse attacks, network partitioning |
| API keys / RPC endpoints | Infrastructure config | Service disruption, data exfiltration |

---

## 3. Trust Boundaries

```
                         UNTRUSTED                     TRUSTED
                    ┌──────────────┐            ┌──────────────────┐
                    │   Internet   │            │   Validator Set  │
                    │   Users      │───TB1──────│   (2/3 honest)   │
                    │   Attackers  │            │                  │
                    └──────────────┘            └────────┬─────────┘
                                                        │
                           TB2                          │ TB3
                    ┌──────────────┐            ┌───────▼──────────┐
                    │   Ethereum   │────────────│   Bridge Relayer │
                    │   L1 Chain   │            │   (multi-sig)    │
                    └──────────────┘            └──────────────────┘
                                                        │
                           TB4                          │ TB5
                    ┌──────────────┐            ┌───────▼──────────┐
                    │   TEE Enclave│────────────│   AI Compute     │
                    │   (attested) │            │   Workers        │
                    └──────────────┘            └──────────────────┘
```

### TB1: Client <-> Validator
- Transactions are signed; validators verify signatures
- RPC inputs are untrusted; full validation required
- P2P gossip is unauthenticated at the message level

### TB2: Ethereum <-> Bridge
- Ethereum finality assumed after 64 confirmations (post-merge)
- Bridge trusts Ethereum block headers (no light client verification yet)
- Relay transactions require multi-sig or guardian approval

### TB3: Consensus <-> Application
- ABCI boundary: CometBFT delivers blocks, app validates state transitions
- Vote extensions carry AI verification attestations (validated per VERIFICATION_POLICY.md)

### TB4: TEE <-> Host
- Attestation quotes bind computation output to enclave identity
- Host is untrusted; enclave must defend against all host-level attacks
- Attestation freshness: quotes must be < 10 minutes old

### TB5: Supply Chain
- Vendored dependencies in `vendor/` (pinned, audited)
- CI artifacts signed; reproducible builds planned for mainnet
- Cargo.lock and go.sum committed and verified

---

## 4. Adversary Model

### 4.1 Remote Unauthenticated Attacker
- **Capabilities**: Send arbitrary transactions, connect to P2P/RPC endpoints
- **Goals**: Steal funds, halt consensus, manipulate AI compute results
- **Relevant attacks**: Transaction malleability, RPC abuse, eclipse attacks, bridge replay

### 4.2 Malicious Validator (< 1/3 Stake)
- **Capabilities**: Propose blocks, vote, produce VRF proofs, submit vote extensions
- **Goals**: MEV extraction, selective censorship, leader election manipulation
- **Relevant attacks**: Equivocation, VRF grinding, attestation forgery, selfish mining

### 4.3 Compromised Bridge Operator
- **Capabilities**: Submit mint/withdrawal proposals, relay messages between chains
- **Goals**: Mint unbacked tokens, steal bridged assets
- **Relevant attacks**: Double-spend, replay, front-running, rate limit bypass

### 4.4 Malicious SDK Consumer
- **Capabilities**: Use SDK with arbitrary inputs, reverse-engineer protocols
- **Goals**: Find input combinations that trigger bugs, bypass validation
- **Relevant attacks**: Integer overflow inputs, malformed proofs, gas griefing

### 4.5 Supply Chain Attacker
- **Capabilities**: Compromise a dependency, inject malicious code in CI
- **Goals**: Backdoor cryptographic primitives, exfiltrate keys
- **Relevant attacks**: Dependency confusion, typosquatting, CI pipeline injection

---

## 5. Threat Scenarios & Mitigations

### 5.1 Consensus Layer

| ID | Threat | Severity | Mitigation | Status |
|----|--------|----------|------------|--------|
| T-C1 | VRF timing side-channel leaks leader election | Critical | RFC 9380 constant-time hash-to-curve (RS-01 fix) | Fixed |
| T-C2 | Equivocation (double-voting) | Critical | CometBFT evidence handling, automatic slashing | Active |
| T-C3 | VRF key extraction from memory | High | Zeroize-on-drop for secret keys (RS-07 fix) | Fixed |
| T-C4 | Epoch seed manipulation | High | VRF output chaining, 2/3 validator agreement | Active |
| T-C5 | Long-range attack | Medium | Weak subjectivity checkpoints (Cosmos SDK) | Active |
| T-C6 | Selfish mining / withholding | Medium | Proposer timeout, round-robin fallback | Active |

### 5.2 Bridge Layer

| ID | Threat | Severity | Mitigation | Status |
|----|--------|----------|------------|--------|
| T-B1 | Bridge replay attack | Critical | burnTxHash-keyed replay protection (C-03 verified) | Active |
| T-B2 | Mint unbacked tokens | Critical | Multi-sig guardian, rate limiting, per-block ceiling | Active |
| T-B3 | Ethereum reorg invalidates deposits | High | 64-block confirmation depth (L-02 fix) | Fixed |
| T-B4 | Rate limit exhaustion DoS | Medium | clearExpiredRateLimitState() gas refund (M-03 fix) | Fixed |
| T-B5 | Emergency pause bypass | Medium | Circuit breaker with 24h-14d bounded timelock (M-07) | Active |
| T-B6 | Cross-layer denomination mismatch | Critical | UAETHEL_TO_WEI_SCALE constants at both layers (C-02 fix) | Fixed |

### 5.3 Token & Vesting Layer

| ID | Threat | Severity | Mitigation | Status |
|----|--------|----------|------------|--------|
| T-T1 | Integer overflow in vesting calculation | Critical | math/big for all intermediate calculations (C-01 fix) | Fixed |
| T-T2 | Batch blacklist gas DoS | High | MAX_BATCH_BLACKLIST_SIZE=200 bound (H-02 fix) | Fixed |
| T-T3 | Schedule ID collision (front-running) | Medium | Removed block.timestamp from hash (M-04 fix) | Fixed |
| T-T4 | releaseAll() unbounded loop | Medium | MAX_SCHEDULES_PER_BENEFICIARY guard (M-06 fix) | Fixed |
| T-T5 | Recovered tokens sent to wrong address | Low | Explicit recipient parameter (L-04 fix) | Fixed |

### 5.4 Governance Layer

| ID | Threat | Severity | Mitigation | Status |
|----|--------|----------|------------|--------|
| T-G1 | Unauthorized key rotation | Critical | Dual signature (Issuer + Foundation) + 7-day timelock | Active |
| T-G2 | Storage layout collision on upgrade | High | uint256[50] __gap in all upgradeable contracts (H-05 fix) | Fixed |
| T-G3 | Admin key compromise | High | AdminMustBeContract check (no EOA admins on mainnet) | Active |

### 5.5 AI Verification Layer

| ID | Threat | Severity | Mitigation | Status |
|----|--------|----------|------------|--------|
| T-V1 | Forged TEE attestation | Critical | Quote validation, measurement binding, nonce freshness | Active |
| T-V2 | Phantom job vote extension | High | Job existence check in VerifyVoteExtension | Active |
| T-V3 | Output mismatch in hybrid verification | High | Fail-closed: both results rejected on mismatch | Active |
| T-V4 | Simulated verification on production | Critical | Dual AllowSimulated flag, CI genesis linting | Active |

---

## 6. Existing Controls

### 6.1 Code-Level Controls

- **Overflow protection**: `math/big` (Go), `u128`/checked arithmetic (Rust), SafeMath (Solidity via 0.8.x)
- **Constant-time crypto**: RFC 9380 hash-to-curve, `subtle.ConstantTimeCompare` (Go), `subtle` crate (Rust)
- **Key zeroization**: `zeroize` crate with `ZeroizeOnDrop` derive
- **Input validation**: Strict type checking, bounds validation, duplicate detection
- **Domain-separated hashing**: All hashes prefixed with unique domain tags
- **Replay protection**: Nonces, burn-tx-hash keying, EIP-712 typed data

### 6.2 Configuration-Level Controls

- **Feature flags**: `#[cfg(feature = "vrf")]` / `#[cfg(feature = "full-pqc")]` gating
- **Environment guards**: `AETHELRED_PRODUCTION_MODE` for non-constant-time code paths (now eliminated)
- **Genesis linting**: CI rejects `AllowSimulated=true` in non-dev genesis configs
- **Minimum delays**: 7-day key rotation timelock, 24h-14d emergency timelock bounds

### 6.3 CI/CD Controls

- **Dependency vendoring**: All Rust/Go deps vendored and pinned
- **Static analysis**: `clippy`, `golangci-lint`, `slither` for Solidity
- **Test gates**: Unit, integration, and property tests must pass before merge
- **Reproducible builds**: Planned for mainnet release

### 6.4 Operational Controls

- **Key management**: HSM-backed keys, Shamir secret sharing for cold keys
- **Monitoring**: Prometheus metrics, PagerDuty alerts, security dashboard
- **Access control**: RBAC, MFA, VPN-gated admin access
- **Incident response**: Documented playbook with 1h SLA for SEV-1

---

## 7. Known Gaps & Assumptions

### 7.1 Assumptions

1. **Honest majority**: >= 2/3 of validator stake is honest (BFT assumption)
2. **Ethereum finality**: 64 confirmations is sufficient for finality (no deep reorgs)
3. **TEE trust**: Intel SGX / AWS Nitro enclaves are not compromised at the hardware level
4. **Clock synchronization**: Validator clocks are within 1 minute of each other
5. **Network synchrony**: Messages are delivered within bounded time (partial synchrony)

### 7.2 Known Gaps (Pre-Mainnet)

| Gap | Risk | Plan | Target |
|-----|------|------|--------|
| No Ethereum light client in bridge | Must trust relay operators | Implement light client verification | Mainnet v2 |
| No formal verification of Solidity contracts | Undiscovered invariant violations | Certora/Halmos formal verification campaign | Pre-mainnet |
| Limited fuzz testing coverage | Edge-case bugs in parsing/crypto | Integrate cargo-fuzz + Foundry fuzzing | Testnet |
| No reproducible builds | Supply chain risk | Bazel or Nix-based reproducible build system | Pre-mainnet |
| Single guardian key for bridge | Single point of compromise | Migrate to multi-sig guardian set | Testnet |

---

## 8. Required Tests & Evidence

### 8.1 Security-Critical Test Matrix

| Category | Test Type | Coverage Target | Tool |
|----------|-----------|-----------------|------|
| VRF correctness | Unit + property | 100% of prove/verify paths | `cargo test`, `proptest` |
| VRF constant-time | Timing analysis | No input-dependent branches | Manual review + `dudect` |
| Bridge replay | Integration | All replay vectors tested | Foundry fork tests |
| Token overflow | Property | All arithmetic paths | `proptest`, Foundry fuzz |
| Vesting calculation | Unit + boundary | Cliff, TGE, linear vesting | `go test`, Foundry |
| Consensus safety | Integration | Equivocation, timeout, partition | CometBFT test harness |
| TEE attestation | Integration | Valid/invalid/stale/forged quotes | Mock TEE + unit tests |
| Key rotation | Integration | Timelock, dual-sig, execution | Foundry + Hardhat |

### 8.2 Test Coverage Targets

| Layer | Current | Target | Deadline |
|-------|---------|--------|----------|
| Go (consensus, modules) | ~75% | >90% | Testnet launch |
| Rust (bridge, consensus, VM) | ~70% | >90% | Testnet launch |
| Solidity (contracts) | ~80% | >95% | Pre-mainnet |

---

## 9. Review & Update Schedule

- **Quarterly**: Full threat model review by security engineering
- **Per-release**: Delta review for new features and attack surface changes
- **Post-incident**: Immediate update for any security incident
- **Post-audit**: Update after each external audit engagement

---

## 10. References

- [Verification Policy](./VERIFICATION_POLICY.md) — AI verification security invariants
- [Gating Plan](./GATING_PLAN.md) — Production vs. development simulation gating
- [Best Practices](./best-practices.md) — Operational security checklist
- [HSM Requirements](./hsm-requirements.md) — Hardware security module specifications
- [Validator Runbook](../VALIDATOR_RUNBOOK.md) — Validator operations manual
