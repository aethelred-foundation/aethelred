# Audit Scope-to-Repository Map

> **Document owner:** Security & Compliance Lead
> **Effective:** 2026-03-25
> **Branch:** `feat/dapps-protocol-updates-2026-03-16`
> **HEAD:** `bf5e3740`

This document maps every subsystem under audit to exact directory paths in the repository, identifies which audit firm covers each scope, and provides code metrics for auditor orientation.

---

## Complexity Rating Scale

| Rating | Definition |
|--------|-----------|
| Critical | Core security / consensus logic; highest scrutiny required |
| High | Direct financial impact or cryptographic operations |
| Medium | Supporting infrastructure with indirect security impact |
| Low | Utilities, configuration, or non-security-critical paths |

---

## Scope Overview

| # | Subsystem | Primary Path(s) | Audit Firm | Engagement | Complexity |
|---|-----------|----------------|------------|------------|------------|
| 1 | ABCI++ / Vote Extensions | `app/` | External Auditor B | AUD-2026-002 | Critical |
| 2 | PoUW Module | `x/pouw/` | External Auditor B | AUD-2026-002 | Critical |
| 3 | Verify Module | `x/verify/` | External Auditor B | AUD-2026-002 | Critical |
| 4 | Bridge Contracts (Solidity) | `contracts/contracts/AethelredBridge.sol`, `contracts/bridges/` | External Auditor A | AUD-2026-001 | Critical |
| 5 | Token Contract | `contracts/contracts/AethelredToken.sol` | External Auditor A | AUD-2026-001 | High |
| 6 | Vesting Contract | `contracts/contracts/AethelredVesting.sol` | External Auditor A | AUD-2026-001 | High |
| 7 | Governance Timelock | `contracts/contracts/SovereignGovernanceTimelock.sol` | External Auditor A | AUD-2026-001 | High |
| 8 | Circuit Breaker | `contracts/contracts/SovereignCircuitBreakerModule.sol` | External Auditor A | AUD-2026-001 | High |
| 9 | Institutional Stablecoin Bridge | `contracts/contracts/InstitutionalStablecoinBridge.sol` | External Auditor A | AUD-2026-001 | High |
| 10 | Reserve Automation Keeper | `contracts/contracts/InstitutionalReserveAutomationKeeper.sol` | External Auditor A | AUD-2026-001 | Medium |
| 11 | Seal Verifier | `contracts/bridges/SealVerifier.sol` | External Auditor A | AUD-2026-001 | High |
| 12 | Bridge Relayer (Rust) | `crates/bridge/` | Internal Review | INT-2026-002 | High |
| 13 | PQC Primitives (Rust) | `crates/core/` | External Consultant | CON-2026-001 | Critical |
| 14 | VRF / Reputation (Rust) | `crates/consensus/` | External Consultant | CON-2026-001 | Critical |
| 15 | WASM VM + zkML Precompiles | `crates/vm/` | Internal Review | INT-2026-002 | High |
| 16 | Custom Mempool (Rust) | `crates/mempool/` | Internal Review | INT-2026-002 | Medium |
| 17 | TEE Worker Service | `services/tee-worker/` | Internal Review | INT-2026-002 | High |
| 18 | zkML Prover Service | `services/zkml-prover/` | Internal Review | INT-2026-002 | High |
| 19 | TEE Internal Package | `internal/tee/` | Internal Review | INT-2026-002 | High |
| 20 | zkML Internal Package | `internal/zkml/` | Internal Review | INT-2026-002 | High |
| 21 | IBC Module | `x/ibc/` | External Auditor B | AUD-2026-002 | High |
| 22 | Light Client Module | `x/lightclient/` | External Auditor B | AUD-2026-002 | High |
| 23 | Validator Module | `x/validator/` | External Auditor B | AUD-2026-002 | High |
| 24 | Seal Module | `x/seal/` | External Auditor B | AUD-2026-002 | Medium |
| 25 | Vault Module | `x/vault/` | Internal Review | INT-2026-002 | Medium |
| 26 | Insurance Module | `x/insurance/` | Internal Review | INT-2026-002 | Medium |
| 27 | Crisis Module | `x/crisis/` | Internal Review | INT-2026-002 | Medium |
| 28 | TypeScript SDK | `sdk/typescript/` | Internal Review | INT-2026-002 | Medium |
| 29 | Python SDK | `sdk/python/`, `sdk/aethelred-py/` | Internal Review | INT-2026-002 | Low |
| 30 | Go SDK | `sdk/go/` | Internal Review | INT-2026-002 | Low |
| 31 | Rust SDK | `sdk/rust/` | Internal Review | INT-2026-002 | Low |
| 32 | Vault Crate (Rust) | `crates/vault/` | Internal Review | INT-2026-002 | Medium |
| 33 | Sandbox Crate (Rust) | `crates/sandbox/` | Internal Review | INT-2026-002 | Medium |
| 34 | Internal Config | `internal/config/` | Internal Review | INT-2026-002 | Low |
| 35 | Internal Circuit Breaker | `internal/circuitbreaker/` | Internal Review | INT-2026-002 | Medium |
| 36 | Internal Consensus | `internal/consensus/` | Internal Review | INT-2026-002 | High |
| 37 | Internal Hardware | `internal/hardware/` | Internal Review | INT-2026-002 | Low |
| 38 | Internal HTTP Client | `internal/httpclient/` | Internal Review | INT-2026-002 | Low |
| 39 | Internal VM | `internal/vm/` | Internal Review | INT-2026-002 | Medium |
| 40 | Internal Errors | `internal/errors/` | Internal Review | INT-2026-002 | Low |

---

## Detailed Subsystem Breakdown

### 1. ABCI++ / Vote Extensions (`app/`)

| File | Lines (approx) | Purpose | Test Coverage |
|------|---------------:|---------|---------------|
| `abci.go` | ~350 | ABCI++ PrepareProposal / ProcessProposal | Integration tests |
| `vote_extension.go` | ~250 | Vote extension core logic | Unit + fuzz tests |
| `vote_extension_signing.go` | ~200 | Cryptographic signing of vote extensions | Unit tests |
| `vote_extension_bls.go` | ~150 | BLS aggregate signature | Unit tests |
| `vote_extension_cache.go` | ~180 | Vote extension caching | Unit tests |
| `verification_pipeline.go` | ~300 | Multi-stage proof verification | Unit tests |
| `consensus_finality.go` | ~200 | Finality tracking | Unit tests |
| `consensus_evidence.go` | ~250 | Evidence collection | Unit tests |
| `consensus_evidence_handler.go` | ~200 | Evidence ABCI handler | Unit tests |
| `consensus_evidence_api.go` | ~150 | Evidence query API | Unit tests |
| `encrypted_mempool_bridge.go` | ~200 | Encrypted mempool integration | Pending |
| `abci_liveness.go` | ~150 | Liveness detection | Pending |
| `abci_recovery.go` | ~150 | Recovery procedures | Pending |
| `pqc.go` | ~100 | Post-quantum crypto integration | Pending |
| `tee_attestation_schema.go` | ~100 | TEE attestation data structures | N/A (types) |
| `tee_client.go` | ~150 | TEE worker client | Pending |
| `ante.go` | ~100 | AnteHandler decorators | Pending |
| `app.go` | ~300 | Application wiring | Integration tests |
| **Total** | **~3,480** | | |

**Audit firm:** External Auditor B (AUD-2026-002)
**Complexity:** Critical
**Test artifacts:** `app/*_test.go`, `app/*_fuzz_test.go`
**Coverage gate:** `make coverage-critical` (>=95% on consensus/verification paths)

---

### 2. PoUW Module (`x/pouw/`)

| Component | Purpose |
|-----------|---------|
| `keeper/` | Keeper implementation: job submission, VRF scheduling, reward distribution |
| `types/` | Protobuf message types, genesis state |
| `module.go` | Module registration and ABCI hooks |
| `client/` | CLI and REST query handlers |

**Audit firm:** External Auditor B (AUD-2026-002)
**Complexity:** Critical
**Test artifacts:** `x/pouw/**/*_test.go`
**Benchmarks:** `make bench` (PoUW benchmarks)

---

### 3. Verify Module (`x/verify/`)

| Component | Purpose |
|-----------|---------|
| `keeper/` | ZK proof + TEE attestation verification logic |
| `types/` | Verification request/response types |
| `module.go` | Module registration |

**Audit firm:** External Auditor B (AUD-2026-002)
**Complexity:** Critical
**Test artifacts:** `x/verify/**/*_test.go`
**Benchmarks:** `make bench` (verify benchmarks)

---

### 4-11. Smart Contracts (`contracts/`)

| Contract | Path | Lines (approx) | Complexity | Formal Verification |
|----------|------|---------------:|------------|---------------------|
| AethelredBridge | `contracts/contracts/AethelredBridge.sol` | ~500 | Critical | `certora/specs/AethelredBridge.spec` |
| AethelredBridge (L1) | `contracts/bridges/AethelredBridge.sol` | ~300 | Critical | Covered by bridge spec |
| SealVerifier | `contracts/bridges/SealVerifier.sol` | ~250 | High | Pending |
| AethelredToken | `contracts/contracts/AethelredToken.sol` | ~350 | High | `certora/specs/AethelredToken.spec` |
| AethelredVesting | `contracts/contracts/AethelredVesting.sol` | ~400 | High | `certora/specs/AethelredVesting.spec` |
| SovereignGovernanceTimelock | `contracts/contracts/SovereignGovernanceTimelock.sol` | ~350 | High | `certora/specs/SovereignGovernanceTimelock.spec` |
| SovereignCircuitBreakerModule | `contracts/contracts/SovereignCircuitBreakerModule.sol` | ~250 | High | Pending |
| InstitutionalStablecoinBridge | `contracts/contracts/InstitutionalStablecoinBridge.sol` | ~400 | High | Pending |
| InstitutionalReserveAutomationKeeper | `contracts/contracts/InstitutionalReserveAutomationKeeper.sol` | ~200 | Medium | N/A |
| AethelredTypes | `contracts/contracts/AethelredTypes.sol` | ~100 | Low | N/A (type library) |
| Interfaces | `contracts/contracts/interfaces/` | ~150 | Low | N/A |
| Mocks | `contracts/contracts/mocks/` | ~200 | N/A | N/A (test-only) |
| Vault contracts | `contracts/contracts/vault/` | ~300 | Medium | Pending |
| **Total** | | **~3,750** | | |

**Audit firm:** External Auditor A (AUD-2026-001)
**Toolchain:** Foundry (primary, Solidity 0.8.20) + Hardhat (TypeChain)
**Test artifacts:** `contracts/test/*.t.sol` (Foundry), `contracts/test/*.test.ts` (Hardhat)
**Formal verification:** Certora Prover (4 specs), Slither static analysis
**Fuzz runs:** 256 (default), 100 (CI profile)

---

### 12. Bridge Relayer -- Rust (`crates/bridge/`)

| Component | Purpose |
|-----------|---------|
| `src/` | Ethereum event listener, relay logic, proof submission |

**Audit firm:** Internal Review (INT-2026-002)
**Complexity:** High
**Test artifacts:** `cargo test -p aethelred-bridge`

---

### 13-14. Cryptographic Primitives (`crates/core/`, `crates/consensus/`)

| Crate | Purpose | Key Files |
|-------|---------|-----------|
| `core` | PQC primitives: Dilithium3 signing, Kyber key exchange | `src/pillars/`, `src/crypto/` |
| `consensus` | VRF implementation, validator reputation scoring | `src/vrf.rs`, `src/reputation.rs` |

**Audit firm:** External Consultant (CON-2026-001)
**Complexity:** Critical
**Test artifacts:** `cargo test -p aethelred-core`, `cargo test -p aethelred-consensus`
**Benchmarks:** `crates/benchmarks/`
**Known finding:** RS-01 (constant-time VRF) -- remediated

---

### 15. WASM VM + zkML Precompiles (`crates/vm/`)

| Component | Purpose |
|-----------|---------|
| `src/` | WASM runtime, zkML precompile dispatch (EZKL, Groth16, Halo2, Plonky2) |

**Audit firm:** Internal Review (INT-2026-002)
**Complexity:** High
**Test artifacts:** `cargo test -p aethelred-vm`

---

### 17-18. TEE and zkML Services (`services/`)

| Service | Path | Purpose | Complexity |
|---------|------|---------|------------|
| TEE Worker | `services/tee-worker/` | TEE execution: Intel SGX / AWS Nitro attestation + inference | High |
| zkML Prover | `services/zkml-prover/` | zkML proof generation service | High |

**Audit firm:** Internal Review (INT-2026-002)
**Test artifacts:** Service-level tests, `cargo test --features attestation-evidence`

---

### 19-20. Internal Packages (`internal/`)

| Package | Path | Purpose | Complexity |
|---------|------|---------|------------|
| TEE | `internal/tee/` | Go TEE integration library | High |
| zkML | `internal/zkml/` | Go zkML integration library | High |
| Consensus | `internal/consensus/` | Go consensus helpers | High |
| Circuit Breaker | `internal/circuitbreaker/` | Circuit breaker pattern | Medium |
| VM | `internal/vm/` | Go VM integration | Medium |
| Config | `internal/config/` | Configuration management | Low |
| Errors | `internal/errors/` | Error types | Low |
| Hardware | `internal/hardware/` | Hardware detection | Low |
| HTTP Client | `internal/httpclient/` | HTTP client utilities | Low |

**Audit firm:** Internal Review (INT-2026-002)
**Test artifacts:** `internal/**/*_test.go`

---

### 21-27. Cosmos SDK Modules (`x/`)

| Module | Path | Purpose | Complexity | Audit Firm |
|--------|------|---------|------------|------------|
| IBC | `x/ibc/` | Cross-chain proof relay | High | External Auditor B |
| Light Client | `x/lightclient/` | Light client verification | High | External Auditor B |
| Validator | `x/validator/` | Validator registration/management | High | External Auditor B |
| Seal | `x/seal/` | Digital seal attestation anchoring | Medium | External Auditor B |
| Vault | `x/vault/` | Vault operations | Medium | Internal Review |
| Insurance | `x/insurance/` | Insurance module | Medium | Internal Review |
| Crisis | `x/crisis/` | Crisis handling / invariant checks | Medium | Internal Review |

**Test artifacts:** `x/<module>/**/*_test.go`

---

### 28-31. SDKs (`sdk/`)

| SDK | Path | Language | Complexity | Audit Firm |
|-----|------|----------|------------|------------|
| TypeScript | `sdk/typescript/` | TypeScript | Medium | Internal Review |
| Python | `sdk/python/`, `sdk/aethelred-py/` | Python | Low | Internal Review |
| Go | `sdk/go/` | Go | Low | Internal Review |
| Rust | `sdk/rust/` | Rust | Low | Internal Review |

**Version tracking:** `sdk/version-matrix.json`
**Test artifacts:** Per-SDK test suites, `make sdk-version-check`

---

## Audit Firm Coverage Summary

### External Auditor A (AUD-2026-001) -- Smart Contracts

| Subsystem | Path | Status |
|-----------|------|--------|
| Bridge contracts | `contracts/contracts/AethelredBridge.sol`, `contracts/bridges/` | In Progress |
| Token contract | `contracts/contracts/AethelredToken.sol` | In Progress |
| Vesting contract | `contracts/contracts/AethelredVesting.sol` | In Progress |
| Governance timelock | `contracts/contracts/SovereignGovernanceTimelock.sol` | In Progress |
| Circuit breaker | `contracts/contracts/SovereignCircuitBreakerModule.sol` | In Progress |
| Institutional bridge | `contracts/contracts/InstitutionalStablecoinBridge.sol` | In Progress |
| Reserve keeper | `contracts/contracts/InstitutionalReserveAutomationKeeper.sol` | In Progress |
| Seal verifier | `contracts/bridges/SealVerifier.sol` | In Progress |

### External Auditor B (AUD-2026-002) -- Consensus + Chain Logic

| Subsystem | Path | Status |
|-----------|------|--------|
| ABCI++ handlers | `app/` | In Progress |
| PoUW module | `x/pouw/` | In Progress |
| Verify module | `x/verify/` | In Progress |
| Validator module | `x/validator/` | In Progress |
| IBC module | `x/ibc/` | In Progress |
| Light client | `x/lightclient/` | In Progress |
| Seal module | `x/seal/` | In Progress |

### External Consultant (CON-2026-001) -- Cryptography

| Subsystem | Path | Status |
|-----------|------|--------|
| PQC primitives | `crates/core/` | Completed |
| VRF / reputation | `crates/consensus/` | Completed |

### Internal Review (INT-2026-002) -- Full Protocol

| Subsystem | Path | Status |
|-----------|------|--------|
| All Go, Rust, Solidity code | Full repository | Completed (36 findings, all remediated) |

---

## Test Coverage Cross-Reference

| Subsystem | Unit Tests | Integration Tests | Fuzz Tests | Formal Verification | Invariant Tests | Load Tests |
|-----------|:----------:|:-----------------:|:----------:|:-------------------:|:---------------:|:----------:|
| ABCI++ / Vote Extensions | Yes | Yes | Yes | -- | -- | Yes |
| PoUW Module | Yes | -- | -- | -- | -- | Yes |
| Verify Module | Yes | -- | -- | -- | -- | -- |
| Bridge (Solidity) | Yes | Yes | Yes (Foundry) | Yes (Certora) | Yes | -- |
| Token | Yes | -- | -- | Yes (Certora) | Yes | -- |
| Vesting | Yes | Yes | -- | Yes (Certora) | Yes | -- |
| Governance | Yes | Yes | -- | Yes (Certora) | Yes | -- |
| Circuit Breaker | Yes | -- | -- | -- | -- | -- |
| ISB | Yes | Yes | -- | -- | -- | -- |
| Bridge (Rust) | Pending | -- | -- | -- | -- | -- |
| PQC Primitives | Pending | -- | -- | -- | -- | -- |
| VRF / Reputation | Pending | -- | -- | -- | -- | -- |
| WASM VM | Pending | -- | -- | -- | -- | -- |
| TEE Worker | Partial | -- | -- | -- | -- | -- |
| zkML Prover | Partial | -- | -- | -- | -- | -- |
| IBC Module | Partial | -- | -- | -- | -- | -- |
| TypeScript SDK | Yes | -- | -- | -- | -- | -- |
| Python SDK | Pending | -- | -- | -- | -- | -- |
| Go SDK | Pending | -- | -- | -- | -- | -- |
| Rust SDK | Pending | -- | -- | -- | -- | -- |

**Coverage commands:**
- Go: `make test-coverage` (output: `coverage.out`), `make coverage-critical` (>=95% gate)
- Solidity: `forge coverage`
- Rust: `cargo tarpaulin --workspace --manifest-path crates/Cargo.toml`

---

## Cross-References

- Evidence index: [`docs/audits/EVIDENCE_INDEX.md`](EVIDENCE_INDEX.md)
- Remediation register: [`docs/audits/REMEDIATION_REGISTER.md`](REMEDIATION_REGISTER.md)
- Audit status: [`docs/audits/STATUS.md`](STATUS.md)
- Subsystem ownership: [`docs/operations/SUBSYSTEM_OWNERSHIP.md`](../operations/SUBSYSTEM_OWNERSHIP.md)
- Gate inventory: [`docs/operations/GATE_INVENTORY.md`](../operations/GATE_INVENTORY.md)
- Protobuf contract: `proto/` (shared interface between Go and Rust stacks)
