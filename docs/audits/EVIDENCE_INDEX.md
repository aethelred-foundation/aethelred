# Audit Evidence Index

> **Document owner:** Security & Compliance Lead
> **Effective:** 2026-03-25
> **Branch:** `feat/dapps-protocol-updates-2026-03-16`
> **HEAD:** `bf5e3740`

This document maps each audit scope area to specific repository paths, commit SHAs, evidence artifacts, and their collection status. It serves as the single index for auditors to locate all supporting evidence for the Aethelred L1 security audit.

---

## Audit Engagements

| Engagement ID | Auditor | Scope | Status | Report Location |
|---------------|---------|-------|--------|-----------------|
| AUD-2026-001 | External Auditor (under NDA) | `/contracts/` -- Solidity smart contracts | In Progress | `docs/audits/reports/2026-02-14-preaudit-baseline.md` |
| AUD-2026-002 | External Auditor (under NDA) | Consensus + vote extensions (`app/`, `x/pouw/`, `x/verify/`) | In Progress | `docs/audits/reports/2026-02-14-preaudit-baseline.md` |
| INT-2026-001 | Internal Security Review | Full protocol (Go, Solidity, Rust) | Completed | 27 findings, all remediated |
| CON-2026-001 | External Consultant | VRF + protocol review | Completed | RS-01 (Critical) addressed |
| INT-2026-002 | Internal Full Audit v2 | Full protocol -- 36 findings | Completed | `docs/audits/aethelred-full-audit-report-v2-remediation-matrix.md` |
| MR-2026-001 | Multi-Repo Strict Snapshot | 9 public repos -- governance/process | Partially Remediated | `docs/audits/aethelred-multi-repo-findings-disposition-2026-02-24.md` |

---

## Evidence Status Legend

| Symbol | Meaning |
|--------|---------|
| COLLECTED | Evidence artifact exists and verified |
| PARTIAL | Evidence exists but coverage incomplete |
| PENDING | Evidence generation scheduled or in progress |
| N/A | Not applicable to this scope area |

---

## 1. Consensus -- ABCI++ / Vote Extensions / Finality

**Scope:** `app/` (ABCI++ handlers, vote extensions, verification pipeline, consensus finality)
**Audit engagement:** AUD-2026-002
**Latest commit:** `ed40b6ee`

### Source Artifacts

| File | Purpose | Commit |
|------|---------|--------|
| `app/abci.go` | ABCI++ PrepareProposal / ProcessProposal handlers | `ed40b6ee` |
| `app/vote_extension.go` | Vote extension logic | `ed40b6ee` |
| `app/vote_extension_signing.go` | Vote extension cryptographic signing | `ed40b6ee` |
| `app/vote_extension_bls.go` | BLS aggregate signature handling | `ed40b6ee` |
| `app/vote_extension_cache.go` | Vote extension caching layer | `ed40b6ee` |
| `app/verification_pipeline.go` | Multi-stage proof verification pipeline | `ed40b6ee` |
| `app/consensus_finality.go` | Consensus finality tracking | `ed40b6ee` |
| `app/consensus_evidence.go` | Consensus evidence collection | `ed40b6ee` |
| `app/consensus_evidence_handler.go` | Consensus evidence ABCI handler | `ed40b6ee` |
| `app/abci_liveness.go` | Liveness detection and recovery | `ed40b6ee` |
| `app/abci_recovery.go` | ABCI recovery procedures | `ed40b6ee` |
| `app/encrypted_mempool_bridge.go` | Encrypted mempool bridge integration | `ed40b6ee` |
| `app/pqc.go` | Post-quantum cryptography integration | `ed40b6ee` |

### Evidence Artifacts

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Unit tests | `app/vote_extension_test.go` | COLLECTED | Vote extension correctness |
| Unit tests | `app/vote_extension_signing_test.go` | COLLECTED | Signing path coverage |
| Unit tests | `app/vote_extension_cache_test.go` | COLLECTED | Cache eviction / consistency |
| Unit tests | `app/verification_pipeline_test.go` | COLLECTED | Pipeline stage validation |
| Unit tests | `app/consensus_evidence_test.go` | COLLECTED | Evidence collection tests |
| Unit tests | `app/consensus_evidence_handler_test.go` | COLLECTED | Handler integration tests |
| Unit tests | `app/consensus_finality_test.go` | COLLECTED | Finality tracking tests |
| Unit tests | `app/health_test.go` | COLLECTED | Health check tests |
| Integration tests | `app/process_proposal_integration_test.go` | COLLECTED | Full proposal lifecycle |
| Integration tests | `app/extend_vote_assignments_crisis_test.go` | COLLECTED | Crisis-mode vote extension |
| Fuzz tests | `app/vote_extension_fuzz_test.go` | COLLECTED | Vote extension fuzzing |
| Coverage report | `make test-coverage` -> `coverage.out` | PENDING | Target: >=95% critical paths |
| Critical path coverage | `make coverage-critical` | PENDING | Enforced >=95% on consensus/verification |
| E2E smoke test | `test-results/e2e-network-smoke-20260325-113510.txt` | COLLECTED | 4-validator testnet smoke |
| E2E runtime test | `test-results/e2e-network-runtime-20260325-113534.txt` | COLLECTED | Runtime stability validation |
| Network doctor | `test-results/e2e-network-doctor-20260325-113510.txt` | COLLECTED | Service health check |
| Exploit simulations | `test-results/dynamic-exploit-simulations-20260325-113147.json` | COLLECTED | Dynamic exploit scenarios |
| Seeded exploit sims | `test-results/dynamic-exploit-simulations-seeded-20260325-113751.json` | COLLECTED | Seeded exploit scenarios |
| E2E Go workflow | `test-results/e2e-go-workflow-20260325-113209.txt` | COLLECTED | Full Go E2E workflow |
| Load test results | `loadtest-results/loadtest-report-20260325-113719.json` | COLLECTED | Throughput / latency benchmarks |
| Benchmark topology | `loadtest-results/BENCHMARK_TOPOLOGY.md` | COLLECTED | Test infrastructure description |

---

## 2. Cosmos SDK Modules -- `x/pouw/`, `x/verify/`

**Scope:** Proof-of-Useful-Work module and ZK/TEE verification module
**Audit engagement:** AUD-2026-002
**Latest commit:** `ed40b6ee`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Source code | `x/pouw/` | COLLECTED | PoUW job submission, VRF scheduling, rewards |
| Source code | `x/verify/` | COLLECTED | ZK + TEE proof verification |
| Unit tests | `x/pouw/` (`*_test.go`) | COLLECTED | Module keeper tests |
| Unit tests | `x/verify/` (`*_test.go`) | COLLECTED | Verifier logic tests |
| Benchmarks | `make bench` | PENDING | PoUW and verify benchmarks |
| Coverage report | `make test-coverage` -> `coverage.out` | PENDING | Part of unified Go coverage |

---

## 3. Bridge -- Ethereum Relayer + Solidity Contracts

**Scope:** `contracts/`, `contracts/bridges/`, `crates/bridge/`
**Audit engagement:** AUD-2026-001
**Latest commit (Solidity):** `e93a0f5b` | **Latest commit (Rust):** `ed40b6ee`

### Source Artifacts

| File | Purpose | Commit |
|------|---------|--------|
| `contracts/contracts/AethelredBridge.sol` | Main bridge contract | `e93a0f5b` |
| `contracts/bridges/AethelredBridge.sol` | L1-side bridge contract | `e93a0f5b` |
| `contracts/bridges/SealVerifier.sol` | Seal verification contract | `e93a0f5b` |
| `contracts/contracts/AethelredTypes.sol` | Shared type definitions | `e93a0f5b` |
| `contracts/contracts/SovereignCircuitBreakerModule.sol` | Emergency circuit breaker | `e93a0f5b` |
| `contracts/contracts/InstitutionalStablecoinBridge.sol` | Institutional stablecoin bridge | `e93a0f5b` |
| `contracts/contracts/InstitutionalReserveAutomationKeeper.sol` | Reserve automation keeper | `e93a0f5b` |
| `crates/bridge/` | Rust Ethereum relayer | `ed40b6ee` |

### Evidence Artifacts

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Foundry unit tests | `contracts/test/AethelredBridge.t.sol` | COLLECTED | Bridge contract tests |
| Foundry emergency tests | `contracts/test/AethelredBridgeEmergency.t.sol` | COLLECTED | Emergency flow tests |
| Foundry invariant tests | `contracts/test/BridgeInvariant.t.sol` | COLLECTED | Bridge invariant fuzzing |
| Hardhat integration tests | `contracts/test/bridge.emergency.test.ts` | COLLECTED | Emergency bridge flows |
| High-severity regression | `contracts/test/high.findings.regression.test.ts` | COLLECTED | Regression for H-01..H-12 |
| Medium-severity regression | `contracts/test/medium.findings.regression.test.ts` | COLLECTED | Regression for M-01..M-10 |
| Formal verification (Certora) | `contracts/certora/specs/AethelredBridge.spec` | COLLECTED | Bridge safety properties |
| Certora configuration | `contracts/certora/conf/` | COLLECTED | Prover configuration |
| Static analysis config | `contracts/slither.config.json` | COLLECTED | Slither configuration |
| Fuzz results (Foundry) | `forge test` (256 runs default, 100 CI) | PENDING | Foundry fuzz corpus |
| Rust relayer tests | `cargo test -p aethelred-bridge` | PENDING | Relayer logic tests |
| Circuit breaker tests | `contracts/test/sovereign.circuit.breaker.module.test.ts` | COLLECTED | CB module tests |
| Institutional integration | `contracts/test/institutional.stablecoin.integration.test.ts` | COLLECTED | ISB integration tests |
| Keeper tests | `contracts/test/institutional.reserve.automation.keeper.test.ts` | COLLECTED | Keeper automation tests |

---

## 4. Token -- AethelredToken + Vesting

**Scope:** `contracts/contracts/AethelredToken.sol`, `contracts/contracts/AethelredVesting.sol`
**Audit engagement:** AUD-2026-001
**Latest commit:** `e93a0f5b`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Token contract | `contracts/contracts/AethelredToken.sol` | COLLECTED | ERC-20 + bridge burn |
| Vesting contract | `contracts/contracts/AethelredVesting.sol` | COLLECTED | Cliff + linear vesting |
| Foundry token tests | `contracts/test/AethelredToken.t.sol` | COLLECTED | Token logic tests |
| Foundry vesting tests | `contracts/test/AethelredVesting.t.sol` | COLLECTED | Vesting math tests |
| Vesting critical tests | `contracts/test/vesting.critical.test.ts` | COLLECTED | Critical vesting edge cases |
| Token vesting invariants | `contracts/test/TokenVestingInvariant.t.sol` | COLLECTED | Invariant fuzzing |
| Vault invariants | `contracts/test/VaultInvariant.t.sol` | COLLECTED | Vault invariant fuzzing |
| Formal verification (Certora) | `contracts/certora/specs/AethelredToken.spec` | COLLECTED | Token safety properties |
| Formal verification (Certora) | `contracts/certora/specs/AethelredVesting.spec` | COLLECTED | Vesting safety properties |

---

## 5. Governance -- SovereignGovernanceTimelock

**Scope:** `contracts/contracts/SovereignGovernanceTimelock.sol`
**Audit engagement:** AUD-2026-001
**Latest commit:** `e93a0f5b`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Governance contract | `contracts/contracts/SovereignGovernanceTimelock.sol` | COLLECTED | Timelock + proposal execution |
| Hardhat governance tests | `contracts/test/sovereign.governance.timelock.test.ts` | COLLECTED | Governance flow tests |
| Governance invariants | `contracts/test/GovernanceInvariant.t.sol` | COLLECTED | Governance invariant fuzzing |
| Formal verification (Certora) | `contracts/certora/specs/SovereignGovernanceTimelock.spec` | COLLECTED | Timelock safety properties |
| Cruzible dApp tests | `contracts/test/Cruzible.t.sol` | COLLECTED | Governance UI interaction tests |
| Cruzible invariants | `contracts/test/CruzibleInvariant.t.sol` | COLLECTED | Cruzible invariant fuzzing |

---

## 6. TEE -- Trusted Execution Environment

**Scope:** `services/tee-worker/`, `internal/tee/`
**Audit engagement:** INT-2026-002
**Latest commit (service):** `3d1bb18d` | **Latest commit (internal):** `031d2e9e`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| TEE worker service | `services/tee-worker/` | COLLECTED | TEE execution worker |
| TEE internal package | `internal/tee/` | COLLECTED | Go TEE integration library |
| TEE attestation schema | `app/tee_attestation_schema.go` | COLLECTED | Attestation data structures |
| TEE client integration | `app/tee_client.go` | COLLECTED | Client-side TEE communication |
| Unit tests | `internal/tee/` (`*_test.go`) | PARTIAL | Core logic covered, edge cases pending |
| Attestation evidence tests | `cargo test --features attestation-evidence` | COLLECTED | SGX/Nitro attestation flow |
| Nitro SDK quote-type fix | M-07 regression (see Remediation Register) | COLLECTED | Feature-gated attestation test |
| SGX/Nitro attestation flow E2E | `services/tee-worker/` integration tests | PENDING | Full attestation lifecycle |

---

## 7. zkML -- Zero-Knowledge Machine Learning

**Scope:** `internal/zkml/`, `services/zkml-prover/`, `crates/vm/`
**Audit engagement:** INT-2026-002
**Latest commit (internal):** `031d2e9e` | **Latest commit (service):** `3d1bb18d`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| zkML internal package | `internal/zkml/` | COLLECTED | Go zkML integration |
| zkML prover service | `services/zkml-prover/` | COLLECTED | Proof generation service |
| WASM + zkML precompiles | `crates/vm/` | COLLECTED | VM precompile implementations |
| Unit tests | `internal/zkml/` (`*_test.go`) | PARTIAL | Core verification paths covered |
| Proof system tests | EZKL, Groth16, Halo2, Plonky2 backends | PENDING | Backend-specific proof tests |
| Rust VM tests | `cargo test -p aethelred-vm` | PENDING | WASM precompile tests |

---

## 8. IBC -- Inter-Blockchain Communication

**Scope:** `x/ibc/`, `x/lightclient/`
**Audit engagement:** AUD-2026-002
**Latest commit:** `e93a0f5b`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| IBC module | `x/ibc/` | COLLECTED | Cross-chain proof relay |
| Light client module | `x/lightclient/` | COLLECTED | Light client verification |
| Unit tests | `x/ibc/` (`*_test.go`) | PARTIAL | Core relay logic covered |
| Cross-chain proof relay E2E | IBC integration tests | PENDING | Multi-chain relay scenarios |

---

## 9. SDK -- Multi-Language Client SDKs

**Scope:** `sdk/typescript/`, `sdk/python/`, `sdk/go/`, `sdk/rust/`
**Audit engagement:** INT-2026-002
**Latest commit:** `ed40b6ee`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| TypeScript SDK | `sdk/typescript/` | COLLECTED | `@aethelred/sdk` |
| Python SDK | `sdk/python/`, `sdk/aethelred-py/` | COLLECTED | `aethelred-sdk` PyPI package |
| Go SDK | `sdk/go/` | COLLECTED | Go client module |
| Rust SDK | `sdk/rust/` | COLLECTED | Rust client crate |
| Version matrix | `sdk/version-matrix.json` | COLLECTED | Cross-SDK version tracking |
| SDK security policy | `sdk/SECURITY.md` | COLLECTED | Vulnerability disclosure |
| TypeScript PQC tests | `sdk/typescript/src/crypto/pqc.test.ts` | COLLECTED | PQC sign/verify regression |
| TypeScript TEE tests | `sdk/typescript/src/crypto/tee.test.ts` | COLLECTED | TEE verification regression |
| TypeScript client tests | `sdk/typescript/src/core/client.test.ts` | COLLECTED | API client tests |
| SDK version gate | `make sdk-version-check` | PENDING | Version consistency check |
| OpenAPI validation | `make openapi-validate` | PENDING | API spec validation |
| SDK release gate | `make sdk-release-check` | PENDING | Publish readiness check |

---

## 10. Cryptographic Primitives

**Scope:** `crates/core/`, `crates/consensus/`
**Audit engagement:** CON-2026-001, INT-2026-002
**Latest commit:** `ed40b6ee`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| PQC primitives (Dilithium3, Kyber) | `crates/core/` | COLLECTED | Post-quantum key exchange + signing |
| VRF implementation | `crates/consensus/src/vrf.rs` | COLLECTED | Verifiable random function |
| Reputation scoring | `crates/consensus/` | COLLECTED | Validator reputation system |
| PQC integration in app | `app/pqc.go` | COLLECTED | Go-side PQC bridge |
| VRF timing fix (RS-01) | `crates/consensus/src/vrf.rs` lines 457-496 | COLLECTED | RFC 9380 constant-time SWU |
| Rust core tests | `cargo test -p aethelred-core` | PENDING | PQC primitive tests |
| Rust consensus tests | `cargo test -p aethelred-consensus` | PENDING | VRF + reputation tests |
| Benchmarks | `crates/benchmarks/` | PENDING | Cryptographic operation benchmarks |

---

## 11. Operational Evidence

| Evidence Type | Path | Status | Notes |
|---------------|------|--------|-------|
| Freeze policy | `docs/operations/FREEZE_POLICY.md` | COLLECTED | Code freeze procedures |
| Gate inventory | `docs/operations/GATE_INVENTORY.md` | COLLECTED | CI/CD gate definitions |
| Operations runbook | `docs/operations/OPS_RUNBOOK.md` | COLLECTED | Incident response procedures |
| Rollback decision tree | `docs/operations/ROLLBACK_DECISION_TREE.md` | COLLECTED | Rollback criteria and process |
| SLO definitions | `docs/operations/SLO_DEFINITIONS.md` | COLLECTED | Service level objectives |
| Subsystem ownership | `docs/operations/SUBSYSTEM_OWNERSHIP.md` | COLLECTED | Team ownership map |
| Performance baselines | `docs/operations/PERFORMANCE_BASELINES.md` | COLLECTED | Performance benchmarks |
| CI/CD gates | `docs/operations/ci-cd-gates.md` | COLLECTED | Pipeline gate documentation |
| Load testing procedures | `docs/operations/load-testing.md` | COLLECTED | Load test methodology |
| Secret management | `docs/operations/secret-management.md` | COLLECTED | Secret rotation and storage |
| Geographic redundancy | `docs/operations/geographic-redundancy.md` | COLLECTED | Multi-region architecture |
| Enterprise infrastructure | `docs/operations/enterprise-infrastructure.md` | COLLECTED | Infrastructure overview |
| Prod gate audit signoff | `test-results/prod-gate-audit-signoff-20260302-231424.txt` | COLLECTED | Production gate check |
| Production readiness checklist | `test-results/production-readiness-gap-checklist-20260302.md` | COLLECTED | Gap analysis |
| Mainnet launch audit | `test-results/mainnet-launch-audit-war-room-20260325.md` | COLLECTED | War room checklist |
| Mainnet engineering board | `test-results/mainnet-engineering-execution-board-20260325.md` | COLLECTED | Engineering execution status |
| Mainnet production program | `test-results/mainnet-production-program-20260325.md` | COLLECTED | Production program status |

---

## CI Artifact References

| Artifact | CI Job | Command | Location |
|----------|--------|---------|----------|
| Go test results | `test-go` | `make test` | GitHub Actions |
| Go unit tests | `test-go-unit` | `make test-unit` | GitHub Actions |
| Go integration tests | `test-go-integration` | `make test-integration` | GitHub Actions |
| Go consensus tests | `test-go-consensus` | `make test-consensus` | GitHub Actions |
| Go coverage | `coverage` | `make test-coverage` | GitHub Actions / `coverage.out` |
| Critical path coverage | `coverage-critical` | `make coverage-critical` | GitHub Actions |
| Rust test results | `test-rust` | `cargo test --workspace` | GitHub Actions |
| Foundry test + fuzz | `test-contracts` | `forge test` | GitHub Actions |
| Foundry CI fuzz | `test-contracts-ci` | `forge test --profile ci` | GitHub Actions |
| Hardhat tests | `test-contracts-hardhat` | `npx hardhat test` | GitHub Actions |
| Certora formal verification | `certora-verify` | Certora Prover | GitHub Actions |
| Slither static analysis | `slither-analysis` | `slither .` | GitHub Actions |
| E2E network smoke | `e2e-smoke` | `make local-testnet-doctor` | GitHub Actions |
| Load test | `loadtest` | `make loadtest-scenarios` | GitHub Actions |
| SDK version check | `sdk-gates` | `make sdk-version-check` | GitHub Actions |
| OpenAPI validation | `openapi-validate` | `make openapi-validate` | GitHub Actions |
| Exploit simulations | `exploit-sims` | Dynamic exploit runner | GitHub Actions |

---

## Evidence Bundles

### Automated Evidence

| Evidence Type | Command / Workflow | Location |
|---------------|-------------------|----------|
| Full remediation bundle | `bash scripts/run-audit-remediation-evidence-bundle.sh .` | CI logs / local output |
| Contract regression tests | `forge test` + `npx hardhat test` | `contracts/test/` |
| Guard scripts | `scripts/validate-compose-security.sh`, `scripts/validate-pouw-medium-guards.sh`, `scripts/validate-low-findings-guards.sh`, `scripts/validate-devnet-genesis.py` | Script output |
| Rust attestation evidence | `cargo test --features attestation-evidence` | `services/tee-worker/nitro-sdk/` |
| Security scans | `.github/workflows/security-scans.yml` | CI artifacts |
| Fuzz corpus | `.github/workflows/fuzzing-ci.yml` | CI artifacts / corpus |

### Manual Evidence Required

| Evidence Type | Owner | Status | Target Date |
|---------------|-------|--------|-------------|
| AUD-2026-001 signed report | External Auditor | In Progress | Before mainnet |
| AUD-2026-002 signed report | External Auditor | In Progress | Before mainnet |
| ADR-0001 Foundation ratification | Governance | Pending | Before mainnet |
| SBOM publication per release | Security | Not Started | Before mainnet |

---

## Cross-References

- Scope-to-repo map: [`docs/audits/SCOPE_MAP.md`](SCOPE_MAP.md)
- Finding disposition register: [`docs/audits/REMEDIATION_REGISTER.md`](REMEDIATION_REGISTER.md)
- Audit status tracker: [`docs/audits/STATUS.md`](STATUS.md)
- Full audit v2 remediation matrix: [`docs/audits/aethelred-full-audit-report-v2-remediation-matrix.md`](aethelred-full-audit-report-v2-remediation-matrix.md)
- Multi-repo findings disposition: [`docs/audits/aethelred-multi-repo-findings-disposition-2026-02-24.md`](aethelred-multi-repo-findings-disposition-2026-02-24.md)
- Retest checklist: [`docs/audits/aethelred-v2-retest-checklist.md`](aethelred-v2-retest-checklist.md)
- Auditability rollout matrix: [`docs/audits/aethel-mr-003-repo-auditability-rollout-matrix.md`](aethel-mr-003-repo-auditability-rollout-matrix.md)
- Subsystem ownership: [`docs/operations/SUBSYSTEM_OWNERSHIP.md`](../operations/SUBSYSTEM_OWNERSHIP.md)
- Gate inventory: [`docs/operations/GATE_INVENTORY.md`](../operations/GATE_INVENTORY.md)
