# Audit Evidence Index

> **Document owner:** Security & Compliance Lead
> **Effective:** 2026-03-25
> **Branch:** `ramesh/protocol-hardening-sweep-20260416`
> **Review Surface:** PR `#141` latest branch head

This document maps each audit scope area to specific repository paths, commit SHAs, evidence artifacts, and their collection status. It serves as the single index for auditors to locate all supporting evidence for the Aethelred L1 security audit.

The current evidence branch is a pre-audit hardening candidate on top of
`main` commit `b66cb735c1`. The tranche summary is recorded in
`docs/audits/protocol-hardening-sweep-2026-04-16.md`.

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
| Unit tests | `app/metrics_exporter_test.go` | COLLECTED | Metrics endpoint boundary tests |
| Unit tests | `app/tee_client_test.go` | COLLECTED | Remote TEE client boundary tests |
| Unit tests | `x/verify/ezkl/prover_remote_test.go` | COLLECTED | Remote EZKL endpoint boundary tests |
| Integration tests | `app/process_proposal_integration_test.go` | COLLECTED | Full proposal lifecycle |
| Integration tests | `app/extend_vote_assignments_crisis_test.go` | COLLECTED | Crisis-mode vote extension |
| Mempool signature regression | `cargo test -p aethelred-mempool` | COLLECTED | Active mempool middleware now performs real hybrid signature verification, sender binding, and tamper rejection on serialized signed transactions |
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
| TEE startup fail-closed regression | `go test ./app -run 'Test(TeeModeRequiresHealthyVerifier|SafeInitTEEClient_.*|NewApp_NoPanic)$'` | COLLECTED | Safe init now treats real remote/Nitro TEE modes as critical startup dependencies instead of degradable simulation fallbacks |
| Simulated Nitro client regression | `go test ./app` | COLLECTED | Simulated Nitro app client now reports `nitro-simulated`, emits schema-consistent Nitro quote JSON, generates valid zk proof artifacts, and keeps orchestrator wiring on the simulated path |
| Nitro payload confidentiality regression | `go test ./x/verify/tee ./services/tee-worker/l1-verifier` | COLLECTED | Nitro verifier packages no longer treat base64 as encryption; simulated Nitro uses authenticated encryption and remote Nitro fails closed without an attested enclave key path |
| Seal signature verification regression | `go test ./x/seal/keeper` | COLLECTED | Seal verification no longer treats signature presence as successful cryptographic verification; signed attestations require an explicit verifier backend or insecure local fallback |
| Seal export provenance regression | `go test ./x/seal/keeper` | COLLECTED | Export signing no longer relies on a dead option flag; signed exports now require an explicit signer backend and bind deterministic export payloads |
| PQC readiness availability regression | `go test ./app` | COLLECTED | PQC startup availability checks now reflect the requested mode and actual CIRCL backend support instead of a placeholder always-available signal |
| Enhanced seal signature regression | `go test ./x/seal/keeper` | COLLECTED | Enhanced seal verification no longer ignores envelope signatures when present; signed enhanced bundles require an explicit verifier backend or insecure local fallback |
| Seal import provenance regression | `go test ./x/seal/keeper` | COLLECTED | Imported seal exports now re-check canonical content hashes and reject signed exports unless an explicit signature verifier backend validates the attached provenance |
| Forwarded operational-route boundary regression | `go test ./app` | COLLECTED | Shared operational-route auth no longer trusts proxied loopback requests carrying forwarding headers; admin audit, metrics, and detailed health diagnostics now require explicit bearer-token authorization when crossing a proxy boundary |
| Remote TEE endpoint validation regression | `go test ./app` | COLLECTED | `RemoteTEEClient` now rejects unsafe configured endpoints at construction time and applies the same SSRF guard to the health-probe path that already protected execution and capability fetches |
| Readiness endpoint validation regression | `go test ./x/verify/...` | COLLECTED | The verify-module startup reachability sweep now validates derived probe URLs with the shared endpoint safety guard, so blocked metadata or private-address targets are treated as unreachable instead of being probed directly |
| EZKL remote endpoint validation regression | `go test ./x/verify/ezkl` | COLLECTED | The EZKL remote prover and remote verifier now validate derived `/prove` and `/verify` URLs with the shared endpoint safety guard before issuing outbound requests |
| TEE platform taxonomy regression | `go test ./app -run 'TestVoteExtensionVerifier(RejectsUnknownTEEPlatform|AcceptsNitroSimulatedTEEPlatform)$'` and `go test ./x/pouw/keeper -run 'TestProduction_(RejectsSimulatedTEEPlatform|RejectsAllSimulatedTEEPlatformAliases|RejectsSimulatedTEEInHybrid|AcceptsRealTEEPlatforms)$'` | COLLECTED | The app vote-extension verifier and PoUW keeper now share one supported/simulated TEE platform policy; simulated aliases are rejected in production and unknown platform names no longer pass application-level verification |
| Vote-extension request binding regression | `go test ./app -run 'TestVerifyVoteExtensionHandlerRejects(MismatchedValidatorAddress|MismatchedHeight)$'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | The ABCI vote-extension ingress path now rejects embedded validator-address or height drift against the authoritative consensus request before staking lookup, signature verification, or later keeper-side aggregation |
| Runtime governance lock regression | `go test ./x/pouw/keeper -run 'Test(UpdateParams|CB7_UpdateParams|ParamChangeProposal|Mainnet)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | The PoUW mainnet lock registry is now enforced by the live `UpdateParams` handler, and the compatibility/proposal tooling now reflects the same fail-closed runtime posture unless a separately attestable elevated-governance execution path exists |
| Governance compliance alignment regression | `go test ./x/pouw/keeper -run 'Test(EvaluateVerificationPolicy|AuditChecklist|FullSecurityComplianceFlow|SecurityComplianceWithCorruptedState)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | The PoUW compliance report and audit checklist now verify runtime governance lock enforcement directly and document the correct consensus-threshold bound instead of relying on lock-registry existence or outdated policy wording |
| Trusted measurement registry auditability regression | `go test ./x/pouw/keeper -run 'TestAttestationRegistry_(AppendTrustedMeasurement_AuditsAndReconcilesLegacyNitroIndex|RevokeTrustedMeasurementBySecurityCommittee_AuditsAndRemovesIndexes|RevokeTrustedMeasurementBySecurityCommittee_RejectsUnknownMeasurement|RegisterAndValidatePCR0|RegisterAndValidateSGXMRENCLAVE)|TestCB(5|6|7)_(AppendTrustedMeasurement|RevokeTrustedMeasurement)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | Privileged trusted-measurement mutations now emit explicit runtime events and structured audit records, authority appends reconcile the legacy Nitro PCR0 index, and emergency committee revocations no longer report false success when a measurement is absent from both trust indexes |
| Trusted measurement revocation quorum regression | `go test ./x/pouw/keeper -run 'TestAttestationRegistry_(RequiresMultiApprovalAndAuditsLifecycle|RequiresMultiMemberCommittee|RejectsUnknownMeasurement|AppendTrustedMeasurement_AuditsAndReconcilesLegacyNitroIndex|RegisterAndValidatePCR0|RegisterAndValidateSGXMRENCLAVE)|TestCB(5|6|7)_(AppendTrustedMeasurement|RevokeTrustedMeasurement)'` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | Emergency trusted-measurement revocation now persists approval state, requires two independent bonded committee approvals for execution, rejects duplicate approvals, and fails closed when the committee cannot satisfy that quorum safely |
| Seal privileged revocation governance regression | `go test ./x/seal/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | Ordinary privileged seal revocation no longer bypasses the request/dispute workflow through direct helper or direct message shortcuts, the raw keeper revoke path is narrowed to an internal self-revocation helper, the default privileged threshold is now multi-party, and the forced direct path is confined to emergency authority with mandatory justification on both single and batch entrypoints |
| Seal emergency revocation quorum regression | `go test ./x/seal/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper` | COLLECTED | Emergency seal revocation no longer acts as a single-signer kill switch; it now stores per-seal emergency approval state, requires two independent emergency-authority approvals for execution, rejects duplicate approvals, restricts break-glass use to urgent reasons, and prevents emergency requests from entering the ordinary dispute workflow |
| Vault governance authority enforcement regression | `go test ./x/vault/keeper` and `go test ./app ./x/pouw/keeper ./x/verify/... ./x/seal/keeper ./x/validator/keeper ./x/vault/keeper` | COLLECTED | Governance-only vault keeper methods for vendor-root keys, enclave and operator lifecycle, and attestation-relay registration / rotation / revocation now enforce the module authority directly instead of relying on comment-level restrictions or caller discipline |
| Security audit truth-alignment regression | `go test ./x/pouw/keeper -run 'Test(AuditRunner_BadParams_(LowConsensusThreshold|BelowProductionConsensusFloor)|AuditRunner_CleanState_.*|ThreatModel_.*|SecurityProperty_OneWayGate.*)'` and `go test ./x/pouw/keeper` | COLLECTED | The built-in audit runner now enforces the hardened `67%+` production consensus floor, and the threat model now describes the live `UpdateParams` one-way gate, runtime governance-lock enforcement, and implemented app-layer vote-extension signing path instead of stale `MergeParams` or TODO-era narratives |
| Pre-audit hardening tranche | `docs/audits/protocol-hardening-sweep-2026-04-16.md` | COLLECTED | Current branch summary and verification log |

---

## 2. Cosmos SDK Modules -- `x/pouw/`, `x/verify/`, `x/validator/`

**Scope:** Proof-of-Useful-Work module, validator control paths, and ZK/TEE verification module
**Audit engagement:** AUD-2026-002
**Latest commit:** `ed40b6ee`

| Evidence Type | Path / Command | Status | Notes |
|---------------|----------------|--------|-------|
| Source code | `x/pouw/` | COLLECTED | PoUW job submission, VRF scheduling, rewards |
| Source code | `x/verify/` | COLLECTED | ZK + TEE proof verification |
| Source code | `x/validator/` | COLLECTED | Validator registry, slashing, and control-plane logic |
| Unit tests | `x/pouw/` (`*_test.go`) | COLLECTED | Module keeper tests |
| Unit tests | `x/verify/` (`*_test.go`) | COLLECTED | Verifier logic tests |
| Validator slashing regression | `go test ./x/validator/keeper` | COLLECTED | Validator keeper now requires real staking slash/jail hooks when configured and fails closed if the economic penalty path cannot be resolved |
| Rust consensus verification regression | `cargo test -p aethelred-consensus test_verification_engine*` | COLLECTED | Work-result binding, allowlist, and tamper rejection on current hardening branch |
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
| Rust relayer tests | `cargo test -p aethelred-bridge` | COLLECTED | Persistence, authority-path, and quorum regressions on current hardening branch |
| Circuit breaker tests | `contracts/test/sovereign.circuit.breaker.module.test.ts` | COLLECTED | CB module tests |
| Institutional integration | `contracts/test/institutional.stablecoin.integration.test.ts` | COLLECTED | ISB integration tests |
| Keeper tests | `contracts/test/institutional.reserve.automation.keeper.test.ts` | COLLECTED | Keeper automation tests |
| Current hardening tranche | `docs/audits/protocol-hardening-sweep-2026-04-16.md` | COLLECTED | Bridge relayer persistence and authority tightening summary |

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
| Production bootstrap hardening | `docs/audits/protocol-hardening-sweep-2026-04-16.md` | COLLECTED | Timelock-first initialization across bridge, token, vesting, vault, and institutional surfaces |
| Reserve automation keeper ownership regression | `npx hardhat test test/institutional.reserve.automation.keeper.test.ts` | COLLECTED | Automation keeper now binds final governance owner at deployment instead of retaining deployer bootstrap authority |

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
| Fail-closed backend regression | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence fails_closed_when_backend_missing` | COLLECTED | Incomplete SGX/Nitro/SEV backends now error explicitly |
| TEE worker compile check | `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features attestation-evidence` | COLLECTED | Current hardening branch compiles with fail-closed verifier changes |
| VM TEE precompile registry regressions | `cargo test -p aethelred-vm precompiles::tee::tests` | COLLECTED | Live VM precompile registration now uses hardened enterprise TEE configs by default, while devnet-only permissive paths require explicit construction |
| Verify keeper attestation regressions | `go test ./x/verify/keeper/...`; `go test ./x/verify/...` | COLLECTED | Keeper simulated-attestation path now requires authenticated quote envelopes and rejects tampering/missing verifier keys |
| Verify keeper zk binding regressions | `go test ./x/verify/keeper/...`; `go test ./x/verify/...` | COLLECTED | Simulated keeper-side zk verification now binds proof bytes to verifying key material, circuit hash, and public inputs instead of accepting any proof of sufficient length |
| EZKL simulated verifier regressions | `go test ./x/verify/...` | COLLECTED | Simulated EZKL verifier now recomputes the deterministic proof transcript and rejects tampered proofs or public inputs |
| Seal revocation workflow regression | `go test ./x/seal/keeper` | COLLECTED | Seal revocation now requires stored request state, approval thresholds, elapsed dispute windows, and no unresolved disputes before execution |
| Hybrid signer/verifier regression | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk hybrid` | COLLECTED | Real secp256k1 + Dilithium hybrid signing/verification on current hardening branch |
| zk proof fail-closed regression | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk zktensor` | COLLECTED | Worker zk proof generation/verification now errors explicitly instead of fabricating proof material |
| Worker full-sdk compile check | `cargo check --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk` | COLLECTED | Current hardening branch compiles cleanly with fail-closed zk proof hooks |
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
| Rust VM tests | `cargo test -p aethelred-vm test_invalid_attestation_response_does_not_satisfy_challenge`; `cargo test -p aethelred-vm test_valid_sgx_attestation_satisfies_challenge` | COLLECTED | Challenge-path and attestation-validation regressions on current hardening branch |
| VM job registry fail-closed regressions | `cargo test -p aethelred-vm job_registry` | COLLECTED | Mainnet/testnet configs now hard-fail on invalid or unavailable TEE/zk precompile verification while devnet keeps an explicit permissive lane |
| Rust VM compile check | `cargo check -p aethelred-vm` | COLLECTED | Current hardening branch compiles with fail-closed verification stubs |
| zkTensor runtime contract | `services/tee-worker/nitro-sdk/src/zktensor/mod.rs` | COLLECTED | Worker zk proof paths fail closed until a real proving backend is configured |

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
| Rust consensus tests | `cargo test -p aethelred-consensus` | PARTIAL | Targeted verification-engine and TEE-binding regressions collected on current hardening branch |
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
| Deployment governance regression | `npx hardhat test test/deployment.governance.config.test.ts test/institutional.reserve.automation.keeper.test.ts` | `contracts/test/deployment.governance.config.test.ts` |
| Admin endpoint boundary regression | `go test ./app` | `app/consensus_evidence_handler_test.go` |
| Health truthfulness regression | `go test ./app` | `app/health_test.go` |
| Metrics endpoint boundary regression | `go test ./app` | `app/metrics_exporter_test.go` |
| Health detail redaction regression | `go test ./app` | `app/health_test.go` |
| DCAP collateral endpoint validation regression | `go test ./x/verify/tee/...` | `x/verify/tee/dcap/verifier_security_test.go` |
| Worker Nitro endpoint validation regression | `go test ./services/tee-worker/l1-verifier/...` | `services/tee-worker/l1-verifier/nitro_test.go` |
| Drand relay boundary regression | `go test ./x/pouw/keeper -run 'TestHTTPDrandPulseProvider_|TestAssignmentEntropyFromContext_'` | `x/pouw/keeper/drand_pulse_test.go` |
| Seal verifier regression | `go test ./x/seal/keeper/...` | `x/seal/keeper/` |
| Vault relay governance regression | `go test ./x/vault/keeper` | `x/vault/keeper/keeper_test.go` |
| Sovereign access-control regression | `cargo test --manifest-path services/tee-worker/nitro-sdk/Cargo.toml --features full-sdk lib_full::sovereign::` | `services/tee-worker/nitro-sdk/src/sovereign/` |
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
