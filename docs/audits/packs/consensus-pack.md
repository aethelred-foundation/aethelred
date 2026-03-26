# Auditor Pack: Consensus Subsystem

**Squad:** SQ4 (Consensus)
**Last Updated:** 2026-03-25
**Classification:** CONFIDENTIAL - For Auditors Only

---

## 1. Subsystem Overview

- **Name:** Consensus (ABCI++, Vote Extensions, Proof-of-Useful-Work)
- **Squad:** SQ4
- **Scope:** Block production, ABCI++ handler lifecycle (ExtendVote, VerifyVoteExtension, PrepareProposal, ProcessProposal), vote extension signing/caching with BLS, VRF-based AI job scheduling, PoUW reward distribution, TEE attestation integration, and the verification pipeline bridging `x/verify` into consensus.
- **Key Source Paths:**
  - `app/abci.go` -- ABCI++ handlers (ExtendVote, PrepareProposal)
  - `app/vote_extension.go` -- Vote extension types, signing, validation, BLS cache
  - `app/verification_pipeline.go` -- Wiring between `x/verify` orchestrator and `x/pouw` keeper
  - `x/pouw/` -- Proof-of-Useful-Work module (job submission, VRF scheduling, reward distribution)
  - `x/verify/` -- ZK + TEE proof verification orchestrator
  - `x/validator/` -- Validator set management
  - `internal/consensus/` -- Internal consensus utilities
- **Language/Stack:** Go 1.24+, Cosmos SDK, CometBFT
- **External Dependencies:** CometBFT ABCI++, Cosmos SDK v0.50+, EZKL, RISC Zero, Groth16, Halo2, Plonky2 verifier backends

---

## 2. Architecture Overview

```
                    CometBFT Consensus Engine
                            │
              ┌─────────────┼──────────────┐
              │             │              │
              ▼             ▼              ▼
        ExtendVote   PrepareProposal  ProcessProposal
        (app/abci.go)  (app/abci.go)   (app/abci.go)
              │
              ▼
     VoteExtension Builder
     (app/vote_extension.go)
              │
              ├─── BLS Signing / Cache
              │
              ▼
     Verification Pipeline
     (app/verification_pipeline.go)
              │
     ┌────────┴────────┐
     │                 │
     ▼                 ▼
  x/verify          x/pouw
  (zkML + TEE       (Job scheduling,
   orchestrator)     VRF assignment,
     │                rewards)
     │
     ├─── EZKL Verifier
     ├─── RISC Zero Verifier
     ├─── Groth16 Verifier
     ├─── Halo2 Verifier
     ├─── Plonky2 Verifier
     └─── TEE Attestation (Intel SGX / AWS Nitro)
```

---

## 3. Trust Boundaries

| Boundary | From | To | Trust Assumption | Verification Mechanism |
|----------|------|----|------------------|----------------------|
| Validator to CometBFT | Validator node | CometBFT consensus engine | CometBFT correctly drives ABCI++ lifecycle | CometBFT BFT consensus (2/3+ honest validators) |
| Vote Extension signing | Validator key (HSM) | Vote extension payload | HSM-protected key cannot be extracted | FIPS 140-2 Level 3 HSM, `app/vote_extension.go` signature verification |
| ExtendVote panic boundary | ABCI handler | Consensus engine | A panic in ExtendVote must not halt consensus | Panic recovery in `app/abci.go` returns empty extension on panic |
| Verification pipeline | `app/` (composition root) | `x/verify/` + `x/pouw/` | Verification results are authentic | Orchestrator validates proofs; bridge adapter enforces type safety |
| ZK proof verification | Untrusted prover | On-chain verifier (`x/verify/`) | Proofs may be malicious | Cryptographic verification (soundness of proof system) |
| TEE attestation | TEE enclave (Intel SGX / AWS Nitro) | Validator node | Attestation report is genuine | Remote attestation verification against known enclave measurements |
| VRF job assignment | `x/pouw/` scheduler | Validators | Assignment is random and verifiable | VRF proof published on-chain, verifiable by any node |
| Job result aggregation | Multiple validators | PrepareProposal | 2/3+ validators agree on result | Aggregated verification requires supermajority in `app/abci.go` |

---

## 4. Access Control Matrix

| Role | Permissions | Assignment Mechanism | Revocation Mechanism |
|------|-------------|---------------------|---------------------|
| Validator | Sign vote extensions, participate in consensus, receive PoUW rewards | Stake bonding via `x/validator/` | Unbonding, slashing, jailing |
| Job Submitter | Submit AI inference jobs to `x/pouw/` | Any account with sufficient gas | N/A (permissionless, gas-gated) |
| Module Authority (`x/pouw`) | Update module params (e.g., reward rates, max verifications) | Governance proposal | Governance proposal |
| Module Authority (`x/verify`) | Update verification backends, enable/disable proof types | Governance proposal | Governance proposal |
| Node Operator | Configure TEE mode, verification pipeline settings | Node config (`config.toml`) | Node restart with new config |

---

## 5. Key State Transitions

| State | Trigger | Next State | Validation | Reversible? |
|-------|---------|------------|------------|-------------|
| Job Submitted | `MsgSubmitJob` tx included in block | Job Pending | Gas payment, valid job spec | No |
| Job Pending | VRF scheduler assigns to validator(s) | Job Assigned | VRF proof valid, validator is active | No |
| Job Assigned | Validator executes in TEE, produces result | Job Verified | TEE attestation + zkML proof valid, within verification time limit | No |
| Job Verified | PrepareProposal aggregates 2/3+ matching results | Job Complete | Supermajority agreement on result | No |
| Job Complete | Reward distribution | Rewards Paid | Correct reward calculation per `x/pouw/` params | No |
| Vote Extension Created | ExtendVote called by CometBFT | Extension Signed | BLS signature valid, timestamp within skew bounds (`app/vote_extension.go`: max past 10m, max future 1m) | No |
| Extension Signed | VerifyVoteExtension called | Extension Accepted/Rejected | Signature verification, version check, verification count <= `MaxVerificationsPerExtension` (100) | No |

---

## 6. Known Risks and Mitigations

| Risk ID | Description | Severity | Mitigation | Status |
|---------|-------------|----------|------------|--------|
| C-001 | Double-signing via concurrent validator instances | Critical | HSM-enforced single-key access, failover procedure requires 100-block inactivity confirmation (see `docs/VALIDATOR_RUNBOOK.md`) | Mitigated |
| C-002 | Panic in ExtendVote halts consensus | Critical | Panic recovery returns empty extension (`app/abci.go` line 27-39) | Mitigated |
| C-003 | Vote extension DoS via excessive verifications | High | `MaxVerificationsPerExtension = 100` cap + wall-clock time bound (`app/vote_extension.go`) | Mitigated |
| C-004 | Vote extension timestamp manipulation | High | Timestamp skew bounds: max 10 min past, 1 min future (`app/vote_extension.go`) | Mitigated |
| C-005 | VRF bias by colluding validators | Medium | VRF proof is published on-chain and verifiable; manipulation requires controlling 2/3+ stake | Accepted (inherent to BFT) |
| C-006 | TEE attestation forgery | High | Remote attestation verified against known enclave measurements; `AllowSimulated` flag disabled in production | Mitigated |
| C-007 | Verification pipeline circular dependency | Low | Pipeline wiring in `app/` (composition root) avoids import cycles between `x/pouw` and `x/verify` | Mitigated |

---

## 7. Test Evidence

| Evidence Type | Location | Coverage/Result |
|---------------|----------|-----------------|
| Unit tests | `make test-unit` / `x/pouw/`, `x/verify/`, `app/` | >= 95% on consensus/verification paths (enforced by `make coverage-critical`) |
| Integration tests | `make test-integration` | Pass |
| Consensus-specific tests | `make test-consensus` | Pass |
| Benchmarks | `make bench` (covers `x/pouw` and `x/verify`) | See CI artifacts |
| Coverage report | `make test-coverage` -> `coverage.out` | >= 95% on critical paths |
| Fuzz tests | Foundry fuzz (256 runs default, 100 CI) for related Solidity; Go fuzz via `go test -fuzz` | Configured per module |
| Static analysis | `make lint` (golangci-lint) | Zero findings required for merge |
| E2E smoke tests | `test-results/e2e-network-smoke-*.txt` | Pass |
| E2E runtime tests | `test-results/e2e-network-runtime-*.txt` | Pass |
| Dynamic exploit simulations | `test-results/dynamic-exploit-simulations.json` | Pass |
| Load tests | `loadtest-results/` via `make loadtest` | See results |

---

## 8. Previous Audit Findings and Remediation

| Finding ID | Auditor | Severity | Description | Status | Remediation |
|------------|---------|----------|-------------|--------|-------------|
| EV-05 | Internal review | Medium | Unbounded verification loop in ExtendVote could cause timeout | Fixed | Bounded by `MaxVerificationsPerExtension` + wall-clock cap |
| EV-06 | Internal review | Medium | Vote extension could include stale verifications | Fixed | Timestamp skew bounds enforced |
| I-06 | Internal review | Informational | Cross-contract dependency documentation needed | Fixed | Architecture docs added to contract headers |

*Note: External audit engagement pending. This pack is prepared for auditor onboarding.*
