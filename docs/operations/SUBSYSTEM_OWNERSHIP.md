# Subsystem Ownership Matrix

**Document Version:** 1.0
**Last Updated:** 2026-03-25 (SQ23 Deliverable)
**Classification:** INTERNAL

---

## Overview

This document maps every major Aethelred subsystem to its responsible squad, primary contact, and escalation path. It is the authoritative source for "who owns what" during incidents, audits, and release gates.

---

## Ownership Table

| Subsystem | Squad | Scope | Key Paths |
|-----------|-------|-------|-----------|
| **Consensus (ABCI++, Vote Extensions, PoUW scheduling)** | SQ4 | `app/abci.go`, `app/vote_extension.go`, `app/verification_pipeline.go`, `x/pouw/` | Block production, vote extension signing, VRF job assignment |
| **IBC (Cross-chain proof relay)** | SQ3 | `x/ibc/` | IBC module, cross-chain proof relay |
| **Verification (ZK + TEE proof verification)** | SQ5 | `x/verify/`, `services/zkml-prover/`, `services/tee-worker/` | zkML proof verification, TEE attestation, EZKL/RISC Zero/Groth16/Halo2/Plonky2 backends |
| **Token & Vesting** | SQ8 | `contracts/contracts/AethelredToken.sol`, `contracts/contracts/AethelredVesting.sol` | Token minting/burning, vesting schedules |
| **Bridge (Ethereum relayer)** | SQ9 | `contracts/contracts/AethelredBridge.sol`, `crates/bridge/` | Lock-and-mint bridge, relayer consensus, fraud proofs, rate limiting |
| **Governance** | SQ10 | `contracts/contracts/SovereignGovernanceTimelock.sol`, `x/crisis/` | Governance timelock, proposal execution, crisis module |
| **Vault** | SQ11 | `x/vault/`, `crates/vault/` | Vault operations, asset custody |
| **Rust Core & Consensus** | SQ12 | `crates/core/`, `crates/consensus/` | PQC primitives (Dilithium3, Kyber), VRF, reputation scoring |
| **Rust Bridge & VM** | SQ13 | `crates/bridge/`, `crates/vm/`, `crates/mempool/`, `crates/sandbox/` | WASM VM, zkML precompiles, priority mempool, sandboxed execution |
| **SDK & CLI** | SQ18 | `sdk/`, `version-matrix.json` | TypeScript, Python, Go, Rust SDKs; CLI tooling |
| **Verifiers (Digital Seals)** | SQ19 | `x/seal/`, `x/verify/` | Attestation anchoring, seal verification |
| **Infrastructure** | SQ21 | `infrastructure/`, `docker/`, `.github/workflows/` | Helm charts, Terraform, Docker, CI/CD pipelines |
| **Validator Management** | SQ4 | `x/validator/` | Validator set management, staking integration |
| **Insurance** | SQ11 | `x/insurance/` | Insurance module |
| **Light Client** | SQ3 | `x/lightclient/` | Light client verification |

---

## Escalation Paths

### Standard Escalation (Non-Critical)

```
L1: Squad On-Call Engineer (respond within 30 min)
 |
 v (no response in 30 min)
L2: Squad Lead
 |
 v (no resolution in 2 hours)
L3: Platform Lead / VP Engineering
 |
 v (cross-squad dependency or architectural decision)
L4: CTO
```

### Critical Escalation (Consensus Halt, Bridge Exploit, Slashing Event)

```
L1: Squad On-Call + NOC Hotline (respond within 5 min)
 |
 v (simultaneously)
L2: Squad Lead + Platform Lead + Security Team
 |
 v (no resolution in 15 min)
L3: VP Engineering + CTO
 |
 v (customer/validator impact)
L4: CEO
```

### Cross-Squad Escalation

When an incident spans multiple subsystems:

1. The squad that first detects the issue owns the incident until handoff.
2. The owning squad's on-call opens a bridge call and pages affected squads.
3. Platform Lead acts as incident commander if three or more squads are involved.

---

## On-Call Rotation Template

Each squad maintains a weekly on-call rotation. The template below should be filled in per squad and kept in the squad's internal wiki.

| Week Starting | Primary On-Call | Secondary On-Call | Notes |
|---------------|-----------------|-------------------|-------|
| YYYY-MM-DD | (engineer name) | (engineer name) | |
| YYYY-MM-DD | (engineer name) | (engineer name) | |
| YYYY-MM-DD | (engineer name) | (engineer name) | |
| YYYY-MM-DD | (engineer name) | (engineer name) | |

### On-Call Expectations

- **Response SLA:** 5 minutes for critical alerts, 30 minutes for warnings.
- **Handoff:** On-call engineers must complete a written handoff at rotation end.
- **Tools:** PagerDuty (or equivalent) must be configured for all critical alert routes.
- **Runbooks:** Each squad must maintain runbooks for their subsystem in `docs/operations/`.

---

## Review Schedule

This document is reviewed and updated:
- At the start of each quarter
- When squads are reorganized
- When new subsystems are added

**Owner of this document:** Platform Lead
