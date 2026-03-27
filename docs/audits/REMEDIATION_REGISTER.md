# Audit Remediation Register

> **Document owner:** Security & Compliance Lead
> **Effective:** 2026-03-25
> **Purpose:** Track the remediation lifecycle for every audit finding across all engagements, categorized by subsystem.

---

## How to Use This Register

1. When a new audit finding is reported, add a row to the appropriate category table below.
2. Update the **Status** column as work progresses through the lifecycle.
3. Link every remediation to a specific PR or commit SHA.
4. Record the verification artifact that proves the fix works.
5. Update the **Date** column when status changes.
6. For Accepted Risk findings, fill in the rationale template at the bottom of this document.

---

## Status Lifecycle

```
Open -> In Progress -> Remediated -> Verified
                    \-> Accepted Risk (with justification + compensating controls)
                    \-> Disputed (with rationale communicated to auditor)
```

| Status | Definition |
|--------|-----------|
| Open | Finding reported, no remediation started |
| In Progress | Remediation work underway, assigned to owner |
| Remediated | Fix merged; regression test or guard script confirms the fix |
| Verified | Auditor has re-tested and confirmed remediation |
| Accepted Risk | Risk acknowledged by Security Lead with documented justification and compensating controls |
| Disputed | Finding validity contested; rationale documented and communicated to auditor |
| Remediated Locally | Fix applied in local clone, pending push to public repo |
| Partially Remediated | Some aspects addressed, remaining action items documented |

---

## Category: Smart Contract

**Scope:** `contracts/contracts/`, `contracts/bridges/`, `contracts/test/`
**Audit engagements:** AUD-2026-001, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| C-01 | INT-2026-002 | Critical | Smart Contract | Bridge deposit lifecycle not finalized on-chain | Remediated | Smart Contracts | `contracts/contracts/AethelredBridge.sol` | `contracts/test/bridge.emergency.test.ts` | 2026-02-23 |
| C-02 | INT-2026-002 | Critical | Smart Contract | Missing admin/multisig enforcement on initializers | Remediated | Smart Contracts | Multiple contract files | Contract regression tests | 2026-02-23 |
| C-04 | INT-2026-002 | Critical | Smart Contract | Vesting cliff/linear math error | Remediated | Smart Contracts | `contracts/contracts/AethelredVesting.sol` | `contracts/test/vesting.critical.test.ts` | 2026-02-23 |
| H-01 | INT-2026-002 | High | Smart Contract | `bridgeBurn()` missing ERC-20 allowance enforcement | Remediated | Smart Contracts | `contracts/contracts/AethelredToken.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-02 | INT-2026-002 | High | Smart Contract | Deposit ID collision risk | Remediated | Smart Contracts | `contracts/contracts/AethelredBridge.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-03 | INT-2026-002 | High | Smart Contract | Relayer count/threshold desync on role changes | Remediated | Smart Contracts | `contracts/contracts/AethelredBridge.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-04 | INT-2026-002 | High | Smart Contract | ISB mint ceiling TOCTOU | Remediated | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` | `contracts/test/institutional.stablecoin.integration.test.ts` | 2026-02-23 |
| H-05 | INT-2026-002 | High | Smart Contract | Emergency withdrawal bypasses pause state | Remediated | Smart Contracts | `contracts/contracts/AethelredBridge.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-06 | INT-2026-002 | High | Smart Contract | Timelock self-grant privilege escalation | Remediated | Smart Contracts | `contracts/contracts/SovereignGovernanceTimelock.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-07 | INT-2026-002 | High | Smart Contract | `setCategoryCap()` invariant violation | Remediated | Smart Contracts | `contracts/contracts/AethelredVesting.sol` | `contracts/test/high.findings.regression.test.ts` | 2026-02-23 |
| H-09 | INT-2026-002 | High | Smart Contract | PoR checks not inline on mint path | Remediated | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` | `contracts/test/institutional.stablecoin.integration.test.ts` | 2026-02-23 |
| M-01 | INT-2026-002 | Medium | Smart Contract | Missing EIP-712 domain separation | Remediated | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` | `contracts/test/institutional.stablecoin.integration.test.ts` | 2026-02-23 |
| M-02 | INT-2026-002 | Medium | Smart Contract | Unbounded outflow mappings | Remediated | Smart Contracts | `contracts/contracts/InstitutionalStablecoinBridge.sol` | `contracts/test/institutional.stablecoin.integration.test.ts` | 2026-02-23 |
| M-03 | INT-2026-002 | Medium | Smart Contract | `recoverTokens()` surplus handling | Remediated | Smart Contracts | `contracts/contracts/AethelredVesting.sol` | `contracts/test/medium.findings.regression.test.ts` | 2026-02-23 |
| M-06 | INT-2026-002 | Medium | Smart Contract | `adminBurn()` unilateral instant burn | Remediated | Smart Contracts | `contracts/contracts/AethelredToken.sol` | `contracts/test/medium.findings.regression.test.ts` | 2026-02-23 |
| L-02 | INT-2026-002 | Low | Smart Contract | Missing upgrade storage gaps in bridge | Remediated | Smart Contracts | Bridge contracts | `scripts/validate-low-findings-guards.sh` | 2026-02-23 |

---

## Category: Consensus

**Scope:** `app/`, `x/pouw/`, `x/verify/`, `x/validator/`
**Audit engagements:** AUD-2026-002, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| C-03 | INT-2026-002 | Critical | Consensus | `AllowSimulated` production bypass not hardened | Remediated | Core Protocol | `x/pouw/keeper/consensus.go` | Production build-tag assertion | 2026-02-23 |
| M-04 | INT-2026-002 | Medium | Consensus | Validator zone-cap TOCTOU | Remediated | Core Protocol | `x/validator/keeper/keeper.go` | `x/validator/keeper/keeper_additional_test.go` | 2026-02-23 |
| M-05 | INT-2026-002 | Medium | Consensus | PoUW validator selection determinism gap | Remediated | Core Protocol | `x/pouw/keeper/staking.go` | `scripts/validate-pouw-medium-guards.sh` | 2026-02-23 |
| M-08 | INT-2026-002 | Medium | Consensus | Test threshold override in production build | Remediated | Core Protocol | `x/pouw/keeper/consensus_testing_override_nonprod.go` | `scripts/validate-pouw-medium-guards.sh` | 2026-02-23 |

---

## Category: Bridge (Rust Relayer)

**Scope:** `crates/bridge/`
**Audit engagements:** INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| _No findings specific to the Rust bridge relayer in current engagements_ | | | | | | | | | |

---

## Category: Cryptographic

**Scope:** `crates/core/`, `crates/consensus/`, `sdk/typescript/src/crypto/`
**Audit engagements:** CON-2026-001, INT-2026-002

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| RS-01 | CON-2026-001 | Critical | Cryptographic | Non-constant-time hash-to-curve in VRF | Remediated | Core Protocol | `crates/consensus/src/vrf.rs` (lines 457-496) | RFC 9380 Simplified SWU via `k256::hash2curve` | 2026-02-28 |
| C-05 | INT-2026-002 | Critical | Cryptographic | TypeScript PQC `verify()` accepts placeholder | Remediated | SDK | `sdk/typescript/src/crypto/pqc.ts` | `sdk/typescript/src/crypto/pqc.test.ts` | 2026-02-23 |
| H-08 | INT-2026-002 | High | Cryptographic | Rust pillar placeholders in production | Remediated | Core Protocol | `core/src/pillars/` | Production compile guards | 2026-02-23 |
| H-10 | INT-2026-002 | High | Cryptographic | TypeScript PQC `sign()` generates fake signatures | Remediated | SDK | `sdk/typescript/src/crypto/pqc.ts` | `sdk/typescript/src/crypto/pqc.test.ts` | 2026-02-23 |
| H-11 | INT-2026-002 | High | Cryptographic | TypeScript SEV/Nitro verification placeholder | Remediated | SDK | `sdk/typescript/src/crypto/tee.ts` | `sdk/typescript/src/crypto/tee.test.ts` | 2026-02-23 |
| L-01 | INT-2026-002 | Low | Cryptographic | Token burn floating-point accounting | Remediated | Core Protocol | `core/src/pillars/quadratic_burn.rs` | Source-level regression tests | 2026-02-23 |
| L-04 | INT-2026-002 | Low | Cryptographic | `cosine_similarity()` zero denominator | Remediated | Core Protocol | `core/src/pillars/vector_vault.rs` | Source-level regression tests | 2026-02-23 |
| L-07 | INT-2026-002 | Low | Cryptographic | Placeholder Nitro root certificate | Remediated | SDK | `sdk/typescript/src/crypto/tee.ts` | `sdk/typescript/src/crypto/tee.test.ts` | 2026-02-23 |

---

## Category: Operational

**Scope:** Infrastructure, CI/CD, configuration, process
**Audit engagements:** INT-2026-002, MR-2026-001

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| C-06 | INT-2026-002 | Critical | Operational | Simulated TEE/prover defaults in production compose | Remediated | Infrastructure | Compose split + `scripts/validate-compose-security.sh` | `audit-config-guards.yml` | 2026-02-23 |
| H-12 | INT-2026-002 | High | Operational | Hardcoded Grafana admin password in compose | Remediated | Infrastructure | Compose files + `scripts/validate-compose-security.sh` | `audit-config-guards.yml` | 2026-02-23 |
| M-07 | INT-2026-002 | Medium | Operational | TEE quote-type detection weakness | Remediated | TEE | `services/tee-worker/nitro-sdk/src/attestation/engine.rs` | Feature-gated attestation test | 2026-02-23 |
| M-09 | INT-2026-002 | Medium | Operational | Devnet unbonding period too low for production | Remediated | Infrastructure | Devnet `genesis.json` | `scripts/validate-devnet-genesis.py` | 2026-02-23 |
| M-10 | INT-2026-002 | Medium | Operational | Devnet attestation floor mismatch | Remediated | Infrastructure | Devnet `genesis.json` | `scripts/validate-devnet-genesis.py` | 2026-02-23 |
| L-03 | INT-2026-002 | Low | Operational | EPID-specific info leak in error messages | Remediated | TEE | `services/tee-worker/nitro-sdk/src/attestation/engine.rs` | Feature-gated test + guard script | 2026-02-23 |
| L-05 | INT-2026-002 | Low | Operational | `.DS_Store` tracked in repos | Remediated | All | `.gitignore` updates | `scripts/validate-low-findings-guards.sh` | 2026-02-23 |
| L-06 | INT-2026-002 | Low | Operational | Rust `target/` artifacts tracked in git | Remediated | All | `.gitignore` updates | `scripts/validate-low-findings-guards.sh` | 2026-02-23 |
| L-08 | INT-2026-002 | Info | Operational | Missing API-key auth header support in SDK | Remediated | SDK | `sdk/typescript/src/core/client.ts` | `sdk/typescript/src/core/client.test.ts` | 2026-02-23 |
| AETHEL-MR-001 | MR-2026-001 | Critical | Operational | Duplicate chain repos with same Go module path | Partially Remediated | Governance | Authority registry + ADR-0001 prepared | Pending Foundation ratification | 2026-02-24 |
| AETHEL-MR-002 | MR-2026-001 | Critical | Operational | `aethelred-rust-node` non-buildable repo | Remediated Locally | Core Protocol | `Cargo.toml` + CI added locally | `cargo check --offline` passes | 2026-02-24 |
| AETHEL-MR-003 | MR-2026-001 | Critical | Operational | Audit evidence fragmented outside public repos | Partially Remediated | Security / PMO | Baseline CI added to 9 local clones | Auditability rollout matrix | 2026-02-24 |
| AETHEL-MR-004 | MR-2026-001 | High | Operational | Absolute local workstation paths in public docs | Remediated Locally | Docs | Path references replaced | `0` absolute paths in scan | 2026-02-24 |
| AETHEL-MR-005 | MR-2026-001 | High | Operational | SDKs pending public artifact publication | Partially Remediated | SDK | Provenance controls added | Pending registry publish | 2026-02-24 |
| AETHEL-MR-006 | MR-2026-001 | High | Operational | Security workflow targets stale contract paths | Remediated Locally | Security | `security-scans.yml` updated | Path existence check | 2026-02-24 |
| AETHEL-MR-007 | MR-2026-001 | High | Operational | Threat models/SBOMs not visible per repo | Partially Remediated | Security | `SECURITY.md` + threat model skeletons | Pending completion per repo | 2026-02-24 |
| AETHEL-MR-008 | MR-2026-001 | Medium | Operational | Dashboard lacks explicit CSP headers | Partially Remediated | Frontend | CSP header added (still has `unsafe-inline`) | Pending nonce/hash migration | 2026-02-24 |
| AETHEL-MR-009 | MR-2026-001 | Medium | Operational | Uneven test maturity across repos | Partially Remediated | All Squads | Baseline CI added everywhere | Pending enforced test gates | 2026-02-24 |
| AETHEL-MR-010 | MR-2026-001 | Medium | Operational | `nitro-sdk` `full-sdk` warnings not at zero | Remediated Locally | TEE | Doc comment fix | `cargo check --features full-sdk` = 0 warnings | 2026-02-24 |

---

## Pending External Audit Findings

### Engagement: AUD-2026-001 (External -- Smart Contracts)

Status: In Progress (started 2026-02-14)

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| _Findings will be added as the audit report is delivered_ | | | | | | | | | |

### Engagement: AUD-2026-002 (External -- Consensus + Vote Extensions)

Status: In Progress (started 2026-02-14)

| Finding ID | Source | Severity | Category | Description | Status | Owner | PR / Commit | Verification | Date |
|------------|--------|----------|----------|-------------|--------|-------|-------------|--------------|------|
| _Findings will be added as the audit report is delivered_ | | | | | | | | | |

---

## Aggregate Statistics

### By Severity (All Engagements)

| Severity | Total | Open | In Progress | Remediated | Partially Remediated | Accepted Risk | Disputed |
|----------|------:|-----:|------------:|-----------:|---------------------:|--------------:|---------:|
| Critical | 10 | 0 | 0 | 7 | 3 | 0 | 0 |
| High | 16 | 0 | 0 | 13 | 3 | 0 | 0 |
| Medium | 13 | 0 | 0 | 10 | 3 | 0 | 0 |
| Low/Info | 8 | 0 | 0 | 8 | 0 | 0 | 0 |
| **Total** | **47** | **0** | **0** | **38** | **9** | **0** | **0** |

### By Category

| Category | Total | Remediated | Partially Remediated | Open |
|----------|------:|-----------:|---------------------:|-----:|
| Smart Contract | 16 | 16 | 0 | 0 |
| Consensus | 4 | 4 | 0 | 0 |
| Cryptographic | 8 | 8 | 0 | 0 |
| Operational | 19 | 10 | 9 | 0 |
| Bridge (Rust) | 0 | 0 | 0 | 0 |
| **Total** | **47** | **38** | **9** | **0** |

### Notes

- 9 findings are "Partially Remediated" or "Remediated Locally" -- these are multi-repo governance/process findings (AETHEL-MR series) that require public repo pushes or Foundation-level ratification.
- 2 external audit engagements (AUD-2026-001, AUD-2026-002) are in progress; findings will be added when reports are delivered.
- All 36 findings from INT-2026-002 and the 1 finding from CON-2026-001 are fully remediated.

---

## Accepted-Risk Rationale Template

When a finding is marked as **Accepted Risk**, copy this template and fill it in as a new section below.

### [Finding ID]: [Brief Description]

| Field | Value |
|-------|-------|
| **Finding ID** | e.g., `M-XX` |
| **Source** | Audit engagement ID |
| **Severity** | Critical / High / Medium / Low |
| **Category** | Smart Contract / Consensus / Bridge / Cryptographic / Operational |
| **Description** | Full description of the finding |
| **Risk Assessment** | Detailed assessment of the residual risk if unresolved |
| **Business Justification** | Why accepting this risk is the appropriate decision |
| **Compensating Controls** | What mitigations are in place to reduce the residual risk |
| **Monitoring** | How the risk will be monitored going forward |
| **Review Date** | When the accepted risk will next be reviewed |
| **Approved By** | Name and role of the approver |
| **Approval Date** | Date of approval |

**Example:**

### AR-001: Example Accepted Risk

| Field | Value |
|-------|-------|
| **Finding ID** | M-99 |
| **Source** | AUD-2026-001 |
| **Severity** | Medium |
| **Category** | Smart Contract |
| **Description** | Example: Gas optimization in rarely-called admin function exceeds recommended threshold |
| **Risk Assessment** | Function is called <1x/month by multisig; gas cost is borne by protocol treasury, not end users |
| **Business Justification** | Refactoring would require a storage layout migration that introduces upgrade risk greater than the gas cost |
| **Compensating Controls** | (1) Function is behind 3-of-5 multisig. (2) Gas monitoring alert triggers if cost exceeds 2x baseline. (3) Upgrade path documented for future optimization |
| **Monitoring** | Monthly gas cost review in ops dashboard |
| **Review Date** | 2026-06-25 (90-day review) |
| **Approved By** | Security Lead |
| **Approval Date** | YYYY-MM-DD |

---

## Template: Adding a New Finding

Copy and paste this row into the appropriate category table:

```
| FINDING-ID | SOURCE-ENGAGEMENT | Severity | Category | Brief description | Open | Squad Name | | | YYYY-MM-DD |
```

Update the aggregate statistics tables when adding or changing finding status.

---

## References

- Evidence index: [`docs/audits/EVIDENCE_INDEX.md`](EVIDENCE_INDEX.md)
- Scope map: [`docs/audits/SCOPE_MAP.md`](SCOPE_MAP.md)
- Audit status tracker: [`docs/audits/STATUS.md`](STATUS.md)
- Full audit v2 matrix: [`docs/audits/aethelred-full-audit-report-v2-remediation-matrix.md`](aethelred-full-audit-report-v2-remediation-matrix.md)
- Multi-repo disposition: [`docs/audits/aethelred-multi-repo-findings-disposition-2026-02-24.md`](aethelred-multi-repo-findings-disposition-2026-02-24.md)
- Retest checklist: [`docs/audits/aethelred-v2-retest-checklist.md`](aethelred-v2-retest-checklist.md)
