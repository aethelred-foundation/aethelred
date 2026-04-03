# Framework-to-Evidence Mapping

> **WARNING:** This is a scaffold. Every claim in the DLT Framework must map to a verifiable evidence source. Claims without evidence must be removed or marked as "pending."

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign] |
| **Version** | 0.1.0 (Scaffold) |
| **Status** | Scaffold |
| **Last Updated** | 2026-04-03 |

---

## Evidence Map

| # | Framework Claim | Section | Evidence Source | Evidence Status | Notes |
|---|----------------|---------|---------------|-----------------|-------|
| 1 | Post-quantum cryptography (ML-DSA-65 + ML-KEM-768) | Security | `crates/` implementation, audit reports | Implemented — audit pending | |
| 2 | TEE attestation (SGX, SEV-SNP, Nitro, Azure, CoCo) | Security | `crates/` implementation | Implemented | |
| 3 | CometBFT consensus | Governance | `go/` implementation, Cosmos SDK integration | Implemented | |
| 4 | Proof of Useful Work (PoUW) | Governance | `crates/consensus/`, whitepaper | Implemented — audit pending | |
| 5 | Slashing for equivocation | Security | `go/` staking module | Implemented | |
| 6 | 27 internal findings remediated | Security | `docs/audits/STATUS.md` | Verified 2026-03-30 | |
| 7 | 36 full audit v2 findings closed | Security | `docs/audits/STATUS.md` | Verified 2026-03-30 | |
| 8 | VRF finding (consultant) fixed | Security | `docs/audits/STATUS.md` | Verified | |
| 9 | Formal verification plan | Security | `docs/security/FORMAL_VERIFICATION.md` | Plan exists — execution pending | |
| 10 | Fuzzing infrastructure | Security | `docs/security/FUZZING.md`, CI pipeline | Active | |
| 11 | Security scanning (gosec, trivy, gitleaks, slither, cargo-audit) | Operations | CI/CD configuration | Active — all passing | |
| 12 | Incident response procedures | Operations | `docs/security/SECURITY_RUNBOOKS.md` | Documented | |
| 13 | Threat model | Security | `docs/security/threat-model.md` | Documented | |
| 14 | Bug bounty program | Security | `docs/security/BUG_BOUNTY_SLA.md`, `SECURITY.md` | Active | |
| 15 | Production gating plan | Operations | `docs/operations/GATE_INVENTORY.md` | Active — mainnet blocked on external audits | |
| 16 | AIP governance process | Change Mgmt | `docs/AIPs/` (3 AIPs published) | Active | |
| 17 | External audits (AUD-2026-001, AUD-2026-002) | Security | `docs/audits/STATUS.md` | **In progress — not yet complete** | |
| 18 | Statutory auditor appointment | Operations | — | **Missing** | SQ-ADGM-09 |
| 19 | CSP appointment | Governance | — | **Missing** | SQ-ADGM-05 |
| 20 | Foundation charter | Governance | `legal/adgm-dlt-foundation/charter/` | **Scaffold only** | SQ-ADGM-04 |

---

## Evidence Status Key

- **Implemented** — Code exists and passes tests
- **Verified** — Independently reviewed and confirmed
- **Documented** — Procedure/policy exists in writing
- **Active** — Ongoing process in operation
- **Plan exists** — Documented plan but not yet executed
- **Scaffold only** — Template created, content not yet written
- **In progress** — Work underway but not complete
- **Missing** — No evidence exists; requires action
