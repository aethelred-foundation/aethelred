# DLT Framework — Draft

> **WARNING:** This is a scaffold. It requires completion by the technical team and review by legal counsel before submission. The framework must convert technical documentation into regulator-readable narrative.

| Attribute | Value |
|-----------|-------|
| **Owner** | [Assign — CTO / Head of Protocol] |
| **Version** | 0.1.0 (Scaffold) |
| **Reviewer** | [Legal Counsel] |
| **Status** | Scaffold |
| **Last Updated** | 2026-04-03 |

---

## 1. Executive Summary

[Convert the whitepaper abstract into a regulator-facing summary. Focus on: what the protocol does, who it serves, what controls are in place, and what the Foundation's role is.]

## 2. Governance

[Describe the governance model in regulatory terms:]
- Foundation governance structure (Council, Founder, Guardian roles)
- Protocol governance (on-chain voting, technical council)
- Relationship between legal governance and protocol governance
- Decision-making authority and escalation paths

**Evidence:** `docs/WHITEPAPER.md` (governance sections), `legal/adgm-dlt-foundation/charter/governance-framework.md`

## 3. Security Controls

[Summarize security posture for regulators:]
- Cryptographic foundations (ML-DSA-65 post-quantum, ECDSA hybrid)
- Trusted Execution Environment (TEE) requirements
- Key management and custody (HSM, FIPS-level)
- Network security (sentry topology, validator isolation)
- Smart contract security (audit status, formal verification plans)

**Evidence:** `docs/security/threat-model.md`, `docs/audits/STATUS.md`, `docs/security/VERIFICATION_POLICY.md`

## 4. Operational Controls

[Describe production operational framework:]
- Validator admission and monitoring
- Incident response procedures
- Disaster recovery and business continuity
- Monitoring and alerting
- Uptime targets and SLA framework

**Evidence:** `docs/security/SECURITY_RUNBOOKS.md`, `docs/operations/GATE_INVENTORY.md`

## 5. Disclosure Controls

[Describe information governance:]
- Canonical source index and document control
- Public claims governance (site claims register)
- Counterparty disclosure controls
- Benchmark governance for performance claims
- Prohibited phrases framework

**Evidence:** `docs/CANONICAL_SOURCE_INDEX.md`, `legal/adgm-dlt-foundation/site-claims-register.md`, `docs/operations/prohibited-phrases/`

## 6. Monitoring and Reporting

[Describe ongoing monitoring:]
- On-chain monitoring and analytics
- Security scanning (SAST, DAST, dependency scanning)
- Compliance monitoring calendar
- Regulatory reporting obligations

**Evidence:** `docs/audits/STATUS.md`, CI/CD pipeline configuration

## 7. Incident Response

[Summarize incident handling:]
- Severity classification
- Response procedures by severity
- Communication procedures (internal, regulator, public)
- Post-incident review process

**Evidence:** `docs/security/SECURITY_RUNBOOKS.md`, `SECURITY.md`

## 8. Change Management

[Describe how protocol changes are governed:]
- Aethelred Improvement Proposal (AIP) process
- Upgrade governance and approval
- Testnet-to-mainnet promotion gates
- Emergency change procedures

**Evidence:** `docs/AIPs/`, `docs/operations/GATE_INVENTORY.md`

## 9. Outstanding Gaps

[List every unresolved gap honestly:]
- [ ] External audits AUD-2026-001 and AUD-2026-002 still in progress
- [ ] Mainnet launch blocked until external audits complete
- [ ] CSP not yet appointed
- [ ] Legal counsel review of all framework claims pending
- [ ] Statutory auditor not yet appointed
- [ ] [Additional gaps to be identified during framework completion]
