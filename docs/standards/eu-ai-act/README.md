# Aethelred EU AI Act Compliance Guide

## Meeting Obligations for High-Risk AI Systems

**Version:** 1.0  
**Last Updated:** April 2026  
**Classification:** Public -- Procurement-Ready

---

## 1. Overview

The EU AI Act establishes a risk-based regulatory framework for AI systems deployed within the European Union. Aethelred is designed to address the requirements placed on providers and deployers of high-risk AI systems, which face the most stringent obligations including conformity assessment, technical documentation, human oversight, and post-market monitoring.

This document maps Aethelred capabilities to each relevant EU AI Act obligation, providing implementation guidance for organizations deploying high-risk AI systems on the Aethelred platform.

---

## 2. Risk Classification Support

The EU AI Act classifies AI systems into four risk tiers. Aethelred provides tooling to support classification and compliance for each tier.

| Risk Tier | EU AI Act Articles | Aethelred Support |
|---|---|---|
| **Unacceptable Risk** | Art. 5 (Prohibited) | PolicyEngine can enforce prohibition rules, blocking deployment of prohibited systems |
| **High Risk** | Art. 6-51 (Full obligations) | Complete compliance stack: documentation, human oversight, monitoring, conformity assessment evidence |
| **Limited Risk** | Art. 52 (Transparency) | Seal provenance chains and audit trails provide transparency evidence |
| **Minimal Risk** | N/A (Voluntary codes) | Governance framework provides optional best-practice compliance |

---

## 3. High-Risk AI System Obligations

### Chapter 2: Requirements for High-Risk AI Systems

#### Article 9 -- Risk Management System

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Continuous iterative risk management | `PolicyEngine` with evolving rule sets; `AuditStudio` continuous monitoring; `pkg/assurance` drift detection | `pkg/governance/policy`, `pkg/audit`, `pkg/assurance` | Policy version history, monitoring records, drift alerts |
| Risk identification and analysis | `pkg/compliance` framework mappings identify risks; `CoverageLevel` (Full/Partial/Planned/Gap) quantifies risk treatment status | `pkg/compliance` | Coverage assessments, gap analysis reports |
| Risk estimation and evaluation | Compliance assessor evaluates risk across 6 frameworks; sector-specific assessments (CMMC, HIPAA, finance) | `pkg/compliance/assessor` | Assessment results, sector-specific evaluations |
| Risk treatment and residual risk | `PolicyEngine.Evaluate()` decision types implement treatments; exception handling for residual risk; break-glass for emergencies | `pkg/governance/policy` | Treatment records, exception logs, break-glass justifications |
| Testing and risk management measures | Evidence bundles document testing; seal verification confirms integrity; hash chain validates audit data | `pkg/audit`, `pkg/seal/sdk` | Test evidence bundles, verification reports |

**Implementation Status:** Full

#### Article 10 -- Data and Data Governance

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Training, validation, and testing data governance | Digital Seals on data provenance; `RegulatoryConfig` captures data classification and jurisdiction | `pkg/seal/sdk` | Data provenance seals, classification records |
| Data quality criteria | FHIR adapter validates resource conformance; EPCIS adapter validates event schemas; policy rules enforce quality constraints | `pkg/integrations/fhir`, `pkg/integrations/epcis`, `pkg/governance/policy` | Validation records, quality assessment logs |
| Bias examination | Integration point: policy rules can enforce fairness constraints; monitoring for disparate outcomes via audit trail analysis | `pkg/governance/policy`, `pkg/audit` | Fairness evaluation records |
| Data subject rights (GDPR alignment) | `ConsentValidator` enforces consent-gated processing; consent revocation workflow; evidence of lawful basis | `pkg/integrations/fhir` | Consent records, revocation logs |

**Implementation Status:** Partial (bias examination is an integration point)

#### Article 11 -- Technical Documentation

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| General description of the AI system | Seal metadata captures system description; `RegulatoryConfig` documents purpose, frameworks, jurisdictions | `pkg/seal/sdk` | System description records |
| Detailed description of system elements | Evidence bundles document architecture, data flows, and components | `pkg/audit` | Technical documentation bundles |
| Development process information | Audit trail captures development lifecycle events; seal provenance tracks system evolution | `pkg/audit`, `pkg/seal/sdk` | Development lifecycle evidence |
| Monitoring, functioning, and control | `AuditStudio` monitoring records; `PolicyEngine` control records; safety controller records (AV) | `pkg/audit`, `pkg/governance/policy`, sector adapters | Monitoring and control evidence |
| Risk management documentation | Complete NIST AI RMF alignment documentation; evidence bundles with framework mappings | `pkg/compliance`, `pkg/audit` | Risk management evidence packages |
| Changes and modifications log | Seal versioning tracks all changes; policy change events audited; configuration seals | `pkg/seal/sdk`, `pkg/governance/policy` | Change log, version history |

**Implementation Status:** Full

#### Article 12 -- Record-Keeping

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Automatic logging capabilities | `AuditStudio` provides automatic, continuous logging with hash chain integrity | `pkg/audit` | Hash-chained audit log |
| Traceability of operation | Seal provenance chains trace every operation; agent receipts trace agent actions | `pkg/seal/sdk`, `pkg/protocol/agent` | Provenance chains, action receipts |
| Identification of input data | Input data sealed with content hash; FHIR resources, EPCIS events, financial transactions all input-sealed | Sector adapters | Input data seals |
| Facilitation of post-market monitoring | Continuous monitoring via `AuditStudio` and `pkg/assurance` | `pkg/audit`, `pkg/assurance` | Monitoring records, drift alerts |

**Implementation Status:** Full

#### Article 13 -- Transparency and Provision of Information

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Transparency for deployers | Seal provenance chains document AI decision lineage; policy decision records show governance rationale | `pkg/seal/sdk`, `pkg/governance/policy` | Provenance chains, decision records |
| Instructions for use | Evidence bundles include operational documentation; sector-specific deployment guides | `pkg/audit` | Documentation bundles |
| Human-interpretable output format | Evidence bundles exportable as JSON, CSV, OSCAL; sector-specific reports in standard formats | `pkg/audit`, sector adapters | Exportable reports |

**Implementation Status:** Full

#### Article 14 -- Human Oversight

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Human oversight measures | `RequireApproval` decision type for single-approver review; `RequireDualControl` for dual approval; `RequireCommittee` for committee review | `pkg/governance/policy` | Approval records, committee decision records |
| Ability to override AI decisions | Break-glass override mechanism with mandatory justification; `Deny` decision enforces human decision | `pkg/governance/policy` | Override records, break-glass logs |
| Ability to stop AI system | Policy Engine `Deny` blocks operation; kill switch (AV); delegation revocation (agents) | `pkg/governance/policy`, `pkg/integrations/av`, `pkg/protocol/agent` | Stop action records |
| Understanding AI outputs | Seal provenance provides output lineage; action receipts document agent reasoning | `pkg/seal/sdk`, `pkg/protocol/agent` | Output lineage records |

**Implementation Status:** Full

#### Article 15 -- Accuracy, Robustness, and Cybersecurity

| Requirement | Aethelred Implementation | Package | Evidence |
|---|---|---|---|
| Appropriate levels of accuracy | Sector-specific accuracy monitoring: sensor confidence (AV), screening match threshold (finance) | Sector adapters | Accuracy monitoring records |
| Resilience against errors | Exception handling workflows; safety controller (AV) with MRC fallback; policy engine escalation | `pkg/governance/policy`, sector adapters | Error handling records, safety response logs |
| Cybersecurity measures | Digital Seals with SHA-256 integrity; ECDSA signatures; HSM-backed key management; air-gap support | `pkg/seal/sdk`, `pkg/integrations/defense` | Integrity verification, security configuration records |
| Robustness against adversarial inputs | Seal verification detects tampered data; hash chain integrity validates audit trail | `pkg/seal/sdk`, `pkg/audit` | Verification results, integrity reports |

**Implementation Status:** Full

---

### Chapter 3: Obligations of Providers and Deployers

#### Article 16 -- Provider Obligations

| Obligation | Aethelred Support | Evidence |
|---|---|---|
| Ensure compliance with Chapter 2 requirements | Complete mapping above; evidence bundles package proof per requirement | Evidence bundles with Article mappings |
| Quality management system | Policy Engine + Audit Studio provide automated quality management | Quality management evidence |
| Technical documentation maintenance | Seal versioning and evidence bundles maintain documentation | Versioned documentation packages |
| Conformity assessment cooperation | Evidence packages structured for conformity body review | Conformity assessment evidence |
| CE marking affixing | Integration point: evidence bundles support CE marking process | CE marking support documentation |
| Post-market monitoring system | AuditStudio + Assurance Fabric provide continuous monitoring | Post-market monitoring records |

#### Article 26 -- Deployer Obligations

| Obligation | Aethelred Support | Evidence |
|---|---|---|
| Technical and organizational measures | PolicyEngine + AuditStudio implement measures; evidence bundles document them | Measure implementation records |
| Input data relevance monitoring | Data quality validation at ingestion; sector-specific validation (FHIR, EPCIS) | Data quality records |
| Human oversight implementation | RequireApproval/RequireDualControl/RequireCommittee decision types | Oversight records |
| Record-keeping per Article 12 | Automatic hash-chained audit log | Audit trail records |
| DPIA per GDPR where applicable | Compliance framework mappings support DPIA process; evidence bundles | DPIA support evidence |
| Incident notification (Art. 62) | Incident response workflows; sector-specific incident management | Incident records, notification evidence |

---

## 4. Conformity Assessment Support

### Article 43 -- Conformity Assessment

Aethelred supports conformity assessment by generating structured evidence packages:

```
Conformity Assessment Package
├── Technical Documentation (Art. 11)
│   ├── System description with RegulatoryConfig
│   ├── Architecture documentation
│   ├── Data governance evidence
│   └── Development lifecycle records
├── Risk Management Evidence (Art. 9)
│   ├── NIST AI RMF alignment report
│   ├── Risk treatment records
│   └── Residual risk documentation
├── Quality Management Evidence (Art. 17)
│   ├── Policy Engine configuration
│   ├── Audit trail integrity verification
│   └── Monitoring records
├── Record-Keeping Evidence (Art. 12)
│   ├── Hash-chained audit log
│   ├── Provenance chains
│   └── Action receipts
├── Human Oversight Evidence (Art. 14)
│   ├── Approval workflow records
│   ├── Override and break-glass logs
│   └── Committee decision records
└── Post-Market Monitoring Evidence (Art. 61)
    ├── Continuous monitoring records
    ├── Drift detection alerts
    └── Incident response records
```

---

## 5. Sector-Specific EU AI Act Compliance

### 5.1 Healthcare (Annex III, Section 5)

High-risk classification applies to AI systems intended to evaluate eligibility for health services, assist in medical diagnoses, or triage patients.

| Additional Requirement | Aethelred Implementation |
|---|---|
| Patient safety | FHIR bridge consent validation, policy engine clinical review |
| Medical device regulation alignment | Evidence bundles structured for MDR/IVDR review |
| Clinical data governance | ConsentRequired enforcement, HIPAA + GDPR dual compliance |

### 5.2 Safety Components (Annex III, Section 1)

High-risk classification applies to AI systems that are safety components of products (e.g., autonomous vehicles).

| Additional Requirement | Aethelred Implementation |
|---|---|
| ISO 26262 alignment | Safety controller with ASIL-mapped levels |
| Functional safety evidence | Telemetry receipts, incident timelines, safety evaluations |
| Post-market surveillance | Continuous monitoring with NHTSA/UNECE reporting |

---

## 6. Implementation Checklist

| Step | Action | Aethelred Tool | Priority |
|---|---|---|---|
| 1 | Classify AI system risk level | `pkg/compliance` framework mapping | Required |
| 2 | Deploy risk management system | `PolicyEngine` + `AuditStudio` | Required |
| 3 | Implement data governance | Sector adapter + `RegulatoryConfig` | Required |
| 4 | Generate technical documentation | `EvidenceBundleBuilder` | Required |
| 5 | Enable automatic record-keeping | `AuditStudio` hash-chained log | Required |
| 6 | Implement human oversight | `RequireApproval`/`RequireDualControl` decisions | Required |
| 7 | Deploy cybersecurity measures | Digital Seals + HSM key management | Required |
| 8 | Establish post-market monitoring | `pkg/assurance` + continuous monitoring | Required |
| 9 | Prepare conformity assessment package | `EvidenceBundleBuilder` with EU AI Act mappings | Required |
| 10 | Configure incident notification | `pkg/operations/incident` + reporting | Required |

---

## 7. Coverage Summary

| EU AI Act Chapter/Article | Coverage |
|---|---|
| Art. 9 -- Risk Management | Full |
| Art. 10 -- Data Governance | Partial (bias examination is integration point) |
| Art. 11 -- Technical Documentation | Full |
| Art. 12 -- Record-Keeping | Full |
| Art. 13 -- Transparency | Full |
| Art. 14 -- Human Oversight | Full |
| Art. 15 -- Accuracy/Robustness/Cybersecurity | Full |
| Art. 16 -- Provider Obligations | Full |
| Art. 26 -- Deployer Obligations | Full |
| Art. 43 -- Conformity Assessment | Full |
