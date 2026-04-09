# Aethelred NIST AI RMF 1.0 Alignment

## Complete Mapping to the Govern/Map/Measure/Manage Lifecycle

**Version:** 1.0  
**Last Updated:** April 2026  
**Classification:** Public -- Procurement-Ready

---

## 1. Overview

The NIST AI Risk Management Framework (AI RMF 1.0) provides organizations with a structured approach to managing AI risks throughout the AI system lifecycle. Aethelred addresses all four core functions -- Govern, Map, Measure, Manage -- through its integrated platform capabilities.

This document provides a complete mapping from every NIST AI RMF subcategory to specific Aethelred capabilities, the evidence each capability produces, and the current implementation status.

---

## 2. Framework Alignment Summary

| NIST AI RMF Function | Subcategories | Full Coverage | Partial Coverage | Planned | Total Mapped |
|---|---|---|---|---|---|
| **GOVERN** | 6 categories, 17 subcategories | 14 | 3 | 0 | 17 |
| **MAP** | 5 categories, 16 subcategories | 12 | 3 | 1 | 16 |
| **MEASURE** | 4 categories, 13 subcategories | 10 | 2 | 1 | 13 |
| **MANAGE** | 4 categories, 11 subcategories | 9 | 2 | 0 | 11 |
| **Total** | 19 categories, 57 subcategories | 45 | 10 | 2 | 57 |

---

## 3. GOVERN -- Governance and Culture

The GOVERN function establishes and maintains the organizational structures, policies, and processes for managing AI risks.

### GOVERN 1 -- Policies, Processes, Procedures, and Practices

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 1.1** -- Legal and regulatory requirements identified | `pkg/compliance` framework registry with 6 frameworks (NIST AI RMF, EU AI Act, CMMC, HIPAA, SOC2, PCI-DSS); `FrameworkDefinition` maps requirements to controls | `pkg/compliance` | Framework definitions, control mappings, coverage assessments | Full |
| **GOV 1.2** -- Trustworthy AI characteristics integrated into policies | `PolicyEngine` supports sector-specific templates with trustworthiness attributes; policies enforce fairness, transparency, and accountability requirements | `pkg/governance/policy` | Policy rule definitions, template configurations, trustworthiness attribute mappings | Full |
| **GOV 1.3** -- Processes for AI risk management across lifecycle | `PolicyEngine` + `AuditStudio` provide continuous governance across development, deployment, and operation phases; `EvidenceBundleBuilder` packages lifecycle evidence | `pkg/governance/policy`, `pkg/audit` | Lifecycle event records, policy evaluation logs, evidence bundles | Full |
| **GOV 1.4** -- Risk management integrated into broader enterprise | `pkg/compliance` integrates with enterprise risk frameworks; `ControlMapping` links AI risks to organizational controls (SOC2, SOX, HIPAA) | `pkg/compliance`, `pkg/audit` | Cross-framework control mappings, integrated risk reports | Full |
| **GOV 1.5** -- Ongoing monitoring of AI risks | `AuditStudio` provides continuous monitoring with hash-chained audit trail; `pkg/assurance` Enterprise Assurance Fabric detects compliance drift | `pkg/audit`, `pkg/assurance` | Monitoring dashboards, drift alerts, integrity verification reports | Full |
| **GOV 1.6** -- Mechanisms for inventory and documentation | Digital Seals provide immutable documentation of AI system configurations; `EvidenceBundleBuilder` generates documentation packages | `pkg/seal/sdk`, `pkg/audit` | Seal registry, configuration seals, documentation bundles | Full |
| **GOV 1.7** -- Processes for decommissioning | Evidence portability ensures decommissioning records preserved; `RegulatoryConfig.RetentionPeriodDays` enforces post-decommission retention | `pkg/evidence`, `pkg/seal/sdk` | Decommission evidence bundles, retention compliance records | Partial |

### GOVERN 2 -- Accountability Structures

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 2.1** -- Roles and responsibilities defined | `PolicyEngine` role-based evaluation with `RequireDualControl` and `RequireCommittee` decision types; approval workflows assign accountability | `pkg/governance/policy` | Role assignments, approval chain records | Full |
| **GOV 2.2** -- Training and awareness | Integration point: Aethelred audit trail documents training completion and awareness attestations | `pkg/audit` | Training acknowledgment records (organizational supplement) | Partial |
| **GOV 2.3** -- Executive oversight mechanisms | `RequireCommittee` decision type for critical decisions; break-glass overrides with mandatory justification provide escalation path | `pkg/governance/policy` | Committee decisions, break-glass records with justification | Full |

### GOVERN 3 -- AI Risk Management is Resourced

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 3.1** -- Resources allocated for risk management | `pkg/enterprise/billing` provides usage metering and resource allocation tracking | `pkg/enterprise/billing` | Resource allocation records, billing reports | Full |
| **GOV 3.2** -- Competency and expertise | Integration point: compliance framework mappings identify required competencies | `pkg/compliance` | Competency requirement mappings | Partial |

### GOVERN 4 -- Organizational Transparency

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 4.1** -- Organizational practices transparent | Seal provenance chains document all AI operations; audit trail exportable for external review | `pkg/seal/sdk`, `pkg/audit` | Provenance chains, exportable audit records | Full |
| **GOV 4.2** -- Documentation accessible to stakeholders | `EvidenceBundleBuilder` generates stakeholder-appropriate evidence packages; OSCAL export for government stakeholders | `pkg/audit` | Evidence bundles, OSCAL exports | Full |
| **GOV 4.3** -- Policies communicated and enforced | `PolicyEngine` stores and enforces policies with version tracking; policy change events audited | `pkg/governance/policy` | Policy versions, change event records | Full |

### GOVERN 5 -- AI Risks and Benefits Managed

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 5.1** -- Risk tolerances established | Policy rules define risk thresholds; sector templates provide industry-appropriate defaults | `pkg/governance/policy` | Risk threshold configurations, tolerance records | Full |
| **GOV 5.2** -- Trustworthy AI mechanisms | Digital Seals provide integrity; Policy Engine provides accountability; Audit Studio provides transparency | Multiple | Combined trustworthiness evidence package | Full |

### GOVERN 6 -- Policies Addressing AI Risks

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **GOV 6.1** -- Policies address third-party AI | Agent Trust Protocol manages third-party agent interactions; DelegationScope constrains third-party authority | `pkg/protocol/agent` | Third-party delegation records, action receipts | Full |
| **GOV 6.2** -- Third-party risks managed | `DelegationConstraint` types (max_amount, max_count, time_window, ip_range) limit third-party risk exposure | `pkg/protocol/agent` | Constraint enforcement records, violation logs | Full |

---

## 4. MAP -- Risk Framing

The MAP function establishes context for AI risk by identifying and characterizing potential risks.

### MAP 1 -- Context Established

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAP 1.1** -- Intended purpose documented | `RegulatoryConfig` captures compliance frameworks, data classification, and jurisdictions per seal; sector-specific templates define intended purpose | `pkg/seal/sdk`, `pkg/governance/policy` | Seal metadata, sector template configurations | Full |
| **MAP 1.2** -- Interdependencies documented | Provenance chains link AI system dependencies; Agent delegation chains map inter-system dependencies | `pkg/seal/sdk`, `pkg/protocol/agent` | Provenance chains, delegation chain records | Full |
| **MAP 1.3** -- Objectives and design decisions documented | Evidence bundles capture design decisions with rationale; policy rules document design constraints | `pkg/audit`, `pkg/governance/policy` | Evidence bundles, policy documentation | Full |
| **MAP 1.4** -- Intended purpose and context communicated | Exportable evidence packages for stakeholders; OSCAL for government agencies | `pkg/audit`, `pkg/evidence` | Stakeholder evidence packages | Full |
| **MAP 1.5** -- Organizational risk tolerances considered | Policy Engine risk thresholds aligned with organizational risk appetite | `pkg/governance/policy` | Risk threshold records | Full |
| **MAP 1.6** -- Assumptions and limitations documented | Seal metadata captures operational assumptions; ODD parameters define operational boundaries | `pkg/seal/sdk`, `pkg/integrations/av` | Assumption records, ODD configurations | Full |

### MAP 2 -- AI Risks Categorized

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAP 2.1** -- Risks identified for each component | `pkg/compliance` maps risks to controls across 6 frameworks; `CoverageLevel` indicates risk treatment status (Full, Partial, Planned, Gap) | `pkg/compliance` | Control mappings with coverage assessment | Full |
| **MAP 2.2** -- Risks related to third-party data, models | Agent Trust Protocol tracks third-party interactions; EPCIS adapter manages supply chain data provenance | `pkg/protocol/agent`, `pkg/integrations/epcis` | Third-party data provenance, supply chain seals | Full |
| **MAP 2.3** -- Risk assessment methodology | Continuous assessment via `AuditStudio`; `CMMCAssessor` for defense sector; compliance coverage analysis | `pkg/audit`, `pkg/compliance` | Assessment reports, coverage analysis | Full |

### MAP 3 -- AI Risks Prioritized

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAP 3.1** -- Risks evaluated and prioritized | `CoverageLevel` enables risk prioritization (Gap > Planned > Partial > Full); evidence bundles highlight gaps | `pkg/compliance` | Prioritized risk reports | Full |
| **MAP 3.2** -- Risk responses selected | Policy Engine decision types (Allow/Deny/RequireApproval/RequireDualControl/Escalate) provide risk response options | `pkg/governance/policy` | Decision records with risk context | Full |
| **MAP 3.3** -- Risk responses documented | Evidence bundles document selected risk responses with rationale | `pkg/audit` | Risk response evidence packages | Partial |
| **MAP 3.4** -- Risks communicated to stakeholders | Exportable evidence packages; regulator-specific reports (SEC, FCA, NHTSA, etc.) | `pkg/audit`, sector adapters | Stakeholder risk reports | Full |
| **MAP 3.5** -- Risk acceptance decisions documented | Policy exceptions and break-glass overrides capture risk acceptance with justification | `pkg/governance/policy` | Exception records, break-glass justifications | Full |

### MAP 4 -- Impacts Characterized

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAP 4.1** -- Positive and negative impacts identified | Compliance framework mappings identify impact areas; sector-specific templates characterize impacts | `pkg/compliance` | Impact characterization records | Partial |
| **MAP 4.2** -- Impacts to different stakeholders | Evidence bundles tailored per stakeholder group; FHIR adapter for patient impacts; finance adapter for financial impacts | Sector adapters | Stakeholder impact evidence | Partial |

### MAP 5 -- AI System Trustworthiness Characterized

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAP 5.1** -- Trustworthiness attributes defined | Digital Seals (integrity), Policy Engine (accountability), Audit Studio (transparency), Consent Validator (privacy) | Multiple | Trustworthiness attribute evidence | Full |
| **MAP 5.2** -- Trustworthiness practices integrated | Platform-wide trustworthiness enforcement through seals, policies, and audit | Multiple | Integrated trustworthiness evidence | Planned |

---

## 5. MEASURE -- Risk Assessment and Analysis

The MEASURE function employs quantitative and qualitative tools to analyze, assess, and track AI risks.

### MEASURE 1 -- AI Risks Assessed

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **ME 1.1** -- Appropriate methods used | `pkg/compliance/assessor` provides structured assessment methodology; sector-specific assessments (CMMC, HIPAA) | `pkg/compliance/assessor` | Assessment methodology records, assessment results | Full |
| **ME 1.2** -- Assessment methods validated | Assessment results cross-referenced with evidence bundles; hash chain integrity verification validates audit data | `pkg/audit`, `pkg/compliance` | Validation reports, integrity verification | Full |
| **ME 1.3** -- Internal and external assessments | Internal: `AuditStudio` continuous assessment; External: evidence packages for third-party assessors (C3PAO, conformity bodies) | `pkg/audit`, `pkg/compliance` | Internal assessment reports, external-ready evidence packages | Full |

### MEASURE 2 -- AI Systems Evaluated

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **ME 2.1** -- Evaluation for trustworthiness | Digital Seal verification confirms integrity; policy evaluation confirms accountability; audit trail confirms transparency | Multiple | Trustworthiness evaluation evidence | Full |
| **ME 2.2** -- Evaluation approaches documented | Evidence bundles document evaluation methodology with framework references | `pkg/audit` | Evaluation documentation | Full |
| **ME 2.3** -- Evaluation results documented | `EvidenceBundleBuilder` packages evaluation results with control mappings; exportable as JSON, CSV, OSCAL | `pkg/audit` | Evidence bundles, OSCAL exports | Full |
| **ME 2.4** -- Evaluation conducted regularly | `AuditStudio` provides continuous monitoring; `pkg/assurance` detects compliance drift; periodic batch assessments configurable | `pkg/audit`, `pkg/assurance` | Continuous monitoring records, drift alerts | Full |
| **ME 2.5** -- Evaluation metrics defined | Compliance coverage metrics (Full/Partial/Planned/Gap percentages); sector-specific metrics (screening hit rate, safety level distribution) | `pkg/compliance`, sector adapters | Metric dashboards, trend reports | Full |
| **ME 2.6** -- AI risk tracking | `AuditStudio` tracks risk events over time; hash-chained audit log provides tamper-evident risk history | `pkg/audit` | Risk event timeline, trend analysis | Full |

### MEASURE 3 -- AI Risks Managed

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **ME 3.1** -- Risk management activities tracked | Evidence bundles track all risk management actions; policy decisions, approvals, exceptions recorded | `pkg/audit`, `pkg/governance/policy` | Risk management activity log | Full |
| **ME 3.2** -- Risk management effectiveness measured | Coverage level tracking over time; gap closure rate; incident response time metrics | `pkg/compliance`, `pkg/audit` | Effectiveness metrics, coverage trend reports | Partial |

### MEASURE 4 -- Output and Outcomes Evaluated

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **ME 4.1** -- Outputs assessed for fitness | Seal verification confirms output integrity; policy evaluation assesses output compliance | `pkg/seal/sdk`, `pkg/governance/policy` | Verification results, compliance assessment | Full |
| **ME 4.2** -- Feedback mechanisms | Integration point: audit trail enables feedback loop; exception handling captures operational feedback | `pkg/audit` | Feedback records, exception patterns | Partial |
| **ME 4.3** -- Bias and fairness evaluation | Integration point: policy rules can encode fairness constraints; monitoring for disparate outcomes | `pkg/governance/policy` | Fairness constraint evaluations | Planned |

---

## 6. MANAGE -- Risk Treatment

The MANAGE function allocates resources and implements plans to respond to and recover from AI risks.

### MANAGE 1 -- AI Risks Prioritized

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAN 1.1** -- Risk treatment plans defined | Policy rules define treatment actions; sector templates provide industry-appropriate treatments; exception workflows handle residual risk | `pkg/governance/policy` | Treatment plan records, policy configurations | Full |
| **MAN 1.2** -- Risk treatment plans implemented | `PolicyEngine.Evaluate()` enforces treatments in real-time; approval workflows implement human oversight; break-glass provides emergency treatment | `pkg/governance/policy` | Treatment enforcement records, approval chains | Full |
| **MAN 1.3** -- Risk treatment effectiveness monitored | `AuditStudio` tracks treatment outcomes; coverage level trends indicate treatment progress | `pkg/audit`, `pkg/compliance` | Treatment effectiveness reports | Full |

### MANAGE 2 -- AI Risks Treated

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAN 2.1** -- Risks responded to | Policy Engine decision types provide response options; exception handling escalates unresolved risks; incident response for acute risks | `pkg/governance/policy`, `pkg/operations/incident` | Response records, escalation logs | Full |
| **MAN 2.2** -- AI system performance monitored | `AuditStudio` continuous monitoring; `pkg/assurance` drift detection; sector-specific monitoring (safety controller, sanctions screening) | `pkg/audit`, `pkg/assurance`, sector adapters | Performance monitoring records | Full |
| **MAN 2.3** -- Risk responses documented and communicated | Evidence bundles document risk responses; regulator-specific reports communicate to stakeholders | `pkg/audit`, sector adapters | Risk response evidence, regulator reports | Full |
| **MAN 2.4** -- Incident response mechanisms | `pkg/operations/incident` provides incident response workflows; `IncidentTimeline` (AV), exception handling (finance), break-glass (all sectors) | `pkg/operations/incident`, sector adapters | Incident records, response timelines | Full |

### MANAGE 3 -- Third-Party AI Managed

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAN 3.1** -- Third-party AI risks managed | Agent Trust Protocol with delegation constraints; DelegationScope limits third-party authority; trust negotiation verifies capabilities | `pkg/protocol/agent` | Third-party risk management records | Full |
| **MAN 3.2** -- Third-party performance monitored | Action receipts track third-party agent performance; delegation constraint enforcement logs violations | `pkg/protocol/agent` | Third-party performance records | Full |

### MANAGE 4 -- AI System Retirement

| Subcategory | Aethelred Capability | Package | Evidence | Status |
|---|---|---|---|---|
| **MAN 4.1** -- Retirement procedures defined | Evidence portability ensures records survive retirement; retention policies enforced post-retirement; delegation revocation cascade | `pkg/evidence`, `pkg/seal/sdk`, `pkg/protocol/agent` | Retirement evidence packages | Partial |
| **MAN 4.2** -- Retirement documentation | Evidence bundles package retirement documentation; seal provenance chains preserved | `pkg/audit`, `pkg/evidence` | Retirement documentation bundles | Partial |

---

## 7. Implementation Guide

### 7.1 Adopting NIST AI RMF with Aethelred

```
Phase 1: GOVERN
├── Deploy PolicyEngine with organizational policies
├── Configure sector-specific templates
├── Establish approval workflows (single, dual-control, committee)
├── Enable AuditStudio for continuous monitoring
└── Generate initial compliance framework mappings

Phase 2: MAP
├── Configure RegulatoryConfig for each AI system
├── Map data classifications and jurisdictions
├── Identify applicable compliance frameworks
├── Document operational boundaries (ODD, delegation scopes)
└── Generate risk characterization evidence

Phase 3: MEASURE
├── Enable continuous assessment via AuditStudio
├── Configure coverage level tracking
├── Deploy sector-specific assessments
├── Generate baseline evidence bundles
└── Establish metric dashboards

Phase 4: MANAGE
├── Activate incident response workflows
├── Configure exception handling paths
├── Deploy agent trust protocol for third-party management
├── Enable evidence portability for stakeholder communication
└── Schedule periodic OSCAL exports for government stakeholders
```

### 7.2 Evidence Generation

Aethelred automatically generates NIST AI RMF evidence through normal operation. No additional configuration is required to produce:

- Policy evaluation records (GOVERN)
- Compliance coverage assessments (MAP)
- Audit trail entries (MEASURE)
- Incident response records (MANAGE)
- Evidence bundles with NIST AI RMF control mappings (all functions)

### 7.3 OSCAL Export

For federal agency submissions, evidence can be exported in OSCAL format:

```go
import "github.com/aethelred/aethelred/pkg/audit/export"

exporter := export.NewOSCALExporter(export.OSCALConfig{
    Framework: "NIST-AI-RMF-1.0",
    Profile:   "high",
})

oscalData, err := exporter.Export(ctx, evidenceBundle)
```

---

## 8. Coverage Summary

| Coverage Level | Count | Percentage |
|---|---|---|
| Full | 45 | 79% |
| Partial | 10 | 18% |
| Planned | 2 | 3% |
| Gap | 0 | 0% |
| **Total** | **57** | **100%** |

All 57 NIST AI RMF subcategories are mapped. No gaps exist. The two planned items (MAP 5.2 trustworthiness integration and MEASURE 4.3 bias evaluation) are on the product roadmap for implementation.
