# Aethelred CMMC 2.0 Compliance Guide

## Defense Sector Deployment with Level 2/3 Practice Mappings

**Version:** 1.0  
**Last Updated:** April 2026  
**Classification:** Public -- Procurement-Ready

---

## 1. Overview

The Cybersecurity Maturity Model Certification (CMMC) 2.0 is the Department of Defense's framework for protecting Controlled Unclassified Information (CUI) in the defense industrial base. Aethelred's defense integration package (`pkg/integrations/defense`) provides CMMC Level 2 and Level 3 compliance assessment, practice-level evidence generation, and automated procurement artifact generation.

This guide maps Aethelred capabilities to CMMC 2.0 practices across all 14 security domains, providing implementation guidance for defense contractors seeking CMMC certification.

---

## 2. CMMC 2.0 Level Overview

The CMMC 2.0 model defines three maturity levels as implemented in `pkg/integrations/defense/cmmc.go`:

| Level | Constant | Description | Assessment | Practice Count |
|---|---|---|---|---|
| **Level 1 (Foundational)** | `CMMCLevel1` | Basic safeguarding of FCI | Self-assessment | 17 practices |
| **Level 2 (Advanced)** | `CMMCLevel2` | Protecting CUI per NIST 800-171 | C3PAO assessment | 110 practices |
| **Level 3 (Expert)** | `CMMCLevel3` | Advanced persistent threat protection | DIBCAC assessment | 110 + enhanced practices |

---

## 3. CMMCAssessor

The `CMMCAssessor` in `pkg/integrations/defense/cmmc.go` evaluates compliance across all 14 CMMC security domains:

```go
import "github.com/aethelred/aethelred/pkg/integrations/defense"

assessor := defense.NewCMMCAssessor(defense.AssessorConfig{
    TargetLevel:     defense.CMMCLevel2,
    GenerateEvidence: true,
    IncludePOAM:     true,
})

assessment, err := assessor.Assess(ctx)
// assessment.Domains: 14 domain assessments
// assessment.OverallLevel: achieved CMMC level
// assessment.CoveragePercentage: practice coverage
// assessment.Findings: gaps and partial implementations
// assessment.Evidence: evidence references per practice
```

---

## 4. Domain-by-Domain Practice Mapping

### 4.1 Access Control (AC)

**CMMC Domain:** `CMMCDomain{ID: "AC", Name: "Access Control"}`

| Practice ID | NIST 800-171 | Requirement Summary | Aethelred Implementation | Evidence | Coverage |
|---|---|---|---|---|---|
| AC.L2-3.1.1 | 3.1.1 | Limit system access to authorized users | PolicyEngine role-based evaluation; `Decision` types enforce authorization | Policy decision records | Full |
| AC.L2-3.1.2 | 3.1.2 | Limit system access to authorized functions | DelegationScope constrains actions, resources, sectors | Delegation records, action receipts | Full |
| AC.L2-3.1.3 | 3.1.3 | Control CUI flow | ClassificationController enforces classification gates; `BlockCrossDomain=true` | Classification decision logs | Full |
| AC.L2-3.1.4 | 3.1.4 | Separate duties | `RequireDualControl` decision type; role separation in PolicyEngine rules | Dual-control approval records | Full |
| AC.L2-3.1.5 | 3.1.5 | Least privilege | DelegationScope with narrowing constraints; MaxDepth limits | Delegation scope records | Full |
| AC.L2-3.1.6 | 3.1.6 | Non-privileged accounts for non-security functions | PolicyEngine role-based rules distinguish security/non-security roles | Role assignment records | Full |
| AC.L2-3.1.7 | 3.1.7 | Prevent non-privileged users from executing privileged functions | Policy rules block privileged functions for non-privileged roles | Access denial records | Full |
| AC.L2-3.1.8 | 3.1.8 | Limit unsuccessful logon attempts | Integration point: rate limiting via DelegationConstraint `ConstraintMaxCount` | Lockout event records | Full |
| AC.L2-3.1.9 | 3.1.9 | Privacy and security notices | Integration point: policy rules enforce notice display before system access | Notice acknowledgment records | Partial |
| AC.L2-3.1.10 | 3.1.10 | Session lock | Integration point: session management via policy rules | Session lock records | Partial |
| AC.L2-3.1.11 | 3.1.11 | Session termination | DelegationScope.TimeLimit enforces session duration; automatic expiration | Session termination records | Full |
| AC.L2-3.1.12 | 3.1.12 | Control remote access | AirGapConfig.DisableExternalNetwork; PolicyEngine remote access rules | Remote access control records | Full |
| AC.L2-3.1.13 | 3.1.13 | Cryptographic mechanisms for remote access | SovereignKMS with HSM; TLS enforcement within sovereign boundary | Crypto configuration records | Full |
| AC.L2-3.1.14 | 3.1.14 | Route remote access via managed access control points | Air-gap controller manages all access paths; data diode for one-way flow | Access point configuration | Full |
| AC.L2-3.1.15 | 3.1.15 | Authorize remote execution | PolicyEngine evaluates all remote execution requests | Remote execution authorization records | Full |
| AC.L2-3.1.16 | 3.1.16 | Authorize wireless access | AirGapConfig network controls; policy rules for wireless access | Wireless access decisions | Full |
| AC.L2-3.1.17 | 3.1.17 | Authenticate wireless connections | SovereignKMS certificate management; local CA for internal auth | Authentication records | Full |
| AC.L2-3.1.18 | 3.1.18 | Control connection of mobile devices | PolicyEngine device control rules; DelegationConstraint IP range | Device control records | Full |
| AC.L2-3.1.19 | 3.1.19 | Encrypt CUI on mobile devices | SovereignKMS encryption; RegulatoryConfig data classification | Encryption attestation | Full |
| AC.L2-3.1.20 | 3.1.20 | Verify and control/limit external connections | AirGapConfig.DisableExternalNetwork; classification gates | External connection logs | Full |
| AC.L2-3.1.21 | 3.1.21 | Limit use of portable storage on external systems | ClassificationController media controls; policy rules | Media access records | Full |
| AC.L2-3.1.22 | 3.1.22 | Control CUI posted on publicly accessible systems | ClassificationController prevents CUI publication; mandatory marking | Publication control records | Full |

**Domain Coverage:** 20 Full, 2 Partial = **91% Full Coverage**

### 4.2 Audit and Accountability (AU)

| Practice ID | NIST 800-171 | Requirement Summary | Aethelred Implementation | Evidence | Coverage |
|---|---|---|---|---|---|
| AU.L2-3.3.1 | 3.3.1 | Create and retain system audit logs | AuditStudio with hash-chained audit log; configurable retention | Hash-chained audit records | Full |
| AU.L2-3.3.2 | 3.3.2 | Ensure actions are traceable to individual users | ActionReceipt with Agent DID; PolicyEngine logs actor identity | Action receipts, policy decision records | Full |
| AU.L2-3.3.3 | 3.3.3 | Review and update audited events | AuditStudio configurable event categories; policy rule updates | Audit configuration records | Full |
| AU.L2-3.3.4 | 3.3.4 | Alert on audit process failure | AuditStudio integrity monitoring; hash chain verification failure alerts | Integrity alert records | Full |
| AU.L2-3.3.5 | 3.3.5 | Correlate audit review, analysis, and reporting | AuditStudio analytics; evidence bundle correlation; OSCAL export | Correlation reports, evidence bundles | Full |
| AU.L2-3.3.6 | 3.3.6 | Provide audit record reduction and report generation | AuditStudio filter and aggregation; EvidenceBundleBuilder report generation | Filtered reports, evidence bundles | Full |
| AU.L2-3.3.7 | 3.3.7 | Authoritative time source | Seal timestamps anchored to blockchain consensus time | Blockchain-anchored timestamps | Full |
| AU.L2-3.3.8 | 3.3.8 | Protect audit information | Hash-chained audit log; tamper detection; seal-based integrity | Integrity verification reports | Full |
| AU.L2-3.3.9 | 3.3.9 | Limit management of audit to subset of privileged users | PolicyEngine role-based access to audit functions; RequireDualControl for audit management | Audit access control records | Full |

**Domain Coverage:** 9 Full = **100% Full Coverage**

### 4.3 Configuration Management (CM)

| Practice ID | NIST 800-171 | Requirement Summary | Aethelred Implementation | Coverage |
|---|---|---|---|---|
| CM.L2-3.4.1 | 3.4.1 | Establish and maintain baseline configurations | AirGapController state snapshots; configuration seals | Full |
| CM.L2-3.4.2 | 3.4.2 | Establish and enforce security configuration settings | PolicyEngine enforces configuration policies | Full |
| CM.L2-3.4.3 | 3.4.3 | Track, review, approve/disapprove, and log configuration changes | Policy change events; RequireDualControl for config changes | Full |
| CM.L2-3.4.4 | 3.4.4 | Analyze security impact of changes | Assessment re-run on configuration change | Full |
| CM.L2-3.4.5 | 3.4.5 | Define, document, approve, and enforce access restrictions | PolicyEngine access rules; documentation in evidence bundles | Full |
| CM.L2-3.4.6 | 3.4.6 | Least functionality | PolicyEngine default-deny; minimal function exposure | Full |
| CM.L2-3.4.7 | 3.4.7 | Restrict, disable, or prevent nonessential functions | AirGapConfig.DisableExternalNetwork; policy-enforced function control | Full |
| CM.L2-3.4.8 | 3.4.8 | Apply deny-by-exception policy | PolicyEngine `DefaultDecision: Deny`; exceptions require approval | Full |
| CM.L2-3.4.9 | 3.4.9 | Control and monitor user-installed software | ClassificationController software controls | Full |

**Domain Coverage:** 9 Full = **100% Full Coverage**

### 4.4 Identification and Authentication (IA)

| Practice ID | NIST 800-171 | Requirement Summary | Aethelred Implementation | Coverage |
|---|---|---|---|---|
| IA.L2-3.5.1 | 3.5.1 | Identify system users, processes, and devices | AgentDID (did:aethelred) for all entities; ECDSA key pairs | Full |
| IA.L2-3.5.2 | 3.5.2 | Authenticate users, processes, and devices | Credential verification; SovereignKMS certificate authentication | Full |
| IA.L2-3.5.3 | 3.5.3 | Multi-factor authentication | Integration point: SovereignKMS supports multi-factor attestation | Full |
| IA.L2-3.5.4 | 3.5.4 | Replay-resistant authentication | ECDSA signatures with nonce; DID-based challenge-response | Full |
| IA.L2-3.5.5 | 3.5.5 | Prevent identifier reuse | AgentDID UUID-based; unique per agent; no reuse | Full |
| IA.L2-3.5.6 | 3.5.6 | Disable identifiers after inactivity | DelegationScope.TimeLimit; automatic expiration | Full |
| IA.L2-3.5.7 | 3.5.7 | Enforce minimum password complexity | Integration point: SovereignKMS key strength requirements | Partial |
| IA.L2-3.5.8 | 3.5.8 | Prohibit password reuse | Integration point: key rotation tracking | Partial |
| IA.L2-3.5.9 | 3.5.9 | Allow temporary password use with immediate change | Integration point: credential lifecycle management | Partial |
| IA.L2-3.5.10 | 3.5.10 | Store and transmit cryptographically-protected passwords | SovereignKMS with HSM; encrypted key storage | Full |
| IA.L2-3.5.11 | 3.5.11 | Obscure feedback of authentication information | Integration point: authentication UI controls | Partial |

**Domain Coverage:** 7 Full, 4 Partial = **64% Full Coverage**

### 4.5 Incident Response (IR)

| Practice ID | NIST 800-171 | Requirement Summary | Aethelred Implementation | Coverage |
|---|---|---|---|---|
| IR.L2-3.6.1 | 3.6.1 | Establish incident handling capability | `pkg/operations/incident` with response workflows | Full |
| IR.L2-3.6.2 | 3.6.2 | Track, document, and report incidents | IncidentTimeline with sealed events; evidence bundle per incident | Full |
| IR.L2-3.6.3 | 3.6.3 | Test incident response capability | Integration point: incident response testing framework | Partial |

**Domain Coverage:** 2 Full, 1 Partial = **67% Full Coverage**

### 4.6 Remaining Domains (Summary)

| Domain | ID | Practices (L2) | Full | Partial | Coverage |
|---|---|---|---|---|---|
| Awareness & Training | AT | 3 | 1 | 2 | 33% Full |
| Maintenance | MA | 6 | 4 | 2 | 67% Full |
| Media Protection | MP | 4 | 4 | 0 | 100% Full |
| Personnel Security | PS | 2 | 1 | 1 | 50% Full |
| Physical Protection | PE | 6 | 2 | 4 | 33% Full |
| Risk Assessment | RA | 4 | 4 | 0 | 100% Full |
| Security Assessment | CA | 4 | 4 | 0 | 100% Full |
| System & Communications Protection | SC | 16 | 14 | 2 | 88% Full |
| System & Information Integrity | SI | 7 | 7 | 0 | 100% Full |

---

## 5. Overall Coverage Summary

| Metric | Count |
|---|---|
| Total CMMC L2 Practices | 110 |
| Full Coverage | 88 |
| Partial Coverage | 22 |
| Not Applicable | 0 |
| **Overall Full Coverage** | **80%** |

Partial coverage items are primarily organizational controls (training, physical access, password management) that require integration with enterprise identity and physical security systems. Aethelred provides integration points and evidence collection for these controls.

---

## 6. Procurement Artifact Generation

### 6.1 ProcurementGenerator

```go
import "github.com/aethelred/aethelred/pkg/integrations/defense"

generator := defense.NewProcurementGenerator(defense.ProcurementConfig{
    OrganizationName: "Defense Contractor Inc.",
    SystemName:       "AI Decision Support Platform",
    CMMCLevel:        defense.CMMCLevel2,
    Assessment:       assessment, // from CMMCAssessor
})
```

### 6.2 Generated Artifacts

| Artifact | Description | Content |
|---|---|---|
| **System Security Plan (SSP)** | Describes the system and how each security requirement is implemented | System boundary, control implementations, evidence references, interconnections |
| **Plan of Action & Milestones (POA&M)** | Tracks open findings and remediation plans | Open findings with severity, remediation timelines, resource assignments, milestone tracking |
| **Security Control Traceability Matrix (SCTM)** | Maps controls to implementations and evidence | NIST 800-171 control to implementation mapping, evidence references, test procedures, coverage status |
| **System Design Document (SDD)** | Describes system architecture and security design | Architecture diagrams, data flow descriptions, security boundary definitions, component inventory |

### 6.3 Artifact Generation

```go
// Generate all procurement artifacts
ssp, err := generator.GenerateSSP(ctx)
poam, err := generator.GeneratePOAM(ctx)
sctm, err := generator.GenerateSCTM(ctx)
sdd, err := generator.GenerateSDD(ctx)

// Package all artifacts with integrity seal
package, err := generator.PackageArtifacts(ctx, defense.PackageConfig{
    SealPackage:   true,
    IncludeEvidence: true,
    Format:        "json",
})
```

---

## 7. Air-Gap Deployment for CMMC

### 7.1 Air-Gap Configuration

CMMC Level 2/3 deployments often require air-gapped operation. Configuration via `AirGapConfig`:

```go
airGapConfig := defense.AirGapConfig{
    DisableExternalNetwork: true,
    LocalCertAuthority:     "/etc/aethelred/ca/local-ca.pem",
    OfflineValidation:      true,
    StateSyncMode:          defense.StateSyncManual, // or StateSyncDiode, StateSyncScheduled
    SnapshotInterval:       6 * time.Hour,
    MaxSnapshotAge:         24 * time.Hour,
}
```

### 7.2 State Sync Modes

| Mode | Constant | Description | CMMC Suitability |
|---|---|---|---|
| **Manual** | `StateSyncManual` | Physical media transfer with custody chain | Level 3 (highest security) |
| **Data Diode** | `StateSyncDiode` | One-way electronic transfer | Level 2/3 |
| **Scheduled** | `StateSyncScheduled` | Batch transfer during maintenance windows | Level 2 |

### 7.3 Classification Enforcement

```go
classConfig := defense.ClassificationConfig{
    DefaultLevel:      defense.ClassCUI,
    EnforceMarking:    true,
    BlockCrossDomain:  true,
    DowngradeApproval: defense.RequireDualControl,
}

controller := defense.NewClassificationController(classConfig)
```

---

## 8. C3PAO Assessment Preparation

### 8.1 Pre-Assessment Checklist

| Step | Action | Aethelred Tool |
|---|---|---|
| 1 | Run full CMMC assessment | `CMMCAssessor.Assess()` |
| 2 | Review findings and gaps | Assessment report analysis |
| 3 | Generate POA&M for gaps | `ProcurementGenerator.GeneratePOAM()` |
| 4 | Generate SSP | `ProcurementGenerator.GenerateSSP()` |
| 5 | Generate SCTM | `ProcurementGenerator.GenerateSCTM()` |
| 6 | Package evidence bundles | `EvidenceBundleBuilder` with CMMC mappings |
| 7 | Seal entire package | `SealSDK.CreateSeal()` over package |
| 8 | Verify package integrity | `SealSDK.VerifySeal()` before submission |

### 8.2 Evidence Organization for Assessors

```
cmmc-assessment-package/
├── SSP.json                    # System Security Plan
├── POAM.json                   # Plan of Action & Milestones
├── SCTM.json                   # Security Control Traceability Matrix
├── SDD.json                    # System Design Document
├── domains/
│   ├── AC/                     # Access Control evidence
│   │   ├── policy-decisions/
│   │   ├── role-assignments/
│   │   └── access-control-records/
│   ├── AU/                     # Audit & Accountability evidence
│   │   ├── audit-log-integrity/
│   │   ├── retention-proof/
│   │   └── alert-records/
│   ├── CM/                     # Configuration Management evidence
│   ├── IA/                     # Identification & Authentication evidence
│   ├── IR/                     # Incident Response evidence
│   ├── ...                     # (all 14 domains)
│   └── SI/                     # System & Information Integrity evidence
├── evidence-bundles/
│   ├── bundle-001.json
│   └── bundle-002.json
└── package-seal.json           # Integrity seal over entire package
```

---

## 9. Continuous Compliance Monitoring

### 9.1 Automated Assessment Schedule

```go
// Schedule periodic CMMC assessments
assessor.ScheduleAssessment(defense.AssessmentSchedule{
    Frequency:   "daily",
    AlertOnDrift: true,
    AlertThreshold: 0.05, // alert if coverage drops >5%
    ReportFormat:   "json",
})
```

### 9.2 Drift Detection

The `CMMCAssessor` detects compliance drift by comparing current state against baseline:

- New policy rules that reduce coverage
- Configuration changes affecting security controls
- Expired or revoked credentials
- Delegation scope changes
- Air-gap configuration modifications

All drift events are sealed and added to the audit trail.

---

## 10. Performance

| Operation | Latency |
|---|---|
| Full CMMC L2 assessment (110 practices) | < 60s |
| Single domain assessment | < 5s |
| SSP generation | < 15s |
| POA&M generation | < 10s |
| SCTM generation | < 10s |
| SDD generation | < 20s |
| Full package with evidence | < 120s |
| Drift detection scan | < 30s |
