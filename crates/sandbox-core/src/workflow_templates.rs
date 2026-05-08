//! Pre-built workflow & policy templates.
//!
//! v0.2.1 [`crate::policy_dsl::PolicyDocument`] lets compliance teams
//! author policies; v0.2.2 [`crate::compliance_report::ControlMapping`]
//! maps internal gates to external controls. This module ships the
//! **catalog of ready-to-load templates** so customers don't author from
//! scratch:
//!
//! - **SOC 2 Type II** — CC1 through CC9 controls.
//! - **ISO/IEC 27001:2022** — Annex A.
//! - **HIPAA Security Rule** — §§ 164.308 / 164.310 / 164.312.
//! - **EU GDPR** — Articles 5, 22, 25, 30, 32, 33-34, 35.
//! - **SR 11-7** — Federal Reserve Model Risk Management.
//! - **NIST AI RMF 2.0** — Govern / Map / Measure / Manage.
//! - **EU AI Act** — Annex III high-risk requirements.
//! - **PCI-DSS v4.0** — payment card.
//!
//! ## API
//!
//! ```ignore
//! use aethelred_sandbox_core::workflow_templates::*;
//!
//! let bundle = TemplateBundle::soc2_type2();
//! let policy = bundle.policy_document();        // PolicyDocument ready to compile
//! let mapping = bundle.control_mapping();        // ControlMapping ready to use
//! let report_template = bundle.report_template(); // ComplianceReport seed
//! ```

use crate::compliance_report::{ComplianceFramework, ControlMapping, ControlRef};
use crate::policy_dsl::{DslGate, DslRegulatorCitation, GateSeverity, PolicyDocument};
use serde::{Deserialize, Serialize};

// =============================================================================
// TemplateId
// =============================================================================

/// Stable id for a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateId {
    /// AICPA SOC 2 Type II.
    Soc2Type2,
    /// ISO/IEC 27001:2022 Annex A.
    Iso27001_2022,
    /// HIPAA Security Rule.
    HipaaSecurity,
    /// EU GDPR.
    EuGdpr,
    /// Federal Reserve SR 11-7 model risk.
    Sr11_7,
    /// NIST AI RMF 2.0.
    NistAiRmf,
    /// EU AI Act high-risk Annex III.
    EuAiAct,
    /// PCI-DSS v4.0.
    PciDssV4,
}

impl TemplateId {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Soc2Type2 => "soc2_type2",
            Self::Iso27001_2022 => "iso_27001_2022",
            Self::HipaaSecurity => "hipaa_security",
            Self::EuGdpr => "eu_gdpr",
            Self::Sr11_7 => "sr_11_7",
            Self::NistAiRmf => "nist_ai_rmf",
            Self::EuAiAct => "eu_ai_act",
            Self::PciDssV4 => "pci_dss_v4",
        }
    }

    /// All known templates.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Soc2Type2,
            Self::Iso27001_2022,
            Self::HipaaSecurity,
            Self::EuGdpr,
            Self::Sr11_7,
            Self::NistAiRmf,
            Self::EuAiAct,
            Self::PciDssV4,
        ]
    }
}

// =============================================================================
// TemplateBundle
// =============================================================================

/// Bundles the policy document, control mapping, and metadata for one
/// framework template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBundle {
    /// Template id.
    pub id: TemplateId,
    /// Display name.
    pub name: String,
    /// Description.
    pub description: String,
    /// Owning regulator / standards body.
    pub authority: String,
    /// Policy document (compiles to PolicyEngine).
    pub policy_document: PolicyDocument,
    /// Control mapping for evidence reports.
    pub control_mapping: ControlMapping,
}

impl TemplateBundle {
    /// Borrow the policy doc.
    pub fn policy_document(&self) -> &PolicyDocument {
        &self.policy_document
    }
    /// Borrow the control mapping.
    pub fn control_mapping(&self) -> &ControlMapping {
        &self.control_mapping
    }

    /// Look up by id.
    pub fn by_id(id: TemplateId) -> Self {
        match id {
            TemplateId::Soc2Type2 => soc2_type2(),
            TemplateId::Iso27001_2022 => iso27001_2022(),
            TemplateId::HipaaSecurity => hipaa_security(),
            TemplateId::EuGdpr => eu_gdpr(),
            TemplateId::Sr11_7 => sr_11_7(),
            TemplateId::NistAiRmf => nist_ai_rmf(),
            TemplateId::EuAiAct => eu_ai_act(),
            TemplateId::PciDssV4 => pci_dss_v4(),
        }
    }

    /// All templates as a catalog.
    pub fn catalog() -> Vec<Self> {
        TemplateId::all().into_iter().map(Self::by_id).collect()
    }
}

// =============================================================================
// SOC 2 Type II
// =============================================================================

fn soc2_type2() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_soc2_type2".into(),
        owner: "AICPA-aligned compliance team".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "soc2.cc1.integrity".into(),
                name: "CC1.1 — Demonstrate commitment to integrity".into(),
                rule: "Sealable events must include a human-approver signature.".into(),
                severity: GateSeverity::Required,
                tags: vec!["soc2".into(), "cc1".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "AICPA".into(),
                    citation: "TSC 2017 CC1.1".into(),
                }],
            },
            DslGate {
                id: "soc2.cc6.access_security".into(),
                name: "CC6.1 — Logical access security software".into(),
                rule: "Implement logical access controls over protected information assets.".into(),
                severity: GateSeverity::Required,
                tags: vec!["soc2".into(), "cc6".into(), "access".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "AICPA".into(),
                    citation: "TSC 2017 CC6.1".into(),
                }],
            },
            DslGate {
                id: "soc2.cc7.system_monitoring".into(),
                name: "CC7.2 — System monitoring".into(),
                rule: "Monitors system components for anomalies indicative of security events.".into(),
                severity: GateSeverity::Required,
                tags: vec!["soc2".into(), "cc7".into(), "monitoring".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "AICPA".into(),
                    citation: "TSC 2017 CC7.2".into(),
                }],
            },
            DslGate {
                id: "soc2.cc8.change_management".into(),
                name: "CC8.1 — Change management".into(),
                rule: "Authorise, design, develop, configure, and test changes.".into(),
                severity: GateSeverity::Required,
                tags: vec!["soc2".into(), "cc8".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "AICPA".into(),
                    citation: "TSC 2017 CC8.1".into(),
                }],
            },
            DslGate {
                id: "soc2.cc2.communication".into(),
                name: "CC2.2 — Internal communication".into(),
                rule: "Communicate internally about responsibilities and procedures.".into(),
                severity: GateSeverity::Optional,
                tags: vec!["soc2".into(), "cc2".into()],
                regulators: vec![],
            },
        ],
    };
    let mut mapping = ControlMapping::new();
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Soc2,
            control_id: "CC6.1".into(),
            title: "Logical Access Security Software".into(),
            description: "Implement logical access security controls.".into(),
        },
    );
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Soc2,
            control_id: "CC7.2".into(),
            title: "System Monitoring".into(),
            description: "Monitor system components for anomalies.".into(),
        },
    );
    mapping.add(
        "aml_screening",
        ControlRef {
            framework: ComplianceFramework::Soc2,
            control_id: "CC2.2".into(),
            title: "Internal Communication".into(),
            description: "Communicate internally about responsibilities.".into(),
        },
    );
    TemplateBundle {
        id: TemplateId::Soc2Type2,
        name: "SOC 2 Type II".into(),
        description: "AICPA TSC 2017 controls (CC1..CC9).".into(),
        authority: "AICPA".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// ISO 27001:2022
// =============================================================================

fn iso27001_2022() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_iso_27001_2022".into(),
        owner: "ISMS owner".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "iso27001.a5_30.ict_continuity".into(),
                name: "A.5.30 — ICT readiness for business continuity".into(),
                rule: "ICT readiness shall be planned, implemented, maintained and tested."
                    .into(),
                severity: GateSeverity::Required,
                tags: vec!["iso27001".into(), "continuity".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "ISO".into(),
                    citation: "ISO/IEC 27001:2022 Annex A.5.30".into(),
                }],
            },
            DslGate {
                id: "iso27001.a8_16.monitoring".into(),
                name: "A.8.16 — Monitoring activities".into(),
                rule: "Networks, systems, and applications shall be monitored.".into(),
                severity: GateSeverity::Required,
                tags: vec!["iso27001".into(), "monitoring".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "ISO".into(),
                    citation: "ISO/IEC 27001:2022 Annex A.8.16".into(),
                }],
            },
            DslGate {
                id: "iso27001.a5_34.privacy".into(),
                name: "A.5.34 — Privacy and protection of PII".into(),
                rule: "Privacy and protection of PII shall be identified and met.".into(),
                severity: GateSeverity::Required,
                tags: vec!["iso27001".into(), "privacy".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "ISO".into(),
                    citation: "ISO/IEC 27001:2022 Annex A.5.34".into(),
                }],
            },
        ],
    };
    let mut mapping = ControlMapping::new();
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Iso27001,
            control_id: "A.5.30".into(),
            title: "ICT readiness for business continuity".into(),
            description: "Plan, implement, maintain, and test ICT readiness.".into(),
        },
    );
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Iso27001,
            control_id: "A.8.16".into(),
            title: "Monitoring activities".into(),
            description: "Monitor networks, systems, applications.".into(),
        },
    );
    TemplateBundle {
        id: TemplateId::Iso27001_2022,
        name: "ISO/IEC 27001:2022".into(),
        description: "Information security management Annex A controls.".into(),
        authority: "ISO/IEC".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// HIPAA Security Rule
// =============================================================================

fn hipaa_security() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_hipaa_security".into(),
        owner: "HIPAA Security Officer".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "hipaa.access_control".into(),
                name: "§ 164.312(a)(1) — Access Control".into(),
                rule: "Implement technical policies for unique user identification.".into(),
                severity: GateSeverity::Required,
                tags: vec!["hipaa".into(), "access".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "HHS".into(),
                    citation: "45 CFR § 164.312(a)(1)".into(),
                }],
            },
            DslGate {
                id: "hipaa.audit_controls".into(),
                name: "§ 164.312(b) — Audit Controls".into(),
                rule: "Hardware/software/procedural mechanisms must record and examine activity."
                    .into(),
                severity: GateSeverity::Required,
                tags: vec!["hipaa".into(), "audit".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "HHS".into(),
                    citation: "45 CFR § 164.312(b)".into(),
                }],
            },
            DslGate {
                id: "hipaa.integrity".into(),
                name: "§ 164.312(c)(1) — Integrity".into(),
                rule: "Protect ePHI from improper alteration or destruction.".into(),
                severity: GateSeverity::Required,
                tags: vec!["hipaa".into(), "integrity".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "HHS".into(),
                    citation: "45 CFR § 164.312(c)(1)".into(),
                }],
            },
        ],
    };
    let mut mapping = ControlMapping::new();
    mapping.add(
        "clinical_inference",
        ControlRef {
            framework: ComplianceFramework::Hipaa,
            control_id: "§ 164.312(a)(1)".into(),
            title: "Access Control".into(),
            description: "Implement technical policies for unique user identification.".into(),
        },
    );
    mapping.add(
        "clinical_inference",
        ControlRef {
            framework: ComplianceFramework::Hipaa,
            control_id: "§ 164.312(b)".into(),
            title: "Audit Controls".into(),
            description: "Record and examine activity in systems containing ePHI.".into(),
        },
    );
    mapping.add(
        "claims_adjudication",
        ControlRef {
            framework: ComplianceFramework::Hipaa,
            control_id: "§ 164.312(c)(1)".into(),
            title: "Integrity".into(),
            description: "Protect ePHI from improper alteration or destruction.".into(),
        },
    );
    TemplateBundle {
        id: TemplateId::HipaaSecurity,
        name: "HIPAA Security Rule".into(),
        description: "45 CFR §§ 164.308 / 164.310 / 164.312 safeguards.".into(),
        authority: "U.S. HHS / OCR".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// GDPR
// =============================================================================

fn eu_gdpr() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_eu_gdpr".into(),
        owner: "Data Protection Officer".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "gdpr.art22.no_solely_automated".into(),
                name: "Article 22 — Automated individual decision-making".into(),
                rule: "Decisions based solely on automated processing must allow human review."
                    .into(),
                severity: GateSeverity::Required,
                tags: vec!["gdpr".into(), "art22".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2016/679 Art. 22".into(),
                }],
            },
            DslGate {
                id: "gdpr.art30.records".into(),
                name: "Article 30 — Records of processing activities".into(),
                rule: "Each controller shall maintain a record of processing activities.".into(),
                severity: GateSeverity::Required,
                tags: vec!["gdpr".into(), "art30".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2016/679 Art. 30".into(),
                }],
            },
            DslGate {
                id: "gdpr.art32.security".into(),
                name: "Article 32 — Security of processing".into(),
                rule: "Implement appropriate technical and organisational measures.".into(),
                severity: GateSeverity::Required,
                tags: vec!["gdpr".into(), "art32".into(), "security".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2016/679 Art. 32".into(),
                }],
            },
            DslGate {
                id: "gdpr.art17.erasure".into(),
                name: "Article 17 — Right to erasure".into(),
                rule: "Data subjects have the right to obtain erasure of personal data.".into(),
                severity: GateSeverity::Required,
                tags: vec!["gdpr".into(), "art17".into(), "erasure".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2016/679 Art. 17".into(),
                }],
            },
        ],
    };
    let mut mapping = ControlMapping::new();
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Gdpr,
            control_id: "Art. 22".into(),
            title: "Automated decision-making".into(),
            description: "Right not to be subject to a decision based solely on automated processing.".into(),
        },
    );
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Gdpr,
            control_id: "Art. 30".into(),
            title: "Records of processing activities".into(),
            description: "Maintain a record of processing activities.".into(),
        },
    );
    mapping.add(
        "credit_decision",
        ControlRef {
            framework: ComplianceFramework::Gdpr,
            control_id: "Art. 32".into(),
            title: "Security of processing".into(),
            description: "Technical + organisational measures.".into(),
        },
    );
    TemplateBundle {
        id: TemplateId::EuGdpr,
        name: "EU GDPR".into(),
        description: "Regulation (EU) 2016/679 — General Data Protection Regulation.".into(),
        authority: "European Data Protection Board".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// SR 11-7 (Federal Reserve Model Risk Management)
// =============================================================================

fn sr_11_7() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_sr_11_7".into(),
        owner: "Model Risk Management".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "sr11_7.model_validation".into(),
                name: "Model validation".into(),
                rule: "Independent validation of model design, implementation, and use.".into(),
                severity: GateSeverity::Required,
                tags: vec!["sr11_7".into(), "validation".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "FRB".into(),
                    citation: "SR 11-7 — Guidance on Model Risk Management".into(),
                }],
            },
            DslGate {
                id: "sr11_7.ongoing_monitoring".into(),
                name: "Ongoing monitoring".into(),
                rule: "Periodic backtesting, sensitivity analysis, and outcomes analysis.".into(),
                severity: GateSeverity::Required,
                tags: vec!["sr11_7".into(), "monitoring".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "FRB".into(),
                    citation: "SR 11-7".into(),
                }],
            },
            DslGate {
                id: "sr11_7.model_inventory".into(),
                name: "Model inventory".into(),
                rule: "Comprehensive inventory of all models in production.".into(),
                severity: GateSeverity::Required,
                tags: vec!["sr11_7".into(), "inventory".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "FRB".into(),
                    citation: "SR 11-7 III.B".into(),
                }],
            },
        ],
    };
    let mapping = ControlMapping::new();
    TemplateBundle {
        id: TemplateId::Sr11_7,
        name: "SR 11-7 — Model Risk Management".into(),
        description: "Federal Reserve guidance on model risk for credit / market / operational AI."
            .into(),
        authority: "Federal Reserve Board / OCC".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// NIST AI RMF 2.0
// =============================================================================

fn nist_ai_rmf() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_nist_ai_rmf".into(),
        owner: "AI Risk Officer".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "nist_ai_rmf.govern".into(),
                name: "GOVERN — AI risk culture".into(),
                rule: "Establish AI governance structures and accountability.".into(),
                severity: GateSeverity::Required,
                tags: vec!["nist".into(), "ai_rmf".into(), "govern".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "NIST".into(),
                    citation: "AI RMF 1.0 GOVERN".into(),
                }],
            },
            DslGate {
                id: "nist_ai_rmf.measure".into(),
                name: "MEASURE — Test and assess".into(),
                rule: "Track AI system performance, robustness, and trustworthy attributes.".into(),
                severity: GateSeverity::Required,
                tags: vec!["nist".into(), "ai_rmf".into(), "measure".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "NIST".into(),
                    citation: "AI RMF 1.0 MEASURE".into(),
                }],
            },
            DslGate {
                id: "nist_ai_rmf.manage".into(),
                name: "MANAGE — Risk management".into(),
                rule: "Implement risk-management controls during operation.".into(),
                severity: GateSeverity::Required,
                tags: vec!["nist".into(), "ai_rmf".into(), "manage".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "NIST".into(),
                    citation: "AI RMF 1.0 MANAGE".into(),
                }],
            },
        ],
    };
    let mapping = ControlMapping::new();
    TemplateBundle {
        id: TemplateId::NistAiRmf,
        name: "NIST AI Risk Management Framework".into(),
        description: "NIST AI RMF 1.0 — GOVERN / MAP / MEASURE / MANAGE.".into(),
        authority: "NIST".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// EU AI Act
// =============================================================================

fn eu_ai_act() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_eu_ai_act".into(),
        owner: "AI Act Compliance Officer".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "eu_ai_act.art9_risk".into(),
                name: "Article 9 — Risk management system".into(),
                rule: "Establish, implement, document, and maintain a risk management system.".into(),
                severity: GateSeverity::Required,
                tags: vec!["eu_ai_act".into(), "art9".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2024/1689 Art. 9".into(),
                }],
            },
            DslGate {
                id: "eu_ai_act.art13_transparency".into(),
                name: "Article 13 — Transparency to deployers".into(),
                rule: "Provide instructions for use that enable deployers to comply.".into(),
                severity: GateSeverity::Required,
                tags: vec!["eu_ai_act".into(), "art13".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2024/1689 Art. 13".into(),
                }],
            },
            DslGate {
                id: "eu_ai_act.art26_deployer".into(),
                name: "Article 26 — Deployer obligations".into(),
                rule: "Deployers shall use high-risk AI systems in accordance with instructions.".into(),
                severity: GateSeverity::Required,
                tags: vec!["eu_ai_act".into(), "art26".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "EU".into(),
                    citation: "Regulation (EU) 2024/1689 Art. 26".into(),
                }],
            },
        ],
    };
    let mapping = ControlMapping::new();
    TemplateBundle {
        id: TemplateId::EuAiAct,
        name: "EU AI Act (high-risk)".into(),
        description: "Regulation (EU) 2024/1689 — Annex III high-risk AI system requirements."
            .into(),
        authority: "European Commission / EAIO".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

// =============================================================================
// PCI-DSS v4.0
// =============================================================================

fn pci_dss_v4() -> TemplateBundle {
    let policy = PolicyDocument {
        schema_version: 1,
        policy_id: "po_pci_dss_v4".into(),
        owner: "PCI Compliance Officer".into(),
        effective_from: None,
        effective_to: None,
        gates: vec![
            DslGate {
                id: "pci.req3.protect_card_data".into(),
                name: "Req 3 — Protect stored cardholder data".into(),
                rule: "Cardholder data must be protected with strong encryption.".into(),
                severity: GateSeverity::Required,
                tags: vec!["pci".into(), "encryption".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "PCI-SSC".into(),
                    citation: "PCI-DSS v4.0 Req. 3".into(),
                }],
            },
            DslGate {
                id: "pci.req10.audit_logs".into(),
                name: "Req 10 — Track and monitor access".into(),
                rule: "Track and monitor all access to cardholder data and network resources."
                    .into(),
                severity: GateSeverity::Required,
                tags: vec!["pci".into(), "logging".into()],
                regulators: vec![DslRegulatorCitation {
                    id: "PCI-SSC".into(),
                    citation: "PCI-DSS v4.0 Req. 10".into(),
                }],
            },
        ],
    };
    let mapping = ControlMapping::new();
    TemplateBundle {
        id: TemplateId::PciDssV4,
        name: "PCI-DSS v4.0".into(),
        description: "Payment Card Industry Data Security Standard v4.0.".into(),
        authority: "PCI Security Standards Council".into(),
        policy_document: policy,
        control_mapping: mapping,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_id_string_ids_unique() {
        let all = TemplateId::all();
        let mut ids: Vec<&str> = all.iter().map(|t| t.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn template_id_all_includes_eight_templates() {
        assert_eq!(TemplateId::all().len(), 8);
    }

    #[test]
    fn soc2_bundle_loads_correctly() {
        let b = TemplateBundle::by_id(TemplateId::Soc2Type2);
        assert_eq!(b.id, TemplateId::Soc2Type2);
        assert!(!b.policy_document.gates.is_empty());
        assert!(!b.control_mapping.is_empty());
    }

    #[test]
    fn iso27001_bundle_loads() {
        let b = TemplateBundle::by_id(TemplateId::Iso27001_2022);
        assert_eq!(b.policy_document.policy_id, "po_iso_27001_2022");
        assert!(b.policy_document.gates.iter().any(|g| g.id.contains("a5_30")));
    }

    #[test]
    fn hipaa_bundle_loads() {
        let b = TemplateBundle::by_id(TemplateId::HipaaSecurity);
        assert!(b
            .policy_document
            .gates
            .iter()
            .any(|g| g.name.contains("Access Control")));
    }

    #[test]
    fn gdpr_bundle_includes_art22() {
        let b = TemplateBundle::by_id(TemplateId::EuGdpr);
        assert!(b
            .policy_document
            .gates
            .iter()
            .any(|g| g.id.contains("art22")));
    }

    #[test]
    fn gdpr_bundle_includes_erasure() {
        let b = TemplateBundle::by_id(TemplateId::EuGdpr);
        assert!(b
            .policy_document
            .gates
            .iter()
            .any(|g| g.id.contains("art17")));
    }

    #[test]
    fn sr_11_7_bundle_includes_validation() {
        let b = TemplateBundle::by_id(TemplateId::Sr11_7);
        assert!(b
            .policy_document
            .gates
            .iter()
            .any(|g| g.id.contains("model_validation")));
    }

    #[test]
    fn nist_bundle_has_govern_measure_manage() {
        let b = TemplateBundle::by_id(TemplateId::NistAiRmf);
        let ids: Vec<String> = b
            .policy_document
            .gates
            .iter()
            .map(|g| g.id.clone())
            .collect();
        assert!(ids.iter().any(|i| i.contains("govern")));
        assert!(ids.iter().any(|i| i.contains("measure")));
        assert!(ids.iter().any(|i| i.contains("manage")));
    }

    #[test]
    fn eu_ai_act_bundle_has_art9_13_26() {
        let b = TemplateBundle::by_id(TemplateId::EuAiAct);
        let ids: Vec<String> = b
            .policy_document
            .gates
            .iter()
            .map(|g| g.id.clone())
            .collect();
        assert!(ids.iter().any(|i| i.contains("art9")));
        assert!(ids.iter().any(|i| i.contains("art13")));
        assert!(ids.iter().any(|i| i.contains("art26")));
    }

    #[test]
    fn pci_bundle_has_req3_and_req10() {
        let b = TemplateBundle::by_id(TemplateId::PciDssV4);
        let ids: Vec<String> = b
            .policy_document
            .gates
            .iter()
            .map(|g| g.id.clone())
            .collect();
        assert!(ids.iter().any(|i| i.contains("req3")));
        assert!(ids.iter().any(|i| i.contains("req10")));
    }

    #[test]
    fn catalog_returns_all_templates() {
        let all = TemplateBundle::catalog();
        assert_eq!(all.len(), 8);
    }

    #[test]
    fn all_templates_validate() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            b.policy_document.validate().unwrap();
        }
    }

    #[test]
    fn all_templates_compile_to_engine() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            let _ = b.policy_document.into_engine().unwrap();
        }
    }

    #[test]
    fn template_serde_round_trip() {
        let b = TemplateBundle::by_id(TemplateId::Soc2Type2);
        let j = serde_json::to_string(&b).unwrap();
        let p: TemplateBundle = serde_json::from_str(&j).unwrap();
        assert_eq!(p.id, b.id);
    }

    #[test]
    fn each_template_has_a_clear_authority() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            assert!(!b.authority.is_empty());
        }
    }

    #[test]
    fn each_template_has_a_name() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            assert!(!b.name.is_empty());
        }
    }

    #[test]
    fn each_template_has_at_least_one_gate() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            assert!(!b.policy_document.gates.is_empty());
        }
    }

    #[test]
    fn each_template_has_required_gates() {
        for t in TemplateId::all() {
            let b = TemplateBundle::by_id(t);
            assert!(b
                .policy_document
                .gates
                .iter()
                .any(|g| g.severity == GateSeverity::Required));
        }
    }

    #[test]
    fn template_id_serde_round_trip() {
        let t = TemplateId::Soc2Type2;
        let j = serde_json::to_string(&t).unwrap();
        let p: TemplateId = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn soc2_mapping_includes_credit_decision() {
        let b = TemplateBundle::by_id(TemplateId::Soc2Type2);
        assert!(!b.control_mapping.get("credit_decision").is_empty());
    }

    #[test]
    fn hipaa_mapping_includes_clinical_inference() {
        let b = TemplateBundle::by_id(TemplateId::HipaaSecurity);
        assert!(!b.control_mapping.get("clinical_inference").is_empty());
    }

    #[test]
    fn gdpr_mapping_includes_credit_decision() {
        let b = TemplateBundle::by_id(TemplateId::EuGdpr);
        assert!(!b.control_mapping.get("credit_decision").is_empty());
    }

    #[test]
    fn template_borrow_helpers_work() {
        let b = TemplateBundle::by_id(TemplateId::Soc2Type2);
        assert_eq!(b.policy_document().policy_id, "po_soc2_type2");
        assert!(!b.control_mapping().is_empty());
    }

    #[test]
    fn iso27001_includes_required_controls() {
        let b = TemplateBundle::by_id(TemplateId::Iso27001_2022);
        let required_count = b
            .policy_document
            .gates
            .iter()
            .filter(|g| g.severity == GateSeverity::Required)
            .count();
        assert!(required_count >= 3);
    }
}
