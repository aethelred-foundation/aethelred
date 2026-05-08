//! Healthcare regulator views.

use serde::{Deserialize, Serialize};

/// Healthcare regulator jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthcareJurisdiction {
    /// Department of Health Abu Dhabi.
    DohAbuDhabi,
    /// Dubai Health Authority.
    Dha,
    /// Ministry of Health and Prevention (UAE).
    Mohap,
    /// Emirates Health Services (UAE Federal).
    Ehs,
    /// US HIPAA / HITECH.
    HipaaUs,
    /// EU AI Act high-risk Annex III §3 (medical devices) + GDPR.
    EuAiActGdpr,
    /// National Health Regulatory Authority (Bahrain), used by Globalpharma exports.
    NhraBahrain,
}

impl HealthcareJurisdiction {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DohAbuDhabi => "doh_abu_dhabi",
            Self::Dha => "dha",
            Self::Mohap => "mohap",
            Self::Ehs => "ehs",
            Self::HipaaUs => "hipaa_us",
            Self::EuAiActGdpr => "eu_ai_act_gdpr",
            Self::NhraBahrain => "nhra_bahrain",
        }
    }

    /// Seal jurisdiction tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::DohAbuDhabi => "AE-AD-DOH",
            Self::Dha => "AE-DXB-DHA",
            Self::Mohap => "AE-MOHAP",
            Self::Ehs => "AE-EHS",
            Self::HipaaUs => "US-HIPAA",
            Self::EuAiActGdpr => "EU-AI-ACT",
            Self::NhraBahrain => "BH-NHRA",
        }
    }

    /// Citations bundled with this regulator's view.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::DohAbuDhabi => vec![RegulatorCitation::doh_abu_dhabi_clinical_governance()],
            Self::Dha => vec![RegulatorCitation::dha_clinical_governance()],
            Self::Mohap => vec![RegulatorCitation::mohap_clinical_governance()],
            Self::Ehs => vec![RegulatorCitation::ehs_clinical_governance()],
            Self::HipaaUs => vec![
                RegulatorCitation::hipaa_security_rule(),
                RegulatorCitation::hipaa_privacy_rule(),
            ],
            Self::EuAiActGdpr => vec![
                RegulatorCitation::eu_ai_act_high_risk_annex_iii_3(),
                RegulatorCitation::gdpr_article_9(),
            ],
            Self::NhraBahrain => vec![RegulatorCitation::nhra_clinical_governance()],
        }
    }
}

/// A single regulator citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Regulator name.
    pub regulator: String,
    /// Citation id.
    pub citation_id: String,
    /// Section.
    pub section: String,
    /// Plain-English summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// DoH Abu Dhabi clinical governance.
    pub fn doh_abu_dhabi_clinical_governance() -> Self {
        Self {
            regulator: "DoH Abu Dhabi".into(),
            citation_id: "Clinical Governance Standards".into(),
            section: "AI safety + auditability".into(),
            summary: "Demonstrate AI-driven clinical decisions are safe, accountable, auditable.".into(),
        }
    }
    /// DHA clinical governance.
    pub fn dha_clinical_governance() -> Self {
        Self {
            regulator: "DHA".into(),
            citation_id: "Clinical Governance Standards".into(),
            section: "Clinical AI oversight".into(),
            summary: "Clinical AI deployment governance + clinician accountability.".into(),
        }
    }
    /// MOHAP clinical governance.
    pub fn mohap_clinical_governance() -> Self {
        Self {
            regulator: "MOHAP".into(),
            citation_id: "MOHAP Clinical Standards".into(),
            section: "Federal-level clinical AI".into(),
            summary: "UAE-federal clinical AI safety + auditability obligations.".into(),
        }
    }
    /// EHS clinical governance.
    pub fn ehs_clinical_governance() -> Self {
        Self {
            regulator: "EHS".into(),
            citation_id: "EHS Standards".into(),
            section: "Northern Emirates clinical AI".into(),
            summary: "EHS clinical AI oversight in Northern Emirates.".into(),
        }
    }
    /// HIPAA Security Rule §164.312(b) — audit controls.
    pub fn hipaa_security_rule() -> Self {
        Self {
            regulator: "HHS / OCR (US)".into(),
            citation_id: "45 CFR §164.312(b)".into(),
            section: "Audit controls".into(),
            summary: "Implement mechanisms that record activity in systems containing or using ePHI.".into(),
        }
    }
    /// HIPAA Privacy Rule §164.502(a).
    pub fn hipaa_privacy_rule() -> Self {
        Self {
            regulator: "HHS / OCR (US)".into(),
            citation_id: "45 CFR §164.502(a)".into(),
            section: "Permitted uses + disclosures".into(),
            summary: "Use / disclosure of PHI must be permitted by the Privacy Rule.".into(),
        }
    }
    /// EU AI Act Annex III §3 — high-risk medical-device AI.
    pub fn eu_ai_act_high_risk_annex_iii_3() -> Self {
        Self {
            regulator: "EU".into(),
            citation_id: "Regulation (EU) 2024/1689".into(),
            section: "Annex III §3".into(),
            summary: "AI systems used as safety components of medical devices are high-risk.".into(),
        }
    }
    /// GDPR Article 9 — special-category data.
    pub fn gdpr_article_9() -> Self {
        Self {
            regulator: "EU".into(),
            citation_id: "Regulation (EU) 2016/679".into(),
            section: "Article 9".into(),
            summary: "Processing of health data is restricted; lawful basis must be explicit.".into(),
        }
    }
    /// NHRA (Bahrain) clinical governance.
    pub fn nhra_clinical_governance() -> Self {
        Self {
            regulator: "NHRA (Bahrain)".into(),
            citation_id: "NHRA Standards".into(),
            section: "Clinical AI governance".into(),
            summary: "Bahrain NHRA clinical AI oversight.".into(),
        }
    }
}

/// A regulator-shape view of a healthcare seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorView {
    /// Jurisdiction.
    pub jurisdiction: HealthcareJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id string.
    pub seal_id: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Event class (e.g., `"genomics_inference"`, `"radiology_recommendation"`).
    pub event_class: String,
    /// Decision (e.g., `"approve_finding"`, `"refer"`).
    pub decision: String,
    /// Tenant id (e.g., `"M42"`).
    pub tenant_id: String,
}

impl RegulatorView {
    /// Project a [`aethelred_sandbox_core::DigitalSeal`] into a regulator-shape view.
    pub fn project(
        seal: &aethelred_sandbox_core::DigitalSeal,
        jurisdiction: HealthcareJurisdiction,
        decision: impl Into<String>,
        event_class: impl Into<String>,
    ) -> Self {
        Self {
            jurisdiction,
            citations: jurisdiction.citations(),
            seal_id: seal.id_string(),
            workflow_id: seal.workflow_id.clone(),
            event_class: event_class.into(),
            decision: decision.into(),
            tenant_id: seal.tenant_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_jurisdictions_covered() {
        let all = [
            HealthcareJurisdiction::DohAbuDhabi,
            HealthcareJurisdiction::Dha,
            HealthcareJurisdiction::Mohap,
            HealthcareJurisdiction::Ehs,
            HealthcareJurisdiction::HipaaUs,
            HealthcareJurisdiction::EuAiActGdpr,
            HealthcareJurisdiction::NhraBahrain,
        ];
        for j in all {
            assert!(!j.citations().is_empty(), "{:?} missing citations", j);
            assert!(!j.seal_tag().is_empty());
        }
    }
}
