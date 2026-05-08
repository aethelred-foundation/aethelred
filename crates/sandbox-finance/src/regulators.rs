//! Finance regulator views.
//!
//! A single [`crate::core::DigitalSeal`] is projected into seven jurisdiction-shape
//! views — same canonical seal, different presentation. Reviewers in
//! different regulators see the fields they care about with the citations
//! they expect.
//!
//! The regulator view is a *transformation*, not a different seal. The
//! underlying cryptographic evidence is identical.

use serde::{Deserialize, Serialize};

/// Finance regulator jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinanceJurisdiction {
    /// Central Bank of UAE — domestic banking + AML/CFT supervision.
    Cbuae,
    /// Securities & Commodities Authority (UAE).
    Sca,
    /// Financial Services Regulatory Authority (Abu Dhabi Global Market).
    Fsra,
    /// Dubai Financial Services Authority (DIFC).
    Dfsa,
    /// Financial Conduct Authority + Prudential Regulation Authority (UK).
    FcaUk,
    /// Office of the Comptroller of the Currency / Federal Reserve / FinCEN (US).
    OccFedFincenUs,
    /// Monetary Authority of Singapore.
    Mas,
}

impl FinanceJurisdiction {
    /// Stable string id (lowercase).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cbuae => "cbuae",
            Self::Sca => "sca",
            Self::Fsra => "fsra",
            Self::Dfsa => "dfsa",
            Self::FcaUk => "fca_uk",
            Self::OccFedFincenUs => "occ_fed_fincen_us",
            Self::Mas => "mas",
        }
    }

    /// Jurisdiction tag used on [`crate::core::DigitalSeal::jurisdiction_tag`].
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::Cbuae => "AE-CBUAE",
            Self::Sca => "AE-SCA",
            Self::Fsra => "AE-ADGM-FSRA",
            Self::Dfsa => "AE-DIFC-DFSA",
            Self::FcaUk => "UK-FCA",
            Self::OccFedFincenUs => "US-OCC",
            Self::Mas => "SG-MAS",
        }
    }

    /// Primary regulator citations for this jurisdiction (used by the
    /// regulator-shape view to render the right citation set).
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::Cbuae => vec![
                RegulatorCitation::cbuae_aml_record_keeping(),
                RegulatorCitation::cbuae_outsourcing_regulation(),
            ],
            Self::Sca => vec![RegulatorCitation::sca_market_conduct()],
            Self::Fsra | Self::Dfsa => vec![RegulatorCitation::adgm_difc_supervisory_obligations()],
            Self::FcaUk => vec![
                RegulatorCitation::fca_sysc(),
                RegulatorCitation::fca_ai_dp_5_22(),
            ],
            Self::OccFedFincenUs => vec![
                RegulatorCitation::occ_sr_11_7(),
                RegulatorCitation::fed_fincen_recordkeeping(),
            ],
            Self::Mas => vec![RegulatorCitation::mas_veritas_feat()],
        }
    }
}

/// A single regulator citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Regulator name.
    pub regulator: String,
    /// Citation id (e.g., `"SR 11-7"`).
    pub citation_id: String,
    /// Section (article / clause / guideline).
    pub section: String,
    /// Plain-English summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// CBUAE AML / CFT Procedures, Article 18 — record-keeping.
    pub fn cbuae_aml_record_keeping() -> Self {
        Self {
            regulator: "CBUAE".into(),
            citation_id: "AML/CFT Procedures".into(),
            section: "Article 18".into(),
            summary: "Five-year retention of transaction records and CDD information.".into(),
        }
    }

    /// CBUAE Outsourcing Regulation (Notice No. 14/2021).
    pub fn cbuae_outsourcing_regulation() -> Self {
        Self {
            regulator: "CBUAE".into(),
            citation_id: "Notice No. 14/2021".into(),
            section: "Outsourcing Regulation".into(),
            summary: "Notification / approval requirements for material outsourcing arrangements.".into(),
        }
    }

    /// SCA Market Conduct Rules.
    pub fn sca_market_conduct() -> Self {
        Self {
            regulator: "SCA".into(),
            citation_id: "Market Conduct Rules".into(),
            section: "Records and disclosures".into(),
            summary: "Market-conduct evidence retention for securities and capital-markets activity.".into(),
        }
    }

    /// ADGM FSRA / DIFC DFSA supervisory obligations.
    pub fn adgm_difc_supervisory_obligations() -> Self {
        Self {
            regulator: "FSRA / DFSA".into(),
            citation_id: "Supervisory Rulebook".into(),
            section: "Records and reporting".into(),
            summary: "Supervisory record-keeping for ADGM / DIFC-licensed activity.".into(),
        }
    }

    /// FCA SYSC — Senior Management Arrangements, Systems and Controls.
    pub fn fca_sysc() -> Self {
        Self {
            regulator: "FCA (UK)".into(),
            citation_id: "SYSC".into(),
            section: "Senior Management Arrangements, Systems and Controls".into(),
            summary: "Governance, accountability, and record-keeping for regulated firms.".into(),
        }
    }

    /// FCA Discussion Paper DP5/22 — AI in financial services.
    pub fn fca_ai_dp_5_22() -> Self {
        Self {
            regulator: "FCA (UK)".into(),
            citation_id: "DP5/22".into(),
            section: "AI in Financial Services".into(),
            summary: "Board-level AI governance and accountability expectations.".into(),
        }
    }

    /// OCC / Federal Reserve SR 11-7 — model risk management.
    pub fn occ_sr_11_7() -> Self {
        Self {
            regulator: "OCC / Federal Reserve (US)".into(),
            citation_id: "SR 11-7".into(),
            section: "Sections IV–V".into(),
            summary: "Effective challenge, documentation, monitoring of model risk.".into(),
        }
    }

    /// Federal Reserve / FinCEN record-keeping (BSA + 12 CFR).
    pub fn fed_fincen_recordkeeping() -> Self {
        Self {
            regulator: "Federal Reserve / FinCEN (US)".into(),
            citation_id: "BSA + 12 CFR".into(),
            section: "Recordkeeping".into(),
            summary: "BSA-aligned recordkeeping and FinCEN reporting requirements.".into(),
        }
    }

    /// MAS Veritas FEAT principles.
    pub fn mas_veritas_feat() -> Self {
        Self {
            regulator: "MAS (Singapore)".into(),
            citation_id: "Veritas".into(),
            section: "FEAT principles".into(),
            summary: "Fairness / Ethics / Accountability / Transparency principles for AI in finance.".into(),
        }
    }
}

/// A regulator-shape view of a finance seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorView {
    /// Jurisdiction this view targets.
    pub jurisdiction: FinanceJurisdiction,
    /// Citations bundled with this view.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id string.
    pub seal_id: String,
    /// Workflow id (e.g., `"credit_decision"`).
    pub workflow_id: String,
    /// Event class (e.g., `"adverse_action"`, `"alert"`, `"order"`).
    pub event_class: String,
    /// Decision (e.g., `"approve"` / `"deny"` / `"alert"`).
    pub decision: String,
    /// Tenant id.
    pub tenant_id: String,
    /// Hex of the validator signature, if present.
    pub validator_signature_hex: Option<String>,
}

impl RegulatorView {
    /// Project a [`crate::core::DigitalSeal`] into a regulator-shape view.
    pub fn project(
        seal: &aethelred_sandbox_core::DigitalSeal,
        jurisdiction: FinanceJurisdiction,
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
            validator_signature_hex: seal.validator_signature_hex.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_jurisdictions_have_citations() {
        let all = [
            FinanceJurisdiction::Cbuae,
            FinanceJurisdiction::Sca,
            FinanceJurisdiction::Fsra,
            FinanceJurisdiction::Dfsa,
            FinanceJurisdiction::FcaUk,
            FinanceJurisdiction::OccFedFincenUs,
            FinanceJurisdiction::Mas,
        ];
        for j in all {
            assert!(!j.citations().is_empty(), "{:?} has no citations", j);
            assert!(!j.seal_tag().is_empty());
        }
    }

    #[test]
    fn jurisdiction_string_ids_unique() {
        let all = [
            FinanceJurisdiction::Cbuae,
            FinanceJurisdiction::Sca,
            FinanceJurisdiction::Fsra,
            FinanceJurisdiction::Dfsa,
            FinanceJurisdiction::FcaUk,
            FinanceJurisdiction::OccFedFincenUs,
            FinanceJurisdiction::Mas,
        ];
        let mut ids: Vec<&str> = all.iter().map(|j| j.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
