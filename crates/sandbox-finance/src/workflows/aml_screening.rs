//! AML / sanctions / PEP screening workflow.
//!
//! Production target: per-alert AML / sanctions / PEP screening evidence
//! aligned to FATF Recommendation 11 (record-keeping), CBUAE AML/CFT
//! procedures Article 18, and Wolfsberg Group principles.
//!
//! Each alert produces a sealed event capturing model, policy class,
//! analyst approval (or escalation), and the alert outcome.

use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// AML alert outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmlAlertOutcome {
    /// Cleared — no SAR / no further action.
    Cleared,
    /// Escalated — Level-2 / Level-3 review required.
    Escalated,
    /// SAR filed — Suspicious Activity Report submitted to authorities.
    SarFiled,
    /// Customer relationship terminated.
    Terminated,
    /// Under investigation — still open at the time of sealing.
    UnderInvestigation,
}

impl AmlAlertOutcome {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleared => "cleared",
            Self::Escalated => "escalated",
            Self::SarFiled => "sar_filed",
            Self::Terminated => "terminated",
            Self::UnderInvestigation => "under_investigation",
        }
    }
}

/// AML screening typology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmlTypology {
    /// Structuring / smurfing.
    Structuring,
    /// PEP (Politically Exposed Person) match.
    PepMatch,
    /// Sanctions list match (OFAC SDN / EU / UN / UAE Local).
    SanctionsMatch,
    /// High-risk jurisdiction movement.
    HighRiskJurisdiction,
    /// Trade-based money laundering.
    TradeBasedMl,
    /// Unusual transaction pattern (model-detected).
    UnusualPattern,
    /// Other / sector-specific.
    Other,
}

impl AmlTypology {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structuring => "structuring",
            Self::PepMatch => "pep_match",
            Self::SanctionsMatch => "sanctions_match",
            Self::HighRiskJurisdiction => "high_risk_jurisdiction",
            Self::TradeBasedMl => "trade_based_ml",
            Self::UnusualPattern => "unusual_pattern",
            Self::Other => "other",
        }
    }
}

/// AML alert input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlAlert {
    /// Bank-issued alert id.
    pub alert_id: String,
    /// Customer pseudonymised id.
    pub customer_pseudo_id: String,
    /// Typology that triggered the alert.
    pub typology: AmlTypology,
    /// Risk score (0–100).
    pub risk_score: u32,
    /// Model id (e.g., `"aml_v8.4"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Optional case-management reference (NICE Actimize / Quantexa / Sensa).
    pub case_management_ref: Option<String>,
    /// Final outcome.
    pub outcome: AmlAlertOutcome,
    /// Analyst role (e.g., `"l1_aml_analyst"`, `"fcc_l2"`, `"mlro"`).
    pub analyst_role: String,
    /// Analyst pseudo id.
    pub analyst_pseudo_id: String,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl AmlAlert {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            alert_id: "alert-2026-12-7411".into(),
            customer_pseudo_id: "psn:c811".into(),
            typology: AmlTypology::Structuring,
            risk_score: 78,
            model_id: "aml_v8.4".into(),
            model_hash_hex: Hasher::sha256(b"demo-aml-model-weights").to_hex(),
            model_version: Some("8.4.1".into()),
            case_management_ref: Some("nice_actimize:case-99812".into()),
            outcome: AmlAlertOutcome::Escalated,
            analyst_role: "l1_aml_analyst".into(),
            analyst_pseudo_id: "role:l1_aml#7c2".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed AML alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmlAlertSeal {
    /// The underlying canonical seal.
    pub seal: DigitalSeal,
    /// Outcome (mirrored).
    pub outcome: AmlAlertOutcome,
}

impl AmlAlertSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &AmlAlert,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference {
        model_hash,
        model_id: input.model_id.clone(),
        model_version: input.model_version.clone(),
        weights_commit_ref: input.case_management_ref.clone(),
        framework: None,
        framework_version: None,
        training_data_class: Some("synthetic_aml_training_v1".into()),
    };
    let input_hash = Hasher::sha256(input.alert_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.outcome.as_str().as_bytes());
        bytes.extend_from_slice(input.typology.as_str().as_bytes());
        bytes.extend_from_slice(&input.risk_score.to_be_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.alert_id.as_bytes());
        bytes.extend_from_slice(input.model_id.as_bytes());
        bytes.extend_from_slice(input.outcome.as_str().as_bytes());
        Hasher::sha256(&bytes)
    };
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("aml_screening"));
    sector_extension.insert("alert_id".into(), serde_json::json!(input.alert_id));
    sector_extension.insert("typology".into(), serde_json::json!(input.typology.as_str()));
    sector_extension.insert("risk_score".into(), serde_json::json!(input.risk_score));
    sector_extension.insert("outcome".into(), serde_json::json!(input.outcome.as_str()));
    if let Some(c) = &input.case_management_ref {
        sector_extension.insert("case_management_ref".into(), serde_json::json!(c));
    }
    let approval = ApprovalRecord {
        approver_ref: input.analyst_pseudo_id.clone(),
        role: input.analyst_role.clone(),
        decision: input.outcome.as_str().to_string(),
        reason_class: Some(input.typology.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: format!("aml_alert.{}", input.outcome.as_str()),
        event_hash,
        model,
        policy_id: "po_aml_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "aml_screening".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
        // FATF Rec 11 mandates 5-year retention; we exceed at 7y for IRS / CBUAE alignment.
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension,
        validator_signature_hex: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seal_carries_typology_and_outcome() {
        let a = AmlAlert::demo();
        let seal = build_seal(&a, "FAB", "AE-CBUAE").unwrap();
        assert_eq!(seal.workflow_id, "aml_screening");
        assert_eq!(
            seal.sector_extension.get("typology").unwrap(),
            &serde_json::json!("structuring")
        );
        assert_eq!(seal.retention, RetentionClass::SevenYears);
    }

    #[test]
    fn outcome_string_ids_unique() {
        let all = [
            AmlAlertOutcome::Cleared,
            AmlAlertOutcome::Escalated,
            AmlAlertOutcome::SarFiled,
            AmlAlertOutcome::Terminated,
            AmlAlertOutcome::UnderInvestigation,
        ];
        let mut ids: Vec<&str> = all.iter().map(|o| o.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
