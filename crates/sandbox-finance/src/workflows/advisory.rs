//! Advisory / robo-advice workflow.
//!
//! Production target: per-recommendation seal with suitability evidence and
//! advisor-bind. Aligned to MiFID II suitability rules and FCA SYSC.

use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Suitability classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Suitability {
    /// Suitable.
    Suitable,
    /// Suitable with conditions / disclosures.
    SuitableWithConditions,
    /// Not suitable — recommendation withheld.
    NotSuitable,
    /// Suitability not assessed (execution-only).
    NotAssessed,
}

impl Suitability {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suitable => "suitable",
            Self::SuitableWithConditions => "suitable_with_conditions",
            Self::NotSuitable => "not_suitable",
            Self::NotAssessed => "not_assessed",
        }
    }
}

/// Client class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientClass {
    /// Retail client.
    Retail,
    /// Professional client.
    Professional,
    /// Eligible counterparty.
    EligibleCounterparty,
}

impl ClientClass {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retail => "retail",
            Self::Professional => "professional",
            Self::EligibleCounterparty => "eligible_counterparty",
        }
    }
}

/// Advisory recommendation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// Recommendation id.
    pub recommendation_id: String,
    /// Client pseudo id.
    pub client_pseudo_id: String,
    /// Client class.
    pub client_class: ClientClass,
    /// Product / instrument id.
    pub product: String,
    /// Recommended notional / amount.
    pub amount: Decimal,
    /// Currency.
    pub currency: String,
    /// AI model id (e.g., `"robo_advisor_v5"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Suitability classification.
    pub suitability: Suitability,
    /// Advisor role (`"rm:private"`, `"robo:auto"`, `"trainee"`).
    pub advisor_role: String,
    /// Advisor pseudo id.
    pub advisor_pseudo_id: String,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl Advisory {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            recommendation_id: "rec-2026-12-444".into(),
            client_pseudo_id: "psn:client#7c2a".into(),
            client_class: ClientClass::Retail,
            product: "balanced_growth_etf_v3".into(),
            amount: Decimal::new(50_000, 0),
            currency: "AED".into(),
            model_id: "robo_advisor_v5".into(),
            model_hash_hex: Hasher::sha256(b"demo-robo-weights").to_hex(),
            model_version: Some("5.0.2".into()),
            suitability: Suitability::Suitable,
            advisor_role: "robo:auto".into(),
            advisor_pseudo_id: "role:robo_auto#001".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed advisory recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorySeal {
    /// The underlying canonical seal.
    pub seal: DigitalSeal,
    /// Suitability classification (mirrored).
    pub suitability: Suitability,
}

impl AdvisorySeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &Advisory,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.recommendation_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.suitability.as_str().as_bytes());
        bytes.extend_from_slice(input.product.as_bytes());
        bytes.extend_from_slice(input.amount.to_string().as_bytes());
        bytes.extend_from_slice(input.currency.as_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.recommendation_id.as_bytes());
        bytes.extend_from_slice(input.model_id.as_bytes());
        bytes.extend_from_slice(input.suitability.as_str().as_bytes());
        Hasher::sha256(&bytes)
    };
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("advisory"));
    sector_extension.insert("recommendation_id".into(), serde_json::json!(input.recommendation_id));
    sector_extension.insert("client_class".into(), serde_json::json!(input.client_class.as_str()));
    sector_extension.insert("product".into(), serde_json::json!(input.product));
    sector_extension.insert("amount".into(), serde_json::json!(input.amount.to_string()));
    sector_extension.insert("suitability".into(), serde_json::json!(input.suitability.as_str()));
    let approval = ApprovalRecord {
        approver_ref: input.advisor_pseudo_id.clone(),
        role: input.advisor_role.clone(),
        decision: input.suitability.as_str().to_string(),
        reason_class: Some(input.client_class.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: format!("advisory.{}", input.suitability.as_str()),
        event_hash,
        model,
        policy_id: "po_advisory_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "advisory".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
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
    fn demo_seal_carries_suitability_and_client_class() {
        let a = Advisory::demo();
        let seal = build_seal(&a, "FAB", "AE-CBUAE").unwrap();
        assert_eq!(seal.workflow_id, "advisory");
        assert_eq!(
            seal.sector_extension.get("suitability").unwrap(),
            &serde_json::json!("suitable")
        );
        assert_eq!(
            seal.sector_extension.get("client_class").unwrap(),
            &serde_json::json!("retail")
        );
    }
}
