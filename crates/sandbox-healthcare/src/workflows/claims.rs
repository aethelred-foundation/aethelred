//! Claims-adjudication workflow (Daman / payor use case).
//!
//! Production target: per-claim AI-assisted adjudication with reviewer
//! approval. The seal carries the claim id, decision, and explanation
//! reason class — the latter is essential for member-appeal evidence.

use crate::protocols::{HealthcareMessageEnvelope, HealthcareProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Claims adjudication outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDecision {
    /// Approved.
    Approved,
    /// Approved with adjustments (partial / co-pay change / network limit).
    ApprovedAdjusted,
    /// Pending information.
    PendingInfo,
    /// Denied (with explanation reason class).
    Denied,
    /// Escalated for medical-necessity review.
    Escalated,
}

impl ClaimDecision {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ApprovedAdjusted => "approved_adjusted",
            Self::PendingInfo => "pending_info",
            Self::Denied => "denied",
            Self::Escalated => "escalated",
        }
    }
    /// `true` for adverse-against-member outcomes.
    pub fn is_adverse(self) -> bool {
        matches!(self, Self::Denied | Self::ApprovedAdjusted)
    }
}

/// Claims adjudication input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsAdjudication {
    /// Claim id (payor case reference).
    pub claim_id: String,
    /// Member pseudo id.
    pub member_pseudo_id: String,
    /// Service / procedure code (e.g., CPT, ICD-10-PCS).
    pub procedure_code: String,
    /// AI model id (e.g., `"daman_adjudication_v3"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Decision.
    pub decision: ClaimDecision,
    /// Optional denial / adjustment reason class (required for adverse outcomes).
    pub reason_class: Option<String>,
    /// Reviewer role (`"medical_director"`, `"l2_claims_reviewer"`, `"auto_adjudication"`).
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// FHIR R4 ExplanationOfBenefit / Internal envelope.
    pub message: HealthcareMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl ClaimsAdjudication {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"FHIR ExplanationOfBenefit id=eob-1");
        Self {
            claim_id: "claim-2026-12-99812".into(),
            member_pseudo_id: "psn:member-7c2".into(),
            procedure_code: "99213".into(),
            model_id: "daman_adjudication_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-daman-weights").to_hex(),
            model_version: Some("3.2.0".into()),
            decision: ClaimDecision::Approved,
            reason_class: None,
            reviewer_role: "auto_adjudication".into(),
            reviewer_pseudo_id: "role:auto_adjudication#001".into(),
            message: HealthcareMessageEnvelope {
                protocol: HealthcareProtocol::Internal,
                resource_type: "Daman-EOB".into(),
                source_system: "daman-claims-platform".into(),
                correlation_id: "eob-1".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed claims adjudication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsAdjudicationSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Decision (mirrored).
    pub decision: ClaimDecision,
}

impl ClaimsAdjudicationSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &ClaimsAdjudication,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.claim_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        bytes.extend_from_slice(input.procedure_code.as_bytes());
        if let Some(r) = &input.reason_class {
            bytes.extend_from_slice(r.as_bytes());
        }
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("claims_adjudication"));
    sector_extension.insert("claim_id".into(), serde_json::json!(input.claim_id));
    sector_extension.insert("procedure_code".into(), serde_json::json!(input.procedure_code));
    sector_extension.insert("decision".into(), serde_json::json!(input.decision.as_str()));
    if let Some(r) = &input.reason_class {
        sector_extension.insert("reason_class".into(), serde_json::json!(r));
    }
    sector_extension.insert("decision_support_only".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.decision.as_str().to_string(),
        reason_class: input.reason_class.clone(),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Healthcare,
        event_type: format!("claims_adjudication.{}", input.decision.as_str()),
        event_hash,
        model,
        policy_id: "po_claims_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "claims_adjudication".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
        retention: RetentionClass::TenYears,
        prior_seal_hash: None,
        sector_extension,
        validator_signature_hex: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seal_carries_decision_and_procedure() {
        let c = ClaimsAdjudication::demo();
        let seal = build_seal(&c, "PureHealth", "AE-AD-DOH").unwrap();
        assert_eq!(seal.workflow_id, "claims_adjudication");
        assert_eq!(
            seal.sector_extension.get("procedure_code").unwrap(),
            &serde_json::json!("99213")
        );
    }
}
