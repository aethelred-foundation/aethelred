//! AI-assisted manufacturing-inspection workflow (defense industrial QA).
//!
//! Production target: AI defect classification on production lines (Caracal,
//! Lahab, Strata Manufacturing) with operator-bind and supplier provenance.

use crate::protocols::{DefenseMessageEnvelope, DefenseProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Inspection outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionOutcome {
    /// Pass.
    Pass,
    /// Fail (defect found above tolerance).
    Fail,
    /// Pending — manual re-inspection needed.
    Pending,
    /// Out of tolerance but within engineering waiver.
    Waiver,
}

impl InspectionOutcome {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Pending => "pending",
            Self::Waiver => "waiver",
        }
    }
}

/// Inspection QA input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionQa {
    /// Lot id.
    pub lot_id: String,
    /// Component id.
    pub component_id: String,
    /// Supplier id (sovereignty bind).
    pub supplier_id: String,
    /// Defect class (e.g., `"surface_porosity"`, `"dimensional_oot"`).
    pub defect_class: Option<String>,
    /// AI inspection model id.
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Outcome.
    pub outcome: InspectionOutcome,
    /// Inspector role.
    pub inspector_role: String,
    /// Inspector pseudo id.
    pub inspector_pseudo_id: String,
    /// Message envelope.
    pub message: DefenseMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl InspectionQa {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"AS9100 inspection record");
        Self {
            lot_id: "lot-2026-12-880".into(),
            component_id: "p/n-771-rev-c".into(),
            supplier_id: "supplier-441".into(),
            defect_class: None,
            model_id: "inspection_ai_v2".into(),
            model_hash_hex: Hasher::sha256(b"demo-insp-weights").to_hex(),
            model_version: Some("2.0.4".into()),
            outcome: InspectionOutcome::Pass,
            inspector_role: "inspector".into(),
            inspector_pseudo_id: "role:inspector#a04".into(),
            message: DefenseMessageEnvelope {
                protocol: DefenseProtocol::Internal,
                message_type: "InspectionRecord".into(),
                source_platform: "as9100-line-1".into(),
                correlation_id: "lot-2026-12-880".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionQaSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Outcome (mirrored).
    pub outcome: InspectionOutcome,
}

impl InspectionQaSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &InspectionQa,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.lot_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.outcome.as_str().as_bytes());
        bytes.extend_from_slice(input.component_id.as_bytes());
        if let Some(d) = &input.defect_class {
            bytes.extend_from_slice(d.as_bytes());
        }
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("inspection_qa"));
    sector_extension.insert("lot_id".into(), serde_json::json!(input.lot_id));
    sector_extension.insert("component_id".into(), serde_json::json!(input.component_id));
    sector_extension.insert("supplier_id".into(), serde_json::json!(input.supplier_id));
    sector_extension.insert("outcome".into(), serde_json::json!(input.outcome.as_str()));
    if let Some(d) = &input.defect_class {
        sector_extension.insert("defect_class".into(), serde_json::json!(d));
    }
    sector_extension.insert("non_weaponized_scope".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.inspector_pseudo_id.clone(),
        role: input.inspector_role.clone(),
        decision: input.outcome.as_str().to_string(),
        reason_class: input.defect_class.clone(),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Defense,
        event_type: format!("inspection_qa.{}", input.outcome.as_str()),
        event_hash,
        model,
        policy_id: "po_inspection_qa_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "inspection_qa".to_string(),
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
