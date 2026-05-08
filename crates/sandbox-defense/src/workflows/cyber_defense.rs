//! Cyber-defense workflow (SOC / SIEM / XDR AI decisions).
//!
//! Production target: AI-driven detection / response decisions in the cyber
//! defense CoE (e.g., EDGE Cyber CoE). The seal carries the decision class,
//! analyst-bind, and a redacted indicator-of-compromise reference.

use crate::protocols::{DefenseMessageEnvelope, DefenseProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Cyber-defense decision class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CyberDecision {
    /// Block.
    Block,
    /// Quarantine.
    Quarantine,
    /// Alert (analyst review required).
    Alert,
    /// Escalate (Tier-2 / Tier-3 review).
    Escalate,
    /// Allow (false-positive after review).
    Allow,
}

impl CyberDecision {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Quarantine => "quarantine",
            Self::Alert => "alert",
            Self::Escalate => "escalate",
            Self::Allow => "allow",
        }
    }
}

/// Cyber-defense input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberDefenseEvent {
    /// Detection id.
    pub detection_id: String,
    /// Decision.
    pub decision: CyberDecision,
    /// MITRE ATT&CK technique id (e.g., `T1059.001`).
    pub mitre_technique: Option<String>,
    /// Severity score (0–100).
    pub severity: u32,
    /// AI detection model id.
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Analyst role.
    pub analyst_role: String,
    /// Analyst pseudo id.
    pub analyst_pseudo_id: String,
    /// Message envelope.
    pub message: DefenseMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl CyberDefenseEvent {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"STIX 2.1 indicator");
        Self {
            detection_id: "det-2026-12-44011".into(),
            decision: CyberDecision::Alert,
            mitre_technique: Some("T1059.001".into()),
            severity: 72,
            model_id: "cyber_xdr_v6".into(),
            model_hash_hex: Hasher::sha256(b"demo-cyber-weights").to_hex(),
            model_version: Some("6.4.2".into()),
            analyst_role: "soc_l1".into(),
            analyst_pseudo_id: "role:soc_l1#011".into(),
            message: DefenseMessageEnvelope {
                protocol: DefenseProtocol::Internal,
                message_type: "STIX-2.1 Indicator".into(),
                source_platform: "edge-cyber-coe-1".into(),
                correlation_id: "det-2026-12-44011".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed cyber-defense event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CyberDefenseSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Decision (mirrored).
    pub decision: CyberDecision,
}

impl CyberDefenseSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &CyberDefenseEvent,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.detection_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        bytes.extend_from_slice(&input.severity.to_be_bytes());
        if let Some(t) = &input.mitre_technique {
            bytes.extend_from_slice(t.as_bytes());
        }
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("cyber_defense"));
    sector_extension.insert("decision".into(), serde_json::json!(input.decision.as_str()));
    sector_extension.insert("severity".into(), serde_json::json!(input.severity));
    if let Some(t) = &input.mitre_technique {
        sector_extension.insert("mitre_technique".into(), serde_json::json!(t));
    }
    sector_extension.insert("non_weaponized_scope".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.analyst_pseudo_id.clone(),
        role: input.analyst_role.clone(),
        decision: input.decision.as_str().to_string(),
        reason_class: input.mitre_technique.clone(),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Defense,
        event_type: format!("cyber_defense.{}", input.decision.as_str()),
        event_hash,
        model,
        policy_id: "po_cyber_defense_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "cyber_defense".to_string(),
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
