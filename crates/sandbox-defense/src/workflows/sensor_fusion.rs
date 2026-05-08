//! Sensor-fusion workflow.
//!
//! Production target: multi-source sensor fusion (radar / EO/IR / SIGINT /
//! acoustics) with confidence threshold, source provenance, and human review.
//! Strict non-weaponised scope.

use crate::protocols::{DefenseMessageEnvelope, DefenseProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Sensor source class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorSource {
    /// Radar.
    Radar,
    /// Electro-optical / infrared.
    EoIr,
    /// Signals intelligence.
    Sigint,
    /// Acoustic.
    Acoustic,
    /// Lidar.
    Lidar,
    /// Other / mixed.
    Other,
}

impl SensorSource {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Radar => "radar",
            Self::EoIr => "eo_ir",
            Self::Sigint => "sigint",
            Self::Acoustic => "acoustic",
            Self::Lidar => "lidar",
            Self::Other => "other",
        }
    }
}

/// Sensor fusion classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionClassification {
    /// Confirmed (above threshold + multi-source consensus).
    Confirmed,
    /// Probable.
    Probable,
    /// Possible.
    Possible,
    /// Unknown.
    Unknown,
    /// Discarded (below confidence floor or contradicted).
    Discarded,
}

impl FusionClassification {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Probable => "probable",
            Self::Possible => "possible",
            Self::Unknown => "unknown",
            Self::Discarded => "discarded",
        }
    }
}

/// Sensor fusion input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorFusion {
    /// Track id.
    pub track_id: String,
    /// Sensor sources fused.
    pub sources: Vec<SensorSource>,
    /// Confidence threshold applied (0.0–1.0).
    pub threshold: f64,
    /// Resulting classification.
    pub classification: FusionClassification,
    /// Confidence (0.0–1.0).
    pub confidence: f64,
    /// AI fusion model id.
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Message envelope.
    pub message: DefenseMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl SensorFusion {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"DDS sensor-fusion fusion-track-1");
        Self {
            track_id: "track-2026-12-771".into(),
            sources: vec![SensorSource::Radar, SensorSource::EoIr],
            threshold: 0.75,
            classification: FusionClassification::Probable,
            confidence: 0.81,
            model_id: "fusion_v2".into(),
            model_hash_hex: Hasher::sha256(b"demo-fusion-weights").to_hex(),
            model_version: Some("2.4.0".into()),
            reviewer_role: "fusion_analyst".into(),
            reviewer_pseudo_id: "role:fusion_analyst#031".into(),
            message: DefenseMessageEnvelope {
                protocol: DefenseProtocol::Dds,
                message_type: "FusionTrack".into(),
                source_platform: "edge-fusion-station-1".into(),
                correlation_id: "track-2026-12-771".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed sensor fusion event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorFusionSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Classification (mirrored).
    pub classification: FusionClassification,
}

impl SensorFusionSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &SensorFusion,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.track_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.classification.as_str().as_bytes());
        bytes.extend_from_slice(input.confidence.to_le_bytes().as_slice());
        for s in &input.sources {
            bytes.extend_from_slice(s.as_str().as_bytes());
        }
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("sensor_fusion"));
    sector_extension.insert(
        "sources".into(),
        serde_json::json!(input.sources.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
    );
    sector_extension.insert(
        "classification".into(),
        serde_json::json!(input.classification.as_str()),
    );
    sector_extension.insert("confidence".into(), serde_json::json!(input.confidence));
    sector_extension.insert("threshold".into(), serde_json::json!(input.threshold));
    sector_extension.insert("non_weaponized_scope".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.classification.as_str().to_string(),
        reason_class: None,
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Defense,
        event_type: format!("sensor_fusion.{}", input.classification.as_str()),
        event_hash,
        model,
        policy_id: "po_sensor_fusion_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "sensor_fusion".to_string(),
        jurisdiction_tag: input
            .jurisdiction_tag
            .clone()
            .unwrap_or_else(|| default_jurisdiction.to_string()),
        retention: RetentionClass::TwentyFiveYears,
        prior_seal_hash: None,
        sector_extension,
        validator_signature_hex: None,
    })
}
