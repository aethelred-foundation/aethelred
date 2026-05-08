//! Autonomous logistics workflow (UGV / UAV fleet operations).
//!
//! Production target: the EDGE / TII / Micropolis / SteerAI Jan 2026
//! autonomous logistics platform. Each mission step is sealed with the
//! decision class, ODD validity, operator override (if any), and human
//! command authority bind.

use crate::protocols::{DefenseMessageEnvelope, DefenseProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Autonomous platform class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformClass {
    /// UGV (unmanned ground vehicle).
    Ugv,
    /// UAV (unmanned aerial vehicle).
    Uav,
    /// USV (unmanned surface vessel).
    Usv,
    /// UUV (unmanned underwater vehicle).
    Uuv,
}

impl PlatformClass {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ugv => "ugv",
            Self::Uav => "uav",
            Self::Usv => "usv",
            Self::Uuv => "uuv",
        }
    }
}

/// Mission step decision class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionDecision {
    /// Route assignment / waypoint accepted.
    RouteAccept,
    /// Route assignment / waypoint rejected.
    RouteReject,
    /// Anomaly stop (sensor anomaly forced halt).
    AnomalyStop,
    /// Operator override (human took control).
    OperatorOverride,
    /// Mission complete.
    MissionComplete,
}

impl MissionDecision {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RouteAccept => "route_accept",
            Self::RouteReject => "route_reject",
            Self::AnomalyStop => "anomaly_stop",
            Self::OperatorOverride => "operator_override",
            Self::MissionComplete => "mission_complete",
        }
    }
}

/// Autonomous logistics input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousLogistics {
    /// Mission id.
    pub mission_id: String,
    /// Platform id (e.g., `"micropolis-ugv-1"`).
    pub platform_id: String,
    /// Platform class.
    pub platform_class: PlatformClass,
    /// Decision.
    pub decision: MissionDecision,
    /// `true` if the mission step is within ODD.
    pub within_odd: bool,
    /// Geofence id.
    pub geofence_id: String,
    /// AI model id (e.g., `"steerai_autonomy_v3"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Operator role (`"mission_commander"`, `"safety_pilot"`, `"none"`).
    pub operator_role: String,
    /// Operator pseudo id (always required for command-bind).
    pub operator_pseudo_id: String,
    /// STANAG 4586 / DDS message envelope.
    pub message: DefenseMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl AutonomousLogistics {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"STANAG 4586 vehicle command set");
        Self {
            mission_id: "mission-2026-12-001".into(),
            platform_id: "micropolis-ugv-1".into(),
            platform_class: PlatformClass::Ugv,
            decision: MissionDecision::RouteAccept,
            within_odd: true,
            geofence_id: "kezad-ad-zone-7".into(),
            model_id: "steerai_autonomy_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-autonomy-weights").to_hex(),
            model_version: Some("3.2.1".into()),
            operator_role: "mission_commander".into(),
            operator_pseudo_id: "role:mission_commander#a1c".into(),
            message: DefenseMessageEnvelope {
                protocol: DefenseProtocol::Stanag4586,
                message_type: "VehicleCommand".into(),
                source_platform: "micropolis-ugv-1".into(),
                correlation_id: "mission-2026-12-001-step-7".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed autonomous logistics step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousLogisticsSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Decision (mirrored).
    pub decision: MissionDecision,
}

impl AutonomousLogisticsSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &AutonomousLogistics,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.mission_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        bytes.extend_from_slice(input.platform_id.as_bytes());
        bytes.extend_from_slice(input.geofence_id.as_bytes());
        bytes.extend_from_slice(&[input.within_odd as u8]);
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("autonomous_logistics"));
    sector_extension.insert("mission_id".into(), serde_json::json!(input.mission_id));
    sector_extension.insert("platform_id".into(), serde_json::json!(input.platform_id));
    sector_extension.insert(
        "platform_class".into(),
        serde_json::json!(input.platform_class.as_str()),
    );
    sector_extension.insert("decision".into(), serde_json::json!(input.decision.as_str()));
    sector_extension.insert("within_odd".into(), serde_json::json!(input.within_odd));
    sector_extension.insert("geofence_id".into(), serde_json::json!(input.geofence_id));
    sector_extension.insert("non_weaponized_scope".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.operator_pseudo_id.clone(),
        role: input.operator_role.clone(),
        decision: input.decision.as_str().to_string(),
        reason_class: Some(input.platform_class.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Defense,
        event_type: format!("autonomous_logistics.{}", input.decision.as_str()),
        event_hash,
        model,
        policy_id: "po_autonomous_logistics_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "autonomous_logistics".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_seal_carries_mission_extension() {
        let a = AutonomousLogistics::demo();
        let seal = build_seal(&a, "EDGE", "AE-AF").unwrap();
        assert_eq!(seal.workflow_id, "autonomous_logistics");
        assert_eq!(seal.sector, Sector::Defense);
        assert_eq!(
            seal.sector_extension.get("non_weaponized_scope").unwrap(),
            &serde_json::json!(true)
        );
        assert_eq!(seal.retention, RetentionClass::TwentyFiveYears);
    }
}
