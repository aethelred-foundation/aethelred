//! # Aethelred Infinity Sandbox — Autonomous Mobility Assurance
//!
//! Production-grade verification & evidence layer for autonomous-mobility
//! systems: Operational Design Domain (ODD) validation, mission replay,
//! safety-case events, and incident reconstruction. ROS2 DDS / FMI / OpenUSD
//! protocol envelopes. ISO 21448 (SOTIF) / ISO 26262 / DO-178C / DO-326A /
//! DO-356A regulator views.
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_autonomous_mobility::prelude::*;
//!
//! let sandbox = AutonomousMobilitySandbox::quickstart("TII VentureOne").unwrap();
//! let seal = sandbox.seal_mission_step(MissionStep::demo()).unwrap();
//! ```

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, EvidenceBundle, EvidenceLogEntry, Hasher, ModelReference,
    RetentionClass, Sandbox, SandboxBuilder, SandboxError, SandboxResult, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

pub use aethelred_sandbox_core as core;

/// Prelude.
pub mod prelude {
    pub use super::{
        AmJurisdiction, AutonomousMobilitySandbox, AutonomousMobilitySandboxBuilder, MissionStep,
        MissionStepSeal, OddProfile, OddValidation, OddValidationSeal, PerceptionEvent,
        PerceptionEventSeal, RegulatorView, SafetyCaseEvent, SafetyCaseEventSeal, SafetyCategory,
        SafetyOutcome, VehicleClass, WeatherCondition,
    };
    pub use aethelred_sandbox_core::{
        DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
        SandboxResult, Sector, Sha256Digest,
    };
}

// =============================================================================
// Policy
// =============================================================================

/// Within ODD bounds.
pub const GATE_ODD_BOUNDARY: &str = "autonomous_mobility.odd_boundary";
/// Approved autonomy model.
pub const GATE_MODEL_APPROVAL: &str = "autonomous_mobility.model_approval";
/// Human safety escalation present where required.
pub const GATE_HUMAN_ESCALATION: &str = "autonomous_mobility.human_escalation";
/// Mission timeline integrity (sensor → AI decision → operator action match).
pub const GATE_TIMELINE_INTEGRITY: &str = "autonomous_mobility.timeline_integrity";
/// Safety case completeness.
pub const GATE_SAFETY_CASE_COMPLETE: &str = "autonomous_mobility.safety_case_complete";
/// Jurisdiction supported.
pub const GATE_JURISDICTION_SUPPORTED: &str = "autonomous_mobility.jurisdiction_supported";

fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(GATE_MODEL_APPROVAL, "Approved autonomy model", "Only approved autonomy model versions can be sealed."),
        PolicyGate::required(GATE_TIMELINE_INTEGRITY, "Timeline integrity", "Sensor / AI decision / operator action must reconcile."),
        PolicyGate::required(GATE_HUMAN_ESCALATION, "Human safety escalation", "High-risk events require operator / safety reviewer."),
        PolicyGate::required(GATE_JURISDICTION_SUPPORTED, "Jurisdiction supported", "Workflow jurisdiction must be configured."),
        PolicyGate::optional(GATE_ODD_BOUNDARY, "ODD boundary", "Out-of-domain operation soft-fails to escalation."),
        PolicyGate::optional(GATE_SAFETY_CASE_COMPLETE, "Safety case completeness", "Soft-fail when safety case fields are missing."),
    ]
}

// =============================================================================
// Regulators
// =============================================================================

/// Autonomous-mobility jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmJurisdiction {
    /// ISO 21448 — Safety of the Intended Function (SOTIF).
    Iso21448Sotif,
    /// ISO 26262 — Road vehicles functional safety.
    Iso26262,
    /// RTCA DO-178C — Airborne software safety.
    Do178c,
    /// RTCA DO-326A — Airworthiness security process.
    Do326a,
    /// RTCA DO-356A — Airworthiness security methods.
    Do356a,
    /// EU Regulation 2018/858 (vehicle approval) + UNECE WP.29.
    EuUneceWp29,
    /// UAE NCEMA + RTA road operations.
    UaeNcemaRta,
}

impl AmJurisdiction {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Iso21448Sotif => "iso_21448_sotif",
            Self::Iso26262 => "iso_26262",
            Self::Do178c => "do_178c",
            Self::Do326a => "do_326a",
            Self::Do356a => "do_356a",
            Self::EuUneceWp29 => "eu_unece_wp29",
            Self::UaeNcemaRta => "uae_ncema_rta",
        }
    }
    /// Seal tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::Iso21448Sotif => "ISO-21448-SOTIF",
            Self::Iso26262 => "ISO-26262",
            Self::Do178c => "DO-178C",
            Self::Do326a => "DO-326A",
            Self::Do356a => "DO-356A",
            Self::EuUneceWp29 => "EU-UNECE-WP29",
            Self::UaeNcemaRta => "AE-NCEMA-RTA",
        }
    }
    /// Citations.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::Iso21448Sotif => vec![RegulatorCitation::iso_21448_annex_e()],
            Self::Iso26262 => vec![RegulatorCitation::iso_26262_part_2()],
            Self::Do178c => vec![RegulatorCitation::do_178c_dal()],
            Self::Do326a => vec![RegulatorCitation::do_326a()],
            Self::Do356a => vec![RegulatorCitation::do_356a()],
            Self::EuUneceWp29 => vec![RegulatorCitation::eu_unece_wp29()],
            Self::UaeNcemaRta => vec![RegulatorCitation::uae_ncema_rta()],
        }
    }
}

/// Citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Regulator.
    pub regulator: String,
    /// Citation id.
    pub citation_id: String,
    /// Section.
    pub section: String,
    /// Summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// ISO 21448 Annex E.
    pub fn iso_21448_annex_e() -> Self { Self { regulator: "ISO".into(), citation_id: "ISO 21448:2022".into(), section: "Annex E".into(), summary: "SOTIF verification & validation activities for autonomous systems.".into() } }
    /// ISO 26262 Part 2.
    pub fn iso_26262_part_2() -> Self { Self { regulator: "ISO".into(), citation_id: "ISO 26262:2018 Part 2".into(), section: "Management of functional safety".into(), summary: "Safety lifecycle management for road-vehicle E/E systems.".into() } }
    /// DO-178C DAL.
    pub fn do_178c_dal() -> Self { Self { regulator: "RTCA / EUROCAE".into(), citation_id: "DO-178C / ED-12C".into(), section: "Software level (DAL)".into(), summary: "Software level assignment based on failure-condition severity.".into() } }
    /// DO-326A.
    pub fn do_326a() -> Self { Self { regulator: "RTCA / EUROCAE".into(), citation_id: "DO-326A / ED-202A".into(), section: "Airworthiness security process".into(), summary: "Airworthiness security risk assessment.".into() } }
    /// DO-356A.
    pub fn do_356a() -> Self { Self { regulator: "RTCA / EUROCAE".into(), citation_id: "DO-356A / ED-203A".into(), section: "Airworthiness security methods".into(), summary: "Methods supporting DO-326A.".into() } }
    /// EU UNECE WP.29.
    pub fn eu_unece_wp29() -> Self { Self { regulator: "EU + UNECE".into(), citation_id: "Regulation (EU) 2018/858 + WP.29".into(), section: "Vehicle approval + automated/autonomous regulations".into(), summary: "EU + UNECE vehicle approval + autonomy regulations.".into() } }
    /// UAE NCEMA + RTA.
    pub fn uae_ncema_rta() -> Self { Self { regulator: "UAE NCEMA + RTA".into(), citation_id: "UAE Autonomy Regulations".into(), section: "Road / mission ops".into(), summary: "UAE National Crisis Management + RTA road operations rules.".into() } }
}

/// Regulator view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorView {
    /// Jurisdiction.
    pub jurisdiction: AmJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id.
    pub seal_id: String,
    /// Workflow.
    pub workflow_id: String,
    /// Event class.
    pub event_class: String,
    /// Decision.
    pub decision: String,
    /// Tenant.
    pub tenant_id: String,
}

impl RegulatorView {
    /// Project a seal.
    pub fn project(seal: &DigitalSeal, jurisdiction: AmJurisdiction, decision: impl Into<String>, event_class: impl Into<String>) -> Self {
        Self { jurisdiction, citations: jurisdiction.citations(), seal_id: seal.id_string(), workflow_id: seal.workflow_id.clone(), event_class: event_class.into(), decision: decision.into(), tenant_id: seal.tenant_id.clone() }
    }
}

// =============================================================================
// Models
// =============================================================================

/// Vehicle class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VehicleClass {
    /// Ground passenger vehicle.
    GroundPassenger,
    /// Ground cargo vehicle.
    GroundCargo,
    /// UAV / drone.
    Uav,
    /// USV / vessel.
    Usv,
    /// Industrial robot / AGV / AMR.
    IndustrialRobot,
}

impl VehicleClass {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroundPassenger => "ground_passenger",
            Self::GroundCargo => "ground_cargo",
            Self::Uav => "uav",
            Self::Usv => "usv",
            Self::IndustrialRobot => "industrial_robot",
        }
    }
}

/// Weather condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WeatherCondition {
    /// Clear.
    Clear,
    /// Rain.
    Rain,
    /// Sand storm.
    SandStorm,
    /// Fog.
    Fog,
    /// Snow.
    Snow,
    /// Other.
    Other,
}

impl WeatherCondition {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear", Self::Rain => "rain", Self::SandStorm => "sand_storm",
            Self::Fog => "fog", Self::Snow => "snow", Self::Other => "other",
        }
    }
}

/// ODD profile (Operational Design Domain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OddProfile {
    /// Geofence id.
    pub geofence_id: String,
    /// Time window start (RFC 3339).
    pub time_window_start: String,
    /// Time window end (RFC 3339).
    pub time_window_end: String,
    /// Allowed weather conditions.
    pub allowed_weather: Vec<WeatherCondition>,
    /// Maximum speed (m/s, k_m/h, etc — tenant-defined).
    pub max_speed: f64,
    /// Mission type.
    pub mission_type: String,
}

impl OddProfile {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            geofence_id: "kezad-zone-7".into(),
            time_window_start: "2026-12-15T06:00:00Z".into(),
            time_window_end: "2026-12-15T18:00:00Z".into(),
            allowed_weather: vec![WeatherCondition::Clear, WeatherCondition::Rain],
            max_speed: 14.0,
            mission_type: "logistics_delivery".into(),
        }
    }
}

/// ODD validation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OddValidation {
    /// Vehicle id.
    pub vehicle_id: String,
    /// Vehicle class.
    pub vehicle_class: VehicleClass,
    /// ODD profile under evaluation.
    pub profile: OddProfile,
    /// `true` if vehicle is within ODD at this moment.
    pub within_odd: bool,
    /// Current weather.
    pub current_weather: WeatherCondition,
    /// Current speed.
    pub current_speed: f64,
    /// AI ODD-validation model id.
    pub model_id: String,
    /// Model hash hex.
    pub model_hash_hex: String,
    /// Operator role.
    pub operator_role: String,
    /// Operator pseudo id.
    pub operator_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl OddValidation {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            vehicle_id: "veh-2026-12-001".into(),
            vehicle_class: VehicleClass::IndustrialRobot,
            profile: OddProfile::demo(),
            within_odd: true,
            current_weather: WeatherCondition::Clear,
            current_speed: 8.5,
            model_id: "odd_validator_v2".into(),
            model_hash_hex: Hasher::sha256(b"demo-odd-weights").to_hex(),
            operator_role: "safety_pilot".into(),
            operator_pseudo_id: "role:safety_pilot#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed ODD validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OddValidationSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// `true` if within ODD (mirrored).
    pub within_odd: bool,
}

impl OddValidationSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_odd_seal(input: &OddValidation, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::hash_value(&input.profile)?;
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[input.within_odd as u8]);
        bytes.extend_from_slice(input.current_weather.as_str().as_bytes());
        bytes.extend_from_slice(input.current_speed.to_le_bytes().as_slice());
        Hasher::sha256(&bytes)
    };
    let event_hash = Hasher::sha256(format!("{}:odd:{}", input.vehicle_id, input.profile.geofence_id).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("odd_validation"));
    sector_extension.insert("vehicle_id".into(), serde_json::json!(input.vehicle_id));
    sector_extension.insert("vehicle_class".into(), serde_json::json!(input.vehicle_class.as_str()));
    sector_extension.insert("within_odd".into(), serde_json::json!(input.within_odd));
    sector_extension.insert("current_weather".into(), serde_json::json!(input.current_weather.as_str()));
    sector_extension.insert("current_speed".into(), serde_json::json!(input.current_speed));
    sector_extension.insert("geofence_id".into(), serde_json::json!(input.profile.geofence_id));
    let approval = ApprovalRecord {
        approver_ref: input.operator_pseudo_id.clone(), role: input.operator_role.clone(),
        decision: if input.within_odd { "within_odd" } else { "out_of_domain" }.into(),
        reason_class: Some(input.profile.mission_type.clone()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AutonomousMobility,
        event_type: format!("odd_validation.{}", if input.within_odd { "within_odd" } else { "out_of_domain" }),
        event_hash, model, policy_id: "po_odd_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "odd_validation".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Mission step (one node on the mission timeline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionStep {
    /// Mission id.
    pub mission_id: String,
    /// Step index.
    pub step_index: u32,
    /// Vehicle id.
    pub vehicle_id: String,
    /// Sensor input hash hex.
    pub sensor_input_hash_hex: String,
    /// AI decision identifier (e.g., "route_continue", "emergency_brake").
    pub ai_decision: String,
    /// Operator action identifier (`"none"` if pure-AI).
    pub operator_action: String,
    /// AI model id.
    pub model_id: String,
    /// Model hash hex.
    pub model_hash_hex: String,
    /// Operator role.
    pub operator_role: String,
    /// Operator pseudo id.
    pub operator_pseudo_id: String,
    /// Optional prior seal hash hex (chains mission steps).
    pub prior_seal_hash_hex: Option<String>,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl MissionStep {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            mission_id: "mission-2026-12-001".into(),
            step_index: 7,
            vehicle_id: "veh-2026-12-001".into(),
            sensor_input_hash_hex: Hasher::sha256(b"sensor frame snapshot").to_hex(),
            ai_decision: "route_continue".into(),
            operator_action: "none".into(),
            model_id: "autonomy_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-autonomy-weights").to_hex(),
            operator_role: "safety_pilot".into(),
            operator_pseudo_id: "role:safety_pilot#a01".into(),
            prior_seal_hash_hex: None,
            jurisdiction_tag: None,
        }
    }
}

/// Sealed mission step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionStepSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// AI decision.
    pub ai_decision: String,
}

impl MissionStepSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_mission_step_seal(input: &MissionStep, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let sensor_hash = Sha256Digest::from_hex(&input.sensor_input_hash_hex).ok_or_else(|| SandboxError::invalid("sensor_input_hash_hex"))?;
    let prior_seal_hash = match &input.prior_seal_hash_hex {
        Some(h) => Some(Sha256Digest::from_hex(h).ok_or_else(|| SandboxError::invalid("prior_seal_hash_hex"))?),
        None => None,
    };
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = sensor_hash;
    let output_hash = Hasher::sha256(format!("{}:{}", input.ai_decision, input.operator_action).as_bytes());
    let event_hash = Hasher::sha256(format!("{}:step:{}", input.mission_id, input.step_index).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("mission_step"));
    sector_extension.insert("mission_id".into(), serde_json::json!(input.mission_id));
    sector_extension.insert("step_index".into(), serde_json::json!(input.step_index));
    sector_extension.insert("vehicle_id".into(), serde_json::json!(input.vehicle_id));
    sector_extension.insert("ai_decision".into(), serde_json::json!(input.ai_decision));
    sector_extension.insert("operator_action".into(), serde_json::json!(input.operator_action));
    let approval = ApprovalRecord {
        approver_ref: input.operator_pseudo_id.clone(), role: input.operator_role.clone(),
        decision: input.ai_decision.clone(),
        reason_class: Some(input.operator_action.clone()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AutonomousMobility,
        event_type: format!("mission_step.{}", input.ai_decision),
        event_hash, model, policy_id: "po_mission_step_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "mission_step".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears, prior_seal_hash, sector_extension,
        validator_signature_hex: None,
    })
}

/// Perception event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionEvent {
    /// Vehicle id.
    pub vehicle_id: String,
    /// Detection class (e.g., `"pedestrian"`, `"vehicle"`, `"obstacle"`).
    pub detection_class: String,
    /// Confidence (0.0–1.0).
    pub confidence: f64,
    /// Threshold used (0.0–1.0).
    pub threshold: f64,
    /// Hash of the sensor frame.
    pub frame_hash_hex: String,
    /// Perception model id.
    pub model_id: String,
    /// Model hash hex.
    pub model_hash_hex: String,
    /// Reviewer role (e.g., `"safety_pilot"`, `"perception_qa"`).
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl PerceptionEvent {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            vehicle_id: "veh-2026-12-001".into(),
            detection_class: "pedestrian".into(),
            confidence: 0.91,
            threshold: 0.6,
            frame_hash_hex: Hasher::sha256(b"frame-data").to_hex(),
            model_id: "perception_v4".into(),
            model_hash_hex: Hasher::sha256(b"demo-perception-weights").to_hex(),
            reviewer_role: "perception_qa".into(),
            reviewer_pseudo_id: "role:perception_qa#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed perception event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionEventSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Detection class.
    pub detection_class: String,
}

impl PerceptionEventSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_perception_seal(input: &PerceptionEvent, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let frame_hash = Sha256Digest::from_hex(&input.frame_hash_hex).ok_or_else(|| SandboxError::invalid("frame_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = frame_hash;
    let output_hash = Hasher::sha256(format!("{}:{}", input.detection_class, input.confidence).as_bytes());
    let event_hash = Hasher::sha256(format!("{}:percept:{}", input.vehicle_id, input.detection_class).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("perception_event"));
    sector_extension.insert("vehicle_id".into(), serde_json::json!(input.vehicle_id));
    sector_extension.insert("detection_class".into(), serde_json::json!(input.detection_class));
    sector_extension.insert("confidence".into(), serde_json::json!(input.confidence));
    sector_extension.insert("threshold".into(), serde_json::json!(input.threshold));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(), role: input.reviewer_role.clone(),
        decision: input.detection_class.clone(),
        reason_class: None,
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AutonomousMobility,
        event_type: format!("perception_event.{}", input.detection_class),
        event_hash, model, policy_id: "po_perception_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "perception_event".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Safety category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCategory {
    /// Hazard (potential).
    Hazard,
    /// Near-miss.
    NearMiss,
    /// Incident (actual harm or damage).
    Incident,
    /// Safe stop (system halted intentionally).
    SafeStop,
}

impl SafetyCategory {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self { Self::Hazard => "hazard", Self::NearMiss => "near_miss", Self::Incident => "incident", Self::SafeStop => "safe_stop" }
    }
}

/// Safety event outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyOutcome {
    /// Resolved without escalation.
    Resolved,
    /// Escalated to safety officer.
    Escalated,
    /// Mission aborted.
    MissionAborted,
}

impl SafetyOutcome {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self { Self::Resolved => "resolved", Self::Escalated => "escalated", Self::MissionAborted => "mission_aborted" }
    }
}

/// Safety case event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCaseEvent {
    /// Mission id.
    pub mission_id: String,
    /// Vehicle id.
    pub vehicle_id: String,
    /// Category.
    pub category: SafetyCategory,
    /// Outcome.
    pub outcome: SafetyOutcome,
    /// Hash of the incident timeline.
    pub timeline_hash_hex: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// AI decision-support model id (`"none"` if not used).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl SafetyCaseEvent {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            mission_id: "mission-2026-12-001".into(),
            vehicle_id: "veh-2026-12-001".into(),
            category: SafetyCategory::SafeStop,
            outcome: SafetyOutcome::Resolved,
            timeline_hash_hex: Hasher::sha256(b"timeline-data").to_hex(),
            reviewer_role: "safety_officer".into(),
            reviewer_pseudo_id: "role:safety_officer#a01".into(),
            model_id: "safety_advisor_v1".into(),
            model_hash_hex: Hasher::sha256(b"demo-safety-weights").to_hex(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed safety event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCaseEventSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Outcome.
    pub outcome: SafetyOutcome,
}

impl SafetyCaseEventSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_safety_seal(input: &SafetyCaseEvent, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let timeline_hash = Sha256Digest::from_hex(&input.timeline_hash_hex).ok_or_else(|| SandboxError::invalid("timeline_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = timeline_hash;
    let output_hash = Hasher::sha256(format!("{}:{}", input.category.as_str(), input.outcome.as_str()).as_bytes());
    let event_hash = Hasher::sha256(format!("{}:safety:{}", input.mission_id, input.category.as_str()).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("safety_case_event"));
    sector_extension.insert("mission_id".into(), serde_json::json!(input.mission_id));
    sector_extension.insert("vehicle_id".into(), serde_json::json!(input.vehicle_id));
    sector_extension.insert("category".into(), serde_json::json!(input.category.as_str()));
    sector_extension.insert("outcome".into(), serde_json::json!(input.outcome.as_str()));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(), role: input.reviewer_role.clone(),
        decision: input.outcome.as_str().to_string(),
        reason_class: Some(input.category.as_str().into()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::AutonomousMobility,
        event_type: format!("safety_case_event.{}", input.category.as_str()),
        event_hash, model, policy_id: "po_safety_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "safety_case_event".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// AutonomousMobilitySandbox
// =============================================================================

/// Plug-and-play entry point.
pub struct AutonomousMobilitySandbox {
    inner: Sandbox,
    primary_jurisdiction: AmJurisdiction,
}

impl AutonomousMobilitySandbox {
    /// Quickstart.
    pub fn quickstart(tenant: impl Into<String>) -> SandboxResult<Self> {
        Self::builder().tenant(tenant).jurisdiction(AmJurisdiction::Iso21448Sotif).build()
    }
    /// Builder.
    pub fn builder() -> AutonomousMobilitySandboxBuilder { AutonomousMobilitySandboxBuilder::default() }
    /// Underlying core sandbox.
    pub fn core(&self) -> &Sandbox { &self.inner }
    /// Tenant.
    pub fn tenant(&self) -> &str { &self.inner.config().tenant_id }
    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> AmJurisdiction { self.primary_jurisdiction }
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> { self.inner.append_seal(seal) }
    /// Export.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.evidence().export(self.tenant().to_string(), Sector::AutonomousMobility)
    }
    /// Project regulator view.
    pub fn regulator_view(&self, seal: &DigitalSeal, jurisdiction: AmJurisdiction) -> RegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal.approvals.first().map(|a| a.decision.clone()).unwrap_or_else(|| "unknown".into());
        RegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    fn common_faults(&self, seal: &DigitalSeal) -> HashMap<String, bool> {
        let mut faults = HashMap::new();
        if seal.model.model_hash.0 == [0u8; 32] { faults.insert(GATE_MODEL_APPROVAL.into(), true); }
        if seal.approvals.is_empty() { faults.insert(GATE_HUMAN_ESCALATION.into(), true); }
        if !is_supported_juris(&seal.jurisdiction_tag) { faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true); }
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_TIMELINE_INTEGRITY.into(), true);
        }
        faults
    }

    /// Seal an ODD validation.
    pub fn seal_odd_validation(&self, input: OddValidation) -> SandboxResult<OddValidationSeal> {
        let seal = build_odd_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let mut faults = self.common_faults(&seal);
        if !input.within_odd { faults.insert(GATE_ODD_BOUNDARY.into(), true); }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("ODD validation for {} blocked", input.vehicle_id)));
        }
        self.append(seal.clone())?;
        Ok(OddValidationSeal { seal, within_odd: input.within_odd })
    }

    /// Seal a mission step.
    pub fn seal_mission_step(&self, input: MissionStep) -> SandboxResult<MissionStepSeal> {
        let seal = build_mission_step_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("mission step {} blocked", input.step_index)));
        }
        let ai_decision = input.ai_decision.clone();
        self.append(seal.clone())?;
        Ok(MissionStepSeal { seal, ai_decision })
    }

    /// Seal a perception event.
    pub fn seal_perception_event(&self, input: PerceptionEvent) -> SandboxResult<PerceptionEventSeal> {
        let seal = build_perception_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("perception event for {} blocked", input.vehicle_id)));
        }
        self.append(seal.clone())?;
        Ok(PerceptionEventSeal { seal, detection_class: input.detection_class })
    }

    /// Seal a safety-case event.
    pub fn seal_safety_case_event(&self, input: SafetyCaseEvent) -> SandboxResult<SafetyCaseEventSeal> {
        let seal = build_safety_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("safety case event for {} blocked", input.mission_id)));
        }
        self.append(seal.clone())?;
        Ok(SafetyCaseEventSeal { seal, outcome: input.outcome })
    }

    // =================================================================
    // Enterprise convenience: bulk + envelope + verify + audit.
    // =================================================================

    /// Bulk seal ODD validations.
    pub fn seal_odd_validations(&self, items: impl IntoIterator<Item = OddValidation>) -> SandboxResult<Vec<OddValidationSeal>> {
        items.into_iter().map(|i| self.seal_odd_validation(i)).collect()
    }
    /// Bulk seal mission steps.
    pub fn seal_mission_steps(&self, items: impl IntoIterator<Item = MissionStep>) -> SandboxResult<Vec<MissionStepSeal>> {
        items.into_iter().map(|i| self.seal_mission_step(i)).collect()
    }
    /// Bulk seal perception events.
    pub fn seal_perception_events(&self, items: impl IntoIterator<Item = PerceptionEvent>) -> SandboxResult<Vec<PerceptionEventSeal>> {
        items.into_iter().map(|i| self.seal_perception_event(i)).collect()
    }
    /// Bulk seal safety-case events.
    pub fn seal_safety_case_events(&self, items: impl IntoIterator<Item = SafetyCaseEvent>) -> SandboxResult<Vec<SafetyCaseEventSeal>> {
        items.into_iter().map(|i| self.seal_safety_case_event(i)).collect()
    }

    /// Envelope at index.
    pub fn envelope_at(&self, index: u64) -> SandboxResult<aethelred_sandbox_core::SealEnvelope> {
        let bundle = self.export_evidence()?;
        let entry = bundle.entries.iter().find(|e| e.index == index).cloned()
            .ok_or_else(|| SandboxError::Evidence(format!("envelope at {index} not found")))?;
        let proof = self.inner.evidence().proof(index)?;
        Ok(aethelred_sandbox_core::SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        })
    }
    /// All envelopes.
    pub fn all_envelopes(&self) -> SandboxResult<Vec<aethelred_sandbox_core::SealEnvelope>> {
        let bundle = self.export_evidence()?;
        let mut out = Vec::with_capacity(bundle.entries.len());
        for entry in bundle.entries {
            let proof = self.inner.evidence().proof(entry.index)?;
            out.push(aethelred_sandbox_core::SealEnvelope {
                seal: entry.seal,
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        Ok(out)
    }
    /// Current root.
    pub fn current_root(&self) -> SandboxResult<aethelred_sandbox_core::Sha256Digest> {
        self.inner.current_root()
    }
    /// Seal count.
    pub fn seal_count(&self) -> usize { self.inner.seal_count() }
    /// Audit trail.
    pub fn audit_trail(&self, format: aethelred_sandbox_core::audit::AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }
    /// Structured audit trail.
    pub fn audit_trail_struct(&self) -> SandboxResult<aethelred_sandbox_core::audit::AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(aethelred_sandbox_core::audit::AuditTrail::from_bundle(&bundle))
    }
    /// Verify all seals.
    pub fn verify_all(&self) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        aethelred_sandbox_core::verify::Verifier::default().verify_batch(&envs, root)
    }
    /// Verify with custom Verifier.
    pub fn verify_all_with(&self, v: &aethelred_sandbox_core::verify::Verifier) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        v.verify_batch(&envs, root)
    }
}

/// Builder.
#[derive(Default)]
pub struct AutonomousMobilitySandboxBuilder {
    tenant: Option<String>,
    primary_jurisdiction: Option<AmJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    label: Option<String>,
}

impl AutonomousMobilitySandboxBuilder {
    /// Tenant.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self { self.tenant = Some(tenant.into()); self }
    /// Jurisdiction.
    pub fn jurisdiction(mut self, j: AmJurisdiction) -> Self { self.primary_jurisdiction = Some(j); self }
    /// Extra gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self { self.extra_gates.push(gate); self }
    /// Label.
    pub fn label(mut self, label: impl Into<String>) -> Self { self.label = Some(label.into()); self }
    /// Build.
    pub fn build(self) -> SandboxResult<AutonomousMobilitySandbox> {
        let tenant = self.tenant.ok_or_else(|| SandboxError::config("tenant not set"))?;
        let primary = self.primary_jurisdiction.unwrap_or(AmJurisdiction::Iso21448Sotif);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self.label.unwrap_or_else(|| format!("{tenant} Autonomous Mobility Sandbox"));
        let inner = SandboxBuilder::new(Sector::AutonomousMobility)
            .crate_name("aethelred-sandbox-autonomous-mobility")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&tenant).label(&label).jurisdiction(primary.seal_tag())
            .workflow("odd_validation").workflow("mission_step")
            .workflow("perception_event").workflow("safety_case_event")
            .with_gates(all_gates).build()?;
        Ok(AutonomousMobilitySandbox { inner, primary_jurisdiction: primary })
    }
}

fn is_supported_juris(tag: &str) -> bool {
    matches!(tag, "ISO-21448-SOTIF" | "ISO-26262" | "DO-178C" | "DO-326A" | "DO-356A" | "EU-UNECE-WP29" | "AE-NCEMA-RTA")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        assert_eq!(sb.tenant(), "TII");
    }
    #[test]
    fn odd_seal_happy_path() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        let s = sb.seal_odd_validation(OddValidation::demo()).unwrap();
        assert!(s.within_odd);
    }
    #[test]
    fn mission_step_seal_happy_path() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        let s = sb.seal_mission_step(MissionStep::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }
    #[test]
    fn perception_event_seal_happy_path() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        let s = sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
        assert_eq!(s.detection_class, "pedestrian");
    }
    #[test]
    fn safety_case_seal_happy_path() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        let s = sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
        assert_eq!(s.outcome, SafetyOutcome::Resolved);
    }
    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = AutonomousMobilitySandbox::quickstart("TII").unwrap();
        sb.seal_odd_validation(OddValidation::demo()).unwrap();
        sb.seal_mission_step(MissionStep::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.sector, Sector::AutonomousMobility);
    }
}
