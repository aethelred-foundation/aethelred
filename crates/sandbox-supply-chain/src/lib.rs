//! # Aethelred Infinity Sandbox — Supply Chain Integrity
//!
//! Production-grade verification & evidence layer for industrial supply
//! chain: batch traceability (GS1 EPCIS 2.0), customs filing (Maqta + WCO
//! SAFE), carbon lifecycle (EU CBAM / US IRA 45V / GHG Protocol Scope 1-3),
//! and methane / flaring events (EU Methane Regulation 2024/1787, OGMP 2.0).
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_supply_chain::prelude::*;
//!
//! let sandbox = SupplyChainSandbox::quickstart("KEZAD").unwrap();
//! let seal = sandbox.seal_batch_event(BatchEvent::demo()).unwrap();
//! ```

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::result_large_err)]

use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, EvidenceBundle, EvidenceLogEntry, Hasher, ModelReference,
    RetentionClass, Sandbox, SandboxBuilder, SandboxError, SandboxResult, Sector, SealVersion,
    Sha256Digest,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

pub use aethelred_sandbox_core as core;

/// Prelude.
pub mod prelude {
    pub use super::{
        BatchEvent, BatchEventSeal, CarbonClaim, CarbonClaimSeal, CarbonStandard, CustomsFiling,
        CustomsFilingSeal, MethaneEvent, MethaneEventSeal, OgmpLevel, SupplyChainJurisdiction,
        SupplyChainSandbox, SupplyChainSandboxBuilder, EpcisEventType, RegulatorView,
    };
    pub use aethelred_sandbox_core::{
        DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
        SandboxResult, Sector, Sha256Digest,
    };
}

// =============================================================================
// Policy gates
// =============================================================================

/// Tenant data must remain off-chain.
pub const GATE_NO_TENANT_DATA: &str = "supply_chain.no_tenant_data";
/// Approved methodology / model.
pub const GATE_METHODOLOGY_APPROVED: &str = "supply_chain.methodology_approved";
/// Approver / reviewer present.
pub const GATE_REVIEWER_BIND: &str = "supply_chain.reviewer_bind";
/// Carbon claim within tolerance threshold.
pub const GATE_CARBON_TOLERANCE: &str = "supply_chain.carbon_tolerance";
/// EPCIS event well-formed (well-defined event-type / biz-step).
pub const GATE_EPCIS_WELL_FORMED: &str = "supply_chain.epcis_well_formed";
/// Jurisdiction supported.
pub const GATE_JURISDICTION_SUPPORTED: &str = "supply_chain.jurisdiction_supported";
/// Evidence integrity.
pub const GATE_EVIDENCE_INTEGRITY: &str = "supply_chain.evidence_integrity";

fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(GATE_NO_TENANT_DATA, "No tenant data on chain", "Tenant operational / commercial data must remain off-chain."),
        PolicyGate::required(GATE_METHODOLOGY_APPROVED, "Methodology approved", "Carbon / customs / methane methodology must be on the approved registry."),
        PolicyGate::required(GATE_REVIEWER_BIND, "Reviewer bind", "Reviewer / approver signature must be present."),
        PolicyGate::required(GATE_EVIDENCE_INTEGRITY, "Evidence integrity", "Tampered batch / customs / methane records fail closed."),
        PolicyGate::required(GATE_JURISDICTION_SUPPORTED, "Jurisdiction supported", "Workflow jurisdiction must match a configured regulator view."),
        PolicyGate::optional(GATE_CARBON_TOLERANCE, "Carbon tolerance", "Soft-fail when carbon claim is outside configured tolerance."),
        PolicyGate::optional(GATE_EPCIS_WELL_FORMED, "EPCIS well-formed", "Soft-fail when EPCIS event is missing biz-step / disposition / read-point."),
    ]
}

// =============================================================================
// Regulators
// =============================================================================

/// Supply-chain regulator jurisdiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplyChainJurisdiction {
    /// EU Carbon Border Adjustment Mechanism (Reg (EU) 2023/956).
    EuCbam,
    /// EU Methane Regulation (Reg (EU) 2024/1787).
    EuMethane,
    /// US IRA Section 45V (clean hydrogen production credit).
    Us45v,
    /// US IRA Section 45Q (carbon oxide sequestration credit).
    Us45q,
    /// EU CSRD / ISSB IFRS S1/S2.
    EuCsrdIssb,
    /// UAE EAD / MoCCAE / Customs.
    UaeEadCustoms,
    /// WCO SAFE Framework (cross-border customs).
    WcoSafe,
}

impl SupplyChainJurisdiction {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EuCbam => "eu_cbam",
            Self::EuMethane => "eu_methane",
            Self::Us45v => "us_45v",
            Self::Us45q => "us_45q",
            Self::EuCsrdIssb => "eu_csrd_issb",
            Self::UaeEadCustoms => "uae_ead_customs",
            Self::WcoSafe => "wco_safe",
        }
    }
    /// Seal jurisdiction tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::EuCbam => "EU-CBAM",
            Self::EuMethane => "EU-METHANE",
            Self::Us45v => "US-IRA-45V",
            Self::Us45q => "US-IRA-45Q",
            Self::EuCsrdIssb => "EU-CSRD-ISSB",
            Self::UaeEadCustoms => "AE-EAD-CUSTOMS",
            Self::WcoSafe => "WCO-SAFE",
        }
    }
    /// Citations.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::EuCbam => vec![RegulatorCitation::eu_cbam_2023_956()],
            Self::EuMethane => vec![RegulatorCitation::eu_methane_2024_1787()],
            Self::Us45v => vec![RegulatorCitation::us_45v()],
            Self::Us45q => vec![RegulatorCitation::us_45q()],
            Self::EuCsrdIssb => vec![
                RegulatorCitation::eu_csrd_2022_2464(),
                RegulatorCitation::issb_s1_s2(),
            ],
            Self::UaeEadCustoms => vec![RegulatorCitation::uae_ead_customs()],
            Self::WcoSafe => vec![RegulatorCitation::wco_safe()],
        }
    }
}

/// Regulator citation.
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
    /// EU CBAM Regulation (EU) 2023/956 Article 7.
    pub fn eu_cbam_2023_956() -> Self {
        Self { regulator: "EU".into(), citation_id: "Regulation (EU) 2023/956".into(), section: "Article 7".into(), summary: "Quarterly CBAM declarations with embedded emissions for in-scope goods.".into() }
    }
    /// EU Methane Regulation (Reg (EU) 2024/1787).
    pub fn eu_methane_2024_1787() -> Self {
        Self { regulator: "EU".into(), citation_id: "Regulation (EU) 2024/1787".into(), section: "Articles 12, 14, 17, 18".into(), summary: "Methane quantification, leak detection and repair, OGMP-2.0-aligned reporting at L4–L5.".into() }
    }
    /// US IRA §45V.
    pub fn us_45v() -> Self {
        Self { regulator: "US Treasury".into(), citation_id: "IRC §45V".into(), section: "Treasury final rule (Jan 2025)".into(), summary: "Lifecycle GHG ≤4 kg CO2e/kg H2; well-to-gate; hourly matching by 2030.".into() }
    }
    /// US IRA §45Q.
    pub fn us_45q() -> Self {
        Self { regulator: "US Treasury".into(), citation_id: "IRC §45Q + 26 CFR 1.45Q".into(), section: "Carbon oxide sequestration".into(), summary: "Verification of qualified carbon oxide sequestration.".into() }
    }
    /// EU CSRD Regulation 2022/2464.
    pub fn eu_csrd_2022_2464() -> Self {
        Self { regulator: "EU".into(), citation_id: "Directive (EU) 2022/2464".into(), section: "CSRD".into(), summary: "Corporate sustainability reporting; integrated with ESRS standards.".into() }
    }
    /// ISSB IFRS S1/S2.
    pub fn issb_s1_s2() -> Self {
        Self { regulator: "IFRS Foundation (ISSB)".into(), citation_id: "IFRS S1 / IFRS S2".into(), section: "General + climate disclosure".into(), summary: "Investor-grade sustainability + climate disclosure.".into() }
    }
    /// UAE EAD + Customs.
    pub fn uae_ead_customs() -> Self {
        Self { regulator: "EAD + Federal Customs Authority (UAE)".into(), citation_id: "UAE Environmental Standards + Customs Code".into(), section: "Emissions + Customs".into(), summary: "UAE environmental + customs reporting obligations.".into() }
    }
    /// WCO SAFE Framework.
    pub fn wco_safe() -> Self {
        Self { regulator: "World Customs Organization".into(), citation_id: "SAFE Framework of Standards".into(), section: "Cross-border supply-chain security".into(), summary: "Cross-border trade security + facilitation framework.".into() }
    }
}

/// A regulator-shape view of a supply-chain seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorView {
    /// Jurisdiction.
    pub jurisdiction: SupplyChainJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id.
    pub seal_id: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Event class.
    pub event_class: String,
    /// Decision (or event sub-type).
    pub decision: String,
    /// Tenant id.
    pub tenant_id: String,
}

impl RegulatorView {
    /// Project a seal.
    pub fn project(seal: &DigitalSeal, jurisdiction: SupplyChainJurisdiction, decision: impl Into<String>, event_class: impl Into<String>) -> Self {
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

// =============================================================================
// Workflow 1: Batch event (GS1 EPCIS 2.0)
// =============================================================================

/// EPCIS 2.0 event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpcisEventType {
    /// ObjectEvent.
    Object,
    /// AggregationEvent.
    Aggregation,
    /// TransformationEvent.
    Transformation,
    /// AssociationEvent (EPCIS 2.0).
    Association,
}

impl EpcisEventType {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object_event",
            Self::Aggregation => "aggregation_event",
            Self::Transformation => "transformation_event",
            Self::Association => "association_event",
        }
    }
}

/// Batch / asset traceability event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEvent {
    /// Batch / lot id.
    pub batch_id: String,
    /// EPCIS event type.
    pub epcis_event_type: EpcisEventType,
    /// Business step (e.g., `"urn:epcglobal:cbv:bizstep:shipping"`).
    pub biz_step: String,
    /// Disposition (e.g., `"urn:epcglobal:cbv:disp:in_transit"`).
    pub disposition: String,
    /// Read point (location).
    pub read_point: String,
    /// Quantity.
    pub quantity: Decimal,
    /// Unit (e.g., `"kg"`, `"each"`).
    pub unit: String,
    /// AI model id (where AI is involved — e.g., `"defect_detection_v3"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl BatchEvent {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            batch_id: "lot-2026-12-882".into(),
            epcis_event_type: EpcisEventType::Object,
            biz_step: "urn:epcglobal:cbv:bizstep:shipping".into(),
            disposition: "urn:epcglobal:cbv:disp:in_transit".into(),
            read_point: "urn:gs1:locations:kezad-warehouse-7".into(),
            quantity: Decimal::new(1_000, 0),
            unit: "kg".into(),
            model_id: "defect_detection_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-defect-weights").to_hex(),
            reviewer_role: "qa_inspector".into(),
            reviewer_pseudo_id: "role:qa_inspector#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed batch event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchEventSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// EPCIS event type.
    pub epcis_event_type: EpcisEventType,
}

impl BatchEventSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String { self.seal.id_string() }
}

fn build_batch_seal(input: &BatchEvent, tenant_id: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.batch_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.epcis_event_type.as_str().as_bytes());
        bytes.extend_from_slice(input.biz_step.as_bytes());
        bytes.extend_from_slice(input.disposition.as_bytes());
        bytes.extend_from_slice(input.read_point.as_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.batch_id.as_bytes());
        bytes.extend_from_slice(input.epcis_event_type.as_str().as_bytes());
        Hasher::sha256(&bytes)
    };
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("batch_event"));
    sector_extension.insert("epcis_event_type".into(), serde_json::json!(input.epcis_event_type.as_str()));
    sector_extension.insert("biz_step".into(), serde_json::json!(input.biz_step));
    sector_extension.insert("disposition".into(), serde_json::json!(input.disposition));
    sector_extension.insert("read_point".into(), serde_json::json!(input.read_point));
    sector_extension.insert("quantity".into(), serde_json::json!(input.quantity.to_string()));
    sector_extension.insert("unit".into(), serde_json::json!(input.unit));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.epcis_event_type.as_str().to_string(),
        reason_class: Some(input.biz_step.clone()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::SupplyChain,
        event_type: format!("batch_event.{}", input.epcis_event_type.as_str()),
        event_hash, model,
        policy_id: "po_batch_event_v1".to_string(),
        input_hash, output_hash,
        approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "batch_event".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// Workflow 2: Customs filing (Maqta + WCO SAFE)
// =============================================================================

/// Customs decision class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomsDecision {
    /// Cleared.
    Cleared,
    /// Held for inspection.
    HeldForInspection,
    /// Rejected.
    Rejected,
    /// Pending information.
    PendingInfo,
}

impl CustomsDecision {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cleared => "cleared",
            Self::HeldForInspection => "held_for_inspection",
            Self::Rejected => "rejected",
            Self::PendingInfo => "pending_info",
        }
    }
}

/// Customs filing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomsFiling {
    /// Filing id.
    pub filing_id: String,
    /// HS code (tariff classification).
    pub hs_code: String,
    /// Origin country (ISO 3166-1 alpha-2).
    pub origin_country: String,
    /// Destination country.
    pub destination_country: String,
    /// AI-assisted classification model id.
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Decision.
    pub decision: CustomsDecision,
    /// Reviewer role (`"customs_broker"`, `"compliance_officer"`).
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl CustomsFiling {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            filing_id: "filing-2026-12-771".into(),
            hs_code: "7202.41".into(),
            origin_country: "AE".into(),
            destination_country: "DE".into(),
            model_id: "tariff_classifier_v1".into(),
            model_hash_hex: Hasher::sha256(b"demo-tariff-weights").to_hex(),
            decision: CustomsDecision::Cleared,
            reviewer_role: "compliance_officer".into(),
            reviewer_pseudo_id: "role:compliance_officer#001".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed customs filing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomsFilingSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Decision (mirrored).
    pub decision: CustomsDecision,
}

impl CustomsFilingSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String { self.seal.id_string() }
}

fn build_customs_seal(input: &CustomsFiling, tenant_id: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.filing_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.decision.as_str().as_bytes());
        bytes.extend_from_slice(input.hs_code.as_bytes());
        bytes.extend_from_slice(input.origin_country.as_bytes());
        bytes.extend_from_slice(input.destination_country.as_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = Hasher::sha256(format!("{}:{}", input.filing_id, input.hs_code).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("customs_filing"));
    sector_extension.insert("hs_code".into(), serde_json::json!(input.hs_code));
    sector_extension.insert("origin_country".into(), serde_json::json!(input.origin_country));
    sector_extension.insert("destination_country".into(), serde_json::json!(input.destination_country));
    sector_extension.insert("decision".into(), serde_json::json!(input.decision.as_str()));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.decision.as_str().to_string(),
        reason_class: None,
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::SupplyChain,
        event_type: format!("customs_filing.{}", input.decision.as_str()),
        event_hash, model,
        policy_id: "po_customs_v1".to_string(),
        input_hash, output_hash,
        approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "customs_filing".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// Workflow 3: Carbon claim (CBAM / 45V / GHG Protocol)
// =============================================================================

/// Carbon-accounting standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarbonStandard {
    /// EU CBAM.
    EuCbam,
    /// US IRA §45V (clean hydrogen).
    Us45v,
    /// US IRA §45Q (carbon sequestration).
    Us45q,
    /// GHG Protocol Scope 1.
    GhgProtocolScope1,
    /// GHG Protocol Scope 2.
    GhgProtocolScope2,
    /// GHG Protocol Scope 3.
    GhgProtocolScope3,
    /// ISO 14064-1.
    Iso14064_1,
    /// ISO 14067.
    Iso14067,
}

impl CarbonStandard {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EuCbam => "eu_cbam",
            Self::Us45v => "us_45v",
            Self::Us45q => "us_45q",
            Self::GhgProtocolScope1 => "ghg_protocol_scope_1",
            Self::GhgProtocolScope2 => "ghg_protocol_scope_2",
            Self::GhgProtocolScope3 => "ghg_protocol_scope_3",
            Self::Iso14064_1 => "iso_14064_1",
            Self::Iso14067 => "iso_14067",
        }
    }
}

/// Carbon claim input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarbonClaim {
    /// Claim id.
    pub claim_id: String,
    /// Reporting period end (RFC 3339).
    pub period_end: String,
    /// Standard used.
    pub standard: CarbonStandard,
    /// Embedded emissions (kg CO2e).
    pub emissions_kg_co2e: Decimal,
    /// Methodology id.
    pub methodology_id: String,
    /// AI model id used in calculation.
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl CarbonClaim {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            claim_id: "claim-2026-q4-001".into(),
            period_end: "2026-12-31T23:59:59Z".into(),
            standard: CarbonStandard::EuCbam,
            emissions_kg_co2e: Decimal::new(123_456, 2), // 1234.56 kg CO2e
            methodology_id: "methodology:cbam_steel_v3".into(),
            model_id: "carbon_calc_v4".into(),
            model_hash_hex: Hasher::sha256(b"demo-carbon-weights").to_hex(),
            reviewer_role: "esg_lead".into(),
            reviewer_pseudo_id: "role:esg_lead#a13".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed carbon claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarbonClaimSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Standard (mirrored).
    pub standard: CarbonStandard,
}

impl CarbonClaimSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String { self.seal.id_string() }
}

fn build_carbon_seal(input: &CarbonClaim, tenant_id: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.claim_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.standard.as_str().as_bytes());
        bytes.extend_from_slice(input.emissions_kg_co2e.to_string().as_bytes());
        bytes.extend_from_slice(input.methodology_id.as_bytes());
        Hasher::sha256(&bytes)
    };
    let event_hash = Hasher::sha256(format!("{}:{}:{}", input.claim_id, input.standard.as_str(), input.period_end).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("carbon_claim"));
    sector_extension.insert("standard".into(), serde_json::json!(input.standard.as_str()));
    sector_extension.insert("emissions_kg_co2e".into(), serde_json::json!(input.emissions_kg_co2e.to_string()));
    sector_extension.insert("methodology_id".into(), serde_json::json!(input.methodology_id));
    sector_extension.insert("period_end".into(), serde_json::json!(input.period_end));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.standard.as_str().to_string(),
        reason_class: Some(input.methodology_id.clone()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::SupplyChain,
        event_type: format!("carbon_claim.{}", input.standard.as_str()),
        event_hash, model,
        policy_id: "po_carbon_claim_v1".to_string(),
        input_hash, output_hash,
        approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "carbon_claim".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears,
        prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// Workflow 4: Methane / flaring event (OGMP 2.0 + EU Methane Reg)
// =============================================================================

/// OGMP 2.0 reporting level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OgmpLevel {
    /// L1 — generic estimates.
    L1,
    /// L2 — generic emission factors.
    L2,
    /// L3 — specific emission factors.
    L3,
    /// L4 — source-level direct measurement.
    L4,
    /// L5 — site-level reconciliation.
    L5,
}

impl OgmpLevel {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::L3 => "l3",
            Self::L4 => "l4",
            Self::L5 => "l5",
        }
    }
}

/// Methane / flaring event input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethaneEvent {
    /// Event id.
    pub event_id: String,
    /// OGMP 2.0 level.
    pub ogmp_level: OgmpLevel,
    /// Methane emission (kg CH4).
    pub emission_kg_ch4: Decimal,
    /// `true` if flaring is involved.
    pub flaring: bool,
    /// Site id.
    pub site_id: String,
    /// AI detection model id (e.g., satellite + SCADA fusion).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl MethaneEvent {
    /// Demo input.
    pub fn demo() -> Self {
        Self {
            event_id: "ch4-2026-12-9001".into(),
            ogmp_level: OgmpLevel::L4,
            emission_kg_ch4: Decimal::new(120, 0),
            flaring: false,
            site_id: "adnoc-site-12".into(),
            model_id: "methane_detection_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-methane-weights").to_hex(),
            reviewer_role: "site_engineer".into(),
            reviewer_pseudo_id: "role:site_engineer#0a1".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed methane event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethaneEventSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// OGMP level (mirrored).
    pub ogmp_level: OgmpLevel,
}

impl MethaneEventSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String { self.seal.id_string() }
}

fn build_methane_seal(input: &MethaneEvent, tenant_id: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.event_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.ogmp_level.as_str().as_bytes());
        bytes.extend_from_slice(input.emission_kg_ch4.to_string().as_bytes());
        bytes.extend_from_slice(&[input.flaring as u8]);
        Hasher::sha256(&bytes)
    };
    let event_hash = Hasher::sha256(format!("{}:{}", input.event_id, input.site_id).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("methane_event"));
    sector_extension.insert("ogmp_level".into(), serde_json::json!(input.ogmp_level.as_str()));
    sector_extension.insert("emission_kg_ch4".into(), serde_json::json!(input.emission_kg_ch4.to_string()));
    sector_extension.insert("flaring".into(), serde_json::json!(input.flaring));
    sector_extension.insert("site_id".into(), serde_json::json!(input.site_id));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.ogmp_level.as_str().to_string(),
        reason_class: if input.flaring { Some("flaring".into()) } else { None },
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::SupplyChain,
        event_type: format!("methane_event.{}", input.ogmp_level.as_str()),
        event_hash, model,
        policy_id: "po_methane_v1".to_string(),
        input_hash, output_hash,
        approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "methane_event".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::TenYears,
        prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// SupplyChainSandbox
// =============================================================================

/// Plug-and-play entry point for supply-chain workflows.
pub struct SupplyChainSandbox {
    inner: Sandbox,
    primary_jurisdiction: SupplyChainJurisdiction,
}

impl SupplyChainSandbox {
    /// One-line quickstart.
    pub fn quickstart(tenant: impl Into<String>) -> SandboxResult<Self> {
        Self::builder().tenant(tenant).jurisdiction(SupplyChainJurisdiction::EuCbam).build()
    }
    /// Builder.
    pub fn builder() -> SupplyChainSandboxBuilder { SupplyChainSandboxBuilder::default() }
    /// Underlying core sandbox.
    pub fn core(&self) -> &Sandbox { &self.inner }
    /// Tenant id.
    pub fn tenant(&self) -> &str { &self.inner.config().tenant_id }
    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> SupplyChainJurisdiction { self.primary_jurisdiction }

    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> { self.inner.append_seal(seal) }
    /// Export evidence.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.evidence().export(self.tenant().to_string(), Sector::SupplyChain)
    }

    /// Project regulator view.
    pub fn regulator_view(&self, seal: &DigitalSeal, jurisdiction: SupplyChainJurisdiction) -> RegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal.approvals.first().map(|a| a.decision.clone()).unwrap_or_else(|| "unknown".into());
        RegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    fn common_faults(&self, seal: &DigitalSeal) -> HashMap<String, bool> {
        let mut faults = HashMap::new();
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_METHODOLOGY_APPROVED.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_REVIEWER_BIND.into(), true);
        }
        if !is_supported_juris(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_EVIDENCE_INTEGRITY.into(), true);
        }
        faults
    }

    /// Seal a batch event.
    pub fn seal_batch_event(&self, input: BatchEvent) -> SandboxResult<BatchEventSeal> {
        let seal = build_batch_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("batch event {} blocked", input.batch_id)));
        }
        self.append(seal.clone())?;
        Ok(BatchEventSeal { seal, epcis_event_type: input.epcis_event_type })
    }
    /// Seal a customs filing.
    pub fn seal_customs_filing(&self, input: CustomsFiling) -> SandboxResult<CustomsFilingSeal> {
        let seal = build_customs_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("customs filing {} blocked", input.filing_id)));
        }
        self.append(seal.clone())?;
        Ok(CustomsFilingSeal { seal, decision: input.decision })
    }
    /// Seal a carbon claim.
    pub fn seal_carbon_claim(&self, input: CarbonClaim) -> SandboxResult<CarbonClaimSeal> {
        if input.emissions_kg_co2e.is_sign_negative() {
            return Err(SandboxError::policy(GATE_CARBON_TOLERANCE, "emissions cannot be negative"));
        }
        let seal = build_carbon_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("carbon claim {} blocked", input.claim_id)));
        }
        self.append(seal.clone())?;
        Ok(CarbonClaimSeal { seal, standard: input.standard })
    }
    /// Seal a methane event.
    pub fn seal_methane_event(&self, input: MethaneEvent) -> SandboxResult<MethaneEventSeal> {
        if input.emission_kg_ch4.is_sign_negative() {
            return Err(SandboxError::policy(GATE_EVIDENCE_INTEGRITY, "emission cannot be negative"));
        }
        let seal = build_methane_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("methane event {} blocked", input.event_id)));
        }
        self.append(seal.clone())?;
        Ok(MethaneEventSeal { seal, ogmp_level: input.ogmp_level })
    }

    // =================================================================
    // Enterprise convenience: bulk API + envelope + verify + audit.
    // =================================================================

    /// Bulk seal batch events.
    pub fn seal_batch_events(&self, items: impl IntoIterator<Item = BatchEvent>) -> SandboxResult<Vec<BatchEventSeal>> {
        items.into_iter().map(|i| self.seal_batch_event(i)).collect()
    }
    /// Bulk seal customs filings.
    pub fn seal_customs_filings(&self, items: impl IntoIterator<Item = CustomsFiling>) -> SandboxResult<Vec<CustomsFilingSeal>> {
        items.into_iter().map(|i| self.seal_customs_filing(i)).collect()
    }
    /// Bulk seal carbon claims.
    pub fn seal_carbon_claims(&self, items: impl IntoIterator<Item = CarbonClaim>) -> SandboxResult<Vec<CarbonClaimSeal>> {
        items.into_iter().map(|i| self.seal_carbon_claim(i)).collect()
    }
    /// Bulk seal methane events.
    pub fn seal_methane_events(&self, items: impl IntoIterator<Item = MethaneEvent>) -> SandboxResult<Vec<MethaneEventSeal>> {
        items.into_iter().map(|i| self.seal_methane_event(i)).collect()
    }

    /// Get an envelope at index.
    pub fn envelope_at(&self, index: u64) -> SandboxResult<aethelred_sandbox_core::SealEnvelope> {
        let bundle = self.export_evidence()?;
        let entry = bundle.entries.iter().find(|e| e.index == index).cloned()
            .ok_or_else(|| SandboxError::Evidence(format!("envelope at index {index} not found")))?;
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
    /// Current Merkle root.
    pub fn current_root(&self) -> SandboxResult<aethelred_sandbox_core::Sha256Digest> {
        self.inner.current_root()
    }
    /// Number of seals.
    pub fn seal_count(&self) -> usize { self.inner.seal_count() }
    /// Audit trail in requested format.
    pub fn audit_trail(&self, format: aethelred_sandbox_core::audit::AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }
    /// Structured audit trail.
    pub fn audit_trail_struct(&self) -> SandboxResult<aethelred_sandbox_core::audit::AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(aethelred_sandbox_core::audit::AuditTrail::from_bundle(&bundle))
    }
    /// Verify all seals against current root.
    pub fn verify_all(&self) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        aethelred_sandbox_core::verify::Verifier::default().verify_batch(&envs, root)
    }
    /// Verify with a custom Verifier.
    pub fn verify_all_with(&self, verifier: &aethelred_sandbox_core::verify::Verifier) -> SandboxResult<Vec<aethelred_sandbox_core::verify::VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        verifier.verify_batch(&envs, root)
    }
}

/// Builder.
#[derive(Default)]
pub struct SupplyChainSandboxBuilder {
    tenant: Option<String>,
    primary_jurisdiction: Option<SupplyChainJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    label: Option<String>,
}

impl SupplyChainSandboxBuilder {
    /// Set tenant.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self { self.tenant = Some(tenant.into()); self }
    /// Set jurisdiction.
    pub fn jurisdiction(mut self, j: SupplyChainJurisdiction) -> Self { self.primary_jurisdiction = Some(j); self }
    /// Add gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self { self.extra_gates.push(gate); self }
    /// Override label.
    pub fn label(mut self, label: impl Into<String>) -> Self { self.label = Some(label.into()); self }
    /// Build.
    pub fn build(self) -> SandboxResult<SupplyChainSandbox> {
        let tenant = self.tenant.ok_or_else(|| SandboxError::config("tenant not set"))?;
        let primary = self.primary_jurisdiction.unwrap_or(SupplyChainJurisdiction::EuCbam);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self.label.unwrap_or_else(|| format!("{tenant} Supply Chain Sandbox"));
        let inner = SandboxBuilder::new(Sector::SupplyChain)
            .crate_name("aethelred-sandbox-supply-chain")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&tenant).label(&label).jurisdiction(primary.seal_tag())
            .workflow("batch_event").workflow("customs_filing")
            .workflow("carbon_claim").workflow("methane_event")
            .with_gates(all_gates).build()?;
        Ok(SupplyChainSandbox { inner, primary_jurisdiction: primary })
    }
}

fn is_supported_juris(tag: &str) -> bool {
    matches!(tag, "EU-CBAM" | "EU-METHANE" | "US-IRA-45V" | "US-IRA-45Q" | "EU-CSRD-ISSB" | "AE-EAD-CUSTOMS" | "WCO-SAFE")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs() {
        let sb = SupplyChainSandbox::quickstart("KEZAD").unwrap();
        assert_eq!(sb.tenant(), "KEZAD");
        assert_eq!(sb.primary_jurisdiction(), SupplyChainJurisdiction::EuCbam);
    }

    #[test]
    fn batch_seal_happy_path() {
        let sb = SupplyChainSandbox::quickstart("KEZAD").unwrap();
        let s = sb.seal_batch_event(BatchEvent::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn customs_seal_happy_path() {
        let sb = SupplyChainSandbox::quickstart("ADNOC").unwrap();
        let s = sb.seal_customs_filing(CustomsFiling::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn carbon_seal_happy_path() {
        let sb = SupplyChainSandbox::quickstart("Masdar").unwrap();
        let s = sb.seal_carbon_claim(CarbonClaim::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn methane_seal_happy_path() {
        let sb = SupplyChainSandbox::builder()
            .tenant("ADNOC")
            .jurisdiction(SupplyChainJurisdiction::EuMethane)
            .build()
            .unwrap();
        let s = sb.seal_methane_event(MethaneEvent::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn negative_emissions_block_carbon_claim() {
        let sb = SupplyChainSandbox::quickstart("Masdar").unwrap();
        let mut c = CarbonClaim::demo();
        c.emissions_kg_co2e = Decimal::new(-1, 0);
        let r = sb.seal_carbon_claim(c);
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = SupplyChainSandbox::quickstart("KEZAD").unwrap();
        sb.seal_batch_event(BatchEvent::demo()).unwrap();
        sb.seal_customs_filing(CustomsFiling::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.sector, Sector::SupplyChain);
    }
}
