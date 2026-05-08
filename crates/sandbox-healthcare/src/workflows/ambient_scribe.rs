//! Ambient AI scribe workflow — clinician-signed AI documentation.
//!
//! Production target: ambient documentation tools (Nuance DAX, Abridge,
//! Suki, Dragon) that produce SOAP notes / encounter summaries from
//! clinician-patient conversations. Seal binds to a FHIR R4
//! `DocumentReference` and a clinician sign-off.

use crate::protocols::{HealthcareMessageEnvelope, HealthcareProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Clinical-note section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteSection {
    /// Subjective.
    Subjective,
    /// Objective.
    Objective,
    /// Assessment.
    Assessment,
    /// Plan.
    Plan,
    /// HPI (history of present illness).
    Hpi,
    /// Discharge summary.
    DischargeSummary,
    /// Other.
    Other,
}

impl NoteSection {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subjective => "subjective",
            Self::Objective => "objective",
            Self::Assessment => "assessment",
            Self::Plan => "plan",
            Self::Hpi => "hpi",
            Self::DischargeSummary => "discharge_summary",
            Self::Other => "other",
        }
    }
}

/// Ambient scribe input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientNote {
    /// Encounter pseudo id.
    pub encounter_pseudo_id: String,
    /// Note section.
    pub section: NoteSection,
    /// AI scribe model id (e.g., `"ambient_scribe_v3"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Hash of the canonicalised AI-produced note (the note never travels).
    pub note_hash_hex: String,
    /// `true` if the clinician signed off on the AI-generated note.
    pub clinician_signed: bool,
    /// Clinician role.
    pub clinician_role: String,
    /// Clinician pseudo id.
    pub clinician_pseudo_id: String,
    /// FHIR R4 DocumentReference envelope.
    pub message: HealthcareMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl AmbientNote {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"FHIR DocumentReference id=docref-1 type=11506-3");
        Self {
            encounter_pseudo_id: "psn:enc-7b3".into(),
            section: NoteSection::Plan,
            model_id: "ambient_scribe_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-scribe-weights").to_hex(),
            model_version: Some("3.4.0".into()),
            note_hash_hex: Hasher::sha256(b"AI-produced note text").to_hex(),
            clinician_signed: true,
            clinician_role: "primary_care_physician".into(),
            clinician_pseudo_id: "role:primary_care#a31".into(),
            message: HealthcareMessageEnvelope {
                protocol: HealthcareProtocol::FhirR4,
                resource_type: "DocumentReference".into(),
                source_system: "epic-cosmos-1".into(),
                correlation_id: "docref-1".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed ambient note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientNoteSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// `true` if the clinician signed off (mirrored).
    pub clinician_signed: bool,
}

impl AmbientNoteSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &AmbientNote,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let note_hash = Sha256Digest::from_hex(&input.note_hash_hex)
        .ok_or_else(|| E::invalid("note_hash_hex must be 64-char hex"))?;
    let model = ModelReference::new(input.model_id.clone(), model_hash);
    let input_hash = Hasher::sha256(input.encounter_pseudo_id.as_bytes());
    let output_hash = note_hash;
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("ambient_scribe"));
    sector_extension.insert("section".into(), serde_json::json!(input.section.as_str()));
    sector_extension.insert("clinician_signed".into(), serde_json::json!(input.clinician_signed));
    sector_extension.insert("decision_support_only".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.clinician_pseudo_id.clone(),
        role: input.clinician_role.clone(),
        decision: if input.clinician_signed { "signed_off" } else { "draft" }.to_string(),
        reason_class: Some(input.section.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Healthcare,
        event_type: format!("ambient_scribe.{}", input.section.as_str()),
        event_hash,
        model,
        policy_id: "po_ambient_scribe_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "ambient_scribe".to_string(),
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
    fn demo_seal_carries_section_and_signoff() {
        let n = AmbientNote::demo();
        let seal = build_seal(&n, "M42", "AE-AD-DOH").unwrap();
        assert_eq!(seal.workflow_id, "ambient_scribe");
        assert_eq!(
            seal.sector_extension.get("clinician_signed").unwrap(),
            &serde_json::json!(true)
        );
    }
}
