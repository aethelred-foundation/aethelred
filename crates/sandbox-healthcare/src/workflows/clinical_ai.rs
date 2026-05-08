//! Clinical AI inference workflow (radiology / pathology / cardiology).
//!
//! Production target: AI-assisted diagnostic support across imaging modalities
//! (X-ray, CT, MRI, US, mammography, digital pathology). DICOM 3.0 envelope
//! for source-of-record reference.

use crate::protocols::{HealthcareMessageEnvelope, HealthcareProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Imaging modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Chest / general X-ray (CR, DX).
    Xray,
    /// Computed tomography.
    Ct,
    /// Magnetic resonance imaging.
    Mri,
    /// Ultrasound.
    Ultrasound,
    /// Mammography.
    Mammography,
    /// Digital pathology / whole-slide imaging.
    Pathology,
    /// Echocardiography.
    Echocardiography,
}

impl Modality {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::Ct => "ct",
            Self::Mri => "mri",
            Self::Ultrasound => "ultrasound",
            Self::Mammography => "mammography",
            Self::Pathology => "pathology",
            Self::Echocardiography => "echocardiography",
        }
    }
}

/// Clinical AI recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClinicalRecommendation {
    /// No abnormality flagged.
    NoAbnormality,
    /// Suspicious finding — refer for review.
    SuspiciousFinding,
    /// High-suspicion finding — urgent referral.
    UrgentFinding,
    /// Image quality / acquisition issue — re-acquire.
    AcquisitionIssue,
}

impl ClinicalRecommendation {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAbnormality => "no_abnormality",
            Self::SuspiciousFinding => "suspicious_finding",
            Self::UrgentFinding => "urgent_finding",
            Self::AcquisitionIssue => "acquisition_issue",
        }
    }
}

/// Clinical AI input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClinicalInference {
    /// Encounter pseudo id.
    pub encounter_pseudo_id: String,
    /// Modality.
    pub modality: Modality,
    /// AI model id (e.g., `"aidoc_chest_xray_v4"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Optional model version.
    pub model_version: Option<String>,
    /// Recommendation.
    pub recommendation: ClinicalRecommendation,
    /// Confidence (0.0–1.0).
    pub confidence: f64,
    /// Reviewer role (e.g., `"radiologist"`, `"pathologist"`).
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// DICOM / FHIR ImagingStudy envelope.
    pub message: HealthcareMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl ClinicalInference {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash =
            Hasher::sha256(b"DICOM SOPInstanceUID 1.2.840.113619.2.55.3.279...");
        Self {
            encounter_pseudo_id: "psn:enc-7b3".into(),
            modality: Modality::Xray,
            model_id: "aidoc_chest_xray_v4".into(),
            model_hash_hex: Hasher::sha256(b"demo-aidoc-weights").to_hex(),
            model_version: Some("4.1.0".into()),
            recommendation: ClinicalRecommendation::SuspiciousFinding,
            confidence: 0.78,
            reviewer_role: "radiologist".into(),
            reviewer_pseudo_id: "role:radiologist#a3f1".into(),
            message: HealthcareMessageEnvelope {
                protocol: HealthcareProtocol::Dicom30,
                resource_type: "DICOM-Study".into(),
                source_system: "m42-pacs-1".into(),
                correlation_id: "study-1.2.840".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed clinical AI inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClinicalInferenceSeal {
    /// Underlying canonical seal.
    pub seal: DigitalSeal,
    /// Recommendation (mirrored).
    pub recommendation: ClinicalRecommendation,
}

impl ClinicalInferenceSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &ClinicalInference,
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
        weights_commit_ref: None,
        framework: Some("clinical_ai".into()),
        framework_version: input.model_version.clone(),
        training_data_class: Some("approved_clinical_dataset".into()),
    };
    let input_hash = Hasher::sha256(input.encounter_pseudo_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.recommendation.as_str().as_bytes());
        bytes.extend_from_slice(input.modality.as_str().as_bytes());
        bytes.extend_from_slice(input.confidence.to_le_bytes().as_slice());
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("clinical_ai"));
    sector_extension.insert("modality".into(), serde_json::json!(input.modality.as_str()));
    sector_extension.insert(
        "recommendation".into(),
        serde_json::json!(input.recommendation.as_str()),
    );
    sector_extension.insert("confidence".into(), serde_json::json!(input.confidence));
    sector_extension.insert("decision_support_only".into(), serde_json::json!(true));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(),
        role: input.reviewer_role.clone(),
        decision: input.recommendation.as_str().to_string(),
        reason_class: Some(input.modality.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Healthcare,
        event_type: format!("clinical_ai.{}", input.recommendation.as_str()),
        event_hash,
        model,
        policy_id: "po_clinical_ai_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "clinical_ai".to_string(),
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
    fn demo_seal_carries_modality_and_recommendation() {
        let c = ClinicalInference::demo();
        let seal = build_seal(&c, "M42", "AE-AD-DOH").unwrap();
        assert_eq!(seal.workflow_id, "clinical_ai");
        assert_eq!(
            seal.sector_extension.get("modality").unwrap(),
            &serde_json::json!("xray")
        );
        assert_eq!(
            seal.sector_extension.get("decision_support_only").unwrap(),
            &serde_json::json!(true)
        );
    }
}
