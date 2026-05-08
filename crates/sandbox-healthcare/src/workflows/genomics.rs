//! Genomics inference workflow.
//!
//! Production target: variant interpretation pipelines (e.g., Illumina
//! DRAGEN, GATK, VEP). Seal binds together the reference genome, pipeline
//! version, model id, dataset class, and clinician sign-off.

use crate::protocols::{HealthcareMessageEnvelope, HealthcareProtocol};
use aethelred_sandbox_core::{
    ApprovalRecord, DigitalSeal, Hasher, ModelReference, RetentionClass, Sector, SealVersion,
    Sha256Digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

/// Genomics dataset class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenomicsDatasetClass {
    /// Synthetic genomes (no real PII).
    Synthetic,
    /// De-identified (under standard SOP).
    DeIdentified,
    /// Consented production (genomic data with explicit consent).
    Consented,
    /// Research-only (under DUA).
    ResearchOnly,
}

impl GenomicsDatasetClass {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::DeIdentified => "de_identified",
            Self::Consented => "consented",
            Self::ResearchOnly => "research_only",
        }
    }
}

/// Reference-genome build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceGenome {
    /// GRCh38.
    Grch38,
    /// GRCh37 / hg19 (legacy).
    Grch37,
    /// T2T-CHM13 (telomere-to-telomere).
    T2tChm13,
}

impl ReferenceGenome {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grch38 => "grch38",
            Self::Grch37 => "grch37",
            Self::T2tChm13 => "t2t_chm13",
        }
    }
}

/// Variant-interpretation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariantClassification {
    /// Pathogenic.
    Pathogenic,
    /// Likely pathogenic.
    LikelyPathogenic,
    /// Variant of uncertain significance.
    Vus,
    /// Likely benign.
    LikelyBenign,
    /// Benign.
    Benign,
}

impl VariantClassification {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pathogenic => "pathogenic",
            Self::LikelyPathogenic => "likely_pathogenic",
            Self::Vus => "vus",
            Self::LikelyBenign => "likely_benign",
            Self::Benign => "benign",
        }
    }
}

/// Genomics inference input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomicsInference {
    /// Sample pseudo id.
    pub sample_pseudo_id: String,
    /// Variant id (e.g., `chr17:43044295:G>A` or HGVS notation).
    pub variant_id: String,
    /// Reference genome build.
    pub reference: ReferenceGenome,
    /// Pipeline name (e.g., `"dragen-3.10"`, `"gatk-4.4.0.0"`).
    pub pipeline: String,
    /// Pipeline version.
    pub pipeline_version: String,
    /// Interpretation model id (e.g., `"acmg_vep_v3"`).
    pub model_id: String,
    /// Model hash (hex).
    pub model_hash_hex: String,
    /// Dataset class.
    pub dataset_class: GenomicsDatasetClass,
    /// Variant classification (output).
    pub classification: VariantClassification,
    /// Confidence (0.0–1.0).
    pub confidence: f64,
    /// Clinician role (e.g., `"clinical_geneticist"`, `"molecular_pathologist"`).
    pub clinician_role: String,
    /// Clinician pseudo id.
    pub clinician_pseudo_id: String,
    /// VCF / GA4GH message envelope (the source-of-record reference).
    pub message: HealthcareMessageEnvelope,
    /// Optional jurisdiction tag override.
    pub jurisdiction_tag: Option<String>,
}

impl GenomicsInference {
    /// Demo input.
    pub fn demo() -> Self {
        let raw_message_hash = Hasher::sha256(b"##fileformat=VCFv4.2 chr17 43044295 . G A");
        Self {
            sample_pseudo_id: "psn:sample-471a".into(),
            variant_id: "chr17:43044295:G>A".into(),
            reference: ReferenceGenome::Grch38,
            pipeline: "dragen-3.10".into(),
            pipeline_version: "3.10.4".into(),
            model_id: "acmg_vep_v3".into(),
            model_hash_hex: Hasher::sha256(b"demo-acmg-weights").to_hex(),
            dataset_class: GenomicsDatasetClass::Synthetic,
            classification: VariantClassification::LikelyPathogenic,
            confidence: 0.92,
            clinician_role: "clinical_geneticist".into(),
            clinician_pseudo_id: "role:clinical_geneticist#0a1".into(),
            message: HealthcareMessageEnvelope {
                protocol: HealthcareProtocol::Vcf,
                resource_type: "VCF-Variant".into(),
                source_system: "m42-genomics-platform".into(),
                correlation_id: "vcf-demo-1".into(),
                raw_message_hash,
            },
            jurisdiction_tag: None,
        }
    }
}

/// Sealed genomics inference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenomicsInferenceSeal {
    /// The underlying canonical seal.
    pub seal: DigitalSeal,
    /// Variant classification (mirrored).
    pub classification: VariantClassification,
}

impl GenomicsInferenceSeal {
    /// Stable id string.
    pub fn id_string(&self) -> String {
        self.seal.id_string()
    }
}

pub(crate) fn build_seal(
    input: &GenomicsInference,
    tenant_id: &str,
    default_jurisdiction: &str,
) -> aethelred_sandbox_core::SandboxResult<DigitalSeal> {
    use aethelred_sandbox_core::SandboxError as E;
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex)
        .ok_or_else(|| E::invalid("model_hash_hex must be 64-char hex"))?;
    let model = ModelReference {
        model_hash,
        model_id: input.model_id.clone(),
        model_version: Some(input.pipeline_version.clone()),
        weights_commit_ref: Some(format!("{}@{}", input.pipeline, input.pipeline_version)),
        framework: Some("genomics_pipeline".into()),
        framework_version: Some(input.pipeline_version.clone()),
        training_data_class: Some(input.dataset_class.as_str().to_string()),
    };
    let input_hash = Hasher::sha256(input.variant_id.as_bytes());
    let output_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(input.classification.as_str().as_bytes());
        bytes.extend_from_slice(input.reference.as_str().as_bytes());
        bytes.extend_from_slice(input.confidence.to_le_bytes().as_slice());
        Hasher::sha256(&bytes)
    };
    let event_hash = input.message.event_hash()?;
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("genomics_inference"));
    sector_extension.insert("variant_id".into(), serde_json::json!(input.variant_id));
    sector_extension.insert("reference".into(), serde_json::json!(input.reference.as_str()));
    sector_extension.insert("pipeline".into(), serde_json::json!(input.pipeline));
    sector_extension.insert(
        "pipeline_version".into(),
        serde_json::json!(input.pipeline_version),
    );
    sector_extension.insert(
        "dataset_class".into(),
        serde_json::json!(input.dataset_class.as_str()),
    );
    sector_extension.insert(
        "classification".into(),
        serde_json::json!(input.classification.as_str()),
    );
    sector_extension.insert("confidence".into(), serde_json::json!(input.confidence));
    sector_extension.insert(
        "decision_support_only".into(),
        serde_json::json!(true),
    );
    let approval = ApprovalRecord {
        approver_ref: input.clinician_pseudo_id.clone(),
        role: input.clinician_role.clone(),
        decision: input.classification.as_str().to_string(),
        reason_class: Some(input.dataset_class.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(),
        signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Healthcare,
        event_type: format!("genomics_inference.{}", input.classification.as_str()),
        event_hash,
        model,
        policy_id: "po_genomics_v1".to_string(),
        input_hash,
        output_hash,
        approvals: vec![approval],
        attestation: None,
        zk_proof: None,
        tenant_id: tenant_id.to_string(),
        workflow_id: "genomics_inference".to_string(),
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
    fn demo_seal_carries_genomics_extension_fields() {
        let g = GenomicsInference::demo();
        let seal = build_seal(&g, "M42", "AE-AD-DOH").unwrap();
        assert_eq!(seal.workflow_id, "genomics_inference");
        assert_eq!(seal.sector, Sector::Healthcare);
        assert_eq!(
            seal.sector_extension.get("classification").unwrap(),
            &serde_json::json!("likely_pathogenic")
        );
        assert_eq!(seal.retention, RetentionClass::TenYears);
    }

    #[test]
    fn classification_string_ids_unique() {
        let all = [
            VariantClassification::Pathogenic,
            VariantClassification::LikelyPathogenic,
            VariantClassification::Vus,
            VariantClassification::LikelyBenign,
            VariantClassification::Benign,
        ];
        let mut ids: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
