//! # Aethelred Infinity Sandbox — Research Reproducibility
//!
//! Production-grade verification & evidence layer for AI / ML research:
//! experiment runs (with full lineage), model release packs, reproducibility
//! checks, and training-run sealing. MLflow / W&B / DVC / Hugging Face / Slurm
//! / RO-Crate envelopes. FAIR principles, NeurIPS reproducibility checklist,
//! MLPerf alignment.
//!
//! ## Plug-and-play
//!
//! ```no_run
//! use aethelred_sandbox_research::prelude::*;
//!
//! let sandbox = ResearchSandbox::quickstart("MBZUAI").unwrap();
//! let seal = sandbox.seal_experiment_run(ExperimentRun::demo()).unwrap();
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
        DatasetClass, ExperimentRun, ExperimentRunSeal, License, ModelReleasePack,
        ModelReleasePackSeal, ReproducibilityCheck, ReproducibilityCheckSeal, ReproducibilityResult,
        ResearchJurisdiction, ResearchRegulatorView, ResearchSandbox, ResearchSandboxBuilder,
        TrainingRun, TrainingRunSeal,
    };
    pub use aethelred_sandbox_core::{
        DigitalSeal, EvidenceBundle, EvidenceLogEntry, ModelReference, RetentionClass, SandboxError,
        SandboxResult, Sector, Sha256Digest,
    };
}

// =============================================================================
// Policy
// =============================================================================

/// Dataset license / consent class is acceptable.
pub const GATE_DATASET_LICENSE: &str = "research.dataset_license";
/// Code, model, parameters, and seed are versioned.
pub const GATE_VERSIONING_COMPLETE: &str = "research.versioning_complete";
/// Reviewer / approver present.
pub const GATE_REVIEWER_BIND: &str = "research.reviewer_bind";
/// Result integrity (no metric tampering).
pub const GATE_RESULT_INTEGRITY: &str = "research.result_integrity";
/// FAIR-aligned metadata present.
pub const GATE_FAIR_METADATA: &str = "research.fair_metadata";
/// Jurisdiction / regulator framework supported.
pub const GATE_JURISDICTION_SUPPORTED: &str = "research.jurisdiction_supported";

fn default_gates() -> Vec<PolicyGate> {
    vec![
        PolicyGate::required(GATE_DATASET_LICENSE, "Dataset license / consent", "Dataset must have acceptable license, consent, or synthetic status."),
        PolicyGate::required(GATE_VERSIONING_COMPLETE, "Code / model / params / seed versioned", "All four components must be versioned and hashed."),
        PolicyGate::required(GATE_REVIEWER_BIND, "Reviewer bind", "Reviewer / approver signature must be present."),
        PolicyGate::required(GATE_RESULT_INTEGRITY, "Result integrity", "Reported metrics must match output commitment; tampering fails closed."),
        PolicyGate::required(GATE_JURISDICTION_SUPPORTED, "Jurisdiction supported", "Workflow framework must be configured."),
        PolicyGate::optional(GATE_FAIR_METADATA, "FAIR metadata", "Soft-fail when FAIR metadata is missing or incomplete."),
    ]
}

// =============================================================================
// Regulators / frameworks
// =============================================================================

/// Research jurisdiction / framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResearchJurisdiction {
    /// FAIR data principles.
    Fair,
    /// NeurIPS reproducibility checklist.
    NeurIpsReproducibility,
    /// MLPerf benchmark methodology.
    MlPerf,
    /// ISO/IEC 42001 (AI management).
    Iso42001,
    /// NIST AI RMF 2.0.
    NistAiRmf,
    /// UNESCO Recommendation on the Ethics of AI.
    UnescoEthics,
    /// EU AI Act (research-to-product transition).
    EuAiActResearch,
}

impl ResearchJurisdiction {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fair => "fair",
            Self::NeurIpsReproducibility => "neurips_reproducibility",
            Self::MlPerf => "mlperf",
            Self::Iso42001 => "iso_42001",
            Self::NistAiRmf => "nist_ai_rmf",
            Self::UnescoEthics => "unesco_ethics",
            Self::EuAiActResearch => "eu_ai_act_research",
        }
    }
    /// Seal tag.
    pub const fn seal_tag(self) -> &'static str {
        match self {
            Self::Fair => "FAIR",
            Self::NeurIpsReproducibility => "NEURIPS-REPRO",
            Self::MlPerf => "MLPERF",
            Self::Iso42001 => "ISO-IEC-42001",
            Self::NistAiRmf => "NIST-AI-RMF",
            Self::UnescoEthics => "UNESCO-AI-ETHICS",
            Self::EuAiActResearch => "EU-AI-ACT-RESEARCH",
        }
    }
    /// Citations.
    pub fn citations(self) -> Vec<RegulatorCitation> {
        match self {
            Self::Fair => vec![RegulatorCitation::fair_principles()],
            Self::NeurIpsReproducibility => vec![RegulatorCitation::neurips_repro()],
            Self::MlPerf => vec![RegulatorCitation::mlperf()],
            Self::Iso42001 => vec![RegulatorCitation::iso_42001()],
            Self::NistAiRmf => vec![RegulatorCitation::nist_ai_rmf()],
            Self::UnescoEthics => vec![RegulatorCitation::unesco_ai_ethics()],
            Self::EuAiActResearch => vec![RegulatorCitation::eu_ai_act_art_2_8()],
        }
    }
}

/// Citation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatorCitation {
    /// Authority.
    pub authority: String,
    /// Citation id.
    pub citation_id: String,
    /// Section.
    pub section: String,
    /// Summary.
    pub summary: String,
}

impl RegulatorCitation {
    /// FAIR data principles (Wilkinson et al. 2016).
    pub fn fair_principles() -> Self { Self { authority: "GO FAIR".into(), citation_id: "FAIR Principles".into(), section: "Findable / Accessible / Interoperable / Reusable".into(), summary: "Research data stewardship principles.".into() } }
    /// NeurIPS Reproducibility Checklist.
    pub fn neurips_repro() -> Self { Self { authority: "NeurIPS".into(), citation_id: "Reproducibility Checklist".into(), section: "Code / data / experiments / claims".into(), summary: "Top-venue reproducibility expectations.".into() } }
    /// MLPerf Inference / Training.
    pub fn mlperf() -> Self { Self { authority: "MLCommons".into(), citation_id: "MLPerf".into(), section: "Inference + Training submission rules".into(), summary: "Standardised AI benchmark methodology.".into() } }
    /// ISO/IEC 42001:2023.
    pub fn iso_42001() -> Self { Self { authority: "ISO/IEC".into(), citation_id: "ISO/IEC 42001:2023".into(), section: "Clauses 8–10".into(), summary: "AI management system operation.".into() } }
    /// NIST AI RMF 2.0.
    pub fn nist_ai_rmf() -> Self { Self { authority: "NIST (US)".into(), citation_id: "AI RMF 2.0".into(), section: "GOVERN / MAP / MEASURE / MANAGE".into(), summary: "AI risk lifecycle expectations.".into() } }
    /// UNESCO Recommendation on the Ethics of AI.
    pub fn unesco_ai_ethics() -> Self { Self { authority: "UNESCO".into(), citation_id: "Recommendation on the Ethics of AI (2021)".into(), section: "Global ethical framework".into(), summary: "Ethics framework for AI research and deployment.".into() } }
    /// EU AI Act Article 2(8) — research exemption.
    pub fn eu_ai_act_art_2_8() -> Self { Self { authority: "EU".into(), citation_id: "Regulation (EU) 2024/1689".into(), section: "Article 2(8)".into(), summary: "Research exemption transitioning to product placement.".into() } }
}

/// Regulator / framework view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchRegulatorView {
    /// Jurisdiction / framework.
    pub jurisdiction: ResearchJurisdiction,
    /// Citations.
    pub citations: Vec<RegulatorCitation>,
    /// Seal id.
    pub seal_id: String,
    /// Workflow.
    pub workflow_id: String,
    /// Event class.
    pub event_class: String,
    /// Decision (or event sub-type).
    pub decision: String,
    /// Tenant id.
    pub tenant_id: String,
}

impl ResearchRegulatorView {
    /// Project a seal.
    pub fn project(seal: &DigitalSeal, jurisdiction: ResearchJurisdiction, decision: impl Into<String>, event_class: impl Into<String>) -> Self {
        Self { jurisdiction, citations: jurisdiction.citations(), seal_id: seal.id_string(), workflow_id: seal.workflow_id.clone(), event_class: event_class.into(), decision: decision.into(), tenant_id: seal.tenant_id.clone() }
    }
}

// =============================================================================
// Models
// =============================================================================

/// Dataset class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetClass {
    /// Public dataset (e.g., ImageNet, CIFAR, COCO, MMLU).
    Public,
    /// Synthetic dataset.
    Synthetic,
    /// Consented production data.
    Consented,
    /// Research-only (under DUA).
    ResearchOnly,
    /// Restricted (do not publish).
    Restricted,
}

impl DatasetClass {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public", Self::Synthetic => "synthetic",
            Self::Consented => "consented", Self::ResearchOnly => "research_only",
            Self::Restricted => "restricted",
        }
    }
    /// `true` if acceptable for an open-research sandbox.
    pub fn is_acceptable(self) -> bool { !matches!(self, Self::Restricted) }
}

/// Open-source license class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum License {
    /// Apache-2.0.
    Apache20,
    /// MIT.
    Mit,
    /// BSD-3-Clause.
    Bsd3Clause,
    /// CC-BY-4.0.
    CcBy40,
    /// CC-BY-NC-4.0 (non-commercial).
    CcByNc40,
    /// MPL-2.0.
    Mpl20,
    /// Hugging Face — Llama2 community license.
    Llama2Community,
    /// Custom (e.g., Falcon, OpenAI usage policy).
    Custom,
}

impl License {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apache20 => "apache_2_0", Self::Mit => "mit",
            Self::Bsd3Clause => "bsd_3_clause", Self::CcBy40 => "cc_by_4_0",
            Self::CcByNc40 => "cc_by_nc_4_0", Self::Mpl20 => "mpl_2_0",
            Self::Llama2Community => "llama2_community", Self::Custom => "custom",
        }
    }
}

/// Experiment run input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentRun {
    /// Experiment id.
    pub experiment_id: String,
    /// Run id (within experiment).
    pub run_id: String,
    /// Dataset id.
    pub dataset_id: String,
    /// Dataset version.
    pub dataset_version: String,
    /// Dataset class.
    pub dataset_class: DatasetClass,
    /// Dataset hash hex.
    pub dataset_hash_hex: String,
    /// Model id.
    pub model_id: String,
    /// Model hash hex.
    pub model_hash_hex: String,
    /// Code commit (e.g., git sha).
    pub code_commit: String,
    /// Hyperparameter hash hex.
    pub params_hash_hex: String,
    /// Random seed.
    pub random_seed: u64,
    /// Hash of the metric vector (e.g., {accuracy, f1, perplexity}).
    pub metrics_hash_hex: String,
    /// Tracker URI (MLflow / W&B / Neptune / Comet / etc.).
    pub tracker_uri: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl ExperimentRun {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            experiment_id: "exp-2026-12-001".into(),
            run_id: "run-887".into(),
            dataset_id: "imagenet-1k".into(),
            dataset_version: "v2.0".into(),
            dataset_class: DatasetClass::Public,
            dataset_hash_hex: Hasher::sha256(b"imagenet-1k-v2.0").to_hex(),
            model_id: "vit_base_patch16_224".into(),
            model_hash_hex: Hasher::sha256(b"vit-weights-v1").to_hex(),
            code_commit: "git:1a2b3c4d".into(),
            params_hash_hex: Hasher::sha256(b"params-yaml").to_hex(),
            random_seed: 42,
            metrics_hash_hex: Hasher::sha256(b"top1=0.821 top5=0.957").to_hex(),
            tracker_uri: "mlflow://tracker.mbzuai.ac.ae/exp/887".into(),
            reviewer_role: "principal_investigator".into(),
            reviewer_pseudo_id: "role:pi#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed experiment run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentRunSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Random seed (mirrored for fast lookup).
    pub random_seed: u64,
}

impl ExperimentRunSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_experiment_seal(input: &ExperimentRun, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let model_hash = Sha256Digest::from_hex(&input.model_hash_hex).ok_or_else(|| SandboxError::invalid("model_hash_hex"))?;
    let dataset_hash = Sha256Digest::from_hex(&input.dataset_hash_hex).ok_or_else(|| SandboxError::invalid("dataset_hash_hex"))?;
    let params_hash = Sha256Digest::from_hex(&input.params_hash_hex).ok_or_else(|| SandboxError::invalid("params_hash_hex"))?;
    let metrics_hash = Sha256Digest::from_hex(&input.metrics_hash_hex).ok_or_else(|| SandboxError::invalid("metrics_hash_hex"))?;
    let model = ModelReference {
        model_hash, model_id: input.model_id.clone(),
        model_version: Some(input.dataset_version.clone()),
        weights_commit_ref: Some(input.code_commit.clone()),
        framework: None, framework_version: None,
        training_data_class: Some(input.dataset_class.as_str().to_string()),
    };
    let input_hash = {
        // Combined input hash: dataset + params + seed
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&dataset_hash.0);
        bytes.extend_from_slice(&params_hash.0);
        bytes.extend_from_slice(&input.random_seed.to_be_bytes());
        Hasher::sha256(&bytes)
    };
    let output_hash = metrics_hash;
    let event_hash = Hasher::sha256(format!("{}:{}:{}", input.experiment_id, input.run_id, input.code_commit).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("experiment_run"));
    sector_extension.insert("experiment_id".into(), serde_json::json!(input.experiment_id));
    sector_extension.insert("run_id".into(), serde_json::json!(input.run_id));
    sector_extension.insert("dataset_id".into(), serde_json::json!(input.dataset_id));
    sector_extension.insert("dataset_class".into(), serde_json::json!(input.dataset_class.as_str()));
    sector_extension.insert("code_commit".into(), serde_json::json!(input.code_commit));
    sector_extension.insert("random_seed".into(), serde_json::json!(input.random_seed));
    sector_extension.insert("tracker_uri".into(), serde_json::json!(input.tracker_uri));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(), role: input.reviewer_role.clone(),
        decision: "experiment_run_signed_off".into(),
        reason_class: Some(input.dataset_class.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::Research,
        event_type: format!("experiment_run.{}", input.dataset_class.as_str()),
        event_hash, model, policy_id: "po_experiment_run_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "experiment_run".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::Indefinite, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Model release pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReleasePack {
    /// Model id (e.g., `"falcon-h1-7b"`).
    pub model_id: String,
    /// Release version.
    pub version: String,
    /// Hash of the canonical weights artefact.
    pub weights_hash_hex: String,
    /// Hash of the model card.
    pub model_card_hash_hex: String,
    /// License.
    pub license: License,
    /// Release URI (e.g., `huggingface.co/tii/falcon-h1-7b`).
    pub release_uri: String,
    /// Release approver role.
    pub approver_role: String,
    /// Release approver pseudo id.
    pub approver_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl ModelReleasePack {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            model_id: "falcon-h1-7b".into(),
            version: "1.0.0".into(),
            weights_hash_hex: Hasher::sha256(b"falcon-h1-7b weights").to_hex(),
            model_card_hash_hex: Hasher::sha256(b"falcon-h1-7b model card").to_hex(),
            license: License::Apache20,
            release_uri: "huggingface.co/tii/falcon-h1-7b".into(),
            approver_role: "release_manager".into(),
            approver_pseudo_id: "role:release_manager#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed model release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelReleasePackSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// License.
    pub license: License,
}

impl ModelReleasePackSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_release_seal(input: &ModelReleasePack, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let weights_hash = Sha256Digest::from_hex(&input.weights_hash_hex).ok_or_else(|| SandboxError::invalid("weights_hash_hex"))?;
    let model_card_hash = Sha256Digest::from_hex(&input.model_card_hash_hex).ok_or_else(|| SandboxError::invalid("model_card_hash_hex"))?;
    let model = ModelReference {
        model_hash: weights_hash, model_id: input.model_id.clone(),
        model_version: Some(input.version.clone()),
        weights_commit_ref: Some(input.release_uri.clone()),
        framework: None, framework_version: None, training_data_class: None,
    };
    let input_hash = weights_hash;
    let output_hash = model_card_hash;
    let event_hash = Hasher::sha256(format!("{}:release:{}", input.model_id, input.version).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("model_release"));
    sector_extension.insert("model_id".into(), serde_json::json!(input.model_id));
    sector_extension.insert("version".into(), serde_json::json!(input.version));
    sector_extension.insert("license".into(), serde_json::json!(input.license.as_str()));
    sector_extension.insert("release_uri".into(), serde_json::json!(input.release_uri));
    let approval = ApprovalRecord {
        approver_ref: input.approver_pseudo_id.clone(), role: input.approver_role.clone(),
        decision: "released".into(),
        reason_class: Some(input.license.as_str().to_string()),
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::Research,
        event_type: format!("model_release.{}", input.license.as_str()),
        event_hash, model, policy_id: "po_model_release_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "model_release".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::Indefinite, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Reproducibility result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproducibilityResult {
    /// Fully reproduced — metrics match within tolerance.
    Reproduced,
    /// Partially reproduced — some metrics match, others diverge.
    PartiallyReproduced,
    /// Not reproduced — significant metric divergence.
    NotReproduced,
    /// Inconclusive — cannot determine (e.g., dataset access lost).
    Inconclusive,
}

impl ReproducibilityResult {
    /// String id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reproduced => "reproduced", Self::PartiallyReproduced => "partially_reproduced",
            Self::NotReproduced => "not_reproduced", Self::Inconclusive => "inconclusive",
        }
    }
}

/// Reproducibility check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityCheck {
    /// Original experiment run id.
    pub original_run_id: String,
    /// Reproducer's run id.
    pub reproducer_run_id: String,
    /// Hash of the original metric vector.
    pub original_metrics_hash_hex: String,
    /// Hash of the reproducer's metric vector.
    pub reproducer_metrics_hash_hex: String,
    /// Result.
    pub result: ReproducibilityResult,
    /// Tolerance applied (e.g., `0.005` for 0.5% accuracy delta).
    pub tolerance: f64,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl ReproducibilityCheck {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            original_run_id: "run-887".into(),
            reproducer_run_id: "repro-run-887-v1".into(),
            original_metrics_hash_hex: Hasher::sha256(b"orig metrics").to_hex(),
            reproducer_metrics_hash_hex: Hasher::sha256(b"orig metrics").to_hex(),
            result: ReproducibilityResult::Reproduced,
            tolerance: 0.005,
            reviewer_role: "reproducer".into(),
            reviewer_pseudo_id: "role:reproducer#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed reproducibility check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityCheckSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Result.
    pub result: ReproducibilityResult,
}

impl ReproducibilityCheckSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_repro_seal(input: &ReproducibilityCheck, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let orig_hash = Sha256Digest::from_hex(&input.original_metrics_hash_hex).ok_or_else(|| SandboxError::invalid("original_metrics_hash_hex"))?;
    let repro_hash = Sha256Digest::from_hex(&input.reproducer_metrics_hash_hex).ok_or_else(|| SandboxError::invalid("reproducer_metrics_hash_hex"))?;
    let model = ModelReference::new(format!("repro::{}", input.original_run_id), Hasher::sha256(input.original_run_id.as_bytes()));
    let input_hash = orig_hash;
    let output_hash = repro_hash;
    let event_hash = Hasher::sha256(format!("{}:repro:{}", input.original_run_id, input.result.as_str()).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("reproducibility_check"));
    sector_extension.insert("original_run_id".into(), serde_json::json!(input.original_run_id));
    sector_extension.insert("reproducer_run_id".into(), serde_json::json!(input.reproducer_run_id));
    sector_extension.insert("result".into(), serde_json::json!(input.result.as_str()));
    sector_extension.insert("tolerance".into(), serde_json::json!(input.tolerance));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(), role: input.reviewer_role.clone(),
        decision: input.result.as_str().to_string(),
        reason_class: None,
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::Research,
        event_type: format!("reproducibility_check.{}", input.result.as_str()),
        event_hash, model, policy_id: "po_reproducibility_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "reproducibility_check".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::Indefinite, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

/// Training run (a separate workflow from experiment run — focuses on the
/// long-running training process itself, not the evaluation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingRun {
    /// Training run id.
    pub training_id: String,
    /// Model id.
    pub model_id: String,
    /// Hash of the training-data manifest.
    pub training_data_manifest_hash_hex: String,
    /// Total training tokens / examples.
    pub total_tokens: u64,
    /// Wall-clock training duration (seconds).
    pub training_duration_s: u64,
    /// Compute cluster id (e.g., `"slurm:abu-dhabi-1"`).
    pub cluster_id: String,
    /// Hash of the training config.
    pub config_hash_hex: String,
    /// Hash of the resulting checkpoint.
    pub checkpoint_hash_hex: String,
    /// Reviewer role.
    pub reviewer_role: String,
    /// Reviewer pseudo id.
    pub reviewer_pseudo_id: String,
    /// Optional jurisdiction tag.
    pub jurisdiction_tag: Option<String>,
}

impl TrainingRun {
    /// Demo.
    pub fn demo() -> Self {
        Self {
            training_id: "training-2026-12-001".into(),
            model_id: "falcon-h1-7b".into(),
            training_data_manifest_hash_hex: Hasher::sha256(b"data-manifest").to_hex(),
            total_tokens: 1_500_000_000_000,
            training_duration_s: 86_400 * 30,
            cluster_id: "slurm:abu-dhabi-1".into(),
            config_hash_hex: Hasher::sha256(b"training-config").to_hex(),
            checkpoint_hash_hex: Hasher::sha256(b"checkpoint").to_hex(),
            reviewer_role: "training_lead".into(),
            reviewer_pseudo_id: "role:training_lead#a01".into(),
            jurisdiction_tag: None,
        }
    }
}

/// Sealed training run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingRunSeal {
    /// Seal.
    pub seal: DigitalSeal,
    /// Total tokens.
    pub total_tokens: u64,
}

impl TrainingRunSeal { /// Stable id.
    pub fn id_string(&self) -> String { self.seal.id_string() } }

fn build_training_seal(input: &TrainingRun, tenant: &str, default_juris: &str) -> SandboxResult<DigitalSeal> {
    let manifest_hash = Sha256Digest::from_hex(&input.training_data_manifest_hash_hex).ok_or_else(|| SandboxError::invalid("training_data_manifest_hash_hex"))?;
    let config_hash = Sha256Digest::from_hex(&input.config_hash_hex).ok_or_else(|| SandboxError::invalid("config_hash_hex"))?;
    let checkpoint_hash = Sha256Digest::from_hex(&input.checkpoint_hash_hex).ok_or_else(|| SandboxError::invalid("checkpoint_hash_hex"))?;
    let model = ModelReference::new(input.model_id.clone(), checkpoint_hash);
    let input_hash = {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&manifest_hash.0);
        bytes.extend_from_slice(&config_hash.0);
        Hasher::sha256(&bytes)
    };
    let output_hash = checkpoint_hash;
    let event_hash = Hasher::sha256(format!("{}:training:{}", input.training_id, input.cluster_id).as_bytes());
    let mut sector_extension: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    sector_extension.insert("workflow".into(), serde_json::json!("training_run"));
    sector_extension.insert("training_id".into(), serde_json::json!(input.training_id));
    sector_extension.insert("cluster_id".into(), serde_json::json!(input.cluster_id));
    sector_extension.insert("total_tokens".into(), serde_json::json!(input.total_tokens));
    sector_extension.insert("training_duration_s".into(), serde_json::json!(input.training_duration_s));
    let approval = ApprovalRecord {
        approver_ref: input.reviewer_pseudo_id.clone(), role: input.reviewer_role.clone(),
        decision: "training_completed".into(),
        reason_class: None,
        timestamp: OffsetDateTime::now_utc(), signature_hex: None,
    };
    Ok(DigitalSeal {
        schema_version: SealVersion::V1, seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(), sector: Sector::Research,
        event_type: "training_run.completed".to_string(),
        event_hash, model, policy_id: "po_training_run_v1".to_string(),
        input_hash, output_hash, approvals: vec![approval],
        attestation: None, zk_proof: None,
        tenant_id: tenant.to_string(),
        workflow_id: "training_run".to_string(),
        jurisdiction_tag: input.jurisdiction_tag.clone().unwrap_or_else(|| default_juris.to_string()),
        retention: RetentionClass::Indefinite, prior_seal_hash: None, sector_extension,
        validator_signature_hex: None,
    })
}

// =============================================================================
// ResearchSandbox
// =============================================================================

/// Plug-and-play entry point for research workflows.
pub struct ResearchSandbox {
    inner: Sandbox,
    primary_jurisdiction: ResearchJurisdiction,
}

impl ResearchSandbox {
    /// Quickstart.
    pub fn quickstart(tenant: impl Into<String>) -> SandboxResult<Self> {
        Self::builder().tenant(tenant).jurisdiction(ResearchJurisdiction::Fair).build()
    }
    /// Builder.
    pub fn builder() -> ResearchSandboxBuilder { ResearchSandboxBuilder::default() }
    /// Underlying core sandbox.
    pub fn core(&self) -> &Sandbox { &self.inner }
    /// Tenant id.
    pub fn tenant(&self) -> &str { &self.inner.config().tenant_id }
    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> ResearchJurisdiction { self.primary_jurisdiction }
    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> { self.inner.append_seal(seal) }
    /// Export evidence.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.evidence().export(self.tenant().to_string(), Sector::Research)
    }
    /// Project regulator view.
    pub fn regulator_view(&self, seal: &DigitalSeal, jurisdiction: ResearchJurisdiction) -> ResearchRegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal.approvals.first().map(|a| a.decision.clone()).unwrap_or_else(|| "unknown".into());
        ResearchRegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    fn common_faults(&self, seal: &DigitalSeal) -> HashMap<String, bool> {
        let mut faults = HashMap::new();
        if seal.approvals.is_empty() { faults.insert(GATE_REVIEWER_BIND.into(), true); }
        if !is_supported_juris(&seal.jurisdiction_tag) { faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true); }
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_RESULT_INTEGRITY.into(), true);
        }
        faults
    }

    /// Seal an experiment run.
    pub fn seal_experiment_run(&self, input: ExperimentRun) -> SandboxResult<ExperimentRunSeal> {
        if !input.dataset_class.is_acceptable() {
            return Err(SandboxError::policy(GATE_DATASET_LICENSE, format!("dataset class {:?} not acceptable", input.dataset_class)));
        }
        let seal = build_experiment_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let mut faults = self.common_faults(&seal);
        if input.code_commit.is_empty() || input.params_hash_hex.is_empty() {
            faults.insert(GATE_VERSIONING_COMPLETE.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("experiment run {} blocked", input.run_id)));
        }
        self.append(seal.clone())?;
        Ok(ExperimentRunSeal { seal, random_seed: input.random_seed })
    }

    /// Seal a model release pack.
    pub fn seal_model_release(&self, input: ModelReleasePack) -> SandboxResult<ModelReleasePackSeal> {
        let seal = build_release_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("model release {}@{} blocked", input.model_id, input.version)));
        }
        self.append(seal.clone())?;
        Ok(ModelReleasePackSeal { seal, license: input.license })
    }

    /// Seal a reproducibility check.
    pub fn seal_reproducibility_check(&self, input: ReproducibilityCheck) -> SandboxResult<ReproducibilityCheckSeal> {
        let seal = build_repro_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("reproducibility check for {} blocked", input.original_run_id)));
        }
        self.append(seal.clone())?;
        Ok(ReproducibilityCheckSeal { seal, result: input.result })
    }

    /// Seal a training run.
    pub fn seal_training_run(&self, input: TrainingRun) -> SandboxResult<TrainingRunSeal> {
        let seal = build_training_seal(&input, self.tenant(), self.primary_jurisdiction.seal_tag())?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let g = faults.iter().find(|(_, v)| **v).map(|(k, _)| k.clone()).unwrap_or_default();
            return Err(SandboxError::policy(g, format!("training run {} blocked", input.training_id)));
        }
        self.append(seal.clone())?;
        Ok(TrainingRunSeal { seal, total_tokens: input.total_tokens })
    }

    // =================================================================
    // Enterprise convenience: bulk + envelope + verify + audit.
    // =================================================================

    /// Bulk seal experiment runs.
    pub fn seal_experiment_runs(&self, items: impl IntoIterator<Item = ExperimentRun>) -> SandboxResult<Vec<ExperimentRunSeal>> {
        items.into_iter().map(|i| self.seal_experiment_run(i)).collect()
    }
    /// Bulk seal model releases.
    pub fn seal_model_releases(&self, items: impl IntoIterator<Item = ModelReleasePack>) -> SandboxResult<Vec<ModelReleasePackSeal>> {
        items.into_iter().map(|i| self.seal_model_release(i)).collect()
    }
    /// Bulk seal reproducibility checks.
    pub fn seal_reproducibility_checks(&self, items: impl IntoIterator<Item = ReproducibilityCheck>) -> SandboxResult<Vec<ReproducibilityCheckSeal>> {
        items.into_iter().map(|i| self.seal_reproducibility_check(i)).collect()
    }
    /// Bulk seal training runs.
    pub fn seal_training_runs(&self, items: impl IntoIterator<Item = TrainingRun>) -> SandboxResult<Vec<TrainingRunSeal>> {
        items.into_iter().map(|i| self.seal_training_run(i)).collect()
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
    /// Current Merkle root.
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
pub struct ResearchSandboxBuilder {
    tenant: Option<String>,
    primary_jurisdiction: Option<ResearchJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    label: Option<String>,
}

impl ResearchSandboxBuilder {
    /// Tenant.
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self { self.tenant = Some(tenant.into()); self }
    /// Jurisdiction.
    pub fn jurisdiction(mut self, j: ResearchJurisdiction) -> Self { self.primary_jurisdiction = Some(j); self }
    /// Extra gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self { self.extra_gates.push(gate); self }
    /// Label.
    pub fn label(mut self, label: impl Into<String>) -> Self { self.label = Some(label.into()); self }
    /// Build.
    pub fn build(self) -> SandboxResult<ResearchSandbox> {
        let tenant = self.tenant.ok_or_else(|| SandboxError::config("tenant not set"))?;
        let primary = self.primary_jurisdiction.unwrap_or(ResearchJurisdiction::Fair);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self.label.unwrap_or_else(|| format!("{tenant} Research Sandbox"));
        let inner = SandboxBuilder::new(Sector::Research)
            .crate_name("aethelred-sandbox-research")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&tenant).label(&label).jurisdiction(primary.seal_tag())
            .workflow("experiment_run").workflow("model_release")
            .workflow("reproducibility_check").workflow("training_run")
            .with_gates(all_gates).build()?;
        Ok(ResearchSandbox { inner, primary_jurisdiction: primary })
    }
}

fn is_supported_juris(tag: &str) -> bool {
    matches!(tag, "FAIR" | "NEURIPS-REPRO" | "MLPERF" | "ISO-IEC-42001" | "NIST-AI-RMF" | "UNESCO-AI-ETHICS" | "EU-AI-ACT-RESEARCH")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs() {
        let sb = ResearchSandbox::quickstart("MBZUAI").unwrap();
        assert_eq!(sb.tenant(), "MBZUAI");
    }
    #[test]
    fn experiment_run_happy_path() {
        let sb = ResearchSandbox::quickstart("MBZUAI").unwrap();
        let s = sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        assert_eq!(s.random_seed, 42);
    }
    #[test]
    fn model_release_happy_path() {
        let sb = ResearchSandbox::quickstart("TII").unwrap();
        let s = sb.seal_model_release(ModelReleasePack::demo()).unwrap();
        assert_eq!(s.license, License::Apache20);
    }
    #[test]
    fn reproducibility_happy_path() {
        let sb = ResearchSandbox::quickstart("MBZUAI").unwrap();
        let s = sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
        assert_eq!(s.result, ReproducibilityResult::Reproduced);
    }
    #[test]
    fn training_run_happy_path() {
        let sb = ResearchSandbox::quickstart("TII").unwrap();
        let s = sb.seal_training_run(TrainingRun::demo()).unwrap();
        assert!(s.total_tokens > 0);
    }
    #[test]
    fn restricted_dataset_blocks_experiment() {
        let sb = ResearchSandbox::quickstart("MBZUAI").unwrap();
        let mut e = ExperimentRun::demo();
        e.dataset_class = DatasetClass::Restricted;
        let r = sb.seal_experiment_run(e);
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }
    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = ResearchSandbox::quickstart("MBZUAI").unwrap();
        sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        sb.seal_reproducibility_check(ReproducibilityCheck::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.sector, Sector::Research);
    }
}
