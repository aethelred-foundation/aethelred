//! Core types for Aethelred SDK.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Address = String;
pub type Hash = String;
pub type TxHash = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    JobStatusUnspecified,
    JobStatusPending,
    JobStatusAssigned,
    JobStatusComputing,
    JobStatusVerifying,
    JobStatusCompleted,
    JobStatusFailed,
    JobStatusCancelled,
    JobStatusExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SealStatus {
    SealStatusUnspecified,
    SealStatusActive,
    SealStatusRevoked,
    SealStatusExpired,
    SealStatusSuperseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofType {
    ProofTypeUnspecified,
    ProofTypeTee,
    ProofTypeZkml,
    ProofTypeHybrid,
    ProofTypeOptimistic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TEEPlatform {
    TeePlatformUnspecified,
    TeePlatformIntelSgx,
    TeePlatformAmdSev,
    TeePlatformAwsNitro,
    TeePlatformArmTrustzone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UtilityCategory {
    UtilityCategoryUnspecified,
    UtilityCategoryMedical,
    UtilityCategoryScientific,
    UtilityCategoryFinancial,
    UtilityCategoryLegal,
    UtilityCategoryEducational,
    UtilityCategoryEnvironmental,
    UtilityCategoryGeneral,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    pub id: String,
    pub creator: Address,
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub output_hash: Option<Hash>,
    pub status: JobStatus,
    pub proof_type: ProofType,
    pub priority: u32,
    pub max_gas: String,
    pub timeout_blocks: u32,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub validator_address: Option<Address>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSeal {
    pub id: String,
    pub job_id: String,
    pub model_hash: Hash,
    pub input_commitment: Hash,
    pub output_commitment: Hash,
    pub model_commitment: Hash,
    pub status: SealStatus,
    pub requester: Address,
    #[serde(default)]
    pub validators: Vec<ValidatorAttestation>,
    pub tee_attestation: Option<TEEAttestation>,
    pub zkml_proof: Option<ZKMLProof>,
    pub regulatory_info: Option<RegulatoryInfo>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAttestation {
    pub validator_address: Address,
    pub signature: String,
    pub timestamp: DateTime<Utc>,
    pub voting_power: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEAttestation {
    pub platform: TEEPlatform,
    pub quote: String,
    pub enclave_hash: Hash,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub pcr_values: HashMap<String, String>,
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKMLProof {
    pub proof_system: String,
    pub proof: String,
    #[serde(default)]
    pub public_inputs: Vec<String>,
    pub verifying_key_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryInfo {
    pub jurisdiction: String,
    #[serde(default)]
    pub compliance_frameworks: Vec<String>,
    pub data_classification: String,
    pub retention_period: String,
    pub audit_trail_hash: Option<Hash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredModel {
    pub model_hash: Hash,
    pub name: String,
    pub owner: Address,
    pub architecture: String,
    pub version: String,
    pub category: UtilityCategory,
    pub input_schema: String,
    pub output_schema: String,
    pub storage_uri: String,
    pub registered_at: DateTime<Utc>,
    pub verified: bool,
    pub total_jobs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStats {
    pub address: Address,
    pub jobs_completed: u64,
    pub jobs_failed: u64,
    pub average_latency_ms: u64,
    pub uptime_percentage: f64,
    pub reputation_score: f64,
    pub total_rewards: String,
    pub slashing_events: u32,
    pub hardware_capabilities: Option<HardwareCapability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapability {
    #[serde(default)]
    pub tee_platforms: Vec<TEEPlatform>,
    pub zkml_supported: bool,
    pub max_model_size_mb: u64,
    pub gpu_memory_gb: u32,
    pub cpu_cores: u32,
    pub memory_gb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub default_node_id: String,
    pub listen_addr: String,
    pub network: String,
    pub version: String,
    pub moniker: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PageRequest {
    pub key: Option<String>,
    pub offset: Option<u64>,
    pub limit: Option<u64>,
    pub count_total: Option<bool>,
    pub reverse: Option<bool>,
}
