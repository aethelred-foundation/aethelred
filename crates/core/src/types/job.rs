//! Aethelred Compute Job Types
//!
//! Job management for AI computation verification.

use super::address::Address;
use crate::crypto::hash::{sha256, Hash256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Job ID (32-byte hash)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub Hash256);

impl JobId {
    /// Create from hash
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash256::from_bytes(bytes))
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Get hex string
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Debug for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JobId({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    /// Job submitted, awaiting validator assignment
    Pending,
    /// Job assigned to validators
    Assigned,
    /// Validators are executing the computation
    Computing,
    /// Validators are verifying results
    Verifying,
    /// Computation complete, seal being created
    Sealing,
    /// Job complete with seal
    Completed,
    /// Job failed (timeout, invalid, etc.)
    Failed,
    /// Job cancelled by requester
    Cancelled,
}

impl JobStatus {
    /// Check if job is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Check if job is active (can be processed)
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Assigned | Self::Computing | Self::Verifying | Self::Sealing
        )
    }
}

/// Compute job
#[derive(Debug, Clone)]
pub struct ComputeJob {
    /// Unique job identifier
    pub id: JobId,
    /// Job version
    pub version: u8,

    // === Computation Identity ===
    /// Hash of the model weights
    pub model_hash: Hash256,
    /// Hash of the input data
    pub input_hash: Hash256,
    /// Model identifier (registered model name)
    pub model_id: Option<String>,

    // === Data References ===
    /// Encrypted input data reference (IPFS, S3, etc.)
    pub input_ref: Option<DataReference>,
    /// Model weights reference
    pub model_ref: Option<DataReference>,

    // === Verification Requirements ===
    /// Required verification method
    pub verification_method: VerificationRequirement,
    /// Minimum validator attestations required
    pub min_attestations: u32,
    /// Required hardware capabilities
    pub hardware_requirements: HardwareRequirements,

    // === SLA Parameters ===
    /// Maximum latency (milliseconds)
    pub max_latency_ms: u64,
    /// Priority level (higher = more urgent)
    pub priority: u8,
    /// Expiry timestamp
    pub expiry: u64,

    // === Compliance ===
    /// Required compliance frameworks
    pub compliance: Vec<String>,
    /// Data residency requirements
    pub data_residency: Option<String>,
    /// Audit requirements
    pub audit_required: bool,

    // === Metadata ===
    /// Requester address
    pub requester: Address,
    /// Maximum fee willing to pay
    pub max_fee: u128,
    /// Submission timestamp
    pub submitted_at: u64,
    /// Current status
    pub status: JobStatus,

    // === Processing State ===
    /// Assigned validators
    pub assigned_validators: Vec<Address>,
    /// Received results
    pub results: Vec<ComputeResult>,
}

impl ComputeJob {
    /// Create a new job
    pub fn new(model_hash: Hash256, input_hash: Hash256, requester: Address) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let timestamp = now.as_secs();
        let id_entropy = now.as_nanos();

        // Compute job ID from model + input + requester + timestamp
        let mut id_data = Vec::new();
        id_data.extend_from_slice(model_hash.as_bytes());
        id_data.extend_from_slice(input_hash.as_bytes());
        id_data.extend_from_slice(&requester.serialize());
        id_data.extend_from_slice(&id_entropy.to_le_bytes());
        let id = JobId::from_hash(sha256(&id_data));

        Self {
            id,
            version: 1,
            model_hash,
            input_hash,
            model_id: None,
            input_ref: None,
            model_ref: None,
            verification_method: VerificationRequirement::Hybrid,
            min_attestations: 2,
            hardware_requirements: HardwareRequirements::default(),
            max_latency_ms: 30_000,
            priority: 5,
            expiry: timestamp + 3600, // 1 hour default
            compliance: Vec::new(),
            data_residency: None,
            audit_required: false,
            requester,
            max_fee: 0,
            submitted_at: timestamp,
            status: JobStatus::Pending,
            assigned_validators: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Set verification method
    pub fn with_verification(mut self, method: VerificationRequirement) -> Self {
        self.verification_method = method;
        self
    }

    /// Set minimum attestations
    pub fn with_min_attestations(mut self, count: u32) -> Self {
        self.min_attestations = count;
        self
    }

    /// Set hardware requirements
    pub fn with_hardware(mut self, requirements: HardwareRequirements) -> Self {
        self.hardware_requirements = requirements;
        self
    }

    /// Set max latency
    pub fn with_max_latency(mut self, ms: u64) -> Self {
        self.max_latency_ms = ms;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Set max fee
    pub fn with_max_fee(mut self, fee: u128) -> Self {
        self.max_fee = fee;
        self
    }

    /// Add compliance requirement
    pub fn with_compliance(mut self, framework: impl Into<String>) -> Self {
        self.compliance.push(framework.into());
        self
    }

    /// Set data residency
    pub fn with_data_residency(mut self, region: impl Into<String>) -> Self {
        self.data_residency = Some(region.into());
        self
    }

    /// Check if job has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expiry
    }

    /// Check if job has enough results for consensus
    pub fn has_consensus(&self) -> bool {
        self.results.len() >= self.min_attestations as usize
    }

    /// Get majority result (if consensus exists)
    pub fn majority_result(&self) -> Option<&ComputeResult> {
        if self.results.is_empty() {
            return None;
        }

        // Count results by output hash
        let mut counts: std::collections::HashMap<&Hash256, usize> =
            std::collections::HashMap::new();

        for result in &self.results {
            *counts.entry(&result.output_hash).or_insert(0) += 1;
        }

        // Find majority
        let threshold = (self.min_attestations as usize).div_ceil(2);
        let majority_hash = counts
            .into_iter()
            .find(|(_, count)| *count >= threshold)
            .map(|(hash, _)| hash)?;

        self.results
            .iter()
            .find(|r| &r.output_hash == majority_hash)
    }

    /// Assign validator to job
    pub fn assign_validator(&mut self, validator: Address) {
        if !self.assigned_validators.contains(&validator) {
            self.assigned_validators.push(validator);
            if self.status == JobStatus::Pending {
                self.status = JobStatus::Assigned;
            }
        }
    }

    /// Add computation result
    pub fn add_result(&mut self, result: ComputeResult) {
        if !self.results.iter().any(|r| r.validator == result.validator) {
            self.results.push(result);
            if self.status == JobStatus::Assigned || self.status == JobStatus::Computing {
                self.status = JobStatus::Verifying;
            }
        }
    }

    /// Serialize job for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.model_hash.as_bytes());
        bytes.extend_from_slice(self.input_hash.as_bytes());
        bytes.extend_from_slice(&self.requester.serialize());
        bytes.extend_from_slice(&self.submitted_at.to_le_bytes());
        bytes.push(self.status as u8);
        bytes
    }
}

/// Data reference for off-chain storage
#[derive(Debug, Clone)]
pub struct DataReference {
    /// Storage type
    pub storage_type: StorageType,
    /// URI/path to data
    pub uri: String,
    /// Data hash for integrity verification
    pub hash: Hash256,
    /// Size in bytes
    pub size: u64,
    /// Encryption key hash (if encrypted)
    pub encryption_key_hash: Option<Hash256>,
}

/// Storage types for data references
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// IPFS content-addressed storage
    Ipfs,
    /// AWS S3
    S3,
    /// On-chain (small data only)
    OnChain,
    /// Arweave permanent storage
    Arweave,
    /// Filecoin
    Filecoin,
}

/// Verification requirement types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationRequirement {
    /// TEE attestation only
    TeeOnly,
    /// zkML proof only
    ZkmlOnly,
    /// Both TEE and zkML (highest assurance)
    Hybrid,
    /// Multi-party computation
    Mpc,
}

impl VerificationRequirement {
    /// Check if zkML proof is required
    pub fn requires_zkml(&self) -> bool {
        matches!(self, Self::ZkmlOnly | Self::Hybrid)
    }

    /// Check if TEE attestation is required
    pub fn requires_tee(&self) -> bool {
        matches!(self, Self::TeeOnly | Self::Hybrid)
    }
}

/// Hardware requirements for job execution
#[derive(Debug, Clone)]
pub struct HardwareRequirements {
    /// Minimum memory (MB)
    pub min_memory_mb: u64,
    /// Minimum compute units
    pub min_compute_units: u64,
    /// Required TEE platform (if any)
    pub tee_platform: Option<TeePlatformRequirement>,
    /// GPU required
    pub gpu_required: bool,
    /// GPU minimum memory (MB)
    pub gpu_min_memory_mb: Option<u64>,
    /// FPGA required
    pub fpga_required: bool,
}

impl Default for HardwareRequirements {
    fn default() -> Self {
        Self {
            min_memory_mb: 1024,
            min_compute_units: 1,
            tee_platform: Some(TeePlatformRequirement::Any),
            gpu_required: false,
            gpu_min_memory_mb: None,
            fpga_required: false,
        }
    }
}

/// TEE platform requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatformRequirement {
    /// Any TEE platform acceptable
    Any,
    /// AWS Nitro required
    AwsNitro,
    /// Intel SGX required
    IntelSgx,
    /// AMD SEV-SNP required
    AmdSev,
}

/// Compute result from a validator
#[derive(Debug, Clone)]
pub struct ComputeResult {
    /// Job ID
    pub job_id: JobId,
    /// Validator address
    pub validator: Address,
    /// Output hash
    pub output_hash: Hash256,
    /// Full output (optional, may be stored off-chain)
    pub output: Option<Vec<u8>>,
    /// TEE attestation (if TEE verification used)
    pub tee_attestation: Option<TeeAttestationResult>,
    /// zkML proof (if zkML verification used)
    pub zkml_proof: Option<ZkmlProofResult>,
    /// Execution time (milliseconds)
    pub execution_time_ms: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Signature over result
    pub signature: Vec<u8>,
}

impl ComputeResult {
    /// Verify result integrity
    pub fn verify_integrity(&self) -> bool {
        if let Some(output) = &self.output {
            sha256(output) == self.output_hash
        } else {
            true // Can't verify without output data
        }
    }
}

/// TEE attestation result
#[derive(Debug, Clone)]
pub struct TeeAttestationResult {
    /// TEE platform
    pub platform: TeePlatformResult,
    /// Attestation document
    pub attestation_doc: Vec<u8>,
    /// Enclave measurement
    pub enclave_hash: Hash256,
    /// PCR values (platform-specific)
    pub pcr_values: Vec<Hash256>,
}

/// TEE platform result identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeePlatformResult {
    AwsNitro,
    IntelSgx,
    AmdSev,
}

/// zkML proof result
#[derive(Debug, Clone)]
pub struct ZkmlProofResult {
    /// Proof bytes
    pub proof: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<u8>,
    /// Circuit identifier
    pub circuit_id: Hash256,
    /// Proof system used
    pub proof_system: ProofSystem,
}

/// Supported proof systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSystem {
    /// Groth16 (fast verification, trusted setup)
    Groth16,
    /// PLONK (universal setup)
    Plonk,
    /// Halo2 (no trusted setup)
    Halo2,
    /// EZKL (zkML-specific)
    Ezkl,
}

/// Job queue priority ordering
impl Ord for ComputeJob {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first, then earlier submission
        other
            .priority
            .cmp(&self.priority)
            .then(self.submitted_at.cmp(&other.submitted_at))
    }
}

impl PartialOrd for ComputeJob {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ComputeJob {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ComputeJob {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_creation() {
        let model_hash = sha256(b"model");
        let input_hash = sha256(b"input");
        let requester = Address::ZERO;

        let job = ComputeJob::new(model_hash, input_hash, requester);
        assert_eq!(job.status, JobStatus::Pending);
        assert!(!job.is_expired());
    }

    #[test]
    fn test_job_id_uniqueness() {
        let model_hash = sha256(b"model");
        let input_hash = sha256(b"input");
        let requester = Address::ZERO;

        let job1 = ComputeJob::new(model_hash, input_hash, requester);

        // IDs should differ due to per-job entropy in ID generation.
        std::thread::sleep(std::time::Duration::from_millis(10));
        let job2 = ComputeJob::new(model_hash, input_hash, requester);

        assert_ne!(job1.id, job2.id);
    }

    #[test]
    fn test_job_status() {
        assert!(JobStatus::Completed.is_terminal());
        assert!(JobStatus::Failed.is_terminal());
        assert!(!JobStatus::Pending.is_terminal());

        assert!(JobStatus::Pending.is_active());
        assert!(!JobStatus::Completed.is_active());
    }

    #[test]
    fn test_verification_requirements() {
        assert!(VerificationRequirement::Hybrid.requires_zkml());
        assert!(VerificationRequirement::Hybrid.requires_tee());
        assert!(!VerificationRequirement::TeeOnly.requires_zkml());
        assert!(!VerificationRequirement::ZkmlOnly.requires_tee());
    }

    #[test]
    fn test_job_priority() {
        let model_hash = sha256(b"model");
        let input_hash = sha256(b"input");

        let mut job1 = ComputeJob::new(model_hash, input_hash, Address::ZERO);
        job1.priority = 5;

        let mut job2 = ComputeJob::new(model_hash, input_hash, Address::ZERO);
        job2.priority = 10;

        // Higher priority should come first
        assert!(job2 < job1);
    }
}
