//! Common Types for System Contracts
//!
//! Shared type definitions used across all system contracts.

use serde::{Deserialize, Serialize};
use std::fmt;

// =============================================================================
// BASIC TYPES
// =============================================================================

/// 32-byte address
pub type Address = [u8; 32];

/// 32-byte hash
pub type Hash = [u8; 32];

/// Job identifier
pub type JobId = [u8; 32];

/// Token amount (18 decimals, like ETH)
pub type TokenAmount = u128;

/// Decentralized Identifier
pub type Did = String;

/// Signature bytes
pub type Signature = Vec<u8>;

// =============================================================================
// JOB TYPES
// =============================================================================

/// Job status in the lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum JobStatus {
    /// Job submitted, waiting for assignment
    Submitted = 0,
    /// Job assigned to a prover
    Assigned = 1,
    /// Prover is executing the computation
    Proving = 2,
    /// Proof submitted, awaiting verification
    Verifying = 3,
    /// Job verified and settled
    Verified = 4,
    /// Job completed and rewards distributed
    Settled = 5,
    /// Job expired (SLA timeout)
    Expired = 6,
    /// Job cancelled by requester
    Cancelled = 7,
    /// Job failed verification
    Failed = 8,
    /// Job disputed
    Disputed = 9,
}

impl JobStatus {
    /// Check if job is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            JobStatus::Settled | JobStatus::Expired | JobStatus::Cancelled | JobStatus::Failed
        )
    }

    /// Check if job can be cancelled
    pub fn can_cancel(&self) -> bool {
        matches!(self, JobStatus::Submitted | JobStatus::Assigned)
    }

    /// Check if job is active
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            JobStatus::Submitted | JobStatus::Assigned | JobStatus::Proving | JobStatus::Verifying
        )
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(JobStatus::Submitted),
            1 => Some(JobStatus::Assigned),
            2 => Some(JobStatus::Proving),
            3 => Some(JobStatus::Verifying),
            4 => Some(JobStatus::Verified),
            5 => Some(JobStatus::Settled),
            6 => Some(JobStatus::Expired),
            7 => Some(JobStatus::Cancelled),
            8 => Some(JobStatus::Failed),
            9 => Some(JobStatus::Disputed),
            _ => None,
        }
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobStatus::Submitted => write!(f, "SUBMITTED"),
            JobStatus::Assigned => write!(f, "ASSIGNED"),
            JobStatus::Proving => write!(f, "PROVING"),
            JobStatus::Verifying => write!(f, "VERIFYING"),
            JobStatus::Verified => write!(f, "VERIFIED"),
            JobStatus::Settled => write!(f, "SETTLED"),
            JobStatus::Expired => write!(f, "EXPIRED"),
            JobStatus::Cancelled => write!(f, "CANCELLED"),
            JobStatus::Failed => write!(f, "FAILED"),
            JobStatus::Disputed => write!(f, "DISPUTED"),
        }
    }
}

/// Job priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum JobPriority {
    /// Low priority (default)
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority (costs more)
    High = 2,
    /// Urgent (costs significantly more)
    Urgent = 3,
}

impl Default for JobPriority {
    fn default() -> Self {
        JobPriority::Normal
    }
}

impl JobPriority {
    /// Get the fee multiplier for this priority
    pub fn fee_multiplier(&self) -> f64 {
        match self {
            JobPriority::Low => 0.8,
            JobPriority::Normal => 1.0,
            JobPriority::High => 1.5,
            JobPriority::Urgent => 2.5,
        }
    }

    /// Get the SLA multiplier (lower = faster required)
    pub fn sla_multiplier(&self) -> f64 {
        match self {
            JobPriority::Low => 2.0,
            JobPriority::Normal => 1.0,
            JobPriority::High => 0.5,
            JobPriority::Urgent => 0.25,
        }
    }
}

/// Verification method for job proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum VerificationMethod {
    /// TEE attestation (SGX, Nitro, SEV)
    TeeAttestation = 0,
    /// Zero-knowledge proof (zkML)
    ZkProof = 1,
    /// Both TEE and ZK (highest assurance)
    Hybrid = 2,
    /// Multiple validators re-execute
    ReExecution = 3,
}

impl Default for VerificationMethod {
    fn default() -> Self {
        // SQ01: Enterprise default - Hybrid verification required
        VerificationMethod::Hybrid
    }
}

// =============================================================================
// ENTERPRISE MODE CONFIGURATION
// =============================================================================

/// Enterprise-mode verification policy.
///
/// When enabled, only `Hybrid` (TEE + ZK) verification is accepted.
/// TEE-only and ZkProof-only submissions are rejected to ensure the highest
/// assurance level for all computations.
///
/// The zkML-specific guards (`require_registered_circuit`,
/// `require_domain_binding`) eliminate soft-acceptance paths so that
/// enterprise deployments always perform real proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseModeConfig {
    /// Whether enterprise mode is active
    pub enabled: bool,
    /// The only allowed verification method in enterprise mode
    pub required_method: VerificationMethod,
    /// Whether zkML fallback is allowed (must be false in enterprise mode)
    pub allow_zkml_fallback: bool,
    /// Require that zkML proof circuit hashes (`vk_hash`) are pre-registered.
    /// When `true`, the proof's `vk_hash` must appear in the registry's set
    /// of known verifying keys.
    pub require_registered_circuit: bool,
    /// Require output-commitment domain binding for zkML proofs.
    /// When `true`, the job must carry an `output_hash` and the proof's
    /// third public input must match it, binding the proof to a concrete
    /// inference result.
    pub require_domain_binding: bool,
}

impl Default for EnterpriseModeConfig {
    fn default() -> Self {
        EnterpriseModeConfig {
            enabled: true,
            required_method: VerificationMethod::Hybrid,
            allow_zkml_fallback: false,
            require_registered_circuit: true,
            require_domain_binding: true,
        }
    }
}

impl EnterpriseModeConfig {
    /// Validate that a verification method is allowed under enterprise policy.
    /// Returns an error message if the method is rejected.
    pub fn validate_method(&self, method: VerificationMethod) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if method != self.required_method {
            return Err(format!(
                "enterprise mode requires {:?} verification, got {:?}",
                self.required_method, method
            ));
        }
        Ok(())
    }
}

// =============================================================================
// PROOF TYPES
// =============================================================================

/// Proof of computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// Proof type
    pub method: VerificationMethod,

    /// TEE attestation (if applicable)
    pub tee_attestation: Option<TeeAttestation>,

    /// ZK proof (if applicable)
    pub zk_proof: Option<ZkProof>,

    /// Output hash (commitment to the result)
    pub output_hash: Hash,

    /// Execution metadata
    pub metadata: ProofMetadata,
}

impl Proof {
    /// Check if this proof is enterprise-compliant.
    ///
    /// Enterprise compliance requires:
    /// 1. Verification method is `Hybrid`
    /// 2. Both `tee_attestation` and `zk_proof` are present (not None)
    pub fn is_enterprise_compliant(&self) -> bool {
        self.method == VerificationMethod::Hybrid
            && self.tee_attestation.is_some()
            && self.zk_proof.is_some()
    }
}

/// TEE attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestation {
    /// TEE type (SGX, Nitro, SEV)
    pub tee_type: TeeType,
    /// Raw attestation bytes
    pub attestation: Vec<u8>,
    /// MRENCLAVE/measurement
    pub measurement: Hash,
    /// Timestamp
    pub timestamp: u64,
}

/// TEE type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TeeType {
    IntelSgx,
    AwsNitro,
    AmdSev,
}

/// Zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Proof system (Groth16, PLONK, etc.)
    pub system: ZkSystem,
    /// Proof bytes
    pub proof: Vec<u8>,
    /// Public inputs
    pub public_inputs: Vec<Hash>,
    /// Verification key hash
    pub vk_hash: Hash,
}

/// ZK proof system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ZkSystem {
    Groth16,
    Plonk,
    Stark,
    Ezkl,
    Halo2,
}

/// Proof metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Memory used in bytes
    pub memory_used: u64,
    /// Number of inference operations
    pub inference_ops: u64,
    /// Model complexity (estimated FLOPS)
    pub complexity: u64,
}

// =============================================================================
// STAKING TYPES
// =============================================================================

/// Stake role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StakeRole {
    /// Validator (consensus participant)
    Validator = 0,
    /// Compute node (prover)
    ComputeNode = 1,
    /// Delegator (delegates to validator)
    Delegator = 2,
}

impl StakeRole {
    /// Get minimum stake for this role
    pub fn min_stake(&self) -> TokenAmount {
        match self {
            StakeRole::Validator => 10_000_000_000_000_000_000_000, // 10,000 AETHEL
            StakeRole::ComputeNode => 50_000_000_000_000_000_000_000, // 50,000 AETHEL
            StakeRole::Delegator => 100_000_000_000_000_000_000,    // 100 AETHEL
        }
    }
}

/// Sanctions list update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctionsUpdate {
    /// Addresses to add
    pub add: Vec<Address>,
    /// Addresses to remove
    pub remove: Vec<Address>,
    /// Update timestamp
    pub timestamp: u64,
    /// Authority signature
    pub signature: Signature,
}

// =============================================================================
// TRANSACTION TYPES
// =============================================================================

/// Transaction for compliance checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Sender address
    pub sender: Address,
    /// Sender DID (if registered)
    pub sender_did: Option<Did>,
    /// Receiver address
    pub receiver: Address,
    /// Receiver DID (if registered)
    pub receiver_did: Option<Did>,
    /// Transaction value
    pub value: TokenAmount,
    /// Transaction data
    pub data: Vec<u8>,
    /// Compliance tags
    pub tags: Vec<ComplianceTag>,
    /// Nonce
    pub nonce: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: TokenAmount,
}

impl Transaction {
    /// Check if transaction has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.name == tag)
    }

    /// Get all tag names
    pub fn tag_names(&self) -> Vec<&str> {
        self.tags.iter().map(|t| t.name.as_str()).collect()
    }
}

/// Compliance tag for transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTag {
    /// Tag name (e.g., "MEDICAL_DATA", "FINANCIAL", "PII")
    pub name: String,
    /// Tag value/metadata
    pub value: Option<String>,
}

// =============================================================================
// SUBMIT PARAMS
// =============================================================================

/// Compliance standard requirement (re-exported as u8 for serialization)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ComplianceRequirement {
    GdprEu = 1,
    HipaaUs = 2,
    OfacSanctions = 3,
    CcpaCa = 4,
    PdpaSg = 5,
    UaeDpl = 6,
    BaselIii = 7,
    Aml = 8,
}

/// Parameters for submitting a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitJobParams {
    /// Job requester
    pub requester: Address,
    /// Model hash
    pub model_hash: Hash,
    /// Input hash
    pub input_hash: Hash,
    /// Maximum bid amount (fee willing to pay)
    pub max_bid: TokenAmount,
    /// Bid amount (fee willing to pay) - alias for max_bid
    pub bid_amount: TokenAmount,
    /// Required verification method
    pub verification_method: VerificationMethod,
    /// Job priority
    pub priority: JobPriority,
    /// Custom SLA timeout (0 = use default)
    pub sla_timeout: u64,
    /// Compliance tags
    pub tags: Vec<ComplianceTag>,
    /// Encrypted input data (for privacy)
    pub encrypted_input: Option<Vec<u8>>,
    /// Callback address (optional)
    pub callback: Option<Address>,

    // Compliance fields
    /// Data provider (whose data is being processed)
    pub data_provider: Option<Address>,
    /// Required compliance standards
    pub required_compliance: Vec<ComplianceRequirement>,
    /// Jurisdiction code (ISO 3166-1 alpha-2)
    pub jurisdiction: Option<String>,
}

impl SubmitJobParams {
    /// Convert to transaction for compliance checking
    pub fn as_transaction(&self) -> Transaction {
        Transaction {
            sender: self.requester,
            sender_did: None,
            receiver: super::JOB_REGISTRY_ADDRESS,
            receiver_did: None,
            value: self.bid_amount,
            data: vec![],
            tags: self.tags.clone(),
            nonce: 0,
            gas_limit: 1_000_000,
            gas_price: 0,
        }
    }
}

/// Parameters for submitting a proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofParams {
    /// Job ID
    pub job_id: JobId,
    /// Prover address
    pub prover: Address,
    /// Proof
    pub proof: Proof,
    /// Result data (encrypted if required)
    pub result: Vec<u8>,
}

// =============================================================================
// RESULT TYPES
// =============================================================================

/// Result of job submission
#[derive(Debug, Clone)]
pub struct JobSubmitResult {
    /// Assigned job ID
    pub job_id: JobId,
    /// Escrowed amount
    pub escrowed: TokenAmount,
    /// SLA deadline
    pub sla_deadline: u64,
}

/// Result of job assignment
#[derive(Debug, Clone)]
pub struct JobAssignResult {
    /// Job ID
    pub job_id: JobId,
    /// Assigned prover
    pub prover: Address,
    /// Assignment timestamp
    pub assigned_at: u64,
}

/// Result of proof submission
#[derive(Debug, Clone)]
pub struct ProofSubmitResult {
    /// Job ID
    pub job_id: JobId,
    /// Verification passed
    pub verified: bool,
    /// Prover reward
    pub prover_reward: TokenAmount,
    /// Validator reward
    pub validator_reward: TokenAmount,
    /// Amount burned
    pub burned: TokenAmount,
}

/// Result of job cancellation
#[derive(Debug, Clone)]
pub struct JobCancelResult {
    /// Job ID
    pub job_id: JobId,
    /// Refunded amount
    pub refunded: TokenAmount,
    /// Cancellation fee charged
    pub cancellation_fee: TokenAmount,
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/// Generate job ID from parameters
pub fn generate_job_id(
    requester: &Address,
    model_hash: &Hash,
    input_hash: &Hash,
    nonce: u64,
) -> JobId {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"aethelred-job-v1:");
    hasher.update(requester);
    hasher.update(model_hash);
    hasher.update(input_hash);
    hasher.update(&nonce.to_le_bytes());

    let result = hasher.finalize();
    let mut job_id = [0u8; 32];
    job_id.copy_from_slice(&result);
    job_id
}

/// Zero address
pub const ZERO_ADDRESS: Address = [0u8; 32];

/// Check if address is zero
pub fn is_zero_address(addr: &Address) -> bool {
    addr == &ZERO_ADDRESS
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_status_terminal() {
        assert!(JobStatus::Settled.is_terminal());
        assert!(JobStatus::Expired.is_terminal());
        assert!(!JobStatus::Submitted.is_terminal());
        assert!(!JobStatus::Proving.is_terminal());
    }

    #[test]
    fn test_job_status_can_cancel() {
        assert!(JobStatus::Submitted.can_cancel());
        assert!(JobStatus::Assigned.can_cancel());
        assert!(!JobStatus::Proving.can_cancel());
        assert!(!JobStatus::Settled.can_cancel());
    }

    #[test]
    fn test_priority_multipliers() {
        assert!(JobPriority::Urgent.fee_multiplier() > JobPriority::Normal.fee_multiplier());
        assert!(JobPriority::Urgent.sla_multiplier() < JobPriority::Normal.sla_multiplier());
    }

    #[test]
    fn test_generate_job_id() {
        let requester = [1u8; 32];
        let model_hash = [2u8; 32];
        let input_hash = [3u8; 32];

        let id1 = generate_job_id(&requester, &model_hash, &input_hash, 1);
        let id2 = generate_job_id(&requester, &model_hash, &input_hash, 2);

        assert_ne!(id1, id2);

        // Same inputs = same ID
        let id1_again = generate_job_id(&requester, &model_hash, &input_hash, 1);
        assert_eq!(id1, id1_again);
    }

    #[test]
    fn test_stake_role_min_stake() {
        assert!(StakeRole::ComputeNode.min_stake() > StakeRole::Validator.min_stake());
        assert!(StakeRole::Validator.min_stake() > StakeRole::Delegator.min_stake());
    }

    #[test]
    fn test_enterprise_default_is_hybrid() {
        // SQ01: Enterprise default verification method must be Hybrid
        let default_method = VerificationMethod::default();
        assert_eq!(
            default_method,
            VerificationMethod::Hybrid,
            "enterprise default verification method must be Hybrid"
        );
    }

    #[test]
    fn test_enterprise_mode_config_defaults() {
        let config = EnterpriseModeConfig::default();
        assert!(config.enabled, "enterprise mode must be enabled by default");
        assert_eq!(
            config.required_method,
            VerificationMethod::Hybrid,
            "enterprise required method must be Hybrid"
        );
        assert!(
            !config.allow_zkml_fallback,
            "zkML fallback must be disabled in enterprise mode"
        );
    }

    #[test]
    fn test_enterprise_mode_rejects_tee_only() {
        let config = EnterpriseModeConfig::default();
        let result = config.validate_method(VerificationMethod::TeeAttestation);
        assert!(
            result.is_err(),
            "enterprise mode must reject TEE-only verification"
        );
    }

    #[test]
    fn test_enterprise_mode_rejects_zkproof_only() {
        let config = EnterpriseModeConfig::default();
        let result = config.validate_method(VerificationMethod::ZkProof);
        assert!(
            result.is_err(),
            "enterprise mode must reject ZkProof-only verification"
        );
    }

    #[test]
    fn test_enterprise_mode_accepts_hybrid() {
        let config = EnterpriseModeConfig::default();
        let result = config.validate_method(VerificationMethod::Hybrid);
        assert!(
            result.is_ok(),
            "enterprise mode must accept Hybrid verification"
        );
    }

    #[test]
    fn test_enterprise_mode_disabled_allows_all() {
        let config = EnterpriseModeConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(config.validate_method(VerificationMethod::TeeAttestation).is_ok());
        assert!(config.validate_method(VerificationMethod::ZkProof).is_ok());
        assert!(config.validate_method(VerificationMethod::Hybrid).is_ok());
        assert!(config.validate_method(VerificationMethod::ReExecution).is_ok());
    }
}
