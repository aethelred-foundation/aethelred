//! Consensus Traits
//!
//! Core trait definitions for the Proof-of-Useful-Work consensus engine.
//!
//! # Design Philosophy
//!
//! Traits are designed to be:
//! - **Synchronous**: No async overhead for in-memory operations
//! - **Testable**: Easy to mock for unit testing
//! - **Flexible**: Support different backend implementations

use crate::error::ConsensusResult;
use crate::types::{Address, Epoch, EpochSeed, PoUWBlockHeader, Slot};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

// =============================================================================
// CORE CONSENSUS TRAIT
// =============================================================================

/// Core consensus trait for Proof-of-Useful-Work
pub trait Consensus: Send + Sync {
    /// Check if a validator is eligible to lead for a given slot
    ///
    /// # Arguments
    /// * `slot` - The slot to check
    /// * `address` - Validator address
    /// * `vrf_output` - VRF output bytes (32 bytes)
    ///
    /// # Returns
    /// * `true` if VRF output is below the validator's threshold
    fn is_leader(&self, slot: Slot, address: &Address, vrf_output: &[u8]) -> ConsensusResult<bool>;

    /// Verify leader credentials from a block proposer
    ///
    /// # Arguments
    /// * `slot` - The slot being proposed
    /// * `address` - Proposer address
    /// * `vrf_proof` - VRF proof bytes
    /// * `vrf_pubkey` - VRF public key
    fn verify_leader_credentials(
        &self,
        slot: Slot,
        address: &Address,
        vrf_proof: &[u8],
        vrf_pubkey: &[u8],
    ) -> ConsensusResult<bool>;

    /// Produce a VRF proof for a given slot
    ///
    /// # Arguments
    /// * `slot` - The slot to produce proof for
    /// * `seed` - The randomness seed
    ///
    /// # Returns
    /// Tuple of (proof_bytes, output_bytes)
    fn produce_vrf_proof(&self, slot: Slot, seed: &[u8]) -> ConsensusResult<(Vec<u8>, Vec<u8>)>;

    /// Get the epoch seed for leader election
    fn get_epoch_seed(&self, epoch: Epoch) -> ConsensusResult<EpochSeed>;
}

// =============================================================================
// CONSENSUS STATE TRAIT
// =============================================================================

/// Consensus state management
pub trait ConsensusState: Send + Sync {
    /// Get validator's current stake
    fn get_stake(&self, address: &Address) -> u128;

    /// Get validator's current useful work score
    fn get_useful_work_score(&self, address: &Address) -> u64;

    /// Get total weighted stake (stake * useful work multiplier for all validators)
    fn total_weighted_stake(&self) -> u128;

    /// Get the epoch seed
    fn get_epoch_seed(&self, epoch: Epoch) -> EpochSeed;

    /// Get number of active validators
    fn validator_count(&self) -> usize;

    /// Check if validator is active
    fn is_validator_active(&self, address: &Address) -> bool;
}

// =============================================================================
// LEADER ELECTION TRAIT
// =============================================================================

/// Leader election trait with useful-work-weighted stake
pub trait LeaderElection: Send + Sync {
    /// Calculate the threshold for a given stake and useful work score
    ///
    /// # Formula
    /// ```text
    /// Threshold = (MaxVrfOutput * Stake * UsefulWorkMultiplier) / TotalWeightedStake
    /// Where: UsefulWorkMultiplier = min(1 + log₁₀(1 + Score) / 6, MAX_MULTIPLIER)
    /// ```
    fn calculate_threshold(
        &self,
        stake: u128,
        useful_work_score: u64,
        total_weighted_stake: u128,
    ) -> BigUint;

    /// Calculate the useful work multiplier for a given score
    ///
    /// Uses logarithmic scaling:
    /// - Score 0: 1.0x
    /// - Score 1,000: ~1.5x
    /// - Score 1,000,000: ~2.0x
    /// - Score 1,000,000,000: ~2.5x
    /// - Score 10^12+: 5.0x (capped)
    fn compute_multiplier(&self, useful_work_score: u64) -> f64;

    /// Check if VRF output meets the threshold
    fn check_vrf_threshold(&self, vrf_output: &[u8], threshold: &BigUint) -> bool;

    /// Calculate weighted stake for a validator
    fn weighted_stake(&self, stake: u128, useful_work_score: u64) -> u128;
}

// =============================================================================
// BLOCK VALIDATOR TRAIT
// =============================================================================

/// Block validation trait
pub trait BlockValidator: Send + Sync {
    /// Validate a complete block header against its parent
    fn validate_header(
        &self,
        header: &PoUWBlockHeader,
        parent: &PoUWBlockHeader,
    ) -> ConsensusResult<()>;

    /// Validate the compute results in a block
    fn validate_compute_results(
        &self,
        header: &PoUWBlockHeader,
        results: &[ComputeResult],
    ) -> ConsensusResult<()>;
}

// =============================================================================
// COMPUTE RESULT
// =============================================================================

/// A verified compute result from an AI job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeResult {
    /// Job ID
    pub job_id: [u8; 32],

    /// Model hash (SHA-256 of model weights)
    pub model_hash: [u8; 32],

    /// Input hash (SHA-256 of input data)
    pub input_hash: [u8; 32],

    /// Output hash (SHA-256 of computation output)
    pub output_hash: [u8; 32],

    /// Complexity units (normalized FLOPS)
    pub complexity: u64,

    /// Verification method used
    pub verification_method: VerificationMethod,

    /// TEE attestation bytes (if applicable)
    pub attestation: Vec<u8>,

    /// zkML proof (if applicable)
    pub zk_proof: Option<Vec<u8>>,

    /// Validator who submitted this result
    pub validator: Address,

    /// Number of confirmations (for re-execution)
    pub confirmations: u32,
}

impl ComputeResult {
    /// Create new compute result
    pub fn new(
        job_id: [u8; 32],
        model_hash: [u8; 32],
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        complexity: u64,
        verification_method: VerificationMethod,
        validator: Address,
    ) -> Self {
        Self {
            job_id,
            model_hash,
            input_hash,
            output_hash,
            complexity,
            verification_method,
            attestation: Vec::new(),
            zk_proof: None,
            validator,
            confirmations: 1,
        }
    }

    /// Add TEE attestation
    pub fn with_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.attestation = attestation;
        self
    }

    /// Add zkML proof
    pub fn with_zk_proof(mut self, proof: Vec<u8>) -> Self {
        self.zk_proof = Some(proof);
        self
    }
}

// =============================================================================
// VERIFICATION METHOD
// =============================================================================

/// Verification method for compute results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum VerificationMethod {
    /// TEE attestation only (SGX, Nitro, SEV-SNP)
    #[default]
    TeeAttestation = 0,

    /// zkML proof only (EZKL, etc.)
    ZkProof = 1,

    /// Both TEE and zkML (highest assurance)
    Hybrid = 2,

    /// Multiple validators re-executed the computation
    ReExecution = 3,
}

impl VerificationMethod {
    /// Get the assurance level (higher = more secure)
    pub fn assurance_level(&self) -> u8 {
        match self {
            VerificationMethod::ReExecution => 1,
            VerificationMethod::TeeAttestation => 2,
            VerificationMethod::ZkProof => 3,
            VerificationMethod::Hybrid => 4,
        }
    }

    /// Get the score multiplier for this method
    pub fn score_multiplier(&self) -> f64 {
        match self {
            VerificationMethod::ReExecution => 0.8,
            VerificationMethod::TeeAttestation => 1.0,
            VerificationMethod::ZkProof => 1.5,
            VerificationMethod::Hybrid => 2.0,
        }
    }

    /// From u8 value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(VerificationMethod::TeeAttestation),
            1 => Some(VerificationMethod::ZkProof),
            2 => Some(VerificationMethod::Hybrid),
            3 => Some(VerificationMethod::ReExecution),
            _ => None,
        }
    }
}

// =============================================================================
// EPOCH HANDLER TRAIT
// =============================================================================

/// Epoch transition handler
pub trait EpochHandler: Send + Sync {
    /// Handle transition to a new epoch
    fn on_epoch_transition(&self, old_epoch: Epoch, new_epoch: Epoch)
        -> ConsensusResult<EpochSeed>;

    /// Calculate new epoch seed from accumulated randomness
    fn compute_epoch_seed(
        &self,
        epoch: Epoch,
        vrf_outputs: &[[u8; 32]],
    ) -> ConsensusResult<EpochSeed>;
}

// =============================================================================
// FINALITY GADGET TRAIT
// =============================================================================

/// Finality gadget trait
pub trait FinalityGadget: Send + Sync {
    /// Check if a block at given slot is finalized
    fn is_finalized(&self, slot: Slot) -> bool;

    /// Get the latest finalized slot
    fn latest_finalized(&self) -> Slot;

    /// Process a finality vote
    fn process_vote(
        &self,
        voter: &Address,
        slot: Slot,
        block_hash: &[u8; 32],
    ) -> ConsensusResult<()>;

    /// Get finality status for a slot
    fn finality_status(&self, slot: Slot) -> FinalityStatus;
}

/// Finality status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityStatus {
    /// Block is finalized (irreversible)
    Finalized,
    /// Block is justified (2/3+1 votes, but not finalized)
    Justified,
    /// Block is proposed but not justified
    Proposed,
    /// No block for this slot
    Empty,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_method_ordering() {
        assert!(
            VerificationMethod::Hybrid.assurance_level()
                > VerificationMethod::TeeAttestation.assurance_level()
        );
        assert!(
            VerificationMethod::ZkProof.assurance_level()
                > VerificationMethod::ReExecution.assurance_level()
        );
    }

    #[test]
    fn test_verification_method_multiplier() {
        assert!(
            VerificationMethod::Hybrid.score_multiplier()
                > VerificationMethod::TeeAttestation.score_multiplier()
        );
    }

    #[test]
    fn test_verification_method_from_u8() {
        assert_eq!(
            VerificationMethod::from_u8(0),
            Some(VerificationMethod::TeeAttestation)
        );
        assert_eq!(
            VerificationMethod::from_u8(2),
            Some(VerificationMethod::Hybrid)
        );
        assert_eq!(VerificationMethod::from_u8(255), None);
    }

    #[test]
    fn test_compute_result_builder() {
        let result = ComputeResult::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            1000,
            VerificationMethod::TeeAttestation,
            [5u8; 32],
        )
        .with_attestation(vec![1, 2, 3]);

        assert_eq!(result.attestation, vec![1, 2, 3]);
        assert!(result.zk_proof.is_none());
    }

    #[test]
    fn test_finality_status() {
        assert_ne!(FinalityStatus::Finalized, FinalityStatus::Justified);
        assert_eq!(FinalityStatus::Empty, FinalityStatus::Empty);
    }
}
