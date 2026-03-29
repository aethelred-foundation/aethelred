//! Consensus Types
//!
//! Core data types for the Proof-of-Useful-Work consensus engine.

use serde::{Deserialize, Serialize};

/// Slot number (6 seconds each)
pub type Slot = u64;

/// Epoch number (collection of slots, typically 30 days)
pub type Epoch = u64;

/// Epoch seed for VRF randomness
pub type EpochSeed = [u8; 32];

/// Hash type
pub type Hash = [u8; 32];

/// Address type
pub type Address = [u8; 32];

/// Proof-of-Useful-Work Block Header
///
/// Extended block header that includes compute provenance fields
/// required for the PoUW consensus mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUWBlockHeader {
    // =========================================================================
    // STANDARD CONSENSUS FIELDS
    // =========================================================================
    /// Hash of the parent block
    pub parent_hash: Hash,

    /// Block height
    pub height: u64,

    /// Slot number when this block was proposed
    pub slot: Slot,

    /// Epoch this block belongs to
    pub epoch: Epoch,

    /// Proposer's address
    pub proposer_address: Address,

    /// Merkle root of the state tree after applying this block
    pub state_root: Hash,

    /// Merkle root of all transactions in this block
    pub transactions_root: Hash,

    /// Merkle root of transaction receipts
    pub receipts_root: Hash,

    /// Block timestamp (Unix timestamp in seconds)
    pub timestamp: u64,

    // =========================================================================
    // AETHELRED PROOF-OF-USEFUL-WORK FIELDS
    // =========================================================================
    /// VRF proof demonstrating leader eligibility
    ///
    /// Format: [VRF Output (32 bytes)][VRF Proof (~80 bytes)]
    /// This proves the proposer was legitimately selected through the
    /// VRF lottery without revealing their secret key.
    pub vrf_proof: Vec<u8>,

    /// Merkle root of all AI computation results in this block
    ///
    /// Separated from transactions to enable light-client verification
    /// of AI work without downloading full transaction data.
    pub compute_results_root: Hash,

    /// Number of verified AI jobs in this block
    pub compute_job_count: u32,

    /// Total complexity units (normalized FLOPS) of verified AI work
    pub compute_complexity: u64,

    /// Proposer's useful work score at time of proposal
    ///
    /// Validators verify this against their local view of the
    /// Compute Reputation Table. Mismatch results in block rejection.
    pub proposer_useful_work_score: u64,

    /// Proposer's staked amount
    pub proposer_stake: u128,

    // =========================================================================
    // FINALITY FIELDS
    // =========================================================================
    /// Hash of the last justified block (for finality gadget)
    pub last_justified_hash: Hash,

    /// Slot of the last finalized block
    pub last_finalized_slot: Slot,

    // =========================================================================
    // SIGNATURE
    // =========================================================================
    /// Block signature (ECDSA + Dilithium hybrid in production)
    pub signature: Vec<u8>,
}

impl PoUWBlockHeader {
    /// Create genesis block header
    pub fn genesis(timestamp: u64) -> Self {
        Self {
            parent_hash: [0u8; 32],
            height: 0,
            slot: 0,
            epoch: 0,
            proposer_address: [0u8; 32],
            state_root: [0u8; 32],
            transactions_root: [0u8; 32],
            receipts_root: [0u8; 32],
            timestamp,
            vrf_proof: vec![],
            compute_results_root: [0u8; 32],
            compute_job_count: 0,
            compute_complexity: 0,
            proposer_useful_work_score: 0,
            proposer_stake: 0,
            last_justified_hash: [0u8; 32],
            last_finalized_slot: 0,
            signature: vec![],
        }
    }

    /// Calculate block hash
    pub fn hash(&self) -> Hash {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash all fields except signature
        hasher.update(&self.parent_hash);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.slot.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.proposer_address);
        hasher.update(&self.state_root);
        hasher.update(&self.transactions_root);
        hasher.update(&self.receipts_root);
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(&self.vrf_proof);
        hasher.update(&self.compute_results_root);
        hasher.update(&self.compute_job_count.to_le_bytes());
        hasher.update(&self.compute_complexity.to_le_bytes());
        hasher.update(&self.proposer_useful_work_score.to_le_bytes());
        hasher.update(&self.proposer_stake.to_le_bytes());
        hasher.update(&self.last_justified_hash);
        hasher.update(&self.last_finalized_slot.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Get signing message (hash without signature)
    pub fn signing_message(&self) -> Hash {
        self.hash()
    }

    /// Check if this is a genesis block
    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.parent_hash == [0u8; 32]
    }

    /// Validate basic header structure
    pub fn validate_structure(&self) -> Result<(), String> {
        // Check VRF proof length (32 byte output + ~80 byte proof)
        if !self.is_genesis() && self.vrf_proof.len() < 100 {
            return Err(format!(
                "VRF proof too short: {} bytes (expected >= 100)",
                self.vrf_proof.len()
            ));
        }

        // Check timestamp is reasonable
        if self.timestamp == 0 && !self.is_genesis() {
            return Err("Timestamp cannot be zero".into());
        }

        // Check slot matches epoch
        let expected_epoch = self.slot / crate::DEFAULT_SLOTS_PER_EPOCH;
        if self.epoch != expected_epoch && !self.is_genesis() {
            return Err(format!(
                "Epoch mismatch: expected {}, got {}",
                expected_epoch, self.epoch
            ));
        }

        Ok(())
    }
}

/// Validator registration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator address
    pub address: Address,

    /// Current stake amount
    pub stake: u128,

    /// VRF public key
    pub vrf_pubkey: Vec<u8>,

    /// Consensus public key (for signing)
    pub consensus_pubkey: Vec<u8>,

    /// Commission rate (basis points, 10000 = 100%)
    pub commission: u16,

    /// Current useful work score
    pub useful_work_score: u64,

    /// Whether validator is active
    pub active: bool,

    /// Jailed until slot (0 = not jailed)
    pub jailed_until: Slot,

    /// Registration slot
    pub registered_at: Slot,

    /// Last proposal slot
    pub last_proposal_slot: Slot,

    /// Total blocks proposed
    pub blocks_proposed: u64,

    /// Total compute jobs verified
    pub jobs_verified: u64,
}

impl ValidatorInfo {
    /// Create new validator info
    pub fn new(
        address: Address,
        stake: u128,
        vrf_pubkey: Vec<u8>,
        consensus_pubkey: Vec<u8>,
        commission: u16,
        registered_at: Slot,
    ) -> Self {
        Self {
            address,
            stake,
            vrf_pubkey,
            consensus_pubkey,
            commission,
            useful_work_score: 0,
            active: true,
            jailed_until: 0,
            registered_at,
            last_proposal_slot: 0,
            blocks_proposed: 0,
            jobs_verified: 0,
        }
    }

    /// Check if validator is eligible for election
    pub fn is_eligible(&self, current_slot: Slot) -> bool {
        self.active
            && (self.jailed_until == 0 || current_slot >= self.jailed_until)
            && self.stake >= crate::MIN_STAKE_FOR_ELECTION
    }

    /// Calculate weighted stake
    pub fn weighted_stake(&self) -> u128 {
        let multiplier = compute_multiplier(self.useful_work_score);
        (self.stake as f64 * multiplier) as u128
    }
}

/// Calculate useful work multiplier from score
///
/// Formula: min(1 + log₁₀(1 + score) / 6, MAX_MULTIPLIER)
///
/// This provides:
/// - Score 0: 1.0x multiplier
/// - Score 1,000: ~1.5x multiplier
/// - Score 1,000,000: ~2.0x multiplier
/// - Score 1,000,000,000: ~2.5x multiplier
/// - Capped at MAX_MULTIPLIER (5.0x)
pub fn compute_multiplier(useful_work_score: u64) -> f64 {
    let multiplier = 1.0 + (1.0 + useful_work_score as f64).log10() / 6.0;
    multiplier.min(crate::MAX_COMPUTE_MULTIPLIER)
}

/// Slot timing information
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SlotTiming {
    /// Slot duration in milliseconds
    pub slot_duration_ms: u64,

    /// Slots per epoch
    pub slots_per_epoch: u64,

    /// Genesis timestamp
    pub genesis_timestamp: u64,
}

impl Default for SlotTiming {
    fn default() -> Self {
        Self {
            slot_duration_ms: 6000, // 6 seconds
            slots_per_epoch: crate::DEFAULT_SLOTS_PER_EPOCH,
            genesis_timestamp: 0,
        }
    }
}

impl SlotTiming {
    /// Calculate slot for a given timestamp
    pub fn slot_for_timestamp(&self, timestamp: u64) -> Slot {
        if timestamp < self.genesis_timestamp {
            return 0;
        }
        let elapsed_ms = (timestamp - self.genesis_timestamp) * 1000;
        elapsed_ms / self.slot_duration_ms
    }

    /// Calculate timestamp for a given slot
    pub fn timestamp_for_slot(&self, slot: Slot) -> u64 {
        self.genesis_timestamp + (slot * self.slot_duration_ms / 1000)
    }

    /// Calculate epoch for a given slot
    pub fn epoch_for_slot(&self, slot: Slot) -> Epoch {
        slot / self.slots_per_epoch
    }

    /// Calculate first slot of an epoch
    pub fn first_slot_of_epoch(&self, epoch: Epoch) -> Slot {
        epoch * self.slots_per_epoch
    }

    /// Calculate last slot of an epoch
    pub fn last_slot_of_epoch(&self, epoch: Epoch) -> Slot {
        (epoch + 1) * self.slots_per_epoch - 1
    }

    /// Check if slot is the first of an epoch
    pub fn is_epoch_boundary(&self, slot: Slot) -> bool {
        slot % self.slots_per_epoch == 0
    }
}

/// Block proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    /// Block header
    pub header: PoUWBlockHeader,

    /// Transaction hashes included
    pub transaction_hashes: Vec<Hash>,

    /// Compute result hashes
    pub compute_result_hashes: Vec<Hash>,
}

/// Vote for finality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityVote {
    /// Voter address
    pub voter: Address,

    /// Voted block hash
    pub block_hash: Hash,

    /// Slot of the block
    pub slot: Slot,

    /// Signature
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_multiplier() {
        // No compute: 1.0x
        assert!((compute_multiplier(0) - 1.0).abs() < 0.01);

        // Some compute: ~1.5x
        let mult_1k = compute_multiplier(1000);
        assert!(mult_1k > 1.4 && mult_1k < 1.6);

        // High compute: ~2x
        let mult_1m = compute_multiplier(1_000_000);
        assert!(mult_1m > 1.9 && mult_1m < 2.1);

        // u64::MAX yields ~4.2x with log10/6 scaling
        let mult_max = compute_multiplier(u64::MAX);
        assert!(mult_max > 4.0 && mult_max < 4.5);
    }

    #[test]
    fn test_genesis_header() {
        let genesis = PoUWBlockHeader::genesis(1234567890);
        assert!(genesis.is_genesis());
        assert_eq!(genesis.height, 0);
        assert_eq!(genesis.slot, 0);
    }

    #[test]
    fn test_block_hash() {
        let header = PoUWBlockHeader::genesis(1234567890);
        let hash1 = header.hash();
        let hash2 = header.hash();
        assert_eq!(hash1, hash2); // Deterministic
    }

    #[test]
    fn test_slot_timing() {
        let timing = SlotTiming {
            slot_duration_ms: 6000,
            slots_per_epoch: 100,
            genesis_timestamp: 1000,
        };

        assert_eq!(timing.slot_for_timestamp(1000), 0);
        assert_eq!(timing.slot_for_timestamp(1006), 1);
        assert_eq!(timing.epoch_for_slot(50), 0);
        assert_eq!(timing.epoch_for_slot(100), 1);
        assert!(timing.is_epoch_boundary(0));
        assert!(timing.is_epoch_boundary(100));
        assert!(!timing.is_epoch_boundary(50));
    }

    #[test]
    fn test_validator_eligibility() {
        let mut validator = ValidatorInfo::new(
            [1u8; 32],
            crate::MIN_STAKE_FOR_ELECTION,
            vec![],
            vec![],
            1000,
            0,
        );

        assert!(validator.is_eligible(100));

        // Jail validator
        validator.jailed_until = 200;
        assert!(!validator.is_eligible(100));
        assert!(validator.is_eligible(200));

        // Insufficient stake
        validator.jailed_until = 0;
        validator.stake = 100;
        assert!(!validator.is_eligible(100));
    }

    #[test]
    fn test_weighted_stake() {
        let mut validator = ValidatorInfo::new(
            [1u8; 32],
            1_000_000_000_000, // 1000 tokens
            vec![],
            vec![],
            1000,
            0,
        );

        // No compute score: weighted = base
        validator.useful_work_score = 0;
        let base = validator.weighted_stake();
        assert_eq!(base, validator.stake);

        // With useful work score: weighted > base
        validator.useful_work_score = 1_000_000;
        let boosted = validator.weighted_stake();
        assert!(boosted > validator.stake);
        assert!(boosted < validator.stake * 3); // Should be ~2x, definitely < 3x
    }

    #[test]
    fn test_header_signing_message() {
        let header = PoUWBlockHeader::genesis(999);
        let msg = header.signing_message();
        assert_eq!(msg, header.hash());
    }

    #[test]
    fn test_header_validate_structure_genesis_ok() {
        let header = PoUWBlockHeader::genesis(1234);
        assert!(header.validate_structure().is_ok());
    }

    #[test]
    fn test_header_validate_structure_short_vrf_proof() {
        let mut header = PoUWBlockHeader::genesis(1234);
        header.height = 1;
        header.parent_hash = [1u8; 32];
        header.timestamp = 100;
        header.vrf_proof = vec![0u8; 50]; // too short
        assert!(header.validate_structure().is_err());
        assert!(header
            .validate_structure()
            .unwrap_err()
            .contains("VRF proof too short"));
    }

    #[test]
    fn test_header_validate_structure_zero_timestamp() {
        let mut header = PoUWBlockHeader::genesis(1234);
        header.height = 1;
        header.parent_hash = [1u8; 32];
        header.timestamp = 0;
        header.vrf_proof = vec![0u8; 120];
        assert!(header.validate_structure().is_err());
        assert!(header
            .validate_structure()
            .unwrap_err()
            .contains("Timestamp"));
    }

    #[test]
    fn test_header_validate_structure_epoch_mismatch() {
        let mut header = PoUWBlockHeader::genesis(1234);
        header.height = 1;
        header.parent_hash = [1u8; 32];
        header.timestamp = 100;
        header.vrf_proof = vec![0u8; 120];
        header.slot = 50;
        header.epoch = 999; // wrong epoch
        assert!(header.validate_structure().is_err());
        assert!(header
            .validate_structure()
            .unwrap_err()
            .contains("Epoch mismatch"));
    }

    #[test]
    fn test_header_validate_structure_valid_non_genesis() {
        let mut header = PoUWBlockHeader::genesis(1234);
        header.height = 1;
        header.parent_hash = [1u8; 32];
        header.timestamp = 100;
        header.vrf_proof = vec![0u8; 120];
        header.slot = 50;
        header.epoch = 50 / crate::DEFAULT_SLOTS_PER_EPOCH;
        assert!(header.validate_structure().is_ok());
    }

    #[test]
    fn test_header_is_not_genesis() {
        let mut header = PoUWBlockHeader::genesis(1234);
        header.height = 1;
        assert!(!header.is_genesis());

        let mut header2 = PoUWBlockHeader::genesis(1234);
        header2.parent_hash = [1u8; 32];
        assert!(!header2.is_genesis());
    }

    #[test]
    fn test_slot_timing_default() {
        let timing = SlotTiming::default();
        assert_eq!(timing.slot_duration_ms, 6000);
        assert_eq!(timing.genesis_timestamp, 0);
    }

    #[test]
    fn test_slot_timing_before_genesis() {
        let timing = SlotTiming {
            slot_duration_ms: 6000,
            slots_per_epoch: 100,
            genesis_timestamp: 1000,
        };
        assert_eq!(timing.slot_for_timestamp(999), 0);
    }

    #[test]
    fn test_slot_timing_timestamp_for_slot() {
        let timing = SlotTiming {
            slot_duration_ms: 6000,
            slots_per_epoch: 100,
            genesis_timestamp: 1000,
        };
        assert_eq!(timing.timestamp_for_slot(0), 1000);
        assert_eq!(timing.timestamp_for_slot(1), 1006);
    }

    #[test]
    fn test_slot_timing_first_last_slot_of_epoch() {
        let timing = SlotTiming {
            slot_duration_ms: 6000,
            slots_per_epoch: 100,
            genesis_timestamp: 0,
        };
        assert_eq!(timing.first_slot_of_epoch(0), 0);
        assert_eq!(timing.first_slot_of_epoch(1), 100);
        assert_eq!(timing.last_slot_of_epoch(0), 99);
        assert_eq!(timing.last_slot_of_epoch(1), 199);
    }

    #[test]
    fn test_validator_inactive_not_eligible() {
        let mut validator = ValidatorInfo::new(
            [1u8; 32],
            crate::MIN_STAKE_FOR_ELECTION,
            vec![],
            vec![],
            1000,
            0,
        );
        validator.active = false;
        assert!(!validator.is_eligible(100));
    }

    #[test]
    fn test_compute_multiplier_boundaries() {
        // Score 0: exactly 1.0
        let m0 = compute_multiplier(0);
        assert!((m0 - 1.0).abs() < 0.01);

        // Score 1 billion: ~2.5x
        let m1b = compute_multiplier(1_000_000_000);
        assert!(m1b > 2.4 && m1b < 2.6);

        // Monotonically increasing
        let m100 = compute_multiplier(100);
        let m10k = compute_multiplier(10000);
        let m10m = compute_multiplier(10_000_000);
        assert!(m100 < m10k);
        assert!(m10k < m10m);
        assert!(m10m < m1b);
    }
}
