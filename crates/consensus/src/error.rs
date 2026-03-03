//! Consensus Error Types
//!
//! Comprehensive error handling for the Proof-of-Useful-Work consensus engine.

use thiserror::Error;

/// Consensus errors
#[derive(Error, Debug, Clone)]
pub enum ConsensusError {
    // =========================================================================
    // VRF ERRORS
    // =========================================================================

    /// VRF proof verification failed
    #[error("VRF proof verification failed: {reason}")]
    VrfVerificationFailed { reason: String },

    /// VRF proof is malformed
    #[error("Malformed VRF proof: expected {expected} bytes, got {actual}")]
    MalformedVrfProof { expected: usize, actual: usize },

    /// VRF key is invalid
    #[error("Invalid VRF key: {0}")]
    InvalidVrfKey(String),

    /// VRF output does not meet threshold
    #[error("VRF output {output_hex} exceeds threshold {threshold_hex}")]
    VrfThresholdNotMet { output_hex: String, threshold_hex: String },

    // =========================================================================
    // LEADER ELECTION ERRORS
    // =========================================================================

    /// Not eligible for leader election
    #[error("Validator {address} not eligible: {reason}")]
    NotEligible { address: String, reason: String },

    /// Insufficient stake
    #[error("Insufficient stake: required {required}, has {actual}")]
    InsufficientStake { required: u128, actual: u128 },

    /// Validator not registered
    #[error("Validator {address} not registered in active set")]
    ValidatorNotRegistered { address: String },

    /// Validator is jailed
    #[error("Validator {address} is jailed until slot {until_slot}")]
    ValidatorJailed { address: String, until_slot: u64 },

    /// Double proposal in same slot
    #[error("Double proposal detected: validator {address} already proposed in slot {slot}")]
    DoubleProposal { address: String, slot: u64 },

    // =========================================================================
    // BLOCK VALIDATION ERRORS
    // =========================================================================

    /// Invalid block header
    #[error("Invalid block header: {0}")]
    InvalidBlockHeader(String),

    /// Parent block not found
    #[error("Parent block {parent_hash} not found")]
    ParentNotFound { parent_hash: String },

    /// Invalid slot progression
    #[error("Invalid slot: expected > {expected}, got {actual}")]
    InvalidSlot { expected: u64, actual: u64 },

    /// Invalid state root
    #[error("State root mismatch: expected {expected}, computed {computed}")]
    InvalidStateRoot { expected: String, computed: String },

    /// Invalid compute results root
    #[error("Compute results root mismatch: expected {expected}, computed {computed}")]
    InvalidComputeResultsRoot { expected: String, computed: String },

    /// Useful work score mismatch
    #[error("Useful work score mismatch for {address}: claimed {claimed}, actual {actual}")]
    UsefulWorkScoreMismatch { address: String, claimed: u64, actual: u64 },

    /// Block timestamp invalid
    #[error("Invalid block timestamp: {reason}")]
    InvalidTimestamp { reason: String },

    // =========================================================================
    // USEFUL WORK ERRORS (PoUW)
    // =========================================================================

    /// Suspicious activity detected
    #[error("Suspicious activity for {address}: {reason}")]
    SuspiciousActivity { address: String, reason: String },

    /// Invalid useful work result
    #[error("Invalid useful work result: {0}")]
    InvalidUsefulWorkResult(String),

    /// AI proof verification failed
    #[error("AI proof verification failed: {reason}")]
    AiProofVerificationFailed { reason: String },

    /// TEE attestation verification failed
    #[error("TEE attestation verification failed: {reason}")]
    TeeAttestationFailed { reason: String },

    /// zkML proof verification failed
    #[error("zkML proof verification failed: {reason}")]
    ZkmlProofFailed { reason: String },

    /// Category not supported
    #[error("Utility category {category} not supported for this operation")]
    UnsupportedCategory { category: String },

    // =========================================================================
    // REPUTATION ERRORS
    // =========================================================================

    /// Reputation update failed
    #[error("Failed to update reputation for {address}: {reason}")]
    ReputationUpdateFailed { address: String, reason: String },

    /// Invalid job result
    #[error("Invalid job result: {0}")]
    InvalidJobResult(String),

    /// Reputation data corrupted
    #[error("Reputation data corrupted: {0}")]
    ReputationCorrupted(String),

    // =========================================================================
    // EPOCH ERRORS
    // =========================================================================

    /// Epoch transition error
    #[error("Epoch transition failed: {0}")]
    EpochTransitionFailed(String),

    /// Invalid epoch seed
    #[error("Invalid epoch seed: {0}")]
    InvalidEpochSeed(String),

    /// Epoch boundary not reached
    #[error("Epoch boundary not reached: current slot {current}, boundary {boundary}")]
    EpochBoundaryNotReached { current: u64, boundary: u64 },

    // =========================================================================
    // FINALITY ERRORS
    // =========================================================================

    /// Block not finalized
    #[error("Block at slot {slot} not finalized")]
    NotFinalized { slot: u64 },

    /// Conflicting finalization
    #[error("Conflicting finalization: {0}")]
    ConflictingFinalization(String),

    /// Insufficient attestations for finality
    #[error("Insufficient attestations: required {required}%, got {actual}%")]
    InsufficientAttestations { required: u64, actual: u64 },

    // =========================================================================
    // SYSTEM ERRORS
    // =========================================================================

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// State access error
    #[error("State access error: {0}")]
    StateAccess(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Internal error
    #[error("Internal consensus error: {0}")]
    Internal(String),

    /// Timeout
    #[error("Consensus timeout: {operation} exceeded {timeout_ms}ms")]
    Timeout { operation: String, timeout_ms: u64 },

    // =========================================================================
    // ADDITIONAL COMPATIBILITY ERRORS
    // =========================================================================

    /// Not a validator
    #[error("Node is not configured as a validator")]
    NotValidator,

    /// Validator not found
    #[error("Validator not found")]
    ValidatorNotFound([u8; 32]),

    /// Validator ineligible
    #[error("Validator is ineligible for this operation")]
    ValidatorIneligible([u8; 32]),

    /// Invalid leader credentials
    #[error("Invalid leader credentials: {0}")]
    InvalidLeaderCredentials(String),

    /// Invalid parent hash
    #[error("Invalid parent hash")]
    InvalidParentHash { expected: [u8; 32], got: [u8; 32] },

    /// Block validation error
    #[error("Block validation failed: {0}")]
    BlockValidation(String),

    /// Slot validation error
    #[error("Slot validation failed: {0}")]
    SlotValidation(String),

    /// Timestamp validation error
    #[error("Timestamp validation failed: {0}")]
    TimestampValidation(String),

    /// VRF validation error
    #[error("VRF validation failed: {0}")]
    VrfValidation(String),

    /// Compute validation error
    #[error("Compute validation failed: {0}")]
    ComputeValidation(String),

    /// Finality validation error
    #[error("Finality validation failed: {0}")]
    FinalityValidation(String),
}

/// Result type for consensus operations
pub type ConsensusResult<T> = Result<T, ConsensusError>;

impl ConsensusError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            ConsensusError::VrfThresholdNotMet { .. } |
            ConsensusError::NotEligible { .. } |
            ConsensusError::InsufficientStake { .. } |
            ConsensusError::Timeout { .. }
        )
    }

    /// Check if error should result in slashing
    pub fn is_slashable(&self) -> bool {
        matches!(
            self,
            ConsensusError::DoubleProposal { .. } |
            ConsensusError::ConflictingFinalization(_)
        )
    }

    /// Get error code for on-chain reporting
    pub fn error_code(&self) -> u32 {
        match self {
            ConsensusError::VrfVerificationFailed { .. } => 1001,
            ConsensusError::MalformedVrfProof { .. } => 1002,
            ConsensusError::InvalidVrfKey(_) => 1003,
            ConsensusError::VrfThresholdNotMet { .. } => 1004,

            ConsensusError::NotEligible { .. } => 2001,
            ConsensusError::InsufficientStake { .. } => 2002,
            ConsensusError::ValidatorNotRegistered { .. } => 2003,
            ConsensusError::ValidatorJailed { .. } => 2004,
            ConsensusError::DoubleProposal { .. } => 2005,

            ConsensusError::InvalidBlockHeader(_) => 3001,
            ConsensusError::ParentNotFound { .. } => 3002,
            ConsensusError::InvalidSlot { .. } => 3003,
            ConsensusError::InvalidStateRoot { .. } => 3004,
            ConsensusError::InvalidComputeResultsRoot { .. } => 3005,
            ConsensusError::UsefulWorkScoreMismatch { .. } => 3006,
            ConsensusError::InvalidTimestamp { .. } => 3007,

            ConsensusError::ReputationUpdateFailed { .. } => 4001,
            ConsensusError::InvalidJobResult(_) => 4002,
            ConsensusError::ReputationCorrupted(_) => 4003,

            ConsensusError::EpochTransitionFailed(_) => 5001,
            ConsensusError::InvalidEpochSeed(_) => 5002,
            ConsensusError::EpochBoundaryNotReached { .. } => 5003,

            ConsensusError::NotFinalized { .. } => 6001,
            ConsensusError::ConflictingFinalization(_) => 6002,
            ConsensusError::InsufficientAttestations { .. } => 6003,

            ConsensusError::Config(_) => 9001,
            ConsensusError::StateAccess(_) => 9002,
            ConsensusError::Crypto(_) => 9003,
            ConsensusError::Internal(_) => 9004,
            ConsensusError::Timeout { .. } => 9005,

            // PoUW errors (7xxx)
            ConsensusError::SuspiciousActivity { .. } => 7002,
            ConsensusError::InvalidUsefulWorkResult(_) => 7003,
            ConsensusError::AiProofVerificationFailed { .. } => 7004,
            ConsensusError::TeeAttestationFailed { .. } => 7005,
            ConsensusError::ZkmlProofFailed { .. } => 7006,
            ConsensusError::UnsupportedCategory { .. } => 7007,

            // Compatibility errors (8xxx)
            ConsensusError::NotValidator => 8001,
            ConsensusError::ValidatorNotFound(_) => 8002,
            ConsensusError::ValidatorIneligible(_) => 8003,
            ConsensusError::InvalidLeaderCredentials(_) => 8004,
            ConsensusError::InvalidParentHash { .. } => 8005,
            ConsensusError::BlockValidation(_) => 8006,
            ConsensusError::SlotValidation(_) => 8007,
            ConsensusError::TimestampValidation(_) => 8008,
            ConsensusError::VrfValidation(_) => 8009,
            ConsensusError::ComputeValidation(_) => 8010,
            ConsensusError::FinalityValidation(_) => 8011,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recoverable() {
        let recoverable = ConsensusError::InsufficientStake {
            required: 1000,
            actual: 100,
        };
        assert!(recoverable.is_recoverable());

        let not_recoverable = ConsensusError::DoubleProposal {
            address: "test".into(),
            slot: 1,
        };
        assert!(!not_recoverable.is_recoverable());
    }

    #[test]
    fn test_error_recoverable_all_variants() {
        // All recoverable error types
        assert!(ConsensusError::VrfThresholdNotMet {
            output_hex: "abc".into(), threshold_hex: "def".into(),
        }.is_recoverable());
        assert!(ConsensusError::NotEligible {
            address: "v1".into(), reason: "too new".into(),
        }.is_recoverable());
        assert!(ConsensusError::InsufficientStake { required: 100, actual: 50 }.is_recoverable());
        assert!(ConsensusError::Timeout { operation: "propose".into(), timeout_ms: 5000 }.is_recoverable());

        // Non-recoverable examples
        assert!(!ConsensusError::VrfVerificationFailed { reason: "bad".into() }.is_recoverable());
        assert!(!ConsensusError::InvalidBlockHeader("bad".into()).is_recoverable());
        assert!(!ConsensusError::Config("bad".into()).is_recoverable());
        assert!(!ConsensusError::NotValidator.is_recoverable());
    }

    #[test]
    fn test_error_slashable() {
        let slashable = ConsensusError::DoubleProposal {
            address: "test".into(),
            slot: 1,
        };
        assert!(slashable.is_slashable());

        let not_slashable = ConsensusError::InsufficientStake {
            required: 1000,
            actual: 100,
        };
        assert!(!not_slashable.is_slashable());
    }

    #[test]
    fn test_error_slashable_all_variants() {
        assert!(ConsensusError::DoubleProposal { address: "v1".into(), slot: 5 }.is_slashable());
        assert!(ConsensusError::ConflictingFinalization("conflict".into()).is_slashable());
        assert!(!ConsensusError::ValidatorJailed { address: "v1".into(), until_slot: 100 }.is_slashable());
        assert!(!ConsensusError::Internal("x".into()).is_slashable());
    }

    #[test]
    fn test_error_codes_all_categories() {
        // VRF errors (1xxx)
        assert_eq!(ConsensusError::VrfVerificationFailed { reason: "t".into() }.error_code(), 1001);
        assert_eq!(ConsensusError::MalformedVrfProof { expected: 97, actual: 33 }.error_code(), 1002);
        assert_eq!(ConsensusError::InvalidVrfKey("bad".into()).error_code(), 1003);
        assert_eq!(ConsensusError::VrfThresholdNotMet { output_hex: "a".into(), threshold_hex: "b".into() }.error_code(), 1004);

        // Leader election errors (2xxx)
        assert_eq!(ConsensusError::NotEligible { address: "v".into(), reason: "r".into() }.error_code(), 2001);
        assert_eq!(ConsensusError::InsufficientStake { required: 1, actual: 0 }.error_code(), 2002);
        assert_eq!(ConsensusError::ValidatorNotRegistered { address: "v".into() }.error_code(), 2003);
        assert_eq!(ConsensusError::ValidatorJailed { address: "v".into(), until_slot: 10 }.error_code(), 2004);
        assert_eq!(ConsensusError::DoubleProposal { address: "v".into(), slot: 1 }.error_code(), 2005);

        // Block validation errors (3xxx)
        assert_eq!(ConsensusError::InvalidBlockHeader("h".into()).error_code(), 3001);
        assert_eq!(ConsensusError::ParentNotFound { parent_hash: "h".into() }.error_code(), 3002);
        assert_eq!(ConsensusError::InvalidSlot { expected: 1, actual: 0 }.error_code(), 3003);
        assert_eq!(ConsensusError::InvalidStateRoot { expected: "a".into(), computed: "b".into() }.error_code(), 3004);
        assert_eq!(ConsensusError::InvalidComputeResultsRoot { expected: "a".into(), computed: "b".into() }.error_code(), 3005);
        assert_eq!(ConsensusError::UsefulWorkScoreMismatch { address: "v".into(), claimed: 10, actual: 5 }.error_code(), 3006);
        assert_eq!(ConsensusError::InvalidTimestamp { reason: "too old".into() }.error_code(), 3007);

        // Reputation errors (4xxx)
        assert_eq!(ConsensusError::ReputationUpdateFailed { address: "v".into(), reason: "r".into() }.error_code(), 4001);
        assert_eq!(ConsensusError::InvalidJobResult("bad".into()).error_code(), 4002);
        assert_eq!(ConsensusError::ReputationCorrupted("corrupt".into()).error_code(), 4003);

        // Epoch errors (5xxx)
        assert_eq!(ConsensusError::EpochTransitionFailed("t".into()).error_code(), 5001);
        assert_eq!(ConsensusError::InvalidEpochSeed("s".into()).error_code(), 5002);
        assert_eq!(ConsensusError::EpochBoundaryNotReached { current: 5, boundary: 10 }.error_code(), 5003);

        // Finality errors (6xxx)
        assert_eq!(ConsensusError::NotFinalized { slot: 42 }.error_code(), 6001);
        assert_eq!(ConsensusError::ConflictingFinalization("c".into()).error_code(), 6002);
        assert_eq!(ConsensusError::InsufficientAttestations { required: 67, actual: 50 }.error_code(), 6003);

        // PoUW errors (7xxx)
        assert_eq!(ConsensusError::SuspiciousActivity { address: "v".into(), reason: "r".into() }.error_code(), 7002);
        assert_eq!(ConsensusError::InvalidUsefulWorkResult("bad".into()).error_code(), 7003);
        assert_eq!(ConsensusError::AiProofVerificationFailed { reason: "r".into() }.error_code(), 7004);
        assert_eq!(ConsensusError::TeeAttestationFailed { reason: "r".into() }.error_code(), 7005);
        assert_eq!(ConsensusError::ZkmlProofFailed { reason: "r".into() }.error_code(), 7006);
        assert_eq!(ConsensusError::UnsupportedCategory { category: "c".into() }.error_code(), 7007);

        // Compatibility errors (8xxx)
        assert_eq!(ConsensusError::NotValidator.error_code(), 8001);
        assert_eq!(ConsensusError::ValidatorNotFound([0u8; 32]).error_code(), 8002);
        assert_eq!(ConsensusError::ValidatorIneligible([0u8; 32]).error_code(), 8003);
        assert_eq!(ConsensusError::InvalidLeaderCredentials("lc".into()).error_code(), 8004);
        assert_eq!(ConsensusError::InvalidParentHash { expected: [0u8; 32], got: [1u8; 32] }.error_code(), 8005);
        assert_eq!(ConsensusError::BlockValidation("bv".into()).error_code(), 8006);
        assert_eq!(ConsensusError::SlotValidation("sv".into()).error_code(), 8007);
        assert_eq!(ConsensusError::TimestampValidation("tv".into()).error_code(), 8008);
        assert_eq!(ConsensusError::VrfValidation("vv".into()).error_code(), 8009);
        assert_eq!(ConsensusError::ComputeValidation("cv".into()).error_code(), 8010);
        assert_eq!(ConsensusError::FinalityValidation("fv".into()).error_code(), 8011);

        // System errors (9xxx)
        assert_eq!(ConsensusError::Config("cfg".into()).error_code(), 9001);
        assert_eq!(ConsensusError::StateAccess("sa".into()).error_code(), 9002);
        assert_eq!(ConsensusError::Crypto("cr".into()).error_code(), 9003);
        assert_eq!(ConsensusError::Internal("in".into()).error_code(), 9004);
        assert_eq!(ConsensusError::Timeout { operation: "op".into(), timeout_ms: 1000 }.error_code(), 9005);
    }

    #[test]
    fn test_error_display_messages() {
        // Test that Display formatting works for all major variants
        let err = ConsensusError::VrfVerificationFailed { reason: "invalid gamma".into() };
        assert!(format!("{}", err).contains("invalid gamma"));

        let err = ConsensusError::MalformedVrfProof { expected: 97, actual: 33 };
        assert!(format!("{}", err).contains("97"));
        assert!(format!("{}", err).contains("33"));

        let err = ConsensusError::NotEligible { address: "cosmos1abc".into(), reason: "jailed".into() };
        assert!(format!("{}", err).contains("cosmos1abc"));
        assert!(format!("{}", err).contains("jailed"));

        let err = ConsensusError::DoubleProposal { address: "val1".into(), slot: 42 };
        assert!(format!("{}", err).contains("val1"));
        assert!(format!("{}", err).contains("42"));

        let err = ConsensusError::InvalidSlot { expected: 10, actual: 5 };
        let msg = format!("{}", err);
        assert!(msg.contains("10"));
        assert!(msg.contains("5"));

        let err = ConsensusError::EpochBoundaryNotReached { current: 5, boundary: 10 };
        assert!(format!("{}", err).contains("5"));

        let err = ConsensusError::InsufficientAttestations { required: 67, actual: 50 };
        assert!(format!("{}", err).contains("67"));

        let err = ConsensusError::Timeout { operation: "finalize".into(), timeout_ms: 3000 };
        assert!(format!("{}", err).contains("finalize"));
        assert!(format!("{}", err).contains("3000"));

        let err = ConsensusError::NotValidator;
        assert!(format!("{}", err).contains("not configured"));

        let err = ConsensusError::InvalidParentHash { expected: [1u8; 32], got: [2u8; 32] };
        assert!(format!("{}", err).contains("Invalid parent hash"));
    }

    #[test]
    fn test_error_debug_trait() {
        let err = ConsensusError::Config("test".into());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Config"));
    }

    #[test]
    fn test_error_clone() {
        let err = ConsensusError::DoubleProposal { address: "v1".into(), slot: 5 };
        let cloned = err.clone();
        assert_eq!(err.error_code(), cloned.error_code());
    }
}
