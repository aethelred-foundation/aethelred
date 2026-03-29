//! Aethelred Consensus Engine
//!
//! Enterprise-grade Proof-of-Useful-Work (PoUW) consensus for the Aethelred Protocol.
//!
//! # Proof-of-Useful-Work (PoUW)
//!
//! PoUW is Aethelred's novel consensus mechanism that verifies AI computations
//! and rewards validators based on utility category multipliers:
//!
//! - **Medical AI**: 2.0x multiplier - Healthcare and diagnostics
//! - **Scientific Computing**: 1.75x multiplier - Research and discovery
//! - **Financial AI**: 1.5x multiplier - Banking, credit scoring, fraud detection
//! - **Environmental**: 1.5x multiplier - Climate modeling, sustainability
//! - **Infrastructure**: 1.25x multiplier - Critical systems
//! - **General AI**: 1.0x multiplier - Other AI workloads
//!
//! ## Module Status
//!
//! - **pouw**: Production consensus - Use for all deployments
//!
//! # Overview
//!
//! Traditional Proof-of-Stake selects leaders based solely on stake:
//! ```text
//! Standard PoS: LeaderProbability ∝ Stake / TotalStake
//! ```
//!
//! Aethelred Proof-of-Useful-Work adds utility value:
//! ```text
//! Aethelred PoUW: LeaderProbability ∝ Stake × UsefulWorkMultiplier / TotalWeightedStake
//! Where: UsefulWorkMultiplier = min(1 + log₁₀(1 + UsefulWorkScore) / 6, 5.0)
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                  PROOF-OF-USEFUL-WORK CONSENSUS ENGINE                        │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │   ┌────────────────────────────────────────────────────────────────────┐    │
//! │   │                      VRF LEADER ELECTION                            │    │
//! │   │                                                                     │    │
//! │   │   EpochSeed ──┐                                                    │    │
//! │   │               │                                                    │    │
//! │   │   SecretKey ──┼──► VRF.Prove() ──► VrfOutput ──┐                   │    │
//! │   │               │                                │                   │    │
//! │   │   Slot ───────┘                                ▼                   │    │
//! │   │                                    VrfOutput < Threshold?          │    │
//! │   │                                                │                   │    │
//! │   │   Stake ──────────┐                            │                   │    │
//! │   │                   ├──► CalculateThreshold() ───┘                   │    │
//! │   │   UsefulWorkScore ───┘                                            │    │
//! │   │                                                                     │    │
//! │   └────────────────────────────────────────────────────────────────────┘    │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   ┌────────────────────────────────────────────────────────────────────┐    │
//! │   │                  USEFUL WORK REPUTATION SYSTEM                      │    │
//! │   │                                                                     │    │
//! │   │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │    │
//! │   │   │  Verified   │    │  Time-      │    │  Compute    │           │    │
//! │   │   │  AI Jobs    │───►│  Weighted   │───►│  Score      │           │    │
//! │   │   │  (30 days)  │    │  Average    │    │  (0-∞)      │           │    │
//! │   │   └─────────────┘    └─────────────┘    └─────────────┘           │    │
//! │   │                                                                     │    │
//! │   └────────────────────────────────────────────────────────────────────┘    │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   ┌────────────────────────────────────────────────────────────────────┐    │
//! │   │                    BLOCK VALIDATION                                 │    │
//! │   │                                                                     │    │
//! │   │   1. Verify VRF Proof (cryptographic proof of leader eligibility)  │    │
//! │   │   2. Verify Compute Score (matches on-chain reputation)            │    │
//! │   │   3. Verify Compute Results Root (all AI proofs in block)          │    │
//! │   │   4. Verify State Transitions                                      │    │
//! │   │                                                                     │    │
//! │   └────────────────────────────────────────────────────────────────────┘    │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Innovations
//!
//! 1. **Utility-Weighted Selection**: Validators who contribute AI compute get
//!    a 2x-5x boost in leader probability, incentivizing network utility.
//!
//! 2. **Logarithmic Scaling**: Prevents GPU whales from total domination while
//!    rewarding consistent contributors.
//!
//! 3. **Verifiable Randomness**: VRF ensures fair, unpredictable, but verifiable
//!    leader selection.
//!
//! 4. **Sliding Window Reputation**: 30-day exponential decay rewards sustained
//!    participation over one-time contributions.
//!
//! # Usage
//!
//! ```rust,ignore
//! use aethelred_consensus::{PoUWConsensus, PoUWConfig, VrfKeys};
//!
//! // Create consensus engine
//! let config = PoUWConfig::mainnet();
//! let genesis_timestamp = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//! let mut consensus = PoUWConsensus::new(config, genesis_timestamp);
//!
//! // Register as validator
//! let keys = VrfKeys::generate();
//! consensus = consensus.with_validator_keys(keys);
//!
//! // Check if we should propose
//! let current_slot = 1000;
//! if consensus.should_propose(current_slot).unwrap_or(false) {
//!     let credentials = consensus.generate_credentials(current_slot).unwrap();
//!     // Create and broadcast block
//! }
//! ```

// =============================================================================
// MODULE DECLARATIONS
// =============================================================================

pub mod error;
pub mod metrics;
pub mod pouw;
pub mod reputation;
pub mod traits;
pub mod types;
pub mod vrf;

#[cfg(test)]
mod tests;

#[cfg(kani)]
mod kani_proofs;

// =============================================================================
// PUBLIC RE-EXPORTS
// =============================================================================

// Error types
pub use error::{ConsensusError, ConsensusResult};

// Traits
pub use traits::{
    BlockValidator, ComputeResult, Consensus, ConsensusState, LeaderElection, VerificationMethod,
};

// Core types
pub use types::{
    compute_multiplier, Address, BlockProposal, Epoch, EpochSeed, FinalityVote, Hash,
    PoUWBlockHeader, Slot, SlotTiming, ValidatorInfo,
};

// VRF
pub use vrf::{VrfEngine, VrfKeys, VrfOutput, VrfProof};

// Reputation
pub use reputation::{
    ComputeJobRecord, JobMetadata, ReputationConfig, ReputationEngine, ReputationMetrics,
    ReputationSnapshot, ScoreUpdate, ValidatorReputation,
};

// Metrics
pub use metrics::{
    BlockMetrics, ComputeMetrics, ConsensusMetricsCollector, MetricsSnapshot, TimingMetrics,
    ValidatorMetrics, VrfMetrics,
};

// =============================================================================
// PROOF-OF-USEFUL-WORK (PRODUCTION CONSENSUS)
// =============================================================================

// PoUW Configuration
pub use pouw::config::{
    AntiGamingConfig, ComplianceLevel, DecayConfig, PoUWConfig, UsefulWorkConfig, UtilityCategory,
    VerificationMethod as PoUWVerificationMethod, VerificationMultipliers,
};

// PoUW Election
pub use pouw::election::{
    ElectionStatistics, ElectionStats as PoUWElectionStats, PoUWElection, UsefulWorkScore,
};

// PoUW Consensus
pub use pouw::consensus::{
    AiProof, CategoryStats, ConsensusMetrics as PoUWMetrics,
    LeaderCredentials as PoUWLeaderCredentials, PendingUsefulWork, PoUWConsensus, PoUWState,
    StateSnapshot as PoUWStateSnapshot, UsefulWorkProcessingResult, UsefulWorkResult,
    VerificationEngine,
};

// PoUW helper functions
pub use pouw::{
    calculate_useful_work_multiplier, calculate_weighted_stake, estimate_leader_probability,
    DEFAULT_DECAY_FACTOR, DEFAULT_MIN_STAKE, DEFAULT_ROLLING_WINDOW_EPOCHS,
    MAX_USEFUL_WORK_MULTIPLIER, POUW_VERSION,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Consensus engine version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default slot duration in milliseconds (6 seconds)
pub const DEFAULT_SLOT_DURATION_MS: u64 = 6000;

/// Default slots per epoch (~30 days at 6s slots)
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

/// Maximum useful work multiplier (prevents unbounded growth)
/// With this cap:
/// - Score 0: 1.0x
/// - Score 1,000: ~1.5x
/// - Score 1,000,000: ~2.0x
/// - Score 1,000,000,000: ~2.5x
/// - Score 10^12+: 5.0x (capped)
pub const MAX_COMPUTE_MULTIPLIER: f64 = 5.0;

/// Minimum stake to be eligible for leader election (in smallest units)
/// 1000 tokens with 12 decimal places
pub const MIN_STAKE_FOR_ELECTION: u128 = 1_000_000_000_000;

/// Maximum validators in active set
pub const MAX_VALIDATORS: usize = 1000;

/// Minimum validators for consensus
pub const MIN_VALIDATORS: usize = 4;

/// Byzantine fault tolerance threshold (1/3 of validators can be faulty)
pub const BFT_THRESHOLD: f64 = 1.0 / 3.0;

// =============================================================================
// PRELUDE MODULE
// =============================================================================

/// Common imports for consensus implementations
pub mod prelude {
    pub use super::{
        Address,

        BlockValidator,

        // Traits
        Consensus,
        // Errors
        ConsensusError,
        ConsensusResult,

        ConsensusState,
        Epoch,
        EpochSeed,
        Hash,
        LeaderElection,
        // Types
        PoUWBlockHeader,
        PoUWConfig,
        // PoUW (Production)
        PoUWConsensus,
        ReputationConfig,

        // Reputation
        ReputationEngine,
        Slot,
        UsefulWorkResult,

        UsefulWorkScore,
        UtilityCategory,
        ValidatorInfo,
        // VRF
        VrfKeys,
        VrfOutput,

        VrfProof,
        // Constants
        DEFAULT_SLOTS_PER_EPOCH,
        MAX_COMPUTE_MULTIPLIER,
        MAX_USEFUL_WORK_MULTIPLIER,
        MIN_STAKE_FOR_ELECTION,
    };
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests_inline {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(DEFAULT_SLOTS_PER_EPOCH > 0);
        assert!(MAX_COMPUTE_MULTIPLIER > 1.0);
        assert!(MIN_STAKE_FOR_ELECTION > 0);
        assert!(MAX_VALIDATORS > MIN_VALIDATORS);
    }

    #[test]
    fn test_compute_multiplier_bounds() {
        // Zero compute should give 1x
        let mult_zero = compute_multiplier(0);
        assert!((mult_zero - 1.0).abs() < 0.01);

        // u64::MAX yields ~4.2x with log10/6 scaling
        let mult_max = compute_multiplier(u64::MAX);
        assert!(mult_max > 4.0 && mult_max < 4.5);
    }

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
