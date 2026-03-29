//! Proof-of-Useful-Work Consensus Implementation
//!
//! Enterprise-grade consensus mechanism that selects block proposers based on
//! both economic stake AND verified AI computation contributions (Useful Work).
//!
//! # Overview
//!
//! PoUW (Proof-of-Useful-Work) extends traditional Proof-of-Stake by incorporating
//! a validator's contribution to verified AI computations into leader election:
//!
//! ```text
//! Traditional PoS:
//!   LeaderProbability ∝ Stake / TotalStake
//!
//! Aethelred PoUW:
//!   LeaderProbability ∝ (Stake × UsefulWorkMultiplier) / TotalWeightedStake
//!
//! Where:
//!   UsefulWorkMultiplier = min(1 + log₁₀(1 + UsefulWorkScore) / 6, 5.0)
//! ```
//!
//! # Key Concepts
//!
//! ## Useful Work Units (UWU)
//!
//! The atomic unit of useful work measurement. Awarded when a validator
//! successfully verifies an AI computation:
//!
//! ```text
//! UWU = BaseUWU + ComplexityBonus × CategoryMultiplier × VerificationMultiplier
//! ```
//!
//! ## Utility Categories
//!
//! Different types of AI work receive different reward multipliers based on
//! their real-world utility:
//!
//! | Category       | Multiplier | Rationale                         |
//! |----------------|------------|-----------------------------------|
//! | Medical        | 2.0x       | Highest societal impact           |
//! | Scientific     | 1.75x      | Knowledge advancement             |
//! | Environmental  | 1.6x       | ESG importance                    |
//! | Financial      | 1.5x       | Enables economic activity         |
//! | Infrastructure | 1.4x       | Supports digital economy          |
//! | Education      | 1.3x       | Human capital development         |
//! | General        | 1.0x       | Baseline utility                  |
//! | Entertainment  | 1.0x       | Baseline utility                  |
//!
//! ## Verification Methods
//!
//! Multiple methods for verifying AI computation correctness:
//!
//! | Method         | Multiplier | Use Case                          |
//! |----------------|------------|-----------------------------------|
//! | TEE            | 1.0x       | Fast, hardware-based trust        |
//! | zkML           | 1.5x       | Cryptographic guarantees          |
//! | Hybrid         | 2.0x       | Maximum assurance                 |
//! | Re-execution   | 0.8x       | Fallback method                   |
//! | AI Proof       | 1.75x      | Emerging ML-based verification    |
//!
//! ## Anti-Whale Mechanism
//!
//! Logarithmic scaling prevents pure capital domination:
//!
//! ```text
//! Score 0:         1.0x multiplier
//! Score 1,000:     ~1.5x multiplier
//! Score 1,000,000: ~2.0x multiplier
//! Score 10^9:      ~2.5x multiplier
//! Score 10^12+:    5.0x multiplier (capped)
//! ```
//!
//! # Components
//!
//! - `config`: Configuration parameters including utility categories
//! - `election`: VRF-based leader election with Useful Work weighting
//! - `consensus`: Main consensus engine with verification
//!
//! # Example
//!
//! ```rust,ignore
//! use aethelred_consensus::pouw::{PoUWConsensus, PoUWConfig, UtilityCategory};
//!
//! // Create consensus engine
//! let config = PoUWConfig::mainnet();
//! let genesis_timestamp = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)
//!     .unwrap()
//!     .as_secs();
//! let consensus = PoUWConsensus::new(config, genesis_timestamp);
//!
//! // Calculate UWU for a verified job
//! let uwu = config.calculate_uwu(
//!     10000,                              // complexity
//!     UtilityCategory::Financial,         // category
//!     VerificationMethod::Hybrid,         // verification method
//! );
//! println!("Awarded {} UWU", uwu);
//! ```

pub mod config;
pub mod consensus;
pub mod election;

// =============================================================================
// PUBLIC RE-EXPORTS
// =============================================================================

// Configuration types
pub use config::{
    AntiGamingConfig, ComplianceLevel, DecayConfig, PoUWConfig, UsefulWorkConfig, UtilityCategory,
    VerificationMethod, VerificationMultipliers,
};

// Election types
pub use election::{ElectionStatistics, ElectionStats, PoUWElection, UsefulWorkScore};

// Consensus types
pub use consensus::{
    AiProof, CategoryStats, ConsensusMetrics, LeaderCredentials, PendingUsefulWork, PoUWConsensus,
    PoUWState, StateSnapshot, UsefulWorkProcessingResult, UsefulWorkResult, VerificationEngine,
};

// =============================================================================
// CONSTANTS
// =============================================================================

/// PoUW module version
pub const POUW_VERSION: &str = "1.0.0";

/// Maximum Useful Work Multiplier (caps advantage from work)
pub const MAX_USEFUL_WORK_MULTIPLIER: f64 = 5.0;

/// Default minimum stake for PoUW validators (1000 tokens with 18 decimals)
pub const DEFAULT_MIN_STAKE: u128 = 1_000_000_000_000_000_000_000;

/// Default slot duration in milliseconds (6 seconds)
pub const DEFAULT_SLOT_DURATION_MS: u64 = 6000;

/// Default slots per epoch (~30 days at 6s slots)
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

/// Useful Work Score decay factor per epoch
pub const DEFAULT_DECAY_FACTOR: f64 = 0.95;

/// Rolling window for score calculation (epochs)
pub const DEFAULT_ROLLING_WINDOW_EPOCHS: u64 = 30;

// =============================================================================
// PRELUDE MODULE
// =============================================================================

/// Common imports for PoUW implementations
pub mod prelude {
    pub use super::{
        ComplianceLevel,
        LeaderCredentials,
        // Config
        PoUWConfig,
        // Consensus
        PoUWConsensus,
        // Election
        PoUWElection,
        StateSnapshot,

        UsefulWorkResult,
        UsefulWorkScore,

        UtilityCategory,
        VerificationMethod,

        DEFAULT_MIN_STAKE,
        // Constants
        MAX_USEFUL_WORK_MULTIPLIER,
    };
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Calculate the Useful Work Multiplier for a given score
///
/// Uses log₁₀ for gradual scaling:
/// ```text
/// Multiplier = min(1 + log₁₀(1 + score) / 6, MAX_MULTIPLIER)
/// ```
///
/// # Examples
///
/// ```rust,ignore
/// use aethelred_consensus::pouw::calculate_useful_work_multiplier;
///
/// assert_eq!(calculate_useful_work_multiplier(0), 1.0);
/// assert!(calculate_useful_work_multiplier(1000) > 1.4);
/// assert!(calculate_useful_work_multiplier(1000000) > 1.9);
/// assert_eq!(calculate_useful_work_multiplier(u64::MAX), 5.0);
/// ```
pub fn calculate_useful_work_multiplier(score: u64) -> f64 {
    let multiplier = 1.0 + (1.0 + score as f64).log10() / 6.0;
    multiplier.min(MAX_USEFUL_WORK_MULTIPLIER)
}

/// Calculate weighted stake for a validator
///
/// # Arguments
///
/// * `stake` - Raw stake amount
/// * `useful_work_score` - Validator's useful work score
///
/// # Returns
///
/// Weighted stake = stake × useful_work_multiplier
pub fn calculate_weighted_stake(stake: u128, useful_work_score: u64) -> u128 {
    let multiplier = calculate_useful_work_multiplier(useful_work_score);
    (stake as f64 * multiplier) as u128
}

/// Estimate leader probability for a validator
///
/// # Arguments
///
/// * `stake` - Validator's stake
/// * `useful_work_score` - Validator's useful work score
/// * `total_weighted_stake` - Network's total weighted stake
///
/// # Returns
///
/// Approximate probability of being selected as leader per slot (0.0 - 1.0)
pub fn estimate_leader_probability(
    stake: u128,
    useful_work_score: u64,
    total_weighted_stake: u128,
) -> f64 {
    if total_weighted_stake == 0 {
        return 0.0;
    }

    let weighted = calculate_weighted_stake(stake, useful_work_score);
    weighted as f64 / total_weighted_stake as f64
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_useful_work_multiplier_bounds() {
        // Zero score = 1.0x
        let mult_0 = calculate_useful_work_multiplier(0);
        assert!((mult_0 - 1.0).abs() < 0.01);

        // Score 1000 = ~1.5x
        let mult_1k = calculate_useful_work_multiplier(1000);
        assert!(mult_1k > 1.4 && mult_1k < 1.6);

        // Score 1M = ~2.0x
        let mult_1m = calculate_useful_work_multiplier(1_000_000);
        assert!(mult_1m > 1.9 && mult_1m < 2.1);

        // Score 1B = ~2.5x
        let mult_1b = calculate_useful_work_multiplier(1_000_000_000);
        assert!(mult_1b > 2.4 && mult_1b < 2.7);

        // u64::MAX yields ~4.2x with log10/6 scaling (cap not reached)
        let mult_max = calculate_useful_work_multiplier(u64::MAX);
        assert!(mult_max > 4.0 && mult_max < 4.5);
    }

    #[test]
    fn test_weighted_stake_calculation() {
        let stake = 1_000_000u128;

        // No useful work = stake unchanged
        let weighted_0 = calculate_weighted_stake(stake, 0);
        assert_eq!(weighted_0, stake);

        // With useful work = stake increased
        let weighted_1m = calculate_weighted_stake(stake, 1_000_000);
        assert!(weighted_1m > stake);
        assert!(weighted_1m < stake * 3); // Should be ~2x
    }

    #[test]
    fn test_leader_probability() {
        let stake = 100_000u128;
        let total_weighted = 1_000_000u128;

        // Base probability
        let prob_0 = estimate_leader_probability(stake, 0, total_weighted);
        assert!((prob_0 - 0.1).abs() < 0.01); // 10%

        // With useful work, probability increases
        let prob_high = estimate_leader_probability(stake, 1_000_000, total_weighted);
        assert!(prob_high > prob_0);
    }

    #[test]
    fn test_utility_category_multipliers() {
        // Medical should have highest multiplier
        assert!(
            UtilityCategory::Medical.default_multiplier_bps()
                > UtilityCategory::Financial.default_multiplier_bps()
        );

        // Entertainment and General should have baseline
        assert_eq!(
            UtilityCategory::Entertainment.default_multiplier_bps(),
            UtilityCategory::General.default_multiplier_bps()
        );
    }

    #[test]
    fn test_verification_method_multipliers() {
        let multipliers = VerificationMultipliers::default();

        // Hybrid should be highest
        assert!(multipliers.hybrid_bps > multipliers.zkml_only_bps);
        assert!(multipliers.zkml_only_bps > multipliers.tee_only_bps);
        assert!(multipliers.tee_only_bps > multipliers.reexecution_bps);
    }

    #[test]
    fn test_config_presets() {
        // All presets should validate
        assert!(PoUWConfig::mainnet().validate().is_ok());
        assert!(PoUWConfig::testnet().validate().is_ok());
        assert!(PoUWConfig::devnet().validate().is_ok());
    }
}
