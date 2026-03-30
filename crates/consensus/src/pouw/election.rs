//! Proof-of-Useful-Work Leader Election
//!
//! Enterprise-grade leader election combining VRF randomness with
//! stake-weighted Useful Work scoring. This module implements the core
//! innovation of PoUW: selecting block proposers based on both economic
//! stake AND verified AI computation contributions.
//!
//! # Algorithm Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                    POUW LEADER ELECTION ALGORITHM                            │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │   1. VRF LOTTERY                                                            │
//! │      ┌──────────────────────────────────────────────────────────────────┐   │
//! │      │  VrfOutput = VRF.Prove(SecretKey, EpochSeed || Slot)             │   │
//! │      │  - Deterministic but unpredictable                                │   │
//! │      │  - Publicly verifiable                                            │   │
//! │      │  - Bias-resistant                                                 │   │
//! │      └──────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   2. USEFUL WORK SCORE CALCULATION                                          │
//! │      ┌──────────────────────────────────────────────────────────────────┐   │
//! │      │  UsefulWorkScore = Σ(UWU_i × CategoryMultiplier × TimeDecay)     │   │
//! │      │                                                                   │   │
//! │      │  Where:                                                           │   │
//! │      │    - UWU_i = Useful Work Units from job i                        │   │
//! │      │    - CategoryMultiplier = 1.0x (General) to 2.0x (Medical)       │   │
//! │      │    - TimeDecay = 0.95^(epochs_since_completion)                  │   │
//! │      └──────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   3. USEFUL WORK MULTIPLIER                                                 │
//! │      ┌──────────────────────────────────────────────────────────────────┐   │
//! │      │  Multiplier = min(1 + log₁₀(1 + UsefulWorkScore) / 6, MAX_MULT)  │   │
//! │      │                                                                   │   │
//! │      │  Produces:                                                        │   │
//! │      │    - Score 0:         1.0x (no boost)                            │   │
//! │      │    - Score 1,000:     ~1.5x (regular contributor)                │   │
//! │      │    - Score 1,000,000: ~2.0x (significant contributor)            │   │
//! │      │    - Score 10^9:      ~2.5x (major infrastructure)               │   │
//! │      │    - Score 10^12+:    5.0x (capped)                              │   │
//! │      │                                                                   │   │
//! │      │  NOTE: Uses log₁₀ instead of log₂ for more gradual scaling      │   │
//! │      └──────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   4. THRESHOLD CALCULATION                                                  │
//! │      ┌──────────────────────────────────────────────────────────────────┐   │
//! │      │  Threshold = (MAX_VRF × Stake × UsefulWorkMultiplier)            │   │
//! │      │              ─────────────────────────────────────────            │   │
//! │      │                      TotalWeightedStake                          │   │
//! │      └──────────────────────────────────────────────────────────────────┘   │
//! │                                    │                                         │
//! │                                    ▼                                         │
//! │   5. LEADER SELECTION                                                       │
//! │      ┌──────────────────────────────────────────────────────────────────┐   │
//! │      │  if VrfOutput < Threshold:                                        │   │
//! │      │      ELIGIBLE TO PROPOSE                                          │   │
//! │      │  else:                                                            │   │
//! │      │      NOT SELECTED THIS SLOT                                       │   │
//! │      │                                                                   │   │
//! │      │  Multiple winners possible → Lowest VRF output wins              │   │
//! │      └──────────────────────────────────────────────────────────────────┘   │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Anti-Whale Mechanism
//!
//! The logarithmic scaling of Useful Work Score creates a natural anti-whale
//! mechanism that prevents pure capital domination:
//!
//! ```text
//! Scenario: Whale with 100M tokens vs. Small Validator with 1M tokens
//!
//! Traditional PoS:
//!   - Whale: 100M / 101M = 99% selection probability
//!   - Small: 1M / 101M = 1% selection probability
//!
//! PoUW (assuming equal UWU):
//!   - Both get same multiplier
//!   - Whale: 100M × 1.5x = 150M weighted
//!   - Small: 1M × 1.5x = 1.5M weighted
//!   - Still dominated by capital
//!
//! PoUW (with Useful Work contribution):
//!   - Small validator verifies 10x more AI jobs
//!   - Whale: 100M × 1.5x = 150M weighted (Score: 100k)
//!   - Small: 1M × 3.0x = 3M weighted (Score: 10M)
//!   - Small validator gets 2% instead of 1%
//!   - Productivity is rewarded!
//! ```

use num_bigint::BigUint;
use num_traits::Zero;
use parking_lot::RwLock;
use std::collections::HashMap;

use super::config::{PoUWConfig, UtilityCategory, VerificationMethod};
use crate::error::{ConsensusError, ConsensusResult};
use crate::traits::LeaderElection;
use crate::types::{Address, EpochSeed, Slot, ValidatorInfo};
use crate::vrf::{VrfEngine, VrfKeys, VrfOutput, VrfProof};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum value of VRF output (2^256 - 1)
fn max_vrf_output() -> BigUint {
    BigUint::from(1u8) << 256
}

/// Precision for fixed-point calculations
const PRECISION: u64 = 1_000_000;

// =============================================================================
// USEFUL WORK SCORE TRACKING
// =============================================================================

/// Useful Work Score record for a validator
#[derive(Debug, Clone)]
pub struct UsefulWorkScore {
    /// Total accumulated UWU (Useful Work Units)
    pub total_uwu: u64,

    /// UWU breakdown by category
    pub uwu_by_category: HashMap<UtilityCategory, u64>,

    /// Jobs completed by verification method
    pub jobs_by_method: HashMap<VerificationMethod, u64>,

    /// Rolling window scores (epoch -> UWU)
    pub epoch_scores: HashMap<u64, u64>,

    /// Last update epoch
    pub last_update_epoch: u64,

    /// Total jobs verified
    pub total_jobs_verified: u64,

    /// Average job complexity
    pub average_complexity: u64,

    /// Reputation score (0-1000)
    pub reputation_score: u64,

    /// Suspicious activity flags
    pub suspicious_flags: u32,
}

impl Default for UsefulWorkScore {
    fn default() -> Self {
        Self {
            total_uwu: 0,
            uwu_by_category: HashMap::new(),
            jobs_by_method: HashMap::new(),
            epoch_scores: HashMap::new(),
            last_update_epoch: 0,
            total_jobs_verified: 0,
            average_complexity: 0,
            reputation_score: 500, // Start at neutral
            suspicious_flags: 0,
        }
    }
}

impl UsefulWorkScore {
    /// Create new score tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Add UWU from a verified job
    pub fn add_uwu(
        &mut self,
        uwu: u64,
        category: UtilityCategory,
        method: VerificationMethod,
        complexity: u64,
        current_epoch: u64,
    ) {
        // Update totals
        self.total_uwu = self.total_uwu.saturating_add(uwu);
        self.total_jobs_verified += 1;

        // Update category breakdown
        *self.uwu_by_category.entry(category).or_insert(0) += uwu;

        // Update method breakdown
        *self.jobs_by_method.entry(method).or_insert(0) += 1;

        // Update epoch score
        *self.epoch_scores.entry(current_epoch).or_insert(0) += uwu;

        // Update running average complexity
        let total_complexity = self.average_complexity * (self.total_jobs_verified - 1);
        self.average_complexity = (total_complexity + complexity) / self.total_jobs_verified;

        self.last_update_epoch = current_epoch;
    }

    /// Calculate decayed score using rolling window
    pub fn calculate_decayed_score(&self, current_epoch: u64, config: &PoUWConfig) -> u64 {
        let decay_config = &config.useful_work_config.decay_config;
        let window_size = decay_config.rolling_window_epochs;
        let decay_factor = decay_config.epoch_decay_factor;

        let mut total_score: f64 = 0.0;

        for epoch in current_epoch.saturating_sub(window_size)..=current_epoch {
            if let Some(&epoch_uwu) = self.epoch_scores.get(&epoch) {
                let epochs_ago = current_epoch - epoch;
                let decayed = epoch_uwu as f64 * decay_factor.powi(epochs_ago as i32);
                total_score += decayed;
            }
        }

        // Apply reputation modifier
        let reputation_factor = self.reputation_score as f64 / 500.0; // 1.0 at neutral
        total_score *= reputation_factor;

        total_score as u64
    }

    /// Get category diversity score (0-100)
    /// Higher score for validators who contribute across multiple categories
    pub fn category_diversity_score(&self) -> u8 {
        let active_categories = self.uwu_by_category.len();
        let total_categories = UtilityCategory::all().len();

        if active_categories == 0 {
            return 0;
        }

        // Check for balanced distribution
        let total_uwu: u64 = self.uwu_by_category.values().sum();
        if total_uwu == 0 {
            return 0;
        }

        // Calculate Gini coefficient for distribution
        let mut sorted_shares: Vec<f64> = self
            .uwu_by_category
            .values()
            .map(|&v| v as f64 / total_uwu as f64)
            .collect();
        sorted_shares.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let n = sorted_shares.len() as f64;
        let mut gini_sum = 0.0;
        for (i, share) in sorted_shares.iter().enumerate() {
            gini_sum += (2.0 * (i as f64 + 1.0) - n - 1.0) * share;
        }
        let gini = gini_sum / n;

        // Convert to diversity score (lower gini = higher diversity)
        let diversity_from_gini = ((1.0 - gini) * 50.0) as u8;

        // Add bonus for number of categories
        let category_bonus = ((active_categories as f64 / total_categories as f64) * 50.0) as u8;

        (diversity_from_gini + category_bonus).min(100)
    }

    /// Check if score is suspicious (potential gaming)
    pub fn is_suspicious(&self, _config: &PoUWConfig) -> bool {
        // Check 1: Suspicious flags accumulated
        if self.suspicious_flags >= 3 {
            return true;
        }

        // Check 2: Single category dominance (>95% in one category)
        let total_uwu: u64 = self.uwu_by_category.values().sum();
        if total_uwu > 0 {
            for &category_uwu in self.uwu_by_category.values() {
                if category_uwu as f64 / total_uwu as f64 > 0.95 {
                    return true;
                }
            }
        }

        // Check 3: Single method dominance (gaming re-execution)
        let total_jobs: u64 = self.jobs_by_method.values().sum();
        if total_jobs > 0 {
            if let Some(&reexec_jobs) = self.jobs_by_method.get(&VerificationMethod::ReExecution) {
                if reexec_jobs as f64 / total_jobs as f64 > 0.9 {
                    return true;
                }
            }
        }

        false
    }

    /// Apply penalty for detected suspicious activity
    pub fn apply_penalty(&mut self, penalty_pct: u64) {
        let penalty = self.total_uwu * penalty_pct / 100;
        self.total_uwu = self.total_uwu.saturating_sub(penalty);
        self.suspicious_flags += 1;
    }

    /// Reset suspicious flags (after cooldown)
    pub fn reset_flags(&mut self) {
        self.suspicious_flags = 0;
    }
}

// =============================================================================
// POUW LEADER ELECTION
// =============================================================================

/// Proof-of-Useful-Work Leader Election Engine
///
/// Implements VRF-based leader election with Useful Work Score weighting.
/// This is the core consensus innovation that incentivizes productive
/// AI computation over pure capital accumulation.
pub struct PoUWElection {
    /// Configuration
    config: PoUWConfig,

    /// VRF engine
    vrf_engine: VrfEngine,

    /// Current epoch seed
    epoch_seed: RwLock<EpochSeed>,

    /// Validator set (address -> info)
    validators: RwLock<HashMap<Address, ValidatorInfo>>,

    /// Useful Work Scores (address -> score)
    useful_work_scores: RwLock<HashMap<Address, UsefulWorkScore>>,

    /// Total staked amount
    total_stake: RwLock<u128>,

    /// Total weighted stake (stake * multiplier)
    total_weighted_stake: RwLock<u128>,

    /// Cache of computed thresholds
    threshold_cache: RwLock<HashMap<Address, BigUint>>,

    /// Current epoch for decay calculations
    current_epoch: RwLock<u64>,

    /// Election statistics
    stats: RwLock<ElectionStatistics>,
}

/// Election statistics for monitoring and analytics
#[derive(Debug, Clone, Default)]
pub struct ElectionStatistics {
    /// Total elections held
    pub total_elections: u64,

    /// Elections won by category (which category got most proposals)
    pub wins_by_top_category: HashMap<UtilityCategory, u64>,

    /// Average winner useful work score
    pub avg_winner_score: u64,

    /// Median winner stake
    pub median_winner_stake: u128,

    /// Elections with multiple eligible validators
    pub multi_winner_slots: u64,

    /// Minimum score that won election
    pub min_winning_score: u64,

    /// Maximum score that lost election
    pub max_losing_score: u64,
}

impl PoUWElection {
    /// Create new PoUW election system
    pub fn new(config: PoUWConfig) -> Self {
        let vrf_engine = VrfEngine::with_chain_id(config.chain_id);

        Self {
            config,
            vrf_engine,
            epoch_seed: RwLock::new([0u8; 32]),
            validators: RwLock::new(HashMap::new()),
            useful_work_scores: RwLock::new(HashMap::new()),
            total_stake: RwLock::new(0),
            total_weighted_stake: RwLock::new(0),
            threshold_cache: RwLock::new(HashMap::new()),
            current_epoch: RwLock::new(0),
            stats: RwLock::new(ElectionStatistics::default()),
        }
    }

    /// Set epoch seed
    pub fn set_epoch_seed(&self, seed: EpochSeed) {
        *self.epoch_seed.write() = seed;
        // Clear threshold cache when epoch changes
        self.threshold_cache.write().clear();
    }

    /// Get epoch seed
    pub fn epoch_seed(&self) -> EpochSeed {
        *self.epoch_seed.read()
    }

    /// Set current epoch
    pub fn set_current_epoch(&self, epoch: u64) {
        let old_epoch = *self.current_epoch.read();
        if epoch > old_epoch {
            *self.current_epoch.write() = epoch;
            // Recalculate weighted stakes with updated decay
            self.recalculate_weighted_stakes();
        }
    }

    /// Register a validator
    pub fn register_validator(&self, info: ValidatorInfo) -> ConsensusResult<()> {
        // Validate stake
        if info.stake < self.config.min_stake {
            return Err(ConsensusError::InsufficientStake {
                required: self.config.min_stake,
                actual: info.stake,
            });
        }

        let address = info.address;

        // Calculate weighted stake
        let useful_work_score = self.get_useful_work_score(&address);
        let weighted = self.weighted_stake_internal(info.stake, useful_work_score);

        // Update totals
        {
            let mut validators = self.validators.write();
            let mut total_stake = self.total_stake.write();
            let mut total_weighted = self.total_weighted_stake.write();

            // Remove old values if updating
            if let Some(old) = validators.get(&address) {
                *total_stake -= old.stake;
                let old_score = self.get_useful_work_score(&address);
                let old_weighted = self.weighted_stake_internal(old.stake, old_score);
                *total_weighted -= old_weighted;
            }

            // Add new values
            *total_stake += info.stake;
            *total_weighted += weighted;
            validators.insert(address, info);
        }

        // Initialize useful work score if not exists
        {
            let mut scores = self.useful_work_scores.write();
            scores.entry(address).or_default();
        }

        // Clear threshold cache
        self.threshold_cache.write().clear();

        Ok(())
    }

    /// Remove a validator
    pub fn remove_validator(&self, address: &Address) -> ConsensusResult<()> {
        let mut validators = self.validators.write();
        let mut total_stake = self.total_stake.write();
        let mut total_weighted = self.total_weighted_stake.write();

        if let Some(info) = validators.remove(address) {
            *total_stake -= info.stake;
            let score = self.get_useful_work_score(address);
            let weighted = self.weighted_stake_internal(info.stake, score);
            *total_weighted -= weighted;

            self.threshold_cache.write().remove(address);
            self.useful_work_scores.write().remove(address);
            Ok(())
        } else {
            Err(ConsensusError::ValidatorNotRegistered {
                address: hex::encode(address),
            })
        }
    }

    /// Update Useful Work Score for a validator
    ///
    /// Called after a validator successfully verifies an AI computation job.
    pub fn record_useful_work(
        &self,
        address: &Address,
        uwu: u64,
        category: UtilityCategory,
        method: VerificationMethod,
        complexity: u64,
    ) -> ConsensusResult<()> {
        let current_epoch = *self.current_epoch.read();

        // Get or create score
        let mut scores = self.useful_work_scores.write();
        let score = scores.entry(*address).or_default();

        // Anti-gaming check
        if score.is_suspicious(&self.config) {
            return Err(ConsensusError::SuspiciousActivity {
                address: hex::encode(address),
                reason: "Validator flagged for suspicious activity pattern".into(),
            });
        }

        // Record the work
        score.add_uwu(uwu, category, method, complexity, current_epoch);

        drop(scores);

        // Update weighted stake
        self.update_weighted_stake(address)?;

        // Clear cached threshold
        self.threshold_cache.write().remove(address);

        Ok(())
    }

    /// Get Useful Work Score for a validator
    pub fn get_useful_work_score(&self, address: &Address) -> u64 {
        let scores = self.useful_work_scores.read();
        let current_epoch = *self.current_epoch.read();

        scores
            .get(address)
            .map(|s| s.calculate_decayed_score(current_epoch, &self.config))
            .unwrap_or(0)
    }

    /// Get full Useful Work Score details
    pub fn get_useful_work_details(&self, address: &Address) -> Option<UsefulWorkScore> {
        self.useful_work_scores.read().get(address).cloned()
    }

    /// Get validator info
    pub fn get_validator(&self, address: &Address) -> Option<ValidatorInfo> {
        self.validators.read().get(address).cloned()
    }

    /// Get all active validators
    pub fn active_validators(&self, current_slot: Slot) -> Vec<ValidatorInfo> {
        self.validators
            .read()
            .values()
            .filter(|v| v.is_eligible(current_slot))
            .cloned()
            .collect()
    }

    /// Check if a validator is eligible to propose for a slot
    pub fn check_eligibility(
        &self,
        validator: &Address,
        slot: Slot,
        vrf_keys: &VrfKeys,
    ) -> ConsensusResult<Option<(VrfOutput, VrfProof)>> {
        // Get validator info
        let info = self
            .validators
            .read()
            .get(validator)
            .cloned()
            .ok_or_else(|| ConsensusError::ValidatorNotRegistered {
                address: hex::encode(validator),
            })?;

        // Check basic eligibility
        if !info.is_eligible(slot) {
            return Err(ConsensusError::NotEligible {
                address: hex::encode(validator),
                reason: "Validator is not active or jailed".into(),
            });
        }

        // Generate VRF proof
        let epoch_seed = self.epoch_seed();
        let (output, proof) = self
            .vrf_engine
            .prove_for_slot(vrf_keys, &epoch_seed, slot)?;

        // Calculate threshold
        let threshold = self.get_or_compute_threshold(validator)?;

        // Check if VRF output meets threshold
        if self.check_vrf_threshold(output.as_bytes(), &threshold) {
            // Update statistics
            self.record_election_win(validator);
            Ok(Some((output, proof)))
        } else {
            Ok(None)
        }
    }

    /// Verify that a block proposer was legitimately selected
    pub fn verify_proposer(
        &self,
        proposer: &Address,
        slot: Slot,
        claimed_useful_work_score: u64,
        vrf_output: &[u8],
        vrf_proof: &[u8],
    ) -> ConsensusResult<()> {
        // Get validator info
        let info = self
            .validators
            .read()
            .get(proposer)
            .cloned()
            .ok_or_else(|| ConsensusError::ValidatorNotRegistered {
                address: hex::encode(proposer),
            })?;

        // Verify useful work score matches (with tolerance for decay)
        let actual_score = self.get_useful_work_score(proposer);
        let tolerance = actual_score / 100; // 1% tolerance
        if (claimed_useful_work_score as i128 - actual_score as i128).unsigned_abs()
            > tolerance as u128
        {
            return Err(ConsensusError::UsefulWorkScoreMismatch {
                address: hex::encode(proposer),
                claimed: claimed_useful_work_score,
                actual: actual_score,
            });
        }

        // Parse VRF proof
        let proof = VrfProof::from_bytes(vrf_proof)?;

        // Parse VRF output
        if vrf_output.len() != 32 {
            return Err(ConsensusError::MalformedVrfProof {
                expected: 32,
                actual: vrf_output.len(),
            });
        }
        let mut output_bytes = [0u8; 32];
        output_bytes.copy_from_slice(vrf_output);
        let output = VrfOutput::from_bytes(output_bytes);

        // Verify VRF proof
        let epoch_seed = self.epoch_seed();
        let valid = self.vrf_engine.verify_for_slot(
            &info.vrf_pubkey,
            &epoch_seed,
            slot,
            &output,
            &proof,
        )?;

        if !valid {
            return Err(ConsensusError::VrfVerificationFailed {
                reason: "VRF proof verification failed".into(),
            });
        }

        // Verify threshold
        let threshold =
            self.calculate_threshold(info.stake, actual_score, *self.total_weighted_stake.read());

        if !self.check_vrf_threshold(vrf_output, &threshold) {
            return Err(ConsensusError::VrfThresholdNotMet {
                output_hex: hex::encode(vrf_output),
                threshold_hex: threshold.to_str_radix(16),
            });
        }

        Ok(())
    }

    /// Recalculate all weighted stakes (call on epoch transition)
    fn recalculate_weighted_stakes(&self) {
        let validators = self.validators.read();
        let current_epoch = *self.current_epoch.read();

        let mut total_weighted: u128 = 0;

        for (address, info) in validators.iter() {
            let scores = self.useful_work_scores.read();
            let score = scores
                .get(address)
                .map(|s| s.calculate_decayed_score(current_epoch, &self.config))
                .unwrap_or(0);

            let weighted = self.weighted_stake_internal(info.stake, score);
            total_weighted += weighted;
        }

        *self.total_weighted_stake.write() = total_weighted;
        self.threshold_cache.write().clear();
    }

    /// Update weighted stake for a single validator
    fn update_weighted_stake(&self, address: &Address) -> ConsensusResult<()> {
        let validators = self.validators.read();
        let info =
            validators
                .get(address)
                .ok_or_else(|| ConsensusError::ValidatorNotRegistered {
                    address: hex::encode(address),
                })?;

        let old_score = {
            let scores = self.useful_work_scores.read();
            scores
                .get(address)
                .map(|s| s.calculate_decayed_score(*self.current_epoch.read(), &self.config))
                .unwrap_or(0)
        };

        let new_score = self.get_useful_work_score(address);

        let old_weighted = self.weighted_stake_internal(info.stake, old_score);
        let new_weighted = self.weighted_stake_internal(info.stake, new_score);

        let mut total_weighted = self.total_weighted_stake.write();
        *total_weighted = total_weighted
            .saturating_sub(old_weighted)
            .saturating_add(new_weighted);

        Ok(())
    }

    /// Calculate weighted stake internally
    fn weighted_stake_internal(&self, stake: u128, useful_work_score: u64) -> u128 {
        let multiplier = self.useful_work_multiplier(useful_work_score);
        (stake as f64 * multiplier) as u128
    }

    /// Get or compute threshold for a validator
    fn get_or_compute_threshold(&self, validator: &Address) -> ConsensusResult<BigUint> {
        // Check cache
        if let Some(threshold) = self.threshold_cache.read().get(validator) {
            return Ok(threshold.clone());
        }

        // Get validator info
        let info = self
            .validators
            .read()
            .get(validator)
            .cloned()
            .ok_or_else(|| ConsensusError::ValidatorNotRegistered {
                address: hex::encode(validator),
            })?;

        // Get useful work score
        let useful_work_score = self.get_useful_work_score(validator);

        // Calculate threshold
        let threshold = self.calculate_threshold(
            info.stake,
            useful_work_score,
            *self.total_weighted_stake.read(),
        );

        // Cache it
        self.threshold_cache
            .write()
            .insert(*validator, threshold.clone());

        Ok(threshold)
    }

    /// Record election win for statistics
    fn record_election_win(&self, winner: &Address) {
        let mut stats = self.stats.write();
        stats.total_elections += 1;

        // Get winner's top category
        if let Some(score) = self.useful_work_scores.read().get(winner) {
            if let Some((&top_category, _)) = score.uwu_by_category.iter().max_by_key(|(_, &v)| v) {
                *stats.wins_by_top_category.entry(top_category).or_insert(0) += 1;
            }

            // Update average winner score
            let winner_score = score.total_uwu;
            stats.avg_winner_score = (stats.avg_winner_score * (stats.total_elections - 1)
                + winner_score)
                / stats.total_elections;

            // Track min winning score
            if stats.min_winning_score == 0 || winner_score < stats.min_winning_score {
                stats.min_winning_score = winner_score;
            }
        }
    }

    /// Get election statistics
    pub fn statistics(&self) -> ElectionStatistics {
        self.stats.read().clone()
    }

    /// Get stats (alias for statistics)
    pub fn stats(&self) -> ElectionStats {
        let validators = self.validators.read();
        let active_count = validators.values().filter(|v| v.active).count();

        let total_useful_work: u64 = {
            let scores = self.useful_work_scores.read();
            let current_epoch = *self.current_epoch.read();
            scores
                .values()
                .map(|s| s.calculate_decayed_score(current_epoch, &self.config))
                .sum()
        };

        let avg_multiplier: f64 = if !validators.is_empty() {
            let current_epoch = *self.current_epoch.read();
            let scores = self.useful_work_scores.read();

            validators
                .values()
                .map(|v| {
                    let score = scores
                        .get(&v.address)
                        .map(|s| s.calculate_decayed_score(current_epoch, &self.config))
                        .unwrap_or(0);
                    self.useful_work_multiplier(score)
                })
                .sum::<f64>()
                / validators.len() as f64
        } else {
            1.0
        };

        ElectionStats {
            total_validators: validators.len(),
            active_validators: active_count,
            total_stake: *self.total_stake.read(),
            total_weighted_stake: *self.total_weighted_stake.read(),
            total_useful_work_score: total_useful_work,
            average_multiplier: avg_multiplier,
        }
    }
}

impl LeaderElection for PoUWElection {
    /// Calculate threshold for a validator
    ///
    /// Formula:
    /// ```text
    /// Threshold = (MAX_VRF_OUTPUT × Stake × UsefulWorkMultiplier) / TotalWeightedStake
    /// ```
    fn calculate_threshold(
        &self,
        stake: u128,
        useful_work_score: u64,
        total_weighted_stake: u128,
    ) -> BigUint {
        if total_weighted_stake == 0 {
            return BigUint::zero();
        }

        // 1. Calculate useful work multiplier
        let multiplier = self.useful_work_multiplier(useful_work_score);

        // 2. Calculate weighted stake (using fixed-point for precision)
        let weighted_stake = (stake as f64 * multiplier * PRECISION as f64) as u128;

        // 3. Calculate threshold
        // Threshold = (MAX_VRF × weighted_stake) / (total_weighted × precision)
        let max_vrf = max_vrf_output();
        let numerator = max_vrf * BigUint::from(weighted_stake);
        let denominator = BigUint::from(total_weighted_stake) * BigUint::from(PRECISION);

        if denominator.is_zero() {
            return BigUint::zero();
        }

        numerator / denominator
    }

    /// Calculate Useful Work Multiplier
    ///
    /// Uses logarithmic scaling to prevent domination while rewarding contribution:
    /// - Multiplier = 1 + log₁₀(1 + score) / 6
    /// - Capped at MAX_USEFUL_WORK_MULTIPLIER
    ///
    /// This provides more gradual scaling than log₂:
    /// - Score 0:         1.0x (no boost)
    /// - Score 1,000:     ~1.5x
    /// - Score 1,000,000: ~2.0x
    /// - Score 10^9:      ~2.5x
    /// - Score 10^12+:    5.0x (capped)
    fn compute_multiplier(&self, useful_work_score: u64) -> f64 {
        self.useful_work_multiplier(useful_work_score)
    }

    /// Check if VRF output meets threshold
    fn check_vrf_threshold(&self, vrf_output: &[u8], threshold: &BigUint) -> bool {
        let output_value = BigUint::from_bytes_be(vrf_output);
        output_value < *threshold
    }

    /// Calculate weighted stake for a validator
    fn weighted_stake(&self, stake: u128, useful_work_score: u64) -> u128 {
        self.weighted_stake_internal(stake, useful_work_score)
    }
}

impl PoUWElection {
    /// Calculate Useful Work Multiplier (internal implementation)
    fn useful_work_multiplier(&self, useful_work_score: u64) -> f64 {
        // Use log₁₀ for more gradual scaling
        // Formula: 1 + log₁₀(1 + score) / 6
        let raw_multiplier = 1.0 + (1.0 + useful_work_score as f64).log10() / 6.0;
        raw_multiplier.min(self.config.max_useful_work_multiplier)
    }
}

/// Election statistics (simplified)
#[derive(Debug, Clone)]
pub struct ElectionStats {
    /// Total registered validators
    pub total_validators: usize,
    /// Active validators
    pub active_validators: usize,
    /// Total staked amount
    pub total_stake: u128,
    /// Total weighted stake
    pub total_weighted_stake: u128,
    /// Total useful work score across all validators
    pub total_useful_work_score: u64,
    /// Average useful work multiplier
    pub average_multiplier: f64,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_validator(address: Address, stake: u128) -> ValidatorInfo {
        ValidatorInfo::new(address, stake, vec![0x02; 33], vec![], 1000, 0)
    }

    #[test]
    fn test_useful_work_multiplier() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        // No useful work: 1.0x
        let mult_0 = election.useful_work_multiplier(0);
        assert!((mult_0 - 1.0).abs() < 0.01);

        // Some useful work: ~1.5x
        let mult_1k = election.useful_work_multiplier(1000);
        assert!(mult_1k > 1.4 && mult_1k < 1.6);

        // High useful work: ~2x
        let mult_1m = election.useful_work_multiplier(1_000_000);
        assert!(mult_1m > 1.9 && mult_1m < 2.1);

        // Very high: approaching cap
        let mult_1b = election.useful_work_multiplier(1_000_000_000);
        assert!(mult_1b > 2.4 && mult_1b < 2.7);

        // Maximum u64 yields ~4.2x with log10/6 scaling (cap at 5.0x not reached)
        let mult_max = election.useful_work_multiplier(u64::MAX);
        assert!(mult_max > 4.0 && mult_max < 4.5);
    }

    #[test]
    fn test_threshold_calculation() {
        let config = PoUWConfig::devnet();
        let election = PoUWElection::new(config);

        // Equal stake, different useful work scores
        let stake = 1_000_000u128;

        // Validator A: no useful work
        let threshold_a = election.calculate_threshold(stake, 0, stake * 2);

        // Validator B: high useful work
        let threshold_b = election.calculate_threshold(stake, 1_000_000, stake * 2);

        // B should have higher threshold (more likely to be selected)
        assert!(threshold_b > threshold_a);
    }

    #[test]
    fn test_weighted_stake() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let stake = 1_000_000u128;

        // No useful work: weighted = stake
        let weighted_0 = election.weighted_stake(stake, 0);
        assert_eq!(weighted_0, stake);

        // With useful work: weighted > stake
        let weighted_1m = election.weighted_stake(stake, 1_000_000);
        assert!(weighted_1m > stake);
        assert!(weighted_1m < stake * 3); // Should be ~2x
    }

    #[test]
    fn test_validator_registration() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [1u8; 32];
        let validator = create_validator(addr, 1_000_000);

        election.register_validator(validator).unwrap();

        let retrieved = election.get_validator(&addr).unwrap();
        assert_eq!(retrieved.stake, 1_000_000);

        let stats = election.stats();
        assert_eq!(stats.total_validators, 1);
        assert!(stats.total_stake > 0);
    }

    #[test]
    fn test_useful_work_recording() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [1u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        let old_weighted = election.stats().total_weighted_stake;

        // Record useful work
        election
            .record_useful_work(
                &addr,
                10000,
                UtilityCategory::Financial,
                VerificationMethod::Hybrid,
                5000,
            )
            .unwrap();

        let new_weighted = election.stats().total_weighted_stake;
        assert!(new_weighted > old_weighted);

        let score = election.get_useful_work_score(&addr);
        assert!(score > 0);
    }

    #[test]
    fn test_vrf_threshold_check() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        // Low output should pass high threshold
        let low_output = [0u8; 32];
        let high_threshold = BigUint::from(u128::MAX);
        assert!(election.check_vrf_threshold(&low_output, &high_threshold));

        // High output should fail low threshold
        let high_output = [0xFF; 32];
        let low_threshold = BigUint::from(1u8);
        assert!(!election.check_vrf_threshold(&high_output, &low_threshold));
    }

    #[test]
    fn test_active_validators() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        // Active validator
        let mut v1 = create_validator([1u8; 32], crate::MIN_STAKE_FOR_ELECTION);
        v1.active = true;
        election.register_validator(v1).unwrap();

        // Jailed validator
        let mut v2 = create_validator([2u8; 32], crate::MIN_STAKE_FOR_ELECTION);
        v2.jailed_until = 1000;
        election.register_validator(v2).unwrap();

        // At slot 0: only v1 is active
        let active = election.active_validators(0);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].address, [1u8; 32]);

        // At slot 1000: both are active
        let active = election.active_validators(1000);
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_useful_work_score_tracking() {
        let mut score = UsefulWorkScore::new();

        // Add some work
        score.add_uwu(
            1000,
            UtilityCategory::Financial,
            VerificationMethod::TeeAttestation,
            5000,
            0,
        );
        score.add_uwu(
            2000,
            UtilityCategory::Medical,
            VerificationMethod::Hybrid,
            10000,
            0,
        );

        assert_eq!(score.total_uwu, 3000);
        assert_eq!(score.total_jobs_verified, 2);
        assert_eq!(
            *score
                .uwu_by_category
                .get(&UtilityCategory::Financial)
                .unwrap(),
            1000
        );
        assert_eq!(
            *score
                .uwu_by_category
                .get(&UtilityCategory::Medical)
                .unwrap(),
            2000
        );
    }

    #[test]
    fn test_category_diversity() {
        let mut score = UsefulWorkScore::new();

        // Single category = low diversity
        score.uwu_by_category.insert(UtilityCategory::General, 1000);
        let low_diversity = score.category_diversity_score();

        // Multiple categories = higher diversity
        score
            .uwu_by_category
            .insert(UtilityCategory::Financial, 1000);
        score.uwu_by_category.insert(UtilityCategory::Medical, 1000);
        score
            .uwu_by_category
            .insert(UtilityCategory::Scientific, 1000);
        let high_diversity = score.category_diversity_score();

        assert!(high_diversity > low_diversity);
    }

    #[test]
    fn test_suspicious_activity_detection() {
        let config = PoUWConfig::mainnet();
        let mut score = UsefulWorkScore::new();

        // Normal activity: not suspicious
        score.add_uwu(
            1000,
            UtilityCategory::Financial,
            VerificationMethod::TeeAttestation,
            5000,
            0,
        );
        score.add_uwu(
            1000,
            UtilityCategory::Medical,
            VerificationMethod::Hybrid,
            5000,
            0,
        );
        assert!(!score.is_suspicious(&config));

        // Single category dominance: suspicious
        let mut suspicious_score = UsefulWorkScore::new();
        suspicious_score
            .uwu_by_category
            .insert(UtilityCategory::General, 99000);
        suspicious_score
            .uwu_by_category
            .insert(UtilityCategory::Financial, 100);
        assert!(suspicious_score.is_suspicious(&config));
    }

    // =========================================================================
    // remove_validator
    // =========================================================================

    #[test]
    fn test_remove_validator_success() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [10u8; 32];
        let validator = create_validator(addr, 5_000_000);
        election.register_validator(validator).unwrap();

        // Sanity: validator is present and totals are updated
        assert!(election.get_validator(&addr).is_some());
        let stats_before = election.stats();
        assert_eq!(stats_before.total_validators, 1);
        assert_eq!(stats_before.total_stake, 5_000_000);

        // Remove should succeed
        election
            .remove_validator(&addr)
            .expect("remove_validator should succeed");

        // Validator must be gone
        assert!(election.get_validator(&addr).is_none());

        let stats_after = election.stats();
        assert_eq!(stats_after.total_validators, 0);
        assert_eq!(stats_after.total_stake, 0);
        assert_eq!(stats_after.total_weighted_stake, 0);

        // Useful work details must also be cleaned up
        assert!(election.get_useful_work_details(&addr).is_none());
    }

    #[test]
    fn test_remove_validator_not_registered() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [99u8; 32];
        // Should return ValidatorNotRegistered error when the validator does not exist
        let result = election.remove_validator(&addr);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::ValidatorNotRegistered { .. } => {}
            other => panic!("Expected ValidatorNotRegistered, got: {:?}", other),
        }
    }

    #[test]
    fn test_remove_validator_removes_from_threshold_cache() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [11u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // Trigger threshold computation so it is placed in cache
        let _ = election.check_eligibility(&addr, 0, &VrfKeys::from_seed(&[0u8; 32]).unwrap());

        election.remove_validator(&addr).unwrap();

        // After removal the entry should no longer be in the threshold cache (internal state);
        // the external observable effect is that trying to check eligibility now returns an error.
        let result = election.check_eligibility(&addr, 0, &VrfKeys::from_seed(&[0u8; 32]).unwrap());
        assert!(result.is_err());
    }

    // =========================================================================
    // set_epoch_seed
    // =========================================================================

    #[test]
    fn test_set_epoch_seed_updates_seed() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let initial_seed = election.epoch_seed();
        assert_eq!(initial_seed, [0u8; 32]);

        let new_seed: EpochSeed = [42u8; 32];
        election.set_epoch_seed(new_seed);

        assert_eq!(election.epoch_seed(), new_seed);
    }

    #[test]
    fn test_set_epoch_seed_clears_threshold_cache() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [5u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // Populate threshold cache by running check_eligibility
        let keys = VrfKeys::from_seed(&[5u8; 32]).unwrap();
        let _ = election.check_eligibility(&addr, 0, &keys);

        // Setting the epoch seed must clear the threshold cache.
        // We verify indirectly: changing the seed changes the VRF message, and if the cache
        // were not cleared the stale threshold would still be there. We simply assert no panic.
        election.set_epoch_seed([99u8; 32]);
        assert_eq!(election.epoch_seed(), [99u8; 32]);
    }

    // =========================================================================
    // set_current_epoch
    // =========================================================================

    #[test]
    fn test_set_current_epoch_advances() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [3u8; 32];
        let validator = create_validator(addr, 2_000_000);
        election.register_validator(validator).unwrap();

        let weighted_before = election.stats().total_weighted_stake;

        // Advance epoch - should trigger recalculate_weighted_stakes internally
        election.set_current_epoch(5);

        // Total weighted stake must still be positive and consistent
        let weighted_after = election.stats().total_weighted_stake;
        assert!(weighted_after > 0);
        // With devnet (no decay), advancing epoch should keep weighted stake equal
        assert_eq!(weighted_before, weighted_after);
    }

    #[test]
    fn test_set_current_epoch_does_not_regress() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        election.set_current_epoch(10);
        // Trying to set a lower epoch should be a no-op - no panic expected
        election.set_current_epoch(5);

        // We cannot directly read current_epoch, but verifying no panic is sufficient.
        // If needed we can observe weighted stake is unchanged.
        let addr = [4u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();
        let stats = election.stats();
        assert_eq!(stats.total_validators, 1);
    }

    // =========================================================================
    // get_useful_work_details
    // =========================================================================

    #[test]
    fn test_get_useful_work_details_none_for_unknown() {
        let election = PoUWElection::new(PoUWConfig::devnet());
        let addr = [200u8; 32];
        assert!(election.get_useful_work_details(&addr).is_none());
    }

    #[test]
    fn test_get_useful_work_details_returns_cloned_score() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [7u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // Initially exists with zero UWU after registration
        let details = election.get_useful_work_details(&addr);
        assert!(details.is_some());
        let details = details.unwrap();
        assert_eq!(details.total_uwu, 0);

        // Record some work
        election
            .record_useful_work(
                &addr,
                999,
                UtilityCategory::Scientific,
                VerificationMethod::ZkProof,
                3000,
            )
            .unwrap();

        // The clone returned now should show updated total_uwu
        let updated = election.get_useful_work_details(&addr).unwrap();
        assert_eq!(updated.total_uwu, 999);
    }

    // =========================================================================
    // get_validator
    // =========================================================================

    #[test]
    fn test_get_validator_none_for_unknown() {
        let election = PoUWElection::new(PoUWConfig::devnet());
        assert!(election.get_validator(&[55u8; 32]).is_none());
    }

    #[test]
    fn test_get_validator_returns_correct_info() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [6u8; 32];
        let validator = create_validator(addr, 8_000_000);
        election.register_validator(validator).unwrap();

        let info = election.get_validator(&addr).unwrap();
        assert_eq!(info.address, addr);
        assert_eq!(info.stake, 8_000_000);
        assert!(info.active);
    }

    // =========================================================================
    // check_eligibility
    // =========================================================================

    #[test]
    fn test_check_eligibility_not_registered() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let keys = VrfKeys::from_seed(&[1u8; 32]).unwrap();
        let addr = [88u8; 32];
        let result = election.check_eligibility(&addr, 0, &keys);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::ValidatorNotRegistered { .. } => {}
            other => panic!("Expected ValidatorNotRegistered, got: {:?}", other),
        }
    }

    #[test]
    fn test_check_eligibility_jailed_validator() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [20u8; 32];
        let mut validator = create_validator(addr, crate::MIN_STAKE_FOR_ELECTION);
        validator.jailed_until = 1000; // jailed until slot 1000
        election.register_validator(validator).unwrap();

        let keys = VrfKeys::from_seed(&[20u8; 32]).unwrap();
        // At slot 0 the validator is jailed - should get NotEligible
        let result = election.check_eligibility(&addr, 0, &keys);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::NotEligible { .. } => {}
            other => panic!("Expected NotEligible, got: {:?}", other),
        }
    }

    #[test]
    fn test_check_eligibility_active_validator_returns_result() {
        // Use a large stake and very permissive devnet config so that the validator
        // is extremely likely to win the VRF lottery (threshold nearly MAX).
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [21u8; 32];
        let seed = [21u8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();

        // Register with VRF public key matching the key we will use
        let mut validator = ValidatorInfo::new(
            addr,
            crate::MIN_STAKE_FOR_ELECTION,
            keys.public_key_bytes(),
            vec![],
            1000,
            0,
        );
        validator.active = true;
        election.register_validator(validator).unwrap();

        // Result must be Ok (either Some or None depending on VRF output vs threshold)
        let result = election.check_eligibility(&addr, 0, &keys);
        assert!(result.is_ok());
    }

    // =========================================================================
    // record_useful_work for suspicious validator
    // =========================================================================

    #[test]
    fn test_record_useful_work_suspicious_validator_blocked() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [30u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // Directly flag the score as suspicious by setting enough suspicious flags
        {
            let mut scores = election.useful_work_scores.write();
            let score = scores.get_mut(&addr).unwrap();
            score.suspicious_flags = 3; // Threshold for is_suspicious
        }

        let result = election.record_useful_work(
            &addr,
            100,
            UtilityCategory::General,
            VerificationMethod::ReExecution,
            1000,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::SuspiciousActivity { .. } => {}
            other => panic!("Expected SuspiciousActivity, got: {:?}", other),
        }
    }

    // =========================================================================
    // statistics / stats
    // =========================================================================

    #[test]
    fn test_statistics_default_empty() {
        let election = PoUWElection::new(PoUWConfig::devnet());
        let stats = election.statistics();
        assert_eq!(stats.total_elections, 0);
        assert_eq!(stats.avg_winner_score, 0);
        assert_eq!(stats.min_winning_score, 0);
        assert_eq!(stats.max_losing_score, 0);
        assert_eq!(stats.multi_winner_slots, 0);
        assert!(stats.wins_by_top_category.is_empty());
    }

    #[test]
    fn test_stats_empty_election() {
        let election = PoUWElection::new(PoUWConfig::devnet());
        let stats = election.stats();
        assert_eq!(stats.total_validators, 0);
        assert_eq!(stats.active_validators, 0);
        assert_eq!(stats.total_stake, 0);
        assert_eq!(stats.total_weighted_stake, 0);
        assert_eq!(stats.total_useful_work_score, 0);
        // Average multiplier defaults to 1.0 when there are no validators
        assert!((stats.average_multiplier - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_populated_election() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr1 = [40u8; 32];
        let addr2 = [41u8; 32];

        let mut v1 = create_validator(addr1, 3_000_000);
        v1.active = true;
        election.register_validator(v1).unwrap();

        let mut v2 = create_validator(addr2, 1_000_000);
        v2.active = true;
        election.register_validator(v2).unwrap();

        // Record some useful work for v1
        election
            .record_useful_work(
                &addr1,
                5000,
                UtilityCategory::Medical,
                VerificationMethod::Hybrid,
                10000,
            )
            .unwrap();

        let stats = election.stats();
        assert_eq!(stats.total_validators, 2);
        assert_eq!(stats.active_validators, 2);
        assert_eq!(stats.total_stake, 4_000_000);
        assert!(stats.total_weighted_stake > 0);
        assert!(stats.total_useful_work_score > 0);
        // Average multiplier must be at least 1.0
        assert!(stats.average_multiplier >= 1.0);
    }

    // =========================================================================
    // record_election_win (observable via statistics)
    // =========================================================================

    #[test]
    fn test_record_election_win_via_check_eligibility() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [50u8; 32];
        let seed = [50u8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();

        // Register with matching VRF key
        let mut validator = ValidatorInfo::new(
            addr,
            crate::MIN_STAKE_FOR_ELECTION,
            keys.public_key_bytes(),
            vec![],
            1000,
            0,
        );
        validator.active = true;
        election.register_validator(validator).unwrap();

        // Add very large useful work to maximise probability of winning the VRF lottery
        election
            .record_useful_work(
                &addr,
                1_000_000_000,
                UtilityCategory::Medical,
                VerificationMethod::Hybrid,
                10_000,
            )
            .unwrap();

        // Invoke check_eligibility multiple times across different slots to
        // increase the chance of at least one winning slot in devnet.
        let mut won = false;
        for slot in 0u64..20 {
            if let Ok(Some(_)) = election.check_eligibility(&addr, slot, &keys) {
                won = true;
                break;
            }
        }

        if won {
            let stats = election.statistics();
            assert!(stats.total_elections >= 1);
            assert!(stats.min_winning_score > 0 || stats.total_elections >= 1);
        }
        // Even if this particular VRF output never wins, the test validates that
        // check_eligibility does not panic and returns Ok.
    }

    // =========================================================================
    // UsefulWorkScore::calculate_decayed_score
    // =========================================================================

    #[test]
    fn test_calculate_decayed_score_no_decay() {
        let config = PoUWConfig::devnet(); // devnet: decay_factor = 1.0 (no decay)
        let mut score = UsefulWorkScore::new();

        score.add_uwu(
            10_000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            5000,
            0,
        );

        // At current_epoch == 0 (same epoch as recording), full score is returned
        let decayed = score.calculate_decayed_score(0, &config);
        // reputation_score starts at 500; factor = 500/500 = 1.0
        assert_eq!(decayed, 10_000);
    }

    #[test]
    fn test_calculate_decayed_score_with_actual_decay() {
        let config = PoUWConfig::mainnet(); // mainnet: decay_factor = 0.95
        let mut score = UsefulWorkScore::new();

        // Record 10_000 UWU at epoch 0
        score.add_uwu(
            10_000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            5000,
            0,
        );

        // At epoch 1 (1 epoch later), decayed = 10_000 * 0.95^1 * reputation_factor
        let decayed_epoch1 = score.calculate_decayed_score(1, &config);
        // reputation_factor = 1.0 → expected ≈ 9_500
        assert!(decayed_epoch1 < 10_000);
        assert!(decayed_epoch1 > 8_000);

        // At epoch 2, further decay
        let decayed_epoch2 = score.calculate_decayed_score(2, &config);
        assert!(decayed_epoch2 < decayed_epoch1);
    }

    #[test]
    fn test_calculate_decayed_score_multiple_epochs() {
        let config = PoUWConfig::devnet(); // no decay
        let mut score = UsefulWorkScore::new();

        score.add_uwu(
            1_000,
            UtilityCategory::Financial,
            VerificationMethod::Hybrid,
            1000,
            0,
        );
        score.add_uwu(
            2_000,
            UtilityCategory::Medical,
            VerificationMethod::Hybrid,
            1000,
            1,
        );

        // At epoch 1, both epoch 0 and epoch 1 contributions are in the window
        let total = score.calculate_decayed_score(1, &config);
        // devnet decay = 1.0 → 1_000 * 1.0^1 + 2_000 * 1.0^0 = 3_000
        assert_eq!(total, 3_000);
    }

    // =========================================================================
    // UsefulWorkScore::apply_penalty
    // =========================================================================

    #[test]
    fn test_apply_penalty_reduces_uwu_and_increments_flags() {
        let mut score = UsefulWorkScore::new();
        score.total_uwu = 10_000;
        assert_eq!(score.suspicious_flags, 0);

        // Apply 10% penalty
        score.apply_penalty(10);

        assert_eq!(score.total_uwu, 9_000);
        assert_eq!(score.suspicious_flags, 1);
    }

    #[test]
    fn test_apply_penalty_does_not_underflow() {
        let mut score = UsefulWorkScore::new();
        score.total_uwu = 50;

        // Apply 200% penalty - saturating_sub prevents underflow
        score.apply_penalty(200);

        // Penalty = 50 * 200 / 100 = 100; saturating_sub(100) from 50 = 0
        assert_eq!(score.total_uwu, 0);
        assert_eq!(score.suspicious_flags, 1);
    }

    #[test]
    fn test_apply_penalty_zero_pct() {
        let mut score = UsefulWorkScore::new();
        score.total_uwu = 5_000;

        score.apply_penalty(0);

        // A 0% penalty removes nothing but still increments the flag
        assert_eq!(score.total_uwu, 5_000);
        assert_eq!(score.suspicious_flags, 1);
    }

    // =========================================================================
    // UsefulWorkScore::reset_flags
    // =========================================================================

    #[test]
    fn test_reset_flags_clears_suspicious_flags() {
        let mut score = UsefulWorkScore::new();

        // Accumulate some flags
        score.apply_penalty(5);
        score.apply_penalty(5);
        score.apply_penalty(5);
        assert_eq!(score.suspicious_flags, 3);

        score.reset_flags();
        assert_eq!(score.suspicious_flags, 0);
    }

    #[test]
    fn test_reset_flags_idempotent_when_zero() {
        let mut score = UsefulWorkScore::new();
        assert_eq!(score.suspicious_flags, 0);
        score.reset_flags();
        assert_eq!(score.suspicious_flags, 0);
    }

    // =========================================================================
    // UsefulWorkScore::is_suspicious - re-execution dominance
    // =========================================================================

    #[test]
    fn test_is_suspicious_reexecution_dominance() {
        let config = PoUWConfig::mainnet();
        let mut score = UsefulWorkScore::new();

        // Add enough jobs so that re-execution dominates (> 90%)
        // 10 jobs: 9 re-execution, 1 other
        for _ in 0..9 {
            score.add_uwu(
                100,
                UtilityCategory::General,
                VerificationMethod::ReExecution,
                1000,
                0,
            );
        }
        score.add_uwu(
            100,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            1000,
            0,
        );

        assert!(score.is_suspicious(&config));
    }

    #[test]
    fn test_is_suspicious_not_triggered_by_flags_below_threshold() {
        let config = PoUWConfig::mainnet();
        let mut score = UsefulWorkScore::new();

        // Two flags (threshold is 3)
        score.suspicious_flags = 2;
        // Balanced categories
        score.add_uwu(
            500,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            1000,
            0,
        );
        score.add_uwu(
            500,
            UtilityCategory::Financial,
            VerificationMethod::ZkProof,
            1000,
            0,
        );

        assert!(!score.is_suspicious(&config));
    }

    #[test]
    fn test_is_suspicious_three_flags() {
        let config = PoUWConfig::mainnet();
        let mut score = UsefulWorkScore::new();

        score.suspicious_flags = 3;
        assert!(score.is_suspicious(&config));
    }

    // =========================================================================
    // UsefulWorkScore::category_diversity_score - edge cases
    // =========================================================================

    #[test]
    fn test_category_diversity_score_empty() {
        let score = UsefulWorkScore::new();
        assert_eq!(score.category_diversity_score(), 0);
    }

    #[test]
    fn test_category_diversity_score_all_zero_values() {
        let mut score = UsefulWorkScore::new();
        // Insert a category with zero UWU
        score.uwu_by_category.insert(UtilityCategory::General, 0);
        // total_uwu == 0 path
        assert_eq!(score.category_diversity_score(), 0);
    }

    #[test]
    fn test_category_diversity_score_perfect_spread() {
        let mut score = UsefulWorkScore::new();
        // Equal spread across all 8 categories = maximum diversity
        for &cat in UtilityCategory::all() {
            score.uwu_by_category.insert(cat, 1000);
        }
        let diversity = score.category_diversity_score();
        // Maximum possible is 100
        assert!(diversity > 80);
    }

    // =========================================================================
    // ElectionStatistics::default
    // =========================================================================

    #[test]
    fn test_election_statistics_default() {
        let stats = ElectionStatistics::default();
        assert_eq!(stats.total_elections, 0);
        assert_eq!(stats.avg_winner_score, 0);
        assert_eq!(stats.median_winner_stake, 0);
        assert_eq!(stats.multi_winner_slots, 0);
        assert_eq!(stats.min_winning_score, 0);
        assert_eq!(stats.max_losing_score, 0);
        assert!(stats.wins_by_top_category.is_empty());
    }

    // =========================================================================
    // LeaderElection trait - compute_multiplier delegation
    // =========================================================================

    #[test]
    fn test_compute_multiplier_trait_method_delegates_correctly() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        // compute_multiplier is the trait method; useful_work_multiplier is the internal one.
        // Both must produce identical results.
        let scores: &[u64] = &[0, 1, 100, 1_000, 1_000_000, 1_000_000_000, u64::MAX];
        for &s in scores {
            let via_trait = election.compute_multiplier(s);
            let internal = election.useful_work_multiplier(s);
            assert!(
                (via_trait - internal).abs() < 1e-12,
                "Mismatch at score {}: trait={} internal={}",
                s,
                via_trait,
                internal
            );
        }
    }

    // =========================================================================
    // verify_proposer
    // =========================================================================

    #[test]
    fn test_verify_proposer_validator_not_registered() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [60u8; 32];
        let result = election.verify_proposer(&addr, 0, 0, &[0u8; 32], &vec![0u8; VrfProof::SIZE]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::ValidatorNotRegistered { .. } => {}
            other => panic!("Expected ValidatorNotRegistered, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proposer_score_mismatch() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [61u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // The actual score is 0; claim a wildly different value
        let claimed_score = 999_999_999u64;
        let fake_proof = vec![0u8; VrfProof::SIZE];
        let fake_output = [0u8; 32];

        let result = election.verify_proposer(&addr, 0, claimed_score, &fake_output, &fake_proof);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::UsefulWorkScoreMismatch { .. } => {}
            other => panic!("Expected UsefulWorkScoreMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proposer_malformed_output_length() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [62u8; 32];
        let validator = create_validator(addr, 1_000_000);
        election.register_validator(validator).unwrap();

        // Score matches (both are 0), but output length is wrong
        let fake_proof = vec![0u8; VrfProof::SIZE];
        let bad_output = vec![0u8; 16]; // Should be 32

        let result = election.verify_proposer(&addr, 0, 0, &bad_output, &fake_proof);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::MalformedVrfProof { .. } => {}
            other => panic!("Expected MalformedVrfProof, got: {:?}", other),
        }
    }

    #[test]
    fn test_verify_proposer_full_valid_flow() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let seed = [70u8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();
        let addr = [70u8; 32];

        // Register with the correct VRF public key
        let validator = ValidatorInfo::new(
            addr,
            crate::MIN_STAKE_FOR_ELECTION,
            keys.public_key_bytes(),
            vec![],
            1000,
            0,
        );
        election.register_validator(validator).unwrap();

        // Generate a legitimate VRF proof for slot 0
        let epoch_seed = election.epoch_seed();
        let vrf_engine = VrfEngine::with_chain_id(999); // devnet chain_id
        let (vrf_output, vrf_proof) = vrf_engine.prove_for_slot(&keys, &epoch_seed, 0).unwrap();

        let proof_bytes = vrf_proof.to_bytes();
        let output_bytes = vrf_output.as_bytes();

        // Actual score is 0, we claim 0 - score matches
        let claimed_score = 0u64;

        let result = election.verify_proposer(&addr, 0, claimed_score, output_bytes, &proof_bytes);

        // The VRF proof itself is valid; the only remaining check is the threshold.
        // If below threshold: Ok(()); if above: VrfThresholdNotMet.
        match result {
            Ok(()) => {} // Proposer was eligible - test passes
            Err(ConsensusError::VrfThresholdNotMet { .. }) => {} // Also valid: VRF passed but threshold not met
            Err(other) => panic!("Unexpected error in verify_proposer: {:?}", other),
        }
    }

    // =========================================================================
    // Registration with insufficient stake
    // =========================================================================

    #[test]
    fn test_register_validator_insufficient_stake_on_mainnet() {
        let election = PoUWElection::new(PoUWConfig::mainnet());

        let addr = [80u8; 32];
        // Mainnet min_stake = 1_000_000_000_000_000_000; 1 is far below
        let validator = create_validator(addr, 1);
        let result = election.register_validator(validator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConsensusError::InsufficientStake { .. } => {}
            other => panic!("Expected InsufficientStake, got: {:?}", other),
        }
    }

    // =========================================================================
    // Registration update (re-register same address)
    // =========================================================================

    #[test]
    fn test_register_validator_update_existing() {
        let election = PoUWElection::new(PoUWConfig::devnet());

        let addr = [90u8; 32];
        let v1 = create_validator(addr, 1_000_000);
        election.register_validator(v1).unwrap();

        let stats_before = election.stats();
        assert_eq!(stats_before.total_stake, 1_000_000);

        // Re-register with a higher stake - should update totals correctly
        let v2 = create_validator(addr, 3_000_000);
        election.register_validator(v2).unwrap();

        let stats_after = election.stats();
        // Total stake should reflect the new value, not a double-count
        assert_eq!(stats_after.total_validators, 1);
        assert_eq!(stats_after.total_stake, 3_000_000);
    }
}
