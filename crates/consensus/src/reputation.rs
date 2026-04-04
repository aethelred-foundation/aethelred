//! Compute Reputation State Machine
//!
//! Enterprise-grade implementation of the sliding-window reputation system
//! that tracks and scores validator compute contributions.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                  COMPUTE REPUTATION STATE MACHINE                        │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌─────────────────────────────────────────────────────────────────────┐ │
//! │  │                        30-DAY SLIDING WINDOW                         │ │
//! │  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ... ┌─────┐       │ │
//! │  │  │Day 1│ │Day 2│ │Day 3│ │Day 4│ │Day 5│ │Day 6│     │Day30│       │ │
//! │  │  │  ▼  │ │  ▼  │ │  ▼  │ │  ▼  │ │  ▼  │ │  ▼  │     │  ▼  │       │ │
//! │  │  │0.97x│ │0.97x│ │0.97x│ │0.97x│ │0.97x│ │0.97x│     │1.00x│       │ │
//! │  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘     └─────┘       │ │
//! │  │                    EXPONENTIAL DECAY                                │ │
//! │  └─────────────────────────────────────────────────────────────────────┘ │
//! │                                                                          │
//! │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐       │
//! │  │   Job Tracker    │  │   Score Decay    │  │ Snapshot Engine  │       │
//! │  │  ─────────────   │  │  ─────────────   │  │  ─────────────   │       │
//! │  │  record_job()    │  │  apply_decay()   │  │  snapshot()      │       │
//! │  │  get_jobs()      │  │  decay_rate()    │  │  restore()       │       │
//! │  └──────────────────┘  └──────────────────┘  └──────────────────┘       │
//! │                                                                          │
//! │  Score Formula:                                                          │
//! │  ┌─────────────────────────────────────────────────────────────────────┐ │
//! │  │  CurrentScore = Σ (JobComplexity × MethodMultiplier × DecayFactor)  │ │
//! │  │                 i=0..30                                              │ │
//! │  │                                                                      │ │
//! │  │  DecayFactor(age_days) = DECAY_RATE ^ age_days                      │ │
//! │  │  DECAY_RATE = 0.97 (configurable)                                   │ │
//! │  │                                                                      │ │
//! │  │  ComputeMultiplier = min(1 + log₂(1 + Score) / 10, MAX_MULT)       │ │
//! │  └─────────────────────────────────────────────────────────────────────┘ │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

use crate::error::{ConsensusError, ConsensusResult};
use crate::traits::VerificationMethod;
use crate::types::{Address, Hash, Slot};
use hex::encode;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Default decay rate per day (0.97 = 3% decay)
pub const DEFAULT_DECAY_RATE: f64 = 0.97;

/// Default window size in days
pub const DEFAULT_WINDOW_DAYS: u32 = 30;

/// Slots per day (6 second slots)
pub const SLOTS_PER_DAY: u64 = 14400;

/// Maximum score to prevent overflow
pub const MAX_SCORE: u64 = u64::MAX / 100;

/// Maximum complexity per job (prevents f64 precision issues in scoring)
/// Real PoUW complexity is bounded by hardware capabilities; this is a safety cap.
pub const MAX_COMPLEXITY: u64 = 1_000_000_000_000; // 1 trillion FLOPS

/// Method multipliers for different verification types
pub const MULTIPLIER_TEE: f64 = 1.0;
pub const MULTIPLIER_ZK: f64 = 1.5;
pub const MULTIPLIER_HYBRID: f64 = 2.0;
pub const MULTIPLIER_REEXEC: f64 = 0.8;

// =============================================================================
// REPUTATION CONFIGURATION
// =============================================================================

/// Configuration for the reputation system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Daily decay rate (0.97 = 3% daily decay)
    pub decay_rate: f64,

    /// Window size in days
    pub window_days: u32,

    /// Minimum complexity to count
    pub min_complexity: u64,

    /// Maximum jobs per validator per day
    pub max_jobs_per_day: u32,

    /// Penalty for failed verifications
    pub failure_penalty_multiplier: f64,

    /// Bonus for consistent uptime
    pub uptime_bonus_threshold: f64,

    /// Enable score smoothing
    pub enable_smoothing: bool,

    /// Smoothing factor (0-1, higher = more smoothing)
    pub smoothing_factor: f64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl ReputationConfig {
    /// Production configuration
    pub fn production() -> Self {
        Self {
            decay_rate: DEFAULT_DECAY_RATE,
            window_days: DEFAULT_WINDOW_DAYS,
            min_complexity: 100,
            max_jobs_per_day: 10000,
            failure_penalty_multiplier: 2.0,
            uptime_bonus_threshold: 0.95,
            enable_smoothing: true,
            smoothing_factor: 0.1,
        }
    }

    /// Testnet configuration (faster decay for testing)
    pub fn testnet() -> Self {
        Self {
            decay_rate: 0.90,
            window_days: 7,
            min_complexity: 10,
            max_jobs_per_day: 100000,
            failure_penalty_multiplier: 1.5,
            uptime_bonus_threshold: 0.80,
            enable_smoothing: false,
            smoothing_factor: 0.0,
        }
    }

    /// Development configuration
    pub fn devnet() -> Self {
        Self {
            decay_rate: 0.80,
            window_days: 3,
            min_complexity: 1,
            max_jobs_per_day: u32::MAX,
            failure_penalty_multiplier: 1.0,
            uptime_bonus_threshold: 0.0,
            enable_smoothing: false,
            smoothing_factor: 0.0,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> ConsensusResult<()> {
        if self.decay_rate <= 0.0 || self.decay_rate > 1.0 {
            return Err(ConsensusError::Config(
                "Decay rate must be in (0, 1]".into(),
            ));
        }

        if self.window_days == 0 {
            return Err(ConsensusError::Config("Window days must be > 0".into()));
        }

        if self.smoothing_factor < 0.0 || self.smoothing_factor > 1.0 {
            return Err(ConsensusError::Config(
                "Smoothing factor must be in [0, 1]".into(),
            ));
        }

        Ok(())
    }
}

// =============================================================================
// COMPUTE JOB RECORD
// =============================================================================

/// Record of a verified compute job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJobRecord {
    /// Unique job ID
    pub job_id: Hash,

    /// Model hash
    pub model_hash: Hash,

    /// Input hash
    pub input_hash: Hash,

    /// Output hash
    pub output_hash: Hash,

    /// Complexity units (normalized FLOPS)
    pub complexity: u64,

    /// Verification method used
    pub verification_method: VerificationMethod,

    /// Slot when job was verified
    pub verified_at_slot: Slot,

    /// Whether verification succeeded
    pub success: bool,

    /// Optional additional metadata
    pub metadata: Option<JobMetadata>,
}

/// Additional job metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobMetadata {
    /// Execution time in milliseconds
    pub execution_time_ms: u64,

    /// Memory used in bytes
    pub memory_used: u64,

    /// Model name/identifier
    pub model_name: Option<String>,

    /// Request origin
    pub request_origin: Option<String>,
}

impl ComputeJobRecord {
    /// Create new job record
    pub fn new(
        job_id: Hash,
        model_hash: Hash,
        input_hash: Hash,
        output_hash: Hash,
        complexity: u64,
        verification_method: VerificationMethod,
        verified_at_slot: Slot,
        success: bool,
    ) -> Self {
        Self {
            job_id,
            model_hash,
            input_hash,
            output_hash,
            complexity,
            verification_method,
            verified_at_slot,
            success,
            metadata: None,
        }
    }

    /// Get method multiplier
    pub fn method_multiplier(&self) -> f64 {
        match self.verification_method {
            VerificationMethod::TeeAttestation => MULTIPLIER_TEE,
            VerificationMethod::ZkProof => MULTIPLIER_ZK,
            VerificationMethod::Hybrid => MULTIPLIER_HYBRID,
            VerificationMethod::ReExecution => MULTIPLIER_REEXEC,
        }
    }

    /// Calculate weighted score contribution
    pub fn weighted_score(&self) -> f64 {
        let base = self.complexity.min(MAX_COMPLEXITY) as f64;
        let multiplier = self.method_multiplier();

        if self.success {
            base * multiplier
        } else {
            0.0 // Failed jobs don't contribute positively
        }
    }

    /// Get age in days
    pub fn age_days(&self, current_slot: Slot) -> u32 {
        if current_slot < self.verified_at_slot {
            return 0;
        }
        let slots_elapsed = current_slot - self.verified_at_slot;
        (slots_elapsed / SLOTS_PER_DAY) as u32
    }
}

// =============================================================================
// VALIDATOR REPUTATION STATE
// =============================================================================

/// Per-validator reputation state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReputation {
    /// Validator address
    pub address: Address,

    /// Current computed score
    pub current_score: u64,

    /// Smoothed score (if smoothing enabled)
    pub smoothed_score: f64,

    /// Jobs within the sliding window (ordered by slot)
    pub window_jobs: VecDeque<ComputeJobRecord>,

    /// Total jobs ever processed
    pub total_jobs: u64,

    /// Total successful jobs
    pub successful_jobs: u64,

    /// Total failed jobs
    pub failed_jobs: u64,

    /// Total complexity ever processed
    pub total_complexity: u128,

    /// Last update slot
    pub last_update_slot: Slot,

    /// Daily job counts (for rate limiting)
    pub daily_job_counts: VecDeque<(u32, u32)>, // (day_index, count)

    /// Consecutive days of activity (for uptime bonus)
    pub active_streak: u32,

    /// Last active day
    pub last_active_day: u32,
}

impl ValidatorReputation {
    /// Create new reputation state
    pub fn new(address: Address) -> Self {
        Self {
            address,
            current_score: 0,
            smoothed_score: 0.0,
            window_jobs: VecDeque::new(),
            total_jobs: 0,
            successful_jobs: 0,
            failed_jobs: 0,
            total_complexity: 0,
            last_update_slot: 0,
            daily_job_counts: VecDeque::new(),
            active_streak: 0,
            last_active_day: 0,
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_jobs == 0 {
            return 1.0;
        }
        self.successful_jobs as f64 / self.total_jobs as f64
    }

    /// Get average complexity per job
    pub fn average_complexity(&self) -> u64 {
        if self.total_jobs == 0 {
            return 0;
        }
        (self.total_complexity / self.total_jobs as u128) as u64
    }
}

// =============================================================================
// REPUTATION ENGINE
// =============================================================================

/// Main reputation state machine
pub struct ReputationEngine {
    /// Configuration
    config: ReputationConfig,

    /// Per-validator reputation states
    validators: RwLock<HashMap<Address, ValidatorReputation>>,

    /// Current slot for age calculations
    current_slot: RwLock<Slot>,

    /// Precomputed decay factors for each day
    decay_factors: Vec<f64>,

    /// Metrics
    metrics: ReputationMetrics,
}

/// Reputation metrics
#[derive(Debug, Default)]
pub struct ReputationMetrics {
    /// Total jobs processed
    pub total_jobs_processed: std::sync::atomic::AtomicU64,
    /// Score recalculations
    pub score_recalculations: std::sync::atomic::AtomicU64,
    /// Window prunings
    pub window_prunings: std::sync::atomic::AtomicU64,
}

impl ReputationEngine {
    /// Create new reputation engine
    pub fn new(config: ReputationConfig) -> Self {
        // Precompute decay factors for efficiency
        let decay_factors: Vec<f64> = (0..=config.window_days)
            .map(|day| config.decay_rate.powi(day as i32))
            .collect();

        Self {
            config,
            validators: RwLock::new(HashMap::new()),
            current_slot: RwLock::new(0),
            decay_factors,
            metrics: ReputationMetrics::default(),
        }
    }

    /// Create with production config
    pub fn production() -> Self {
        Self::new(ReputationConfig::production())
    }

    /// Create with testnet config
    pub fn testnet() -> Self {
        Self::new(ReputationConfig::testnet())
    }

    /// Update current slot
    pub fn update_slot(&self, slot: Slot) {
        *self.current_slot.write() = slot;
    }

    /// Get current slot
    pub fn current_slot(&self) -> Slot {
        *self.current_slot.read()
    }

    // =========================================================================
    // CORE OPERATIONS
    // =========================================================================

    /// Record a compute job for a validator
    ///
    /// Called at the end of every block execution to update scores
    /// based on the Proof-of-Useful-Work transactions in the block.
    pub fn record_job(
        &self,
        validator: Address,
        job: ComputeJobRecord,
    ) -> ConsensusResult<ScoreUpdate> {
        let current_slot = self.current_slot();

        // Validate job
        if job.complexity < self.config.min_complexity {
            return Err(ConsensusError::ReputationUpdateFailed {
                address: encode(validator),
                reason: "Job complexity below minimum".into(),
            });
        }

        // Clamp complexity to MAX_COMPLEXITY to prevent f64 precision issues
        // in scoring calculations. Real PoUW complexity is bounded by hardware.
        let mut job = job;
        job.complexity = job.complexity.min(MAX_COMPLEXITY);

        let mut validators = self.validators.write();
        let state = validators
            .entry(validator)
            .or_insert_with(|| ValidatorReputation::new(validator));

        // Check daily rate limit
        let current_day = (current_slot / SLOTS_PER_DAY) as u32;
        let daily_count = self.get_daily_count(state, current_day);
        if daily_count >= self.config.max_jobs_per_day {
            return Err(ConsensusError::ReputationUpdateFailed {
                address: encode(validator),
                reason: "Daily job limit exceeded".into(),
            });
        }

        // Record the job
        let old_score = state.current_score;
        state.window_jobs.push_back(job.clone());
        state.total_jobs += 1;
        state.total_complexity += job.complexity as u128;

        if job.success {
            state.successful_jobs += 1;
        } else {
            state.failed_jobs += 1;
        }

        // Update daily counts
        self.update_daily_count(state, current_day);

        // Update active streak
        self.update_active_streak(state, current_day);

        // Recalculate score
        let new_score = self.calculate_score(state, current_slot);
        state.current_score = new_score;
        state.last_update_slot = current_slot;

        // Apply smoothing if enabled
        if self.config.enable_smoothing {
            state.smoothed_score = state.smoothed_score * (1.0 - self.config.smoothing_factor)
                + new_score as f64 * self.config.smoothing_factor;
        }

        use std::sync::atomic::Ordering;
        self.metrics
            .total_jobs_processed
            .fetch_add(1, Ordering::Relaxed);

        Ok(ScoreUpdate {
            validator,
            old_score,
            new_score,
            delta: (new_score as i64).saturating_sub(old_score as i64),
            job_id: job.job_id,
        })
    }

    /// Process all compute results from a block
    pub fn process_block_results(
        &self,
        slot: Slot,
        results: &[(Address, ComputeJobRecord)],
    ) -> ConsensusResult<Vec<ScoreUpdate>> {
        self.update_slot(slot);

        let mut updates = Vec::with_capacity(results.len());

        for (validator, job) in results {
            match self.record_job(*validator, job.clone()) {
                Ok(update) => updates.push(update),
                Err(e) => {
                    // Log but don't fail entire block processing
                    log::warn!("Failed to record job for validator {:?}: {}", validator, e);
                }
            }
        }

        // Prune expired jobs from all validators
        self.prune_expired_jobs(slot);

        Ok(updates)
    }

    /// Apply end-of-day decay to all validators
    pub fn apply_daily_decay(&self, current_slot: Slot) -> ConsensusResult<Vec<ScoreUpdate>> {
        let mut validators = self.validators.write();
        let mut updates = Vec::new();

        for (address, state) in validators.iter_mut() {
            let old_score = state.current_score;

            // Prune old jobs and recalculate
            self.prune_window_jobs(state, current_slot);
            let new_score = self.calculate_score(state, current_slot);

            state.current_score = new_score;
            state.last_update_slot = current_slot;

            if old_score != new_score {
                updates.push(ScoreUpdate {
                    validator: *address,
                    old_score,
                    new_score,
                    delta: (new_score as i64).saturating_sub(old_score as i64),
                    job_id: [0u8; 32], // No specific job
                });
            }
        }

        use std::sync::atomic::Ordering;
        self.metrics
            .score_recalculations
            .fetch_add(updates.len() as u64, Ordering::Relaxed);

        Ok(updates)
    }

    /// Get current score for a validator
    pub fn get_score(&self, validator: &Address) -> u64 {
        self.validators
            .read()
            .get(validator)
            .map(|s| s.current_score)
            .unwrap_or(0)
    }

    /// Get smoothed score for a validator
    pub fn get_smoothed_score(&self, validator: &Address) -> f64 {
        self.validators
            .read()
            .get(validator)
            .map(|s| s.smoothed_score)
            .unwrap_or(0.0)
    }

    /// Get full reputation state for a validator
    pub fn get_reputation(&self, validator: &Address) -> Option<ValidatorReputation> {
        self.validators.read().get(validator).cloned()
    }

    /// Get all validator scores
    pub fn get_all_scores(&self) -> HashMap<Address, u64> {
        self.validators
            .read()
            .iter()
            .map(|(addr, state)| (*addr, state.current_score))
            .collect()
    }

    /// Get top validators by score
    pub fn get_top_validators(&self, n: usize) -> Vec<(Address, u64)> {
        let validators = self.validators.read();
        let mut scores: Vec<_> = validators
            .iter()
            .map(|(addr, state)| (*addr, state.current_score))
            .collect();

        scores.sort_by(|a, b| b.1.cmp(&a.1));
        scores.truncate(n);
        scores
    }

    // =========================================================================
    // INTERNAL CALCULATIONS
    // =========================================================================

    /// Calculate current score from window jobs
    fn calculate_score(&self, state: &ValidatorReputation, current_slot: Slot) -> u64 {
        let mut total_weighted: f64 = 0.0;

        for job in &state.window_jobs {
            let age_days = job.age_days(current_slot);

            // Skip jobs outside window
            if age_days > self.config.window_days {
                continue;
            }

            // Get decay factor
            let decay = self
                .decay_factors
                .get(age_days as usize)
                .copied()
                .unwrap_or(0.0);

            // Calculate weighted contribution
            let contribution = if job.success {
                job.weighted_score() * decay
            } else {
                // Penalty for failed jobs
                -(job.complexity as f64 * self.config.failure_penalty_multiplier * decay)
            };

            total_weighted += contribution;
        }

        // Apply uptime bonus if applicable
        if state.success_rate() >= self.config.uptime_bonus_threshold {
            let streak_bonus = 1.0 + (state.active_streak as f64 * 0.01).min(0.2);
            total_weighted *= streak_bonus;
        }

        // Clamp and convert
        total_weighted.max(0.0).min(MAX_SCORE as f64) as u64
    }

    /// Prune jobs outside the window
    fn prune_window_jobs(&self, state: &mut ValidatorReputation, current_slot: Slot) {
        let window_start_slot =
            current_slot.saturating_sub(self.config.window_days as u64 * SLOTS_PER_DAY);

        while let Some(job) = state.window_jobs.front() {
            if job.verified_at_slot < window_start_slot {
                state.window_jobs.pop_front();
            } else {
                break;
            }
        }
    }

    /// Prune expired jobs from all validators
    fn prune_expired_jobs(&self, current_slot: Slot) {
        let mut validators = self.validators.write();

        for state in validators.values_mut() {
            self.prune_window_jobs(state, current_slot);
        }

        use std::sync::atomic::Ordering;
        self.metrics.window_prunings.fetch_add(1, Ordering::Relaxed);
    }

    /// Get daily job count
    fn get_daily_count(&self, state: &ValidatorReputation, day: u32) -> u32 {
        state
            .daily_job_counts
            .iter()
            .find(|(d, _)| *d == day)
            .map(|(_, count)| *count)
            .unwrap_or(0)
    }

    /// Update daily job count
    fn update_daily_count(&self, state: &mut ValidatorReputation, day: u32) {
        if let Some(entry) = state.daily_job_counts.iter_mut().find(|(d, _)| *d == day) {
            entry.1 = entry.1.saturating_add(1);
        } else {
            // Remove old day counts
            while state.daily_job_counts.len() >= 7 {
                state.daily_job_counts.pop_front();
            }
            state.daily_job_counts.push_back((day, 1));
        }
    }

    /// Update active streak
    fn update_active_streak(&self, state: &mut ValidatorReputation, current_day: u32) {
        let next_active_day = state.last_active_day.saturating_add(1);
        if state.last_active_day == 0 {
            state.active_streak = 1;
        } else if current_day == next_active_day {
            state.active_streak = state.active_streak.saturating_add(1);
        } else if current_day > next_active_day {
            state.active_streak = 1;
        }
        state.last_active_day = current_day;
    }

    // =========================================================================
    // SNAPSHOT & RESTORE
    // =========================================================================

    /// Create snapshot of all reputation state
    pub fn snapshot(&self) -> ReputationSnapshot {
        let validators = self.validators.read();
        ReputationSnapshot {
            slot: self.current_slot(),
            validators: validators.clone(),
            config: self.config.clone(),
        }
    }

    /// Restore from snapshot
    pub fn restore(&self, snapshot: ReputationSnapshot) -> ConsensusResult<()> {
        *self.current_slot.write() = snapshot.slot;
        *self.validators.write() = snapshot.validators;
        Ok(())
    }

    /// Get metrics
    pub fn metrics(&self) -> &ReputationMetrics {
        &self.metrics
    }
}

// =============================================================================
// SUPPORTING TYPES
// =============================================================================

/// Score update result
#[derive(Debug, Clone)]
pub struct ScoreUpdate {
    /// Validator address
    pub validator: Address,
    /// Old score
    pub old_score: u64,
    /// New score
    pub new_score: u64,
    /// Delta (can be negative)
    pub delta: i64,
    /// Job that triggered update
    pub job_id: Hash,
}

/// Reputation snapshot for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSnapshot {
    /// Slot at snapshot
    pub slot: Slot,
    /// All validator states
    pub validators: HashMap<Address, ValidatorReputation>,
    /// Config used
    pub config: ReputationConfig,
}

// =============================================================================
// TRAIT IMPLEMENTATIONS FOR VERIFICATION METHOD
// =============================================================================

impl VerificationMethod {
    /// Get multiplier for this method
    pub fn multiplier(&self) -> f64 {
        match self {
            VerificationMethod::TeeAttestation => MULTIPLIER_TEE,
            VerificationMethod::ZkProof => MULTIPLIER_ZK,
            VerificationMethod::Hybrid => MULTIPLIER_HYBRID,
            VerificationMethod::ReExecution => MULTIPLIER_REEXEC,
        }
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> ReputationEngine {
        ReputationEngine::new(ReputationConfig::devnet())
    }

    fn make_job(complexity: u64, success: bool, slot: Slot) -> ComputeJobRecord {
        ComputeJobRecord::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            complexity,
            VerificationMethod::TeeAttestation,
            slot,
            success,
        )
    }

    #[test]
    fn test_engine_creation() {
        let engine = test_engine();
        assert_eq!(engine.current_slot(), 0);
    }

    #[test]
    fn test_record_job() {
        let engine = test_engine();
        let validator = [1u8; 32];
        let job = make_job(1000, true, 100);

        engine.update_slot(100);
        let update = engine.record_job(validator, job).unwrap();

        assert_eq!(update.validator, validator);
        assert_eq!(update.old_score, 0);
        assert!(update.new_score > 0);
        assert!(update.delta > 0);
    }

    #[test]
    fn test_score_accumulation() {
        let engine = test_engine();
        let validator = [1u8; 32];

        engine.update_slot(100);

        // Add multiple jobs
        for i in 0..5 {
            let job = make_job(1000, true, 100 + i);
            engine.record_job(validator, job).unwrap();
        }

        let score = engine.get_score(&validator);
        assert!(score > 4000); // Should be accumulated
    }

    #[test]
    fn test_score_decay() {
        let engine = test_engine();
        let validator = [1u8; 32];

        // Record job at slot 0
        engine.update_slot(0);
        let job = make_job(1000, true, 0);
        engine.record_job(validator, job).unwrap();

        let initial_score = engine.get_score(&validator);

        // Advance multiple days
        let slots_per_day = SLOTS_PER_DAY;
        engine.update_slot(slots_per_day * 5);

        // Apply decay
        engine.apply_daily_decay(slots_per_day * 5).unwrap();

        let decayed_score = engine.get_score(&validator);
        assert!(decayed_score < initial_score);
    }

    #[test]
    fn test_failed_job_penalty() {
        let engine = test_engine();
        let validator = [1u8; 32];

        engine.update_slot(100);

        // Add successful jobs first
        for _ in 0..5 {
            let job = make_job(1000, true, 100);
            engine.record_job(validator, job).unwrap();
        }

        let score_before_failure = engine.get_score(&validator);

        // Add failed job
        let failed_job = make_job(1000, false, 100);
        engine.record_job(validator, failed_job).unwrap();

        let score_after_failure = engine.get_score(&validator);

        // Score should decrease or stay same (penalty applied)
        assert!(score_after_failure <= score_before_failure);
    }

    #[test]
    fn test_method_multipliers() {
        let engine = test_engine();
        let validator = [1u8; 32];

        engine.update_slot(100);

        // TEE job
        let tee_job = ComputeJobRecord::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            1000,
            VerificationMethod::TeeAttestation,
            100,
            true,
        );
        engine.record_job(validator, tee_job).unwrap();
        let tee_score = engine.get_score(&validator);

        // Reset
        let validator2 = [2u8; 32];

        // Hybrid job (should give higher score)
        let hybrid_job = ComputeJobRecord::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            1000,
            VerificationMethod::Hybrid,
            100,
            true,
        );
        engine.record_job(validator2, hybrid_job).unwrap();
        let hybrid_score = engine.get_score(&validator2);

        assert!(hybrid_score > tee_score);
    }

    #[test]
    fn test_snapshot_restore() {
        let engine = test_engine();
        let validator = [1u8; 32];

        engine.update_slot(100);
        let job = make_job(1000, true, 100);
        engine.record_job(validator, job).unwrap();

        let snapshot = engine.snapshot();
        let score_before = engine.get_score(&validator);

        // Create new engine and restore
        let engine2 = test_engine();
        engine2.restore(snapshot).unwrap();

        let score_after = engine2.get_score(&validator);
        assert_eq!(score_before, score_after);
    }

    #[test]
    fn test_top_validators() {
        let engine = test_engine();

        engine.update_slot(100);

        // Add validators with different scores
        for i in 0..10 {
            let validator = [i as u8; 32];
            let job = make_job((i as u64 + 1) * 1000, true, 100);
            engine.record_job(validator, job).unwrap();
        }

        let top = engine.get_top_validators(3);
        assert_eq!(top.len(), 3);

        // Should be sorted descending
        assert!(top[0].1 >= top[1].1);
        assert!(top[1].1 >= top[2].1);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ReputationConfig::production();

        // Valid config
        assert!(config.validate().is_ok());

        // Invalid decay rate
        config.decay_rate = 1.5;
        assert!(config.validate().is_err());

        config.decay_rate = 0.97;
        config.window_days = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_success_rate() {
        let engine = test_engine();
        let validator = [1u8; 32];

        engine.update_slot(100);

        // 7 successful, 3 failed
        for i in 0..7 {
            let job = make_job(1000, true, 100 + i);
            engine.record_job(validator, job).unwrap();
        }
        for i in 0..3 {
            let job = make_job(1000, false, 110 + i);
            engine.record_job(validator, job).unwrap();
        }

        let rep = engine.get_reputation(&validator).unwrap();
        let rate = rep.success_rate();

        assert!((rate - 0.7).abs() < 0.01);
    }
}
