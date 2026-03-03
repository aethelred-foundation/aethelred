//! Consensus Metrics & Monitoring
//!
//! Enterprise-grade metrics collection for the Proof-of-Useful-Work consensus engine.
//!
//! # Metric Categories
//!
//! - **Consensus**: Block production, validation, finality
//! - **VRF**: Proof generation, verification, threshold hits
//! - **Compute**: Job processing, verification methods, complexity
//! - **Reputation**: Score distributions, updates, decay events
//! - **Network**: Latency, peer connections, message propagation

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::types::{Address, Slot, Epoch};

// =============================================================================
// METRICS COLLECTOR
// =============================================================================

/// Main metrics collector for consensus
pub struct ConsensusMetricsCollector {
    /// Block metrics
    pub blocks: BlockMetrics,

    /// VRF metrics
    pub vrf: VrfMetrics,

    /// Compute job metrics
    pub compute: ComputeMetrics,

    /// Reputation metrics
    pub reputation: ReputationMetrics,

    /// Timing metrics
    pub timing: TimingMetrics,

    /// Validator-specific metrics
    pub validators: RwLock<HashMap<Address, ValidatorMetrics>>,

    /// Start time
    start_time: Instant,

    /// Enabled flag
    enabled: bool,
}

impl Default for ConsensusMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusMetricsCollector {
    /// Create new metrics collector
    pub fn new() -> Self {
        Self {
            blocks: BlockMetrics::default(),
            vrf: VrfMetrics::default(),
            compute: ComputeMetrics::default(),
            reputation: ReputationMetrics::default(),
            timing: TimingMetrics::default(),
            validators: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
            enabled: true,
        }
    }

    /// Create disabled collector (for benchmarking)
    pub fn disabled() -> Self {
        let mut collector = Self::new();
        collector.enabled = false;
        collector
    }

    /// Check if metrics are enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get uptime
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get complete metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            uptime_secs: self.uptime().as_secs(),
            blocks: self.blocks.snapshot(),
            vrf: self.vrf.snapshot(),
            compute: self.compute.snapshot(),
            reputation: self.reputation.snapshot(),
            timing: self.timing.snapshot(),
        }
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.blocks.reset();
        self.vrf.reset();
        self.compute.reset();
        self.reputation.reset();
        self.timing.reset();
        self.validators.write().clear();
    }

    /// Get or create validator metrics
    pub fn validator(&self, address: Address) -> ValidatorMetrics {
        let validators = self.validators.read();
        if let Some(metrics) = validators.get(&address) {
            return metrics.clone();
        }
        drop(validators);

        let mut validators = self.validators.write();
        validators.entry(address).or_insert_with(|| ValidatorMetrics::new(address)).clone()
    }

    /// Update validator metrics
    pub fn update_validator<F>(&self, address: Address, f: F)
    where
        F: FnOnce(&mut ValidatorMetrics),
    {
        if !self.enabled {
            return;
        }

        let mut validators = self.validators.write();
        let metrics = validators.entry(address).or_insert_with(|| ValidatorMetrics::new(address));
        f(metrics);
    }
}

// =============================================================================
// BLOCK METRICS
// =============================================================================

/// Block-related metrics
#[derive(Debug, Default)]
pub struct BlockMetrics {
    /// Blocks proposed by local node
    pub blocks_proposed: AtomicU64,
    /// Blocks validated
    pub blocks_validated: AtomicU64,
    /// Blocks rejected
    pub blocks_rejected: AtomicU64,
    /// Blocks finalized
    pub blocks_finalized: AtomicU64,
    /// Orphaned blocks
    pub blocks_orphaned: AtomicU64,
    /// Total transactions processed
    pub transactions_processed: AtomicU64,
    /// Current height
    pub current_height: AtomicU64,
    /// Current slot
    pub current_slot: AtomicU64,
    /// Current epoch
    pub current_epoch: AtomicU64,
    /// Slots since last block
    pub slots_since_last_block: AtomicU64,
}

impl BlockMetrics {
    /// Record block proposed
    pub fn record_proposed(&self) {
        self.blocks_proposed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record block validated
    pub fn record_validated(&self) {
        self.blocks_validated.fetch_add(1, Ordering::Relaxed);
    }

    /// Record block rejected
    pub fn record_rejected(&self) {
        self.blocks_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record block finalized
    pub fn record_finalized(&self) {
        self.blocks_finalized.fetch_add(1, Ordering::Relaxed);
    }

    /// Update current slot
    pub fn update_slot(&self, slot: Slot, epoch: Epoch) {
        self.current_slot.store(slot, Ordering::Relaxed);
        self.current_epoch.store(epoch, Ordering::Relaxed);
    }

    /// Update current height
    pub fn update_height(&self, height: u64) {
        self.current_height.store(height, Ordering::Relaxed);
    }

    /// Get snapshot
    pub fn snapshot(&self) -> BlockMetricsSnapshot {
        BlockMetricsSnapshot {
            blocks_proposed: self.blocks_proposed.load(Ordering::Relaxed),
            blocks_validated: self.blocks_validated.load(Ordering::Relaxed),
            blocks_rejected: self.blocks_rejected.load(Ordering::Relaxed),
            blocks_finalized: self.blocks_finalized.load(Ordering::Relaxed),
            blocks_orphaned: self.blocks_orphaned.load(Ordering::Relaxed),
            transactions_processed: self.transactions_processed.load(Ordering::Relaxed),
            current_height: self.current_height.load(Ordering::Relaxed),
            current_slot: self.current_slot.load(Ordering::Relaxed),
            current_epoch: self.current_epoch.load(Ordering::Relaxed),
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.blocks_proposed.store(0, Ordering::Relaxed);
        self.blocks_validated.store(0, Ordering::Relaxed);
        self.blocks_rejected.store(0, Ordering::Relaxed);
        self.blocks_finalized.store(0, Ordering::Relaxed);
        self.blocks_orphaned.store(0, Ordering::Relaxed);
        self.transactions_processed.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetricsSnapshot {
    pub blocks_proposed: u64,
    pub blocks_validated: u64,
    pub blocks_rejected: u64,
    pub blocks_finalized: u64,
    pub blocks_orphaned: u64,
    pub transactions_processed: u64,
    pub current_height: u64,
    pub current_slot: u64,
    pub current_epoch: u64,
}

// =============================================================================
// VRF METRICS
// =============================================================================

/// VRF-related metrics
#[derive(Debug, Default)]
pub struct VrfMetrics {
    /// Proofs generated
    pub proofs_generated: AtomicU64,
    /// Proofs verified (success)
    pub proofs_verified_success: AtomicU64,
    /// Proofs verified (failure)
    pub proofs_verified_failure: AtomicU64,
    /// Threshold hits (won lottery)
    pub threshold_hits: AtomicU64,
    /// Threshold misses
    pub threshold_misses: AtomicU64,
    /// Proof generation time (total microseconds)
    pub proof_generation_time_us: AtomicU64,
    /// Proof verification time (total microseconds)
    pub proof_verification_time_us: AtomicU64,
}

impl VrfMetrics {
    /// Record proof generated
    pub fn record_proof_generated(&self, duration_us: u64) {
        self.proofs_generated.fetch_add(1, Ordering::Relaxed);
        self.proof_generation_time_us.fetch_add(duration_us, Ordering::Relaxed);
    }

    /// Record proof verified
    pub fn record_proof_verified(&self, success: bool, duration_us: u64) {
        if success {
            self.proofs_verified_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.proofs_verified_failure.fetch_add(1, Ordering::Relaxed);
        }
        self.proof_verification_time_us.fetch_add(duration_us, Ordering::Relaxed);
    }

    /// Record threshold check
    pub fn record_threshold_check(&self, won: bool) {
        if won {
            self.threshold_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.threshold_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get average proof generation time
    pub fn avg_proof_generation_us(&self) -> f64 {
        let count = self.proofs_generated.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.proof_generation_time_us.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get snapshot
    pub fn snapshot(&self) -> VrfMetricsSnapshot {
        VrfMetricsSnapshot {
            proofs_generated: self.proofs_generated.load(Ordering::Relaxed),
            proofs_verified_success: self.proofs_verified_success.load(Ordering::Relaxed),
            proofs_verified_failure: self.proofs_verified_failure.load(Ordering::Relaxed),
            threshold_hits: self.threshold_hits.load(Ordering::Relaxed),
            threshold_misses: self.threshold_misses.load(Ordering::Relaxed),
            avg_proof_generation_us: self.avg_proof_generation_us(),
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.proofs_generated.store(0, Ordering::Relaxed);
        self.proofs_verified_success.store(0, Ordering::Relaxed);
        self.proofs_verified_failure.store(0, Ordering::Relaxed);
        self.threshold_hits.store(0, Ordering::Relaxed);
        self.threshold_misses.store(0, Ordering::Relaxed);
        self.proof_generation_time_us.store(0, Ordering::Relaxed);
        self.proof_verification_time_us.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfMetricsSnapshot {
    pub proofs_generated: u64,
    pub proofs_verified_success: u64,
    pub proofs_verified_failure: u64,
    pub threshold_hits: u64,
    pub threshold_misses: u64,
    pub avg_proof_generation_us: f64,
}

// =============================================================================
// COMPUTE METRICS
// =============================================================================

/// Compute job metrics
#[derive(Debug, Default)]
pub struct ComputeMetrics {
    /// Total jobs submitted
    pub jobs_submitted: AtomicU64,
    /// Jobs verified (success)
    pub jobs_verified_success: AtomicU64,
    /// Jobs verified (failure)
    pub jobs_verified_failure: AtomicU64,
    /// Total complexity processed
    pub total_complexity: AtomicU64,
    /// TEE verifications
    pub verifications_tee: AtomicU64,
    /// zkML verifications
    pub verifications_zkml: AtomicU64,
    /// Hybrid verifications
    pub verifications_hybrid: AtomicU64,
    /// Re-execution verifications
    pub verifications_reexec: AtomicU64,
    /// Verification time (total microseconds)
    pub verification_time_us: AtomicU64,
}

impl ComputeMetrics {
    /// Record job submitted
    pub fn record_job_submitted(&self) {
        self.jobs_submitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record job verified
    pub fn record_job_verified(&self, success: bool, method: u8, complexity: u64, duration_us: u64) {
        if success {
            self.jobs_verified_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.jobs_verified_failure.fetch_add(1, Ordering::Relaxed);
        }

        self.total_complexity.fetch_add(complexity, Ordering::Relaxed);
        self.verification_time_us.fetch_add(duration_us, Ordering::Relaxed);

        match method {
            0 => self.verifications_tee.fetch_add(1, Ordering::Relaxed),
            1 => self.verifications_zkml.fetch_add(1, Ordering::Relaxed),
            2 => self.verifications_hybrid.fetch_add(1, Ordering::Relaxed),
            3 => self.verifications_reexec.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Get verification success rate
    pub fn success_rate(&self) -> f64 {
        let success = self.jobs_verified_success.load(Ordering::Relaxed);
        let total = success + self.jobs_verified_failure.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        success as f64 / total as f64
    }

    /// Get snapshot
    pub fn snapshot(&self) -> ComputeMetricsSnapshot {
        ComputeMetricsSnapshot {
            jobs_submitted: self.jobs_submitted.load(Ordering::Relaxed),
            jobs_verified_success: self.jobs_verified_success.load(Ordering::Relaxed),
            jobs_verified_failure: self.jobs_verified_failure.load(Ordering::Relaxed),
            total_complexity: self.total_complexity.load(Ordering::Relaxed),
            verifications_tee: self.verifications_tee.load(Ordering::Relaxed),
            verifications_zkml: self.verifications_zkml.load(Ordering::Relaxed),
            verifications_hybrid: self.verifications_hybrid.load(Ordering::Relaxed),
            verifications_reexec: self.verifications_reexec.load(Ordering::Relaxed),
            success_rate: self.success_rate(),
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.jobs_submitted.store(0, Ordering::Relaxed);
        self.jobs_verified_success.store(0, Ordering::Relaxed);
        self.jobs_verified_failure.store(0, Ordering::Relaxed);
        self.total_complexity.store(0, Ordering::Relaxed);
        self.verifications_tee.store(0, Ordering::Relaxed);
        self.verifications_zkml.store(0, Ordering::Relaxed);
        self.verifications_hybrid.store(0, Ordering::Relaxed);
        self.verifications_reexec.store(0, Ordering::Relaxed);
        self.verification_time_us.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeMetricsSnapshot {
    pub jobs_submitted: u64,
    pub jobs_verified_success: u64,
    pub jobs_verified_failure: u64,
    pub total_complexity: u64,
    pub verifications_tee: u64,
    pub verifications_zkml: u64,
    pub verifications_hybrid: u64,
    pub verifications_reexec: u64,
    pub success_rate: f64,
}

// =============================================================================
// REPUTATION METRICS
// =============================================================================

/// Reputation system metrics
#[derive(Debug, Default)]
pub struct ReputationMetrics {
    /// Score updates
    pub score_updates: AtomicU64,
    /// Decay events applied
    pub decay_events: AtomicU64,
    /// Window prunings
    pub window_prunings: AtomicU64,
    /// Active validators tracked
    pub active_validators: AtomicU64,
    /// Total score across all validators
    pub total_score: AtomicU64,
}

impl ReputationMetrics {
    /// Record score update
    pub fn record_score_update(&self, delta: i64) {
        self.score_updates.fetch_add(1, Ordering::Relaxed);
        if delta >= 0 {
            self.total_score.fetch_add(delta as u64, Ordering::Relaxed);
        }
    }

    /// Record decay event
    pub fn record_decay_event(&self) {
        self.decay_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Update active validator count
    pub fn update_active_count(&self, count: u64) {
        self.active_validators.store(count, Ordering::Relaxed);
    }

    /// Get snapshot
    pub fn snapshot(&self) -> ReputationMetricsSnapshot {
        ReputationMetricsSnapshot {
            score_updates: self.score_updates.load(Ordering::Relaxed),
            decay_events: self.decay_events.load(Ordering::Relaxed),
            window_prunings: self.window_prunings.load(Ordering::Relaxed),
            active_validators: self.active_validators.load(Ordering::Relaxed),
            total_score: self.total_score.load(Ordering::Relaxed),
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.score_updates.store(0, Ordering::Relaxed);
        self.decay_events.store(0, Ordering::Relaxed);
        self.window_prunings.store(0, Ordering::Relaxed);
        self.total_score.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationMetricsSnapshot {
    pub score_updates: u64,
    pub decay_events: u64,
    pub window_prunings: u64,
    pub active_validators: u64,
    pub total_score: u64,
}

// =============================================================================
// TIMING METRICS
// =============================================================================

/// Timing and latency metrics
#[derive(Debug, Default)]
pub struct TimingMetrics {
    /// Block production time (total microseconds)
    pub block_production_time_us: AtomicU64,
    /// Block production count
    pub block_production_count: AtomicU64,
    /// Block validation time (total microseconds)
    pub block_validation_time_us: AtomicU64,
    /// Block validation count
    pub block_validation_count: AtomicU64,
    /// Consensus round time (total microseconds)
    pub consensus_round_time_us: AtomicU64,
    /// Consensus round count
    pub consensus_round_count: AtomicU64,
}

impl TimingMetrics {
    /// Record block production time
    pub fn record_block_production(&self, duration_us: u64) {
        self.block_production_time_us.fetch_add(duration_us, Ordering::Relaxed);
        self.block_production_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record block validation time
    pub fn record_block_validation(&self, duration_us: u64) {
        self.block_validation_time_us.fetch_add(duration_us, Ordering::Relaxed);
        self.block_validation_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record consensus round time
    pub fn record_consensus_round(&self, duration_us: u64) {
        self.consensus_round_time_us.fetch_add(duration_us, Ordering::Relaxed);
        self.consensus_round_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average block production time
    pub fn avg_block_production_us(&self) -> f64 {
        let count = self.block_production_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.block_production_time_us.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get average block validation time
    pub fn avg_block_validation_us(&self) -> f64 {
        let count = self.block_validation_count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.block_validation_time_us.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get snapshot
    pub fn snapshot(&self) -> TimingMetricsSnapshot {
        TimingMetricsSnapshot {
            avg_block_production_us: self.avg_block_production_us(),
            avg_block_validation_us: self.avg_block_validation_us(),
            block_production_count: self.block_production_count.load(Ordering::Relaxed),
            block_validation_count: self.block_validation_count.load(Ordering::Relaxed),
            consensus_round_count: self.consensus_round_count.load(Ordering::Relaxed),
        }
    }

    /// Reset metrics
    pub fn reset(&self) {
        self.block_production_time_us.store(0, Ordering::Relaxed);
        self.block_production_count.store(0, Ordering::Relaxed);
        self.block_validation_time_us.store(0, Ordering::Relaxed);
        self.block_validation_count.store(0, Ordering::Relaxed);
        self.consensus_round_time_us.store(0, Ordering::Relaxed);
        self.consensus_round_count.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetricsSnapshot {
    pub avg_block_production_us: f64,
    pub avg_block_validation_us: f64,
    pub block_production_count: u64,
    pub block_validation_count: u64,
    pub consensus_round_count: u64,
}

// =============================================================================
// VALIDATOR METRICS
// =============================================================================

/// Per-validator metrics
#[derive(Debug, Clone)]
pub struct ValidatorMetrics {
    /// Validator address
    pub address: Address,
    /// Blocks proposed
    pub blocks_proposed: u64,
    /// Blocks missed
    pub blocks_missed: u64,
    /// Jobs verified
    pub jobs_verified: u64,
    /// Jobs failed
    pub jobs_failed: u64,
    /// Current useful work score
    pub useful_work_score: u64,
    /// Current stake
    pub stake: u128,
    /// Slashing events
    pub slashing_events: u64,
    /// Uptime percentage (0-100)
    pub uptime_percent: f64,
    /// Last active slot
    pub last_active_slot: Slot,
}

impl ValidatorMetrics {
    /// Create new validator metrics
    pub fn new(address: Address) -> Self {
        Self {
            address,
            blocks_proposed: 0,
            blocks_missed: 0,
            jobs_verified: 0,
            jobs_failed: 0,
            useful_work_score: 0,
            stake: 0,
            slashing_events: 0,
            uptime_percent: 100.0,
            last_active_slot: 0,
        }
    }

    /// Get proposal rate
    pub fn proposal_rate(&self) -> f64 {
        let total = self.blocks_proposed + self.blocks_missed;
        if total == 0 {
            return 0.0;
        }
        self.blocks_proposed as f64 / total as f64
    }

    /// Get job success rate
    pub fn job_success_rate(&self) -> f64 {
        let total = self.jobs_verified + self.jobs_failed;
        if total == 0 {
            return 1.0;
        }
        self.jobs_verified as f64 / total as f64
    }
}

// =============================================================================
// COMPLETE SNAPSHOT
// =============================================================================

/// Complete metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: u64,
    pub uptime_secs: u64,
    pub blocks: BlockMetricsSnapshot,
    pub vrf: VrfMetricsSnapshot,
    pub compute: ComputeMetricsSnapshot,
    pub reputation: ReputationMetricsSnapshot,
    pub timing: TimingMetricsSnapshot,
}

impl MetricsSnapshot {
    /// Export as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Export as Prometheus format
    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        // Block metrics
        output.push_str(&format!("aethelred_blocks_proposed {}\n", self.blocks.blocks_proposed));
        output.push_str(&format!("aethelred_blocks_validated {}\n", self.blocks.blocks_validated));
        output.push_str(&format!("aethelred_blocks_rejected {}\n", self.blocks.blocks_rejected));
        output.push_str(&format!("aethelred_blocks_finalized {}\n", self.blocks.blocks_finalized));
        output.push_str(&format!("aethelred_current_height {}\n", self.blocks.current_height));
        output.push_str(&format!("aethelred_current_slot {}\n", self.blocks.current_slot));
        output.push_str(&format!("aethelred_current_epoch {}\n", self.blocks.current_epoch));

        // VRF metrics
        output.push_str(&format!("aethelred_vrf_proofs_generated {}\n", self.vrf.proofs_generated));
        output.push_str(&format!("aethelred_vrf_threshold_hits {}\n", self.vrf.threshold_hits));
        output.push_str(&format!("aethelred_vrf_avg_generation_us {}\n", self.vrf.avg_proof_generation_us));

        // Compute metrics
        output.push_str(&format!("aethelred_jobs_submitted {}\n", self.compute.jobs_submitted));
        output.push_str(&format!("aethelred_jobs_verified {}\n", self.compute.jobs_verified_success));
        output.push_str(&format!("aethelred_total_complexity {}\n", self.compute.total_complexity));
        output.push_str(&format!("aethelred_job_success_rate {}\n", self.compute.success_rate));

        // Reputation metrics
        output.push_str(&format!("aethelred_reputation_updates {}\n", self.reputation.score_updates));
        output.push_str(&format!("aethelred_active_validators {}\n", self.reputation.active_validators));
        output.push_str(&format!("aethelred_total_score {}\n", self.reputation.total_score));

        // Timing metrics
        output.push_str(&format!("aethelred_avg_block_production_us {}\n", self.timing.avg_block_production_us));
        output.push_str(&format!("aethelred_avg_block_validation_us {}\n", self.timing.avg_block_validation_us));

        // Meta
        output.push_str(&format!("aethelred_uptime_seconds {}\n", self.uptime_secs));

        output
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = ConsensusMetricsCollector::new();
        assert!(collector.is_enabled());
    }

    #[test]
    fn test_block_metrics() {
        let metrics = BlockMetrics::default();

        metrics.record_proposed();
        metrics.record_proposed();
        metrics.record_validated();
        metrics.record_rejected();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.blocks_proposed, 2);
        assert_eq!(snapshot.blocks_validated, 1);
        assert_eq!(snapshot.blocks_rejected, 1);
    }

    #[test]
    fn test_vrf_metrics() {
        let metrics = VrfMetrics::default();

        metrics.record_proof_generated(1000);
        metrics.record_proof_generated(2000);
        metrics.record_threshold_check(true);
        metrics.record_threshold_check(false);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.proofs_generated, 2);
        assert_eq!(snapshot.threshold_hits, 1);
        assert_eq!(snapshot.threshold_misses, 1);
        assert!((snapshot.avg_proof_generation_us - 1500.0).abs() < 0.1);
    }

    #[test]
    fn test_compute_metrics() {
        let metrics = ComputeMetrics::default();

        metrics.record_job_verified(true, 0, 1000, 500);
        metrics.record_job_verified(true, 1, 2000, 1000);
        metrics.record_job_verified(false, 0, 500, 200);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.jobs_verified_success, 2);
        assert_eq!(snapshot.jobs_verified_failure, 1);
        assert_eq!(snapshot.total_complexity, 3500);
        assert!((snapshot.success_rate - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_timing_metrics() {
        let metrics = TimingMetrics::default();

        metrics.record_block_production(1000);
        metrics.record_block_production(2000);
        metrics.record_block_validation(500);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.block_production_count, 2);
        assert_eq!(snapshot.block_validation_count, 1);
        assert!((snapshot.avg_block_production_us - 1500.0).abs() < 0.1);
    }

    #[test]
    fn test_validator_metrics() {
        let mut metrics = ValidatorMetrics::new([1u8; 32]);

        metrics.blocks_proposed = 90;
        metrics.blocks_missed = 10;
        metrics.jobs_verified = 95;
        metrics.jobs_failed = 5;

        assert!((metrics.proposal_rate() - 0.9).abs() < 0.01);
        assert!((metrics.job_success_rate() - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_complete_snapshot() {
        let collector = ConsensusMetricsCollector::new();

        collector.blocks.record_proposed();
        collector.vrf.record_proof_generated(1000);
        collector.compute.record_job_verified(true, 0, 1000, 500);

        let snapshot = collector.snapshot();

        assert_eq!(snapshot.blocks.blocks_proposed, 1);
        assert_eq!(snapshot.vrf.proofs_generated, 1);
        assert_eq!(snapshot.compute.jobs_verified_success, 1);
    }

    #[test]
    fn test_prometheus_export() {
        let collector = ConsensusMetricsCollector::new();
        collector.blocks.record_proposed();

        let snapshot = collector.snapshot();
        let prometheus = snapshot.to_prometheus();

        assert!(prometheus.contains("aethelred_blocks_proposed 1"));
        assert!(prometheus.contains("aethelred_uptime_seconds"));
    }

    #[test]
    fn test_metrics_reset() {
        let collector = ConsensusMetricsCollector::new();

        collector.blocks.record_proposed();
        collector.vrf.record_proof_generated(1000);

        collector.reset();

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.blocks.blocks_proposed, 0);
        assert_eq!(snapshot.vrf.proofs_generated, 0);
    }
}
