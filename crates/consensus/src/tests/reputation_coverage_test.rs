//! Comprehensive coverage tests for Reputation Engine
//!
//! Targets uncovered lines in reputation.rs

use crate::reputation::{
    ComputeJobRecord, JobMetadata, ReputationConfig, ReputationEngine, ReputationMetrics,
    ReputationSnapshot, ScoreUpdate, ValidatorReputation, DEFAULT_DECAY_RATE, DEFAULT_WINDOW_DAYS,
    MAX_SCORE, MULTIPLIER_HYBRID, MULTIPLIER_REEXEC, MULTIPLIER_TEE, MULTIPLIER_ZK, SLOTS_PER_DAY,
};
use crate::traits::VerificationMethod;
use std::collections::HashMap;

// =============================================================================
// HELPERS
// =============================================================================

fn test_engine() -> ReputationEngine {
    ReputationEngine::new(ReputationConfig::devnet())
}

fn make_job(complexity: u64, success: bool, slot: u64) -> ComputeJobRecord {
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

fn make_job_method(complexity: u64, method: VerificationMethod, slot: u64) -> ComputeJobRecord {
    ComputeJobRecord::new(
        [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], complexity, method, slot, true,
    )
}

// =============================================================================
// REPUTATION CONFIG TESTS
// =============================================================================

#[test]
fn test_config_production() {
    let config = ReputationConfig::production();
    assert!((config.decay_rate - DEFAULT_DECAY_RATE).abs() < 0.001);
    assert_eq!(config.window_days, DEFAULT_WINDOW_DAYS);
    config.validate().unwrap();
}

#[test]
fn test_config_testnet() {
    let config = ReputationConfig::testnet();
    assert!((config.decay_rate - 0.90).abs() < 0.001);
    assert_eq!(config.window_days, 7);
    config.validate().unwrap();
}

#[test]
fn test_config_devnet() {
    let config = ReputationConfig::devnet();
    assert!((config.decay_rate - 0.80).abs() < 0.001);
    assert_eq!(config.window_days, 3);
    config.validate().unwrap();
}

#[test]
fn test_config_default() {
    let config = ReputationConfig::default();
    assert!((config.decay_rate - DEFAULT_DECAY_RATE).abs() < 0.001);
}

#[test]
fn test_config_validate_bad_decay_rate() {
    let mut config = ReputationConfig::devnet();
    config.decay_rate = 0.0;
    assert!(config.validate().is_err());

    config.decay_rate = -0.5;
    assert!(config.validate().is_err());

    config.decay_rate = 1.5;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_bad_window() {
    let mut config = ReputationConfig::devnet();
    config.window_days = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_bad_smoothing() {
    let mut config = ReputationConfig::devnet();
    config.smoothing_factor = -0.1;
    assert!(config.validate().is_err());

    config.smoothing_factor = 1.1;
    assert!(config.validate().is_err());
}

// =============================================================================
// COMPUTE JOB RECORD TESTS
// =============================================================================

#[test]
fn test_job_record_new() {
    let job = make_job(1000, true, 100);
    assert_eq!(job.complexity, 1000);
    assert!(job.success);
    assert_eq!(job.verified_at_slot, 100);
    assert!(job.metadata.is_none());
}

#[test]
fn test_job_record_method_multiplier() {
    let tee = make_job_method(100, VerificationMethod::TeeAttestation, 0);
    assert!((tee.method_multiplier() - MULTIPLIER_TEE).abs() < 0.001);

    let zk = make_job_method(100, VerificationMethod::ZkProof, 0);
    assert!((zk.method_multiplier() - MULTIPLIER_ZK).abs() < 0.001);

    let hybrid = make_job_method(100, VerificationMethod::Hybrid, 0);
    assert!((hybrid.method_multiplier() - MULTIPLIER_HYBRID).abs() < 0.001);

    let reexec = make_job_method(100, VerificationMethod::ReExecution, 0);
    assert!((reexec.method_multiplier() - MULTIPLIER_REEXEC).abs() < 0.001);
}

#[test]
fn test_job_record_weighted_score() {
    let success = make_job(1000, true, 100);
    let score = success.weighted_score();
    assert!(score > 0.0);
    assert!((score - 1000.0 * MULTIPLIER_TEE).abs() < 0.01);

    let fail = make_job(1000, false, 100);
    assert!((fail.weighted_score() - 0.0).abs() < 0.001);
}

#[test]
fn test_job_record_age_days() {
    let job = make_job(100, true, 100);

    // Same slot
    assert_eq!(job.age_days(100), 0);

    // One day later
    assert_eq!(job.age_days(100 + SLOTS_PER_DAY), 1);

    // Two days later
    assert_eq!(job.age_days(100 + 2 * SLOTS_PER_DAY), 2);

    // Before job's slot
    assert_eq!(job.age_days(50), 0);
}

// =============================================================================
// VALIDATOR REPUTATION TESTS
// =============================================================================

#[test]
fn test_validator_reputation_new() {
    let rep = ValidatorReputation::new([1u8; 32]);
    assert_eq!(rep.current_score, 0);
    assert_eq!(rep.total_jobs, 0);
    assert_eq!(rep.successful_jobs, 0);
    assert_eq!(rep.failed_jobs, 0);
}

#[test]
fn test_validator_reputation_success_rate() {
    let mut rep = ValidatorReputation::new([1u8; 32]);
    assert!((rep.success_rate() - 1.0).abs() < 0.001); // Empty = 100%

    rep.total_jobs = 10;
    rep.successful_jobs = 8;
    assert!((rep.success_rate() - 0.8).abs() < 0.001);
}

#[test]
fn test_validator_reputation_average_complexity() {
    let mut rep = ValidatorReputation::new([1u8; 32]);
    assert_eq!(rep.average_complexity(), 0);

    rep.total_jobs = 4;
    rep.total_complexity = 4000;
    assert_eq!(rep.average_complexity(), 1000);
}

// =============================================================================
// REPUTATION ENGINE TESTS
// =============================================================================

#[test]
fn test_engine_production() {
    let engine = ReputationEngine::production();
    assert_eq!(engine.current_slot(), 0);
}

#[test]
fn test_engine_testnet() {
    let engine = ReputationEngine::testnet();
    assert_eq!(engine.current_slot(), 0);
}

#[test]
fn test_engine_update_slot() {
    let engine = test_engine();
    engine.update_slot(1000);
    assert_eq!(engine.current_slot(), 1000);
}

#[test]
fn test_engine_record_job() {
    let engine = test_engine();
    engine.update_slot(100);
    let validator = [1u8; 32];
    let job = make_job(100, true, 100);

    let update = engine.record_job(validator, job).unwrap();
    assert_eq!(update.validator, validator);
    assert!(update.new_score > 0);
}

#[test]
fn test_engine_record_failed_job() {
    let engine = test_engine();
    engine.update_slot(100);
    let validator = [1u8; 32];
    let job = make_job(100, false, 100);

    let update = engine.record_job(validator, job).unwrap();
    assert_eq!(update.new_score, 0); // Failed jobs don't add positive score
}

#[test]
fn test_engine_record_job_below_min_complexity() {
    let engine = ReputationEngine::new(ReputationConfig::production()); // min_complexity = 100
    engine.update_slot(100);
    let validator = [1u8; 32];
    let job = make_job(50, true, 100); // below min_complexity

    let result = engine.record_job(validator, job);
    assert!(result.is_err());
}

#[test]
fn test_engine_get_score() {
    let engine = test_engine();
    assert_eq!(engine.get_score(&[1u8; 32]), 0);

    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(100, true, 100))
        .unwrap();
    assert!(engine.get_score(&[1u8; 32]) > 0);
}

#[test]
fn test_engine_get_smoothed_score() {
    // Devnet has smoothing disabled, so test with production
    let engine = ReputationEngine::new(ReputationConfig::production());
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(500, true, 100))
        .unwrap();

    let smoothed = engine.get_smoothed_score(&[1u8; 32]);
    assert!(smoothed >= 0.0);

    // Nonexistent
    assert!((engine.get_smoothed_score(&[99u8; 32]) - 0.0).abs() < 0.001);
}

#[test]
fn test_engine_get_reputation() {
    let engine = test_engine();
    assert!(engine.get_reputation(&[1u8; 32]).is_none());

    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(100, true, 100))
        .unwrap();
    let rep = engine.get_reputation(&[1u8; 32]).unwrap();
    assert_eq!(rep.total_jobs, 1);
    assert_eq!(rep.successful_jobs, 1);
}

#[test]
fn test_engine_get_all_scores() {
    let engine = test_engine();
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(100, true, 100))
        .unwrap();
    engine
        .record_job([2u8; 32], make_job(200, true, 100))
        .unwrap();

    let scores = engine.get_all_scores();
    assert_eq!(scores.len(), 2);
}

#[test]
fn test_engine_get_top_validators() {
    let engine = test_engine();
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(100, true, 100))
        .unwrap();
    engine
        .record_job([2u8; 32], make_job(500, true, 100))
        .unwrap();
    engine
        .record_job([3u8; 32], make_job(300, true, 100))
        .unwrap();

    let top = engine.get_top_validators(2);
    assert_eq!(top.len(), 2);
    // Highest score should be first
    assert!(top[0].1 >= top[1].1);
}

#[test]
fn test_engine_process_block_results() {
    let engine = test_engine();
    let results = vec![
        ([1u8; 32], make_job(100, true, 100)),
        ([2u8; 32], make_job(200, true, 100)),
    ];

    let updates = engine.process_block_results(100, &results).unwrap();
    assert_eq!(updates.len(), 2);
}

#[test]
fn test_engine_apply_daily_decay() {
    let engine = test_engine();
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(1000, true, 100))
        .unwrap();

    let score_before = engine.get_score(&[1u8; 32]);
    assert!(score_before > 0);

    // Advance a full day and apply decay
    let new_slot = 100 + SLOTS_PER_DAY;
    engine.update_slot(new_slot);
    let updates = engine.apply_daily_decay(new_slot).unwrap();

    let score_after = engine.get_score(&[1u8; 32]);
    // Score should have decayed due to age
    assert!(score_after <= score_before);
}

#[test]
fn test_engine_snapshot_restore() {
    let engine = test_engine();
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(1000, true, 100))
        .unwrap();

    let snapshot = engine.snapshot();
    assert_eq!(snapshot.slot, 100);
    assert!(snapshot.validators.contains_key(&[1u8; 32]));

    // Restore into a new engine
    let engine2 = test_engine();
    engine2.restore(snapshot).unwrap();
    assert_eq!(engine2.current_slot(), 100);
    assert!(engine2.get_score(&[1u8; 32]) > 0);
}

#[test]
fn test_engine_metrics() {
    let engine = test_engine();
    engine.update_slot(100);
    engine
        .record_job([1u8; 32], make_job(100, true, 100))
        .unwrap();

    let metrics = engine.metrics();
    use std::sync::atomic::Ordering;
    assert_eq!(metrics.total_jobs_processed.load(Ordering::Relaxed), 1);
}

#[test]
fn test_engine_multiple_methods_scoring() {
    let engine = test_engine();
    engine.update_slot(100);

    // ZkProof jobs should score higher due to 1.5x multiplier
    engine
        .record_job(
            [1u8; 32],
            make_job_method(1000, VerificationMethod::TeeAttestation, 100),
        )
        .unwrap();
    engine
        .record_job(
            [2u8; 32],
            make_job_method(1000, VerificationMethod::ZkProof, 100),
        )
        .unwrap();

    let tee_score = engine.get_score(&[1u8; 32]);
    let zk_score = engine.get_score(&[2u8; 32]);
    assert!(zk_score > tee_score);
}

#[test]
fn test_engine_active_streak() {
    let engine = test_engine();

    // Record jobs on consecutive days
    for day in 0..5u64 {
        let slot = day * SLOTS_PER_DAY + 100;
        engine.update_slot(slot);
        engine
            .record_job([1u8; 32], make_job(100, true, slot))
            .unwrap();
    }

    let rep = engine.get_reputation(&[1u8; 32]).unwrap();
    assert!(rep.active_streak >= 4);
}

#[test]
fn test_engine_active_streak_broken() {
    let engine = test_engine();

    // Day 1
    engine.update_slot(SLOTS_PER_DAY);
    engine
        .record_job([1u8; 32], make_job(100, true, SLOTS_PER_DAY))
        .unwrap();

    // Day 2
    engine.update_slot(2 * SLOTS_PER_DAY);
    engine
        .record_job([1u8; 32], make_job(100, true, 2 * SLOTS_PER_DAY))
        .unwrap();

    // Skip day 3, go to day 4 (streak breaks)
    engine.update_slot(4 * SLOTS_PER_DAY);
    engine
        .record_job([1u8; 32], make_job(100, true, 4 * SLOTS_PER_DAY))
        .unwrap();

    let rep = engine.get_reputation(&[1u8; 32]).unwrap();
    assert_eq!(rep.active_streak, 1); // Reset after gap
}

#[test]
fn test_engine_active_streak_saturates_at_u32_max() {
    let engine = test_engine();
    let validator = [9u8; 32];
    let current_day = u32::MAX;
    let slot = current_day as u64 * SLOTS_PER_DAY;

    let mut state = ValidatorReputation::new(validator);
    state.active_streak = u32::MAX;
    state.last_active_day = u32::MAX;

    let snapshot = ReputationSnapshot {
        slot,
        validators: HashMap::from([(validator, state)]),
        config: ReputationConfig::devnet(),
    };
    engine.restore(snapshot).unwrap();
    engine.update_slot(slot);

    engine
        .record_job(validator, make_job(100, true, slot))
        .unwrap();

    let rep = engine.get_reputation(&validator).unwrap();
    assert_eq!(rep.active_streak, u32::MAX);
    assert_eq!(rep.last_active_day, u32::MAX);
}

#[test]
fn test_engine_window_pruning() {
    let engine = test_engine(); // Devnet: window_days = 3

    // Record a job at slot 0
    engine.update_slot(0);
    engine
        .record_job([1u8; 32], make_job(100, true, 0))
        .unwrap();

    // Advance far past the window
    let far_future = 10 * SLOTS_PER_DAY;
    engine.update_slot(far_future);
    engine.apply_daily_decay(far_future).unwrap();

    // Score should be 0 after pruning (job expired)
    assert_eq!(engine.get_score(&[1u8; 32]), 0);
}

// =============================================================================
// VERIFICATION METHOD MULTIPLIER TESTS (in reputation.rs scope)
// =============================================================================

#[test]
fn test_verification_method_multiplier() {
    assert!((VerificationMethod::TeeAttestation.multiplier() - MULTIPLIER_TEE).abs() < 0.001);
    assert!((VerificationMethod::ZkProof.multiplier() - MULTIPLIER_ZK).abs() < 0.001);
    assert!((VerificationMethod::Hybrid.multiplier() - MULTIPLIER_HYBRID).abs() < 0.001);
    assert!((VerificationMethod::ReExecution.multiplier() - MULTIPLIER_REEXEC).abs() < 0.001);
}
