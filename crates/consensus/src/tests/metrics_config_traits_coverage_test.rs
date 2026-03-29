//! Comprehensive coverage tests for Metrics, Config, and Traits modules

use crate::metrics::{
    BlockMetrics, ComputeMetrics, ConsensusMetricsCollector, MetricsSnapshot,
    ReputationMetrics as MetricsReputationMetrics, TimingMetrics, ValidatorMetrics, VrfMetrics,
};
use crate::pouw::config::{PoUWConfig, UtilityCategory, VerificationMethod};
use crate::traits;

// =============================================================================
// METRICS COLLECTOR TESTS
// =============================================================================

#[test]
fn test_metrics_collector_new() {
    let collector = ConsensusMetricsCollector::new();
    assert!(collector.is_enabled());
    assert!(collector.uptime().as_nanos() >= 0);
}

#[test]
fn test_metrics_collector_default() {
    let collector = ConsensusMetricsCollector::default();
    assert!(collector.is_enabled());
}

#[test]
fn test_metrics_collector_disabled() {
    let collector = ConsensusMetricsCollector::disabled();
    assert!(!collector.is_enabled());

    // Update on disabled collector should be no-op
    collector.update_validator([1u8; 32], |m| {
        m.blocks_proposed = 100;
    });
}

#[test]
fn test_metrics_collector_snapshot() {
    let collector = ConsensusMetricsCollector::new();
    let snapshot = collector.snapshot();

    assert_eq!(snapshot.blocks.blocks_proposed, 0);
    assert_eq!(snapshot.vrf.proofs_generated, 0);
    assert!(snapshot.uptime_secs < 10); // Just created
}

#[test]
fn test_metrics_collector_reset() {
    let collector = ConsensusMetricsCollector::new();

    // Add some metrics
    collector.blocks.record_proposed();
    collector.vrf.record_proof_generated(100);
    collector.compute.record_job_submitted();

    // Reset
    collector.reset();

    let snapshot = collector.snapshot();
    assert_eq!(snapshot.blocks.blocks_proposed, 0);
    assert_eq!(snapshot.vrf.proofs_generated, 0);
    assert_eq!(snapshot.compute.jobs_submitted, 0);
}

#[test]
fn test_metrics_collector_validator() {
    let collector = ConsensusMetricsCollector::new();
    let addr = [1u8; 32];

    // First access creates new
    let m1 = collector.validator(addr);
    assert_eq!(m1.blocks_proposed, 0);

    // Update
    collector.update_validator(addr, |m| {
        m.blocks_proposed = 5;
        m.stake = 1000;
    });

    // Read updated
    let m2 = collector.validator(addr);
    assert_eq!(m2.blocks_proposed, 5);
    assert_eq!(m2.stake, 1000);
}

// =============================================================================
// BLOCK METRICS TESTS
// =============================================================================

#[test]
fn test_block_metrics() {
    let metrics = BlockMetrics::default();

    metrics.record_proposed();
    metrics.record_validated();
    metrics.record_rejected();
    metrics.record_finalized();
    metrics.update_slot(100, 1);
    metrics.update_height(50);

    let snap = metrics.snapshot();
    assert_eq!(snap.blocks_proposed, 1);
    assert_eq!(snap.blocks_validated, 1);
    assert_eq!(snap.blocks_rejected, 1);
    assert_eq!(snap.blocks_finalized, 1);
    assert_eq!(snap.current_slot, 100);
    assert_eq!(snap.current_epoch, 1);
    assert_eq!(snap.current_height, 50);

    metrics.reset();
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.blocks_proposed, 0);
}

// =============================================================================
// VRF METRICS TESTS
// =============================================================================

#[test]
fn test_vrf_metrics() {
    let metrics = VrfMetrics::default();

    metrics.record_proof_generated(100);
    metrics.record_proof_generated(200);
    metrics.record_proof_verified(true, 50);
    metrics.record_proof_verified(false, 30);
    metrics.record_threshold_check(true);
    metrics.record_threshold_check(false);

    let snap = metrics.snapshot();
    assert_eq!(snap.proofs_generated, 2);
    assert_eq!(snap.proofs_verified_success, 1);
    assert_eq!(snap.proofs_verified_failure, 1);
    assert_eq!(snap.threshold_hits, 1);
    assert_eq!(snap.threshold_misses, 1);
    assert!((snap.avg_proof_generation_us - 150.0).abs() < 0.1);

    metrics.reset();
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.proofs_generated, 0);
}

#[test]
fn test_vrf_metrics_avg_zero_proofs() {
    let metrics = VrfMetrics::default();
    assert!((metrics.avg_proof_generation_us() - 0.0).abs() < 0.001);
}

// =============================================================================
// COMPUTE METRICS TESTS
// =============================================================================

#[test]
fn test_compute_metrics() {
    let metrics = ComputeMetrics::default();

    metrics.record_job_submitted();
    metrics.record_job_verified(true, 0, 100, 50); // TEE
    metrics.record_job_verified(true, 1, 200, 60); // zkML
    metrics.record_job_verified(true, 2, 300, 70); // Hybrid
    metrics.record_job_verified(false, 3, 50, 40); // ReExecution, failed
    metrics.record_job_verified(true, 99, 10, 5); // Unknown method

    let snap = metrics.snapshot();
    assert_eq!(snap.jobs_submitted, 1);
    assert_eq!(snap.jobs_verified_success, 4);
    assert_eq!(snap.jobs_verified_failure, 1);
    assert_eq!(snap.verifications_tee, 1);
    assert_eq!(snap.verifications_zkml, 1);
    assert_eq!(snap.verifications_hybrid, 1);
    assert_eq!(snap.verifications_reexec, 1);
    assert!(snap.success_rate > 0.7);

    metrics.reset();
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.jobs_submitted, 0);
}

#[test]
fn test_compute_metrics_success_rate_empty() {
    let metrics = ComputeMetrics::default();
    assert!((metrics.success_rate() - 1.0).abs() < 0.001);
}

// =============================================================================
// REPUTATION METRICS TESTS
// =============================================================================

#[test]
fn test_reputation_metrics() {
    let metrics = MetricsReputationMetrics::default();

    metrics.record_score_update(100);
    metrics.record_score_update(-50); // Negative delta
    metrics.record_decay_event();
    metrics.update_active_count(10);

    let snap = metrics.snapshot();
    assert_eq!(snap.score_updates, 2);
    assert_eq!(snap.decay_events, 1);
    assert_eq!(snap.active_validators, 10);
    assert_eq!(snap.total_score, 100); // Only positive delta

    metrics.reset();
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.score_updates, 0);
}

// =============================================================================
// TIMING METRICS TESTS
// =============================================================================

#[test]
fn test_timing_metrics() {
    let metrics = TimingMetrics::default();

    metrics.record_block_production(100);
    metrics.record_block_production(200);
    metrics.record_block_validation(50);
    metrics.record_consensus_round(500);

    assert!((metrics.avg_block_production_us() - 150.0).abs() < 0.1);
    assert!((metrics.avg_block_validation_us() - 50.0).abs() < 0.1);

    let snap = metrics.snapshot();
    assert_eq!(snap.block_production_count, 2);
    assert_eq!(snap.block_validation_count, 1);
    assert_eq!(snap.consensus_round_count, 1);

    metrics.reset();
    let snap2 = metrics.snapshot();
    assert_eq!(snap2.block_production_count, 0);
}

#[test]
fn test_timing_metrics_avg_zero() {
    let metrics = TimingMetrics::default();
    assert!((metrics.avg_block_production_us() - 0.0).abs() < 0.001);
    assert!((metrics.avg_block_validation_us() - 0.0).abs() < 0.001);
}

// =============================================================================
// VALIDATOR METRICS TESTS
// =============================================================================

#[test]
fn test_validator_metrics_new() {
    let m = ValidatorMetrics::new([1u8; 32]);
    assert_eq!(m.blocks_proposed, 0);
    assert!((m.uptime_percent - 100.0).abs() < 0.001);
}

#[test]
fn test_validator_metrics_proposal_rate() {
    let mut m = ValidatorMetrics::new([1u8; 32]);
    assert!((m.proposal_rate() - 0.0).abs() < 0.001); // Zero total

    m.blocks_proposed = 8;
    m.blocks_missed = 2;
    assert!((m.proposal_rate() - 0.8).abs() < 0.001);
}

#[test]
fn test_validator_metrics_job_success_rate() {
    let mut m = ValidatorMetrics::new([1u8; 32]);
    assert!((m.job_success_rate() - 1.0).abs() < 0.001); // Zero total

    m.jobs_verified = 9;
    m.jobs_failed = 1;
    assert!((m.job_success_rate() - 0.9).abs() < 0.001);
}

// =============================================================================
// METRICS SNAPSHOT TESTS
// =============================================================================

#[test]
fn test_metrics_snapshot_to_json() {
    let collector = ConsensusMetricsCollector::new();
    collector.blocks.record_proposed();
    let snapshot = collector.snapshot();

    let json = snapshot.to_json();
    assert!(json.contains("blocks_proposed"));
    assert!(json.contains("proofs_generated"));
}

#[test]
fn test_metrics_snapshot_to_prometheus() {
    let collector = ConsensusMetricsCollector::new();
    collector.blocks.record_proposed();
    collector.blocks.update_slot(100, 1);
    let snapshot = collector.snapshot();

    let prom = snapshot.to_prometheus();
    assert!(prom.contains("aethelred_blocks_proposed 1"));
    assert!(prom.contains("aethelred_current_slot 100"));
}

// =============================================================================
// POUW CONFIG TESTS
// =============================================================================

#[test]
fn test_config_devnet() {
    let config = PoUWConfig::devnet();
    assert!(config.slot_duration_ms > 0);
    assert!(config.slots_per_epoch > 0);
}

#[test]
fn test_config_testnet() {
    let config = PoUWConfig::testnet();
    assert!(config.slot_duration_ms > 0);
}

#[test]
fn test_config_mainnet() {
    let config = PoUWConfig::mainnet();
    assert!(config.slot_duration_ms > 0);
}

#[test]
fn test_config_category_multiplier() {
    let config = PoUWConfig::devnet();

    let general = config.category_multiplier(UtilityCategory::General);
    let medical = config.category_multiplier(UtilityCategory::Medical);
    let financial = config.category_multiplier(UtilityCategory::Financial);
    let scientific = config.category_multiplier(UtilityCategory::Scientific);

    assert_eq!(general, 10000); // 1.0x in BPS
    assert!(medical > general);
    assert!(financial > general);
    assert!(scientific > general);
}

#[test]
fn test_utility_category_variants() {
    let categories = [
        UtilityCategory::General,
        UtilityCategory::Financial,
        UtilityCategory::Medical,
        UtilityCategory::Scientific,
        UtilityCategory::Environmental,
        UtilityCategory::Infrastructure,
        UtilityCategory::Education,
    ];

    for cat in &categories {
        let _ = format!("{:?}", cat);
        let cloned = *cat;
        assert_eq!(cloned, *cat);
    }
}

#[test]
fn test_verification_method_variants() {
    let methods = [
        VerificationMethod::TeeAttestation,
        VerificationMethod::ZkProof,
        VerificationMethod::Hybrid,
        VerificationMethod::ReExecution,
        VerificationMethod::AiProof,
    ];

    for method in &methods {
        let _ = format!("{:?}", method);
        let cloned = *method;
        assert_eq!(cloned, *method);
    }
}

// =============================================================================
// TRAITS TESTS
// =============================================================================

#[test]
fn test_compute_result_new() {
    let result = traits::ComputeResult::new(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [5u8; 32],
        100,
        traits::VerificationMethod::TeeAttestation,
        [4u8; 32],
    );

    assert_eq!(result.job_id, [1u8; 32]);
    assert_eq!(result.model_hash, [2u8; 32]);
    assert_eq!(result.output_hash, [5u8; 32]);
    assert_eq!(result.complexity, 100);
    assert!(result.attestation.is_empty());
    assert!(result.zk_proof.is_none());
}

#[test]
fn test_compute_result_with_attestation() {
    let result = traits::ComputeResult::new(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [5u8; 32],
        100,
        traits::VerificationMethod::TeeAttestation,
        [4u8; 32],
    )
    .with_attestation(vec![0xAA; 200]);

    assert_eq!(result.attestation.len(), 200);
}

#[test]
fn test_compute_result_with_zk_proof() {
    let result = traits::ComputeResult::new(
        [1u8; 32],
        [2u8; 32],
        [3u8; 32],
        [5u8; 32],
        100,
        traits::VerificationMethod::ZkProof,
        [4u8; 32],
    )
    .with_zk_proof(vec![0xBB; 300]);

    assert!(result.zk_proof.is_some());
    assert_eq!(result.zk_proof.unwrap().len(), 300);
}

#[test]
fn test_verification_method_assurance_level() {
    assert_eq!(traits::VerificationMethod::ReExecution.assurance_level(), 1);
    assert_eq!(
        traits::VerificationMethod::TeeAttestation.assurance_level(),
        2
    );
    assert_eq!(traits::VerificationMethod::ZkProof.assurance_level(), 3);
    assert_eq!(traits::VerificationMethod::Hybrid.assurance_level(), 4);
}

#[test]
fn test_verification_method_score_multiplier() {
    assert!((traits::VerificationMethod::ReExecution.score_multiplier() - 0.8).abs() < 0.001);
    assert!((traits::VerificationMethod::TeeAttestation.score_multiplier() - 1.0).abs() < 0.001);
    assert!((traits::VerificationMethod::ZkProof.score_multiplier() - 1.5).abs() < 0.001);
    assert!((traits::VerificationMethod::Hybrid.score_multiplier() - 2.0).abs() < 0.001);
}

#[test]
fn test_verification_method_from_u8() {
    assert_eq!(
        traits::VerificationMethod::from_u8(0),
        Some(traits::VerificationMethod::TeeAttestation)
    );
    assert_eq!(
        traits::VerificationMethod::from_u8(1),
        Some(traits::VerificationMethod::ZkProof)
    );
    assert_eq!(
        traits::VerificationMethod::from_u8(2),
        Some(traits::VerificationMethod::Hybrid)
    );
    assert_eq!(
        traits::VerificationMethod::from_u8(3),
        Some(traits::VerificationMethod::ReExecution)
    );
    assert_eq!(traits::VerificationMethod::from_u8(4), None);
    assert_eq!(traits::VerificationMethod::from_u8(255), None);
}

#[test]
fn test_verification_method_default() {
    let default: traits::VerificationMethod = Default::default();
    assert_eq!(default, traits::VerificationMethod::TeeAttestation);
}
