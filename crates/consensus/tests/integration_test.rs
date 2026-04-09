//! Integration tests for the aethelred-consensus crate.
//!
//! Tests cover VRF key generation, reputation engine scoring, PoUW
//! configuration, and compute multiplier math.

use aethelred_consensus::{
    compute_multiplier, calculate_useful_work_multiplier,
    PoUWConfig, ReputationConfig, ReputationEngine,
    VrfKeys,
    DEFAULT_SLOT_DURATION_MS, DEFAULT_SLOTS_PER_EPOCH,
    MAX_COMPUTE_MULTIPLIER, MAX_USEFUL_WORK_MULTIPLIER,
    MIN_STAKE_FOR_ELECTION, MAX_VALIDATORS, MIN_VALIDATORS,
    VERSION,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_version_populated() {
    assert!(!VERSION.is_empty());
}

#[test]
fn test_constants_sensible_values() {
    assert!(DEFAULT_SLOT_DURATION_MS > 0);
    assert!(DEFAULT_SLOTS_PER_EPOCH > 0);
    assert!(MAX_COMPUTE_MULTIPLIER > 1.0);
    assert!(MIN_STAKE_FOR_ELECTION > 0);
    assert!(MAX_VALIDATORS > MIN_VALIDATORS);
}

// ---------------------------------------------------------------------------
// Compute Multiplier
// ---------------------------------------------------------------------------

#[test]
fn test_compute_multiplier_zero_score_yields_one() {
    let mult = compute_multiplier(0);
    assert!(
        (mult - 1.0).abs() < 0.01,
        "zero compute should give ~1.0x, got {mult}"
    );
}

#[test]
fn test_compute_multiplier_increases_with_score() {
    let m_low = compute_multiplier(100);
    let m_mid = compute_multiplier(1_000_000);
    let m_high = compute_multiplier(1_000_000_000);

    assert!(m_low < m_mid, "m_low={m_low} should be < m_mid={m_mid}");
    assert!(m_mid < m_high, "m_mid={m_mid} should be < m_high={m_high}");
}

#[test]
fn test_compute_multiplier_capped() {
    let mult = compute_multiplier(u64::MAX);
    assert!(
        mult <= MAX_COMPUTE_MULTIPLIER + 0.01,
        "multiplier {mult} should not exceed cap {MAX_COMPUTE_MULTIPLIER}"
    );
}

#[test]
fn test_useful_work_multiplier_bounds() {
    let mult = calculate_useful_work_multiplier(0);
    assert!((mult - 1.0).abs() < 0.01);

    let mult_max = calculate_useful_work_multiplier(u64::MAX);
    assert!(mult_max <= MAX_USEFUL_WORK_MULTIPLIER + 0.01);
}

// ---------------------------------------------------------------------------
// VRF Keys
// ---------------------------------------------------------------------------

#[test]
fn test_vrf_keys_generate() {
    let keys = VrfKeys::generate();
    // Keys should be non-degenerate (public key is derived from secret).
    let keys2 = VrfKeys::generate();
    // Two independent key pairs are almost certainly distinct.
    assert_ne!(
        format!("{:?}", keys),
        format!("{:?}", keys2),
        "two independent VRF key generations should differ"
    );
}

// ---------------------------------------------------------------------------
// PoUW Configuration
// ---------------------------------------------------------------------------

#[test]
fn test_pouw_config_mainnet() {
    let config = PoUWConfig::mainnet();
    assert!(config.slot_duration_ms > 0);
}

#[test]
fn test_pouw_config_testnet() {
    let config = PoUWConfig::testnet();
    assert!(config.slot_duration_ms > 0);
}

// ---------------------------------------------------------------------------
// Reputation Engine
// ---------------------------------------------------------------------------

#[test]
fn test_reputation_engine_new() {
    let config = ReputationConfig::default();
    let engine = ReputationEngine::new(config);
    // Fresh engine should have no validators tracked.
    let snapshot = engine.snapshot();
    assert!(snapshot.validators.is_empty());
}
