//! Miner Boost Test
//!
//! This test proves that validators with high useful work scores win more blocks
//! than validators with the same stake but zero useful work score.
//!
//! # Test Design
//!
//! We simulate 10,000 slots with two validators:
//! - Validator A: 10,000 stake + 0 useful work score
//! - Validator B: 10,000 stake + HIGH useful work score
//!
//! We count how many times each validator wins the VRF lottery.
//! Validator B should win significantly more often (~2-3x) due to
//! the useful work multiplier boosting their threshold.

use crate::pouw::{
    calculate_useful_work_multiplier, estimate_leader_probability, PoUWConfig, PoUWElection,
    UtilityCategory, VerificationMethod,
};
use crate::reputation::{ComputeJobRecord, ReputationConfig, ReputationEngine};
use crate::traits::VerificationMethod as RepVerificationMethod;
use crate::types::{Address, ValidatorInfo};
use crate::vrf::VrfKeys;

/// Create a validator with specific parameters
fn make_validator(seed: u8, stake: u128) -> (Address, ValidatorInfo, VrfKeys) {
    let mut addr = [0u8; 32];
    addr[0] = seed;

    let key_seed = [seed; 32];
    let vrf_keys = VrfKeys::from_seed(&key_seed).unwrap();

    let info = ValidatorInfo::new(
        addr,
        stake,
        vrf_keys.public_key_bytes(),
        vec![],
        0, // commission
        0, // registered at slot 0
    );

    (addr, info, vrf_keys)
}

/// Test that validators with useful work score win more blocks
///
/// This is the critical test requested by the consultants.
#[test]
fn test_miner_boost() {
    // Configuration
    let stake = 10_000_000_000_000u128; // 10,000 tokens (12 decimals)
    let high_work = 1_000_000u64; // High useful work score (~2x multiplier)
    let num_slots = 10_000u64;
    let epoch_seed = [42u8; 32];

    // Create election system
    let config = PoUWConfig::devnet();
    let election = PoUWElection::new(config.clone());

    // Create two validators with same stake
    let (addr_a, mut info_a, keys_a) = make_validator(1, stake);
    let (addr_b, mut info_b, keys_b) = make_validator(2, stake);

    // Ensure both are active
    info_a.active = true;
    info_b.active = true;

    // Register validators
    election.register_validator(info_a).unwrap();
    election.register_validator(info_b).unwrap();
    election.set_epoch_seed(epoch_seed);

    // Grant useful work to validator B
    election
        .record_useful_work(
            &addr_b,
            high_work,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            10_000,
        )
        .unwrap();

    // Get stats to verify setup
    let stats = election.stats();
    assert_eq!(stats.total_validators, 2);
    assert_eq!(stats.active_validators, 2);

    println!("=== MINER BOOST TEST ===");
    println!("Stake per validator: {}", stake);
    println!("Validator A useful work score: 0");
    println!("Validator B useful work score: {}", high_work);
    println!();
    println!("Multiplier A: {:.4}", calculate_useful_work_multiplier(0));
    println!(
        "Multiplier B: {:.4}",
        calculate_useful_work_multiplier(high_work)
    );
    println!();
    println!("Total weighted stake: {}", stats.total_weighted_stake);
    println!();

    // Simulate many slots
    let mut wins_a = 0u64;
    let mut wins_b = 0u64;
    let mut both_win = 0u64;
    let mut neither_win = 0u64;

    for slot in 0..num_slots {
        let a_wins = election
            .check_eligibility(&addr_a, slot, &keys_a)
            .unwrap()
            .is_some();
        let b_wins = election
            .check_eligibility(&addr_b, slot, &keys_b)
            .unwrap()
            .is_some();

        match (a_wins, b_wins) {
            (true, true) => both_win += 1,
            (true, false) => wins_a += 1,
            (false, true) => wins_b += 1,
            (false, false) => neither_win += 1,
        }
    }

    println!("=== RESULTS over {} slots ===", num_slots);
    println!("Validator A (no useful work) wins: {}", wins_a);
    println!("Validator B (high useful work) wins: {}", wins_b);
    println!("Both win (tiebreaker needed): {}", both_win);
    println!("Neither wins (empty slot): {}", neither_win);
    println!();

    // Calculate win rates
    let total_a_eligible = wins_a + both_win;
    let total_b_eligible = wins_b + both_win;
    let ratio = total_b_eligible as f64 / total_a_eligible.max(1) as f64;

    println!("Total A eligible: {}", total_a_eligible);
    println!("Total B eligible: {}", total_b_eligible);
    println!("B/A ratio: {:.2}x", ratio);

    // CRITICAL ASSERTION: Validator B must win MORE than Validator A
    assert!(
        total_b_eligible > total_a_eligible,
        "Validator B (with {} useful work score) should be eligible more often than A (with 0). \
         Got A={}, B={}",
        high_work,
        total_a_eligible,
        total_b_eligible
    );

    // The useful work multiplier at 1M score is ~2x
    // We'll check that it's at least 1.3x (conservative)
    assert!(
        ratio > 1.3,
        "Validator B should win at least 1.3x more often than A. Got ratio: {:.2}",
        ratio
    );

    println!();
    println!("=== TEST PASSED ===");
    println!(
        "Useful work boost verified: {}x advantage for {} useful work score",
        ratio, high_work
    );
}

/// Test that the multiplier scales logarithmically
#[test]
fn test_useful_work_multiplier_scaling() {
    // Test various useful work scores
    let test_cases = vec![
        (0, 1.0),
        (1, 1.05),            // log10(2)/6 ≈ 0.05
        (1_000, 1.5),         // log10(1000)/6 = 0.5
        (1_000_000, 2.0),     // log10(1,000,000)/6 = 1.0
        (1_000_000_000, 2.5), // log10(1,000,000,000)/6 = 1.5
        (u64::MAX, 4.2),      // u64 max yields ~4.21x with log10/6
    ];

    println!("=== USEFUL WORK MULTIPLIER SCALING ===");
    for (score, expected) in test_cases {
        let actual = calculate_useful_work_multiplier(score);
        println!(
            "Score {}: {:.4}x (expected ~{:.1}x)",
            score, actual, expected
        );

        // Allow 10% tolerance
        let tolerance = 0.2;
        assert!(
            (actual - expected).abs() < tolerance,
            "Score {} should give ~{:.1}x multiplier, got {:.4}x",
            score,
            expected,
            actual
        );
    }
    println!("=== SCALING TEST PASSED ===");
}

/// Test that weighted stake increases with useful work score
#[test]
fn test_weighted_stake_boost() {
    let base_stake = 1_000_000_000_000u128; // 1000 tokens

    // No useful work
    let weighted_0 = crate::pouw::calculate_weighted_stake(base_stake, 0);
    assert_eq!(
        weighted_0, base_stake,
        "Zero useful work should give 1x stake"
    );

    // Medium useful work
    let weighted_1m = crate::pouw::calculate_weighted_stake(base_stake, 1_000_000);
    let ratio_1m = weighted_1m as f64 / base_stake as f64;
    println!("1M useful work: {:.2}x boost", ratio_1m);
    assert!(
        ratio_1m > 1.8 && ratio_1m < 2.2,
        "1M useful work should give ~2x boost"
    );

    // High useful work
    let weighted_1b = crate::pouw::calculate_weighted_stake(base_stake, 1_000_000_000);
    let ratio_1b = weighted_1b as f64 / base_stake as f64;
    println!("1B useful work: {:.2}x boost", ratio_1b);
    assert!(
        ratio_1b > 2.3 && ratio_1b < 2.7,
        "1B useful work should give ~2.5x boost"
    );

    // Max useful work (capped at 5x)
    let weighted_max = crate::pouw::calculate_weighted_stake(base_stake, u64::MAX);
    let ratio_max = weighted_max as f64 / base_stake as f64;
    println!("MAX useful work: {:.2}x boost (u64 max ~4.2x)", ratio_max);
    assert!(
        (ratio_max - 4.2).abs() < 0.2,
        "Max useful work should be ~4.2x for u64::MAX"
    );
}

/// Test election with multiple validators at different useful work levels
#[test]
fn test_multi_validator_useful_work_distribution() {
    let stake = 1_000_000_000_000u128;
    let num_slots = 5_000u64;
    let epoch_seed = [123u8; 32];

    let config = PoUWConfig::devnet();
    let election = PoUWElection::new(config);

    // Create validators with different useful work scores
    // V1: 0 work (1x)
    // V2: 1,000 work (~1.5x)
    // V3: 1,000,000 work (~2.0x)
    // V4: 1,000,000,000 work (~2.5x)
    let work_scores = [0u64, 1_000, 1_000_000, 1_000_000_000];
    let mut validators = Vec::new();

    for (i, &work) in work_scores.iter().enumerate() {
        let (addr, mut info, keys) = make_validator((i + 1) as u8, stake);
        info.active = true;
        election.register_validator(info).unwrap();
        if work > 0 {
            election
                .record_useful_work(
                    &addr,
                    work,
                    UtilityCategory::General,
                    VerificationMethod::TeeAttestation,
                    10_000,
                )
                .unwrap();
        }
        validators.push((addr, keys, work));
    }
    election.set_epoch_seed(epoch_seed);

    // Calculate expected win ratios based on multipliers
    let multipliers: Vec<f64> = work_scores
        .iter()
        .map(|&s| calculate_useful_work_multiplier(s))
        .collect();
    let total_multiplier: f64 = multipliers.iter().sum();

    println!("=== MULTI-VALIDATOR DISTRIBUTION ===");
    println!(
        "Validators: {} with equal stake {}",
        work_scores.len(),
        stake
    );
    for (i, (&score, &mult)) in work_scores.iter().zip(multipliers.iter()).enumerate() {
        let expected_share = mult / total_multiplier * 100.0;
        println!(
            "V{}: work_score={}, multiplier={:.2}x, expected share={:.1}%",
            i + 1,
            score,
            mult,
            expected_share
        );
    }
    println!();

    // Simulate slots
    let mut wins = vec![0u64; 4];

    for slot in 0..num_slots {
        for (i, (addr, keys, _work)) in validators.iter().enumerate() {
            if election
                .check_eligibility(addr, slot, keys)
                .unwrap()
                .is_some()
            {
                wins[i] += 1;
            }
        }
    }

    println!("=== ACTUAL RESULTS over {} slots ===", num_slots);
    let total_wins: u64 = wins.iter().sum();
    for (i, &w) in wins.iter().enumerate() {
        let actual_share = w as f64 / total_wins.max(1) as f64 * 100.0;
        println!("V{}: {} wins ({:.1}%)", i + 1, w, actual_share);
    }

    // Verify ordering: higher useful work = more wins
    assert!(wins[1] > wins[0], "V2 (1K work) should beat V1 (0 work)");
    assert!(wins[2] > wins[1], "V3 (1M work) should beat V2 (1K work)");
    assert!(wins[3] > wins[2], "V4 (1B work) should beat V3 (1M work)");

    println!();
    println!("=== MULTI-VALIDATOR TEST PASSED ===");
}

/// Integration test: ReputationEngine -> Election flow
#[test]
fn test_reputation_to_election_integration() {
    // Create reputation engine
    let rep_engine = ReputationEngine::new(ReputationConfig::devnet());

    // Create election system
    let config = PoUWConfig::devnet();
    let election = PoUWElection::new(config);

    // Two validators with same stake
    let stake = 10_000_000_000_000u128;
    let (_addr_a, mut info_a, _) = make_validator(1, stake);
    let (addr_b, mut info_b, _) = make_validator(2, stake);
    info_a.active = true;
    info_b.active = true;

    election.register_validator(info_a).unwrap();
    election.register_validator(info_b).unwrap();

    // Initial state: both have 0 useful work, equal thresholds
    let stats = election.stats();
    let p_a_initial = estimate_leader_probability(stake, 0, stats.total_weighted_stake);
    let p_b_initial = estimate_leader_probability(stake, 0, stats.total_weighted_stake);
    assert!((p_a_initial - p_b_initial).abs() < f64::EPSILON);

    // Validator B performs verification jobs
    rep_engine.update_slot(1000);
    for i in 0..100 {
        let job = ComputeJobRecord::new(
            [i as u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            10_000, // 10K complexity per job
            RepVerificationMethod::TeeAttestation,
            1000 + i as u64,
            true,
        );
        rep_engine.record_job(addr_b, job).unwrap();
    }

    // Get B's new score
    let b_score = rep_engine.get_score(&addr_b);
    println!("Validator B reputation score after 100 jobs: {}", b_score);
    assert!(b_score > 0, "B should have non-zero score after jobs");

    // Update election system with new useful work score (mapped from reputation)
    election
        .record_useful_work(
            &addr_b,
            b_score,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
            10_000,
        )
        .unwrap();

    // Now B should have higher threshold
    let stats_updated = election.stats();
    let p_a_new = estimate_leader_probability(stake, 0, stats_updated.total_weighted_stake);
    let p_b_new = estimate_leader_probability(stake, b_score, stats_updated.total_weighted_stake);

    println!("After reputation update:");
    println!("  P(A): {:.6}", p_a_new);
    println!("  P(B): {:.6}", p_b_new);

    assert!(
        p_b_new > p_a_new,
        "B with useful work should have higher leader probability"
    );

    println!();
    println!("=== REPUTATION -> ELECTION INTEGRATION TEST PASSED ===");
}
