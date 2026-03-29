//! Kani formal verification proof harnesses for aethelred-consensus.
//!
//! These harnesses use the Kani model checker to formally verify safety
//! properties of the PoUW consensus engine.
//!
//! Run with: `cargo kani --manifest-path crates/consensus/Cargo.toml`

use super::*;

// =============================================================================
// compute_multiplier proofs
// =============================================================================

/// Proves that `compute_multiplier` always returns a value in [1.0, MAX_COMPUTE_MULTIPLIER]
/// for any u64 input. This is critical for consensus safety: an unbounded multiplier
/// could allow a validator to monopolize block production.
#[kani::proof]
fn verify_compute_multiplier_bounded() {
    let score: u64 = kani::any();
    let mult = types::compute_multiplier(score);

    assert!(
        mult >= 1.0,
        "compute_multiplier must be >= 1.0 for any input"
    );
    assert!(
        mult <= MAX_COMPUTE_MULTIPLIER,
        "compute_multiplier must be <= MAX_COMPUTE_MULTIPLIER"
    );
}

/// Proves that `compute_multiplier(0)` returns exactly 1.0 (within f64 precision).
/// A zero useful-work score must not give any advantage in leader election.
#[kani::proof]
fn verify_compute_multiplier_zero_is_unity() {
    let mult = types::compute_multiplier(0);
    // log10(1) = 0, so multiplier = 1 + 0/6 = 1.0 exactly
    assert!(
        (mult - 1.0).abs() < 1e-10,
        "compute_multiplier(0) must equal 1.0"
    );
}

// =============================================================================
// SlotTiming proofs
// =============================================================================

/// Proves that `epoch_for_slot` and `first_slot_of_epoch` are consistent:
/// the first slot of an epoch maps back to that epoch.
#[kani::proof]
fn verify_slot_epoch_roundtrip() {
    let slots_per_epoch: u64 = kani::any();
    kani::assume(slots_per_epoch > 0);
    kani::assume(slots_per_epoch <= 1_000_000); // bound for tractability

    let timing = types::SlotTiming {
        slot_duration_ms: 6000,
        slots_per_epoch,
        genesis_timestamp: 0,
    };

    let epoch: u64 = kani::any();
    kani::assume(epoch <= u64::MAX / slots_per_epoch); // prevent overflow

    let first_slot = timing.first_slot_of_epoch(epoch);
    let recovered_epoch = timing.epoch_for_slot(first_slot);

    assert!(
        recovered_epoch == epoch,
        "epoch_for_slot(first_slot_of_epoch(e)) must equal e"
    );
}

/// Proves that `is_epoch_boundary` is true if and only if the slot is
/// divisible by `slots_per_epoch`.
#[kani::proof]
fn verify_epoch_boundary_consistency() {
    let slots_per_epoch: u64 = kani::any();
    kani::assume(slots_per_epoch > 0);
    kani::assume(slots_per_epoch <= 1_000_000);

    let slot: u64 = kani::any();

    let timing = types::SlotTiming {
        slot_duration_ms: 6000,
        slots_per_epoch,
        genesis_timestamp: 0,
    };

    let is_boundary = timing.is_epoch_boundary(slot);
    let is_divisible = slot % slots_per_epoch == 0;

    assert!(
        is_boundary == is_divisible,
        "is_epoch_boundary must be true iff slot % slots_per_epoch == 0"
    );
}

// =============================================================================
// ValidatorInfo proofs
// =============================================================================

/// Proves that a jailed validator is never eligible before their jail expiry,
/// and that an unjailed active validator with sufficient stake is always eligible.
#[kani::proof]
fn verify_validator_eligibility_jail_logic() {
    let current_slot: u64 = kani::any();
    let jailed_until: u64 = kani::any();
    let active: bool = kani::any();
    let stake: u128 = kani::any();

    let mut validator = types::ValidatorInfo::new([1u8; 32], stake, vec![], vec![], 1000, 0);
    validator.active = active;
    validator.jailed_until = jailed_until;

    let eligible = validator.is_eligible(current_slot);

    // If jailed and jail hasn't expired, must not be eligible
    if jailed_until > 0 && current_slot < jailed_until {
        assert!(
            !eligible,
            "Jailed validator must not be eligible before jail expiry"
        );
    }

    // If active, unjailed, and sufficient stake, must be eligible
    if active
        && (jailed_until == 0 || current_slot >= jailed_until)
        && stake >= MIN_STAKE_FOR_ELECTION
    {
        assert!(
            eligible,
            "Active unjailed validator with sufficient stake must be eligible"
        );
    }
}
