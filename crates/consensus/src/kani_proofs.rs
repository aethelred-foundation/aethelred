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

/// Checks representative regression points for `compute_multiplier`.
///
/// Kani is a poor fit for universal proofs over floating-point `log10` with an
/// arbitrary `u64` domain. CI therefore locks in the consensus-critical boundary
/// behavior here and relies on the Rust unit tests in `types.rs` for broader
/// numeric coverage.
#[kani::proof]
fn verify_compute_multiplier_regression_points() {
    let mult_zero = types::compute_multiplier(0);
    let mult_1k = types::compute_multiplier(1_000);
    let mult_1m = types::compute_multiplier(1_000_000);
    let mult_max = types::compute_multiplier(u64::MAX);

    assert!(
        (mult_zero - 1.0).abs() < 1e-10,
        "compute_multiplier(0) must equal 1.0"
    );
    assert!(
        mult_zero >= 1.0 && mult_zero <= MAX_COMPUTE_MULTIPLIER,
        "zero-score multiplier must stay in bounds"
    );
    assert!(
        mult_1k >= mult_zero && mult_1k <= MAX_COMPUTE_MULTIPLIER,
        "1k-score multiplier must stay bounded and monotonic"
    );
    assert!(
        mult_1m >= mult_1k && mult_1m <= MAX_COMPUTE_MULTIPLIER,
        "1m-score multiplier must stay bounded and monotonic"
    );
    assert!(
        mult_max >= mult_1m && mult_max <= MAX_COMPUTE_MULTIPLIER,
        "max-score multiplier must stay bounded and monotonic"
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
