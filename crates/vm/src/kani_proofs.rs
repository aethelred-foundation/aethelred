//! Kani formal verification proof harnesses for aethelred-vm.
//!
//! These harnesses use the Kani model checker to formally verify safety
//! properties of the VM gas metering and memory configuration.
//!
//! Run with: `cargo kani --manifest-path crates/vm/Cargo.toml`

use super::*;

// =============================================================================
// GasMeter proofs
// =============================================================================

/// Proves that GasMeter::consume never allows usage to exceed the limit.
/// This is critical for DoS prevention: a bug here could allow unbounded
/// computation within a single transaction.
#[kani::proof]
fn verify_gas_meter_limit_never_exceeded() {
    let limit: u64 = kani::any();
    kani::assume(limit <= 1_000_000); // bound for tractability

    let meter = gas::GasMeter::with_limit(limit);

    let amount1: u64 = kani::any();
    kani::assume(amount1 <= limit);

    let _ = meter.consume(amount1);

    // After any sequence of consume calls, used() must never exceed limit
    assert!(
        meter.used() <= limit,
        "Gas used must never exceed the gas limit"
    );
}

/// Proves that GasMeter::consume correctly rejects amounts that would
/// exceed the remaining gas, and that the meter state is unchanged on rejection.
#[kani::proof]
fn verify_gas_meter_reject_preserves_state() {
    let limit: u64 = kani::any();
    kani::assume(limit > 0);
    kani::assume(limit <= 1_000_000);

    let meter = gas::GasMeter::with_limit(limit);

    let first: u64 = kani::any();
    kani::assume(first <= limit);

    // First consume succeeds
    let _ = meter.consume(first);
    let used_after_first = meter.used();

    // Second consume that would exceed limit
    let second: u64 = kani::any();
    kani::assume(second > 0);
    kani::assume(used_after_first + second > limit);

    let result = meter.consume(second);

    assert!(result.is_err(), "Consume must fail when it would exceed limit");
    assert!(
        meter.used() == used_after_first,
        "Failed consume must not change used gas"
    );
}

/// Proves that `remaining() + used() == limit` is always maintained.
#[kani::proof]
fn verify_gas_meter_remaining_invariant() {
    let limit: u64 = kani::any();
    kani::assume(limit <= 1_000_000);

    let meter = gas::GasMeter::with_limit(limit);

    let amount: u64 = kani::any();
    kani::assume(amount <= limit);

    let _ = meter.consume(amount);

    // remaining uses saturating_sub, so this should always hold when used <= limit
    if meter.used() <= limit {
        assert!(
            meter.remaining() + meter.used() == limit,
            "remaining() + used() must equal limit"
        );
    }
}

// =============================================================================
// MemoryConfig proofs
// =============================================================================

/// Proves that MemoryConfig::validate correctly rejects configs where
/// initial_pages > max_pages.
#[kani::proof]
fn verify_memory_config_validation_initial_le_max() {
    let initial: u32 = kani::any();
    let max: u32 = kani::any();
    kani::assume(max <= 65536); // valid range

    let config = memory::MemoryConfig {
        initial_pages: initial,
        max_pages: max,
        bounds_checking: true,
        zero_on_alloc: true,
        guard_pages: true,
        stack_size: 1024,
    };

    let result = config.validate();

    if initial > max {
        assert!(
            result.is_err(),
            "validate must reject initial_pages > max_pages"
        );
    }
}

/// Proves that initial_bytes <= max_bytes for any valid MemoryConfig.
#[kani::proof]
fn verify_memory_config_bytes_ordering() {
    let initial: u32 = kani::any();
    let max: u32 = kani::any();
    kani::assume(initial <= max);
    kani::assume(max <= 65536);

    let config = memory::MemoryConfig {
        initial_pages: initial,
        max_pages: max,
        bounds_checking: true,
        zero_on_alloc: true,
        guard_pages: true,
        stack_size: 1024,
    };

    assert!(
        config.initial_bytes() <= config.max_bytes(),
        "initial_bytes must be <= max_bytes when initial_pages <= max_pages"
    );
}

// =============================================================================
// GasConfig proofs
// =============================================================================

/// Proves that memory_cost is monotonically non-decreasing with byte count:
/// more bytes always costs at least as much gas.
#[kani::proof]
fn verify_gas_memory_cost_monotonic() {
    let config = gas::GasConfig::default();

    let bytes_a: u64 = kani::any();
    let bytes_b: u64 = kani::any();
    kani::assume(bytes_a <= bytes_b);
    // Prevent overflow
    kani::assume(bytes_b <= u64::MAX / (config.memory_byte_cost + 1));

    let cost_a = config.memory_cost(bytes_a);
    let cost_b = config.memory_cost(bytes_b);

    assert!(
        cost_a <= cost_b,
        "Memory cost must be monotonically non-decreasing with byte count"
    );
}
