//! Integration tests for the aethelred-vm crate.
//!
//! Tests cover VM creation, gas metering, memory configuration, precompile
//! registry, and system contract wiring.

use aethelred_vm::{
    create_vm, create_vm_with_config,
    GasConfig, GasMeter, MemoryConfig, MemoryLimits,
    PrecompileRegistry, WasmConfig,
    VERSION,
};

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

#[test]
fn test_vm_version_populated() {
    assert!(!VERSION.is_empty());
}

// ---------------------------------------------------------------------------
// VM Creation
// ---------------------------------------------------------------------------

#[test]
fn test_create_vm_default() {
    let vm = create_vm();
    assert!(vm.is_ok(), "default VM creation should succeed: {:?}", vm.err());
}

#[test]
fn test_create_vm_with_custom_config() {
    let config = WasmConfig {
        max_memory_pages: 256,
        max_stack_size: 1024 * 1024,
        ..WasmConfig::default()
    };
    let vm = create_vm_with_config(config);
    assert!(vm.is_ok(), "custom VM creation should succeed: {:?}", vm.err());
}

// ---------------------------------------------------------------------------
// Gas Metering
// ---------------------------------------------------------------------------

#[test]
fn test_gas_meter_creation() {
    let config = GasConfig::default();
    let meter = GasMeter::new(1_000_000, config);
    assert_eq!(meter.remaining(), 1_000_000);
}

#[test]
fn test_gas_meter_consume_reduces_remaining() {
    let meter = GasMeter::new(100, GasConfig::default());
    assert!(meter.consume(30).is_ok());
    assert_eq!(meter.remaining(), 70);
}

#[test]
fn test_gas_meter_out_of_gas() {
    let meter = GasMeter::new(10, GasConfig::default());
    let result = meter.consume(20);
    assert!(result.is_err(), "consuming more gas than available should fail");
}

// ---------------------------------------------------------------------------
// Memory Configuration
// ---------------------------------------------------------------------------

#[test]
fn test_memory_config_default() {
    let config = MemoryConfig::default();
    assert!(config.initial_pages > 0);
    assert!(config.max_pages >= config.initial_pages);
}

#[test]
fn test_memory_limits_default() {
    let limits = MemoryLimits::default();
    assert!(limits.max_instance_memory > 0);
    assert!(limits.max_total_memory > 0);
    assert!(limits.max_stack_depth > 0);
}

// ---------------------------------------------------------------------------
// Precompile Registry
// ---------------------------------------------------------------------------

#[test]
fn test_precompile_registry_creation() {
    let registry = PrecompileRegistry::new();
    // A fresh registry should have some built-in precompiles.
    // We cannot call .len() directly, so test via .get() for a known
    // non-existent address.
    let result = registry.get(0xFFFF_FFFF);
    assert!(result.is_none(), "unknown address should return None");
}

#[test]
fn test_precompile_registry_lookup_zero() {
    let registry = PrecompileRegistry::new();
    // Address 0 may or may not be registered; just verify no panic.
    let _ = registry.get(0);
}

// ---------------------------------------------------------------------------
// WasmConfig Defaults
// ---------------------------------------------------------------------------

#[test]
fn test_wasm_config_default() {
    let config = WasmConfig::default();
    assert!(config.max_memory_pages > 0);
    assert!(config.max_stack_size > 0);
}

// ---------------------------------------------------------------------------
// System Contract Module Wiring
// ---------------------------------------------------------------------------

#[test]
fn test_system_contracts_accessible() {
    // Verify system contract types are exported from the crate root.
    let _ = std::any::type_name::<aethelred_vm::BankConfig>();
    let _ = std::any::type_name::<aethelred_vm::StakingConfig>();
    let _ = std::any::type_name::<aethelred_vm::JobConfig>();
    let _ = std::any::type_name::<aethelred_vm::ComplianceConfig>();
}
