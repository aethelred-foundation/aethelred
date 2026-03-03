//! Gas Metering
//!
//! Enterprise-grade gas metering for WASM execution with configurable costs.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Gas meter for tracking and limiting execution costs
#[derive(Debug)]
pub struct GasMeter {
    /// Gas used so far
    used: AtomicU64,
    /// Gas limit
    limit: u64,
    /// Configuration
    config: GasConfig,
}

impl GasMeter {
    /// Create new gas meter
    pub fn new(limit: u64, config: GasConfig) -> Self {
        Self {
            used: AtomicU64::new(0),
            limit,
            config,
        }
    }

    /// Create with default configuration
    pub fn with_limit(limit: u64) -> Self {
        Self::new(limit, GasConfig::default())
    }

    /// Create unlimited meter (for testing)
    pub fn unlimited() -> Self {
        Self::new(u64::MAX, GasConfig::default())
    }

    /// Consume gas
    pub fn consume(&self, amount: u64) -> Result<(), GasExhausted> {
        let current = self.used.fetch_add(amount, Ordering::SeqCst);
        let new_total = current + amount;

        if new_total > self.limit {
            // Rollback
            self.used.fetch_sub(amount, Ordering::SeqCst);
            return Err(GasExhausted {
                used: current,
                limit: self.limit,
                attempted: amount,
            });
        }

        Ok(())
    }

    /// Consume gas for WASM operation
    pub fn consume_wasm_op(&self, op: WasmOp) -> Result<(), GasExhausted> {
        let cost = self.config.wasm_cost(op);
        self.consume(cost)
    }

    /// Consume gas for memory operation
    pub fn consume_memory(&self, bytes: u64) -> Result<(), GasExhausted> {
        let cost = self.config.memory_cost(bytes);
        self.consume(cost)
    }

    /// Consume gas for host function call
    pub fn consume_host_call(&self, call: HostCall) -> Result<(), GasExhausted> {
        let cost = self.config.host_cost(call);
        self.consume(cost)
    }

    /// Get gas used
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::SeqCst)
    }

    /// Get gas remaining
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used())
    }

    /// Get gas limit
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Check if gas is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.used() >= self.limit
    }

    /// Reset meter
    pub fn reset(&self) {
        self.used.store(0, Ordering::SeqCst);
    }

    /// Get configuration
    pub fn config(&self) -> &GasConfig {
        &self.config
    }
}

impl Clone for GasMeter {
    fn clone(&self) -> Self {
        Self {
            used: AtomicU64::new(self.used.load(Ordering::SeqCst)),
            limit: self.limit,
            config: self.config.clone(),
        }
    }
}

/// Gas exhausted error
#[derive(Debug, Clone)]
pub struct GasExhausted {
    /// Gas already used
    pub used: u64,
    /// Gas limit
    pub limit: u64,
    /// Amount attempted to consume
    pub attempted: u64,
}

impl std::fmt::Display for GasExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gas exhausted: used {}, limit {}, attempted {}",
            self.used, self.limit, self.attempted
        )
    }
}

impl std::error::Error for GasExhausted {}

/// Gas configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Base cost for WASM operations
    pub wasm_base_cost: u64,

    /// Cost per WASM instruction
    pub wasm_instruction_cost: u64,

    /// Cost per byte of memory allocation
    pub memory_byte_cost: u64,

    /// Cost per memory page (64KB)
    pub memory_page_cost: u64,

    /// Cost for memory grow operation
    pub memory_grow_cost: u64,

    /// Cost multiplier for expensive operations
    pub expensive_op_multiplier: u64,

    /// Host function call base cost
    pub host_call_base: u64,

    /// Storage read cost per byte
    pub storage_read_cost: u64,

    /// Storage write cost per byte
    pub storage_write_cost: u64,

    /// Precompile call base cost
    pub precompile_call_base: u64,

    /// Network operation cost
    pub network_cost: u64,

    /// Cryptographic operation cost multiplier
    pub crypto_multiplier: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            wasm_base_cost: 1,
            wasm_instruction_cost: 1,
            memory_byte_cost: 1,
            memory_page_cost: 65536, // 64KB
            memory_grow_cost: 1000,
            expensive_op_multiplier: 10,
            host_call_base: 100,
            storage_read_cost: 200,
            storage_write_cost: 5000,
            precompile_call_base: 50,
            network_cost: 10000,
            crypto_multiplier: 100,
        }
    }
}

impl GasConfig {
    /// Production configuration (higher costs)
    pub fn production() -> Self {
        Self {
            wasm_base_cost: 10,
            wasm_instruction_cost: 1,
            memory_byte_cost: 3,
            memory_page_cost: 200_000,
            memory_grow_cost: 10_000,
            expensive_op_multiplier: 100,
            host_call_base: 1000,
            storage_read_cost: 2100,    // EIP-2929
            storage_write_cost: 20_000, // EIP-2929
            precompile_call_base: 700,
            network_cost: 100_000,
            crypto_multiplier: 1000,
        }
    }

    /// Testing configuration (lower costs)
    pub fn testing() -> Self {
        Self {
            wasm_base_cost: 0,
            wasm_instruction_cost: 0,
            memory_byte_cost: 0,
            memory_page_cost: 0,
            memory_grow_cost: 0,
            expensive_op_multiplier: 1,
            host_call_base: 0,
            storage_read_cost: 0,
            storage_write_cost: 0,
            precompile_call_base: 0,
            network_cost: 0,
            crypto_multiplier: 1,
        }
    }

    /// Calculate cost for WASM operation
    pub fn wasm_cost(&self, op: WasmOp) -> u64 {
        let base = self.wasm_instruction_cost;

        match op {
            // Control flow
            WasmOp::Unreachable | WasmOp::Nop => base,
            WasmOp::Block | WasmOp::Loop | WasmOp::If | WasmOp::Else | WasmOp::End => base,
            WasmOp::Br | WasmOp::BrIf => base * 2,
            WasmOp::BrTable => base * 3,
            WasmOp::Return | WasmOp::Call | WasmOp::CallIndirect => base * 5,

            // Constants
            WasmOp::I32Const | WasmOp::I64Const | WasmOp::F32Const | WasmOp::F64Const => base,

            // Locals
            WasmOp::LocalGet | WasmOp::LocalSet | WasmOp::LocalTee => base,
            WasmOp::GlobalGet | WasmOp::GlobalSet => base * 2,

            // Memory
            WasmOp::I32Load | WasmOp::I64Load | WasmOp::F32Load | WasmOp::F64Load => base * 3,
            WasmOp::I32Store | WasmOp::I64Store | WasmOp::F32Store | WasmOp::F64Store => base * 3,
            WasmOp::MemorySize | WasmOp::MemoryGrow => self.memory_grow_cost,

            // Integer arithmetic (cheap)
            WasmOp::I32Add
            | WasmOp::I32Sub
            | WasmOp::I32Mul
            | WasmOp::I64Add
            | WasmOp::I64Sub
            | WasmOp::I64Mul => base,

            // Integer division (expensive)
            WasmOp::I32DivS
            | WasmOp::I32DivU
            | WasmOp::I32RemS
            | WasmOp::I32RemU
            | WasmOp::I64DivS
            | WasmOp::I64DivU
            | WasmOp::I64RemS
            | WasmOp::I64RemU => base * self.expensive_op_multiplier,

            // Bitwise (cheap)
            WasmOp::I32And
            | WasmOp::I32Or
            | WasmOp::I32Xor
            | WasmOp::I64And
            | WasmOp::I64Or
            | WasmOp::I64Xor => base,

            // Shifts (cheap)
            WasmOp::I32Shl
            | WasmOp::I32ShrS
            | WasmOp::I32ShrU
            | WasmOp::I64Shl
            | WasmOp::I64ShrS
            | WasmOp::I64ShrU => base,

            // Floating point (moderate)
            WasmOp::F32Add
            | WasmOp::F32Sub
            | WasmOp::F32Mul
            | WasmOp::F32Div
            | WasmOp::F64Add
            | WasmOp::F64Sub
            | WasmOp::F64Mul
            | WasmOp::F64Div => base * 3,

            // Floating point expensive
            WasmOp::F32Sqrt | WasmOp::F64Sqrt => base * 5,

            // Comparisons (cheap)
            WasmOp::I32Eqz
            | WasmOp::I32Eq
            | WasmOp::I32Ne
            | WasmOp::I32LtS
            | WasmOp::I32LtU
            | WasmOp::I32GtS
            | WasmOp::I32GtU
            | WasmOp::I64Eqz
            | WasmOp::I64Eq
            | WasmOp::I64Ne => base,

            // Conversions (moderate)
            WasmOp::I32WrapI64 | WasmOp::I64ExtendI32S | WasmOp::I64ExtendI32U => base * 2,
            WasmOp::F32ConvertI32S
            | WasmOp::F32ConvertI64S
            | WasmOp::F64ConvertI32S
            | WasmOp::F64ConvertI64S => base * 3,

            // Generic/other
            WasmOp::Other => base * 2,
        }
    }

    /// Calculate cost for memory operation
    pub fn memory_cost(&self, bytes: u64) -> u64 {
        self.memory_byte_cost * bytes
    }

    /// Calculate cost for host function call
    pub fn host_cost(&self, call: HostCall) -> u64 {
        match call {
            HostCall::Log => self.host_call_base,
            HostCall::GetTime => self.host_call_base,
            HostCall::Random => self.host_call_base * 2,
            HostCall::StorageRead => self.storage_read_cost,
            HostCall::StorageWrite => self.storage_write_cost,
            HostCall::PrecompileCall => self.precompile_call_base,
            HostCall::CryptoOp => self.host_call_base * self.crypto_multiplier,
            HostCall::NetworkOp => self.network_cost,
            HostCall::Other => self.host_call_base,
        }
    }
}

/// WASM operation categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmOp {
    // Control flow
    Unreachable,
    Nop,
    Block,
    Loop,
    If,
    Else,
    End,
    Br,
    BrIf,
    BrTable,
    Return,
    Call,
    CallIndirect,

    // Constants
    I32Const,
    I64Const,
    F32Const,
    F64Const,

    // Variables
    LocalGet,
    LocalSet,
    LocalTee,
    GlobalGet,
    GlobalSet,

    // Memory
    I32Load,
    I64Load,
    F32Load,
    F64Load,
    I32Store,
    I64Store,
    F32Store,
    F64Store,
    MemorySize,
    MemoryGrow,

    // Integer arithmetic
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,

    // Bitwise
    I32And,
    I32Or,
    I32Xor,
    I64And,
    I64Or,
    I64Xor,

    // Shifts
    I32Shl,
    I32ShrS,
    I32ShrU,
    I64Shl,
    I64ShrS,
    I64ShrU,

    // Floating point
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Sqrt,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Sqrt,

    // Comparisons
    I32Eqz,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I64Eqz,
    I64Eq,
    I64Ne,

    // Conversions
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    F32ConvertI32S,
    F32ConvertI64S,
    F64ConvertI32S,
    F64ConvertI64S,

    // Other
    Other,
}

/// Host function call categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCall {
    /// Logging
    Log,
    /// Get current time
    GetTime,
    /// Random number generation
    Random,
    /// Storage read
    StorageRead,
    /// Storage write
    StorageWrite,
    /// Precompile call
    PrecompileCall,
    /// Cryptographic operation
    CryptoOp,
    /// Network operation
    NetworkOp,
    /// Other
    Other,
}

/// Thread-safe gas meter wrapper
pub type SharedGasMeter = Arc<GasMeter>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_meter_basic() {
        let meter = GasMeter::with_limit(1000);

        assert!(meter.consume(100).is_ok());
        assert_eq!(meter.used(), 100);
        assert_eq!(meter.remaining(), 900);

        assert!(meter.consume(500).is_ok());
        assert_eq!(meter.used(), 600);

        assert!(meter.consume(500).is_err()); // Would exceed
        assert_eq!(meter.used(), 600); // Unchanged
    }

    #[test]
    fn test_gas_meter_exhausted() {
        let meter = GasMeter::with_limit(100);

        assert!(meter.consume(100).is_ok());
        assert!(meter.is_exhausted());

        let err = meter.consume(1).unwrap_err();
        assert_eq!(err.used, 100);
        assert_eq!(err.limit, 100);
        assert_eq!(err.attempted, 1);
    }

    #[test]
    fn test_gas_config_presets() {
        let default = GasConfig::default();
        let production = GasConfig::production();
        let testing = GasConfig::testing();

        // Production should have higher costs
        assert!(production.storage_write_cost > default.storage_write_cost);

        // Testing should have zero costs
        assert_eq!(testing.wasm_instruction_cost, 0);
    }

    #[test]
    fn test_wasm_op_costs() {
        let config = GasConfig::default();

        // Division should be more expensive than addition
        let add_cost = config.wasm_cost(WasmOp::I32Add);
        let div_cost = config.wasm_cost(WasmOp::I32DivS);
        assert!(div_cost > add_cost);

        // Memory grow should be expensive
        let grow_cost = config.wasm_cost(WasmOp::MemoryGrow);
        assert!(grow_cost > config.wasm_instruction_cost * 100);
    }

    #[test]
    fn test_gas_meter_reset() {
        let meter = GasMeter::with_limit(1000);

        meter.consume(500).unwrap();
        assert_eq!(meter.used(), 500);

        meter.reset();
        assert_eq!(meter.used(), 0);
        assert_eq!(meter.remaining(), 1000);
    }

    #[test]
    fn test_gas_meter_clone() {
        let meter = GasMeter::with_limit(1000);
        meter.consume(300).unwrap();

        let cloned = meter.clone();
        assert_eq!(cloned.used(), 300);
        assert_eq!(cloned.limit(), 1000);

        // Changes to clone don't affect original
        cloned.consume(200).unwrap();
        assert_eq!(meter.used(), 300);
        assert_eq!(cloned.used(), 500);
    }
}
