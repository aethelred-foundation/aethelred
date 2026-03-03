//! Aethelred Virtual Machine
//!
//! Enterprise-grade WebAssembly virtual machine for executing verified AI computations.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │                         AETHELRED VM                                      │
//! ├──────────────────────────────────────────────────────────────────────────┤
//! │                                                                           │
//! │   ┌───────────────────────────────────────────────────────────────────┐  │
//! │   │                     WASM RUNTIME (wasmer)                          │  │
//! │   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐               │  │
//! │   │  │   Module    │  │  Instance   │  │   Memory    │               │  │
//! │   │  │   Store     │  │   Pool      │  │   Sandbox   │               │  │
//! │   │  └─────────────┘  └─────────────┘  └─────────────┘               │  │
//! │   └───────────────────────────────────────────────────────────────────┘  │
//! │                                    │                                      │
//! │   ┌───────────────────────────────────────────────────────────────────┐  │
//! │   │                     PRECOMPILES                                    │  │
//! │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │  │
//! │   │  │ Crypto  │ │   PQC   │ │   ZKP   │ │   TEE   │ │  Seal   │    │  │
//! │   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘    │  │
//! │   └───────────────────────────────────────────────────────────────────┘  │
//! │                                    │                                      │
//! │   ┌───────────────────────────────────────────────────────────────────┐  │
//! │   │                     HOST FUNCTIONS                                 │  │
//! │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │  │
//! │   │  │  Log    │ │  Time   │ │ Random  │ │ Storage │ │   Net   │    │  │
//! │   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘    │  │
//! │   └───────────────────────────────────────────────────────────────────┘  │
//! │                                                                           │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **wasmer-runtime**: Use Wasmer as the WASM runtime (default)
//! - **wasmtime-runtime**: Use Wasmtime as the WASM runtime (alternative)
//! - **mock-tee**: Mock TEE for development without real hardware
//! - **sgx**: Enable Intel SGX DCAP verification
//! - **zkp**: Enable ZK proof verification (arkworks)

pub mod error;
pub mod gas;
pub mod host;
pub mod memory;
pub mod precompiles;
pub mod runtime;
pub mod system_contracts;

pub use error::{VmError, VmResult};
pub use gas::{GasConfig, GasMeter};
pub use memory::{MemoryConfig, MemoryLimits};
pub use precompiles::{
    ExecutionResult, Precompile, PrecompileError, PrecompileRegistry, PrecompileResult,
};
pub use runtime::{WasmConfig, WasmInstance, WasmModule, WasmRuntime};

// Re-export system contracts
pub use system_contracts::{
    Bank, BankConfig, BlockContext, ComplianceConfig, ComplianceModule, ComplianceStandard,
    GenesisConfig, JobConfig, JobRegistry, StakingConfig, StakingManager, SystemKernel,
};

/// VM version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Create a new VM with default configuration
pub fn create_vm() -> VmResult<WasmRuntime> {
    WasmRuntime::new(WasmConfig::default())
}

/// Create a VM with custom configuration
pub fn create_vm_with_config(config: WasmConfig) -> VmResult<WasmRuntime> {
    WasmRuntime::new(config)
}
