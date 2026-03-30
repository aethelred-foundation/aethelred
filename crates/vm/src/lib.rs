#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_doc_comments)]
#![allow(ambiguous_glob_reexports)]
#![allow(unexpected_cfgs)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::panicking_unwrap)]
#![allow(non_camel_case_types)]
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

#[cfg(kani)]
mod kani_proofs;

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
