//! VM Error Types
//!
//! Comprehensive error handling for the Aethelred VM.

use thiserror::Error;

/// VM errors
#[derive(Error, Debug)]
pub enum VmError {
    /// WASM compilation error
    #[error("Compilation error: {0}")]
    Compilation(String),

    /// WASM instantiation error
    #[error("Instantiation error: {0}")]
    Instantiation(String),

    /// WASM execution error
    #[error("Execution error: {0}")]
    Execution(String),

    /// Out of gas
    #[error("Out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    /// Memory access violation
    #[error("Memory access violation: address {address}, size {size}")]
    MemoryViolation { address: u64, size: u64 },

    /// Stack overflow
    #[error("Stack overflow")]
    StackOverflow,

    /// Invalid function signature
    #[error("Invalid function signature: {0}")]
    InvalidSignature(String),

    /// Function not found
    #[error("Function not found: {0}")]
    FunctionNotFound(String),

    /// Module not found
    #[error("Module not found: {0}")]
    ModuleNotFound(String),

    /// Invalid WASM binary
    #[error("Invalid WASM binary: {0}")]
    InvalidBinary(String),

    /// Memory limit exceeded
    #[error("Memory limit exceeded: requested {requested} pages, max {max}")]
    MemoryLimitExceeded { requested: u32, max: u32 },

    /// Execution timeout
    #[error("Execution timeout after {0}ms")]
    Timeout(u64),

    /// Precompile error
    #[error("Precompile error: {0}")]
    Precompile(#[from] crate::precompiles::PrecompileError),

    /// Host function error
    #[error("Host function error: {0}")]
    HostFunction(String),

    /// Import error
    #[error("Import error: {0}")]
    Import(String),

    /// Export error
    #[error("Export error: {0}")]
    Export(String),

    /// Trap
    #[error("Trap: {0}")]
    Trap(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type for VM operations
pub type VmResult<T> = Result<T, VmError>;

impl VmError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VmError::OutOfGas { .. } | VmError::Timeout(_) | VmError::MemoryLimitExceeded { .. }
        )
    }

    /// Check if error is a trap
    pub fn is_trap(&self) -> bool {
        matches!(
            self,
            VmError::Trap(_) | VmError::StackOverflow | VmError::MemoryViolation { .. }
        )
    }

    /// Get error code for on-chain reporting
    pub fn error_code(&self) -> u32 {
        match self {
            VmError::Compilation(_) => 1,
            VmError::Instantiation(_) => 2,
            VmError::Execution(_) => 3,
            VmError::OutOfGas { .. } => 4,
            VmError::MemoryViolation { .. } => 5,
            VmError::StackOverflow => 6,
            VmError::InvalidSignature(_) => 7,
            VmError::FunctionNotFound(_) => 8,
            VmError::ModuleNotFound(_) => 9,
            VmError::InvalidBinary(_) => 10,
            VmError::MemoryLimitExceeded { .. } => 11,
            VmError::Timeout(_) => 12,
            VmError::Precompile(_) => 13,
            VmError::HostFunction(_) => 14,
            VmError::Import(_) => 15,
            VmError::Export(_) => 16,
            VmError::Trap(_) => 17,
            VmError::Internal(_) => 18,
            VmError::Config(_) => 19,
        }
    }
}
