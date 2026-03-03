//! # Aethelred SDK
//!
//! High-performance AI blockchain SDK with optional accelerator backends.
//!
//! Official Rust SDK for the Aethelred AI Blockchain with zero-cost abstractions.
//!
//! ## Features
//!
//! ### Core Runtime
//! - Hardware Abstraction Layer (HAL) for CPUs, GPUs, TEEs
//! - Lock-free memory pool with NUMA awareness
//! - Async execution streams with dependency graphs
//! - JIT compilation with LLVM backend
//! - Comprehensive profiling with Chrome Trace export
//!
//! ### Tensor Operations
//! - Lazy evaluation with operation fusion
//! - SIMD-accelerated operations
//! - Memory-efficient views and broadcasting
//! - Automatic differentiation support
//!
//! ### Neural Network
//! - PyTorch-compatible nn::Module trait
//! - Transformer and attention layers
//! - Modern activations (GELU, SiLU, RMSNorm)
//! - Loss functions and optimizers
//!
//! ### Distributed Computing
//! - Data parallelism with MPI backend
//! - Model parallelism (tensor, pipeline)
//! - ZeRO optimizer (stages 1-3)
//! - Gradient compression
//!
//! ### Quantization
//! - Post-training quantization (PTQ)
//! - Quantization-aware training (QAT)
//! - INT8, INT4, FP16, BF16, FP8 support
//!
//! ### Blockchain Integration
//! - AI compute job submission and tracking
//! - Digital seal creation and verification
//! - TEE attestation (Intel SGX, AMD SEV, AWS Nitro)
//! - zkML proof verification
//! - Post-quantum cryptography (Dilithium, Kyber)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use aethelred_sdk::{
//!     AethelredClient, Network, Runtime, Device, Tensor,
//!     nn::{Module, Linear, Sequential},
//!     optim::Adam,
//! };
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Initialize runtime
//!     let runtime = Runtime::instance();
//!     runtime.initialize()?;
//!     runtime.enable_profiling();
//!
//!     // Create tensors
//!     let device = Device::cpu();
//!     let x = Tensor::randn(vec![32, 784], device.clone())?;
//!
//!     // Build model
//!     let model = Sequential::new(vec![
//!         Box::new(Linear::new(784, 256)),
//!         Box::new(nn::ReLU),
//!         Box::new(Linear::new(256, 10)),
//!     ]);
//!
//!     // Forward pass
//!     let output = model.forward(&x)?;
//!
//!     // Submit to blockchain
//!     let client = AethelredClient::new(Network::Testnet).await?;
//!     let seal = client.seals().create(&output).await?;
//!     println!("Seal ID: {}", seal.id);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `gpu` - Enable GPU accelerator support
//! - `rocm` - Enable AMD ROCm support
//! - `metal` - Enable Apple Metal support
//! - `vulkan` - Enable Vulkan compute support
//! - `sgx` - Enable Intel SGX TEE support
//! - `sev` - Enable AMD SEV TEE support
//! - `nitro` - Enable AWS Nitro Enclave support
//! - `distributed` - Enable distributed training
//! - `quantize` - Enable quantization support

#![allow(missing_docs)]
#![allow(rustdoc::missing_doc_code_examples)]
#![allow(dead_code)]

// ============ Core Modules ============

/// Core client and configuration
pub mod core;

/// High-performance runtime engine
pub mod runtime;

/// Tensor operations with lazy evaluation
pub mod tensor;

/// Neural network layers and modules
pub mod nn;

/// Optimizers and learning rate schedulers
pub mod optim;

/// Distributed training support
#[cfg(feature = "distributed")]
pub mod distributed;

/// Quantization and model optimization
#[cfg(feature = "quantize")]
pub mod quantize;

/// Extended compatibility exports for full SDK builds.
#[cfg(feature = "full-sdk")]
pub mod lib_full;

// ============ Blockchain Modules ============

/// Job submission and tracking
pub mod jobs;

/// Digital seal management
pub mod seals;

/// Model registry
pub mod models;

/// Validator operations
pub mod validators;

/// Verification and attestation
pub mod verification;

/// Cryptographic primitives
pub mod crypto;

// ============ Re-exports ============

// Core client
pub use crate::core::client::AethelredClient;
pub use crate::core::config::{Config, Network};
pub use crate::core::error::{AethelredError, Result};
pub use crate::core::types::*;

// Runtime
pub use crate::runtime::{
    CompileError, CompiledKernel, Device, DeviceCapabilities, DeviceError, DeviceType, Event,
    JITCompiler, JITOptions, MemoryBlock, MemoryError, MemoryPool, PoolStats, ProfileEvent,
    ProfileEventType, ProfileSummary, Profiler, Runtime, Stream, StreamState,
};

// Tensor
pub use crate::tensor::{
    BinaryOp, DType, LazyOp, ReduceOp, Tensor, TensorError, TensorId, TensorStorage, UnaryOp,
};

// Modules
pub use crate::jobs::JobsModule;
pub use crate::models::ModelsModule;
pub use crate::seals::{
    parse_borrowed_seal_json, BorrowedDigitalSeal, BorrowedSealEnvelope, BorrowedTEEAttestation,
    BorrowedValidatorAttestation, SealsModule,
};
pub use crate::validators::ValidatorsModule;
pub use crate::verification::VerificationModule;

// ============ SDK Information ============

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK author
pub const AUTHOR: &str = "Aethelred Team";

/// SDK license
pub const LICENSE: &str = "Apache-2.0";

/// Get comprehensive SDK information
pub fn get_sdk_info() -> SdkInfo {
    SdkInfo {
        name: "aethelred-sdk".to_string(),
        version: VERSION.to_string(),
        author: AUTHOR.to_string(),
        license: LICENSE.to_string(),
        description: "High-performance AI blockchain SDK with optional accelerator backends."
            .to_string(),
        features: SdkFeatures {
            core: vec![
                "Hardware Abstraction Layer (CPU, GPU, TEE)".to_string(),
                "Lock-free memory pool with NUMA awareness".to_string(),
                "Async execution streams with dependency graphs".to_string(),
                "JIT compilation with LLVM backend".to_string(),
                "Comprehensive profiling (Chrome Trace export)".to_string(),
            ],
            tensor: vec![
                "Lazy evaluation with operation fusion".to_string(),
                "SIMD-accelerated operations".to_string(),
                "Memory-efficient views and broadcasting".to_string(),
                "Automatic differentiation support".to_string(),
            ],
            neural_network: vec![
                "PyTorch-compatible nn::Module trait".to_string(),
                "Transformer and attention layers".to_string(),
                "Modern activations (GELU, SiLU, RMSNorm)".to_string(),
                "Loss functions and optimizers".to_string(),
            ],
            distributed: vec![
                "Data parallelism (MPI backend)".to_string(),
                "Model parallelism (Tensor, Pipeline)".to_string(),
                "ZeRO optimizer (Stages 1-3)".to_string(),
                "Gradient compression".to_string(),
            ],
            quantization: vec![
                "Post-training quantization (PTQ)".to_string(),
                "Quantization-aware training (QAT)".to_string(),
                "INT8, INT4, FP16, BF16, FP8 precision".to_string(),
                "Per-tensor, per-channel granularity".to_string(),
            ],
            blockchain: vec![
                "AI compute job submission and tracking".to_string(),
                "Digital seal creation and verification".to_string(),
                "TEE attestation (Intel SGX, AMD SEV, AWS Nitro)".to_string(),
                "zkML proof verification (Groth16, PLONK, STARK)".to_string(),
                "Post-quantum cryptography (Dilithium, Kyber)".to_string(),
            ],
        },
        supported_devices: vec![
            "CPU (x86, ARM)".to_string(),
            "GPU Accelerator".to_string(),
            "AMD GPU (ROCm)".to_string(),
            "Apple GPU (Metal)".to_string(),
            "Intel SGX Enclave".to_string(),
            "AMD SEV Enclave".to_string(),
            "AWS Nitro Enclave".to_string(),
        ],
    }
}

/// SDK information
#[derive(Debug, Clone)]
pub struct SdkInfo {
    /// SDK name
    pub name: String,
    /// SDK version
    pub version: String,
    /// SDK author
    pub author: String,
    /// SDK license
    pub license: String,
    /// SDK description
    pub description: String,
    /// Feature list
    pub features: SdkFeatures,
    /// Supported devices
    pub supported_devices: Vec<String>,
}

/// SDK feature categories
#[derive(Debug, Clone)]
pub struct SdkFeatures {
    /// Core runtime features
    pub core: Vec<String>,
    /// Tensor operation features
    pub tensor: Vec<String>,
    /// Neural network features
    pub neural_network: Vec<String>,
    /// Distributed computing features
    pub distributed: Vec<String>,
    /// Quantization features
    pub quantization: Vec<String>,
    /// Blockchain integration features
    pub blockchain: Vec<String>,
}

// ============ Prelude ============

/// Commonly used types and traits
pub mod prelude {
    pub use crate::{
        nn::{Module, Parameter},
        optim::Optimizer,
        AethelredClient, Config, DType, Device, DeviceType, Network, Runtime, Tensor,
    };
}

// ============ Tests ============

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_sdk_info() {
        let info = get_sdk_info();
        assert_eq!(info.name, "aethelred-sdk");
        assert!(!info.features.core.is_empty());
    }
}
