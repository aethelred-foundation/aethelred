//! # Aethelred SDK - The Verifiable Compute Chain Toolkit
//!
//! **"The logic of PyTorch. The speed of Rust. The security of verifiable compute."**
//!
//! The Aethelred SDK is the world's first **Verifiable Compute Chain (VCC)** toolkit.
//! It combines high-performance compute workflows with the cryptographic certainty of
//! Zero-Knowledge (ZK) proofs and Trusted Execution Environments (TEE).
//!
//! ## Positioning
//!
//! The SDK does not claim native GPU dispatch by default.
//! Native GPU dispatch requires dedicated backend integration and explicit build/runtime configuration.
//! The default runtime prioritizes deterministic behavior and verifiability guarantees.
//!
//! ## Key Features
//!
//! ### 1. Sovereign Types
//! Data that enforces jurisdiction and hardware constraints at compile time.
//!
//! ```rust,ignore
//! use aethelred_sdk::sovereign::Sovereign;
//!
//! // This data can ONLY be accessed inside UAE on TEE hardware
//! let patient_dna: Sovereign<GenomicData> = Sovereign::new(data)
//!     .require_jurisdiction(Jurisdiction::UAE)
//!     .require_hardware(Hardware::IntelSGX)
//!     .build();
//! ```
//!
//! ### 2. zkTensors
//! Tensors that automatically generate ZK proofs of computation.
//!
//! ```rust,ignore
//! use aethelred_sdk::zktensor::ZkTensor;
//!
//! let a = ZkTensor::from_vec(vec![1.0, 2.0, 3.0]);
//! let b = ZkTensor::from_vec(vec![4.0, 5.0, 6.0]);
//! let c = a.matmul(&b); // Proof generated automatically!
//!
//! assert!(c.verify_proof().is_ok());
//! ```
//!
//! ### 3. The @sovereign Decorator (Python)
//!
//! ```python
//! from aethelred import sovereign, Hardware, Compliance
//!
//! @sovereign(
//!     hardware=Hardware.H100_TEE,
//!     compliance=Compliance.UAE_DATA_RESIDENCY
//! )
//! def run_cancer_screening(patient_scan):
//!     return model(patient_scan)
//! ```
//!
//! ### 4. Compliance Linting
//!
//! The SDK includes a "Legal Linter" that catches compliance violations at compile time:
//!
//! ```text
//! 🔴 CRITICAL: Data Exfiltration Risk
//!    This function sends Private<PatientID> to a Public endpoint.
//!    Violation: GDPR Article 44, UAE Data Law Article 7
//!    Suggestion: Use Aethelred.secure_fetch() instead.
//! ```
//!
//! ## Module Overview
//!
//! - [`sovereign`]: Compile-time jurisdiction and hardware enforcement
//! - [`attestation`]: TEE attestation (Intel SGX, AMD SEV, AWS Nitro)
//! - [`compliance`]: Regulatory engine with legal citations
//! - [`crypto`]: Hybrid post-quantum cryptography
//! - [`zktensor`]: Zero-knowledge tensor operations
//! - [`helix`]: The Helix DSL for verifiable AI
//! - [`registry`]: Model registry and licensing
//! - [`client`]: Network client for Aethelred nodes

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
#![deny(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

// ============================================================================
// Core Modules
// ============================================================================

/// Sovereign data types with compile-time jurisdiction enforcement
pub mod sovereign;

/// TEE attestation engine (Intel SGX, AMD SEV, AWS Nitro, ARM TrustZone)
pub mod attestation;

/// Regulatory compliance engine with legal citations
pub mod compliance;

/// Hybrid post-quantum cryptography (ECDSA + Dilithium3)
pub mod crypto;

/// Zero-knowledge tensor operations with automatic proof generation
pub mod zktensor;

/// The Helix DSL - Rust-based language for verifiable AI
pub mod helix;

/// Model registry, versioning, and licensing
pub mod registry;

/// Foreign Function Interface for Python/JS/Go
pub mod ffi;

// ============================================================================
// Client & Networking
// ============================================================================

/// Network client for Aethelred nodes
pub mod client;

/// Transaction building and signing
pub mod transaction;

/// Digital Seal creation and verification
pub mod seal;

// ============================================================================
// Re-exports for convenience
// ============================================================================

pub use sovereign::{Sovereign, SovereignBuilder, SovereignError};
pub use attestation::{
    AttestationEngine, EnclaveReport, HardwareType, AttestationError,
    AttestationConfig, TcbStatus, VerificationResult,
};
pub use compliance::{
    ComplianceEngine, Jurisdiction, Regulation, ComplianceViolation,
    ComplianceResult, DataOperation, DataClassification,
};
pub use crypto::{
    HybridKeypair, HybridSignature, HybridPublicKey,
    CryptoError, EncryptionAlgorithm, HashAlgorithm,
};
pub use zktensor::{ZkTensor, ZkProof, TensorOp, ProofVerifier};
pub use helix::{HelixCompiler, HelixProgram, HelixError};
pub use registry::{ModelRegistry, ModelLicense, ModelVersion};
pub use client::{AethelredClient, ClientConfig};
pub use seal::{DigitalSeal, SealBuilder, SealId};

// ============================================================================
// Version & Build Info
// ============================================================================

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK name
pub const NAME: &str = "Aethelred SDK";

/// Build timestamp
pub const BUILD_TIME: &str = env!("CARGO_PKG_VERSION");

/// Get SDK version information
pub fn version_info() -> VersionInfo {
    VersionInfo {
        name: NAME.to_string(),
        version: VERSION.to_string(),
        features: Features {
            python_bindings: cfg!(feature = "python"),
            wasm_bindings: cfg!(feature = "wasm"),
            intel_sgx: cfg!(feature = "intel_sgx"),
            amd_sev: cfg!(feature = "amd_sev"),
            grpc: cfg!(feature = "grpc"),
        },
    }
}

/// SDK version information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VersionInfo {
    /// SDK name
    pub name: String,
    /// SDK version
    pub version: String,
    /// Enabled features
    pub features: Features,
}

/// SDK feature flags
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Features {
    /// Python bindings enabled
    pub python_bindings: bool,
    /// WASM bindings enabled
    pub wasm_bindings: bool,
    /// Intel SGX support
    pub intel_sgx: bool,
    /// AMD SEV support
    pub amd_sev: bool,
    /// gRPC support
    pub grpc: bool,
}

// ============================================================================
// Prelude
// ============================================================================

/// Commonly used types and traits
pub mod prelude {
    pub use crate::sovereign::{Sovereign, SovereignBuilder};
    pub use crate::attestation::{AttestationEngine, HardwareType};
    pub use crate::compliance::{Jurisdiction, CompliancePolicy};
    pub use crate::crypto::{HybridKeypair, HybridSignature};
    pub use crate::zktensor::ZkTensor;
    pub use crate::client::AethelredClient;
}
