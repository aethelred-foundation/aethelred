//! # TEE Attestation Engine
//!
//! **"The Bridge Between Physical Hardware and Logical Trust"**
//!
//! This module provides unified attestation verification for multiple
//! Trusted Execution Environment (TEE) platforms:
//!
//! - **Intel SGX** (DCAP attestation)
//! - **AMD SEV-SNP** (AMD attestation)
//! - **AWS Nitro Enclaves** (COSE/CBOR attestation)
//! - **ARM TrustZone** (Realm attestation)
//!
//! ## Architecture
//!
//! ```text
//!                          ┌─────────────────────┐
//!                          │  AttestationEngine  │
//!                          └─────────┬───────────┘
//!                                    │
//!          ┌─────────────────────────┼─────────────────────────┐
//!          │                         │                         │
//!          ▼                         ▼                         ▼
//!   ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
//!   │  Intel SGX  │          │   AMD SEV   │          │  AWS Nitro  │
//!   │    DCAP     │          │    SNP      │          │   Enclave   │
//!   └─────────────┘          └─────────────┘          └─────────────┘
//!          │                         │                         │
//!          └─────────────────────────┼─────────────────────────┘
//!                                    │
//!                                    ▼
//!                          ┌─────────────────────┐
//!                          │   EnclaveReport     │
//!                          │   (Unified Output)  │
//!                          └─────────────────────┘
//! ```
//!
//! ## Security Model
//!
//! 1. **Quote Verification**: Cryptographic verification against Intel/AMD root of trust
//! 2. **TCB Validation**: Check for known vulnerabilities and security updates
//! 3. **Measurement Binding**: Verify code hash (MRENCLAVE/MRSIGNER)
//! 4. **Report Data Binding**: Bind attestation to specific session/data
//! 5. **Geo-Location Injection**: Add jurisdiction based on verified IP/geo-fencing

mod intel_sgx;
mod amd_sev;
mod aws_nitro;
mod arm_trustzone;
mod engine;
mod report;

pub use intel_sgx::*;
pub use amd_sev::*;
pub use aws_nitro::*;
pub use arm_trustzone::*;
pub use engine::*;
pub use report::*;

use crate::compliance::Jurisdiction;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Attestation errors
#[derive(Error, Debug, Clone)]
pub enum AttestationError {
    /// Invalid quote format
    #[error("Invalid quote format: {0}")]
    InvalidFormat(String),

    /// Signature verification failed
    #[error("Quote signature verification failed")]
    InvalidSignature,

    /// TCB is out of date
    #[error("TCB out of date: {description}. Required SVN: {required_svn}, Actual: {actual_svn}")]
    OutOfDateTcb {
        /// Description
        description: String,
        /// Required security version
        required_svn: u16,
        /// Actual security version
        actual_svn: u16,
    },

    /// TCB is revoked
    #[error("TCB has been revoked: {reason}")]
    RevokedTcb {
        /// Reason for revocation
        reason: String,
    },

    /// Enclave is in debug mode
    #[error("Enclave is in debug mode (not production-ready)")]
    DebugMode,

    /// Measurement mismatch
    #[error("Enclave measurement mismatch: expected {expected}, got {actual}")]
    MeasurementMismatch {
        /// Expected measurement
        expected: String,
        /// Actual measurement
        actual: String,
    },

    /// Intel DCAP error
    #[error("Intel DCAP error: {0}")]
    IntelDcap(String),

    /// AMD SEV error
    #[error("AMD SEV error: {0}")]
    AmdSev(String),

    /// AWS Nitro error
    #[error("AWS Nitro error: {0}")]
    AwsNitro(String),

    /// ARM TrustZone error
    #[error("ARM TrustZone error: {0}")]
    ArmTrustZone(String),

    /// Network error fetching collateral
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Certificate chain invalid
    #[error("Certificate chain validation failed: {0}")]
    CertificateError(String),

    /// Unsupported hardware
    #[error("Unsupported hardware type: {0:?}")]
    UnsupportedHardware(HardwareType),

    /// Collateral expired
    #[error("Attestation collateral expired")]
    CollateralExpired,

    /// Quote replay detected
    #[error("Quote replay detected (nonce mismatch)")]
    ReplayDetected,
}

// ============================================================================
// Hardware Types
// ============================================================================

/// Supported TEE hardware types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HardwareType {
    /// No specific hardware requirement
    Any = 0,

    /// Intel SGX (Software Guard Extensions)
    IntelSGX = 1,

    /// Intel SGX with DCAP attestation
    IntelSgxDcap = 2,

    /// Intel TDX (Trust Domain Extensions)
    IntelTdx = 3,

    /// AMD SEV (Secure Encrypted Virtualization)
    AmdSev = 4,

    /// AMD SEV-ES (Encrypted State)
    AmdSevEs = 5,

    /// AMD SEV-SNP (Secure Nested Paging)
    AmdSevSnp = 6,

    /// AWS Nitro Enclaves
    AwsNitro = 7,

    /// ARM TrustZone
    ArmTrustZone = 8,

    /// ARM CCA (Confidential Compute Architecture)
    ArmCca = 9,

    /// NVIDIA Confidential Computing
    NvidiaCC = 10,

    /// Mock/Simulation (for testing only)
    Mock = 255,
}

impl HardwareType {
    /// Check if this hardware type satisfies a requirement
    pub fn satisfies(&self, required: HardwareType) -> bool {
        match (self, required) {
            // Any hardware satisfies "Any" requirement
            (_, HardwareType::Any) => true,

            // Same hardware satisfies same requirement
            (a, b) if a == &b => true,

            // SGX DCAP satisfies plain SGX
            (HardwareType::IntelSgxDcap, HardwareType::IntelSGX) => true,

            // SEV-SNP satisfies lesser SEV variants
            (HardwareType::AmdSevSnp, HardwareType::AmdSevEs) => true,
            (HardwareType::AmdSevSnp, HardwareType::AmdSev) => true,
            (HardwareType::AmdSevEs, HardwareType::AmdSev) => true,

            // Real hardware satisfies mock (for backward compatibility)
            (_, HardwareType::Mock) if *self != HardwareType::Mock => true,

            // Mock NEVER satisfies real hardware
            (HardwareType::Mock, _) => false,

            // Default: no satisfaction
            _ => false,
        }
    }

    /// Get the security level (1-5)
    pub fn security_level(&self) -> u8 {
        match self {
            HardwareType::Any => 0,
            HardwareType::Mock => 0,
            HardwareType::ArmTrustZone => 2,
            HardwareType::AmdSev => 3,
            HardwareType::AmdSevEs => 3,
            HardwareType::IntelSGX => 4,
            HardwareType::IntelSgxDcap => 4,
            HardwareType::AwsNitro => 4,
            HardwareType::ArmCca => 4,
            HardwareType::AmdSevSnp => 5,
            HardwareType::IntelTdx => 5,
            HardwareType::NvidiaCC => 5,
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            HardwareType::Any => "Any Hardware",
            HardwareType::IntelSGX => "Intel SGX",
            HardwareType::IntelSgxDcap => "Intel SGX (DCAP)",
            HardwareType::IntelTdx => "Intel TDX",
            HardwareType::AmdSev => "AMD SEV",
            HardwareType::AmdSevEs => "AMD SEV-ES",
            HardwareType::AmdSevSnp => "AMD SEV-SNP",
            HardwareType::AwsNitro => "AWS Nitro Enclaves",
            HardwareType::ArmTrustZone => "ARM TrustZone",
            HardwareType::ArmCca => "ARM CCA",
            HardwareType::NvidiaCC => "NVIDIA Confidential Computing",
            HardwareType::Mock => "Mock (Testing Only)",
        }
    }

    /// Check if this is a production-ready TEE
    pub fn is_production_ready(&self) -> bool {
        !matches!(self, HardwareType::Any | HardwareType::Mock)
    }
}

impl Default for HardwareType {
    fn default() -> Self {
        HardwareType::Any
    }
}

// ============================================================================
// TCB Status
// ============================================================================

/// Trusted Computing Base status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcbStatus {
    /// TCB is up to date
    UpToDate,

    /// TCB needs configuration update (software-only fix)
    ConfigurationNeeded,

    /// TCB needs configuration and software update
    ConfigurationAndSwNeeded,

    /// TCB is out of date (needs full update)
    OutOfDate,

    /// TCB is revoked (security issue)
    Revoked,

    /// Unknown status
    Unknown,
}

impl TcbStatus {
    /// Check if this status is acceptable for production
    pub fn is_acceptable(&self) -> bool {
        matches!(
            self,
            TcbStatus::UpToDate | TcbStatus::ConfigurationNeeded
        )
    }

    /// Check if this status is a hard failure
    pub fn is_failure(&self) -> bool {
        matches!(self, TcbStatus::Revoked)
    }
}

// ============================================================================
// Verification Result
// ============================================================================

/// Result of attestation verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether verification passed
    pub verified: bool,

    /// The enclave report (if verification passed)
    pub report: Option<EnclaveReport>,

    /// TCB status
    pub tcb_status: TcbStatus,

    /// Warnings (non-fatal issues)
    pub warnings: Vec<VerificationWarning>,

    /// Verification timestamp
    pub verified_at: std::time::SystemTime,

    /// Collateral info
    pub collateral: CollateralInfo,
}

/// Non-fatal verification warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationWarning {
    /// Warning code
    pub code: String,
    /// Warning message
    pub message: String,
    /// Severity (1-5)
    pub severity: u8,
}

/// Information about attestation collateral
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralInfo {
    /// Collateral source
    pub source: CollateralSource,
    /// Collateral freshness
    pub fetched_at: std::time::SystemTime,
    /// Expiration time
    pub expires_at: std::time::SystemTime,
}

/// Source of attestation collateral
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollateralSource {
    /// Intel Provisioning Certification Caching Service
    IntelPccs { url: String },
    /// AMD Key Distribution Service
    AmdKds { url: String },
    /// AWS Nitro Certificate
    AwsCert,
    /// Local cache
    LocalCache,
    /// Aethelred network
    AethelredNetwork,
}

// ============================================================================
// Configuration
// ============================================================================

/// Attestation verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Allow out-of-date TCB (not recommended)
    pub allow_out_of_date_tcb: bool,

    /// Allow configuration-needed status
    pub allow_configuration_needed: bool,

    /// Allow debug mode (testing only!)
    pub allow_debug_mode: bool,

    /// Required minimum security version
    pub min_security_version: u16,

    /// Expected MRENCLAVE values (if set, must match one)
    pub expected_measurements: Vec<[u8; 32]>,

    /// Expected MRSIGNER values (if set, must match one)
    pub expected_signers: Vec<[u8; 32]>,

    /// Intel PCCS URL (for SGX DCAP)
    pub intel_pccs_url: Option<String>,

    /// AMD KDS URL (for SEV)
    pub amd_kds_url: Option<String>,

    /// Network timeout
    pub network_timeout: std::time::Duration,

    /// Enable collateral caching
    pub enable_caching: bool,

    /// Cache TTL
    pub cache_ttl: std::time::Duration,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        AttestationConfig {
            allow_out_of_date_tcb: false,
            allow_configuration_needed: true,
            allow_debug_mode: false,
            min_security_version: 0,
            expected_measurements: Vec::new(),
            expected_signers: Vec::new(),
            intel_pccs_url: Some("https://pccs.aethelred.network".to_string()),
            amd_kds_url: Some("https://kdsintf.amd.com".to_string()),
            network_timeout: std::time::Duration::from_secs(10),
            enable_caching: true,
            cache_ttl: std::time::Duration::from_secs(3600),
        }
    }
}

impl AttestationConfig {
    /// Production configuration (strict)
    pub fn production() -> Self {
        AttestationConfig {
            allow_out_of_date_tcb: false,
            allow_configuration_needed: false,
            allow_debug_mode: false,
            min_security_version: 10, // Require recent microcode
            ..Default::default()
        }
    }

    /// Development configuration (permissive)
    pub fn development() -> Self {
        AttestationConfig {
            allow_out_of_date_tcb: true,
            allow_configuration_needed: true,
            allow_debug_mode: true,
            min_security_version: 0,
            ..Default::default()
        }
    }

    /// Testnet configuration
    pub fn testnet() -> Self {
        AttestationConfig {
            allow_out_of_date_tcb: true,
            allow_configuration_needed: true,
            allow_debug_mode: false,
            min_security_version: 5,
            ..Default::default()
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_satisfies() {
        assert!(HardwareType::IntelSGX.satisfies(HardwareType::Any));
        assert!(HardwareType::IntelSGX.satisfies(HardwareType::IntelSGX));
        assert!(HardwareType::IntelSgxDcap.satisfies(HardwareType::IntelSGX));
        assert!(!HardwareType::IntelSGX.satisfies(HardwareType::AmdSev));
        assert!(!HardwareType::Mock.satisfies(HardwareType::IntelSGX));
    }

    #[test]
    fn test_security_level() {
        assert_eq!(HardwareType::Mock.security_level(), 0);
        assert_eq!(HardwareType::AmdSev.security_level(), 3);
        assert_eq!(HardwareType::IntelSGX.security_level(), 4);
        assert_eq!(HardwareType::AmdSevSnp.security_level(), 5);
    }

    #[test]
    fn test_tcb_status() {
        assert!(TcbStatus::UpToDate.is_acceptable());
        assert!(TcbStatus::ConfigurationNeeded.is_acceptable());
        assert!(!TcbStatus::OutOfDate.is_acceptable());
        assert!(TcbStatus::Revoked.is_failure());
    }
}
