//! # Project Helix-Guard: Error Types
//!
//! Comprehensive error handling for sovereign genomics collaboration operations.

use thiserror::Error;

/// Helix-Guard error types
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum HelixGuardError {
    // =========================================================================
    // SOVEREIGNTY ERRORS
    // =========================================================================
    /// Data sovereignty violation
    #[error("Data sovereignty violation: {0}")]
    SovereigntyViolation(String),

    /// Cross-border transfer not allowed
    #[error("Cross-border data transfer not allowed from {from} to {to}")]
    CrossBorderNotAllowed { from: String, to: String },

    /// Data residency requirement violated
    #[error("Data residency requirement violated: data must remain in {required_jurisdiction}")]
    DataResidencyViolation { required_jurisdiction: String },

    /// Processing region not allowed
    #[error("Processing region {region} not allowed for this data")]
    ProcessingRegionNotAllowed { region: String },

    // =========================================================================
    // COMPLIANCE ERRORS
    // =========================================================================
    /// Ethics approval required
    #[error("Ethics approval required before accessing this data")]
    EthicsApprovalRequired,

    /// DoH approval required
    #[error("Department of Health approval required")]
    DohApprovalRequired,

    /// Data agreement missing
    #[error("Data sharing agreement not in place")]
    DataAgreementMissing,

    /// Use case not allowed
    #[error("Use case '{use_case}' is prohibited for this data")]
    UseCaseProhibited { use_case: String },

    /// Minimum aggregation size not met
    #[error("Minimum aggregation size of {required} not met (got {actual})")]
    MinimumAggregationNotMet { required: u32, actual: u32 },

    /// Compliance check failed
    #[error("Compliance check failed: {0}")]
    ComplianceCheckFailed(String),

    // =========================================================================
    // TEE ERRORS
    // =========================================================================
    /// TEE initialization failed
    #[error("TEE enclave initialization failed: {reason}")]
    TeeInitializationFailed { reason: String },

    /// TEE attestation failed
    #[error("TEE attestation verification failed: {reason}")]
    TeeAttestationFailed { reason: String },

    /// TEE not available
    #[error("Required TEE type {tee_type} not available")]
    TeeNotAvailable { tee_type: String },

    /// Enclave memory insufficient
    #[error("Enclave memory insufficient: required {required_gb}GB, available {available_gb}GB")]
    EnclaveMemoryInsufficient { required_gb: u32, available_gb: u32 },

    /// Memory encryption required but not enabled
    #[error("Memory encryption required but not enabled")]
    MemoryEncryptionRequired,

    /// RAM-only processing required
    #[error("RAM-only processing required but disk access detected")]
    RamOnlyViolation,

    /// Enclave measurement mismatch
    #[error("Enclave measurement mismatch: expected {expected}, got {actual}")]
    EnclaveMeasurementMismatch { expected: String, actual: String },

    // =========================================================================
    // DATA ERRORS
    // =========================================================================
    /// Genome cohort not found
    #[error("Genome cohort not found: {0}")]
    CohortNotFound(String),

    /// Drug candidate not found
    #[error("Drug candidate not found: {0}")]
    DrugCandidateNotFound(String),

    /// Data reference expired
    #[error("Data reference has expired")]
    DataReferenceExpired,

    /// Data reference invalid
    #[error("Data reference invalid: {0}")]
    DataReferenceInvalid(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Data integrity check failed
    #[error("Data integrity check failed: hash mismatch")]
    DataIntegrityFailed,

    /// Marker type not available
    #[error("Genetic marker type {marker_type} not available in this cohort")]
    MarkerTypeNotAvailable { marker_type: String },

    // =========================================================================
    // MODEL ERRORS
    // =========================================================================
    /// Model not found
    #[error("AI model not found: {0}")]
    ModelNotFound(String),

    /// Model version mismatch
    #[error("Model version mismatch: expected {expected}, got {actual}")]
    ModelVersionMismatch { expected: String, actual: String },

    /// Model hash mismatch
    #[error("Model integrity check failed: hash mismatch")]
    ModelHashMismatch,

    /// Model inference failed
    #[error("Model inference failed: {0}")]
    InferenceFailed(String),

    /// GPU not available
    #[error("Required GPU {gpu_type} not available")]
    GpuNotAvailable { gpu_type: String },

    // =========================================================================
    // COMPUTATION ERRORS
    // =========================================================================
    /// Job not found
    #[error("Compute job not found: {0}")]
    JobNotFound(String),

    /// Job already exists
    #[error("Compute job already exists: {0}")]
    JobAlreadyExists(String),

    /// Job timeout
    #[error("Compute job timed out after {timeout_secs} seconds")]
    JobTimeout { timeout_secs: u64 },

    /// Job cancelled
    #[error("Compute job was cancelled")]
    JobCancelled,

    /// Insufficient confidence
    #[error("Result confidence {actual}% below minimum threshold {required}%")]
    InsufficientConfidence { required: u8, actual: u8 },

    /// SLA violation
    #[error("SLA violation: {0}")]
    SlaViolation(String),

    // =========================================================================
    // PROOF ERRORS
    // =========================================================================
    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Proof verification failed
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// Proof expired
    #[error("Cryptographic proof has expired")]
    ProofExpired,

    /// Invalid proof
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    // =========================================================================
    // PAYMENT ERRORS
    // =========================================================================
    /// Payment failed
    #[error("Royalty payment failed: {0}")]
    PaymentFailed(String),

    /// Insufficient funds
    #[error("Insufficient funds for royalty payment")]
    InsufficientFunds,

    /// Payment already processed
    #[error("Payment already processed: {0}")]
    PaymentAlreadyProcessed(String),

    /// Invalid payment amount
    #[error("Invalid payment amount: {0}")]
    InvalidPaymentAmount(String),

    // =========================================================================
    // PARTNER ERRORS
    // =========================================================================
    /// Partner not found
    #[error("Partner not found: {0}")]
    PartnerNotFound(String),

    /// Partner not authorized
    #[error("Partner not authorized for this operation")]
    PartnerNotAuthorized,

    /// Partner tier insufficient
    #[error("Partner tier insufficient for this data access")]
    PartnerTierInsufficient,

    /// Partner agreement expired
    #[error("Partner agreement has expired")]
    PartnerAgreementExpired,

    // =========================================================================
    // SYSTEM ERRORS
    // =========================================================================
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Timeout
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
}

/// Result type for Helix-Guard operations
pub type HelixGuardResult<T> = Result<T, HelixGuardError>;

impl HelixGuardError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            HelixGuardError::Timeout(_)
                | HelixGuardError::NetworkError(_)
                | HelixGuardError::JobTimeout { .. }
                | HelixGuardError::InsufficientConfidence { .. }
        )
    }

    /// Check if error should block the operation permanently
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            HelixGuardError::SovereigntyViolation(_)
                | HelixGuardError::CrossBorderNotAllowed { .. }
                | HelixGuardError::DataResidencyViolation { .. }
                | HelixGuardError::UseCaseProhibited { .. }
                | HelixGuardError::ComplianceCheckFailed(_)
        )
    }

    /// Check if error requires regulatory notification
    pub fn requires_notification(&self) -> bool {
        matches!(
            self,
            HelixGuardError::SovereigntyViolation(_)
                | HelixGuardError::DataResidencyViolation { .. }
                | HelixGuardError::TeeAttestationFailed { .. }
                | HelixGuardError::DataIntegrityFailed
        )
    }

    /// Get error code for logging
    pub fn error_code(&self) -> u32 {
        match self {
            // Sovereignty errors (1xxx)
            HelixGuardError::SovereigntyViolation(_) => 1001,
            HelixGuardError::CrossBorderNotAllowed { .. } => 1002,
            HelixGuardError::DataResidencyViolation { .. } => 1003,
            HelixGuardError::ProcessingRegionNotAllowed { .. } => 1004,

            // Compliance errors (2xxx)
            HelixGuardError::EthicsApprovalRequired => 2001,
            HelixGuardError::DohApprovalRequired => 2002,
            HelixGuardError::DataAgreementMissing => 2003,
            HelixGuardError::UseCaseProhibited { .. } => 2004,
            HelixGuardError::MinimumAggregationNotMet { .. } => 2005,
            HelixGuardError::ComplianceCheckFailed(_) => 2006,

            // TEE errors (3xxx)
            HelixGuardError::TeeInitializationFailed { .. } => 3001,
            HelixGuardError::TeeAttestationFailed { .. } => 3002,
            HelixGuardError::TeeNotAvailable { .. } => 3003,
            HelixGuardError::EnclaveMemoryInsufficient { .. } => 3004,
            HelixGuardError::MemoryEncryptionRequired => 3005,
            HelixGuardError::RamOnlyViolation => 3006,
            HelixGuardError::EnclaveMeasurementMismatch { .. } => 3007,

            // Data errors (4xxx)
            HelixGuardError::CohortNotFound(_) => 4001,
            HelixGuardError::DrugCandidateNotFound(_) => 4002,
            HelixGuardError::DataReferenceExpired => 4003,
            HelixGuardError::DataReferenceInvalid(_) => 4004,
            HelixGuardError::DecryptionFailed(_) => 4005,
            HelixGuardError::DataIntegrityFailed => 4006,
            HelixGuardError::MarkerTypeNotAvailable { .. } => 4007,

            // Model errors (5xxx)
            HelixGuardError::ModelNotFound(_) => 5001,
            HelixGuardError::ModelVersionMismatch { .. } => 5002,
            HelixGuardError::ModelHashMismatch => 5003,
            HelixGuardError::InferenceFailed(_) => 5004,
            HelixGuardError::GpuNotAvailable { .. } => 5005,

            // Computation errors (6xxx)
            HelixGuardError::JobNotFound(_) => 6001,
            HelixGuardError::JobAlreadyExists(_) => 6002,
            HelixGuardError::JobTimeout { .. } => 6003,
            HelixGuardError::JobCancelled => 6004,
            HelixGuardError::InsufficientConfidence { .. } => 6005,
            HelixGuardError::SlaViolation(_) => 6006,

            // Proof errors (7xxx)
            HelixGuardError::ProofGenerationFailed(_) => 7001,
            HelixGuardError::ProofVerificationFailed(_) => 7002,
            HelixGuardError::ProofExpired => 7003,
            HelixGuardError::InvalidProof(_) => 7004,

            // Payment errors (8xxx)
            HelixGuardError::PaymentFailed(_) => 8001,
            HelixGuardError::InsufficientFunds => 8002,
            HelixGuardError::PaymentAlreadyProcessed(_) => 8003,
            HelixGuardError::InvalidPaymentAmount(_) => 8004,

            // Partner errors (8xxx continued)
            HelixGuardError::PartnerNotFound(_) => 8101,
            HelixGuardError::PartnerNotAuthorized => 8102,
            HelixGuardError::PartnerTierInsufficient => 8103,
            HelixGuardError::PartnerAgreementExpired => 8104,

            // System errors (9xxx)
            HelixGuardError::Internal(_) => 9001,
            HelixGuardError::ConfigError(_) => 9002,
            HelixGuardError::NetworkError(_) => 9003,
            HelixGuardError::Timeout(_) => 9004,
            HelixGuardError::SerializationError(_) => 9005,
            HelixGuardError::IoError(_) => 9006,
        }
    }
}

// Implement From for common error types
impl From<serde_json::Error> for HelixGuardError {
    fn from(err: serde_json::Error) -> Self {
        HelixGuardError::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for HelixGuardError {
    fn from(err: std::io::Error) -> Self {
        HelixGuardError::IoError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recoverable() {
        assert!(HelixGuardError::Timeout(1000).is_recoverable());
        assert!(HelixGuardError::NetworkError("connection refused".into()).is_recoverable());
        assert!(!HelixGuardError::SovereigntyViolation("test".into()).is_recoverable());
    }

    #[test]
    fn test_error_blocking() {
        assert!(HelixGuardError::SovereigntyViolation("test".into()).is_blocking());
        assert!(HelixGuardError::CrossBorderNotAllowed {
            from: "UAE".into(),
            to: "UK".into()
        }
        .is_blocking());
        assert!(!HelixGuardError::Timeout(1000).is_blocking());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            HelixGuardError::SovereigntyViolation("".into()).error_code(),
            1001
        );
        assert_eq!(
            HelixGuardError::TeeInitializationFailed { reason: "".into() }.error_code(),
            3001
        );
        assert_eq!(HelixGuardError::Internal("".into()).error_code(), 9001);
    }
}
