//! # Project Falcon-Lion: Error Types
//!
//! Comprehensive error handling for cross-border trade finance operations.

use thiserror::Error;

/// Falcon-Lion error types
#[derive(Error, Debug)]
pub enum FalconLionError {
    // =========================================================================
    // JURISDICTION ERRORS
    // =========================================================================

    /// Unsupported jurisdiction
    #[error("Unsupported jurisdiction: {0}")]
    UnsupportedJurisdiction(String),

    /// Cross-border data transfer not allowed
    #[error("Cross-border data transfer not allowed from {from} to {to}")]
    CrossBorderNotAllowed { from: String, to: String },

    // =========================================================================
    // COMPLIANCE ERRORS
    // =========================================================================

    /// Session not found
    #[error("Verification session not found: {0}")]
    SessionNotFound(String),

    /// Consent not given
    #[error("Data processing consent not given")]
    ConsentNotGiven,

    /// No checks performed
    #[error("No compliance checks performed in session")]
    NoChecksPerformed,

    /// Compliance check failed
    #[error("Compliance check failed: {0}")]
    ComplianceCheckFailed(String),

    /// Sanctions match found
    #[error("Sanctions match found for entity")]
    SanctionsMatch,

    /// KYC verification failed
    #[error("KYC verification failed: {0}")]
    KycFailed(String),

    /// Credit score below threshold
    #[error("Credit score {score} below minimum threshold {threshold}")]
    CreditScoreBelowThreshold { score: u8, threshold: u8 },

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
    #[error("Proof has expired")]
    ProofExpired,

    /// Invalid proof
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    // =========================================================================
    // TRADE DEAL ERRORS
    // =========================================================================

    /// Trade deal not found
    #[error("Trade deal not found: {0}")]
    TradeDealNotFound(String),

    /// Invalid trade deal state
    #[error("Invalid trade deal state: expected {expected}, got {actual}")]
    InvalidDealState { expected: String, actual: String },

    /// Participant not found
    #[error("Trade participant not found: {0}")]
    ParticipantNotFound(String),

    /// Bank not found
    #[error("Bank not found: {0}")]
    BankNotFound(String),

    // =========================================================================
    // LETTER OF CREDIT ERRORS
    // =========================================================================

    /// LC not found
    #[error("Letter of Credit not found: {0}")]
    LcNotFound(String),

    /// LC already exists
    #[error("Letter of Credit already exists: {0}")]
    LcAlreadyExists(String),

    /// LC amount mismatch
    #[error("LC amount mismatch: expected {expected}, got {actual}")]
    LcAmountMismatch { expected: String, actual: String },

    /// LC expired
    #[error("Letter of Credit has expired")]
    LcExpired,

    /// Invalid LC state
    #[error("Invalid LC state for operation: {0}")]
    InvalidLcState(String),

    // =========================================================================
    // SETTLEMENT ERRORS
    // =========================================================================

    /// Settlement failed
    #[error("Settlement failed: {0}")]
    SettlementFailed(String),

    /// Insufficient funds
    #[error("Insufficient funds for settlement")]
    InsufficientFunds,

    /// Settlement already completed
    #[error("Settlement already completed for deal: {0}")]
    SettlementAlreadyCompleted(String),

    /// Contract deployment failed
    #[error("Smart contract deployment failed: {0}")]
    ContractDeploymentFailed(String),

    /// Transaction failed
    #[error("Blockchain transaction failed: {0}")]
    TransactionFailed(String),

    // =========================================================================
    // VALIDATION ERRORS
    // =========================================================================

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Invalid currency
    #[error("Invalid currency: {0}")]
    InvalidCurrency(String),

    /// Invalid date
    #[error("Invalid date: {0}")]
    InvalidDate(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingRequiredField(String),

    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),

    // =========================================================================
    // SYSTEM ERRORS
    // =========================================================================

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Timeout
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for Falcon-Lion operations
pub type FalconLionResult<T> = Result<T, FalconLionError>;

impl FalconLionError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            FalconLionError::Timeout(_) |
            FalconLionError::SessionNotFound(_) |
            FalconLionError::CreditScoreBelowThreshold { .. }
        )
    }

    /// Check if error should block the transaction
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            FalconLionError::SanctionsMatch |
            FalconLionError::ComplianceCheckFailed(_) |
            FalconLionError::CrossBorderNotAllowed { .. }
        )
    }

    /// Get error code for logging
    pub fn error_code(&self) -> u32 {
        match self {
            FalconLionError::UnsupportedJurisdiction(_) => 1001,
            FalconLionError::CrossBorderNotAllowed { .. } => 1002,

            FalconLionError::SessionNotFound(_) => 2001,
            FalconLionError::ConsentNotGiven => 2002,
            FalconLionError::NoChecksPerformed => 2003,
            FalconLionError::ComplianceCheckFailed(_) => 2004,
            FalconLionError::SanctionsMatch => 2005,
            FalconLionError::KycFailed(_) => 2006,
            FalconLionError::CreditScoreBelowThreshold { .. } => 2007,

            FalconLionError::ProofGenerationFailed(_) => 3001,
            FalconLionError::ProofVerificationFailed(_) => 3002,
            FalconLionError::ProofExpired => 3003,
            FalconLionError::InvalidProof(_) => 3004,

            FalconLionError::TradeDealNotFound(_) => 4001,
            FalconLionError::InvalidDealState { .. } => 4002,
            FalconLionError::ParticipantNotFound(_) => 4003,
            FalconLionError::BankNotFound(_) => 4004,

            FalconLionError::LcNotFound(_) => 5001,
            FalconLionError::LcAlreadyExists(_) => 5002,
            FalconLionError::LcAmountMismatch { .. } => 5003,
            FalconLionError::LcExpired => 5004,
            FalconLionError::InvalidLcState(_) => 5005,

            FalconLionError::SettlementFailed(_) => 6001,
            FalconLionError::InsufficientFunds => 6002,
            FalconLionError::SettlementAlreadyCompleted(_) => 6003,
            FalconLionError::ContractDeploymentFailed(_) => 6004,
            FalconLionError::TransactionFailed(_) => 6005,

            FalconLionError::InvalidAmount(_) => 7001,
            FalconLionError::InvalidCurrency(_) => 7002,
            FalconLionError::InvalidDate(_) => 7003,
            FalconLionError::MissingRequiredField(_) => 7004,
            FalconLionError::ValidationError(_) => 7005,

            FalconLionError::Internal(_) => 9001,
            FalconLionError::Timeout(_) => 9002,
            FalconLionError::SerializationError(_) => 9003,
            FalconLionError::IoError(_) => 9004,
            FalconLionError::ConfigError(_) => 9005,
        }
    }
}

// Implement From for common error types
impl From<serde_json::Error> for FalconLionError {
    fn from(err: serde_json::Error) -> Self {
        FalconLionError::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for FalconLionError {
    fn from(err: std::io::Error) -> Self {
        FalconLionError::IoError(err.to_string())
    }
}
