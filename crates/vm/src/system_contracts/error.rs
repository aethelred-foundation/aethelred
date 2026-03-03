//! System Contract Error Types
//!
//! Comprehensive error handling for all system contract operations.

use super::types::{JobStatus, TokenAmount};
use thiserror::Error;

/// Result type for system contract operations
pub type SystemContractResult<T> = std::result::Result<T, SystemContractError>;
/// Backward-compatible short alias used by module internals.
pub type Result<T> = SystemContractResult<T>;

/// System contract error
#[derive(Debug, Error)]
pub enum SystemContractError {
    // =========================================================================
    // JOB REGISTRY ERRORS
    // =========================================================================
    /// Job not found
    #[error("Job not found: {job_id}")]
    JobNotFound { job_id: String },

    /// Invalid job status transition
    #[error("Invalid job status: expected {expected}, got {actual}")]
    InvalidJobStatus { expected: String, actual: String },

    /// Unauthorized prover
    #[error("Unauthorized prover: job was assigned to {assigned}, not {attempted}")]
    UnauthorizedProver { assigned: String, attempted: String },

    /// SLA violation (timeout)
    #[error("SLA violation: job {job_id} deadline was {deadline}, current time is {current}")]
    SlaViolation {
        job_id: String,
        deadline: u64,
        current: u64,
    },

    /// Insufficient bid amount
    #[error("Insufficient bid: minimum is {minimum}, got {actual}")]
    InsufficientBid {
        minimum: TokenAmount,
        actual: TokenAmount,
    },

    /// Job already assigned
    #[error("Job {job_id} already assigned to prover {prover}")]
    JobAlreadyAssigned { job_id: String, prover: String },

    /// Job cannot be cancelled in current state
    #[error("Job {job_id} cannot be cancelled in status {status}")]
    CannotCancelJob { job_id: String, status: JobStatus },

    /// Only requester can cancel
    #[error("Only job requester can cancel: requester is {requester}, caller is {caller}")]
    OnlyRequesterCanCancel { requester: String, caller: String },

    // =========================================================================
    // STAKING ERRORS
    // =========================================================================
    /// Insufficient stake
    #[error("Insufficient stake: required {required}, actual {actual}")]
    InsufficientStake {
        required: TokenAmount,
        actual: TokenAmount,
    },

    /// Staker not found
    #[error("Staker not found: {address}")]
    StakerNotFound { address: String },

    /// Cannot unstake (not enough unlocked)
    #[error("Cannot unstake {requested}: only {available} available")]
    CannotUnstake {
        requested: TokenAmount,
        available: TokenAmount,
    },

    /// Unstake in progress
    #[error("Unstake already in progress, unlocks at {unlock_time}")]
    UnstakeInProgress { unlock_time: u64 },

    /// Nothing to withdraw
    #[error("No unlocked stake to withdraw")]
    NothingToWithdraw,

    /// Slashing in progress
    #[error("Cannot unstake during slashing period")]
    SlashingInProgress,

    /// Invalid stake role
    #[error("Invalid stake role for operation")]
    InvalidStakeRole,

    // =========================================================================
    // COMPLIANCE ERRORS
    // =========================================================================
    /// Sanctioned entity
    #[error("Compliance block: {entity_type} {address} is on sanctions list")]
    SanctionedEntity {
        entity_type: String,
        address: String,
    },

    /// Missing certification
    #[error("Compliance block: {entity} missing {certification} certification")]
    MissingCertification {
        entity: String,
        certification: String,
    },

    /// Data type requires certification
    #[error("Transaction tagged as {tag} requires both parties to have {certification}")]
    CertificationRequired { tag: String, certification: String },

    /// Jurisdiction blocked
    #[error("Transaction blocked: {reason}")]
    JurisdictionBlocked { reason: String },

    /// Compliance module disabled
    #[error("Compliance module {module} is not active")]
    ComplianceModuleInactive { module: String },

    /// Invalid certification
    #[error("Invalid certification: {reason}")]
    InvalidCertification { reason: String },

    /// Expired certification
    #[error("Certification for {entity} expired at {expired_at}")]
    ExpiredCertification { entity: String, expired_at: u64 },

    // =========================================================================
    // BANK / TOKEN ERRORS
    // =========================================================================
    /// Insufficient balance
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance {
        required: TokenAmount,
        available: TokenAmount,
    },

    /// Transfer failed
    #[error("Transfer failed: {reason}")]
    TransferFailed { reason: String },

    /// Invalid amount
    #[error("Invalid amount: {reason}")]
    InvalidAmount { reason: String },

    /// Account locked
    #[error("Account {address} is locked until {unlock_time}")]
    AccountLocked { address: String, unlock_time: u64 },

    /// Escrow not found
    #[error("Escrow {escrow_id} not found")]
    EscrowNotFound { escrow_id: String },

    // =========================================================================
    // PROOF VERIFICATION ERRORS
    // =========================================================================
    /// Invalid proof
    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    /// TEE verification failed
    #[error("TEE attestation verification failed: {reason}")]
    TeeVerificationFailed { reason: String },

    /// ZK verification failed
    #[error("ZK proof verification failed: {reason}")]
    ZkVerificationFailed { reason: String },

    /// Measurement mismatch
    #[error("TEE measurement mismatch: expected {expected}, got {actual}")]
    MeasurementMismatch { expected: String, actual: String },

    /// Proof method mismatch
    #[error("Proof method mismatch: required {required:?}, got {actual:?}")]
    ProofMethodMismatch {
        required: super::types::VerificationMethod,
        actual: super::types::VerificationMethod,
    },

    // =========================================================================
    // CONFIGURATION ERRORS
    // =========================================================================
    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Genesis error
    #[error("Genesis initialization failed: {0}")]
    GenesisError(String),

    /// State corruption
    #[error("State corruption detected: {0}")]
    StateCorruption(String),

    // =========================================================================
    // AUTHORIZATION ERRORS
    // =========================================================================
    /// Unauthorized caller
    #[error("Unauthorized: caller {caller} is not authorized for this operation")]
    Unauthorized { caller: String },

    /// Governance required
    #[error("This operation requires governance approval")]
    GovernanceRequired,

    /// Invalid signature
    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    // =========================================================================
    // POUW ENGINE ERRORS
    // =========================================================================
    /// Insufficient compliance bond
    #[error("Insufficient compliance bond: required {required}, provided {provided}")]
    InsufficientBond {
        required: TokenAmount,
        provided: TokenAmount,
    },

    /// Node in cooldown (after attestation failure)
    #[error("Node is in cooldown until {until}")]
    NodeInCooldown { until: u64 },

    /// No bond found for node
    #[error("No compliance bond found for this node")]
    NoBondFound,

    /// Bond expired
    #[error("Compliance bond has expired")]
    BondExpired,

    /// Tokenomics error
    #[error("Tokenomics error: {0}")]
    Tokenomics(String),

    /// Generic compliance error
    #[error("Compliance error: {0}")]
    Compliance(String),

    /// Generic slashing subsystem error
    #[error("Slashing error: {0}")]
    Slashing(String),

    // =========================================================================
    // INTERNAL ERRORS
    // =========================================================================
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Overflow
    #[error("Arithmetic overflow: {0}")]
    Overflow(String),
}

impl SystemContractError {
    // =========================================================================
    // HELPER CONSTRUCTORS
    // =========================================================================

    pub fn job_not_found(job_id: &[u8; 32]) -> Self {
        SystemContractError::JobNotFound {
            job_id: hex::encode(job_id),
        }
    }

    pub fn unauthorized_prover(assigned: &[u8; 32], attempted: &[u8; 32]) -> Self {
        SystemContractError::UnauthorizedProver {
            assigned: hex::encode(assigned),
            attempted: hex::encode(attempted),
        }
    }

    pub fn sla_violation(job_id: &[u8; 32], deadline: u64, current: u64) -> Self {
        SystemContractError::SlaViolation {
            job_id: hex::encode(job_id),
            deadline,
            current,
        }
    }

    pub fn staker_not_found(address: &[u8; 32]) -> Self {
        SystemContractError::StakerNotFound {
            address: hex::encode(address),
        }
    }

    pub fn sanctioned_sender(address: &[u8; 32]) -> Self {
        SystemContractError::SanctionedEntity {
            entity_type: "Sender".into(),
            address: hex::encode(address),
        }
    }

    pub fn sanctioned_receiver(address: &[u8; 32]) -> Self {
        SystemContractError::SanctionedEntity {
            entity_type: "Receiver".into(),
            address: hex::encode(address),
        }
    }

    pub fn missing_hipaa(entity: &str) -> Self {
        SystemContractError::MissingCertification {
            entity: entity.into(),
            certification: "HIPAA".into(),
        }
    }

    pub fn missing_gdpr(entity: &str) -> Self {
        SystemContractError::MissingCertification {
            entity: entity.into(),
            certification: "GDPR".into(),
        }
    }

    // =========================================================================
    // ERROR CODE
    // =========================================================================

    /// Get numeric error code for RPC responses
    pub fn error_code(&self) -> u32 {
        match self {
            // Job errors: 1000-1099
            SystemContractError::JobNotFound { .. } => 1000,
            SystemContractError::InvalidJobStatus { .. } => 1001,
            SystemContractError::UnauthorizedProver { .. } => 1002,
            SystemContractError::SlaViolation { .. } => 1003,
            SystemContractError::InsufficientBid { .. } => 1004,
            SystemContractError::JobAlreadyAssigned { .. } => 1005,
            SystemContractError::CannotCancelJob { .. } => 1006,
            SystemContractError::OnlyRequesterCanCancel { .. } => 1007,

            // Staking errors: 1100-1199
            SystemContractError::InsufficientStake { .. } => 1100,
            SystemContractError::StakerNotFound { .. } => 1101,
            SystemContractError::CannotUnstake { .. } => 1102,
            SystemContractError::UnstakeInProgress { .. } => 1103,
            SystemContractError::NothingToWithdraw => 1104,
            SystemContractError::SlashingInProgress => 1105,
            SystemContractError::InvalidStakeRole => 1106,

            // Compliance errors: 1200-1299
            SystemContractError::SanctionedEntity { .. } => 1200,
            SystemContractError::MissingCertification { .. } => 1201,
            SystemContractError::CertificationRequired { .. } => 1202,
            SystemContractError::JurisdictionBlocked { .. } => 1203,
            SystemContractError::ComplianceModuleInactive { .. } => 1204,
            SystemContractError::InvalidCertification { .. } => 1205,
            SystemContractError::ExpiredCertification { .. } => 1206,

            // Bank errors: 1300-1399
            SystemContractError::InsufficientBalance { .. } => 1300,
            SystemContractError::TransferFailed { .. } => 1301,
            SystemContractError::InvalidAmount { .. } => 1302,
            SystemContractError::AccountLocked { .. } => 1303,
            SystemContractError::EscrowNotFound { .. } => 1304,

            // Proof errors: 1400-1499
            SystemContractError::InvalidProof { .. } => 1400,
            SystemContractError::TeeVerificationFailed { .. } => 1401,
            SystemContractError::ZkVerificationFailed { .. } => 1402,
            SystemContractError::MeasurementMismatch { .. } => 1403,
            SystemContractError::ProofMethodMismatch { .. } => 1404,

            // Config errors: 1500-1599
            SystemContractError::InvalidConfig(_) => 1500,
            SystemContractError::GenesisError(_) => 1501,
            SystemContractError::StateCorruption(_) => 1502,

            // Auth errors: 1600-1699
            SystemContractError::Unauthorized { .. } => 1600,
            SystemContractError::GovernanceRequired => 1601,
            SystemContractError::InvalidSignature { .. } => 1602,

            // PoUW errors: 1700-1799
            SystemContractError::InsufficientBond { .. } => 1700,
            SystemContractError::NodeInCooldown { .. } => 1701,
            SystemContractError::NoBondFound => 1702,
            SystemContractError::BondExpired => 1703,
            SystemContractError::Tokenomics(_) => 1704,
            SystemContractError::Compliance(_) => 1705,
            SystemContractError::Slashing(_) => 1706,

            // Internal errors: 1900-1999
            SystemContractError::Internal(_) => 1900,
            SystemContractError::Serialization(_) => 1901,
            SystemContractError::Overflow(_) => 1902,
        }
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            SystemContractError::StateCorruption(_) => false,
            SystemContractError::Internal(_) => false,
            SystemContractError::GenesisError(_) => false,
            _ => true,
        }
    }

    /// Check if error should trigger slashing
    pub fn should_slash(&self) -> bool {
        matches!(
            self,
            SystemContractError::SlaViolation { .. }
                | SystemContractError::InvalidProof { .. }
                | SystemContractError::MeasurementMismatch { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes_unique() {
        // Error codes should be in expected ranges
        let job_error = SystemContractError::job_not_found(&[0u8; 32]);
        assert!(job_error.error_code() >= 1000 && job_error.error_code() < 1100);

        let staking_error = SystemContractError::staker_not_found(&[0u8; 32]);
        assert!(staking_error.error_code() >= 1100 && staking_error.error_code() < 1200);

        let compliance_error = SystemContractError::sanctioned_sender(&[0u8; 32]);
        assert!(compliance_error.error_code() >= 1200 && compliance_error.error_code() < 1300);
    }

    #[test]
    fn test_recoverable_errors() {
        assert!(SystemContractError::JobNotFound {
            job_id: "test".into()
        }
        .is_recoverable());
        assert!(!SystemContractError::StateCorruption("test".into()).is_recoverable());
    }

    #[test]
    fn test_slashable_errors() {
        let sla = SystemContractError::sla_violation(&[0u8; 32], 100, 200);
        assert!(sla.should_slash());

        let not_found = SystemContractError::job_not_found(&[0u8; 32]);
        assert!(!not_found.should_slash());
    }
}
