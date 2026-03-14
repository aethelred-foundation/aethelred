//! # NoblePay TEE Compliance Engine
//!
//! Privacy-preserving compliance infrastructure for enterprise payment screening.
//! Runs inside AWS Nitro Enclaves to ensure that sensitive counterparty data never
//! leaves the trusted execution environment in plaintext.
//!
//! ## Architecture
//!
//! The engine is composed of four independent subsystems orchestrated by
//! [`engine::ComplianceEngine`]:
//!
//! 1. **Sanctions Screening** ([`sanctions`]) — multi-list fuzzy entity matching
//!    against OFAC, UAE Central Bank, UN, and EU consolidated lists.
//! 2. **AML Risk Scoring** ([`aml`]) — weighted composite scoring across velocity,
//!    geography, amount, counterparty, and pattern factors.
//! 3. **Travel Rule Verification** ([`travel_rule`]) — FATF / IVMS101 completeness
//!    checks with encrypted VASP-to-VASP data packaging.
//! 4. **TEE Attestation** ([`attestation`]) — cryptographic proof that the
//!    compliance computation ran inside a genuine enclave.
//!
//! ## Feature Flags
//!
//! | Flag       | Description                                      |
//! |------------|--------------------------------------------------|
//! | `mock-tee` | *(default)* Deterministic mock attestation        |
//! | `nitro`    | AWS Nitro Enclave attestation via NSM device      |
//! | `sgx`      | Intel SGX attestation (experimental)              |
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use noblepay_compliance::engine::ComplianceEngine;
//! use noblepay_compliance::types::Payment;
//!
//! #[tokio::main]
//! async fn main() {
//!     let engine = ComplianceEngine::new().await;
//!     // screen a payment ...
//! }
//! ```

pub mod aml;
pub mod attestation;
pub mod engine;
pub mod sanctions;
pub mod server;
pub mod travel_rule;
pub mod types;

// Re-export the most commonly used items at the crate root for ergonomic imports.
pub use engine::ComplianceEngine;
pub use types::{
    AMLRiskLevel, ComplianceResult, ComplianceStatus, Payment, RiskFactor, ScreeningRequest,
    ScreeningResponse,
};

/// Crate-level error type that unifies all subsystem errors.
#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    #[error("sanctions screening failed: {0}")]
    SanctionsError(String),

    #[error("AML risk scoring failed: {0}")]
    AmlError(String),

    #[error("travel rule verification failed: {0}")]
    TravelRuleError(String),

    #[error("attestation generation failed: {0}")]
    AttestationError(String),

    #[error("screening timed out after {0}ms")]
    Timeout(u64),

    #[error("sanctions list update failed for {list}: {reason}")]
    ListUpdateError { list: String, reason: String },

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, ComplianceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages_are_human_readable() {
        let err = ComplianceError::Timeout(5000);
        assert_eq!(err.to_string(), "screening timed out after 5000ms");

        let err = ComplianceError::SanctionsError("list unavailable".into());
        assert!(err.to_string().contains("sanctions screening failed"));
    }

    #[test]
    fn result_alias_works_with_question_mark() {
        fn inner() -> Result<u32> {
            Ok(42)
        }
        assert_eq!(inner().unwrap(), 42);
    }

    #[test]
    fn re_exports_are_accessible() {
        // Verify that key types are re-exported at the crate root.
        let _status = ComplianceStatus::Passed;
        let _level = AMLRiskLevel::Low;
    }
}
