//! Unified error type for every sector sandbox.
//!
//! By convention, sector-specific failures (e.g., "DICOM modality not in
//! approved list") are wrapped under [`SandboxError::PolicyDenied`] with a
//! descriptive `policy_gate` and `reason`. Cryptographic failures bubble up
//! as [`SandboxError::Crypto`].

use thiserror::Error;

/// Result type used across every sandbox crate.
pub type SandboxResult<T> = Result<T, SandboxError>;

/// Unified sandbox error.
///
/// Every public API in `aethelred-sandbox-core` and the seven sector crates
/// returns `Result<_, SandboxError>` so that downstream clients can `?` across
/// them without conversion code.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// A policy gate denied the workflow. This is the primary "fail-closed"
    /// path — every adversarial test in every sector exits through here.
    #[error("policy gate `{policy_gate}` denied: {reason}")]
    PolicyDenied {
        /// The policy gate id (e.g., `"finance.human_authority"`).
        policy_gate: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The customer supplied input that the sector workflow rejected as
    /// malformed (e.g., missing required field, schema mismatch).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The sandbox detected an unsafe data class (e.g., production PHI in a
    /// healthcare sandbox configured for synthetic-only).
    #[error("data boundary violation: {0}")]
    DataBoundary(String),

    /// Evidence-log integrity failure (Merkle proof, anchoring, or replay).
    #[error("evidence integrity failure: {0}")]
    Evidence(String),

    /// Cryptographic operation failed (sign / verify / hash).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The connector / source-of-record adapter rejected the operation.
    #[error("connector `{connector}` failed: {reason}")]
    Connector {
        /// Connector identifier.
        connector: String,
        /// Failure reason.
        reason: String,
    },

    /// TEE attestation verification failed.
    #[error("TEE attestation failed ({platform}): {reason}")]
    Attestation {
        /// Platform name (e.g., "intel_tdx").
        platform: String,
        /// Failure reason.
        reason: String,
    },

    /// zkML proof generation or verification failed.
    #[error("zkML `{system}` failure: {reason}")]
    Zkml {
        /// Proof system (e.g., "ezkl").
        system: String,
        /// Failure reason.
        reason: String,
    },

    /// Configuration is incomplete or inconsistent.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Any other failure that does not fit a structured variant.
    #[error("sandbox failure: {0}")]
    Other(String),
}

impl SandboxError {
    /// Helper: construct a `PolicyDenied` from any displayable reason.
    pub fn policy(gate: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::PolicyDenied {
            policy_gate: gate.into(),
            reason: reason.into(),
        }
    }

    /// Helper: construct an `InvalidInput` from any displayable message.
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Helper: construct a `Configuration` error.
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// `true` if this error came from a fail-closed policy gate.
    pub fn is_policy_denial(&self) -> bool {
        matches!(self, Self::PolicyDenied { .. })
    }
}
