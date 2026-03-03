//! Bridge Error Types

use thiserror::Error;

/// Bridge error type
#[derive(Error, Debug)]
pub enum BridgeError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Ethereum connection error
    #[error("Ethereum error: {0}")]
    Ethereum(String),

    /// Aethelred connection error
    #[error("Aethelred error: {0}")]
    Aethelred(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Consensus error
    #[error("Consensus error: {0}")]
    Consensus(String),

    /// Signing error
    #[error("Signing error: {0}")]
    Signing(String),

    /// Verification error
    #[error("Verification error: {0}")]
    Verification(String),

    /// Duplicate event
    #[error("Duplicate event: {0}")]
    Duplicate(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Timeout
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for bridge operations
pub type Result<T> = std::result::Result<T, BridgeError>;

impl From<std::io::Error> for BridgeError {
    fn from(e: std::io::Error) -> Self {
        BridgeError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for BridgeError {
    fn from(e: serde_json::Error) -> Self {
        BridgeError::Internal(e.to_string())
    }
}
