//! Error types for Aethelred SDK.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, AethelredError>;

#[derive(Debug, Error)]
pub enum AethelredError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Rate limit exceeded, retry after {retry_after:?} seconds")]
    RateLimit { retry_after: Option<u64> },

    #[error("Request timeout after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Job error: {message} (job_id: {job_id:?})")]
    Job {
        message: String,
        job_id: Option<String>,
    },

    #[error("Seal error: {message} (seal_id: {seal_id:?})")]
    Seal {
        message: String,
        seal_id: Option<String>,
    },

    #[error("Model error: {message}")]
    Model { message: String },

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Validation error: {message} (field: {field:?})")]
    Validation {
        message: String,
        field: Option<String>,
    },

    #[error("Transaction error: {message} (tx_hash: {tx_hash:?})")]
    Transaction {
        message: String,
        tx_hash: Option<String>,
    },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("HTTP error: {status} - {message}")]
    Http { status: u16, message: String },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("Unknown error: {0}")]
    Unknown(String),
}
