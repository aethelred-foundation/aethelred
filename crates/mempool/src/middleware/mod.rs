//! Mempool Middleware
//!
//! Transaction validation and filtering middleware for the mempool.
//!
//! # Middleware Stack
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Incoming Transaction                  │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              1. Signature Verification                   │
//! │    (Hybrid ECDSA + Dilithium with threat awareness)     │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              2. Compliance Middleware                    │
//! │    (GDPR, HIPAA, PCI-DSS, CCPA pre-flight checks)       │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              3. Rate Limiting                            │
//! │    (Per-address, per-type, global limits)               │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              4. Fee Validation                           │
//! │    (Minimum fee, gas price, balance check)              │
//! └─────────────────────────────────────────────────────────┘
//!                            │
//!                            ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Mempool                               │
//! └─────────────────────────────────────────────────────────┘
//! ```

pub mod compliance;
pub mod signature;
pub mod rate_limit;
pub mod fee;

use std::sync::Arc;
use thiserror::Error;

/// Middleware errors
#[derive(Error, Debug, Clone)]
pub enum MiddlewareError {
    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("Compliance check failed: {0}")]
    ComplianceError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Fee validation failed: {0}")]
    FeeError(String),

    #[error("Transaction rejected: {0}")]
    Rejected(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for middleware operations
pub type MiddlewareResult<T> = Result<T, MiddlewareError>;

/// Middleware trait for transaction processing
pub trait Middleware: Send + Sync {
    /// Process a transaction through this middleware
    fn process(&self, ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction>;

    /// Get middleware name
    fn name(&self) -> &'static str;

    /// Get middleware priority (lower = earlier in chain)
    fn priority(&self) -> u32;
}

/// Middleware action after processing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiddlewareAction {
    /// Continue to next middleware
    Continue,
    /// Skip remaining middleware and accept
    Accept,
    /// Reject transaction with reason
    Reject(String),
    /// Delay transaction (requeue for later)
    Delay { milliseconds: u64, reason: String },
}

/// Context passed through middleware chain
pub struct MiddlewareContext {
    /// Transaction bytes (serialized SignedTransaction)
    pub tx_bytes: Vec<u8>,
    /// Parsed transaction (may be set by signature middleware)
    pub parsed_tx: Option<ParsedTransaction>,
    /// Metadata collected by middleware
    pub metadata: MiddlewareMetadata,
    /// Global configuration
    pub config: Arc<MiddlewareConfig>,
}

impl MiddlewareContext {
    /// Create new context
    pub fn new(tx_bytes: Vec<u8>, config: Arc<MiddlewareConfig>) -> Self {
        Self {
            tx_bytes,
            parsed_tx: None,
            metadata: MiddlewareMetadata::default(),
            config,
        }
    }

    /// Add metadata tag
    pub fn add_tag(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.tags.push((key.into(), value.into()));
    }

    /// Check if has tag
    pub fn has_tag(&self, key: &str) -> bool {
        self.metadata.tags.iter().any(|(k, _)| k == key)
    }

    /// Get tag value
    pub fn get_tag(&self, key: &str) -> Option<&str> {
        self.metadata
            .tags
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parsed transaction for middleware processing
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// Transaction ID
    pub tx_id: [u8; 32],
    /// Sender address bytes
    pub sender: [u8; 21],
    /// Transaction type byte
    pub tx_type: u8,
    /// Nonce
    pub nonce: u64,
    /// Gas price
    pub gas_price: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Size in bytes
    pub size: usize,
    /// Has valid hybrid signature
    pub signature_valid: bool,
    /// Compliance metadata extracted from payload
    pub compliance_metadata: Option<ComplianceMetadata>,
}

/// Compliance-related metadata extracted from transaction
#[derive(Debug, Clone, Default)]
pub struct ComplianceMetadata {
    /// Required compliance frameworks
    pub required_frameworks: Vec<String>,
    /// Data residency requirements
    pub data_residency: Option<String>,
    /// Audit trail required
    pub audit_required: bool,
    /// PII detected (pre-flight check)
    pub pii_detected: bool,
    /// PII types detected
    pub pii_types: Vec<String>,
}

/// Metadata collected during middleware processing
#[derive(Debug, Clone, Default)]
pub struct MiddlewareMetadata {
    /// Key-value tags
    pub tags: Vec<(String, String)>,
    /// Processing timestamps
    pub timestamps: Vec<(String, u64)>,
    /// Compliance check results
    pub compliance_results: Vec<ComplianceCheckResult>,
    /// Warnings (non-fatal issues)
    pub warnings: Vec<String>,
}

/// Result of a compliance check
#[derive(Debug, Clone)]
pub struct ComplianceCheckResult {
    /// Check name
    pub check_name: String,
    /// Passed
    pub passed: bool,
    /// Framework (GDPR, HIPAA, etc.)
    pub framework: Option<String>,
    /// Details
    pub details: Option<String>,
}

/// Global middleware configuration
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    /// Enabled compliance frameworks
    pub enabled_frameworks: Vec<String>,
    /// Quantum threat level (0-5)
    pub quantum_threat_level: u8,
    /// Minimum gas price
    pub min_gas_price: u64,
    /// Maximum transaction size
    pub max_tx_size: usize,
    /// Rate limit per address (tx/minute)
    pub rate_limit_per_address: u32,
    /// Global rate limit (tx/second)
    pub global_rate_limit: u32,
    /// Blocked addresses
    pub blocked_addresses: Vec<[u8; 21]>,
    /// Required compliance for compute jobs
    pub compute_requires_compliance: bool,
    /// Enable PII pre-flight scanning
    pub enable_pii_scanning: bool,
}

impl Default for MiddlewareConfig {
    fn default() -> Self {
        Self {
            enabled_frameworks: vec![
                "GDPR".into(),
                "HIPAA".into(),
                "PCI-DSS".into(),
            ],
            quantum_threat_level: 0,
            min_gas_price: 1,
            max_tx_size: 1_048_576, // 1 MB
            rate_limit_per_address: 60, // 1 per second
            global_rate_limit: 10_000,
            blocked_addresses: Vec::new(),
            compute_requires_compliance: true,
            enable_pii_scanning: true,
        }
    }
}

/// Middleware chain for processing transactions
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
    config: Arc<MiddlewareConfig>,
}

impl MiddlewareChain {
    /// Create new middleware chain
    pub fn new(config: MiddlewareConfig) -> Self {
        Self {
            middlewares: Vec::new(),
            config: Arc::new(config),
        }
    }

    /// Add middleware to chain
    pub fn add(&mut self, middleware: impl Middleware + 'static) {
        self.middlewares.push(Box::new(middleware));
        // Sort by priority
        self.middlewares.sort_by_key(|m| m.priority());
    }

    /// Process transaction through all middleware
    pub fn process(&self, tx_bytes: Vec<u8>) -> MiddlewareResult<ProcessingResult> {
        let mut ctx = MiddlewareContext::new(tx_bytes, self.config.clone());
        let mut results = Vec::new();

        for middleware in &self.middlewares {
            let start = std::time::Instant::now();
            let action = middleware.process(&mut ctx)?;
            let elapsed = start.elapsed().as_micros() as u64;

            ctx.metadata.timestamps.push((middleware.name().into(), elapsed));

            results.push(MiddlewareStepResult {
                middleware_name: middleware.name().into(),
                action: action.clone(),
                duration_us: elapsed,
            });

            match action {
                MiddlewareAction::Continue => continue,
                MiddlewareAction::Accept => break,
                MiddlewareAction::Reject(reason) => {
                    return Ok(ProcessingResult {
                        accepted: false,
                        rejection_reason: Some(reason),
                        steps: results,
                        metadata: ctx.metadata,
                    });
                }
                MiddlewareAction::Delay { .. } => {
                    return Ok(ProcessingResult {
                        accepted: false,
                        rejection_reason: Some("Transaction delayed".into()),
                        steps: results,
                        metadata: ctx.metadata,
                    });
                }
            }
        }

        Ok(ProcessingResult {
            accepted: true,
            rejection_reason: None,
            steps: results,
            metadata: ctx.metadata,
        })
    }

    /// Get configuration
    pub fn config(&self) -> &MiddlewareConfig {
        &self.config
    }
}

/// Result of middleware chain processing
#[derive(Debug)]
pub struct ProcessingResult {
    /// Whether transaction was accepted
    pub accepted: bool,
    /// Rejection reason (if rejected)
    pub rejection_reason: Option<String>,
    /// Results from each middleware step
    pub steps: Vec<MiddlewareStepResult>,
    /// Collected metadata
    pub metadata: MiddlewareMetadata,
}

/// Result from a single middleware step
#[derive(Debug)]
pub struct MiddlewareStepResult {
    /// Middleware name
    pub middleware_name: String,
    /// Action taken
    pub action: MiddlewareAction,
    /// Processing duration (microseconds)
    pub duration_us: u64,
}

/// Create default middleware chain with all standard middleware
pub fn create_default_chain(config: MiddlewareConfig) -> MiddlewareChain {
    let mut chain = MiddlewareChain::new(config);

    // Add middleware in priority order
    chain.add(signature::SignatureMiddleware::new());
    chain.add(compliance::ComplianceMiddleware::new());
    chain.add(rate_limit::RateLimitMiddleware::new());
    chain.add(fee::FeeMiddleware::new());

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMiddleware {
        name: &'static str,
        priority: u32,
        action: MiddlewareAction,
    }

    impl Middleware for TestMiddleware {
        fn process(&self, _ctx: &mut MiddlewareContext) -> MiddlewareResult<MiddlewareAction> {
            Ok(self.action.clone())
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> u32 {
            self.priority
        }
    }

    #[test]
    fn test_middleware_chain() {
        let mut chain = MiddlewareChain::new(MiddlewareConfig::default());

        chain.add(TestMiddleware {
            name: "first",
            priority: 1,
            action: MiddlewareAction::Continue,
        });

        chain.add(TestMiddleware {
            name: "second",
            priority: 2,
            action: MiddlewareAction::Continue,
        });

        let result = chain.process(vec![0; 100]).unwrap();
        assert!(result.accepted);
        assert_eq!(result.steps.len(), 2);
    }

    #[test]
    fn test_middleware_rejection() {
        let mut chain = MiddlewareChain::new(MiddlewareConfig::default());

        chain.add(TestMiddleware {
            name: "rejector",
            priority: 1,
            action: MiddlewareAction::Reject("test rejection".into()),
        });

        let result = chain.process(vec![0; 100]).unwrap();
        assert!(!result.accepted);
        assert_eq!(result.rejection_reason, Some("test rejection".into()));
    }

    #[test]
    fn test_middleware_priority_ordering() {
        let mut chain = MiddlewareChain::new(MiddlewareConfig::default());

        // Add in wrong order
        chain.add(TestMiddleware {
            name: "third",
            priority: 30,
            action: MiddlewareAction::Continue,
        });
        chain.add(TestMiddleware {
            name: "first",
            priority: 10,
            action: MiddlewareAction::Continue,
        });
        chain.add(TestMiddleware {
            name: "second",
            priority: 20,
            action: MiddlewareAction::Continue,
        });

        let result = chain.process(vec![0; 100]).unwrap();

        // Should be processed in priority order
        assert_eq!(result.steps[0].middleware_name, "first");
        assert_eq!(result.steps[1].middleware_name, "second");
        assert_eq!(result.steps[2].middleware_name, "third");
    }
}
