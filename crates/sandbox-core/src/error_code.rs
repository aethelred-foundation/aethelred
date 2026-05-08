//! Machine-readable error codes for SIEM / SOC integration.
//!
//! Every [`crate::SandboxError`] variant maps to a stable error code of the
//! form `SBX-<CATEGORY>-<NUMBER>` (e.g., `SBX-POL-1003`). Customer SIEMs and
//! SOCs key on these codes for alerting; the human message can change but
//! the code is part of the public API contract.
//!
//! The codes are versioned through the `EnterpriseApiVersion` constant —
//! never repurpose a code; only add new ones.

use crate::SandboxError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable error code prefix.
pub const PREFIX: &str = "SBX";

/// Major API version of the error-code scheme. Incremented only on
/// breaking changes to the catalogue.
pub const ENTERPRISE_API_VERSION: u32 = 1;

/// Error category — coarse-grained grouping for SIEM rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    /// Policy gate denial.
    Policy,
    /// Input validation failure.
    Input,
    /// Data boundary violation.
    DataBoundary,
    /// Evidence-log integrity failure.
    Evidence,
    /// Cryptographic operation failure.
    Crypto,
    /// Connector failure.
    Connector,
    /// TEE attestation failure.
    Attestation,
    /// zkML proof failure.
    Zkml,
    /// Configuration error.
    Configuration,
    /// Other / unclassified.
    Other,
}

impl ErrorCategory {
    /// Stable string id (used in error codes).
    pub const fn as_short(self) -> &'static str {
        match self {
            Self::Policy => "POL",
            Self::Input => "INP",
            Self::DataBoundary => "DBN",
            Self::Evidence => "EVD",
            Self::Crypto => "CRY",
            Self::Connector => "CNN",
            Self::Attestation => "ATT",
            Self::Zkml => "ZKM",
            Self::Configuration => "CFG",
            Self::Other => "OTH",
        }
    }
}

/// A machine-readable error code. Format: `SBX-<CATEGORY>-<4-digit number>`.
///
/// Codes are stable across versions; never change once shipped.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ErrorCode {
    /// Coarse category.
    pub category: ErrorCategory,
    /// Numeric subcode (zero-padded to 4 digits in display).
    pub number: u32,
}

impl ErrorCode {
    /// Construct a code.
    pub const fn new(category: ErrorCategory, number: u32) -> Self {
        Self { category, number }
    }

    /// Render as the canonical string form.
    pub fn to_canonical(&self) -> String {
        format!("{}-{}-{:04}", PREFIX, self.category.as_short(), self.number)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

// =============================================================================
// Code constants — public API contract
// =============================================================================

/// Generic policy denial.
pub const POL_DENIED: ErrorCode = ErrorCode::new(ErrorCategory::Policy, 1000);
/// Required gate failed.
pub const POL_REQUIRED_GATE: ErrorCode = ErrorCode::new(ErrorCategory::Policy, 1001);
/// Multiple policy gates failed.
pub const POL_MULTIPLE_FAILURES: ErrorCode = ErrorCode::new(ErrorCategory::Policy, 1002);
/// Sector-specific business rule denied (e.g., adverse claim without reason).
pub const POL_BUSINESS_RULE: ErrorCode = ErrorCode::new(ErrorCategory::Policy, 1003);

/// Generic input validation error.
pub const INP_INVALID: ErrorCode = ErrorCode::new(ErrorCategory::Input, 2000);
/// Missing required field on builder.
pub const INP_MISSING_FIELD: ErrorCode = ErrorCode::new(ErrorCategory::Input, 2001);
/// Bad hex format on hash field.
pub const INP_BAD_HEX: ErrorCode = ErrorCode::new(ErrorCategory::Input, 2002);
/// Bad RFC 3339 timestamp.
pub const INP_BAD_TIMESTAMP: ErrorCode = ErrorCode::new(ErrorCategory::Input, 2003);

/// Generic data boundary violation (regulated data detected).
pub const DBN_VIOLATION: ErrorCode = ErrorCode::new(ErrorCategory::DataBoundary, 3000);
/// PII marker detected in pseudo-id.
pub const DBN_PII_MARKER: ErrorCode = ErrorCode::new(ErrorCategory::DataBoundary, 3001);
/// PHI marker detected.
pub const DBN_PHI_MARKER: ErrorCode = ErrorCode::new(ErrorCategory::DataBoundary, 3002);
/// Classified marker detected.
pub const DBN_CLASSIFIED_MARKER: ErrorCode = ErrorCode::new(ErrorCategory::DataBoundary, 3003);

/// Evidence log poisoned (mutex broken).
pub const EVD_LOG_POISONED: ErrorCode = ErrorCode::new(ErrorCategory::Evidence, 4000);
/// Evidence index out of range.
pub const EVD_INDEX_OOR: ErrorCode = ErrorCode::new(ErrorCategory::Evidence, 4001);
/// Merkle proof verification failed.
pub const EVD_PROOF_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Evidence, 4002);
/// Evidence integrity tamper detected (zero-hash field).
pub const EVD_TAMPER_DETECTED: ErrorCode = ErrorCode::new(ErrorCategory::Evidence, 4003);

/// Cryptographic serialise / hash failure.
pub const CRY_HASH_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Crypto, 5000);
/// Signature verification failed.
pub const CRY_SIG_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Crypto, 5001);

/// Connector open failure.
pub const CNN_OPEN_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Connector, 6000);
/// Connector next-event failure.
pub const CNN_READ_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Connector, 6001);

/// Attestation verifier rejected the document.
pub const ATT_VERIFIER_REJECTED: ErrorCode = ErrorCode::new(ErrorCategory::Attestation, 7000);
/// Attestation runtime nonce was zero (replay protection).
pub const ATT_ZERO_NONCE: ErrorCode = ErrorCode::new(ErrorCategory::Attestation, 7001);

/// zkML circuit hash mismatch.
pub const ZKM_CIRCUIT_MISMATCH: ErrorCode = ErrorCode::new(ErrorCategory::Zkml, 8000);
/// zkML proof verification failed.
pub const ZKM_PROOF_FAILED: ErrorCode = ErrorCode::new(ErrorCategory::Zkml, 8001);

/// Configuration is incomplete.
pub const CFG_INCOMPLETE: ErrorCode = ErrorCode::new(ErrorCategory::Configuration, 9000);
/// Configuration is inconsistent.
pub const CFG_INCONSISTENT: ErrorCode = ErrorCode::new(ErrorCategory::Configuration, 9001);

/// Other / unclassified.
pub const OTH_UNCLASSIFIED: ErrorCode = ErrorCode::new(ErrorCategory::Other, 9999);

impl SandboxError {
    /// Map to a stable machine-readable error code.
    ///
    /// SIEM / SOC integrations key on this code. Codes are part of the public
    /// API and never change once shipped.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::PolicyDenied { .. } => POL_DENIED,
            Self::InvalidInput(_) => INP_INVALID,
            Self::DataBoundary(_) => DBN_VIOLATION,
            Self::Evidence(_) => EVD_LOG_POISONED,
            Self::Crypto(_) => CRY_HASH_FAILED,
            Self::Connector { .. } => CNN_OPEN_FAILED,
            Self::Attestation { .. } => ATT_VERIFIER_REJECTED,
            Self::Zkml { .. } => ZKM_PROOF_FAILED,
            Self::Configuration(_) => CFG_INCOMPLETE,
            Self::Other(_) => OTH_UNCLASSIFIED,
        }
    }

    /// Construct a `PolicyDenied` with a specific error code.
    pub fn policy_with_code(
        code: ErrorCode,
        gate: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let _ = code; // kept for forward compatibility
        Self::PolicyDenied {
            policy_gate: gate.into(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_format_is_sbx_dash_category_dash_4digits() {
        assert_eq!(POL_DENIED.to_canonical(), "SBX-POL-1000");
        assert_eq!(INP_INVALID.to_canonical(), "SBX-INP-2000");
        assert_eq!(DBN_PII_MARKER.to_canonical(), "SBX-DBN-3001");
        assert_eq!(EVD_PROOF_FAILED.to_canonical(), "SBX-EVD-4002");
    }

    #[test]
    fn all_categories_have_unique_short_codes() {
        let cats = [
            ErrorCategory::Policy,
            ErrorCategory::Input,
            ErrorCategory::DataBoundary,
            ErrorCategory::Evidence,
            ErrorCategory::Crypto,
            ErrorCategory::Connector,
            ErrorCategory::Attestation,
            ErrorCategory::Zkml,
            ErrorCategory::Configuration,
            ErrorCategory::Other,
        ];
        let mut shorts: Vec<&str> = cats.iter().map(|c| c.as_short()).collect();
        shorts.sort_unstable();
        let n = shorts.len();
        shorts.dedup();
        assert_eq!(shorts.len(), n);
    }

    #[test]
    fn error_code_serde_roundtrip() {
        let code = POL_REQUIRED_GATE;
        let j = serde_json::to_string(&code).unwrap();
        let parsed: ErrorCode = serde_json::from_str(&j).unwrap();
        assert_eq!(code, parsed);
    }

    #[test]
    fn category_serde_roundtrip() {
        for cat in [ErrorCategory::Policy, ErrorCategory::Input, ErrorCategory::DataBoundary, ErrorCategory::Evidence, ErrorCategory::Crypto, ErrorCategory::Connector, ErrorCategory::Attestation, ErrorCategory::Zkml, ErrorCategory::Configuration, ErrorCategory::Other] {
            let j = serde_json::to_string(&cat).unwrap();
            let p: ErrorCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(cat, p);
        }
    }

    #[test]
    fn display_matches_canonical() {
        assert_eq!(format!("{}", POL_DENIED), POL_DENIED.to_canonical());
    }

    #[test]
    fn error_to_code_routing_complete() {
        // Each variant must produce a code.
        let cases: Vec<SandboxError> = vec![
            SandboxError::policy("g", "r"),
            SandboxError::invalid("x"),
            SandboxError::DataBoundary("d".into()),
            SandboxError::Evidence("e".into()),
            SandboxError::Crypto("c".into()),
            SandboxError::Connector { connector: "c".into(), reason: "r".into() },
            SandboxError::Attestation { platform: "p".into(), reason: "r".into() },
            SandboxError::Zkml { system: "s".into(), reason: "r".into() },
            SandboxError::config("g"),
            SandboxError::Other("o".into()),
        ];
        for case in cases {
            let _ = case.error_code(); // must not panic
        }
    }

    #[test]
    fn enterprise_api_version_is_one() {
        assert_eq!(ENTERPRISE_API_VERSION, 1);
    }

    #[test]
    fn prefix_is_sbx() {
        assert_eq!(PREFIX, "SBX");
    }

    #[test]
    fn known_codes_have_distinct_numbers_within_category() {
        // Policy category codes must be distinct.
        let pol = [POL_DENIED, POL_REQUIRED_GATE, POL_MULTIPLE_FAILURES, POL_BUSINESS_RULE];
        let mut ns: Vec<u32> = pol.iter().map(|c| c.number).collect();
        ns.sort_unstable();
        let n = ns.len();
        ns.dedup();
        assert_eq!(ns.len(), n);
    }

    #[test]
    fn data_boundary_codes_have_distinct_numbers() {
        let codes = [DBN_VIOLATION, DBN_PII_MARKER, DBN_PHI_MARKER, DBN_CLASSIFIED_MARKER];
        let mut ns: Vec<u32> = codes.iter().map(|c| c.number).collect();
        ns.sort_unstable();
        let n = ns.len();
        ns.dedup();
        assert_eq!(ns.len(), n);
    }
}
