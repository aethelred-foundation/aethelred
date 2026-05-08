//! Canonical error-code taxonomy.
//!
//! Complements [`crate::error_code`] (a small enum used in the protocol
//! API) by providing a *registry* of operator-defined error codes per
//! service. Each code has an HTTP-status, severity, retryable flag, and
//! customer-facing message template.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ErrorClass
// =============================================================================

/// High-level class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Validation / 4xx.
    Validation,
    /// Authentication / authz.
    Auth,
    /// Quota / rate-limit.
    Quota,
    /// Configuration error.
    Configuration,
    /// Dependency outage.
    DependencyOutage,
    /// Internal bug.
    Internal,
    /// Network / timeout.
    Network,
    /// Conflict.
    Conflict,
}

// =============================================================================
// ErrorSeverity
// =============================================================================

/// Severity for triage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    /// Informational.
    Info,
    /// Warning.
    Warning,
    /// Error.
    Error,
    /// Critical.
    Critical,
}

// =============================================================================
// CanonicalError
// =============================================================================

/// One canonical error definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalError {
    /// Stable code (e.g. `"AETH_001"`).
    pub code: String,
    /// Service emitting it.
    pub service_id: String,
    /// Class.
    pub class: ErrorClass,
    /// Severity.
    pub severity: ErrorSeverity,
    /// HTTP status to surface.
    pub http_status: u16,
    /// `true` if retrying may succeed.
    pub retryable: bool,
    /// Customer-facing message.
    pub customer_message: String,
    /// Internal-only detailed description.
    pub internal_description: String,
    /// Optional documentation URL.
    pub doc_url: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
}

// =============================================================================
// ErrorTaxonomy
// =============================================================================

#[derive(Default)]
struct State {
    errors: HashMap<String, CanonicalError>,
}

/// Taxonomy.
pub struct ErrorTaxonomy {
    state: RwLock<State>,
}

impl Default for ErrorTaxonomy {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ErrorTaxonomy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErrorTaxonomy")
            .field("count", &self.len())
            .finish()
    }
}

impl ErrorTaxonomy {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register.
    pub fn register(&self, e: CanonicalError) -> SandboxResult<()> {
        if !(100..=599).contains(&e.http_status) {
            return Err(SandboxError::Other(format!(
                "http_status out of range: {}",
                e.http_status
            )));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("error taxonomy poisoned".into()))?;
        if g.errors.contains_key(&e.code) {
            return Err(SandboxError::Other(format!(
                "code {} already registered",
                e.code
            )));
        }
        g.errors.insert(e.code.clone(), e);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, code: &str) -> Option<CanonicalError> {
        self.state.read().ok()?.errors.get(code).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<CanonicalError> {
        self.state
            .read()
            .map(|g| g.errors.values().cloned().collect())
            .unwrap_or_default()
    }

    /// By service.
    pub fn for_service(&self, service: &str) -> Vec<CanonicalError> {
        self.all()
            .into_iter()
            .filter(|e| e.service_id == service)
            .collect()
    }

    /// By class.
    pub fn by_class(&self, class: ErrorClass) -> Vec<CanonicalError> {
        self.all().into_iter().filter(|e| e.class == class).collect()
    }

    /// By severity at least.
    pub fn at_or_above(&self, severity: ErrorSeverity) -> Vec<CanonicalError> {
        self.all()
            .into_iter()
            .filter(|e| sev_rank(e.severity) <= sev_rank(severity))
            .collect()
    }

    /// Retryable errors.
    pub fn retryable(&self) -> Vec<CanonicalError> {
        self.all().into_iter().filter(|e| e.retryable).collect()
    }

    /// Render the customer message with substitutions (`{key}` placeholders).
    pub fn render(&self, code: &str, vars: &HashMap<String, String>) -> SandboxResult<String> {
        let e = self
            .get(code)
            .ok_or_else(|| SandboxError::Other(format!("code {} not found", code)))?;
        let mut out = e.customer_message.clone();
        for (k, v) in vars {
            out = out.replace(&format!("{{{}}}", k), v);
        }
        Ok(out)
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.errors.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn sev_rank(s: ErrorSeverity) -> u8 {
    match s {
        ErrorSeverity::Critical => 0,
        ErrorSeverity::Error => 1,
        ErrorSeverity::Warning => 2,
        ErrorSeverity::Info => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: &str, class: ErrorClass, status: u16, retryable: bool) -> CanonicalError {
        CanonicalError {
            code: code.into(),
            service_id: "sandbox-finance".into(),
            class,
            severity: ErrorSeverity::Error,
            http_status: status,
            retryable,
            customer_message: "Something went wrong: {detail}".into(),
            internal_description: "internal".into(),
            doc_url: Some("https://docs.example.com/x".into()),
            tags: vec![],
        }
    }

    #[test]
    fn register_succeeds() {
        let t = ErrorTaxonomy::new();
        t.register(err("E001", ErrorClass::Validation, 400, false))
            .unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let t = ErrorTaxonomy::new();
        t.register(err("E001", ErrorClass::Validation, 400, false))
            .unwrap();
        assert!(t
            .register(err("E001", ErrorClass::Validation, 400, false))
            .is_err());
    }

    #[test]
    fn invalid_http_status_errors() {
        let t = ErrorTaxonomy::new();
        assert!(t
            .register(err("E001", ErrorClass::Validation, 99, false))
            .is_err());
        assert!(t
            .register(err("E002", ErrorClass::Validation, 700, false))
            .is_err());
    }

    #[test]
    fn lookup_returns_record() {
        let t = ErrorTaxonomy::new();
        t.register(err("E001", ErrorClass::Validation, 400, false))
            .unwrap();
        assert!(t.get("E001").is_some());
        assert!(t.get("ghost").is_none());
    }

    #[test]
    fn for_service_filters() {
        let t = ErrorTaxonomy::new();
        t.register(err("E001", ErrorClass::Validation, 400, false))
            .unwrap();
        let mut other = err("E002", ErrorClass::Validation, 400, false);
        other.service_id = "other".into();
        t.register(other).unwrap();
        assert_eq!(t.for_service("sandbox-finance").len(), 1);
        assert_eq!(t.for_service("other").len(), 1);
    }

    #[test]
    fn by_class_filters() {
        let t = ErrorTaxonomy::new();
        t.register(err("E1", ErrorClass::Validation, 400, false))
            .unwrap();
        t.register(err("E2", ErrorClass::Quota, 429, true)).unwrap();
        assert_eq!(t.by_class(ErrorClass::Validation).len(), 1);
        assert_eq!(t.by_class(ErrorClass::Quota).len(), 1);
    }

    #[test]
    fn at_or_above_severity() {
        let t = ErrorTaxonomy::new();
        let mut e = err("E1", ErrorClass::Internal, 500, false);
        e.severity = ErrorSeverity::Critical;
        t.register(e).unwrap();
        let mut e2 = err("E2", ErrorClass::Validation, 400, false);
        e2.severity = ErrorSeverity::Warning;
        t.register(e2).unwrap();
        assert_eq!(t.at_or_above(ErrorSeverity::Error).len(), 1);
        assert_eq!(t.at_or_above(ErrorSeverity::Warning).len(), 2);
    }

    #[test]
    fn retryable_filters() {
        let t = ErrorTaxonomy::new();
        t.register(err("E1", ErrorClass::Quota, 429, true)).unwrap();
        t.register(err("E2", ErrorClass::Validation, 400, false))
            .unwrap();
        assert_eq!(t.retryable().len(), 1);
    }

    #[test]
    fn render_substitutes_vars() {
        let t = ErrorTaxonomy::new();
        t.register(err("E1", ErrorClass::Validation, 400, false))
            .unwrap();
        let mut vars = HashMap::new();
        vars.insert("detail".into(), "missing field 'x'".into());
        let out = t.render("E1", &vars).unwrap();
        assert!(out.contains("missing field 'x'"));
    }

    #[test]
    fn render_unknown_errors() {
        let t = ErrorTaxonomy::new();
        let vars = HashMap::new();
        assert!(t.render("ghost", &vars).is_err());
    }

    #[test]
    fn render_no_vars_passes_template_through() {
        let t = ErrorTaxonomy::new();
        t.register(err("E1", ErrorClass::Validation, 400, false))
            .unwrap();
        let vars = HashMap::new();
        let out = t.render("E1", &vars).unwrap();
        assert!(out.contains("{detail}"));
    }

    #[test]
    fn canonical_error_serde() {
        let e = err("E1", ErrorClass::Validation, 400, false);
        let j = serde_json::to_string(&e).unwrap();
        let p: CanonicalError = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn class_serde() {
        for c in [
            ErrorClass::Validation,
            ErrorClass::Auth,
            ErrorClass::Quota,
            ErrorClass::Configuration,
            ErrorClass::DependencyOutage,
            ErrorClass::Internal,
            ErrorClass::Network,
            ErrorClass::Conflict,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: ErrorClass = serde_json::from_str(&j).unwrap();
            assert_eq!(p, c);
        }
    }

    #[test]
    fn severity_serde() {
        for s in [
            ErrorSeverity::Info,
            ErrorSeverity::Warning,
            ErrorSeverity::Error,
            ErrorSeverity::Critical,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ErrorSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn registry_count_tracks() {
        let t = ErrorTaxonomy::new();
        assert!(t.is_empty());
        t.register(err("E1", ErrorClass::Validation, 400, false))
            .unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn many_codes_aggregate() {
        let t = ErrorTaxonomy::new();
        for i in 0..50 {
            t.register(err(&format!("E{i:03}"), ErrorClass::Validation, 400, false))
                .unwrap();
        }
        assert_eq!(t.len(), 50);
    }

    #[test]
    fn doc_url_recorded() {
        let t = ErrorTaxonomy::new();
        let mut e = err("E1", ErrorClass::Validation, 400, false);
        e.doc_url = Some("https://docs.test/E1".into());
        t.register(e).unwrap();
        let got = t.get("E1").unwrap();
        assert_eq!(got.doc_url.as_deref(), Some("https://docs.test/E1"));
    }

    #[test]
    fn at_or_above_critical_only() {
        let t = ErrorTaxonomy::new();
        let mut e = err("E1", ErrorClass::Internal, 500, false);
        e.severity = ErrorSeverity::Critical;
        t.register(e).unwrap();
        let mut e2 = err("E2", ErrorClass::Internal, 500, false);
        e2.severity = ErrorSeverity::Error;
        t.register(e2).unwrap();
        assert_eq!(t.at_or_above(ErrorSeverity::Critical).len(), 1);
    }

    #[test]
    fn render_with_multiple_vars() {
        let t = ErrorTaxonomy::new();
        let mut e = err("E1", ErrorClass::Validation, 400, false);
        e.customer_message = "field {name} value {value} is invalid".into();
        t.register(e).unwrap();
        let mut vars = HashMap::new();
        vars.insert("name".into(), "age".into());
        vars.insert("value".into(), "200".into());
        let out = t.render("E1", &vars).unwrap();
        assert_eq!(out, "field age value 200 is invalid");
    }

    #[test]
    fn all_returns_all_codes() {
        let t = ErrorTaxonomy::new();
        for i in 0..3 {
            t.register(err(&format!("E{i}"), ErrorClass::Validation, 400, false))
                .unwrap();
        }
        assert_eq!(t.all().len(), 3);
    }
}
