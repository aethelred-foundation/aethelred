//! Incident response integration.
//!
//! Production sandboxes need to produce **structured incident records**
//! that flow into ITSM (ServiceNow / Jira), paging (PagerDuty / Opsgenie),
//! and the SOC. This module ships:
//!
//! - [`Incident`] — structured incident with id, severity, error code,
//!   timestamps, runbook URL, affected tenants, and free-form context.
//! - [`RunbookCatalog`] — maps a `SBX-*` error code → runbook URL.
//! - [`IncidentDispatcher`] — pluggable trait for sending incidents to a
//!   downstream system.
//! - [`InMemoryDispatcher`] — collects incidents in-process (for tests).
//! - [`WebhookDispatcher`] — emits a JSON POST body suitable for any
//!   webhook receiver (PagerDuty Events v2, Opsgenie REST, Slack
//!   incoming, generic).
//!
//! ## What this module does *not* do
//!
//! Make actual HTTP calls. Pulling `reqwest` / `hyper` / `ureq` would
//! drag a TLS stack into sandbox-core. Instead, [`WebhookDispatcher`]
//! produces the canonical JSON body and lets the caller's HTTP client
//! send it. This is the right separation for an open-source library.

use crate::error_code::ErrorCode;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// IncidentSeverity
// =============================================================================

/// Severity levels (PagerDuty-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    /// Informational — log only.
    Info,
    /// Low — needs human attention this week.
    Low,
    /// Warning — needs human attention this shift.
    Warning,
    /// Error — breaks one workflow but contained.
    Error,
    /// Critical — impacts a tenant or breaches policy.
    Critical,
}

// =============================================================================
// Incident
// =============================================================================

/// Structured incident record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Incident {
    /// Stable incident id (UUIDv7 — time-orderable).
    pub id: Uuid,
    /// Short title (suitable for paging).
    pub title: String,
    /// Severity.
    pub severity: IncidentSeverity,
    /// Optional `SBX-*` machine-readable error code.
    pub error_code: Option<ErrorCode>,
    /// RFC 3339 occurrence timestamp.
    pub occurred_at: String,
    /// Affected tenant ids.
    pub affected_tenants: Vec<String>,
    /// Affected workflow ids.
    pub affected_workflows: Vec<String>,
    /// Free-form details (multi-line description).
    pub details: String,
    /// Optional runbook URL.
    pub runbook_url: Option<String>,
    /// Optional metric snapshot (key-value).
    pub context: HashMap<String, String>,
}

impl Incident {
    /// New incident builder.
    pub fn builder(title: impl Into<String>, severity: IncidentSeverity) -> IncidentBuilder {
        IncidentBuilder {
            title: title.into(),
            severity,
            error_code: None,
            tenants: Vec::new(),
            workflows: Vec::new(),
            details: String::new(),
            runbook_url: None,
            context: HashMap::new(),
        }
    }

    /// `true` if severity is `Error` or `Critical`.
    pub fn is_high_severity(&self) -> bool {
        matches!(
            self.severity,
            IncidentSeverity::Error | IncidentSeverity::Critical
        )
    }
}

/// Builder for [`Incident`].
pub struct IncidentBuilder {
    title: String,
    severity: IncidentSeverity,
    error_code: Option<ErrorCode>,
    tenants: Vec<String>,
    workflows: Vec<String>,
    details: String,
    runbook_url: Option<String>,
    context: HashMap<String, String>,
}

impl IncidentBuilder {
    /// Attach an error code.
    pub fn error_code(mut self, code: ErrorCode) -> Self {
        self.error_code = Some(code);
        self
    }
    /// Add an affected tenant.
    pub fn tenant(mut self, t: impl Into<String>) -> Self {
        self.tenants.push(t.into());
        self
    }
    /// Add an affected workflow.
    pub fn workflow(mut self, w: impl Into<String>) -> Self {
        self.workflows.push(w.into());
        self
    }
    /// Append details.
    pub fn details(mut self, d: impl Into<String>) -> Self {
        self.details = d.into();
        self
    }
    /// Set the runbook URL.
    pub fn runbook_url(mut self, u: impl Into<String>) -> Self {
        self.runbook_url = Some(u.into());
        self
    }
    /// Add context key-value.
    pub fn context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.context.insert(k.into(), v.into());
        self
    }
    /// Finalize.
    pub fn build(self) -> Incident {
        let occurred_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Incident {
            id: Uuid::now_v7(),
            title: self.title,
            severity: self.severity,
            error_code: self.error_code,
            occurred_at,
            affected_tenants: self.tenants,
            affected_workflows: self.workflows,
            details: self.details,
            runbook_url: self.runbook_url,
            context: self.context,
        }
    }
}

// =============================================================================
// RunbookCatalog
// =============================================================================

/// Maps error codes to runbook URLs.
#[derive(Debug, Default, Clone)]
pub struct RunbookCatalog {
    by_code: HashMap<ErrorCode, String>,
    default_url: Option<String>,
}

impl RunbookCatalog {
    /// New empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the fallback URL used when no specific mapping is found.
    pub fn with_default(mut self, url: impl Into<String>) -> Self {
        self.default_url = Some(url.into());
        self
    }

    /// Register a mapping.
    pub fn register(&mut self, code: ErrorCode, url: impl Into<String>) -> &mut Self {
        self.by_code.insert(code, url.into());
        self
    }

    /// Look up a runbook URL for a given code.
    pub fn lookup(&self, code: &ErrorCode) -> Option<String> {
        self.by_code
            .get(code)
            .cloned()
            .or_else(|| self.default_url.clone())
    }

    /// Number of explicit mappings (not counting default).
    pub fn len(&self) -> usize {
        self.by_code.len()
    }

    /// `true` if no explicit mappings.
    pub fn is_empty(&self) -> bool {
        self.by_code.is_empty()
    }
}

// =============================================================================
// Dispatcher
// =============================================================================

/// Pluggable incident sink.
pub trait IncidentDispatcher: Send + Sync {
    /// Stable id of this dispatcher (e.g., `"pagerduty"`, `"opsgenie"`).
    fn id(&self) -> &str;
    /// Send an incident.
    fn dispatch(&self, incident: &Incident) -> SandboxResult<()>;
}

/// In-memory dispatcher (tests / dev).
pub struct InMemoryDispatcher {
    id: String,
    received: Mutex<Vec<Incident>>,
}

impl InMemoryDispatcher {
    /// New dispatcher.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            received: Mutex::new(Vec::new()),
        }
    }

    /// All incidents received so far.
    pub fn received(&self) -> Vec<Incident> {
        match self.received.lock() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// Number received.
    pub fn count(&self) -> usize {
        self.received.lock().map(|g| g.len()).unwrap_or(0)
    }
}

impl IncidentDispatcher for InMemoryDispatcher {
    fn id(&self) -> &str {
        &self.id
    }
    fn dispatch(&self, incident: &Incident) -> SandboxResult<()> {
        match self.received.lock() {
            Ok(mut g) => g.push(incident.clone()),
            Err(e) => e.into_inner().push(incident.clone()),
        }
        Ok(())
    }
}

/// Webhook style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookStyle {
    /// PagerDuty Events API v2 layout.
    PagerDutyV2,
    /// Opsgenie REST v2 layout.
    Opsgenie,
    /// Slack incoming webhook (text-only block).
    Slack,
    /// Generic — emits the structured `Incident` JSON unchanged.
    Generic,
}

/// Webhook dispatcher — produces the JSON body without sending.
///
/// The caller takes the body from [`WebhookDispatcher::format_body`] and
/// POSTs it via their HTTP client. The dispatcher records every incident
/// it has rendered for testability.
pub struct WebhookDispatcher {
    id: String,
    style: WebhookStyle,
    url: String,
    rendered: Mutex<Vec<(Incident, String)>>,
}

impl WebhookDispatcher {
    /// New dispatcher.
    pub fn new(
        id: impl Into<String>,
        style: WebhookStyle,
        url: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            style,
            url: url.into(),
            rendered: Mutex::new(Vec::new()),
        }
    }

    /// URL the caller should POST to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Style.
    pub fn style(&self) -> WebhookStyle {
        self.style
    }

    /// Render the incident body for the configured style.
    pub fn format_body(&self, incident: &Incident) -> String {
        match self.style {
            WebhookStyle::PagerDutyV2 => format_pagerduty(incident),
            WebhookStyle::Opsgenie => format_opsgenie(incident),
            WebhookStyle::Slack => format_slack(incident),
            WebhookStyle::Generic => serde_json::to_string(incident).unwrap_or_default(),
        }
    }

    /// All `(incident, rendered_body)` pairs dispatched.
    pub fn rendered(&self) -> Vec<(Incident, String)> {
        match self.rendered.lock() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }

    /// Number rendered.
    pub fn count(&self) -> usize {
        self.rendered.lock().map(|g| g.len()).unwrap_or(0)
    }
}

impl IncidentDispatcher for WebhookDispatcher {
    fn id(&self) -> &str {
        &self.id
    }
    fn dispatch(&self, incident: &Incident) -> SandboxResult<()> {
        let body = self.format_body(incident);
        match self.rendered.lock() {
            Ok(mut g) => g.push((incident.clone(), body)),
            Err(e) => e.into_inner().push((incident.clone(), body)),
        }
        Ok(())
    }
}

fn pagerduty_severity(s: IncidentSeverity) -> &'static str {
    match s {
        IncidentSeverity::Info => "info",
        IncidentSeverity::Low | IncidentSeverity::Warning => "warning",
        IncidentSeverity::Error => "error",
        IncidentSeverity::Critical => "critical",
    }
}

fn format_pagerduty(i: &Incident) -> String {
    let payload = serde_json::json!({
        "routing_key": "<set-by-caller>",
        "event_action": "trigger",
        "dedup_key": i.id.to_string(),
        "payload": {
            "summary": i.title,
            "severity": pagerduty_severity(i.severity),
            "source": "aethelred-sandbox",
            "timestamp": i.occurred_at,
            "component": i.affected_workflows.join(","),
            "group": i.affected_tenants.join(","),
            "class": i.error_code.as_ref().map(|c| c.to_canonical()).unwrap_or_default(),
            "custom_details": {
                "details": i.details,
                "runbook": i.runbook_url,
                "context": i.context,
            }
        }
    });
    serde_json::to_string(&payload).unwrap_or_default()
}

fn format_opsgenie(i: &Incident) -> String {
    let payload = serde_json::json!({
        "message": i.title,
        "alias": i.id.to_string(),
        "priority": match i.severity {
            IncidentSeverity::Info => "P5",
            IncidentSeverity::Low => "P4",
            IncidentSeverity::Warning => "P3",
            IncidentSeverity::Error => "P2",
            IncidentSeverity::Critical => "P1",
        },
        "description": i.details,
        "tags": ["aethelred", "sandbox"],
        "details": {
            "tenants": i.affected_tenants.join(","),
            "workflows": i.affected_workflows.join(","),
            "error_code": i.error_code.as_ref().map(|c| c.to_canonical()).unwrap_or_default(),
            "runbook": i.runbook_url,
            "occurred_at": i.occurred_at,
        }
    });
    serde_json::to_string(&payload).unwrap_or_default()
}

fn format_slack(i: &Incident) -> String {
    let prefix = match i.severity {
        IncidentSeverity::Critical => ":rotating_light: CRITICAL",
        IncidentSeverity::Error => ":x: ERROR",
        IncidentSeverity::Warning => ":warning: WARNING",
        IncidentSeverity::Low => ":memo: LOW",
        IncidentSeverity::Info => ":information_source: INFO",
    };
    let code = i
        .error_code
        .as_ref()
        .map(|c| format!(" [{}]", c.to_canonical()))
        .unwrap_or_default();
    let runbook = i
        .runbook_url
        .as_ref()
        .map(|u| format!("\nRunbook: {u}"))
        .unwrap_or_default();
    serde_json::json!({
        "text": format!("{prefix}{code}: {}\n{}{}", i.title, i.details, runbook),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_code::POL_DENIED;

    #[test]
    fn builder_constructs_incident() {
        let i = Incident::builder("title", IncidentSeverity::Critical)
            .error_code(POL_DENIED)
            .tenant("FAB")
            .workflow("credit_decision")
            .details("policy denial")
            .runbook_url("https://runbooks.aethelred.io/SBX-POL-1000")
            .context("seal_id", "abc123")
            .build();
        assert_eq!(i.title, "title");
        assert_eq!(i.severity, IncidentSeverity::Critical);
        assert_eq!(i.error_code, Some(POL_DENIED));
        assert_eq!(i.affected_tenants, vec!["FAB"]);
        assert_eq!(i.affected_workflows, vec!["credit_decision"]);
        assert!(i.runbook_url.is_some());
        assert_eq!(i.context.get("seal_id").map(String::as_str), Some("abc123"));
    }

    #[test]
    fn high_severity_for_error_and_critical() {
        let e = Incident::builder("e", IncidentSeverity::Error).build();
        let c = Incident::builder("c", IncidentSeverity::Critical).build();
        let w = Incident::builder("w", IncidentSeverity::Warning).build();
        assert!(e.is_high_severity());
        assert!(c.is_high_severity());
        assert!(!w.is_high_severity());
    }

    #[test]
    fn runbook_catalog_lookup_returns_url() {
        let mut cat = RunbookCatalog::new();
        cat.register(POL_DENIED, "https://runbooks.example/pol-1000");
        let r = cat.lookup(&POL_DENIED);
        assert_eq!(r, Some("https://runbooks.example/pol-1000".to_string()));
    }

    #[test]
    fn runbook_catalog_default_used_when_missing() {
        let cat = RunbookCatalog::new().with_default("https://runbooks.example/default");
        let r = cat.lookup(&POL_DENIED);
        assert_eq!(r, Some("https://runbooks.example/default".to_string()));
    }

    #[test]
    fn runbook_catalog_explicit_overrides_default() {
        let mut cat = RunbookCatalog::new().with_default("default-url");
        cat.register(POL_DENIED, "specific-url");
        assert_eq!(cat.lookup(&POL_DENIED), Some("specific-url".to_string()));
    }

    #[test]
    fn runbook_catalog_no_default_no_specific_returns_none() {
        let cat = RunbookCatalog::new();
        assert!(cat.lookup(&POL_DENIED).is_none());
    }

    #[test]
    fn in_memory_dispatcher_collects_incidents() {
        let d = InMemoryDispatcher::new("test");
        let i = Incident::builder("x", IncidentSeverity::Error).build();
        d.dispatch(&i).unwrap();
        d.dispatch(&i).unwrap();
        assert_eq!(d.count(), 2);
        assert_eq!(d.received().len(), 2);
    }

    #[test]
    fn in_memory_dispatcher_id() {
        let d = InMemoryDispatcher::new("test");
        assert_eq!(d.id(), "test");
    }

    #[test]
    fn webhook_pagerduty_renders_payload() {
        let d = WebhookDispatcher::new("pd", WebhookStyle::PagerDutyV2, "https://events.pagerduty.com");
        let i = Incident::builder("title", IncidentSeverity::Critical)
            .error_code(POL_DENIED)
            .build();
        let body = d.format_body(&i);
        assert!(body.contains("event_action"));
        assert!(body.contains("critical"));
    }

    #[test]
    fn webhook_opsgenie_renders_payload() {
        let d = WebhookDispatcher::new("og", WebhookStyle::Opsgenie, "https://api.opsgenie.com");
        let i = Incident::builder("title", IncidentSeverity::Error).build();
        let body = d.format_body(&i);
        assert!(body.contains("priority"));
        assert!(body.contains("\"P2\""));
    }

    #[test]
    fn webhook_slack_renders_payload() {
        let d = WebhookDispatcher::new("sl", WebhookStyle::Slack, "https://hooks.slack.com/x");
        let i = Incident::builder("title", IncidentSeverity::Critical)
            .error_code(POL_DENIED)
            .runbook_url("https://runbooks/x")
            .build();
        let body = d.format_body(&i);
        assert!(body.contains("CRITICAL"));
        assert!(body.contains("Runbook"));
    }

    #[test]
    fn webhook_generic_renders_raw_incident() {
        let d = WebhookDispatcher::new("g", WebhookStyle::Generic, "https://example/x");
        let i = Incident::builder("title", IncidentSeverity::Info).build();
        let body = d.format_body(&i);
        assert!(body.contains("title"));
        assert!(body.contains("\"info\""));
    }

    #[test]
    fn webhook_dispatch_records_rendered() {
        let d = WebhookDispatcher::new("g", WebhookStyle::Generic, "https://example/x");
        let i = Incident::builder("x", IncidentSeverity::Warning).build();
        d.dispatch(&i).unwrap();
        let r = d.rendered();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].0.title, "x");
    }

    #[test]
    fn webhook_url_is_returned() {
        let d = WebhookDispatcher::new("g", WebhookStyle::Generic, "https://example/x");
        assert_eq!(d.url(), "https://example/x");
        assert_eq!(d.style(), WebhookStyle::Generic);
    }

    #[test]
    fn pagerduty_severity_mapping() {
        assert_eq!(pagerduty_severity(IncidentSeverity::Info), "info");
        assert_eq!(pagerduty_severity(IncidentSeverity::Low), "warning");
        assert_eq!(pagerduty_severity(IncidentSeverity::Warning), "warning");
        assert_eq!(pagerduty_severity(IncidentSeverity::Error), "error");
        assert_eq!(pagerduty_severity(IncidentSeverity::Critical), "critical");
    }

    #[test]
    fn incident_serde_round_trip() {
        let i = Incident::builder("t", IncidentSeverity::Error)
            .error_code(POL_DENIED)
            .build();
        let j = serde_json::to_string(&i).unwrap();
        let p: Incident = serde_json::from_str(&j).unwrap();
        assert_eq!(p, i);
    }

    #[test]
    fn catalog_len_and_empty() {
        let mut c = RunbookCatalog::new();
        assert!(c.is_empty());
        c.register(POL_DENIED, "url");
        assert_eq!(c.len(), 1);
        assert!(!c.is_empty());
    }

    #[test]
    fn many_incidents_dispatch_correctly() {
        let d = InMemoryDispatcher::new("test");
        for i in 0..50 {
            let inc = Incident::builder(format!("i-{i}"), IncidentSeverity::Warning).build();
            d.dispatch(&inc).unwrap();
        }
        assert_eq!(d.count(), 50);
    }

    #[test]
    fn opsgenie_priority_mapping_for_low() {
        let d = WebhookDispatcher::new("og", WebhookStyle::Opsgenie, "https://api.opsgenie.com");
        let i = Incident::builder("x", IncidentSeverity::Low).build();
        let body = d.format_body(&i);
        assert!(body.contains("\"P4\""));
    }

    #[test]
    fn opsgenie_priority_mapping_for_critical() {
        let d = WebhookDispatcher::new("og", WebhookStyle::Opsgenie, "https://api.opsgenie.com");
        let i = Incident::builder("x", IncidentSeverity::Critical).build();
        let body = d.format_body(&i);
        assert!(body.contains("\"P1\""));
    }
}
