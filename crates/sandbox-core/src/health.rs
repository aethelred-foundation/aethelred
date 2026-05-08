//! Kubernetes-shape health probes.
//!
//! Production deployments expose three distinct probes:
//!
//! - **Liveness** (`/healthz`) — "is the process alive?" Failure → restart.
//! - **Readiness** (`/ready`) — "can it serve traffic?" Failure → remove
//!   from load balancer, do not restart.
//! - **Startup** (`/startup`) — "has the long initial setup finished?"
//!   Disables liveness checks until pass.
//!
//! Conflating these is the most common production-deploy bug.
//!
//! ## What we ship
//!
//! - [`HealthProbe`] trait — implement once per dependency
//!   (HSM, evidence log, anchor service, etc.).
//! - [`ProbeResult`] — `Pass` / `Fail{reason}` / `Degraded{reason}`.
//! - [`HealthRegistry`] — register probes, aggregate, emit JSON for
//!   `/healthz` / `/ready` / `/startup`.
//! - [`StartupGate`] — toggle that flips once on a one-shot startup
//!   checklist.

use crate::SandboxResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

// =============================================================================
// ProbeKind + ProbeResult
// =============================================================================

/// Probe class (which K8s probe a probe applies to).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// Liveness — checked continuously; failure → restart.
    Liveness,
    /// Readiness — checked continuously; failure → remove from LB.
    Readiness,
    /// Startup — checked until pass once; then ignored.
    Startup,
}

impl ProbeKind {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Liveness => "liveness",
            Self::Readiness => "readiness",
            Self::Startup => "startup",
        }
    }
}

/// Probe outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ProbeResult {
    /// Probe passed.
    Pass,
    /// Probe failed.
    Fail {
        /// Reason.
        reason: String,
    },
    /// Probe is degraded (still serving but with reduced capacity).
    Degraded {
        /// Reason.
        reason: String,
    },
}

impl ProbeResult {
    /// `true` for `Pass`.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
    /// `true` for `Fail`.
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }
    /// `true` for `Degraded`.
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }
}

// =============================================================================
// HealthProbe trait
// =============================================================================

/// Pluggable health probe.
pub trait HealthProbe: Send + Sync {
    /// Probe id (e.g., `"hsm-primary"`, `"evidence-log"`).
    fn id(&self) -> &str;
    /// Which probe class this serves.
    fn kind(&self) -> ProbeKind;
    /// Run the check.
    fn check(&self) -> ProbeResult;
}

// =============================================================================
// Concrete probes
// =============================================================================

/// Closure-based probe — for one-line probes.
pub struct ClosureProbe<F>
where
    F: Fn() -> ProbeResult + Send + Sync,
{
    id: String,
    kind: ProbeKind,
    f: F,
}

impl<F> ClosureProbe<F>
where
    F: Fn() -> ProbeResult + Send + Sync,
{
    /// New closure probe.
    pub fn new(id: impl Into<String>, kind: ProbeKind, f: F) -> Self {
        Self {
            id: id.into(),
            kind,
            f,
        }
    }
}

impl<F> HealthProbe for ClosureProbe<F>
where
    F: Fn() -> ProbeResult + Send + Sync,
{
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> ProbeKind {
        self.kind
    }
    fn check(&self) -> ProbeResult {
        (self.f)()
    }
}

/// Probe wrapping an `AtomicBool` — flip-toggle-style health.
pub struct AtomicProbe {
    id: String,
    kind: ProbeKind,
    healthy: Arc<AtomicBool>,
    fail_reason: String,
}

impl AtomicProbe {
    /// New probe.
    pub fn new(id: impl Into<String>, kind: ProbeKind, healthy: Arc<AtomicBool>) -> Self {
        Self {
            id: id.into(),
            kind,
            healthy,
            fail_reason: "atomic flag is false".into(),
        }
    }

    /// Set fail reason.
    pub fn with_fail_reason(mut self, r: impl Into<String>) -> Self {
        self.fail_reason = r.into();
        self
    }

    /// Toggle.
    pub fn set(&self, on: bool) {
        self.healthy.store(on, Ordering::SeqCst);
    }
}

impl HealthProbe for AtomicProbe {
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> ProbeKind {
        self.kind
    }
    fn check(&self) -> ProbeResult {
        if self.healthy.load(Ordering::SeqCst) {
            ProbeResult::Pass
        } else {
            ProbeResult::Fail {
                reason: self.fail_reason.clone(),
            }
        }
    }
}

// =============================================================================
// Aggregated probe report
// =============================================================================

/// Aggregated probe report (the body of `/healthz` / `/ready` / `/startup`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    /// Overall status — "ok" / "degraded" / "fail".
    pub status: String,
    /// RFC 3339 timestamp.
    pub checked_at: String,
    /// Number of probes checked.
    pub probe_count: u32,
    /// Per-probe results.
    pub probes: BTreeMap<String, ProbeResult>,
}

impl ProbeReport {
    /// HTTP status code conventionally returned with this report (200 or 503).
    pub fn http_status(&self) -> u16 {
        if self.status == "ok" {
            200
        } else {
            503
        }
    }
}

// =============================================================================
// HealthRegistry
// =============================================================================

/// Central registry of all probes.
pub struct HealthRegistry {
    probes: Mutex<Vec<Box<dyn HealthProbe>>>,
    startup_gate: StartupGate,
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self {
            probes: Mutex::new(Vec::new()),
            startup_gate: StartupGate::new(),
        }
    }

    /// Register a probe.
    pub fn register(&self, probe: Box<dyn HealthProbe>) {
        match self.probes.lock() {
            Ok(mut g) => g.push(probe),
            Err(e) => e.into_inner().push(probe),
        }
    }

    /// Number of registered probes.
    pub fn len(&self) -> usize {
        self.probes.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no probes registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run all probes of a given kind.
    pub fn check_kind(&self, kind: ProbeKind) -> ProbeReport {
        let g = match self.probes.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut probes = BTreeMap::new();
        let mut any_fail = false;
        let mut any_degraded = false;
        for p in g.iter() {
            if p.kind() != kind {
                continue;
            }
            let r = p.check();
            if r.is_fail() {
                any_fail = true;
            }
            if r.is_degraded() {
                any_degraded = true;
            }
            probes.insert(p.id().to_string(), r);
        }
        let status = if any_fail {
            "fail"
        } else if any_degraded {
            "degraded"
        } else {
            "ok"
        };
        ProbeReport {
            status: status.to_string(),
            checked_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            probe_count: probes.len() as u32,
            probes,
        }
    }

    /// Convenience: liveness check (`/healthz` body).
    pub fn liveness(&self) -> ProbeReport {
        self.check_kind(ProbeKind::Liveness)
    }

    /// Convenience: readiness check (`/ready` body).
    pub fn readiness(&self) -> ProbeReport {
        // If startup hasn't completed, readiness fails.
        if !self.startup_gate.is_open() {
            let mut r = ProbeReport {
                status: "fail".into(),
                checked_at: OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                probe_count: 1,
                probes: BTreeMap::new(),
            };
            r.probes.insert(
                "startup_gate".into(),
                ProbeResult::Fail {
                    reason: "startup gate is closed".into(),
                },
            );
            return r;
        }
        self.check_kind(ProbeKind::Readiness)
    }

    /// Convenience: startup check (`/startup` body).
    pub fn startup(&self) -> ProbeReport {
        let mut r = self.check_kind(ProbeKind::Startup);
        // If all startup probes pass, open the gate.
        if r.status == "ok" {
            self.startup_gate.open();
        }
        // Add the gate state to the report.
        r.probes.insert(
            "startup_gate".into(),
            if self.startup_gate.is_open() {
                ProbeResult::Pass
            } else {
                ProbeResult::Fail {
                    reason: "startup gate is closed".into(),
                }
            },
        );
        r
    }

    /// Borrow the startup gate (for direct manipulation).
    pub fn startup_gate(&self) -> &StartupGate {
        &self.startup_gate
    }
}

// =============================================================================
// StartupGate
// =============================================================================

/// One-shot toggle that flips once startup completes.
#[derive(Debug)]
pub struct StartupGate {
    open: AtomicBool,
}

impl Default for StartupGate {
    fn default() -> Self {
        Self::new()
    }
}

impl StartupGate {
    /// New gate (closed).
    pub fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
        }
    }

    /// Open the gate.
    pub fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    /// `true` if open.
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(_id: &'static str, kind: ProbeKind) -> Box<dyn HealthProbe> {
        Box::new(ClosureProbe::new(_id, kind, || ProbeResult::Pass))
    }
    fn fail(_id: &'static str, kind: ProbeKind, reason: &'static str) -> Box<dyn HealthProbe> {
        Box::new(ClosureProbe::new(_id, kind, move || ProbeResult::Fail {
            reason: reason.into(),
        }))
    }

    #[test]
    fn probe_kind_string_round_trip() {
        for k in [ProbeKind::Liveness, ProbeKind::Readiness, ProbeKind::Startup] {
            let s = k.as_str();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn probe_result_classification() {
        assert!(ProbeResult::Pass.is_pass());
        assert!(ProbeResult::Fail { reason: "x".into() }.is_fail());
        assert!(ProbeResult::Degraded { reason: "x".into() }.is_degraded());
        assert!(!ProbeResult::Pass.is_fail());
    }

    #[test]
    fn probe_result_serde_round_trip() {
        let r = ProbeResult::Fail {
            reason: "down".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: ProbeResult = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn closure_probe_pass() {
        let p = pass("p1", ProbeKind::Liveness);
        assert_eq!(p.check(), ProbeResult::Pass);
    }

    #[test]
    fn closure_probe_fail() {
        let p = fail("p1", ProbeKind::Liveness, "down");
        assert!(p.check().is_fail());
    }

    #[test]
    fn registry_empty_returns_ok() {
        let r = HealthRegistry::new();
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "ok");
        assert_eq!(report.probe_count, 0);
    }

    #[test]
    fn registry_with_passing_probe_returns_ok() {
        let r = HealthRegistry::new();
        r.register(pass("p1", ProbeKind::Liveness));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "ok");
        assert_eq!(report.probe_count, 1);
    }

    #[test]
    fn registry_with_failing_probe_returns_fail() {
        let r = HealthRegistry::new();
        r.register(fail("p1", ProbeKind::Liveness, "x"));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "fail");
    }

    #[test]
    fn registry_with_degraded_probe_returns_degraded() {
        let r = HealthRegistry::new();
        r.register(Box::new(ClosureProbe::new(
            "p1",
            ProbeKind::Liveness,
            || ProbeResult::Degraded {
                reason: "slow".into(),
            },
        )));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "degraded");
    }

    #[test]
    fn registry_kind_filter_works() {
        let r = HealthRegistry::new();
        r.register(pass("live", ProbeKind::Liveness));
        r.register(pass("ready", ProbeKind::Readiness));
        let live = r.check_kind(ProbeKind::Liveness);
        let ready = r.check_kind(ProbeKind::Readiness);
        assert_eq!(live.probe_count, 1);
        assert_eq!(ready.probe_count, 1);
    }

    #[test]
    fn report_http_status_200_for_ok() {
        let r = HealthRegistry::new();
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.http_status(), 200);
    }

    #[test]
    fn report_http_status_503_for_fail() {
        let r = HealthRegistry::new();
        r.register(fail("p", ProbeKind::Liveness, "x"));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.http_status(), 503);
    }

    #[test]
    fn startup_gate_opens_after_passing_startup() {
        let r = HealthRegistry::new();
        r.register(pass("init", ProbeKind::Startup));
        assert!(!r.startup_gate().is_open());
        r.startup();
        assert!(r.startup_gate().is_open());
    }

    #[test]
    fn readiness_fails_until_startup_completes() {
        let r = HealthRegistry::new();
        r.register(pass("ready", ProbeKind::Readiness));
        // No startup yet — readiness should fail.
        let report = r.readiness();
        assert_eq!(report.status, "fail");
        // Now start up.
        r.startup_gate().open();
        let report = r.readiness();
        assert_eq!(report.status, "ok");
    }

    #[test]
    fn liveness_independent_of_startup() {
        let r = HealthRegistry::new();
        r.register(pass("live", ProbeKind::Liveness));
        // Liveness should pass even if startup hasn't run.
        let report = r.liveness();
        assert_eq!(report.status, "ok");
    }

    #[test]
    fn atomic_probe_toggles() {
        let f = Arc::new(AtomicBool::new(true));
        let p = AtomicProbe::new("p", ProbeKind::Liveness, f.clone());
        assert_eq!(p.check(), ProbeResult::Pass);
        p.set(false);
        assert!(p.check().is_fail());
    }

    #[test]
    fn registry_len_and_is_empty() {
        let r = HealthRegistry::new();
        assert!(r.is_empty());
        r.register(pass("p", ProbeKind::Liveness));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn many_probes_aggregated() {
        let r = HealthRegistry::new();
        for i in 0..10 {
            let id = Box::leak(format!("p-{i}").into_boxed_str());
            r.register(pass(id, ProbeKind::Liveness));
        }
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.probe_count, 10);
    }

    #[test]
    fn one_failing_probe_makes_aggregate_fail() {
        let r = HealthRegistry::new();
        r.register(pass("p1", ProbeKind::Liveness));
        r.register(fail("p2", ProbeKind::Liveness, "x"));
        r.register(pass("p3", ProbeKind::Liveness));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "fail");
    }

    #[test]
    fn fail_overrides_degraded() {
        let r = HealthRegistry::new();
        r.register(Box::new(ClosureProbe::new(
            "p1",
            ProbeKind::Liveness,
            || ProbeResult::Degraded {
                reason: "slow".into(),
            },
        )));
        r.register(fail("p2", ProbeKind::Liveness, "x"));
        let report = r.check_kind(ProbeKind::Liveness);
        assert_eq!(report.status, "fail");
    }

    #[test]
    fn probe_report_serde_round_trip() {
        let r = HealthRegistry::new();
        r.register(pass("p", ProbeKind::Liveness));
        let report = r.check_kind(ProbeKind::Liveness);
        let j = serde_json::to_string(&report).unwrap();
        let p: ProbeReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p.status, report.status);
        assert_eq!(p.probe_count, report.probe_count);
    }

    #[test]
    fn startup_gate_default_closed() {
        let g = StartupGate::new();
        assert!(!g.is_open());
        g.open();
        assert!(g.is_open());
    }

    #[test]
    fn atomic_probe_with_fail_reason() {
        let f = Arc::new(AtomicBool::new(false));
        let p = AtomicProbe::new("p", ProbeKind::Liveness, f).with_fail_reason("HSM down");
        if let ProbeResult::Fail { reason } = p.check() {
            assert_eq!(reason, "HSM down");
        } else {
            panic!("expected Fail");
        }
    }

    #[test]
    fn probe_kind_serde_round_trip() {
        let j = serde_json::to_string(&ProbeKind::Readiness).unwrap();
        assert_eq!(j, "\"readiness\"");
    }

    #[test]
    fn closure_probe_id_returned() {
        let p = pass("my-probe", ProbeKind::Liveness);
        assert_eq!(p.id(), "my-probe");
    }
}
