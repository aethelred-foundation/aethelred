//! Service Level Objectives (SLOs), error budgets, and burn-rate alerting.
//!
//! Maps Google SRE workbook concepts to the sandbox:
//!
//! - **SLI** (Service Level Indicator) — a measured success ratio
//!   (`good / total`).
//! - **SLO** (Service Level Objective) — the target for that SLI
//!   (e.g., 99.9% over 30 days).
//! - **Error budget** — `(1 - SLO) * total`: the failures you're allowed.
//! - **Burn rate** — how fast you're consuming the budget; `1×` means
//!   spending it linearly, `14.4×` means you'd burn the full 30-day budget
//!   in ~50 hours.
//!
//! Use [`SloDefinition`], record events via [`SloRegistry::record`], and
//! query [`SloStatus`] for compliance, error-budget remaining, and burn
//! rates over multiple windows.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::{Duration, OffsetDateTime};

// =============================================================================
// SloId
// =============================================================================

/// Stable id for one SLO.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SloId(pub String);

impl SloId {
    /// New id.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// SloDefinition
// =============================================================================

/// One SLO definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SloDefinition {
    /// Stable id (e.g., `"seal-mint-availability"`).
    pub id: SloId,
    /// Human-readable name.
    pub name: String,
    /// Target ratio in `[0.0, 1.0]` (e.g., `0.999`).
    pub target: f64,
    /// Compliance window in seconds (e.g., 30 days = 2,592,000).
    pub window_seconds: i64,
}

impl SloDefinition {
    /// New SLO with explicit fields.
    pub fn new(id: SloId, name: impl Into<String>, target: f64, window: Duration) -> Self {
        Self {
            id,
            name: name.into(),
            target,
            window_seconds: window.whole_seconds(),
        }
    }

    /// `(1 - target)` — the failure ratio that exhausts the budget.
    pub fn allowed_failure_ratio(&self) -> f64 {
        1.0 - self.target
    }
}

// =============================================================================
// SloEvent
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SloEvent {
    at: i64, // unix seconds
    success: bool,
}

// =============================================================================
// SloStatus
// =============================================================================

/// Aggregate status snapshot for one SLO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SloStatus {
    /// Definition id.
    pub id: SloId,
    /// Total events counted in the window.
    pub total: u64,
    /// Successful events.
    pub good: u64,
    /// Failed events.
    pub bad: u64,
    /// Achieved ratio over the window.
    pub achieved_ratio: f64,
    /// `true` if `achieved_ratio >= target`.
    pub compliant: bool,
    /// Error budget remaining in `[0.0, 1.0]`. 0 = exhausted, 1 = unused.
    pub budget_remaining_ratio: f64,
    /// Burn rates over short / medium / long windows (1h / 6h / 24h).
    pub burn_rates: BurnRates,
}

/// Burn rates over standard reference windows.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BurnRates {
    /// Burn rate over the last 1 hour.
    pub one_hour: f64,
    /// Burn rate over the last 6 hours.
    pub six_hours: f64,
    /// Burn rate over the last 24 hours.
    pub twenty_four_hours: f64,
}

/// A burn-rate alert classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnAlert {
    /// No alert.
    Ok,
    /// Sustained slow burn — likely a regression.
    SlowBurn,
    /// Fast burn — alert paging.
    FastBurn,
    /// Critical — budget exhausted at current rate within hours.
    Critical,
}

// =============================================================================
// SloRegistry
// =============================================================================

#[derive(Default)]
struct SloState {
    defs: HashMap<SloId, SloDefinition>,
    events: HashMap<SloId, Vec<SloEvent>>,
}

/// Per-SLO registry.
#[derive(Default)]
pub struct SloRegistry {
    state: RwLock<SloState>,
}

impl std::fmt::Debug for SloRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SloRegistry")
            .field("slos", &self.state.read().map(|g| g.defs.len()).unwrap_or(0))
            .finish()
    }
}

impl SloRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an SLO definition. Errors on bad target ratio.
    pub fn register(&self, def: SloDefinition) -> SandboxResult<()> {
        if !(def.target > 0.0 && def.target < 1.0) {
            return Err(SandboxError::Other(format!(
                "slo target must be in (0,1), got {}",
                def.target
            )));
        }
        if def.window_seconds <= 0 {
            return Err(SandboxError::Other("slo window must be positive".into()));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("slo registry poisoned".into()))?;
        g.events.entry(def.id.clone()).or_default();
        g.defs.insert(def.id.clone(), def);
        Ok(())
    }

    /// Record one observation now.
    pub fn record(&self, slo: &SloId, success: bool) -> SandboxResult<()> {
        self.record_at(slo, success, OffsetDateTime::now_utc())
    }

    /// Record one observation at a specific instant (for testing).
    pub fn record_at(
        &self,
        slo: &SloId,
        success: bool,
        at: OffsetDateTime,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("slo registry poisoned".into()))?;
        if !g.defs.contains_key(slo) {
            return Err(SandboxError::Other(format!(
                "unknown slo: {}",
                slo.as_str()
            )));
        }
        g.events.entry(slo.clone()).or_default().push(SloEvent {
            at: at.unix_timestamp(),
            success,
        });
        Ok(())
    }

    /// All registered SLO ids.
    pub fn ids(&self) -> Vec<SloId> {
        self.state
            .read()
            .map(|g| g.defs.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// `true` if the SLO is registered.
    pub fn is_registered(&self, slo: &SloId) -> bool {
        self.state
            .read()
            .map(|g| g.defs.contains_key(slo))
            .unwrap_or(false)
    }

    /// Compute current status for one SLO.
    pub fn status(&self, slo: &SloId) -> SandboxResult<SloStatus> {
        self.status_at(slo, OffsetDateTime::now_utc())
    }

    /// Compute status as of `now` (for tests).
    pub fn status_at(&self, slo: &SloId, now: OffsetDateTime) -> SandboxResult<SloStatus> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("slo registry poisoned".into()))?;
        let def = g
            .defs
            .get(slo)
            .ok_or_else(|| SandboxError::Other(format!("unknown slo: {}", slo.as_str())))?
            .clone();
        let events = g.events.get(slo).cloned().unwrap_or_default();
        drop(g);

        let now_ts = now.unix_timestamp();
        let window_lo = now_ts - def.window_seconds;
        let in_window: Vec<&SloEvent> = events.iter().filter(|e| e.at >= window_lo).collect();
        let total = in_window.len() as u64;
        let good = in_window.iter().filter(|e| e.success).count() as u64;
        let bad = total - good;
        let achieved = if total == 0 { 1.0 } else { good as f64 / total as f64 };
        let allowed_failures = def.allowed_failure_ratio() * total.max(1) as f64;
        let budget_remaining = if allowed_failures == 0.0 {
            0.0
        } else {
            ((allowed_failures - bad as f64) / allowed_failures).clamp(0.0, 1.0)
        };

        // Burn rates over reference windows.
        let burn = BurnRates {
            one_hour: burn_rate(&events, &def, now_ts, 60 * 60),
            six_hours: burn_rate(&events, &def, now_ts, 6 * 60 * 60),
            twenty_four_hours: burn_rate(&events, &def, now_ts, 24 * 60 * 60),
        };
        Ok(SloStatus {
            id: def.id,
            total,
            good,
            bad,
            achieved_ratio: achieved,
            compliant: achieved >= def.target,
            budget_remaining_ratio: budget_remaining,
            burn_rates: burn,
        })
    }

    /// Drop events outside every registered SLO's window — keeps memory bounded.
    pub fn prune(&self) -> SandboxResult<usize> {
        self.prune_at(OffsetDateTime::now_utc())
    }

    /// Prune as of a given time (for tests).
    pub fn prune_at(&self, now: OffsetDateTime) -> SandboxResult<usize> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("slo registry poisoned".into()))?;
        let now_ts = now.unix_timestamp();
        let mut pruned = 0usize;
        // Map SloId → window_seconds copy so we don't hold &g while mutating.
        let windows: HashMap<SloId, i64> = g
            .defs
            .iter()
            .map(|(k, v)| (k.clone(), v.window_seconds))
            .collect();
        for (id, win) in windows {
            if let Some(v) = g.events.get_mut(&id) {
                let before = v.len();
                v.retain(|e| e.at >= now_ts - win);
                pruned += before - v.len();
            }
        }
        Ok(pruned)
    }
}

fn burn_rate(events: &[SloEvent], def: &SloDefinition, now_ts: i64, span_seconds: i64) -> f64 {
    let lo = now_ts - span_seconds;
    let win_events: Vec<&SloEvent> = events.iter().filter(|e| e.at >= lo).collect();
    let total = win_events.len() as f64;
    if total == 0.0 {
        return 0.0;
    }
    let bad = win_events.iter().filter(|e| !e.success).count() as f64;
    let observed_failure_ratio = bad / total;
    let allowed = def.allowed_failure_ratio();
    if allowed == 0.0 {
        // Zero error budget means *any* failure is infinite burn — surface as
        // a large but finite sentinel for callers that don't want NaN.
        return if bad > 0.0 { f64::MAX } else { 0.0 };
    }
    observed_failure_ratio / allowed
}

/// Classify a [`BurnRates`] sample. Thresholds match Google SRE workbook
/// suggestions: critical = 14.4× / 1h, fast = 6× / 6h, slow = 1× / 24h.
pub fn classify_burn(b: &BurnRates) -> BurnAlert {
    if b.one_hour >= 14.4 {
        BurnAlert::Critical
    } else if b.six_hours >= 6.0 {
        BurnAlert::FastBurn
    } else if b.twenty_four_hours >= 1.0 {
        BurnAlert::SlowBurn
    } else {
        BurnAlert::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(target: f64) -> SloDefinition {
        SloDefinition::new(SloId::new("seal-mint"), "Seal mint availability", target, Duration::days(30))
    }

    #[test]
    fn allowed_failure_ratio_correct() {
        assert!((def(0.99).allowed_failure_ratio() - 0.01).abs() < 1e-9);
        assert!((def(0.999).allowed_failure_ratio() - 0.001).abs() < 1e-9);
    }

    #[test]
    fn register_rejects_invalid_target() {
        let r = SloRegistry::new();
        assert!(r.register(def(0.0)).is_err());
        assert!(r.register(def(1.0)).is_err());
        assert!(r.register(def(-0.1)).is_err());
    }

    #[test]
    fn register_rejects_zero_window() {
        let r = SloRegistry::new();
        assert!(r
            .register(SloDefinition::new(
                SloId::new("x"),
                "x",
                0.99,
                Duration::seconds(0)
            ))
            .is_err());
    }

    #[test]
    fn register_succeeds() {
        let r = SloRegistry::new();
        assert!(r.register(def(0.99)).is_ok());
        assert!(r.is_registered(&SloId::new("seal-mint")));
    }

    #[test]
    fn record_unknown_errors() {
        let r = SloRegistry::new();
        assert!(r.record(&SloId::new("ghost"), true).is_err());
    }

    #[test]
    fn status_with_no_events_is_compliant_at_max_budget() {
        let r = SloRegistry::new();
        r.register(def(0.999)).unwrap();
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert_eq!(s.total, 0);
        assert_eq!(s.good, 0);
        assert!(s.compliant);
    }

    #[test]
    fn status_all_success_at_one_hundred_percent() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        for _ in 0..100 {
            r.record(&SloId::new("seal-mint"), true).unwrap();
        }
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert!(s.compliant);
        assert!((s.achieved_ratio - 1.0).abs() < 1e-9);
        assert!((s.budget_remaining_ratio - 1.0).abs() < 1e-9);
    }

    #[test]
    fn status_failures_burn_budget() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        // 100 events, 1 failure → exactly at budget (0% remaining).
        for _ in 0..99 {
            r.record(&SloId::new("seal-mint"), true).unwrap();
        }
        r.record(&SloId::new("seal-mint"), false).unwrap();
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert_eq!(s.bad, 1);
        assert!((s.budget_remaining_ratio - 0.0).abs() < 1e-9);
    }

    #[test]
    fn status_excess_failures_breach_slo() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        for _ in 0..50 {
            r.record(&SloId::new("seal-mint"), true).unwrap();
        }
        for _ in 0..5 {
            r.record(&SloId::new("seal-mint"), false).unwrap();
        }
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert!(!s.compliant, "5/55 = ~9% bad violates 1% budget");
    }

    #[test]
    fn events_outside_window_excluded() {
        let r = SloRegistry::new();
        // Tiny window: 1 minute.
        let d = SloDefinition::new(
            SloId::new("x"),
            "x",
            0.99,
            Duration::minutes(1),
        );
        r.register(d).unwrap();
        let now = OffsetDateTime::now_utc();
        // 1 hour ago — outside window.
        r.record_at(&SloId::new("x"), false, now - Duration::hours(1))
            .unwrap();
        // Now — inside.
        r.record_at(&SloId::new("x"), true, now).unwrap();
        let s = r.status_at(&SloId::new("x"), now).unwrap();
        assert_eq!(s.total, 1, "old event excluded");
    }

    #[test]
    fn burn_rate_zero_when_all_success() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        let now = OffsetDateTime::now_utc();
        for _ in 0..50 {
            r.record_at(&SloId::new("seal-mint"), true, now).unwrap();
        }
        let s = r.status_at(&SloId::new("seal-mint"), now).unwrap();
        assert_eq!(s.burn_rates.one_hour, 0.0);
    }

    #[test]
    fn burn_rate_increases_with_failures() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        let now = OffsetDateTime::now_utc();
        for _ in 0..90 {
            r.record_at(&SloId::new("seal-mint"), true, now).unwrap();
        }
        for _ in 0..10 {
            r.record_at(&SloId::new("seal-mint"), false, now).unwrap();
        }
        let s = r.status_at(&SloId::new("seal-mint"), now).unwrap();
        // 10/100 failures = 10% observed, allowed 1% → burn = 10x.
        assert!((s.burn_rates.one_hour - 10.0).abs() < 1e-6);
    }

    #[test]
    fn classify_burn_thresholds() {
        let b = BurnRates {
            one_hour: 0.5,
            six_hours: 0.0,
            twenty_four_hours: 0.0,
        };
        assert_eq!(classify_burn(&b), BurnAlert::Ok);

        let b = BurnRates {
            one_hour: 0.0,
            six_hours: 0.0,
            twenty_four_hours: 1.5,
        };
        assert_eq!(classify_burn(&b), BurnAlert::SlowBurn);

        let b = BurnRates {
            one_hour: 0.0,
            six_hours: 6.5,
            twenty_four_hours: 0.0,
        };
        assert_eq!(classify_burn(&b), BurnAlert::FastBurn);

        let b = BurnRates {
            one_hour: 14.5,
            six_hours: 0.0,
            twenty_four_hours: 0.0,
        };
        assert_eq!(classify_burn(&b), BurnAlert::Critical);
    }

    #[test]
    fn ids_returns_all_registered() {
        let r = SloRegistry::new();
        r.register(SloDefinition::new(
            SloId::new("a"),
            "a",
            0.99,
            Duration::days(30),
        ))
        .unwrap();
        r.register(SloDefinition::new(
            SloId::new("b"),
            "b",
            0.95,
            Duration::days(7),
        ))
        .unwrap();
        let mut ids = r.ids();
        ids.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(ids, vec![SloId::new("a"), SloId::new("b")]);
    }

    #[test]
    fn prune_drops_old_events() {
        let r = SloRegistry::new();
        let d = SloDefinition::new(SloId::new("x"), "x", 0.99, Duration::hours(1));
        r.register(d).unwrap();
        let now = OffsetDateTime::now_utc();
        r.record_at(&SloId::new("x"), true, now - Duration::hours(2))
            .unwrap();
        r.record_at(&SloId::new("x"), true, now - Duration::hours(2))
            .unwrap();
        let dropped = r.prune_at(now).unwrap();
        assert_eq!(dropped, 2);
    }

    #[test]
    fn slo_definition_serde_round_trip() {
        let d = def(0.999);
        let j = serde_json::to_string(&d).unwrap();
        let p: SloDefinition = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn slo_status_serde_round_trip() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        for _ in 0..3 {
            r.record(&SloId::new("seal-mint"), true).unwrap();
        }
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        let j = serde_json::to_string(&s).unwrap();
        let p: SloStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn burn_alert_serde_round_trip() {
        for a in [
            BurnAlert::Ok,
            BurnAlert::SlowBurn,
            BurnAlert::FastBurn,
            BurnAlert::Critical,
        ] {
            let j = serde_json::to_string(&a).unwrap();
            let p: BurnAlert = serde_json::from_str(&j).unwrap();
            assert_eq!(p, a);
        }
    }

    #[test]
    fn double_register_overwrites_definition() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        r.register(def(0.999)).unwrap();
        // Status should reflect new definition.
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert!(s.compliant); // empty events
    }

    #[test]
    fn slo_id_serde_transparent() {
        let id = SloId::new("x");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"x\"");
    }

    #[test]
    fn unknown_slo_status_errors() {
        let r = SloRegistry::new();
        assert!(r.status(&SloId::new("ghost")).is_err());
    }

    #[test]
    fn burn_rate_six_hour_window_independent_of_24h() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        let now = OffsetDateTime::now_utc();
        // Failures 12 hours ago — inside 24h, outside 6h.
        for _ in 0..50 {
            r.record_at(&SloId::new("seal-mint"), false, now - Duration::hours(12))
                .unwrap();
        }
        let s = r.status_at(&SloId::new("seal-mint"), now).unwrap();
        assert_eq!(s.burn_rates.six_hours, 0.0);
        assert!(s.burn_rates.twenty_four_hours > 0.0);
    }

    #[test]
    fn many_records_no_panic() {
        let r = SloRegistry::new();
        r.register(def(0.99)).unwrap();
        for i in 0..1000 {
            r.record(&SloId::new("seal-mint"), i % 100 != 0).unwrap();
        }
        let s = r.status(&SloId::new("seal-mint")).unwrap();
        assert_eq!(s.total, 1000);
        assert_eq!(s.bad, 10);
    }
}
