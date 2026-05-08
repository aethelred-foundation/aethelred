//! Tenant quota watermark alerts.
//!
//! Wraps any quota counter (seal mints, storage GB, API calls) and emits
//! [`QuotaAlert`]s when usage crosses configurable watermarks
//! (e.g. 50% / 75% / 90% / 100% of the limit).
//!
//! Designed so each watermark fires *exactly once* per period — no spam.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// QuotaKind
// =============================================================================

/// Quota kind label.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuotaKind(pub String);

impl QuotaKind {
    /// New.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// AlertLevel
// =============================================================================

/// Severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertLevel {
    /// Approaching usage cap.
    Info,
    /// Warning — significant utilization.
    Warning,
    /// Critical — near or at cap.
    Critical,
    /// Cap reached.
    CapReached,
}

// =============================================================================
// Watermark
// =============================================================================

/// One watermark threshold.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Watermark {
    /// Percentage of cap (0..=100).
    pub pct: u32,
    /// Level fired at this percentage.
    pub level: AlertLevel,
}

impl Watermark {
    /// New.
    pub fn new(pct: u32, level: AlertLevel) -> Self {
        Self { pct, level }
    }
}

/// Standard 4-tier watermarks.
pub fn standard_watermarks() -> Vec<Watermark> {
    vec![
        Watermark::new(50, AlertLevel::Info),
        Watermark::new(75, AlertLevel::Warning),
        Watermark::new(90, AlertLevel::Critical),
        Watermark::new(100, AlertLevel::CapReached),
    ]
}

// =============================================================================
// QuotaAlert
// =============================================================================

/// One emitted alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuotaAlert {
    /// Stable id.
    pub alert_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Kind.
    pub kind: QuotaKind,
    /// Period.
    pub period: String,
    /// Watermark level.
    pub level: AlertLevel,
    /// Watermark pct.
    pub pct: u32,
    /// Current usage.
    pub current_usage: i64,
    /// Cap.
    pub cap: i64,
    /// RFC 3339.
    pub at: String,
}

// =============================================================================
// QuotaTracker
// =============================================================================

#[derive(Default)]
struct QuotaState {
    /// `(tenant, kind, period)` → cap.
    caps: HashMap<(String, QuotaKind, String), i64>,
    /// `(tenant, kind, period)` → cumulative usage.
    usage: HashMap<(String, QuotaKind, String), i64>,
    /// `(tenant, kind, period)` → set of fired pct levels (so each fires once).
    fired: HashMap<(String, QuotaKind, String), HashSet<u32>>,
    /// All alerts, in order.
    alerts: Vec<QuotaAlert>,
    /// Watermarks per `kind`.
    watermarks: HashMap<QuotaKind, Vec<Watermark>>,
}

/// Tracker.
pub struct QuotaAlertTracker {
    state: RwLock<QuotaState>,
}

impl Default for QuotaAlertTracker {
    fn default() -> Self {
        Self {
            state: RwLock::new(QuotaState::default()),
        }
    }
}

impl std::fmt::Debug for QuotaAlertTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuotaAlertTracker")
            .field("alerts", &self.alert_count())
            .finish()
    }
}

impl QuotaAlertTracker {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure watermarks for a quota kind.
    pub fn set_watermarks(&self, kind: QuotaKind, watermarks: Vec<Watermark>) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("quota tracker poisoned".into()))?
            .watermarks
            .insert(kind, watermarks);
        Ok(())
    }

    /// Set cap.
    pub fn set_cap(
        &self,
        tenant: impl Into<String>,
        kind: QuotaKind,
        period: impl Into<String>,
        cap: i64,
    ) -> SandboxResult<()> {
        if cap <= 0 {
            return Err(SandboxError::Other("cap must be > 0".into()));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("quota tracker poisoned".into()))?
            .caps
            .insert((tenant.into(), kind, period.into()), cap);
        Ok(())
    }

    /// Record usage; returns any newly-fired alerts.
    pub fn record(
        &self,
        tenant: impl Into<String>,
        kind: QuotaKind,
        period: impl Into<String>,
        delta: i64,
    ) -> SandboxResult<Vec<QuotaAlert>> {
        if delta < 0 {
            return Err(SandboxError::Other("delta must be non-negative".into()));
        }
        let tenant = tenant.into();
        let period = period.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("quota tracker poisoned".into()))?;
        let key = (tenant.clone(), kind.clone(), period.clone());
        let entry = g.usage.entry(key.clone()).or_insert(0);
        *entry += delta;
        let usage = *entry;
        // Look up cap and watermarks.
        let cap = match g.caps.get(&key) {
            Some(c) => *c,
            None => return Ok(Vec::new()),
        };
        let watermarks = g
            .watermarks
            .get(&kind)
            .cloned()
            .unwrap_or_else(standard_watermarks);
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let pct_now = if cap > 0 {
            (usage * 100 / cap).min(i64::MAX) as u32
        } else {
            0
        };
        let mut new_alerts = Vec::new();
        // Sort watermarks by pct ascending for stable iteration.
        let mut wms = watermarks.clone();
        wms.sort_by_key(|w| w.pct);
        // Snapshot the currently-fired set, then update through the map directly.
        let already_fired: HashSet<u32> = g
            .fired
            .get(&key)
            .cloned()
            .unwrap_or_default();
        for w in &wms {
            if pct_now >= w.pct && !already_fired.contains(&w.pct) {
                let a = QuotaAlert {
                    alert_id: Uuid::now_v7(),
                    tenant_id: tenant.clone(),
                    kind: kind.clone(),
                    period: period.clone(),
                    level: w.level,
                    pct: w.pct,
                    current_usage: usage,
                    cap,
                    at: now.clone(),
                };
                new_alerts.push(a.clone());
                g.alerts.push(a);
                g.fired.entry(key.clone()).or_default().insert(w.pct);
            }
        }
        Ok(new_alerts)
    }

    /// Look up usage.
    pub fn usage(&self, tenant: &str, kind: &QuotaKind, period: &str) -> i64 {
        self.state
            .read()
            .map(|g| {
                g.usage
                    .get(&(tenant.to_string(), kind.clone(), period.to_string()))
                    .copied()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    /// Look up cap.
    pub fn cap(&self, tenant: &str, kind: &QuotaKind, period: &str) -> Option<i64> {
        self.state
            .read()
            .ok()?
            .caps
            .get(&(tenant.to_string(), kind.clone(), period.to_string()))
            .copied()
    }

    /// All alerts.
    pub fn alerts(&self) -> Vec<QuotaAlert> {
        self.state.read().map(|g| g.alerts.clone()).unwrap_or_default()
    }

    /// Alerts for a tenant + period.
    pub fn alerts_for(&self, tenant: &str, period: &str) -> Vec<QuotaAlert> {
        self.alerts()
            .into_iter()
            .filter(|a| a.tenant_id == tenant && a.period == period)
            .collect()
    }

    /// Reset firing state for new period.
    pub fn reset(&self, tenant: &str, kind: &QuotaKind, period: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("quota tracker poisoned".into()))?;
        let key = (tenant.to_string(), kind.clone(), period.to_string());
        g.usage.remove(&key);
        g.fired.remove(&key);
        Ok(())
    }

    /// Total alerts.
    pub fn alert_count(&self) -> usize {
        self.state.read().map(|g| g.alerts.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k() -> QuotaKind {
        QuotaKind::new("seal-mints")
    }

    #[test]
    fn standard_watermarks_4_tiers() {
        let w = standard_watermarks();
        assert_eq!(w.len(), 4);
    }

    #[test]
    fn record_under_50pct_no_alert() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let alerts = t.record("FAB", k(), "2026-05", 25).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn record_at_50pct_fires_info() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let alerts = t.record("FAB", k(), "2026-05", 50).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].level, AlertLevel::Info);
    }

    #[test]
    fn jumping_to_100_fires_all_levels() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let alerts = t.record("FAB", k(), "2026-05", 100).unwrap();
        // All four levels should fire since we crossed all watermarks.
        assert_eq!(alerts.len(), 4);
    }

    #[test]
    fn watermark_fires_exactly_once() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let a1 = t.record("FAB", k(), "2026-05", 50).unwrap();
        assert_eq!(a1.len(), 1);
        let a2 = t.record("FAB", k(), "2026-05", 1).unwrap();
        // Still at 51% — same Info watermark, no new alert.
        assert!(a2.is_empty());
    }

    #[test]
    fn no_cap_no_alert() {
        let t = QuotaAlertTracker::new();
        let alerts = t.record("FAB", k(), "2026-05", 1000).unwrap();
        assert!(alerts.is_empty());
    }

    #[test]
    fn negative_delta_errors() {
        let t = QuotaAlertTracker::new();
        assert!(t.record("FAB", k(), "2026-05", -1).is_err());
    }

    #[test]
    fn set_cap_zero_errors() {
        let t = QuotaAlertTracker::new();
        assert!(t.set_cap("FAB", k(), "2026-05", 0).is_err());
    }

    #[test]
    fn usage_returns_cumulative() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 1000).unwrap();
        for _ in 0..5 {
            t.record("FAB", k(), "2026-05", 10).unwrap();
        }
        assert_eq!(t.usage("FAB", &k(), "2026-05"), 50);
    }

    #[test]
    fn cap_lookup_works() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        assert_eq!(t.cap("FAB", &k(), "2026-05"), Some(100));
    }

    #[test]
    fn reset_clears_state() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        t.record("FAB", k(), "2026-05", 50).unwrap();
        t.reset("FAB", &k(), "2026-05").unwrap();
        assert_eq!(t.usage("FAB", &k(), "2026-05"), 0);
        // After reset, hitting 50 again fires the alert again.
        let alerts = t.record("FAB", k(), "2026-05", 50).unwrap();
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn alerts_for_tenant_filters() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        t.set_cap("ENBD", k(), "2026-05", 100).unwrap();
        t.record("FAB", k(), "2026-05", 50).unwrap();
        t.record("ENBD", k(), "2026-05", 50).unwrap();
        assert_eq!(t.alerts_for("FAB", "2026-05").len(), 1);
        assert_eq!(t.alerts_for("ENBD", "2026-05").len(), 1);
    }

    #[test]
    fn custom_watermarks_used() {
        let t = QuotaAlertTracker::new();
        t.set_watermarks(
            k(),
            vec![
                Watermark::new(80, AlertLevel::Warning),
                Watermark::new(100, AlertLevel::CapReached),
            ],
        )
        .unwrap();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let a1 = t.record("FAB", k(), "2026-05", 50).unwrap();
        assert!(a1.is_empty()); // 50% → custom doesn't have 50
        let a2 = t.record("FAB", k(), "2026-05", 30).unwrap();
        assert_eq!(a2.len(), 1); // 80% → Warning
    }

    #[test]
    fn alert_serde() {
        let a = QuotaAlert {
            alert_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            kind: k(),
            period: "2026-05".into(),
            level: AlertLevel::Critical,
            pct: 90,
            current_usage: 90,
            cap: 100,
            at: "t".into(),
        };
        let j = serde_json::to_string(&a).unwrap();
        let p: QuotaAlert = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn watermark_serde() {
        let w = Watermark::new(75, AlertLevel::Warning);
        let j = serde_json::to_string(&w).unwrap();
        let p: Watermark = serde_json::from_str(&j).unwrap();
        assert_eq!(p, w);
    }

    #[test]
    fn level_serde() {
        for l in [
            AlertLevel::Info,
            AlertLevel::Warning,
            AlertLevel::Critical,
            AlertLevel::CapReached,
        ] {
            let j = serde_json::to_string(&l).unwrap();
            let p: AlertLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, l);
        }
    }

    #[test]
    fn quota_kind_serde_transparent() {
        let kk = QuotaKind::new("api-calls");
        assert_eq!(serde_json::to_string(&kk).unwrap(), "\"api-calls\"");
    }

    #[test]
    fn record_at_75_fires_info_and_warning() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let alerts = t.record("FAB", k(), "2026-05", 75).unwrap();
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn at_cap_fires_cap_reached() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        let alerts = t.record("FAB", k(), "2026-05", 100).unwrap();
        assert!(alerts.iter().any(|a| a.level == AlertLevel::CapReached));
    }

    #[test]
    fn isolated_per_period() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        t.set_cap("FAB", k(), "2026-06", 100).unwrap();
        t.record("FAB", k(), "2026-05", 50).unwrap();
        let a = t.record("FAB", k(), "2026-06", 50).unwrap();
        assert_eq!(a.len(), 1); // fresh period fires its own
    }

    #[test]
    fn many_records_no_duplicate_alerts() {
        let t = QuotaAlertTracker::new();
        t.set_cap("FAB", k(), "2026-05", 100).unwrap();
        for _ in 0..20 {
            t.record("FAB", k(), "2026-05", 5).unwrap();
        }
        // Total usage = 100, so all 4 levels should have fired exactly once.
        assert_eq!(t.alerts_for("FAB", "2026-05").len(), 4);
    }
}
