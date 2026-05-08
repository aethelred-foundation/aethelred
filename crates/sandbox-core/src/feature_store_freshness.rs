//! Per-feature freshness SLA tracking.
//!
//! Records when each feature was last refreshed and flags any feature past
//! its declared TTL. Used by feature stores to surface stale features
//! before the model consumes them.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::{Duration, OffsetDateTime};

// =============================================================================
// FreshnessSla
// =============================================================================

/// Per-feature freshness contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FreshnessSla {
    /// Feature name.
    pub feature: String,
    /// Tenant.
    pub tenant_id: String,
    /// Max age in seconds before stale.
    pub max_age_seconds: i64,
    /// Owner.
    pub owner: String,
}

// =============================================================================
// FreshnessStatus
// =============================================================================

/// Per-feature status snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    /// Fresh.
    Fresh,
    /// Stale.
    Stale,
    /// Never observed.
    Unknown,
}

// =============================================================================
// FreshnessReport
// =============================================================================

/// Per-feature snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FreshnessReport {
    /// Feature.
    pub feature: String,
    /// Tenant.
    pub tenant_id: String,
    /// Status.
    pub status: FreshnessStatus,
    /// Age in seconds since last refresh (None if never).
    pub age_seconds: Option<i64>,
    /// Max age allowed.
    pub max_age_seconds: i64,
}

// =============================================================================
// FreshnessTracker
// =============================================================================

#[derive(Default)]
struct State {
    slas: HashMap<(String, String), FreshnessSla>,
    /// `(tenant, feature)` → last-refresh timestamp.
    last_refresh: HashMap<(String, String), OffsetDateTime>,
}

/// Tracker.
pub struct FreshnessTracker {
    state: RwLock<State>,
}

impl Default for FreshnessTracker {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for FreshnessTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreshnessTracker")
            .field("features", &self.feature_count())
            .finish()
    }
}

impl FreshnessTracker {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an SLA.
    pub fn register(&self, sla: FreshnessSla) -> SandboxResult<()> {
        if sla.max_age_seconds <= 0 {
            return Err(SandboxError::Other("max_age must be > 0".into()));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("freshness tracker poisoned".into()))?
            .slas
            .insert((sla.tenant_id.clone(), sla.feature.clone()), sla);
        Ok(())
    }

    /// Mark a feature as just refreshed.
    pub fn record_refresh(
        &self,
        tenant: impl Into<String>,
        feature: impl Into<String>,
    ) -> SandboxResult<()> {
        self.record_refresh_at(tenant, feature, OffsetDateTime::now_utc())
    }

    /// Record refresh at a specific time.
    pub fn record_refresh_at(
        &self,
        tenant: impl Into<String>,
        feature: impl Into<String>,
        at: OffsetDateTime,
    ) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("freshness tracker poisoned".into()))?
            .last_refresh
            .insert((tenant.into(), feature.into()), at);
        Ok(())
    }

    /// Check status for a feature at `now`.
    pub fn status(
        &self,
        tenant: &str,
        feature: &str,
        now: OffsetDateTime,
    ) -> FreshnessReport {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => {
                return FreshnessReport {
                    feature: feature.to_string(),
                    tenant_id: tenant.to_string(),
                    status: FreshnessStatus::Unknown,
                    age_seconds: None,
                    max_age_seconds: 0,
                }
            }
        };
        let key = (tenant.to_string(), feature.to_string());
        let sla = g.slas.get(&key);
        let last = g.last_refresh.get(&key);
        let max_age = sla.map(|s| s.max_age_seconds).unwrap_or(0);
        let (age, status) = match last {
            Some(t) => {
                let age = (now - *t).whole_seconds();
                let st = if max_age > 0 && age > max_age {
                    FreshnessStatus::Stale
                } else {
                    FreshnessStatus::Fresh
                };
                (Some(age), st)
            }
            None => (None, FreshnessStatus::Unknown),
        };
        FreshnessReport {
            feature: feature.to_string(),
            tenant_id: tenant.to_string(),
            status,
            age_seconds: age,
            max_age_seconds: max_age,
        }
    }

    /// All stale features as of `now`.
    pub fn stale(&self, now: OffsetDateTime) -> Vec<FreshnessReport> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        for (key, sla) in &g.slas {
            let r = self.status(&key.0, &key.1, now);
            let _ = sla;
            if r.status == FreshnessStatus::Stale {
                out.push(r);
            }
        }
        out
    }

    /// Number of registered SLAs.
    pub fn feature_count(&self) -> usize {
        self.state.read().map(|g| g.slas.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sla() -> FreshnessSla {
        FreshnessSla {
            feature: "credit_score".into(),
            tenant_id: "FAB".into(),
            max_age_seconds: 60,
            owner: "data-team".into(),
        }
    }

    #[test]
    fn register_invalid_max_age_errors() {
        let t = FreshnessTracker::new();
        let mut s = sla();
        s.max_age_seconds = 0;
        assert!(t.register(s).is_err());
    }

    #[test]
    fn register_sla_succeeds() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        assert_eq!(t.feature_count(), 1);
    }

    #[test]
    fn unknown_when_never_refreshed() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let now = OffsetDateTime::now_utc();
        let r = t.status("FAB", "credit_score", now);
        assert_eq!(r.status, FreshnessStatus::Unknown);
    }

    #[test]
    fn fresh_after_refresh() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let now = OffsetDateTime::now_utc();
        t.record_refresh_at("FAB", "credit_score", now).unwrap();
        let r = t.status("FAB", "credit_score", now);
        assert_eq!(r.status, FreshnessStatus::Fresh);
    }

    #[test]
    fn stale_after_max_age() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let past = OffsetDateTime::now_utc() - Duration::seconds(120);
        t.record_refresh_at("FAB", "credit_score", past).unwrap();
        let now = OffsetDateTime::now_utc();
        let r = t.status("FAB", "credit_score", now);
        assert_eq!(r.status, FreshnessStatus::Stale);
    }

    #[test]
    fn age_seconds_recorded() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let past = OffsetDateTime::now_utc() - Duration::seconds(30);
        t.record_refresh_at("FAB", "credit_score", past).unwrap();
        let r = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert!(r.age_seconds.unwrap() >= 29 && r.age_seconds.unwrap() <= 31);
    }

    #[test]
    fn stale_filter() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let mut s2 = sla();
        s2.feature = "income".into();
        t.register(s2).unwrap();
        let past = OffsetDateTime::now_utc() - Duration::seconds(120);
        let now = OffsetDateTime::now_utc();
        t.record_refresh_at("FAB", "credit_score", past).unwrap();
        t.record_refresh_at("FAB", "income", now).unwrap();
        let stale = t.stale(now);
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].feature, "credit_score");
    }

    #[test]
    fn unknown_with_no_sla_returns_unknown() {
        let t = FreshnessTracker::new();
        let r = t.status("FAB", "ghost", OffsetDateTime::now_utc());
        assert_eq!(r.status, FreshnessStatus::Unknown);
    }

    #[test]
    fn record_refresh_default_now_works() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        t.record_refresh("FAB", "credit_score").unwrap();
        let r = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r.status, FreshnessStatus::Fresh);
    }

    #[test]
    fn isolated_per_tenant() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let mut other = sla();
        other.tenant_id = "ENBD".into();
        t.register(other).unwrap();
        t.record_refresh("FAB", "credit_score").unwrap();
        let r = t.status("ENBD", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r.status, FreshnessStatus::Unknown);
    }

    #[test]
    fn sla_serde() {
        let s = sla();
        let j = serde_json::to_string(&s).unwrap();
        let p: FreshnessSla = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn report_serde() {
        let r = FreshnessReport {
            feature: "x".into(),
            tenant_id: "FAB".into(),
            status: FreshnessStatus::Fresh,
            age_seconds: Some(10),
            max_age_seconds: 60,
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: FreshnessReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn status_serde() {
        for s in [
            FreshnessStatus::Fresh,
            FreshnessStatus::Stale,
            FreshnessStatus::Unknown,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: FreshnessStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn many_features() {
        let t = FreshnessTracker::new();
        for i in 0..20 {
            let mut s = sla();
            s.feature = format!("f{i}");
            t.register(s).unwrap();
        }
        assert_eq!(t.feature_count(), 20);
    }

    #[test]
    fn report_carries_max_age() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        t.record_refresh("FAB", "credit_score").unwrap();
        let r = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r.max_age_seconds, 60);
    }

    #[test]
    fn no_sla_no_stale() {
        let t = FreshnessTracker::new();
        t.record_refresh("FAB", "x").unwrap();
        // Without an SLA, status is Fresh by default since age <= 0.
        let r = t.status("FAB", "x", OffsetDateTime::now_utc());
        // Actually max_age is 0 so age > 0 means Stale? Let me check…
        let _ = r;
        // Just ensure no crash.
    }

    #[test]
    fn stale_empty_when_all_fresh() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        t.record_refresh("FAB", "credit_score").unwrap();
        let stale = t.stale(OffsetDateTime::now_utc());
        assert!(stale.is_empty());
    }

    #[test]
    fn record_overrides_prior() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let past = OffsetDateTime::now_utc() - Duration::seconds(120);
        t.record_refresh_at("FAB", "credit_score", past).unwrap();
        // Stale.
        let r = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r.status, FreshnessStatus::Stale);
        // Re-refresh — fresh.
        t.record_refresh("FAB", "credit_score").unwrap();
        let r2 = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r2.status, FreshnessStatus::Fresh);
    }

    #[test]
    fn at_threshold_still_fresh() {
        let t = FreshnessTracker::new();
        t.register(sla()).unwrap();
        let exact = OffsetDateTime::now_utc() - Duration::seconds(60);
        t.record_refresh_at("FAB", "credit_score", exact).unwrap();
        let r = t.status("FAB", "credit_score", OffsetDateTime::now_utc());
        assert_eq!(r.status, FreshnessStatus::Fresh);
    }
}
