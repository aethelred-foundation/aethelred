//! Per-tenant privacy-budget tracker (DP / k-anon / quasi-id).
//!
//! Builds on [`crate::differential_privacy`] but adds **persistent
//! per-tenant cumulative spend tracking**: every privacy-sensitive query
//! deducts from the tenant's epsilon (or k-anon equivalent) budget.
//! Queries are blocked when the budget is exhausted.
//!
//! Critical for: GDPR data-minimization, statistics releases over PII,
//! audit reports that aggregate sensitive cohorts.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// BudgetKind
// =============================================================================

/// Kind of privacy budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetKind {
    /// (ε,δ)-Differential privacy.
    DpEpsilonDelta,
    /// Pure ε-DP.
    DpEpsilon,
    /// k-anonymity (smaller k = more privacy spent).
    KAnonymity,
    /// Custom unit.
    Custom,
}

// =============================================================================
// BudgetEntry
// =============================================================================

/// One spend record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BudgetEntry {
    /// Stable id.
    pub entry_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Kind.
    pub kind: BudgetKind,
    /// Amount spent (positive number).
    pub spend: f64,
    /// Free-text purpose / query description.
    pub purpose: String,
    /// RFC 3339 spent at.
    pub at: String,
    /// Optional decision id.
    pub decision_id: Option<String>,
}

// =============================================================================
// BudgetLimits
// =============================================================================

/// Per-tenant total budgets.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BudgetLimits {
    /// Total ε for `DpEpsilon` and `DpEpsilonDelta`.
    pub epsilon_cap: Option<f64>,
    /// Total δ for `DpEpsilonDelta`.
    pub delta_cap: Option<f64>,
    /// Minimum k for `KAnonymity` queries (a stricter k spends "more").
    pub min_k: Option<u32>,
    /// Custom budget cap.
    pub custom_cap: Option<f64>,
    /// Period label (e.g. `"2026-Q2"`).
    pub period: String,
}

// =============================================================================
// BudgetStatus
// =============================================================================

/// Per-tenant + period status snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BudgetStatus {
    /// Tenant.
    pub tenant_id: String,
    /// Period.
    pub period: String,
    /// Cumulative ε spent.
    pub epsilon_spent: f64,
    /// Cumulative custom spent.
    pub custom_spent: f64,
    /// Number of entries.
    pub entries: u64,
    /// `true` if any cap has been exhausted.
    pub exhausted: bool,
    /// `true` if approaching (≥ 80%) on at least one cap.
    pub approaching: bool,
}

// =============================================================================
// PrivacyBudgetTracker
// =============================================================================

#[derive(Default)]
struct State {
    /// `(tenant, period)` → entries.
    entries: HashMap<(String, String), Vec<BudgetEntry>>,
    /// `(tenant, period)` → limits.
    limits: HashMap<(String, String), BudgetLimits>,
}

/// Tracker.
pub struct PrivacyBudgetTracker {
    state: RwLock<State>,
}

impl Default for PrivacyBudgetTracker {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for PrivacyBudgetTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivacyBudgetTracker").finish()
    }
}

impl PrivacyBudgetTracker {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a tenant's budget for a period.
    pub fn set_limit(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        limits: BudgetLimits,
    ) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("budget tracker poisoned".into()))?
            .limits
            .insert((tenant.into(), period.into()), limits);
        Ok(())
    }

    /// Check whether a spend would fit. Returns Ok with `true` if the spend
    /// is allowed, `false` if it would exceed.
    pub fn would_fit(
        &self,
        tenant: &str,
        period: &str,
        kind: BudgetKind,
        spend: f64,
    ) -> bool {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let key = (tenant.to_string(), period.to_string());
        let limits = match g.limits.get(&key) {
            Some(l) => l,
            None => return true, // no limit set = allow
        };
        let cumulative = current_spend(&g.entries, &key, kind);
        let proposed = cumulative + spend;
        match kind {
            BudgetKind::DpEpsilon | BudgetKind::DpEpsilonDelta => {
                limits.epsilon_cap.map(|c| proposed <= c).unwrap_or(true)
            }
            BudgetKind::Custom => {
                limits.custom_cap.map(|c| proposed <= c).unwrap_or(true)
            }
            BudgetKind::KAnonymity => true, // k handled separately at recording time
        }
    }

    /// Record a spend (errors if would exceed cap).
    pub fn record(
        &self,
        tenant: impl Into<String>,
        period: impl Into<String>,
        kind: BudgetKind,
        spend: f64,
        purpose: impl Into<String>,
        decision_id: Option<String>,
    ) -> SandboxResult<BudgetEntry> {
        if spend < 0.0 {
            return Err(SandboxError::Other("spend must be non-negative".into()));
        }
        let tenant = tenant.into();
        let period = period.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("budget tracker poisoned".into()))?;
        let key = (tenant.clone(), period.clone());
        // Cap check.
        let cumulative = current_spend(&g.entries, &key, kind);
        if let Some(limits) = g.limits.get(&key) {
            match kind {
                BudgetKind::DpEpsilon | BudgetKind::DpEpsilonDelta => {
                    if let Some(c) = limits.epsilon_cap {
                        if cumulative + spend > c {
                            return Err(SandboxError::Other(format!(
                                "epsilon cap {} exceeded ({} + {} > cap)",
                                c, cumulative, spend
                            )));
                        }
                    }
                }
                BudgetKind::Custom => {
                    if let Some(c) = limits.custom_cap {
                        if cumulative + spend > c {
                            return Err(SandboxError::Other(format!(
                                "custom cap {} exceeded ({} + {} > cap)",
                                c, cumulative, spend
                            )));
                        }
                    }
                }
                BudgetKind::KAnonymity => {} // checked elsewhere
            }
        }
        let entry = BudgetEntry {
            entry_id: Uuid::now_v7(),
            tenant_id: tenant,
            kind,
            spend,
            purpose: purpose.into(),
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            decision_id,
        };
        g.entries.entry(key).or_default().push(entry.clone());
        Ok(entry)
    }

    /// Per-tenant + period status.
    pub fn status(&self, tenant: &str, period: &str) -> BudgetStatus {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return BudgetStatus::default(),
        };
        let key = (tenant.to_string(), period.to_string());
        let entries = g.entries.get(&key).cloned().unwrap_or_default();
        let epsilon_spent = entries
            .iter()
            .filter(|e| matches!(e.kind, BudgetKind::DpEpsilon | BudgetKind::DpEpsilonDelta))
            .map(|e| e.spend)
            .sum::<f64>();
        let custom_spent = entries
            .iter()
            .filter(|e| e.kind == BudgetKind::Custom)
            .map(|e| e.spend)
            .sum::<f64>();
        let mut exhausted = false;
        let mut approaching = false;
        if let Some(limits) = g.limits.get(&key) {
            if let Some(c) = limits.epsilon_cap {
                if epsilon_spent >= c {
                    exhausted = true;
                } else if epsilon_spent >= c * 0.8 {
                    approaching = true;
                }
            }
            if let Some(c) = limits.custom_cap {
                if custom_spent >= c {
                    exhausted = true;
                } else if custom_spent >= c * 0.8 {
                    approaching = true;
                }
            }
        }
        BudgetStatus {
            tenant_id: tenant.to_string(),
            period: period.to_string(),
            epsilon_spent,
            custom_spent,
            entries: entries.len() as u64,
            exhausted,
            approaching,
        }
    }

    /// All entries for a tenant/period.
    pub fn entries(&self, tenant: &str, period: &str) -> Vec<BudgetEntry> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        g.entries
            .get(&(tenant.to_string(), period.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// Reset (operator override) — useful for new budget periods.
    pub fn reset(&self, tenant: &str, period: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("budget tracker poisoned".into()))?;
        g.entries.remove(&(tenant.to_string(), period.to_string()));
        Ok(())
    }
}

fn current_spend(
    entries: &HashMap<(String, String), Vec<BudgetEntry>>,
    key: &(String, String),
    kind: BudgetKind,
) -> f64 {
    let v = match entries.get(key) {
        Some(v) => v,
        None => return 0.0,
    };
    let buckets: &[BudgetKind] = match kind {
        BudgetKind::DpEpsilon | BudgetKind::DpEpsilonDelta => {
            &[BudgetKind::DpEpsilon, BudgetKind::DpEpsilonDelta]
        }
        BudgetKind::Custom => &[BudgetKind::Custom],
        BudgetKind::KAnonymity => &[BudgetKind::KAnonymity],
    };
    v.iter()
        .filter(|e| buckets.contains(&e.kind))
        .map(|e| e.spend)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> BudgetLimits {
        BudgetLimits {
            epsilon_cap: Some(1.0),
            delta_cap: Some(1e-5),
            min_k: Some(5),
            custom_cap: Some(100.0),
            period: "2026-Q2".into(),
        }
    }

    #[test]
    fn record_within_cap_succeeds() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "x", None)
            .unwrap();
    }

    #[test]
    fn record_exceeds_cap_errors() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "x", None)
            .unwrap();
        // Next 0.6 → cumulative 1.1 > cap 1.0.
        assert!(t
            .record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.6, "y", None)
            .is_err());
    }

    #[test]
    fn no_limit_means_no_cap() {
        let t = PrivacyBudgetTracker::new();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 999.0, "x", None)
            .unwrap();
    }

    #[test]
    fn would_fit_returns_true_within() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "x", None)
            .unwrap();
        assert!(t.would_fit("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.4));
    }

    #[test]
    fn would_fit_returns_false_exceeding() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.9, "x", None)
            .unwrap();
        assert!(!t.would_fit("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5));
    }

    #[test]
    fn negative_spend_errors() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        assert!(t
            .record("FAB", "2026-Q2", BudgetKind::DpEpsilon, -0.1, "x", None)
            .is_err());
    }

    #[test]
    fn dp_epsilon_and_dp_epsilon_delta_share_cap() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.6, "x", None)
            .unwrap();
        // Both spend types share the epsilon cap.
        assert!(t
            .record("FAB", "2026-Q2", BudgetKind::DpEpsilonDelta, 0.6, "y", None)
            .is_err());
    }

    #[test]
    fn custom_cap_separate_from_epsilon() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.99, "x", None)
            .unwrap();
        // Custom cap is 100, so this should still succeed.
        t.record("FAB", "2026-Q2", BudgetKind::Custom, 50.0, "y", None)
            .unwrap();
    }

    #[test]
    fn status_reports_spent() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.3, "x", None)
            .unwrap();
        let s = t.status("FAB", "2026-Q2");
        assert!((s.epsilon_spent - 0.3).abs() < 1e-9);
        assert_eq!(s.entries, 1);
    }

    #[test]
    fn status_exhausted_flag() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 1.0, "x", None)
            .unwrap();
        let s = t.status("FAB", "2026-Q2");
        assert!(s.exhausted);
    }

    #[test]
    fn status_approaching_flag() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.85, "x", None)
            .unwrap();
        let s = t.status("FAB", "2026-Q2");
        assert!(s.approaching);
    }

    #[test]
    fn reset_clears_entries() {
        let t = PrivacyBudgetTracker::new();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "x", None)
            .unwrap();
        t.reset("FAB", "2026-Q2").unwrap();
        assert_eq!(t.status("FAB", "2026-Q2").epsilon_spent, 0.0);
    }

    #[test]
    fn entries_returns_recorded() {
        let t = PrivacyBudgetTracker::new();
        for _ in 0..5 {
            t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.01, "x", None)
                .unwrap();
        }
        assert_eq!(t.entries("FAB", "2026-Q2").len(), 5);
    }

    #[test]
    fn isolated_per_tenant() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.set_limit("ENBD", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.99, "x", None)
            .unwrap();
        // ENBD untouched.
        t.record("ENBD", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "x", None)
            .unwrap();
    }

    #[test]
    fn isolated_per_period() {
        let t = PrivacyBudgetTracker::new();
        t.set_limit("FAB", "2026-Q1", limits()).unwrap();
        t.set_limit("FAB", "2026-Q2", limits()).unwrap();
        t.record("FAB", "2026-Q1", BudgetKind::DpEpsilon, 0.99, "x", None)
            .unwrap();
        t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.5, "y", None)
            .unwrap();
    }

    #[test]
    fn entry_serde() {
        let e = BudgetEntry {
            entry_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            kind: BudgetKind::DpEpsilon,
            spend: 0.1,
            purpose: "x".into(),
            at: "t".into(),
            decision_id: None,
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: BudgetEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn limits_serde() {
        let l = limits();
        let j = serde_json::to_string(&l).unwrap();
        let p: BudgetLimits = serde_json::from_str(&j).unwrap();
        assert_eq!(p, l);
    }

    #[test]
    fn status_serde() {
        let s = BudgetStatus::default();
        let j = serde_json::to_string(&s).unwrap();
        let p: BudgetStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn kind_serde() {
        for k in [
            BudgetKind::DpEpsilon,
            BudgetKind::DpEpsilonDelta,
            BudgetKind::KAnonymity,
            BudgetKind::Custom,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: BudgetKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, p);
        }
    }

    #[test]
    fn empty_status_zero_values() {
        let t = PrivacyBudgetTracker::new();
        let s = t.status("FAB", "2026-Q2");
        assert_eq!(s.epsilon_spent, 0.0);
        assert!(!s.exhausted);
    }

    #[test]
    fn many_records_accumulate() {
        let t = PrivacyBudgetTracker::new();
        let big = BudgetLimits {
            epsilon_cap: Some(100.0),
            ..limits()
        };
        t.set_limit("FAB", "2026-Q2", big).unwrap();
        for _ in 0..50 {
            t.record("FAB", "2026-Q2", BudgetKind::DpEpsilon, 0.01, "x", None)
                .unwrap();
        }
        let s = t.status("FAB", "2026-Q2");
        assert!((s.epsilon_spent - 0.5).abs() < 1e-9);
    }
}
