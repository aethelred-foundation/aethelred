//! Budget register — department / project / tenant budgets with variance.
//!
//! Distinct from [`crate::cost_attribution`] (which records what was
//! spent and on whose behalf), this module tracks **what was planned**:
//! per-period budgets with cumulative actual spend, computed variance,
//! and threshold-based alert states. Maps to FinOps Foundation
//! "Operate" capability and SOX §404 financial-control evidence.
//!
//! ## State model
//!
//! - **`Budget`**: amount budgeted per period, with watermark thresholds
//!   (e.g., 50% / 75% / 90% / 100%).
//! - **`spend(amount)`**: increments cumulative spend. Recomputes
//!   `current_state` based on which watermark has been crossed.
//! - **`reset_period(period)`**: starts a new period with cleared spend.
//!
//! State transitions are deterministic: given a budget amount, watermarks,
//! and total spend, the state is `OnTrack | Warning | Critical | Exceeded`.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// BudgetState
// =============================================================================

/// Current state of a budget given its watermarks and actual spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetState {
    /// Within the warning watermark.
    OnTrack,
    /// Crossed warning threshold.
    Warning,
    /// Crossed critical threshold.
    Critical,
    /// Exceeded budget (>= 100% of amount).
    Exceeded,
}

impl BudgetState {
    /// True if alerting should fire.
    pub fn is_alerting(self) -> bool {
        !matches!(self, Self::OnTrack)
    }
}

// =============================================================================
// Watermarks
// =============================================================================

/// Three-level threshold (in percent of budget) that drives state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Watermarks {
    /// Warning threshold (e.g., 75).
    pub warning_pct: u8,
    /// Critical threshold (e.g., 90).
    pub critical_pct: u8,
    /// Exceeded threshold (typically 100; allow >100 for soft caps).
    pub exceeded_pct: u8,
}

impl Default for Watermarks {
    fn default() -> Self {
        Self {
            warning_pct: 75,
            critical_pct: 90,
            exceeded_pct: 100,
        }
    }
}

impl Watermarks {
    /// True if `warning <= critical <= exceeded` and all in (0, 200].
    pub fn is_well_formed(&self) -> bool {
        self.warning_pct > 0
            && self.warning_pct <= self.critical_pct
            && self.critical_pct <= self.exceeded_pct
            && self.exceeded_pct <= 200
    }
}

// =============================================================================
// SpendEvent
// =============================================================================

/// One spend event recorded against a budget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendEvent {
    /// RFC 3339.
    pub at: String,
    /// Amount in micro-units (always non-negative; refunds via `credit`).
    pub amount_micro: i64,
    /// Optional label / description.
    pub note: Option<String>,
}

// =============================================================================
// Budget
// =============================================================================

/// One budget row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Budget {
    /// Stable id (e.g., "BUDGET-PLATFORM-2025").
    pub budget_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Owner / cost-center.
    pub owner: String,
    /// Display name.
    pub name: String,
    /// Period label ("2025-04", "Q1-2025", "FY2025").
    pub period: String,
    /// Budgeted amount in micro-units.
    pub amount_micro: i64,
    /// Currency.
    pub currency: String,
    /// Cumulative spend so far in this period (micro-units).
    pub spent_micro: i64,
    /// Watermark thresholds.
    pub watermarks: Watermarks,
    /// Current state (recomputed on every spend / credit / amount change).
    pub current_state: BudgetState,
    /// Spend timeline.
    pub events: Vec<SpendEvent>,
    /// True if the budget is currently active (still tracking spend).
    pub active: bool,
    /// RFC 3339 — period started.
    pub period_started_at: String,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Budget {
    /// Construct a new active budget with default watermarks.
    pub fn new(
        budget_id: impl Into<String>,
        tenant_id: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
        period: impl Into<String>,
        amount_micro: i64,
        currency: impl Into<String>,
        period_started_at: impl Into<String>,
    ) -> Self {
        Self {
            budget_id: budget_id.into(),
            tenant_id: tenant_id.into(),
            owner: owner.into(),
            name: name.into(),
            period: period.into(),
            amount_micro,
            currency: currency.into(),
            spent_micro: 0,
            watermarks: Watermarks::default(),
            current_state: BudgetState::OnTrack,
            events: Vec::new(),
            active: true,
            period_started_at: period_started_at.into(),
            tags: Vec::new(),
        }
    }

    /// Variance in micro-units (positive = under budget, negative = over).
    pub fn variance_micro(&self) -> i64 {
        self.amount_micro.saturating_sub(self.spent_micro)
    }

    /// Spend percentage in basis points (10_000 = 100.00%). Uses i128 to
    /// avoid overflow on large amounts.
    pub fn spend_basis_points(&self) -> i64 {
        if self.amount_micro <= 0 {
            return 0;
        }
        let bp = (self.spent_micro as i128 * 10_000) / (self.amount_micro as i128);
        bp.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

fn compute_state(amount_micro: i64, spent_micro: i64, w: Watermarks) -> BudgetState {
    if amount_micro <= 0 {
        // Pathological budget; never on track.
        return BudgetState::Exceeded;
    }
    // Compare basis-points (1% = 100 bp) to avoid float drift.
    let bp = (spent_micro as i128 * 100) / (amount_micro as i128);
    let bp = bp as i64;
    if bp >= w.exceeded_pct as i64 {
        BudgetState::Exceeded
    } else if bp >= w.critical_pct as i64 {
        BudgetState::Critical
    } else if bp >= w.warning_pct as i64 {
        BudgetState::Warning
    } else {
        BudgetState::OnTrack
    }
}

// =============================================================================
// BudgetRegister
// =============================================================================

/// Thread-safe budget registry.
#[derive(Debug, Default)]
pub struct BudgetRegister {
    inner: RwLock<HashMap<String, Budget>>,
}

impl BudgetRegister {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new budget.
    pub fn register(&self, budget: Budget) -> SandboxResult<()> {
        if !budget.watermarks.is_well_formed() {
            return Err(SandboxError::Other(format!(
                "budget {} watermarks malformed: warning={} critical={} exceeded={}",
                budget.budget_id,
                budget.watermarks.warning_pct,
                budget.watermarks.critical_pct,
                budget.watermarks.exceeded_pct
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        if g.contains_key(&budget.budget_id) {
            return Err(SandboxError::Other(format!(
                "budget already registered: {}",
                budget.budget_id
            )));
        }
        g.insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    /// Set custom watermarks.
    pub fn set_watermarks(
        &self,
        budget_id: &str,
        watermarks: Watermarks,
    ) -> SandboxResult<()> {
        if !watermarks.is_well_formed() {
            return Err(SandboxError::Other("watermarks malformed".into()));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        b.watermarks = watermarks;
        b.current_state = compute_state(b.amount_micro, b.spent_micro, b.watermarks);
        Ok(())
    }

    /// Update budget amount (allowed mid-period for reforecasts).
    pub fn set_amount(&self, budget_id: &str, amount_micro: i64) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        b.amount_micro = amount_micro;
        b.current_state = compute_state(b.amount_micro, b.spent_micro, b.watermarks);
        Ok(())
    }

    /// Record a spend event. Errors if budget is inactive or amount < 0.
    pub fn spend(
        &self,
        budget_id: &str,
        amount_micro: i64,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<Budget> {
        if amount_micro < 0 {
            return Err(SandboxError::Other(
                "spend amount must be non-negative; use credit() for refunds".into(),
            ));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        if !b.active {
            return Err(SandboxError::Other(format!(
                "budget {budget_id} is not active"
            )));
        }
        b.spent_micro = b.spent_micro.saturating_add(amount_micro);
        b.events.push(SpendEvent {
            at: at.into(),
            amount_micro,
            note,
        });
        b.current_state = compute_state(b.amount_micro, b.spent_micro, b.watermarks);
        Ok(b.clone())
    }

    /// Apply a credit / refund (decreases spent_micro).
    pub fn credit(
        &self,
        budget_id: &str,
        amount_micro: i64,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<Budget> {
        if amount_micro < 0 {
            return Err(SandboxError::Other(
                "credit amount must be non-negative".into(),
            ));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        b.spent_micro = b.spent_micro.saturating_sub(amount_micro);
        b.events.push(SpendEvent {
            at: at.into(),
            amount_micro: -amount_micro,
            note,
        });
        b.current_state = compute_state(b.amount_micro, b.spent_micro, b.watermarks);
        Ok(b.clone())
    }

    /// Reset the budget for a new period — clears spend and event log,
    /// updates `period` and `period_started_at`. Reactivates if was
    /// deactivated.
    pub fn reset_period(
        &self,
        budget_id: &str,
        new_period: impl Into<String>,
        period_started_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        b.period = new_period.into();
        b.period_started_at = period_started_at.into();
        b.spent_micro = 0;
        b.events.clear();
        b.current_state = compute_state(b.amount_micro, b.spent_micro, b.watermarks);
        b.active = true;
        Ok(())
    }

    /// Deactivate (stops accepting spend events).
    pub fn deactivate(&self, budget_id: &str) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        b.active = false;
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, budget_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("budget register poisoned".into()))?;
        let b = g
            .get_mut(budget_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown budget {budget_id}")))?;
        let tag = tag.into();
        if !b.tags.contains(&tag) {
            b.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, budget_id: &str) -> Option<Budget> {
        let g = self.inner.read().ok()?;
        g.get(budget_id).cloned()
    }

    /// All budgets.
    pub fn all(&self) -> Vec<Budget> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Budgets for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<Budget> {
        self.all()
            .into_iter()
            .filter(|b| b.tenant_id == tenant_id)
            .collect()
    }

    /// Budgets for an owner.
    pub fn for_owner(&self, owner: &str) -> Vec<Budget> {
        self.all().into_iter().filter(|b| b.owner == owner).collect()
    }

    /// Budgets for a period.
    pub fn for_period(&self, period: &str) -> Vec<Budget> {
        self.all()
            .into_iter()
            .filter(|b| b.period == period)
            .collect()
    }

    /// Budgets currently in an alerting state.
    pub fn alerting(&self) -> Vec<Budget> {
        self.all()
            .into_iter()
            .filter(|b| b.active && b.current_state.is_alerting())
            .collect()
    }

    /// Budgets that have exceeded their amount.
    pub fn exceeded(&self) -> Vec<Budget> {
        self.all()
            .into_iter()
            .filter(|b| matches!(b.current_state, BudgetState::Exceeded))
            .collect()
    }

    /// Number of registered budgets.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(id: &str, amount: i64) -> Budget {
        Budget::new(
            id,
            "tenant-a",
            "platform",
            format!("name-{id}"),
            "2025-04",
            amount,
            "USD",
            "2025-04-01T00:00:00Z",
        )
    }

    #[test]
    fn register_and_get() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000_000)).unwrap();
        let b = r.get("b1").unwrap();
        assert_eq!(b.amount_micro, 1_000_000);
        assert_eq!(b.spent_micro, 0);
        assert_eq!(b.current_state, BudgetState::OnTrack);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000_000)).unwrap();
        let err = r.register(budget("b1", 500_000)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn malformed_watermarks_error() {
        let r = BudgetRegister::new();
        let mut b = budget("b1", 1_000_000);
        b.watermarks = Watermarks {
            warning_pct: 90,
            critical_pct: 50, // less than warning
            exceeded_pct: 100,
        };
        let err = r.register(b).unwrap_err();
        assert!(format!("{err}").contains("malformed"));
    }

    #[test]
    fn watermarks_well_formed() {
        let w = Watermarks::default();
        assert!(w.is_well_formed());
        let w = Watermarks {
            warning_pct: 0,
            critical_pct: 50,
            exceeded_pct: 100,
        };
        assert!(!w.is_well_formed());
    }

    #[test]
    fn spend_advances_state_through_thresholds() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        // 50% — still on track (default warning is 75%)
        r.spend("b1", 500, "2025-04-10T00:00:00Z", None).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::OnTrack);
        // 80% — warning
        r.spend("b1", 300, "2025-04-15T00:00:00Z", None).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Warning);
        // 95% — critical
        r.spend("b1", 150, "2025-04-20T00:00:00Z", None).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Critical);
        // 100% — exceeded
        r.spend("b1", 50, "2025-04-25T00:00:00Z", None).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Exceeded);
    }

    #[test]
    fn spend_negative_errors() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        let err = r.spend("b1", -100, "2025-04-10T00:00:00Z", None).unwrap_err();
        assert!(format!("{err}").contains("non-negative"));
    }

    #[test]
    fn spend_inactive_errors() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.deactivate("b1").unwrap();
        let err = r.spend("b1", 100, "2025-04-10T00:00:00Z", None).unwrap_err();
        assert!(format!("{err}").contains("not active"));
    }

    #[test]
    fn credit_decreases_spent_and_recomputes_state() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 950, "2025-04-15T00:00:00Z", None).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Critical);
        r.credit("b1", 700, "2025-04-20T00:00:00Z", Some("refund".into()))
            .unwrap();
        let b = r.get("b1").unwrap();
        assert_eq!(b.spent_micro, 250);
        assert_eq!(b.current_state, BudgetState::OnTrack);
        // Last event reflects the credit.
        assert_eq!(b.events.last().unwrap().amount_micro, -700);
    }

    #[test]
    fn credit_negative_errors() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        let err = r.credit("b1", -100, "2025-04-10T00:00:00Z", None).unwrap_err();
        assert!(format!("{err}").contains("non-negative"));
    }

    #[test]
    fn reset_period_clears_state() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 800, "2025-04-15T00:00:00Z", None).unwrap();
        r.deactivate("b1").unwrap();
        r.reset_period("b1", "2025-05", "2025-05-01T00:00:00Z").unwrap();
        let b = r.get("b1").unwrap();
        assert_eq!(b.period, "2025-05");
        assert_eq!(b.spent_micro, 0);
        assert!(b.events.is_empty());
        assert!(b.active);
        assert_eq!(b.current_state, BudgetState::OnTrack);
    }

    #[test]
    fn set_amount_recomputes_state() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 800, "2025-04-15T00:00:00Z", None).unwrap();
        // 80% → warning. Now reduce budget to 700 → exceeded.
        r.set_amount("b1", 700).unwrap();
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Exceeded);
    }

    #[test]
    fn set_watermarks_recomputes_state() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 600, "2025-04-15T00:00:00Z", None).unwrap();
        // 60% with default (75/90/100) → OnTrack
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::OnTrack);
        // Make watermarks more aggressive (50/70/90).
        r.set_watermarks(
            "b1",
            Watermarks {
                warning_pct: 50,
                critical_pct: 70,
                exceeded_pct: 90,
            },
        )
        .unwrap();
        // 60% under new thresholds → Warning.
        assert_eq!(r.get("b1").unwrap().current_state, BudgetState::Warning);
    }

    #[test]
    fn set_watermarks_malformed_errors() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        let err = r
            .set_watermarks(
                "b1",
                Watermarks {
                    warning_pct: 90,
                    critical_pct: 50,
                    exceeded_pct: 100,
                },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("malformed"));
    }

    #[test]
    fn variance_and_basis_points() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 250, "2025-04-15T00:00:00Z", None).unwrap();
        let b = r.get("b1").unwrap();
        assert_eq!(b.variance_micro(), 750);
        assert_eq!(b.spend_basis_points(), 2_500); // 25.00%
    }

    #[test]
    fn variance_negative_when_over() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.spend("b1", 1_500, "2025-04-15T00:00:00Z", None).unwrap();
        let b = r.get("b1").unwrap();
        assert_eq!(b.variance_micro(), -500);
        assert_eq!(b.spend_basis_points(), 15_000); // 150.00%
    }

    #[test]
    fn add_tag_dedupes() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        r.add_tag("b1", "engineering").unwrap();
        r.add_tag("b1", "engineering").unwrap();
        r.add_tag("b1", "platform").unwrap();
        assert_eq!(r.get("b1").unwrap().tags, vec!["engineering", "platform"]);
    }

    #[test]
    fn unknown_budget_errors() {
        let r = BudgetRegister::new();
        let err = r.set_amount("nope", 100).unwrap_err();
        assert!(format!("{err}").contains("unknown budget"));
    }

    #[test]
    fn for_tenant_for_owner_for_period_filters() {
        let r = BudgetRegister::new();
        r.register(budget("b1", 1_000)).unwrap();
        let mut other = budget("b2", 500);
        other.tenant_id = "tenant-b".into();
        other.owner = "data".into();
        other.period = "2025-05".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_owner("platform").len(), 1);
        assert_eq!(r.for_owner("data").len(), 1);
        assert_eq!(r.for_period("2025-04").len(), 1);
        assert_eq!(r.for_period("2025-05").len(), 1);
    }

    #[test]
    fn alerting_and_exceeded_filters() {
        let r = BudgetRegister::new();
        r.register(budget("ok", 1_000)).unwrap();
        r.register(budget("warn", 1_000)).unwrap();
        r.register(budget("crit", 1_000)).unwrap();
        r.register(budget("over", 1_000)).unwrap();
        r.spend("warn", 800, "2025-04-15T00:00:00Z", None).unwrap();
        r.spend("crit", 950, "2025-04-15T00:00:00Z", None).unwrap();
        r.spend("over", 1_500, "2025-04-15T00:00:00Z", None).unwrap();
        let alerting_ids: Vec<_> = r
            .alerting()
            .iter()
            .map(|b| b.budget_id.clone())
            .collect();
        assert!(alerting_ids.contains(&"warn".to_string()));
        assert!(alerting_ids.contains(&"crit".to_string()));
        assert!(alerting_ids.contains(&"over".to_string()));
        assert!(!alerting_ids.contains(&"ok".to_string()));
        let exceeded_ids: Vec<_> = r
            .exceeded()
            .iter()
            .map(|b| b.budget_id.clone())
            .collect();
        assert_eq!(exceeded_ids, vec!["over"]);
    }

    #[test]
    fn alerting_excludes_inactive() {
        let r = BudgetRegister::new();
        r.register(budget("over", 1_000)).unwrap();
        r.spend("over", 1_500, "2025-04-15T00:00:00Z", None).unwrap();
        r.deactivate("over").unwrap();
        assert!(r.alerting().is_empty());
    }

    #[test]
    fn state_helpers() {
        assert!(BudgetState::Warning.is_alerting());
        assert!(BudgetState::Critical.is_alerting());
        assert!(BudgetState::Exceeded.is_alerting());
        assert!(!BudgetState::OnTrack.is_alerting());
    }

    #[test]
    fn count_tracks() {
        let r = BudgetRegister::new();
        assert_eq!(r.count(), 0);
        r.register(budget("b1", 1_000)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn budget_serde() {
        let b = budget("b1", 1_000);
        let j = serde_json::to_string(&b).unwrap();
        let back: Budget = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn watermarks_serde() {
        let w = Watermarks::default();
        let j = serde_json::to_string(&w).unwrap();
        let back: Watermarks = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            BudgetState::OnTrack,
            BudgetState::Warning,
            BudgetState::Critical,
            BudgetState::Exceeded,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<BudgetState>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn zero_amount_budget_is_exceeded() {
        let s = compute_state(0, 100, Watermarks::default());
        assert_eq!(s, BudgetState::Exceeded);
    }
}
