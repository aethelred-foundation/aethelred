//! Per-tenant SLA contract management with automatic credit calculation.
//!
//! Each tenant has an SLA agreement defining uptime targets, response-time
//! targets, and a credit schedule when breached. This module is the
//! canonical source: feed it monthly observations and it produces
//! [`SlaCreditEvaluation`] records the billing system applies.
//!
//! Composes with [`crate::slo_tracking`] (engineering metric tracking)
//! and [`crate::billing_meter`] (final invoice).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SlaTarget
// =============================================================================

/// One SLA target.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SlaTarget {
    /// Uptime ratio (0.0..=1.0).
    Uptime,
    /// p99 response-time threshold in milliseconds.
    P99ResponseMillis,
    /// Mean time to acknowledge incident (minutes).
    MeanTimeToAck,
}

// =============================================================================
// CreditTier
// =============================================================================

/// One band in the credit schedule.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct CreditTier {
    /// Threshold (interpretation per `SlaTarget`).
    pub threshold: f64,
    /// Percentage credit (0.0..=1.0).
    pub credit_pct: f64,
}

// =============================================================================
// SlaContract
// =============================================================================

/// Full SLA contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlaContract {
    /// Stable id.
    pub contract_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Target uptime (e.g. 0.999).
    pub uptime_target: f64,
    /// Target p99 response in milliseconds.
    pub p99_target_millis: u64,
    /// Target MTTA in minutes.
    pub mtta_target_minutes: u64,
    /// Credit tiers, sorted worst (most credit) to best (least).
    pub credit_tiers: Vec<CreditTier>,
    /// RFC 3339 effective from.
    pub effective_from: String,
    /// RFC 3339 effective to (None = open).
    pub effective_to: Option<String>,
}

impl SlaContract {
    /// Compute credit percentage for an `achieved_uptime` value.
    /// Picks the most generous tier whose threshold is met.
    pub fn credit_for_uptime(&self, achieved: f64) -> f64 {
        if achieved >= self.uptime_target {
            return 0.0;
        }
        // Sort credit tiers by threshold ascending (worst → best).
        let mut tiers = self.credit_tiers.clone();
        tiers.sort_by(|a, b| a.threshold.partial_cmp(&b.threshold).unwrap_or(std::cmp::Ordering::Equal));
        // Find the worst tier whose threshold is `>= achieved` (i.e., we
        // dropped to or below that level → the credit applies).
        let mut credit: f64 = 0.0;
        for t in &tiers {
            if achieved <= t.threshold {
                credit = credit.max(t.credit_pct);
            }
        }
        credit
    }
}

// =============================================================================
// SlaObservation
// =============================================================================

/// Per-period observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlaObservation {
    /// Period.
    pub period: String,
    /// Tenant.
    pub tenant_id: String,
    /// Achieved uptime.
    pub achieved_uptime: f64,
    /// Achieved p99 in millis.
    pub achieved_p99_millis: Option<u64>,
    /// Achieved MTTA in minutes.
    pub achieved_mtta_minutes: Option<u64>,
}

// =============================================================================
// SlaCreditEvaluation
// =============================================================================

/// Per-period evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlaCreditEvaluation {
    /// Stable id.
    pub evaluation_id: Uuid,
    /// Contract id.
    pub contract_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Period.
    pub period: String,
    /// Achieved uptime ratio.
    pub achieved_uptime: f64,
    /// Whether each target was met.
    pub uptime_met: bool,
    /// Final credit pct (0.0..=1.0).
    pub credit_pct: f64,
    /// RFC 3339 evaluated at.
    pub evaluated_at: String,
}

// =============================================================================
// SlaRegistry
// =============================================================================

#[derive(Default)]
struct State {
    contracts: HashMap<String, SlaContract>,
    evaluations: Vec<SlaCreditEvaluation>,
}

/// Registry.
pub struct SlaRegistry {
    state: RwLock<State>,
}

impl Default for SlaRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for SlaRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlaRegistry")
            .field("contracts", &self.contract_count())
            .field("evaluations", &self.evaluation_count())
            .finish()
    }
}

impl SlaRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a contract.
    pub fn register(&self, c: SlaContract) -> SandboxResult<()> {
        if !(c.uptime_target > 0.0 && c.uptime_target <= 1.0) {
            return Err(SandboxError::Other(format!(
                "uptime target out of range: {}",
                c.uptime_target
            )));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sla registry poisoned".into()))?;
        if g.contracts.contains_key(&c.contract_id) {
            return Err(SandboxError::Other(format!(
                "contract {} already registered",
                c.contract_id
            )));
        }
        g.contracts.insert(c.contract_id.clone(), c);
        Ok(())
    }

    /// Evaluate a period's observation.
    pub fn evaluate(
        &self,
        contract_id: &str,
        observation: &SlaObservation,
    ) -> SandboxResult<SlaCreditEvaluation> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sla registry poisoned".into()))?;
        let c = g
            .contracts
            .get(contract_id)
            .cloned()
            .ok_or_else(|| SandboxError::Other(format!("contract {} not found", contract_id)))?;
        let credit = c.credit_for_uptime(observation.achieved_uptime);
        let uptime_met = observation.achieved_uptime >= c.uptime_target;
        let eval = SlaCreditEvaluation {
            evaluation_id: Uuid::now_v7(),
            contract_id: c.contract_id.clone(),
            tenant_id: c.tenant_id.clone(),
            period: observation.period.clone(),
            achieved_uptime: observation.achieved_uptime,
            uptime_met,
            credit_pct: credit,
            evaluated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        g.evaluations.push(eval.clone());
        Ok(eval)
    }

    /// Lookup contract.
    pub fn contract(&self, id: &str) -> Option<SlaContract> {
        self.state.read().ok()?.contracts.get(id).cloned()
    }
    /// All contracts.
    pub fn contracts(&self) -> Vec<SlaContract> {
        self.state
            .read()
            .map(|g| g.contracts.values().cloned().collect())
            .unwrap_or_default()
    }
    /// All evaluations.
    pub fn evaluations(&self) -> Vec<SlaCreditEvaluation> {
        self.state.read().map(|g| g.evaluations.clone()).unwrap_or_default()
    }
    /// Evaluations for a tenant.
    pub fn evaluations_for_tenant(&self, tenant: &str) -> Vec<SlaCreditEvaluation> {
        self.evaluations()
            .into_iter()
            .filter(|e| e.tenant_id == tenant)
            .collect()
    }
    /// Evaluations for a tenant and period.
    pub fn evaluation_for(
        &self,
        tenant: &str,
        period: &str,
    ) -> Option<SlaCreditEvaluation> {
        self.evaluations()
            .into_iter()
            .find(|e| e.tenant_id == tenant && e.period == period)
    }
    /// Counts.
    pub fn contract_count(&self) -> usize {
        self.state.read().map(|g| g.contracts.len()).unwrap_or(0)
    }
    /// Evaluation count.
    pub fn evaluation_count(&self) -> usize {
        self.state.read().map(|g| g.evaluations.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.contract_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> SlaContract {
        SlaContract {
            contract_id: "fab-2026".into(),
            tenant_id: "FAB".into(),
            uptime_target: 0.999,
            p99_target_millis: 200,
            mtta_target_minutes: 15,
            credit_tiers: vec![
                CreditTier {
                    threshold: 0.99,
                    credit_pct: 0.10,
                },
                CreditTier {
                    threshold: 0.95,
                    credit_pct: 0.25,
                },
                CreditTier {
                    threshold: 0.90,
                    credit_pct: 0.50,
                },
            ],
            effective_from: "2026-01-01T00:00:00Z".into(),
            effective_to: None,
        }
    }

    #[test]
    fn meeting_target_zero_credit() {
        let c = contract();
        assert_eq!(c.credit_for_uptime(0.999), 0.0);
        assert_eq!(c.credit_for_uptime(1.0), 0.0);
    }

    #[test]
    fn drop_to_99_gives_10_credit() {
        let c = contract();
        assert!((c.credit_for_uptime(0.99) - 0.10).abs() < 1e-9);
    }

    #[test]
    fn drop_to_95_gives_25_credit() {
        let c = contract();
        assert!((c.credit_for_uptime(0.95) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn drop_to_90_gives_50_credit() {
        let c = contract();
        assert!((c.credit_for_uptime(0.90) - 0.50).abs() < 1e-9);
    }

    #[test]
    fn drop_below_lowest_tier_takes_lowest_credit() {
        let c = contract();
        // 80% achieved is worse than the 90% tier.
        assert!((c.credit_for_uptime(0.80) - 0.50).abs() < 1e-9);
    }

    #[test]
    fn register_invalid_target_errors() {
        let r = SlaRegistry::new();
        let mut c = contract();
        c.uptime_target = 0.0;
        assert!(r.register(c).is_err());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        assert!(r.register(contract()).is_err());
    }

    #[test]
    fn evaluate_creates_record() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        // 0.985 is below the 0.99 tier → triggers 10% credit.
        let obs = SlaObservation {
            period: "2026-05".into(),
            tenant_id: "FAB".into(),
            achieved_uptime: 0.985,
            achieved_p99_millis: Some(180),
            achieved_mtta_minutes: Some(10),
        };
        let e = r.evaluate("fab-2026", &obs).unwrap();
        assert!(!e.uptime_met);
        assert!(e.credit_pct > 0.0);
    }

    #[test]
    fn evaluate_uptime_met_no_credit() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        let obs = SlaObservation {
            period: "2026-05".into(),
            tenant_id: "FAB".into(),
            achieved_uptime: 0.9999,
            achieved_p99_millis: None,
            achieved_mtta_minutes: None,
        };
        let e = r.evaluate("fab-2026", &obs).unwrap();
        assert!(e.uptime_met);
        assert_eq!(e.credit_pct, 0.0);
    }

    #[test]
    fn evaluate_unknown_contract_errors() {
        let r = SlaRegistry::new();
        let obs = SlaObservation {
            period: "2026-05".into(),
            tenant_id: "FAB".into(),
            achieved_uptime: 0.99,
            achieved_p99_millis: None,
            achieved_mtta_minutes: None,
        };
        assert!(r.evaluate("ghost", &obs).is_err());
    }

    #[test]
    fn evaluations_for_tenant_filters() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        let obs = SlaObservation {
            period: "2026-05".into(),
            tenant_id: "FAB".into(),
            achieved_uptime: 0.985,
            achieved_p99_millis: None,
            achieved_mtta_minutes: None,
        };
        r.evaluate("fab-2026", &obs).unwrap();
        assert_eq!(r.evaluations_for_tenant("FAB").len(), 1);
        assert!(r.evaluations_for_tenant("ENBD").is_empty());
    }

    #[test]
    fn evaluation_for_lookup() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        let obs = SlaObservation {
            period: "2026-05".into(),
            tenant_id: "FAB".into(),
            achieved_uptime: 0.985,
            achieved_p99_millis: None,
            achieved_mtta_minutes: None,
        };
        r.evaluate("fab-2026", &obs).unwrap();
        assert!(r.evaluation_for("FAB", "2026-05").is_some());
        assert!(r.evaluation_for("FAB", "2025-01").is_none());
    }

    #[test]
    fn contract_serde() {
        let c = contract();
        let j = serde_json::to_string(&c).unwrap();
        let p: SlaContract = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn evaluation_serde() {
        let e = SlaCreditEvaluation {
            evaluation_id: Uuid::now_v7(),
            contract_id: "x".into(),
            tenant_id: "y".into(),
            period: "z".into(),
            achieved_uptime: 0.999,
            uptime_met: true,
            credit_pct: 0.0,
            evaluated_at: "t".into(),
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: SlaCreditEvaluation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn observation_serde() {
        let o = SlaObservation {
            period: "x".into(),
            tenant_id: "y".into(),
            achieved_uptime: 0.99,
            achieved_p99_millis: Some(100),
            achieved_mtta_minutes: Some(5),
        };
        let j = serde_json::to_string(&o).unwrap();
        let p: SlaObservation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn credit_tier_serde() {
        let t = CreditTier {
            threshold: 0.95,
            credit_pct: 0.25,
        };
        let j = serde_json::to_string(&t).unwrap();
        let p: CreditTier = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn target_serde() {
        for t in [
            SlaTarget::Uptime,
            SlaTarget::P99ResponseMillis,
            SlaTarget::MeanTimeToAck,
        ] {
            let j = serde_json::to_string(&t).unwrap();
            let p: SlaTarget = serde_json::from_str(&j).unwrap();
            assert_eq!(p, t);
        }
    }

    #[test]
    fn registry_count_tracks() {
        let r = SlaRegistry::new();
        assert!(r.is_empty());
        r.register(contract()).unwrap();
        assert_eq!(r.contract_count(), 1);
    }

    #[test]
    fn many_evaluations_aggregate() {
        let r = SlaRegistry::new();
        r.register(contract()).unwrap();
        for i in 0..12 {
            let obs = SlaObservation {
                period: format!("2026-{:02}", i + 1),
                tenant_id: "FAB".into(),
                achieved_uptime: 0.998,
                achieved_p99_millis: None,
                achieved_mtta_minutes: None,
            };
            r.evaluate("fab-2026", &obs).unwrap();
        }
        assert_eq!(r.evaluation_count(), 12);
    }

    #[test]
    fn lookup_contract_unknown_none() {
        let r = SlaRegistry::new();
        assert!(r.contract("ghost").is_none());
    }

    #[test]
    fn worst_tier_picks_largest_credit() {
        let mut c = contract();
        // Put tiers in non-sorted order — credit_for_uptime should still
        // resolve correctly.
        c.credit_tiers = vec![
            CreditTier {
                threshold: 0.90,
                credit_pct: 0.50,
            },
            CreditTier {
                threshold: 0.99,
                credit_pct: 0.10,
            },
            CreditTier {
                threshold: 0.95,
                credit_pct: 0.25,
            },
        ];
        assert!((c.credit_for_uptime(0.92) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn empty_credit_tiers_zero_credit() {
        let mut c = contract();
        c.credit_tiers = vec![];
        // Even with poor uptime, no tiers means no credit.
        assert_eq!(c.credit_for_uptime(0.5), 0.0);
    }
}
