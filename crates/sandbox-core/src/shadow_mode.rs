//! Shadow-mode evaluation.
//!
//! Run a candidate model in parallel with the production model, *without*
//! using its output to drive decisions. The shadow model sees the same
//! inputs and produces predictions; the orchestrator records both and
//! computes agreement / drift metrics over time.
//!
//! This is the standard SR 11-7 / NIST AI RMF "challenger model" pattern:
//! evidence accumulates that the candidate is at parity (or better) before
//! it's promoted to a canary or full deployment.
//!
//! ## Metrics
//!
//! - **Agreement rate** — fraction of inputs where shadow and prod agree.
//! - **Confusion matrix** — TP / FP / FN / TN where prod's decision is treated
//!   as the gold label.
//! - **Cohen's kappa (κ)** — inter-rater agreement controlling for chance.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

// =============================================================================
// ShadowDecision
// =============================================================================

/// One paired observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowDecision {
    /// Observation id.
    pub observation_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Production model id.
    pub prod_model_id: String,
    /// Shadow model id.
    pub shadow_model_id: String,
    /// Production decision (`true` = positive).
    pub prod_decision: bool,
    /// Shadow decision (`true` = positive).
    pub shadow_decision: bool,
    /// Optional ground truth (if available later).
    pub ground_truth: Option<bool>,
}

// =============================================================================
// AgreementStats
// =============================================================================

/// Confusion matrix using prod as the reference.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgreementStats {
    /// Total comparisons.
    pub total: u64,
    /// Both positive.
    pub both_positive: u64,
    /// Both negative.
    pub both_negative: u64,
    /// Prod positive, shadow negative.
    pub prod_only_positive: u64,
    /// Shadow positive, prod negative.
    pub shadow_only_positive: u64,
}

impl AgreementStats {
    /// Agreement rate = (both_positive + both_negative) / total.
    pub fn agreement_rate(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        (self.both_positive + self.both_negative) as f64 / self.total as f64
    }

    /// Cohen's kappa.
    pub fn cohens_kappa(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        let n = self.total as f64;
        let p_o = self.agreement_rate();
        let p_yes_a = (self.both_positive + self.prod_only_positive) as f64 / n;
        let p_yes_b = (self.both_positive + self.shadow_only_positive) as f64 / n;
        let p_no_a = 1.0 - p_yes_a;
        let p_no_b = 1.0 - p_yes_b;
        let p_e = p_yes_a * p_yes_b + p_no_a * p_no_b;
        if (1.0 - p_e).abs() < 1e-12 {
            return 1.0;
        }
        (p_o - p_e) / (1.0 - p_e)
    }
}

// =============================================================================
// PerformanceStats — when ground truth is known
// =============================================================================

/// Per-side performance vs ground truth.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PerformanceStats {
    /// Total observations with ground truth.
    pub total: u64,
    /// True positives.
    pub tp: u64,
    /// False positives.
    pub fp: u64,
    /// True negatives.
    pub tn: u64,
    /// False negatives.
    pub fn_count: u64,
}

impl PerformanceStats {
    /// Accuracy = (tp + tn) / total.
    pub fn accuracy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f64 / self.total as f64
    }
    /// Precision = tp / (tp + fp).
    pub fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            return 0.0;
        }
        self.tp as f64 / denom as f64
    }
    /// Recall = tp / (tp + fn).
    pub fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_count;
        if denom == 0 {
            return 0.0;
        }
        self.tp as f64 / denom as f64
    }
    /// F1 score.
    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            return 0.0;
        }
        2.0 * p * r / (p + r)
    }
}

// =============================================================================
// ShadowReport
// =============================================================================

/// Aggregate shadow report.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ShadowReport {
    /// Total observations.
    pub total: u64,
    /// Agreement matrix.
    pub agreement: AgreementStats,
    /// Production performance vs truth (if any).
    pub prod_performance: PerformanceStats,
    /// Shadow performance vs truth (if any).
    pub shadow_performance: PerformanceStats,
    /// Cohen's kappa.
    pub cohens_kappa: f64,
}

// =============================================================================
// ShadowRegistry
// =============================================================================

#[derive(Default)]
struct State {
    /// Per-shadow-pair (`prod_model_id || "::" || shadow_model_id`) → decisions.
    decisions: HashMap<String, Vec<ShadowDecision>>,
}

/// Registry of shadow comparisons.
pub struct ShadowRegistry {
    state: RwLock<State>,
}

impl Default for ShadowRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ShadowRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowRegistry")
            .field("pairs", &self.pair_count())
            .finish()
    }
}

impl ShadowRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one shadow-vs-prod observation.
    pub fn record(&self, decision: ShadowDecision) -> SandboxResult<Uuid> {
        let key = format!(
            "{}::{}",
            decision.prod_model_id, decision.shadow_model_id
        );
        let id = decision.observation_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("shadow registry poisoned".into()))?
            .decisions
            .entry(key)
            .or_default()
            .push(decision);
        Ok(id)
    }

    /// Convenience: record by parts.
    pub fn record_simple(
        &self,
        tenant: impl Into<String>,
        prod_model: impl Into<String>,
        shadow_model: impl Into<String>,
        prod_decision: bool,
        shadow_decision: bool,
        ground_truth: Option<bool>,
    ) -> SandboxResult<Uuid> {
        self.record(ShadowDecision {
            observation_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            prod_model_id: prod_model.into(),
            shadow_model_id: shadow_model.into(),
            prod_decision,
            shadow_decision,
            ground_truth,
        })
    }

    /// Number of shadow pairs.
    pub fn pair_count(&self) -> usize {
        self.state.read().map(|g| g.decisions.len()).unwrap_or(0)
    }

    /// Number of decisions for a pair.
    pub fn decision_count(&self, prod: &str, shadow: &str) -> usize {
        let key = format!("{}::{}", prod, shadow);
        self.state
            .read()
            .map(|g| g.decisions.get(&key).map(|v| v.len()).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Compute report for one pair.
    pub fn report(&self, prod: &str, shadow: &str) -> SandboxResult<ShadowReport> {
        let key = format!("{}::{}", prod, shadow);
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("shadow registry poisoned".into()))?;
        let decisions = g.decisions.get(&key).cloned().unwrap_or_default();
        drop(g);

        let mut agreement = AgreementStats::default();
        let mut prod_perf = PerformanceStats::default();
        let mut shadow_perf = PerformanceStats::default();

        for d in &decisions {
            agreement.total += 1;
            match (d.prod_decision, d.shadow_decision) {
                (true, true) => agreement.both_positive += 1,
                (false, false) => agreement.both_negative += 1,
                (true, false) => agreement.prod_only_positive += 1,
                (false, true) => agreement.shadow_only_positive += 1,
            }
            if let Some(truth) = d.ground_truth {
                update_performance(&mut prod_perf, d.prod_decision, truth);
                update_performance(&mut shadow_perf, d.shadow_decision, truth);
            }
        }

        let cohens_kappa = agreement.cohens_kappa();
        Ok(ShadowReport {
            total: decisions.len() as u64,
            agreement,
            prod_performance: prod_perf,
            shadow_performance: shadow_perf,
            cohens_kappa,
        })
    }

    /// Snapshot decisions for a pair.
    pub fn decisions(&self, prod: &str, shadow: &str) -> Vec<ShadowDecision> {
        let key = format!("{}::{}", prod, shadow);
        self.state
            .read()
            .map(|g| g.decisions.get(&key).cloned().unwrap_or_default())
            .unwrap_or_default()
    }
}

fn update_performance(s: &mut PerformanceStats, predicted: bool, truth: bool) {
    s.total += 1;
    match (predicted, truth) {
        (true, true) => s.tp += 1,
        (true, false) => s.fp += 1,
        (false, true) => s.fn_count += 1,
        (false, false) => s.tn += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(reg: &ShadowRegistry, prod: bool, shadow: bool, truth: Option<bool>) {
        reg.record_simple("FAB", "v1", "v2", prod, shadow, truth)
            .unwrap();
    }

    #[test]
    fn empty_registry_ok() {
        let r = ShadowRegistry::new();
        assert_eq!(r.pair_count(), 0);
    }

    #[test]
    fn records_increment_count() {
        let r = ShadowRegistry::new();
        for _ in 0..5 {
            record(&r, true, true, None);
        }
        assert_eq!(r.decision_count("v1", "v2"), 5);
    }

    #[test]
    fn full_agreement_kappa_one() {
        let r = ShadowRegistry::new();
        for _ in 0..10 {
            record(&r, true, true, None);
        }
        for _ in 0..10 {
            record(&r, false, false, None);
        }
        let rep = r.report("v1", "v2").unwrap();
        assert_eq!(rep.agreement.agreement_rate(), 1.0);
        assert!((rep.cohens_kappa - 1.0).abs() < 1e-9);
    }

    #[test]
    fn random_disagreement_low_kappa() {
        let r = ShadowRegistry::new();
        // 50/50 disagreement.
        for _ in 0..50 {
            record(&r, true, false, None);
        }
        for _ in 0..50 {
            record(&r, false, true, None);
        }
        let rep = r.report("v1", "v2").unwrap();
        assert!(rep.cohens_kappa < 0.0, "kappa {}", rep.cohens_kappa);
    }

    #[test]
    fn agreement_rate_partial() {
        let r = ShadowRegistry::new();
        for _ in 0..7 {
            record(&r, true, true, None);
        }
        for _ in 0..3 {
            record(&r, true, false, None);
        }
        let rep = r.report("v1", "v2").unwrap();
        assert!((rep.agreement.agreement_rate() - 0.7).abs() < 1e-9);
    }

    #[test]
    fn performance_with_ground_truth() {
        let r = ShadowRegistry::new();
        // Prod: 9 TP, 1 FP. Shadow: 8 TP, 2 FP, 0 FN.
        for _ in 0..9 {
            record(&r, true, true, Some(true));
        }
        record(&r, true, true, Some(false));
        for _ in 0..2 {
            // Adjust shadow to be 0 → false predictions.
            record(&r, false, false, Some(false));
        }
        let rep = r.report("v1", "v2").unwrap();
        assert!(rep.prod_performance.total > 0);
        assert!(rep.shadow_performance.total > 0);
    }

    #[test]
    fn confusion_matrix_correct() {
        let r = ShadowRegistry::new();
        record(&r, true, true, None); // both_pos
        record(&r, false, false, None); // both_neg
        record(&r, true, false, None); // prod_only
        record(&r, false, true, None); // shadow_only
        let rep = r.report("v1", "v2").unwrap();
        assert_eq!(rep.agreement.both_positive, 1);
        assert_eq!(rep.agreement.both_negative, 1);
        assert_eq!(rep.agreement.prod_only_positive, 1);
        assert_eq!(rep.agreement.shadow_only_positive, 1);
    }

    #[test]
    fn unknown_pair_empty_report() {
        let r = ShadowRegistry::new();
        let rep = r.report("v1", "v2").unwrap();
        assert_eq!(rep.total, 0);
        assert_eq!(rep.agreement.agreement_rate(), 1.0);
    }

    #[test]
    fn pairs_isolated() {
        let r = ShadowRegistry::new();
        r.record_simple("FAB", "v1", "v2", true, true, None).unwrap();
        r.record_simple("FAB", "v1", "v3", true, false, None).unwrap();
        assert_eq!(r.decision_count("v1", "v2"), 1);
        assert_eq!(r.decision_count("v1", "v3"), 1);
    }

    #[test]
    fn performance_accuracy_correct() {
        let s = PerformanceStats {
            total: 10,
            tp: 7,
            fp: 1,
            tn: 1,
            fn_count: 1,
        };
        // Accuracy = (7 + 1) / 10 = 0.8.
        assert!((s.accuracy() - 0.8).abs() < 1e-9);
        // Precision = 7 / 8 = 0.875.
        assert!((s.precision() - 0.875).abs() < 1e-9);
        // Recall = 7 / 8 = 0.875.
        assert!((s.recall() - 0.875).abs() < 1e-9);
        // F1 = 2*p*r / (p+r) = 0.875.
        assert!((s.f1() - 0.875).abs() < 1e-9);
    }

    #[test]
    fn performance_zero_total_zero_metrics() {
        let s = PerformanceStats::default();
        assert_eq!(s.accuracy(), 0.0);
        assert_eq!(s.precision(), 0.0);
        assert_eq!(s.recall(), 0.0);
        assert_eq!(s.f1(), 0.0);
    }

    #[test]
    fn agreement_zero_total_rate_one() {
        let s = AgreementStats::default();
        assert_eq!(s.agreement_rate(), 1.0);
        assert_eq!(s.cohens_kappa(), 1.0);
    }

    #[test]
    fn decisions_lookup_returns_clone() {
        let r = ShadowRegistry::new();
        record(&r, true, true, None);
        let v = r.decisions("v1", "v2");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn report_serde_round_trip() {
        let r = ShadowRegistry::new();
        record(&r, true, true, Some(true));
        let rep = r.report("v1", "v2").unwrap();
        let j = serde_json::to_string(&rep).unwrap();
        let p: ShadowReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, rep);
    }

    #[test]
    fn shadow_decision_serde() {
        let d = ShadowDecision {
            observation_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            prod_model_id: "v1".into(),
            shadow_model_id: "v2".into(),
            prod_decision: true,
            shadow_decision: false,
            ground_truth: Some(true),
        };
        let j = serde_json::to_string(&d).unwrap();
        let p: ShadowDecision = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn many_decisions_aggregate() {
        let r = ShadowRegistry::new();
        for i in 0..1000 {
            let agree = i % 5 != 0;
            record(&r, true, agree, None);
        }
        let rep = r.report("v1", "v2").unwrap();
        assert_eq!(rep.total, 1000);
    }

    #[test]
    fn ground_truth_optional() {
        let r = ShadowRegistry::new();
        record(&r, true, true, None);
        let rep = r.report("v1", "v2").unwrap();
        assert_eq!(rep.prod_performance.total, 0);
    }

    #[test]
    fn agreement_stats_only_pos() {
        let s = AgreementStats {
            total: 10,
            both_positive: 10,
            both_negative: 0,
            prod_only_positive: 0,
            shadow_only_positive: 0,
        };
        assert_eq!(s.agreement_rate(), 1.0);
    }

    #[test]
    fn pair_count_unique() {
        let r = ShadowRegistry::new();
        r.record_simple("FAB", "v1", "v2", true, true, None).unwrap();
        r.record_simple("FAB", "v1", "v2", true, true, None).unwrap();
        r.record_simple("FAB", "v1", "v3", true, true, None).unwrap();
        assert_eq!(r.pair_count(), 2);
    }

    #[test]
    fn confusion_kappa_chance_aligned() {
        let r = ShadowRegistry::new();
        // Both predict positive 100% of the time → expected = observed agreement.
        // Cohen's kappa should be 1.0 since p_o == 1.0 and p_e is also 1.0
        // (1-1)/(1-1) → returns 1.0 in our impl.
        for _ in 0..100 {
            record(&r, true, true, None);
        }
        let rep = r.report("v1", "v2").unwrap();
        assert!((rep.cohens_kappa - 1.0).abs() < 1e-9);
    }

    #[test]
    fn agreement_serde() {
        let s = AgreementStats {
            total: 4,
            both_positive: 2,
            both_negative: 1,
            prod_only_positive: 1,
            shadow_only_positive: 0,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: AgreementStats = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }
}
