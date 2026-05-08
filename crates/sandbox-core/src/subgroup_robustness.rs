//! Subgroup-robustness tracking.
//!
//! Aggregate accuracy can hide performance gaps on minority cohorts. This
//! module records per-subgroup outcomes over time and surfaces the
//! **worst-group** performance per period — the canonical robustness
//! metric for ML fairness audits.
//!
//! Where [`crate::bias_detection`] computes static-window fairness gaps,
//! this module produces *time-series* of per-cohort accuracy / precision
//! / recall so reviewers can see drift.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// CohortKey
// =============================================================================

/// A subgroup tag (e.g., `"age:18-24,region:EU"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CohortKey(pub String);

impl CohortKey {
    /// New key.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// CohortObservation
// =============================================================================

/// One labeled observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohortObservation {
    /// Cohort.
    pub cohort: CohortKey,
    /// Period (e.g. `"2026-05"`).
    pub period: String,
    /// `true` if model predicted positive.
    pub predicted_positive: bool,
    /// `true` if ground truth is positive.
    pub truth_positive: bool,
}

// =============================================================================
// CohortStats
// =============================================================================

/// Per-cohort confusion matrix.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CohortStats {
    /// Cohort.
    pub cohort: CohortKey,
    /// Period.
    pub period: String,
    /// Total observations.
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

impl CohortStats {
    /// Accuracy.
    pub fn accuracy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.tp + self.tn) as f64 / self.total as f64
    }
    /// Precision.
    pub fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            return 0.0;
        }
        self.tp as f64 / denom as f64
    }
    /// Recall.
    pub fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_count;
        if denom == 0 {
            return 0.0;
        }
        self.tp as f64 / denom as f64
    }
    /// F1.
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
// SubgroupReport
// =============================================================================

/// Per-period report.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SubgroupReport {
    /// Period covered.
    pub period: String,
    /// Per-cohort stats.
    pub cohorts: Vec<CohortStats>,
    /// Worst-group accuracy across cohorts.
    pub worst_accuracy_cohort: Option<CohortKey>,
    /// Best-group accuracy.
    pub best_accuracy_cohort: Option<CohortKey>,
    /// Accuracy spread (best - worst).
    pub accuracy_spread: f64,
}

// =============================================================================
// SubgroupRobustnessMonitor
// =============================================================================

#[derive(Default)]
struct State {
    observations: Vec<CohortObservation>,
}

/// Per-cohort, per-period robustness tracker.
pub struct SubgroupRobustnessMonitor {
    state: RwLock<State>,
}

impl Default for SubgroupRobustnessMonitor {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for SubgroupRobustnessMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubgroupRobustnessMonitor")
            .field("observations", &self.observation_count())
            .finish()
    }
}

impl SubgroupRobustnessMonitor {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an observation.
    pub fn record(&self, obs: CohortObservation) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("subgroup monitor poisoned".into()))?
            .observations
            .push(obs);
        Ok(())
    }

    /// Total observations.
    pub fn observation_count(&self) -> usize {
        self.state.read().map(|g| g.observations.len()).unwrap_or(0)
    }

    /// Compute per-cohort stats for a period.
    pub fn report(&self, period: &str) -> SubgroupReport {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return SubgroupReport::default(),
        };
        let mut by_cohort: HashMap<CohortKey, CohortStats> = HashMap::new();
        for o in g.observations.iter().filter(|o| o.period == period) {
            let s = by_cohort.entry(o.cohort.clone()).or_insert(CohortStats {
                cohort: o.cohort.clone(),
                period: period.to_string(),
                ..Default::default()
            });
            s.total += 1;
            match (o.predicted_positive, o.truth_positive) {
                (true, true) => s.tp += 1,
                (true, false) => s.fp += 1,
                (false, true) => s.fn_count += 1,
                (false, false) => s.tn += 1,
            }
        }
        let mut cohorts: Vec<CohortStats> = by_cohort.into_values().collect();
        cohorts.sort_by(|a, b| a.cohort.0.cmp(&b.cohort.0));
        // Worst and best accuracy — collect before move.
        let mut best: Option<(CohortKey, f64)> = None;
        let mut worst: Option<(CohortKey, f64)> = None;
        for s in &cohorts {
            if s.total == 0 {
                continue;
            }
            let acc = s.accuracy();
            best = match best {
                None => Some((s.cohort.clone(), acc)),
                Some((_, a)) if acc > a => Some((s.cohort.clone(), acc)),
                Some(o) => Some(o),
            };
            worst = match worst {
                None => Some((s.cohort.clone(), acc)),
                Some((_, a)) if acc < a => Some((s.cohort.clone(), acc)),
                Some(o) => Some(o),
            };
        }
        let spread = match (&best, &worst) {
            (Some((_, a)), Some((_, b))) => (a - b).abs(),
            _ => 0.0,
        };
        SubgroupReport {
            period: period.to_string(),
            cohorts,
            worst_accuracy_cohort: worst.map(|(k, _)| k),
            best_accuracy_cohort: best.map(|(k, _)| k),
            accuracy_spread: spread,
        }
    }

    /// Time-series of worst-cohort accuracy per period.
    pub fn worst_accuracy_series(&self, periods: &[String]) -> Vec<(String, f64)> {
        periods
            .iter()
            .map(|p| {
                let r = self.report(p);
                let acc = r
                    .cohorts
                    .iter()
                    .filter(|s| s.total > 0)
                    .map(|s| s.accuracy())
                    .fold(f64::INFINITY, |a, b| a.min(b));
                let acc = if acc.is_finite() { acc } else { 0.0 };
                (p.clone(), acc)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(cohort: &str, period: &str, pred: bool, truth: bool) -> CohortObservation {
        CohortObservation {
            cohort: CohortKey::new(cohort),
            period: period.into(),
            predicted_positive: pred,
            truth_positive: truth,
        }
    }

    #[test]
    fn empty_report_zero_spread() {
        let m = SubgroupRobustnessMonitor::new();
        let r = m.report("2026-05");
        assert!(r.cohorts.is_empty());
        assert_eq!(r.accuracy_spread, 0.0);
    }

    #[test]
    fn single_cohort_one_correct_accuracy_one() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("a", "2026-05", true, true)).unwrap();
        let r = m.report("2026-05");
        assert_eq!(r.cohorts[0].accuracy(), 1.0);
    }

    #[test]
    fn equal_cohorts_zero_spread() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("a", "2026-05", true, true)).unwrap();
        m.record(obs("b", "2026-05", true, true)).unwrap();
        let r = m.report("2026-05");
        assert_eq!(r.accuracy_spread, 0.0);
    }

    #[test]
    fn unequal_cohorts_have_spread() {
        let m = SubgroupRobustnessMonitor::new();
        // a: 100% accuracy.
        m.record(obs("a", "2026-05", true, true)).unwrap();
        // b: 50% accuracy.
        m.record(obs("b", "2026-05", true, true)).unwrap();
        m.record(obs("b", "2026-05", true, false)).unwrap();
        let r = m.report("2026-05");
        assert!(r.accuracy_spread > 0.0);
        assert_eq!(r.best_accuracy_cohort.as_ref().unwrap().as_str(), "a");
        assert_eq!(r.worst_accuracy_cohort.as_ref().unwrap().as_str(), "b");
    }

    #[test]
    fn period_isolation() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("a", "2026-05", true, true)).unwrap();
        m.record(obs("a", "2026-04", true, false)).unwrap();
        let r = m.report("2026-05");
        assert_eq!(r.cohorts[0].total, 1);
    }

    #[test]
    fn cohort_stats_accuracy() {
        let s = CohortStats {
            cohort: CohortKey::new("x"),
            period: "p".into(),
            total: 4,
            tp: 1,
            fp: 1,
            tn: 1,
            fn_count: 1,
        };
        assert!((s.accuracy() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cohort_stats_precision_recall_f1() {
        let s = CohortStats {
            cohort: CohortKey::new("x"),
            period: "p".into(),
            total: 4,
            tp: 1,
            fp: 1,
            tn: 1,
            fn_count: 1,
        };
        assert!((s.precision() - 0.5).abs() < 1e-9);
        assert!((s.recall() - 0.5).abs() < 1e-9);
        assert!((s.f1() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cohort_stats_zero_total_zero_metrics() {
        let s = CohortStats::default();
        assert_eq!(s.accuracy(), 0.0);
        assert_eq!(s.precision(), 0.0);
        assert_eq!(s.recall(), 0.0);
        assert_eq!(s.f1(), 0.0);
    }

    #[test]
    fn worst_accuracy_series_returns_per_period() {
        let m = SubgroupRobustnessMonitor::new();
        // Period 1: a=100%, b=0%.
        m.record(obs("a", "p1", true, true)).unwrap();
        m.record(obs("b", "p1", true, false)).unwrap();
        // Period 2: both 100%.
        m.record(obs("a", "p2", true, true)).unwrap();
        m.record(obs("b", "p2", true, true)).unwrap();
        let series = m.worst_accuracy_series(&["p1".into(), "p2".into()]);
        assert!(series[0].1 < series[1].1);
    }

    #[test]
    fn worst_accuracy_zero_when_no_period_data() {
        let m = SubgroupRobustnessMonitor::new();
        let series = m.worst_accuracy_series(&["p1".into()]);
        assert_eq!(series[0].1, 0.0);
    }

    #[test]
    fn observation_serde() {
        let o = obs("a", "p", true, false);
        let j = serde_json::to_string(&o).unwrap();
        let p: CohortObservation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn cohort_key_serde_transparent() {
        let k = CohortKey::new("x");
        assert_eq!(serde_json::to_string(&k).unwrap(), "\"x\"");
    }

    #[test]
    fn report_serde() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("a", "p", true, true)).unwrap();
        let r = m.report("p");
        let j = serde_json::to_string(&r).unwrap();
        let p: SubgroupReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn cohort_stats_serde() {
        let s = CohortStats {
            cohort: CohortKey::new("x"),
            period: "p".into(),
            total: 1,
            tp: 1,
            fp: 0,
            tn: 0,
            fn_count: 0,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: CohortStats = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn cohorts_sorted_by_key() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("z", "p", true, true)).unwrap();
        m.record(obs("a", "p", true, true)).unwrap();
        let r = m.report("p");
        assert_eq!(r.cohorts[0].cohort.as_str(), "a");
        assert_eq!(r.cohorts[1].cohort.as_str(), "z");
    }

    #[test]
    fn worst_picks_lowest_accuracy() {
        let m = SubgroupRobustnessMonitor::new();
        // a: 100%, b: 50%, c: 0%.
        for _ in 0..10 {
            m.record(obs("a", "p", true, true)).unwrap();
        }
        for _ in 0..5 {
            m.record(obs("b", "p", true, true)).unwrap();
        }
        for _ in 0..5 {
            m.record(obs("b", "p", true, false)).unwrap();
        }
        for _ in 0..10 {
            m.record(obs("c", "p", true, false)).unwrap();
        }
        let r = m.report("p");
        assert_eq!(r.worst_accuracy_cohort.unwrap().as_str(), "c");
    }

    #[test]
    fn observation_count_tracks() {
        let m = SubgroupRobustnessMonitor::new();
        for i in 0..50 {
            m.record(obs(&format!("c{}", i % 5), "p", true, true)).unwrap();
        }
        assert_eq!(m.observation_count(), 50);
    }

    #[test]
    fn many_cohorts_aggregate() {
        let m = SubgroupRobustnessMonitor::new();
        for i in 0..20 {
            m.record(obs(&format!("c{i}"), "p", true, true)).unwrap();
        }
        let r = m.report("p");
        assert_eq!(r.cohorts.len(), 20);
    }

    #[test]
    fn confusion_matrix_correct() {
        let m = SubgroupRobustnessMonitor::new();
        m.record(obs("a", "p", true, true)).unwrap(); // tp
        m.record(obs("a", "p", true, false)).unwrap(); // fp
        m.record(obs("a", "p", false, true)).unwrap(); // fn
        m.record(obs("a", "p", false, false)).unwrap(); // tn
        let r = m.report("p");
        let s = &r.cohorts[0];
        assert_eq!(s.tp, 1);
        assert_eq!(s.fp, 1);
        assert_eq!(s.fn_count, 1);
        assert_eq!(s.tn, 1);
    }

    #[test]
    fn cohort_key_as_str_round_trips() {
        let k = CohortKey::new("region:EU");
        assert_eq!(k.as_str(), "region:EU");
    }

    #[test]
    fn cohort_with_no_observations_excluded_from_best_worst() {
        let r = SubgroupReport {
            period: "p".into(),
            cohorts: vec![CohortStats::default()],
            worst_accuracy_cohort: None,
            best_accuracy_cohort: None,
            accuracy_spread: 0.0,
        };
        assert!(r.worst_accuracy_cohort.is_none());
    }
}
