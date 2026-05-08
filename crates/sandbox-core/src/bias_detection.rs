//! Bias / fairness detection.
//!
//! Implements the standard fairness metrics used in EU AI Act compliance,
//! NIST AI RMF, and SR 11-7 model validation:
//!
//! - **Demographic parity** — outcome rate is the same across groups.
//! - **Equal opportunity** — true-positive rate is the same across groups.
//! - **Equalized odds** — both TPR and FPR are equal across groups.
//! - **Disparate impact ratio (DIR)** — selection rate ratio between
//!   protected and reference group; the EEOC's "four-fifths rule" requires
//!   DIR ≥ 0.8.
//!
//! Operators feed labeled outcome events into a [`FairnessAuditor`] and
//! query [`FairnessReport`]s. The auditor is **descriptive, not prescriptive**:
//! it computes metrics and flags threshold breaches, but the response (re-train,
//! audit, suspend) belongs to the operator.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ProtectedClass + GroupLabel
// =============================================================================

/// Protected class (e.g. `"gender"`, `"age_band"`, `"race"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtectedClass(pub String);

impl ProtectedClass {
    /// New class.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One group within a protected class (e.g. `"female"`, `"18-24"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupLabel(pub String);

impl GroupLabel {
    /// New label.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// OutcomeEvent
// =============================================================================

/// One labeled outcome (model decision + ground truth + group).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutcomeEvent {
    /// Group membership (one entry per protected class).
    pub groups: HashMap<ProtectedClass, GroupLabel>,
    /// Model's decision: `true` = positive (e.g., loan approved).
    pub decision_positive: bool,
    /// Ground truth label (`None` if unknown).
    pub truth_positive: Option<bool>,
}

// =============================================================================
// GroupStats
// =============================================================================

/// Per-group counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupStats {
    /// Group label.
    pub group: GroupLabel,
    /// Total events.
    pub total: u64,
    /// Decisions = positive.
    pub decision_positive: u64,
    /// Decisions = positive AND truth = positive.
    pub true_positive: u64,
    /// Decisions = positive AND truth = negative.
    pub false_positive: u64,
    /// Decisions = negative AND truth = positive.
    pub false_negative: u64,
    /// Decisions = negative AND truth = negative.
    pub true_negative: u64,
}

impl GroupStats {
    /// Selection rate = `decision_positive / total`.
    pub fn selection_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.decision_positive as f64 / self.total as f64
    }
    /// True-positive rate (recall): `tp / (tp + fn)`.
    pub fn tpr(&self) -> Option<f64> {
        let pos = self.true_positive + self.false_negative;
        if pos == 0 {
            return None;
        }
        Some(self.true_positive as f64 / pos as f64)
    }
    /// False-positive rate: `fp / (fp + tn)`.
    pub fn fpr(&self) -> Option<f64> {
        let neg = self.false_positive + self.true_negative;
        if neg == 0 {
            return None;
        }
        Some(self.false_positive as f64 / neg as f64)
    }
}

// =============================================================================
// FairnessReport
// =============================================================================

/// Whole report for one protected class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FairnessReport {
    /// Class examined.
    pub class: ProtectedClass,
    /// Group used as reference (typically the *largest* or operator-chosen).
    pub reference_group: GroupLabel,
    /// Per-group stats.
    pub groups: Vec<GroupStats>,
    /// Demographic parity gap = max selection-rate diff between any group and reference.
    pub demographic_parity_gap: f64,
    /// Disparate impact ratio = min(group_rate / reference_rate).
    pub disparate_impact_ratio: f64,
    /// Equal-opportunity gap = max |TPR_group - TPR_reference|. None if any group missing TPR.
    pub equal_opportunity_gap: Option<f64>,
    /// Equalized-odds gap = max(TPR-gap, FPR-gap). None if missing.
    pub equalized_odds_gap: Option<f64>,
    /// `true` if `disparate_impact_ratio >= 0.8` (EEOC four-fifths rule).
    pub passes_four_fifths_rule: bool,
}

// =============================================================================
// FairnessAuditor
// =============================================================================

/// Fairness auditor — receives [`OutcomeEvent`]s and produces reports per
/// protected class.
#[derive(Default)]
pub struct FairnessAuditor {
    state: RwLock<Vec<OutcomeEvent>>,
}

impl std::fmt::Debug for FairnessAuditor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FairnessAuditor")
            .field("events", &self.event_count())
            .finish()
    }
}

impl FairnessAuditor {
    /// New auditor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one outcome.
    pub fn record(&self, event: OutcomeEvent) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("fairness state poisoned".into()))?
            .push(event);
        Ok(())
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.state.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Compute a report for `class`. Errors if no events have a label for
    /// `class`. The reference group is auto-chosen as the largest group;
    /// callers can override via [`Self::report_with_reference`].
    pub fn report(&self, class: &ProtectedClass) -> SandboxResult<FairnessReport> {
        // Auto-pick the largest group as reference.
        let counts = self.group_totals(class)?;
        if counts.is_empty() {
            return Err(SandboxError::Other(format!(
                "no events for class {}",
                class.as_str()
            )));
        }
        let reference = counts
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(g, _)| g)
            .ok_or_else(|| SandboxError::Other("no groups".into()))?;
        self.report_with_reference(class, &reference)
    }

    /// Compute a report for `class` with explicit `reference`.
    pub fn report_with_reference(
        &self,
        class: &ProtectedClass,
        reference: &GroupLabel,
    ) -> SandboxResult<FairnessReport> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("fairness state poisoned".into()))?;
        let mut by_group: HashMap<GroupLabel, GroupStats> = HashMap::new();
        for ev in g.iter() {
            let label = match ev.groups.get(class) {
                Some(l) => l.clone(),
                None => continue,
            };
            let s = by_group.entry(label.clone()).or_insert(GroupStats {
                group: label,
                ..Default::default()
            });
            s.total += 1;
            if ev.decision_positive {
                s.decision_positive += 1;
            }
            match (ev.decision_positive, ev.truth_positive) {
                (true, Some(true)) => s.true_positive += 1,
                (true, Some(false)) => s.false_positive += 1,
                (false, Some(true)) => s.false_negative += 1,
                (false, Some(false)) => s.true_negative += 1,
                _ => {}
            }
        }
        if by_group.is_empty() {
            return Err(SandboxError::Other(format!(
                "no events for class {}",
                class.as_str()
            )));
        }
        let ref_stats = by_group
            .get(reference)
            .cloned()
            .ok_or_else(|| {
                SandboxError::Other(format!(
                    "reference group {} not found in events",
                    reference.as_str()
                ))
            })?;
        let ref_rate = ref_stats.selection_rate();
        let mut max_dp_gap = 0.0_f64;
        let mut min_dir = f64::INFINITY;
        let mut max_eo_gap: Option<f64> = None;
        let mut max_eodds_gap: Option<f64> = None;
        let mut groups: Vec<GroupStats> = by_group.values().cloned().collect();
        groups.sort_by(|a, b| a.group.0.cmp(&b.group.0));
        for s in &groups {
            let rate = s.selection_rate();
            let dp = (rate - ref_rate).abs();
            if dp > max_dp_gap {
                max_dp_gap = dp;
            }
            if ref_rate > 0.0 {
                let dir = rate / ref_rate;
                if dir < min_dir {
                    min_dir = dir;
                }
            }
            if let (Some(t1), Some(t2)) = (s.tpr(), ref_stats.tpr()) {
                let g = (t1 - t2).abs();
                max_eo_gap = Some(max_eo_gap.unwrap_or(0.0).max(g));
            }
            if let (Some(t1), Some(t2), Some(f1), Some(f2)) =
                (s.tpr(), ref_stats.tpr(), s.fpr(), ref_stats.fpr())
            {
                let gap = (t1 - t2).abs().max((f1 - f2).abs());
                max_eodds_gap = Some(max_eodds_gap.unwrap_or(0.0).max(gap));
            }
        }
        if !min_dir.is_finite() {
            min_dir = 0.0;
        }
        Ok(FairnessReport {
            class: class.clone(),
            reference_group: reference.clone(),
            groups,
            demographic_parity_gap: max_dp_gap,
            disparate_impact_ratio: min_dir,
            equal_opportunity_gap: max_eo_gap,
            equalized_odds_gap: max_eodds_gap,
            passes_four_fifths_rule: min_dir >= 0.8,
        })
    }

    fn group_totals(&self, class: &ProtectedClass) -> SandboxResult<Vec<(GroupLabel, u64)>> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("fairness state poisoned".into()))?;
        let mut counts: HashMap<GroupLabel, u64> = HashMap::new();
        for ev in g.iter() {
            if let Some(l) = ev.groups.get(class) {
                *counts.entry(l.clone()).or_insert(0) += 1;
            }
        }
        Ok(counts.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(class: &str, group: &str, decision: bool, truth: Option<bool>) -> OutcomeEvent {
        let mut groups = HashMap::new();
        groups.insert(ProtectedClass::new(class), GroupLabel::new(group));
        OutcomeEvent {
            groups,
            decision_positive: decision,
            truth_positive: truth,
        }
    }

    #[test]
    fn empty_class_errors() {
        let a = FairnessAuditor::new();
        assert!(a.report(&ProtectedClass::new("gender")).is_err());
    }

    #[test]
    fn one_group_perfect_parity() {
        let a = FairnessAuditor::new();
        for _ in 0..10 {
            a.record(evt("gender", "f", true, Some(true))).unwrap();
        }
        let r = a.report(&ProtectedClass::new("gender")).unwrap();
        assert_eq!(r.demographic_parity_gap, 0.0);
        assert!(r.passes_four_fifths_rule);
    }

    #[test]
    fn equal_groups_equal_rates_no_gap() {
        let a = FairnessAuditor::new();
        for _ in 0..10 {
            a.record(evt("gender", "f", true, Some(true))).unwrap();
        }
        for _ in 0..10 {
            a.record(evt("gender", "m", true, Some(true))).unwrap();
        }
        let r = a.report(&ProtectedClass::new("gender")).unwrap();
        assert_eq!(r.demographic_parity_gap, 0.0);
        assert_eq!(r.disparate_impact_ratio, 1.0);
    }

    #[test]
    fn unequal_groups_have_gap() {
        let a = FairnessAuditor::new();
        // Group F: 100% positive.
        for _ in 0..10 {
            a.record(evt("gender", "f", true, None)).unwrap();
        }
        // Group M: 50% positive.
        for _ in 0..5 {
            a.record(evt("gender", "m", true, None)).unwrap();
        }
        for _ in 0..5 {
            a.record(evt("gender", "m", false, None)).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("gender"), &GroupLabel::new("f"))
            .unwrap();
        // M selection rate = 0.5, F = 1.0.
        assert!((r.demographic_parity_gap - 0.5).abs() < 1e-9);
        assert!((r.disparate_impact_ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn four_fifths_violation_flagged() {
        let a = FairnessAuditor::new();
        for _ in 0..100 {
            a.record(evt("gender", "f", true, None)).unwrap();
        }
        // M: 50% selection.
        for _ in 0..50 {
            a.record(evt("gender", "m", true, None)).unwrap();
        }
        for _ in 0..50 {
            a.record(evt("gender", "m", false, None)).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("gender"), &GroupLabel::new("f"))
            .unwrap();
        assert!(!r.passes_four_fifths_rule);
    }

    #[test]
    fn four_fifths_pass_at_eighty_percent() {
        let a = FairnessAuditor::new();
        // F: 100/100 = 1.0
        for _ in 0..100 {
            a.record(evt("gender", "f", true, None)).unwrap();
        }
        // M: 80/100 = 0.8
        for _ in 0..80 {
            a.record(evt("gender", "m", true, None)).unwrap();
        }
        for _ in 0..20 {
            a.record(evt("gender", "m", false, None)).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("gender"), &GroupLabel::new("f"))
            .unwrap();
        assert!(r.passes_four_fifths_rule);
    }

    #[test]
    fn equal_opportunity_gap_computed() {
        let a = FairnessAuditor::new();
        // Group F: TPR = 1.0 (10 TP, 0 FN).
        for _ in 0..10 {
            a.record(evt("gender", "f", true, Some(true))).unwrap();
        }
        // Group M: TPR = 0.5 (5 TP, 5 FN).
        for _ in 0..5 {
            a.record(evt("gender", "m", true, Some(true))).unwrap();
        }
        for _ in 0..5 {
            a.record(evt("gender", "m", false, Some(true))).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("gender"), &GroupLabel::new("f"))
            .unwrap();
        let gap = r.equal_opportunity_gap.unwrap();
        assert!((gap - 0.5).abs() < 1e-9);
    }

    #[test]
    fn equal_opportunity_none_when_no_truth() {
        let a = FairnessAuditor::new();
        for _ in 0..10 {
            a.record(evt("gender", "f", true, None)).unwrap();
        }
        let r = a.report(&ProtectedClass::new("gender")).unwrap();
        assert!(r.equal_opportunity_gap.is_none());
    }

    #[test]
    fn group_stats_tpr_correct() {
        let s = GroupStats {
            group: GroupLabel::new("g"),
            total: 10,
            decision_positive: 7,
            true_positive: 6,
            false_positive: 1,
            false_negative: 2,
            true_negative: 1,
        };
        // TPR = 6 / (6 + 2) = 0.75.
        assert!((s.tpr().unwrap() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn group_stats_fpr_correct() {
        let s = GroupStats {
            group: GroupLabel::new("g"),
            total: 10,
            decision_positive: 5,
            true_positive: 4,
            false_positive: 1,
            false_negative: 1,
            true_negative: 4,
        };
        // FPR = 1 / (1 + 4) = 0.2.
        assert!((s.fpr().unwrap() - 0.2).abs() < 1e-9);
    }

    #[test]
    fn group_stats_selection_rate_zero_for_empty() {
        let s = GroupStats::default();
        assert_eq!(s.selection_rate(), 0.0);
    }

    #[test]
    fn three_groups_minimum_dir() {
        let a = FairnessAuditor::new();
        // A: 100/100 = 1.0
        for _ in 0..100 {
            a.record(evt("g", "a", true, None)).unwrap();
        }
        // B: 70/100 = 0.7
        for _ in 0..70 {
            a.record(evt("g", "b", true, None)).unwrap();
        }
        for _ in 0..30 {
            a.record(evt("g", "b", false, None)).unwrap();
        }
        // C: 30/100 = 0.3
        for _ in 0..30 {
            a.record(evt("g", "c", true, None)).unwrap();
        }
        for _ in 0..70 {
            a.record(evt("g", "c", false, None)).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("g"), &GroupLabel::new("a"))
            .unwrap();
        assert!((r.disparate_impact_ratio - 0.3).abs() < 1e-9, "min dir = group C");
    }

    #[test]
    fn auto_reference_picks_largest_group() {
        let a = FairnessAuditor::new();
        for _ in 0..100 {
            a.record(evt("g", "big", true, None)).unwrap();
        }
        for _ in 0..10 {
            a.record(evt("g", "small", false, None)).unwrap();
        }
        let r = a.report(&ProtectedClass::new("g")).unwrap();
        assert_eq!(r.reference_group, GroupLabel::new("big"));
    }

    #[test]
    fn report_unknown_reference_errors() {
        let a = FairnessAuditor::new();
        a.record(evt("g", "x", true, None)).unwrap();
        assert!(a
            .report_with_reference(&ProtectedClass::new("g"), &GroupLabel::new("ghost"))
            .is_err());
    }

    #[test]
    fn record_increments_count() {
        let a = FairnessAuditor::new();
        a.record(evt("g", "x", true, None)).unwrap();
        a.record(evt("g", "x", false, None)).unwrap();
        assert_eq!(a.event_count(), 2);
    }

    #[test]
    fn report_serde_round_trip() {
        let a = FairnessAuditor::new();
        a.record(evt("g", "x", true, Some(true))).unwrap();
        let r = a.report(&ProtectedClass::new("g")).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: FairnessReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn protected_class_serde_transparent() {
        let c = ProtectedClass::new("gender");
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"gender\"");
    }

    #[test]
    fn group_label_serde_transparent() {
        let g = GroupLabel::new("f");
        assert_eq!(serde_json::to_string(&g).unwrap(), "\"f\"");
    }

    #[test]
    fn outcome_event_serde() {
        let e = evt("g", "x", true, Some(true));
        let j = serde_json::to_string(&e).unwrap();
        let p: OutcomeEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn report_lists_groups_alphabetically() {
        let a = FairnessAuditor::new();
        for _ in 0..10 {
            a.record(evt("g", "z", true, None)).unwrap();
        }
        for _ in 0..10 {
            a.record(evt("g", "a", true, None)).unwrap();
        }
        let r = a.report(&ProtectedClass::new("g")).unwrap();
        assert_eq!(r.groups[0].group, GroupLabel::new("a"));
    }

    #[test]
    fn group_stats_total_zero_returns_no_tpr() {
        let s = GroupStats::default();
        assert!(s.tpr().is_none());
        assert!(s.fpr().is_none());
    }

    #[test]
    fn equalized_odds_includes_fpr_difference() {
        let a = FairnessAuditor::new();
        // Group F: TPR=1.0, FPR=0.0.
        for _ in 0..10 {
            a.record(evt("g", "f", true, Some(true))).unwrap();
        }
        for _ in 0..10 {
            a.record(evt("g", "f", false, Some(false))).unwrap();
        }
        // Group M: TPR=1.0, FPR=1.0.
        for _ in 0..10 {
            a.record(evt("g", "m", true, Some(true))).unwrap();
        }
        for _ in 0..10 {
            a.record(evt("g", "m", true, Some(false))).unwrap();
        }
        let r = a
            .report_with_reference(&ProtectedClass::new("g"), &GroupLabel::new("f"))
            .unwrap();
        // EO gap for TPR is 0, but FPR gap is 1.0 → equalized-odds should be 1.0.
        let eg = r.equalized_odds_gap.unwrap();
        assert!((eg - 1.0).abs() < 1e-9);
    }
}
