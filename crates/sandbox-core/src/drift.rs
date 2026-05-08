//! Model & data drift detection.
//!
//! v0.2.2 [`crate::anomaly`] handles per-stream Z-score outliers. Drift is
//! the *distributional* analog: did the feature mix change vs. the
//! reference window? Production AI assurance needs both — anomaly catches
//! "this one event is weird"; drift catches "the whole population
//! shifted."
//!
//! ## Statistics shipped
//!
//! - **PSI (Population Stability Index)** — industry standard for credit
//!   risk. PSI < 0.10 = stable; 0.10–0.25 = warning; ≥ 0.25 = drift.
//! - **KL divergence** (D_KL(P‖Q)) — information-theoretic drift.
//! - **JS divergence** — symmetric KL.
//! - **Wasserstein-1** distance for ordered numeric distributions.
//! - **Chi-squared** for categorical drift.
//!
//! ## API shape
//!
//! - [`Histogram`] — bucketed count distribution.
//! - [`DriftDetector`] — holds a reference distribution, accepts new
//!   samples, computes PSI / KL / JS / Wasserstein and emits
//!   [`DriftEvent`] when thresholds are breached.
//! - [`DriftConfig`] — tunable thresholds.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// Histogram
// =============================================================================

/// Bucketed count distribution. Buckets are user-defined upper bounds
/// (sorted ascending). The last bucket is `+∞`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Histogram {
    /// Sorted upper-bound bucket edges.
    pub edges: Vec<f64>,
    /// `counts.len() == edges.len() + 1` (last is `+∞`).
    pub counts: Vec<u64>,
    /// Total samples.
    pub total: u64,
}

impl Histogram {
    /// New histogram with the given (sorted) bucket edges.
    pub fn new(mut edges: Vec<f64>) -> Self {
        edges.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = edges.len() + 1;
        Self {
            edges,
            counts: vec![0u64; n],
            total: 0,
        }
    }

    /// Standard 10-bucket uniform spacing on `[0, 1]` — useful for
    /// probability scores.
    pub fn unit_interval_decile() -> Self {
        Self::new(vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    }

    /// Observe a single sample.
    pub fn observe(&mut self, value: f64) {
        let mut idx = self.edges.len(); // default to +inf
        for (i, &e) in self.edges.iter().enumerate() {
            if value <= e {
                idx = i;
                break;
            }
        }
        self.counts[idx] += 1;
        self.total += 1;
    }

    /// Observe multiple samples.
    pub fn observe_all(&mut self, values: &[f64]) {
        for v in values {
            self.observe(*v);
        }
    }

    /// Probability density (counts / total). Adds a tiny epsilon to zero
    /// buckets to keep KL/PSI finite.
    pub fn density(&self) -> Vec<f64> {
        if self.total == 0 {
            return self.counts.iter().map(|_| 0.0).collect();
        }
        let denom = self.total as f64;
        self.counts
            .iter()
            .map(|c| {
                let p = (*c as f64) / denom;
                p.max(1e-12)
            })
            .collect()
    }

    /// Number of buckets (`edges.len() + 1`).
    pub fn bucket_count(&self) -> usize {
        self.counts.len()
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Population Stability Index (PSI).
///
/// `Σ (p_i − q_i) · ln(p_i / q_i)`.
pub fn psi(reference: &Histogram, current: &Histogram) -> f64 {
    let p = reference.density();
    let q = current.density();
    let n = p.len().min(q.len());
    let mut sum = 0.0;
    for i in 0..n {
        sum += (p[i] - q[i]) * (p[i] / q[i]).ln();
    }
    sum
}

/// Kullback-Leibler divergence `D_KL(reference ‖ current)`.
pub fn kl_divergence(reference: &Histogram, current: &Histogram) -> f64 {
    let p = reference.density();
    let q = current.density();
    let n = p.len().min(q.len());
    let mut sum = 0.0;
    for i in 0..n {
        sum += p[i] * (p[i] / q[i]).ln();
    }
    sum
}

/// Symmetric Jensen-Shannon divergence (mean of KL(P‖M) and KL(Q‖M),
/// where M = (P+Q)/2).
pub fn js_divergence(reference: &Histogram, current: &Histogram) -> f64 {
    let p = reference.density();
    let q = current.density();
    let n = p.len().min(q.len());
    let m: Vec<f64> = (0..n).map(|i| 0.5 * (p[i] + q[i])).collect();
    let mut kl_pm = 0.0;
    let mut kl_qm = 0.0;
    for i in 0..n {
        kl_pm += p[i] * (p[i] / m[i]).ln();
        kl_qm += q[i] * (q[i] / m[i]).ln();
    }
    0.5 * (kl_pm + kl_qm)
}

/// 1-Wasserstein distance between two ordered numeric distributions.
///
/// Computed as `Σ |F_p(x) - F_q(x)|` over bucket edges (proxy for the
/// full integral). Suitable for ordered-numeric features.
pub fn wasserstein1(reference: &Histogram, current: &Histogram) -> f64 {
    let p = reference.density();
    let q = current.density();
    let n = p.len().min(q.len());
    let mut cum_p = 0.0;
    let mut cum_q = 0.0;
    let mut sum = 0.0;
    for i in 0..n {
        cum_p += p[i];
        cum_q += q[i];
        sum += (cum_p - cum_q).abs();
    }
    sum
}

/// Chi-squared distance for categorical drift.
pub fn chi_squared(reference: &Histogram, current: &Histogram) -> f64 {
    let p = reference.density();
    let q = current.density();
    let n = p.len().min(q.len());
    let mut sum = 0.0;
    for i in 0..n {
        let denom = p[i] + q[i];
        if denom > 0.0 {
            sum += (p[i] - q[i]).powi(2) / denom;
        }
    }
    sum
}

// =============================================================================
// DriftConfig + DriftEvent
// =============================================================================

/// Tunable thresholds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftConfig {
    /// PSI threshold for `Severity::Warning`. Default: 0.10 (industry).
    pub psi_warning: f64,
    /// PSI threshold for `Severity::Critical`. Default: 0.25.
    pub psi_critical: f64,
    /// KL divergence warning threshold.
    pub kl_warning: f64,
    /// KL divergence critical threshold.
    pub kl_critical: f64,
    /// Minimum samples in current window before drift can fire.
    pub min_samples: u64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            psi_warning: 0.10,
            psi_critical: 0.25,
            kl_warning: 0.05,
            kl_critical: 0.20,
            min_samples: 100,
        }
    }
}

impl DriftConfig {
    /// Aggressive: low thresholds + small min samples.
    pub fn aggressive() -> Self {
        Self {
            psi_warning: 0.05,
            psi_critical: 0.15,
            kl_warning: 0.02,
            kl_critical: 0.10,
            min_samples: 50,
        }
    }
    /// Conservative.
    pub fn conservative() -> Self {
        Self {
            psi_warning: 0.20,
            psi_critical: 0.50,
            kl_warning: 0.10,
            kl_critical: 0.40,
            min_samples: 500,
        }
    }
}

/// Drift severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// No drift.
    Stable,
    /// Mild drift.
    Warning,
    /// Significant drift.
    Critical,
}

/// Emitted when drift is detected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftEvent {
    /// Stable feature key (e.g., `"FAB:credit_decision:dti_ratio"`).
    pub feature: String,
    /// PSI value.
    pub psi: f64,
    /// KL divergence.
    pub kl: f64,
    /// JS divergence.
    pub js: f64,
    /// Wasserstein-1.
    pub wasserstein: f64,
    /// Severity.
    pub severity: DriftSeverity,
    /// RFC 3339 timestamp.
    pub detected_at: String,
    /// Sample counts.
    pub reference_total: u64,
    /// Current window total.
    pub current_total: u64,
}

// =============================================================================
// DriftDetector
// =============================================================================

#[derive(Debug)]
struct FeatureEntry {
    reference: Histogram,
    current: Histogram,
}

/// Top-level drift detector.
pub struct DriftDetector {
    config: DriftConfig,
    features: RwLock<BTreeMap<String, FeatureEntry>>,
    events: RwLock<Vec<DriftEvent>>,
}

impl DriftDetector {
    /// New detector.
    pub fn new(config: DriftConfig) -> Self {
        Self {
            config,
            features: RwLock::new(BTreeMap::new()),
            events: RwLock::new(Vec::new()),
        }
    }

    /// Default detector.
    pub fn default_config() -> Self {
        Self::new(DriftConfig::default())
    }

    /// Set or replace the reference distribution for `feature`.
    pub fn set_reference(&self, feature: impl Into<String>, hist: Histogram) {
        let mut g = match self.features.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let edges = hist.edges.clone();
        g.insert(
            feature.into(),
            FeatureEntry {
                reference: hist,
                current: Histogram::new(edges),
            },
        );
    }

    /// Observe a sample for `feature`. The bucketing comes from the
    /// reference's edges (must be set first).
    pub fn observe(&self, feature: &str, value: f64) -> crate::SandboxResult<()> {
        let mut g = match self.features.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let entry = g.get_mut(feature).ok_or_else(|| {
            crate::SandboxError::Other(format!(
                "drift: no reference set for feature {feature}"
            ))
        })?;
        entry.current.observe(value);
        Ok(())
    }

    /// Reset the current window for `feature` (e.g., after each reporting
    /// period).
    pub fn reset_current(&self, feature: &str) {
        let mut g = match self.features.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let Some(e) = g.get_mut(feature) {
            let edges = e.reference.edges.clone();
            e.current = Histogram::new(edges);
        }
    }

    /// Run the drift check for `feature` and return the event if drift
    /// thresholds breach.
    pub fn check(&self, feature: &str) -> crate::SandboxResult<Option<DriftEvent>> {
        let g = match self.features.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let entry = g.get(feature).ok_or_else(|| {
            crate::SandboxError::Other(format!("drift: feature {feature} not found"))
        })?;
        if entry.current.total < self.config.min_samples {
            return Ok(None);
        }
        let psi_v = psi(&entry.reference, &entry.current);
        let kl_v = kl_divergence(&entry.reference, &entry.current);
        let js_v = js_divergence(&entry.reference, &entry.current);
        let w1 = wasserstein1(&entry.reference, &entry.current);

        let severity = if psi_v >= self.config.psi_critical
            || kl_v >= self.config.kl_critical
        {
            DriftSeverity::Critical
        } else if psi_v >= self.config.psi_warning || kl_v >= self.config.kl_warning {
            DriftSeverity::Warning
        } else {
            DriftSeverity::Stable
        };

        if matches!(severity, DriftSeverity::Stable) {
            return Ok(None);
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let event = DriftEvent {
            feature: feature.to_string(),
            psi: psi_v,
            kl: kl_v,
            js: js_v,
            wasserstein: w1,
            severity,
            detected_at: now,
            reference_total: entry.reference.total,
            current_total: entry.current.total,
        };
        drop(g);
        let mut ev = match self.events.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        ev.push(event.clone());
        Ok(Some(event))
    }

    /// Number of registered features.
    pub fn feature_count(&self) -> usize {
        self.features.read().map(|g| g.len()).unwrap_or(0)
    }

    /// All drift events seen so far.
    pub fn events(&self) -> Vec<DriftEvent> {
        match self.events.read() {
            Ok(g) => g.clone(),
            Err(e) => e.into_inner().clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deciles() -> Vec<f64> {
        vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    }

    #[test]
    fn histogram_observe_increments_correct_bucket() {
        let mut h = Histogram::new(vec![0.5, 1.0]);
        h.observe(0.3);
        h.observe(0.6);
        h.observe(2.0);
        assert_eq!(h.counts[0], 1);
        assert_eq!(h.counts[1], 1);
        assert_eq!(h.counts[2], 1);
        assert_eq!(h.total, 3);
    }

    #[test]
    fn histogram_density_sums_to_one() {
        let mut h = Histogram::new(deciles());
        for v in [0.05, 0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85, 0.95] {
            h.observe(v);
        }
        let d = h.density();
        let sum: f64 = d.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6);
    }

    #[test]
    fn histogram_unit_decile_constructor() {
        let h = Histogram::unit_interval_decile();
        assert_eq!(h.edges.len(), 9);
        assert_eq!(h.bucket_count(), 10);
    }

    #[test]
    fn psi_zero_for_identical_distributions() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for v in 0..100 {
            let x = (v as f64) / 100.0;
            a.observe(x);
            b.observe(x);
        }
        let v = psi(&a, &b);
        assert!(v.abs() < 1e-6);
    }

    #[test]
    fn psi_positive_for_shifted_distributions() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        // Reference all in low range.
        for _ in 0..1000 {
            a.observe(0.1);
        }
        // Current all in high range.
        for _ in 0..1000 {
            b.observe(0.9);
        }
        let v = psi(&a, &b);
        assert!(v > 0.5);
    }

    #[test]
    fn kl_zero_for_identical() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for _ in 0..100 {
            a.observe(0.5);
            b.observe(0.5);
        }
        let v = kl_divergence(&a, &b);
        assert!(v.abs() < 1e-6);
    }

    #[test]
    fn js_symmetric() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for _ in 0..50 {
            a.observe(0.3);
        }
        for _ in 0..50 {
            b.observe(0.7);
        }
        let ab = js_divergence(&a, &b);
        let ba = js_divergence(&b, &a);
        assert!((ab - ba).abs() < 1e-9);
    }

    #[test]
    fn wasserstein_zero_for_identical() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for _ in 0..100 {
            a.observe(0.5);
            b.observe(0.5);
        }
        let v = wasserstein1(&a, &b);
        assert!(v.abs() < 1e-6);
    }

    #[test]
    fn wasserstein_positive_for_shifted() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for _ in 0..1000 {
            a.observe(0.1);
            b.observe(0.9);
        }
        let v = wasserstein1(&a, &b);
        assert!(v > 1.0);
    }

    #[test]
    fn chi_squared_zero_for_identical() {
        let mut a = Histogram::new(deciles());
        let mut b = Histogram::new(deciles());
        for _ in 0..100 {
            a.observe(0.5);
            b.observe(0.5);
        }
        let v = chi_squared(&a, &b);
        assert!(v.abs() < 1e-6);
    }

    #[test]
    fn detector_set_reference_then_observe() {
        let det = DriftDetector::default_config();
        let mut ref_hist = Histogram::new(deciles());
        for _ in 0..1000 {
            ref_hist.observe(0.5);
        }
        det.set_reference("f", ref_hist);
        for _ in 0..200 {
            det.observe("f", 0.5).unwrap();
        }
        // Identical distributions → no drift.
        let r = det.check("f").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn detector_fires_on_drift() {
        let det = DriftDetector::default_config();
        let mut ref_hist = Histogram::new(deciles());
        for _ in 0..1000 {
            ref_hist.observe(0.1);
        }
        det.set_reference("f", ref_hist);
        for _ in 0..200 {
            det.observe("f", 0.9).unwrap();
        }
        let r = det.check("f").unwrap();
        assert!(r.is_some());
        let e = r.unwrap();
        assert!(matches!(
            e.severity,
            DriftSeverity::Warning | DriftSeverity::Critical
        ));
    }

    #[test]
    fn detector_silent_below_min_samples() {
        let det = DriftDetector::default_config();
        let mut ref_hist = Histogram::new(deciles());
        ref_hist.observe(0.1);
        det.set_reference("f", ref_hist);
        det.observe("f", 0.9).unwrap();
        let r = det.check("f").unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn detector_unknown_feature_errors() {
        let det = DriftDetector::default_config();
        let r = det.observe("nope", 0.5);
        assert!(r.is_err());
    }

    #[test]
    fn detector_check_unknown_feature_errors() {
        let det = DriftDetector::default_config();
        let r = det.check("nope");
        assert!(r.is_err());
    }

    #[test]
    fn detector_reset_clears_current() {
        let det = DriftDetector::default_config();
        let mut ref_hist = Histogram::new(deciles());
        ref_hist.observe(0.5);
        det.set_reference("f", ref_hist);
        for _ in 0..200 {
            det.observe("f", 0.5).unwrap();
        }
        det.reset_current("f");
        let r = det.check("f").unwrap();
        // No samples in current after reset → silent.
        assert!(r.is_none());
    }

    #[test]
    fn detector_records_events() {
        let det = DriftDetector::default_config();
        let mut ref_hist = Histogram::new(deciles());
        for _ in 0..1000 {
            ref_hist.observe(0.1);
        }
        det.set_reference("f", ref_hist);
        for _ in 0..200 {
            det.observe("f", 0.9).unwrap();
        }
        det.check("f").unwrap();
        assert!(!det.events().is_empty());
    }

    #[test]
    fn detector_feature_count_increments() {
        let det = DriftDetector::default_config();
        det.set_reference("a", Histogram::new(deciles()));
        det.set_reference("b", Histogram::new(deciles()));
        assert_eq!(det.feature_count(), 2);
    }

    #[test]
    fn aggressive_config_lower_thresholds() {
        let c = DriftConfig::aggressive();
        let d = DriftConfig::default();
        assert!(c.psi_warning < d.psi_warning);
        assert!(c.psi_critical < d.psi_critical);
        assert!(c.min_samples < d.min_samples);
    }

    #[test]
    fn conservative_config_higher_thresholds() {
        let c = DriftConfig::conservative();
        let d = DriftConfig::default();
        assert!(c.psi_warning > d.psi_warning);
        assert!(c.psi_critical > d.psi_critical);
        assert!(c.min_samples > d.min_samples);
    }

    #[test]
    fn drift_event_serde_round_trip() {
        let e = DriftEvent {
            feature: "f".into(),
            psi: 0.3,
            kl: 0.15,
            js: 0.05,
            wasserstein: 0.5,
            severity: DriftSeverity::Critical,
            detected_at: "2026-05-06T10:00:00Z".into(),
            reference_total: 1000,
            current_total: 200,
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: DriftEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn drift_severity_serde() {
        let s = DriftSeverity::Critical;
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(j, "\"critical\"");
    }

    #[test]
    fn histogram_serde_round_trip() {
        let mut h = Histogram::new(vec![0.5, 1.0]);
        h.observe(0.3);
        let j = serde_json::to_string(&h).unwrap();
        let p: Histogram = serde_json::from_str(&j).unwrap();
        assert_eq!(p, h);
    }
}
