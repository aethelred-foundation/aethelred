//! Baseline metric storage for anomaly detection.
//!
//! Stores rolling baselines for any operational metric (request rate,
//! latency, error rate, model output distribution). [`crate::anomaly`]
//! consumes these baselines to detect drift; this module is the storage
//! and computation layer.
//!
//! Each [`Baseline`] is computed from a window of [`MetricSample`]s with
//! mean / stdev / p50 / p95 / p99 — enough for distance-based
//! anomaly detection.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// MetricSample
// =============================================================================

/// One observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricSample {
    /// RFC 3339.
    pub at: String,
    /// Numeric value.
    pub value: f64,
}

// =============================================================================
// Baseline
// =============================================================================

/// Computed baseline.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    /// Sample count.
    pub count: u64,
    /// Mean.
    pub mean: f64,
    /// Sample standard deviation.
    pub stddev: f64,
    /// p50 (median).
    pub p50: f64,
    /// p95.
    pub p95: f64,
    /// p99.
    pub p99: f64,
    /// Min.
    pub min: f64,
    /// Max.
    pub max: f64,
    /// RFC 3339 baseline computed.
    pub computed_at: String,
}

impl Baseline {
    /// Compute a baseline from samples.
    pub fn from_samples(samples: &[MetricSample]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        let mut values: Vec<f64> = samples.iter().map(|s| s.value).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let count = values.len() as u64;
        let mean = values.iter().sum::<f64>() / count as f64;
        let var = if count > 1 {
            values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (count as f64 - 1.0)
        } else {
            0.0
        };
        let stddev = var.sqrt();
        Baseline {
            count,
            mean,
            stddev,
            p50: percentile(&values, 50.0),
            p95: percentile(&values, 95.0),
            p99: percentile(&values, 99.0),
            min: *values.first().unwrap(),
            max: *values.last().unwrap(),
            computed_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    /// Z-score for a value against this baseline.
    pub fn z_score(&self, value: f64) -> f64 {
        if self.stddev <= f64::EPSILON {
            return 0.0;
        }
        (value - self.mean) / self.stddev
    }

    /// `true` if `value` exceeds `n_sigma`.
    pub fn is_anomalous(&self, value: f64, n_sigma: f64) -> bool {
        self.z_score(value).abs() >= n_sigma
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len() as f64;
    let rank = (p / 100.0) * (n - 1.0);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = rank - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

// =============================================================================
// MetricKey
// =============================================================================

/// Composite key per (tenant, metric).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetricKey {
    /// Tenant.
    pub tenant: String,
    /// Metric name.
    pub metric: String,
}

impl MetricKey {
    /// New.
    pub fn new(tenant: impl Into<String>, metric: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            metric: metric.into(),
        }
    }
}

// =============================================================================
// BaselineRegistry
// =============================================================================

#[derive(Default)]
struct State {
    samples: HashMap<MetricKey, Vec<MetricSample>>,
    baselines: HashMap<MetricKey, Baseline>,
    /// Per-key window size cap.
    window_caps: HashMap<MetricKey, usize>,
}

/// Registry.
pub struct BaselineRegistry {
    state: RwLock<State>,
}

impl Default for BaselineRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for BaselineRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaselineRegistry")
            .field("metrics", &self.metric_count())
            .finish()
    }
}

impl BaselineRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set window cap for a metric (older samples evicted FIFO).
    pub fn set_window_cap(&self, key: MetricKey, cap: usize) -> SandboxResult<()> {
        if cap == 0 {
            return Err(SandboxError::Other("window cap must be > 0".into()));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("baseline registry poisoned".into()))?
            .window_caps
            .insert(key, cap);
        Ok(())
    }

    /// Record a sample.
    pub fn record(&self, key: MetricKey, value: f64) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("baseline registry poisoned".into()))?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let cap = g.window_caps.get(&key).copied();
        let v = g.samples.entry(key).or_default();
        v.push(MetricSample { at: now, value });
        if let Some(c) = cap {
            while v.len() > c {
                v.remove(0);
            }
        }
        Ok(())
    }

    /// (Re)compute baseline.
    pub fn compute_baseline(&self, key: &MetricKey) -> SandboxResult<Baseline> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("baseline registry poisoned".into()))?;
        let samples = g.samples.get(key).cloned().unwrap_or_default();
        let baseline = Baseline::from_samples(&samples);
        g.baselines.insert(key.clone(), baseline.clone());
        Ok(baseline)
    }

    /// Lookup baseline.
    pub fn baseline(&self, key: &MetricKey) -> Option<Baseline> {
        self.state.read().ok()?.baselines.get(key).cloned()
    }

    /// Check a value against a baseline.
    pub fn is_anomalous(&self, key: &MetricKey, value: f64, n_sigma: f64) -> bool {
        match self.baseline(key) {
            Some(b) => b.is_anomalous(value, n_sigma),
            None => false,
        }
    }

    /// Sample count for a metric.
    pub fn sample_count(&self, key: &MetricKey) -> usize {
        self.state
            .read()
            .map(|g| g.samples.get(key).map(|v| v.len()).unwrap_or(0))
            .unwrap_or(0)
    }

    /// Number of metrics tracked.
    pub fn metric_count(&self) -> usize {
        self.state.read().map(|g| g.samples.len()).unwrap_or(0)
    }

    /// Clear samples for a metric (keeps baseline).
    pub fn clear_samples(&self, key: &MetricKey) -> SandboxResult<()> {
        self.state
            .write()
            .map_err(|_| SandboxError::Other("baseline registry poisoned".into()))?
            .samples
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> MetricKey {
        MetricKey::new("FAB", "request_latency")
    }

    fn samples(values: &[f64]) -> Vec<MetricSample> {
        values
            .iter()
            .map(|&v| MetricSample {
                at: "2026-01-01T00:00:00Z".into(),
                value: v,
            })
            .collect()
    }

    #[test]
    fn baseline_from_empty() {
        let b = Baseline::from_samples(&[]);
        assert_eq!(b.count, 0);
    }

    #[test]
    fn baseline_simple_mean() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0, 4.0, 5.0]));
        assert!((b.mean - 3.0).abs() < 1e-9);
        assert_eq!(b.count, 5);
        assert_eq!(b.min, 1.0);
        assert_eq!(b.max, 5.0);
    }

    #[test]
    fn baseline_stddev_correct() {
        let b = Baseline::from_samples(&samples(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]));
        // Sample stddev = sqrt(32/7) ≈ 2.138.
        assert!((b.stddev - 2.138_089_935_299_395).abs() < 0.01);
    }

    #[test]
    fn baseline_p50_median() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0, 4.0, 5.0]));
        assert!((b.p50 - 3.0).abs() < 1e-9);
    }

    #[test]
    fn baseline_p95_high() {
        let mut values: Vec<f64> = (1..=100).map(|n| n as f64).collect();
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let s = samples(&values);
        let b = Baseline::from_samples(&s);
        assert!(b.p95 >= 95.0 && b.p95 <= 96.0);
    }

    #[test]
    fn z_score_zero_at_mean() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0]));
        assert!(b.z_score(2.0).abs() < 1e-9);
    }

    #[test]
    fn z_score_positive_above_mean() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0, 4.0, 5.0]));
        assert!(b.z_score(10.0) > 0.0);
    }

    #[test]
    fn is_anomalous_threshold() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0, 4.0, 5.0]));
        // 100 is way above mean 3, stddev ~1.58 → z ~61.
        assert!(b.is_anomalous(100.0, 3.0));
        // Slightly above mean is not anomalous.
        assert!(!b.is_anomalous(3.5, 3.0));
    }

    #[test]
    fn z_score_zero_when_stddev_zero() {
        let b = Baseline::from_samples(&samples(&[5.0, 5.0, 5.0]));
        assert_eq!(b.z_score(10.0), 0.0);
    }

    #[test]
    fn registry_record_and_count() {
        let r = BaselineRegistry::new();
        for v in [1.0, 2.0, 3.0] {
            r.record(key(), v).unwrap();
        }
        assert_eq!(r.sample_count(&key()), 3);
    }

    #[test]
    fn window_cap_evicts() {
        let r = BaselineRegistry::new();
        r.set_window_cap(key(), 5).unwrap();
        for i in 0..10 {
            r.record(key(), i as f64).unwrap();
        }
        assert_eq!(r.sample_count(&key()), 5);
    }

    #[test]
    fn invalid_window_cap_errors() {
        let r = BaselineRegistry::new();
        assert!(r.set_window_cap(key(), 0).is_err());
    }

    #[test]
    fn compute_baseline_stores() {
        let r = BaselineRegistry::new();
        for v in [1.0, 2.0, 3.0] {
            r.record(key(), v).unwrap();
        }
        let b = r.compute_baseline(&key()).unwrap();
        assert_eq!(b.count, 3);
        assert!(r.baseline(&key()).is_some());
    }

    #[test]
    fn anomaly_check_uses_baseline() {
        let r = BaselineRegistry::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            r.record(key(), v).unwrap();
        }
        r.compute_baseline(&key()).unwrap();
        assert!(r.is_anomalous(&key(), 100.0, 3.0));
        assert!(!r.is_anomalous(&key(), 3.0, 3.0));
    }

    #[test]
    fn anomaly_no_baseline_returns_false() {
        let r = BaselineRegistry::new();
        assert!(!r.is_anomalous(&key(), 10.0, 3.0));
    }

    #[test]
    fn clear_samples_works() {
        let r = BaselineRegistry::new();
        r.record(key(), 1.0).unwrap();
        r.clear_samples(&key()).unwrap();
        assert_eq!(r.sample_count(&key()), 0);
    }

    #[test]
    fn metric_count_tracks() {
        let r = BaselineRegistry::new();
        r.record(MetricKey::new("FAB", "a"), 1.0).unwrap();
        r.record(MetricKey::new("FAB", "b"), 1.0).unwrap();
        r.record(MetricKey::new("ENBD", "a"), 1.0).unwrap();
        assert_eq!(r.metric_count(), 3);
    }

    #[test]
    fn baseline_serde() {
        let b = Baseline::from_samples(&samples(&[1.0, 2.0, 3.0]));
        let j = serde_json::to_string(&b).unwrap();
        let p: Baseline = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn sample_serde() {
        let s = MetricSample {
            at: "2026-01-01T00:00:00Z".into(),
            value: 1.5,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: MetricSample = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn key_serde() {
        let k = key();
        let j = serde_json::to_string(&k).unwrap();
        let p: MetricKey = serde_json::from_str(&j).unwrap();
        assert_eq!(p, k);
    }

    #[test]
    fn percentile_unit_test() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&v, 0.0) - 1.0).abs() < 1e-9);
        assert!((percentile(&v, 100.0) - 5.0).abs() < 1e-9);
        assert!((percentile(&v, 50.0) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn percentile_empty_zero() {
        assert_eq!(percentile(&[], 50.0), 0.0);
    }

    #[test]
    fn many_samples_baseline() {
        let r = BaselineRegistry::new();
        for i in 1..=1000 {
            r.record(key(), i as f64).unwrap();
        }
        let b = r.compute_baseline(&key()).unwrap();
        assert!((b.mean - 500.5).abs() < 1.0);
    }

    #[test]
    fn isolated_per_tenant() {
        let r = BaselineRegistry::new();
        r.record(MetricKey::new("FAB", "x"), 1.0).unwrap();
        r.record(MetricKey::new("ENBD", "x"), 2.0).unwrap();
        assert_eq!(r.sample_count(&MetricKey::new("FAB", "x")), 1);
        assert_eq!(r.sample_count(&MetricKey::new("ENBD", "x")), 1);
    }
}
