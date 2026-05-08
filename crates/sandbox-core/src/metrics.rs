//! Prometheus-compatible metrics.
//!
//! A lightweight, dependency-free metrics layer. Exposes counters,
//! histograms, and gauges, with a Prometheus text-format exporter that
//! plugs into any Prometheus / OpenTelemetry / Grafana stack.
//!
//! ## Why hand-rolled
//!
//! The official `metrics` and `prometheus` crates pull in significant
//! transitive deps. For the sandbox, we want a small, auditable surface
//! that production deployments can swap for full-fat metrics if they
//! prefer (and the `MetricsRecorder` trait below makes that easy).
//!
//! ## Standard metrics
//!
//! [`SandboxMetrics`] exposes the canonical metric set every Aethelred
//! deployment should expose:
//!
//! - `aethelred_seals_total` (counter, labels: `sector`, `workflow_id`, `outcome`)
//! - `aethelred_seal_duration_seconds` (histogram)
//! - `aethelred_evidence_log_size_bytes` (gauge)
//! - `aethelred_policy_denials_total` (counter, labels: `gate_id`)
//! - `aethelred_signature_failures_total` (counter, labels: `signer_id`)
//! - `aethelred_attestation_failures_total` (counter, labels: `platform`)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};

/// Label set — sorted for stable text-format output.
pub type Labels = BTreeMap<String, String>;

/// A monotonic counter.
#[derive(Debug, Default)]
pub struct Counter {
    inner: RwLock<BTreeMap<Labels, u64>>,
}

impl Counter {
    /// Increment by 1.
    pub fn inc(&self, labels: Labels) {
        self.inc_by(labels, 1);
    }

    /// Increment by `n`.
    pub fn inc_by(&self, labels: Labels, n: u64) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        *g.entry(labels).or_insert(0) += n;
    }

    /// Sum of all values across all label sets.
    pub fn total(&self) -> u64 {
        self.inner
            .read()
            .map(|g| g.values().sum())
            .unwrap_or(0)
    }

    /// Snapshot of all label sets and their values.
    pub fn snapshot(&self) -> BTreeMap<Labels, u64> {
        self.inner
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

/// A point-in-time gauge.
#[derive(Debug, Default)]
pub struct Gauge {
    inner: RwLock<BTreeMap<Labels, f64>>,
}

impl Gauge {
    /// Set to `v`.
    pub fn set(&self, labels: Labels, v: f64) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.insert(labels, v);
    }

    /// Snapshot.
    pub fn snapshot(&self) -> BTreeMap<Labels, f64> {
        self.inner
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }
}

/// A simple histogram with fixed buckets.
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<f64>,
    inner: Mutex<HistogramInner>,
}

#[derive(Debug, Default)]
struct HistogramInner {
    /// Per-label-set bucket counts.
    /// Last bucket is +Inf.
    series: BTreeMap<Labels, HistogramSeries>,
}

#[derive(Debug, Default, Clone)]
struct HistogramSeries {
    counts: Vec<u64>, // length == buckets.len() + 1 (last is +Inf)
    count: u64,
    sum: f64,
}

impl Histogram {
    /// New histogram with the given upper-bound buckets (sorted).
    pub fn new(buckets: Vec<f64>) -> Self {
        let mut sorted = buckets.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            buckets: sorted,
            inner: Mutex::new(HistogramInner::default()),
        }
    }

    /// Default latency buckets (seconds): 1ms .. 60s.
    pub fn default_latency() -> Self {
        Self::new(vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
        ])
    }

    /// Observe a value.
    pub fn observe(&self, labels: Labels, value: f64) {
        let mut g = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let series = g
            .series
            .entry(labels)
            .or_insert_with(|| HistogramSeries {
                counts: vec![0u64; self.buckets.len() + 1],
                count: 0,
                sum: 0.0,
            });
        series.count += 1;
        series.sum += value;
        for (i, &edge) in self.buckets.iter().enumerate() {
            if value <= edge {
                series.counts[i] += 1;
            }
        }
        // +Inf bucket always increments.
        let last = series.counts.len() - 1;
        series.counts[last] += 1;
    }

    /// Total observations across all label sets.
    pub fn total_count(&self) -> u64 {
        self.inner
            .lock()
            .map(|g| g.series.values().map(|s| s.count).sum())
            .unwrap_or(0)
    }

    /// Total sum across all label sets.
    pub fn total_sum(&self) -> f64 {
        self.inner
            .lock()
            .map(|g| g.series.values().map(|s| s.sum).sum())
            .unwrap_or(0.0)
    }

    fn snapshot(&self) -> BTreeMap<Labels, HistogramSeries> {
        self.inner
            .lock()
            .map(|g| g.series.clone())
            .unwrap_or_default()
    }
}

/// Trait abstraction so production deployments can swap us out for a
/// full-fat metrics crate.
pub trait MetricsRecorder: Send + Sync {
    /// Record a seal.
    fn record_seal(&self, sector: &str, workflow: &str, outcome: &str);
    /// Record a seal duration.
    fn record_seal_duration(&self, sector: &str, workflow: &str, secs: f64);
    /// Record a policy denial.
    fn record_policy_denial(&self, gate_id: &str);
    /// Record a signature failure.
    fn record_signature_failure(&self, signer_id: &str);
    /// Record an attestation failure.
    fn record_attestation_failure(&self, platform: &str);
    /// Update the evidence-log size gauge.
    fn set_evidence_log_size(&self, tenant: &str, bytes: u64);
}

/// Standard sandbox metrics.
#[derive(Debug)]
pub struct SandboxMetrics {
    /// `aethelred_seals_total`.
    pub seals_total: Counter,
    /// `aethelred_seal_duration_seconds`.
    pub seal_duration_seconds: Histogram,
    /// `aethelred_evidence_log_size_bytes`.
    pub evidence_log_size_bytes: Gauge,
    /// `aethelred_policy_denials_total`.
    pub policy_denials_total: Counter,
    /// `aethelred_signature_failures_total`.
    pub signature_failures_total: Counter,
    /// `aethelred_attestation_failures_total`.
    pub attestation_failures_total: Counter,
}

impl Default for SandboxMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxMetrics {
    /// New empty metrics.
    pub fn new() -> Self {
        Self {
            seals_total: Counter::default(),
            seal_duration_seconds: Histogram::default_latency(),
            evidence_log_size_bytes: Gauge::default(),
            policy_denials_total: Counter::default(),
            signature_failures_total: Counter::default(),
            attestation_failures_total: Counter::default(),
        }
    }

    /// Render as Prometheus text format (suitable for `/metrics` endpoint).
    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();
        // Counters
        out.push_str("# HELP aethelred_seals_total Total seals appended to evidence logs.\n");
        out.push_str("# TYPE aethelred_seals_total counter\n");
        for (labels, val) in self.seals_total.snapshot() {
            out.push_str(&format!(
                "aethelred_seals_total{} {}\n",
                fmt_labels(&labels),
                val
            ));
        }
        out.push_str("# HELP aethelred_policy_denials_total Total policy-gate denials.\n");
        out.push_str("# TYPE aethelred_policy_denials_total counter\n");
        for (labels, val) in self.policy_denials_total.snapshot() {
            out.push_str(&format!(
                "aethelred_policy_denials_total{} {}\n",
                fmt_labels(&labels),
                val
            ));
        }
        out.push_str("# HELP aethelred_signature_failures_total Hybrid signature verification failures.\n");
        out.push_str("# TYPE aethelred_signature_failures_total counter\n");
        for (labels, val) in self.signature_failures_total.snapshot() {
            out.push_str(&format!(
                "aethelred_signature_failures_total{} {}\n",
                fmt_labels(&labels),
                val
            ));
        }
        out.push_str("# HELP aethelred_attestation_failures_total TEE attestation verification failures.\n");
        out.push_str("# TYPE aethelred_attestation_failures_total counter\n");
        for (labels, val) in self.attestation_failures_total.snapshot() {
            out.push_str(&format!(
                "aethelred_attestation_failures_total{} {}\n",
                fmt_labels(&labels),
                val
            ));
        }
        // Gauges
        out.push_str(
            "# HELP aethelred_evidence_log_size_bytes On-disk evidence-log size in bytes.\n",
        );
        out.push_str("# TYPE aethelred_evidence_log_size_bytes gauge\n");
        for (labels, val) in self.evidence_log_size_bytes.snapshot() {
            out.push_str(&format!(
                "aethelred_evidence_log_size_bytes{} {}\n",
                fmt_labels(&labels),
                val
            ));
        }
        // Histogram
        out.push_str(
            "# HELP aethelred_seal_duration_seconds Seal-emission duration distribution.\n",
        );
        out.push_str("# TYPE aethelred_seal_duration_seconds histogram\n");
        let snap = self.seal_duration_seconds.snapshot();
        for (labels, series) in snap {
            for (i, &edge) in self.seal_duration_seconds.buckets.iter().enumerate() {
                let mut le_labels = labels.clone();
                le_labels.insert("le".into(), format!("{edge}"));
                out.push_str(&format!(
                    "aethelred_seal_duration_seconds_bucket{} {}\n",
                    fmt_labels(&le_labels),
                    series.counts[i]
                ));
            }
            // +Inf bucket
            let mut inf_labels = labels.clone();
            inf_labels.insert("le".into(), "+Inf".into());
            let last = series.counts.len() - 1;
            out.push_str(&format!(
                "aethelred_seal_duration_seconds_bucket{} {}\n",
                fmt_labels(&inf_labels),
                series.counts[last]
            ));
            out.push_str(&format!(
                "aethelred_seal_duration_seconds_sum{} {}\n",
                fmt_labels(&labels),
                series.sum
            ));
            out.push_str(&format!(
                "aethelred_seal_duration_seconds_count{} {}\n",
                fmt_labels(&labels),
                series.count
            ));
        }
        out
    }
}

impl MetricsRecorder for SandboxMetrics {
    fn record_seal(&self, sector: &str, workflow: &str, outcome: &str) {
        let mut l = Labels::new();
        l.insert("sector".into(), sector.into());
        l.insert("workflow_id".into(), workflow.into());
        l.insert("outcome".into(), outcome.into());
        self.seals_total.inc(l);
    }
    fn record_seal_duration(&self, sector: &str, workflow: &str, secs: f64) {
        let mut l = Labels::new();
        l.insert("sector".into(), sector.into());
        l.insert("workflow_id".into(), workflow.into());
        self.seal_duration_seconds.observe(l, secs);
    }
    fn record_policy_denial(&self, gate_id: &str) {
        let mut l = Labels::new();
        l.insert("gate_id".into(), gate_id.into());
        self.policy_denials_total.inc(l);
    }
    fn record_signature_failure(&self, signer_id: &str) {
        let mut l = Labels::new();
        l.insert("signer_id".into(), signer_id.into());
        self.signature_failures_total.inc(l);
    }
    fn record_attestation_failure(&self, platform: &str) {
        let mut l = Labels::new();
        l.insert("platform".into(), platform.into());
        self.attestation_failures_total.inc(l);
    }
    fn set_evidence_log_size(&self, tenant: &str, bytes: u64) {
        let mut l = Labels::new();
        l.insert("tenant".into(), tenant.into());
        self.evidence_log_size_bytes.set(l, bytes as f64);
    }
}

/// Snapshot of metric values, suitable for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Total seals observed.
    pub seals_total: u64,
    /// Total policy denials.
    pub policy_denials_total: u64,
    /// Total signature failures.
    pub signature_failures_total: u64,
    /// Total attestation failures.
    pub attestation_failures_total: u64,
    /// Total seal-duration observations.
    pub seal_duration_count: u64,
    /// Sum of seal durations.
    pub seal_duration_sum_seconds: f64,
}

impl SandboxMetrics {
    /// Take a JSON-friendly snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            seals_total: self.seals_total.total(),
            policy_denials_total: self.policy_denials_total.total(),
            signature_failures_total: self.signature_failures_total.total(),
            attestation_failures_total: self.attestation_failures_total.total(),
            seal_duration_count: self.seal_duration_seconds.total_count(),
            seal_duration_sum_seconds: self.seal_duration_seconds.total_sum(),
        }
    }
}

fn fmt_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", escape_label_value(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

fn escape_label_value(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab(k: &str, v: &str) -> Labels {
        let mut l = Labels::new();
        l.insert(k.into(), v.into());
        l
    }

    #[test]
    fn counter_increments() {
        let c = Counter::default();
        c.inc(lab("a", "1"));
        c.inc(lab("a", "1"));
        assert_eq!(c.total(), 2);
    }

    #[test]
    fn counter_inc_by_works() {
        let c = Counter::default();
        c.inc_by(lab("a", "1"), 5);
        assert_eq!(c.total(), 5);
    }

    #[test]
    fn counter_separate_labels_separate_series() {
        let c = Counter::default();
        c.inc(lab("a", "1"));
        c.inc(lab("a", "2"));
        let snap = c.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn gauge_set_value() {
        let g = Gauge::default();
        g.set(lab("x", "1"), 42.0);
        let snap = g.snapshot();
        assert_eq!(snap.values().next().copied(), Some(42.0));
    }

    #[test]
    fn histogram_observe_increments_buckets() {
        let h = Histogram::new(vec![1.0, 5.0, 10.0]);
        h.observe(lab("op", "x"), 3.0);
        h.observe(lab("op", "x"), 7.0);
        h.observe(lab("op", "x"), 100.0);
        assert_eq!(h.total_count(), 3);
        let sum = h.total_sum();
        assert!((sum - 110.0).abs() < 1e-9);
    }

    #[test]
    fn histogram_default_latency_has_14_buckets() {
        let h = Histogram::default_latency();
        assert_eq!(h.buckets.len(), 14);
    }

    #[test]
    fn sandbox_metrics_record_seal() {
        let m = SandboxMetrics::new();
        m.record_seal("finance", "credit_decision", "allow");
        assert_eq!(m.seals_total.total(), 1);
    }

    #[test]
    fn sandbox_metrics_record_seal_duration() {
        let m = SandboxMetrics::new();
        m.record_seal_duration("finance", "credit_decision", 0.05);
        assert_eq!(m.seal_duration_seconds.total_count(), 1);
    }

    #[test]
    fn sandbox_metrics_record_policy_denial() {
        let m = SandboxMetrics::new();
        m.record_policy_denial("finance.amount_bounds");
        assert_eq!(m.policy_denials_total.total(), 1);
    }

    #[test]
    fn sandbox_metrics_record_signature_failure() {
        let m = SandboxMetrics::new();
        m.record_signature_failure("validator-1");
        assert_eq!(m.signature_failures_total.total(), 1);
    }

    #[test]
    fn sandbox_metrics_record_attestation_failure() {
        let m = SandboxMetrics::new();
        m.record_attestation_failure("intel_tdx");
        assert_eq!(m.attestation_failures_total.total(), 1);
    }

    #[test]
    fn sandbox_metrics_set_evidence_log_size() {
        let m = SandboxMetrics::new();
        m.set_evidence_log_size("FAB", 1024);
        let snap = m.evidence_log_size_bytes.snapshot();
        assert_eq!(snap.values().next().copied(), Some(1024.0));
    }

    #[test]
    fn export_prometheus_includes_all_metric_names() {
        let m = SandboxMetrics::new();
        m.record_seal("finance", "credit_decision", "allow");
        m.record_policy_denial("finance.x");
        m.record_signature_failure("v1");
        m.record_attestation_failure("intel_tdx");
        m.set_evidence_log_size("FAB", 100);
        m.record_seal_duration("finance", "credit_decision", 0.01);
        let out = m.export_prometheus();
        assert!(out.contains("aethelred_seals_total"));
        assert!(out.contains("aethelred_policy_denials_total"));
        assert!(out.contains("aethelred_signature_failures_total"));
        assert!(out.contains("aethelred_attestation_failures_total"));
        assert!(out.contains("aethelred_evidence_log_size_bytes"));
        assert!(out.contains("aethelred_seal_duration_seconds"));
    }

    #[test]
    fn export_prometheus_includes_help_lines() {
        let m = SandboxMetrics::new();
        m.record_seal("a", "b", "c");
        let out = m.export_prometheus();
        assert!(out.contains("# HELP aethelred_seals_total"));
        assert!(out.contains("# TYPE aethelred_seals_total counter"));
    }

    #[test]
    fn snapshot_serde_round_trip() {
        let m = SandboxMetrics::new();
        m.record_seal("a", "b", "c");
        m.record_seal_duration("a", "b", 0.1);
        let snap = m.snapshot();
        let j = serde_json::to_string(&snap).unwrap();
        let p: MetricsSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p.seals_total, 1);
        assert_eq!(p.seal_duration_count, 1);
    }

    #[test]
    fn fmt_labels_empty_is_empty() {
        let l = Labels::new();
        assert_eq!(fmt_labels(&l), "");
    }

    #[test]
    fn fmt_labels_renders_kv_pairs() {
        let mut l = Labels::new();
        l.insert("a".into(), "1".into());
        l.insert("b".into(), "2".into());
        let s = fmt_labels(&l);
        // BTreeMap iteration is sorted: a then b.
        assert!(s.contains("a=\"1\""));
        assert!(s.contains("b=\"2\""));
    }

    #[test]
    fn escape_label_value_handles_quotes() {
        assert_eq!(escape_label_value("a\"b"), "a\\\"b");
    }

    #[test]
    fn histogram_separate_labels_separate_series() {
        let h = Histogram::new(vec![1.0, 5.0]);
        h.observe(lab("op", "x"), 0.5);
        h.observe(lab("op", "y"), 0.7);
        let snap = h.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn empty_metrics_snapshot_is_zero() {
        let m = SandboxMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.seals_total, 0);
        assert_eq!(s.policy_denials_total, 0);
    }

    #[test]
    fn export_prometheus_when_no_observations_still_emits_help() {
        let m = SandboxMetrics::new();
        let out = m.export_prometheus();
        assert!(out.contains("# HELP aethelred_seals_total"));
    }

    #[test]
    fn many_observations_are_summed() {
        let m = SandboxMetrics::new();
        for _ in 0..1000 {
            m.record_seal("a", "b", "c");
        }
        assert_eq!(m.seals_total.total(), 1000);
    }
}
