//! Structured model-evaluation harness.
//!
//! Distinct from [`crate::bias_detection`] (fairness audit) and
//! [`crate::subgroup_robustness`] (cohort-level performance), this module
//! is the **release-gate evaluator**: each [`EvaluationRun`] executes a
//! suite of named [`Benchmark`]s against a model and records pass/fail
//! per benchmark. The run rolls those into an aggregate verdict that gates
//! promotion (Beta → GA, etc.).
//!
//! Maps to NIST AI RMF GOVERN-1.4 (independent evaluation), EU AI Act
//! Art 15 (accuracy, robustness, cybersecurity), and ISO/IEC 23053
//! (AI system test framework).
//!
//! ## Lifecycle
//!
//! `Pending → Running → (Passed | Failed | Aborted)`
//!
//! Any benchmark whose recorded `status` is `Failed` flips the run to
//! `Failed` once finalised; if all are `Passed` (or `Skipped`) the run
//! becomes `Passed`. `Aborted` is operator-driven for runs killed
//! mid-execution.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// BenchmarkKind
// =============================================================================

/// Category of benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkKind {
    /// Accuracy / quality of correct outputs.
    Accuracy,
    /// Latency / throughput.
    Performance,
    /// Robustness to perturbed inputs.
    Robustness,
    /// Safety / refusal of unsafe outputs.
    Safety,
    /// Fairness / parity across cohorts.
    Fairness,
    /// Hallucination / factuality.
    Factuality,
    /// Calibration / confidence-quality match.
    Calibration,
    /// Drift relative to a baseline distribution.
    Drift,
}

// =============================================================================
// BenchmarkStatus
// =============================================================================

/// Per-benchmark result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkStatus {
    /// Recorded but not yet executed.
    Pending,
    /// Executed and meets threshold.
    Passed,
    /// Executed and below threshold.
    Failed,
    /// Skipped — flagged but not run (e.g., unavailable dataset).
    Skipped,
}

// =============================================================================
// Benchmark
// =============================================================================

/// One named benchmark within an evaluation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Benchmark {
    /// Stable id within the run.
    pub benchmark_id: String,
    /// Display name.
    pub name: String,
    /// Kind.
    pub kind: BenchmarkKind,
    /// Threshold the metric must beat. (Direction is per-benchmark; for
    /// "lower is better" metrics like latency, the threshold is the
    /// upper bound.)
    pub threshold: f64,
    /// Direction — `true` = higher is better.
    pub higher_is_better: bool,
    /// Recorded measurement, when available.
    pub measured: Option<f64>,
    /// Status.
    pub status: BenchmarkStatus,
    /// Free-form note (e.g., dataset id, sample size).
    pub note: Option<String>,
}

impl Benchmark {
    /// New `Pending` benchmark.
    pub fn new(
        benchmark_id: impl Into<String>,
        name: impl Into<String>,
        kind: BenchmarkKind,
        threshold: f64,
        higher_is_better: bool,
    ) -> Self {
        Self {
            benchmark_id: benchmark_id.into(),
            name: name.into(),
            kind,
            threshold,
            higher_is_better,
            measured: None,
            status: BenchmarkStatus::Pending,
            note: None,
        }
    }

    /// Compute pass/fail given a measurement, respecting direction.
    fn pass_with(&self, value: f64) -> bool {
        if self.higher_is_better {
            value >= self.threshold
        } else {
            value <= self.threshold
        }
    }
}

// =============================================================================
// RunStage
// =============================================================================

/// Lifecycle stage of an evaluation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStage {
    /// Created but not started.
    Pending,
    /// Currently executing.
    Running,
    /// All benchmarks passed (or skipped).
    Passed,
    /// One or more benchmarks failed.
    Failed,
    /// Operator killed the run.
    Aborted,
}

impl RunStage {
    /// True if no further state changes are expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed | Self::Aborted)
    }

    /// True if the run gated a promotion decision (i.e., reached Passed).
    pub fn allows_promotion(self) -> bool {
        matches!(self, Self::Passed)
    }
}

// =============================================================================
// EvaluationRun
// =============================================================================

/// One evaluation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationRun {
    /// Unique id (e.g., "eval-2025-05-08-fraud-v3").
    pub run_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Model under evaluation.
    pub model_id: String,
    /// Model version under evaluation.
    pub model_version: String,
    /// Display title.
    pub title: String,
    /// Owning team.
    pub owner: String,
    /// Benchmarks.
    pub benchmarks: Vec<Benchmark>,
    /// Current stage.
    pub stage: RunStage,
    /// RFC 3339 — created.
    pub created_at: String,
    /// RFC 3339 — started running.
    pub started_at: Option<String>,
    /// RFC 3339 — finalised (any terminal stage).
    pub finalised_at: Option<String>,
    /// Operator-supplied free-text summary of the run outcome.
    pub summary: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl EvaluationRun {
    /// New `Pending` run.
    pub fn new(
        run_id: impl Into<String>,
        tenant_id: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
        title: impl Into<String>,
        owner: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            tenant_id: tenant_id.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            title: title.into(),
            owner: owner.into(),
            benchmarks: Vec::new(),
            stage: RunStage::Pending,
            created_at: created_at.into(),
            started_at: None,
            finalised_at: None,
            summary: None,
            tags: Vec::new(),
        }
    }

    /// Number of benchmarks in each status bucket.
    pub fn status_counts(&self) -> (usize, usize, usize, usize) {
        let mut p = 0;
        let mut f = 0;
        let mut sk = 0;
        let mut pe = 0;
        for b in &self.benchmarks {
            match b.status {
                BenchmarkStatus::Passed => p += 1,
                BenchmarkStatus::Failed => f += 1,
                BenchmarkStatus::Skipped => sk += 1,
                BenchmarkStatus::Pending => pe += 1,
            }
        }
        (p, f, sk, pe)
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RunStage, to: RunStage) -> bool {
    use RunStage::*;
    match (from, to) {
        (Pending, Running)
        | (Pending, Aborted)
        | (Running, Passed)
        | (Running, Failed)
        | (Running, Aborted) => true,
        _ => false,
    }
}

// =============================================================================
// EvaluationHarness
// =============================================================================

/// Thread-safe registry of evaluation runs.
#[derive(Debug, Default)]
pub struct EvaluationHarness {
    inner: RwLock<HashMap<String, EvaluationRun>>,
}

impl EvaluationHarness {
    /// New empty harness.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a run.
    pub fn register(&self, run: EvaluationRun) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        if g.contains_key(&run.run_id) {
            return Err(SandboxError::Other(format!(
                "evaluation run already registered: {}",
                run.run_id
            )));
        }
        g.insert(run.run_id.clone(), run);
        Ok(())
    }

    /// Append a benchmark to a Pending run.
    pub fn add_benchmark(&self, run_id: &str, benchmark: Benchmark) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !matches!(r.stage, RunStage::Pending) {
            return Err(SandboxError::Other(format!(
                "cannot add benchmark to {run_id}: stage is {:?}",
                r.stage
            )));
        }
        if r.benchmarks
            .iter()
            .any(|b| b.benchmark_id == benchmark.benchmark_id)
        {
            return Err(SandboxError::Other(format!(
                "benchmark already present: {}",
                benchmark.benchmark_id
            )));
        }
        r.benchmarks.push(benchmark);
        Ok(())
    }

    /// Move run to Running.
    pub fn start(&self, run_id: &str, at: impl Into<String>) -> SandboxResult<EvaluationRun> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !legal_transition(r.stage, RunStage::Running) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Running",
                r.stage
            )));
        }
        r.stage = RunStage::Running;
        r.started_at = Some(at.into());
        Ok(r.clone())
    }

    /// Record a measurement against a benchmark in a Running run. Pass/fail
    /// is computed from the threshold.
    pub fn record_measurement(
        &self,
        run_id: &str,
        benchmark_id: &str,
        measured: f64,
        note: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !matches!(r.stage, RunStage::Running) {
            return Err(SandboxError::Other(format!(
                "cannot record on {run_id}: stage is {:?}",
                r.stage
            )));
        }
        let b = r
            .benchmarks
            .iter_mut()
            .find(|b| b.benchmark_id == benchmark_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown benchmark {benchmark_id}"))
            })?;
        b.measured = Some(measured);
        b.status = if b.pass_with(measured) {
            BenchmarkStatus::Passed
        } else {
            BenchmarkStatus::Failed
        };
        if let Some(n) = note {
            b.note = Some(n);
        }
        Ok(())
    }

    /// Mark a benchmark Skipped (operator action).
    pub fn skip_benchmark(
        &self,
        run_id: &str,
        benchmark_id: &str,
        reason: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !matches!(r.stage, RunStage::Running) {
            return Err(SandboxError::Other(format!(
                "cannot skip on {run_id}: stage is {:?}",
                r.stage
            )));
        }
        let b = r
            .benchmarks
            .iter_mut()
            .find(|b| b.benchmark_id == benchmark_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown benchmark {benchmark_id}"))
            })?;
        b.status = BenchmarkStatus::Skipped;
        b.note = Some(reason.into());
        Ok(())
    }

    /// Finalise a Running run. Returns the resolved stage:
    /// - any `Failed` benchmark → `Failed`.
    /// - any remaining `Pending` benchmark → error (caller must record /
    ///   skip first).
    /// - otherwise → `Passed`.
    pub fn finalise(
        &self,
        run_id: &str,
        at: impl Into<String>,
        summary: Option<String>,
    ) -> SandboxResult<EvaluationRun> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !matches!(r.stage, RunStage::Running) {
            return Err(SandboxError::Other(format!(
                "cannot finalise {run_id}: stage is {:?}",
                r.stage
            )));
        }
        if r.benchmarks
            .iter()
            .any(|b| matches!(b.status, BenchmarkStatus::Pending))
        {
            return Err(SandboxError::Other(format!(
                "cannot finalise {run_id}: pending benchmarks remain"
            )));
        }
        let any_failed = r
            .benchmarks
            .iter()
            .any(|b| matches!(b.status, BenchmarkStatus::Failed));
        r.stage = if any_failed {
            RunStage::Failed
        } else {
            RunStage::Passed
        };
        r.finalised_at = Some(at.into());
        if let Some(s) = summary {
            r.summary = Some(s);
        }
        Ok(r.clone())
    }

    /// Abort a non-terminal run.
    pub fn abort(
        &self,
        run_id: &str,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<EvaluationRun> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        if !legal_transition(r.stage, RunStage::Aborted) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Aborted",
                r.stage
            )));
        }
        r.stage = RunStage::Aborted;
        r.finalised_at = Some(at.into());
        r.summary = Some(reason.into());
        Ok(r.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, run_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("evaluation harness poisoned".into()))?;
        let r = g
            .get_mut(run_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown run {run_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, run_id: &str) -> Option<EvaluationRun> {
        let g = self.inner.read().ok()?;
        g.get(run_id).cloned()
    }

    /// All runs.
    pub fn all(&self) -> Vec<EvaluationRun> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Runs for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<EvaluationRun> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Runs for a model.
    pub fn for_model(&self, model_id: &str) -> Vec<EvaluationRun> {
        self.all()
            .into_iter()
            .filter(|r| r.model_id == model_id)
            .collect()
    }

    /// Latest passed run for a model.
    pub fn latest_passed_for_model(&self, model_id: &str) -> Option<EvaluationRun> {
        let mut runs: Vec<EvaluationRun> = self
            .for_model(model_id)
            .into_iter()
            .filter(|r| r.stage.allows_promotion())
            .collect();
        runs.sort_by(|a, b| {
            a.finalised_at
                .as_deref()
                .unwrap_or("")
                .cmp(b.finalised_at.as_deref().unwrap_or(""))
        });
        runs.last().cloned()
    }

    /// Count.
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

    fn run(id: &str) -> EvaluationRun {
        EvaluationRun::new(
            id,
            "tenant-a",
            "fraud-scorer",
            "v3",
            "fraud release gate",
            "ml-platform",
            "2025-05-01T00:00:00Z",
        )
    }

    fn bench(id: &str, kind: BenchmarkKind, thr: f64, higher: bool) -> Benchmark {
        Benchmark::new(id, format!("name-{id}"), kind, thr, higher)
    }

    #[test]
    fn register_and_get() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        let r = h.get("r1").unwrap();
        assert_eq!(r.stage, RunStage::Pending);
    }

    #[test]
    fn duplicate_register_errors() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        let err = h.register(run("r1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn add_benchmark_to_pending() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        assert_eq!(h.get("r1").unwrap().benchmarks.len(), 1);
    }

    #[test]
    fn add_benchmark_dedupes_id() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        let err = h
            .add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.95, true))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_benchmark_after_running_errors() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        let err = h
            .add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add benchmark"));
    }

    #[test]
    fn legal_transitions() {
        use RunStage::*;
        assert!(legal_transition(Pending, Running));
        assert!(legal_transition(Pending, Aborted));
        assert!(legal_transition(Running, Passed));
        assert!(legal_transition(Running, Failed));
        assert!(legal_transition(Running, Aborted));
        assert!(!legal_transition(Pending, Passed));
        assert!(!legal_transition(Pending, Failed));
        assert!(!legal_transition(Passed, Failed));
        assert!(!legal_transition(Failed, Passed));
    }

    #[test]
    fn higher_is_better_pass() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        let r = h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();
        assert_eq!(r.stage, RunStage::Passed);
        assert!(r.stage.allows_promotion());
    }

    #[test]
    fn lower_is_better_pass() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        // latency p99 ≤ 200ms
        h.add_benchmark("r1", bench("p99", BenchmarkKind::Performance, 200.0, false))
            .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "p99", 150.0, None).unwrap();
        let r = h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();
        assert_eq!(r.stage, RunStage::Passed);
    }

    #[test]
    fn one_failed_makes_run_failed() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.add_benchmark(
            "r1",
            bench("p99", BenchmarkKind::Performance, 200.0, false),
        )
        .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        h.record_measurement("r1", "p99", 999.0, None).unwrap();
        let r = h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();
        assert_eq!(r.stage, RunStage::Failed);
        assert!(!r.stage.allows_promotion());
    }

    #[test]
    fn finalise_rejects_pending_benchmarks() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.add_benchmark(
            "r1",
            bench("safety", BenchmarkKind::Safety, 0.99, true),
        )
        .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        let err = h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap_err();
        assert!(format!("{err}").contains("pending benchmarks remain"));
    }

    #[test]
    fn skip_benchmark_allows_finalise() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.add_benchmark(
            "r1",
            bench("fairness", BenchmarkKind::Fairness, 0.95, true),
        )
        .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        h.skip_benchmark("r1", "fairness", "cohort dataset unavailable")
            .unwrap();
        let r = h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();
        assert_eq!(r.stage, RunStage::Passed);
    }

    #[test]
    fn record_measurement_unknown_benchmark_errors() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        let err = h.record_measurement("r1", "nope", 0.5, None).unwrap_err();
        assert!(format!("{err}").contains("unknown benchmark"));
    }

    #[test]
    fn record_measurement_when_not_running_errors() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        let err = h.record_measurement("r1", "acc", 0.95, None).unwrap_err();
        assert!(format!("{err}").contains("cannot record"));
    }

    #[test]
    fn abort_from_pending() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        let r = h
            .abort("r1", "2025-05-02T00:00:00Z", "model unavailable")
            .unwrap();
        assert_eq!(r.stage, RunStage::Aborted);
        assert!(r.stage.is_terminal());
    }

    #[test]
    fn abort_from_running() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.abort("r1", "2025-05-02T01:00:00Z", "killed").unwrap();
        assert_eq!(h.get("r1").unwrap().stage, RunStage::Aborted);
    }

    #[test]
    fn abort_terminal_errors() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();
        let err = h
            .abort("r1", "2025-05-02T02:00:00Z", "too late")
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_tag_dedupes() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_tag("r1", "ga-gate").unwrap();
        h.add_tag("r1", "ga-gate").unwrap();
        h.add_tag("r1", "fraud").unwrap();
        assert_eq!(h.get("r1").unwrap().tags, vec!["ga-gate", "fraud"]);
    }

    #[test]
    fn unknown_run_errors() {
        let h = EvaluationHarness::new();
        let err = h.start("nope", "2025-05-02T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown run"));
    }

    #[test]
    fn for_tenant_for_model_filters() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        let mut other = run("r2");
        other.tenant_id = "tenant-b".into();
        other.model_id = "scoring-other".into();
        h.register(other).unwrap();
        assert_eq!(h.for_tenant("tenant-a").len(), 1);
        assert_eq!(h.for_tenant("tenant-b").len(), 1);
        assert_eq!(h.for_model("fraud-scorer").len(), 1);
        assert_eq!(h.for_model("scoring-other").len(), 1);
    }

    #[test]
    fn latest_passed_for_model() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "acc", 0.95, None).unwrap();
        h.finalise("r1", "2025-05-02T01:00:00Z", None).unwrap();

        let mut r2 = run("r2");
        r2.run_id = "r2".into();
        h.register(r2).unwrap();
        h.add_benchmark("r2", bench("acc", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.start("r2", "2025-05-03T00:00:00Z").unwrap();
        h.record_measurement("r2", "acc", 0.5, None).unwrap();
        h.finalise("r2", "2025-05-03T01:00:00Z", None).unwrap(); // failed

        let latest = h.latest_passed_for_model("fraud-scorer").unwrap();
        assert_eq!(latest.run_id, "r1");
    }

    #[test]
    fn status_counts_buckets() {
        let h = EvaluationHarness::new();
        h.register(run("r1")).unwrap();
        h.add_benchmark("r1", bench("a", BenchmarkKind::Accuracy, 0.9, true))
            .unwrap();
        h.add_benchmark("r1", bench("b", BenchmarkKind::Safety, 0.99, true))
            .unwrap();
        h.add_benchmark(
            "r1",
            bench("c", BenchmarkKind::Performance, 200.0, false),
        )
        .unwrap();
        h.start("r1", "2025-05-02T00:00:00Z").unwrap();
        h.record_measurement("r1", "a", 0.95, None).unwrap();
        h.record_measurement("r1", "c", 999.0, None).unwrap();
        h.skip_benchmark("r1", "b", "n/a").unwrap();
        let r = h.get("r1").unwrap();
        let (p, f, sk, pe) = r.status_counts();
        assert_eq!(p, 1);
        assert_eq!(f, 1);
        assert_eq!(sk, 1);
        assert_eq!(pe, 0);
    }

    #[test]
    fn run_serde() {
        let r = run("r1");
        let j = serde_json::to_string(&r).unwrap();
        let back: EvaluationRun = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn benchmark_serde() {
        let b = bench("a", BenchmarkKind::Accuracy, 0.9, true);
        let j = serde_json::to_string(&b).unwrap();
        let back: Benchmark = serde_json::from_str(&j).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            BenchmarkKind::Accuracy,
            BenchmarkKind::Performance,
            BenchmarkKind::Robustness,
            BenchmarkKind::Safety,
            BenchmarkKind::Fairness,
            BenchmarkKind::Factuality,
            BenchmarkKind::Calibration,
            BenchmarkKind::Drift,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<BenchmarkKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            BenchmarkStatus::Pending,
            BenchmarkStatus::Passed,
            BenchmarkStatus::Failed,
            BenchmarkStatus::Skipped,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<BenchmarkStatus>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for s in [
            RunStage::Pending,
            RunStage::Running,
            RunStage::Passed,
            RunStage::Failed,
            RunStage::Aborted,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RunStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn count_tracks() {
        let h = EvaluationHarness::new();
        assert_eq!(h.count(), 0);
        h.register(run("r1")).unwrap();
        assert_eq!(h.count(), 1);
    }
}
