//! Training-run register.
//!
//! Records every training run with hyperparams, dataset references, output
//! artifact hashes, and metric scores. Closes the loop with
//! [`crate::dataset_lineage`] (which datasets fed the run) and
//! [`crate::model_card`] (the published model documentation).

use crate::hashing::Sha256Digest;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RunStatus
// =============================================================================

/// Run status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Queued.
    Queued,
    /// Running.
    Running,
    /// Completed successfully.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

// =============================================================================
// Hyperparameters / Metric
// =============================================================================

/// One hyperparameter (name + value as string).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hyperparam {
    /// Name.
    pub name: String,
    /// Value.
    pub value: String,
}

/// One metric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMetric {
    /// Name.
    pub name: String,
    /// Numeric value.
    pub value: f64,
    /// Unit.
    pub unit: String,
}

// =============================================================================
// TrainingRun
// =============================================================================

/// One training run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrainingRun {
    /// Stable id.
    pub run_id: Uuid,
    /// Display id (e.g. `"run-2026-0001"`).
    pub display_id: String,
    /// Owner.
    pub owner: String,
    /// Model id (target).
    pub model_id: String,
    /// Model version produced.
    pub model_version: String,
    /// Datasets used (`"id@version"` keys).
    pub training_datasets: Vec<String>,
    /// Eval datasets (`"id@version"` keys).
    pub eval_datasets: Vec<String>,
    /// Hyperparameters.
    pub hyperparameters: Vec<Hyperparam>,
    /// Output artifact hashes (e.g. weights file).
    pub output_artifact_hashes: HashMap<String, Sha256Digest>,
    /// Metrics.
    pub metrics: Vec<RunMetric>,
    /// Status.
    pub status: RunStatus,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 ended.
    pub ended_at: Option<String>,
    /// Free-text notes.
    pub notes: String,
}

impl TrainingRun {
    /// Duration in seconds.
    pub fn duration_seconds(&self) -> Option<i64> {
        let start = OffsetDateTime::parse(
            &self.started_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        let end = self
            .ended_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        Some((end - start).whole_seconds())
    }
    /// Find a metric.
    pub fn metric(&self, name: &str) -> Option<&RunMetric> {
        self.metrics.iter().find(|m| m.name == name)
    }
}

// =============================================================================
// TrainingRunRegistry
// =============================================================================

#[derive(Default)]
struct State {
    runs: HashMap<Uuid, TrainingRun>,
    seq: HashMap<String, u32>, // year prefix → sequence
}

/// Registry.
pub struct TrainingRunRegistry {
    state: RwLock<State>,
}

impl Default for TrainingRunRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for TrainingRunRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrainingRunRegistry")
            .field("runs", &self.len())
            .finish()
    }
}

impl TrainingRunRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new run.
    pub fn open(
        &self,
        owner: impl Into<String>,
        model_id: impl Into<String>,
        model_version: impl Into<String>,
    ) -> SandboxResult<TrainingRun> {
        let now = OffsetDateTime::now_utc();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let prefix = format!("run-{}", now.year());
        let seq = g.seq.entry(prefix.clone()).or_insert(0);
        *seq += 1;
        let display_id = format!("{}-{:04}", prefix, *seq);
        let run = TrainingRun {
            run_id: Uuid::now_v7(),
            display_id,
            owner: owner.into(),
            model_id: model_id.into(),
            model_version: model_version.into(),
            training_datasets: Vec::new(),
            eval_datasets: Vec::new(),
            hyperparameters: Vec::new(),
            output_artifact_hashes: HashMap::new(),
            metrics: Vec::new(),
            status: RunStatus::Queued,
            started_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            ended_at: None,
            notes: String::new(),
        };
        g.runs.insert(run.run_id, run.clone());
        Ok(run)
    }

    /// Add training dataset key.
    pub fn add_training_dataset(&self, run_id: Uuid, key: impl Into<String>) -> SandboxResult<()> {
        let key = key.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        if !r.training_datasets.contains(&key) {
            r.training_datasets.push(key);
        }
        Ok(())
    }

    /// Add eval dataset key.
    pub fn add_eval_dataset(&self, run_id: Uuid, key: impl Into<String>) -> SandboxResult<()> {
        let key = key.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        if !r.eval_datasets.contains(&key) {
            r.eval_datasets.push(key);
        }
        Ok(())
    }

    /// Set hyperparam.
    pub fn set_hyperparam(
        &self,
        run_id: Uuid,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> SandboxResult<()> {
        let name = name.into();
        let value = value.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        // Replace existing if present.
        if let Some(p) = r.hyperparameters.iter_mut().find(|h| h.name == name) {
            p.value = value;
        } else {
            r.hyperparameters.push(Hyperparam { name, value });
        }
        Ok(())
    }

    /// Add a metric.
    pub fn add_metric(&self, run_id: Uuid, m: RunMetric) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        r.metrics.push(m);
        Ok(())
    }

    /// Add output artifact hash.
    pub fn add_artifact(
        &self,
        run_id: Uuid,
        name: impl Into<String>,
        hash: Sha256Digest,
    ) -> SandboxResult<()> {
        let name = name.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        r.output_artifact_hashes.insert(name, hash);
        Ok(())
    }

    /// Transition state.
    pub fn set_status(&self, run_id: Uuid, status: RunStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("training run registry poisoned".into()))?;
        let r = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        let terminal = matches!(
            status,
            RunStatus::Completed | RunStatus::Failed | RunStatus::Cancelled
        );
        r.status = status;
        if terminal && r.ended_at.is_none() {
            r.ended_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<TrainingRun> {
        self.state.read().ok()?.runs.get(&id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<TrainingRun> {
        self.state
            .read()
            .map(|g| g.runs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// By model id.
    pub fn for_model(&self, model_id: &str) -> Vec<TrainingRun> {
        self.all().into_iter().filter(|r| r.model_id == model_id).collect()
    }

    /// By status.
    pub fn by_status(&self, status: RunStatus) -> Vec<TrainingRun> {
        self.all().into_iter().filter(|r| r.status == status).collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.runs.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    fn open(reg: &TrainingRunRegistry) -> TrainingRun {
        reg.open("ml-team", "credit-risk", "1.0.0").unwrap()
    }

    #[test]
    fn open_creates_run() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        assert_eq!(r.status, RunStatus::Queued);
        assert!(r.display_id.starts_with("run-"));
    }

    #[test]
    fn add_training_dataset_dedupes() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.add_training_dataset(r.run_id, "ds@v1").unwrap();
        reg.add_training_dataset(r.run_id, "ds@v1").unwrap();
        assert_eq!(reg.get(r.run_id).unwrap().training_datasets.len(), 1);
    }

    #[test]
    fn add_eval_dataset_dedupes() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.add_eval_dataset(r.run_id, "ds@v1").unwrap();
        reg.add_eval_dataset(r.run_id, "ds@v1").unwrap();
        assert_eq!(reg.get(r.run_id).unwrap().eval_datasets.len(), 1);
    }

    #[test]
    fn set_hyperparam_replaces() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.set_hyperparam(r.run_id, "lr", "0.01").unwrap();
        reg.set_hyperparam(r.run_id, "lr", "0.001").unwrap();
        let updated = reg.get(r.run_id).unwrap();
        assert_eq!(updated.hyperparameters[0].value, "0.001");
    }

    #[test]
    fn add_metric_appends() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.add_metric(
            r.run_id,
            RunMetric {
                name: "auc".into(),
                value: 0.85,
                unit: "ratio".into(),
            },
        )
        .unwrap();
        assert_eq!(reg.get(r.run_id).unwrap().metrics.len(), 1);
    }

    #[test]
    fn add_artifact_records_hash() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.add_artifact(r.run_id, "weights", Hasher::sha256(b"weights"))
            .unwrap();
        let updated = reg.get(r.run_id).unwrap();
        assert!(updated.output_artifact_hashes.contains_key("weights"));
    }

    #[test]
    fn set_status_completed_sets_ended_at() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.set_status(r.run_id, RunStatus::Completed).unwrap();
        let updated = reg.get(r.run_id).unwrap();
        assert!(updated.ended_at.is_some());
    }

    #[test]
    fn set_status_running_does_not_set_ended() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.set_status(r.run_id, RunStatus::Running).unwrap();
        assert!(reg.get(r.run_id).unwrap().ended_at.is_none());
    }

    #[test]
    fn duration_after_completion() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.set_status(r.run_id, RunStatus::Completed).unwrap();
        let updated = reg.get(r.run_id).unwrap();
        assert!(updated.duration_seconds().is_some());
    }

    #[test]
    fn metric_lookup() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.add_metric(
            r.run_id,
            RunMetric {
                name: "auc".into(),
                value: 0.85,
                unit: "ratio".into(),
            },
        )
        .unwrap();
        let updated = reg.get(r.run_id).unwrap();
        assert_eq!(updated.metric("auc").unwrap().value, 0.85);
        assert!(updated.metric("ghost").is_none());
    }

    #[test]
    fn for_model_filters() {
        let reg = TrainingRunRegistry::new();
        reg.open("x", "model-a", "1").unwrap();
        reg.open("x", "model-b", "1").unwrap();
        assert_eq!(reg.for_model("model-a").len(), 1);
        assert_eq!(reg.for_model("model-b").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        reg.set_status(r.run_id, RunStatus::Completed).unwrap();
        open(&reg);
        assert_eq!(reg.by_status(RunStatus::Completed).len(), 1);
        assert_eq!(reg.by_status(RunStatus::Queued).len(), 1);
    }

    #[test]
    fn run_serde() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        let j = serde_json::to_string(&r).unwrap();
        let p: TrainingRun = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn metric_serde() {
        let m = RunMetric {
            name: "x".into(),
            value: 0.5,
            unit: "y".into(),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: RunMetric = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn hyperparam_serde() {
        let h = Hyperparam {
            name: "lr".into(),
            value: "0.001".into(),
        };
        let j = serde_json::to_string(&h).unwrap();
        let p: Hyperparam = serde_json::from_str(&j).unwrap();
        assert_eq!(p, h);
    }

    #[test]
    fn status_serde() {
        for s in [
            RunStatus::Queued,
            RunStatus::Running,
            RunStatus::Completed,
            RunStatus::Failed,
            RunStatus::Cancelled,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: RunStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn unknown_run_lookups_none() {
        let reg = TrainingRunRegistry::new();
        assert!(reg.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn add_training_unknown_errors() {
        let reg = TrainingRunRegistry::new();
        assert!(reg.add_training_dataset(Uuid::now_v7(), "x").is_err());
    }

    #[test]
    fn count_tracks() {
        let reg = TrainingRunRegistry::new();
        assert!(reg.is_empty());
        open(&reg);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn many_runs_increment_display_id() {
        let reg = TrainingRunRegistry::new();
        let r1 = open(&reg);
        let r2 = open(&reg);
        assert_ne!(r1.display_id, r2.display_id);
    }

    #[test]
    fn duration_none_until_complete() {
        let reg = TrainingRunRegistry::new();
        let r = open(&reg);
        assert!(r.duration_seconds().is_none());
    }
}
