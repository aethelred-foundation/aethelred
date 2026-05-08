//! CI/CD deployment pipeline records.
//!
//! Tracks every deployment with its commit SHA, environment, status,
//! deployer, and per-stage timing. Composes with [`crate::canary_deployment`]
//! (which tracks model A/B), [`crate::supply_chain_sbom`] (for SBOM at
//! deploy time), and [`crate::workspace_audit`] (operator action log).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// Environment
// =============================================================================

/// Deployment environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    /// Production.
    Production,
    /// Staging.
    Staging,
    /// QA.
    Qa,
    /// Dev.
    Dev,
    /// Sandbox / preview.
    Preview,
}

// =============================================================================
// PipelineStatus
// =============================================================================

/// Overall status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    /// In progress.
    Running,
    /// Completed successfully.
    Succeeded,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
    /// Rolled back.
    RolledBack,
}

// =============================================================================
// PipelineStage
// =============================================================================

/// One stage record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineStage {
    /// Stage name (e.g. `"build"`, `"test"`, `"deploy"`).
    pub name: String,
    /// Status.
    pub status: PipelineStatus,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 ended.
    pub ended_at: Option<String>,
    /// Optional error message.
    pub error: Option<String>,
}

// =============================================================================
// PipelineRun
// =============================================================================

/// One pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PipelineRun {
    /// Stable id.
    pub run_id: Uuid,
    /// Display id (e.g. `"deploy-2026-0001"`).
    pub display_id: String,
    /// Service.
    pub service_id: String,
    /// Version being deployed.
    pub service_version: String,
    /// Commit SHA.
    pub commit_sha: String,
    /// Environment.
    pub environment: Environment,
    /// Triggered by.
    pub triggered_by: String,
    /// Trigger reason.
    pub trigger_reason: String,
    /// Stages.
    pub stages: Vec<PipelineStage>,
    /// Status.
    pub status: PipelineStatus,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 ended.
    pub ended_at: Option<String>,
    /// Optional rollback target run id.
    pub rollback_target: Option<Uuid>,
}

impl PipelineRun {
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

    /// Lookup stage by name.
    pub fn stage(&self, name: &str) -> Option<&PipelineStage> {
        self.stages.iter().find(|s| s.name == name)
    }
}

// =============================================================================
// PipelineRegistry
// =============================================================================

#[derive(Default)]
struct State {
    runs: HashMap<Uuid, PipelineRun>,
    seq: HashMap<String, u32>,
}

/// Registry.
pub struct PipelineRegistry {
    state: RwLock<State>,
}

impl Default for PipelineRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for PipelineRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineRegistry")
            .field("runs", &self.len())
            .finish()
    }
}

impl PipelineRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new pipeline run.
    pub fn open(
        &self,
        service_id: impl Into<String>,
        service_version: impl Into<String>,
        commit_sha: impl Into<String>,
        environment: Environment,
        triggered_by: impl Into<String>,
        trigger_reason: impl Into<String>,
    ) -> SandboxResult<PipelineRun> {
        let now = OffsetDateTime::now_utc();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("pipeline registry poisoned".into()))?;
        let prefix = format!("deploy-{}", now.year());
        let seq = g.seq.entry(prefix.clone()).or_insert(0);
        *seq += 1;
        let display_id = format!("{}-{:04}", prefix, *seq);
        let run = PipelineRun {
            run_id: Uuid::now_v7(),
            display_id,
            service_id: service_id.into(),
            service_version: service_version.into(),
            commit_sha: commit_sha.into(),
            environment,
            triggered_by: triggered_by.into(),
            trigger_reason: trigger_reason.into(),
            stages: Vec::new(),
            status: PipelineStatus::Running,
            started_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            ended_at: None,
            rollback_target: None,
        };
        g.runs.insert(run.run_id, run.clone());
        Ok(run)
    }

    /// Start a stage.
    pub fn start_stage(
        &self,
        run_id: Uuid,
        name: impl Into<String>,
    ) -> SandboxResult<()> {
        let name = name.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("pipeline registry poisoned".into()))?;
        let run = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        if run.stages.iter().any(|s| s.name == name) {
            return Err(SandboxError::Other(format!("stage {} already started", name)));
        }
        run.stages.push(PipelineStage {
            name,
            status: PipelineStatus::Running,
            started_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            ended_at: None,
            error: None,
        });
        Ok(())
    }

    /// Complete a stage.
    pub fn complete_stage(
        &self,
        run_id: Uuid,
        name: &str,
        status: PipelineStatus,
        error: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("pipeline registry poisoned".into()))?;
        let run = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        let s = run
            .stages
            .iter_mut()
            .find(|s| s.name == name)
            .ok_or_else(|| SandboxError::Other(format!("stage {} not found", name)))?;
        s.status = status;
        s.error = error;
        s.ended_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Mark run as final status.
    pub fn finalize(&self, run_id: Uuid, status: PipelineStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("pipeline registry poisoned".into()))?;
        let run = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        run.status = status;
        if matches!(
            status,
            PipelineStatus::Succeeded | PipelineStatus::Failed | PipelineStatus::Cancelled | PipelineStatus::RolledBack
        ) {
            run.ended_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    /// Mark a run as a rollback of another.
    pub fn mark_rollback_of(&self, run_id: Uuid, target: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("pipeline registry poisoned".into()))?;
        let run = g
            .runs
            .get_mut(&run_id)
            .ok_or_else(|| SandboxError::Other(format!("run {} not found", run_id)))?;
        run.rollback_target = Some(target);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<PipelineRun> {
        self.state.read().ok()?.runs.get(&id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<PipelineRun> {
        self.state
            .read()
            .map(|g| g.runs.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Filter by service.
    pub fn for_service(&self, service: &str) -> Vec<PipelineRun> {
        self.all().into_iter().filter(|r| r.service_id == service).collect()
    }

    /// Filter by environment.
    pub fn for_env(&self, env: Environment) -> Vec<PipelineRun> {
        self.all().into_iter().filter(|r| r.environment == env).collect()
    }

    /// Filter by status.
    pub fn by_status(&self, status: PipelineStatus) -> Vec<PipelineRun> {
        self.all().into_iter().filter(|r| r.status == status).collect()
    }

    /// Latest run for service in env.
    pub fn latest_for(
        &self,
        service: &str,
        env: Environment,
    ) -> Option<PipelineRun> {
        let mut runs: Vec<PipelineRun> = self
            .all()
            .into_iter()
            .filter(|r| r.service_id == service && r.environment == env)
            .collect();
        runs.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        runs.into_iter().next()
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

    fn open(reg: &PipelineRegistry) -> PipelineRun {
        reg.open(
            "sandbox-finance",
            "0.2.17",
            "abc123def",
            Environment::Production,
            "ci-bot",
            "merge to main",
        )
        .unwrap()
    }

    #[test]
    fn open_creates_run() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        assert_eq!(r.status, PipelineStatus::Running);
        assert!(r.display_id.starts_with("deploy-"));
    }

    #[test]
    fn start_stage_appends() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.start_stage(r.run_id, "build").unwrap();
        assert_eq!(reg.get(r.run_id).unwrap().stages.len(), 1);
    }

    #[test]
    fn duplicate_start_stage_errors() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.start_stage(r.run_id, "build").unwrap();
        assert!(reg.start_stage(r.run_id, "build").is_err());
    }

    #[test]
    fn complete_stage_sets_status() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.start_stage(r.run_id, "build").unwrap();
        reg.complete_stage(r.run_id, "build", PipelineStatus::Succeeded, None)
            .unwrap();
        let updated = reg.get(r.run_id).unwrap();
        let s = updated.stage("build").unwrap();
        assert_eq!(s.status, PipelineStatus::Succeeded);
        assert!(s.ended_at.is_some());
    }

    #[test]
    fn complete_unknown_stage_errors() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        assert!(reg
            .complete_stage(r.run_id, "ghost", PipelineStatus::Succeeded, None)
            .is_err());
    }

    #[test]
    fn finalize_sets_ended_at() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.finalize(r.run_id, PipelineStatus::Succeeded).unwrap();
        assert!(reg.get(r.run_id).unwrap().ended_at.is_some());
    }

    #[test]
    fn finalize_running_does_not_set_ended() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.finalize(r.run_id, PipelineStatus::Running).unwrap();
        assert!(reg.get(r.run_id).unwrap().ended_at.is_none());
    }

    #[test]
    fn duration_after_finalize() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.finalize(r.run_id, PipelineStatus::Succeeded).unwrap();
        assert!(reg.get(r.run_id).unwrap().duration_seconds().is_some());
    }

    #[test]
    fn rollback_target_recorded() {
        let reg = PipelineRegistry::new();
        let r1 = open(&reg);
        let r2 = open(&reg);
        reg.mark_rollback_of(r2.run_id, r1.run_id).unwrap();
        assert_eq!(
            reg.get(r2.run_id).unwrap().rollback_target,
            Some(r1.run_id)
        );
    }

    #[test]
    fn for_service_filters() {
        let reg = PipelineRegistry::new();
        open(&reg);
        reg.open(
            "other-service",
            "1",
            "x",
            Environment::Production,
            "ci",
            "x",
        )
        .unwrap();
        assert_eq!(reg.for_service("sandbox-finance").len(), 1);
        assert_eq!(reg.for_service("other-service").len(), 1);
    }

    #[test]
    fn for_env_filters() {
        let reg = PipelineRegistry::new();
        open(&reg);
        reg.open(
            "sandbox-finance",
            "0.2.17",
            "x",
            Environment::Staging,
            "ci",
            "x",
        )
        .unwrap();
        assert_eq!(reg.for_env(Environment::Production).len(), 1);
        assert_eq!(reg.for_env(Environment::Staging).len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.finalize(r.run_id, PipelineStatus::Succeeded).unwrap();
        open(&reg);
        assert_eq!(reg.by_status(PipelineStatus::Succeeded).len(), 1);
        assert_eq!(reg.by_status(PipelineStatus::Running).len(), 1);
    }

    #[test]
    fn latest_for_returns_newest() {
        let reg = PipelineRegistry::new();
        open(&reg);
        let r2 = open(&reg);
        let latest = reg.latest_for("sandbox-finance", Environment::Production).unwrap();
        assert_eq!(latest.run_id, r2.run_id);
    }

    #[test]
    fn run_serde() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        let j = serde_json::to_string(&r).unwrap();
        let p: PipelineRun = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn stage_serde() {
        let s = PipelineStage {
            name: "build".into(),
            status: PipelineStatus::Succeeded,
            started_at: "t".into(),
            ended_at: None,
            error: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: PipelineStage = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn environment_serde() {
        for e in [
            Environment::Production,
            Environment::Staging,
            Environment::Qa,
            Environment::Dev,
            Environment::Preview,
        ] {
            let j = serde_json::to_string(&e).unwrap();
            let p: Environment = serde_json::from_str(&j).unwrap();
            assert_eq!(p, e);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            PipelineStatus::Running,
            PipelineStatus::Succeeded,
            PipelineStatus::Failed,
            PipelineStatus::Cancelled,
            PipelineStatus::RolledBack,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: PipelineStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn count_tracks() {
        let reg = PipelineRegistry::new();
        assert!(reg.is_empty());
        open(&reg);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn lookup_unknown_none() {
        let reg = PipelineRegistry::new();
        assert!(reg.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn many_runs_increment_display() {
        let reg = PipelineRegistry::new();
        let r1 = open(&reg);
        let r2 = open(&reg);
        assert_ne!(r1.display_id, r2.display_id);
    }

    #[test]
    fn stage_with_error_recorded() {
        let reg = PipelineRegistry::new();
        let r = open(&reg);
        reg.start_stage(r.run_id, "test").unwrap();
        reg.complete_stage(
            r.run_id,
            "test",
            PipelineStatus::Failed,
            Some("flaky".into()),
        )
        .unwrap();
        let s = reg.get(r.run_id).unwrap();
        assert_eq!(s.stage("test").unwrap().error.as_deref(), Some("flaky"));
    }

    #[test]
    fn rollback_unknown_errors() {
        let reg = PipelineRegistry::new();
        assert!(reg.mark_rollback_of(Uuid::now_v7(), Uuid::now_v7()).is_err());
    }
}
