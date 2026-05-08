//! Operator runbook engine — encoded incident response with step
//! verification.
//!
//! Existing runbooks live as documents (Confluence, Notion). This module
//! upgrades them to **executable artifacts**: a [`Runbook`] is a sequence
//! of [`RunbookStep`]s. An operator runs the runbook against an active
//! [`crate::incident::Incident`] (or any other context) and records each
//! step's outcome — `Started → Completed` or `Skipped/Failed` — with
//! free-text notes and an optional verification command output.
//!
//! Each [`RunbookExecution`] is tamper-evident (chained hashes) so the
//! runbook execution trail can be sealed.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RunbookStep
// =============================================================================

/// One step in a runbook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunbookStep {
    /// Stable id within the runbook.
    pub step_id: String,
    /// Display title.
    pub title: String,
    /// Free-text instructions.
    pub instructions: String,
    /// Optional verification command (shell, HTTP, etc.) — operator runs it.
    pub verification: Option<String>,
    /// `true` if this step requires a specific approver role.
    pub requires_approval: bool,
    /// `true` if step can be safely skipped.
    pub skippable: bool,
}

// =============================================================================
// Runbook
// =============================================================================

/// One runbook template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Runbook {
    /// Stable id (e.g. `"hsm-rotation"`).
    pub runbook_id: String,
    /// Display name.
    pub name: String,
    /// Free-text description.
    pub description: String,
    /// Owner.
    pub owner: String,
    /// Steps in order.
    pub steps: Vec<RunbookStep>,
    /// Version number.
    pub version: u32,
    /// Hash of the steps (for tamper evidence).
    pub steps_hash: Sha256Digest,
}

impl Runbook {
    fn compute_steps_hash(steps: &[RunbookStep]) -> Sha256Digest {
        let mut buf = Vec::new();
        for s in steps {
            buf.extend_from_slice(s.step_id.as_bytes());
            buf.push(0);
            buf.extend_from_slice(s.title.as_bytes());
            buf.push(0);
            buf.extend_from_slice(s.instructions.as_bytes());
            buf.push(0);
            if let Some(v) = &s.verification {
                buf.extend_from_slice(v.as_bytes());
            }
        }
        Hasher::sha256(&buf)
    }

    /// Build with auto-computed hash.
    pub fn build(
        runbook_id: impl Into<String>,
        name: impl Into<String>,
        owner: impl Into<String>,
        description: impl Into<String>,
        steps: Vec<RunbookStep>,
        version: u32,
    ) -> Self {
        let steps_hash = Self::compute_steps_hash(&steps);
        Self {
            runbook_id: runbook_id.into(),
            name: name.into(),
            description: description.into(),
            owner: owner.into(),
            steps,
            version,
            steps_hash,
        }
    }
}

// =============================================================================
// StepStatus
// =============================================================================

/// Per-step outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Not yet started.
    Pending,
    /// Started.
    Started,
    /// Completed successfully.
    Completed,
    /// Skipped (legitimate skip via `skippable`).
    Skipped,
    /// Failed.
    Failed,
}

// =============================================================================
// StepRecord
// =============================================================================

/// One step's execution record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StepRecord {
    /// Step id.
    pub step_id: String,
    /// Status.
    pub status: StepStatus,
    /// Operator who executed.
    pub actor: Option<String>,
    /// RFC 3339 started.
    pub started_at: Option<String>,
    /// RFC 3339 ended.
    pub ended_at: Option<String>,
    /// Free-text notes.
    pub notes: Option<String>,
    /// Verification output (truncated).
    pub verification_output: Option<String>,
    /// Hash of prior step record.
    pub prior_hash: Option<Sha256Digest>,
    /// Hash of this record content.
    pub record_hash: Sha256Digest,
}

impl StepRecord {
    fn compute_hash(
        step_id: &str,
        status: StepStatus,
        actor: Option<&str>,
        notes: Option<&str>,
        prior: Option<&Sha256Digest>,
    ) -> Sha256Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(step_id.as_bytes());
        buf.push(0);
        buf.push(status_byte(status));
        if let Some(a) = actor {
            buf.extend_from_slice(a.as_bytes());
        }
        buf.push(0);
        if let Some(n) = notes {
            buf.extend_from_slice(n.as_bytes());
        }
        if let Some(p) = prior {
            buf.extend_from_slice(&p.0);
        }
        Hasher::sha256(&buf)
    }
}

fn status_byte(s: StepStatus) -> u8 {
    match s {
        StepStatus::Pending => 0,
        StepStatus::Started => 1,
        StepStatus::Completed => 2,
        StepStatus::Skipped => 3,
        StepStatus::Failed => 4,
    }
}

// =============================================================================
// RunbookExecution
// =============================================================================

/// One run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunbookExecution {
    /// Stable id.
    pub execution_id: Uuid,
    /// Runbook id.
    pub runbook_id: String,
    /// Runbook version executed.
    pub runbook_version: u32,
    /// Captured `steps_hash` of the runbook at exec time.
    pub runbook_steps_hash: Sha256Digest,
    /// Optional incident / case linkage.
    pub linked_id: Option<String>,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 finished (None = still running).
    pub finished_at: Option<String>,
    /// Initiator.
    pub initiator: String,
    /// Step records (in execution order).
    pub steps: Vec<StepRecord>,
}

impl RunbookExecution {
    /// `true` if every required step is completed.
    pub fn all_completed(&self, runbook: &Runbook) -> bool {
        for spec in &runbook.steps {
            if spec.skippable {
                continue;
            }
            let r = self.steps.iter().find(|r| r.step_id == spec.step_id);
            match r {
                Some(rec)
                    if rec.status == StepStatus::Completed
                        || rec.status == StepStatus::Skipped =>
                {
                    continue
                }
                _ => return false,
            }
        }
        true
    }

    /// `true` if any step is in Failed.
    pub fn has_failure(&self) -> bool {
        self.steps.iter().any(|r| r.status == StepStatus::Failed)
    }
}

// =============================================================================
// RunbookEngine
// =============================================================================

#[derive(Default)]
struct State {
    runbooks: HashMap<String, Runbook>,
    executions: HashMap<Uuid, RunbookExecution>,
}

/// Engine.
pub struct RunbookEngine {
    state: RwLock<State>,
}

impl Default for RunbookEngine {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RunbookEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunbookEngine")
            .field("runbooks", &self.runbook_count())
            .field("executions", &self.execution_count())
            .finish()
    }
}

impl RunbookEngine {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a runbook.
    pub fn register(&self, r: Runbook) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("runbook engine poisoned".into()))?;
        g.runbooks.insert(r.runbook_id.clone(), r);
        Ok(())
    }

    /// Number of runbooks.
    pub fn runbook_count(&self) -> usize {
        self.state.read().map(|g| g.runbooks.len()).unwrap_or(0)
    }

    /// Number of executions.
    pub fn execution_count(&self) -> usize {
        self.state.read().map(|g| g.executions.len()).unwrap_or(0)
    }

    /// Lookup runbook.
    pub fn runbook(&self, id: &str) -> Option<Runbook> {
        self.state.read().ok()?.runbooks.get(id).cloned()
    }

    /// Begin an execution.
    pub fn begin(
        &self,
        runbook_id: &str,
        initiator: impl Into<String>,
        linked_id: Option<String>,
    ) -> SandboxResult<RunbookExecution> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("runbook engine poisoned".into()))?;
        let rb = g
            .runbooks
            .get(runbook_id)
            .ok_or_else(|| SandboxError::Other(format!("runbook {} not found", runbook_id)))?
            .clone();
        drop(g);
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let exec = RunbookExecution {
            execution_id: Uuid::now_v7(),
            runbook_id: rb.runbook_id.clone(),
            runbook_version: rb.version,
            runbook_steps_hash: rb.steps_hash.clone(),
            linked_id,
            started_at: now,
            finished_at: None,
            initiator: initiator.into(),
            steps: Vec::new(),
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("runbook engine poisoned".into()))?;
        g.executions.insert(exec.execution_id, exec.clone());
        Ok(exec)
    }

    /// Record a step outcome.
    pub fn record_step(
        &self,
        execution_id: Uuid,
        step_id: impl Into<String>,
        status: StepStatus,
        actor: impl Into<String>,
        notes: Option<String>,
        verification_output: Option<String>,
    ) -> SandboxResult<StepRecord> {
        let step_id = step_id.into();
        let actor = actor.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("runbook engine poisoned".into()))?;
        let exec = g
            .executions
            .get_mut(&execution_id)
            .ok_or_else(|| SandboxError::Other(format!("execution {} not found", execution_id)))?;
        if exec.finished_at.is_some() {
            return Err(SandboxError::Other(format!(
                "execution {} already finished",
                execution_id
            )));
        }
        let prior = exec.steps.last().map(|r| r.record_hash.clone());
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let record_hash = StepRecord::compute_hash(
            &step_id,
            status,
            Some(&actor),
            notes.as_deref(),
            prior.as_ref(),
        );
        let r = StepRecord {
            step_id,
            status,
            actor: Some(actor),
            started_at: Some(now.clone()),
            ended_at: Some(now),
            notes,
            verification_output,
            prior_hash: prior,
            record_hash,
        };
        exec.steps.push(r.clone());
        Ok(r)
    }

    /// Finish.
    pub fn finish(&self, execution_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("runbook engine poisoned".into()))?;
        let exec = g
            .executions
            .get_mut(&execution_id)
            .ok_or_else(|| SandboxError::Other(format!("execution {} not found", execution_id)))?;
        exec.finished_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Lookup execution.
    pub fn execution(&self, id: Uuid) -> Option<RunbookExecution> {
        self.state.read().ok()?.executions.get(&id).cloned()
    }

    /// All executions.
    pub fn all_executions(&self) -> Vec<RunbookExecution> {
        self.state
            .read()
            .map(|g| g.executions.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Verify chain.
    pub fn verify_chain(&self, execution_id: Uuid) -> SandboxResult<()> {
        let exec = self.execution(execution_id).ok_or_else(|| {
            SandboxError::Other(format!("execution {} not found", execution_id))
        })?;
        let mut prior: Option<Sha256Digest> = None;
        for (i, r) in exec.steps.iter().enumerate() {
            match (&r.prior_hash, &prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "execution {} chain break at step {}",
                        execution_id, i
                    )))
                }
            }
            let recomputed = StepRecord::compute_hash(
                &r.step_id,
                r.status,
                r.actor.as_deref(),
                r.notes.as_deref(),
                r.prior_hash.as_ref(),
            );
            if recomputed != r.record_hash {
                return Err(SandboxError::Other(format!(
                    "execution {} step {} hash mismatch",
                    execution_id, i
                )));
            }
            prior = Some(r.record_hash.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(id: &str, skippable: bool) -> RunbookStep {
        RunbookStep {
            step_id: id.into(),
            title: id.into(),
            instructions: format!("do step {id}"),
            verification: None,
            requires_approval: false,
            skippable,
        }
    }

    fn rb() -> Runbook {
        Runbook::build(
            "hsm-rotate",
            "HSM Rotation",
            "platform",
            "rotate hsm key",
            vec![step("a", false), step("b", false), step("c", true)],
            1,
        )
    }

    #[test]
    fn register_increments_count() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        assert_eq!(e.runbook_count(), 1);
    }

    #[test]
    fn begin_creates_execution() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", Some("INC-1".into())).unwrap();
        assert_eq!(exec.runbook_id, "hsm-rotate");
        assert_eq!(exec.linked_id.as_deref(), Some("INC-1"));
        assert_eq!(e.execution_count(), 1);
    }

    #[test]
    fn begin_unknown_runbook_errors() {
        let e = RunbookEngine::new();
        assert!(e.begin("ghost", "ops", None).is_err());
    }

    #[test]
    fn record_step_appends_with_chain() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        let r1 = e
            .record_step(
                exec.execution_id,
                "a",
                StepStatus::Completed,
                "ops",
                Some("ok".into()),
                None,
            )
            .unwrap();
        let r2 = e
            .record_step(
                exec.execution_id,
                "b",
                StepStatus::Completed,
                "ops",
                None,
                None,
            )
            .unwrap();
        assert!(r1.prior_hash.is_none());
        assert_eq!(r2.prior_hash, Some(r1.record_hash));
    }

    #[test]
    fn finish_sets_finished_at() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        e.finish(exec.execution_id).unwrap();
        let updated = e.execution(exec.execution_id).unwrap();
        assert!(updated.finished_at.is_some());
    }

    #[test]
    fn cannot_record_after_finish() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        e.finish(exec.execution_id).unwrap();
        assert!(e
            .record_step(
                exec.execution_id,
                "a",
                StepStatus::Completed,
                "ops",
                None,
                None
            )
            .is_err());
    }

    #[test]
    fn all_completed_handles_skippable() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        // a, b mandatory; c skippable.
        e.record_step(
            exec.execution_id,
            "a",
            StepStatus::Completed,
            "ops",
            None,
            None,
        )
        .unwrap();
        e.record_step(
            exec.execution_id,
            "b",
            StepStatus::Completed,
            "ops",
            None,
            None,
        )
        .unwrap();
        let updated = e.execution(exec.execution_id).unwrap();
        assert!(updated.all_completed(&rb()));
    }

    #[test]
    fn missing_step_means_not_complete() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        e.record_step(
            exec.execution_id,
            "a",
            StepStatus::Completed,
            "ops",
            None,
            None,
        )
        .unwrap();
        let updated = e.execution(exec.execution_id).unwrap();
        assert!(!updated.all_completed(&rb()));
    }

    #[test]
    fn failed_step_recorded() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        e.record_step(
            exec.execution_id,
            "a",
            StepStatus::Failed,
            "ops",
            Some("err".into()),
            None,
        )
        .unwrap();
        let updated = e.execution(exec.execution_id).unwrap();
        assert!(updated.has_failure());
    }

    #[test]
    fn verify_chain_passes() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        for s in ["a", "b"] {
            e.record_step(
                exec.execution_id,
                s,
                StepStatus::Completed,
                "ops",
                None,
                None,
            )
            .unwrap();
        }
        e.verify_chain(exec.execution_id).unwrap();
    }

    #[test]
    fn verify_chain_unknown_errors() {
        let e = RunbookEngine::new();
        assert!(e.verify_chain(Uuid::now_v7()).is_err());
    }

    #[test]
    fn runbook_steps_hash_deterministic() {
        let r1 = rb();
        let r2 = rb();
        assert_eq!(r1.steps_hash, r2.steps_hash);
    }

    #[test]
    fn runbook_steps_hash_changes_with_step() {
        let r1 = rb();
        let mut s = r1.steps.clone();
        s[0].instructions = "different".into();
        let r2 = Runbook::build("x", "x", "x", "x", s, 1);
        assert_ne!(r1.steps_hash, r2.steps_hash);
    }

    #[test]
    fn step_status_serde() {
        for s in [
            StepStatus::Pending,
            StepStatus::Started,
            StepStatus::Completed,
            StepStatus::Skipped,
            StepStatus::Failed,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: StepStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn runbook_serde() {
        let r = rb();
        let j = serde_json::to_string(&r).unwrap();
        let p: Runbook = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn execution_serde() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        let exec = e.begin("hsm-rotate", "ops", None).unwrap();
        let j = serde_json::to_string(&exec).unwrap();
        let p: RunbookExecution = serde_json::from_str(&j).unwrap();
        assert_eq!(p, exec);
    }

    #[test]
    fn step_record_serde() {
        let r = StepRecord {
            step_id: "x".into(),
            status: StepStatus::Completed,
            actor: Some("a".into()),
            started_at: Some("t".into()),
            ended_at: Some("t2".into()),
            notes: None,
            verification_output: None,
            prior_hash: None,
            record_hash: Hasher::sha256(b"x"),
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: StepRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn record_unknown_execution_errors() {
        let e = RunbookEngine::new();
        assert!(e
            .record_step(
                Uuid::now_v7(),
                "a",
                StepStatus::Completed,
                "x",
                None,
                None
            )
            .is_err());
    }

    #[test]
    fn runbook_count_zero_initially() {
        let e = RunbookEngine::new();
        assert_eq!(e.runbook_count(), 0);
    }

    #[test]
    fn many_steps_chain_intact() {
        let e = RunbookEngine::new();
        let r = Runbook::build(
            "many",
            "many",
            "x",
            "x",
            (0..20).map(|i| step(&format!("s{i}"), false)).collect(),
            1,
        );
        e.register(r).unwrap();
        let exec = e.begin("many", "ops", None).unwrap();
        for i in 0..20 {
            e.record_step(
                exec.execution_id,
                &format!("s{i}"),
                StepStatus::Completed,
                "ops",
                None,
                None,
            )
            .unwrap();
        }
        e.verify_chain(exec.execution_id).unwrap();
    }

    #[test]
    fn runbook_lookup() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        assert!(e.runbook("hsm-rotate").is_some());
        assert!(e.runbook("ghost").is_none());
    }

    #[test]
    fn all_executions_returns_all() {
        let e = RunbookEngine::new();
        e.register(rb()).unwrap();
        e.begin("hsm-rotate", "ops", None).unwrap();
        e.begin("hsm-rotate", "ops", None).unwrap();
        assert_eq!(e.all_executions().len(), 2);
    }
}
