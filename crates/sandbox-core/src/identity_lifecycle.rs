//! Identity lifecycle (joiner / mover / leaver) register.
//!
//! Maps to **SOC 2 CC6.2** (logical access provisioning), **ISO 27001
//! A.9.2.1-2** (user registration / deregistration), and **NIST 800-53
//! AC-2** (account management). Every employee, contractor, and
//! service-account life event — onboarding, role change, transfer,
//! offboarding, termination — must be tracked from request through
//! every provisioning action with timing evidence.
//!
//! ## Lifecycle stages
//!
//! `Requested → InProgress → Completed | Cancelled`
//!
//! Each event has provisioning **tasks** (create account, assign role,
//! grant access, revoke access, disable account). Tasks have their own
//! lifecycle (`Pending → InProgress → Completed | Failed`). The event
//! cannot move to `Completed` while any task is unfinished.
//!
//! Distinct from [`crate::access_certification`] (periodic review),
//! [`crate::privileged_access_register`] (per-grant elevation), and
//! [`crate::user_session`] (active sessions): this is the
//! **provisioning workflow** that creates / changes / removes identities
//! end-to-end.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// EventKind
// =============================================================================

/// Kind of lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// New hire / new account.
    Joiner,
    /// Role / scope change.
    Mover,
    /// Internal transfer between teams.
    Transfer,
    /// Voluntary departure.
    Leaver,
    /// Involuntary termination (immediate access removal).
    Termination,
    /// Contractor end-of-engagement.
    ContractEnd,
    /// Long-term leave (LOA — disable but don't remove).
    Loa,
    /// Return from leave (re-enable).
    LoaReturn,
}

impl EventKind {
    /// True if the event must complete urgently (typically same-day).
    pub fn is_urgent(self) -> bool {
        matches!(self, Self::Termination | Self::Leaver | Self::Loa)
    }
}

// =============================================================================
// EventStage
// =============================================================================

/// Lifecycle stage of the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStage {
    /// Logged but not yet started.
    Requested,
    /// Provisioning tasks underway.
    InProgress,
    /// All tasks completed.
    Completed,
    /// Cancelled mid-flight.
    Cancelled,
}

impl EventStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

// =============================================================================
// TaskKind
// =============================================================================

/// Kind of provisioning task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Create account in IdP.
    CreateAccount,
    /// Disable account (suspend without delete).
    DisableAccount,
    /// Delete account (after retention).
    DeleteAccount,
    /// Re-enable suspended account.
    EnableAccount,
    /// Assign role / group.
    AssignRole,
    /// Remove role / group.
    RemoveRole,
    /// Grant a specific permission.
    GrantPermission,
    /// Revoke a specific permission.
    RevokePermission,
    /// Issue a credential (laptop, badge, MFA token).
    IssueCredential,
    /// Reclaim a credential.
    ReclaimCredential,
    /// Notify HR / compliance / payroll.
    Notify,
}

// =============================================================================
// TaskStatus
// =============================================================================

/// Per-task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Not yet started.
    Pending,
    /// Currently underway.
    InProgress,
    /// Done.
    Completed,
    /// Failed; needs intervention.
    Failed,
    /// Skipped (e.g., not applicable).
    Skipped,
}

impl TaskStatus {
    /// True if no further work is expected.
    pub fn is_resolved(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Skipped)
    }
}

// =============================================================================
// ProvisioningTask
// =============================================================================

/// One provisioning task.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProvisioningTask {
    /// Stable id within the event.
    pub task_id: String,
    /// Kind.
    pub kind: TaskKind,
    /// Target system / role / permission name.
    pub target: String,
    /// Owner responsible for executing the task.
    pub owner: String,
    /// Status.
    pub status: TaskStatus,
    /// RFC 3339 — when status was last updated.
    pub updated_at: Option<String>,
    /// Free-text note (failure reason, completion summary).
    pub note: Option<String>,
}

impl ProvisioningTask {
    /// New `Pending` task.
    pub fn new(
        task_id: impl Into<String>,
        kind: TaskKind,
        target: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            kind,
            target: target.into(),
            owner: owner.into(),
            status: TaskStatus::Pending,
            updated_at: None,
            note: None,
        }
    }
}

// =============================================================================
// IdentityEvent
// =============================================================================

/// One identity-lifecycle event with provisioning tasks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityEvent {
    /// Unique id (e.g., "JLM-2025-0123").
    pub event_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Subject (employee id, contractor id, service-account id).
    pub subject_id: String,
    /// Display name of the subject.
    pub subject_name: String,
    /// Kind.
    pub kind: EventKind,
    /// Owning HR / IT contact.
    pub owner: String,
    /// Initiator (who requested the change).
    pub initiator: String,
    /// Tasks.
    pub tasks: Vec<ProvisioningTask>,
    /// Lifecycle stage.
    pub stage: EventStage,
    /// RFC 3339 — when requested.
    pub requested_at: String,
    /// RFC 3339 — provisioning effective date (e.g., termination effective).
    pub effective_at: Option<String>,
    /// RFC 3339 — closed (terminal).
    pub closed_at: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl IdentityEvent {
    /// New `Requested` event.
    pub fn new(
        event_id: impl Into<String>,
        tenant_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_name: impl Into<String>,
        kind: EventKind,
        owner: impl Into<String>,
        initiator: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            tenant_id: tenant_id.into(),
            subject_id: subject_id.into(),
            subject_name: subject_name.into(),
            kind,
            owner: owner.into(),
            initiator: initiator.into(),
            tasks: Vec::new(),
            stage: EventStage::Requested,
            requested_at: requested_at.into(),
            effective_at: None,
            closed_at: None,
            tags: Vec::new(),
        }
    }

    /// Number of tasks not yet resolved.
    pub fn pending_task_count(&self) -> usize {
        self.tasks.iter().filter(|t| !t.status.is_resolved()).count()
    }

    /// Number of failed tasks.
    pub fn failed_task_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|t| matches!(t.status, TaskStatus::Failed))
            .count()
    }

    /// True if this event is past its effective date and not yet
    /// completed (urgent kinds especially).
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match self.effective_at.as_deref() {
            Some(eff) => now >= eff,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: EventStage, to: EventStage) -> bool {
    use EventStage::*;
    matches!(
        (from, to),
        (Requested, InProgress)
            | (Requested, Cancelled)
            | (InProgress, Completed)
            | (InProgress, Cancelled)
    )
}

// =============================================================================
// IdentityLifecycleRegistry
// =============================================================================

/// Thread-safe register of identity-lifecycle events.
#[derive(Debug, Default)]
pub struct IdentityLifecycleRegistry {
    inner: RwLock<HashMap<String, IdentityEvent>>,
}

impl IdentityLifecycleRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new event.
    pub fn open(&self, event: IdentityEvent) -> SandboxResult<()> {
        if !matches!(event.stage, EventStage::Requested) {
            return Err(SandboxError::Other(format!(
                "event must start Requested, got {:?}",
                event.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        if g.contains_key(&event.event_id) {
            return Err(SandboxError::Other(format!(
                "event already opened: {}",
                event.event_id
            )));
        }
        g.insert(event.event_id.clone(), event);
        Ok(())
    }

    /// Add a task to a Requested event.
    pub fn add_task(&self, event_id: &str, task: ProvisioningTask) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !matches!(e.stage, EventStage::Requested) {
            return Err(SandboxError::Other(format!(
                "cannot add task to {event_id}: stage is {:?}",
                e.stage
            )));
        }
        if e.tasks.iter().any(|t| t.task_id == task.task_id) {
            return Err(SandboxError::Other(format!(
                "task already present: {}",
                task.task_id
            )));
        }
        e.tasks.push(task);
        Ok(())
    }

    /// Move event to InProgress.
    pub fn start(
        &self,
        event_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<IdentityEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !legal_transition(e.stage, EventStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> InProgress",
                e.stage
            )));
        }
        e.stage = EventStage::InProgress;
        let _ = at.into();
        Ok(e.clone())
    }

    /// Update task status. Event must be InProgress.
    pub fn set_task_status(
        &self,
        event_id: &str,
        task_id: &str,
        status: TaskStatus,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !matches!(e.stage, EventStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "cannot update task on {event_id}: stage is {:?}",
                e.stage
            )));
        }
        let t = e
            .tasks
            .iter_mut()
            .find(|t| t.task_id == task_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown task {task_id}")))?;
        t.status = status;
        t.updated_at = Some(at.into());
        if let Some(n) = note {
            t.note = Some(n);
        }
        Ok(())
    }

    /// Complete the event. All tasks must be resolved (Completed / Failed
    /// / Skipped). Failed tasks do not block completion — the event closes
    /// with a non-zero failed_task_count for audit visibility.
    pub fn complete(
        &self,
        event_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<IdentityEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !legal_transition(e.stage, EventStage::Completed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Completed",
                e.stage
            )));
        }
        if e.pending_task_count() > 0 {
            return Err(SandboxError::Other(format!(
                "cannot complete {event_id}: {} tasks still unresolved",
                e.pending_task_count()
            )));
        }
        let when = at.into();
        e.stage = EventStage::Completed;
        e.closed_at = Some(when);
        Ok(e.clone())
    }

    /// Cancel a non-terminal event.
    pub fn cancel(
        &self,
        event_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<IdentityEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !legal_transition(e.stage, EventStage::Cancelled) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Cancelled",
                e.stage
            )));
        }
        let when = at.into();
        e.stage = EventStage::Cancelled;
        e.closed_at = Some(when);
        Ok(e.clone())
    }

    /// Set the effective date.
    pub fn set_effective(&self, event_id: &str, at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        e.effective_at = Some(at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, event_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("identity lifecycle registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        let tag = tag.into();
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, event_id: &str) -> Option<IdentityEvent> {
        let g = self.inner.read().ok()?;
        g.get(event_id).cloned()
    }

    /// All events.
    pub fn all(&self) -> Vec<IdentityEvent> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Events for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<IdentityEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    /// Events for a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<IdentityEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.subject_id == subject_id)
            .collect()
    }

    /// Events of a kind.
    pub fn by_kind(&self, kind: EventKind) -> Vec<IdentityEvent> {
        self.all().into_iter().filter(|e| e.kind == kind).collect()
    }

    /// Events at a stage.
    pub fn by_stage(&self, stage: EventStage) -> Vec<IdentityEvent> {
        self.all().into_iter().filter(|e| e.stage == stage).collect()
    }

    /// Open events (not terminal).
    pub fn open_events(&self) -> Vec<IdentityEvent> {
        self.all()
            .into_iter()
            .filter(|e| !e.stage.is_terminal())
            .collect()
    }

    /// Open events past their effective date at `now` (urgent backlog).
    pub fn overdue(&self, now: &str) -> Vec<IdentityEvent> {
        self.all().into_iter().filter(|e| e.is_overdue(now)).collect()
    }

    /// Events that closed with at least one failed task.
    pub fn closed_with_failures(&self) -> Vec<IdentityEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.stage.is_terminal() && e.failed_task_count() > 0)
            .collect()
    }

    /// Number of registered events.
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

    fn ev(id: &str, kind: EventKind) -> IdentityEvent {
        IdentityEvent::new(
            id,
            "tenant-a",
            format!("subject-{id}"),
            format!("Name {id}"),
            kind,
            "iam-team",
            "hr",
            "2025-05-08T00:00:00Z",
        )
    }

    fn task(id: &str, kind: TaskKind, target: &str) -> ProvisioningTask {
        ProvisioningTask::new(id, kind, target, "iam-team")
    }

    #[test]
    fn open_and_get() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        assert!(r.get("e1").is_some());
    }

    #[test]
    fn duplicate_open_errors() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        let err = r.open(ev("e1", EventKind::Joiner)).unwrap_err();
        assert!(format!("{err}").contains("already opened"));
    }

    #[test]
    fn must_start_requested() {
        let mut e = ev("e1", EventKind::Joiner);
        e.stage = EventStage::Completed;
        let r = IdentityLifecycleRegistry::new();
        let err = r.open(e).unwrap_err();
        assert!(format!("{err}").contains("must start Requested"));
    }

    #[test]
    fn add_task_to_requested() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        assert_eq!(r.get("e1").unwrap().tasks.len(), 1);
    }

    #[test]
    fn add_task_dedupes_id() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        let err = r
            .add_task("e1", task("t1", TaskKind::AssignRole, "okta"))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_task_after_started_errors() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        let err = r
            .add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add task"));
    }

    #[test]
    fn legal_transitions() {
        use EventStage::*;
        assert!(legal_transition(Requested, InProgress));
        assert!(legal_transition(Requested, Cancelled));
        assert!(legal_transition(InProgress, Completed));
        assert!(legal_transition(InProgress, Cancelled));
        // illegal
        assert!(!legal_transition(Requested, Completed));
        assert!(!legal_transition(Completed, InProgress));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        r.add_task("e1", task("t2", TaskKind::AssignRole, "engineer"))
            .unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Completed,
            "2025-05-08T01:30:00Z",
            None,
        )
        .unwrap();
        r.set_task_status(
            "e1",
            "t2",
            TaskStatus::Completed,
            "2025-05-08T01:35:00Z",
            None,
        )
        .unwrap();
        let e = r.complete("e1", "2025-05-08T02:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Completed);
        assert_eq!(e.closed_at.as_deref(), Some("2025-05-08T02:00:00Z"));
        assert_eq!(e.pending_task_count(), 0);
    }

    #[test]
    fn complete_rejects_pending_tasks() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        let err = r.complete("e1", "2025-05-08T02:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("tasks still unresolved"));
    }

    #[test]
    fn complete_with_failed_tasks_succeeds() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Termination)).unwrap();
        r.add_task("e1", task("t1", TaskKind::DisableAccount, "okta"))
            .unwrap();
        r.add_task("e1", task("t2", TaskKind::ReclaimCredential, "laptop"))
            .unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Completed,
            "2025-05-08T01:05:00Z",
            None,
        )
        .unwrap();
        r.set_task_status(
            "e1",
            "t2",
            TaskStatus::Failed,
            "2025-05-08T01:10:00Z",
            Some("laptop not returned".into()),
        )
        .unwrap();
        let e = r.complete("e1", "2025-05-08T02:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Completed);
        assert_eq!(e.failed_task_count(), 1);
    }

    #[test]
    fn skipped_tasks_are_resolved() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::IssueCredential, "yubikey"))
            .unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Skipped,
            "2025-05-08T01:30:00Z",
            Some("subject already has yubikey".into()),
        )
        .unwrap();
        let e = r.complete("e1", "2025-05-08T02:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Completed);
    }

    #[test]
    fn cancel_works_from_pending_or_in_progress() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        let e = r.cancel("e1", "2025-05-08T01:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Cancelled);
        let mut other = ev("e2", EventKind::Joiner);
        other.event_id = "e2".into();
        r.open(other).unwrap();
        r.start("e2", "2025-05-08T01:00:00Z").unwrap();
        let e = r.cancel("e2", "2025-05-08T02:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Cancelled);
    }

    #[test]
    fn set_task_status_when_not_in_progress_errors() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_task("e1", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        let err = r
            .set_task_status(
                "e1",
                "t1",
                TaskStatus::Completed,
                "2025-05-08T01:30:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot update task"));
    }

    #[test]
    fn set_task_status_unknown_task_errors() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        let err = r
            .set_task_status(
                "e1",
                "nope",
                TaskStatus::Completed,
                "2025-05-08T01:30:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown task"));
    }

    #[test]
    fn set_effective_overdue_query() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Termination)).unwrap();
        r.set_effective("e1", "2025-05-08T17:00:00Z").unwrap();
        // After effective date and not closed → overdue
        assert_eq!(r.overdue("2025-05-08T18:00:00Z").len(), 1);
        r.cancel("e1", "2025-05-08T17:30:00Z").unwrap();
        assert_eq!(r.overdue("2025-05-08T18:00:00Z").len(), 0);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.add_tag("e1", "engineering").unwrap();
        r.add_tag("e1", "engineering").unwrap();
        r.add_tag("e1", "starter-kit").unwrap();
        assert_eq!(
            r.get("e1").unwrap().tags,
            vec!["engineering", "starter-kit"]
        );
    }

    #[test]
    fn unknown_event_errors() {
        let r = IdentityLifecycleRegistry::new();
        let err = r.set_effective("nope", "2025-05-08T17:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown event"));
    }

    #[test]
    fn for_tenant_for_subject_filters() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        let mut other = ev("e2", EventKind::Joiner);
        other.tenant_id = "tenant-b".into();
        other.subject_id = "subject-other".into();
        r.open(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_subject("subject-e1").len(), 1);
        assert_eq!(r.for_subject("subject-other").len(), 1);
    }

    #[test]
    fn by_kind_by_stage_filters() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.open(ev("e2", EventKind::Termination)).unwrap();
        assert_eq!(r.by_kind(EventKind::Joiner).len(), 1);
        assert_eq!(r.by_kind(EventKind::Termination).len(), 1);
        assert_eq!(r.by_stage(EventStage::Requested).len(), 2);
    }

    #[test]
    fn open_filter() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        r.open(ev("e2", EventKind::Joiner)).unwrap();
        r.cancel("e2", "2025-05-08T01:00:00Z").unwrap();
        let open = r.open_events();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].event_id, "e1");
    }

    #[test]
    fn closed_with_failures_query() {
        let r = IdentityLifecycleRegistry::new();
        r.open(ev("e1", EventKind::Termination)).unwrap();
        r.add_task("e1", task("t1", TaskKind::DisableAccount, "okta"))
            .unwrap();
        r.add_task("e1", task("t2", TaskKind::ReclaimCredential, "laptop"))
            .unwrap();
        r.start("e1", "2025-05-08T01:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Completed,
            "2025-05-08T01:05:00Z",
            None,
        )
        .unwrap();
        r.set_task_status(
            "e1",
            "t2",
            TaskStatus::Failed,
            "2025-05-08T01:10:00Z",
            None,
        )
        .unwrap();
        r.complete("e1", "2025-05-08T02:00:00Z").unwrap();
        // e2: clean
        r.open(ev("e2", EventKind::Joiner)).unwrap();
        r.add_task("e2", task("t1", TaskKind::CreateAccount, "okta"))
            .unwrap();
        r.start("e2", "2025-05-08T01:00:00Z").unwrap();
        r.set_task_status(
            "e2",
            "t1",
            TaskStatus::Completed,
            "2025-05-08T01:30:00Z",
            None,
        )
        .unwrap();
        r.complete("e2", "2025-05-08T02:00:00Z").unwrap();
        let f = r.closed_with_failures();
        let ids: Vec<_> = f.iter().map(|e| e.event_id.clone()).collect();
        assert_eq!(ids, vec!["e1"]);
    }

    #[test]
    fn kind_urgent_helpers() {
        assert!(EventKind::Termination.is_urgent());
        assert!(EventKind::Leaver.is_urgent());
        assert!(EventKind::Loa.is_urgent());
        assert!(!EventKind::Joiner.is_urgent());
        assert!(!EventKind::Mover.is_urgent());
    }

    #[test]
    fn task_resolved_helpers() {
        assert!(TaskStatus::Completed.is_resolved());
        assert!(TaskStatus::Failed.is_resolved());
        assert!(TaskStatus::Skipped.is_resolved());
        assert!(!TaskStatus::Pending.is_resolved());
        assert!(!TaskStatus::InProgress.is_resolved());
    }

    #[test]
    fn count_tracks() {
        let r = IdentityLifecycleRegistry::new();
        assert_eq!(r.count(), 0);
        r.open(ev("e1", EventKind::Joiner)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn event_serde() {
        let e = ev("e1", EventKind::Joiner);
        let j = serde_json::to_string(&e).unwrap();
        let back: IdentityEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn task_serde() {
        let t = task("t1", TaskKind::CreateAccount, "okta");
        let j = serde_json::to_string(&t).unwrap();
        let back: ProvisioningTask = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            EventKind::Joiner,
            EventKind::Mover,
            EventKind::Transfer,
            EventKind::Leaver,
            EventKind::Termination,
            EventKind::ContractEnd,
            EventKind::Loa,
            EventKind::LoaReturn,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<EventKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            EventStage::Requested,
            EventStage::InProgress,
            EventStage::Completed,
            EventStage::Cancelled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<EventStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for tk in [
            TaskKind::CreateAccount,
            TaskKind::DisableAccount,
            TaskKind::DeleteAccount,
            TaskKind::EnableAccount,
            TaskKind::AssignRole,
            TaskKind::RemoveRole,
            TaskKind::GrantPermission,
            TaskKind::RevokePermission,
            TaskKind::IssueCredential,
            TaskKind::ReclaimCredential,
            TaskKind::Notify,
        ] {
            assert_eq!(
                tk,
                serde_json::from_str::<TaskKind>(&serde_json::to_string(&tk).unwrap()).unwrap()
            );
        }
        for ts in [
            TaskStatus::Pending,
            TaskStatus::InProgress,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Skipped,
        ] {
            assert_eq!(
                ts,
                serde_json::from_str::<TaskStatus>(&serde_json::to_string(&ts).unwrap()).unwrap()
            );
        }
    }
}
