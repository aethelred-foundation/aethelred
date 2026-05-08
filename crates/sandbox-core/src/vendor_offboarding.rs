//! Structured vendor offboarding workflow.
//!
//! Maps to **GDPR Art 28(3)(g)** (return / deletion of personal data on
//! end of services), **HIPAA §164.504(e)(2)(ii)(I)** (return or destruction
//! of PHI), **SOC 2 CC9.2** (vendor offboarding), and **ISO 27001 A.15.2.1**
//! (monitoring and review of supplier services).
//!
//! ## Why a dedicated module?
//!
//! Onboarding gets the attention; offboarding is the one auditors actually
//! examine. "Did the vendor return or destroy our data? Was access
//! revoked? Were credentials reclaimed?" — every offboarding event must
//! produce a documented **completion certificate** answering each of
//! those questions.
//!
//! ## Lifecycle
//!
//! `Initiated → InProgress → Completed | Cancelled`
//!
//! Each event has structured **tasks**: revoke access, return data,
//! confirm destruction, terminate contract, etc. Tasks have their own
//! lifecycle (Pending / InProgress / Completed / Failed / Skipped). The
//! event cannot move to Completed unless every task is resolved.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// EventStage
// =============================================================================

/// Lifecycle stage of an offboarding event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStage {
    /// Initiated; tasks being scoped.
    Initiated,
    /// Tasks underway.
    InProgress,
    /// All tasks resolved; certificate issued.
    Completed,
    /// Cancelled before completion.
    Cancelled,
}

impl EventStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

// =============================================================================
// OffboardingTrigger
// =============================================================================

/// Reason the offboarding was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OffboardingTrigger {
    /// Contract reached end of term.
    ContractEnd,
    /// Vendor replaced by alternative provider.
    Replacement,
    /// Cost reduction.
    CostReduction,
    /// Vendor failed audit.
    AuditFailure,
    /// Vendor security breach / incident.
    SecurityIncident,
    /// Mergers / restructuring.
    Restructuring,
    /// Regulator-mandated.
    Regulatory,
    /// Other.
    Other,
}

// =============================================================================
// TaskKind
// =============================================================================

/// Kind of offboarding task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    /// Revoke vendor's access to our systems.
    RevokeAccess,
    /// Reclaim credentials issued to the vendor.
    ReclaimCredentials,
    /// Vendor must return our data.
    ReturnData,
    /// Vendor must destroy / shred remaining copies.
    ConfirmDataDestruction,
    /// Confirm subprocessors also destroyed copies.
    ConfirmSubprocessorDestruction,
    /// Final invoice settlement.
    SettleFinalInvoice,
    /// Terminate / close out the contract.
    TerminateContract,
    /// Update DPA / subprocessor list.
    UpdateRegisters,
    /// Knowledge transfer to replacement vendor / internal team.
    KnowledgeTransfer,
    /// Notify customers (when vendor was a subprocessor).
    NotifyCustomers,
    /// Other.
    Other,
}

// =============================================================================
// TaskStatus
// =============================================================================

/// Per-task status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Not started.
    Pending,
    /// Underway.
    InProgress,
    /// Completed.
    Completed,
    /// Failed; needs intervention.
    Failed,
    /// Skipped (not applicable).
    Skipped,
}

impl TaskStatus {
    /// True if no further work expected.
    pub fn is_resolved(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Skipped)
    }
}

// =============================================================================
// OffboardingTask
// =============================================================================

/// One task within an offboarding event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OffboardingTask {
    /// Stable id within the event.
    pub task_id: String,
    /// Kind.
    pub kind: TaskKind,
    /// Description.
    pub description: String,
    /// Owner.
    pub owner: String,
    /// Status.
    pub status: TaskStatus,
    /// Optional evidence URI (e.g., destruction certificate, log).
    pub evidence_uri: Option<String>,
    /// RFC 3339 — last status update.
    pub updated_at: Option<String>,
    /// Optional note (failure reason, completion summary).
    pub note: Option<String>,
}

impl OffboardingTask {
    /// New `Pending` task.
    pub fn new(
        task_id: impl Into<String>,
        kind: TaskKind,
        description: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            kind,
            description: description.into(),
            owner: owner.into(),
            status: TaskStatus::Pending,
            evidence_uri: None,
            updated_at: None,
            note: None,
        }
    }
}

// =============================================================================
// CompletionCertificate
// =============================================================================

/// Issued when an offboarding event reaches Completed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletionCertificate {
    /// RFC 3339 — issued.
    pub issued_at: String,
    /// Operator who certified the offboarding.
    pub certified_by: String,
    /// Free-text summary.
    pub summary: String,
    /// Optional storage URI for the certificate document.
    pub document_uri: Option<String>,
    /// SHA-256 of the document.
    pub document_sha256: Option<String>,
}

// =============================================================================
// VendorOffboardingEvent
// =============================================================================

/// One vendor-offboarding event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VendorOffboardingEvent {
    /// Unique id (e.g., "VOFF-2025-007").
    pub event_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Linked vendor id.
    pub vendor_id: String,
    /// Vendor name.
    pub vendor_name: String,
    /// Display title.
    pub title: String,
    /// Owner / programme manager.
    pub owner: String,
    /// Trigger.
    pub trigger: OffboardingTrigger,
    /// Tasks.
    pub tasks: Vec<OffboardingTask>,
    /// Stage.
    pub stage: EventStage,
    /// RFC 3339 — initiated.
    pub initiated_at: String,
    /// RFC 3339 — target completion deadline.
    pub deadline_at: Option<String>,
    /// RFC 3339 — actually completed (terminal).
    pub closed_at: Option<String>,
    /// Completion certificate (set on Completed).
    pub certificate: Option<CompletionCertificate>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl VendorOffboardingEvent {
    /// New `Initiated` event.
    pub fn new(
        event_id: impl Into<String>,
        tenant_id: impl Into<String>,
        vendor_id: impl Into<String>,
        vendor_name: impl Into<String>,
        title: impl Into<String>,
        owner: impl Into<String>,
        trigger: OffboardingTrigger,
        initiated_at: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            tenant_id: tenant_id.into(),
            vendor_id: vendor_id.into(),
            vendor_name: vendor_name.into(),
            title: title.into(),
            owner: owner.into(),
            trigger,
            tasks: Vec::new(),
            stage: EventStage::Initiated,
            initiated_at: initiated_at.into(),
            deadline_at: None,
            closed_at: None,
            certificate: None,
            tags: Vec::new(),
        }
    }

    /// Number of unresolved tasks.
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

    /// True if `now >= deadline_at` and event is non-terminal.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match self.deadline_at.as_deref() {
            Some(d) => now >= d,
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
        (Initiated, InProgress)
            | (Initiated, Cancelled)
            | (InProgress, Completed)
            | (InProgress, Cancelled)
    )
}

// =============================================================================
// VendorOffboardingRegistry
// =============================================================================

/// Thread-safe registry of vendor-offboarding events.
#[derive(Debug, Default)]
pub struct VendorOffboardingRegistry {
    inner: RwLock<HashMap<String, VendorOffboardingEvent>>,
}

impl VendorOffboardingRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Initiate a new event.
    pub fn initiate(&self, event: VendorOffboardingEvent) -> SandboxResult<()> {
        if !matches!(event.stage, EventStage::Initiated) {
            return Err(SandboxError::Other(format!(
                "event must start Initiated, got {:?}",
                event.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
        if g.contains_key(&event.event_id) {
            return Err(SandboxError::Other(format!(
                "event already initiated: {}",
                event.event_id
            )));
        }
        g.insert(event.event_id.clone(), event);
        Ok(())
    }

    /// Add a task to an Initiated event.
    pub fn add_task(&self, event_id: &str, task: OffboardingTask) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if !matches!(e.stage, EventStage::Initiated) {
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

    /// Move event to InProgress. Errors if no tasks.
    pub fn start(
        &self,
        event_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<VendorOffboardingEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        if e.tasks.is_empty() {
            return Err(SandboxError::Other(format!(
                "cannot start {event_id}: no tasks"
            )));
        }
        if !legal_transition(e.stage, EventStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> InProgress",
                e.stage
            )));
        }
        let _ = at;
        e.stage = EventStage::InProgress;
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
        evidence_uri: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
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
        if let Some(uri) = evidence_uri {
            t.evidence_uri = Some(uri);
        }
        Ok(())
    }

    /// Complete the event. Issues the completion certificate. All tasks
    /// must be resolved.
    pub fn complete(
        &self,
        event_id: &str,
        at: impl Into<String>,
        certificate: CompletionCertificate,
    ) -> SandboxResult<VendorOffboardingEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
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
        e.certificate = Some(certificate);
        Ok(e.clone())
    }

    /// Cancel a non-terminal event.
    pub fn cancel(
        &self,
        event_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<VendorOffboardingEvent> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
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

    /// Set deadline.
    pub fn set_deadline(&self, event_id: &str, at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
        let e = g
            .get_mut(event_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown event {event_id}")))?;
        e.deadline_at = Some(at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, event_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor offboarding registry poisoned".into()))?;
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
    pub fn get(&self, event_id: &str) -> Option<VendorOffboardingEvent> {
        let g = self.inner.read().ok()?;
        g.get(event_id).cloned()
    }

    /// All events.
    pub fn all(&self) -> Vec<VendorOffboardingEvent> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Events for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<VendorOffboardingEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.tenant_id == tenant_id)
            .collect()
    }

    /// Events for a vendor.
    pub fn for_vendor(&self, vendor_id: &str) -> Vec<VendorOffboardingEvent> {
        self.all()
            .into_iter()
            .filter(|e| e.vendor_id == vendor_id)
            .collect()
    }

    /// Events at a stage.
    pub fn by_stage(&self, stage: EventStage) -> Vec<VendorOffboardingEvent> {
        self.all().into_iter().filter(|e| e.stage == stage).collect()
    }

    /// Open events (not terminal).
    pub fn open(&self) -> Vec<VendorOffboardingEvent> {
        self.all()
            .into_iter()
            .filter(|e| !e.stage.is_terminal())
            .collect()
    }

    /// Open events past their deadline.
    pub fn overdue(&self, now: &str) -> Vec<VendorOffboardingEvent> {
        self.all().into_iter().filter(|e| e.is_overdue(now)).collect()
    }

    /// Completed events that closed with at least one failed task.
    pub fn closed_with_failures(&self) -> Vec<VendorOffboardingEvent> {
        self.all()
            .into_iter()
            .filter(|e| matches!(e.stage, EventStage::Completed) && e.failed_task_count() > 0)
            .collect()
    }

    /// Number of events.
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

    fn evt(id: &str) -> VendorOffboardingEvent {
        VendorOffboardingEvent::new(
            id,
            "tenant-a",
            "VENDOR-007",
            "Acme Corp",
            format!("offboard {id}"),
            "compliance",
            OffboardingTrigger::ContractEnd,
            "2025-04-01T00:00:00Z",
        )
    }

    fn task(id: &str, kind: TaskKind) -> OffboardingTask {
        OffboardingTask::new(id, kind, format!("desc-{id}"), "iam-team")
    }

    fn cert(certifier: &str) -> CompletionCertificate {
        CompletionCertificate {
            issued_at: "2025-05-01T00:00:00Z".into(),
            certified_by: certifier.into(),
            summary: "all data destroyed".into(),
            document_uri: Some("vault://cert/v1".into()),
            document_sha256: Some("abcdef".into()),
        }
    }

    #[test]
    fn initiate_and_get() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        assert!(r.get("e1").is_some());
    }

    #[test]
    fn duplicate_initiate_errors() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        let err = r.initiate(evt("e1")).unwrap_err();
        assert!(format!("{err}").contains("already initiated"));
    }

    #[test]
    fn must_start_initiated() {
        let mut e = evt("e1");
        e.stage = EventStage::InProgress;
        let r = VendorOffboardingRegistry::new();
        let err = r.initiate(e).unwrap_err();
        assert!(format!("{err}").contains("must start Initiated"));
    }

    #[test]
    fn legal_transitions() {
        use EventStage::*;
        assert!(legal_transition(Initiated, InProgress));
        assert!(legal_transition(Initiated, Cancelled));
        assert!(legal_transition(InProgress, Completed));
        assert!(legal_transition(InProgress, Cancelled));
        // illegal
        assert!(!legal_transition(Initiated, Completed));
        assert!(!legal_transition(Completed, InProgress));
    }

    #[test]
    fn add_task_to_initiated() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        assert_eq!(r.get("e1").unwrap().tasks.len(), 1);
    }

    #[test]
    fn add_task_dedupes_id() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        let err = r
            .add_task("e1", task("t1", TaskKind::ReturnData))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_task_after_started_errors() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .add_task("e1", task("t2", TaskKind::ReturnData))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add task"));
    }

    #[test]
    fn start_requires_tasks() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        let err = r.start("e1", "2025-04-02T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("no tasks"));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.add_task(
            "e1",
            task("t2", TaskKind::ConfirmDataDestruction),
        )
        .unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Completed,
            "2025-04-15T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.set_task_status(
            "e1",
            "t2",
            TaskStatus::Completed,
            "2025-04-20T00:00:00Z",
            Some("destruction certificate received".into()),
            Some("vault://destruction/c1".into()),
        )
        .unwrap();
        let e = r
            .complete("e1", "2025-05-01T00:00:00Z", cert("ciso"))
            .unwrap();
        assert_eq!(e.stage, EventStage::Completed);
        assert!(e.stage.is_terminal());
        assert_eq!(e.closed_at.as_deref(), Some("2025-05-01T00:00:00Z"));
        assert!(e.certificate.is_some());
        assert_eq!(e.pending_task_count(), 0);
    }

    #[test]
    fn complete_rejects_pending_tasks() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .complete("e1", "2025-05-01T00:00:00Z", cert("ciso"))
            .unwrap_err();
        assert!(format!("{err}").contains("tasks still unresolved"));
    }

    #[test]
    fn complete_with_failed_tasks_succeeds() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task(
            "e1",
            task("t1", TaskKind::ConfirmSubprocessorDestruction),
        )
        .unwrap();
        r.add_task("e1", task("t2", TaskKind::ReclaimCredentials))
            .unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Failed,
            "2025-04-15T00:00:00Z",
            Some("subprocessor unresponsive".into()),
            None,
        )
        .unwrap();
        r.set_task_status(
            "e1",
            "t2",
            TaskStatus::Completed,
            "2025-04-20T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let e = r
            .complete("e1", "2025-05-01T00:00:00Z", cert("ciso"))
            .unwrap();
        assert_eq!(e.stage, EventStage::Completed);
        assert_eq!(e.failed_task_count(), 1);
    }

    #[test]
    fn skipped_tasks_are_resolved() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::NotifyCustomers))
            .unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Skipped,
            "2025-04-15T00:00:00Z",
            Some("vendor was not a subprocessor".into()),
            None,
        )
        .unwrap();
        let e = r
            .complete("e1", "2025-05-01T00:00:00Z", cert("ciso"))
            .unwrap();
        assert_eq!(e.stage, EventStage::Completed);
    }

    #[test]
    fn cancel_works_from_initiated_or_in_progress() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        let e = r.cancel("e1", "2025-04-15T00:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Cancelled);

        let mut other = evt("e2");
        other.event_id = "e2".into();
        r.initiate(other).unwrap();
        r.add_task("e2", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.start("e2", "2025-04-02T00:00:00Z").unwrap();
        let e = r.cancel("e2", "2025-04-15T00:00:00Z").unwrap();
        assert_eq!(e.stage, EventStage::Cancelled);
    }

    #[test]
    fn cancel_terminal_errors() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.cancel("e1", "2025-04-15T00:00:00Z").unwrap();
        let err = r.cancel("e1", "2025-04-16T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_task_status_when_not_in_progress_errors() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        let err = r
            .set_task_status(
                "e1",
                "t1",
                TaskStatus::Completed,
                "2025-04-15T00:00:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot update task"));
    }

    #[test]
    fn set_task_status_unknown_task_errors() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task("e1", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .set_task_status(
                "e1",
                "nope",
                TaskStatus::Completed,
                "2025-04-15T00:00:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown task"));
    }

    #[test]
    fn deadline_overdue() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.set_deadline("e1", "2025-05-01T00:00:00Z").unwrap();
        assert_eq!(r.overdue("2025-06-01T00:00:00Z").len(), 1);
        r.cancel("e1", "2025-05-15T00:00:00Z").unwrap();
        assert_eq!(r.overdue("2025-06-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_tag("e1", "annual").unwrap();
        r.add_tag("e1", "annual").unwrap();
        r.add_tag("e1", "regulator").unwrap();
        assert_eq!(r.get("e1").unwrap().tags, vec!["annual", "regulator"]);
    }

    #[test]
    fn unknown_event_errors() {
        let r = VendorOffboardingRegistry::new();
        let err = r.set_deadline("nope", "2025-05-01T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown event"));
    }

    #[test]
    fn for_tenant_for_vendor_filters() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        let mut other = evt("e2");
        other.tenant_id = "tenant-b".into();
        other.vendor_id = "VENDOR-008".into();
        r.initiate(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_vendor("VENDOR-007").len(), 1);
        assert_eq!(r.for_vendor("VENDOR-008").len(), 1);
    }

    #[test]
    fn open_filter() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.initiate(evt("e2")).unwrap();
        r.cancel("e2", "2025-04-15T00:00:00Z").unwrap();
        let open = r.open();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].event_id, "e1");
    }

    #[test]
    fn closed_with_failures_query() {
        let r = VendorOffboardingRegistry::new();
        r.initiate(evt("e1")).unwrap();
        r.add_task(
            "e1",
            task("t1", TaskKind::ConfirmSubprocessorDestruction),
        )
        .unwrap();
        r.start("e1", "2025-04-02T00:00:00Z").unwrap();
        r.set_task_status(
            "e1",
            "t1",
            TaskStatus::Failed,
            "2025-04-15T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.complete("e1", "2025-05-01T00:00:00Z", cert("ciso")).unwrap();
        // e2: clean
        r.initiate(evt("e2")).unwrap();
        r.add_task("e2", task("t1", TaskKind::RevokeAccess)).unwrap();
        r.start("e2", "2025-04-02T00:00:00Z").unwrap();
        r.set_task_status(
            "e2",
            "t1",
            TaskStatus::Completed,
            "2025-04-15T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.complete("e2", "2025-05-01T00:00:00Z", cert("ciso")).unwrap();
        let f = r.closed_with_failures();
        let ids: Vec<_> = f.iter().map(|e| e.event_id.clone()).collect();
        assert_eq!(ids, vec!["e1"]);
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
        let r = VendorOffboardingRegistry::new();
        assert_eq!(r.count(), 0);
        r.initiate(evt("e1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn event_serde() {
        let e = evt("e1");
        let j = serde_json::to_string(&e).unwrap();
        let back: VendorOffboardingEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn task_certificate_serde() {
        let t = task("t1", TaskKind::RevokeAccess);
        assert_eq!(
            t,
            serde_json::from_str::<OffboardingTask>(&serde_json::to_string(&t).unwrap()).unwrap()
        );
        let c = cert("ciso");
        assert_eq!(
            c,
            serde_json::from_str::<CompletionCertificate>(&serde_json::to_string(&c).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn enums_serde() {
        for s in [
            EventStage::Initiated,
            EventStage::InProgress,
            EventStage::Completed,
            EventStage::Cancelled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<EventStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for t in [
            OffboardingTrigger::ContractEnd,
            OffboardingTrigger::Replacement,
            OffboardingTrigger::CostReduction,
            OffboardingTrigger::AuditFailure,
            OffboardingTrigger::SecurityIncident,
            OffboardingTrigger::Restructuring,
            OffboardingTrigger::Regulatory,
            OffboardingTrigger::Other,
        ] {
            assert_eq!(
                t,
                serde_json::from_str::<OffboardingTrigger>(&serde_json::to_string(&t).unwrap())
                    .unwrap()
            );
        }
        for k in [
            TaskKind::RevokeAccess,
            TaskKind::ReclaimCredentials,
            TaskKind::ReturnData,
            TaskKind::ConfirmDataDestruction,
            TaskKind::ConfirmSubprocessorDestruction,
            TaskKind::SettleFinalInvoice,
            TaskKind::TerminateContract,
            TaskKind::UpdateRegisters,
            TaskKind::KnowledgeTransfer,
            TaskKind::NotifyCustomers,
            TaskKind::Other,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<TaskKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            TaskStatus::Pending,
            TaskStatus::InProgress,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Skipped,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<TaskStatus>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
