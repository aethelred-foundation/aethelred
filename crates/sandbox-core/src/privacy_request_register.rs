//! Privacy-rights request register — DSAR / right-to-know / right-to-delete.
//!
//! Maps to **GDPR Articles 15-22**, **CCPA / CPRA** subject rights, **HIPAA**
//! patient access requests, and Indian DPDPA. Whenever a data subject
//! exercises a privacy right (access, deletion, rectification, portability,
//! restriction, objection, automated-decision review), the controller has a
//! **statutory deadline** to respond — typically 30 calendar days under
//! GDPR with a possible 60-day extension.
//!
//! This registry is the system of record for the request lifecycle:
//!
//! `Received → Verified → InProgress → Fulfilled | Rejected | Withdrawn`
//!
//! Each request carries a deadline; the registry can return all requests
//! that are **due-soon** (within N days of deadline) or **overdue** so
//! ops dashboards can surface them.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// PrivacyRightKind
// =============================================================================

/// Kind of privacy right exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRightKind {
    /// GDPR Art 15 / CCPA right-to-know — copy of personal data.
    Access,
    /// GDPR Art 16 — correct inaccurate data.
    Rectification,
    /// GDPR Art 17 / CCPA right-to-delete.
    Erasure,
    /// GDPR Art 18 — restrict processing.
    Restriction,
    /// GDPR Art 20 — portability (machine-readable export).
    Portability,
    /// GDPR Art 21 — object to processing (incl. opt-out of profiling).
    Objection,
    /// GDPR Art 22 — review of automated decision-making.
    AutomatedDecisionReview,
    /// CCPA right-to-opt-out of sale or sharing.
    OptOut,
}

// =============================================================================
// RequestStage
// =============================================================================

/// Lifecycle stage of a privacy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStage {
    /// Request received; identity not yet verified.
    Received,
    /// Subject identity verified; awaiting handling.
    Verified,
    /// Identity verification failed — closed.
    VerificationFailed,
    /// Handling underway.
    InProgress,
    /// Completed; deliverable issued or action performed.
    Fulfilled,
    /// Lawful basis to refuse (e.g., manifestly unfounded).
    Rejected,
    /// Subject withdrew the request.
    Withdrawn,
}

impl RequestStage {
    /// True if no further action is expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Fulfilled | Self::Rejected | Self::Withdrawn | Self::VerificationFailed
        )
    }
}

// =============================================================================
// SubjectKind
// =============================================================================

/// Kind of data subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// End-user (consumer / customer).
    Consumer,
    /// Employee.
    Employee,
    /// Patient (HIPAA).
    Patient,
    /// Authorised agent acting on behalf of a subject.
    Agent,
}

// =============================================================================
// RequestEvent
// =============================================================================

/// One event on the request timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestEvent {
    /// RFC 3339.
    pub at: String,
    /// Operator / system actor.
    pub actor: String,
    /// Stage applied.
    pub stage: RequestStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// PrivacyRequest
// =============================================================================

/// One privacy-rights request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivacyRequest {
    /// Unique id.
    pub request_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Subject id (opaque).
    pub subject_id: String,
    /// Subject kind.
    pub subject_kind: SubjectKind,
    /// Right being exercised.
    pub right: PrivacyRightKind,
    /// Current stage.
    pub stage: RequestStage,
    /// RFC 3339 — request received.
    pub received_at: String,
    /// RFC 3339 — statutory deadline.
    pub deadline_at: String,
    /// RFC 3339 — terminal date (when fulfilled / rejected / etc.).
    pub closed_at: Option<String>,
    /// Free-text reason (if rejected).
    pub close_reason: Option<String>,
    /// Operator handling the request.
    pub assignee: Option<String>,
    /// Channel through which the request arrived ("email", "portal",
    /// "letter", "phone").
    pub channel: String,
    /// Verification method ("kba", "id_check", "mfa_login").
    pub verification_method: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Event timeline.
    pub events: Vec<RequestEvent>,
}

impl PrivacyRequest {
    /// New `Received` request.
    pub fn new(
        request_id: impl Into<String>,
        tenant_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_kind: SubjectKind,
        right: PrivacyRightKind,
        channel: impl Into<String>,
        received_at: impl Into<String>,
        deadline_at: impl Into<String>,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            tenant_id: tenant_id.into(),
            subject_id: subject_id.into(),
            subject_kind,
            right,
            stage: RequestStage::Received,
            received_at: received_at.into(),
            deadline_at: deadline_at.into(),
            closed_at: None,
            close_reason: None,
            assignee: None,
            channel: channel.into(),
            verification_method: None,
            tags: Vec::new(),
            events: Vec::new(),
        }
    }

    /// True if `now >= deadline_at`.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        now >= self.deadline_at.as_str()
    }

    /// True if 0 ≤ days_until_deadline ≤ `days`.
    pub fn is_due_within(&self, now: &str, days: u64) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match days_until(now, &self.deadline_at) {
            Some(d) => d >= 0 && d <= days as i64,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RequestStage, to: RequestStage) -> bool {
    use RequestStage::*;
    match (from, to) {
        (Received, Verified)
        | (Received, VerificationFailed)
        | (Received, Withdrawn)
        | (Verified, InProgress)
        | (Verified, Withdrawn)
        | (Verified, Rejected)
        | (InProgress, Fulfilled)
        | (InProgress, Rejected)
        | (InProgress, Withdrawn) => true,
        _ => false,
    }
}

// =============================================================================
// PrivacyRequestRegister
// =============================================================================

/// Thread-safe register of privacy-rights requests.
#[derive(Debug, Default)]
pub struct PrivacyRequestRegister {
    inner: RwLock<HashMap<String, PrivacyRequest>>,
}

impl PrivacyRequestRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new request. Errors on duplicate id.
    pub fn open(&self, req: PrivacyRequest) -> SandboxResult<()> {
        if !matches!(req.stage, RequestStage::Received) {
            return Err(SandboxError::Other(format!(
                "request must start Received, got {:?}",
                req.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privacy register poisoned".into()))?;
        if g.contains_key(&req.request_id) {
            return Err(SandboxError::Other(format!(
                "request already registered: {}",
                req.request_id
            )));
        }
        g.insert(req.request_id.clone(), req);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        request_id: &str,
        new_stage: RequestStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<PrivacyRequest> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privacy register poisoned".into()))?;
        let r = g
            .get_mut(request_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown request {request_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        r.stage = new_stage;
        r.events.push(RequestEvent {
            at: when.clone(),
            actor,
            stage: new_stage,
            note: note.clone(),
        });
        if new_stage.is_terminal() {
            r.closed_at = Some(when);
            r.close_reason = Some(note);
        }
        Ok(r.clone())
    }

    /// Assign the request to an operator.
    pub fn assign(&self, request_id: &str, assignee: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privacy register poisoned".into()))?;
        let r = g
            .get_mut(request_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown request {request_id}")))?;
        r.assignee = Some(assignee.into());
        Ok(())
    }

    /// Set the verification method (typically used between Received and
    /// Verified).
    pub fn set_verification(
        &self,
        request_id: &str,
        method: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privacy register poisoned".into()))?;
        let r = g
            .get_mut(request_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown request {request_id}")))?;
        r.verification_method = Some(method.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, request_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privacy register poisoned".into()))?;
        let r = g
            .get_mut(request_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown request {request_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, request_id: &str) -> Option<PrivacyRequest> {
        let g = self.inner.read().ok()?;
        g.get(request_id).cloned()
    }

    /// All requests.
    pub fn all(&self) -> Vec<PrivacyRequest> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Requests for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<PrivacyRequest> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Requests for a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<PrivacyRequest> {
        self.all()
            .into_iter()
            .filter(|r| r.subject_id == subject_id)
            .collect()
    }

    /// Requests at a stage.
    pub fn by_stage(&self, stage: RequestStage) -> Vec<PrivacyRequest> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Requests of a kind.
    pub fn by_right(&self, right: PrivacyRightKind) -> Vec<PrivacyRequest> {
        self.all().into_iter().filter(|r| r.right == right).collect()
    }

    /// Open requests overdue at `now`.
    pub fn overdue(&self, now: &str) -> Vec<PrivacyRequest> {
        self.all().into_iter().filter(|r| r.is_overdue(now)).collect()
    }

    /// Open requests with deadline within `days` of `now`.
    pub fn due_within(&self, now: &str, days: u64) -> Vec<PrivacyRequest> {
        self.all()
            .into_iter()
            .filter(|r| r.is_due_within(now, days))
            .collect()
    }

    /// Count.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn days_until(now_rfc3339: &str, deadline_rfc3339: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::parse(now_rfc3339, &Rfc3339).ok()?;
    let dl = time::OffsetDateTime::parse(deadline_rfc3339, &Rfc3339).ok()?;
    Some((dl - now).whole_days())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str, right: PrivacyRightKind) -> PrivacyRequest {
        PrivacyRequest::new(
            id,
            "tenant-a",
            "subject-1",
            SubjectKind::Consumer,
            right,
            "portal",
            "2025-05-01T00:00:00Z",
            "2025-05-31T00:00:00Z",
        )
    }

    #[test]
    fn open_creates_received() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        let q = r.get("a").unwrap();
        assert_eq!(q.stage, RequestStage::Received);
    }

    #[test]
    fn duplicate_open_errors() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        let err = r.open(req("a", PrivacyRightKind::Access)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_received() {
        let mut q = req("a", PrivacyRightKind::Access);
        q.stage = RequestStage::InProgress;
        let r = PrivacyRequestRegister::new();
        let err = r.open(q).unwrap_err();
        assert!(format!("{err}").contains("must start Received"));
    }

    #[test]
    fn legal_transitions_table() {
        use RequestStage::*;
        assert!(legal_transition(Received, Verified));
        assert!(legal_transition(Received, VerificationFailed));
        assert!(legal_transition(Received, Withdrawn));
        assert!(legal_transition(Verified, InProgress));
        assert!(legal_transition(Verified, Rejected));
        assert!(legal_transition(InProgress, Fulfilled));
        assert!(legal_transition(InProgress, Withdrawn));
        // illegal
        assert!(!legal_transition(Received, InProgress));
        assert!(!legal_transition(Received, Fulfilled));
        assert!(!legal_transition(Fulfilled, Verified));
        assert!(!legal_transition(VerificationFailed, Verified));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.transition(
            "a",
            RequestStage::Verified,
            "ops",
            "kba passed",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "a",
            RequestStage::InProgress,
            "ops",
            "fetching data",
            "2025-05-03T00:00:00Z",
        )
        .unwrap();
        let q = r
            .transition(
                "a",
                RequestStage::Fulfilled,
                "ops",
                "exported",
                "2025-05-15T00:00:00Z",
            )
            .unwrap();
        assert_eq!(q.stage, RequestStage::Fulfilled);
        assert_eq!(q.closed_at.as_deref(), Some("2025-05-15T00:00:00Z"));
        assert_eq!(q.events.len(), 3);
    }

    #[test]
    fn rejection_carries_reason() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.transition(
            "a",
            RequestStage::Verified,
            "ops",
            "ok",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        let q = r
            .transition(
                "a",
                RequestStage::Rejected,
                "dpo",
                "manifestly unfounded",
                "2025-05-03T00:00:00Z",
            )
            .unwrap();
        assert_eq!(q.close_reason.as_deref(), Some("manifestly unfounded"));
    }

    #[test]
    fn illegal_transition_errors() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        let err = r
            .transition(
                "a",
                RequestStage::Fulfilled,
                "ops",
                "skip",
                "2025-05-02T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn assign_and_verification() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Erasure)).unwrap();
        r.assign("a", "alice").unwrap();
        r.set_verification("a", "kba").unwrap();
        let q = r.get("a").unwrap();
        assert_eq!(q.assignee.as_deref(), Some("alice"));
        assert_eq!(q.verification_method.as_deref(), Some("kba"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.add_tag("a", "vip").unwrap();
        r.add_tag("a", "vip").unwrap();
        r.add_tag("a", "regulator").unwrap();
        assert_eq!(r.get("a").unwrap().tags, vec!["vip", "regulator"]);
    }

    #[test]
    fn unknown_request_errors() {
        let r = PrivacyRequestRegister::new();
        let err = r.assign("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown request"));
    }

    #[test]
    fn for_tenant_for_subject_filters() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        let mut other = req("b", PrivacyRightKind::Erasure);
        other.tenant_id = "tenant-b".into();
        other.subject_id = "subject-9".into();
        r.open(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_subject("subject-1").len(), 1);
        assert_eq!(r.for_subject("subject-9").len(), 1);
    }

    #[test]
    fn by_stage_by_right_filters() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.open(req("b", PrivacyRightKind::Erasure)).unwrap();
        assert_eq!(r.by_stage(RequestStage::Received).len(), 2);
        assert_eq!(r.by_right(PrivacyRightKind::Access).len(), 1);
        assert_eq!(r.by_right(PrivacyRightKind::Erasure).len(), 1);
    }

    #[test]
    fn overdue_only_open() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        // a is open with deadline 2025-05-31; ask after that
        assert_eq!(r.overdue("2025-06-01T00:00:00Z").len(), 1);
        // close it
        r.transition(
            "a",
            RequestStage::Verified,
            "x",
            "n",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "a",
            RequestStage::InProgress,
            "x",
            "n",
            "2025-05-03T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "a",
            RequestStage::Fulfilled,
            "x",
            "n",
            "2025-05-04T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.overdue("2025-06-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn due_within_window() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        // deadline 2025-05-31; check 2025-05-29 with window 5d
        assert_eq!(r.due_within("2025-05-29T00:00:00Z", 5).len(), 1);
        assert_eq!(r.due_within("2025-04-15T00:00:00Z", 5).len(), 0);
    }

    #[test]
    fn due_within_excludes_terminal() {
        let r = PrivacyRequestRegister::new();
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.transition(
            "a",
            RequestStage::Withdrawn,
            "x",
            "n",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.due_within("2025-05-29T00:00:00Z", 5).len(), 0);
    }

    #[test]
    fn stage_terminal_helpers() {
        for s in [
            RequestStage::Fulfilled,
            RequestStage::Rejected,
            RequestStage::Withdrawn,
            RequestStage::VerificationFailed,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            RequestStage::Received,
            RequestStage::Verified,
            RequestStage::InProgress,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = PrivacyRequestRegister::new();
        assert_eq!(r.count(), 0);
        r.open(req("a", PrivacyRightKind::Access)).unwrap();
        r.open(req("b", PrivacyRightKind::Erasure)).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn request_serde() {
        let q = req("a", PrivacyRightKind::Access);
        let j = serde_json::to_string(&q).unwrap();
        let back: PrivacyRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn enums_serde() {
        for r in [
            PrivacyRightKind::Access,
            PrivacyRightKind::Rectification,
            PrivacyRightKind::Erasure,
            PrivacyRightKind::Restriction,
            PrivacyRightKind::Portability,
            PrivacyRightKind::Objection,
            PrivacyRightKind::AutomatedDecisionReview,
            PrivacyRightKind::OptOut,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<PrivacyRightKind>(&serde_json::to_string(&r).unwrap())
                    .unwrap()
            );
        }
        for s in [
            RequestStage::Received,
            RequestStage::Verified,
            RequestStage::VerificationFailed,
            RequestStage::InProgress,
            RequestStage::Fulfilled,
            RequestStage::Rejected,
            RequestStage::Withdrawn,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RequestStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for k in [
            SubjectKind::Consumer,
            SubjectKind::Employee,
            SubjectKind::Patient,
            SubjectKind::Agent,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<SubjectKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
    }
}
