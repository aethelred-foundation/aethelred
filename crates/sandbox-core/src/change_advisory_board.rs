//! Change Advisory Board (CAB) approval workflow.
//!
//! ITIL-style change-management register: each proposed change is filed,
//! reviewed by named voters with weighted votes, and either approved,
//! rejected, or deferred. Composes with [`crate::deployment_pipeline`] (which
//! triggers from approved changes) and [`crate::workspace_audit`] (records
//! the operator action).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ChangeKind
// =============================================================================

/// ITIL change category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Standard (low-risk, pre-approved).
    Standard,
    /// Normal (CAB review required).
    Normal,
    /// Emergency (expedited).
    Emergency,
}

// =============================================================================
// ChangeRiskLevel
// =============================================================================

/// Risk band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRiskLevel {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Critical.
    Critical,
}

// =============================================================================
// ChangeStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeStatus {
    /// Filed, pending review.
    Submitted,
    /// Under review.
    InReview,
    /// Approved.
    Approved,
    /// Rejected.
    Rejected,
    /// Deferred to next CAB cycle.
    Deferred,
    /// Implemented.
    Implemented,
    /// Withdrawn by submitter.
    Withdrawn,
}

// =============================================================================
// CabVote
// =============================================================================

/// One CAB member's vote.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CabVote {
    /// Voter id.
    pub voter: String,
    /// Weight (typically 1, e.g. 2 for chair).
    pub weight: u32,
    /// `true` for approve, `false` for reject.
    pub approve: bool,
    /// Free-text comment.
    pub comment: Option<String>,
    /// RFC 3339 cast at.
    pub cast_at: String,
}

// =============================================================================
// ChangeRequest
// =============================================================================

/// One change request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeRequest {
    /// Stable id.
    pub change_id: Uuid,
    /// Display id (e.g. `"CHG-2026-0001"`).
    pub display_id: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Submitter.
    pub submitter: String,
    /// Affected services.
    pub affected_services: Vec<String>,
    /// Kind.
    pub kind: ChangeKind,
    /// Risk level.
    pub risk: ChangeRiskLevel,
    /// Required quorum (sum of vote weights to pass).
    pub required_quorum: u32,
    /// RFC 3339 scheduled.
    pub scheduled_at: Option<String>,
    /// Rollback plan summary.
    pub rollback_plan: String,
    /// Status.
    pub status: ChangeStatus,
    /// Votes.
    pub votes: Vec<CabVote>,
    /// RFC 3339 filed.
    pub filed_at: String,
    /// RFC 3339 last-updated.
    pub last_updated_at: String,
}

impl ChangeRequest {
    /// Sum of approve weights.
    pub fn approve_weight(&self) -> u32 {
        self.votes
            .iter()
            .filter(|v| v.approve)
            .map(|v| v.weight)
            .sum()
    }
    /// Sum of reject weights.
    pub fn reject_weight(&self) -> u32 {
        self.votes
            .iter()
            .filter(|v| !v.approve)
            .map(|v| v.weight)
            .sum()
    }
    /// `true` if quorum reached.
    pub fn quorum_reached(&self) -> bool {
        self.approve_weight() >= self.required_quorum
    }
}

// =============================================================================
// CabRegistry
// =============================================================================

#[derive(Default)]
struct State {
    changes: HashMap<Uuid, ChangeRequest>,
    seq: HashMap<String, u32>, // year prefix → seq
}

/// Registry.
pub struct CabRegistry {
    state: RwLock<State>,
}

impl Default for CabRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CabRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CabRegistry").field("changes", &self.len()).finish()
    }
}

impl CabRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// File a change.
    pub fn file(
        &self,
        title: impl Into<String>,
        description: impl Into<String>,
        submitter: impl Into<String>,
        kind: ChangeKind,
        risk: ChangeRiskLevel,
        required_quorum: u32,
        affected_services: Vec<String>,
        rollback_plan: impl Into<String>,
    ) -> SandboxResult<ChangeRequest> {
        if required_quorum == 0 {
            return Err(SandboxError::Other("required_quorum must be > 0".into()));
        }
        let now = OffsetDateTime::now_utc();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cab registry poisoned".into()))?;
        let prefix = format!("CHG-{}", now.year());
        let seq = g.seq.entry(prefix.clone()).or_insert(0);
        *seq += 1;
        let display_id = format!("{}-{:04}", prefix, *seq);
        let now_s = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let cr = ChangeRequest {
            change_id: Uuid::now_v7(),
            display_id,
            title: title.into(),
            description: description.into(),
            submitter: submitter.into(),
            affected_services,
            kind,
            risk,
            required_quorum,
            scheduled_at: None,
            rollback_plan: rollback_plan.into(),
            status: ChangeStatus::Submitted,
            votes: Vec::new(),
            filed_at: now_s.clone(),
            last_updated_at: now_s,
        };
        g.changes.insert(cr.change_id, cr.clone());
        Ok(cr)
    }

    /// Move to InReview.
    pub fn open_review(&self, change_id: Uuid) -> SandboxResult<()> {
        self.transition(change_id, ChangeStatus::InReview, &[ChangeStatus::Submitted])
    }

    /// Cast vote.
    pub fn vote(
        &self,
        change_id: Uuid,
        voter: impl Into<String>,
        weight: u32,
        approve: bool,
        comment: Option<String>,
    ) -> SandboxResult<CabVote> {
        let voter = voter.into();
        if weight == 0 {
            return Err(SandboxError::Other("vote weight must be > 0".into()));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cab registry poisoned".into()))?;
        let cr = g
            .changes
            .get_mut(&change_id)
            .ok_or_else(|| SandboxError::Other(format!("change {} not found", change_id)))?;
        if !matches!(cr.status, ChangeStatus::InReview) {
            return Err(SandboxError::Other(format!(
                "cannot vote in state {:?}",
                cr.status
            )));
        }
        if cr.votes.iter().any(|v| v.voter == voter) {
            return Err(SandboxError::Other(format!(
                "voter {} already voted",
                voter
            )));
        }
        let vote = CabVote {
            voter,
            weight,
            approve,
            comment,
            cast_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        cr.votes.push(vote.clone());
        cr.last_updated_at = vote.cast_at.clone();
        Ok(vote)
    }

    /// Approve (must have quorum).
    pub fn approve(&self, change_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cab registry poisoned".into()))?;
        let cr = g
            .changes
            .get_mut(&change_id)
            .ok_or_else(|| SandboxError::Other(format!("change {} not found", change_id)))?;
        if !matches!(cr.status, ChangeStatus::InReview) {
            return Err(SandboxError::Other(format!(
                "cannot approve in state {:?}",
                cr.status
            )));
        }
        if !cr.quorum_reached() {
            return Err(SandboxError::Other(format!(
                "quorum not reached: {} of {}",
                cr.approve_weight(),
                cr.required_quorum
            )));
        }
        cr.status = ChangeStatus::Approved;
        cr.last_updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Reject.
    pub fn reject(&self, change_id: Uuid) -> SandboxResult<()> {
        self.transition(
            change_id,
            ChangeStatus::Rejected,
            &[ChangeStatus::InReview, ChangeStatus::Submitted],
        )
    }

    /// Defer.
    pub fn defer(&self, change_id: Uuid) -> SandboxResult<()> {
        self.transition(
            change_id,
            ChangeStatus::Deferred,
            &[ChangeStatus::InReview, ChangeStatus::Submitted],
        )
    }

    /// Mark implemented.
    pub fn mark_implemented(&self, change_id: Uuid) -> SandboxResult<()> {
        self.transition(change_id, ChangeStatus::Implemented, &[ChangeStatus::Approved])
    }

    /// Withdraw (submitter only).
    pub fn withdraw(&self, change_id: Uuid) -> SandboxResult<()> {
        self.transition(
            change_id,
            ChangeStatus::Withdrawn,
            &[
                ChangeStatus::Submitted,
                ChangeStatus::InReview,
                ChangeStatus::Deferred,
            ],
        )
    }

    /// Set scheduled time.
    pub fn schedule(&self, change_id: Uuid, at: OffsetDateTime) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cab registry poisoned".into()))?;
        let cr = g
            .changes
            .get_mut(&change_id)
            .ok_or_else(|| SandboxError::Other(format!("change {} not found", change_id)))?;
        cr.scheduled_at = Some(
            at.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    fn transition(
        &self,
        change_id: Uuid,
        target: ChangeStatus,
        from_allowed: &[ChangeStatus],
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("cab registry poisoned".into()))?;
        let cr = g
            .changes
            .get_mut(&change_id)
            .ok_or_else(|| SandboxError::Other(format!("change {} not found", change_id)))?;
        if !from_allowed.contains(&cr.status) {
            return Err(SandboxError::Other(format!(
                "illegal transition from {:?}",
                cr.status
            )));
        }
        cr.status = target;
        cr.last_updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<ChangeRequest> {
        self.state.read().ok()?.changes.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ChangeRequest> {
        self.state
            .read()
            .map(|g| g.changes.values().cloned().collect())
            .unwrap_or_default()
    }
    /// By status.
    pub fn by_status(&self, status: ChangeStatus) -> Vec<ChangeRequest> {
        self.all().into_iter().filter(|c| c.status == status).collect()
    }
    /// By risk.
    pub fn by_risk(&self, risk: ChangeRiskLevel) -> Vec<ChangeRequest> {
        self.all().into_iter().filter(|c| c.risk == risk).collect()
    }
    /// Affecting a service.
    pub fn affecting(&self, service: &str) -> Vec<ChangeRequest> {
        self.all()
            .into_iter()
            .filter(|c| c.affected_services.iter().any(|s| s == service))
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.changes.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(reg: &CabRegistry) -> ChangeRequest {
        reg.file(
            "Upgrade HSM firmware",
            "Quarterly HSM firmware update",
            "platform-team",
            ChangeKind::Normal,
            ChangeRiskLevel::High,
            3,
            vec!["hsm".into()],
            "Roll back via vendor recovery USB",
        )
        .unwrap()
    }

    #[test]
    fn file_creates_submitted() {
        let r = CabRegistry::new();
        let c = file(&r);
        assert_eq!(c.status, ChangeStatus::Submitted);
        assert!(c.display_id.starts_with("CHG-"));
    }

    #[test]
    fn zero_quorum_errors() {
        let r = CabRegistry::new();
        assert!(r
            .file(
                "x",
                "y",
                "z",
                ChangeKind::Normal,
                ChangeRiskLevel::Low,
                0,
                vec![],
                ""
            )
            .is_err());
    }

    #[test]
    fn open_review_advances() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        assert_eq!(r.get(c.change_id).unwrap().status, ChangeStatus::InReview);
    }

    #[test]
    fn vote_in_submitted_errors() {
        let r = CabRegistry::new();
        let c = file(&r);
        assert!(r.vote(c.change_id, "alice", 1, true, None).is_err());
    }

    #[test]
    fn vote_records_after_review() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.vote(c.change_id, "alice", 1, true, Some("LGTM".into())).unwrap();
        let cr = r.get(c.change_id).unwrap();
        assert_eq!(cr.votes.len(), 1);
        assert_eq!(cr.approve_weight(), 1);
    }

    #[test]
    fn duplicate_voter_errors() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.vote(c.change_id, "alice", 1, true, None).unwrap();
        assert!(r.vote(c.change_id, "alice", 1, false, None).is_err());
    }

    #[test]
    fn zero_weight_errors() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        assert!(r.vote(c.change_id, "alice", 0, true, None).is_err());
    }

    #[test]
    fn weights_aggregate() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.vote(c.change_id, "alice", 1, true, None).unwrap();
        r.vote(c.change_id, "bob", 1, true, None).unwrap();
        r.vote(c.change_id, "carol", 1, false, None).unwrap();
        let cr = r.get(c.change_id).unwrap();
        assert_eq!(cr.approve_weight(), 2);
        assert_eq!(cr.reject_weight(), 1);
    }

    #[test]
    fn approve_below_quorum_errors() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.vote(c.change_id, "alice", 1, true, None).unwrap();
        assert!(r.approve(c.change_id).is_err());
    }

    #[test]
    fn approve_at_quorum_succeeds() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        for v in ["alice", "bob", "carol"] {
            r.vote(c.change_id, v, 1, true, None).unwrap();
        }
        r.approve(c.change_id).unwrap();
        assert_eq!(r.get(c.change_id).unwrap().status, ChangeStatus::Approved);
    }

    #[test]
    fn weighted_quorum_works() {
        let r = CabRegistry::new();
        let c = r
            .file(
                "x",
                "y",
                "z",
                ChangeKind::Normal,
                ChangeRiskLevel::High,
                4,
                vec![],
                "",
            )
            .unwrap();
        r.open_review(c.change_id).unwrap();
        // Chair has weight 2.
        r.vote(c.change_id, "chair", 2, true, None).unwrap();
        r.vote(c.change_id, "alice", 1, true, None).unwrap();
        // Total = 3, below quorum 4 → can't approve.
        assert!(r.approve(c.change_id).is_err());
        r.vote(c.change_id, "bob", 1, true, None).unwrap();
        // Total = 4, can approve.
        r.approve(c.change_id).unwrap();
    }

    #[test]
    fn reject_blocks_further_state() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.reject(c.change_id).unwrap();
        assert!(r.approve(c.change_id).is_err());
    }

    #[test]
    fn defer_keeps_open_for_relisting() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        r.defer(c.change_id).unwrap();
        assert_eq!(r.get(c.change_id).unwrap().status, ChangeStatus::Deferred);
    }

    #[test]
    fn implement_only_after_approval() {
        let r = CabRegistry::new();
        let c = file(&r);
        assert!(r.mark_implemented(c.change_id).is_err());
    }

    #[test]
    fn withdraw_from_submitted() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.withdraw(c.change_id).unwrap();
        assert_eq!(r.get(c.change_id).unwrap().status, ChangeStatus::Withdrawn);
    }

    #[test]
    fn schedule_records_time() {
        let r = CabRegistry::new();
        let c = file(&r);
        let when = OffsetDateTime::now_utc() + time::Duration::days(7);
        r.schedule(c.change_id, when).unwrap();
        assert!(r.get(c.change_id).unwrap().scheduled_at.is_some());
    }

    #[test]
    fn by_status_filters() {
        let r = CabRegistry::new();
        let c = file(&r);
        r.open_review(c.change_id).unwrap();
        file(&r);
        assert_eq!(r.by_status(ChangeStatus::Submitted).len(), 1);
        assert_eq!(r.by_status(ChangeStatus::InReview).len(), 1);
    }

    #[test]
    fn by_risk_filters() {
        let r = CabRegistry::new();
        file(&r);
        r.file(
            "y",
            "z",
            "a",
            ChangeKind::Standard,
            ChangeRiskLevel::Low,
            1,
            vec![],
            "",
        )
        .unwrap();
        assert_eq!(r.by_risk(ChangeRiskLevel::High).len(), 1);
        assert_eq!(r.by_risk(ChangeRiskLevel::Low).len(), 1);
    }

    #[test]
    fn affecting_filters() {
        let r = CabRegistry::new();
        file(&r);
        assert_eq!(r.affecting("hsm").len(), 1);
        assert!(r.affecting("ghost").is_empty());
    }

    #[test]
    fn change_serde() {
        let r = CabRegistry::new();
        let c = file(&r);
        let j = serde_json::to_string(&c).unwrap();
        let p: ChangeRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn vote_serde() {
        let v = CabVote {
            voter: "x".into(),
            weight: 1,
            approve: true,
            comment: None,
            cast_at: "t".into(),
        };
        let j = serde_json::to_string(&v).unwrap();
        let p: CabVote = serde_json::from_str(&j).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn kind_serde() {
        for k in [
            ChangeKind::Standard,
            ChangeKind::Normal,
            ChangeKind::Emergency,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: ChangeKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            ChangeStatus::Submitted,
            ChangeStatus::InReview,
            ChangeStatus::Approved,
            ChangeStatus::Rejected,
            ChangeStatus::Deferred,
            ChangeStatus::Implemented,
            ChangeStatus::Withdrawn,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ChangeStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn risk_serde() {
        for r in [
            ChangeRiskLevel::Low,
            ChangeRiskLevel::Medium,
            ChangeRiskLevel::High,
            ChangeRiskLevel::Critical,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let p: ChangeRiskLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, r);
        }
    }

    #[test]
    fn count_tracks() {
        let r = CabRegistry::new();
        assert!(r.is_empty());
        file(&r);
        assert_eq!(r.len(), 1);
    }
}
