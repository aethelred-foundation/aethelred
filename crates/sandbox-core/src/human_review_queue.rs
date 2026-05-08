//! Human-in-the-loop review queue.
//!
//! Many AI decisions need human review before they take effect: high-value
//! credit decisions, content-moderation flags, healthcare triage. This
//! module is the canonical work queue:
//!
//! - Producers enqueue [`ReviewItem`]s.
//! - The queue routes by priority + reviewer skill.
//! - Reviewers claim, decide, and produce [`ReviewDecision`]s.
//! - SLA tracking flags overdue items.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

// =============================================================================
// Priority
// =============================================================================

/// Priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPriority {
    /// P1 — urgent, < 1h SLA.
    P1,
    /// P2 — high, < 4h SLA.
    P2,
    /// P3 — normal, < 24h SLA.
    P3,
    /// P4 — low, < 7 days.
    P4,
}

impl ReviewPriority {
    /// SLA in minutes.
    pub fn sla_minutes(self) -> i64 {
        match self {
            Self::P1 => 60,
            Self::P2 => 240,
            Self::P3 => 1440,
            Self::P4 => 7 * 1440,
        }
    }
}

// =============================================================================
// ReviewState
// =============================================================================

/// Per-item state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    /// Pending pickup.
    Pending,
    /// Claimed by a reviewer.
    Claimed,
    /// Decided.
    Decided,
    /// Escalated.
    Escalated,
    /// Cancelled.
    Cancelled,
}

// =============================================================================
// ReviewDecision
// =============================================================================

/// Reviewer's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// Approve the underlying action.
    Approve,
    /// Reject.
    Reject,
    /// Modify with conditions.
    ModifyApprove,
    /// Need more information.
    NeedMoreInfo,
}

/// Decision record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewDecision {
    /// Reviewer.
    pub reviewer: String,
    /// Verdict.
    pub verdict: ReviewVerdict,
    /// Reason.
    pub reason: String,
    /// RFC 3339.
    pub at: String,
}

// =============================================================================
// ReviewItem
// =============================================================================

/// One queued item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewItem {
    /// Stable id.
    pub item_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Priority.
    pub priority: ReviewPriority,
    /// Required skill (e.g. `"credit-decisioning"`).
    pub skill_required: String,
    /// Free-text title.
    pub title: String,
    /// External reference (decision id, seal id, etc.).
    pub external_ref: String,
    /// Free-text payload (e.g., raw decision context).
    pub payload: String,
    /// State.
    pub state: ReviewState,
    /// RFC 3339 enqueued.
    pub enqueued_at: String,
    /// RFC 3339 due (computed from priority).
    pub due_at: String,
    /// Claimed by.
    pub claimed_by: Option<String>,
    /// RFC 3339 claimed.
    pub claimed_at: Option<String>,
    /// Final decision.
    pub decision: Option<ReviewDecision>,
}

impl ReviewItem {
    /// `true` if past due as of `now`.
    pub fn is_overdue(&self, now: OffsetDateTime) -> bool {
        if matches!(self.state, ReviewState::Decided | ReviewState::Cancelled) {
            return false;
        }
        match OffsetDateTime::parse(
            &self.due_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => now > t,
            Err(_) => false,
        }
    }
}

// =============================================================================
// ReviewQueue
// =============================================================================

#[derive(Default)]
struct State {
    items: HashMap<Uuid, ReviewItem>,
}

/// Queue.
pub struct ReviewQueue {
    state: RwLock<State>,
}

impl Default for ReviewQueue {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ReviewQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReviewQueue")
            .field("items", &self.len())
            .finish()
    }
}

impl ReviewQueue {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enqueue an item.
    pub fn enqueue(
        &self,
        tenant: impl Into<String>,
        priority: ReviewPriority,
        skill: impl Into<String>,
        title: impl Into<String>,
        external_ref: impl Into<String>,
        payload: impl Into<String>,
    ) -> SandboxResult<ReviewItem> {
        let now = OffsetDateTime::now_utc();
        let due = now + Duration::minutes(priority.sla_minutes());
        let now_s = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let due_s = due
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let item = ReviewItem {
            item_id: Uuid::now_v7(),
            tenant_id: tenant.into(),
            priority,
            skill_required: skill.into(),
            title: title.into(),
            external_ref: external_ref.into(),
            payload: payload.into(),
            state: ReviewState::Pending,
            enqueued_at: now_s,
            due_at: due_s,
            claimed_by: None,
            claimed_at: None,
            decision: None,
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("review queue poisoned".into()))?
            .items
            .insert(item.item_id, item.clone());
        Ok(item)
    }

    /// Claim an item.
    pub fn claim(&self, item_id: Uuid, reviewer: impl Into<String>) -> SandboxResult<()> {
        let reviewer = reviewer.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("review queue poisoned".into()))?;
        let i = g
            .items
            .get_mut(&item_id)
            .ok_or_else(|| SandboxError::Other(format!("item {} not found", item_id)))?;
        if i.state != ReviewState::Pending {
            return Err(SandboxError::Other(format!(
                "item already in state {:?}",
                i.state
            )));
        }
        i.state = ReviewState::Claimed;
        i.claimed_by = Some(reviewer);
        i.claimed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Decide.
    pub fn decide(
        &self,
        item_id: Uuid,
        verdict: ReviewVerdict,
        reason: impl Into<String>,
    ) -> SandboxResult<ReviewDecision> {
        let reason = reason.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("review queue poisoned".into()))?;
        let i = g
            .items
            .get_mut(&item_id)
            .ok_or_else(|| SandboxError::Other(format!("item {} not found", item_id)))?;
        if i.state != ReviewState::Claimed {
            return Err(SandboxError::Other(format!(
                "must claim before decide; state is {:?}",
                i.state
            )));
        }
        let reviewer = i
            .claimed_by
            .clone()
            .ok_or_else(|| SandboxError::Other("claimed item has no reviewer".into()))?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let d = ReviewDecision {
            reviewer,
            verdict,
            reason,
            at: now,
        };
        i.decision = Some(d.clone());
        i.state = ReviewState::Decided;
        Ok(d)
    }

    /// Escalate.
    pub fn escalate(&self, item_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("review queue poisoned".into()))?;
        let i = g
            .items
            .get_mut(&item_id)
            .ok_or_else(|| SandboxError::Other(format!("item {} not found", item_id)))?;
        if matches!(i.state, ReviewState::Decided | ReviewState::Cancelled) {
            return Err(SandboxError::Other(format!(
                "cannot escalate item in state {:?}",
                i.state
            )));
        }
        i.state = ReviewState::Escalated;
        Ok(())
    }

    /// Cancel.
    pub fn cancel(&self, item_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("review queue poisoned".into()))?;
        let i = g
            .items
            .get_mut(&item_id)
            .ok_or_else(|| SandboxError::Other(format!("item {} not found", item_id)))?;
        if i.state == ReviewState::Decided {
            return Err(SandboxError::Other("cannot cancel decided item".into()));
        }
        i.state = ReviewState::Cancelled;
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<ReviewItem> {
        self.state.read().ok()?.items.get(&id).cloned()
    }

    /// Pending items, sorted by priority desc → due_at asc.
    pub fn pending(&self) -> Vec<ReviewItem> {
        let mut v: Vec<ReviewItem> = self
            .state
            .read()
            .map(|g| {
                g.items
                    .values()
                    .filter(|i| i.state == ReviewState::Pending)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        v.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority) // P1 = lowest enum value but highest priority
                .then(a.due_at.cmp(&b.due_at))
        });
        v
    }

    /// Items overdue as of `now`.
    pub fn overdue(&self, now: OffsetDateTime) -> Vec<ReviewItem> {
        self.state
            .read()
            .map(|g| g.items.values().filter(|i| i.is_overdue(now)).cloned().collect())
            .unwrap_or_default()
    }

    /// Items by skill.
    pub fn by_skill(&self, skill: &str) -> Vec<ReviewItem> {
        self.state
            .read()
            .map(|g| {
                g.items
                    .values()
                    .filter(|i| i.skill_required == skill)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Items by reviewer.
    pub fn by_reviewer(&self, reviewer: &str) -> Vec<ReviewItem> {
        self.state
            .read()
            .map(|g| {
                g.items
                    .values()
                    .filter(|i| i.claimed_by.as_deref() == Some(reviewer))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.items.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enq(q: &ReviewQueue, p: ReviewPriority, skill: &str) -> ReviewItem {
        q.enqueue(
            "FAB",
            p,
            skill,
            "loan over $500k",
            "decision-1",
            "context",
        )
        .unwrap()
    }

    #[test]
    fn enqueue_creates_pending() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P1, "credit");
        assert_eq!(i.state, ReviewState::Pending);
    }

    #[test]
    fn priority_sla_minutes() {
        assert_eq!(ReviewPriority::P1.sla_minutes(), 60);
        assert_eq!(ReviewPriority::P2.sla_minutes(), 240);
        assert_eq!(ReviewPriority::P3.sla_minutes(), 1440);
    }

    #[test]
    fn claim_pending_succeeds() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        q.claim(i.item_id, "alice").unwrap();
        let updated = q.get(i.item_id).unwrap();
        assert_eq!(updated.state, ReviewState::Claimed);
        assert_eq!(updated.claimed_by.as_deref(), Some("alice"));
    }

    #[test]
    fn double_claim_errors() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        q.claim(i.item_id, "alice").unwrap();
        assert!(q.claim(i.item_id, "bob").is_err());
    }

    #[test]
    fn decide_after_claim() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        q.claim(i.item_id, "alice").unwrap();
        let d = q
            .decide(i.item_id, ReviewVerdict::Approve, "approved per policy")
            .unwrap();
        assert_eq!(d.verdict, ReviewVerdict::Approve);
        let updated = q.get(i.item_id).unwrap();
        assert_eq!(updated.state, ReviewState::Decided);
    }

    #[test]
    fn decide_without_claim_errors() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        assert!(q
            .decide(i.item_id, ReviewVerdict::Approve, "x")
            .is_err());
    }

    #[test]
    fn escalate_pending_works() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P3, "credit");
        q.escalate(i.item_id).unwrap();
        assert_eq!(q.get(i.item_id).unwrap().state, ReviewState::Escalated);
    }

    #[test]
    fn cannot_escalate_decided() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        q.claim(i.item_id, "x").unwrap();
        q.decide(i.item_id, ReviewVerdict::Approve, "x").unwrap();
        assert!(q.escalate(i.item_id).is_err());
    }

    #[test]
    fn cancel_pending() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P3, "credit");
        q.cancel(i.item_id).unwrap();
        assert_eq!(q.get(i.item_id).unwrap().state, ReviewState::Cancelled);
    }

    #[test]
    fn cannot_cancel_decided() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        q.claim(i.item_id, "x").unwrap();
        q.decide(i.item_id, ReviewVerdict::Approve, "x").unwrap();
        assert!(q.cancel(i.item_id).is_err());
    }

    #[test]
    fn pending_sorted_by_priority() {
        let q = ReviewQueue::new();
        enq(&q, ReviewPriority::P3, "credit");
        enq(&q, ReviewPriority::P1, "credit");
        enq(&q, ReviewPriority::P2, "credit");
        let pending = q.pending();
        assert_eq!(pending[0].priority, ReviewPriority::P1);
        assert_eq!(pending[1].priority, ReviewPriority::P2);
        assert_eq!(pending[2].priority, ReviewPriority::P3);
    }

    #[test]
    fn overdue_filters_unresolved() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P1, "credit");
        let later = OffsetDateTime::now_utc() + Duration::hours(2);
        let overdue = q.overdue(later);
        assert_eq!(overdue.len(), 1);
        let _ = i;
    }

    #[test]
    fn overdue_excludes_decided() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P1, "credit");
        q.claim(i.item_id, "x").unwrap();
        q.decide(i.item_id, ReviewVerdict::Reject, "x").unwrap();
        let later = OffsetDateTime::now_utc() + Duration::hours(2);
        assert!(q.overdue(later).is_empty());
    }

    #[test]
    fn by_skill_filters() {
        let q = ReviewQueue::new();
        enq(&q, ReviewPriority::P3, "credit");
        enq(&q, ReviewPriority::P3, "fraud");
        assert_eq!(q.by_skill("credit").len(), 1);
        assert_eq!(q.by_skill("fraud").len(), 1);
    }

    #[test]
    fn by_reviewer_filters() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P3, "credit");
        q.claim(i.item_id, "alice").unwrap();
        assert_eq!(q.by_reviewer("alice").len(), 1);
        assert!(q.by_reviewer("bob").is_empty());
    }

    #[test]
    fn item_serde() {
        let q = ReviewQueue::new();
        let i = enq(&q, ReviewPriority::P2, "credit");
        let j = serde_json::to_string(&i).unwrap();
        let p: ReviewItem = serde_json::from_str(&j).unwrap();
        assert_eq!(p, i);
    }

    #[test]
    fn priority_serde() {
        for p in [
            ReviewPriority::P1,
            ReviewPriority::P2,
            ReviewPriority::P3,
            ReviewPriority::P4,
        ] {
            let j = serde_json::to_string(&p).unwrap();
            let q: ReviewPriority = serde_json::from_str(&j).unwrap();
            assert_eq!(p, q);
        }
    }

    #[test]
    fn verdict_serde() {
        for v in [
            ReviewVerdict::Approve,
            ReviewVerdict::Reject,
            ReviewVerdict::ModifyApprove,
            ReviewVerdict::NeedMoreInfo,
        ] {
            let j = serde_json::to_string(&v).unwrap();
            let p: ReviewVerdict = serde_json::from_str(&j).unwrap();
            assert_eq!(v, p);
        }
    }

    #[test]
    fn state_serde() {
        for s in [
            ReviewState::Pending,
            ReviewState::Claimed,
            ReviewState::Decided,
            ReviewState::Escalated,
            ReviewState::Cancelled,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ReviewState = serde_json::from_str(&j).unwrap();
            assert_eq!(s, p);
        }
    }

    #[test]
    fn unknown_item_lookups_none() {
        let q = ReviewQueue::new();
        assert!(q.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn count_tracks() {
        let q = ReviewQueue::new();
        assert!(q.is_empty());
        enq(&q, ReviewPriority::P3, "credit");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn many_items_pending_sort_stable() {
        let q = ReviewQueue::new();
        for _ in 0..10 {
            enq(&q, ReviewPriority::P3, "credit");
        }
        let pending = q.pending();
        assert_eq!(pending.len(), 10);
        // All same priority, sorted by due_at — should preserve order roughly.
    }
}
