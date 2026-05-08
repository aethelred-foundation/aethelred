//! Webhook replay — operator-initiated retry of past dead-lettered deliveries.
//!
//! Pairs with [`crate::webhook_subscriptions::DeadLetterQueue`]: when a
//! customer reports they missed an event window, an operator selects the
//! relevant DLQ records and triggers a replay. This module records the
//! request, tracks per-attempt outcome, and produces a tamper-evident
//! replay log.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ReplayRequest
// =============================================================================

/// Replay request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayRequest {
    /// Stable id.
    pub request_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Webhook subscription id (the original delivery target).
    pub subscription_id: Uuid,
    /// Time window covered (RFC 3339).
    pub from_at: String,
    /// Time window covered (RFC 3339).
    pub to_at: String,
    /// Optional kind filter.
    pub kind_filter: Option<String>,
    /// IDs of DLQ entries (or original delivery_ids) to replay.
    pub target_delivery_ids: Vec<Uuid>,
    /// Operator who requested.
    pub requested_by: String,
    /// Free-text reason.
    pub reason: String,
    /// RFC 3339 created.
    pub created_at: String,
    /// Status.
    pub status: ReplayStatus,
    /// Replay attempts so far.
    pub attempts: Vec<ReplayAttempt>,
}

// =============================================================================
// ReplayStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    /// Pending operator confirmation.
    Pending,
    /// In progress.
    InProgress,
    /// Completed (some or all delivered).
    Completed,
    /// Aborted.
    Aborted,
}

// =============================================================================
// ReplayAttempt
// =============================================================================

/// One per-target attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayAttempt {
    /// Attempt id.
    pub attempt_id: Uuid,
    /// Original delivery id targeted.
    pub original_delivery_id: Uuid,
    /// Status.
    pub status: AttemptStatus,
    /// Error message.
    pub error: Option<String>,
    /// RFC 3339 attempted at.
    pub at: String,
    /// Hash chain.
    pub prior_hash: Option<Sha256Digest>,
    /// Self hash.
    pub self_hash: Sha256Digest,
}

/// Per-attempt status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    /// Delivered successfully.
    Delivered,
    /// Failed.
    Failed,
    /// Skipped (no longer available, e.g. expired).
    Skipped,
}

impl ReplayAttempt {
    fn compute_hash(
        original_delivery_id: &Uuid,
        status: AttemptStatus,
        at: &str,
        prior: Option<&Sha256Digest>,
    ) -> Sha256Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(original_delivery_id.as_bytes());
        buf.push(status_byte(status));
        buf.extend_from_slice(at.as_bytes());
        if let Some(p) = prior {
            buf.extend_from_slice(&p.0);
        }
        Hasher::sha256(&buf)
    }
}

fn status_byte(s: AttemptStatus) -> u8 {
    match s {
        AttemptStatus::Delivered => 1,
        AttemptStatus::Failed => 2,
        AttemptStatus::Skipped => 3,
    }
}

// =============================================================================
// ReplayLog
// =============================================================================

#[derive(Default)]
struct State {
    requests: HashMap<Uuid, ReplayRequest>,
}

/// Log.
pub struct ReplayLog {
    state: RwLock<State>,
}

impl Default for ReplayLog {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ReplayLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayLog")
            .field("requests", &self.len())
            .finish()
    }
}

impl ReplayLog {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new request.
    pub fn open(
        &self,
        tenant_id: impl Into<String>,
        subscription_id: Uuid,
        from_at: impl Into<String>,
        to_at: impl Into<String>,
        target_delivery_ids: Vec<Uuid>,
        requested_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<ReplayRequest> {
        if target_delivery_ids.is_empty() {
            return Err(SandboxError::Other("no targets to replay".into()));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let r = ReplayRequest {
            request_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            subscription_id,
            from_at: from_at.into(),
            to_at: to_at.into(),
            kind_filter: None,
            target_delivery_ids,
            requested_by: requested_by.into(),
            reason: reason.into(),
            created_at: now,
            status: ReplayStatus::Pending,
            attempts: Vec::new(),
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("replay log poisoned".into()))?
            .requests
            .insert(r.request_id, r.clone());
        Ok(r)
    }

    /// Begin processing.
    pub fn begin(&self, request_id: Uuid) -> SandboxResult<()> {
        self.transition(request_id, ReplayStatus::InProgress)
    }

    /// Record an attempt.
    pub fn record_attempt(
        &self,
        request_id: Uuid,
        original_delivery_id: Uuid,
        status: AttemptStatus,
        error: Option<String>,
    ) -> SandboxResult<ReplayAttempt> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replay log poisoned".into()))?;
        let req = g
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        if req.status != ReplayStatus::InProgress {
            return Err(SandboxError::Other(format!(
                "cannot record attempt in state {:?}",
                req.status
            )));
        }
        if !req.target_delivery_ids.contains(&original_delivery_id) {
            return Err(SandboxError::Other(format!(
                "delivery {} not in target list",
                original_delivery_id
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let prior = req.attempts.last().map(|a| a.self_hash.clone());
        let self_hash =
            ReplayAttempt::compute_hash(&original_delivery_id, status, &now, prior.as_ref());
        let attempt = ReplayAttempt {
            attempt_id: Uuid::now_v7(),
            original_delivery_id,
            status,
            error,
            at: now,
            prior_hash: prior,
            self_hash,
        };
        req.attempts.push(attempt.clone());
        Ok(attempt)
    }

    /// Complete the request (transitions to Completed).
    pub fn complete(&self, request_id: Uuid) -> SandboxResult<()> {
        self.transition(request_id, ReplayStatus::Completed)
    }

    /// Abort.
    pub fn abort(&self, request_id: Uuid) -> SandboxResult<()> {
        self.transition(request_id, ReplayStatus::Aborted)
    }

    fn transition(&self, request_id: Uuid, target: ReplayStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("replay log poisoned".into()))?;
        let req = g
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        // Lifecycle rules.
        match (req.status, target) {
            (ReplayStatus::Pending, ReplayStatus::InProgress) => {}
            (ReplayStatus::InProgress, ReplayStatus::Completed) => {}
            (ReplayStatus::Pending, ReplayStatus::Aborted) => {}
            (ReplayStatus::InProgress, ReplayStatus::Aborted) => {}
            _ => {
                return Err(SandboxError::Other(format!(
                    "illegal transition {:?} -> {:?}",
                    req.status, target
                )))
            }
        }
        req.status = target;
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<ReplayRequest> {
        self.state.read().ok()?.requests.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ReplayRequest> {
        self.state
            .read()
            .map(|g| g.requests.values().cloned().collect())
            .unwrap_or_default()
    }
    /// By tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<ReplayRequest> {
        self.all().into_iter().filter(|r| r.tenant_id == tenant).collect()
    }
    /// By status.
    pub fn by_status(&self, s: ReplayStatus) -> Vec<ReplayRequest> {
        self.all().into_iter().filter(|r| r.status == s).collect()
    }
    /// Verify chain integrity for one request's attempts.
    pub fn verify(&self, id: Uuid) -> SandboxResult<()> {
        let req = self
            .get(id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", id)))?;
        let mut prior: Option<Sha256Digest> = None;
        for (i, a) in req.attempts.iter().enumerate() {
            match (&a.prior_hash, &prior) {
                (None, None) => {}
                (Some(x), Some(y)) if x == y => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "request {} chain break at attempt {}",
                        id, i
                    )))
                }
            }
            let recomputed = ReplayAttempt::compute_hash(
                &a.original_delivery_id,
                a.status,
                &a.at,
                a.prior_hash.as_ref(),
            );
            if recomputed != a.self_hash {
                return Err(SandboxError::Other(format!(
                    "request {} attempt {} hash mismatch",
                    id, i
                )));
            }
            prior = Some(a.self_hash.clone());
        }
        Ok(())
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.requests.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(l: &ReplayLog) -> ReplayRequest {
        l.open(
            "FAB",
            Uuid::now_v7(),
            "2026-05-01T00:00:00Z",
            "2026-05-31T23:59:59Z",
            vec![Uuid::now_v7(), Uuid::now_v7()],
            "ops",
            "customer reported missing events",
        )
        .unwrap()
    }

    #[test]
    fn open_creates_request() {
        let l = ReplayLog::new();
        let r = open(&l);
        assert_eq!(r.status, ReplayStatus::Pending);
        assert_eq!(r.target_delivery_ids.len(), 2);
    }

    #[test]
    fn open_empty_targets_errors() {
        let l = ReplayLog::new();
        assert!(l
            .open(
                "FAB",
                Uuid::now_v7(),
                "x",
                "y",
                vec![],
                "ops",
                "reason"
            )
            .is_err());
    }

    #[test]
    fn begin_advances_to_in_progress() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        assert_eq!(l.get(r.request_id).unwrap().status, ReplayStatus::InProgress);
    }

    #[test]
    fn record_attempt_appends_with_chain() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        let did = r.target_delivery_ids[0];
        let a1 = l
            .record_attempt(r.request_id, did, AttemptStatus::Delivered, None)
            .unwrap();
        let did2 = r.target_delivery_ids[1];
        let a2 = l
            .record_attempt(r.request_id, did2, AttemptStatus::Failed, Some("503".into()))
            .unwrap();
        assert!(a1.prior_hash.is_none());
        assert_eq!(a2.prior_hash, Some(a1.self_hash));
    }

    #[test]
    fn record_attempt_outside_targets_errors() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        assert!(l
            .record_attempt(r.request_id, Uuid::now_v7(), AttemptStatus::Delivered, None)
            .is_err());
    }

    #[test]
    fn record_attempt_in_pending_errors() {
        let l = ReplayLog::new();
        let r = open(&l);
        let did = r.target_delivery_ids[0];
        // Not yet begun.
        assert!(l
            .record_attempt(r.request_id, did, AttemptStatus::Delivered, None)
            .is_err());
    }

    #[test]
    fn complete_after_in_progress() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        l.complete(r.request_id).unwrap();
        assert_eq!(l.get(r.request_id).unwrap().status, ReplayStatus::Completed);
    }

    #[test]
    fn abort_from_pending() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.abort(r.request_id).unwrap();
        assert_eq!(l.get(r.request_id).unwrap().status, ReplayStatus::Aborted);
    }

    #[test]
    fn abort_from_in_progress() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        l.abort(r.request_id).unwrap();
        assert_eq!(l.get(r.request_id).unwrap().status, ReplayStatus::Aborted);
    }

    #[test]
    fn cannot_complete_from_pending() {
        let l = ReplayLog::new();
        let r = open(&l);
        assert!(l.complete(r.request_id).is_err());
    }

    #[test]
    fn verify_chain_passes() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        for d in &r.target_delivery_ids {
            l.record_attempt(r.request_id, *d, AttemptStatus::Delivered, None)
                .unwrap();
        }
        l.verify(r.request_id).unwrap();
    }

    #[test]
    fn verify_unknown_errors() {
        let l = ReplayLog::new();
        assert!(l.verify(Uuid::now_v7()).is_err());
    }

    #[test]
    fn for_tenant_filters() {
        let l = ReplayLog::new();
        open(&l);
        l.open(
            "ENBD",
            Uuid::now_v7(),
            "x",
            "y",
            vec![Uuid::now_v7()],
            "ops",
            "x",
        )
        .unwrap();
        assert_eq!(l.for_tenant("FAB").len(), 1);
        assert_eq!(l.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.begin(r.request_id).unwrap();
        let r2 = open(&l);
        l.abort(r2.request_id).unwrap();
        assert_eq!(l.by_status(ReplayStatus::InProgress).len(), 1);
        assert_eq!(l.by_status(ReplayStatus::Aborted).len(), 1);
    }

    #[test]
    fn request_serde() {
        let l = ReplayLog::new();
        let r = open(&l);
        let j = serde_json::to_string(&r).unwrap();
        let p: ReplayRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn attempt_serde() {
        let a = ReplayAttempt {
            attempt_id: Uuid::now_v7(),
            original_delivery_id: Uuid::now_v7(),
            status: AttemptStatus::Delivered,
            error: None,
            at: "t".into(),
            prior_hash: None,
            self_hash: Hasher::sha256(b"x"),
        };
        let j = serde_json::to_string(&a).unwrap();
        let p: ReplayAttempt = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn status_serde() {
        for s in [
            ReplayStatus::Pending,
            ReplayStatus::InProgress,
            ReplayStatus::Completed,
            ReplayStatus::Aborted,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ReplayStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn attempt_status_serde() {
        for s in [
            AttemptStatus::Delivered,
            AttemptStatus::Failed,
            AttemptStatus::Skipped,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: AttemptStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn count_tracks() {
        let l = ReplayLog::new();
        assert!(l.is_empty());
        open(&l);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn cannot_begin_after_abort() {
        let l = ReplayLog::new();
        let r = open(&l);
        l.abort(r.request_id).unwrap();
        assert!(l.begin(r.request_id).is_err());
    }
}
