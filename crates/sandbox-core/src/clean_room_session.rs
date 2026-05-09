//! Data clean-room session register.
//!
//! Distinct from [`crate::secure_aggregation_log`] (federated learning
//! aggregation) and [`crate::evidence_packager`] (audit-evidence
//! bundles), this module tracks **clean-room sessions**: sandboxed
//! environments where one party hosts data and another party submits
//! pre-approved queries. The host's data never leaves the room; the
//! querier only sees aggregated, policy-gated outputs.
//!
//! Maps to the AWS Clean Rooms / GCP BigQuery Data Clean Rooms / Snowflake
//! Data Clean Rooms patterns. Pairs with [`crate::differential_privacy`]
//! to enforce per-session privacy budgets.
//!
//! ## Lifecycle
//!
//! `Provisioned → DataLoaded → InUse → Sealed → Destroyed`
//!
//! `Provisioned`: room created, no data yet. `DataLoaded`: host has
//! ingested data. `InUse`: querier running pre-approved queries.
//! `Sealed`: session ended, no further queries permitted but evidence
//! retained. `Destroyed`: data wiped (terminal).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SessionStage
// =============================================================================

/// Lifecycle stage of a clean-room session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStage {
    /// Room provisioned; no data loaded.
    Provisioned,
    /// Host has loaded data.
    DataLoaded,
    /// Querier running queries.
    InUse,
    /// Session ended; evidence retained, no further queries.
    Sealed,
    /// Data wiped; session record retained for audit.
    Destroyed,
}

impl SessionStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Destroyed)
    }

    /// True if querier may submit new queries.
    pub fn permits_queries(self) -> bool {
        matches!(self, Self::InUse)
    }
}

// =============================================================================
// QueryPolicy
// =============================================================================

/// Policy class governing what queries are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryPolicy {
    /// Aggregate-only (counts, sums, means with k-anon threshold).
    AggregateOnly,
    /// Pre-approved list of named queries.
    AllowList,
    /// Differential-privacy with per-query epsilon accounting.
    DifferentialPrivacy,
    /// Sampling — return a randomised subset.
    Sampling,
    /// Custom policy.
    Custom,
}

// =============================================================================
// QueryStatus
// =============================================================================

/// Status of an issued query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    /// Submitted; awaiting policy gate.
    Pending,
    /// Gate passed; running.
    Running,
    /// Returned a result.
    Completed,
    /// Failed at execution.
    Failed,
    /// Blocked by policy (e.g., k-anon threshold).
    PolicyBlocked,
}

impl QueryStatus {
    /// True if no further state changes expected.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending | Self::Running)
    }
}

// =============================================================================
// QueryRecord
// =============================================================================

/// One issued query record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryRecord {
    /// Stable query id.
    pub query_id: String,
    /// Querier party id.
    pub querier: String,
    /// SHA-256 of the query (for tamper-evident audit).
    pub query_sha256: String,
    /// SHA-256 of the result (only set on Completed).
    pub result_sha256: Option<String>,
    /// Status.
    pub status: QueryStatus,
    /// Number of rows scanned (operator-supplied estimate).
    pub rows_scanned: u64,
    /// Differential-privacy epsilon spent (in micro-units; 1.0 ε =
    /// 1_000_000 micro-ε), if DP policy applies.
    pub epsilon_micro: u64,
    /// RFC 3339 — submitted.
    pub submitted_at: String,
    /// RFC 3339 — completed (terminal).
    pub completed_at: Option<String>,
    /// Optional reason text.
    pub reason: Option<String>,
}

// =============================================================================
// SessionEvent
// =============================================================================

/// One event on the session timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: SessionStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// CleanRoomSession
// =============================================================================

/// One clean-room session record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanRoomSession {
    /// Unique session id.
    pub session_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Host party id (data provider).
    pub host_party: String,
    /// Querier party id (data consumer).
    pub querier_party: String,
    /// Display title.
    pub title: String,
    /// Free-text purpose.
    pub purpose: String,
    /// Query policy.
    pub policy: QueryPolicy,
    /// Stage.
    pub stage: SessionStage,
    /// Total privacy budget allocated (micro-ε); 0 = no DP.
    pub budget_epsilon_micro: u64,
    /// Privacy budget consumed so far.
    pub spent_epsilon_micro: u64,
    /// Issued queries.
    pub queries: Vec<QueryRecord>,
    /// SHA-256 of the loaded data (set on DataLoaded).
    pub data_sha256: Option<String>,
    /// Linked DPA / participation agreement id.
    pub agreement_id: Option<String>,
    /// RFC 3339 — provisioned.
    pub provisioned_at: String,
    /// RFC 3339 — sealed.
    pub sealed_at: Option<String>,
    /// RFC 3339 — destroyed (terminal).
    pub destroyed_at: Option<String>,
    /// Event log.
    pub events: Vec<SessionEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl CleanRoomSession {
    /// New `Provisioned` session.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        tenant_id: impl Into<String>,
        host_party: impl Into<String>,
        querier_party: impl Into<String>,
        title: impl Into<String>,
        purpose: impl Into<String>,
        policy: QueryPolicy,
        budget_epsilon_micro: u64,
        provisioned_at: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            tenant_id: tenant_id.into(),
            host_party: host_party.into(),
            querier_party: querier_party.into(),
            title: title.into(),
            purpose: purpose.into(),
            policy,
            stage: SessionStage::Provisioned,
            budget_epsilon_micro,
            spent_epsilon_micro: 0,
            queries: Vec::new(),
            data_sha256: None,
            agreement_id: None,
            provisioned_at: provisioned_at.into(),
            sealed_at: None,
            destroyed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if the session has spent its full DP budget.
    pub fn budget_exhausted(&self) -> bool {
        self.budget_epsilon_micro > 0
            && self.spent_epsilon_micro >= self.budget_epsilon_micro
    }

    /// Remaining DP budget in micro-ε.
    pub fn remaining_budget_micro(&self) -> u64 {
        self.budget_epsilon_micro
            .saturating_sub(self.spent_epsilon_micro)
    }

    /// Number of completed queries.
    pub fn completed_query_count(&self) -> usize {
        self.queries
            .iter()
            .filter(|q| matches!(q.status, QueryStatus::Completed))
            .count()
    }

    /// Number of policy-blocked queries.
    pub fn blocked_query_count(&self) -> usize {
        self.queries
            .iter()
            .filter(|q| matches!(q.status, QueryStatus::PolicyBlocked))
            .count()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: SessionStage, to: SessionStage) -> bool {
    use SessionStage::*;
    matches!(
        (from, to),
        (Provisioned, DataLoaded)
            | (Provisioned, Sealed)
            | (Provisioned, Destroyed)
            | (DataLoaded, InUse)
            | (DataLoaded, Sealed)
            | (DataLoaded, Destroyed)
            | (InUse, Sealed)
            | (InUse, Destroyed)
            | (Sealed, Destroyed)
    )
}

// =============================================================================
// CleanRoomSessionRegister
// =============================================================================

/// Thread-safe register of clean-room sessions.
#[derive(Debug, Default)]
pub struct CleanRoomSessionRegister {
    inner: RwLock<HashMap<String, CleanRoomSession>>,
}

impl CleanRoomSessionRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a new session.
    pub fn provision(&self, session: CleanRoomSession) -> SandboxResult<()> {
        if !matches!(session.stage, SessionStage::Provisioned) {
            return Err(SandboxError::Other(format!(
                "session must start Provisioned, got {:?}",
                session.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        if g.contains_key(&session.session_id) {
            return Err(SandboxError::Other(format!(
                "session already provisioned: {}",
                session.session_id
            )));
        }
        g.insert(session.session_id.clone(), session);
        Ok(())
    }

    /// Mark DataLoaded with the data SHA-256.
    pub fn mark_data_loaded(
        &self,
        session_id: &str,
        data_sha256: impl Into<String>,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<CleanRoomSession> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if !legal_transition(s.stage, SessionStage::DataLoaded) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> DataLoaded",
                s.stage
            )));
        }
        let when = at.into();
        s.stage = SessionStage::DataLoaded;
        s.data_sha256 = Some(data_sha256.into());
        s.events.push(SessionEvent {
            at: when,
            actor: actor.into(),
            stage: SessionStage::DataLoaded,
            note: "data loaded".into(),
        });
        Ok(s.clone())
    }

    /// Open the session for queries (DataLoaded → InUse).
    pub fn open_for_queries(
        &self,
        session_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<CleanRoomSession> {
        self.simple_transition(
            session_id,
            SessionStage::InUse,
            actor,
            at,
            "querier connected",
        )
    }

    /// Submit a query. Allowed only in InUse. Errors if budget exhausted.
    pub fn submit_query(
        &self,
        session_id: &str,
        query: QueryRecord,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if !s.stage.permits_queries() {
            return Err(SandboxError::Other(format!(
                "cannot submit query on {session_id}: stage is {:?}",
                s.stage
            )));
        }
        if s.budget_exhausted() {
            return Err(SandboxError::Other(format!(
                "cannot submit query on {session_id}: privacy budget exhausted"
            )));
        }
        if s.queries.iter().any(|q| q.query_id == query.query_id) {
            return Err(SandboxError::Other(format!(
                "query already submitted: {}",
                query.query_id
            )));
        }
        // Check that adding this query's epsilon wouldn't push over budget.
        if s.budget_epsilon_micro > 0
            && s.spent_epsilon_micro.saturating_add(query.epsilon_micro)
                > s.budget_epsilon_micro
        {
            return Err(SandboxError::Other(format!(
                "cannot submit query on {session_id}: would exceed privacy budget"
            )));
        }
        s.queries.push(query);
        Ok(())
    }

    /// Update a query's status. On Completed, accumulates spent_epsilon.
    pub fn set_query_status(
        &self,
        session_id: &str,
        query_id: &str,
        status: QueryStatus,
        at: impl Into<String>,
        result_sha256: Option<String>,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        let q = s
            .queries
            .iter_mut()
            .find(|q| q.query_id == query_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown query {query_id}")))?;
        if q.status.is_resolved() {
            return Err(SandboxError::Other(format!(
                "query {query_id} already resolved"
            )));
        }
        let was_pending_or_running = !q.status.is_resolved();
        q.status = status;
        if matches!(status, QueryStatus::Completed) {
            q.completed_at = Some(at.into());
            if let Some(r) = result_sha256 {
                q.result_sha256 = Some(r);
            }
            // Accumulate epsilon only on successful completion.
            if was_pending_or_running {
                s.spent_epsilon_micro =
                    s.spent_epsilon_micro.saturating_add(q.epsilon_micro);
            }
        } else if matches!(
            status,
            QueryStatus::Failed | QueryStatus::PolicyBlocked
        ) {
            q.completed_at = Some(at.into());
        } else {
            // Running — no completed_at update.
            let _ = at;
        }
        if let Some(r) = reason {
            q.reason = Some(r);
        }
        Ok(())
    }

    /// Seal the session.
    pub fn seal(
        &self,
        session_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<CleanRoomSession> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if !legal_transition(s.stage, SessionStage::Sealed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Sealed",
                s.stage
            )));
        }
        let when = at.into();
        s.stage = SessionStage::Sealed;
        s.sealed_at = Some(when.clone());
        s.events.push(SessionEvent {
            at: when,
            actor: actor.into(),
            stage: SessionStage::Sealed,
            note: reason.into(),
        });
        Ok(s.clone())
    }

    /// Destroy the session.
    pub fn destroy(
        &self,
        session_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<CleanRoomSession> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if !legal_transition(s.stage, SessionStage::Destroyed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Destroyed",
                s.stage
            )));
        }
        let when = at.into();
        s.stage = SessionStage::Destroyed;
        s.destroyed_at = Some(when.clone());
        s.events.push(SessionEvent {
            at: when,
            actor: actor.into(),
            stage: SessionStage::Destroyed,
            note: reason.into(),
        });
        Ok(s.clone())
    }

    fn simple_transition(
        &self,
        session_id: &str,
        new_stage: SessionStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<CleanRoomSession> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        if !legal_transition(s.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                s.stage, new_stage
            )));
        }
        let when = at.into();
        s.stage = new_stage;
        s.events.push(SessionEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(s.clone())
    }

    /// Link a participation agreement.
    pub fn link_agreement(
        &self,
        session_id: &str,
        agreement_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        s.agreement_id = Some(agreement_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, session_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("clean room register poisoned".into()))?;
        let s = g
            .get_mut(session_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown session {session_id}")))?;
        let tag = tag.into();
        if !s.tags.contains(&tag) {
            s.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, session_id: &str) -> Option<CleanRoomSession> {
        let g = self.inner.read().ok()?;
        g.get(session_id).cloned()
    }

    /// All sessions.
    pub fn all(&self) -> Vec<CleanRoomSession> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<CleanRoomSession> {
        self.all()
            .into_iter()
            .filter(|s| s.tenant_id == tenant_id)
            .collect()
    }

    /// Sessions a party participated in (host or querier).
    pub fn for_party(&self, party_id: &str) -> Vec<CleanRoomSession> {
        self.all()
            .into_iter()
            .filter(|s| s.host_party == party_id || s.querier_party == party_id)
            .collect()
    }

    /// Sessions by stage.
    pub fn by_stage(&self, stage: SessionStage) -> Vec<CleanRoomSession> {
        self.all().into_iter().filter(|s| s.stage == stage).collect()
    }

    /// Currently in-use sessions.
    pub fn in_use(&self) -> Vec<CleanRoomSession> {
        self.by_stage(SessionStage::InUse)
    }

    /// Sessions that exhausted their privacy budget.
    pub fn budget_exhausted(&self) -> Vec<CleanRoomSession> {
        self.all()
            .into_iter()
            .filter(|s| s.budget_exhausted())
            .collect()
    }

    /// Number of sessions.
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

    fn session(id: &str, host: &str, querier: &str, budget: u64) -> CleanRoomSession {
        CleanRoomSession::new(
            id,
            "tenant-orch",
            host,
            querier,
            format!("Title {id}"),
            "joint analysis purpose",
            QueryPolicy::DifferentialPrivacy,
            budget,
            "2025-04-01T00:00:00Z",
        )
    }

    fn query(id: &str, querier: &str, epsilon: u64) -> QueryRecord {
        QueryRecord {
            query_id: id.into(),
            querier: querier.into(),
            query_sha256: format!("sha-q-{id}"),
            result_sha256: None,
            status: QueryStatus::Pending,
            rows_scanned: 1_000,
            epsilon_micro: epsilon,
            submitted_at: "2025-04-15T00:00:00Z".into(),
            completed_at: None,
            reason: None,
        }
    }

    fn drive_to_in_use(r: &CleanRoomSessionRegister, id: &str) {
        r.mark_data_loaded(id, "data-sha", "host", "2025-04-05T00:00:00Z").unwrap();
        r.open_for_queries(id, "querier", "2025-04-06T00:00:00Z").unwrap();
    }

    #[test]
    fn provision_and_get() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        assert!(r.get("s1").is_some());
    }

    #[test]
    fn duplicate_provision_errors() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        let err = r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap_err();
        assert!(format!("{err}").contains("already provisioned"));
    }

    #[test]
    fn must_start_provisioned() {
        let mut s = session("s1", "host-a", "querier-b", 1_000_000);
        s.stage = SessionStage::InUse;
        let r = CleanRoomSessionRegister::new();
        let err = r.provision(s).unwrap_err();
        assert!(format!("{err}").contains("must start Provisioned"));
    }

    #[test]
    fn legal_transitions() {
        use SessionStage::*;
        assert!(legal_transition(Provisioned, DataLoaded));
        assert!(legal_transition(Provisioned, Sealed));
        assert!(legal_transition(DataLoaded, InUse));
        assert!(legal_transition(InUse, Sealed));
        assert!(legal_transition(Sealed, Destroyed));
        // illegal
        assert!(!legal_transition(Provisioned, InUse));
        assert!(!legal_transition(Destroyed, Sealed));
        assert!(!legal_transition(InUse, Provisioned));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha-r-q1".into()),
            None,
        )
        .unwrap();
        r.seal("s1", "orch", "2025-04-20T00:00:00Z", "session ended").unwrap();
        let s = r.destroy("s1", "orch", "2025-04-25T00:00:00Z", "data wiped").unwrap();
        assert_eq!(s.stage, SessionStage::Destroyed);
        assert!(s.stage.is_terminal());
        assert_eq!(s.spent_epsilon_micro, 200_000);
        assert_eq!(s.completed_query_count(), 1);
    }

    #[test]
    fn submit_query_only_in_use() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        let err = r.submit_query("s1", query("q1", "querier-b", 100)).unwrap_err();
        assert!(format!("{err}").contains("cannot submit query"));
    }

    #[test]
    fn submit_query_dedupes() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 100)).unwrap();
        let err = r.submit_query("s1", query("q1", "querier-b", 200)).unwrap_err();
        assert!(format!("{err}").contains("already submitted"));
    }

    #[test]
    fn submit_query_budget_check() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 500_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 300_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha".into()),
            None,
        )
        .unwrap();
        // Try to submit q2 with epsilon that would exceed budget (300k spent, 200k left, q2 wants 300k).
        let err = r
            .submit_query("s1", query("q2", "querier-b", 300_000))
            .unwrap_err();
        assert!(format!("{err}").contains("would exceed privacy budget"));
    }

    #[test]
    fn submit_query_after_exhausted_errors() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 200_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha".into()),
            None,
        )
        .unwrap();
        assert!(r.get("s1").unwrap().budget_exhausted());
        let err = r.submit_query("s1", query("q2", "querier-b", 1)).unwrap_err();
        assert!(format!("{err}").contains("privacy budget exhausted"));
    }

    #[test]
    fn set_query_status_failed_no_budget_charge() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Failed,
            "2025-04-15T00:01:00Z",
            None,
            Some("execution timeout".into()),
        )
        .unwrap();
        // Failed → no epsilon charged
        assert_eq!(r.get("s1").unwrap().spent_epsilon_micro, 0);
    }

    #[test]
    fn set_query_status_policy_blocked_no_budget_charge() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::PolicyBlocked,
            "2025-04-15T00:01:00Z",
            None,
            Some("k-anon threshold".into()),
        )
        .unwrap();
        assert_eq!(r.get("s1").unwrap().spent_epsilon_micro, 0);
        assert_eq!(r.get("s1").unwrap().blocked_query_count(), 1);
    }

    #[test]
    fn set_query_status_already_resolved_errors() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "querier-b", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha".into()),
            None,
        )
        .unwrap();
        let err = r
            .set_query_status(
                "s1",
                "q1",
                QueryStatus::Failed,
                "2025-04-15T00:02:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("already resolved"));
    }

    #[test]
    fn set_query_status_unknown_query_errors() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s1");
        let err = r
            .set_query_status(
                "s1",
                "ghost",
                QueryStatus::Completed,
                "2025-04-15T00:01:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown query"));
    }

    #[test]
    fn seal_from_any_non_terminal() {
        let r = CleanRoomSessionRegister::new();
        // From Provisioned
        r.provision(session("s1", "h", "q", 1_000_000)).unwrap();
        r.seal("s1", "orch", "2025-04-02T00:00:00Z", "n").unwrap();
        // From DataLoaded
        r.provision(session("s2", "h", "q", 1_000_000)).unwrap();
        r.mark_data_loaded("s2", "sha", "h", "2025-04-05T00:00:00Z").unwrap();
        r.seal("s2", "orch", "2025-04-06T00:00:00Z", "n").unwrap();
        // From InUse
        r.provision(session("s3", "h", "q", 1_000_000)).unwrap();
        drive_to_in_use(&r, "s3");
        r.seal("s3", "orch", "2025-04-20T00:00:00Z", "n").unwrap();
    }

    #[test]
    fn destroy_from_sealed() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 1_000_000)).unwrap();
        r.seal("s1", "orch", "2025-04-02T00:00:00Z", "n").unwrap();
        let s = r.destroy("s1", "orch", "2025-04-03T00:00:00Z", "wiped").unwrap();
        assert_eq!(s.stage, SessionStage::Destroyed);
    }

    #[test]
    fn destroy_terminal_errors() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 1_000_000)).unwrap();
        r.destroy("s1", "orch", "2025-04-02T00:00:00Z", "wiped").unwrap();
        let err = r.destroy("s1", "orch", "2025-04-03T00:00:00Z", "n").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn link_agreement_set_tag() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 1_000_000)).unwrap();
        r.link_agreement("s1", "DPA-007").unwrap();
        r.add_tag("s1", "joint-research").unwrap();
        r.add_tag("s1", "joint-research").unwrap();
        let s = r.get("s1").unwrap();
        assert_eq!(s.agreement_id.as_deref(), Some("DPA-007"));
        assert_eq!(s.tags, vec!["joint-research"]);
    }

    #[test]
    fn unknown_session_errors() {
        let r = CleanRoomSessionRegister::new();
        let err = r.link_agreement("nope", "DPA").unwrap_err();
        assert!(format!("{err}").contains("unknown session"));
    }

    #[test]
    fn for_tenant_party_filters() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "host-a", "querier-b", 1_000_000)).unwrap();
        let mut other = session("s2", "host-c", "querier-d", 1_000_000);
        other.tenant_id = "tenant-other".into();
        r.provision(other).unwrap();
        assert_eq!(r.for_tenant("tenant-orch").len(), 1);
        assert_eq!(r.for_tenant("tenant-other").len(), 1);
        assert_eq!(r.for_party("host-a").len(), 1);
        assert_eq!(r.for_party("querier-d").len(), 1);
        assert_eq!(r.for_party("ghost").len(), 0);
    }

    #[test]
    fn budget_exhausted_filter() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 200_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "q", 200_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha".into()),
            None,
        )
        .unwrap();
        let exhausted = r.budget_exhausted();
        assert_eq!(exhausted.len(), 1);
        assert_eq!(exhausted[0].session_id, "s1");
    }

    #[test]
    fn remaining_budget_helper() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 500_000)).unwrap();
        drive_to_in_use(&r, "s1");
        r.submit_query("s1", query("q1", "q", 100_000)).unwrap();
        r.set_query_status(
            "s1",
            "q1",
            QueryStatus::Completed,
            "2025-04-15T00:01:00Z",
            Some("sha".into()),
            None,
        )
        .unwrap();
        assert_eq!(r.get("s1").unwrap().remaining_budget_micro(), 400_000);
    }

    #[test]
    fn zero_budget_treated_as_no_dp() {
        let r = CleanRoomSessionRegister::new();
        r.provision(session("s1", "h", "q", 0)).unwrap();
        drive_to_in_use(&r, "s1");
        // budget 0 means no DP enforcement
        r.submit_query("s1", query("q1", "q", 1_000_000)).unwrap();
        let s = r.get("s1").unwrap();
        assert!(!s.budget_exhausted());
    }

    #[test]
    fn stage_helpers() {
        assert!(SessionStage::Destroyed.is_terminal());
        assert!(SessionStage::InUse.permits_queries());
        assert!(!SessionStage::Sealed.permits_queries());
        assert!(!SessionStage::DataLoaded.permits_queries());
    }

    #[test]
    fn count_tracks() {
        let r = CleanRoomSessionRegister::new();
        assert_eq!(r.count(), 0);
        r.provision(session("s1", "h", "q", 1_000_000)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn session_serde() {
        let s = session("s1", "h", "q", 1_000_000);
        let j = serde_json::to_string(&s).unwrap();
        let back: CleanRoomSession = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            SessionStage::Provisioned,
            SessionStage::DataLoaded,
            SessionStage::InUse,
            SessionStage::Sealed,
            SessionStage::Destroyed,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<SessionStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for p in [
            QueryPolicy::AggregateOnly,
            QueryPolicy::AllowList,
            QueryPolicy::DifferentialPrivacy,
            QueryPolicy::Sampling,
            QueryPolicy::Custom,
        ] {
            assert_eq!(
                p,
                serde_json::from_str::<QueryPolicy>(&serde_json::to_string(&p).unwrap()).unwrap()
            );
        }
        for s in [
            QueryStatus::Pending,
            QueryStatus::Running,
            QueryStatus::Completed,
            QueryStatus::Failed,
            QueryStatus::PolicyBlocked,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<QueryStatus>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
