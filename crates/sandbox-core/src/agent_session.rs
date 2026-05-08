//! Multi-turn agent session tracking.
//!
//! Records every turn of a multi-step agent session: user input, model
//! reasoning, tool calls, final response. Each session has a chain-evident
//! turn log so auditors can reconstruct the agent's full trajectory.
//!
//! Distinct from [`crate::workflow`] (orchestration of static steps) — this
//! module is for *dynamic* agent loops where the model decides what to do.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SessionStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Active.
    Active,
    /// Completed normally.
    Completed,
    /// Aborted by user.
    Aborted,
    /// Failed.
    Failed,
    /// Timed out.
    TimedOut,
}

// =============================================================================
// TurnRole
// =============================================================================

/// Role for a turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    /// User input.
    User,
    /// Assistant / model output.
    Assistant,
    /// Tool result returning to model.
    Tool,
    /// System prompt update.
    System,
}

// =============================================================================
// SessionTurn
// =============================================================================

/// One turn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTurn {
    /// Stable id within the session.
    pub turn_id: Uuid,
    /// Sequence number.
    pub seq: u32,
    /// Role.
    pub role: TurnRole,
    /// Content hash (raw text not stored — privacy by default).
    pub content_hash: Sha256Digest,
    /// Length of content in chars.
    pub content_len: u64,
    /// Optional content snippet (first 200 chars, redacted-safe).
    pub content_snippet: Option<String>,
    /// Tool name (if Tool role).
    pub tool_name: Option<String>,
    /// RFC 3339.
    pub at: String,
    /// Hash chain.
    pub prior_hash: Option<Sha256Digest>,
    /// Self hash.
    pub self_hash: Sha256Digest,
}

impl SessionTurn {
    fn compute_hash(
        seq: u32,
        role: TurnRole,
        content_hash: &Sha256Digest,
        prior: Option<&Sha256Digest>,
    ) -> Sha256Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.push(role_byte(role));
        buf.extend_from_slice(&content_hash.0);
        if let Some(p) = prior {
            buf.extend_from_slice(&p.0);
        }
        Hasher::sha256(&buf)
    }
}

fn role_byte(r: TurnRole) -> u8 {
    match r {
        TurnRole::User => 1,
        TurnRole::Assistant => 2,
        TurnRole::Tool => 3,
        TurnRole::System => 4,
    }
}

// =============================================================================
// AgentSession
// =============================================================================

/// One agent session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSession {
    /// Session id.
    pub session_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Agent / model id.
    pub agent_id: String,
    /// Model version.
    pub model_version: String,
    /// User who initiated.
    pub user_id: String,
    /// Turns.
    pub turns: Vec<SessionTurn>,
    /// Status.
    pub status: SessionStatus,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 ended.
    pub ended_at: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
}

impl AgentSession {
    /// Number of user turns.
    pub fn user_turn_count(&self) -> usize {
        self.turns.iter().filter(|t| t.role == TurnRole::User).count()
    }
    /// Number of tool calls.
    pub fn tool_call_count(&self) -> usize {
        self.turns.iter().filter(|t| t.role == TurnRole::Tool).count()
    }
    /// Total content length across turns.
    pub fn total_content_length(&self) -> u64 {
        self.turns.iter().map(|t| t.content_len).sum()
    }
}

// =============================================================================
// AgentSessionRegistry
// =============================================================================

#[derive(Default)]
struct State {
    sessions: HashMap<Uuid, AgentSession>,
}

/// Registry.
pub struct AgentSessionRegistry {
    state: RwLock<State>,
}

impl Default for AgentSessionRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for AgentSessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSessionRegistry")
            .field("sessions", &self.len())
            .finish()
    }
}

impl AgentSessionRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a session.
    pub fn open(
        &self,
        tenant_id: impl Into<String>,
        agent_id: impl Into<String>,
        model_version: impl Into<String>,
        user_id: impl Into<String>,
    ) -> SandboxResult<AgentSession> {
        let s = AgentSession {
            session_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            agent_id: agent_id.into(),
            model_version: model_version.into(),
            user_id: user_id.into(),
            turns: Vec::new(),
            status: SessionStatus::Active,
            started_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            ended_at: None,
            tags: Vec::new(),
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("agent registry poisoned".into()))?
            .sessions
            .insert(s.session_id, s.clone());
        Ok(s)
    }

    /// Add a turn.
    pub fn record_turn(
        &self,
        session_id: Uuid,
        role: TurnRole,
        content: &str,
        snippet: Option<String>,
        tool_name: Option<String>,
    ) -> SandboxResult<SessionTurn> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("agent registry poisoned".into()))?;
        let s = g
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| SandboxError::Other(format!("session {} not found", session_id)))?;
        if s.status != SessionStatus::Active {
            return Err(SandboxError::Other(format!(
                "cannot add turn to session in state {:?}",
                s.status
            )));
        }
        let seq = (s.turns.len() as u32) + 1;
        let content_hash = Hasher::sha256(content.as_bytes());
        let prior = s.turns.last().map(|t| t.self_hash.clone());
        let self_hash = SessionTurn::compute_hash(seq, role, &content_hash, prior.as_ref());
        let turn = SessionTurn {
            turn_id: Uuid::now_v7(),
            seq,
            role,
            content_hash,
            content_len: content.len() as u64,
            content_snippet: snippet,
            tool_name,
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            prior_hash: prior,
            self_hash,
        };
        s.turns.push(turn.clone());
        Ok(turn)
    }

    /// Set status (terminal sets ended_at).
    pub fn set_status(&self, session_id: Uuid, status: SessionStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("agent registry poisoned".into()))?;
        let s = g
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| SandboxError::Other(format!("session {} not found", session_id)))?;
        let terminal = matches!(
            status,
            SessionStatus::Completed
                | SessionStatus::Aborted
                | SessionStatus::Failed
                | SessionStatus::TimedOut
        );
        s.status = status;
        if terminal && s.ended_at.is_none() {
            s.ended_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    /// Tag a session.
    pub fn add_tag(&self, session_id: Uuid, tag: impl Into<String>) -> SandboxResult<()> {
        let tag = tag.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("agent registry poisoned".into()))?;
        let s = g
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| SandboxError::Other(format!("session {} not found", session_id)))?;
        if !s.tags.contains(&tag) {
            s.tags.push(tag);
        }
        Ok(())
    }

    /// Verify chain.
    pub fn verify_chain(&self, session_id: Uuid) -> SandboxResult<()> {
        let s = self
            .get(session_id)
            .ok_or_else(|| SandboxError::Other(format!("session {} not found", session_id)))?;
        let mut prior: Option<Sha256Digest> = None;
        for (i, t) in s.turns.iter().enumerate() {
            match (&t.prior_hash, &prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "session {} chain break at turn {}",
                        session_id, i
                    )))
                }
            }
            let recomputed = SessionTurn::compute_hash(
                t.seq,
                t.role,
                &t.content_hash,
                t.prior_hash.as_ref(),
            );
            if recomputed != t.self_hash {
                return Err(SandboxError::Other(format!(
                    "session {} turn {} hash mismatch",
                    session_id, i
                )));
            }
            prior = Some(t.self_hash.clone());
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<AgentSession> {
        self.state.read().ok()?.sessions.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<AgentSession> {
        self.state
            .read()
            .map(|g| g.sessions.values().cloned().collect())
            .unwrap_or_default()
    }
    /// By tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<AgentSession> {
        self.all().into_iter().filter(|s| s.tenant_id == tenant).collect()
    }
    /// By user.
    pub fn for_user(&self, user: &str) -> Vec<AgentSession> {
        self.all().into_iter().filter(|s| s.user_id == user).collect()
    }
    /// By status.
    pub fn by_status(&self, status: SessionStatus) -> Vec<AgentSession> {
        self.all().into_iter().filter(|s| s.status == status).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.sessions.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(reg: &AgentSessionRegistry) -> AgentSession {
        reg.open("FAB", "credit-agent", "1.0", "user-1").unwrap()
    }

    #[test]
    fn open_creates_session() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        assert_eq!(s.status, SessionStatus::Active);
        assert!(s.turns.is_empty());
    }

    #[test]
    fn record_turn_chains() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let t1 = reg
            .record_turn(s.session_id, TurnRole::User, "hi", None, None)
            .unwrap();
        let t2 = reg
            .record_turn(s.session_id, TurnRole::Assistant, "hello", None, None)
            .unwrap();
        assert!(t1.prior_hash.is_none());
        assert_eq!(t2.prior_hash, Some(t1.self_hash));
    }

    #[test]
    fn record_turn_stores_hash_not_content() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let t = reg
            .record_turn(s.session_id, TurnRole::User, "secret content", None, None)
            .unwrap();
        assert_eq!(t.content_hash, Hasher::sha256(b"secret content"));
        assert_eq!(t.content_len, 14);
    }

    #[test]
    fn record_turn_with_snippet_stores() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let t = reg
            .record_turn(
                s.session_id,
                TurnRole::User,
                "long body",
                Some("first 9 chars".into()),
                None,
            )
            .unwrap();
        assert_eq!(t.content_snippet.as_deref(), Some("first 9 chars"));
    }

    #[test]
    fn record_turn_after_terminal_errors() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.set_status(s.session_id, SessionStatus::Completed).unwrap();
        assert!(reg
            .record_turn(s.session_id, TurnRole::User, "x", None, None)
            .is_err());
    }

    #[test]
    fn set_status_completed_sets_ended() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.set_status(s.session_id, SessionStatus::Completed).unwrap();
        assert!(reg.get(s.session_id).unwrap().ended_at.is_some());
    }

    #[test]
    fn user_turn_count() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.record_turn(s.session_id, TurnRole::User, "a", None, None).unwrap();
        reg.record_turn(s.session_id, TurnRole::Assistant, "b", None, None)
            .unwrap();
        reg.record_turn(s.session_id, TurnRole::User, "c", None, None).unwrap();
        let updated = reg.get(s.session_id).unwrap();
        assert_eq!(updated.user_turn_count(), 2);
    }

    #[test]
    fn tool_call_count() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.record_turn(
            s.session_id,
            TurnRole::Tool,
            "result",
            None,
            Some("calc".into()),
        )
        .unwrap();
        let updated = reg.get(s.session_id).unwrap();
        assert_eq!(updated.tool_call_count(), 1);
    }

    #[test]
    fn total_content_length_sums() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.record_turn(s.session_id, TurnRole::User, "abc", None, None).unwrap();
        reg.record_turn(s.session_id, TurnRole::Assistant, "wxyz", None, None)
            .unwrap();
        let updated = reg.get(s.session_id).unwrap();
        assert_eq!(updated.total_content_length(), 7);
    }

    #[test]
    fn add_tag_dedupes() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.add_tag(s.session_id, "fraud").unwrap();
        reg.add_tag(s.session_id, "fraud").unwrap();
        let updated = reg.get(s.session_id).unwrap();
        assert_eq!(updated.tags, vec!["fraud"]);
    }

    #[test]
    fn verify_chain_passes() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        for r in [TurnRole::User, TurnRole::Assistant, TurnRole::User] {
            reg.record_turn(s.session_id, r, "x", None, None).unwrap();
        }
        reg.verify_chain(s.session_id).unwrap();
    }

    #[test]
    fn verify_unknown_errors() {
        let reg = AgentSessionRegistry::new();
        assert!(reg.verify_chain(Uuid::now_v7()).is_err());
    }

    #[test]
    fn for_tenant_filters() {
        let reg = AgentSessionRegistry::new();
        open(&reg);
        reg.open("ENBD", "agent", "1", "user").unwrap();
        assert_eq!(reg.for_tenant("FAB").len(), 1);
        assert_eq!(reg.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn for_user_filters() {
        let reg = AgentSessionRegistry::new();
        open(&reg);
        reg.open("FAB", "agent", "1", "user-2").unwrap();
        assert_eq!(reg.for_user("user-1").len(), 1);
        assert_eq!(reg.for_user("user-2").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        reg.set_status(s.session_id, SessionStatus::Completed).unwrap();
        open(&reg);
        assert_eq!(reg.by_status(SessionStatus::Completed).len(), 1);
        assert_eq!(reg.by_status(SessionStatus::Active).len(), 1);
    }

    #[test]
    fn turn_serde() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let t = reg
            .record_turn(s.session_id, TurnRole::User, "hi", None, None)
            .unwrap();
        let j = serde_json::to_string(&t).unwrap();
        let p: SessionTurn = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn session_serde() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let j = serde_json::to_string(&s).unwrap();
        let p: AgentSession = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn role_serde() {
        for r in [
            TurnRole::User,
            TurnRole::Assistant,
            TurnRole::Tool,
            TurnRole::System,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let p: TurnRole = serde_json::from_str(&j).unwrap();
            assert_eq!(p, r);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            SessionStatus::Active,
            SessionStatus::Completed,
            SessionStatus::Aborted,
            SessionStatus::Failed,
            SessionStatus::TimedOut,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: SessionStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn unknown_session_returns_none() {
        let reg = AgentSessionRegistry::new();
        assert!(reg.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn count_tracks() {
        let reg = AgentSessionRegistry::new();
        assert!(reg.is_empty());
        open(&reg);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn many_turns_chain_intact() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        for _ in 0..30 {
            reg.record_turn(s.session_id, TurnRole::User, "x", None, None).unwrap();
        }
        reg.verify_chain(s.session_id).unwrap();
    }

    #[test]
    fn tool_name_recorded() {
        let reg = AgentSessionRegistry::new();
        let s = open(&reg);
        let t = reg
            .record_turn(
                s.session_id,
                TurnRole::Tool,
                "result",
                None,
                Some("calculator".into()),
            )
            .unwrap();
        assert_eq!(t.tool_name.as_deref(), Some("calculator"));
    }
}
