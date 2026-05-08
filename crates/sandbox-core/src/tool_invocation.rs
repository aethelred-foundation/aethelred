//! Tool-use call tracking with arg/result hashes.
//!
//! When an [`crate::agent_session::AgentSession`] invokes a tool (search,
//! calculator, code execution, function calling), this module records the
//! invocation with structured arg / result hashes. Auditors can later ask
//! "what tools did this agent call?" with full per-call provenance.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// InvocationStatus
// =============================================================================

/// Per-call status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    /// Pending.
    Pending,
    /// Succeeded.
    Succeeded,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
    /// Timed out.
    TimedOut,
}

// =============================================================================
// ToolInvocation
// =============================================================================

/// One tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolInvocation {
    /// Stable id.
    pub invocation_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Session id (if part of an agent session).
    pub session_id: Option<Uuid>,
    /// Tool name.
    pub tool_name: String,
    /// Tool version.
    pub tool_version: String,
    /// SHA-256 of canonicalized arguments.
    pub args_hash: Sha256Digest,
    /// SHA-256 of canonicalized result.
    pub result_hash: Option<Sha256Digest>,
    /// Status.
    pub status: InvocationStatus,
    /// Error message if Failed.
    pub error: Option<String>,
    /// RFC 3339 invoked.
    pub invoked_at: String,
    /// RFC 3339 completed.
    pub completed_at: Option<String>,
    /// Duration in microseconds.
    pub duration_micros: Option<u64>,
}

// =============================================================================
// ToolRegistry
// =============================================================================

#[derive(Default)]
struct State {
    invocations: HashMap<Uuid, ToolInvocation>,
}

/// Registry.
pub struct ToolInvocationRegistry {
    state: RwLock<State>,
}

impl Default for ToolInvocationRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ToolInvocationRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolInvocationRegistry")
            .field("invocations", &self.len())
            .finish()
    }
}

impl ToolInvocationRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin a new invocation.
    pub fn begin(
        &self,
        tenant_id: impl Into<String>,
        session_id: Option<Uuid>,
        tool_name: impl Into<String>,
        tool_version: impl Into<String>,
        args: &[u8],
    ) -> SandboxResult<ToolInvocation> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let inv = ToolInvocation {
            invocation_id: Uuid::now_v7(),
            tenant_id: tenant_id.into(),
            session_id,
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            args_hash: Hasher::sha256(args),
            result_hash: None,
            status: InvocationStatus::Pending,
            error: None,
            invoked_at: now,
            completed_at: None,
            duration_micros: None,
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("tool registry poisoned".into()))?
            .invocations
            .insert(inv.invocation_id, inv.clone());
        Ok(inv)
    }

    /// Complete with result.
    pub fn complete(
        &self,
        invocation_id: Uuid,
        result: &[u8],
        duration_micros: u64,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tool registry poisoned".into()))?;
        let i = g
            .invocations
            .get_mut(&invocation_id)
            .ok_or_else(|| SandboxError::Other(format!("invocation {} not found", invocation_id)))?;
        if i.status != InvocationStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot complete invocation in state {:?}",
                i.status
            )));
        }
        i.status = InvocationStatus::Succeeded;
        i.result_hash = Some(Hasher::sha256(result));
        i.duration_micros = Some(duration_micros);
        i.completed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Mark failed.
    pub fn fail(
        &self,
        invocation_id: Uuid,
        error: impl Into<String>,
        duration_micros: u64,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tool registry poisoned".into()))?;
        let i = g
            .invocations
            .get_mut(&invocation_id)
            .ok_or_else(|| SandboxError::Other(format!("invocation {} not found", invocation_id)))?;
        if i.status != InvocationStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot fail invocation in state {:?}",
                i.status
            )));
        }
        i.status = InvocationStatus::Failed;
        i.error = Some(error.into());
        i.duration_micros = Some(duration_micros);
        i.completed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Mark cancelled or timed out.
    pub fn terminate(
        &self,
        invocation_id: Uuid,
        status: InvocationStatus,
    ) -> SandboxResult<()> {
        if !matches!(
            status,
            InvocationStatus::Cancelled | InvocationStatus::TimedOut
        ) {
            return Err(SandboxError::Other(
                "terminate must use Cancelled or TimedOut".into(),
            ));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("tool registry poisoned".into()))?;
        let i = g
            .invocations
            .get_mut(&invocation_id)
            .ok_or_else(|| SandboxError::Other(format!("invocation {} not found", invocation_id)))?;
        if i.status != InvocationStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot terminate in state {:?}",
                i.status
            )));
        }
        i.status = status;
        i.completed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<ToolInvocation> {
        self.state.read().ok()?.invocations.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ToolInvocation> {
        self.state
            .read()
            .map(|g| g.invocations.values().cloned().collect())
            .unwrap_or_default()
    }
    /// For session.
    pub fn for_session(&self, session_id: Uuid) -> Vec<ToolInvocation> {
        self.all()
            .into_iter()
            .filter(|i| i.session_id == Some(session_id))
            .collect()
    }
    /// For tool.
    pub fn for_tool(&self, tool: &str) -> Vec<ToolInvocation> {
        self.all().into_iter().filter(|i| i.tool_name == tool).collect()
    }
    /// By status.
    pub fn by_status(&self, status: InvocationStatus) -> Vec<ToolInvocation> {
        self.all().into_iter().filter(|i| i.status == status).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.invocations.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(reg: &ToolInvocationRegistry) -> ToolInvocation {
        reg.begin(
            "FAB",
            None,
            "calculator",
            "1.0",
            b"{\"a\":1,\"b\":2}",
        )
        .unwrap()
    }

    #[test]
    fn begin_creates_pending() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        assert_eq!(i.status, InvocationStatus::Pending);
        assert_eq!(i.args_hash, Hasher::sha256(b"{\"a\":1,\"b\":2}"));
    }

    #[test]
    fn complete_sets_success() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"3", 1500).unwrap();
        let updated = reg.get(i.invocation_id).unwrap();
        assert_eq!(updated.status, InvocationStatus::Succeeded);
        assert!(updated.result_hash.is_some());
        assert_eq!(updated.duration_micros, Some(1500));
    }

    #[test]
    fn fail_sets_failure() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.fail(i.invocation_id, "div by zero", 100).unwrap();
        let updated = reg.get(i.invocation_id).unwrap();
        assert_eq!(updated.status, InvocationStatus::Failed);
        assert_eq!(updated.error.as_deref(), Some("div by zero"));
    }

    #[test]
    fn terminate_cancelled() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.terminate(i.invocation_id, InvocationStatus::Cancelled).unwrap();
        assert_eq!(reg.get(i.invocation_id).unwrap().status, InvocationStatus::Cancelled);
    }

    #[test]
    fn terminate_invalid_status_errors() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        assert!(reg
            .terminate(i.invocation_id, InvocationStatus::Succeeded)
            .is_err());
    }

    #[test]
    fn cannot_complete_after_terminal() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"x", 100).unwrap();
        assert!(reg.complete(i.invocation_id, b"y", 100).is_err());
    }

    #[test]
    fn cannot_fail_after_terminal() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.fail(i.invocation_id, "x", 100).unwrap();
        assert!(reg.fail(i.invocation_id, "y", 100).is_err());
    }

    #[test]
    fn for_session_filters() {
        let reg = ToolInvocationRegistry::new();
        let sid = Uuid::now_v7();
        reg.begin("FAB", Some(sid), "calc", "1", b"x").unwrap();
        reg.begin("FAB", None, "calc", "1", b"y").unwrap();
        assert_eq!(reg.for_session(sid).len(), 1);
    }

    #[test]
    fn for_tool_filters() {
        let reg = ToolInvocationRegistry::new();
        reg.begin("FAB", None, "calc", "1", b"x").unwrap();
        reg.begin("FAB", None, "search", "1", b"y").unwrap();
        assert_eq!(reg.for_tool("calc").len(), 1);
        assert_eq!(reg.for_tool("search").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"x", 100).unwrap();
        begin(&reg);
        assert_eq!(reg.by_status(InvocationStatus::Succeeded).len(), 1);
        assert_eq!(reg.by_status(InvocationStatus::Pending).len(), 1);
    }

    #[test]
    fn invocation_serde() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        let j = serde_json::to_string(&i).unwrap();
        let p: ToolInvocation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, i);
    }

    #[test]
    fn status_serde() {
        for s in [
            InvocationStatus::Pending,
            InvocationStatus::Succeeded,
            InvocationStatus::Failed,
            InvocationStatus::Cancelled,
            InvocationStatus::TimedOut,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: InvocationStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn lookup_unknown_none() {
        let reg = ToolInvocationRegistry::new();
        assert!(reg.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn complete_unknown_errors() {
        let reg = ToolInvocationRegistry::new();
        assert!(reg.complete(Uuid::now_v7(), b"x", 100).is_err());
    }

    #[test]
    fn registry_count_tracks() {
        let reg = ToolInvocationRegistry::new();
        assert!(reg.is_empty());
        begin(&reg);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn args_hash_changes_with_args() {
        let reg = ToolInvocationRegistry::new();
        let i1 = reg.begin("FAB", None, "calc", "1", b"a").unwrap();
        let i2 = reg.begin("FAB", None, "calc", "1", b"b").unwrap();
        assert_ne!(i1.args_hash, i2.args_hash);
    }

    #[test]
    fn result_hash_recorded() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"42", 100).unwrap();
        let updated = reg.get(i.invocation_id).unwrap();
        assert_eq!(updated.result_hash, Some(Hasher::sha256(b"42")));
    }

    #[test]
    fn many_invocations_aggregate() {
        let reg = ToolInvocationRegistry::new();
        for _ in 0..50 {
            begin(&reg);
        }
        assert_eq!(reg.len(), 50);
    }

    #[test]
    fn duration_recorded_on_complete() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"x", 12345).unwrap();
        assert_eq!(reg.get(i.invocation_id).unwrap().duration_micros, Some(12345));
    }

    #[test]
    fn completed_at_set_after_complete() {
        let reg = ToolInvocationRegistry::new();
        let i = begin(&reg);
        reg.complete(i.invocation_id, b"x", 100).unwrap();
        assert!(reg.get(i.invocation_id).unwrap().completed_at.is_some());
    }
}
