//! Sandbox cloning for testing / staging.
//!
//! Lets operators clone an existing tenant sandbox into a new tenant id for
//! testing without affecting production. Clones can include or exclude:
//!
//! - Seal evidence
//! - Policy versions
//! - Workflows
//! - Audit logs
//! - Customer consent records
//!
//! Each clone produces a [`CloneRecord`] with a redaction policy, source
//! tenant, target tenant, and what was copied.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// CloneScope
// =============================================================================

/// What to include in the clone.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloneScope {
    /// Include seals.
    pub include_seals: bool,
    /// Include policies.
    pub include_policies: bool,
    /// Include workflows.
    pub include_workflows: bool,
    /// Include audit logs.
    pub include_audit: bool,
    /// Include consent records.
    pub include_consent: bool,
    /// Include feature flags.
    pub include_feature_flags: bool,
    /// Include API keys.
    pub include_api_keys: bool,
}

impl CloneScope {
    /// All-on scope (full clone).
    pub fn full() -> Self {
        Self {
            include_seals: true,
            include_policies: true,
            include_workflows: true,
            include_audit: true,
            include_consent: true,
            include_feature_flags: true,
            include_api_keys: true,
        }
    }
    /// Policies + workflows only (config-only clone).
    pub fn config_only() -> Self {
        Self {
            include_seals: false,
            include_policies: true,
            include_workflows: true,
            include_audit: false,
            include_consent: false,
            include_feature_flags: true,
            include_api_keys: false,
        }
    }
}

// =============================================================================
// RedactionPolicy
// =============================================================================

/// How to handle PII in the clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionPolicy {
    /// Pass through unchanged (production -> production-like staging).
    None,
    /// Replace PII with hashes.
    HashOnly,
    /// Drop fields that contain PII entirely.
    DropPii,
    /// Synthesize fake values.
    Synthesize,
}

// =============================================================================
// CloneStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloneStatus {
    /// Pending.
    Pending,
    /// Running.
    Running,
    /// Completed.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

// =============================================================================
// CloneRecord
// =============================================================================

/// One clone operation record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloneRecord {
    /// Stable id.
    pub clone_id: Uuid,
    /// Source tenant.
    pub source_tenant_id: String,
    /// Target tenant.
    pub target_tenant_id: String,
    /// Scope.
    pub scope: CloneScope,
    /// Redaction policy.
    pub redaction_policy: RedactionPolicy,
    /// Status.
    pub status: CloneStatus,
    /// RFC 3339 started.
    pub started_at: String,
    /// RFC 3339 completed.
    pub completed_at: Option<String>,
    /// Per-category counts of items copied.
    pub items_copied: HashMap<String, u64>,
    /// Optional error message.
    pub error: Option<String>,
    /// Snapshot hash of source state at clone time.
    pub source_snapshot_hash: Sha256Digest,
    /// Operator who initiated.
    pub initiated_by: String,
    /// Free-text reason.
    pub reason: String,
}

impl CloneRecord {
    /// Total items copied across categories.
    pub fn total_items(&self) -> u64 {
        self.items_copied.values().sum()
    }
}

// =============================================================================
// SandboxCloneRegistry
// =============================================================================

#[derive(Default)]
struct State {
    clones: HashMap<Uuid, CloneRecord>,
}

/// Registry.
pub struct SandboxCloneRegistry {
    state: RwLock<State>,
}

impl Default for SandboxCloneRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for SandboxCloneRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxCloneRegistry")
            .field("clones", &self.len())
            .finish()
    }
}

impl SandboxCloneRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a clone request.
    pub fn open(
        &self,
        source_tenant: impl Into<String>,
        target_tenant: impl Into<String>,
        scope: CloneScope,
        redaction_policy: RedactionPolicy,
        initiated_by: impl Into<String>,
        reason: impl Into<String>,
        source_snapshot: &[u8],
    ) -> SandboxResult<CloneRecord> {
        let source = source_tenant.into();
        let target = target_tenant.into();
        if source == target {
            return Err(SandboxError::Other(
                "source and target tenants must differ".into(),
            ));
        }
        let r = CloneRecord {
            clone_id: Uuid::now_v7(),
            source_tenant_id: source,
            target_tenant_id: target,
            scope,
            redaction_policy,
            status: CloneStatus::Pending,
            started_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            completed_at: None,
            items_copied: HashMap::new(),
            error: None,
            source_snapshot_hash: Hasher::sha256(source_snapshot),
            initiated_by: initiated_by.into(),
            reason: reason.into(),
        };
        self.state
            .write()
            .map_err(|_| SandboxError::Other("clone registry poisoned".into()))?
            .clones
            .insert(r.clone_id, r.clone());
        Ok(r)
    }

    /// Mark running.
    pub fn begin(&self, clone_id: Uuid) -> SandboxResult<()> {
        self.transition(clone_id, CloneStatus::Running)
    }

    /// Record items copied for a category.
    pub fn record_items(
        &self,
        clone_id: Uuid,
        category: impl Into<String>,
        count: u64,
    ) -> SandboxResult<()> {
        let category = category.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("clone registry poisoned".into()))?;
        let r = g
            .clones
            .get_mut(&clone_id)
            .ok_or_else(|| SandboxError::Other(format!("clone {} not found", clone_id)))?;
        if r.status != CloneStatus::Running {
            return Err(SandboxError::Other(format!(
                "cannot record items in state {:?}",
                r.status
            )));
        }
        *r.items_copied.entry(category).or_insert(0) += count;
        Ok(())
    }

    /// Complete.
    pub fn complete(&self, clone_id: Uuid) -> SandboxResult<()> {
        self.transition(clone_id, CloneStatus::Completed)
    }

    /// Fail.
    pub fn fail(&self, clone_id: Uuid, error: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("clone registry poisoned".into()))?;
        let r = g
            .clones
            .get_mut(&clone_id)
            .ok_or_else(|| SandboxError::Other(format!("clone {} not found", clone_id)))?;
        r.status = CloneStatus::Failed;
        r.error = Some(error.into());
        r.completed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Cancel.
    pub fn cancel(&self, clone_id: Uuid) -> SandboxResult<()> {
        self.transition(clone_id, CloneStatus::Cancelled)
    }

    fn transition(&self, clone_id: Uuid, target: CloneStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("clone registry poisoned".into()))?;
        let r = g
            .clones
            .get_mut(&clone_id)
            .ok_or_else(|| SandboxError::Other(format!("clone {} not found", clone_id)))?;
        match (r.status, target) {
            (CloneStatus::Pending, CloneStatus::Running) => {}
            (CloneStatus::Running, CloneStatus::Completed) => {}
            (CloneStatus::Pending, CloneStatus::Cancelled) => {}
            (CloneStatus::Running, CloneStatus::Cancelled) => {}
            _ => {
                return Err(SandboxError::Other(format!(
                    "illegal transition {:?} -> {:?}",
                    r.status, target
                )))
            }
        }
        r.status = target;
        if matches!(
            target,
            CloneStatus::Completed | CloneStatus::Cancelled
        ) {
            r.completed_at = Some(
                OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<CloneRecord> {
        self.state.read().ok()?.clones.get(&id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<CloneRecord> {
        self.state
            .read()
            .map(|g| g.clones.values().cloned().collect())
            .unwrap_or_default()
    }

    /// By target tenant.
    pub fn for_target(&self, tenant: &str) -> Vec<CloneRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.target_tenant_id == tenant)
            .collect()
    }

    /// By status.
    pub fn by_status(&self, status: CloneStatus) -> Vec<CloneRecord> {
        self.all().into_iter().filter(|r| r.status == status).collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.clones.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(reg: &SandboxCloneRegistry) -> CloneRecord {
        reg.open(
            "FAB-prod",
            "FAB-staging",
            CloneScope::full(),
            RedactionPolicy::HashOnly,
            "ops",
            "QA test",
            b"snapshot",
        )
        .unwrap()
    }

    #[test]
    fn open_creates_pending() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        assert_eq!(r.status, CloneStatus::Pending);
    }

    #[test]
    fn same_source_target_errors() {
        let reg = SandboxCloneRegistry::new();
        assert!(reg
            .open(
                "FAB",
                "FAB",
                CloneScope::full(),
                RedactionPolicy::None,
                "ops",
                "x",
                b"x"
            )
            .is_err());
    }

    #[test]
    fn begin_advances() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        assert_eq!(reg.get(r.clone_id).unwrap().status, CloneStatus::Running);
    }

    #[test]
    fn record_items_accumulates() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        reg.record_items(r.clone_id, "seals", 100).unwrap();
        reg.record_items(r.clone_id, "seals", 50).unwrap();
        reg.record_items(r.clone_id, "policies", 5).unwrap();
        let updated = reg.get(r.clone_id).unwrap();
        assert_eq!(updated.items_copied["seals"], 150);
        assert_eq!(updated.items_copied["policies"], 5);
        assert_eq!(updated.total_items(), 155);
    }

    #[test]
    fn record_items_pending_errors() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        assert!(reg.record_items(r.clone_id, "seals", 1).is_err());
    }

    #[test]
    fn complete_after_running() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        reg.complete(r.clone_id).unwrap();
        let updated = reg.get(r.clone_id).unwrap();
        assert_eq!(updated.status, CloneStatus::Completed);
        assert!(updated.completed_at.is_some());
    }

    #[test]
    fn cannot_complete_pending() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        assert!(reg.complete(r.clone_id).is_err());
    }

    #[test]
    fn fail_records_error() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.fail(r.clone_id, "disk full").unwrap();
        let updated = reg.get(r.clone_id).unwrap();
        assert_eq!(updated.status, CloneStatus::Failed);
        assert_eq!(updated.error.as_deref(), Some("disk full"));
    }

    #[test]
    fn cancel_pending_works() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.cancel(r.clone_id).unwrap();
        assert_eq!(reg.get(r.clone_id).unwrap().status, CloneStatus::Cancelled);
    }

    #[test]
    fn cancel_running_works() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        reg.cancel(r.clone_id).unwrap();
        assert_eq!(reg.get(r.clone_id).unwrap().status, CloneStatus::Cancelled);
    }

    #[test]
    fn cannot_cancel_completed() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        reg.complete(r.clone_id).unwrap();
        assert!(reg.cancel(r.clone_id).is_err());
    }

    #[test]
    fn snapshot_hash_recorded() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        assert_eq!(r.source_snapshot_hash, Hasher::sha256(b"snapshot"));
    }

    #[test]
    fn config_only_scope() {
        let s = CloneScope::config_only();
        assert!(!s.include_seals);
        assert!(s.include_policies);
        assert!(s.include_workflows);
        assert!(!s.include_audit);
    }

    #[test]
    fn full_scope() {
        let s = CloneScope::full();
        assert!(s.include_seals);
        assert!(s.include_policies);
        assert!(s.include_audit);
        assert!(s.include_api_keys);
    }

    #[test]
    fn for_target_filters() {
        let reg = SandboxCloneRegistry::new();
        open(&reg);
        reg.open(
            "FAB-prod",
            "FAB-dev",
            CloneScope::full(),
            RedactionPolicy::None,
            "ops",
            "x",
            b"x",
        )
        .unwrap();
        assert_eq!(reg.for_target("FAB-staging").len(), 1);
        assert_eq!(reg.for_target("FAB-dev").len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        reg.begin(r.clone_id).unwrap();
        reg.complete(r.clone_id).unwrap();
        open(&reg);
        assert_eq!(reg.by_status(CloneStatus::Completed).len(), 1);
        assert_eq!(reg.by_status(CloneStatus::Pending).len(), 1);
    }

    #[test]
    fn record_serde() {
        let reg = SandboxCloneRegistry::new();
        let r = open(&reg);
        let j = serde_json::to_string(&r).unwrap();
        let p: CloneRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn scope_serde() {
        let s = CloneScope::full();
        let j = serde_json::to_string(&s).unwrap();
        let p: CloneScope = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn policy_serde() {
        for p in [
            RedactionPolicy::None,
            RedactionPolicy::HashOnly,
            RedactionPolicy::DropPii,
            RedactionPolicy::Synthesize,
        ] {
            let j = serde_json::to_string(&p).unwrap();
            let q: RedactionPolicy = serde_json::from_str(&j).unwrap();
            assert_eq!(p, q);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            CloneStatus::Pending,
            CloneStatus::Running,
            CloneStatus::Completed,
            CloneStatus::Failed,
            CloneStatus::Cancelled,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CloneStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn count_tracks() {
        let reg = SandboxCloneRegistry::new();
        assert!(reg.is_empty());
        open(&reg);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn lookup_unknown_none() {
        let reg = SandboxCloneRegistry::new();
        assert!(reg.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn many_clones_aggregate() {
        let reg = SandboxCloneRegistry::new();
        for _ in 0..10 {
            open(&reg);
        }
        assert_eq!(reg.len(), 10);
    }
}
