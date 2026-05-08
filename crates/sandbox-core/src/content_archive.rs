//! Content lifecycle (active / archived / deleted).
//!
//! Generic content lifecycle wrapper for any addressable resource —
//! seal bundles, evidence packages, model versions, deprecated dashboards.
//! Each entry has stages with timestamps; the `delete` is logical,
//! not physical (composes with [`crate::retention_purge`] for physical).

use crate::hashing::Sha256Digest;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// LifecycleStage
// =============================================================================

/// Per-entry stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    /// Active.
    Active,
    /// Archived (not visible by default).
    Archived,
    /// Deleted (logical).
    Deleted,
    /// Restored (post-deletion recovery).
    Restored,
}

// =============================================================================
// LifecycleTransition
// =============================================================================

/// One state transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleTransition {
    /// To stage.
    pub to_stage: LifecycleStage,
    /// Actor.
    pub actor: String,
    /// Reason.
    pub reason: Option<String>,
    /// RFC 3339.
    pub at: String,
}

// =============================================================================
// ContentEntry
// =============================================================================

/// One content entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContentEntry {
    /// Stable id.
    pub entry_id: Uuid,
    /// External resource id (e.g. `"seal:abc"`).
    pub resource_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Kind (free-form, e.g. `"seal_bundle"`, `"evidence_package"`).
    pub kind: String,
    /// Hash of the underlying content.
    pub content_hash: Sha256Digest,
    /// Current stage.
    pub current_stage: LifecycleStage,
    /// Owner.
    pub owner: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Transitions.
    pub history: Vec<LifecycleTransition>,
    /// RFC 3339 created.
    pub created_at: String,
}

impl ContentEntry {
    /// Most-recent transition.
    pub fn latest_transition(&self) -> Option<&LifecycleTransition> {
        self.history.last()
    }
    /// `true` if currently active.
    pub fn is_active(&self) -> bool {
        matches!(self.current_stage, LifecycleStage::Active | LifecycleStage::Restored)
    }
}

// =============================================================================
// ContentArchive
// =============================================================================

#[derive(Default)]
struct State {
    entries: HashMap<Uuid, ContentEntry>,
    by_resource: HashMap<String, Uuid>,
}

/// Archive.
pub struct ContentArchive {
    state: RwLock<State>,
}

impl Default for ContentArchive {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ContentArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentArchive").field("entries", &self.len()).finish()
    }
}

impl ContentArchive {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new entry as Active.
    pub fn register(
        &self,
        resource_id: impl Into<String>,
        tenant_id: impl Into<String>,
        kind: impl Into<String>,
        content_hash: Sha256Digest,
        owner: impl Into<String>,
    ) -> SandboxResult<ContentEntry> {
        let resource_id = resource_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("content archive poisoned".into()))?;
        if g.by_resource.contains_key(&resource_id) {
            return Err(SandboxError::Other(format!(
                "resource {} already registered",
                resource_id
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let entry = ContentEntry {
            entry_id: Uuid::now_v7(),
            resource_id: resource_id.clone(),
            tenant_id: tenant_id.into(),
            kind: kind.into(),
            content_hash,
            current_stage: LifecycleStage::Active,
            owner: owner.into(),
            tags: Vec::new(),
            history: vec![LifecycleTransition {
                to_stage: LifecycleStage::Active,
                actor: "system".into(),
                reason: Some("registered".into()),
                at: now.clone(),
            }],
            created_at: now,
        };
        g.by_resource.insert(resource_id, entry.entry_id);
        g.entries.insert(entry.entry_id, entry.clone());
        Ok(entry)
    }

    /// Transition stage.
    pub fn transition(
        &self,
        entry_id: Uuid,
        to_stage: LifecycleStage,
        actor: impl Into<String>,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let actor = actor.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("content archive poisoned".into()))?;
        let e = g
            .entries
            .get_mut(&entry_id)
            .ok_or_else(|| SandboxError::Other(format!("entry {} not found", entry_id)))?;
        if !legal_transition(e.current_stage, to_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                e.current_stage, to_stage
            )));
        }
        e.current_stage = to_stage;
        e.history.push(LifecycleTransition {
            to_stage,
            actor,
            reason,
            at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        });
        Ok(())
    }

    /// Add a tag.
    pub fn add_tag(&self, entry_id: Uuid, tag: impl Into<String>) -> SandboxResult<()> {
        let tag = tag.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("content archive poisoned".into()))?;
        let e = g
            .entries
            .get_mut(&entry_id)
            .ok_or_else(|| SandboxError::Other(format!("entry {} not found", entry_id)))?;
        if !e.tags.contains(&tag) {
            e.tags.push(tag);
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, entry_id: Uuid) -> Option<ContentEntry> {
        self.state.read().ok()?.entries.get(&entry_id).cloned()
    }

    /// Lookup by resource id.
    pub fn by_resource(&self, resource_id: &str) -> Option<ContentEntry> {
        let g = self.state.read().ok()?;
        let id = g.by_resource.get(resource_id)?;
        g.entries.get(id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<ContentEntry> {
        self.state
            .read()
            .map(|g| g.entries.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Filter by stage.
    pub fn by_stage(&self, stage: LifecycleStage) -> Vec<ContentEntry> {
        self.all()
            .into_iter()
            .filter(|e| e.current_stage == stage)
            .collect()
    }

    /// Filter by kind.
    pub fn by_kind(&self, kind: &str) -> Vec<ContentEntry> {
        self.all().into_iter().filter(|e| e.kind == kind).collect()
    }

    /// Filter by tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<ContentEntry> {
        self.all().into_iter().filter(|e| e.tenant_id == tenant).collect()
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.entries.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn legal_transition(from: LifecycleStage, to: LifecycleStage) -> bool {
    use LifecycleStage::*;
    matches!(
        (from, to),
        (Active, Archived)
            | (Active, Deleted)
            | (Archived, Active)
            | (Archived, Deleted)
            | (Deleted, Restored)
            | (Restored, Archived)
            | (Restored, Deleted)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    fn register(a: &ContentArchive) -> ContentEntry {
        a.register(
            "seal:abc",
            "FAB",
            "seal_bundle",
            Hasher::sha256(b"content"),
            "ops",
        )
        .unwrap()
    }

    #[test]
    fn register_creates_active() {
        let a = ContentArchive::new();
        let e = register(&a);
        assert_eq!(e.current_stage, LifecycleStage::Active);
        assert_eq!(e.history.len(), 1);
    }

    #[test]
    fn duplicate_resource_errors() {
        let a = ContentArchive::new();
        register(&a);
        assert!(a
            .register(
                "seal:abc",
                "FAB",
                "x",
                Hasher::sha256(b"y"),
                "ops"
            )
            .is_err());
    }

    #[test]
    fn active_to_archived_works() {
        let a = ContentArchive::new();
        let e = register(&a);
        a.transition(e.entry_id, LifecycleStage::Archived, "ops", None).unwrap();
        assert_eq!(a.get(e.entry_id).unwrap().current_stage, LifecycleStage::Archived);
    }

    #[test]
    fn archived_to_active_works() {
        let a = ContentArchive::new();
        let e = register(&a);
        a.transition(e.entry_id, LifecycleStage::Archived, "ops", None).unwrap();
        a.transition(e.entry_id, LifecycleStage::Active, "ops", None).unwrap();
        assert_eq!(a.get(e.entry_id).unwrap().current_stage, LifecycleStage::Active);
    }

    #[test]
    fn deleted_to_restored() {
        let a = ContentArchive::new();
        let e = register(&a);
        a.transition(e.entry_id, LifecycleStage::Deleted, "ops", None).unwrap();
        a.transition(e.entry_id, LifecycleStage::Restored, "ops", None).unwrap();
        assert_eq!(
            a.get(e.entry_id).unwrap().current_stage,
            LifecycleStage::Restored
        );
    }

    #[test]
    fn illegal_transition_errors() {
        let a = ContentArchive::new();
        let e = register(&a);
        // Active → Restored is illegal.
        assert!(a
            .transition(e.entry_id, LifecycleStage::Restored, "ops", None)
            .is_err());
    }

    #[test]
    fn add_tag_dedupes() {
        let a = ContentArchive::new();
        let e = register(&a);
        a.add_tag(e.entry_id, "regulator").unwrap();
        a.add_tag(e.entry_id, "regulator").unwrap();
        assert_eq!(a.get(e.entry_id).unwrap().tags.len(), 1);
    }

    #[test]
    fn by_resource_lookup() {
        let a = ContentArchive::new();
        register(&a);
        assert!(a.by_resource("seal:abc").is_some());
        assert!(a.by_resource("ghost").is_none());
    }

    #[test]
    fn by_stage_filters() {
        let a = ContentArchive::new();
        let e1 = register(&a);
        let e2 = a
            .register(
                "seal:def",
                "FAB",
                "seal_bundle",
                Hasher::sha256(b"x"),
                "ops",
            )
            .unwrap();
        a.transition(e2.entry_id, LifecycleStage::Archived, "ops", None).unwrap();
        assert_eq!(a.by_stage(LifecycleStage::Active).len(), 1);
        assert_eq!(a.by_stage(LifecycleStage::Archived).len(), 1);
        let _ = e1;
    }

    #[test]
    fn by_kind_filters() {
        let a = ContentArchive::new();
        register(&a);
        a.register(
            "ev:1",
            "FAB",
            "evidence_package",
            Hasher::sha256(b"x"),
            "ops",
        )
        .unwrap();
        assert_eq!(a.by_kind("seal_bundle").len(), 1);
        assert_eq!(a.by_kind("evidence_package").len(), 1);
    }

    #[test]
    fn for_tenant_filters() {
        let a = ContentArchive::new();
        register(&a);
        a.register(
            "seal:def",
            "ENBD",
            "seal_bundle",
            Hasher::sha256(b"x"),
            "ops",
        )
        .unwrap();
        assert_eq!(a.for_tenant("FAB").len(), 1);
        assert_eq!(a.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn latest_transition_records() {
        let a = ContentArchive::new();
        let e = register(&a);
        a.transition(e.entry_id, LifecycleStage::Archived, "ops", Some("Q2 cleanup".into()))
            .unwrap();
        let updated = a.get(e.entry_id).unwrap();
        let last = updated.latest_transition().unwrap();
        assert_eq!(last.to_stage, LifecycleStage::Archived);
        assert_eq!(last.reason.as_deref(), Some("Q2 cleanup"));
    }

    #[test]
    fn is_active_helper() {
        let a = ContentArchive::new();
        let e = register(&a);
        assert!(a.get(e.entry_id).unwrap().is_active());
        a.transition(e.entry_id, LifecycleStage::Deleted, "ops", None).unwrap();
        assert!(!a.get(e.entry_id).unwrap().is_active());
        a.transition(e.entry_id, LifecycleStage::Restored, "ops", None).unwrap();
        assert!(a.get(e.entry_id).unwrap().is_active());
    }

    #[test]
    fn legal_transitions_table() {
        assert!(legal_transition(LifecycleStage::Active, LifecycleStage::Archived));
        assert!(legal_transition(LifecycleStage::Active, LifecycleStage::Deleted));
        assert!(legal_transition(LifecycleStage::Archived, LifecycleStage::Active));
        assert!(legal_transition(LifecycleStage::Deleted, LifecycleStage::Restored));
        assert!(legal_transition(LifecycleStage::Restored, LifecycleStage::Deleted));
        assert!(!legal_transition(LifecycleStage::Deleted, LifecycleStage::Active));
        assert!(!legal_transition(LifecycleStage::Active, LifecycleStage::Restored));
    }

    #[test]
    fn entry_serde() {
        let a = ContentArchive::new();
        let e = register(&a);
        let j = serde_json::to_string(&e).unwrap();
        let p: ContentEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn transition_serde() {
        let t = LifecycleTransition {
            to_stage: LifecycleStage::Active,
            actor: "x".into(),
            reason: Some("y".into()),
            at: "t".into(),
        };
        let j = serde_json::to_string(&t).unwrap();
        let p: LifecycleTransition = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn stage_serde() {
        for s in [
            LifecycleStage::Active,
            LifecycleStage::Archived,
            LifecycleStage::Deleted,
            LifecycleStage::Restored,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: LifecycleStage = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn count_tracks() {
        let a = ContentArchive::new();
        assert!(a.is_empty());
        register(&a);
        assert_eq!(a.len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let a = ContentArchive::new();
        assert!(a.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn many_transitions_recorded() {
        let a = ContentArchive::new();
        let e = register(&a);
        for to in [
            LifecycleStage::Archived,
            LifecycleStage::Active,
            LifecycleStage::Deleted,
            LifecycleStage::Restored,
        ] {
            a.transition(e.entry_id, to, "ops", None).unwrap();
        }
        let updated = a.get(e.entry_id).unwrap();
        // 1 (registration) + 4 transitions = 5 records.
        assert_eq!(updated.history.len(), 5);
    }
}
