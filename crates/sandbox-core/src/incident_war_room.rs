//! Real-time incident war-room state.
//!
//! Distinct from [`crate::incident`] (the historical incident record),
//! [`crate::incident_drill`] (planned exercises), and
//! [`crate::incident_postmortem`] (after-action report), this module
//! tracks the **active state of an in-flight incident**: who is the
//! incident commander right now, who is the comms lead, what's the
//! current working hypothesis, what timeline events have been logged,
//! and what action items are open.
//!
//! Maps to NIST 800-53 IR-4 (incident handling), ITIL incident
//! management, SOC2 CC7.3 (security incidents), and ISO 27035.
//!
//! ## Lifecycle
//!
//! `Activated → InProgress → Mitigated → Resolved`
//!
//! `Activated` covers the very early phase when the war room is opened
//! but roles aren't fully assigned yet. `InProgress` covers active
//! coordination. `Mitigated` covers the period after symptoms stop but
//! before root cause is confirmed. `Resolved` is terminal.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// WarRoomStage
// =============================================================================

/// Lifecycle stage of the war room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarRoomStage {
    /// Just opened; roles not yet assigned.
    Activated,
    /// Active coordination; commander assigned.
    InProgress,
    /// Symptoms have stopped; root cause not yet confirmed.
    Mitigated,
    /// Resolved; war room closed.
    Resolved,
}

impl WarRoomStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Resolved)
    }

    /// True if customer impact is still ongoing.
    pub fn has_customer_impact(self) -> bool {
        matches!(self, Self::Activated | Self::InProgress)
    }
}

// =============================================================================
// Role
// =============================================================================

/// Functional role in the war room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Incident commander — runs the response.
    Commander,
    /// Communications lead — internal + external comms.
    CommsLead,
    /// Technical lead — drives the diagnosis / fix.
    TechLead,
    /// Scribe — records timeline events.
    Scribe,
    /// Subject matter expert.
    Sme,
    /// Executive sponsor / liaison.
    ExecSponsor,
    /// Customer liaison / support lead.
    CustomerLiaison,
}

// =============================================================================
// RoleAssignment
// =============================================================================

/// One role assigned to a person.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoleAssignment {
    /// Role.
    pub role: Role,
    /// Operator.
    pub user_id: String,
    /// Display name.
    pub display_name: String,
    /// RFC 3339 — when assigned.
    pub assigned_at: String,
}

// =============================================================================
// TimelineEntry
// =============================================================================

/// One entry on the war-room timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEntry {
    /// RFC 3339.
    pub at: String,
    /// Author.
    pub author: String,
    /// Free-text note.
    pub note: String,
    /// Optional category ("hypothesis", "action", "decision", "comms").
    pub category: Option<String>,
}

// =============================================================================
// WarRoomActionItem
// =============================================================================

/// Action item raised inside the war room. Distinct from the postmortem
/// action items in [`crate::incident_postmortem`] — these are *during the
/// incident*, the postmortem ones are *after*.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarRoomActionItem {
    /// Stable id within the war room.
    pub item_id: String,
    /// Description.
    pub description: String,
    /// Owner.
    pub owner: String,
    /// True if completed.
    pub completed: bool,
    /// RFC 3339 — created.
    pub created_at: String,
    /// RFC 3339 — completed (set when `completed` flips to true).
    pub completed_at: Option<String>,
}

// =============================================================================
// WarRoom
// =============================================================================

/// One in-flight incident war room.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WarRoom {
    /// Unique id.
    pub war_room_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Linked incident id (often shared with [`crate::incident`]).
    pub incident_id: String,
    /// Display title.
    pub title: String,
    /// Current stage.
    pub stage: WarRoomStage,
    /// Severity at activation (sev1 / sev2 / sev3 / sev4 — free text).
    pub severity: String,
    /// Current working hypothesis (mutable as understanding evolves).
    pub hypothesis: Option<String>,
    /// Customer-facing summary (what we'd say in a status update).
    pub customer_summary: Option<String>,
    /// Role assignments (one per role; later assignments overwrite).
    pub roles: Vec<RoleAssignment>,
    /// Timeline.
    pub timeline: Vec<TimelineEntry>,
    /// Action items.
    pub action_items: Vec<WarRoomActionItem>,
    /// RFC 3339 — activated.
    pub activated_at: String,
    /// RFC 3339 — mitigated (set when stage hits Mitigated).
    pub mitigated_at: Option<String>,
    /// RFC 3339 — resolved (set when stage hits Resolved).
    pub resolved_at: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl WarRoom {
    /// New `Activated` war room.
    pub fn new(
        war_room_id: impl Into<String>,
        tenant_id: impl Into<String>,
        incident_id: impl Into<String>,
        title: impl Into<String>,
        severity: impl Into<String>,
        activated_at: impl Into<String>,
    ) -> Self {
        Self {
            war_room_id: war_room_id.into(),
            tenant_id: tenant_id.into(),
            incident_id: incident_id.into(),
            title: title.into(),
            stage: WarRoomStage::Activated,
            severity: severity.into(),
            hypothesis: None,
            customer_summary: None,
            roles: Vec::new(),
            timeline: Vec::new(),
            action_items: Vec::new(),
            activated_at: activated_at.into(),
            mitigated_at: None,
            resolved_at: None,
            tags: Vec::new(),
        }
    }

    /// Get the current holder of a role, if any (latest assignment wins).
    pub fn role_holder(&self, role: Role) -> Option<&RoleAssignment> {
        self.roles.iter().rev().find(|r| r.role == role)
    }

    /// True if the war room is missing a key role (Commander) past
    /// activation.
    pub fn missing_commander(&self) -> bool {
        matches!(self.stage, WarRoomStage::InProgress | WarRoomStage::Mitigated)
            && self.role_holder(Role::Commander).is_none()
    }

    /// Number of incomplete action items.
    pub fn open_action_items(&self) -> usize {
        self.action_items.iter().filter(|a| !a.completed).count()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: WarRoomStage, to: WarRoomStage) -> bool {
    use WarRoomStage::*;
    match (from, to) {
        (Activated, InProgress)
        | (Activated, Mitigated)
        | (Activated, Resolved)
        | (InProgress, Mitigated)
        | (InProgress, Resolved)
        | (Mitigated, Resolved)
        | (Mitigated, InProgress) // re-flare
        => true,
        _ => false,
    }
}

// =============================================================================
// IncidentWarRoomRegistry
// =============================================================================

/// Thread-safe registry of war rooms.
#[derive(Debug, Default)]
pub struct IncidentWarRoomRegistry {
    inner: RwLock<HashMap<String, WarRoom>>,
}

impl IncidentWarRoomRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Activate a new war room. Errors on duplicate id or non-Activated
    /// initial stage.
    pub fn activate(&self, room: WarRoom) -> SandboxResult<()> {
        if !matches!(room.stage, WarRoomStage::Activated) {
            return Err(SandboxError::Other(format!(
                "war room must start Activated, got {:?}",
                room.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        if g.contains_key(&room.war_room_id) {
            return Err(SandboxError::Other(format!(
                "war room already activated: {}",
                room.war_room_id
            )));
        }
        g.insert(room.war_room_id.clone(), room);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        war_room_id: &str,
        new_stage: WarRoomStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<WarRoom> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
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
        r.timeline.push(TimelineEntry {
            at: when.clone(),
            author: actor,
            note,
            category: Some("stage".into()),
        });
        match new_stage {
            WarRoomStage::Mitigated => r.mitigated_at = Some(when),
            WarRoomStage::Resolved => r.resolved_at = Some(when),
            _ => {}
        }
        Ok(r.clone())
    }

    /// Assign a role.
    pub fn assign_role(
        &self,
        war_room_id: &str,
        assignment: RoleAssignment,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        if r.stage.is_terminal() {
            return Err(SandboxError::Other(format!(
                "war room {war_room_id} is resolved; cannot assign roles"
            )));
        }
        r.roles.push(assignment);
        Ok(())
    }

    /// Update the working hypothesis.
    pub fn set_hypothesis(
        &self,
        war_room_id: &str,
        hypothesis: impl Into<String>,
        author: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        let h = hypothesis.into();
        let author = author.into();
        let when = at.into();
        r.hypothesis = Some(h.clone());
        r.timeline.push(TimelineEntry {
            at: when,
            author,
            note: format!("hypothesis: {h}"),
            category: Some("hypothesis".into()),
        });
        Ok(())
    }

    /// Update the customer-facing summary.
    pub fn set_customer_summary(
        &self,
        war_room_id: &str,
        summary: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        r.customer_summary = Some(summary.into());
        Ok(())
    }

    /// Append a free-form timeline note.
    pub fn note(
        &self,
        war_room_id: &str,
        author: impl Into<String>,
        note: impl Into<String>,
        category: Option<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        r.timeline.push(TimelineEntry {
            at: at.into(),
            author: author.into(),
            note: note.into(),
            category,
        });
        Ok(())
    }

    /// Add an action item.
    pub fn add_action_item(
        &self,
        war_room_id: &str,
        item: WarRoomActionItem,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        if r.action_items.iter().any(|a| a.item_id == item.item_id) {
            return Err(SandboxError::Other(format!(
                "action item already present: {}",
                item.item_id
            )));
        }
        r.action_items.push(item);
        Ok(())
    }

    /// Mark an action item complete.
    pub fn complete_action_item(
        &self,
        war_room_id: &str,
        item_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        let it = r
            .action_items
            .iter_mut()
            .find(|a| a.item_id == item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown action item {item_id}")))?;
        if it.completed {
            return Err(SandboxError::Other(format!(
                "action item {item_id} already completed"
            )));
        }
        it.completed = true;
        it.completed_at = Some(at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, war_room_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("war room registry poisoned".into()))?;
        let r = g
            .get_mut(war_room_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown war room {war_room_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, war_room_id: &str) -> Option<WarRoom> {
        let g = self.inner.read().ok()?;
        g.get(war_room_id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<WarRoom> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active war rooms (not Resolved).
    pub fn active(&self) -> Vec<WarRoom> {
        self.all()
            .into_iter()
            .filter(|r| !r.stage.is_terminal())
            .collect()
    }

    /// War rooms for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<WarRoom> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// War rooms with customer impact.
    pub fn customer_impacting(&self) -> Vec<WarRoom> {
        self.all()
            .into_iter()
            .filter(|r| r.stage.has_customer_impact())
            .collect()
    }

    /// War rooms missing an incident commander past activation.
    pub fn missing_commander(&self) -> Vec<WarRoom> {
        self.all()
            .into_iter()
            .filter(|r| r.missing_commander())
            .collect()
    }

    /// Number of registered war rooms.
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

    fn room(id: &str) -> WarRoom {
        WarRoom::new(
            id,
            "tenant-a",
            format!("incident-{id}"),
            format!("title-{id}"),
            "sev2",
            "2025-05-08T00:00:00Z",
        )
    }

    fn assignment(role: Role, user: &str) -> RoleAssignment {
        RoleAssignment {
            role,
            user_id: user.into(),
            display_name: user.into(),
            assigned_at: "2025-05-08T00:01:00Z".into(),
        }
    }

    fn item(id: &str) -> WarRoomActionItem {
        WarRoomActionItem {
            item_id: id.into(),
            description: format!("do-{id}"),
            owner: "alice".into(),
            completed: false,
            created_at: "2025-05-08T00:05:00Z".into(),
            completed_at: None,
        }
    }

    #[test]
    fn activate_and_get() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        let w = r.get("w1").unwrap();
        assert_eq!(w.stage, WarRoomStage::Activated);
    }

    #[test]
    fn duplicate_activate_errors() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        let err = r.activate(room("w1")).unwrap_err();
        assert!(format!("{err}").contains("already activated"));
    }

    #[test]
    fn must_start_activated() {
        let mut w = room("w1");
        w.stage = WarRoomStage::InProgress;
        let r = IncidentWarRoomRegistry::new();
        let err = r.activate(w).unwrap_err();
        assert!(format!("{err}").contains("must start Activated"));
    }

    #[test]
    fn legal_transitions_table() {
        use WarRoomStage::*;
        assert!(legal_transition(Activated, InProgress));
        assert!(legal_transition(Activated, Mitigated));
        assert!(legal_transition(Activated, Resolved));
        assert!(legal_transition(InProgress, Mitigated));
        assert!(legal_transition(InProgress, Resolved));
        assert!(legal_transition(Mitigated, Resolved));
        assert!(legal_transition(Mitigated, InProgress)); // re-flare
        // illegal
        assert!(!legal_transition(Resolved, Mitigated));
        assert!(!legal_transition(Resolved, InProgress));
        assert!(!legal_transition(InProgress, Activated));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.transition(
            "w1",
            WarRoomStage::InProgress,
            "ic",
            "starting response",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        r.transition(
            "w1",
            WarRoomStage::Mitigated,
            "ic",
            "rolled back",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        let w = r
            .transition(
                "w1",
                WarRoomStage::Resolved,
                "ic",
                "root cause confirmed",
                "2025-05-08T03:00:00Z",
            )
            .unwrap();
        assert_eq!(w.stage, WarRoomStage::Resolved);
        assert!(w.stage.is_terminal());
        assert_eq!(w.mitigated_at.as_deref(), Some("2025-05-08T01:00:00Z"));
        assert_eq!(w.resolved_at.as_deref(), Some("2025-05-08T03:00:00Z"));
        assert_eq!(w.timeline.len(), 3);
    }

    #[test]
    fn re_flare_allowed() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.transition(
            "w1",
            WarRoomStage::InProgress,
            "ic",
            "n",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        r.transition(
            "w1",
            WarRoomStage::Mitigated,
            "ic",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        // symptoms returned
        let w = r
            .transition(
                "w1",
                WarRoomStage::InProgress,
                "ic",
                "re-flare",
                "2025-05-08T02:00:00Z",
            )
            .unwrap();
        assert_eq!(w.stage, WarRoomStage::InProgress);
    }

    #[test]
    fn illegal_transition_errors() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.transition(
            "w1",
            WarRoomStage::Resolved,
            "ic",
            "false alarm",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        let err = r
            .transition(
                "w1",
                WarRoomStage::InProgress,
                "ic",
                "wait",
                "2025-05-08T00:10:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn assign_role_records_holder() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.assign_role("w1", assignment(Role::Commander, "alice"))
            .unwrap();
        let w = r.get("w1").unwrap();
        assert_eq!(
            w.role_holder(Role::Commander).unwrap().user_id,
            "alice"
        );
    }

    #[test]
    fn assign_role_latest_wins() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.assign_role("w1", assignment(Role::Commander, "alice"))
            .unwrap();
        r.assign_role("w1", assignment(Role::Commander, "bob")).unwrap();
        let w = r.get("w1").unwrap();
        assert_eq!(w.role_holder(Role::Commander).unwrap().user_id, "bob");
    }

    #[test]
    fn assign_role_after_resolved_errors() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.transition(
            "w1",
            WarRoomStage::Resolved,
            "ic",
            "n",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        let err = r
            .assign_role("w1", assignment(Role::Commander, "alice"))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot assign roles"));
    }

    #[test]
    fn missing_commander_query() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        // Activated but no commander → should NOT yet flag; only InProgress / Mitigated do.
        assert!(r.missing_commander().is_empty());
        r.transition(
            "w1",
            WarRoomStage::InProgress,
            "ic",
            "go",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        assert_eq!(r.missing_commander().len(), 1);
        // Once commander is assigned → not missing.
        r.assign_role("w1", assignment(Role::Commander, "alice")).unwrap();
        assert!(r.missing_commander().is_empty());
    }

    #[test]
    fn set_hypothesis_logs_timeline() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.set_hypothesis("w1", "DB pool exhausted", "alice", "2025-05-08T00:10:00Z")
            .unwrap();
        let w = r.get("w1").unwrap();
        assert_eq!(w.hypothesis.as_deref(), Some("DB pool exhausted"));
        assert!(w
            .timeline
            .iter()
            .any(|e| e.category.as_deref() == Some("hypothesis")));
    }

    #[test]
    fn set_customer_summary() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.set_customer_summary("w1", "Some users seeing errors").unwrap();
        assert_eq!(
            r.get("w1").unwrap().customer_summary.as_deref(),
            Some("Some users seeing errors")
        );
    }

    #[test]
    fn note_appends_timeline() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.note(
            "w1",
            "alice",
            "rolling back deploy",
            Some("action".into()),
            "2025-05-08T00:15:00Z",
        )
        .unwrap();
        let w = r.get("w1").unwrap();
        assert_eq!(w.timeline.len(), 1);
        assert_eq!(w.timeline[0].category.as_deref(), Some("action"));
    }

    #[test]
    fn add_action_item_dedupes() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.add_action_item("w1", item("a1")).unwrap();
        let err = r.add_action_item("w1", item("a1")).unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn complete_action_item() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.add_action_item("w1", item("a1")).unwrap();
        r.complete_action_item("w1", "a1", "2025-05-08T00:30:00Z")
            .unwrap();
        let w = r.get("w1").unwrap();
        assert!(w.action_items[0].completed);
        assert_eq!(w.open_action_items(), 0);
    }

    #[test]
    fn complete_action_item_twice_errors() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.add_action_item("w1", item("a1")).unwrap();
        r.complete_action_item("w1", "a1", "2025-05-08T00:30:00Z")
            .unwrap();
        let err = r
            .complete_action_item("w1", "a1", "2025-05-08T00:31:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("already completed"));
    }

    #[test]
    fn complete_action_item_unknown_errors() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        let err = r
            .complete_action_item("w1", "nope", "2025-05-08T00:30:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown action item"));
    }

    #[test]
    fn open_action_items_counts() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.add_action_item("w1", item("a1")).unwrap();
        r.add_action_item("w1", item("a2")).unwrap();
        r.add_action_item("w1", item("a3")).unwrap();
        r.complete_action_item("w1", "a1", "2025-05-08T00:30:00Z")
            .unwrap();
        assert_eq!(r.get("w1").unwrap().open_action_items(), 2);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.add_tag("w1", "customer-impact").unwrap();
        r.add_tag("w1", "customer-impact").unwrap();
        r.add_tag("w1", "p0").unwrap();
        assert_eq!(r.get("w1").unwrap().tags, vec!["customer-impact", "p0"]);
    }

    #[test]
    fn unknown_war_room_errors() {
        let r = IncidentWarRoomRegistry::new();
        let err = r.add_tag("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown war room"));
    }

    #[test]
    fn for_tenant_filters() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        let mut other = room("w2");
        other.tenant_id = "tenant-b".into();
        r.activate(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn active_excludes_resolved() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.activate(room("w2")).unwrap();
        r.transition(
            "w1",
            WarRoomStage::Resolved,
            "ic",
            "n",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        assert_eq!(r.active().len(), 1);
        assert_eq!(r.active()[0].war_room_id, "w2");
    }

    #[test]
    fn customer_impacting_only_active_phases() {
        let r = IncidentWarRoomRegistry::new();
        r.activate(room("w1")).unwrap();
        r.activate(room("w2")).unwrap();
        r.transition(
            "w2",
            WarRoomStage::InProgress,
            "ic",
            "n",
            "2025-05-08T00:05:00Z",
        )
        .unwrap();
        r.transition(
            "w2",
            WarRoomStage::Mitigated,
            "ic",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        // w1 = Activated → impacting; w2 = Mitigated → not impacting
        let imp = r.customer_impacting();
        let ids: Vec<_> = imp.iter().map(|w| w.war_room_id.clone()).collect();
        assert!(ids.contains(&"w1".to_string()));
        assert!(!ids.contains(&"w2".to_string()));
    }

    #[test]
    fn count_tracks() {
        let r = IncidentWarRoomRegistry::new();
        assert_eq!(r.count(), 0);
        r.activate(room("w1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn stage_helpers() {
        assert!(WarRoomStage::Resolved.is_terminal());
        assert!(!WarRoomStage::Activated.is_terminal());
        assert!(WarRoomStage::Activated.has_customer_impact());
        assert!(WarRoomStage::InProgress.has_customer_impact());
        assert!(!WarRoomStage::Mitigated.has_customer_impact());
        assert!(!WarRoomStage::Resolved.has_customer_impact());
    }

    #[test]
    fn war_room_serde() {
        let w = room("w1");
        let j = serde_json::to_string(&w).unwrap();
        let back: WarRoom = serde_json::from_str(&j).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            WarRoomStage::Activated,
            WarRoomStage::InProgress,
            WarRoomStage::Mitigated,
            WarRoomStage::Resolved,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<WarRoomStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for r in [
            Role::Commander,
            Role::CommsLead,
            Role::TechLead,
            Role::Scribe,
            Role::Sme,
            Role::ExecSponsor,
            Role::CustomerLiaison,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<Role>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
    }
}
