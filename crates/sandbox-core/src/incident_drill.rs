//! Incident drill register — tabletop / live drills.
//!
//! Distinct from [`crate::business_continuity`] (RTO/RPO testing) and
//! [`crate::chaos_inject`] (live fault injection). This module records
//! *human-process* incident drills: tabletop walkthroughs with stakeholders,
//! crisis-management exercises, regulatory-notification drills.
//!
//! Each drill has a scenario, participants, observed gaps, and follow-up
//! actions. Auditors and regulators ask for this register at least annually.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// DrillKind
// =============================================================================

/// Kind of drill.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillKind {
    /// Tabletop walkthrough.
    Tabletop,
    /// Functional exercise (partial system).
    Functional,
    /// Full-scale exercise (live).
    FullScale,
    /// Communications-only (notification path).
    Communications,
}

// =============================================================================
// DrillOutcome
// =============================================================================

/// Outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillOutcome {
    /// Met all objectives.
    Pass,
    /// Some objectives missed.
    PartialPass,
    /// Failed objectives.
    Fail,
    /// Cancelled.
    Cancelled,
}

// =============================================================================
// Participant
// =============================================================================

/// One participant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Participant {
    /// Name.
    pub name: String,
    /// Role.
    pub role: String,
    /// `true` if attended.
    pub attended: bool,
}

// =============================================================================
// DrillFollowUp
// =============================================================================

/// One follow-up action item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrillFollowUp {
    /// Stable id.
    pub id: Uuid,
    /// Description.
    pub description: String,
    /// Owner.
    pub owner: String,
    /// Due date (RFC 3339).
    pub due_at: Option<String>,
    /// `true` if completed.
    pub completed: bool,
}

impl DrillFollowUp {
    /// New open.
    pub fn new(description: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            id: Uuid::now_v7(),
            description: description.into(),
            owner: owner.into(),
            due_at: None,
            completed: false,
        }
    }
}

// =============================================================================
// DrillRecord
// =============================================================================

/// One drill record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrillRecord {
    /// Stable id.
    pub drill_id: Uuid,
    /// Drill name.
    pub name: String,
    /// Scenario description.
    pub scenario: String,
    /// Kind.
    pub kind: DrillKind,
    /// Conducted at (RFC 3339).
    pub conducted_at: String,
    /// Coordinator.
    pub coordinator: String,
    /// Participants.
    pub participants: Vec<Participant>,
    /// Outcome.
    pub outcome: DrillOutcome,
    /// Observed gaps.
    pub gaps: Vec<String>,
    /// Follow-up actions.
    pub follow_ups: Vec<DrillFollowUp>,
    /// Free-text summary.
    pub summary: String,
    /// Tags.
    pub tags: Vec<String>,
}

impl DrillRecord {
    /// Number of participants who attended.
    pub fn attendance(&self) -> u32 {
        self.participants.iter().filter(|p| p.attended).count() as u32
    }
    /// Number of open follow-ups.
    pub fn open_follow_ups(&self) -> usize {
        self.follow_ups.iter().filter(|f| !f.completed).count()
    }
}

// =============================================================================
// DrillRegistry
// =============================================================================

#[derive(Default)]
struct State {
    drills: HashMap<Uuid, DrillRecord>,
}

/// Registry.
pub struct DrillRegistry {
    state: RwLock<State>,
}

impl Default for DrillRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for DrillRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DrillRegistry")
            .field("drills", &self.len())
            .finish()
    }
}

impl DrillRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append.
    pub fn append(&self, d: DrillRecord) -> SandboxResult<Uuid> {
        let id = d.drill_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("drill registry poisoned".into()))?
            .drills
            .insert(id, d);
        Ok(id)
    }

    /// Add a follow-up.
    pub fn add_follow_up(&self, drill_id: Uuid, fu: DrillFollowUp) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("drill registry poisoned".into()))?;
        let d = g
            .drills
            .get_mut(&drill_id)
            .ok_or_else(|| SandboxError::Other(format!("drill {} not found", drill_id)))?;
        d.follow_ups.push(fu);
        Ok(())
    }

    /// Mark a follow-up complete.
    pub fn complete_follow_up(&self, drill_id: Uuid, fu_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("drill registry poisoned".into()))?;
        let d = g
            .drills
            .get_mut(&drill_id)
            .ok_or_else(|| SandboxError::Other(format!("drill {} not found", drill_id)))?;
        let f = d.follow_ups.iter_mut().find(|f| f.id == fu_id).ok_or_else(|| {
            SandboxError::Other(format!("follow-up {} not in drill", fu_id))
        })?;
        f.completed = true;
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<DrillRecord> {
        self.state.read().ok()?.drills.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<DrillRecord> {
        self.state
            .read()
            .map(|g| g.drills.values().cloned().collect())
            .unwrap_or_default()
    }
    /// By kind.
    pub fn by_kind(&self, k: DrillKind) -> Vec<DrillRecord> {
        self.all().into_iter().filter(|d| d.kind == k).collect()
    }
    /// By outcome.
    pub fn by_outcome(&self, o: DrillOutcome) -> Vec<DrillRecord> {
        self.all().into_iter().filter(|d| d.outcome == o).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.drills.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for [`DrillRecord`].
pub struct DrillBuilder {
    name: String,
    scenario: String,
    kind: DrillKind,
    coordinator: String,
    participants: Vec<Participant>,
    outcome: DrillOutcome,
    gaps: Vec<String>,
    follow_ups: Vec<DrillFollowUp>,
    summary: String,
    tags: Vec<String>,
}

impl DrillBuilder {
    /// New builder.
    pub fn new(
        name: impl Into<String>,
        kind: DrillKind,
        coordinator: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            scenario: String::new(),
            kind,
            coordinator: coordinator.into(),
            participants: Vec::new(),
            outcome: DrillOutcome::Pass,
            gaps: Vec::new(),
            follow_ups: Vec::new(),
            summary: String::new(),
            tags: Vec::new(),
        }
    }
    /// Scenario.
    pub fn scenario(mut self, s: impl Into<String>) -> Self {
        self.scenario = s.into();
        self
    }
    /// Add participant.
    pub fn participant(mut self, p: Participant) -> Self {
        self.participants.push(p);
        self
    }
    /// Outcome.
    pub fn outcome(mut self, o: DrillOutcome) -> Self {
        self.outcome = o;
        self
    }
    /// Add gap.
    pub fn gap(mut self, g: impl Into<String>) -> Self {
        self.gaps.push(g.into());
        self
    }
    /// Add follow-up.
    pub fn follow_up(mut self, f: DrillFollowUp) -> Self {
        self.follow_ups.push(f);
        self
    }
    /// Summary.
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }
    /// Tag.
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        let t = t.into();
        if !self.tags.contains(&t) {
            self.tags.push(t);
        }
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<DrillRecord> {
        if self.name.trim().is_empty() {
            return Err(SandboxError::Other("drill name required".into()));
        }
        Ok(DrillRecord {
            drill_id: Uuid::now_v7(),
            name: self.name,
            scenario: self.scenario,
            kind: self.kind,
            conducted_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            coordinator: self.coordinator,
            participants: self.participants,
            outcome: self.outcome,
            gaps: self.gaps,
            follow_ups: self.follow_ups,
            summary: self.summary,
            tags: self.tags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, attended: bool) -> Participant {
        Participant {
            name: name.into(),
            role: "ops".into(),
            attended,
        }
    }

    fn drill() -> DrillRecord {
        DrillBuilder::new("Q2-tabletop", DrillKind::Tabletop, "ciso")
            .scenario("HSM partial outage")
            .participant(p("alice", true))
            .participant(p("bob", true))
            .outcome(DrillOutcome::PartialPass)
            .gap("Notification list outdated")
            .follow_up(DrillFollowUp::new("Update notification list", "ops"))
            .summary("identified 1 gap")
            .tag("annual")
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_record() {
        let d = drill();
        assert_eq!(d.name, "Q2-tabletop");
        assert_eq!(d.kind, DrillKind::Tabletop);
        assert_eq!(d.attendance(), 2);
    }

    #[test]
    fn empty_name_errors() {
        let r = DrillBuilder::new("", DrillKind::Tabletop, "x").build();
        assert!(r.is_err());
    }

    #[test]
    fn attendance_excludes_absent() {
        let d = DrillBuilder::new("x", DrillKind::Tabletop, "y")
            .participant(p("a", true))
            .participant(p("b", false))
            .build()
            .unwrap();
        assert_eq!(d.attendance(), 1);
    }

    #[test]
    fn open_follow_ups() {
        let d = drill();
        assert_eq!(d.open_follow_ups(), 1);
    }

    #[test]
    fn registry_append_and_get() {
        let r = DrillRegistry::new();
        let id = r.append(drill()).unwrap();
        assert!(r.get(id).is_some());
    }

    #[test]
    fn add_follow_up_appends() {
        let r = DrillRegistry::new();
        let id = r.append(drill()).unwrap();
        r.add_follow_up(id, DrillFollowUp::new("more", "x"))
            .unwrap();
        assert_eq!(r.get(id).unwrap().follow_ups.len(), 2);
    }

    #[test]
    fn add_follow_up_unknown_errors() {
        let r = DrillRegistry::new();
        let f = DrillFollowUp::new("x", "y");
        assert!(r.add_follow_up(Uuid::now_v7(), f).is_err());
    }

    #[test]
    fn complete_follow_up_works() {
        let r = DrillRegistry::new();
        let id = r.append(drill()).unwrap();
        let d = r.get(id).unwrap();
        let fu_id = d.follow_ups[0].id;
        r.complete_follow_up(id, fu_id).unwrap();
        assert_eq!(r.get(id).unwrap().open_follow_ups(), 0);
    }

    #[test]
    fn complete_unknown_follow_up_errors() {
        let r = DrillRegistry::new();
        let id = r.append(drill()).unwrap();
        assert!(r.complete_follow_up(id, Uuid::now_v7()).is_err());
    }

    #[test]
    fn by_kind_filters() {
        let r = DrillRegistry::new();
        r.append(drill()).unwrap();
        r.append(
            DrillBuilder::new("y", DrillKind::FullScale, "x")
                .build()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.by_kind(DrillKind::Tabletop).len(), 1);
        assert_eq!(r.by_kind(DrillKind::FullScale).len(), 1);
    }

    #[test]
    fn by_outcome_filters() {
        let r = DrillRegistry::new();
        r.append(drill()).unwrap();
        r.append(
            DrillBuilder::new("y", DrillKind::Functional, "x")
                .outcome(DrillOutcome::Pass)
                .build()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.by_outcome(DrillOutcome::PartialPass).len(), 1);
        assert_eq!(r.by_outcome(DrillOutcome::Pass).len(), 1);
    }

    #[test]
    fn drill_serde() {
        let d = drill();
        let j = serde_json::to_string(&d).unwrap();
        let p: DrillRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn participant_serde() {
        let p = Participant {
            name: "alice".into(),
            role: "ciso".into(),
            attended: true,
        };
        let j = serde_json::to_string(&p).unwrap();
        let q: Participant = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn follow_up_serde() {
        let f = DrillFollowUp::new("x", "y");
        let j = serde_json::to_string(&f).unwrap();
        let p: DrillFollowUp = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn kind_serde() {
        for k in [
            DrillKind::Tabletop,
            DrillKind::Functional,
            DrillKind::FullScale,
            DrillKind::Communications,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: DrillKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, p);
        }
    }

    #[test]
    fn outcome_serde() {
        for o in [
            DrillOutcome::Pass,
            DrillOutcome::PartialPass,
            DrillOutcome::Fail,
            DrillOutcome::Cancelled,
        ] {
            let j = serde_json::to_string(&o).unwrap();
            let p: DrillOutcome = serde_json::from_str(&j).unwrap();
            assert_eq!(o, p);
        }
    }

    #[test]
    fn tag_dedupes() {
        let d = DrillBuilder::new("x", DrillKind::Tabletop, "y")
            .tag("annual")
            .tag("annual")
            .build()
            .unwrap();
        assert_eq!(d.tags.len(), 1);
    }

    #[test]
    fn registry_count_tracks() {
        let r = DrillRegistry::new();
        assert!(r.is_empty());
        r.append(drill()).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = DrillRegistry::new();
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn many_participants_recorded() {
        let mut b = DrillBuilder::new("x", DrillKind::Tabletop, "y");
        for i in 0..20 {
            b = b.participant(p(&format!("u{i}"), i % 2 == 0));
        }
        let d = b.build().unwrap();
        assert_eq!(d.participants.len(), 20);
        assert_eq!(d.attendance(), 10);
    }
}
