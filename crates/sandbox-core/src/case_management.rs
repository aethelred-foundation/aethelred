//! Case management — link related events into investigation cases.
//!
//! Compliance investigations span many seals, postmortems, audit entries,
//! erasure requests, vendor issues, etc. This module is the canonical
//! glue: a [`Case`] records a *theme* (fraud investigation, regulator
//! query, customer complaint, security incident) and links to all
//! relevant events by id.
//!
//! Operators search, filter, and assign cases. The case carries a
//! tamper-evident timeline of ownership and notes.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// CaseStatus
// =============================================================================

/// Lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Open / active.
    Open,
    /// In review / pending decision.
    Review,
    /// Resolved.
    Resolved,
    /// Closed (terminal).
    Closed,
    /// Escalated.
    Escalated,
}

impl CaseStatus {
    /// `true` if terminal.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

// =============================================================================
// CaseSeverity
// =============================================================================

/// Severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseSeverity {
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
// LinkedItem
// =============================================================================

/// One linked artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkedItem {
    /// Item kind label (e.g., `"seal"`, `"postmortem"`, `"audit_entry"`).
    pub kind: String,
    /// External id (UUID string, hash, etc.).
    pub external_id: String,
    /// RFC 3339 linked at.
    pub linked_at: String,
    /// Operator who linked it.
    pub linked_by: String,
    /// Optional note.
    pub note: Option<String>,
}

// =============================================================================
// CaseEvent
// =============================================================================

/// One event in the case timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaseEvent {
    /// Event id.
    pub event_id: Uuid,
    /// RFC 3339.
    pub at: String,
    /// Operator.
    pub actor: String,
    /// Free-text description.
    pub description: String,
    /// Hash of prior event (None = first).
    pub prior_hash: Option<Sha256Digest>,
    /// Hash of this event content.
    pub event_hash: Sha256Digest,
}

impl CaseEvent {
    fn compute_hash(
        at: &str,
        actor: &str,
        description: &str,
        prior: Option<&Sha256Digest>,
    ) -> Sha256Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(at.as_bytes());
        buf.push(0);
        buf.extend_from_slice(actor.as_bytes());
        buf.push(0);
        buf.extend_from_slice(description.as_bytes());
        if let Some(p) = prior {
            buf.extend_from_slice(&p.0);
        }
        Hasher::sha256(&buf)
    }
}

// =============================================================================
// Case
// =============================================================================

/// One investigation case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Case {
    /// Stable id.
    pub case_id: Uuid,
    /// Stable customer-facing case number (e.g. `"CASE-2026-001"`).
    pub case_number: String,
    /// Title.
    pub title: String,
    /// Owner.
    pub owner: String,
    /// Tenant (if any).
    pub tenant_id: Option<String>,
    /// Free-text summary.
    pub summary: String,
    /// Status.
    pub status: CaseStatus,
    /// Severity.
    pub severity: CaseSeverity,
    /// Linked items.
    pub linked_items: Vec<LinkedItem>,
    /// Tamper-evident timeline.
    pub timeline: Vec<CaseEvent>,
    /// RFC 3339 opened at.
    pub opened_at: String,
    /// RFC 3339 last-changed.
    pub last_changed_at: String,
    /// Tags.
    pub tags: Vec<String>,
}

impl Case {
    /// Number of open links.
    pub fn link_count(&self) -> usize {
        self.linked_items.len()
    }
}

// =============================================================================
// CaseManager
// =============================================================================

#[derive(Default)]
struct State {
    cases: HashMap<Uuid, Case>,
    /// case_number → case_id (uniqueness guard).
    by_number: HashMap<String, Uuid>,
}

/// Manager.
pub struct CaseManager {
    state: RwLock<State>,
}

impl Default for CaseManager {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CaseManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaseManager")
            .field("cases", &self.len())
            .finish()
    }
}

impl CaseManager {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new case.
    pub fn open(
        &self,
        case_number: impl Into<String>,
        title: impl Into<String>,
        owner: impl Into<String>,
        severity: CaseSeverity,
        tenant_id: Option<String>,
    ) -> SandboxResult<Case> {
        let number = case_number.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        if g.by_number.contains_key(&number) {
            return Err(SandboxError::Other(format!(
                "case number {} already exists",
                number
            )));
        }
        let owner = owner.into();
        let title = title.into();
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let event_hash = CaseEvent::compute_hash(&now, &owner, "case opened", None);
        let initial_event = CaseEvent {
            event_id: Uuid::now_v7(),
            at: now.clone(),
            actor: owner.clone(),
            description: "case opened".into(),
            prior_hash: None,
            event_hash,
        };
        let c = Case {
            case_id: Uuid::now_v7(),
            case_number: number.clone(),
            title,
            owner,
            tenant_id,
            summary: String::new(),
            status: CaseStatus::Open,
            severity,
            linked_items: Vec::new(),
            timeline: vec![initial_event],
            opened_at: now.clone(),
            last_changed_at: now,
            tags: Vec::new(),
        };
        g.by_number.insert(number, c.case_id);
        g.cases.insert(c.case_id, c.clone());
        Ok(c)
    }

    /// Append a timeline event.
    pub fn add_event(
        &self,
        case_id: Uuid,
        actor: impl Into<String>,
        description: impl Into<String>,
    ) -> SandboxResult<CaseEvent> {
        let actor = actor.into();
        let description = description.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        let c = g
            .cases
            .get_mut(&case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let prior = c.timeline.last().map(|e| e.event_hash.clone());
        let event_hash = CaseEvent::compute_hash(&now, &actor, &description, prior.as_ref());
        let event = CaseEvent {
            event_id: Uuid::now_v7(),
            at: now.clone(),
            actor,
            description,
            prior_hash: prior,
            event_hash,
        };
        c.timeline.push(event.clone());
        c.last_changed_at = now;
        Ok(event)
    }

    /// Link an external item.
    pub fn link(
        &self,
        case_id: Uuid,
        kind: impl Into<String>,
        external_id: impl Into<String>,
        linked_by: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        let kind = kind.into();
        let external_id = external_id.into();
        let linked_by = linked_by.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        let c = g
            .cases
            .get_mut(&case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        // Dedup.
        if c.linked_items
            .iter()
            .any(|l| l.kind == kind && l.external_id == external_id)
        {
            return Err(SandboxError::Other(format!(
                "{}:{} already linked",
                kind, external_id
            )));
        }
        c.linked_items.push(LinkedItem {
            kind,
            external_id,
            linked_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            linked_by,
            note,
        });
        Ok(())
    }

    /// Set status.
    pub fn set_status(&self, case_id: Uuid, status: CaseStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        let c = g
            .cases
            .get_mut(&case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        if c.status.is_terminal() {
            return Err(SandboxError::Other(format!(
                "case {} is closed",
                case_id
            )));
        }
        c.status = status;
        c.last_changed_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }

    /// Add a tag (dedups).
    pub fn add_tag(&self, case_id: Uuid, tag: impl Into<String>) -> SandboxResult<()> {
        let tag = tag.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        let c = g
            .cases
            .get_mut(&case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Update summary.
    pub fn set_summary(&self, case_id: Uuid, summary: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("case manager poisoned".into()))?;
        let c = g
            .cases
            .get_mut(&case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        c.summary = summary.into();
        Ok(())
    }

    /// Lookup by id.
    pub fn get(&self, case_id: Uuid) -> Option<Case> {
        self.state.read().ok()?.cases.get(&case_id).cloned()
    }
    /// Lookup by case number.
    pub fn by_number(&self, number: &str) -> Option<Case> {
        let g = self.state.read().ok()?;
        let id = g.by_number.get(number)?;
        g.cases.get(id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<Case> {
        self.state
            .read()
            .map(|g| g.cases.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Filter by status.
    pub fn by_status(&self, status: CaseStatus) -> Vec<Case> {
        self.all().into_iter().filter(|c| c.status == status).collect()
    }
    /// Filter by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<Case> {
        self.all()
            .into_iter()
            .filter(|c| c.tags.iter().any(|t| t == tag))
            .collect()
    }
    /// Filter by external linked id.
    pub fn cases_with_link(&self, kind: &str, external_id: &str) -> Vec<Case> {
        self.all()
            .into_iter()
            .filter(|c| {
                c.linked_items
                    .iter()
                    .any(|l| l.kind == kind && l.external_id == external_id)
            })
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.cases.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Verify timeline chain integrity.
    pub fn verify_timeline(&self, case_id: Uuid) -> SandboxResult<()> {
        let c = self
            .get(case_id)
            .ok_or_else(|| SandboxError::Other(format!("case {} not found", case_id)))?;
        let mut prior: Option<Sha256Digest> = None;
        for (i, e) in c.timeline.iter().enumerate() {
            match (&e.prior_hash, &prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "case {} chain break at event {}",
                        case_id, i
                    )))
                }
            }
            let recomputed =
                CaseEvent::compute_hash(&e.at, &e.actor, &e.description, e.prior_hash.as_ref());
            if recomputed != e.event_hash {
                return Err(SandboxError::Other(format!(
                    "case {} event {} hash mismatch",
                    case_id, i
                )));
            }
            prior = Some(e.event_hash.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(m: &CaseManager) -> Case {
        m.open(
            "CASE-1",
            "Suspicious tx pattern",
            "ops",
            CaseSeverity::High,
            Some("FAB".into()),
        )
        .unwrap()
    }

    #[test]
    fn open_creates_case() {
        let m = CaseManager::new();
        let c = open(&m);
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.timeline.len(), 1);
    }

    #[test]
    fn duplicate_number_errors() {
        let m = CaseManager::new();
        open(&m);
        assert!(m
            .open("CASE-1", "x", "y", CaseSeverity::Low, None)
            .is_err());
    }

    #[test]
    fn add_event_appends_and_chains() {
        let m = CaseManager::new();
        let c = open(&m);
        let e = m.add_event(c.case_id, "alice", "investigated").unwrap();
        let case = m.get(c.case_id).unwrap();
        assert_eq!(case.timeline.len(), 2);
        assert_eq!(case.timeline[1].event_hash, e.event_hash);
        assert!(case.timeline[1].prior_hash.is_some());
    }

    #[test]
    fn link_items_dedupes() {
        let m = CaseManager::new();
        let c = open(&m);
        m.link(c.case_id, "seal", "uuid-1", "ops", None).unwrap();
        assert!(m.link(c.case_id, "seal", "uuid-1", "ops", None).is_err());
    }

    #[test]
    fn link_count_tracks() {
        let m = CaseManager::new();
        let c = open(&m);
        m.link(c.case_id, "seal", "u1", "ops", None).unwrap();
        m.link(c.case_id, "seal", "u2", "ops", None).unwrap();
        let case = m.get(c.case_id).unwrap();
        assert_eq!(case.link_count(), 2);
    }

    #[test]
    fn set_status_works() {
        let m = CaseManager::new();
        let c = open(&m);
        m.set_status(c.case_id, CaseStatus::Review).unwrap();
        assert_eq!(m.get(c.case_id).unwrap().status, CaseStatus::Review);
    }

    #[test]
    fn cannot_change_closed() {
        let m = CaseManager::new();
        let c = open(&m);
        m.set_status(c.case_id, CaseStatus::Closed).unwrap();
        assert!(m.set_status(c.case_id, CaseStatus::Open).is_err());
    }

    #[test]
    fn add_tag_dedupes() {
        let m = CaseManager::new();
        let c = open(&m);
        m.add_tag(c.case_id, "fraud").unwrap();
        m.add_tag(c.case_id, "fraud").unwrap();
        assert_eq!(m.get(c.case_id).unwrap().tags, vec!["fraud"]);
    }

    #[test]
    fn set_summary_works() {
        let m = CaseManager::new();
        let c = open(&m);
        m.set_summary(c.case_id, "summary text").unwrap();
        assert_eq!(m.get(c.case_id).unwrap().summary, "summary text");
    }

    #[test]
    fn by_status_filters() {
        let m = CaseManager::new();
        let a = open(&m);
        m.open("CASE-2", "x", "y", CaseSeverity::Low, None).unwrap();
        m.set_status(a.case_id, CaseStatus::Closed).unwrap();
        assert_eq!(m.by_status(CaseStatus::Closed).len(), 1);
        assert_eq!(m.by_status(CaseStatus::Open).len(), 1);
    }

    #[test]
    fn by_tag_filters() {
        let m = CaseManager::new();
        let a = open(&m);
        m.add_tag(a.case_id, "fraud").unwrap();
        let b = m.open("CASE-2", "x", "y", CaseSeverity::Low, None).unwrap();
        m.add_tag(b.case_id, "operational").unwrap();
        assert_eq!(m.by_tag("fraud").len(), 1);
        assert_eq!(m.by_tag("operational").len(), 1);
    }

    #[test]
    fn cases_with_link_filters() {
        let m = CaseManager::new();
        let a = open(&m);
        m.link(a.case_id, "seal", "u-1", "ops", None).unwrap();
        let b = m.open("CASE-2", "x", "y", CaseSeverity::Low, None).unwrap();
        m.link(b.case_id, "seal", "u-2", "ops", None).unwrap();
        assert_eq!(m.cases_with_link("seal", "u-1").len(), 1);
    }

    #[test]
    fn lookup_by_number() {
        let m = CaseManager::new();
        open(&m);
        assert!(m.by_number("CASE-1").is_some());
        assert!(m.by_number("missing").is_none());
    }

    #[test]
    fn verify_timeline_after_writes() {
        let m = CaseManager::new();
        let c = open(&m);
        m.add_event(c.case_id, "a", "step 1").unwrap();
        m.add_event(c.case_id, "a", "step 2").unwrap();
        m.verify_timeline(c.case_id).unwrap();
    }

    #[test]
    fn verify_unknown_case_errors() {
        let m = CaseManager::new();
        assert!(m.verify_timeline(Uuid::now_v7()).is_err());
    }

    #[test]
    fn case_serde() {
        let m = CaseManager::new();
        let c = open(&m);
        let j = serde_json::to_string(&c).unwrap();
        let p: Case = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn linked_item_serde() {
        let l = LinkedItem {
            kind: "x".into(),
            external_id: "y".into(),
            linked_at: "z".into(),
            linked_by: "ops".into(),
            note: Some("n".into()),
        };
        let j = serde_json::to_string(&l).unwrap();
        let p: LinkedItem = serde_json::from_str(&j).unwrap();
        assert_eq!(p, l);
    }

    #[test]
    fn case_event_serde() {
        let m = CaseManager::new();
        let c = open(&m);
        let e = &c.timeline[0];
        let j = serde_json::to_string(e).unwrap();
        let p: CaseEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(&p, e);
    }

    #[test]
    fn status_serde() {
        for s in [
            CaseStatus::Open,
            CaseStatus::Review,
            CaseStatus::Resolved,
            CaseStatus::Closed,
            CaseStatus::Escalated,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CaseStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn severity_serde() {
        for s in [
            CaseSeverity::Low,
            CaseSeverity::Medium,
            CaseSeverity::High,
            CaseSeverity::Critical,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CaseSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn many_events_chain_intact() {
        let m = CaseManager::new();
        let c = open(&m);
        for i in 0..30 {
            m.add_event(c.case_id, "a", &format!("event-{i}")).unwrap();
        }
        m.verify_timeline(c.case_id).unwrap();
        assert_eq!(m.get(c.case_id).unwrap().timeline.len(), 31);
    }

    #[test]
    fn registry_count_tracks() {
        let m = CaseManager::new();
        assert!(m.is_empty());
        open(&m);
        assert_eq!(m.len(), 1);
    }
}
