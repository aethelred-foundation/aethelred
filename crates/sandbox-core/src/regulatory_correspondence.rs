//! Regulatory correspondence log.
//!
//! Distinct from [`crate::regulatory_change`] (tracking new rules) and
//! [`crate::compliance_report`] (point-in-time compliance bundles), this
//! is the **bidirectional log of communications with regulators**:
//! every information request, examination notice, response submitted,
//! enforcement action, and follow-up letter is logged here.
//!
//! Maps to SEC Rule 17a-4 (broker-dealer record retention),
//! FFIEC examination correspondence requirements, FCA Principle 11
//! (open and cooperative dealings with regulators), and SOX §906
//! certifications.
//!
//! ## Why a dedicated registry?
//!
//! Regulators expect a chronological, immutable trail of every interaction.
//! Internal wikis and email threads aren't enough — you need a registry
//! that exposes "what did we tell the FCA on March 12, who acknowledged
//! it, and what was the outcome?" in a single query.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// Direction
// =============================================================================

/// Direction of the correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Inbound — from the regulator to us.
    Inbound,
    /// Outbound — from us to the regulator.
    Outbound,
}

// =============================================================================
// CorrespondenceKind
// =============================================================================

/// Kind of correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrespondenceKind {
    /// Information request from regulator.
    InformationRequest,
    /// Examination notice or scoping letter.
    ExaminationNotice,
    /// Voluntary self-disclosure / breach notification.
    SelfDisclosure,
    /// Inquiry / question.
    Inquiry,
    /// Response to a regulator request.
    Response,
    /// Filing (periodic regulatory submission).
    Filing,
    /// Examination findings letter.
    ExaminationFindings,
    /// Enforcement action / consent order.
    EnforcementAction,
    /// No-action letter.
    NoActionLetter,
    /// General correspondence.
    General,
}

impl CorrespondenceKind {
    /// True if this kind generally requires a response by the controller.
    pub fn requires_response(self) -> bool {
        matches!(
            self,
            Self::InformationRequest
                | Self::ExaminationNotice
                | Self::Inquiry
                | Self::ExaminationFindings
                | Self::EnforcementAction
        )
    }
}

// =============================================================================
// Status
// =============================================================================

/// Lifecycle status of the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Logged but no further action yet.
    Logged,
    /// Acknowledged by recipient (regulator or us).
    Acknowledged,
    /// Response drafted internally.
    ResponseDrafted,
    /// Response submitted to regulator.
    ResponseSubmitted,
    /// Closed — no further action required.
    Closed,
}

impl Status {
    /// True if no further action is expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

// =============================================================================
// CorrespondenceEvent
// =============================================================================

/// One event on the correspondence timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrespondenceEvent {
    /// RFC 3339.
    pub at: String,
    /// Author / actor.
    pub actor: String,
    /// Status applied.
    pub status: Status,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// CorrespondenceItem
// =============================================================================

/// One regulatory correspondence item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrespondenceItem {
    /// Unique id (e.g., "REG-FCA-2025-007").
    pub item_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Regulator / authority (e.g., "FCA", "SEC", "OCC", "EU AI Office").
    pub regulator: String,
    /// Direction.
    pub direction: Direction,
    /// Kind.
    pub kind: CorrespondenceKind,
    /// Public title / subject line.
    pub subject: String,
    /// Long-form summary of the content.
    pub summary: String,
    /// Reference id supplied by the regulator (case number, exam id).
    pub regulator_reference: Option<String>,
    /// Internal owner (compliance officer, GC).
    pub owner: String,
    /// Sender (named individual or team).
    pub sender: String,
    /// Recipient (named individual or team).
    pub recipient: String,
    /// Channel ("portal", "email", "hand_delivery", "registered_mail").
    pub channel: String,
    /// Storage URI for the actual document (S3/Vault/file path).
    pub document_uri: Option<String>,
    /// SHA-256 hex of the document, for tamper-evidence.
    pub document_sha256: Option<String>,
    /// Linked finding id, if this item is part of an audit finding response.
    pub linked_finding_id: Option<String>,
    /// Linked enterprise risk id.
    pub linked_risk_id: Option<String>,
    /// RFC 3339 — when sent / received.
    pub occurred_at: String,
    /// RFC 3339 — deadline for our response, if any.
    pub response_due_at: Option<String>,
    /// Current status.
    pub status: Status,
    /// RFC 3339 — closed.
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<CorrespondenceEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl CorrespondenceItem {
    /// New `Logged` item.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        item_id: impl Into<String>,
        tenant_id: impl Into<String>,
        regulator: impl Into<String>,
        direction: Direction,
        kind: CorrespondenceKind,
        subject: impl Into<String>,
        summary: impl Into<String>,
        owner: impl Into<String>,
        sender: impl Into<String>,
        recipient: impl Into<String>,
        channel: impl Into<String>,
        occurred_at: impl Into<String>,
    ) -> Self {
        Self {
            item_id: item_id.into(),
            tenant_id: tenant_id.into(),
            regulator: regulator.into(),
            direction,
            kind,
            subject: subject.into(),
            summary: summary.into(),
            regulator_reference: None,
            owner: owner.into(),
            sender: sender.into(),
            recipient: recipient.into(),
            channel: channel.into(),
            document_uri: None,
            document_sha256: None,
            linked_finding_id: None,
            linked_risk_id: None,
            occurred_at: occurred_at.into(),
            response_due_at: None,
            status: Status::Logged,
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if this item is past its response deadline and not yet closed.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        match self.response_due_at.as_deref() {
            Some(due) => now >= due,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: Status, to: Status) -> bool {
    use Status::*;
    match (from, to) {
        (Logged, Acknowledged)
        | (Logged, ResponseDrafted)
        | (Logged, Closed)
        | (Acknowledged, ResponseDrafted)
        | (Acknowledged, Closed)
        | (ResponseDrafted, ResponseSubmitted)
        | (ResponseDrafted, Closed)
        | (ResponseSubmitted, Closed)
        | (ResponseSubmitted, ResponseDrafted) // re-draft after rejection
        => true,
        _ => false,
    }
}

// =============================================================================
// RegulatoryCorrespondence
// =============================================================================

/// Thread-safe regulatory correspondence log.
#[derive(Debug, Default)]
pub struct RegulatoryCorrespondence {
    inner: RwLock<HashMap<String, CorrespondenceItem>>,
}

impl RegulatoryCorrespondence {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Log a new correspondence item.
    pub fn log(&self, item: CorrespondenceItem) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        if g.contains_key(&item.item_id) {
            return Err(SandboxError::Other(format!(
                "item already logged: {}",
                item.item_id
            )));
        }
        g.insert(item.item_id.clone(), item);
        Ok(())
    }

    /// Apply a status transition.
    pub fn transition(
        &self,
        item_id: &str,
        new_status: Status,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<CorrespondenceItem> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        if !legal_transition(i.status, new_status) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                i.status, new_status
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        i.status = new_status;
        i.events.push(CorrespondenceEvent {
            at: when.clone(),
            actor,
            status: new_status,
            note,
        });
        if new_status.is_terminal() {
            i.closed_at = Some(when);
        }
        Ok(i.clone())
    }

    /// Set the regulator's reference number.
    pub fn set_regulator_reference(
        &self,
        item_id: &str,
        reference: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        i.regulator_reference = Some(reference.into());
        Ok(())
    }

    /// Set the document storage URI and SHA-256 hash.
    pub fn set_document(
        &self,
        item_id: &str,
        uri: impl Into<String>,
        sha256: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        i.document_uri = Some(uri.into());
        i.document_sha256 = Some(sha256.into());
        Ok(())
    }

    /// Set the response deadline.
    pub fn set_response_due(
        &self,
        item_id: &str,
        due_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        i.response_due_at = Some(due_at.into());
        Ok(())
    }

    /// Link this item to an audit finding.
    pub fn link_finding(
        &self,
        item_id: &str,
        finding_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        i.linked_finding_id = Some(finding_id.into());
        Ok(())
    }

    /// Link this item to an enterprise risk.
    pub fn link_risk(
        &self,
        item_id: &str,
        risk_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        i.linked_risk_id = Some(risk_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, item_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("regulatory correspondence poisoned".into()))?;
        let i = g
            .get_mut(item_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown item {item_id}")))?;
        let tag = tag.into();
        if !i.tags.contains(&tag) {
            i.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, item_id: &str) -> Option<CorrespondenceItem> {
        let g = self.inner.read().ok()?;
        g.get(item_id).cloned()
    }

    /// All items.
    pub fn all(&self) -> Vec<CorrespondenceItem> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Items for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| i.tenant_id == tenant_id)
            .collect()
    }

    /// Items for a regulator.
    pub fn for_regulator(&self, regulator: &str) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| i.regulator == regulator)
            .collect()
    }

    /// Items by direction.
    pub fn by_direction(&self, direction: Direction) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| i.direction == direction)
            .collect()
    }

    /// Items by kind.
    pub fn by_kind(&self, kind: CorrespondenceKind) -> Vec<CorrespondenceItem> {
        self.all().into_iter().filter(|i| i.kind == kind).collect()
    }

    /// Items by status.
    pub fn by_status(&self, status: Status) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| i.status == status)
            .collect()
    }

    /// Open items (not Closed).
    pub fn open(&self) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| !i.status.is_terminal())
            .collect()
    }

    /// Items overdue at `now`.
    pub fn overdue(&self, now: &str) -> Vec<CorrespondenceItem> {
        self.all().into_iter().filter(|i| i.is_overdue(now)).collect()
    }

    /// Items linked to a given audit finding.
    pub fn for_finding(&self, finding_id: &str) -> Vec<CorrespondenceItem> {
        self.all()
            .into_iter()
            .filter(|i| i.linked_finding_id.as_deref() == Some(finding_id))
            .collect()
    }

    /// Items in chronological order by `occurred_at` ascending.
    pub fn chronological(&self) -> Vec<CorrespondenceItem> {
        let mut all = self.all();
        all.sort_by(|a, b| a.occurred_at.cmp(&b.occurred_at));
        all
    }

    /// Count.
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

    fn item(id: &str, dir: Direction, kind: CorrespondenceKind) -> CorrespondenceItem {
        CorrespondenceItem::new(
            id,
            "global",
            "FCA",
            dir,
            kind,
            format!("subject-{id}"),
            "summary",
            "compliance-officer",
            "fca@regulator.test",
            "compliance@example.test",
            "portal",
            "2025-04-01T00:00:00Z",
        )
    }

    #[test]
    fn log_and_get() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        let i = l.get("i1").unwrap();
        assert_eq!(i.status, Status::Logged);
        assert_eq!(i.regulator, "FCA");
    }

    #[test]
    fn duplicate_log_errors() {
        let l = RegulatoryCorrespondence::new();
        l.log(item("i1", Direction::Inbound, CorrespondenceKind::Inquiry))
            .unwrap();
        let err = l
            .log(item("i1", Direction::Inbound, CorrespondenceKind::Inquiry))
            .unwrap_err();
        assert!(format!("{err}").contains("already logged"));
    }

    #[test]
    fn legal_transitions_table() {
        use Status::*;
        assert!(legal_transition(Logged, Acknowledged));
        assert!(legal_transition(Logged, ResponseDrafted));
        assert!(legal_transition(Logged, Closed));
        assert!(legal_transition(Acknowledged, ResponseDrafted));
        assert!(legal_transition(ResponseDrafted, ResponseSubmitted));
        assert!(legal_transition(ResponseSubmitted, Closed));
        assert!(legal_transition(ResponseSubmitted, ResponseDrafted));
        // illegal
        assert!(!legal_transition(Logged, ResponseSubmitted));
        assert!(!legal_transition(Closed, Logged));
        assert!(!legal_transition(Closed, ResponseSubmitted));
    }

    #[test]
    fn happy_path_lifecycle() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.transition(
            "i1",
            Status::Acknowledged,
            "compliance",
            "we received it",
            "2025-04-02T00:00:00Z",
        )
        .unwrap();
        l.transition(
            "i1",
            Status::ResponseDrafted,
            "compliance",
            "draft prepared",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        l.transition(
            "i1",
            Status::ResponseSubmitted,
            "compliance",
            "submitted via portal",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        let i = l
            .transition(
                "i1",
                Status::Closed,
                "compliance",
                "regulator confirmed receipt",
                "2025-05-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(i.status, Status::Closed);
        assert!(i.status.is_terminal());
        assert_eq!(i.closed_at.as_deref(), Some("2025-05-01T00:00:00Z"));
        assert_eq!(i.events.len(), 4);
    }

    #[test]
    fn re_draft_after_rejection() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.transition(
            "i1",
            Status::ResponseDrafted,
            "x",
            "n",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        l.transition(
            "i1",
            Status::ResponseSubmitted,
            "x",
            "n",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        // Regulator rejected; re-draft.
        let i = l
            .transition(
                "i1",
                Status::ResponseDrafted,
                "x",
                "regulator wants more detail",
                "2025-04-25T00:00:00Z",
            )
            .unwrap();
        assert_eq!(i.status, Status::ResponseDrafted);
    }

    #[test]
    fn illegal_transition_errors() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        let err = l
            .transition(
                "i1",
                Status::ResponseSubmitted,
                "x",
                "skip",
                "2025-04-15T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_metadata_fields() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.set_regulator_reference("i1", "FCA-CASE-2025-0123").unwrap();
        l.set_document("i1", "vault://docs/fca-2025-0123", "abcdef")
            .unwrap();
        l.set_response_due("i1", "2025-05-01T00:00:00Z").unwrap();
        l.link_finding("i1", "FIND-2025-007").unwrap();
        l.link_risk("i1", "RISK-2025-007").unwrap();
        let i = l.get("i1").unwrap();
        assert_eq!(i.regulator_reference.as_deref(), Some("FCA-CASE-2025-0123"));
        assert_eq!(i.document_uri.as_deref(), Some("vault://docs/fca-2025-0123"));
        assert_eq!(i.document_sha256.as_deref(), Some("abcdef"));
        assert_eq!(i.response_due_at.as_deref(), Some("2025-05-01T00:00:00Z"));
        assert_eq!(i.linked_finding_id.as_deref(), Some("FIND-2025-007"));
        assert_eq!(i.linked_risk_id.as_deref(), Some("RISK-2025-007"));
    }

    #[test]
    fn add_tag_dedupes() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.add_tag("i1", "p0").unwrap();
        l.add_tag("i1", "p0").unwrap();
        l.add_tag("i1", "exam").unwrap();
        assert_eq!(l.get("i1").unwrap().tags, vec!["p0", "exam"]);
    }

    #[test]
    fn unknown_item_errors() {
        let l = RegulatoryCorrespondence::new();
        let err = l.set_response_due("nope", "2025-05-01T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown item"));
    }

    #[test]
    fn for_tenant_for_regulator_filters() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        let mut other = item("i2", Direction::Inbound, CorrespondenceKind::Inquiry);
        other.tenant_id = "tenant-b".into();
        other.regulator = "SEC".into();
        l.log(other).unwrap();
        assert_eq!(l.for_tenant("global").len(), 1);
        assert_eq!(l.for_tenant("tenant-b").len(), 1);
        assert_eq!(l.for_regulator("FCA").len(), 1);
        assert_eq!(l.for_regulator("SEC").len(), 1);
    }

    #[test]
    fn by_direction_kind_status_filters() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.log(item(
            "i2",
            Direction::Outbound,
            CorrespondenceKind::Response,
        ))
        .unwrap();
        assert_eq!(l.by_direction(Direction::Inbound).len(), 1);
        assert_eq!(l.by_direction(Direction::Outbound).len(), 1);
        assert_eq!(l.by_kind(CorrespondenceKind::Response).len(), 1);
        assert_eq!(l.by_status(Status::Logged).len(), 2);
    }

    #[test]
    fn open_filters() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.log(item("i2", Direction::Inbound, CorrespondenceKind::Inquiry))
            .unwrap();
        l.transition(
            "i2",
            Status::Closed,
            "x",
            "no action",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        let open = l.open();
        let ids: Vec<_> = open.iter().map(|i| i.item_id.clone()).collect();
        assert_eq!(ids, vec!["i1"]);
    }

    #[test]
    fn overdue_filters() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.set_response_due("i1", "2025-05-01T00:00:00Z").unwrap();
        assert_eq!(l.overdue("2025-06-01T00:00:00Z").len(), 1);
        l.transition(
            "i1",
            Status::Closed,
            "x",
            "n",
            "2025-05-15T00:00:00Z",
        )
        .unwrap();
        assert_eq!(l.overdue("2025-06-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn for_finding_filters() {
        let l = RegulatoryCorrespondence::new();
        l.log(item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        ))
        .unwrap();
        l.link_finding("i1", "FIND-007").unwrap();
        assert_eq!(l.for_finding("FIND-007").len(), 1);
        assert_eq!(l.for_finding("FIND-999").len(), 0);
    }

    #[test]
    fn chronological_orders_ascending() {
        let l = RegulatoryCorrespondence::new();
        let mut a = item(
            "a",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        );
        a.occurred_at = "2025-04-15T00:00:00Z".into();
        let mut b = item(
            "b",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        );
        b.occurred_at = "2025-04-01T00:00:00Z".into();
        let mut c = item(
            "c",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        );
        c.occurred_at = "2025-04-30T00:00:00Z".into();
        l.log(a).unwrap();
        l.log(b).unwrap();
        l.log(c).unwrap();
        let v: Vec<_> = l.chronological().into_iter().map(|i| i.item_id).collect();
        assert_eq!(v, vec!["b", "a", "c"]);
    }

    #[test]
    fn requires_response_helpers() {
        assert!(CorrespondenceKind::InformationRequest.requires_response());
        assert!(CorrespondenceKind::ExaminationNotice.requires_response());
        assert!(CorrespondenceKind::Inquiry.requires_response());
        assert!(CorrespondenceKind::ExaminationFindings.requires_response());
        assert!(CorrespondenceKind::EnforcementAction.requires_response());
        assert!(!CorrespondenceKind::Response.requires_response());
        assert!(!CorrespondenceKind::Filing.requires_response());
        assert!(!CorrespondenceKind::SelfDisclosure.requires_response());
        assert!(!CorrespondenceKind::NoActionLetter.requires_response());
    }

    #[test]
    fn count_tracks() {
        let l = RegulatoryCorrespondence::new();
        assert_eq!(l.count(), 0);
        l.log(item("i1", Direction::Inbound, CorrespondenceKind::Inquiry))
            .unwrap();
        assert_eq!(l.count(), 1);
    }

    #[test]
    fn item_serde() {
        let i = item(
            "i1",
            Direction::Inbound,
            CorrespondenceKind::InformationRequest,
        );
        let j = serde_json::to_string(&i).unwrap();
        let back: CorrespondenceItem = serde_json::from_str(&j).unwrap();
        assert_eq!(i, back);
    }

    #[test]
    fn enums_serde() {
        for d in [Direction::Inbound, Direction::Outbound] {
            assert_eq!(
                d,
                serde_json::from_str::<Direction>(&serde_json::to_string(&d).unwrap()).unwrap()
            );
        }
        for k in [
            CorrespondenceKind::InformationRequest,
            CorrespondenceKind::ExaminationNotice,
            CorrespondenceKind::SelfDisclosure,
            CorrespondenceKind::Inquiry,
            CorrespondenceKind::Response,
            CorrespondenceKind::Filing,
            CorrespondenceKind::ExaminationFindings,
            CorrespondenceKind::EnforcementAction,
            CorrespondenceKind::NoActionLetter,
            CorrespondenceKind::General,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<CorrespondenceKind>(&serde_json::to_string(&k).unwrap())
                    .unwrap()
            );
        }
        for s in [
            Status::Logged,
            Status::Acknowledged,
            Status::ResponseDrafted,
            Status::ResponseSubmitted,
            Status::Closed,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<Status>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
