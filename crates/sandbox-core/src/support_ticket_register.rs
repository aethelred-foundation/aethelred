//! Customer support ticket register.
//!
//! Distinct from [`crate::case_management`] (internal incident / fraud
//! cases) and [`crate::incident`] (operational outages), this is the
//! **external customer-facing ticket** register used by the support
//! desk: every inbound question, complaint, and bug report from a
//! customer is logged here through to resolution and CSAT capture.
//!
//! Maps to ITIL Service Operation, ITSM ticket-management practice,
//! and the canonical Zendesk / Freshdesk / Salesforce Service Cloud
//! ticket schema.
//!
//! ## Lifecycle
//!
//! `Open → Assigned → InProgress → AwaitingCustomer → (Resolved →
//! Closed) | Cancelled`
//!
//! Re-opening is allowed (`Closed → InProgress`) when a customer
//! follows up on a closed ticket.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// TicketChannel
// =============================================================================

/// Channel through which the ticket arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketChannel {
    Email,
    WebForm,
    InAppChat,
    Phone,
    Slack,
    Api,
    SocialMedia,
    Other,
}

// =============================================================================
// TicketPriority
// =============================================================================

/// Priority of the ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketPriority {
    /// Critical — production-down, data loss, security event.
    P0,
    /// High — major impact on customer.
    P1,
    /// Normal — single-feature impact.
    P2,
    /// Low — cosmetic / question.
    P3,
}

impl TicketPriority {
    /// Numeric rank (lower = higher priority).
    pub fn rank(self) -> u8 {
        match self {
            Self::P0 => 0,
            Self::P1 => 1,
            Self::P2 => 2,
            Self::P3 => 3,
        }
    }

    /// True if SLA is tight enough to require pager response.
    pub fn requires_paging(self) -> bool {
        matches!(self, Self::P0 | Self::P1)
    }
}

// =============================================================================
// TicketCategory
// =============================================================================

/// Category of the ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketCategory {
    /// Bug report.
    Bug,
    /// Question / how-to.
    Question,
    /// Billing / invoice issue.
    Billing,
    /// Feature request.
    FeatureRequest,
    /// Account / login issue.
    Account,
    /// Performance issue.
    Performance,
    /// Security report (often elevated to a real incident).
    Security,
    /// General feedback (often diverted to feedback_register).
    Feedback,
    /// Other.
    Other,
}

// =============================================================================
// TicketStage
// =============================================================================

/// Lifecycle stage of a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStage {
    /// Logged but not yet assigned.
    Open,
    /// Assigned to an agent.
    Assigned,
    /// Agent actively working.
    InProgress,
    /// Waiting on customer for info.
    AwaitingCustomer,
    /// Resolved; awaiting customer confirmation / auto-close.
    Resolved,
    /// Fully closed.
    Closed,
    /// Cancelled (duplicate / spam / customer withdrew).
    Cancelled,
}

impl TicketStage {
    /// True if no further customer-facing work is expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Cancelled)
    }

    /// True if currently assignable to an agent.
    pub fn is_open(self) -> bool {
        !self.is_terminal()
    }
}

// =============================================================================
// TicketReply
// =============================================================================

/// One reply on a ticket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TicketReply {
    /// RFC 3339.
    pub at: String,
    /// Author identifier.
    pub author: String,
    /// True if the author is the customer (vs. agent).
    pub from_customer: bool,
    /// Reply body (may be redacted upstream).
    pub body: String,
    /// Internal-only note (not visible to customer).
    pub internal: bool,
}

// =============================================================================
// CsatRating
// =============================================================================

/// Customer satisfaction rating after resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsatRating {
    /// Very dissatisfied.
    VeryDissatisfied,
    /// Dissatisfied.
    Dissatisfied,
    /// Neutral.
    Neutral,
    /// Satisfied.
    Satisfied,
    /// Very satisfied.
    VerySatisfied,
}

impl CsatRating {
    /// Numeric score (1-5).
    pub fn score(self) -> u8 {
        match self {
            Self::VeryDissatisfied => 1,
            Self::Dissatisfied => 2,
            Self::Neutral => 3,
            Self::Satisfied => 4,
            Self::VerySatisfied => 5,
        }
    }

    /// True if positive (Satisfied or VerySatisfied).
    pub fn is_positive(self) -> bool {
        self.score() >= 4
    }
}

// =============================================================================
// TicketEvent
// =============================================================================

/// One event on the ticket timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TicketEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: TicketStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// SupportTicket
// =============================================================================

/// One customer support ticket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SupportTicket {
    /// Unique ticket id (e.g., "TICK-2025-12345").
    pub ticket_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Customer id.
    pub customer_id: String,
    /// Customer display name.
    pub customer_name: String,
    /// Subject line.
    pub subject: String,
    /// Initial body (the customer's first message).
    pub initial_body: String,
    /// Channel.
    pub channel: TicketChannel,
    /// Priority.
    pub priority: TicketPriority,
    /// Category.
    pub category: TicketCategory,
    /// Current stage.
    pub stage: TicketStage,
    /// Assigned agent (set when entering Assigned).
    pub assignee: Option<String>,
    /// Replies thread.
    pub replies: Vec<TicketReply>,
    /// CSAT recorded after resolution.
    pub csat: Option<CsatRating>,
    /// Free-text resolution summary.
    pub resolution: Option<String>,
    /// Linked incident id (if escalated).
    pub linked_incident_id: Option<String>,
    /// SLA response deadline (RFC 3339).
    pub response_due_at: Option<String>,
    /// SLA resolution deadline.
    pub resolution_due_at: Option<String>,
    /// RFC 3339 — opened.
    pub opened_at: String,
    /// RFC 3339 — first agent reply.
    pub first_response_at: Option<String>,
    /// RFC 3339 — resolved.
    pub resolved_at: Option<String>,
    /// RFC 3339 — closed.
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<TicketEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl SupportTicket {
    /// New `Open` ticket.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ticket_id: impl Into<String>,
        tenant_id: impl Into<String>,
        customer_id: impl Into<String>,
        customer_name: impl Into<String>,
        subject: impl Into<String>,
        initial_body: impl Into<String>,
        channel: TicketChannel,
        priority: TicketPriority,
        category: TicketCategory,
        opened_at: impl Into<String>,
    ) -> Self {
        Self {
            ticket_id: ticket_id.into(),
            tenant_id: tenant_id.into(),
            customer_id: customer_id.into(),
            customer_name: customer_name.into(),
            subject: subject.into(),
            initial_body: initial_body.into(),
            channel,
            priority,
            category,
            stage: TicketStage::Open,
            assignee: None,
            replies: Vec::new(),
            csat: None,
            resolution: None,
            linked_incident_id: None,
            response_due_at: None,
            resolution_due_at: None,
            opened_at: opened_at.into(),
            first_response_at: None,
            resolved_at: None,
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if `now >= response_due_at` and no first response yet.
    pub fn is_response_overdue(&self, now: &str) -> bool {
        if self.first_response_at.is_some() || self.stage.is_terminal() {
            return false;
        }
        match self.response_due_at.as_deref() {
            Some(d) => now >= d,
            None => false,
        }
    }

    /// True if `now >= resolution_due_at` and not yet resolved/closed.
    pub fn is_resolution_overdue(&self, now: &str) -> bool {
        if matches!(self.stage, TicketStage::Resolved | TicketStage::Closed | TicketStage::Cancelled) {
            return false;
        }
        match self.resolution_due_at.as_deref() {
            Some(d) => now >= d,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: TicketStage, to: TicketStage) -> bool {
    use TicketStage::*;
    matches!(
        (from, to),
        (Open, Assigned)
            | (Open, Cancelled)
            | (Assigned, InProgress)
            | (Assigned, AwaitingCustomer)
            | (Assigned, Cancelled)
            | (InProgress, AwaitingCustomer)
            | (InProgress, Resolved)
            | (InProgress, Cancelled)
            | (AwaitingCustomer, InProgress)
            | (AwaitingCustomer, Resolved)
            | (AwaitingCustomer, Cancelled)
            | (Resolved, Closed)
            | (Resolved, InProgress)        // re-open after customer push-back
            | (Closed, InProgress)          // re-open after customer reply
    )
}

// =============================================================================
// SupportTicketRegister
// =============================================================================

/// Thread-safe register of customer support tickets.
#[derive(Debug, Default)]
pub struct SupportTicketRegister {
    inner: RwLock<HashMap<String, SupportTicket>>,
}

impl SupportTicketRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new ticket.
    pub fn open(&self, ticket: SupportTicket) -> SandboxResult<()> {
        if !matches!(ticket.stage, TicketStage::Open) {
            return Err(SandboxError::Other(format!(
                "ticket must start Open, got {:?}",
                ticket.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        if g.contains_key(&ticket.ticket_id) {
            return Err(SandboxError::Other(format!(
                "ticket already opened: {}",
                ticket.ticket_id
            )));
        }
        g.insert(ticket.ticket_id.clone(), ticket);
        Ok(())
    }

    /// Assign to an agent (Open → Assigned).
    pub fn assign(
        &self,
        ticket_id: &str,
        assignee: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<SupportTicket> {
        let assignee = assignee.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        if !legal_transition(t.stage, TicketStage::Assigned) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Assigned",
                t.stage
            )));
        }
        let when = at.into();
        t.stage = TicketStage::Assigned;
        t.assignee = Some(assignee.clone());
        t.events.push(TicketEvent {
            at: when,
            actor: assignee,
            stage: TicketStage::Assigned,
            note: "assigned".into(),
        });
        Ok(t.clone())
    }

    /// Apply a stage transition with bookkeeping for first response /
    /// resolved / closed timestamps.
    pub fn transition(
        &self,
        ticket_id: &str,
        new_stage: TicketStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<SupportTicket> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        if !legal_transition(t.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                t.stage, new_stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        t.stage = new_stage;
        match new_stage {
            TicketStage::Resolved => {
                t.resolved_at = Some(when.clone());
                if t.resolution.is_none() {
                    t.resolution = Some(note.clone());
                }
            }
            TicketStage::Closed => {
                t.closed_at = Some(when.clone());
            }
            TicketStage::Cancelled => {
                t.closed_at = Some(when.clone());
            }
            _ => {}
        }
        t.events.push(TicketEvent {
            at: when,
            actor,
            stage: new_stage,
            note,
        });
        Ok(t.clone())
    }

    /// Add a reply. Records first_response_at on the first agent reply.
    pub fn reply(&self, ticket_id: &str, reply: TicketReply) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        if t.stage.is_terminal() {
            return Err(SandboxError::Other(format!(
                "ticket {ticket_id} is terminal"
            )));
        }
        if !reply.from_customer && t.first_response_at.is_none() && !reply.internal {
            t.first_response_at = Some(reply.at.clone());
        }
        t.replies.push(reply);
        Ok(())
    }

    /// Record CSAT after resolution.
    pub fn record_csat(&self, ticket_id: &str, rating: CsatRating) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        if !matches!(t.stage, TicketStage::Resolved | TicketStage::Closed) {
            return Err(SandboxError::Other(format!(
                "cannot record CSAT on {ticket_id}: stage is {:?}",
                t.stage
            )));
        }
        t.csat = Some(rating);
        Ok(())
    }

    /// Set SLA deadlines.
    pub fn set_sla(
        &self,
        ticket_id: &str,
        response_due_at: Option<String>,
        resolution_due_at: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        if let Some(r) = response_due_at {
            t.response_due_at = Some(r);
        }
        if let Some(r) = resolution_due_at {
            t.resolution_due_at = Some(r);
        }
        Ok(())
    }

    /// Link to an incident (e.g., when escalated).
    pub fn link_incident(
        &self,
        ticket_id: &str,
        incident_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        t.linked_incident_id = Some(incident_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, ticket_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("ticket register poisoned".into()))?;
        let t = g
            .get_mut(ticket_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown ticket {ticket_id}")))?;
        let tag = tag.into();
        if !t.tags.contains(&tag) {
            t.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, ticket_id: &str) -> Option<SupportTicket> {
        let g = self.inner.read().ok()?;
        g.get(ticket_id).cloned()
    }

    /// All tickets.
    pub fn all(&self) -> Vec<SupportTicket> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Tickets for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.tenant_id == tenant_id)
            .collect()
    }

    /// Tickets for a customer.
    pub fn for_customer(&self, customer_id: &str) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.customer_id == customer_id)
            .collect()
    }

    /// Tickets for an assignee.
    pub fn for_assignee(&self, assignee: &str) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.assignee.as_deref() == Some(assignee))
            .collect()
    }

    /// Tickets at a stage.
    pub fn by_stage(&self, stage: TicketStage) -> Vec<SupportTicket> {
        self.all().into_iter().filter(|t| t.stage == stage).collect()
    }

    /// Open tickets (non-terminal).
    pub fn open_tickets(&self) -> Vec<SupportTicket> {
        self.all().into_iter().filter(|t| t.stage.is_open()).collect()
    }

    /// Tickets at or above a priority threshold (lower rank = higher pri).
    pub fn at_least_priority(&self, threshold: TicketPriority) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.priority.rank() <= threshold.rank())
            .collect()
    }

    /// Tickets whose first-response SLA is overdue at `now`.
    pub fn response_overdue(&self, now: &str) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.is_response_overdue(now))
            .collect()
    }

    /// Tickets whose resolution SLA is overdue at `now`.
    pub fn resolution_overdue(&self, now: &str) -> Vec<SupportTicket> {
        self.all()
            .into_iter()
            .filter(|t| t.is_resolution_overdue(now))
            .collect()
    }

    /// Mean CSAT score across resolved/closed tickets with CSAT recorded.
    pub fn mean_csat_score(&self) -> Option<f64> {
        let scores: Vec<u8> = self
            .all()
            .iter()
            .filter_map(|t| t.csat.map(|c| c.score()))
            .collect();
        if scores.is_empty() {
            return None;
        }
        let sum: u32 = scores.iter().map(|s| *s as u32).sum();
        Some(sum as f64 / scores.len() as f64)
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

    fn ticket(id: &str, customer: &str, priority: TicketPriority) -> SupportTicket {
        SupportTicket::new(
            id,
            "tenant-a",
            customer,
            format!("Customer {customer}"),
            "Subject line",
            "Initial message body",
            TicketChannel::Email,
            priority,
            TicketCategory::Question,
            "2025-04-01T00:00:00Z",
        )
    }

    fn reply(at: &str, author: &str, from_customer: bool, internal: bool) -> TicketReply {
        TicketReply {
            at: at.into(),
            author: author.into(),
            from_customer,
            body: "reply body".into(),
            internal,
        }
    }

    #[test]
    fn open_and_get() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        assert!(r.get("t1").is_some());
    }

    #[test]
    fn duplicate_open_errors() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        let err = r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap_err();
        assert!(format!("{err}").contains("already opened"));
    }

    #[test]
    fn must_start_open() {
        let mut t = ticket("t1", "alice", TicketPriority::P2);
        t.stage = TicketStage::InProgress;
        let r = SupportTicketRegister::new();
        let err = r.open(t).unwrap_err();
        assert!(format!("{err}").contains("must start Open"));
    }

    #[test]
    fn legal_transitions() {
        use TicketStage::*;
        assert!(legal_transition(Open, Assigned));
        assert!(legal_transition(Open, Cancelled));
        assert!(legal_transition(Assigned, InProgress));
        assert!(legal_transition(Assigned, AwaitingCustomer));
        assert!(legal_transition(InProgress, Resolved));
        assert!(legal_transition(AwaitingCustomer, InProgress));
        assert!(legal_transition(AwaitingCustomer, Resolved));
        assert!(legal_transition(Resolved, Closed));
        assert!(legal_transition(Resolved, InProgress));
        assert!(legal_transition(Closed, InProgress));
        // illegal
        assert!(!legal_transition(Open, Resolved));
        assert!(!legal_transition(Open, Closed));
        assert!(!legal_transition(Cancelled, Open));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.assign("t1", "agent-bob", "2025-04-01T00:01:00Z").unwrap();
        r.transition(
            "t1",
            TicketStage::InProgress,
            "agent-bob",
            "2025-04-01T00:05:00Z",
            "started",
        )
        .unwrap();
        r.reply("t1", reply("2025-04-01T00:10:00Z", "agent-bob", false, false))
            .unwrap();
        r.transition(
            "t1",
            TicketStage::Resolved,
            "agent-bob",
            "2025-04-01T01:00:00Z",
            "issue resolved",
        )
        .unwrap();
        r.record_csat("t1", CsatRating::VerySatisfied).unwrap();
        let t = r
            .transition(
                "t1",
                TicketStage::Closed,
                "system",
                "2025-04-08T00:00:00Z",
                "auto-closed",
            )
            .unwrap();
        assert_eq!(t.stage, TicketStage::Closed);
        assert!(t.stage.is_terminal());
        assert_eq!(t.first_response_at.as_deref(), Some("2025-04-01T00:10:00Z"));
        assert_eq!(t.resolved_at.as_deref(), Some("2025-04-01T01:00:00Z"));
        assert_eq!(t.csat, Some(CsatRating::VerySatisfied));
    }

    #[test]
    fn first_response_only_set_for_agent_non_internal() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.assign("t1", "agent-bob", "2025-04-01T00:01:00Z").unwrap();
        // Customer reply doesn't count
        r.reply("t1", reply("2025-04-01T00:02:00Z", "alice", true, false))
            .unwrap();
        assert!(r.get("t1").unwrap().first_response_at.is_none());
        // Internal note doesn't count
        r.reply("t1", reply("2025-04-01T00:03:00Z", "agent-bob", false, true))
            .unwrap();
        assert!(r.get("t1").unwrap().first_response_at.is_none());
        // External agent reply does count
        r.reply("t1", reply("2025-04-01T00:04:00Z", "agent-bob", false, false))
            .unwrap();
        assert_eq!(
            r.get("t1").unwrap().first_response_at.as_deref(),
            Some("2025-04-01T00:04:00Z")
        );
    }

    #[test]
    fn reply_terminal_errors() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.transition(
            "t1",
            TicketStage::Cancelled,
            "system",
            "2025-04-01T00:01:00Z",
            "spam",
        )
        .unwrap();
        let err = r
            .reply("t1", reply("2025-04-01T00:02:00Z", "agent", false, false))
            .unwrap_err();
        assert!(format!("{err}").contains("terminal"));
    }

    #[test]
    fn record_csat_only_after_resolved() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        let err = r.record_csat("t1", CsatRating::Satisfied).unwrap_err();
        assert!(format!("{err}").contains("cannot record CSAT"));
    }

    #[test]
    fn re_open_from_closed() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.assign("t1", "agent", "2025-04-01T00:01:00Z").unwrap();
        r.transition(
            "t1",
            TicketStage::InProgress,
            "agent",
            "2025-04-01T00:05:00Z",
            "n",
        )
        .unwrap();
        r.transition(
            "t1",
            TicketStage::Resolved,
            "agent",
            "2025-04-01T01:00:00Z",
            "n",
        )
        .unwrap();
        r.transition(
            "t1",
            TicketStage::Closed,
            "system",
            "2025-04-08T00:00:00Z",
            "n",
        )
        .unwrap();
        // Customer follows up — re-open
        let t = r
            .transition(
                "t1",
                TicketStage::InProgress,
                "agent",
                "2025-04-10T00:00:00Z",
                "customer follow-up",
            )
            .unwrap();
        assert_eq!(t.stage, TicketStage::InProgress);
    }

    #[test]
    fn illegal_transition_errors() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        let err = r
            .transition(
                "t1",
                TicketStage::Resolved,
                "agent",
                "2025-04-01T00:05:00Z",
                "n",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_sla_response_overdue_query() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P0)).unwrap();
        r.set_sla(
            "t1",
            Some("2025-04-01T00:15:00Z".into()),
            Some("2025-04-01T04:00:00Z".into()),
        )
        .unwrap();
        // Past response SLA, no first response → overdue
        assert_eq!(r.response_overdue("2025-04-01T00:30:00Z").len(), 1);
        // Send agent reply → not overdue
        r.assign("t1", "agent", "2025-04-01T00:01:00Z").unwrap();
        r.reply("t1", reply("2025-04-01T00:10:00Z", "agent", false, false))
            .unwrap();
        assert_eq!(r.response_overdue("2025-04-01T00:30:00Z").len(), 0);
    }

    #[test]
    fn resolution_overdue_query() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P0)).unwrap();
        r.set_sla(
            "t1",
            None,
            Some("2025-04-01T04:00:00Z".into()),
        )
        .unwrap();
        // Past resolution SLA, not yet resolved → overdue
        assert_eq!(r.resolution_overdue("2025-04-01T05:00:00Z").len(), 1);
        // Resolve → not overdue
        r.assign("t1", "agent", "2025-04-01T00:01:00Z").unwrap();
        r.transition(
            "t1",
            TicketStage::InProgress,
            "agent",
            "2025-04-01T00:02:00Z",
            "n",
        )
        .unwrap();
        r.transition(
            "t1",
            TicketStage::Resolved,
            "agent",
            "2025-04-01T03:00:00Z",
            "n",
        )
        .unwrap();
        assert_eq!(r.resolution_overdue("2025-04-01T05:00:00Z").len(), 0);
    }

    #[test]
    fn link_incident() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P0)).unwrap();
        r.link_incident("t1", "INC-2025-007").unwrap();
        assert_eq!(
            r.get("t1").unwrap().linked_incident_id.as_deref(),
            Some("INC-2025-007")
        );
    }

    #[test]
    fn add_tag_dedupes() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.add_tag("t1", "billing").unwrap();
        r.add_tag("t1", "billing").unwrap();
        r.add_tag("t1", "vip").unwrap();
        assert_eq!(r.get("t1").unwrap().tags, vec!["billing", "vip"]);
    }

    #[test]
    fn unknown_ticket_errors() {
        let r = SupportTicketRegister::new();
        let err = r.assign("nope", "agent", "2025-04-01T00:01:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown ticket"));
    }

    #[test]
    fn for_tenant_customer_assignee_filters() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        let mut other = ticket("t2", "bob", TicketPriority::P2);
        other.tenant_id = "tenant-b".into();
        r.open(other).unwrap();
        r.assign("t1", "agent-bob", "2025-04-01T00:01:00Z").unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_customer("alice").len(), 1);
        assert_eq!(r.for_customer("bob").len(), 1);
        assert_eq!(r.for_assignee("agent-bob").len(), 1);
        assert_eq!(r.for_assignee("ghost").len(), 0);
    }

    #[test]
    fn by_stage_filters() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.open(ticket("t2", "bob", TicketPriority::P2)).unwrap();
        r.transition(
            "t2",
            TicketStage::Cancelled,
            "system",
            "2025-04-01T00:05:00Z",
            "spam",
        )
        .unwrap();
        assert_eq!(r.by_stage(TicketStage::Open).len(), 1);
        assert_eq!(r.by_stage(TicketStage::Cancelled).len(), 1);
    }

    #[test]
    fn open_tickets_filter() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        r.open(ticket("t2", "bob", TicketPriority::P2)).unwrap();
        r.transition(
            "t2",
            TicketStage::Cancelled,
            "system",
            "2025-04-01T00:05:00Z",
            "spam",
        )
        .unwrap();
        let open = r.open_tickets();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].ticket_id, "t1");
    }

    #[test]
    fn at_least_priority_filter() {
        let r = SupportTicketRegister::new();
        r.open(ticket("p0", "alice", TicketPriority::P0)).unwrap();
        r.open(ticket("p1", "bob", TicketPriority::P1)).unwrap();
        r.open(ticket("p2", "carol", TicketPriority::P2)).unwrap();
        r.open(ticket("p3", "dave", TicketPriority::P3)).unwrap();
        // P1 threshold returns P0 + P1
        let high = r.at_least_priority(TicketPriority::P1);
        let ids: Vec<_> = high.iter().map(|t| t.ticket_id.clone()).collect();
        assert!(ids.contains(&"p0".to_string()));
        assert!(ids.contains(&"p1".to_string()));
        assert!(!ids.contains(&"p2".to_string()));
    }

    #[test]
    fn priority_helpers() {
        assert!(TicketPriority::P0.requires_paging());
        assert!(TicketPriority::P1.requires_paging());
        assert!(!TicketPriority::P2.requires_paging());
        assert!(!TicketPriority::P3.requires_paging());
        assert!(TicketPriority::P0.rank() < TicketPriority::P3.rank());
    }

    #[test]
    fn csat_helpers() {
        assert!(CsatRating::VerySatisfied.is_positive());
        assert!(CsatRating::Satisfied.is_positive());
        assert!(!CsatRating::Neutral.is_positive());
        assert!(!CsatRating::Dissatisfied.is_positive());
        assert_eq!(CsatRating::VeryDissatisfied.score(), 1);
        assert_eq!(CsatRating::VerySatisfied.score(), 5);
    }

    #[test]
    fn mean_csat_score() {
        let r = SupportTicketRegister::new();
        // Open a few tickets, resolve them, record CSAT.
        for (id, csat) in [
            ("t1", CsatRating::VerySatisfied),
            ("t2", CsatRating::Satisfied),
            ("t3", CsatRating::Neutral),
        ] {
            r.open(ticket(id, "alice", TicketPriority::P2)).unwrap();
            r.assign(id, "agent", "2025-04-01T00:01:00Z").unwrap();
            r.transition(id, TicketStage::InProgress, "agent", "2025-04-01T00:02:00Z", "n").unwrap();
            r.transition(id, TicketStage::Resolved, "agent", "2025-04-01T01:00:00Z", "n").unwrap();
            r.record_csat(id, csat).unwrap();
        }
        // Mean = (5+4+3)/3 = 4.0
        let mean = r.mean_csat_score().unwrap();
        assert!((mean - 4.0).abs() < 1e-9);
    }

    #[test]
    fn mean_csat_none_when_no_ratings() {
        let r = SupportTicketRegister::new();
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        assert!(r.mean_csat_score().is_none());
    }

    #[test]
    fn stage_helpers() {
        for s in [TicketStage::Closed, TicketStage::Cancelled] {
            assert!(s.is_terminal());
            assert!(!s.is_open());
        }
        for s in [
            TicketStage::Open,
            TicketStage::Assigned,
            TicketStage::InProgress,
            TicketStage::AwaitingCustomer,
            TicketStage::Resolved,
        ] {
            assert!(s.is_open());
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = SupportTicketRegister::new();
        assert_eq!(r.count(), 0);
        r.open(ticket("t1", "alice", TicketPriority::P2)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn ticket_serde() {
        let t = ticket("t1", "alice", TicketPriority::P2);
        let j = serde_json::to_string(&t).unwrap();
        let back: SupportTicket = serde_json::from_str(&j).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn enums_serde() {
        for c in [
            TicketChannel::Email,
            TicketChannel::WebForm,
            TicketChannel::InAppChat,
            TicketChannel::Phone,
            TicketChannel::Slack,
            TicketChannel::Api,
            TicketChannel::SocialMedia,
            TicketChannel::Other,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<TicketChannel>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
        for p in [
            TicketPriority::P0,
            TicketPriority::P1,
            TicketPriority::P2,
            TicketPriority::P3,
        ] {
            assert_eq!(
                p,
                serde_json::from_str::<TicketPriority>(&serde_json::to_string(&p).unwrap())
                    .unwrap()
            );
        }
        for cat in [
            TicketCategory::Bug,
            TicketCategory::Question,
            TicketCategory::Billing,
            TicketCategory::FeatureRequest,
            TicketCategory::Account,
            TicketCategory::Performance,
            TicketCategory::Security,
            TicketCategory::Feedback,
            TicketCategory::Other,
        ] {
            assert_eq!(
                cat,
                serde_json::from_str::<TicketCategory>(&serde_json::to_string(&cat).unwrap())
                    .unwrap()
            );
        }
        for s in [
            TicketStage::Open,
            TicketStage::Assigned,
            TicketStage::InProgress,
            TicketStage::AwaitingCustomer,
            TicketStage::Resolved,
            TicketStage::Closed,
            TicketStage::Cancelled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<TicketStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for c in [
            CsatRating::VeryDissatisfied,
            CsatRating::Dissatisfied,
            CsatRating::Neutral,
            CsatRating::Satisfied,
            CsatRating::VerySatisfied,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<CsatRating>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
    }
}
