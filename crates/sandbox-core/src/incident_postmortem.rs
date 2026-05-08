//! Structured incident postmortem (RCA) records.
//!
//! Complements [`crate::incident`] (which raises and dispatches incidents)
//! by providing the *retrospective* artifact every regulator and SRE org
//! produces after the fact. A [`Postmortem`] captures:
//!
//! - **Timeline** — chronological events with timestamps.
//! - **Root cause(s)** — categorized using the standard SRE buckets.
//! - **Impact** — affected tenants, blast radius, duration, dollar impact.
//! - **Action items** — owners, due dates, severity.
//! - **Lessons learned** — what we'd do differently.
//!
//! Every postmortem has a `postmortem_hash` so it can be sealed and
//! referenced from regulator filings.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RootCauseCategory
// =============================================================================

/// SRE-style root-cause classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootCauseCategory {
    /// Bug in own code.
    SoftwareBug,
    /// Misconfiguration.
    Configuration,
    /// Capacity / resource exhaustion.
    Capacity,
    /// Hardware / infrastructure failure.
    Infrastructure,
    /// Third-party / vendor outage.
    ThirdParty,
    /// Human error / process gap.
    Process,
    /// Security incident.
    Security,
    /// Data quality issue (drift, schema, missingness).
    DataQuality,
    /// Model performance issue (e.g., bias, drift).
    Model,
    /// Other.
    Other,
}

// =============================================================================
// Severity
// =============================================================================

/// Postmortem severity (per the team's incident framework).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostmortemSeverity {
    /// SEV-1: outage, customer impact.
    Sev1,
    /// SEV-2: degraded.
    Sev2,
    /// SEV-3: minor / internal.
    Sev3,
    /// SEV-4: near-miss.
    Sev4,
}

// =============================================================================
// TimelineEvent
// =============================================================================

/// One point on the incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEvent {
    /// RFC 3339 wall-clock.
    pub at: String,
    /// Free-text event description.
    pub event: String,
    /// Optional actor (operator / system / customer).
    pub actor: Option<String>,
}

// =============================================================================
// ActionItem
// =============================================================================

/// Action-item priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPriority {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
}

/// One follow-up action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionItem {
    /// Stable id.
    pub action_id: Uuid,
    /// Description.
    pub description: String,
    /// Owner (team or person).
    pub owner: String,
    /// Priority.
    pub priority: ActionPriority,
    /// Due date (RFC 3339).
    pub due_at: Option<String>,
    /// `true` if completed.
    pub completed: bool,
    /// Optional ticket reference (Jira / Linear / GitHub).
    pub ticket_ref: Option<String>,
}

impl ActionItem {
    /// New open action.
    pub fn new(
        description: impl Into<String>,
        owner: impl Into<String>,
        priority: ActionPriority,
    ) -> Self {
        Self {
            action_id: Uuid::now_v7(),
            description: description.into(),
            owner: owner.into(),
            priority,
            due_at: None,
            completed: false,
            ticket_ref: None,
        }
    }
    /// Builder: due date.
    pub fn due(mut self, due_at: impl Into<String>) -> Self {
        self.due_at = Some(due_at.into());
        self
    }
    /// Builder: ticket reference.
    pub fn with_ticket(mut self, t: impl Into<String>) -> Self {
        self.ticket_ref = Some(t.into());
        self
    }
}

// =============================================================================
// Impact
// =============================================================================

/// Quantified impact.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Impact {
    /// Affected tenant ids.
    pub affected_tenants: Vec<String>,
    /// Total minutes of degradation.
    pub minutes_of_degradation: u64,
    /// Number of seals affected.
    pub seals_affected: u64,
    /// Number of customer-facing requests affected.
    pub customer_requests_affected: u64,
    /// Estimated revenue impact in micro-currency-units.
    pub micro_revenue_impact: i64,
    /// Free-text summary.
    pub summary: String,
}

// =============================================================================
// Postmortem
// =============================================================================

/// One postmortem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Postmortem {
    /// Stable id.
    pub postmortem_id: Uuid,
    /// Originating incident id (if linked).
    pub incident_id: Option<String>,
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: PostmortemSeverity,
    /// Author (postmortem owner).
    pub author: String,
    /// Tenant scope (None for cross-tenant).
    pub tenant_id: Option<String>,
    /// Service most directly affected.
    pub primary_service: Option<String>,
    /// RFC 3339 incident start.
    pub started_at: Option<String>,
    /// RFC 3339 incident detected.
    pub detected_at: Option<String>,
    /// RFC 3339 incident resolved.
    pub resolved_at: Option<String>,
    /// Timeline (chronological).
    pub timeline: Vec<TimelineEvent>,
    /// Root cause categories.
    pub root_causes: Vec<RootCauseCategory>,
    /// Free-text root cause analysis.
    pub root_cause_analysis: String,
    /// Quantified impact.
    pub impact: Impact,
    /// Action items.
    pub action_items: Vec<ActionItem>,
    /// Lessons learned.
    pub lessons_learned: Vec<String>,
    /// RFC 3339 created.
    pub created_at: String,
    /// `true` if blameless framing was applied.
    pub blameless: bool,
    /// Hash of the postmortem (excluding `postmortem_hash`).
    pub postmortem_hash: Sha256Digest,
}

impl Postmortem {
    /// Number of open actions.
    pub fn open_actions(&self) -> usize {
        self.action_items.iter().filter(|a| !a.completed).count()
    }

    /// MTTR in minutes (started → resolved). None if dates missing.
    pub fn mttr_minutes(&self) -> Option<i64> {
        let start = self
            .started_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        let end = self
            .resolved_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        Some(((end - start).whole_seconds() / 60).max(0))
    }

    /// MTTD in minutes (started → detected). None if dates missing.
    pub fn mttd_minutes(&self) -> Option<i64> {
        let start = self
            .started_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        let detect = self
            .detected_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        Some(((detect - start).whole_seconds() / 60).max(0))
    }

    fn compute_hash(
        title: &str,
        severity: PostmortemSeverity,
        rca: &str,
        timeline: &[TimelineEvent],
        actions: &[ActionItem],
    ) -> Sha256Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(title.as_bytes());
        buf.push(0);
        buf.push(severity_rank(severity));
        buf.extend_from_slice(rca.as_bytes());
        for t in timeline {
            buf.extend_from_slice(t.at.as_bytes());
            buf.extend_from_slice(t.event.as_bytes());
        }
        for a in actions {
            buf.extend_from_slice(a.description.as_bytes());
            buf.extend_from_slice(a.owner.as_bytes());
        }
        Hasher::sha256(&buf)
    }
}

fn severity_rank(s: PostmortemSeverity) -> u8 {
    match s {
        PostmortemSeverity::Sev1 => 1,
        PostmortemSeverity::Sev2 => 2,
        PostmortemSeverity::Sev3 => 3,
        PostmortemSeverity::Sev4 => 4,
    }
}

// =============================================================================
// PostmortemBuilder
// =============================================================================

/// Builder for [`Postmortem`].
pub struct PostmortemBuilder {
    title: String,
    severity: PostmortemSeverity,
    author: String,
    incident_id: Option<String>,
    tenant_id: Option<String>,
    primary_service: Option<String>,
    started_at: Option<String>,
    detected_at: Option<String>,
    resolved_at: Option<String>,
    timeline: Vec<TimelineEvent>,
    root_causes: Vec<RootCauseCategory>,
    rca: String,
    impact: Impact,
    actions: Vec<ActionItem>,
    lessons: Vec<String>,
    blameless: bool,
}

impl PostmortemBuilder {
    /// New builder with required fields.
    pub fn new(
        title: impl Into<String>,
        severity: PostmortemSeverity,
        author: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            severity,
            author: author.into(),
            incident_id: None,
            tenant_id: None,
            primary_service: None,
            started_at: None,
            detected_at: None,
            resolved_at: None,
            timeline: Vec::new(),
            root_causes: Vec::new(),
            rca: String::new(),
            impact: Impact::default(),
            actions: Vec::new(),
            lessons: Vec::new(),
            blameless: true,
        }
    }
    /// Builder helpers.
    pub fn incident(mut self, id: impl Into<String>) -> Self {
        self.incident_id = Some(id.into());
        self
    }
    /// Tenant scope.
    pub fn tenant(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = Some(id.into());
        self
    }
    /// Primary service.
    pub fn service(mut self, s: impl Into<String>) -> Self {
        self.primary_service = Some(s.into());
        self
    }
    /// Started at.
    pub fn started(mut self, t: impl Into<String>) -> Self {
        self.started_at = Some(t.into());
        self
    }
    /// Detected at.
    pub fn detected(mut self, t: impl Into<String>) -> Self {
        self.detected_at = Some(t.into());
        self
    }
    /// Resolved at.
    pub fn resolved(mut self, t: impl Into<String>) -> Self {
        self.resolved_at = Some(t.into());
        self
    }
    /// Add a timeline event.
    pub fn timeline_event(mut self, e: TimelineEvent) -> Self {
        self.timeline.push(e);
        self
    }
    /// Add a root cause.
    pub fn root_cause(mut self, c: RootCauseCategory) -> Self {
        if !self.root_causes.contains(&c) {
            self.root_causes.push(c);
        }
        self
    }
    /// Set RCA text.
    pub fn rca(mut self, r: impl Into<String>) -> Self {
        self.rca = r.into();
        self
    }
    /// Set impact.
    pub fn impact(mut self, i: Impact) -> Self {
        self.impact = i;
        self
    }
    /// Add an action.
    pub fn action(mut self, a: ActionItem) -> Self {
        self.actions.push(a);
        self
    }
    /// Add a lesson.
    pub fn lesson(mut self, l: impl Into<String>) -> Self {
        self.lessons.push(l.into());
        self
    }
    /// Toggle blameless.
    pub fn blameless(mut self, b: bool) -> Self {
        self.blameless = b;
        self
    }
    /// Finalize.
    pub fn build(self) -> SandboxResult<Postmortem> {
        if self.title.trim().is_empty() {
            return Err(SandboxError::Other("postmortem requires title".into()));
        }
        // Sort timeline chronologically.
        let mut timeline = self.timeline;
        timeline.sort_by(|a, b| a.at.cmp(&b.at));

        let hash = Postmortem::compute_hash(
            &self.title,
            self.severity,
            &self.rca,
            &timeline,
            &self.actions,
        );
        Ok(Postmortem {
            postmortem_id: Uuid::now_v7(),
            incident_id: self.incident_id,
            title: self.title,
            severity: self.severity,
            author: self.author,
            tenant_id: self.tenant_id,
            primary_service: self.primary_service,
            started_at: self.started_at,
            detected_at: self.detected_at,
            resolved_at: self.resolved_at,
            timeline,
            root_causes: self.root_causes,
            root_cause_analysis: self.rca,
            impact: self.impact,
            action_items: self.actions,
            lessons_learned: self.lessons,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            blameless: self.blameless,
            postmortem_hash: hash,
        })
    }
}

// =============================================================================
// PostmortemRegistry
// =============================================================================

/// Append-only registry of postmortems.
#[derive(Default)]
pub struct PostmortemRegistry {
    inner: RwLock<Vec<Postmortem>>,
}

impl std::fmt::Debug for PostmortemRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostmortemRegistry")
            .field("count", &self.len())
            .finish()
    }
}

impl PostmortemRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append.
    pub fn append(&self, p: Postmortem) -> SandboxResult<Uuid> {
        let id = p.postmortem_id;
        self.inner
            .write()
            .map_err(|_| SandboxError::Other("postmortem registry poisoned".into()))?
            .push(p);
        Ok(id)
    }
    /// Find.
    pub fn find(&self, id: Uuid) -> Option<Postmortem> {
        self.inner
            .read()
            .ok()?
            .iter()
            .find(|p| p.postmortem_id == id)
            .cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<Postmortem> {
        self.inner.read().map(|g| g.clone()).unwrap_or_default()
    }
    /// Filter by severity.
    pub fn by_severity(&self, s: PostmortemSeverity) -> Vec<Postmortem> {
        self.all().into_iter().filter(|p| p.severity == s).collect()
    }
    /// Filter by root cause category.
    pub fn by_root_cause(&self, c: RootCauseCategory) -> Vec<Postmortem> {
        self.all()
            .into_iter()
            .filter(|p| p.root_causes.contains(&c))
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
    /// Empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pm() -> Postmortem {
        PostmortemBuilder::new("HSM outage", PostmortemSeverity::Sev1, "sre-team")
            .incident("INC-001")
            .service("hsm")
            .root_cause(RootCauseCategory::Infrastructure)
            .rca("HSM cluster lost quorum due to network partition")
            .lesson("Add multi-region HSM failover")
            .action(ActionItem::new(
                "Add multi-region failover",
                "platform",
                ActionPriority::High,
            ))
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_postmortem() {
        let p = pm();
        assert_eq!(p.title, "HSM outage");
        assert_eq!(p.severity, PostmortemSeverity::Sev1);
        assert_eq!(p.action_items.len(), 1);
    }

    #[test]
    fn empty_title_errors() {
        let r = PostmortemBuilder::new("", PostmortemSeverity::Sev1, "x").build();
        assert!(r.is_err());
    }

    #[test]
    fn timeline_sorted_chronologically() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev2, "a")
            .timeline_event(TimelineEvent {
                at: "2026-01-02T00:00:00Z".into(),
                event: "second".into(),
                actor: None,
            })
            .timeline_event(TimelineEvent {
                at: "2026-01-01T00:00:00Z".into(),
                event: "first".into(),
                actor: None,
            })
            .build()
            .unwrap();
        assert_eq!(p.timeline[0].event, "first");
    }

    #[test]
    fn root_causes_dedupe() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev2, "a")
            .root_cause(RootCauseCategory::Infrastructure)
            .root_cause(RootCauseCategory::Infrastructure)
            .build()
            .unwrap();
        assert_eq!(p.root_causes.len(), 1);
    }

    #[test]
    fn open_actions_count() {
        let p = pm();
        assert_eq!(p.open_actions(), 1);
    }

    #[test]
    fn mttr_calculated() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev2, "a")
            .started("2026-01-01T00:00:00Z")
            .resolved("2026-01-01T01:00:00Z")
            .build()
            .unwrap();
        assert_eq!(p.mttr_minutes(), Some(60));
    }

    #[test]
    fn mttd_calculated() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev2, "a")
            .started("2026-01-01T00:00:00Z")
            .detected("2026-01-01T00:15:00Z")
            .build()
            .unwrap();
        assert_eq!(p.mttd_minutes(), Some(15));
    }

    #[test]
    fn mttr_none_without_dates() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev2, "a")
            .build()
            .unwrap();
        assert!(p.mttr_minutes().is_none());
    }

    #[test]
    fn registry_append_and_find() {
        let r = PostmortemRegistry::new();
        let id = r.append(pm()).unwrap();
        assert!(r.find(id).is_some());
    }

    #[test]
    fn registry_filter_by_severity() {
        let r = PostmortemRegistry::new();
        r.append(pm()).unwrap();
        r.append(
            PostmortemBuilder::new("y", PostmortemSeverity::Sev3, "a")
                .build()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.by_severity(PostmortemSeverity::Sev1).len(), 1);
        assert_eq!(r.by_severity(PostmortemSeverity::Sev3).len(), 1);
    }

    #[test]
    fn registry_filter_by_root_cause() {
        let r = PostmortemRegistry::new();
        r.append(pm()).unwrap();
        assert_eq!(
            r.by_root_cause(RootCauseCategory::Infrastructure).len(),
            1
        );
        assert_eq!(r.by_root_cause(RootCauseCategory::Security).len(), 0);
    }

    #[test]
    fn action_priority_serde() {
        for p in [
            ActionPriority::Critical,
            ActionPriority::High,
            ActionPriority::Medium,
            ActionPriority::Low,
        ] {
            let j = serde_json::to_string(&p).unwrap();
            let q: ActionPriority = serde_json::from_str(&j).unwrap();
            assert_eq!(p, q);
        }
    }

    #[test]
    fn root_cause_serde() {
        for c in [
            RootCauseCategory::SoftwareBug,
            RootCauseCategory::Configuration,
            RootCauseCategory::Capacity,
            RootCauseCategory::Infrastructure,
            RootCauseCategory::ThirdParty,
            RootCauseCategory::Process,
            RootCauseCategory::Security,
            RootCauseCategory::DataQuality,
            RootCauseCategory::Model,
            RootCauseCategory::Other,
        ] {
            let j = serde_json::to_string(&c).unwrap();
            let p: RootCauseCategory = serde_json::from_str(&j).unwrap();
            assert_eq!(c, p);
        }
    }

    #[test]
    fn severity_serde() {
        for s in [
            PostmortemSeverity::Sev1,
            PostmortemSeverity::Sev2,
            PostmortemSeverity::Sev3,
            PostmortemSeverity::Sev4,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: PostmortemSeverity = serde_json::from_str(&j).unwrap();
            assert_eq!(s, p);
        }
    }

    #[test]
    fn postmortem_serde() {
        let p = pm();
        let j = serde_json::to_string(&p).unwrap();
        let q: Postmortem = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn action_item_with_due_and_ticket() {
        let a = ActionItem::new("x", "y", ActionPriority::High)
            .due("2026-12-31T00:00:00Z")
            .with_ticket("JIRA-1");
        assert_eq!(a.due_at.as_deref(), Some("2026-12-31T00:00:00Z"));
        assert_eq!(a.ticket_ref.as_deref(), Some("JIRA-1"));
    }

    #[test]
    fn impact_default_zero() {
        let i = Impact::default();
        assert_eq!(i.minutes_of_degradation, 0);
        assert_eq!(i.seals_affected, 0);
    }

    #[test]
    fn blameless_default_true() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev1, "a")
            .build()
            .unwrap();
        assert!(p.blameless);
    }

    #[test]
    fn blameless_can_be_disabled() {
        let p = PostmortemBuilder::new("x", PostmortemSeverity::Sev1, "a")
            .blameless(false)
            .build()
            .unwrap();
        assert!(!p.blameless);
    }

    #[test]
    fn registry_count_tracks() {
        let r = PostmortemRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
        r.append(pm()).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn hash_changes_with_title() {
        let p1 = PostmortemBuilder::new("a", PostmortemSeverity::Sev1, "x")
            .build()
            .unwrap();
        let p2 = PostmortemBuilder::new("b", PostmortemSeverity::Sev1, "x")
            .build()
            .unwrap();
        assert_ne!(p1.postmortem_hash, p2.postmortem_hash);
    }

    #[test]
    fn timeline_event_serde() {
        let e = TimelineEvent {
            at: "2026-01-01T00:00:00Z".into(),
            event: "x".into(),
            actor: Some("y".into()),
        };
        let j = serde_json::to_string(&e).unwrap();
        let p: TimelineEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn impact_serde() {
        let i = Impact {
            affected_tenants: vec!["FAB".into()],
            minutes_of_degradation: 30,
            seals_affected: 100,
            customer_requests_affected: 1000,
            micro_revenue_impact: -5_000_000,
            summary: "x".into(),
        };
        let j = serde_json::to_string(&i).unwrap();
        let p: Impact = serde_json::from_str(&j).unwrap();
        assert_eq!(p, i);
    }

    #[test]
    fn action_item_serde() {
        let a = ActionItem::new("x", "y", ActionPriority::Critical);
        let j = serde_json::to_string(&a).unwrap();
        let p: ActionItem = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }
}
