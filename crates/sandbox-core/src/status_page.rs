//! Public status-page state.
//!
//! Maps to the customer-facing status page (Statuspage.io / Atlassian
//! Statuspage / instatus pattern). Distinct from [`crate::incident`] (the
//! internal incident record) and [`crate::compliance_dashboard`]
//! (regulator dashboard), this module is the **public-facing component
//! status board** that customers refresh during outages.
//!
//! Each [`Component`] (e.g., "API", "Web UI", "Webhooks", "Authentication")
//! has a current [`OperationalStatus`]. Each public-facing [`PublicIncident`]
//! groups updates over time (`investigating → identified → monitoring →
//! resolved`) and lists the components it impacts. The registry exposes
//! `summary()` to produce a single-page snapshot suitable for rendering
//! to a public HTML/JSON status page.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// OperationalStatus
// =============================================================================

/// Operational status of a single component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalStatus {
    /// Fully operational.
    Operational,
    /// Subset of users see degraded performance.
    DegradedPerformance,
    /// Subset of users see outright failures.
    PartialOutage,
    /// All users see failures.
    MajorOutage,
    /// Planned maintenance window.
    UnderMaintenance,
}

impl OperationalStatus {
    /// Display label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Operational => "Operational",
            Self::DegradedPerformance => "Degraded Performance",
            Self::PartialOutage => "Partial Outage",
            Self::MajorOutage => "Major Outage",
            Self::UnderMaintenance => "Under Maintenance",
        }
    }

    /// Numeric severity rank (higher = worse).
    pub fn severity_rank(self) -> u8 {
        match self {
            Self::Operational => 0,
            Self::UnderMaintenance => 1,
            Self::DegradedPerformance => 2,
            Self::PartialOutage => 3,
            Self::MajorOutage => 4,
        }
    }
}

// =============================================================================
// IncidentStage
// =============================================================================

/// Public incident lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStage {
    /// Investigating — we know something is wrong.
    Investigating,
    /// Identified — root cause known.
    Identified,
    /// Monitoring — fix deployed; watching for stability.
    Monitoring,
    /// Resolved.
    Resolved,
    /// Postmortem published.
    PostmortemPublished,
}

impl IncidentStage {
    /// True if the incident is fully closed for the customer.
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Resolved | Self::PostmortemPublished)
    }
}

// =============================================================================
// Component
// =============================================================================

/// One status-page component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Component {
    /// Unique id within the page.
    pub component_id: String,
    /// Display name.
    pub name: String,
    /// Long description (shown when the component is expanded).
    pub description: Option<String>,
    /// Current status.
    pub status: OperationalStatus,
    /// Sort order (lower first).
    pub display_order: u32,
    /// RFC 3339 — last updated.
    pub last_updated_at: String,
}

// =============================================================================
// IncidentUpdate
// =============================================================================

/// One update on a public incident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IncidentUpdate {
    /// RFC 3339.
    pub at: String,
    /// Stage at the time of this update.
    pub stage: IncidentStage,
    /// Author / posting team.
    pub author: String,
    /// Public-facing message.
    pub message: String,
}

// =============================================================================
// PublicIncident
// =============================================================================

/// A customer-facing incident record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicIncident {
    /// Unique id.
    pub incident_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Public title.
    pub title: String,
    /// Current stage.
    pub stage: IncidentStage,
    /// Component ids impacted.
    pub impacted_components: Vec<String>,
    /// Updates (chronological).
    pub updates: Vec<IncidentUpdate>,
    /// RFC 3339 — first publicly posted.
    pub started_at: String,
    /// RFC 3339 — resolved.
    pub resolved_at: Option<String>,
    /// Postmortem URL if published.
    pub postmortem_url: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl PublicIncident {
    /// New incident in `Investigating`.
    pub fn new(
        incident_id: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        started_at: impl Into<String>,
    ) -> Self {
        Self {
            incident_id: incident_id.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            stage: IncidentStage::Investigating,
            impacted_components: Vec::new(),
            updates: Vec::new(),
            started_at: started_at.into(),
            resolved_at: None,
            postmortem_url: None,
            tags: Vec::new(),
        }
    }
}

// =============================================================================
// PageSummary
// =============================================================================

/// Snapshot of the public status page suitable for a single render.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PageSummary {
    /// Tenant.
    pub tenant_id: String,
    /// Aggregate status across all components (worst severity wins).
    pub overall_status: OperationalStatus,
    /// Components in display order.
    pub components: Vec<Component>,
    /// Active (not closed) incidents, in start order.
    pub active_incidents: Vec<PublicIncident>,
    /// Recent resolved incidents (limited count).
    pub recent_resolved: Vec<PublicIncident>,
    /// RFC 3339 — when this snapshot was taken.
    pub generated_at: String,
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: IncidentStage, to: IncidentStage) -> bool {
    use IncidentStage::*;
    match (from, to) {
        (Investigating, Identified)
        | (Investigating, Monitoring)
        | (Investigating, Resolved)
        | (Identified, Monitoring)
        | (Identified, Resolved)
        | (Monitoring, Resolved)
        | (Monitoring, Investigating) // re-flare
        | (Resolved, PostmortemPublished) => true,
        _ => false,
    }
}

// =============================================================================
// StatusPage
// =============================================================================

/// Per-tenant status-page registry — components plus public incidents.
#[derive(Debug, Default)]
pub struct StatusPage {
    components: RwLock<HashMap<String, Component>>,
    incidents: RwLock<HashMap<String, PublicIncident>>,
    tenant_id: String,
}

impl StatusPage {
    /// New empty status page for a tenant.
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            components: RwLock::new(HashMap::new()),
            incidents: RwLock::new(HashMap::new()),
            tenant_id: tenant_id.into(),
        }
    }

    /// Register a component.
    pub fn register_component(&self, component: Component) -> SandboxResult<()> {
        let mut g = self
            .components
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        if g.contains_key(&component.component_id) {
            return Err(SandboxError::Other(format!(
                "component already registered: {}",
                component.component_id
            )));
        }
        g.insert(component.component_id.clone(), component);
        Ok(())
    }

    /// Update a component's operational status.
    pub fn set_component_status(
        &self,
        component_id: &str,
        status: OperationalStatus,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .components
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        let c = g
            .get_mut(component_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown component {component_id}")))?;
        c.status = status;
        c.last_updated_at = at.into();
        Ok(())
    }

    /// Look up a component.
    pub fn get_component(&self, component_id: &str) -> Option<Component> {
        let g = self.components.read().ok()?;
        g.get(component_id).cloned()
    }

    /// All components in display order.
    pub fn all_components(&self) -> Vec<Component> {
        let mut out: Vec<Component> = match self.components.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => return Vec::new(),
        };
        out.sort_by_key(|c| c.display_order);
        out
    }

    /// Open a public incident.
    pub fn open_incident(&self, incident: PublicIncident) -> SandboxResult<()> {
        if !matches!(incident.stage, IncidentStage::Investigating) {
            return Err(SandboxError::Other(format!(
                "incident must start Investigating, got {:?}",
                incident.stage
            )));
        }
        let mut g = self
            .incidents
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        if g.contains_key(&incident.incident_id) {
            return Err(SandboxError::Other(format!(
                "incident already opened: {}",
                incident.incident_id
            )));
        }
        g.insert(incident.incident_id.clone(), incident);
        Ok(())
    }

    /// Apply a stage transition. Optionally append an update message.
    pub fn transition_incident(
        &self,
        incident_id: &str,
        new_stage: IncidentStage,
        author: impl Into<String>,
        message: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<PublicIncident> {
        let mut g = self
            .incidents
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        let i = g
            .get_mut(incident_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown incident {incident_id}")))?;
        if !legal_transition(i.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                i.stage, new_stage
            )));
        }
        let when = at.into();
        let upd = IncidentUpdate {
            at: when.clone(),
            stage: new_stage,
            author: author.into(),
            message: message.into(),
        };
        i.stage = new_stage;
        i.updates.push(upd);
        if matches!(new_stage, IncidentStage::Resolved) {
            i.resolved_at = Some(when);
        }
        Ok(i.clone())
    }

    /// Add an impacted component to an open incident (deduplicated).
    pub fn add_impacted_component(
        &self,
        incident_id: &str,
        component_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .incidents
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        let i = g
            .get_mut(incident_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown incident {incident_id}")))?;
        let c = component_id.into();
        if !i.impacted_components.contains(&c) {
            i.impacted_components.push(c);
        }
        Ok(())
    }

    /// Set postmortem URL.
    pub fn set_postmortem_url(
        &self,
        incident_id: &str,
        url: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .incidents
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        let i = g
            .get_mut(incident_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown incident {incident_id}")))?;
        i.postmortem_url = Some(url.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_incident_tag(
        &self,
        incident_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .incidents
            .write()
            .map_err(|_| SandboxError::Other("status page poisoned".into()))?;
        let i = g
            .get_mut(incident_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown incident {incident_id}")))?;
        let tag = tag.into();
        if !i.tags.contains(&tag) {
            i.tags.push(tag);
        }
        Ok(())
    }

    /// Look up an incident.
    pub fn get_incident(&self, incident_id: &str) -> Option<PublicIncident> {
        let g = self.incidents.read().ok()?;
        g.get(incident_id).cloned()
    }

    /// All incidents.
    pub fn all_incidents(&self) -> Vec<PublicIncident> {
        match self.incidents.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active (not Resolved / PostmortemPublished) incidents, sorted by
    /// `started_at` ascending.
    pub fn active_incidents(&self) -> Vec<PublicIncident> {
        let mut out: Vec<PublicIncident> = self
            .all_incidents()
            .into_iter()
            .filter(|i| !i.stage.is_closed())
            .collect();
        out.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        out
    }

    /// Resolved incidents, sorted by resolved_at descending (newest first).
    pub fn resolved_incidents(&self) -> Vec<PublicIncident> {
        let mut out: Vec<PublicIncident> = self
            .all_incidents()
            .into_iter()
            .filter(|i| i.stage.is_closed())
            .collect();
        out.sort_by(|a, b| {
            b.resolved_at
                .as_deref()
                .unwrap_or("")
                .cmp(a.resolved_at.as_deref().unwrap_or(""))
        });
        out
    }

    /// Aggregate operational status (worst severity across components).
    pub fn overall_status(&self) -> OperationalStatus {
        let comps = self.all_components();
        if comps.is_empty() {
            return OperationalStatus::Operational;
        }
        comps
            .iter()
            .map(|c| c.status)
            .max_by_key(|s| s.severity_rank())
            .unwrap_or(OperationalStatus::Operational)
    }

    /// Single-page summary suitable for rendering.
    pub fn summary(&self, generated_at: impl Into<String>, recent_count: usize) -> PageSummary {
        let mut recent = self.resolved_incidents();
        recent.truncate(recent_count);
        PageSummary {
            tenant_id: self.tenant_id.clone(),
            overall_status: self.overall_status(),
            components: self.all_components(),
            active_incidents: self.active_incidents(),
            recent_resolved: recent,
            generated_at: generated_at.into(),
        }
    }

    /// Component count.
    pub fn component_count(&self) -> usize {
        self.components.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Incident count.
    pub fn incident_count(&self) -> usize {
        self.incidents.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(id: &str, status: OperationalStatus, order: u32) -> Component {
        Component {
            component_id: id.into(),
            name: id.to_uppercase(),
            description: None,
            status,
            display_order: order,
            last_updated_at: "2025-05-08T00:00:00Z".into(),
        }
    }

    fn incident(id: &str) -> PublicIncident {
        PublicIncident::new(id, "tenant-a", format!("title-{id}"), "2025-05-08T00:00:00Z")
    }

    #[test]
    fn register_component_and_get() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        let c = s.get_component("api").unwrap();
        assert_eq!(c.status, OperationalStatus::Operational);
    }

    #[test]
    fn duplicate_component_errors() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        let err = s
            .register_component(comp("api", OperationalStatus::Operational, 2))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn set_component_status_updates_timestamp() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        s.set_component_status(
            "api",
            OperationalStatus::PartialOutage,
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        let c = s.get_component("api").unwrap();
        assert_eq!(c.status, OperationalStatus::PartialOutage);
        assert_eq!(c.last_updated_at, "2025-05-08T01:00:00Z");
    }

    #[test]
    fn unknown_component_errors() {
        let s = StatusPage::new("tenant-a");
        let err = s
            .set_component_status(
                "nope",
                OperationalStatus::Operational,
                "2025-05-08T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown component"));
    }

    #[test]
    fn all_components_sorted_by_order() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("ui", OperationalStatus::Operational, 2))
            .unwrap();
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        s.register_component(comp("hooks", OperationalStatus::Operational, 3))
            .unwrap();
        let v: Vec<_> = s
            .all_components()
            .into_iter()
            .map(|c| c.component_id)
            .collect();
        assert_eq!(v, vec!["api", "ui", "hooks"]);
    }

    #[test]
    fn open_incident_must_start_investigating() {
        let s = StatusPage::new("tenant-a");
        let mut i = incident("i1");
        i.stage = IncidentStage::Resolved;
        let err = s.open_incident(i).unwrap_err();
        assert!(format!("{err}").contains("must start Investigating"));
    }

    #[test]
    fn duplicate_incident_errors() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        let err = s.open_incident(incident("i1")).unwrap_err();
        assert!(format!("{err}").contains("already opened"));
    }

    #[test]
    fn legal_transitions_table() {
        use IncidentStage::*;
        assert!(legal_transition(Investigating, Identified));
        assert!(legal_transition(Investigating, Monitoring));
        assert!(legal_transition(Investigating, Resolved));
        assert!(legal_transition(Identified, Monitoring));
        assert!(legal_transition(Identified, Resolved));
        assert!(legal_transition(Monitoring, Resolved));
        assert!(legal_transition(Monitoring, Investigating)); // re-flare
        assert!(legal_transition(Resolved, PostmortemPublished));
        // illegal
        assert!(!legal_transition(Investigating, PostmortemPublished));
        assert!(!legal_transition(PostmortemPublished, Investigating));
        assert!(!legal_transition(Resolved, Identified));
    }

    #[test]
    fn happy_path_lifecycle() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Identified,
            "ops",
            "found root cause",
            "2025-05-08T00:30:00Z",
        )
        .unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Monitoring,
            "ops",
            "fix deployed",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        let i = s
            .transition_incident(
                "i1",
                IncidentStage::Resolved,
                "ops",
                "stable",
                "2025-05-08T02:00:00Z",
            )
            .unwrap();
        assert_eq!(i.stage, IncidentStage::Resolved);
        assert_eq!(i.resolved_at.as_deref(), Some("2025-05-08T02:00:00Z"));
        assert_eq!(i.updates.len(), 3);
    }

    #[test]
    fn re_flare_allowed() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Monitoring,
            "ops",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        let i = s
            .transition_incident(
                "i1",
                IncidentStage::Investigating,
                "ops",
                "re-flare",
                "2025-05-08T02:00:00Z",
            )
            .unwrap();
        assert_eq!(i.stage, IncidentStage::Investigating);
    }

    #[test]
    fn add_impacted_component_dedupes() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.add_impacted_component("i1", "api").unwrap();
        s.add_impacted_component("i1", "api").unwrap();
        s.add_impacted_component("i1", "ui").unwrap();
        assert_eq!(
            s.get_incident("i1").unwrap().impacted_components,
            vec!["api", "ui"]
        );
    }

    #[test]
    fn set_postmortem_url() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.set_postmortem_url("i1", "https://example.com/postmortem")
            .unwrap();
        assert_eq!(
            s.get_incident("i1").unwrap().postmortem_url.as_deref(),
            Some("https://example.com/postmortem")
        );
    }

    #[test]
    fn add_incident_tag_dedupes() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.add_incident_tag("i1", "p0").unwrap();
        s.add_incident_tag("i1", "p0").unwrap();
        s.add_incident_tag("i1", "data-loss").unwrap();
        assert_eq!(
            s.get_incident("i1").unwrap().tags,
            vec!["p0", "data-loss"]
        );
    }

    #[test]
    fn active_incidents_excludes_closed() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.open_incident(incident("i2")).unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Resolved,
            "ops",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        let active = s.active_incidents();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].incident_id, "i2");
    }

    #[test]
    fn resolved_incidents_newest_first() {
        let s = StatusPage::new("tenant-a");
        s.open_incident(incident("i1")).unwrap();
        s.open_incident(incident("i2")).unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Resolved,
            "ops",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        s.transition_incident(
            "i2",
            IncidentStage::Resolved,
            "ops",
            "n",
            "2025-05-08T03:00:00Z",
        )
        .unwrap();
        let r = s.resolved_incidents();
        assert_eq!(r[0].incident_id, "i2");
        assert_eq!(r[1].incident_id, "i1");
    }

    #[test]
    fn overall_status_picks_worst() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        s.register_component(comp(
            "ui",
            OperationalStatus::DegradedPerformance,
            2,
        ))
        .unwrap();
        s.register_component(comp("hooks", OperationalStatus::PartialOutage, 3))
            .unwrap();
        assert_eq!(s.overall_status(), OperationalStatus::PartialOutage);
    }

    #[test]
    fn overall_status_empty_is_operational() {
        let s = StatusPage::new("tenant-a");
        assert_eq!(s.overall_status(), OperationalStatus::Operational);
    }

    #[test]
    fn summary_renders() {
        let s = StatusPage::new("tenant-a");
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        s.register_component(comp(
            "ui",
            OperationalStatus::PartialOutage,
            2,
        ))
        .unwrap();
        s.open_incident(incident("i1")).unwrap();
        s.transition_incident(
            "i1",
            IncidentStage::Resolved,
            "ops",
            "n",
            "2025-05-08T01:00:00Z",
        )
        .unwrap();
        s.open_incident(incident("i2")).unwrap();
        let sum = s.summary("2025-05-08T02:00:00Z", 5);
        assert_eq!(sum.tenant_id, "tenant-a");
        assert_eq!(sum.overall_status, OperationalStatus::PartialOutage);
        assert_eq!(sum.components.len(), 2);
        assert_eq!(sum.active_incidents.len(), 1);
        assert_eq!(sum.active_incidents[0].incident_id, "i2");
        assert_eq!(sum.recent_resolved.len(), 1);
    }

    #[test]
    fn summary_truncates_recent_count() {
        let s = StatusPage::new("tenant-a");
        for i in 1..=5 {
            let id = format!("i{i}");
            s.open_incident(PublicIncident::new(
                &id,
                "tenant-a",
                format!("title-{id}"),
                format!("2025-05-08T0{i}:00:00Z"),
            ))
            .unwrap();
            s.transition_incident(
                &id,
                IncidentStage::Resolved,
                "ops",
                "n",
                format!("2025-05-08T0{i}:30:00Z"),
            )
            .unwrap();
        }
        let sum = s.summary("2025-05-08T10:00:00Z", 2);
        assert_eq!(sum.recent_resolved.len(), 2);
    }

    #[test]
    fn count_helpers() {
        let s = StatusPage::new("tenant-a");
        assert_eq!(s.component_count(), 0);
        assert_eq!(s.incident_count(), 0);
        s.register_component(comp("api", OperationalStatus::Operational, 1))
            .unwrap();
        s.open_incident(incident("i1")).unwrap();
        assert_eq!(s.component_count(), 1);
        assert_eq!(s.incident_count(), 1);
    }

    #[test]
    fn status_helpers() {
        assert_eq!(OperationalStatus::Operational.label(), "Operational");
        assert!(
            OperationalStatus::MajorOutage.severity_rank()
                > OperationalStatus::PartialOutage.severity_rank()
        );
        assert!(IncidentStage::Resolved.is_closed());
        assert!(IncidentStage::PostmortemPublished.is_closed());
        assert!(!IncidentStage::Monitoring.is_closed());
    }

    #[test]
    fn component_serde() {
        let c = comp("api", OperationalStatus::Operational, 1);
        let j = serde_json::to_string(&c).unwrap();
        let back: Component = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn incident_and_summary_serde() {
        let i = incident("i1");
        assert_eq!(
            i,
            serde_json::from_str::<PublicIncident>(&serde_json::to_string(&i).unwrap()).unwrap()
        );
        let s = StatusPage::new("tenant-a");
        let sum = s.summary("2025-05-08T02:00:00Z", 5);
        assert_eq!(
            sum,
            serde_json::from_str::<PageSummary>(&serde_json::to_string(&sum).unwrap()).unwrap()
        );
    }

    #[test]
    fn enums_serde() {
        for s in [
            OperationalStatus::Operational,
            OperationalStatus::DegradedPerformance,
            OperationalStatus::PartialOutage,
            OperationalStatus::MajorOutage,
            OperationalStatus::UnderMaintenance,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<OperationalStatus>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for s in [
            IncidentStage::Investigating,
            IncidentStage::Identified,
            IncidentStage::Monitoring,
            IncidentStage::Resolved,
            IncidentStage::PostmortemPublished,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<IncidentStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
