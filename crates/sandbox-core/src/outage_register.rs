//! Public-facing outage history.
//!
//! Customers and regulators expect a status page–style record of outages.
//! This module is the canonical source: every operator-acknowledged outage
//! gets an [`OutageEvent`] with affected services, duration, RCA reference,
//! and customer-facing summary.
//!
//! Distinct from [`crate::incident_postmortem`] which is internal RCA;
//! this module is the *external-facing* narrative.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// OutageStatus
// =============================================================================

/// Status of an outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageStatus {
    /// Currently investigating.
    Investigating,
    /// Identified.
    Identified,
    /// Monitoring (mitigated, not yet resolved).
    Monitoring,
    /// Resolved.
    Resolved,
}

// =============================================================================
// OutageImpactLevel
// =============================================================================

/// Customer-facing impact level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutageImpactLevel {
    /// Minor: degraded performance, no outage.
    Minor,
    /// Major: partial outage.
    Major,
    /// Critical: full outage.
    Critical,
}

// =============================================================================
// OutageUpdate
// =============================================================================

/// One status update inside an outage timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutageUpdate {
    /// RFC 3339.
    pub at: String,
    /// Status at this time.
    pub status: OutageStatus,
    /// Customer-facing message.
    pub message: String,
}

// =============================================================================
// OutageEvent
// =============================================================================

/// One outage record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutageEvent {
    /// Stable id.
    pub outage_id: Uuid,
    /// Title.
    pub title: String,
    /// Affected services.
    pub affected_services: Vec<String>,
    /// Affected tenants (None = global).
    pub affected_tenants: Option<Vec<String>>,
    /// Customer-facing summary.
    pub summary: String,
    /// Impact level.
    pub impact: OutageImpactLevel,
    /// Started at.
    pub started_at: String,
    /// Resolved at.
    pub resolved_at: Option<String>,
    /// Linked postmortem id.
    pub postmortem_ref: Option<String>,
    /// Updates.
    pub updates: Vec<OutageUpdate>,
}

impl OutageEvent {
    /// Most recent status from updates, or Investigating if none.
    pub fn current_status(&self) -> OutageStatus {
        self.updates
            .last()
            .map(|u| u.status)
            .unwrap_or(OutageStatus::Investigating)
    }
    /// Duration in minutes (None if unresolved).
    pub fn duration_minutes(&self) -> Option<i64> {
        let start = OffsetDateTime::parse(
            &self.started_at,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        let end = self
            .resolved_at
            .as_ref()
            .and_then(|s| OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok())?;
        Some((end - start).whole_seconds() / 60)
    }
}

// =============================================================================
// OutageRegister
// =============================================================================

#[derive(Default)]
struct State {
    outages: HashMap<Uuid, OutageEvent>,
}

/// Register.
pub struct OutageRegister {
    state: RwLock<State>,
}

impl Default for OutageRegister {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for OutageRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutageRegister")
            .field("outages", &self.len())
            .finish()
    }
}

impl OutageRegister {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open an outage.
    pub fn open(
        &self,
        title: impl Into<String>,
        affected_services: Vec<String>,
        impact: OutageImpactLevel,
        summary: impl Into<String>,
    ) -> SandboxResult<OutageEvent> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let initial = OutageUpdate {
            at: now.clone(),
            status: OutageStatus::Investigating,
            message: "We are aware of the issue and investigating.".into(),
        };
        let o = OutageEvent {
            outage_id: Uuid::now_v7(),
            title: title.into(),
            affected_services,
            affected_tenants: None,
            summary: summary.into(),
            impact,
            started_at: now,
            resolved_at: None,
            postmortem_ref: None,
            updates: vec![initial],
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("outage register poisoned".into()))?;
        g.outages.insert(o.outage_id, o.clone());
        Ok(o)
    }

    /// Add an update.
    pub fn add_update(
        &self,
        outage_id: Uuid,
        status: OutageStatus,
        message: impl Into<String>,
    ) -> SandboxResult<OutageUpdate> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("outage register poisoned".into()))?;
        let o = g
            .outages
            .get_mut(&outage_id)
            .ok_or_else(|| SandboxError::Other(format!("outage {} not found", outage_id)))?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let u = OutageUpdate {
            at: now.clone(),
            status,
            message: message.into(),
        };
        o.updates.push(u.clone());
        if status == OutageStatus::Resolved && o.resolved_at.is_none() {
            o.resolved_at = Some(now);
        }
        Ok(u)
    }

    /// Link postmortem.
    pub fn link_postmortem(
        &self,
        outage_id: Uuid,
        postmortem_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("outage register poisoned".into()))?;
        let o = g
            .outages
            .get_mut(&outage_id)
            .ok_or_else(|| SandboxError::Other(format!("outage {} not found", outage_id)))?;
        o.postmortem_ref = Some(postmortem_id.into());
        Ok(())
    }

    /// Mark affected tenants.
    pub fn set_affected_tenants(
        &self,
        outage_id: Uuid,
        tenants: Vec<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("outage register poisoned".into()))?;
        let o = g
            .outages
            .get_mut(&outage_id)
            .ok_or_else(|| SandboxError::Other(format!("outage {} not found", outage_id)))?;
        o.affected_tenants = Some(tenants);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<OutageEvent> {
        self.state.read().ok()?.outages.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<OutageEvent> {
        self.state
            .read()
            .map(|g| g.outages.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Open outages.
    pub fn open_outages(&self) -> Vec<OutageEvent> {
        self.all()
            .into_iter()
            .filter(|o| o.current_status() != OutageStatus::Resolved)
            .collect()
    }
    /// Outages affecting a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<OutageEvent> {
        self.all()
            .into_iter()
            .filter(|o| match &o.affected_tenants {
                Some(ts) => ts.iter().any(|t| t == tenant),
                None => true, // None = global → affects all
            })
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.outages.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_one(r: &OutageRegister) -> OutageEvent {
        r.open(
            "API latency spike",
            vec!["api".into(), "ingest".into()],
            OutageImpactLevel::Major,
            "Customers seeing elevated 5xx",
        )
        .unwrap()
    }

    #[test]
    fn open_creates_outage() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        assert_eq!(o.impact, OutageImpactLevel::Major);
        assert_eq!(o.updates.len(), 1);
        assert_eq!(o.current_status(), OutageStatus::Investigating);
    }

    #[test]
    fn add_update_advances_status() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.add_update(o.outage_id, OutageStatus::Identified, "root cause found")
            .unwrap();
        let updated = r.get(o.outage_id).unwrap();
        assert_eq!(updated.current_status(), OutageStatus::Identified);
    }

    #[test]
    fn resolve_sets_resolved_at() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.add_update(o.outage_id, OutageStatus::Resolved, "resolved")
            .unwrap();
        let updated = r.get(o.outage_id).unwrap();
        assert!(updated.resolved_at.is_some());
    }

    #[test]
    fn duration_calculated_after_resolve() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.add_update(o.outage_id, OutageStatus::Resolved, "resolved")
            .unwrap();
        let d = r.get(o.outage_id).unwrap().duration_minutes();
        assert!(d.is_some());
    }

    #[test]
    fn duration_none_when_unresolved() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        assert!(r.get(o.outage_id).unwrap().duration_minutes().is_none());
    }

    #[test]
    fn link_postmortem_sets_ref() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.link_postmortem(o.outage_id, "PM-1").unwrap();
        assert_eq!(r.get(o.outage_id).unwrap().postmortem_ref.as_deref(), Some("PM-1"));
    }

    #[test]
    fn link_unknown_errors() {
        let r = OutageRegister::new();
        assert!(r.link_postmortem(Uuid::now_v7(), "x").is_err());
    }

    #[test]
    fn set_affected_tenants() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.set_affected_tenants(o.outage_id, vec!["FAB".into(), "ENBD".into()])
            .unwrap();
        let updated = r.get(o.outage_id).unwrap();
        assert_eq!(updated.affected_tenants.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn open_outages_excludes_resolved() {
        let r = OutageRegister::new();
        let o1 = open_one(&r);
        let o2 = open_one(&r);
        r.add_update(o1.outage_id, OutageStatus::Resolved, "fixed")
            .unwrap();
        let open = r.open_outages();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].outage_id, o2.outage_id);
    }

    #[test]
    fn for_tenant_global_includes_all() {
        let r = OutageRegister::new();
        open_one(&r);
        // No affected_tenants set → global.
        assert_eq!(r.for_tenant("anyone").len(), 1);
    }

    #[test]
    fn for_tenant_filters_when_set() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        r.set_affected_tenants(o.outage_id, vec!["FAB".into()]).unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
        assert!(r.for_tenant("ENBD").is_empty());
    }

    #[test]
    fn add_update_unknown_errors() {
        let r = OutageRegister::new();
        assert!(r
            .add_update(Uuid::now_v7(), OutageStatus::Identified, "x")
            .is_err());
    }

    #[test]
    fn outage_serde() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        let j = serde_json::to_string(&o).unwrap();
        let p: OutageEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn update_serde() {
        let u = OutageUpdate {
            at: "t".into(),
            status: OutageStatus::Identified,
            message: "x".into(),
        };
        let j = serde_json::to_string(&u).unwrap();
        let p: OutageUpdate = serde_json::from_str(&j).unwrap();
        assert_eq!(p, u);
    }

    #[test]
    fn status_serde() {
        for s in [
            OutageStatus::Investigating,
            OutageStatus::Identified,
            OutageStatus::Monitoring,
            OutageStatus::Resolved,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: OutageStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn impact_serde() {
        for i in [
            OutageImpactLevel::Minor,
            OutageImpactLevel::Major,
            OutageImpactLevel::Critical,
        ] {
            let j = serde_json::to_string(&i).unwrap();
            let p: OutageImpactLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, i);
        }
    }

    #[test]
    fn register_count_tracks() {
        let r = OutageRegister::new();
        assert!(r.is_empty());
        open_one(&r);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = OutageRegister::new();
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn many_updates_chronological() {
        let r = OutageRegister::new();
        let o = open_one(&r);
        for i in 0..5 {
            r.add_update(
                o.outage_id,
                OutageStatus::Monitoring,
                format!("update-{i}"),
            )
            .unwrap();
        }
        let updated = r.get(o.outage_id).unwrap();
        assert_eq!(updated.updates.len(), 6); // 1 initial + 5
    }

    #[test]
    fn current_status_no_updates_investigating() {
        let mut o = OutageEvent {
            outage_id: Uuid::now_v7(),
            title: "x".into(),
            affected_services: vec![],
            affected_tenants: None,
            summary: "x".into(),
            impact: OutageImpactLevel::Minor,
            started_at: "t".into(),
            resolved_at: None,
            postmortem_ref: None,
            updates: vec![],
        };
        let _ = &mut o;
        assert_eq!(o.current_status(), OutageStatus::Investigating);
    }
}
