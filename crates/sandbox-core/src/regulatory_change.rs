//! Regulatory change tracker.
//!
//! Compliance teams maintain a register of upcoming regulatory changes
//! that will affect the organization. Each [`RegulatoryChange`] captures:
//!
//! - The regulator and citation.
//! - Effective date.
//! - Impact assessment (which products / processes / models / policies
//!   are affected).
//! - Tracking status: Identified → Assessing → Implementing → Implemented.
//! - Owner accountable for landing the change before the effective date.
//!
//! [`RegulatoryChangeRegistry`] supports the queries auditors actually
//! run: "what regulations take effect in the next 90 days?", "show me
//! every change still in `Implementing` status", "which controls are
//! affected by GDPR Schrems III?".

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// TrackingStatus
// =============================================================================

/// Tracking lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrackingStatus {
    /// Identified, not yet assessed.
    Identified,
    /// Impact assessment in progress.
    Assessing,
    /// Implementation in progress.
    Implementing,
    /// Implementation complete.
    Implemented,
    /// No action required.
    NotApplicable,
}

// =============================================================================
// ImpactArea
// =============================================================================

/// Affected internal areas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactArea {
    /// Policy documents.
    Policy,
    /// Workflows.
    Workflow,
    /// Models.
    Model,
    /// Data handling / pipelines.
    Data,
    /// Customer-facing UX.
    Cx,
    /// Reporting.
    Reporting,
    /// Vendor relationships.
    Vendor,
    /// Operations / processes.
    Operations,
}

// =============================================================================
// RegulatoryChange
// =============================================================================

/// One tracked regulatory change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegulatoryChange {
    /// Stable id.
    pub change_id: Uuid,
    /// Regulator (e.g. `"EU Commission"`, `"HKMA"`, `"OCC"`).
    pub regulator: String,
    /// Citation (e.g. `"GDPR Art. 22"`, `"HKMA Module SS-1"`).
    pub citation: String,
    /// Title.
    pub title: String,
    /// Free-text description.
    pub description: String,
    /// RFC 3339 effective date.
    pub effective_date: String,
    /// Owner accountable.
    pub owner: String,
    /// Affected internal areas.
    pub impact_areas: Vec<ImpactArea>,
    /// Affected policy ids.
    pub affected_policy_ids: Vec<String>,
    /// Affected workflow ids.
    pub affected_workflow_ids: Vec<String>,
    /// Affected model ids.
    pub affected_model_ids: Vec<String>,
    /// Tracking status.
    pub status: TrackingStatus,
    /// Notes.
    pub notes: String,
    /// RFC 3339 last-updated.
    pub last_updated_at: String,
}

impl RegulatoryChange {
    /// `true` if effective date is within `days` of `now`.
    pub fn is_within(&self, now: OffsetDateTime, days: i64) -> bool {
        let eff = match OffsetDateTime::parse(
            &self.effective_date,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };
        eff > now && (eff - now).whole_days() <= days
    }
    /// `true` if effective date has passed and status is not Implemented or
    /// NotApplicable (overdue).
    pub fn is_overdue(&self, now: OffsetDateTime) -> bool {
        let eff = match OffsetDateTime::parse(
            &self.effective_date,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };
        eff <= now
            && self.status != TrackingStatus::Implemented
            && self.status != TrackingStatus::NotApplicable
    }
}

// =============================================================================
// ChangeBuilder
// =============================================================================

/// Builder for [`RegulatoryChange`].
pub struct ChangeBuilder {
    regulator: String,
    citation: String,
    title: String,
    description: String,
    effective_date: String,
    owner: String,
    impact_areas: Vec<ImpactArea>,
    policies: Vec<String>,
    workflows: Vec<String>,
    models: Vec<String>,
}

impl ChangeBuilder {
    /// New builder with required fields.
    pub fn new(
        regulator: impl Into<String>,
        citation: impl Into<String>,
        title: impl Into<String>,
        effective_date: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            regulator: regulator.into(),
            citation: citation.into(),
            title: title.into(),
            description: String::new(),
            effective_date: effective_date.into(),
            owner: owner.into(),
            impact_areas: Vec::new(),
            policies: Vec::new(),
            workflows: Vec::new(),
            models: Vec::new(),
        }
    }
    /// Description.
    pub fn description(mut self, s: impl Into<String>) -> Self {
        self.description = s.into();
        self
    }
    /// Add impact area.
    pub fn impact(mut self, a: ImpactArea) -> Self {
        if !self.impact_areas.contains(&a) {
            self.impact_areas.push(a);
        }
        self
    }
    /// Affected policy.
    pub fn policy(mut self, id: impl Into<String>) -> Self {
        self.policies.push(id.into());
        self
    }
    /// Affected workflow.
    pub fn workflow(mut self, id: impl Into<String>) -> Self {
        self.workflows.push(id.into());
        self
    }
    /// Affected model.
    pub fn model(mut self, id: impl Into<String>) -> Self {
        self.models.push(id.into());
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<RegulatoryChange> {
        if self.regulator.trim().is_empty()
            || self.citation.trim().is_empty()
            || self.title.trim().is_empty()
        {
            return Err(SandboxError::Other(
                "regulator, citation, and title are required".into(),
            ));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(RegulatoryChange {
            change_id: Uuid::now_v7(),
            regulator: self.regulator,
            citation: self.citation,
            title: self.title,
            description: self.description,
            effective_date: self.effective_date,
            owner: self.owner,
            impact_areas: self.impact_areas,
            affected_policy_ids: self.policies,
            affected_workflow_ids: self.workflows,
            affected_model_ids: self.models,
            status: TrackingStatus::Identified,
            notes: String::new(),
            last_updated_at: now,
        })
    }
}

// =============================================================================
// RegulatoryChangeRegistry
// =============================================================================

#[derive(Default)]
struct State {
    changes: HashMap<Uuid, RegulatoryChange>,
}

/// Registry.
pub struct RegulatoryChangeRegistry {
    state: RwLock<State>,
}

impl Default for RegulatoryChangeRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for RegulatoryChangeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegulatoryChangeRegistry")
            .field("changes", &self.len())
            .finish()
    }
}

impl RegulatoryChangeRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append.
    pub fn add(&self, c: RegulatoryChange) -> SandboxResult<Uuid> {
        let id = c.change_id;
        self.state
            .write()
            .map_err(|_| SandboxError::Other("change registry poisoned".into()))?
            .changes
            .insert(id, c);
        Ok(id)
    }
    /// Update status.
    pub fn set_status(&self, id: Uuid, s: TrackingStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("change registry poisoned".into()))?;
        let c = g.changes.get_mut(&id).ok_or_else(|| {
            SandboxError::Other(format!("change {} not found", id))
        })?;
        c.status = s;
        c.last_updated_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Ok(())
    }
    /// Append note.
    pub fn append_note(&self, id: Uuid, note: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("change registry poisoned".into()))?;
        let c = g.changes.get_mut(&id).ok_or_else(|| {
            SandboxError::Other(format!("change {} not found", id))
        })?;
        if !c.notes.is_empty() {
            c.notes.push('\n');
        }
        c.notes.push_str(&note.into());
        Ok(())
    }
    /// Lookup.
    pub fn get(&self, id: Uuid) -> Option<RegulatoryChange> {
        self.state.read().ok()?.changes.get(&id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<RegulatoryChange> {
        self.state
            .read()
            .map(|g| g.changes.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Filter by status.
    pub fn by_status(&self, s: TrackingStatus) -> Vec<RegulatoryChange> {
        self.all().into_iter().filter(|c| c.status == s).collect()
    }
    /// Effective within `days` of `now`.
    pub fn upcoming(&self, now: OffsetDateTime, days: i64) -> Vec<RegulatoryChange> {
        self.all().into_iter().filter(|c| c.is_within(now, days)).collect()
    }
    /// Overdue (effective passed without Implemented status).
    pub fn overdue(&self, now: OffsetDateTime) -> Vec<RegulatoryChange> {
        self.all().into_iter().filter(|c| c.is_overdue(now)).collect()
    }
    /// Filter affecting a model id.
    pub fn affecting_model(&self, model_id: &str) -> Vec<RegulatoryChange> {
        self.all()
            .into_iter()
            .filter(|c| c.affected_model_ids.iter().any(|m| m == model_id))
            .collect()
    }
    /// Filter affecting a policy id.
    pub fn affecting_policy(&self, policy_id: &str) -> Vec<RegulatoryChange> {
        self.all()
            .into_iter()
            .filter(|c| c.affected_policy_ids.iter().any(|p| p == policy_id))
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.changes.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(eff: &str) -> RegulatoryChange {
        ChangeBuilder::new("EBA", "EBA-2026-01", "AML update", eff, "compliance")
            .description("Updated KYC requirements")
            .impact(ImpactArea::Policy)
            .impact(ImpactArea::Workflow)
            .policy("po_kyc_v2")
            .workflow("wf_loan")
            .model("m1")
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_change() {
        let c = ch("2027-01-01T00:00:00Z");
        assert_eq!(c.regulator, "EBA");
        assert_eq!(c.status, TrackingStatus::Identified);
    }

    #[test]
    fn missing_required_errors() {
        let r = ChangeBuilder::new("", "x", "y", "z", "o").build();
        assert!(r.is_err());
    }

    #[test]
    fn add_and_get() {
        let r = RegulatoryChangeRegistry::new();
        let id = r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        assert!(r.get(id).is_some());
    }

    #[test]
    fn set_status_updates() {
        let r = RegulatoryChangeRegistry::new();
        let id = r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        r.set_status(id, TrackingStatus::Implementing).unwrap();
        assert_eq!(r.get(id).unwrap().status, TrackingStatus::Implementing);
    }

    #[test]
    fn set_status_unknown_errors() {
        let r = RegulatoryChangeRegistry::new();
        assert!(r.set_status(Uuid::now_v7(), TrackingStatus::Implemented).is_err());
    }

    #[test]
    fn append_note_concatenates() {
        let r = RegulatoryChangeRegistry::new();
        let id = r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        r.append_note(id, "first").unwrap();
        r.append_note(id, "second").unwrap();
        assert!(r.get(id).unwrap().notes.contains("first"));
        assert!(r.get(id).unwrap().notes.contains("second"));
    }

    #[test]
    fn is_within_future() {
        let now = OffsetDateTime::now_utc();
        let future = now + time::Duration::days(30);
        let s = future
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let c = ch(&s);
        assert!(c.is_within(now, 60));
        assert!(!c.is_within(now, 10));
    }

    #[test]
    fn is_overdue_when_past_and_not_done() {
        let past = OffsetDateTime::now_utc() - time::Duration::days(5);
        let s = past
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let c = ch(&s);
        assert!(c.is_overdue(OffsetDateTime::now_utc()));
    }

    #[test]
    fn is_not_overdue_when_implemented() {
        let past = OffsetDateTime::now_utc() - time::Duration::days(5);
        let s = past
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut c = ch(&s);
        c.status = TrackingStatus::Implemented;
        assert!(!c.is_overdue(OffsetDateTime::now_utc()));
    }

    #[test]
    fn upcoming_filters_by_window() {
        let now = OffsetDateTime::now_utc();
        let r = RegulatoryChangeRegistry::new();
        r.add(ch(&(now + time::Duration::days(30))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()))
            .unwrap();
        r.add(ch(&(now + time::Duration::days(200))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()))
            .unwrap();
        assert_eq!(r.upcoming(now, 60).len(), 1);
        assert_eq!(r.upcoming(now, 365).len(), 2);
    }

    #[test]
    fn overdue_filter() {
        let now = OffsetDateTime::now_utc();
        let r = RegulatoryChangeRegistry::new();
        r.add(ch(&(now - time::Duration::days(10))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()))
            .unwrap();
        r.add(ch(&(now + time::Duration::days(10))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()))
            .unwrap();
        assert_eq!(r.overdue(now).len(), 1);
    }

    #[test]
    fn affecting_model_filter() {
        let r = RegulatoryChangeRegistry::new();
        r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(r.affecting_model("m1").len(), 1);
        assert_eq!(r.affecting_model("ghost").len(), 0);
    }

    #[test]
    fn affecting_policy_filter() {
        let r = RegulatoryChangeRegistry::new();
        r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        assert_eq!(r.affecting_policy("po_kyc_v2").len(), 1);
    }

    #[test]
    fn by_status_filter() {
        let r = RegulatoryChangeRegistry::new();
        let id = r.add(ch("2027-01-01T00:00:00Z")).unwrap();
        r.set_status(id, TrackingStatus::Implementing).unwrap();
        assert_eq!(r.by_status(TrackingStatus::Implementing).len(), 1);
        assert_eq!(r.by_status(TrackingStatus::Identified).len(), 0);
    }

    #[test]
    fn change_serde() {
        let c = ch("2027-01-01T00:00:00Z");
        let j = serde_json::to_string(&c).unwrap();
        let p: RegulatoryChange = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn tracking_status_serde() {
        for s in [
            TrackingStatus::Identified,
            TrackingStatus::Assessing,
            TrackingStatus::Implementing,
            TrackingStatus::Implemented,
            TrackingStatus::NotApplicable,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: TrackingStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn impact_area_serde() {
        for a in [
            ImpactArea::Policy,
            ImpactArea::Workflow,
            ImpactArea::Model,
            ImpactArea::Data,
            ImpactArea::Cx,
            ImpactArea::Reporting,
            ImpactArea::Vendor,
            ImpactArea::Operations,
        ] {
            let j = serde_json::to_string(&a).unwrap();
            let p: ImpactArea = serde_json::from_str(&j).unwrap();
            assert_eq!(p, a);
        }
    }

    #[test]
    fn impact_area_dedupes() {
        let c = ChangeBuilder::new("a", "b", "c", "2027-01-01T00:00:00Z", "o")
            .impact(ImpactArea::Policy)
            .impact(ImpactArea::Policy)
            .build()
            .unwrap();
        assert_eq!(c.impact_areas.len(), 1);
    }

    #[test]
    fn registry_count_empty_zero() {
        let r = RegulatoryChangeRegistry::new();
        assert_eq!(r.len(), 0);
        assert!(r.is_empty());
    }

    #[test]
    fn registry_all_returns_all() {
        let r = RegulatoryChangeRegistry::new();
        for i in 0..5 {
            r.add(ch(&format!("2027-{:02}-01T00:00:00Z", i + 1))).unwrap();
        }
        assert_eq!(r.all().len(), 5);
    }

    #[test]
    fn malformed_effective_date_within_returns_false() {
        let mut c = ch("2027-01-01T00:00:00Z");
        c.effective_date = "not-a-date".into();
        assert!(!c.is_within(OffsetDateTime::now_utc(), 1000));
    }

    #[test]
    fn malformed_effective_date_overdue_returns_false() {
        let mut c = ch("2027-01-01T00:00:00Z");
        c.effective_date = "not-a-date".into();
        assert!(!c.is_overdue(OffsetDateTime::now_utc()));
    }
}
