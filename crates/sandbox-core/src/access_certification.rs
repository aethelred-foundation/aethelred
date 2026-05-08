//! Periodic access certification register.
//!
//! Maps to **SOC 2 CC6.3** (controller requires periodic access review),
//! **ISO 27001 A.9.2.5** (review of user access rights), and **PCI-DSS 7.x**.
//! Every quarter (or whatever the cadence is), every privileged role and
//! every system entitlement must be reviewed by the access owner; reviewers
//! either reaffirm, modify, or revoke access.
//!
//! ## Lifecycle
//!
//! `Pending → InProgress → Completed | Cancelled`
//!
//! Within a campaign, every [`Entitlement`] under review gets a per-entry
//! [`ReviewVerdict`]: `Reaffirmed`, `RevokeRequested`, `ModifyRequested`,
//! or `Pending`. The campaign cannot move to `Completed` while any
//! entitlement is still `Pending`.
//!
//! Distinct from [`crate::approval_workflow`] (one-off approvals) and
//! [`crate::user_session`] (active sessions); this is the **periodic
//! review** that proves access is still appropriate.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// CampaignStage
// =============================================================================

/// Lifecycle stage of a certification campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStage {
    /// Campaign created; reviews not started.
    Pending,
    /// Reviewers actively certifying.
    InProgress,
    /// All entitlements certified (with verdicts).
    Completed,
    /// Campaign cancelled mid-flight.
    Cancelled,
}

impl CampaignStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

// =============================================================================
// ReviewVerdict
// =============================================================================

/// Per-entitlement reviewer verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// Not yet reviewed.
    Pending,
    /// Access reaffirmed.
    Reaffirmed,
    /// Reviewer requested revocation.
    RevokeRequested,
    /// Reviewer requested scope modification.
    ModifyRequested,
}

impl ReviewVerdict {
    /// True if a follow-up action is needed.
    pub fn requires_action(self) -> bool {
        matches!(self, Self::RevokeRequested | Self::ModifyRequested)
    }

    /// True if the reviewer has already acted.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

// =============================================================================
// EntitlementKind
// =============================================================================

/// Kind of entitlement under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementKind {
    /// Role membership (RBAC role).
    Role,
    /// Group membership.
    Group,
    /// Specific permission grant.
    Permission,
    /// System / dataset access.
    SystemAccess,
    /// Privileged-account credential.
    PrivilegedAccount,
    /// API key issued to a user.
    ApiKey,
    /// Service-account credential.
    ServiceAccount,
}

// =============================================================================
// Entitlement
// =============================================================================

/// One entitlement reviewed within a campaign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entitlement {
    /// Stable id within the campaign.
    pub entitlement_id: String,
    /// Subject (user / service principal) holding the entitlement.
    pub principal: String,
    /// Kind.
    pub kind: EntitlementKind,
    /// Resource / role label.
    pub resource: String,
    /// Owner who is responsible for reviewing.
    pub reviewer: String,
    /// Optional supporting business justification (free text).
    pub justification: Option<String>,
    /// Verdict.
    pub verdict: ReviewVerdict,
    /// RFC 3339 — when verdict was recorded.
    pub reviewed_at: Option<String>,
    /// Reviewer's note when modify/revoke requested.
    pub reviewer_note: Option<String>,
}

impl Entitlement {
    /// New `Pending` entitlement.
    pub fn new(
        entitlement_id: impl Into<String>,
        principal: impl Into<String>,
        kind: EntitlementKind,
        resource: impl Into<String>,
        reviewer: impl Into<String>,
    ) -> Self {
        Self {
            entitlement_id: entitlement_id.into(),
            principal: principal.into(),
            kind,
            resource: resource.into(),
            reviewer: reviewer.into(),
            justification: None,
            verdict: ReviewVerdict::Pending,
            reviewed_at: None,
            reviewer_note: None,
        }
    }
}

// =============================================================================
// CertificationCampaign
// =============================================================================

/// One periodic access certification campaign.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificationCampaign {
    /// Unique id (e.g., "ACERT-2025-Q1").
    pub campaign_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display title.
    pub title: String,
    /// Period label ("Q1-2025", "2025-04").
    pub period: String,
    /// Owning team (compliance / security / IAM).
    pub owner: String,
    /// Lifecycle stage.
    pub stage: CampaignStage,
    /// Entitlements under review.
    pub entitlements: Vec<Entitlement>,
    /// RFC 3339 — created.
    pub created_at: String,
    /// RFC 3339 — started.
    pub started_at: Option<String>,
    /// RFC 3339 — completed (terminal).
    pub completed_at: Option<String>,
    /// RFC 3339 — deadline for reviewers.
    pub deadline_at: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl CertificationCampaign {
    /// New `Pending` campaign.
    pub fn new(
        campaign_id: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        period: impl Into<String>,
        owner: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            campaign_id: campaign_id.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            period: period.into(),
            owner: owner.into(),
            stage: CampaignStage::Pending,
            entitlements: Vec::new(),
            created_at: created_at.into(),
            started_at: None,
            completed_at: None,
            deadline_at: None,
            tags: Vec::new(),
        }
    }

    /// Number of entitlements not yet reviewed.
    pub fn pending_count(&self) -> usize {
        self.entitlements
            .iter()
            .filter(|e| !e.verdict.is_resolved())
            .count()
    }

    /// Number of entitlements where reviewer requested follow-up action.
    pub fn action_required_count(&self) -> usize {
        self.entitlements
            .iter()
            .filter(|e| e.verdict.requires_action())
            .count()
    }

    /// True if `now >= deadline_at` and not yet completed.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        match self.deadline_at.as_deref() {
            Some(due) => now >= due,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: CampaignStage, to: CampaignStage) -> bool {
    use CampaignStage::*;
    matches!(
        (from, to),
        (Pending, InProgress)
            | (Pending, Cancelled)
            | (InProgress, Completed)
            | (InProgress, Cancelled)
    )
}

// =============================================================================
// AccessCertificationRegistry
// =============================================================================

/// Thread-safe registry of access-certification campaigns.
#[derive(Debug, Default)]
pub struct AccessCertificationRegistry {
    inner: RwLock<HashMap<String, CertificationCampaign>>,
}

impl AccessCertificationRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new campaign.
    pub fn register(&self, campaign: CertificationCampaign) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        if g.contains_key(&campaign.campaign_id) {
            return Err(SandboxError::Other(format!(
                "campaign already registered: {}",
                campaign.campaign_id
            )));
        }
        g.insert(campaign.campaign_id.clone(), campaign);
        Ok(())
    }

    /// Add an entitlement to a campaign (must be Pending).
    pub fn add_entitlement(
        &self,
        campaign_id: &str,
        entitlement: Entitlement,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        if !matches!(c.stage, CampaignStage::Pending) {
            return Err(SandboxError::Other(format!(
                "cannot add entitlement to {campaign_id}: stage is {:?}",
                c.stage
            )));
        }
        if c.entitlements
            .iter()
            .any(|e| e.entitlement_id == entitlement.entitlement_id)
        {
            return Err(SandboxError::Other(format!(
                "entitlement already present: {}",
                entitlement.entitlement_id
            )));
        }
        c.entitlements.push(entitlement);
        Ok(())
    }

    /// Move campaign to InProgress.
    pub fn start(
        &self,
        campaign_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<CertificationCampaign> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        if !legal_transition(c.stage, CampaignStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> InProgress",
                c.stage
            )));
        }
        c.stage = CampaignStage::InProgress;
        c.started_at = Some(at.into());
        Ok(c.clone())
    }

    /// Record a reviewer verdict on an entitlement. Campaign must be
    /// InProgress.
    pub fn record_verdict(
        &self,
        campaign_id: &str,
        entitlement_id: &str,
        verdict: ReviewVerdict,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        if matches!(verdict, ReviewVerdict::Pending) {
            return Err(SandboxError::Other(
                "cannot record verdict Pending".into(),
            ));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        if !matches!(c.stage, CampaignStage::InProgress) {
            return Err(SandboxError::Other(format!(
                "cannot record on {campaign_id}: stage is {:?}",
                c.stage
            )));
        }
        let e = c
            .entitlements
            .iter_mut()
            .find(|e| e.entitlement_id == entitlement_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown entitlement {entitlement_id}"))
            })?;
        e.verdict = verdict;
        e.reviewed_at = Some(at.into());
        if let Some(n) = note {
            e.reviewer_note = Some(n);
        }
        Ok(())
    }

    /// Complete the campaign. All entitlements must have a non-Pending
    /// verdict.
    pub fn complete(
        &self,
        campaign_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<CertificationCampaign> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        if !legal_transition(c.stage, CampaignStage::Completed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Completed",
                c.stage
            )));
        }
        if c.pending_count() > 0 {
            return Err(SandboxError::Other(format!(
                "cannot complete {campaign_id}: {} entitlements still pending",
                c.pending_count()
            )));
        }
        c.stage = CampaignStage::Completed;
        c.completed_at = Some(at.into());
        Ok(c.clone())
    }

    /// Cancel a non-terminal campaign.
    pub fn cancel(
        &self,
        campaign_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<CertificationCampaign> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        if !legal_transition(c.stage, CampaignStage::Cancelled) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Cancelled",
                c.stage
            )));
        }
        c.stage = CampaignStage::Cancelled;
        c.completed_at = Some(at.into());
        Ok(c.clone())
    }

    /// Set the reviewer deadline.
    pub fn set_deadline(
        &self,
        campaign_id: &str,
        deadline_at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        c.deadline_at = Some(deadline_at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, campaign_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("access cert registry poisoned".into()))?;
        let c = g
            .get_mut(campaign_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown campaign {campaign_id}")))?;
        let tag = tag.into();
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, campaign_id: &str) -> Option<CertificationCampaign> {
        let g = self.inner.read().ok()?;
        g.get(campaign_id).cloned()
    }

    /// All campaigns.
    pub fn all(&self) -> Vec<CertificationCampaign> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Campaigns for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<CertificationCampaign> {
        self.all()
            .into_iter()
            .filter(|c| c.tenant_id == tenant_id)
            .collect()
    }

    /// Campaigns at a stage.
    pub fn by_stage(&self, stage: CampaignStage) -> Vec<CertificationCampaign> {
        self.all().into_iter().filter(|c| c.stage == stage).collect()
    }

    /// Open campaigns past their deadline at `now`.
    pub fn overdue(&self, now: &str) -> Vec<CertificationCampaign> {
        self.all()
            .into_iter()
            .filter(|c| c.is_overdue(now))
            .collect()
    }

    /// Number of registered campaigns.
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

    fn camp(id: &str) -> CertificationCampaign {
        CertificationCampaign::new(
            id,
            "tenant-a",
            format!("title-{id}"),
            "Q1-2025",
            "iam-team",
            "2025-04-01T00:00:00Z",
        )
    }

    fn ent(id: &str, principal: &str, kind: EntitlementKind) -> Entitlement {
        Entitlement::new(id, principal, kind, format!("resource-{id}"), "owner")
    }

    #[test]
    fn register_and_get() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        assert!(r.get("c1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        let err = r.register(camp("c1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn add_entitlement_to_pending() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        assert_eq!(r.get("c1").unwrap().entitlements.len(), 1);
    }

    #[test]
    fn add_entitlement_dedupes_id() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        let err = r
            .add_entitlement("c1", ent("e1", "alice", EntitlementKind::Group))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_entitlement_after_started_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add entitlement"));
    }

    #[test]
    fn legal_transitions() {
        use CampaignStage::*;
        assert!(legal_transition(Pending, InProgress));
        assert!(legal_transition(Pending, Cancelled));
        assert!(legal_transition(InProgress, Completed));
        assert!(legal_transition(InProgress, Cancelled));
        // illegal
        assert!(!legal_transition(Pending, Completed));
        assert!(!legal_transition(Completed, Pending));
        assert!(!legal_transition(Cancelled, InProgress));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        r.add_entitlement("c1", ent("e2", "bob", EntitlementKind::Permission))
            .unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        r.record_verdict(
            "c1",
            "e1",
            ReviewVerdict::Reaffirmed,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.record_verdict(
            "c1",
            "e2",
            ReviewVerdict::RevokeRequested,
            "2025-04-15T00:00:00Z",
            Some("transferred to other team".into()),
        )
        .unwrap();
        let c = r.complete("c1", "2025-04-30T00:00:00Z").unwrap();
        assert_eq!(c.stage, CampaignStage::Completed);
        assert_eq!(c.completed_at.as_deref(), Some("2025-04-30T00:00:00Z"));
        assert_eq!(c.action_required_count(), 1);
    }

    #[test]
    fn complete_rejects_pending_entitlements() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        let err = r.complete("c1", "2025-04-30T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("entitlements still pending"));
    }

    #[test]
    fn record_verdict_pending_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .record_verdict(
                "c1",
                "e1",
                ReviewVerdict::Pending,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("verdict Pending"));
    }

    #[test]
    fn record_verdict_unknown_entitlement_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        let err = r
            .record_verdict(
                "c1",
                "nope",
                ReviewVerdict::Reaffirmed,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown entitlement"));
    }

    #[test]
    fn record_verdict_when_not_in_progress_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        let err = r
            .record_verdict(
                "c1",
                "e1",
                ReviewVerdict::Reaffirmed,
                "2025-04-15T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot record"));
    }

    #[test]
    fn cancel_works_from_pending_or_in_progress() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        let c = r.cancel("c1", "2025-04-15T00:00:00Z").unwrap();
        assert_eq!(c.stage, CampaignStage::Cancelled);

        let mut other = camp("c2");
        other.campaign_id = "c2".into();
        r.register(other).unwrap();
        r.start("c2", "2025-04-02T00:00:00Z").unwrap();
        let c = r.cancel("c2", "2025-04-15T00:00:00Z").unwrap();
        assert_eq!(c.stage, CampaignStage::Cancelled);
    }

    #[test]
    fn cancel_terminal_errors() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.cancel("c1", "2025-04-15T00:00:00Z").unwrap();
        let err = r.cancel("c1", "2025-04-16T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_deadline_overdue() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.set_deadline("c1", "2025-04-30T00:00:00Z").unwrap();
        assert_eq!(r.overdue("2025-05-15T00:00:00Z").len(), 1);
        // Cancel — no longer overdue
        r.cancel("c1", "2025-05-01T00:00:00Z").unwrap();
        assert_eq!(r.overdue("2025-05-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_tag("c1", "quarterly").unwrap();
        r.add_tag("c1", "quarterly").unwrap();
        r.add_tag("c1", "p0").unwrap();
        assert_eq!(r.get("c1").unwrap().tags, vec!["quarterly", "p0"]);
    }

    #[test]
    fn unknown_campaign_errors() {
        let r = AccessCertificationRegistry::new();
        let err = r.set_deadline("nope", "2025-05-01T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown campaign"));
    }

    #[test]
    fn for_tenant_by_stage_filters() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        let mut other = camp("c2");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        r.cancel("c2", "2025-04-15T00:00:00Z").unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.by_stage(CampaignStage::Pending).len(), 1);
        assert_eq!(r.by_stage(CampaignStage::Cancelled).len(), 1);
    }

    #[test]
    fn pending_action_counts() {
        let r = AccessCertificationRegistry::new();
        r.register(camp("c1")).unwrap();
        r.add_entitlement("c1", ent("e1", "alice", EntitlementKind::Role))
            .unwrap();
        r.add_entitlement("c1", ent("e2", "bob", EntitlementKind::Permission))
            .unwrap();
        r.add_entitlement("c1", ent("e3", "carol", EntitlementKind::Group))
            .unwrap();
        r.start("c1", "2025-04-02T00:00:00Z").unwrap();
        r.record_verdict(
            "c1",
            "e1",
            ReviewVerdict::Reaffirmed,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        r.record_verdict(
            "c1",
            "e2",
            ReviewVerdict::ModifyRequested,
            "2025-04-15T00:00:00Z",
            None,
        )
        .unwrap();
        let c = r.get("c1").unwrap();
        assert_eq!(c.pending_count(), 1);
        assert_eq!(c.action_required_count(), 1);
    }

    #[test]
    fn verdict_helpers() {
        assert!(ReviewVerdict::RevokeRequested.requires_action());
        assert!(ReviewVerdict::ModifyRequested.requires_action());
        assert!(!ReviewVerdict::Reaffirmed.requires_action());
        assert!(!ReviewVerdict::Pending.requires_action());
        assert!(ReviewVerdict::Reaffirmed.is_resolved());
        assert!(ReviewVerdict::RevokeRequested.is_resolved());
        assert!(ReviewVerdict::ModifyRequested.is_resolved());
        assert!(!ReviewVerdict::Pending.is_resolved());
    }

    #[test]
    fn count_tracks() {
        let r = AccessCertificationRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(camp("c1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn campaign_serde() {
        let c = camp("c1");
        let j = serde_json::to_string(&c).unwrap();
        let back: CertificationCampaign = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn entitlement_serde() {
        let e = ent("e1", "alice", EntitlementKind::Role);
        let j = serde_json::to_string(&e).unwrap();
        let back: Entitlement = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            CampaignStage::Pending,
            CampaignStage::InProgress,
            CampaignStage::Completed,
            CampaignStage::Cancelled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<CampaignStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for v in [
            ReviewVerdict::Pending,
            ReviewVerdict::Reaffirmed,
            ReviewVerdict::RevokeRequested,
            ReviewVerdict::ModifyRequested,
        ] {
            assert_eq!(
                v,
                serde_json::from_str::<ReviewVerdict>(&serde_json::to_string(&v).unwrap()).unwrap()
            );
        }
        for k in [
            EntitlementKind::Role,
            EntitlementKind::Group,
            EntitlementKind::Permission,
            EntitlementKind::SystemAccess,
            EntitlementKind::PrivilegedAccount,
            EntitlementKind::ApiKey,
            EntitlementKind::ServiceAccount,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<EntitlementKind>(&serde_json::to_string(&k).unwrap())
                    .unwrap()
            );
        }
    }
}
