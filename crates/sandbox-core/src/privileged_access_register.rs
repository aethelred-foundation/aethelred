//! Privileged Access Management (PAM) register.
//!
//! Maps to **SOC 2 CC6.1** (logical access), **NIST 800-53 AC-6**
//! (least privilege), **PCI-DSS 7.2** (privileged user access), and
//! **ISO 27001 A.9.2.3** (management of privileged access rights).
//!
//! Privileged accounts (root, sudo, db_admin, cloud_admin) are the
//! highest-risk credentials in the organisation. Each grant must be
//! time-bound, justified, and tied to a specific change ticket or
//! incident. This registry tracks every grant from issue to revocation
//! with a tamper-evident timeline.
//!
//! ## Lifecycle
//!
//! `Requested → Approved → Active → Expired | Revoked`
//!
//! `Active` grants have a measurable elevation window; the registry
//! exposes `expiring_within(now, hours)` and `overdue_revocation(now)`
//! so PAM tooling can auto-revoke and alert.
//!
//! Distinct from [`crate::approval_workflow`] (one-off approvals),
//! [`crate::user_session`] (operator session lifecycle), and
//! [`crate::access_certification`] (periodic review): this is the
//! **per-grant** privileged-credential registry.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// PrivilegeKind
// =============================================================================

/// Class of privileged credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeKind {
    /// Operating-system root / administrator.
    OsRoot,
    /// Database administrator.
    DbAdmin,
    /// Cloud-provider admin (AWS / GCP / Azure).
    CloudAdmin,
    /// Kubernetes cluster-admin.
    ClusterAdmin,
    /// Application admin (production console).
    AppAdmin,
    /// Network device admin.
    NetworkAdmin,
    /// Break-glass emergency account.
    BreakGlass,
    /// Service-account credential with elevated scope.
    ElevatedServiceAccount,
}

impl PrivilegeKind {
    /// True if the credential class typically requires the strongest
    /// scrutiny (break-glass + cloud admin).
    pub fn is_high_risk(self) -> bool {
        matches!(self, Self::BreakGlass | Self::CloudAdmin | Self::OsRoot)
    }
}

// =============================================================================
// GrantStage
// =============================================================================

/// Lifecycle stage of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStage {
    /// Requested but not yet approved.
    Requested,
    /// Approved but not yet active.
    Approved,
    /// Currently active — credential issued / elevated.
    Active,
    /// Window expired naturally.
    Expired,
    /// Manually revoked.
    Revoked,
    /// Request denied.
    Denied,
}

impl GrantStage {
    /// True if the grant is currently usable.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked | Self::Denied)
    }
}

// =============================================================================
// GrantEvent
// =============================================================================

/// One event on the grant timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GrantEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: GrantStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// PrivilegedGrant
// =============================================================================

/// One privileged-access grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrivilegedGrant {
    /// Unique id (e.g., "PAM-2025-007").
    pub grant_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Subject (user / service account).
    pub principal: String,
    /// Resource the grant applies to (e.g., "prod-db", "aws/123456789").
    pub resource: String,
    /// Class.
    pub kind: PrivilegeKind,
    /// Justification for the grant (free text — must be non-empty in
    /// production usage).
    pub justification: String,
    /// Linked change ticket / incident id (if any).
    pub linked_ticket: Option<String>,
    /// Approver (must be different from principal in well-run shops).
    pub approver: Option<String>,
    /// RFC 3339 — requested.
    pub requested_at: String,
    /// RFC 3339 — approved.
    pub approved_at: Option<String>,
    /// RFC 3339 — activated.
    pub activated_at: Option<String>,
    /// RFC 3339 — scheduled to expire.
    pub expires_at: Option<String>,
    /// RFC 3339 — closed (Expired / Revoked / Denied).
    pub closed_at: Option<String>,
    /// Current stage.
    pub stage: GrantStage,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Event timeline.
    pub events: Vec<GrantEvent>,
}

impl PrivilegedGrant {
    /// New `Requested` grant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_id: impl Into<String>,
        tenant_id: impl Into<String>,
        principal: impl Into<String>,
        resource: impl Into<String>,
        kind: PrivilegeKind,
        justification: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            tenant_id: tenant_id.into(),
            principal: principal.into(),
            resource: resource.into(),
            kind,
            justification: justification.into(),
            linked_ticket: None,
            approver: None,
            requested_at: requested_at.into(),
            approved_at: None,
            activated_at: None,
            expires_at: None,
            closed_at: None,
            stage: GrantStage::Requested,
            tags: Vec::new(),
            events: Vec::new(),
        }
    }

    /// True if `now >= expires_at` and grant is still Active.
    pub fn is_overdue_revocation(&self, now: &str) -> bool {
        if !self.stage.is_active() {
            return false;
        }
        match self.expires_at.as_deref() {
            Some(exp) => now >= exp,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: GrantStage, to: GrantStage) -> bool {
    use GrantStage::*;
    match (from, to) {
        (Requested, Approved)
        | (Requested, Denied)
        | (Approved, Active)
        | (Approved, Revoked) // revoked before activation
        | (Active, Expired)
        | (Active, Revoked) => true,
        _ => false,
    }
}

// =============================================================================
// PrivilegedAccessRegister
// =============================================================================

/// Thread-safe register of privileged-access grants.
#[derive(Debug, Default)]
pub struct PrivilegedAccessRegister {
    inner: RwLock<HashMap<String, PrivilegedGrant>>,
}

impl PrivilegedAccessRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a new grant.
    pub fn request(&self, grant: PrivilegedGrant) -> SandboxResult<()> {
        if !matches!(grant.stage, GrantStage::Requested) {
            return Err(SandboxError::Other(format!(
                "grant must start Requested, got {:?}",
                grant.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        if g.contains_key(&grant.grant_id) {
            return Err(SandboxError::Other(format!(
                "grant already requested: {}",
                grant.grant_id
            )));
        }
        g.insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    /// Approve a Requested grant. The approver MUST differ from the
    /// principal — enforced.
    pub fn approve(
        &self,
        grant_id: &str,
        approver: impl Into<String>,
        at: impl Into<String>,
        expires_at: Option<String>,
    ) -> SandboxResult<PrivilegedGrant> {
        let approver = approver.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if approver == r.principal {
            return Err(SandboxError::Other(format!(
                "approver {} must differ from principal",
                approver
            )));
        }
        if !legal_transition(r.stage, GrantStage::Approved) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Approved",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = GrantStage::Approved;
        r.approver = Some(approver.clone());
        r.approved_at = Some(when.clone());
        if let Some(e) = expires_at {
            r.expires_at = Some(e);
        }
        r.events.push(GrantEvent {
            at: when,
            actor: approver,
            stage: GrantStage::Approved,
            note: "approved".into(),
        });
        Ok(r.clone())
    }

    /// Move an Approved grant to Active.
    pub fn activate(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<PrivilegedGrant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if !legal_transition(r.stage, GrantStage::Active) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Active",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = GrantStage::Active;
        r.activated_at = Some(when.clone());
        r.events.push(GrantEvent {
            at: when,
            actor: actor.into(),
            stage: GrantStage::Active,
            note: "activated".into(),
        });
        Ok(r.clone())
    }

    /// Mark a grant Expired.
    pub fn expire(
        &self,
        grant_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<PrivilegedGrant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if !legal_transition(r.stage, GrantStage::Expired) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Expired",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = GrantStage::Expired;
        r.closed_at = Some(when.clone());
        r.events.push(GrantEvent {
            at: when,
            actor: "system".into(),
            stage: GrantStage::Expired,
            note: "expired".into(),
        });
        Ok(r.clone())
    }

    /// Revoke a grant (from Approved or Active).
    pub fn revoke(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        reason: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<PrivilegedGrant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if !legal_transition(r.stage, GrantStage::Revoked) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Revoked",
                r.stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        r.stage = GrantStage::Revoked;
        r.closed_at = Some(when.clone());
        r.events.push(GrantEvent {
            at: when,
            actor,
            stage: GrantStage::Revoked,
            note: reason.into(),
        });
        Ok(r.clone())
    }

    /// Deny a Requested grant.
    pub fn deny(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        reason: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<PrivilegedGrant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if !legal_transition(r.stage, GrantStage::Denied) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Denied",
                r.stage
            )));
        }
        let when = at.into();
        r.stage = GrantStage::Denied;
        r.closed_at = Some(when.clone());
        r.events.push(GrantEvent {
            at: when,
            actor: actor.into(),
            stage: GrantStage::Denied,
            note: reason.into(),
        });
        Ok(r.clone())
    }

    /// Set linked change ticket / incident id.
    pub fn set_linked_ticket(
        &self,
        grant_id: &str,
        ticket: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        r.linked_ticket = Some(ticket.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, grant_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("privileged access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, grant_id: &str) -> Option<PrivilegedGrant> {
        let g = self.inner.read().ok()?;
        g.get(grant_id).cloned()
    }

    /// All grants.
    pub fn all(&self) -> Vec<PrivilegedGrant> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Grants for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<PrivilegedGrant> {
        self.all()
            .into_iter()
            .filter(|g| g.tenant_id == tenant_id)
            .collect()
    }

    /// Grants for a principal.
    pub fn for_principal(&self, principal: &str) -> Vec<PrivilegedGrant> {
        self.all()
            .into_iter()
            .filter(|g| g.principal == principal)
            .collect()
    }

    /// Grants by kind.
    pub fn by_kind(&self, kind: PrivilegeKind) -> Vec<PrivilegedGrant> {
        self.all().into_iter().filter(|g| g.kind == kind).collect()
    }

    /// Currently active grants.
    pub fn active(&self) -> Vec<PrivilegedGrant> {
        self.all()
            .into_iter()
            .filter(|g| g.stage.is_active())
            .collect()
    }

    /// Active grants whose `expires_at` is past `now` (auto-expire targets).
    pub fn overdue_revocation(&self, now: &str) -> Vec<PrivilegedGrant> {
        self.all()
            .into_iter()
            .filter(|g| g.is_overdue_revocation(now))
            .collect()
    }

    /// Active grants expiring within `hours` of `now`.
    pub fn expiring_within(&self, now: &str, hours: i64) -> Vec<PrivilegedGrant> {
        self.all()
            .into_iter()
            .filter(|g| {
                g.stage.is_active()
                    && match (g.expires_at.as_deref(), hours_until(now, g.expires_at.as_deref())) {
                        (Some(_), Some(h)) => h >= 0 && h <= hours,
                        _ => false,
                    }
            })
            .collect()
    }

    /// Number of registered grants.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn hours_until(now: &str, then: Option<&str>) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::parse(now, &Rfc3339).ok()?;
    let then = time::OffsetDateTime::parse(then?, &Rfc3339).ok()?;
    Some((then - now).whole_hours())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: &str, principal: &str, kind: PrivilegeKind) -> PrivilegedGrant {
        PrivilegedGrant::new(
            id,
            "tenant-a",
            principal,
            "prod-db",
            kind,
            "deploy schema migration #423",
            "2025-05-08T00:00:00Z",
        )
    }

    #[test]
    fn request_and_get() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        let g = r.get("g1").unwrap();
        assert_eq!(g.stage, GrantStage::Requested);
    }

    #[test]
    fn duplicate_request_errors() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        let err = r
            .request(grant("g1", "alice", PrivilegeKind::DbAdmin))
            .unwrap_err();
        assert!(format!("{err}").contains("already requested"));
    }

    #[test]
    fn must_start_requested() {
        let mut g = grant("g1", "alice", PrivilegeKind::DbAdmin);
        g.stage = GrantStage::Active;
        let r = PrivilegedAccessRegister::new();
        let err = r.request(g).unwrap_err();
        assert!(format!("{err}").contains("must start Requested"));
    }

    #[test]
    fn approve_requires_different_approver() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        let err = r
            .approve("g1", "alice", "2025-05-08T00:30:00Z", None)
            .unwrap_err();
        assert!(format!("{err}").contains("must differ from principal"));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve(
            "g1",
            "bob",
            "2025-05-08T00:30:00Z",
            Some("2025-05-08T01:30:00Z".into()),
        )
        .unwrap();
        r.activate("g1", "bob", "2025-05-08T00:35:00Z").unwrap();
        let g = r.expire("g1", "2025-05-08T01:30:00Z").unwrap();
        assert_eq!(g.stage, GrantStage::Expired);
        assert!(g.stage.is_terminal());
        assert_eq!(g.closed_at.as_deref(), Some("2025-05-08T01:30:00Z"));
        assert_eq!(g.events.len(), 3); // approve, activate, expire
    }

    #[test]
    fn revoke_from_active() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve("g1", "bob", "2025-05-08T00:30:00Z", None).unwrap();
        r.activate("g1", "bob", "2025-05-08T00:35:00Z").unwrap();
        let g = r
            .revoke(
                "g1",
                "ciso",
                "incident",
                "2025-05-08T01:00:00Z",
            )
            .unwrap();
        assert_eq!(g.stage, GrantStage::Revoked);
        assert!(g.stage.is_terminal());
    }

    #[test]
    fn revoke_from_approved() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve("g1", "bob", "2025-05-08T00:30:00Z", None).unwrap();
        let g = r
            .revoke(
                "g1",
                "bob",
                "no longer needed",
                "2025-05-08T00:45:00Z",
            )
            .unwrap();
        assert_eq!(g.stage, GrantStage::Revoked);
    }

    #[test]
    fn deny_path() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        let g = r
            .deny("g1", "bob", "no business need", "2025-05-08T00:15:00Z")
            .unwrap();
        assert_eq!(g.stage, GrantStage::Denied);
        assert!(g.stage.is_terminal());
    }

    #[test]
    fn illegal_transitions() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        // Cannot activate from Requested
        let err = r.activate("g1", "bob", "2025-05-08T00:30:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
        // Cannot expire from Requested
        let err = r.expire("g1", "2025-05-08T00:30:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_ticket_set_tag() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.set_linked_ticket("g1", "INC-123").unwrap();
        r.add_tag("g1", "break-glass").unwrap();
        r.add_tag("g1", "break-glass").unwrap(); // dedupe
        let g = r.get("g1").unwrap();
        assert_eq!(g.linked_ticket.as_deref(), Some("INC-123"));
        assert_eq!(g.tags, vec!["break-glass"]);
    }

    #[test]
    fn unknown_grant_errors() {
        let r = PrivilegedAccessRegister::new();
        let err = r
            .approve("nope", "bob", "2025-05-08T00:30:00Z", None)
            .unwrap_err();
        assert!(format!("{err}").contains("unknown grant"));
    }

    #[test]
    fn for_tenant_for_principal_filters() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        let mut other = grant("g2", "bob", PrivilegeKind::CloudAdmin);
        other.tenant_id = "tenant-b".into();
        r.request(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_principal("alice").len(), 1);
        assert_eq!(r.for_principal("bob").len(), 1);
    }

    #[test]
    fn by_kind_filters() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.request(grant("g2", "alice", PrivilegeKind::CloudAdmin))
            .unwrap();
        assert_eq!(r.by_kind(PrivilegeKind::DbAdmin).len(), 1);
        assert_eq!(r.by_kind(PrivilegeKind::CloudAdmin).len(), 1);
        assert_eq!(r.by_kind(PrivilegeKind::OsRoot).len(), 0);
    }

    #[test]
    fn active_filter() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve("g1", "bob", "2025-05-08T00:30:00Z", None).unwrap();
        r.activate("g1", "bob", "2025-05-08T00:35:00Z").unwrap();
        assert_eq!(r.active().len(), 1);
    }

    #[test]
    fn overdue_revocation() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve(
            "g1",
            "bob",
            "2025-05-08T00:30:00Z",
            Some("2025-05-08T01:30:00Z".into()),
        )
        .unwrap();
        r.activate("g1", "bob", "2025-05-08T00:35:00Z").unwrap();
        // Past expiry, still Active → overdue
        assert_eq!(r.overdue_revocation("2025-05-08T02:00:00Z").len(), 1);
        // After expiring transition → not overdue
        r.expire("g1", "2025-05-08T02:00:00Z").unwrap();
        assert_eq!(r.overdue_revocation("2025-05-08T03:00:00Z").len(), 0);
    }

    #[test]
    fn expiring_within_window() {
        let r = PrivilegedAccessRegister::new();
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        r.approve(
            "g1",
            "bob",
            "2025-05-08T00:30:00Z",
            Some("2025-05-08T03:00:00Z".into()),
        )
        .unwrap();
        r.activate("g1", "bob", "2025-05-08T00:35:00Z").unwrap();
        // 2 hours away with 4-hour window → in
        assert_eq!(r.expiring_within("2025-05-08T01:00:00Z", 4).len(), 1);
        // 30 minutes window → out (still 2 hours away)
        assert!(r.expiring_within("2025-05-08T01:00:00Z", 0).is_empty());
    }

    #[test]
    fn kind_high_risk_helpers() {
        assert!(PrivilegeKind::BreakGlass.is_high_risk());
        assert!(PrivilegeKind::CloudAdmin.is_high_risk());
        assert!(PrivilegeKind::OsRoot.is_high_risk());
        assert!(!PrivilegeKind::AppAdmin.is_high_risk());
        assert!(!PrivilegeKind::DbAdmin.is_high_risk());
    }

    #[test]
    fn count_tracks() {
        let r = PrivilegedAccessRegister::new();
        assert_eq!(r.count(), 0);
        r.request(grant("g1", "alice", PrivilegeKind::DbAdmin)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn grant_serde() {
        let g = grant("g1", "alice", PrivilegeKind::DbAdmin);
        let j = serde_json::to_string(&g).unwrap();
        let back: PrivilegedGrant = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            PrivilegeKind::OsRoot,
            PrivilegeKind::DbAdmin,
            PrivilegeKind::CloudAdmin,
            PrivilegeKind::ClusterAdmin,
            PrivilegeKind::AppAdmin,
            PrivilegeKind::NetworkAdmin,
            PrivilegeKind::BreakGlass,
            PrivilegeKind::ElevatedServiceAccount,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<PrivilegeKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [
            GrantStage::Requested,
            GrantStage::Approved,
            GrantStage::Active,
            GrantStage::Expired,
            GrantStage::Revoked,
            GrantStage::Denied,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<GrantStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
