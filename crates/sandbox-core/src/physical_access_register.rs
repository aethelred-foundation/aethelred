//! Physical access register — badge / facility access tracking.
//!
//! Maps to **ISO 27001 A.11.1.1-3** (physical security perimeter and
//! controls), **SOC 2 CC6.4** (physical access), **NIST 800-53 PE-2/3**
//! (physical access authorisations and control), and HIPAA §164.310
//! (facility access controls). Every secure facility (data centre, lab,
//! controlled office floor) maintains a register of who is permitted
//! to enter, the physical credential issued (badge, biometric enrolment),
//! and a tamper-evident log of issuance, suspension, and revocation
//! events.
//!
//! Two-level model:
//!
//! - **[`Facility`]** — one secure location (data centre, lab, secure
//!   office). Has a sensitivity tier and an owner.
//! - **[`AccessGrant`]** — one (subject, facility) pair with the
//!   credential issued and lifecycle from
//!   `Requested → Approved → Active → (Suspended | Expired | Revoked)`.
//!
//! Distinct from [`crate::access_certification`] (logical access),
//! [`crate::privileged_access_register`] (privileged credentials), and
//! [`crate::user_session`] (active sessions); this is the **physical
//! perimeter** evidence.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// FacilityTier
// =============================================================================

/// Sensitivity tier of a facility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FacilityTier {
    /// Reception / public-accessible.
    Public,
    /// Standard office floor.
    Internal,
    /// Restricted (engineering, R&D).
    Restricted,
    /// Critical infrastructure (data centre, secure lab).
    Critical,
}

impl FacilityTier {
    /// True if the tier requires elevated approval (Restricted or Critical).
    pub fn requires_elevated_approval(self) -> bool {
        matches!(self, Self::Restricted | Self::Critical)
    }
}

// =============================================================================
// CredentialKind
// =============================================================================

/// Kind of physical credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// RFID badge.
    Badge,
    /// PIN code.
    Pin,
    /// Biometric (fingerprint / iris / face).
    Biometric,
    /// Mobile credential (NFC / mobile wallet).
    Mobile,
    /// Hardware key (YubiKey for door).
    HardwareKey,
    /// Escorted-only (no credential — must be escorted by a host).
    Escorted,
}

// =============================================================================
// GrantStage
// =============================================================================

/// Lifecycle stage of an access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantStage {
    /// Requested by HR / sponsor.
    Requested,
    /// Approved by facility owner.
    Approved,
    /// Currently active.
    Active,
    /// Temporarily suspended (e.g., LOA, investigation).
    Suspended,
    /// Window naturally expired.
    Expired,
    /// Manually revoked.
    Revoked,
    /// Request denied.
    Denied,
}

impl GrantStage {
    /// True if the credential is currently usable.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Revoked | Self::Denied)
    }
}

// =============================================================================
// AccessEvent
// =============================================================================

/// One event on the grant timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessEvent {
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
// Facility
// =============================================================================

/// One secure facility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Facility {
    /// Stable id (e.g., "DC-EAST-01").
    pub facility_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Tier.
    pub tier: FacilityTier,
    /// Address / location string.
    pub location: String,
    /// Owner / facility manager.
    pub owner: String,
    /// True if active.
    pub active: bool,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Facility {
    /// Construct a new active facility.
    pub fn new(
        facility_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        tier: FacilityTier,
        location: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            facility_id: facility_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            tier,
            location: location.into(),
            owner: owner.into(),
            active: true,
            tags: Vec::new(),
        }
    }
}

// =============================================================================
// AccessGrant
// =============================================================================

/// One access grant (subject × facility).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessGrant {
    /// Unique grant id (e.g., "PHYS-2025-007").
    pub grant_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Facility id.
    pub facility_id: String,
    /// Subject (employee / contractor id).
    pub subject_id: String,
    /// Subject display name.
    pub subject_name: String,
    /// Credential kind.
    pub credential: CredentialKind,
    /// Optional credential identifier (badge serial, biometric template id).
    pub credential_id: Option<String>,
    /// Sponsor (HR, manager).
    pub sponsor: String,
    /// Approver.
    pub approver: Option<String>,
    /// Justification.
    pub justification: String,
    /// Stage.
    pub stage: GrantStage,
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
    /// Event timeline.
    pub events: Vec<AccessEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl AccessGrant {
    /// New `Requested` grant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        grant_id: impl Into<String>,
        tenant_id: impl Into<String>,
        facility_id: impl Into<String>,
        subject_id: impl Into<String>,
        subject_name: impl Into<String>,
        credential: CredentialKind,
        sponsor: impl Into<String>,
        justification: impl Into<String>,
        requested_at: impl Into<String>,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            tenant_id: tenant_id.into(),
            facility_id: facility_id.into(),
            subject_id: subject_id.into(),
            subject_name: subject_name.into(),
            credential,
            credential_id: None,
            sponsor: sponsor.into(),
            approver: None,
            justification: justification.into(),
            stage: GrantStage::Requested,
            requested_at: requested_at.into(),
            approved_at: None,
            activated_at: None,
            expires_at: None,
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if `now >= expires_at` and grant is still Active or Suspended.
    pub fn is_overdue_revocation(&self, now: &str) -> bool {
        if !matches!(self.stage, GrantStage::Active | GrantStage::Suspended) {
            return false;
        }
        match self.expires_at.as_deref() {
            Some(e) => now >= e,
            None => false,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: GrantStage, to: GrantStage) -> bool {
    use GrantStage::*;
    matches!(
        (from, to),
        (Requested, Approved)
            | (Requested, Denied)
            | (Approved, Active)
            | (Approved, Revoked)
            | (Active, Suspended)
            | (Active, Expired)
            | (Active, Revoked)
            | (Suspended, Active)
            | (Suspended, Revoked)
            | (Suspended, Expired)
    )
}

// =============================================================================
// PhysicalAccessRegister
// =============================================================================

/// Thread-safe physical access registry.
#[derive(Debug, Default)]
pub struct PhysicalAccessRegister {
    facilities: RwLock<HashMap<String, Facility>>,
    grants: RwLock<HashMap<String, AccessGrant>>,
}

impl PhysicalAccessRegister {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a facility.
    pub fn register_facility(&self, facility: Facility) -> SandboxResult<()> {
        let mut g = self
            .facilities
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        if g.contains_key(&facility.facility_id) {
            return Err(SandboxError::Other(format!(
                "facility already registered: {}",
                facility.facility_id
            )));
        }
        g.insert(facility.facility_id.clone(), facility);
        Ok(())
    }

    /// Set facility active flag.
    pub fn set_facility_active(&self, facility_id: &str, active: bool) -> SandboxResult<()> {
        let mut g = self
            .facilities
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        let f = g
            .get_mut(facility_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown facility {facility_id}")))?;
        f.active = active;
        Ok(())
    }

    /// Add a tag to a facility (deduplicated).
    pub fn add_facility_tag(
        &self,
        facility_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .facilities
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        let f = g
            .get_mut(facility_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown facility {facility_id}")))?;
        let tag = tag.into();
        if !f.tags.contains(&tag) {
            f.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get_facility(&self, facility_id: &str) -> Option<Facility> {
        let g = self.facilities.read().ok()?;
        g.get(facility_id).cloned()
    }

    /// All facilities.
    pub fn all_facilities(&self) -> Vec<Facility> {
        match self.facilities.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active facilities.
    pub fn active_facilities(&self) -> Vec<Facility> {
        self.all_facilities()
            .into_iter()
            .filter(|f| f.active)
            .collect()
    }

    /// Request a new grant. Errors if facility unknown / inactive, tenant
    /// mismatched, or grant id collides.
    pub fn request(&self, grant: AccessGrant) -> SandboxResult<()> {
        if !matches!(grant.stage, GrantStage::Requested) {
            return Err(SandboxError::Other(format!(
                "grant must start Requested, got {:?}",
                grant.stage
            )));
        }
        let facility_active = {
            let fg = self
                .facilities
                .read()
                .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
            let f = fg.get(&grant.facility_id).ok_or_else(|| {
                SandboxError::Other(format!("unknown facility {}", grant.facility_id))
            })?;
            if f.tenant_id != grant.tenant_id {
                return Err(SandboxError::Other(format!(
                    "tenant mismatch: grant {} vs facility {}",
                    grant.tenant_id, f.tenant_id
                )));
            }
            f.active
        };
        if !facility_active {
            return Err(SandboxError::Other(format!(
                "facility {} is inactive",
                grant.facility_id
            )));
        }
        let mut g = self
            .grants
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        if g.contains_key(&grant.grant_id) {
            return Err(SandboxError::Other(format!(
                "grant already requested: {}",
                grant.grant_id
            )));
        }
        g.insert(grant.grant_id.clone(), grant);
        Ok(())
    }

    /// Approve a Requested grant. Approver must differ from sponsor for
    /// facilities at Restricted or Critical tiers (separation of duty).
    pub fn approve(
        &self,
        grant_id: &str,
        approver: impl Into<String>,
        at: impl Into<String>,
        expires_at: Option<String>,
        credential_id: Option<String>,
    ) -> SandboxResult<AccessGrant> {
        let approver = approver.into();
        // Look up facility tier.
        let tier = {
            let mut g = self
                .grants
                .write()
                .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
            let r = g
                .get(grant_id)
                .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
            let fg = self
                .facilities
                .read()
                .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
            let f = fg.get(&r.facility_id).ok_or_else(|| {
                SandboxError::Other(format!("unknown facility {}", r.facility_id))
            })?;
            let sponsor = r.sponsor.clone();
            if f.tier.requires_elevated_approval() && approver == sponsor {
                return Err(SandboxError::Other(format!(
                    "approver {} must differ from sponsor for facility tier {:?}",
                    approver, f.tier
                )));
            }
            // Apply the transition while we still hold the write lock.
            let r = g
                .get_mut(grant_id)
                .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
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
            if let Some(c) = credential_id {
                r.credential_id = Some(c);
            }
            r.events.push(AccessEvent {
                at: when,
                actor: approver,
                stage: GrantStage::Approved,
                note: "approved".into(),
            });
            f.tier
        };
        let _ = tier;
        Ok(self.get_grant(grant_id).expect("just modified"))
    }

    /// Activate an Approved grant.
    pub fn activate(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Active, actor, at, "activated")
    }

    /// Suspend an Active grant.
    pub fn suspend(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Suspended, actor, at, reason)
    }

    /// Resume a Suspended grant (back to Active).
    pub fn resume(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Active, actor, at, "resumed")
    }

    /// Expire a grant (natural end of window).
    pub fn expire(
        &self,
        grant_id: &str,
        at: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Expired, "system", at, "expired")
    }

    /// Revoke a grant.
    pub fn revoke(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Revoked, actor, at, reason)
    }

    /// Deny a grant.
    pub fn deny(
        &self,
        grant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        self.simple_transition(grant_id, GrantStage::Denied, actor, at, reason)
    }

    fn simple_transition(
        &self,
        grant_id: &str,
        new_stage: GrantStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<AccessGrant> {
        let mut g = self
            .grants
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        r.stage = new_stage;
        match new_stage {
            GrantStage::Active => {
                if r.activated_at.is_none() {
                    r.activated_at = Some(when.clone());
                }
            }
            GrantStage::Expired | GrantStage::Revoked | GrantStage::Denied => {
                r.closed_at = Some(when.clone());
            }
            _ => {}
        }
        r.events.push(AccessEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(r.clone())
    }

    /// Add a tag to a grant (deduplicated).
    pub fn add_grant_tag(&self, grant_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .grants
            .write()
            .map_err(|_| SandboxError::Other("physical access register poisoned".into()))?;
        let r = g
            .get_mut(grant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown grant {grant_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a grant.
    pub fn get_grant(&self, grant_id: &str) -> Option<AccessGrant> {
        let g = self.grants.read().ok()?;
        g.get(grant_id).cloned()
    }

    /// All grants.
    pub fn all_grants(&self) -> Vec<AccessGrant> {
        match self.grants.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Grants for a tenant.
    pub fn grants_for_tenant(&self, tenant_id: &str) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.tenant_id == tenant_id)
            .collect()
    }

    /// Grants for a facility.
    pub fn grants_for_facility(&self, facility_id: &str) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.facility_id == facility_id)
            .collect()
    }

    /// Grants for a subject.
    pub fn grants_for_subject(&self, subject_id: &str) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.subject_id == subject_id)
            .collect()
    }

    /// Currently active grants.
    pub fn active_grants(&self) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.stage.is_active())
            .collect()
    }

    /// Grants by stage.
    pub fn by_stage(&self, stage: GrantStage) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.stage == stage)
            .collect()
    }

    /// Grants with expires_at past `now` and still Active or Suspended.
    pub fn overdue_revocation(&self, now: &str) -> Vec<AccessGrant> {
        self.all_grants()
            .into_iter()
            .filter(|g| g.is_overdue_revocation(now))
            .collect()
    }

    /// Counts.
    pub fn facility_count(&self) -> usize {
        self.facilities.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Counts.
    pub fn grant_count(&self) -> usize {
        self.grants.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fac(id: &str, tier: FacilityTier) -> Facility {
        Facility::new(id, "tenant-a", format!("Facility {id}"), tier, "loc", "facmgr")
    }

    fn grant(gid: &str, fid: &str, subject: &str, sponsor: &str) -> AccessGrant {
        AccessGrant::new(
            gid,
            "tenant-a",
            fid,
            subject,
            format!("Subject {subject}"),
            CredentialKind::Badge,
            sponsor,
            "needs facility access",
            "2025-04-01T00:00:00Z",
        )
    }

    #[test]
    fn register_facility_and_get() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        assert!(r.get_facility("f1").is_some());
    }

    #[test]
    fn duplicate_facility_errors() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        let err = r
            .register_facility(fac("f1", FacilityTier::Internal))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn request_unknown_facility_errors() {
        let r = PhysicalAccessRegister::new();
        let err = r.request(grant("g1", "missing", "alice", "manager")).unwrap_err();
        assert!(format!("{err}").contains("unknown facility"));
    }

    #[test]
    fn request_inactive_facility_errors() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.set_facility_active("f1", false).unwrap();
        let err = r.request(grant("g1", "f1", "alice", "manager")).unwrap_err();
        assert!(format!("{err}").contains("inactive"));
    }

    #[test]
    fn request_tenant_mismatch_errors() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        let mut g = grant("g1", "f1", "alice", "manager");
        g.tenant_id = "tenant-b".into();
        let err = r.request(g).unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn request_must_start_requested() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        let mut g = grant("g1", "f1", "alice", "manager");
        g.stage = GrantStage::Active;
        let err = r.request(g).unwrap_err();
        assert!(format!("{err}").contains("must start Requested"));
    }

    #[test]
    fn legal_transitions() {
        use GrantStage::*;
        assert!(legal_transition(Requested, Approved));
        assert!(legal_transition(Requested, Denied));
        assert!(legal_transition(Approved, Active));
        assert!(legal_transition(Approved, Revoked));
        assert!(legal_transition(Active, Suspended));
        assert!(legal_transition(Active, Revoked));
        assert!(legal_transition(Suspended, Active));
        assert!(legal_transition(Suspended, Revoked));
        // illegal
        assert!(!legal_transition(Requested, Active));
        assert!(!legal_transition(Revoked, Active));
        assert!(!legal_transition(Denied, Approved));
    }

    #[test]
    fn elevated_approval_requires_distinct_approver() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Critical)).unwrap();
        r.request(grant("g1", "f1", "alice", "alice-manager")).unwrap();
        // Approver = sponsor (who happens to be "alice-manager")
        let err = r
            .approve(
                "g1",
                "alice-manager",
                "2025-04-05T00:00:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("must differ from sponsor"));
        // Approver different — succeeds.
        r.approve(
            "g1",
            "facmgr",
            "2025-04-05T00:00:00Z",
            Some("2025-12-31T00:00:00Z".into()),
            Some("BADGE-123".into()),
        )
        .unwrap();
        let g = r.get_grant("g1").unwrap();
        assert_eq!(g.stage, GrantStage::Approved);
        assert_eq!(g.credential_id.as_deref(), Some("BADGE-123"));
    }

    #[test]
    fn internal_tier_does_not_enforce_distinct_approver() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "alice-manager")).unwrap();
        // Approver = sponsor — allowed for Internal tier.
        r.approve(
            "g1",
            "alice-manager",
            "2025-04-05T00:00:00Z",
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Restricted)).unwrap();
        r.request(grant("g1", "f1", "alice", "alice-manager")).unwrap();
        r.approve(
            "g1",
            "facmgr",
            "2025-04-05T00:00:00Z",
            Some("2025-12-31T00:00:00Z".into()),
            Some("BADGE-123".into()),
        )
        .unwrap();
        r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap();
        let g = r.suspend("g1", "ciso", "2025-06-01T00:00:00Z", "investigation").unwrap();
        assert_eq!(g.stage, GrantStage::Suspended);
        r.resume("g1", "ciso", "2025-06-15T00:00:00Z").unwrap();
        let g = r.expire("g1", "2025-12-31T00:00:00Z").unwrap();
        assert_eq!(g.stage, GrantStage::Expired);
        assert!(g.stage.is_terminal());
        // event log contains all transitions
        assert!(g.events.len() >= 5);
    }

    #[test]
    fn revoke_from_active() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.approve("g1", "facmgr", "2025-04-05T00:00:00Z", None, None).unwrap();
        r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap();
        let g = r
            .revoke("g1", "ciso", "2025-05-01T00:00:00Z", "termination")
            .unwrap();
        assert_eq!(g.stage, GrantStage::Revoked);
        assert!(g.stage.is_terminal());
    }

    #[test]
    fn revoke_from_suspended() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.approve("g1", "facmgr", "2025-04-05T00:00:00Z", None, None).unwrap();
        r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap();
        r.suspend("g1", "ciso", "2025-05-01T00:00:00Z", "x").unwrap();
        let g = r
            .revoke("g1", "ciso", "2025-06-01T00:00:00Z", "termination")
            .unwrap();
        assert_eq!(g.stage, GrantStage::Revoked);
    }

    #[test]
    fn deny_from_requested() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        let g = r
            .deny("g1", "facmgr", "2025-04-05T00:00:00Z", "no business need")
            .unwrap();
        assert_eq!(g.stage, GrantStage::Denied);
    }

    #[test]
    fn illegal_transitions_error() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        // Cannot activate from Requested
        let err = r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
        // Cannot expire from Requested
        let err = r.expire("g1", "2025-04-10T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn overdue_revocation_query() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.approve(
            "g1",
            "facmgr",
            "2025-04-05T00:00:00Z",
            Some("2025-12-31T00:00:00Z".into()),
            None,
        )
        .unwrap();
        r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap();
        // Past expiry, still Active → overdue
        assert_eq!(r.overdue_revocation("2026-01-15T00:00:00Z").len(), 1);
        r.expire("g1", "2026-01-15T00:00:00Z").unwrap();
        assert_eq!(r.overdue_revocation("2026-02-01T00:00:00Z").len(), 0);
    }

    #[test]
    fn add_facility_grant_tag_dedupes() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.add_facility_tag("f1", "audited").unwrap();
        r.add_facility_tag("f1", "audited").unwrap();
        r.add_grant_tag("g1", "vendor").unwrap();
        r.add_grant_tag("g1", "vendor").unwrap();
        assert_eq!(r.get_facility("f1").unwrap().tags, vec!["audited"]);
        assert_eq!(r.get_grant("g1").unwrap().tags, vec!["vendor"]);
    }

    #[test]
    fn unknown_facility_grant_errors() {
        let r = PhysicalAccessRegister::new();
        let err = r.set_facility_active("nope", false).unwrap_err();
        assert!(format!("{err}").contains("unknown facility"));
        let err = r
            .activate("nope", "secops", "2025-04-10T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown grant"));
    }

    #[test]
    fn grants_filters() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.register_facility(fac("f2", FacilityTier::Restricted)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.request(grant("g2", "f2", "alice", "manager")).unwrap();
        r.request(grant("g3", "f1", "bob", "manager")).unwrap();
        assert_eq!(r.grants_for_tenant("tenant-a").len(), 3);
        assert_eq!(r.grants_for_facility("f1").len(), 2);
        assert_eq!(r.grants_for_facility("f2").len(), 1);
        assert_eq!(r.grants_for_subject("alice").len(), 2);
        assert_eq!(r.grants_for_subject("bob").len(), 1);
    }

    #[test]
    fn active_grants_filter() {
        let r = PhysicalAccessRegister::new();
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        r.approve("g1", "facmgr", "2025-04-05T00:00:00Z", None, None).unwrap();
        r.activate("g1", "secops", "2025-04-10T00:00:00Z").unwrap();
        r.request(grant("g2", "f1", "bob", "manager")).unwrap();
        assert_eq!(r.active_grants().len(), 1);
        assert_eq!(r.by_stage(GrantStage::Requested).len(), 1);
    }

    #[test]
    fn tier_helpers() {
        assert!(FacilityTier::Restricted.requires_elevated_approval());
        assert!(FacilityTier::Critical.requires_elevated_approval());
        assert!(!FacilityTier::Internal.requires_elevated_approval());
        assert!(!FacilityTier::Public.requires_elevated_approval());
    }

    #[test]
    fn stage_helpers() {
        assert!(GrantStage::Active.is_active());
        assert!(!GrantStage::Suspended.is_active());
        for s in [GrantStage::Expired, GrantStage::Revoked, GrantStage::Denied] {
            assert!(s.is_terminal());
        }
        for s in [
            GrantStage::Requested,
            GrantStage::Approved,
            GrantStage::Active,
            GrantStage::Suspended,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = PhysicalAccessRegister::new();
        assert_eq!(r.facility_count(), 0);
        assert_eq!(r.grant_count(), 0);
        r.register_facility(fac("f1", FacilityTier::Internal)).unwrap();
        r.request(grant("g1", "f1", "alice", "manager")).unwrap();
        assert_eq!(r.facility_count(), 1);
        assert_eq!(r.grant_count(), 1);
    }

    #[test]
    fn facility_serde() {
        let f = fac("f1", FacilityTier::Critical);
        let j = serde_json::to_string(&f).unwrap();
        let back: Facility = serde_json::from_str(&j).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn grant_serde() {
        let g = grant("g1", "f1", "alice", "manager");
        let j = serde_json::to_string(&g).unwrap();
        let back: AccessGrant = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn enums_serde() {
        for t in [
            FacilityTier::Public,
            FacilityTier::Internal,
            FacilityTier::Restricted,
            FacilityTier::Critical,
        ] {
            assert_eq!(
                t,
                serde_json::from_str::<FacilityTier>(&serde_json::to_string(&t).unwrap()).unwrap()
            );
        }
        for c in [
            CredentialKind::Badge,
            CredentialKind::Pin,
            CredentialKind::Biometric,
            CredentialKind::Mobile,
            CredentialKind::HardwareKey,
            CredentialKind::Escorted,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<CredentialKind>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
        for s in [
            GrantStage::Requested,
            GrantStage::Approved,
            GrantStage::Active,
            GrantStage::Suspended,
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
