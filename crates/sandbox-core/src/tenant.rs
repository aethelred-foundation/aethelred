//! Multi-tenant isolation, RBAC, and per-tenant quotas.
//!
//! Replaces "one Sandbox = one tenant, all-or-nothing access" with a
//! production-grade tenancy model:
//!
//! - **Strong tenant id** typed as [`TenantId`], compared structurally.
//! - **Role-based access control** with [`Role`] grants (`Admin`, `Operator`,
//!   `Auditor`, `Reviewer`, `Reader`) and a [`Permission`] enum.
//! - **Per-tenant quotas** ([`Quota`] + [`QuotaTracker`]) — seals/min, daily
//!   ceiling, evidence-log size cap.
//! - **Tenant directory** ([`TenantDirectory`]) — central registry of
//!   tenants with their RBAC matrix, quotas, and active state.
//!
//! ## Why it matters
//!
//! In production, a single sandbox process serves many tenants — separating
//! "FAB credit" from "ENBD AML" requires:
//!
//! 1. Tenant-id checks on every operation.
//! 2. Quota enforcement before sealing (so a runaway tenant can't fill
//!    your evidence disk).
//! 3. RBAC checks (an auditor must not be able to add or remove gates;
//!    only an admin can rotate keys).
//! 4. A clear failure mode for cross-tenant access attempts.
//!
//! This module ships all four. The [`PermissionContext`] wraps a request
//! with `(tenant_id, principal_id, role)` and resolves permission checks
//! before any state mutation happens.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, RwLock};
use time::OffsetDateTime;

// =============================================================================
// TenantId
// =============================================================================

/// Strong tenant identifier.
///
/// Construct via [`TenantId::new`]; never compare raw strings — always go
/// through this type so an accidental case-sensitivity change can't slip in
/// as a security regression.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Construct a tenant id. Normalises by trimming whitespace.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into().trim().to_string())
    }
    /// Borrow the canonical form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// =============================================================================
// Role + Permission
// =============================================================================

/// Predefined role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Owner of the tenant — all permissions including key rotation, RBAC.
    Admin,
    /// Operator — append seals, run workflows, but no admin actions.
    Operator,
    /// Auditor — read-only access to evidence + audit trails.
    Auditor,
    /// Reviewer — verify seals + sign approvals (no append).
    Reviewer,
    /// Reader — minimum: read seals only.
    Reader,
    /// Custom role with explicit permission set.
    Custom,
}

/// Atomic permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Append a seal.
    SealAppend,
    /// Read seals / evidence bundle.
    SealRead,
    /// Verify seals (reviewer-side).
    SealVerify,
    /// Render audit trails.
    AuditRead,
    /// Export evidence bundles.
    EvidenceExport,
    /// Rotate signer keys.
    KeyRotate,
    /// Modify policy gates.
    PolicyModify,
    /// Manage tenants (admin).
    TenantManage,
    /// Read metrics.
    MetricsRead,
    /// Anchor Merkle roots.
    AnchorSubmit,
    /// Run zkML verification.
    ZkmlVerify,
    /// Manage RBAC grants.
    RbacManage,
}

impl Role {
    /// Default permission set for a role.
    pub fn default_permissions(self) -> HashSet<Permission> {
        use Permission::*;
        match self {
            Self::Admin => vec![
                SealAppend,
                SealRead,
                SealVerify,
                AuditRead,
                EvidenceExport,
                KeyRotate,
                PolicyModify,
                TenantManage,
                MetricsRead,
                AnchorSubmit,
                ZkmlVerify,
                RbacManage,
            ]
            .into_iter()
            .collect(),
            Self::Operator => vec![
                SealAppend,
                SealRead,
                SealVerify,
                AuditRead,
                EvidenceExport,
                MetricsRead,
                AnchorSubmit,
                ZkmlVerify,
            ]
            .into_iter()
            .collect(),
            Self::Auditor => vec![SealRead, AuditRead, EvidenceExport, MetricsRead]
                .into_iter()
                .collect(),
            Self::Reviewer => vec![SealRead, SealVerify, AuditRead].into_iter().collect(),
            Self::Reader => vec![SealRead].into_iter().collect(),
            Self::Custom => HashSet::new(), // explicit grants only
        }
    }
}

// =============================================================================
// Quota
// =============================================================================

/// Per-tenant rate limits and disk caps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quota {
    /// Maximum seals per minute. `None` = unlimited.
    pub seals_per_minute: Option<u64>,
    /// Maximum seals per day. `None` = unlimited.
    pub seals_per_day: Option<u64>,
    /// Maximum on-disk evidence-log size in bytes.
    pub max_disk_bytes: Option<u64>,
}

impl Default for Quota {
    fn default() -> Self {
        Self {
            seals_per_minute: Some(10_000),
            seals_per_day: Some(50_000_000),
            max_disk_bytes: Some(100 * 1024 * 1024 * 1024), // 100 GiB
        }
    }
}

impl Quota {
    /// No quotas (dev / unbounded).
    pub fn unlimited() -> Self {
        Self {
            seals_per_minute: None,
            seals_per_day: None,
            max_disk_bytes: None,
        }
    }

    /// Enterprise / pilot quota.
    pub fn pilot() -> Self {
        Self {
            seals_per_minute: Some(1_000),
            seals_per_day: Some(1_000_000),
            max_disk_bytes: Some(10 * 1024 * 1024 * 1024), // 10 GiB
        }
    }
}

// =============================================================================
// QuotaTracker
// =============================================================================

#[derive(Debug)]
struct QuotaTrackerInner {
    quota: Quota,
    minute_window_start: OffsetDateTime,
    minute_count: u64,
    day_window_start: OffsetDateTime,
    day_count: u64,
    disk_bytes: u64,
}

/// Tracks usage against a quota. Thread-safe.
#[derive(Debug)]
pub struct QuotaTracker {
    inner: Mutex<QuotaTrackerInner>,
}

impl QuotaTracker {
    /// New tracker with the given quota.
    pub fn new(quota: Quota) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            inner: Mutex::new(QuotaTrackerInner {
                quota,
                minute_window_start: now,
                minute_count: 0,
                day_window_start: now,
                day_count: 0,
                disk_bytes: 0,
            }),
        }
    }

    /// Check & reserve a single seal slot.
    pub fn try_reserve_seal(&self) -> SandboxResult<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SandboxError::Other("quota lock poisoned".into()))?;
        let now = OffsetDateTime::now_utc();
        // Roll the minute window if needed.
        if (now - g.minute_window_start).whole_seconds() >= 60 {
            g.minute_window_start = now;
            g.minute_count = 0;
        }
        // Roll the day window if needed.
        if (now - g.day_window_start).whole_seconds() >= 86_400 {
            g.day_window_start = now;
            g.day_count = 0;
        }
        if let Some(limit) = g.quota.seals_per_minute {
            if g.minute_count + 1 > limit {
                return Err(SandboxError::Other(format!(
                    "seals/min quota exceeded: {} > {}",
                    g.minute_count + 1,
                    limit
                )));
            }
        }
        if let Some(limit) = g.quota.seals_per_day {
            if g.day_count + 1 > limit {
                return Err(SandboxError::Other(format!(
                    "seals/day quota exceeded: {} > {}",
                    g.day_count + 1,
                    limit
                )));
            }
        }
        g.minute_count += 1;
        g.day_count += 1;
        Ok(())
    }

    /// Update the on-disk byte tracker (called by persistence).
    pub fn record_disk_bytes(&self, bytes: u64) -> SandboxResult<()> {
        let mut g = self
            .inner
            .lock()
            .map_err(|_| SandboxError::Other("quota lock poisoned".into()))?;
        g.disk_bytes = bytes;
        if let Some(limit) = g.quota.max_disk_bytes {
            if bytes > limit {
                return Err(SandboxError::Other(format!(
                    "disk-bytes quota exceeded: {bytes} > {limit}"
                )));
            }
        }
        Ok(())
    }

    /// Snapshot current usage.
    pub fn snapshot(&self) -> QuotaSnapshot {
        let g = match self.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        QuotaSnapshot {
            minute_count: g.minute_count,
            day_count: g.day_count,
            disk_bytes: g.disk_bytes,
        }
    }
}

/// Point-in-time usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuotaSnapshot {
    /// Seals consumed in current minute window.
    pub minute_count: u64,
    /// Seals consumed in current day window.
    pub day_count: u64,
    /// Disk bytes used.
    pub disk_bytes: u64,
}

// =============================================================================
// Principal + grants
// =============================================================================

/// Principal id (user / service-account / agent).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// New principal id.
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into().trim().to_string())
    }
    /// Borrow.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Single grant: a principal has a role within a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    /// Principal.
    pub principal: PrincipalId,
    /// Tenant.
    pub tenant: TenantId,
    /// Role.
    pub role: Role,
    /// Optional explicit permissions (overrides role's default).
    pub explicit_permissions: Option<HashSet<Permission>>,
    /// RFC 3339 expiry (`None` = no expiry).
    pub expires_at: Option<String>,
}

impl Grant {
    /// Effective permissions.
    pub fn effective(&self) -> HashSet<Permission> {
        match &self.explicit_permissions {
            Some(p) => p.clone(),
            None => self.role.default_permissions(),
        }
    }

    /// `true` if the grant is currently in effect (not expired).
    pub fn is_active(&self) -> bool {
        match &self.expires_at {
            None => true,
            Some(exp) => match OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(t) => OffsetDateTime::now_utc() < t,
                Err(_) => false,
            },
        }
    }
}

// =============================================================================
// TenantRecord + TenantDirectory
// =============================================================================

/// One tenant entry.
#[derive(Debug)]
pub struct TenantRecord {
    /// Tenant id.
    pub id: TenantId,
    /// Display label (e.g., `"FAB Finance Sandbox"`).
    pub label: String,
    /// Quota.
    pub quota: QuotaTracker,
    /// Active flag (admins can suspend a tenant).
    pub active: bool,
    /// Grants attached to this tenant.
    pub grants: RwLock<Vec<Grant>>,
}

impl TenantRecord {
    fn new(id: TenantId, label: impl Into<String>, quota: Quota) -> Self {
        Self {
            id,
            label: label.into(),
            quota: QuotaTracker::new(quota),
            active: true,
            grants: RwLock::new(Vec::new()),
        }
    }
}

/// Central tenant directory.
pub struct TenantDirectory {
    tenants: RwLock<HashMap<TenantId, TenantRecord>>,
}

impl Default for TenantDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantDirectory {
    /// Empty directory.
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(HashMap::new()),
        }
    }

    /// Register a tenant (idempotent).
    pub fn register(
        &self,
        id: TenantId,
        label: impl Into<String>,
        quota: Quota,
    ) -> SandboxResult<()> {
        let mut g = self.tenants.write().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        if g.contains_key(&id) {
            return Ok(());
        }
        g.insert(id.clone(), TenantRecord::new(id, label, quota));
        Ok(())
    }

    /// Suspend a tenant.
    pub fn suspend(&self, id: &TenantId) -> SandboxResult<()> {
        let mut g = self.tenants.write().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g
            .get_mut(id)
            .ok_or_else(|| SandboxError::Other(format!("unknown tenant: {id}")))?;
        t.active = false;
        Ok(())
    }

    /// Resume a suspended tenant.
    pub fn resume(&self, id: &TenantId) -> SandboxResult<()> {
        let mut g = self.tenants.write().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g
            .get_mut(id)
            .ok_or_else(|| SandboxError::Other(format!("unknown tenant: {id}")))?;
        t.active = true;
        Ok(())
    }

    /// Look up a tenant.
    pub fn has(&self, id: &TenantId) -> bool {
        self.tenants
            .read()
            .map(|g| g.contains_key(id))
            .unwrap_or(false)
    }

    /// Total tenants.
    pub fn len(&self) -> usize {
        self.tenants.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no tenants.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add a grant.
    pub fn add_grant(&self, grant: Grant) -> SandboxResult<()> {
        let g = self.tenants.read().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g.get(&grant.tenant).ok_or_else(|| {
            SandboxError::Other(format!("unknown tenant: {}", grant.tenant))
        })?;
        let mut grants = t
            .grants
            .write()
            .map_err(|_| SandboxError::Other("grants lock poisoned".into()))?;
        grants.push(grant);
        Ok(())
    }

    /// Remove all grants for a principal in a tenant.
    pub fn revoke_principal(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
    ) -> SandboxResult<usize> {
        let g = self.tenants.read().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g
            .get(tenant)
            .ok_or_else(|| SandboxError::Other(format!("unknown tenant: {tenant}")))?;
        let mut grants = t
            .grants
            .write()
            .map_err(|_| SandboxError::Other("grants lock poisoned".into()))?;
        let before = grants.len();
        grants.retain(|gr| &gr.principal != principal);
        Ok(before - grants.len())
    }

    /// Check that `principal` has `permission` for `tenant`.
    pub fn check(
        &self,
        tenant: &TenantId,
        principal: &PrincipalId,
        permission: Permission,
    ) -> SandboxResult<()> {
        let g = self.tenants.read().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g.get(tenant).ok_or_else(|| {
            SandboxError::Other(format!("unknown tenant: {tenant}"))
        })?;
        if !t.active {
            return Err(SandboxError::Other(format!(
                "tenant {tenant} is suspended"
            )));
        }
        let grants = t
            .grants
            .read()
            .map_err(|_| SandboxError::Other("grants lock poisoned".into()))?;
        for gr in grants.iter() {
            if &gr.principal == principal && gr.is_active() {
                if gr.effective().contains(&permission) {
                    return Ok(());
                }
            }
        }
        Err(SandboxError::Other(format!(
            "principal {principal:?} lacks permission {permission:?} on tenant {tenant}"
        )))
    }

    /// Reserve a seal slot in tenant's quota tracker.
    pub fn reserve_seal(&self, tenant: &TenantId) -> SandboxResult<()> {
        let g = self.tenants.read().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g.get(tenant).ok_or_else(|| {
            SandboxError::Other(format!("unknown tenant: {tenant}"))
        })?;
        if !t.active {
            return Err(SandboxError::Other(format!(
                "tenant {tenant} is suspended"
            )));
        }
        t.quota.try_reserve_seal()
    }

    /// Snapshot a tenant's quota usage.
    pub fn quota_snapshot(&self, tenant: &TenantId) -> SandboxResult<QuotaSnapshot> {
        let g = self.tenants.read().map_err(|_| {
            SandboxError::Other("tenant directory lock poisoned".into())
        })?;
        let t = g.get(tenant).ok_or_else(|| {
            SandboxError::Other(format!("unknown tenant: {tenant}"))
        })?;
        Ok(t.quota.snapshot())
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// =============================================================================
// PermissionContext — wraps a request
// =============================================================================

/// Bundle of `(tenant, principal)` you pass to permission checks.
#[derive(Debug, Clone)]
pub struct PermissionContext<'a> {
    /// Tenant.
    pub tenant: &'a TenantId,
    /// Principal making the request.
    pub principal: &'a PrincipalId,
    /// Optional auxiliary context tags (e.g., `"session_id"`, `"ip"`).
    pub tags: HashMap<String, String>,
}

impl<'a> PermissionContext<'a> {
    /// New context.
    pub fn new(tenant: &'a TenantId, principal: &'a PrincipalId) -> Self {
        Self {
            tenant,
            principal,
            tags: HashMap::new(),
        }
    }

    /// Add an audit tag.
    pub fn with_tag(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.tags.insert(k.into(), v.into());
        self
    }

    /// Run the permission check via the given directory.
    pub fn require(
        &self,
        directory: &TenantDirectory,
        permission: Permission,
    ) -> SandboxResult<()> {
        directory.check(self.tenant, self.principal, permission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fab_directory() -> TenantDirectory {
        let dir = TenantDirectory::new();
        dir.register(TenantId::new("FAB"), "FAB Finance Sandbox", Quota::pilot())
            .unwrap();
        dir
    }

    fn alice() -> PrincipalId {
        PrincipalId::new("alice")
    }

    #[test]
    fn tenant_id_normalises_whitespace() {
        let t1 = TenantId::new("  FAB  ");
        let t2 = TenantId::new("FAB");
        assert_eq!(t1, t2);
    }

    #[test]
    fn role_default_permissions_admin_has_all() {
        let p = Role::Admin.default_permissions();
        assert!(p.contains(&Permission::SealAppend));
        assert!(p.contains(&Permission::TenantManage));
        assert!(p.contains(&Permission::KeyRotate));
    }

    #[test]
    fn role_default_permissions_reader_has_only_read() {
        let p = Role::Reader.default_permissions();
        assert!(p.contains(&Permission::SealRead));
        assert!(!p.contains(&Permission::SealAppend));
        assert!(!p.contains(&Permission::KeyRotate));
    }

    #[test]
    fn role_auditor_can_export() {
        let p = Role::Auditor.default_permissions();
        assert!(p.contains(&Permission::EvidenceExport));
        assert!(!p.contains(&Permission::SealAppend));
    }

    #[test]
    fn role_reviewer_can_verify_only() {
        let p = Role::Reviewer.default_permissions();
        assert!(p.contains(&Permission::SealVerify));
        assert!(!p.contains(&Permission::SealAppend));
    }

    #[test]
    fn role_custom_starts_empty() {
        assert_eq!(Role::Custom.default_permissions().len(), 0);
    }

    #[test]
    fn quota_unlimited_has_no_caps() {
        let q = Quota::unlimited();
        assert!(q.seals_per_minute.is_none());
        assert!(q.seals_per_day.is_none());
    }

    #[test]
    fn quota_tracker_allows_under_limit() {
        let t = QuotaTracker::new(Quota {
            seals_per_minute: Some(5),
            seals_per_day: Some(100),
            max_disk_bytes: None,
        });
        for _ in 0..5 {
            t.try_reserve_seal().unwrap();
        }
    }

    #[test]
    fn quota_tracker_rejects_over_minute_limit() {
        let t = QuotaTracker::new(Quota {
            seals_per_minute: Some(2),
            seals_per_day: None,
            max_disk_bytes: None,
        });
        t.try_reserve_seal().unwrap();
        t.try_reserve_seal().unwrap();
        assert!(t.try_reserve_seal().is_err());
    }

    #[test]
    fn quota_tracker_rejects_over_disk_limit() {
        let t = QuotaTracker::new(Quota {
            seals_per_minute: None,
            seals_per_day: None,
            max_disk_bytes: Some(100),
        });
        t.record_disk_bytes(50).unwrap();
        assert!(t.record_disk_bytes(101).is_err());
    }

    #[test]
    fn quota_snapshot_reflects_usage() {
        let t = QuotaTracker::new(Quota::default());
        t.try_reserve_seal().unwrap();
        t.try_reserve_seal().unwrap();
        let s = t.snapshot();
        assert_eq!(s.minute_count, 2);
        assert_eq!(s.day_count, 2);
    }

    #[test]
    fn directory_register_and_lookup() {
        let dir = fab_directory();
        assert!(dir.has(&TenantId::new("FAB")));
        assert!(!dir.has(&TenantId::new("ENBD")));
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn directory_register_idempotent() {
        let dir = fab_directory();
        dir.register(TenantId::new("FAB"), "FAB v2", Quota::default())
            .unwrap();
        assert_eq!(dir.len(), 1);
    }

    #[test]
    fn suspended_tenant_rejects_seal() {
        let dir = fab_directory();
        dir.suspend(&TenantId::new("FAB")).unwrap();
        let r = dir.reserve_seal(&TenantId::new("FAB"));
        assert!(r.is_err());
    }

    #[test]
    fn suspended_tenant_rejects_permission_check() {
        let dir = fab_directory();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Admin,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        dir.suspend(&TenantId::new("FAB")).unwrap();
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .is_err());
    }

    #[test]
    fn resume_re_enables_tenant() {
        let dir = fab_directory();
        dir.suspend(&TenantId::new("FAB")).unwrap();
        dir.resume(&TenantId::new("FAB")).unwrap();
        dir.reserve_seal(&TenantId::new("FAB")).unwrap();
    }

    #[test]
    fn unknown_tenant_returns_error() {
        let dir = TenantDirectory::new();
        assert!(dir.reserve_seal(&TenantId::new("NEVER")).is_err());
    }

    #[test]
    fn admin_can_seal() {
        let dir = fab_directory();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Admin,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        dir.check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .unwrap();
    }

    #[test]
    fn reader_cannot_seal() {
        let dir = fab_directory();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Reader,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .is_err());
    }

    #[test]
    fn principal_with_no_grant_is_denied() {
        let dir = fab_directory();
        let alice = alice();
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealRead)
            .is_err());
    }

    #[test]
    fn revoke_removes_grants() {
        let dir = fab_directory();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Admin,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        let removed = dir
            .revoke_principal(&TenantId::new("FAB"), &alice)
            .unwrap();
        assert_eq!(removed, 1);
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealRead)
            .is_err());
    }

    #[test]
    fn explicit_permissions_override_role() {
        let dir = fab_directory();
        let alice = alice();
        let mut perms = HashSet::new();
        perms.insert(Permission::ZkmlVerify);
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Reader, // Reader has only SealRead by default
            explicit_permissions: Some(perms),
            expires_at: None,
        })
        .unwrap();
        // Reader's SealRead is GONE because explicit overrides:
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealRead)
            .is_err());
        // ZkmlVerify is granted explicitly:
        dir.check(&TenantId::new("FAB"), &alice, Permission::ZkmlVerify)
            .unwrap();
    }

    #[test]
    fn expired_grant_is_inactive() {
        let dir = fab_directory();
        let alice = alice();
        let past = OffsetDateTime::now_utc() - time::Duration::hours(1);
        let s = past
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Admin,
            explicit_permissions: None,
            expires_at: Some(s),
        })
        .unwrap();
        assert!(dir
            .check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .is_err());
    }

    #[test]
    fn future_expiry_is_active() {
        let dir = fab_directory();
        let alice = alice();
        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let s = future
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Operator,
            explicit_permissions: None,
            expires_at: Some(s),
        })
        .unwrap();
        dir.check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .unwrap();
    }

    #[test]
    fn quota_snapshot_via_directory() {
        let dir = fab_directory();
        let t = TenantId::new("FAB");
        dir.reserve_seal(&t).unwrap();
        dir.reserve_seal(&t).unwrap();
        let s = dir.quota_snapshot(&t).unwrap();
        assert_eq!(s.minute_count, 2);
    }

    #[test]
    fn permission_context_runs_check() {
        let dir = fab_directory();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Operator,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        let tenant = TenantId::new("FAB");
        let ctx = PermissionContext::new(&tenant, &alice).with_tag("session", "s1");
        ctx.require(&dir, Permission::SealAppend).unwrap();
        assert_eq!(ctx.tags.get("session").map(String::as_str), Some("s1"));
    }

    #[test]
    fn grant_serde_round_trip() {
        let g = Grant {
            principal: alice(),
            tenant: TenantId::new("FAB"),
            role: Role::Operator,
            explicit_permissions: None,
            expires_at: None,
        };
        let j = serde_json::to_string(&g).unwrap();
        let p: Grant = serde_json::from_str(&j).unwrap();
        assert_eq!(p.tenant, g.tenant);
        assert_eq!(p.role, g.role);
    }

    #[test]
    fn directory_is_empty_on_creation() {
        let dir = TenantDirectory::new();
        assert!(dir.is_empty());
    }

    #[test]
    fn many_principals_each_independent() {
        let dir = fab_directory();
        for i in 0..10 {
            let p = PrincipalId::new(format!("user-{i}"));
            dir.add_grant(Grant {
                principal: p,
                tenant: TenantId::new("FAB"),
                role: Role::Reader,
                explicit_permissions: None,
                expires_at: None,
            })
            .unwrap();
        }
        for i in 0..10 {
            let p = PrincipalId::new(format!("user-{i}"));
            dir.check(&TenantId::new("FAB"), &p, Permission::SealRead)
                .unwrap();
        }
    }

    #[test]
    fn cross_tenant_isolation() {
        let dir = TenantDirectory::new();
        dir.register(TenantId::new("FAB"), "FAB", Quota::default()).unwrap();
        dir.register(TenantId::new("ENBD"), "ENBD", Quota::default()).unwrap();
        let alice = alice();
        dir.add_grant(Grant {
            principal: alice.clone(),
            tenant: TenantId::new("FAB"),
            role: Role::Admin,
            explicit_permissions: None,
            expires_at: None,
        })
        .unwrap();
        // Alice has admin on FAB.
        dir.check(&TenantId::new("FAB"), &alice, Permission::SealAppend)
            .unwrap();
        // But not on ENBD.
        assert!(dir
            .check(&TenantId::new("ENBD"), &alice, Permission::SealAppend)
            .is_err());
    }
}
