//! Enterprise SSO integration registry — SAML / OIDC config per tenant.
//!
//! Models the configuration that lets a customer hook up Okta / Azure AD /
//! PingFederate / Auth0 to the sandbox. Records:
//!
//! - Identity provider type + endpoint URLs.
//! - Certificate thumbprint (for SAML).
//! - Group → role mappings.
//! - JIT-provisioning toggles.
//! - Last-rotation timestamp (cert rotation tracking).
//!
//! It does **not** perform authentication — that lives in the auth layer.
//! This module is the **operational source of truth** for what's
//! configured, used by support teams diagnosing login issues.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// IdpKind
// =============================================================================

/// IdP protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdpKind {
    /// SAML 2.0.
    Saml2,
    /// OIDC.
    Oidc,
    /// SCIM (provisioning only, paired with SAML/OIDC).
    Scim,
}

// =============================================================================
// SsoStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsoStatus {
    /// Active.
    Active,
    /// Configured but not yet enabled for users.
    Pending,
    /// Disabled.
    Disabled,
}

// =============================================================================
// GroupMapping
// =============================================================================

/// Map IdP group → internal role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMapping {
    /// IdP group name.
    pub idp_group: String,
    /// Internal role.
    pub role: String,
}

// =============================================================================
// SsoConfig
// =============================================================================

/// SSO config for one tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SsoConfig {
    /// Stable id.
    pub config_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// IdP kind.
    pub kind: IdpKind,
    /// IdP entity id / issuer URL.
    pub issuer: String,
    /// SSO endpoint URL.
    pub sso_url: String,
    /// SLO endpoint (logout).
    pub slo_url: Option<String>,
    /// Certificate thumbprint (SAML) or JWKS URI (OIDC).
    pub cert_or_jwks: String,
    /// Group → role mappings.
    pub group_mappings: Vec<GroupMapping>,
    /// `true` if Just-in-Time provisioning is enabled.
    pub jit_enabled: bool,
    /// Status.
    pub status: SsoStatus,
    /// RFC 3339 last cert rotation.
    pub last_rotated_at: Option<String>,
    /// RFC 3339 created.
    pub created_at: String,
}

impl SsoConfig {
    /// Days since last cert rotation (None if never).
    pub fn days_since_rotation(&self, now: OffsetDateTime) -> Option<i64> {
        let last = self.last_rotated_at.as_ref()?;
        let t = OffsetDateTime::parse(
            last,
            &time::format_description::well_known::Rfc3339,
        )
        .ok()?;
        Some((now - t).whole_days())
    }
    /// Resolve role for an IdP group.
    pub fn role_for_group(&self, idp_group: &str) -> Option<&str> {
        self.group_mappings
            .iter()
            .find(|m| m.idp_group == idp_group)
            .map(|m| m.role.as_str())
    }
}

// =============================================================================
// SsoRegistry
// =============================================================================

#[derive(Default)]
struct State {
    configs: HashMap<String, SsoConfig>,
}

/// Registry.
pub struct SsoRegistry {
    state: RwLock<State>,
}

impl Default for SsoRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for SsoRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoRegistry")
            .field("configs", &self.len())
            .finish()
    }
}

impl SsoRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a config.
    pub fn register(&self, c: SsoConfig) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sso registry poisoned".into()))?;
        if g.configs.contains_key(&c.config_id) {
            return Err(SandboxError::Other(format!(
                "config {} already registered",
                c.config_id
            )));
        }
        g.configs.insert(c.config_id.clone(), c);
        Ok(())
    }

    /// Update status.
    pub fn set_status(&self, config_id: &str, status: SsoStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sso registry poisoned".into()))?;
        let c = g
            .configs
            .get_mut(config_id)
            .ok_or_else(|| SandboxError::Other(format!("config {} not found", config_id)))?;
        c.status = status;
        Ok(())
    }

    /// Mark cert rotated.
    pub fn record_cert_rotation(&self, config_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sso registry poisoned".into()))?;
        let c = g
            .configs
            .get_mut(config_id)
            .ok_or_else(|| SandboxError::Other(format!("config {} not found", config_id)))?;
        c.last_rotated_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Add a group mapping.
    pub fn add_mapping(
        &self,
        config_id: &str,
        idp_group: impl Into<String>,
        role: impl Into<String>,
    ) -> SandboxResult<()> {
        let idp_group = idp_group.into();
        let role = role.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("sso registry poisoned".into()))?;
        let c = g
            .configs
            .get_mut(config_id)
            .ok_or_else(|| SandboxError::Other(format!("config {} not found", config_id)))?;
        if c.group_mappings.iter().any(|m| m.idp_group == idp_group) {
            return Err(SandboxError::Other(format!(
                "mapping for group {} already exists",
                idp_group
            )));
        }
        c.group_mappings.push(GroupMapping { idp_group, role });
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<SsoConfig> {
        self.state.read().ok()?.configs.get(id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<SsoConfig> {
        self.state
            .read()
            .map(|g| g.configs.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Configs for a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<SsoConfig> {
        self.all().into_iter().filter(|c| c.tenant_id == tenant).collect()
    }
    /// Configs older than `days` since last rotation.
    pub fn rotation_overdue(&self, now: OffsetDateTime, days: i64) -> Vec<SsoConfig> {
        self.all()
            .into_iter()
            .filter(|c| match c.days_since_rotation(now) {
                Some(d) => d > days,
                None => true,
            })
            .collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.configs.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// SsoConfigBuilder
// =============================================================================

/// Builder.
pub struct SsoConfigBuilder {
    config_id: String,
    tenant_id: String,
    name: String,
    kind: IdpKind,
    issuer: String,
    sso_url: String,
    slo_url: Option<String>,
    cert_or_jwks: String,
    group_mappings: Vec<GroupMapping>,
    jit_enabled: bool,
}

impl SsoConfigBuilder {
    /// New.
    pub fn new(
        config_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        kind: IdpKind,
        issuer: impl Into<String>,
        sso_url: impl Into<String>,
        cert_or_jwks: impl Into<String>,
    ) -> Self {
        Self {
            config_id: config_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            kind,
            issuer: issuer.into(),
            sso_url: sso_url.into(),
            slo_url: None,
            cert_or_jwks: cert_or_jwks.into(),
            group_mappings: Vec::new(),
            jit_enabled: false,
        }
    }
    /// SLO url.
    pub fn slo(mut self, url: impl Into<String>) -> Self {
        self.slo_url = Some(url.into());
        self
    }
    /// Group mapping.
    pub fn map_group(
        mut self,
        idp_group: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        self.group_mappings.push(GroupMapping {
            idp_group: idp_group.into(),
            role: role.into(),
        });
        self
    }
    /// JIT toggle.
    pub fn jit(mut self, enabled: bool) -> Self {
        self.jit_enabled = enabled;
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<SsoConfig> {
        if self.config_id.trim().is_empty() {
            return Err(SandboxError::Other("config_id required".into()));
        }
        if self.cert_or_jwks.trim().is_empty() {
            return Err(SandboxError::Other("cert/JWKS required".into()));
        }
        Ok(SsoConfig {
            config_id: self.config_id,
            tenant_id: self.tenant_id,
            name: self.name,
            kind: self.kind,
            issuer: self.issuer,
            sso_url: self.sso_url,
            slo_url: self.slo_url,
            cert_or_jwks: self.cert_or_jwks,
            group_mappings: self.group_mappings,
            jit_enabled: self.jit_enabled,
            status: SsoStatus::Pending,
            last_rotated_at: None,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SsoConfig {
        SsoConfigBuilder::new(
            "fab-okta",
            "FAB",
            "FAB Okta",
            IdpKind::Saml2,
            "https://okta.test/issuer",
            "https://okta.test/sso",
            "ABC123CERTHASH",
        )
        .map_group("okta-admins", "admin")
        .map_group("okta-readers", "reader")
        .jit(true)
        .build()
        .unwrap()
    }

    #[test]
    fn build_creates_config() {
        let c = cfg();
        assert_eq!(c.tenant_id, "FAB");
        assert_eq!(c.kind, IdpKind::Saml2);
        assert_eq!(c.status, SsoStatus::Pending);
    }

    #[test]
    fn empty_id_errors() {
        assert!(SsoConfigBuilder::new(
            "",
            "x",
            "y",
            IdpKind::Saml2,
            "i",
            "s",
            "c"
        )
        .build()
        .is_err());
    }

    #[test]
    fn empty_cert_errors() {
        assert!(SsoConfigBuilder::new(
            "id",
            "x",
            "y",
            IdpKind::Saml2,
            "i",
            "s",
            ""
        )
        .build()
        .is_err());
    }

    #[test]
    fn role_for_group_resolves() {
        let c = cfg();
        assert_eq!(c.role_for_group("okta-admins"), Some("admin"));
        assert_eq!(c.role_for_group("ghost"), None);
    }

    #[test]
    fn register_and_lookup() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        assert!(r.get("fab-okta").is_some());
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        assert!(r.register(cfg()).is_err());
    }

    #[test]
    fn set_status_works() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        r.set_status("fab-okta", SsoStatus::Active).unwrap();
        assert_eq!(r.get("fab-okta").unwrap().status, SsoStatus::Active);
    }

    #[test]
    fn record_cert_rotation_sets_timestamp() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        r.record_cert_rotation("fab-okta").unwrap();
        assert!(r.get("fab-okta").unwrap().last_rotated_at.is_some());
    }

    #[test]
    fn add_mapping_dedupes() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        // Already has okta-admins. Adding it again should error.
        assert!(r.add_mapping("fab-okta", "okta-admins", "admin").is_err());
        // New mapping should succeed.
        r.add_mapping("fab-okta", "okta-ops", "ops").unwrap();
    }

    #[test]
    fn for_tenant_filters() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        let mut other = cfg();
        other.config_id = "enbd-azure".into();
        other.tenant_id = "ENBD".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
        assert_eq!(r.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn days_since_rotation_when_set() {
        let mut c = cfg();
        let when = OffsetDateTime::now_utc() - time::Duration::days(60);
        c.last_rotated_at = Some(
            when.format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        );
        let d = c.days_since_rotation(OffsetDateTime::now_utc()).unwrap();
        assert!(d >= 59 && d <= 61);
    }

    #[test]
    fn days_since_rotation_none_when_never() {
        let c = cfg();
        assert!(c.days_since_rotation(OffsetDateTime::now_utc()).is_none());
    }

    #[test]
    fn rotation_overdue_includes_never_rotated() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        let due = r.rotation_overdue(OffsetDateTime::now_utc(), 30);
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn rotation_overdue_excludes_recent() {
        let r = SsoRegistry::new();
        r.register(cfg()).unwrap();
        r.record_cert_rotation("fab-okta").unwrap();
        let due = r.rotation_overdue(OffsetDateTime::now_utc(), 30);
        assert!(due.is_empty());
    }

    #[test]
    fn config_serde() {
        let c = cfg();
        let j = serde_json::to_string(&c).unwrap();
        let p: SsoConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn idp_kind_serde() {
        for k in [IdpKind::Saml2, IdpKind::Oidc, IdpKind::Scim] {
            let j = serde_json::to_string(&k).unwrap();
            let p: IdpKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn sso_status_serde() {
        for s in [SsoStatus::Active, SsoStatus::Pending, SsoStatus::Disabled] {
            let j = serde_json::to_string(&s).unwrap();
            let p: SsoStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn group_mapping_serde() {
        let m = GroupMapping {
            idp_group: "x".into(),
            role: "y".into(),
        };
        let j = serde_json::to_string(&m).unwrap();
        let p: GroupMapping = serde_json::from_str(&j).unwrap();
        assert_eq!(p, m);
    }

    #[test]
    fn record_cert_unknown_errors() {
        let r = SsoRegistry::new();
        assert!(r.record_cert_rotation("ghost").is_err());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = SsoRegistry::new();
        assert!(r.get("ghost").is_none());
    }

    #[test]
    fn slo_url_recorded() {
        let c = SsoConfigBuilder::new(
            "x",
            "y",
            "z",
            IdpKind::Oidc,
            "i",
            "s",
            "c",
        )
        .slo("https://logout.test")
        .build()
        .unwrap();
        assert_eq!(c.slo_url.as_deref(), Some("https://logout.test"));
    }

    #[test]
    fn jit_default_false() {
        let c = SsoConfigBuilder::new(
            "x",
            "y",
            "z",
            IdpKind::Oidc,
            "i",
            "s",
            "c",
        )
        .build()
        .unwrap();
        assert!(!c.jit_enabled);
    }

    #[test]
    fn registry_count_tracks() {
        let r = SsoRegistry::new();
        assert!(r.is_empty());
        r.register(cfg()).unwrap();
        assert_eq!(r.len(), 1);
    }
}
