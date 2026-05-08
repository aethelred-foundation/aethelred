//! Per-tenant API key issuance, rotation, and revocation.
//!
//! Distinct from [`crate::capability_token`] (signed JWT-ish tokens carrying
//! tight permissions) and [`crate::token_delegation`] (delegated sub-tokens):
//! API keys are *long-lived* shared secrets that customers store in their
//! systems and use to authenticate against the protocol.
//!
//! Each key is shown to the customer once (at creation) and stored as a
//! hash in the registry — never recoverable in clear after.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// KeyScope
// =============================================================================

/// Scope of permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyScope {
    /// Read-only access.
    ReadOnly,
    /// Read + write to seals.
    SealWrite,
    /// Admin scope.
    Admin,
}

// =============================================================================
// KeyStatus
// =============================================================================

/// Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// Active.
    Active,
    /// Revoked.
    Revoked,
    /// Expired.
    Expired,
}

// =============================================================================
// ApiKey
// =============================================================================

/// One key record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKey {
    /// Stable id.
    pub key_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Hash of the key (key itself never stored).
    pub key_hash: Sha256Digest,
    /// First 8 chars of the original key (for display: `"ak_a1b2c3d4..."`).
    pub display_prefix: String,
    /// Scope.
    pub scope: KeyScope,
    /// Status.
    pub status: KeyStatus,
    /// RFC 3339 issued.
    pub issued_at: String,
    /// RFC 3339 expires (None = never).
    pub expires_at: Option<String>,
    /// RFC 3339 last used (rotated by verifier).
    pub last_used_at: Option<String>,
    /// RFC 3339 revoked.
    pub revoked_at: Option<String>,
    /// Issued by.
    pub issued_by: String,
    /// Revoked by.
    pub revoked_by: Option<String>,
}

impl ApiKey {
    /// `true` if currently active and unexpired.
    pub fn is_active(&self, now: OffsetDateTime) -> bool {
        if self.status != KeyStatus::Active {
            return false;
        }
        if let Some(exp) = &self.expires_at {
            if let Ok(t) = OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now >= t {
                    return false;
                }
            }
        }
        true
    }
}

// =============================================================================
// IssuedKey — what the caller gets at create time
// =============================================================================

/// Returned at issuance with the *clear* key (only time it's visible).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedKey {
    /// The record.
    pub key: ApiKey,
    /// The plaintext key (e.g., `"ak_..."`).
    pub plaintext: String,
}

// =============================================================================
// ApiKeyRegistry
// =============================================================================

#[derive(Default)]
struct State {
    keys: HashMap<String, ApiKey>,
    /// hash → key_id.
    by_hash: HashMap<Sha256Digest, String>,
}

/// Registry.
pub struct ApiKeyRegistry {
    state: RwLock<State>,
}

impl Default for ApiKeyRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ApiKeyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyRegistry")
            .field("keys", &self.len())
            .finish()
    }
}

impl ApiKeyRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new key.
    pub fn issue(
        &self,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        scope: KeyScope,
        issued_by: impl Into<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> SandboxResult<IssuedKey> {
        let key_id = format!("key_{}", Uuid::now_v7());
        // Plaintext is `ak_<32 hex chars>` — derived from a fresh UUID.
        let plaintext = format!("ak_{}", Uuid::now_v7().simple());
        let key_hash = Hasher::sha256(plaintext.as_bytes());
        let display_prefix = plaintext.chars().take(11).collect::<String>();
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let exp = expires_at.map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        });
        let key = ApiKey {
            key_id: key_id.clone(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            key_hash: key_hash.clone(),
            display_prefix,
            scope,
            status: KeyStatus::Active,
            issued_at: now,
            expires_at: exp,
            last_used_at: None,
            revoked_at: None,
            issued_by: issued_by.into(),
            revoked_by: None,
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("api key registry poisoned".into()))?;
        g.by_hash.insert(key_hash, key_id.clone());
        g.keys.insert(key_id, key.clone());
        Ok(IssuedKey { key, plaintext })
    }

    /// Verify a key plaintext against the registry. Returns the matching
    /// record if active.
    pub fn verify(&self, plaintext: &str, now: OffsetDateTime) -> Option<ApiKey> {
        let h = Hasher::sha256(plaintext.as_bytes());
        let g = self.state.read().ok()?;
        let id = g.by_hash.get(&h)?;
        let k = g.keys.get(id)?;
        if k.is_active(now) {
            Some(k.clone())
        } else {
            None
        }
    }

    /// Mark last-used (called by the verifier).
    pub fn touch(&self, key_id: &str) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("api key registry poisoned".into()))?;
        let k = g
            .keys
            .get_mut(key_id)
            .ok_or_else(|| SandboxError::Other(format!("key {} not found", key_id)))?;
        k.last_used_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Revoke.
    pub fn revoke(&self, key_id: &str, revoked_by: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("api key registry poisoned".into()))?;
        let k = g
            .keys
            .get_mut(key_id)
            .ok_or_else(|| SandboxError::Other(format!("key {} not found", key_id)))?;
        k.status = KeyStatus::Revoked;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        k.revoked_at = Some(now);
        k.revoked_by = Some(revoked_by.into());
        Ok(())
    }

    /// Rotate: revoke + issue a new key with the same scope.
    pub fn rotate(
        &self,
        key_id: &str,
        rotated_by: impl Into<String>,
    ) -> SandboxResult<IssuedKey> {
        let rotated_by = rotated_by.into();
        let existing = self
            .get(key_id)
            .ok_or_else(|| SandboxError::Other(format!("key {} not found", key_id)))?;
        self.revoke(key_id, rotated_by.clone())?;
        self.issue(
            existing.tenant_id,
            format!("{} (rotated)", existing.name),
            existing.scope,
            rotated_by,
            existing.expires_at.and_then(|s| {
                OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339).ok()
            }),
        )
    }

    /// Lookup.
    pub fn get(&self, key_id: &str) -> Option<ApiKey> {
        self.state.read().ok()?.keys.get(key_id).cloned()
    }
    /// All.
    pub fn all(&self) -> Vec<ApiKey> {
        self.state
            .read()
            .map(|g| g.keys.values().cloned().collect())
            .unwrap_or_default()
    }
    /// Active keys for a tenant.
    pub fn active_for_tenant(&self, tenant: &str, now: OffsetDateTime) -> Vec<ApiKey> {
        self.all()
            .into_iter()
            .filter(|k| k.tenant_id == tenant && k.is_active(now))
            .collect()
    }
    /// All for a tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<ApiKey> {
        self.all().into_iter().filter(|k| k.tenant_id == tenant).collect()
    }
    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.keys.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    #[test]
    fn issue_returns_plaintext() {
        let r = ApiKeyRegistry::new();
        let k = r
            .issue("FAB", "prod-key", KeyScope::SealWrite, "ops", None)
            .unwrap();
        assert!(k.plaintext.starts_with("ak_"));
        assert!(!k.plaintext.is_empty());
    }

    #[test]
    fn key_hash_matches_plaintext() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        assert_eq!(k.key.key_hash, Hasher::sha256(k.plaintext.as_bytes()));
    }

    #[test]
    fn display_prefix_recorded() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        assert!(k.key.display_prefix.starts_with("ak_"));
        assert_eq!(k.key.display_prefix.len(), 11);
    }

    #[test]
    fn verify_succeeds_for_active() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        assert!(r.verify(&k.plaintext, now()).is_some());
    }

    #[test]
    fn verify_fails_for_unknown() {
        let r = ApiKeyRegistry::new();
        assert!(r.verify("ak_unknown", now()).is_none());
    }

    #[test]
    fn revoked_key_does_not_verify() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        r.revoke(&k.key.key_id, "ops").unwrap();
        assert!(r.verify(&k.plaintext, now()).is_none());
    }

    #[test]
    fn expired_key_does_not_verify() {
        let r = ApiKeyRegistry::new();
        let exp = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", Some(exp)).unwrap();
        assert!(r.verify(&k.plaintext, now()).is_none());
    }

    #[test]
    fn touch_updates_last_used() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        r.touch(&k.key.key_id).unwrap();
        assert!(r.get(&k.key.key_id).unwrap().last_used_at.is_some());
    }

    #[test]
    fn rotate_creates_new_key() {
        let r = ApiKeyRegistry::new();
        let original = r
            .issue("FAB", "prod", KeyScope::SealWrite, "ops", None)
            .unwrap();
        let new_k = r.rotate(&original.key.key_id, "ops").unwrap();
        assert_ne!(original.key.key_id, new_k.key.key_id);
        // Original should be revoked.
        assert_eq!(
            r.get(&original.key.key_id).unwrap().status,
            KeyStatus::Revoked
        );
        // New is active.
        assert!(new_k.key.is_active(now()));
    }

    #[test]
    fn rotate_unknown_errors() {
        let r = ApiKeyRegistry::new();
        assert!(r.rotate("ghost", "ops").is_err());
    }

    #[test]
    fn revoke_unknown_errors() {
        let r = ApiKeyRegistry::new();
        assert!(r.revoke("ghost", "ops").is_err());
    }

    #[test]
    fn active_for_tenant_filters() {
        let r = ApiKeyRegistry::new();
        let a = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        r.issue("ENBD", "y", KeyScope::ReadOnly, "ops", None).unwrap();
        r.revoke(&a.key.key_id, "ops").unwrap();
        let fab = r.active_for_tenant("FAB", now());
        assert!(fab.is_empty()); // only one issued and revoked
    }

    #[test]
    fn for_tenant_includes_revoked() {
        let r = ApiKeyRegistry::new();
        let a = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        r.revoke(&a.key.key_id, "ops").unwrap();
        assert_eq!(r.for_tenant("FAB").len(), 1);
    }

    #[test]
    fn key_serde() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        let j = serde_json::to_string(&k.key).unwrap();
        let p: ApiKey = serde_json::from_str(&j).unwrap();
        assert_eq!(p, k.key);
    }

    #[test]
    fn issued_key_serde() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        let j = serde_json::to_string(&k).unwrap();
        let p: IssuedKey = serde_json::from_str(&j).unwrap();
        assert_eq!(p, k);
    }

    #[test]
    fn scope_serde() {
        for s in [KeyScope::ReadOnly, KeyScope::SealWrite, KeyScope::Admin] {
            let j = serde_json::to_string(&s).unwrap();
            let p: KeyScope = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn status_serde() {
        for s in [KeyStatus::Active, KeyStatus::Revoked, KeyStatus::Expired] {
            let j = serde_json::to_string(&s).unwrap();
            let p: KeyStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn registry_count_tracks() {
        let r = ApiKeyRegistry::new();
        assert!(r.is_empty());
        r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn touch_unknown_errors() {
        let r = ApiKeyRegistry::new();
        assert!(r.touch("ghost").is_err());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = ApiKeyRegistry::new();
        assert!(r.get("ghost").is_none());
    }

    #[test]
    fn many_keys_unique_hashes() {
        let r = ApiKeyRegistry::new();
        let mut hashes = std::collections::HashSet::new();
        for _ in 0..50 {
            let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
            assert!(hashes.insert(k.key.key_hash));
        }
    }

    #[test]
    fn issued_by_recorded() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "alice", None).unwrap();
        assert_eq!(k.key.issued_by, "alice");
    }

    #[test]
    fn revoked_by_recorded() {
        let r = ApiKeyRegistry::new();
        let k = r.issue("FAB", "x", KeyScope::ReadOnly, "ops", None).unwrap();
        r.revoke(&k.key.key_id, "alice").unwrap();
        assert_eq!(r.get(&k.key.key_id).unwrap().revoked_by.as_deref(), Some("alice"));
    }
}
