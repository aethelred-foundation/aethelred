//! Encryption-at-rest inventory.
//!
//! Maps to NIST 800-53 SC-28 (protection of information at rest), PCI 3.5,
//! HIPAA §164.312(a)(2)(iv), and SOC2 CC6.1. Auditors ask "for every
//! sensitive datastore, what algorithm encrypts it, what key, and when was
//! the key last rotated?" — and they expect a complete catalog.
//!
//! This registry is that catalog. Each [`EncryptedAsset`] records:
//!
//! - the **datastore identifier** ("postgres-prod-billing", "s3://logs"),
//! - the **encryption algorithm** (AES-256-GCM, ChaCha20-Poly1305, ...),
//! - the **key reference** (KMS key id, HSM slot, BYOK alias),
//! - the **rotation policy** (max key age days),
//! - the **rotation history** (with timestamps).
//!
//! It is **metadata-only** — the registry never holds key material. For
//! the lifecycle of the key bytes themselves see [`crate::bring_your_own_key`]
//! and [`crate::secrets_rotation`].

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// EncryptionAlgorithm
// =============================================================================

/// Symmetric encryption algorithm for at-rest protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionAlgorithm {
    /// AES-128-GCM
    Aes128Gcm,
    /// AES-256-GCM (recommended default).
    Aes256Gcm,
    /// AES-256-CBC with HMAC-SHA-256 (legacy).
    Aes256CbcHmac,
    /// ChaCha20-Poly1305 (FIPS not-approved but constant-time on platforms
    /// without AES-NI).
    Chacha20Poly1305,
    /// XChaCha20-Poly1305 (extended nonce).
    Xchacha20Poly1305,
    /// Vendor-managed envelope encryption (e.g., AWS S3 SSE-KMS).
    VendorManaged,
}

impl EncryptionAlgorithm {
    /// True if the algorithm is FIPS 140-3 approved.
    pub fn is_fips_approved(self) -> bool {
        matches!(
            self,
            Self::Aes128Gcm | Self::Aes256Gcm | Self::Aes256CbcHmac
        )
    }

    /// True if generally considered modern / acceptable for new systems.
    pub fn is_modern(self) -> bool {
        matches!(
            self,
            Self::Aes256Gcm
                | Self::Chacha20Poly1305
                | Self::Xchacha20Poly1305
                | Self::VendorManaged
        )
    }
}

// =============================================================================
// KeyManager
// =============================================================================

/// Where the encryption key is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyManager {
    /// Cloud provider KMS (AWS KMS, GCP KMS, Azure Key Vault).
    CloudKms,
    /// Hardware Security Module.
    Hsm,
    /// Customer-supplied (BYOK).
    Byok,
    /// Application-managed (discouraged for sensitive data).
    Application,
}

// =============================================================================
// DataClass
// =============================================================================

/// Sensitivity classification of the data stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Non-sensitive / public.
    Public,
    /// Internal use only.
    Internal,
    /// PII (personal identifying information).
    Pii,
    /// PHI (protected health information — HIPAA).
    Phi,
    /// PCI cardholder data.
    Pci,
    /// Customer financial data.
    Financial,
    /// Authentication secrets (passwords / tokens).
    Secrets,
}

// =============================================================================
// RotationRecord
// =============================================================================

/// One key-rotation event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RotationRecord {
    /// RFC 3339 — when the rotation completed.
    pub at: String,
    /// Operator who triggered the rotation.
    pub actor: String,
    /// New key reference after rotation.
    pub new_key_ref: String,
    /// Optional reason / context.
    pub reason: Option<String>,
}

// =============================================================================
// EncryptedAsset
// =============================================================================

/// One catalogued encrypted datastore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedAsset {
    /// Unique id within the registry.
    pub asset_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Datastore identifier (free text, recommended URI-like).
    pub datastore: String,
    /// What the datastore stores.
    pub description: String,
    /// Owning team.
    pub owner: String,
    /// Sensitivity class.
    pub data_class: DataClass,
    /// Algorithm.
    pub algorithm: EncryptionAlgorithm,
    /// Where the key is held.
    pub key_manager: KeyManager,
    /// Reference to the key (KMS arn, HSM slot, BYOK alias).
    pub key_ref: String,
    /// Maximum acceptable key age in days; 0 = no rotation policy.
    pub key_rotation_days: u64,
    /// RFC 3339 — when the asset was registered.
    pub registered_at: String,
    /// RFC 3339 — most recent rotation, if any.
    pub last_rotated_at: Option<String>,
    /// Rotation history.
    pub history: Vec<RotationRecord>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl EncryptedAsset {
    /// Construct a new asset.
    pub fn new(
        asset_id: impl Into<String>,
        tenant_id: impl Into<String>,
        datastore: impl Into<String>,
        description: impl Into<String>,
        owner: impl Into<String>,
        data_class: DataClass,
        algorithm: EncryptionAlgorithm,
        key_manager: KeyManager,
        key_ref: impl Into<String>,
        key_rotation_days: u64,
        registered_at: impl Into<String>,
    ) -> Self {
        Self {
            asset_id: asset_id.into(),
            tenant_id: tenant_id.into(),
            datastore: datastore.into(),
            description: description.into(),
            owner: owner.into(),
            data_class,
            algorithm,
            key_manager,
            key_ref: key_ref.into(),
            key_rotation_days,
            registered_at: registered_at.into(),
            last_rotated_at: None,
            history: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Effective anchor for rotation due-date — last rotation else
    /// registration time.
    pub fn anchor(&self) -> &str {
        self.last_rotated_at.as_deref().unwrap_or(&self.registered_at)
    }

    /// True if the key is past its rotation policy at `now`.
    pub fn rotation_overdue(&self, now: &str) -> bool {
        if self.key_rotation_days == 0 {
            return false;
        }
        match age_in_days(self.anchor(), now) {
            Some(d) => d >= self.key_rotation_days as i64,
            None => false,
        }
    }

    /// True if the asset uses a modern algorithm and a non-Application key
    /// manager (i.e., would pass a routine audit at face value).
    pub fn audit_ready(&self) -> bool {
        self.algorithm.is_modern() && !matches!(self.key_manager, KeyManager::Application)
    }
}

// =============================================================================
// EncryptionInventory
// =============================================================================

/// Thread-safe registry of encrypted assets.
#[derive(Debug, Default)]
pub struct EncryptionInventory {
    inner: RwLock<HashMap<String, EncryptedAsset>>,
}

impl EncryptionInventory {
    /// New empty inventory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new asset.
    pub fn register(&self, asset: EncryptedAsset) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("encryption inventory poisoned".into()))?;
        if g.contains_key(&asset.asset_id) {
            return Err(SandboxError::Other(format!(
                "asset already registered: {}",
                asset.asset_id
            )));
        }
        g.insert(asset.asset_id.clone(), asset);
        Ok(())
    }

    /// Record a key-rotation event. Updates `last_rotated_at` and `key_ref`.
    pub fn record_rotation(
        &self,
        asset_id: &str,
        record: RotationRecord,
    ) -> SandboxResult<EncryptedAsset> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("encryption inventory poisoned".into()))?;
        let a = g
            .get_mut(asset_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown asset {asset_id}")))?;
        a.last_rotated_at = Some(record.at.clone());
        a.key_ref = record.new_key_ref.clone();
        a.history.push(record);
        Ok(a.clone())
    }

    /// Update the rotation policy.
    pub fn set_rotation_days(&self, asset_id: &str, days: u64) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("encryption inventory poisoned".into()))?;
        let a = g
            .get_mut(asset_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown asset {asset_id}")))?;
        a.key_rotation_days = days;
        Ok(())
    }

    /// Update algorithm — used during migrations from legacy to modern.
    pub fn set_algorithm(
        &self,
        asset_id: &str,
        alg: EncryptionAlgorithm,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("encryption inventory poisoned".into()))?;
        let a = g
            .get_mut(asset_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown asset {asset_id}")))?;
        a.algorithm = alg;
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, asset_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("encryption inventory poisoned".into()))?;
        let a = g
            .get_mut(asset_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown asset {asset_id}")))?;
        let tag = tag.into();
        if !a.tags.contains(&tag) {
            a.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, asset_id: &str) -> Option<EncryptedAsset> {
        let g = self.inner.read().ok()?;
        g.get(asset_id).cloned()
    }

    /// All assets.
    pub fn all(&self) -> Vec<EncryptedAsset> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Assets for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<EncryptedAsset> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Assets with a given data class.
    pub fn by_data_class(&self, class: DataClass) -> Vec<EncryptedAsset> {
        self.all()
            .into_iter()
            .filter(|a| a.data_class == class)
            .collect()
    }

    /// Assets using a given algorithm.
    pub fn by_algorithm(&self, alg: EncryptionAlgorithm) -> Vec<EncryptedAsset> {
        self.all()
            .into_iter()
            .filter(|a| a.algorithm == alg)
            .collect()
    }

    /// Assets whose key is overdue at `now`.
    pub fn rotation_overdue(&self, now: &str) -> Vec<EncryptedAsset> {
        self.all()
            .into_iter()
            .filter(|a| a.rotation_overdue(now))
            .collect()
    }

    /// Assets that would NOT pass a routine audit (legacy algorithm or
    /// application-managed key).
    pub fn audit_failures(&self) -> Vec<EncryptedAsset> {
        self.all().into_iter().filter(|a| !a.audit_ready()).collect()
    }

    /// Count.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn age_in_days(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(id: &str, alg: EncryptionAlgorithm, mgr: KeyManager, days: u64) -> EncryptedAsset {
        EncryptedAsset::new(
            id,
            "tenant-a",
            format!("ds-{id}"),
            "billing data",
            "platform",
            DataClass::Pii,
            alg,
            mgr,
            "kms://abc",
            days,
            "2025-01-01T00:00:00Z",
        )
    }

    #[test]
    fn register_and_get() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        let g = i.get("a").unwrap();
        assert_eq!(g.data_class, DataClass::Pii);
        assert!(g.history.is_empty());
    }

    #[test]
    fn duplicate_register_errors() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        let err = i
            .register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn record_rotation_updates_anchor_and_key_ref() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        i.record_rotation(
            "a",
            RotationRecord {
                at: "2025-04-01T00:00:00Z".into(),
                actor: "ops".into(),
                new_key_ref: "kms://def".into(),
                reason: None,
            },
        )
        .unwrap();
        let g = i.get("a").unwrap();
        assert_eq!(g.last_rotated_at.as_deref(), Some("2025-04-01T00:00:00Z"));
        assert_eq!(g.key_ref, "kms://def");
        assert_eq!(g.history.len(), 1);
    }

    #[test]
    fn record_rotation_unknown_errors() {
        let i = EncryptionInventory::new();
        let err = i
            .record_rotation(
                "x",
                RotationRecord {
                    at: "2025-04-01T00:00:00Z".into(),
                    actor: "ops".into(),
                    new_key_ref: "k".into(),
                    reason: None,
                },
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown asset"));
    }

    #[test]
    fn set_rotation_days() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        i.set_rotation_days("a", 30).unwrap();
        assert_eq!(i.get("a").unwrap().key_rotation_days, 30);
    }

    #[test]
    fn set_algorithm() {
        let i = EncryptionInventory::new();
        i.register(asset(
            "a",
            EncryptionAlgorithm::Aes256CbcHmac,
            KeyManager::Application,
            90,
        ))
        .unwrap();
        i.set_algorithm("a", EncryptionAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(i.get("a").unwrap().algorithm, EncryptionAlgorithm::Aes256Gcm);
    }

    #[test]
    fn add_tag_dedupes() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        i.add_tag("a", "fips").unwrap();
        i.add_tag("a", "fips").unwrap();
        i.add_tag("a", "audit-2025").unwrap();
        assert_eq!(i.get("a").unwrap().tags, vec!["fips", "audit-2025"]);
    }

    #[test]
    fn rotation_overdue_uses_registered_when_no_history() {
        let a = asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90);
        // 2025-01-01 + 90 days = 2025-04-01
        assert!(!a.rotation_overdue("2025-03-01T00:00:00Z"));
        assert!(a.rotation_overdue("2025-04-15T00:00:00Z"));
    }

    #[test]
    fn rotation_overdue_uses_last_rotated_when_present() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        i.record_rotation(
            "a",
            RotationRecord {
                at: "2025-04-01T00:00:00Z".into(),
                actor: "ops".into(),
                new_key_ref: "kms://def".into(),
                reason: None,
            },
        )
        .unwrap();
        let g = i.get("a").unwrap();
        assert!(!g.rotation_overdue("2025-06-01T00:00:00Z"));
        assert!(g.rotation_overdue("2025-08-01T00:00:00Z"));
    }

    #[test]
    fn rotation_overdue_zero_days_never_due() {
        let a = asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 0);
        assert!(!a.rotation_overdue("2030-01-01T00:00:00Z"));
    }

    #[test]
    fn rotation_overdue_query() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 30))
            .unwrap();
        i.register(asset("b", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 365))
            .unwrap();
        i.register(asset("c", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 0))
            .unwrap();
        let due = i.rotation_overdue("2025-03-01T00:00:00Z");
        let ids: Vec<_> = due.iter().map(|a| a.asset_id.clone()).collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[test]
    fn audit_ready_modern_algo_and_non_app_manager() {
        assert!(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90).audit_ready());
        assert!(asset("a", EncryptionAlgorithm::Chacha20Poly1305, KeyManager::Hsm, 90).audit_ready());
    }

    #[test]
    fn audit_failures_legacy_or_app_manager() {
        let i = EncryptionInventory::new();
        i.register(asset(
            "legacy",
            EncryptionAlgorithm::Aes256CbcHmac,
            KeyManager::CloudKms,
            90,
        ))
        .unwrap();
        i.register(asset(
            "app",
            EncryptionAlgorithm::Aes256Gcm,
            KeyManager::Application,
            90,
        ))
        .unwrap();
        i.register(asset(
            "good",
            EncryptionAlgorithm::Aes256Gcm,
            KeyManager::CloudKms,
            90,
        ))
        .unwrap();
        let fails = i.audit_failures();
        let ids: Vec<_> = fails.iter().map(|a| a.asset_id.clone()).collect();
        assert!(ids.contains(&"legacy".to_string()));
        assert!(ids.contains(&"app".to_string()));
        assert!(!ids.contains(&"good".to_string()));
    }

    #[test]
    fn for_tenant_filters() {
        let i = EncryptionInventory::new();
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        let mut other = asset("b", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90);
        other.tenant_id = "tenant-b".into();
        i.register(other).unwrap();
        assert_eq!(i.for_tenant("tenant-a").len(), 1);
        assert_eq!(i.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_data_class_and_algorithm_filters() {
        let i = EncryptionInventory::new();
        let mut a = asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90);
        a.data_class = DataClass::Phi;
        i.register(a).unwrap();
        let mut b = asset(
            "b",
            EncryptionAlgorithm::Chacha20Poly1305,
            KeyManager::Hsm,
            90,
        );
        b.data_class = DataClass::Pci;
        i.register(b).unwrap();
        assert_eq!(i.by_data_class(DataClass::Phi).len(), 1);
        assert_eq!(i.by_data_class(DataClass::Pci).len(), 1);
        assert_eq!(i.by_algorithm(EncryptionAlgorithm::Aes256Gcm).len(), 1);
        assert_eq!(i.by_algorithm(EncryptionAlgorithm::VendorManaged).len(), 0);
    }

    #[test]
    fn algorithm_helpers() {
        assert!(EncryptionAlgorithm::Aes256Gcm.is_fips_approved());
        assert!(!EncryptionAlgorithm::Chacha20Poly1305.is_fips_approved());
        assert!(EncryptionAlgorithm::Aes256Gcm.is_modern());
        assert!(!EncryptionAlgorithm::Aes256CbcHmac.is_modern());
        assert!(EncryptionAlgorithm::VendorManaged.is_modern());
    }

    #[test]
    fn count_tracks() {
        let i = EncryptionInventory::new();
        assert_eq!(i.count(), 0);
        i.register(asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90))
            .unwrap();
        assert_eq!(i.count(), 1);
    }

    #[test]
    fn asset_serde() {
        let a = asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90);
        let j = serde_json::to_string(&a).unwrap();
        let back: EncryptedAsset = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enums_serde() {
        for alg in [
            EncryptionAlgorithm::Aes128Gcm,
            EncryptionAlgorithm::Aes256Gcm,
            EncryptionAlgorithm::Aes256CbcHmac,
            EncryptionAlgorithm::Chacha20Poly1305,
            EncryptionAlgorithm::Xchacha20Poly1305,
            EncryptionAlgorithm::VendorManaged,
        ] {
            assert_eq!(
                alg,
                serde_json::from_str::<EncryptionAlgorithm>(&serde_json::to_string(&alg).unwrap())
                    .unwrap()
            );
        }
        for m in [
            KeyManager::CloudKms,
            KeyManager::Hsm,
            KeyManager::Byok,
            KeyManager::Application,
        ] {
            assert_eq!(
                m,
                serde_json::from_str::<KeyManager>(&serde_json::to_string(&m).unwrap()).unwrap()
            );
        }
        for c in [
            DataClass::Public,
            DataClass::Internal,
            DataClass::Pii,
            DataClass::Phi,
            DataClass::Pci,
            DataClass::Financial,
            DataClass::Secrets,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<DataClass>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn rotation_record_serde() {
        let r = RotationRecord {
            at: "2025-04-01T00:00:00Z".into(),
            actor: "ops".into(),
            new_key_ref: "kms://x".into(),
            reason: Some("scheduled".into()),
        };
        let j = serde_json::to_string(&r).unwrap();
        let back: RotationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn anchor_uses_registered_when_unrotated() {
        let a = asset("a", EncryptionAlgorithm::Aes256Gcm, KeyManager::CloudKms, 90);
        assert_eq!(a.anchor(), "2025-01-01T00:00:00Z");
    }
}
