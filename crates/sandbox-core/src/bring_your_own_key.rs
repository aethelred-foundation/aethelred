//! Bring-Your-Own-Key (BYOK) — customer-managed envelope encryption.
//!
//! In the BYOK model:
//!
//! - The **customer** owns the **Key Encryption Key (KEK)**, typically held
//!   in their HSM or KMS (AWS KMS / Azure Key Vault / GCP KMS / Thales /
//!   Utimaco). The KEK never leaves the customer's trust boundary.
//! - The **sandbox** holds **Data Encryption Keys (DEKs)** *wrapped* under
//!   the customer's KEK. Wrapped DEKs are useless without access to the KEK.
//! - To use a DEK, the sandbox calls the customer's KEK-holder to *unwrap*
//!   the DEK in memory; the unwrapped DEK is used and discarded.
//! - To revoke all sandbox access, the customer disables or destroys the KEK
//!   in their HSM. Every wrapped DEK becomes permanently undecryptable.
//!
//! ## Why this is required for enterprise
//!
//! - **FedRAMP / FIPS 140-3** — most agencies require keys remain in
//!   FIPS-validated customer hardware.
//! - **HIPAA / HITRUST** — covered entities frequently retain key control as
//!   a business associate agreement (BAA) condition.
//! - **Bank procurement** — HKMA, MAS, FCA all expect tenant-controlled keys.
//! - **Data residency** — KEKs in the customer's region pin DEKs to that region.
//!
//! ## Module layout
//!
//! - [`KekProvider`] — trait for any KEK backend (HSM / cloud KMS / file).
//! - [`InMemoryKek`] — local test KEK (NOT for production).
//! - [`KekRegistry`] — per-tenant KEK lookup.
//! - [`Dek`] — a 32-byte data key plus its wrapped form.
//! - [`DekManager`] — handles `wrap` / `unwrap` / `rotate`.
//! - [`KekRotation`] — record of a KEK rotation event.
//! - [`KekRevocation`] — record of a KEK destruction.
//!
//! Wrap algorithm here is intentionally simple (XOR-then-MAC-with-keyed-hash)
//! so the dep tree stays minimal. **Production deployments must swap for an
//! AEAD** (AES-256-GCM, AES-KW, or your HSM's wrap operation).

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// KekId
// =============================================================================

/// Stable identifier for a customer KEK.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KekId(pub String);

impl KekId {
    /// New id.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// KekProvider trait
// =============================================================================

/// Pluggable KEK backend. Implementations may call AWS KMS, Azure Key Vault,
/// GCP KMS, an on-prem HSM (PKCS#11), or a file-backed test impl.
pub trait KekProvider: Send + Sync {
    /// Provider name (e.g., `"aws-kms"`, `"azure-keyvault"`, `"in-memory"`).
    fn provider_name(&self) -> &str;

    /// Wrap a 32-byte DEK under the named KEK.
    fn wrap(&self, kek_id: &KekId, dek: &[u8; 32]) -> SandboxResult<Vec<u8>>;

    /// Unwrap a wrapped-DEK back to 32 bytes.
    fn unwrap(&self, kek_id: &KekId, wrapped: &[u8]) -> SandboxResult<[u8; 32]>;

    /// `true` if `kek_id` is currently usable (not destroyed/disabled).
    fn is_active(&self, kek_id: &KekId) -> bool;
}

// =============================================================================
// InMemoryKek — for tests only
// =============================================================================

#[derive(Debug, Default)]
struct InMemoryKekState {
    keks: HashMap<KekId, [u8; 32]>,
    revoked: HashMap<KekId, OffsetDateTime>,
}

/// In-memory KEK provider — TEST ONLY. Production uses a real HSM/KMS.
#[derive(Default)]
pub struct InMemoryKek {
    state: RwLock<InMemoryKekState>,
}

impl std::fmt::Debug for InMemoryKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKek").finish()
    }
}

impl InMemoryKek {
    /// New empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a new KEK from raw bytes. **Tests only.**
    pub fn provision(&self, id: KekId, bytes: [u8; 32]) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("kek lock poisoned".into()))?;
        if g.revoked.contains_key(&id) {
            return Err(SandboxError::Other(format!(
                "kek {} already revoked",
                id.as_str()
            )));
        }
        g.keks.insert(id, bytes);
        Ok(())
    }

    /// Provision a deterministic test KEK from a string seed.
    pub fn provision_from_seed(&self, id: KekId, seed: &str) -> SandboxResult<()> {
        let h = Hasher::sha256(seed.as_bytes()).0;
        self.provision(id, h)
    }

    /// Destroy a KEK. After revocation, all DEKs wrapped under it become
    /// permanently undecryptable.
    pub fn revoke(&self, id: &KekId) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("kek lock poisoned".into()))?;
        if !g.keks.contains_key(id) && !g.revoked.contains_key(id) {
            return Err(SandboxError::Other(format!(
                "kek {} not found",
                id.as_str()
            )));
        }
        g.keks.remove(id);
        g.revoked.insert(id.clone(), OffsetDateTime::now_utc());
        Ok(())
    }

    /// Number of currently-active KEKs.
    pub fn active_count(&self) -> usize {
        self.state.read().map(|g| g.keks.len()).unwrap_or(0)
    }
}

impl KekProvider for InMemoryKek {
    fn provider_name(&self) -> &str {
        "in-memory"
    }

    fn wrap(&self, kek_id: &KekId, dek: &[u8; 32]) -> SandboxResult<Vec<u8>> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("kek lock poisoned".into()))?;
        let kek = g
            .keks
            .get(kek_id)
            .ok_or_else(|| SandboxError::Other(format!("kek {} not active", kek_id.as_str())))?;
        // Wrap = XOR with kek-derived stream + MAC under keyed-hash.
        let mut out = Vec::with_capacity(32 + 32);
        let stream = derive_stream(kek);
        for i in 0..32 {
            out.push(dek[i] ^ stream[i]);
        }
        let mac = mac(kek, &out[..32]);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    fn unwrap(&self, kek_id: &KekId, wrapped: &[u8]) -> SandboxResult<[u8; 32]> {
        if wrapped.len() != 64 {
            return Err(SandboxError::Other(format!(
                "wrapped dek wrong length: expected 64 got {}",
                wrapped.len()
            )));
        }
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("kek lock poisoned".into()))?;
        let kek = g
            .keks
            .get(kek_id)
            .ok_or_else(|| SandboxError::Other(format!("kek {} not active", kek_id.as_str())))?;
        let body = &wrapped[..32];
        let tag = &wrapped[32..];
        let expected = mac(kek, body);
        // Constant-time compare.
        let mut diff: u8 = 0;
        for i in 0..32 {
            diff |= tag[i] ^ expected[i];
        }
        if diff != 0 {
            return Err(SandboxError::Other("wrapped dek MAC mismatch".into()));
        }
        let stream = derive_stream(kek);
        let mut dek = [0u8; 32];
        for i in 0..32 {
            dek[i] = body[i] ^ stream[i];
        }
        Ok(dek)
    }

    fn is_active(&self, kek_id: &KekId) -> bool {
        self.state
            .read()
            .map(|g| g.keks.contains_key(kek_id))
            .unwrap_or(false)
    }
}

fn derive_stream(kek: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 5);
    buf.extend_from_slice(kek);
    buf.extend_from_slice(b"wrap");
    buf.push(0);
    Hasher::sha256(&buf).0
}

fn mac(kek: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + data.len() + 32);
    buf.extend_from_slice(kek);
    buf.extend_from_slice(data);
    buf.extend_from_slice(kek);
    Hasher::sha256(&buf).0
}

// =============================================================================
// Dek — wrapped data key
// =============================================================================

/// Wrapped data encryption key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dek {
    /// Stable id.
    pub dek_id: Uuid,
    /// KEK that wrapped this DEK.
    pub kek_id: KekId,
    /// Wrapped (encrypted-under-KEK) bytes — hex-encoded.
    pub wrapped_hex: String,
    /// RFC 3339 wrap time.
    pub created_at: String,
    /// Hash of the (unwrapped) DEK — used as a stable fingerprint without
    /// exposing the key.
    pub dek_fingerprint: Sha256Digest,
}

// =============================================================================
// KekRotation — operator-action record
// =============================================================================

/// Record of a KEK rotation event for audit trails.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KekRotation {
    /// Rotation id.
    pub rotation_id: Uuid,
    /// Tenant whose KEK was rotated.
    pub tenant_id: String,
    /// Old KEK id.
    pub old_kek: KekId,
    /// New KEK id.
    pub new_kek: KekId,
    /// RFC 3339 timestamp.
    pub at: String,
    /// Number of DEKs re-wrapped under the new KEK.
    pub deks_rewrapped: u64,
}

// =============================================================================
// KekRegistry — per-tenant KEK assignment
// =============================================================================

/// Maps `tenant_id` → currently-active [`KekId`].
#[derive(Default)]
pub struct KekRegistry {
    inner: RwLock<HashMap<String, KekId>>,
}

impl std::fmt::Debug for KekRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KekRegistry")
            .field("tenants", &self.inner.read().map(|g| g.len()).unwrap_or(0))
            .finish()
    }
}

impl KekRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign a KEK to a tenant.
    pub fn assign(&self, tenant: impl Into<String>, kek: KekId) -> SandboxResult<()> {
        self.inner
            .write()
            .map_err(|_| SandboxError::Other("kek registry poisoned".into()))?
            .insert(tenant.into(), kek);
        Ok(())
    }

    /// Look up a tenant's KEK.
    pub fn get(&self, tenant: &str) -> Option<KekId> {
        self.inner.read().ok()?.get(tenant).cloned()
    }

    /// Number of tenants registered.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no tenants registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// DekManager
// =============================================================================

/// Owns DEK lifecycle: generate → wrap → unwrap → rotate.
pub struct DekManager<'a, P: KekProvider + ?Sized> {
    provider: &'a P,
}

impl<'a, P: KekProvider + ?Sized> DekManager<'a, P> {
    /// New manager bound to a KEK provider.
    pub fn new(provider: &'a P) -> Self {
        Self { provider }
    }

    /// Generate a fresh 32-byte DEK and wrap it under `kek_id`.
    pub fn generate(&self, kek_id: KekId, seed_bytes: &[u8]) -> SandboxResult<(Dek, [u8; 32])> {
        // Deterministic-from-seed for tests; production uses an HSM RNG.
        let mut buf = Vec::with_capacity(seed_bytes.len() + 8);
        buf.extend_from_slice(seed_bytes);
        buf.extend_from_slice(
            OffsetDateTime::now_utc()
                .unix_timestamp_nanos()
                .to_le_bytes()
                .as_ref(),
        );
        let mut dek = [0u8; 32];
        let h = Hasher::sha256(&buf).0;
        dek.copy_from_slice(&h);
        let wrapped = self.provider.wrap(&kek_id, &dek)?;
        let dek_obj = Dek {
            dek_id: Uuid::now_v7(),
            kek_id,
            wrapped_hex: hex::encode(&wrapped),
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            dek_fingerprint: Hasher::sha256(&dek),
        };
        Ok((dek_obj, dek))
    }

    /// Unwrap a [`Dek`].
    pub fn unwrap(&self, dek: &Dek) -> SandboxResult<[u8; 32]> {
        let wrapped = hex::decode(&dek.wrapped_hex)
            .map_err(|e| SandboxError::Other(format!("wrapped hex decode: {e}")))?;
        let bytes = self.provider.unwrap(&dek.kek_id, &wrapped)?;
        // Verify fingerprint hasn't changed.
        if Hasher::sha256(&bytes) != dek.dek_fingerprint {
            return Err(SandboxError::Other(
                "unwrapped dek fingerprint mismatch — corrupted wrapped key".into(),
            ));
        }
        Ok(bytes)
    }

    /// Re-wrap a [`Dek`] under a new KEK (KEK rotation).
    /// Customer must keep both KEKs available during the migration window.
    pub fn rewrap(&self, dek: &Dek, new_kek: KekId) -> SandboxResult<Dek> {
        let bytes = self.unwrap(dek)?;
        let wrapped = self.provider.wrap(&new_kek, &bytes)?;
        Ok(Dek {
            dek_id: dek.dek_id,
            kek_id: new_kek,
            wrapped_hex: hex::encode(&wrapped),
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            dek_fingerprint: dek.dek_fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_with_two_keks() -> InMemoryKek {
        let p = InMemoryKek::new();
        p.provision_from_seed(KekId::new("kek-A"), "seed-A").unwrap();
        p.provision_from_seed(KekId::new("kek-B"), "seed-B").unwrap();
        p
    }

    #[test]
    fn provider_name_is_in_memory() {
        let p = InMemoryKek::new();
        assert_eq!(p.provider_name(), "in-memory");
    }

    #[test]
    fn provision_then_active_count() {
        let p = InMemoryKek::new();
        assert_eq!(p.active_count(), 0);
        p.provision_from_seed(KekId::new("k1"), "s1").unwrap();
        assert_eq!(p.active_count(), 1);
    }

    #[test]
    fn wrap_unwrap_round_trips() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (dek_obj, raw) = mgr.generate(KekId::new("kek-A"), b"unit-test").unwrap();
        let unwrapped = mgr.unwrap(&dek_obj).unwrap();
        assert_eq!(unwrapped, raw);
    }

    #[test]
    fn unwrap_fails_after_revoke() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (dek_obj, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        p.revoke(&KekId::new("kek-A")).unwrap();
        assert!(mgr.unwrap(&dek_obj).is_err());
    }

    #[test]
    fn rewrap_under_new_kek_succeeds() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (dek_a, raw_a) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        let dek_b = mgr.rewrap(&dek_a, KekId::new("kek-B")).unwrap();
        let raw_b = mgr.unwrap(&dek_b).unwrap();
        assert_eq!(raw_a, raw_b);
        assert_eq!(dek_a.dek_fingerprint, dek_b.dek_fingerprint);
        assert_ne!(dek_a.wrapped_hex, dek_b.wrapped_hex);
    }

    #[test]
    fn unwrap_unknown_kek_errors() {
        let p = InMemoryKek::new();
        p.provision_from_seed(KekId::new("k"), "s").unwrap();
        let mgr = DekManager::new(&p);
        let (mut dek, _) = mgr.generate(KekId::new("k"), b"x").unwrap();
        dek.kek_id = KekId::new("missing");
        assert!(mgr.unwrap(&dek).is_err());
    }

    #[test]
    fn unwrap_tampered_wrapped_errors() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (mut dek, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        // Flip a byte in the wrapped hex.
        let mut bytes = hex::decode(&dek.wrapped_hex).unwrap();
        bytes[0] ^= 0xFF;
        dek.wrapped_hex = hex::encode(&bytes);
        let err = mgr.unwrap(&dek).expect_err("MAC must reject");
        assert!(format!("{err}").contains("MAC") || format!("{err}").contains("fingerprint"));
    }

    #[test]
    fn wrong_kek_unwrap_fails() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (mut dek, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        // Try unwrapping with kek-B.
        dek.kek_id = KekId::new("kek-B");
        assert!(mgr.unwrap(&dek).is_err());
    }

    #[test]
    fn revoke_marks_kek_inactive() {
        let p = provider_with_two_keks();
        assert!(p.is_active(&KekId::new("kek-A")));
        p.revoke(&KekId::new("kek-A")).unwrap();
        assert!(!p.is_active(&KekId::new("kek-A")));
    }

    #[test]
    fn revoke_unknown_errors() {
        let p = InMemoryKek::new();
        assert!(p.revoke(&KekId::new("ghost")).is_err());
    }

    #[test]
    fn provision_after_revoke_errors() {
        let p = InMemoryKek::new();
        p.provision_from_seed(KekId::new("k"), "s").unwrap();
        p.revoke(&KekId::new("k")).unwrap();
        assert!(p.provision_from_seed(KekId::new("k"), "s2").is_err());
    }

    #[test]
    fn registry_assign_and_get() {
        let r = KekRegistry::new();
        r.assign("FAB", KekId::new("kek-A")).unwrap();
        assert_eq!(r.get("FAB"), Some(KekId::new("kek-A")));
        assert!(r.get("ENBD").is_none());
    }

    #[test]
    fn registry_len_and_empty() {
        let r = KekRegistry::new();
        assert!(r.is_empty());
        r.assign("FAB", KekId::new("k")).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn registry_rebind_overrides() {
        let r = KekRegistry::new();
        r.assign("FAB", KekId::new("k1")).unwrap();
        r.assign("FAB", KekId::new("k2")).unwrap();
        assert_eq!(r.get("FAB"), Some(KekId::new("k2")));
    }

    #[test]
    fn dek_serde_round_trip() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (dek, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        let j = serde_json::to_string(&dek).unwrap();
        let p: Dek = serde_json::from_str(&j).unwrap();
        assert_eq!(p, dek);
    }

    #[test]
    fn kek_id_serde_transparent() {
        let id = KekId::new("k1");
        let j = serde_json::to_string(&id).unwrap();
        assert_eq!(j, "\"k1\"");
        let p: KekId = serde_json::from_str(&j).unwrap();
        assert_eq!(p, id);
    }

    #[test]
    fn kek_rotation_serde_round_trip() {
        let r = KekRotation {
            rotation_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            old_kek: KekId::new("a"),
            new_kek: KekId::new("b"),
            at: "2026-01-01T00:00:00Z".into(),
            deks_rewrapped: 7,
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: KekRotation = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn many_deks_under_one_kek_all_unwrap() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let mut pairs = Vec::new();
        for i in 0..10 {
            let seed = format!("dek-{i}");
            pairs.push(mgr.generate(KekId::new("kek-A"), seed.as_bytes()).unwrap());
        }
        for (dek, raw) in &pairs {
            assert_eq!(&mgr.unwrap(dek).unwrap(), raw);
        }
    }

    #[test]
    fn kek_rotation_rewraps_many_deks() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let mut deks = Vec::new();
        for i in 0..5 {
            let s = format!("d{i}");
            let (d, _) = mgr.generate(KekId::new("kek-A"), s.as_bytes()).unwrap();
            deks.push(d);
        }
        let mut rewrapped = Vec::new();
        for d in &deks {
            rewrapped.push(mgr.rewrap(d, KekId::new("kek-B")).unwrap());
        }
        // Both should still unwrap.
        for d in &rewrapped {
            assert!(mgr.unwrap(d).is_ok());
        }
    }

    #[test]
    fn revocation_invalidates_all_deks_under_kek() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (d1, _) = mgr.generate(KekId::new("kek-A"), b"1").unwrap();
        let (d2, _) = mgr.generate(KekId::new("kek-A"), b"2").unwrap();
        p.revoke(&KekId::new("kek-A")).unwrap();
        assert!(mgr.unwrap(&d1).is_err());
        assert!(mgr.unwrap(&d2).is_err());
    }

    #[test]
    fn dek_fingerprint_stable_across_rewrap() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (d1, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        let d2 = mgr.rewrap(&d1, KekId::new("kek-B")).unwrap();
        assert_eq!(d1.dek_fingerprint, d2.dek_fingerprint);
    }

    #[test]
    fn dek_id_stable_across_rewrap() {
        let p = provider_with_two_keks();
        let mgr = DekManager::new(&p);
        let (d1, _) = mgr.generate(KekId::new("kek-A"), b"x").unwrap();
        let d2 = mgr.rewrap(&d1, KekId::new("kek-B")).unwrap();
        assert_eq!(d1.dek_id, d2.dek_id);
    }

    #[test]
    fn unwrap_wrong_length_errors() {
        let p = InMemoryKek::new();
        p.provision_from_seed(KekId::new("k"), "s").unwrap();
        assert!(p.unwrap(&KekId::new("k"), &[0u8; 10]).is_err());
    }
}
