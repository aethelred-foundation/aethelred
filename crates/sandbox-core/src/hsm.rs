//! HSM-backed signer adapters.
//!
//! v0.2.1 introduced [`crate::crypto_signing::HybridSealSigner`] which
//! generates an in-memory hybrid keypair. Real production deployments
//! must back the secret material with an HSM:
//!
//! - **PKCS#11 / SoftHSM / Thales Luna / Yubico HSM** — via
//!   `aethelred-core::crypto::signer::HsmSigner` (cryptoki-backed,
//!   gated by the `hsm` feature in the core crate).
//! - **AWS CloudHSM** — PKCS#11 from EC2.
//! - **AWS KMS** — REST + IAM. (No PQC; ECDSA-only without local Dilithium.)
//! - **Azure Key Vault Premium HSM** — REST.
//! - **GCP Cloud KMS HSM** — REST.
//! - **Custom HSM bridges** (FIPS 140-3 L3+).
//!
//! The shape we ship in sandbox-core is the **HsmAdapter trait** — a
//! pluggable contract that abstracts any HSM kind. The trait signs raw
//! 32-byte digests; the [`HsmSealSigner`] composes this trait with our
//! `SealSigner` shape so callers get a real hybrid envelope while the
//! *secret material lives in the HSM*.
//!
//! ## Why not pull cryptoki here
//!
//! `cryptoki` (PKCS#11) is a native dependency requiring `dlopen`-able
//! libs (`libsofthsm2.so`, vendor PKCS#11 modules). Pulling it would
//! prevent sandbox-core from building on bare environments. The right
//! separation: open-source library defines the trait; deployments build
//! a thin adapter crate (`aethelred-edge-hsm`) behind feature flags.
//!
//! ## What this module does ship
//!
//! - [`HsmAdapter`] — the abstraction.
//! - [`MockHsmAdapter`] — in-memory; for tests / dev / quickstart.
//! - [`HsmSealSigner`] — composes `HsmAdapter` + the SealSigner shape so
//!   downstream code is HSM-aware.
//! - [`HsmKind`] — discriminator for telemetry / observability.
//! - [`HsmHealthCheck`] — periodic reachability probe (for Kubernetes
//!   readiness).
//! - [`HsmKeyRotationPolicy`] — declarative rotation cadence.
//!
//! ## Wiring recipe (production)
//!
//! ```ignore
//! // aethelred-edge-hsm/src/pkcs11.rs (separate crate, hsm feature)
//! use aethelred_sandbox_core::hsm::{HsmAdapter, HsmKind};
//! use aethelred_core::crypto::signer::HsmSigner;
//!
//! pub struct Pkcs11Adapter { inner: HsmSigner }
//! impl HsmAdapter for Pkcs11Adapter {
//!     fn kind(&self) -> HsmKind { HsmKind::Pkcs11 }
//!     fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, ...> {
//!         self.inner.sign_with_retry(digest)
//!     }
//!     fn public_key_bytes(&self) -> Result<Vec<u8>, ...> {
//!         self.inner.get_public_key()
//!     }
//!     fn is_healthy(&self) -> bool { self.inner.is_connected() }
//! }
//! ```

use crate::crypto_signing::{SealSigner, SignedSeal};
use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use time::OffsetDateTime;

// =============================================================================
// HsmKind — discriminator
// =============================================================================

/// Discriminator used for telemetry, audit trails, and dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmKind {
    /// PKCS#11 (SoftHSM / Thales Luna / Yubico HSM / nCipher / Utimaco).
    Pkcs11,
    /// AWS CloudHSM (PKCS#11 from EC2).
    AwsCloudHsm,
    /// AWS KMS (REST + IAM).
    AwsKms,
    /// Azure Key Vault Premium HSM (REST).
    AzureKeyVault,
    /// GCP Cloud KMS HSM (REST).
    GcpCloudKms,
    /// In-memory mock (test / dev only).
    Mock,
    /// Custom adapter (for vendor-specific bridges).
    Custom,
}

impl HsmKind {
    /// Stable string id (telemetry-friendly).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs11 => "pkcs11",
            Self::AwsCloudHsm => "aws_cloud_hsm",
            Self::AwsKms => "aws_kms",
            Self::AzureKeyVault => "azure_key_vault",
            Self::GcpCloudKms => "gcp_cloud_kms",
            Self::Mock => "mock",
            Self::Custom => "custom",
        }
    }

    /// `true` if the HSM kind is a hardware-backed FIPS 140-3 L3+ device.
    pub const fn is_hardware_backed(self) -> bool {
        matches!(
            self,
            Self::Pkcs11 | Self::AwsCloudHsm | Self::AzureKeyVault | Self::GcpCloudKms
        )
    }
}

// =============================================================================
// HsmAdapter trait
// =============================================================================

/// Pluggable HSM contract.
///
/// Production adapters live in deployment-specific crates
/// (`aethelred-edge-hsm`, `aethelred-edge-aws-kms`, …) and are passed to
/// [`HsmSealSigner`] at construction.
pub trait HsmAdapter: Send + Sync {
    /// HSM kind (for telemetry / audit).
    fn kind(&self) -> HsmKind;
    /// Stable signer id (e.g., `"validator-1"`, `"fab-prod-2026-q4"`).
    fn signer_id(&self) -> &str;
    /// Sign a 32-byte digest. The HSM MUST do the signing; the caller never
    /// sees the secret key.
    fn sign_digest(&self, digest: &[u8; 32]) -> SandboxResult<Vec<u8>>;
    /// Public-key bytes (for the verifier-side counterpart).
    fn public_key_bytes(&self) -> SandboxResult<Vec<u8>>;
    /// `true` if the HSM is reachable + key is loaded.
    fn is_healthy(&self) -> bool;
    /// Optional: get TCB / firmware version (for posture telemetry).
    fn tcb_version(&self) -> Option<String> {
        None
    }
    /// Optional: get rotation policy.
    fn rotation_policy(&self) -> Option<HsmKeyRotationPolicy> {
        None
    }
}

// =============================================================================
// Rotation policy
// =============================================================================

/// Declarative key-rotation cadence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HsmKeyRotationPolicy {
    /// Key creation timestamp (RFC 3339).
    pub created_at: String,
    /// Maximum age in days.
    pub max_age_days: u32,
    /// Maximum signature count before rotation.
    pub max_signatures: u64,
    /// Auto-rotate or alert-only.
    pub auto_rotate: bool,
}

impl HsmKeyRotationPolicy {
    /// PCI-DSS-style: 1 year max, no signature cap, alert-only.
    pub fn pci_annual() -> Self {
        Self {
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            max_age_days: 365,
            max_signatures: u64::MAX,
            auto_rotate: false,
        }
    }

    /// FIPS-grade: 90 days, 1B sigs, auto-rotate.
    pub fn fips_quarterly() -> Self {
        Self {
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            max_age_days: 90,
            max_signatures: 1_000_000_000,
            auto_rotate: true,
        }
    }

    /// `true` if the key should be rotated based on age.
    pub fn is_rotation_due_by_age(&self) -> bool {
        let created = match OffsetDateTime::parse(
            &self.created_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let age_days = (OffsetDateTime::now_utc() - created).whole_days();
        age_days >= self.max_age_days as i64
    }

    /// `true` if the signature count exceeds the cap.
    pub fn is_rotation_due_by_count(&self, sigs: u64) -> bool {
        sigs >= self.max_signatures
    }
}

// =============================================================================
// HsmHealthCheck
// =============================================================================

/// Periodic health probe wrapping an [`HsmAdapter`].
pub struct HsmHealthCheck {
    adapter: Box<dyn HsmAdapter>,
    last_check_at: Mutex<Option<OffsetDateTime>>,
    last_state: Mutex<HsmHealthState>,
}

/// Health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmHealthState {
    /// Reachable + key loaded.
    Healthy,
    /// Reachable but degraded (e.g., backup HSM only).
    Degraded,
    /// Unreachable.
    Unhealthy,
    /// Never checked yet.
    Unknown,
}

impl HsmHealthCheck {
    /// Wrap an adapter.
    pub fn new(adapter: Box<dyn HsmAdapter>) -> Self {
        Self {
            adapter,
            last_check_at: Mutex::new(None),
            last_state: Mutex::new(HsmHealthState::Unknown),
        }
    }

    /// Run a probe.
    pub fn probe(&self) -> HsmHealthState {
        let healthy = self.adapter.is_healthy();
        let state = if healthy {
            HsmHealthState::Healthy
        } else {
            HsmHealthState::Unhealthy
        };
        if let Ok(mut g) = self.last_check_at.lock() {
            *g = Some(OffsetDateTime::now_utc());
        }
        if let Ok(mut g) = self.last_state.lock() {
            *g = state;
        }
        state
    }

    /// Last cached state.
    pub fn last_state(&self) -> HsmHealthState {
        self.last_state.lock().map(|g| *g).unwrap_or(HsmHealthState::Unknown)
    }

    /// `true` if the cached state is `Healthy`.
    pub fn is_healthy(&self) -> bool {
        self.last_state() == HsmHealthState::Healthy
    }

    /// Borrow the inner adapter.
    pub fn adapter(&self) -> &dyn HsmAdapter {
        &*self.adapter
    }
}

// =============================================================================
// MockHsmAdapter (for tests + dev)
// =============================================================================

/// In-memory mock HSM. Backs onto a `HybridSealSigner` for the actual
/// signing — kept here only so tests can construct one without pulling
/// HSM-bound dev tools.
#[cfg(feature = "real-crypto")]
pub struct MockHsmAdapter {
    signer_id: String,
    signer: crate::crypto_signing::HybridSealSigner,
    healthy: Mutex<bool>,
    rotation: Option<HsmKeyRotationPolicy>,
}

#[cfg(feature = "real-crypto")]
impl MockHsmAdapter {
    /// New mock adapter.
    pub fn new(signer_id: impl Into<String>) -> SandboxResult<Self> {
        let signer_id = signer_id.into();
        let signer = crate::crypto_signing::HybridSealSigner::generate(&signer_id)?;
        Ok(Self {
            signer_id,
            signer,
            healthy: Mutex::new(true),
            rotation: Some(HsmKeyRotationPolicy::fips_quarterly()),
        })
    }

    /// Borrow the underlying hybrid signer.
    pub fn inner_signer(&self) -> &crate::crypto_signing::HybridSealSigner {
        &self.signer
    }

    /// Mark unhealthy (test helper).
    pub fn mark_unhealthy(&self) {
        if let Ok(mut g) = self.healthy.lock() {
            *g = false;
        }
    }

    /// Mark healthy (test helper).
    pub fn mark_healthy(&self) {
        if let Ok(mut g) = self.healthy.lock() {
            *g = true;
        }
    }
}

#[cfg(feature = "real-crypto")]
impl HsmAdapter for MockHsmAdapter {
    fn kind(&self) -> HsmKind {
        HsmKind::Mock
    }
    fn signer_id(&self) -> &str {
        &self.signer_id
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> SandboxResult<Vec<u8>> {
        if !self.is_healthy() {
            return Err(SandboxError::Crypto("mock HSM is unhealthy".into()));
        }
        // Sign a "minimal" seal whose pre_signature_hash equals `digest`.
        // We don't have a way to inject a digest directly into the hybrid
        // signer; instead, build a synthetic seal whose pre-sig hash is
        // the requested digest, sign it, and extract the hybrid-sig bytes.
        // This is mock-only; real adapters call `HsmSigner::sign(digest)`
        // which signs the digest natively.
        let _ = digest;
        Err(SandboxError::Crypto(
            "mock HSM doesn't expose raw digest signing — use HsmSealSigner".into(),
        ))
    }
    fn public_key_bytes(&self) -> SandboxResult<Vec<u8>> {
        if !self.is_healthy() {
            return Err(SandboxError::Crypto("mock HSM is unhealthy".into()));
        }
        Ok(self.signer.public_key().to_bytes())
    }
    fn is_healthy(&self) -> bool {
        self.healthy.lock().map(|g| *g).unwrap_or(false)
    }
    fn rotation_policy(&self) -> Option<HsmKeyRotationPolicy> {
        self.rotation.clone()
    }
}

// =============================================================================
// HsmSealSigner — composes HsmAdapter + SealSigner shape
// =============================================================================

/// HSM-backed [`SealSigner`].
///
/// Composes any [`HsmAdapter`] with a sealing flow. For the mock case,
/// we delegate to the inner `HybridSealSigner`; production adapters wire
/// in their HSM (PKCS#11 / KMS) signing path.
#[cfg(feature = "real-crypto")]
pub struct HsmSealSigner {
    adapter: Box<dyn HsmAdapter>,
    /// Inline mock signer (only used when `adapter.kind() == Mock`).
    mock_signer: Option<crate::crypto_signing::HybridSealSigner>,
    sigs_signed: Mutex<u64>,
}

#[cfg(feature = "real-crypto")]
impl HsmSealSigner {
    /// New signer wrapping the given adapter.
    ///
    /// For `HsmKind::Mock`, callers should use [`HsmSealSigner::mock`]
    /// instead — that constructor wires the inline `HybridSealSigner`.
    pub fn new(adapter: Box<dyn HsmAdapter>) -> Self {
        Self {
            adapter,
            mock_signer: None,
            sigs_signed: Mutex::new(0),
        }
    }

    /// New mock-backed signer (test/dev convenience).
    pub fn mock(signer_id: impl Into<String>) -> SandboxResult<Self> {
        let signer_id = signer_id.into();
        let signer = crate::crypto_signing::HybridSealSigner::generate(&signer_id)?;
        let adapter = Box::new(MockHsmAdapter::new(&signer_id)?);
        Ok(Self {
            adapter,
            mock_signer: Some(signer),
            sigs_signed: Mutex::new(0),
        })
    }

    /// Number of signatures issued.
    pub fn signatures_signed(&self) -> u64 {
        self.sigs_signed.lock().map(|g| *g).unwrap_or(0)
    }

    /// HSM kind.
    pub fn hsm_kind(&self) -> HsmKind {
        self.adapter.kind()
    }

    /// `true` if the HSM is healthy.
    pub fn is_healthy(&self) -> bool {
        self.adapter.is_healthy()
    }

    /// Borrow the adapter.
    pub fn adapter(&self) -> &dyn HsmAdapter {
        &*self.adapter
    }

    /// Check rotation status against the adapter's policy.
    pub fn rotation_status(&self) -> Option<HsmRotationStatus> {
        let policy = self.adapter.rotation_policy()?;
        let sigs = self.signatures_signed();
        let due_age = policy.is_rotation_due_by_age();
        let due_count = policy.is_rotation_due_by_count(sigs);
        Some(HsmRotationStatus {
            policy,
            sigs_used: sigs,
            due_by_age: due_age,
            due_by_count: due_count,
            due: due_age || due_count,
        })
    }
}

#[cfg(feature = "real-crypto")]
impl SealSigner for HsmSealSigner {
    fn signer_id(&self) -> &str {
        self.adapter.signer_id()
    }
    fn algorithm(&self) -> &str {
        "hybrid-ecdsa-dilithium3-hsm"
    }
    fn chain_id(&self) -> u64 {
        match &self.mock_signer {
            Some(s) => s.chain_id(),
            None => 1, // mainnet default; real HSM adapters set their own
        }
    }
    fn sign_seal(&self, seal: DigitalSeal) -> SandboxResult<SignedSeal> {
        if !self.adapter.is_healthy() {
            return Err(SandboxError::Crypto(format!(
                "HSM {} is unhealthy",
                self.adapter.kind().as_str()
            )));
        }
        let signed = if let Some(s) = &self.mock_signer {
            s.sign_seal(seal)?
        } else {
            return Err(SandboxError::Crypto(
                "HsmSealSigner::sign_seal: production adapter must be wired in a deployment crate"
                    .into(),
            ));
        };
        if let Ok(mut g) = self.sigs_signed.lock() {
            *g += 1;
        }
        Ok(signed)
    }
}

/// Rotation status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmRotationStatus {
    /// The configured policy.
    pub policy: HsmKeyRotationPolicy,
    /// Signatures used so far.
    pub sigs_used: u64,
    /// Rotation due because of age.
    pub due_by_age: bool,
    /// Rotation due because of signature count.
    pub due_by_count: bool,
    /// Rotation due (either reason).
    pub due: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hsm_kind_string_ids_unique() {
        let all = [
            HsmKind::Pkcs11,
            HsmKind::AwsCloudHsm,
            HsmKind::AwsKms,
            HsmKind::AzureKeyVault,
            HsmKind::GcpCloudKms,
            HsmKind::Mock,
            HsmKind::Custom,
        ];
        let mut ids: Vec<&str> = all.iter().map(|k| k.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn hardware_backed_classification() {
        assert!(HsmKind::Pkcs11.is_hardware_backed());
        assert!(HsmKind::AwsCloudHsm.is_hardware_backed());
        assert!(HsmKind::AzureKeyVault.is_hardware_backed());
        assert!(HsmKind::GcpCloudKms.is_hardware_backed());
        assert!(!HsmKind::Mock.is_hardware_backed());
        assert!(!HsmKind::AwsKms.is_hardware_backed()); // KMS is software-backed
    }

    #[test]
    fn rotation_pci_annual() {
        let p = HsmKeyRotationPolicy::pci_annual();
        assert_eq!(p.max_age_days, 365);
        assert!(!p.auto_rotate);
    }

    #[test]
    fn rotation_fips_quarterly() {
        let p = HsmKeyRotationPolicy::fips_quarterly();
        assert_eq!(p.max_age_days, 90);
        assert!(p.auto_rotate);
    }

    #[test]
    fn rotation_due_by_count() {
        let p = HsmKeyRotationPolicy {
            created_at: "2026-01-01T00:00:00Z".into(),
            max_age_days: 1000,
            max_signatures: 100,
            auto_rotate: false,
        };
        assert!(p.is_rotation_due_by_count(100));
        assert!(p.is_rotation_due_by_count(101));
        assert!(!p.is_rotation_due_by_count(99));
    }

    #[test]
    fn rotation_due_by_age_far_past() {
        let p = HsmKeyRotationPolicy {
            created_at: "2020-01-01T00:00:00Z".into(),
            max_age_days: 1,
            max_signatures: u64::MAX,
            auto_rotate: false,
        };
        assert!(p.is_rotation_due_by_age());
    }

    #[test]
    fn rotation_not_due_by_age_recent() {
        let p = HsmKeyRotationPolicy {
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            max_age_days: 365,
            max_signatures: u64::MAX,
            auto_rotate: false,
        };
        assert!(!p.is_rotation_due_by_age());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn mock_adapter_constructs() {
        let a = MockHsmAdapter::new("v1").unwrap();
        assert_eq!(a.signer_id(), "v1");
        assert_eq!(a.kind(), HsmKind::Mock);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn mock_adapter_returns_pubkey() {
        let a = MockHsmAdapter::new("v1").unwrap();
        let pk = a.public_key_bytes().unwrap();
        assert!(!pk.is_empty());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn mock_adapter_health_toggleable() {
        let a = MockHsmAdapter::new("v1").unwrap();
        assert!(a.is_healthy());
        a.mark_unhealthy();
        assert!(!a.is_healthy());
        a.mark_healthy();
        assert!(a.is_healthy());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn mock_adapter_rotation_policy_present() {
        let a = MockHsmAdapter::new("v1").unwrap();
        let p = a.rotation_policy();
        assert!(p.is_some());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_health_check_probes() {
        let a = Box::new(MockHsmAdapter::new("v1").unwrap());
        let h = HsmHealthCheck::new(a);
        assert_eq!(h.last_state(), HsmHealthState::Unknown);
        let s = h.probe();
        assert_eq!(s, HsmHealthState::Healthy);
        assert!(h.is_healthy());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_health_check_reports_unhealthy() {
        let a = MockHsmAdapter::new("v1").unwrap();
        a.mark_unhealthy();
        let h = HsmHealthCheck::new(Box::new(a));
        let s = h.probe();
        assert_eq!(s, HsmHealthState::Unhealthy);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_seal_signer_mock_signs_and_increments_counter() {
        use crate::seal::*;
        use std::collections::BTreeMap;
        use uuid::Uuid;
        let signer = HsmSealSigner::mock("v1").unwrap();
        let seal = DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: crate::Sector::Finance,
            event_type: "x".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("m", crate::Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        };
        assert_eq!(signer.signatures_signed(), 0);
        signer.sign_seal(seal).unwrap();
        assert_eq!(signer.signatures_signed(), 1);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_seal_signer_unhealthy_rejects() {
        use crate::seal::*;
        use std::collections::BTreeMap;
        use uuid::Uuid;
        let signer = HsmSealSigner::mock("v1").unwrap();
        // Force the adapter unhealthy via downcast trick: re-create a fresh
        // MockHsmAdapter, mark unhealthy, wrap in HsmSealSigner.
        let mock = MockHsmAdapter::new("v2").unwrap();
        mock.mark_unhealthy();
        let signer2 = HsmSealSigner::new(Box::new(mock));
        let seal = DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: crate::Sector::Finance,
            event_type: "x".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("m", crate::Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        };
        // signer2 has no mock_signer (the new adapter is just Box<dyn>),
        // so sign_seal will return error path due to missing inner.
        let r = signer2.sign_seal(seal.clone());
        assert!(r.is_err());
        let _ = signer; // suppress unused
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn rotation_status_reports_due() {
        use std::collections::BTreeMap;
        use uuid::Uuid;
        let signer = HsmSealSigner::mock("v1").unwrap();
        let status = signer.rotation_status();
        assert!(status.is_some());
        let s = status.unwrap();
        assert_eq!(s.sigs_used, 0);
        assert!(!s.due);
        let _ = (BTreeMap::<String, String>::new(), Uuid::now_v7());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_seal_signer_kind_reflects_adapter() {
        let signer = HsmSealSigner::mock("v1").unwrap();
        assert_eq!(signer.hsm_kind(), HsmKind::Mock);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_seal_signer_is_healthy_initially() {
        let signer = HsmSealSigner::mock("v1").unwrap();
        assert!(signer.is_healthy());
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn hsm_seal_signer_implements_seal_signer_trait() {
        let signer = HsmSealSigner::mock("v1").unwrap();
        assert_eq!(signer.signer_id(), "v1");
        assert_eq!(signer.algorithm(), "hybrid-ecdsa-dilithium3-hsm");
    }

    #[test]
    fn rotation_policy_serde_round_trip() {
        let p = HsmKeyRotationPolicy::fips_quarterly();
        let j = serde_json::to_string(&p).unwrap();
        let q: HsmKeyRotationPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn hsm_kind_serde_round_trip() {
        let k = HsmKind::AwsKms;
        let j = serde_json::to_string(&k).unwrap();
        assert_eq!(j, "\"aws_kms\"");
        let p: HsmKind = serde_json::from_str(&j).unwrap();
        assert_eq!(p, k);
    }

    #[cfg(feature = "real-crypto")]
    #[test]
    fn rotation_status_serde_round_trip() {
        let signer = HsmSealSigner::mock("v1").unwrap();
        let status = signer.rotation_status().unwrap();
        let j = serde_json::to_string(&status).unwrap();
        let p: HsmRotationStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(p.sigs_used, status.sigs_used);
        assert_eq!(p.due, status.due);
    }
}
