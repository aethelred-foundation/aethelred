//! Trusted Execution Environment (TEE) attestation primitives.
//!
//! The sandbox does not implement TEE attestation in software — that is the
//! job of the host platform. What the sandbox *does* do is:
//!
//! 1. Define a stable, sector-agnostic [`Attestation`] envelope that the
//!    [`crate::seal::DigitalSeal`] embeds.
//! 2. Define the [`TeePlatform`] vendor enum so sectors can pick the right
//!    attestation flow.
//! 3. Provide a `mock-tee` feature for development / CI that always succeeds.
//! 4. Expose a verifier surface that real platform integrators (the Aethelred
//!    edge runtime) plug into.
//!
//! ## Real attestation in production
//!
//! Production uses platform-specific verifier crates (in
//! `aethelred-core::tee::*`). The sandbox-core attestation is the
//! *receipt-side* representation; the *generation-side* is platform code.

use crate::hashing::{Hasher, Sha256Digest};
use crate::SandboxError;
use serde::{Deserialize, Serialize};

/// TEE platform vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePlatform {
    /// Intel TDX (Trust Domain Extensions, Xeon SPR/EMR/GNR).
    IntelTdx,
    /// AMD SEV-SNP (Secure Encrypted Virtualization, EPYC Milan/Genoa/Turin).
    AmdSevSnp,
    /// AWS Nitro Enclaves.
    AwsNitro,
    /// NVIDIA H100 Confidential Computing (paired with TDX or SEV-SNP host).
    NvidiaH100Cc,
    /// ARM Confidential Compute Architecture (Realms).
    ArmCca,
    /// Azure Confidential Computing (Microsoft Azure Attestation).
    AzureCc,
    /// Google Cloud Confidential Space.
    GcpConfidentialSpace,
    /// No TEE — used for development, mock attestation only.
    None,
}

impl TeePlatform {
    /// Stable string id used in seal export.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntelTdx => "intel_tdx",
            Self::AmdSevSnp => "amd_sev_snp",
            Self::AwsNitro => "aws_nitro",
            Self::NvidiaH100Cc => "nvidia_h100_cc",
            Self::ArmCca => "arm_cca",
            Self::AzureCc => "azure_cc",
            Self::GcpConfidentialSpace => "gcp_confidential_space",
            Self::None => "none",
        }
    }

    /// `true` if attestation is required for production (everything except
    /// `None` — defense / nuclear-adjacent customers also require non-None).
    pub fn requires_attestation(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Attestation vendor chain root reference.
///
/// A real verifier consults the platform's PKI:
/// - Intel TDX: Intel PCS root (current production: 2025.10 / 2026.01).
/// - AMD SEV-SNP: AMD KDS via ARK + ASK chain.
/// - AWS Nitro: AWS Nitro Root CA.
/// - NVIDIA H100: NVIDIA RIM (Reference Integrity Manifest).
/// - ARM CCA: Arm CCA verification service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVendor {
    /// Platform.
    pub platform: TeePlatform,
    /// Vendor PKI root reference (e.g., `"intel_pcs_2025.q4"`).
    pub root_ref: String,
    /// TCB version (firmware/microcode).
    pub tcb_version: Option<String>,
}

/// Attestation envelope embedded in a [`crate::seal::DigitalSeal`].
///
/// The envelope carries the *hash* of the platform-issued attestation
/// document plus a runtime nonce. The full attestation document itself is
/// stored alongside the seal in the [`crate::EvidenceLog`] for reviewer-side
/// independent verification — it never travels inside the seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Vendor reference.
    pub vendor: AttestationVendor,
    /// Hash of the platform-issued attestation document (TDQUOTE / GUEST_REPORT
    /// / NSM_GET_ATTESTATION_DOC / etc.).
    pub attestation_doc_hash: Sha256Digest,
    /// Hash of the workload measurement (MRTD / SNP measurement / PCR list).
    pub workload_measurement: Sha256Digest,
    /// Runtime nonce bound to the seal at attestation time.
    pub runtime_nonce: Sha256Digest,
    /// Verification status — `true` only if a verifier accepted the document.
    pub verified: bool,
    /// Verifier identifier (e.g., `"aethelred-edge-tdx-verifier-1"`).
    pub verifier_id: Option<String>,
}

impl Attestation {
    /// Construct a mock attestation for development / CI. Always reports
    /// `verified = true` and uses deterministic synthetic hashes.
    ///
    /// **Do not** use in production. Sector workflows that require a real TEE
    /// will refuse to seal when `attestation.is_mock()` is `true` and the
    /// `mock-tee` feature is not enabled.
    pub fn mock(platform: TeePlatform, runtime_nonce: Sha256Digest) -> Self {
        Self {
            vendor: AttestationVendor {
                platform,
                root_ref: "mock-vendor-root".into(),
                tcb_version: Some("mock-tcb-1".into()),
            },
            attestation_doc_hash: Hasher::sha256(b"mock-attestation-doc"),
            workload_measurement: Hasher::sha256(b"mock-workload-measurement"),
            runtime_nonce,
            verified: true,
            verifier_id: Some("mock-verifier".into()),
        }
    }

    /// `true` if this attestation came from the `mock` constructor.
    pub fn is_mock(&self) -> bool {
        self.verifier_id.as_deref() == Some("mock-verifier")
    }

    /// Verify this attestation. The default implementation only checks
    /// non-trivial structure; real verification is provided by the host
    /// platform integrator via [`Verifier`].
    pub fn verify_structure(&self) -> crate::SandboxResult<()> {
        if self.runtime_nonce.0 == [0u8; 32] {
            return Err(SandboxError::Attestation {
                platform: self.vendor.platform.as_str().into(),
                reason: "runtime_nonce is zero (replay protection failed)".into(),
            });
        }
        if !self.verified {
            return Err(SandboxError::Attestation {
                platform: self.vendor.platform.as_str().into(),
                reason: "verifier did not accept attestation".into(),
            });
        }
        Ok(())
    }
}

/// Pluggable attestation verifier. The sandbox does not implement these;
/// production code (e.g., `aethelred-edge-tdx`) does.
pub trait Verifier: Send + Sync {
    /// Platform this verifier supports.
    fn platform(&self) -> TeePlatform;
    /// Verify an attestation document against the platform PKI.
    fn verify(&self, attestation_doc: &[u8], runtime_nonce: &Sha256Digest)
        -> crate::SandboxResult<Attestation>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_attestation_verifies() {
        let nonce = Hasher::sha256(b"test-nonce");
        let att = Attestation::mock(TeePlatform::IntelTdx, nonce);
        att.verify_structure().unwrap();
    }

    #[test]
    fn zero_nonce_fails_verification() {
        let nonce = Sha256Digest([0u8; 32]);
        let att = Attestation::mock(TeePlatform::IntelTdx, nonce);
        let err = att.verify_structure().unwrap_err();
        assert!(matches!(err, SandboxError::Attestation { .. }));
    }

    #[test]
    fn platform_string_ids_unique() {
        let all = [
            TeePlatform::IntelTdx,
            TeePlatform::AmdSevSnp,
            TeePlatform::AwsNitro,
            TeePlatform::NvidiaH100Cc,
            TeePlatform::ArmCca,
            TeePlatform::AzureCc,
            TeePlatform::GcpConfidentialSpace,
            TeePlatform::None,
        ];
        let mut ids: Vec<&str> = all.iter().map(|p| p.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }
}
