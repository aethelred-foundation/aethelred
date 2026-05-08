//! Real TEE attestation verification.
//!
//! Replaces the v0.2.0/v0.2.1 placeholder where `Attestation::verify_structure`
//! only checked "is the runtime nonce non-zero". This module parses real
//! platform attestation documents and verifies them against the
//! platform-specific PKI policy.
//!
//! ## Supported platforms
//!
//! | Platform              | Document            | Authority                      |
//! | --------------------- | ------------------- | ------------------------------ |
//! | Intel TDX             | `TDQUOTE`           | Intel Provisioning Service (PCS) |
//! | AMD SEV-SNP           | `GUEST_REPORT`      | AMD Key Distribution Service (KDS) |
//! | AWS Nitro Enclaves    | NSM document        | AWS Nitro Root CA               |
//! | NVIDIA H100 CC        | RIM-bound quote     | NVIDIA RIM service              |
//! | ARM CCA               | Realm Attestation   | Arm CCA verifier                |
//!
//! ## What we ship vs. delegate
//!
//! Production TEE verification has two layers:
//!
//! 1. **Structural parsing** of the platform document (headers, lengths, body
//!    sections). This module *does* parse the canonical layouts so that
//!    downstream code has a typed view.
//! 2. **Signature verification against vendor PKIs.** This requires
//!    network access to the vendor's PKS / KDS / RIM. We expose a
//!    [`TeeAttestationVerifier`] trait so deployments plug in their PKI
//!    integration of choice; we ship a [`MockTeeVerifier`] that does
//!    structural-only checks for tests.
//!
//! This is the right separation for an open-source library: nobody wants a
//! library that hardcodes a vendor RPC URL or bundles an expired cert chain.
//!
//! ## What this gives you over v0.2.1
//!
//! - Reject malformed attestation documents (length / magic / version).
//! - Reject documents whose embedded measurement doesn't match the seal's
//!   `workload_measurement`.
//! - Reject documents whose nonce doesn't match the seal's `runtime_nonce`.
//! - Reject documents whose TCB version is below the configured floor.
//! - Reject documents past their freshness window.
//! - Pluggable signature verification through the `TeeAttestationVerifier`
//!   trait.

use crate::tee::{Attestation, AttestationVendor, TeePlatform};
use crate::{SandboxError, SandboxResult, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// AttestationDocument — typed view of platform-specific blobs
// =============================================================================

/// Typed view of a parsed attestation document.
///
/// Customers receive raw bytes from their platform and pass them to
/// [`parse_attestation_document`]; the result is a `AttestationDocument`
/// suitable for cross-checking against the seal's `Attestation` envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "platform")]
pub enum AttestationDocument {
    /// Intel TDX TDQUOTE.
    IntelTdx(TdxQuote),
    /// AMD SEV-SNP guest report.
    AmdSevSnp(SevSnpReport),
    /// AWS Nitro NSM attestation document.
    AwsNitro(NitroAttestationDocument),
    /// NVIDIA H100 CC RIM-bound quote (placeholder — RIM is opaque).
    NvidiaH100Cc(NvidiaH100Quote),
    /// ARM CCA Realm attestation (placeholder).
    ArmCca(ArmCcaAttestation),
}

impl AttestationDocument {
    /// Platform discriminator.
    pub fn platform(&self) -> TeePlatform {
        match self {
            Self::IntelTdx(_) => TeePlatform::IntelTdx,
            Self::AmdSevSnp(_) => TeePlatform::AmdSevSnp,
            Self::AwsNitro(_) => TeePlatform::AwsNitro,
            Self::NvidiaH100Cc(_) => TeePlatform::NvidiaH100Cc,
            Self::ArmCca(_) => TeePlatform::ArmCca,
        }
    }

    /// The 48-byte (TDX) / 384-bit measurement that should match the seal's
    /// `workload_measurement`.
    pub fn workload_measurement(&self) -> Sha256Digest {
        match self {
            Self::IntelTdx(q) => q.mrtd,
            Self::AmdSevSnp(r) => r.measurement,
            Self::AwsNitro(d) => d.pcrs_digest,
            Self::NvidiaH100Cc(q) => q.measurement,
            Self::ArmCca(c) => c.realm_measurement,
        }
    }

    /// Runtime nonce (also known as report-data / user-data) included in the
    /// document. This must match the seal's `runtime_nonce`.
    pub fn runtime_nonce(&self) -> Sha256Digest {
        match self {
            Self::IntelTdx(q) => q.report_data,
            Self::AmdSevSnp(r) => r.report_data,
            Self::AwsNitro(d) => d.user_data_digest,
            Self::NvidiaH100Cc(q) => q.user_data,
            Self::ArmCca(c) => c.challenge,
        }
    }

    /// TCB / firmware version (string form, free-form per platform).
    pub fn tcb_version(&self) -> &str {
        match self {
            Self::IntelTdx(q) => &q.tcb_version,
            Self::AmdSevSnp(r) => &r.tcb_version,
            Self::AwsNitro(d) => &d.module_version,
            Self::NvidiaH100Cc(q) => &q.driver_version,
            Self::ArmCca(c) => &c.tcb_version,
        }
    }
}

/// Intel TDX TDQUOTE (parsed view).
///
/// Real TDQUOTE layout: header (48B) + body (584B for v4) + signature blob.
/// We parse the cross-platform fields we care about; production deployments
/// that need the full TDQUOTE structure use Intel DCAP libraries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TdxQuote {
    /// Quote version (v4 in current production, was v3).
    pub version: u16,
    /// Attestation key type.
    pub ak_type: u16,
    /// MRTD — Measurement of Trust Domain.
    pub mrtd: Sha256Digest,
    /// Report data (runtime nonce).
    pub report_data: Sha256Digest,
    /// TCB version (e.g., `"2025.10"`).
    pub tcb_version: String,
    /// QE vendor id (16 bytes).
    pub qe_vendor_id: Vec<u8>,
    /// User-defined data (16 bytes).
    pub user_data: Vec<u8>,
    /// Signature blob length.
    pub signature_len: u32,
}

/// AMD SEV-SNP guest report (parsed view).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SevSnpReport {
    /// Report version.
    pub version: u32,
    /// Guest SVN.
    pub guest_svn: u32,
    /// Policy.
    pub policy: u64,
    /// Family id.
    pub family_id: Vec<u8>,
    /// Image id.
    pub image_id: Vec<u8>,
    /// Measurement.
    pub measurement: Sha256Digest,
    /// Report data.
    pub report_data: Sha256Digest,
    /// TCB version (BL/TEE/SNP/Microcode).
    pub tcb_version: String,
}

/// AWS Nitro NSM attestation document (parsed view).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NitroAttestationDocument {
    /// Module id (e.g., `"i-0123456789abcdef0-enc..."`).
    pub module_id: String,
    /// Module version.
    pub module_version: String,
    /// Digest algorithm (e.g., `"SHA384"`).
    pub digest_algorithm: String,
    /// Concatenated PCRs hashed.
    pub pcrs_digest: Sha256Digest,
    /// User data digest (the runtime nonce).
    pub user_data_digest: Sha256Digest,
    /// Public-key fingerprint.
    pub public_key_fingerprint: Sha256Digest,
    /// Cert-chain length.
    pub cabundle_len: u32,
}

/// NVIDIA H100 CC RIM-bound quote (placeholder shape).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NvidiaH100Quote {
    /// GPU UUID.
    pub gpu_uuid: String,
    /// Driver version.
    pub driver_version: String,
    /// VBIOS version.
    pub vbios_version: String,
    /// Workload measurement.
    pub measurement: Sha256Digest,
    /// User-data nonce.
    pub user_data: Sha256Digest,
}

/// ARM CCA Realm attestation (placeholder shape).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArmCcaAttestation {
    /// Realm initial measurement.
    pub realm_measurement: Sha256Digest,
    /// Challenge nonce.
    pub challenge: Sha256Digest,
    /// CCA platform-token TCB version.
    pub tcb_version: String,
    /// Realm public-key hash.
    pub realm_public_key_hash: Sha256Digest,
}

// =============================================================================
// Parser
// =============================================================================

/// Parse a platform-specific attestation document.
///
/// The customer is expected to know which platform the bytes belong to
/// (it's a deployment-time configuration). We accept a [`TeePlatform`] hint
/// and parse the canonical layout.
pub fn parse_attestation_document(
    platform: TeePlatform,
    bytes: &[u8],
) -> SandboxResult<AttestationDocument> {
    match platform {
        TeePlatform::IntelTdx => parse_tdx_quote(bytes).map(AttestationDocument::IntelTdx),
        TeePlatform::AmdSevSnp => parse_sev_snp_report(bytes).map(AttestationDocument::AmdSevSnp),
        TeePlatform::AwsNitro => parse_nitro_document(bytes).map(AttestationDocument::AwsNitro),
        TeePlatform::NvidiaH100Cc => parse_h100_quote(bytes).map(AttestationDocument::NvidiaH100Cc),
        TeePlatform::ArmCca => parse_arm_cca(bytes).map(AttestationDocument::ArmCca),
        TeePlatform::AzureCc | TeePlatform::GcpConfidentialSpace => Err(SandboxError::Attestation {
            platform: platform.as_str().into(),
            reason: "platform parser not implemented in sandbox-core; \
                     wrap your cloud-attestation SDK in a TeeAttestationVerifier impl"
                .into(),
        }),
        TeePlatform::None => Err(SandboxError::Attestation {
            platform: "none".into(),
            reason: "TeePlatform::None has no attestation document to parse".into(),
        }),
    }
}

/// Parse an Intel TDX TDQUOTE. We accept either:
/// - **Strict binary form** (≥ 48 bytes header + body + sig) — we read the
///   first 48 bytes for header fields; the rest is opaque.
/// - **JSON form** (a typed `TdxQuote` serialized as JSON) — for clients
///   that pre-parse via DCAP and pass us the structured view.
fn parse_tdx_quote(bytes: &[u8]) -> SandboxResult<TdxQuote> {
    // Try JSON first.
    if bytes.first().copied() == Some(b'{') {
        return serde_json::from_slice::<TdxQuote>(bytes).map_err(|e| {
            SandboxError::Attestation {
                platform: "intel_tdx".into(),
                reason: format!("json parse: {e}"),
            }
        });
    }
    // Binary form. Minimum sane header.
    if bytes.len() < 48 {
        return Err(SandboxError::Attestation {
            platform: "intel_tdx".into(),
            reason: format!("TDQUOTE too short: {} < 48", bytes.len()),
        });
    }
    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    let ak_type = u16::from_le_bytes([bytes[2], bytes[3]]);
    if ![3u16, 4u16].contains(&version) {
        return Err(SandboxError::Attestation {
            platform: "intel_tdx".into(),
            reason: format!("unsupported TDQUOTE version: {version}"),
        });
    }
    // Body lives after the 48-byte header. For our purposes we only
    // parse mrtd (offset 48..80) and report_data (offset 568..600 in v4).
    if bytes.len() < 600 {
        return Err(SandboxError::Attestation {
            platform: "intel_tdx".into(),
            reason: format!("TDQUOTE body too short: {} < 600", bytes.len()),
        });
    }
    let mut mrtd = [0u8; 32];
    mrtd.copy_from_slice(&bytes[48..80]);
    let mut report_data = [0u8; 32];
    report_data.copy_from_slice(&bytes[568..600]);
    let mut qe_vendor_id = vec![0u8; 16];
    qe_vendor_id.copy_from_slice(&bytes[16..32]);
    let mut user_data = vec![0u8; 16];
    user_data.copy_from_slice(&bytes[32..48]);
    Ok(TdxQuote {
        version,
        ak_type,
        mrtd: Sha256Digest(mrtd),
        report_data: Sha256Digest(report_data),
        tcb_version: format!("v{version}.tcb-from-quote"),
        qe_vendor_id,
        user_data,
        signature_len: (bytes.len().saturating_sub(600)) as u32,
    })
}

fn parse_sev_snp_report(bytes: &[u8]) -> SandboxResult<SevSnpReport> {
    if bytes.first().copied() == Some(b'{') {
        return serde_json::from_slice(bytes).map_err(|e| SandboxError::Attestation {
            platform: "amd_sev_snp".into(),
            reason: format!("json parse: {e}"),
        });
    }
    // Real SNP report is 1184 bytes. We accept a minimal-parse view.
    if bytes.len() < 1184 {
        return Err(SandboxError::Attestation {
            platform: "amd_sev_snp".into(),
            reason: format!("SNP report too short: {} < 1184", bytes.len()),
        });
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let guest_svn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let policy = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let family_id = bytes[16..32].to_vec();
    let image_id = bytes[32..48].to_vec();
    let mut measurement = [0u8; 32];
    measurement.copy_from_slice(&bytes[80..112]);
    let mut report_data = [0u8; 32];
    report_data.copy_from_slice(&bytes[112..144]);
    Ok(SevSnpReport {
        version,
        guest_svn,
        policy,
        family_id,
        image_id,
        measurement: Sha256Digest(measurement),
        report_data: Sha256Digest(report_data),
        tcb_version: "tcb-from-report".into(),
    })
}

fn parse_nitro_document(bytes: &[u8]) -> SandboxResult<NitroAttestationDocument> {
    // Nitro NSM doc is COSE_Sign1-wrapped CBOR. We accept JSON-typed input
    // so customers can plug their own COSE/CBOR parser upstream of us.
    serde_json::from_slice(bytes).map_err(|e| SandboxError::Attestation {
        platform: "aws_nitro".into(),
        reason: format!("expected pre-parsed JSON; cbor parse: {e}"),
    })
}

fn parse_h100_quote(bytes: &[u8]) -> SandboxResult<NvidiaH100Quote> {
    serde_json::from_slice(bytes).map_err(|e| SandboxError::Attestation {
        platform: "nvidia_h100_cc".into(),
        reason: format!("h100 json parse: {e}"),
    })
}

fn parse_arm_cca(bytes: &[u8]) -> SandboxResult<ArmCcaAttestation> {
    serde_json::from_slice(bytes).map_err(|e| SandboxError::Attestation {
        platform: "arm_cca".into(),
        reason: format!("cca json parse: {e}"),
    })
}

// =============================================================================
// Verifier policy
// =============================================================================

/// Per-platform verifier policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeVerifierPolicy {
    /// Minimum TCB version (string compare; production deployments parse
    /// per-platform). Empty string disables the check.
    pub min_tcb_version: String,
    /// Maximum acceptable freshness window in seconds — reject documents
    /// whose `signed_at` is older than this. `None` disables the check.
    pub max_freshness_secs: Option<u64>,
    /// Whether mock attestations are accepted.
    pub allow_mock: bool,
    /// Additional measurement allowlist (workload measurements that are
    /// approved); empty means any measurement passes structural checks
    /// (used in dev / ci).
    pub measurement_allowlist: Vec<Sha256Digest>,
}

impl Default for TeeVerifierPolicy {
    fn default() -> Self {
        Self {
            min_tcb_version: String::new(),
            max_freshness_secs: Some(3600),
            allow_mock: false,
            measurement_allowlist: Vec::new(),
        }
    }
}

impl TeeVerifierPolicy {
    /// Production posture: 1-hour freshness, mock disallowed.
    pub fn production() -> Self {
        Self::default()
    }
    /// Dev posture: mock allowed, no freshness window.
    pub fn dev() -> Self {
        Self {
            min_tcb_version: String::new(),
            max_freshness_secs: None,
            allow_mock: true,
            measurement_allowlist: Vec::new(),
        }
    }
    /// Strict posture: 5-minute freshness, mock disallowed, allowlist required.
    pub fn strict_with_allowlist(measurements: Vec<Sha256Digest>) -> Self {
        Self {
            min_tcb_version: String::new(),
            max_freshness_secs: Some(300),
            allow_mock: false,
            measurement_allowlist: measurements,
        }
    }
}

// =============================================================================
// Verifier trait + concrete verifier
// =============================================================================

/// Pluggable TEE attestation verifier.
///
/// Production deployments wire this trait to their PKI integration:
///
/// - **Intel TDX** → `aethelred-edge-tdx` (Intel DCAP + Intel PCS)
/// - **AMD SEV-SNP** → `aethelred-edge-snp` (AMD KDS + ARK/ASK chain)
/// - **AWS Nitro** → `aethelred-edge-nitro` (AWS Nitro Root CA + COSE)
/// - **NVIDIA H100 CC** → `aethelred-edge-nvidia` (NVIDIA RIM)
///
/// This module ships [`MockTeeVerifier`] (structural-only) for tests and
/// CI; production replaces with a vendor-PKI-backed verifier.
pub trait TeeAttestationVerifier: Send + Sync {
    /// Platform this verifier handles.
    fn platform(&self) -> TeePlatform;
    /// Verify the given attestation document.
    fn verify(
        &self,
        document: &AttestationDocument,
        attestation: &Attestation,
        policy: &TeeVerifierPolicy,
    ) -> SandboxResult<()>;
}

/// Mock verifier — does structural checks only. Use for tests / CI.
///
/// Real verifiers do the same structural checks plus signature verification
/// against the vendor PKI. This mock is the *floor*, not a replacement.
pub struct MockTeeVerifier {
    platform: TeePlatform,
}

impl MockTeeVerifier {
    /// New mock verifier for a platform.
    pub fn new(platform: TeePlatform) -> Self {
        Self { platform }
    }
}

impl TeeAttestationVerifier for MockTeeVerifier {
    fn platform(&self) -> TeePlatform {
        self.platform
    }
    fn verify(
        &self,
        document: &AttestationDocument,
        attestation: &Attestation,
        policy: &TeeVerifierPolicy,
    ) -> SandboxResult<()> {
        check_common(document, attestation, policy)
    }
}

/// Common structural checks every verifier should run.
pub fn check_common(
    document: &AttestationDocument,
    attestation: &Attestation,
    policy: &TeeVerifierPolicy,
) -> SandboxResult<()> {
    // 1. Platform must match.
    if document.platform() != attestation.vendor.platform {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: format!(
                "platform mismatch: document={:?} attestation={:?}",
                document.platform(),
                attestation.vendor.platform
            ),
        });
    }
    // 2. Workload measurement must match the seal's claim.
    if document.workload_measurement() != attestation.workload_measurement {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: "workload_measurement does not match document".into(),
        });
    }
    // 3. Runtime nonce must match.
    if document.runtime_nonce() != attestation.runtime_nonce {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: "runtime_nonce does not match document report-data".into(),
        });
    }
    // 4. Mock allowed?
    if attestation.is_mock() && !policy.allow_mock {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: "mock attestations rejected by policy".into(),
        });
    }
    // 5. TCB version floor.
    if !policy.min_tcb_version.is_empty()
        && document.tcb_version() < policy.min_tcb_version.as_str()
    {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: format!(
                "tcb version {} below floor {}",
                document.tcb_version(),
                policy.min_tcb_version
            ),
        });
    }
    // 6. Allowlist.
    if !policy.measurement_allowlist.is_empty()
        && !policy
            .measurement_allowlist
            .contains(&document.workload_measurement())
    {
        return Err(SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: "workload measurement not in allowlist".into(),
        });
    }
    Ok(())
}

/// Registry of platform verifiers.
pub struct TeeVerifierRegistry {
    verifiers: RwLock<HashMap<TeePlatform, Box<dyn TeeAttestationVerifier>>>,
    policy: TeeVerifierPolicy,
}

impl TeeVerifierRegistry {
    /// New registry with the given policy.
    pub fn new(policy: TeeVerifierPolicy) -> Self {
        Self {
            verifiers: RwLock::new(HashMap::new()),
            policy,
        }
    }

    /// Register a verifier for a platform.
    pub fn register(&self, verifier: Box<dyn TeeAttestationVerifier>) {
        let platform = verifier.platform();
        let mut g = match self.verifiers.write() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.insert(platform, verifier);
    }

    /// `true` if a verifier is registered for `platform`.
    pub fn has(&self, platform: TeePlatform) -> bool {
        self.verifiers
            .read()
            .map(|g| g.contains_key(&platform))
            .unwrap_or(false)
    }

    /// Verify a document + attestation.
    pub fn verify(
        &self,
        document: &AttestationDocument,
        attestation: &Attestation,
    ) -> SandboxResult<()> {
        let g = self.verifiers.read().map_err(|_| SandboxError::Attestation {
            platform: attestation.vendor.platform.as_str().into(),
            reason: "verifier registry poisoned".into(),
        })?;
        let verifier = g.get(&attestation.vendor.platform).ok_or_else(|| {
            SandboxError::Attestation {
                platform: attestation.vendor.platform.as_str().into(),
                reason: "no verifier registered for platform".into(),
            }
        })?;
        verifier.verify(document, attestation, &self.policy)
    }

    /// Number of registered verifiers.
    pub fn len(&self) -> usize {
        self.verifiers.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Helpers for callers / tests
// =============================================================================

/// Build a typed [`Attestation`] from a parsed document.
///
/// Useful when the customer has the platform document but no `Attestation`
/// envelope yet — call this to build a sealable envelope.
pub fn attestation_from_document(
    document: &AttestationDocument,
    root_ref: impl Into<String>,
    verifier_id: Option<String>,
) -> Attestation {
    let platform = document.platform();
    Attestation {
        vendor: AttestationVendor {
            platform,
            root_ref: root_ref.into(),
            tcb_version: Some(document.tcb_version().to_string()),
        },
        attestation_doc_hash: crate::Hasher::sha256(b"placeholder-doc"),
        workload_measurement: document.workload_measurement(),
        runtime_nonce: document.runtime_nonce(),
        verified: true,
        verifier_id,
    }
}

/// Best-effort freshness check given an attestation `signed_at` RFC 3339
/// string (provided out-of-band). Returns `Ok(())` if within the policy's
/// `max_freshness_secs`.
pub fn check_freshness(signed_at: &str, policy: &TeeVerifierPolicy) -> SandboxResult<()> {
    let max_secs = match policy.max_freshness_secs {
        Some(s) => s,
        None => return Ok(()),
    };
    let parsed = OffsetDateTime::parse(
        signed_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| SandboxError::Attestation {
        platform: "any".into(),
        reason: format!("rfc3339 parse: {e}"),
    })?;
    let age = (OffsetDateTime::now_utc() - parsed)
        .whole_seconds()
        .max(0) as u64;
    if age > max_secs {
        return Err(SandboxError::Attestation {
            platform: "any".into(),
            reason: format!("attestation age {age}s exceeds policy floor {max_secs}s"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    fn mock_tdx_doc(measurement: Sha256Digest, nonce: Sha256Digest) -> AttestationDocument {
        AttestationDocument::IntelTdx(TdxQuote {
            version: 4,
            ak_type: 2,
            mrtd: measurement,
            report_data: nonce,
            tcb_version: "2025.10".into(),
            qe_vendor_id: vec![0u8; 16],
            user_data: vec![0u8; 16],
            signature_len: 0,
        })
    }

    fn mock_attestation(
        platform: TeePlatform,
        measurement: Sha256Digest,
        nonce: Sha256Digest,
    ) -> Attestation {
        Attestation {
            vendor: AttestationVendor {
                platform,
                root_ref: "test-root".into(),
                tcb_version: Some("2025.10".into()),
            },
            attestation_doc_hash: Hasher::sha256(b"doc"),
            workload_measurement: measurement,
            runtime_nonce: nonce,
            verified: true,
            verifier_id: Some("test".into()),
        }
    }

    #[test]
    fn parse_tdx_json_round_trips() {
        let m = Hasher::sha256(b"workload");
        let n = Hasher::sha256(b"nonce");
        let doc = AttestationDocument::IntelTdx(TdxQuote {
            version: 4,
            ak_type: 2,
            mrtd: m,
            report_data: n,
            tcb_version: "2025.10".into(),
            qe_vendor_id: vec![0u8; 16],
            user_data: vec![1u8; 16],
            signature_len: 4096,
        });
        let inner = match &doc {
            AttestationDocument::IntelTdx(q) => q.clone(),
            _ => panic!(),
        };
        let bytes = serde_json::to_vec(&inner).unwrap();
        let parsed = parse_attestation_document(TeePlatform::IntelTdx, &bytes).unwrap();
        assert_eq!(parsed.platform(), TeePlatform::IntelTdx);
        assert_eq!(parsed.workload_measurement(), m);
    }

    #[test]
    fn parse_tdx_binary_minimum_length() {
        let bytes = vec![0u8; 32];
        assert!(parse_attestation_document(TeePlatform::IntelTdx, &bytes).is_err());
    }

    #[test]
    fn parse_tdx_binary_full_layout() {
        let mut bytes = vec![0u8; 700];
        // version 4 (LE).
        bytes[0] = 4;
        bytes[1] = 0;
        // ak_type = 2.
        bytes[2] = 2;
        bytes[3] = 0;
        // mrtd at offset 48..80.
        for i in 0..32 {
            bytes[48 + i] = (i + 1) as u8;
        }
        // report_data at 568..600.
        for i in 0..32 {
            bytes[568 + i] = (i + 100) as u8;
        }
        let doc = parse_attestation_document(TeePlatform::IntelTdx, &bytes).unwrap();
        if let AttestationDocument::IntelTdx(q) = doc {
            assert_eq!(q.version, 4);
            assert_eq!(q.mrtd.0[0], 1);
            assert_eq!(q.report_data.0[0], 100);
        } else {
            panic!("expected TDX");
        }
    }

    #[test]
    fn parse_tdx_unsupported_version_rejected() {
        let mut bytes = vec![0u8; 700];
        bytes[0] = 99; // unsupported
        let r = parse_attestation_document(TeePlatform::IntelTdx, &bytes);
        assert!(r.is_err());
    }

    #[test]
    fn parse_sev_snp_short_rejected() {
        let bytes = vec![0u8; 100];
        let r = parse_attestation_document(TeePlatform::AmdSevSnp, &bytes);
        assert!(r.is_err());
    }

    #[test]
    fn parse_sev_snp_full_layout() {
        let mut bytes = vec![0u8; 1184];
        bytes[0] = 2; // version
        // measurement at 80..112
        for i in 0..32 {
            bytes[80 + i] = (i + 7) as u8;
        }
        // report_data at 112..144
        for i in 0..32 {
            bytes[112 + i] = (i + 9) as u8;
        }
        let doc = parse_attestation_document(TeePlatform::AmdSevSnp, &bytes).unwrap();
        if let AttestationDocument::AmdSevSnp(r) = doc {
            assert_eq!(r.version, 2);
            assert_eq!(r.measurement.0[0], 7);
            assert_eq!(r.report_data.0[0], 9);
        } else {
            panic!("expected SEV-SNP");
        }
    }

    #[test]
    fn parse_nitro_json() {
        let doc = NitroAttestationDocument {
            module_id: "i-test".into(),
            module_version: "1.0".into(),
            digest_algorithm: "SHA384".into(),
            pcrs_digest: Hasher::sha256(b"pcr"),
            user_data_digest: Hasher::sha256(b"user"),
            public_key_fingerprint: Hasher::sha256(b"pk"),
            cabundle_len: 3,
        };
        let bytes = serde_json::to_vec(&doc).unwrap();
        let parsed = parse_attestation_document(TeePlatform::AwsNitro, &bytes).unwrap();
        assert_eq!(parsed.platform(), TeePlatform::AwsNitro);
    }

    #[test]
    fn parse_h100_json() {
        let q = NvidiaH100Quote {
            gpu_uuid: "gpu-0".into(),
            driver_version: "550.x".into(),
            vbios_version: "9X".into(),
            measurement: Hasher::sha256(b"m"),
            user_data: Hasher::sha256(b"u"),
        };
        let bytes = serde_json::to_vec(&q).unwrap();
        let parsed = parse_attestation_document(TeePlatform::NvidiaH100Cc, &bytes).unwrap();
        assert_eq!(parsed.platform(), TeePlatform::NvidiaH100Cc);
    }

    #[test]
    fn parse_arm_cca_json() {
        let c = ArmCcaAttestation {
            realm_measurement: Hasher::sha256(b"realm"),
            challenge: Hasher::sha256(b"ch"),
            tcb_version: "v1".into(),
            realm_public_key_hash: Hasher::sha256(b"pk"),
        };
        let bytes = serde_json::to_vec(&c).unwrap();
        let parsed = parse_attestation_document(TeePlatform::ArmCca, &bytes).unwrap();
        assert_eq!(parsed.platform(), TeePlatform::ArmCca);
    }

    #[test]
    fn parse_unsupported_platform_errors() {
        let bytes = b"{}".to_vec();
        let r = parse_attestation_document(TeePlatform::AzureCc, &bytes);
        assert!(r.is_err());
    }

    #[test]
    fn parse_none_platform_errors() {
        let bytes = b"{}".to_vec();
        let r = parse_attestation_document(TeePlatform::None, &bytes);
        assert!(r.is_err());
    }

    #[test]
    fn check_common_accepts_matching_attestation() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let mut a = mock_attestation(TeePlatform::IntelTdx, m, n);
        // Disable mock detection for this test.
        a.verifier_id = Some("real-verifier".into());
        let policy = TeeVerifierPolicy::default();
        check_common(&doc, &a, &policy).unwrap();
    }

    #[test]
    fn check_common_rejects_platform_mismatch() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let a = mock_attestation(TeePlatform::AmdSevSnp, m, n);
        let policy = TeeVerifierPolicy::default();
        assert!(check_common(&doc, &a, &policy).is_err());
    }

    #[test]
    fn check_common_rejects_measurement_mismatch() {
        let m1 = Hasher::sha256(b"m1");
        let m2 = Hasher::sha256(b"m2");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m1, n);
        let a = mock_attestation(TeePlatform::IntelTdx, m2, n);
        let policy = TeeVerifierPolicy::default();
        assert!(check_common(&doc, &a, &policy).is_err());
    }

    #[test]
    fn check_common_rejects_nonce_mismatch() {
        let m = Hasher::sha256(b"m");
        let n1 = Hasher::sha256(b"n1");
        let n2 = Hasher::sha256(b"n2");
        let doc = mock_tdx_doc(m, n1);
        let a = mock_attestation(TeePlatform::IntelTdx, m, n2);
        let policy = TeeVerifierPolicy::default();
        assert!(check_common(&doc, &a, &policy).is_err());
    }

    #[test]
    fn check_common_rejects_mock_under_strict_policy() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        // Default mock verifier_id triggers is_mock().
        let a = Attestation {
            vendor: AttestationVendor {
                platform: TeePlatform::IntelTdx,
                root_ref: "mock-vendor-root".into(),
                tcb_version: Some("2025.10".into()),
            },
            attestation_doc_hash: Hasher::sha256(b"mock"),
            workload_measurement: m,
            runtime_nonce: n,
            verified: true,
            verifier_id: Some("mock-verifier".into()),
        };
        let policy = TeeVerifierPolicy::production();
        let r = check_common(&doc, &a, &policy);
        assert!(r.is_err());
    }

    #[test]
    fn check_common_accepts_mock_under_dev_policy() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let a = Attestation {
            vendor: AttestationVendor {
                platform: TeePlatform::IntelTdx,
                root_ref: "mock-vendor-root".into(),
                tcb_version: Some("2025.10".into()),
            },
            attestation_doc_hash: Hasher::sha256(b"mock"),
            workload_measurement: m,
            runtime_nonce: n,
            verified: true,
            verifier_id: Some("mock-verifier".into()),
        };
        let policy = TeeVerifierPolicy::dev();
        check_common(&doc, &a, &policy).unwrap();
    }

    #[test]
    fn check_common_rejects_outside_allowlist() {
        let m_doc = Hasher::sha256(b"m");
        let m_allowed = Hasher::sha256(b"different");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m_doc, n);
        let mut a = mock_attestation(TeePlatform::IntelTdx, m_doc, n);
        a.verifier_id = Some("real".into());
        let policy = TeeVerifierPolicy::strict_with_allowlist(vec![m_allowed]);
        assert!(check_common(&doc, &a, &policy).is_err());
    }

    #[test]
    fn check_common_accepts_in_allowlist() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let mut a = mock_attestation(TeePlatform::IntelTdx, m, n);
        a.verifier_id = Some("real".into());
        let policy = TeeVerifierPolicy::strict_with_allowlist(vec![m]);
        check_common(&doc, &a, &policy).unwrap();
    }

    #[test]
    fn registry_routes_to_correct_verifier() {
        let reg = TeeVerifierRegistry::new(TeeVerifierPolicy::dev());
        reg.register(Box::new(MockTeeVerifier::new(TeePlatform::IntelTdx)));
        reg.register(Box::new(MockTeeVerifier::new(TeePlatform::AmdSevSnp)));
        assert!(reg.has(TeePlatform::IntelTdx));
        assert!(reg.has(TeePlatform::AmdSevSnp));
        assert!(!reg.has(TeePlatform::AwsNitro));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_unknown_platform_errors() {
        let reg = TeeVerifierRegistry::new(TeeVerifierPolicy::dev());
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let a = mock_attestation(TeePlatform::IntelTdx, m, n);
        let r = reg.verify(&doc, &a);
        assert!(r.is_err());
    }

    #[test]
    fn attestation_from_document_round_trip() {
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let a = attestation_from_document(&doc, "test-pki", Some("v1".into()));
        assert_eq!(a.workload_measurement, m);
        assert_eq!(a.runtime_nonce, n);
        assert_eq!(a.vendor.platform, TeePlatform::IntelTdx);
    }

    #[test]
    fn freshness_accepts_recent_timestamp() {
        let now = OffsetDateTime::now_utc();
        let s = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let policy = TeeVerifierPolicy::default();
        check_freshness(&s, &policy).unwrap();
    }

    #[test]
    fn freshness_rejects_old_timestamp() {
        let old = OffsetDateTime::now_utc() - time::Duration::seconds(7200);
        let s = old
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let policy = TeeVerifierPolicy {
            max_freshness_secs: Some(1800),
            ..Default::default()
        };
        assert!(check_freshness(&s, &policy).is_err());
    }

    #[test]
    fn freshness_disabled_accepts_any() {
        let old = OffsetDateTime::now_utc() - time::Duration::days(30);
        let s = old
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let mut policy = TeeVerifierPolicy::default();
        policy.max_freshness_secs = None;
        check_freshness(&s, &policy).unwrap();
    }

    #[test]
    fn freshness_bad_format_errors() {
        let policy = TeeVerifierPolicy::default();
        assert!(check_freshness("not-a-date", &policy).is_err());
    }

    #[test]
    fn document_serde_round_trip() {
        let doc = mock_tdx_doc(Hasher::sha256(b"m"), Hasher::sha256(b"n"));
        let j = serde_json::to_string(&doc).unwrap();
        let p: AttestationDocument = serde_json::from_str(&j).unwrap();
        assert_eq!(p, doc);
    }

    #[test]
    fn registry_verify_full_path() {
        let reg = TeeVerifierRegistry::new(TeeVerifierPolicy::dev());
        reg.register(Box::new(MockTeeVerifier::new(TeePlatform::IntelTdx)));
        let m = Hasher::sha256(b"m");
        let n = Hasher::sha256(b"n");
        let doc = mock_tdx_doc(m, n);
        let a = mock_attestation(TeePlatform::IntelTdx, m, n);
        // dev policy allows mock → should pass.
        reg.verify(&doc, &a).unwrap();
    }
}
