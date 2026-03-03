//! # Enclave Report
//!
//! Unified output structure for all TEE attestation types.
//! This is the "lingua franca" that bridges Intel SGX, AMD SEV,
//! AWS Nitro, and ARM TrustZone attestations.

use super::{HardwareType, TcbStatus};
use crate::compliance::Jurisdiction;
#[cfg(not(feature = "attestation-evidence"))]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

// ============================================================================
// Enclave Report - The Universal Trust Object
// ============================================================================

/// Unified enclave report across all TEE platforms
///
/// This is the primary output of attestation verification. Regardless of
/// whether the quote came from Intel SGX, AMD SEV-SNP, or AWS Nitro,
/// the verifier produces this standardized structure.
///
/// # Security Properties
///
/// - **Immutable Identity**: The `mrenclave`/`measurement` uniquely identifies the code
/// - **Signer Authority**: The `mrsigner` identifies who built and signed the enclave
/// - **Freshness**: The `report_data` binds the attestation to a specific session
/// - **TCB Level**: Security version numbers track microcode/firmware updates
///
/// # Example
///
/// ```rust,ignore
/// let report = attestation_engine.verify(&quote, &nonce)?;
///
/// // Check the enclave identity
/// if report.measurement != expected_measurement {
///     return Err("Untrusted enclave code");
/// }
///
/// // Verify report data binding
/// if report.report_data[..32] != session_nonce {
///     return Err("Stale or replayed attestation");
/// }
///
/// // Check security posture
/// if report.tcb_status != TcbStatus::UpToDate {
///     log::warn!("TCB requires update");
/// }
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct EnclaveReport {
    // ========================================================================
    // Identity Fields
    // ========================================================================
    /// Unique measurement of enclave code (MRENCLAVE for SGX)
    ///
    /// This is a SHA-256 hash of the enclave's initial memory layout.
    /// Any change to the enclave code produces a different measurement.
    pub measurement: [u8; 32],

    /// Signer identity (MRSIGNER for SGX)
    ///
    /// This identifies the key that signed the enclave. For enterprise
    /// deployments, this should be your organization's signing key.
    pub signer: [u8; 32],

    /// Product ID (ISV_PROD_ID for SGX)
    ///
    /// Used to differentiate between different products from the same signer.
    pub product_id: u16,

    /// Security Version Number (ISV_SVN for SGX)
    ///
    /// Monotonically increasing version. Used to prevent rollback attacks.
    pub security_version: u16,

    // ========================================================================
    // Report Data (User-Defined Binding)
    // ========================================================================
    /// Report data (64 bytes of user-defined data)
    ///
    /// This is the critical binding field. The enclave includes this data
    /// in the hardware-signed attestation. Common uses:
    ///
    /// - First 32 bytes: Session nonce (prevents replay)
    /// - Last 32 bytes: Hash of data being processed
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_64")
    )]
    pub report_data: [u8; 64],

    // ========================================================================
    // Hardware Information
    // ========================================================================
    /// Hardware type that generated this report
    pub hardware_type: HardwareType,

    /// CPU Security Version Number
    ///
    /// For Intel: Platform SVN including microcode version
    /// For AMD: SNP firmware version
    pub cpu_svn: [u8; 16],

    /// Platform Configuration Registers (if available)
    ///
    /// For AMD SEV-SNP: Contains launch measurements
    /// For Intel TDX: Contains TD measurements
    pub platform_info: Option<PlatformInfo>,

    // ========================================================================
    // Security Status
    // ========================================================================
    /// Trusted Computing Base status
    pub tcb_status: TcbStatus,

    /// Security flags
    pub flags: EnclaveFlags,

    /// Known vulnerabilities (if any)
    pub advisories: Vec<SecurityAdvisory>,

    // ========================================================================
    // Attestation Metadata
    // ========================================================================
    /// When this report was generated
    pub timestamp: SystemTime,

    /// Unique identifier for this attestation
    pub attestation_id: [u8; 32],

    /// Collateral version used for verification
    pub collateral_version: String,

    /// Additional platform-specific data
    pub extensions: HashMap<String, Vec<u8>>,
}

impl EnclaveReport {
    /// Create a new enclave report (typically done by verifier)
    pub fn new(
        measurement: [u8; 32],
        signer: [u8; 32],
        report_data: [u8; 64],
        hardware_type: HardwareType,
    ) -> Self {
        EnclaveReport {
            measurement,
            signer,
            product_id: 0,
            security_version: 0,
            report_data,
            hardware_type,
            cpu_svn: [0u8; 16],
            platform_info: None,
            tcb_status: TcbStatus::Unknown,
            flags: EnclaveFlags::default(),
            advisories: Vec::new(),
            timestamp: SystemTime::now(),
            attestation_id: Self::generate_attestation_id(),
            collateral_version: String::new(),
            extensions: HashMap::new(),
        }
    }

    /// Check if report data matches expected nonce
    pub fn verify_nonce(&self, expected: &[u8; 32]) -> bool {
        self.report_data[..32] == expected[..]
    }

    /// Check if report data matches expected data hash
    pub fn verify_data_hash(&self, expected: &[u8; 32]) -> bool {
        self.report_data[32..64] == expected[..]
    }

    /// Check if measurement matches any expected value
    pub fn verify_measurement(&self, expected: &[[u8; 32]]) -> bool {
        expected.iter().any(|m| m == &self.measurement)
    }

    /// Check if signer matches any expected value
    pub fn verify_signer(&self, expected: &[[u8; 32]]) -> bool {
        expected.iter().any(|s| s == &self.signer)
    }

    /// Check if enclave is in production mode
    pub fn is_production(&self) -> bool {
        !self.flags.debug_mode
    }

    /// Check if TCB is acceptable for production
    pub fn is_tcb_acceptable(&self) -> bool {
        self.tcb_status.is_acceptable()
    }

    /// Get a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Enclave Report:\n\
             - Hardware: {}\n\
             - Measurement: {}\n\
             - Signer: {}\n\
             - Product ID: {}\n\
             - Security Version: {}\n\
             - TCB Status: {:?}\n\
             - Debug Mode: {}\n\
             - Timestamp: {:?}",
            self.hardware_type.display_name(),
            hex::encode(&self.measurement[..8]),
            hex::encode(&self.signer[..8]),
            self.product_id,
            self.security_version,
            self.tcb_status,
            self.flags.debug_mode,
            self.timestamp,
        )
    }

    /// Generate unique attestation ID
    fn generate_attestation_id() -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&uuid::Uuid::new_v4().as_bytes()[..]);
        hasher.update(
            &SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .to_le_bytes(),
        );
        hasher.finalize().into()
    }

    /// Serialize to canonical bytes (for signing/hashing)
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&self.measurement);
        bytes.extend_from_slice(&self.signer);
        bytes.extend_from_slice(&self.product_id.to_le_bytes());
        bytes.extend_from_slice(&self.security_version.to_le_bytes());
        bytes.extend_from_slice(&self.report_data);
        bytes.push(self.hardware_type as u8);
        bytes.extend_from_slice(&self.cpu_svn);
        bytes
    }
}

// ============================================================================
// Platform-Specific Information
// ============================================================================

/// Platform-specific configuration and measurements
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum PlatformInfo {
    /// Intel SGX Quote Info
    IntelSgx(SgxPlatformInfo),

    /// Intel TDX Quote Info
    IntelTdx(TdxPlatformInfo),

    /// AMD SEV-SNP Platform Info
    AmdSevSnp(SevSnpPlatformInfo),

    /// AWS Nitro Platform Info
    AwsNitro(NitroPlatformInfo),

    /// ARM CCA Platform Info
    ArmCca(CcaPlatformInfo),
}

/// Intel SGX platform information
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct SgxPlatformInfo {
    /// FMSPC (Family-Model-Stepping-Platform-CustomSKU)
    pub fmspc: [u8; 6],

    /// PCE ID
    pub pce_id: u16,

    /// QE (Quoting Enclave) identity
    pub qe_identity: [u8; 32],

    /// PCE SVN
    pub pce_svn: u16,

    /// Quote type (ECDSA or EPID)
    pub quote_type: SgxQuoteType,

    /// TCB components
    pub tcb_components: [u8; 16],
}

/// Intel TDX platform information
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct TdxPlatformInfo {
    /// TD attributes
    pub td_attributes: u64,

    /// XFAM (eXtended Feature Activation Mask)
    pub xfam: u64,

    /// MRTD (Measurement of initial TD contents)
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub mrtd: [u8; 48],

    /// MRCONFIGID
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub mrconfigid: [u8; 48],

    /// MROWNER
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub mrowner: [u8; 48],

    /// MROWNERCONFIG
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub mrownerconfig: [u8; 48],

    /// Runtime measurements (RTMR0-3)
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48x4")
    )]
    pub rtmrs: [[u8; 48]; 4],
}

/// AMD SEV-SNP platform information
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct SevSnpPlatformInfo {
    /// Guest SVN
    pub guest_svn: u32,

    /// Policy flags
    pub policy: u64,

    /// Family ID
    pub family_id: [u8; 16],

    /// Image ID
    pub image_id: [u8; 16],

    /// VMPL (Virtual Machine Privilege Level)
    pub vmpl: u8,

    /// Platform version
    pub platform_version: SevPlatformVersion,

    /// Launch measurement
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub launch_measurement: [u8; 48],

    /// ID key digest
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub id_key_digest: [u8; 48],

    /// Author key digest
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_48")
    )]
    pub author_key_digest: [u8; 48],

    /// Host data
    pub host_data: [u8; 32],
}

/// AMD SEV platform version
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct SevPlatformVersion {
    /// Boot loader security patch level (SPL).
    pub boot_loader: u8,
    /// TEE firmware security patch level (SPL).
    pub tee: u8,
    /// SEV-SNP firmware security patch level (SPL).
    pub snp: u8,
    /// CPU microcode security patch level (SPL).
    pub microcode: u8,
}

/// AWS Nitro platform information
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct NitroPlatformInfo {
    /// Module ID
    pub module_id: String,

    /// Timestamp
    pub timestamp: u64,

    /// Digest algorithm
    pub digest: NitroDigestAlgorithm,

    /// PCRs (Platform Configuration Registers)
    pub pcrs: HashMap<u8, Vec<u8>>,

    /// Certificate chain
    pub certificate_chain: Vec<Vec<u8>>,

    /// Public key from enclave
    pub public_key: Option<Vec<u8>>,

    /// User data
    pub user_data: Option<Vec<u8>>,

    /// Nonce
    pub nonce: Option<Vec<u8>>,
}

/// ARM CCA platform information
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct CcaPlatformInfo {
    /// Realm challenge
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_64")
    )]
    pub challenge: [u8; 64],

    /// Realm measurements
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_64x4")
    )]
    pub realm_measurements: [[u8; 64]; 4],

    /// Realm public key hash
    #[cfg_attr(
        not(feature = "attestation-evidence"),
        serde(with = "crate::serde_arrays::u8_64")
    )]
    pub rpv: [u8; 64],

    /// Platform hash algorithm
    pub hash_algorithm: String,

    /// Platform implementation ID
    pub implementation_id: [u8; 32],
}

// ============================================================================
// Enums and Flags
// ============================================================================

/// SGX Quote type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum SgxQuoteType {
    /// ECDSA-based attestation (DCAP)
    EcdsaP256,
    /// EPID-based attestation (legacy)
    Epid,
}

/// Nitro digest algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum NitroDigestAlgorithm {
    /// SHA-256 digest.
    Sha256,
    /// SHA-384 digest.
    Sha384,
    /// SHA-512 digest.
    Sha512,
}

/// Enclave security flags
#[derive(Debug, Clone, Default)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct EnclaveFlags {
    /// Enclave is in debug mode (NEVER trust in production!)
    pub debug_mode: bool,

    /// 64-bit mode
    pub mode64bit: bool,

    /// Provisioning key access
    pub provision_key: bool,

    /// EINITTOKEN key access
    pub einittoken_key: bool,

    /// Key Separation & Sharing (KSS) enabled
    pub kss: bool,

    /// AEX Notify enabled
    pub aex_notify: bool,

    /// Memory encryption enabled (SEV)
    pub memory_encryption: bool,

    /// SMT protection enabled
    pub smt_protection: bool,
}

// ============================================================================
// Security Advisories
// ============================================================================

/// Security advisory affecting the platform
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct SecurityAdvisory {
    /// Advisory ID (e.g., "INTEL-SA-00334")
    pub id: String,

    /// CVE identifiers
    pub cves: Vec<String>,

    /// Severity level
    pub severity: AdvisorySeverity,

    /// Description
    pub description: String,

    /// Mitigation status
    pub mitigation: MitigationStatus,

    /// Affected components
    pub affected_components: Vec<String>,
}

/// Advisory severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum AdvisorySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Mitigation status
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum MitigationStatus {
    /// Not mitigated
    NotMitigated,
    /// Partially mitigated
    PartiallyMitigated {
        /// What was done
        actions: Vec<String>,
    },
    /// Fully mitigated
    FullyMitigated {
        /// How it was mitigated
        method: String,
    },
    /// Not applicable to this configuration
    NotApplicable,
}

// ============================================================================
// Geo-Location Binding
// ============================================================================

/// Geographic information injected into report
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub struct GeoBinding {
    /// Verified jurisdiction
    pub jurisdiction: Jurisdiction,

    /// Data center identifier
    pub datacenter_id: String,

    /// Cloud provider
    pub provider: String,

    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,

    /// Region identifier
    pub region: String,

    /// Verification method
    pub verification_method: GeoVerificationMethod,
}

/// How geographic location was verified
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "attestation-evidence"), derive(Serialize, Deserialize))]
pub enum GeoVerificationMethod {
    /// IP geolocation
    IpGeolocation {
        /// Source IP address used for geolocation.
        ip_address: String,
        /// Confidence score in the geolocation determination (0.0-1.0).
        confidence: f32,
    },
    /// Provider attestation
    ProviderAttestation {
        /// Cloud/provider name asserting the region.
        provider: String,
        /// Provider-issued attestation reference/identifier.
        attestation_id: String,
    },
    /// Hardware binding
    HardwareBinding {
        /// Hardware/platform identifier bound to a geographic deployment.
        platform_id: String,
    },
    /// Manual configuration
    ManualConfiguration,
}

// ============================================================================
// Report Builder
// ============================================================================

/// Builder for constructing EnclaveReport
pub struct EnclaveReportBuilder {
    report: EnclaveReport,
}

impl EnclaveReportBuilder {
    /// Create a new builder
    pub fn new(hardware_type: HardwareType) -> Self {
        EnclaveReportBuilder {
            report: EnclaveReport {
                measurement: [0u8; 32],
                signer: [0u8; 32],
                product_id: 0,
                security_version: 0,
                report_data: [0u8; 64],
                hardware_type,
                cpu_svn: [0u8; 16],
                platform_info: None,
                tcb_status: TcbStatus::Unknown,
                flags: EnclaveFlags::default(),
                advisories: Vec::new(),
                timestamp: SystemTime::now(),
                attestation_id: EnclaveReport::generate_attestation_id(),
                collateral_version: String::new(),
                extensions: HashMap::new(),
            },
        }
    }

    /// Set measurement
    pub fn measurement(mut self, measurement: [u8; 32]) -> Self {
        self.report.measurement = measurement;
        self
    }

    /// Set signer
    pub fn signer(mut self, signer: [u8; 32]) -> Self {
        self.report.signer = signer;
        self
    }

    /// Set product ID
    pub fn product_id(mut self, id: u16) -> Self {
        self.report.product_id = id;
        self
    }

    /// Set security version
    pub fn security_version(mut self, version: u16) -> Self {
        self.report.security_version = version;
        self
    }

    /// Set report data
    pub fn report_data(mut self, data: [u8; 64]) -> Self {
        self.report.report_data = data;
        self
    }

    /// Set CPU SVN
    pub fn cpu_svn(mut self, svn: [u8; 16]) -> Self {
        self.report.cpu_svn = svn;
        self
    }

    /// Set platform info
    pub fn platform_info(mut self, info: PlatformInfo) -> Self {
        self.report.platform_info = Some(info);
        self
    }

    /// Set TCB status
    pub fn tcb_status(mut self, status: TcbStatus) -> Self {
        self.report.tcb_status = status;
        self
    }

    /// Set flags
    pub fn flags(mut self, flags: EnclaveFlags) -> Self {
        self.report.flags = flags;
        self
    }

    /// Add advisory
    pub fn advisory(mut self, advisory: SecurityAdvisory) -> Self {
        self.report.advisories.push(advisory);
        self
    }

    /// Set collateral version
    pub fn collateral_version(mut self, version: String) -> Self {
        self.report.collateral_version = version;
        self
    }

    /// Add extension
    pub fn extension(mut self, key: String, value: Vec<u8>) -> Self {
        self.report.extensions.insert(key, value);
        self
    }

    /// Build the report
    pub fn build(self) -> EnclaveReport {
        self.report
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_creation() {
        let measurement = [1u8; 32];
        let signer = [2u8; 32];
        let report_data = [3u8; 64];

        let report = EnclaveReport::new(measurement, signer, report_data, HardwareType::IntelSGX);

        assert_eq!(report.measurement, measurement);
        assert_eq!(report.signer, signer);
        assert_eq!(report.report_data, report_data);
    }

    #[test]
    fn test_nonce_verification() {
        let mut report_data = [0u8; 64];
        let nonce = [42u8; 32];
        report_data[..32].copy_from_slice(&nonce);

        let report = EnclaveReport::new([0u8; 32], [0u8; 32], report_data, HardwareType::IntelSGX);

        assert!(report.verify_nonce(&nonce));
        assert!(!report.verify_nonce(&[0u8; 32]));
    }

    #[test]
    fn test_builder() {
        let report = EnclaveReportBuilder::new(HardwareType::AmdSevSnp)
            .measurement([1u8; 32])
            .signer([2u8; 32])
            .product_id(100)
            .security_version(5)
            .tcb_status(TcbStatus::UpToDate)
            .build();

        assert_eq!(report.product_id, 100);
        assert_eq!(report.security_version, 5);
        assert_eq!(report.tcb_status, TcbStatus::UpToDate);
    }

    #[test]
    fn test_canonical_bytes() {
        let report = EnclaveReport::new([1u8; 32], [2u8; 32], [3u8; 64], HardwareType::IntelSGX);

        let bytes = report.to_canonical_bytes();
        assert!(bytes.len() >= 32 + 32 + 2 + 2 + 64 + 1 + 16);
    }

    #[cfg(feature = "full-sdk")]
    #[test]
    fn test_bincode_roundtrip_enclave_report_with_large_arrays() {
        let mut report =
            EnclaveReport::new([7u8; 32], [8u8; 32], [9u8; 64], HardwareType::IntelTdx);
        report.tcb_status = TcbStatus::UpToDate;
        report.platform_info = Some(PlatformInfo::IntelTdx(TdxPlatformInfo {
            td_attributes: 11,
            xfam: 22,
            mrtd: [1u8; 48],
            mrconfigid: [2u8; 48],
            mrowner: [3u8; 48],
            mrownerconfig: [4u8; 48],
            rtmrs: [[5u8; 48]; 4],
        }));

        let encoded = bincode::serialize(&report).expect("serialize report");
        let decoded: EnclaveReport = bincode::deserialize(&encoded).expect("deserialize report");
        assert_eq!(decoded.report_data, [9u8; 64]);
        assert!(matches!(
            decoded.platform_info,
            Some(PlatformInfo::IntelTdx(_))
        ));
    }

    #[cfg(feature = "full-sdk")]
    #[test]
    fn test_bincode_roundtrip_cca_platform_info_large_arrays() {
        let cca = CcaPlatformInfo {
            challenge: [1u8; 64],
            realm_measurements: [[2u8; 64]; 4],
            rpv: [3u8; 64],
            hash_algorithm: "sha256".to_string(),
            implementation_id: [4u8; 32],
        };
        let encoded = bincode::serialize(&cca).expect("serialize cca");
        let decoded: CcaPlatformInfo = bincode::deserialize(&encoded).expect("deserialize cca");
        assert_eq!(decoded.challenge, [1u8; 64]);
        assert_eq!(decoded.realm_measurements, [[2u8; 64]; 4]);
        assert_eq!(decoded.rpv, [3u8; 64]);
    }
}
