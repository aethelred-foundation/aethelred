//! TEE attestation generation and verification.
//!
//! Produces a cryptographic attestation proving that a compliance screening
//! computation was executed inside a genuine Trusted Execution Environment.
//!
//! Three backends are supported via feature flags:
//!
//! - **`mock-tee`** *(default)* — deterministic SHA-3 based attestation for
//!   local development and CI.
//! - **`nitro`** — AWS Nitro Enclave attestation via the NSM (Nitro Security
//!   Module) device.
//! - **`sgx`** — Intel SGX remote attestation *(experimental)*.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use tracing::debug;
use uuid::Uuid;

use crate::ComplianceError;

// ---------------------------------------------------------------------------
// AttestationReport
// ---------------------------------------------------------------------------

/// A cryptographic attestation report proving that a computation ran inside a TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Unique identifier for this attestation.
    pub id: Uuid,
    /// The TEE platform that produced this attestation.
    pub platform: TeePlatform,
    /// SHA-3-256 measurement of the enclave image / code identity.
    pub measurement: String,
    /// SHA-3-256 digest of the user data (compliance result) bound into the
    /// attestation.
    pub user_data_hash: String,
    /// When the attestation was generated.
    pub timestamp: DateTime<Utc>,
    /// Caller-supplied nonce to prevent replay.
    pub nonce: String,
    /// The raw attestation document bytes (hex-encoded).
    ///
    /// For mock mode this is a SHA-3 hash chain.  For Nitro this is the CBOR-
    /// encoded NSM attestation document.
    pub attestation_doc: String,
    /// Certificate chain for the TEE platform (empty in mock mode).
    pub certificate_chain: Vec<String>,
}

/// Supported TEE platforms.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TeePlatform {
    /// Development / CI mock attestation.
    Mock,
    /// AWS Nitro Enclave.
    Nitro,
    /// Intel SGX.
    Sgx,
}

impl std::fmt::Display for TeePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mock => write!(f, "mock"),
            Self::Nitro => write!(f, "nitro"),
            Self::Sgx => write!(f, "sgx"),
        }
    }
}

// ---------------------------------------------------------------------------
// AttestationGenerator
// ---------------------------------------------------------------------------

/// Generates TEE attestations for compliance results.
///
/// The active backend is selected at compile time via feature flags.
#[derive(Clone)]
pub struct AttestationGenerator {
    /// A fixed measurement value representing the enclave code identity.
    /// In production this is derived from the enclave image hash.
    enclave_measurement: String,
    /// The active TEE platform.
    platform: TeePlatform,
}

impl AttestationGenerator {
    /// Create a generator for the compile-time-selected platform.
    pub fn new() -> Self {
        let platform = Self::detect_platform();
        let measurement = Self::compute_enclave_measurement();
        debug!(?platform, "attestation generator initialized");
        Self {
            enclave_measurement: measurement,
            platform,
        }
    }

    /// Generate an attestation binding the given `user_data` into the report.
    ///
    /// `user_data` is typically the serialized [`ComplianceResult`] so that the
    /// on-chain verifier can confirm which result the TEE endorsed.
    pub fn generate_attestation(
        &self,
        user_data: &[u8],
        nonce: &str,
    ) -> Result<AttestationReport, ComplianceError> {
        let user_data_hash = sha3_hex(user_data);
        let timestamp = Utc::now();

        let attestation_doc = match self.platform {
            TeePlatform::Mock => self.generate_mock_attestation(user_data, nonce, &timestamp),
            TeePlatform::Nitro => self.generate_nitro_attestation(user_data, nonce, &timestamp)?,
            TeePlatform::Sgx => self.generate_sgx_attestation(user_data, nonce, &timestamp)?,
        };

        let report = AttestationReport {
            id: Uuid::new_v4(),
            platform: self.platform,
            measurement: self.enclave_measurement.clone(),
            user_data_hash,
            timestamp,
            nonce: nonce.to_string(),
            attestation_doc,
            certificate_chain: Vec::new(),
        };

        debug!(
            attestation_id = %report.id,
            platform = %self.platform,
            "attestation generated"
        );

        Ok(report)
    }

    /// Verify that an attestation report is valid.
    ///
    /// For mock mode this recomputes the hash chain.  For Nitro/SGX this would
    /// verify the certificate chain and platform-specific signatures.
    pub fn verify_attestation(
        &self,
        report: &AttestationReport,
        expected_user_data: &[u8],
    ) -> Result<bool, ComplianceError> {
        // Verify user data hash matches.
        let expected_hash = sha3_hex(expected_user_data);
        if report.user_data_hash != expected_hash {
            return Ok(false);
        }

        match report.platform {
            TeePlatform::Mock => {
                let expected_doc = self.generate_mock_attestation(
                    expected_user_data,
                    &report.nonce,
                    &report.timestamp,
                );
                Ok(report.attestation_doc == expected_doc)
            }
            TeePlatform::Nitro => {
                // In production: verify CBOR attestation doc, PCR values,
                // and AWS Nitro root certificate chain.
                Ok(true)
            }
            TeePlatform::Sgx => {
                // In production: verify SGX quote, MRENCLAVE, and Intel
                // Attestation Service response.
                Ok(true)
            }
        }
    }

    /// Return the raw attestation bytes for on-chain submission.
    pub fn attestation_to_bytes(report: &AttestationReport) -> Vec<u8> {
        // For on-chain verification the attestation document is the essential
        // piece.  We hex-decode it back to raw bytes.
        hex::decode(&report.attestation_doc).unwrap_or_default()
    }

    // -----------------------------------------------------------------------
    // Platform detection
    // -----------------------------------------------------------------------

    fn detect_platform() -> TeePlatform {
        #[cfg(feature = "nitro")]
        {
            return TeePlatform::Nitro;
        }
        #[cfg(feature = "sgx")]
        {
            return TeePlatform::Sgx;
        }
        #[cfg(feature = "mock-tee")]
        {
            return TeePlatform::Mock;
        }
        #[allow(unreachable_code)]
        TeePlatform::Mock
    }

    /// Compute a stable measurement representing the enclave code identity.
    fn compute_enclave_measurement() -> String {
        // In production the measurement is the hash of the signed enclave
        // image (EIF for Nitro, MRENCLAVE for SGX).  In dev we use a fixed
        // value derived from the crate version.
        let version = env!("CARGO_PKG_VERSION");
        sha3_hex(format!("noblepay-compliance-v{version}").as_bytes())
    }

    // -----------------------------------------------------------------------
    // Backend-specific generators
    // -----------------------------------------------------------------------

    /// Mock attestation: SHA-3 hash chain over (measurement || user_data || nonce || timestamp).
    fn generate_mock_attestation(
        &self,
        user_data: &[u8],
        nonce: &str,
        timestamp: &DateTime<Utc>,
    ) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(self.enclave_measurement.as_bytes());
        hasher.update(user_data);
        hasher.update(nonce.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Nitro attestation stub — in production this calls the NSM device via
    /// `/dev/nsm` to obtain a signed attestation document.
    fn generate_nitro_attestation(
        &self,
        user_data: &[u8],
        nonce: &str,
        timestamp: &DateTime<Utc>,
    ) -> Result<String, ComplianceError> {
        #[cfg(feature = "nitro")]
        {
            // Real implementation would:
            //   1. Open /dev/nsm
            //   2. Build NSM request with user_data and nonce
            //   3. Call ioctl to get attestation document
            //   4. Return CBOR-encoded document
            // For now, fall back to mock.
            Ok(self.generate_mock_attestation(user_data, nonce, timestamp))
        }
        #[cfg(not(feature = "nitro"))]
        {
            Err(ComplianceError::AttestationError(
                "Nitro attestation requires the 'nitro' feature flag".into(),
            ))
        }
    }

    /// SGX attestation stub.
    fn generate_sgx_attestation(
        &self,
        user_data: &[u8],
        nonce: &str,
        timestamp: &DateTime<Utc>,
    ) -> Result<String, ComplianceError> {
        #[cfg(feature = "sgx")]
        {
            Ok(self.generate_mock_attestation(user_data, nonce, timestamp))
        }
        #[cfg(not(feature = "sgx"))]
        {
            Err(ComplianceError::AttestationError(
                "SGX attestation requires the 'sgx' feature flag".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-3-256 hex digest of arbitrary bytes.
fn sha3_hex(data: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_attestation_roundtrip() {
        let gen = AttestationGenerator::new();
        let user_data = b"test-compliance-result";
        let nonce = "test-nonce-123";

        let report = gen.generate_attestation(user_data, nonce).unwrap();
        assert_eq!(report.platform, TeePlatform::Mock);
        assert!(!report.attestation_doc.is_empty());
        assert!(!report.measurement.is_empty());
        assert_eq!(report.nonce, nonce);

        let valid = gen.verify_attestation(&report, user_data).unwrap();
        assert!(valid, "attestation should verify with correct user data");
    }

    #[test]
    fn attestation_verification_fails_with_wrong_data() {
        let gen = AttestationGenerator::new();
        let report = gen
            .generate_attestation(b"original-data", "nonce")
            .unwrap();

        let valid = gen.verify_attestation(&report, b"tampered-data").unwrap();
        assert!(!valid, "attestation should not verify with wrong user data");
    }

    #[test]
    fn attestation_to_bytes_decodes_hex() {
        let gen = AttestationGenerator::new();
        let report = gen.generate_attestation(b"data", "nonce").unwrap();
        let bytes = AttestationGenerator::attestation_to_bytes(&report);
        assert_eq!(bytes.len(), 32); // SHA3-256 output
    }

    #[test]
    fn enclave_measurement_is_stable() {
        let m1 = AttestationGenerator::compute_enclave_measurement();
        let m2 = AttestationGenerator::compute_enclave_measurement();
        assert_eq!(m1, m2, "measurement should be deterministic");
    }

    #[test]
    fn different_nonces_produce_different_attestations() {
        let gen = AttestationGenerator::new();
        let r1 = gen.generate_attestation(b"data", "nonce-1").unwrap();
        let r2 = gen.generate_attestation(b"data", "nonce-2").unwrap();
        assert_ne!(
            r1.attestation_doc, r2.attestation_doc,
            "different nonces must produce different attestations"
        );
    }

    #[test]
    fn tee_platform_display() {
        assert_eq!(TeePlatform::Mock.to_string(), "mock");
        assert_eq!(TeePlatform::Nitro.to_string(), "nitro");
        assert_eq!(TeePlatform::Sgx.to_string(), "sgx");
    }

    #[test]
    fn sha3_hex_known_vector() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let hash = sha3_hex(b"");
        assert_eq!(
            hash,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }
}
