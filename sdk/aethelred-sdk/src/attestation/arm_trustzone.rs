//! # ARM TrustZone & CCA Attestation
//!
//! Enterprise-grade ARM TrustZone and Confidential Compute Architecture (CCA)
//! attestation verification.
//!
//! ## Architecture
//!
//! ARM provides two security architectures:
//!
//! ### TrustZone (Older)
//! - Secure World / Normal World separation
//! - Hardware-enforced isolation
//! - Used in mobile, IoT, and some server deployments
//!
//! ### CCA (Confidential Compute Architecture)
//! - Realm Management Extension (RME)
//! - Dynamic realm creation
//! - Cryptographic attestation
//!
//! ## CCA Attestation Token Structure
//!
//! ```text
//! CCA Platform Token (CBOR/COSE)
//! ├── Platform Claims
//! │   ├── Challenge
//! │   ├── Implementation ID
//! │   ├── Instance ID
//! │   ├── Configuration
//! │   ├── Lifecycle State
//! │   ├── Platform Hash Algorithm
//! │   └── Boot Seed
//! │
//! └── Realm Token (nested)
//!     ├── Realm Challenge
//!     ├── Realm Personalization Value
//!     ├── Initial Measurements (RIM)
//!     ├── Extensible Measurements (REM)
//!     ├── Realm Hash Algorithm
//!     └── Realm Public Key Hash
//! ```

use super::*;
use std::time::SystemTime;

// ============================================================================
// ARM CCA Structures
// ============================================================================

/// ARM CCA Platform Token
#[derive(Debug, Clone)]
pub struct CcaPlatformToken {
    /// Platform claims
    pub platform: CcaPlatformClaims,
    /// Nested realm token
    pub realm: CcaRealmToken,
    /// COSE signature
    pub signature: Vec<u8>,
}

/// CCA Platform Claims
#[derive(Debug, Clone)]
pub struct CcaPlatformClaims {
    /// Challenge (from verifier)
    pub challenge: [u8; 64],
    /// Implementation ID (identifies the RMM implementation)
    pub implementation_id: [u8; 32],
    /// Instance ID (unique per platform)
    pub instance_id: [u8; 33],
    /// Platform configuration
    pub config: [u8; 32],
    /// Lifecycle state
    pub lifecycle: CcaLifecycleState,
    /// Hash algorithm ID
    pub hash_algo_id: String,
    /// Boot seed (random per boot)
    pub boot_seed: [u8; 32],
    /// Security state
    pub security_state: CcaSecurityState,
}

/// CCA Realm Token
#[derive(Debug, Clone)]
pub struct CcaRealmToken {
    /// Realm challenge
    pub challenge: [u8; 64],
    /// Realm Personalization Value (RPV)
    pub personalization_value: [u8; 64],
    /// Initial measurements (RIM)
    pub initial_measurements: [[u8; 64]; 4],
    /// Extensible measurements (REM)
    pub extensible_measurements: [[u8; 64]; 4],
    /// Hash algorithm
    pub hash_algo_id: String,
    /// Realm public key hash
    pub public_key_hash: [u8; 64],
    /// COSE signature
    pub signature: Vec<u8>,
}

/// CCA Lifecycle State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcaLifecycleState {
    /// Unknown state
    Unknown = 0x0000,
    /// Assembly and Test
    AssemblyAndTest = 0x1000,
    /// Platform Security Lifecycle Enabled - Rotatable
    PsaRotEnabled = 0x2000,
    /// Platform Security Lifecycle Enabled
    PsaRotProvisioning = 0x2001,
    /// Secured
    Secured = 0x3000,
    /// Non-PSA Lifecycle
    NonPsaRot = 0x4000,
    /// Recoverable Debug Enabled
    RecoverableDebug = 0x5000,
    /// Decommissioned
    Decommissioned = 0x6000,
}

/// CCA Security State
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcaSecurityState {
    /// Debug enabled
    Debug,
    /// Secure state
    Secure,
}

// ============================================================================
// TrustZone Structures
// ============================================================================

/// ARM TrustZone Attestation Token
#[derive(Debug, Clone)]
pub struct TrustZoneToken {
    /// Token type
    pub token_type: TrustZoneTokenType,
    /// Claims
    pub claims: TrustZoneClaims,
    /// Signature
    pub signature: Vec<u8>,
}

/// TrustZone Token Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustZoneTokenType {
    /// Platform Security Architecture (PSA) token
    Psa,
    /// OP-TEE specific token
    OpTee,
    /// Vendor-specific token
    Vendor,
}

/// TrustZone Claims
#[derive(Debug, Clone)]
pub struct TrustZoneClaims {
    /// Instance ID
    pub instance_id: Vec<u8>,
    /// Implementation ID
    pub implementation_id: [u8; 32],
    /// Boot seed
    pub boot_seed: [u8; 32],
    /// Hardware version
    pub hw_version: String,
    /// Software components
    pub sw_components: Vec<SwComponent>,
    /// Security lifecycle
    pub lifecycle: CcaLifecycleState,
    /// Client ID
    pub client_id: i32,
    /// Profile ID
    pub profile_id: String,
}

/// Software Component measurement
#[derive(Debug, Clone)]
pub struct SwComponent {
    /// Component type
    pub measurement_type: String,
    /// Measurement value
    pub measurement_value: Vec<u8>,
    /// Signer ID
    pub signer_id: Option<Vec<u8>>,
    /// Version
    pub version: Option<String>,
}

// ============================================================================
// ARM Verifier
// ============================================================================

/// ARM TrustZone/CCA Attestation Verifier
pub struct ArmVerifier {
    /// Configuration
    config: AttestationConfig,
}

impl ArmVerifier {
    /// Create a new ARM verifier
    pub fn new(config: AttestationConfig) -> Self {
        ArmVerifier { config }
    }

    /// Verify CCA attestation token
    pub fn verify_cca(
        &self,
        token: &[u8],
        expected_nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        // 1. Parse CCA token
        let cca_token = self.parse_cca_token(token)?;

        // 2. Verify platform signature
        self.verify_platform_signature(&cca_token)?;

        // 3. Verify realm signature
        self.verify_realm_signature(&cca_token)?;

        // 4. Verify challenge/nonce
        if !self.verify_challenge(&cca_token.realm.challenge, expected_nonce) {
            return Err(AttestationError::ReplayDetected);
        }

        // 5. Check lifecycle state
        self.check_lifecycle(&cca_token.platform)?;

        // 6. Check security state
        if cca_token.platform.security_state == CcaSecurityState::Debug
            && !self.config.allow_debug_mode
        {
            return Err(AttestationError::DebugMode);
        }

        // 7. Verify measurements
        self.verify_measurements(&cca_token)?;

        // 8. Build enclave report
        let enclave_report = self.build_cca_report(&cca_token);

        // 9. Generate warnings
        let warnings = self.generate_cca_warnings(&cca_token);

        Ok(VerificationResult {
            verified: true,
            report: Some(enclave_report),
            tcb_status: TcbStatus::UpToDate,
            warnings,
            verified_at: SystemTime::now(),
            collateral: CollateralInfo {
                source: CollateralSource::LocalCache,
                fetched_at: SystemTime::now(),
                expires_at: SystemTime::now() + self.config.cache_ttl,
            },
        })
    }

    /// Verify TrustZone PSA attestation token
    pub fn verify_psa(
        &self,
        token: &[u8],
        expected_nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        // 1. Parse PSA token
        let tz_token = self.parse_psa_token(token)?;

        // 2. Verify signature
        self.verify_tz_signature(&tz_token)?;

        // 3. Check nonce (in boot_seed or challenge)
        if tz_token.claims.boot_seed[..32] != expected_nonce[..] {
            return Err(AttestationError::ReplayDetected);
        }

        // 4. Check lifecycle
        if tz_token.claims.lifecycle == CcaLifecycleState::Decommissioned {
            return Err(AttestationError::ArmTrustZone(
                "Platform is decommissioned".to_string(),
            ));
        }

        // 5. Build report
        let enclave_report = self.build_tz_report(&tz_token);

        Ok(VerificationResult {
            verified: true,
            report: Some(enclave_report),
            tcb_status: TcbStatus::UpToDate,
            warnings: Vec::new(),
            verified_at: SystemTime::now(),
            collateral: CollateralInfo {
                source: CollateralSource::LocalCache,
                fetched_at: SystemTime::now(),
                expires_at: SystemTime::now() + self.config.cache_ttl,
            },
        })
    }

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parse CCA token (CBOR/COSE format)
    fn parse_cca_token(&self, token: &[u8]) -> Result<CcaPlatformToken, AttestationError> {
        if token.len() < 16 {
            return Err(AttestationError::InvalidFormat(
                "CCA token too short".to_string(),
            ));
        }

        // Check for CCA magic
        if &token[0..4] != b"CCA\x00" {
            return Err(AttestationError::InvalidFormat(
                "Invalid CCA token magic".to_string(),
            ));
        }

        // In production, use CBOR parser
        // For now, return placeholder
        Ok(CcaPlatformToken {
            platform: CcaPlatformClaims {
                challenge: [0u8; 64],
                implementation_id: [0u8; 32],
                instance_id: [0u8; 33],
                config: [0u8; 32],
                lifecycle: CcaLifecycleState::Secured,
                hash_algo_id: "sha-384".to_string(),
                boot_seed: [0u8; 32],
                security_state: CcaSecurityState::Secure,
            },
            realm: CcaRealmToken {
                challenge: [0u8; 64],
                personalization_value: [0u8; 64],
                initial_measurements: [[0u8; 64]; 4],
                extensible_measurements: [[0u8; 64]; 4],
                hash_algo_id: "sha-384".to_string(),
                public_key_hash: [0u8; 64],
                signature: Vec::new(),
            },
            signature: Vec::new(),
        })
    }

    /// Parse PSA attestation token
    fn parse_psa_token(&self, token: &[u8]) -> Result<TrustZoneToken, AttestationError> {
        if token.is_empty() {
            return Err(AttestationError::InvalidFormat(
                "Empty PSA token".to_string(),
            ));
        }

        // PSA tokens are CBOR-encoded
        // In production, use proper CBOR parsing

        Ok(TrustZoneToken {
            token_type: TrustZoneTokenType::Psa,
            claims: TrustZoneClaims {
                instance_id: Vec::new(),
                implementation_id: [0u8; 32],
                boot_seed: [0u8; 32],
                hw_version: String::new(),
                sw_components: Vec::new(),
                lifecycle: CcaLifecycleState::Secured,
                client_id: 0,
                profile_id: "http://arm.com/psa/2.0.0".to_string(),
            },
            signature: Vec::new(),
        })
    }

    // ========================================================================
    // Verification
    // ========================================================================

    /// Verify platform signature
    fn verify_platform_signature(&self, token: &CcaPlatformToken) -> Result<(), AttestationError> {
        // Platform token is signed by the RMM (Realm Management Monitor)
        // using ECDSA P-384 or ECDSA P-256

        if token.signature.is_empty() {
            return Err(AttestationError::InvalidSignature);
        }

        // TODO: Implement actual signature verification
        Ok(())
    }

    /// Verify realm signature
    fn verify_realm_signature(&self, token: &CcaPlatformToken) -> Result<(), AttestationError> {
        // Realm token is signed by the realm's attestation key

        if token.realm.signature.is_empty() {
            return Err(AttestationError::InvalidSignature);
        }

        // TODO: Implement actual signature verification
        Ok(())
    }

    /// Verify TrustZone signature
    fn verify_tz_signature(&self, token: &TrustZoneToken) -> Result<(), AttestationError> {
        if token.signature.is_empty() {
            return Err(AttestationError::InvalidSignature);
        }

        // TODO: Implement actual signature verification
        Ok(())
    }

    /// Verify challenge
    fn verify_challenge(&self, challenge: &[u8; 64], expected: &[u8; 32]) -> bool {
        // Challenge may be in first or last 32 bytes
        challenge[..32] == expected[..] || challenge[32..64] == expected[..]
    }

    /// Check lifecycle state
    fn check_lifecycle(&self, platform: &CcaPlatformClaims) -> Result<(), AttestationError> {
        match platform.lifecycle {
            CcaLifecycleState::Secured => Ok(()),
            CcaLifecycleState::Decommissioned => Err(AttestationError::ArmTrustZone(
                "Platform is decommissioned".to_string(),
            )),
            CcaLifecycleState::RecoverableDebug => {
                if !self.config.allow_debug_mode {
                    Err(AttestationError::DebugMode)
                } else {
                    Ok(())
                }
            }
            _ => {
                // Other states might be acceptable depending on use case
                Ok(())
            }
        }
    }

    /// Verify measurements
    fn verify_measurements(&self, token: &CcaPlatformToken) -> Result<(), AttestationError> {
        if self.config.expected_measurements.is_empty() {
            return Ok(());
        }

        // Check RIM[0] (initial measurement)
        let rim0 = &token.realm.initial_measurements[0];
        let mut rim0_32 = [0u8; 32];
        rim0_32.copy_from_slice(&rim0[..32]);

        if !self.config.expected_measurements.iter().any(|m| m == &rim0_32) {
            return Err(AttestationError::MeasurementMismatch {
                expected: hex::encode(&self.config.expected_measurements[0]),
                actual: hex::encode(&rim0_32),
            });
        }

        Ok(())
    }

    // ========================================================================
    // Report Building
    // ========================================================================

    /// Build enclave report from CCA token
    fn build_cca_report(&self, token: &CcaPlatformToken) -> EnclaveReport {
        // Use RIM[0] as measurement
        let mut measurement = [0u8; 32];
        measurement.copy_from_slice(&token.realm.initial_measurements[0][..32]);

        // Use implementation ID as signer
        let signer = token.platform.implementation_id;

        // Build report data
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&token.realm.challenge);

        EnclaveReportBuilder::new(HardwareType::ArmCca)
            .measurement(measurement)
            .signer(signer)
            .report_data(report_data)
            .tcb_status(TcbStatus::UpToDate)
            .flags(EnclaveFlags {
                debug_mode: token.platform.security_state == CcaSecurityState::Debug,
                mode64bit: true,
                provision_key: false,
                einittoken_key: false,
                kss: false,
                aex_notify: false,
                memory_encryption: true,
                smt_protection: true,
            })
            .platform_info(PlatformInfo::ArmCca(CcaPlatformInfo {
                challenge: token.realm.challenge,
                realm_measurements: token.realm.initial_measurements,
                rpv: token.realm.personalization_value,
                hash_algorithm: token.realm.hash_algo_id.clone(),
                implementation_id: token.platform.implementation_id,
            }))
            .build()
    }

    /// Build enclave report from TrustZone token
    fn build_tz_report(&self, token: &TrustZoneToken) -> EnclaveReport {
        // Use first SW component measurement
        let mut measurement = [0u8; 32];
        if let Some(comp) = token.claims.sw_components.first() {
            let len = std::cmp::min(comp.measurement_value.len(), 32);
            measurement[..len].copy_from_slice(&comp.measurement_value[..len]);
        }

        let signer = token.claims.implementation_id;

        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&token.claims.boot_seed);

        EnclaveReportBuilder::new(HardwareType::ArmTrustZone)
            .measurement(measurement)
            .signer(signer)
            .report_data(report_data)
            .tcb_status(TcbStatus::UpToDate)
            .flags(EnclaveFlags {
                debug_mode: false,
                mode64bit: true,
                provision_key: false,
                einittoken_key: false,
                kss: false,
                aex_notify: false,
                memory_encryption: false, // Basic TZ doesn't encrypt all memory
                smt_protection: false,
            })
            .build()
    }

    /// Generate warnings for CCA token
    fn generate_cca_warnings(&self, token: &CcaPlatformToken) -> Vec<VerificationWarning> {
        let mut warnings = Vec::new();

        // Check lifecycle state
        match token.platform.lifecycle {
            CcaLifecycleState::PsaRotProvisioning => {
                warnings.push(VerificationWarning {
                    code: "PROVISIONING_STATE".to_string(),
                    message: "Platform is in provisioning state".to_string(),
                    severity: 2,
                });
            }
            CcaLifecycleState::RecoverableDebug => {
                warnings.push(VerificationWarning {
                    code: "DEBUG_STATE".to_string(),
                    message: "Platform has recoverable debug enabled".to_string(),
                    severity: 3,
                });
            }
            _ => {}
        }

        // Check hash algorithm
        if token.realm.hash_algo_id != "sha-384" && token.realm.hash_algo_id != "sha-512" {
            warnings.push(VerificationWarning {
                code: "WEAK_HASH".to_string(),
                message: format!(
                    "Non-standard hash algorithm: {}",
                    token.realm.hash_algo_id
                ),
                severity: 2,
            });
        }

        warnings
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_state() {
        assert_eq!(CcaLifecycleState::Secured as u32, 0x3000);
        assert_eq!(CcaLifecycleState::Decommissioned as u32, 0x6000);
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = ArmVerifier::new(AttestationConfig::default());
        assert!(verifier.config.allow_debug_mode == false);
    }

    #[test]
    fn test_empty_token() {
        let verifier = ArmVerifier::new(AttestationConfig::default());
        let result = verifier.parse_psa_token(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_verification() {
        let verifier = ArmVerifier::new(AttestationConfig::default());

        let mut challenge = [0u8; 64];
        let nonce = [42u8; 32];
        challenge[..32].copy_from_slice(&nonce);

        assert!(verifier.verify_challenge(&challenge, &nonce));

        let mut challenge2 = [0u8; 64];
        challenge2[32..].copy_from_slice(&nonce);
        assert!(verifier.verify_challenge(&challenge2, &nonce));
    }
}
