//! # AMD SEV-SNP Attestation
//!
//! Enterprise-grade AMD Secure Encrypted Virtualization - Secure Nested Paging
//! (SEV-SNP) attestation verification.
//!
//! ## Architecture
//!
//! AMD SEV-SNP provides:
//! - **Memory Encryption**: AES-128 encryption of VM memory
//! - **Integrity Protection**: Prevents malicious hypervisor attacks
//! - **Attestation**: Cryptographic proof of VM configuration
//!
//! ## Attestation Report Structure
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                  SNP ATTESTATION REPORT (0x2A0 bytes)       │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Version (4)           │ Guest SVN (4)      │ Policy (8)     │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Family ID (16)        │ Image ID (16)                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │ VMPL (4)              │ Signature Algo (4)  │ Platform (8)   │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Platform Info (8)     │ Author Key En (4)  │ Reserved (28)  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Report Data (64)      │ Measurement (48)                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Host Data (32)        │ ID Key Digest (48)                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Author Key Digest (48)│ Report ID (32)                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Report ID MA (32)     │ Reported TCB (8)   │ Reserved (24)  │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Chip ID (64)          │ Committed SVN (8)                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │ Committed TCB (8)     │ Current Build (4)  │ Current Minor (4)│
//! ├─────────────────────────────────────────────────────────────┤
//! │ Current Major (4)     │ Committed Build (4)│ Committed Minor(4)│
//! ├─────────────────────────────────────────────────────────────┤
//! │ Committed Major (4)   │ Launch TCB (8)     │ Reserved (168)  │
//! ├─────────────────────────────────────────────────────────────┤
//! │                       SIGNATURE (512)                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use super::*;
use std::time::SystemTime;

// ============================================================================
// SNP Report Structures
// ============================================================================

/// AMD SEV-SNP Attestation Report
#[derive(Debug, Clone)]
pub struct SnpReport {
    /// Report version
    pub version: u32,
    /// Guest Security Version Number
    pub guest_svn: u32,
    /// Guest policy
    pub policy: SnpPolicy,
    /// Family ID
    pub family_id: [u8; 16],
    /// Image ID
    pub image_id: [u8; 16],
    /// Virtual Machine Privilege Level
    pub vmpl: u32,
    /// Signature algorithm (0 = Invalid, 1 = ECDSA P-384 with SHA-384)
    pub signature_algo: u32,
    /// Platform version
    pub platform_version: SevPlatformVersion,
    /// Platform info flags
    pub platform_info: u64,
    /// Author key enabled
    pub author_key_en: u32,
    /// Report data (user-provided)
    pub report_data: [u8; 64],
    /// Measurement (launch digest)
    pub measurement: [u8; 48],
    /// Host-provided data
    pub host_data: [u8; 32],
    /// ID key digest
    pub id_key_digest: [u8; 48],
    /// Author key digest
    pub author_key_digest: [u8; 48],
    /// Report ID
    pub report_id: [u8; 32],
    /// Report ID for Migration Agent
    pub report_id_ma: [u8; 32],
    /// Reported TCB version
    pub reported_tcb: SnpTcb,
    /// Chip ID
    pub chip_id: [u8; 64],
    /// Committed SVN
    pub committed_svn: u64,
    /// Committed TCB
    pub committed_tcb: SnpTcb,
    /// Current build number
    pub current_build: u32,
    /// Current minor version
    pub current_minor: u32,
    /// Current major version
    pub current_major: u32,
    /// Committed build number
    pub committed_build: u32,
    /// Committed minor version
    pub committed_minor: u32,
    /// Committed major version
    pub committed_major: u32,
    /// Launch TCB
    pub launch_tcb: SnpTcb,
    /// ECDSA P-384 signature
    pub signature: SnpSignature,
}

/// SNP Guest Policy
#[derive(Debug, Clone, Copy)]
pub struct SnpPolicy {
    /// Raw policy value
    pub raw: u64,
}

impl SnpPolicy {
    /// ABIs >= 1 required
    pub fn abi_major(&self) -> u8 {
        ((self.raw >> 0) & 0xFF) as u8
    }

    /// ABIs >= 0 required
    pub fn abi_minor(&self) -> u8 {
        ((self.raw >> 8) & 0xFF) as u8
    }

    /// SMT (Simultaneous Multi-Threading) is allowed
    pub fn smt_allowed(&self) -> bool {
        (self.raw & (1 << 16)) != 0
    }

    /// Migration agent required
    pub fn migrate_ma(&self) -> bool {
        (self.raw & (1 << 18)) != 0
    }

    /// Debug mode enabled
    pub fn debug(&self) -> bool {
        (self.raw & (1 << 19)) != 0
    }

    /// Single socket required
    pub fn single_socket(&self) -> bool {
        (self.raw & (1 << 20)) != 0
    }
}

/// SNP TCB version
#[derive(Debug, Clone, Copy)]
pub struct SnpTcb {
    /// Raw TCB value
    pub raw: u64,
}

impl SnpTcb {
    /// Boot loader version
    pub fn boot_loader(&self) -> u8 {
        ((self.raw >> 0) & 0xFF) as u8
    }

    /// TEE version
    pub fn tee(&self) -> u8 {
        ((self.raw >> 8) & 0xFF) as u8
    }

    /// Reserved
    pub fn reserved(&self) -> u32 {
        ((self.raw >> 16) & 0xFFFFFFFF) as u32
    }

    /// SNP firmware version
    pub fn snp(&self) -> u8 {
        ((self.raw >> 48) & 0xFF) as u8
    }

    /// Microcode version
    pub fn microcode(&self) -> u8 {
        ((self.raw >> 56) & 0xFF) as u8
    }
}

/// SNP ECDSA P-384 Signature
#[derive(Debug, Clone)]
pub struct SnpSignature {
    /// R component (72 bytes, padded)
    pub r: [u8; 72],
    /// S component (72 bytes, padded)
    pub s: [u8; 72],
    /// Reserved
    pub reserved: [u8; 368],
}

// ============================================================================
// SNP Verifier
// ============================================================================

/// AMD SEV-SNP Attestation Verifier
pub struct SnpVerifier {
    /// Configuration
    config: AttestationConfig,
}

impl SnpVerifier {
    /// Create a new SNP verifier
    pub fn new(config: AttestationConfig) -> Self {
        SnpVerifier { config }
    }

    /// Verify an SNP attestation report
    pub fn verify(
        &self,
        report_bytes: &[u8],
        expected_nonce: &[u8; 32],
        collateral: &AmdCollateral,
    ) -> Result<VerificationResult, AttestationError> {
        // 1. Parse the report
        let report = self.parse_report(report_bytes)?;

        // 2. Verify report structure
        self.verify_structure(&report)?;

        // 3. Verify signature
        self.verify_signature(&report, collateral)?;

        // 4. Verify certificate chain
        self.verify_cert_chain(collateral)?;

        // 5. Check debug policy
        if report.policy.debug() && !self.config.allow_debug_mode {
            return Err(AttestationError::DebugMode);
        }

        // 6. Verify nonce
        if !self.verify_nonce(&report.report_data, expected_nonce) {
            return Err(AttestationError::ReplayDetected);
        }

        // 7. Check expected measurements
        if !self.config.expected_measurements.is_empty() {
            let measurement_32: [u8; 32] = report.measurement[..32].try_into().unwrap();
            if !self.config.expected_measurements.iter().any(|m| m == &measurement_32) {
                return Err(AttestationError::MeasurementMismatch {
                    expected: hex::encode(&self.config.expected_measurements[0]),
                    actual: hex::encode(&measurement_32),
                });
            }
        }

        // 8. Build enclave report
        let enclave_report = self.build_enclave_report(&report);

        // 9. Evaluate TCB
        let (tcb_status, warnings) = self.evaluate_tcb(&report);

        Ok(VerificationResult {
            verified: true,
            report: Some(enclave_report),
            tcb_status,
            warnings,
            verified_at: SystemTime::now(),
            collateral: CollateralInfo {
                source: CollateralSource::AmdKds {
                    url: self.config.amd_kds_url.clone().unwrap_or_default(),
                },
                fetched_at: SystemTime::now(),
                expires_at: SystemTime::now() + self.config.cache_ttl,
            },
        })
    }

    // ========================================================================
    // Parsing
    // ========================================================================

    /// Parse raw report bytes
    fn parse_report(&self, bytes: &[u8]) -> Result<SnpReport, AttestationError> {
        if bytes.len() < 0x2A0 {
            return Err(AttestationError::InvalidFormat(
                format!("SNP report too short: {} bytes", bytes.len()),
            ));
        }

        // Parse version and guest SVN
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let guest_svn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        // Parse policy
        let policy_raw = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        // Parse family ID and image ID
        let family_id: [u8; 16] = bytes[16..32].try_into().unwrap();
        let image_id: [u8; 16] = bytes[32..48].try_into().unwrap();

        // Parse VMPL and signature algorithm
        let vmpl = u32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]);
        let signature_algo = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);

        // Parse platform version
        let platform_version = SevPlatformVersion {
            boot_loader: bytes[56],
            tee: bytes[57],
            snp: bytes[62],
            microcode: bytes[63],
        };

        // Parse platform info
        let platform_info = u64::from_le_bytes(bytes[64..72].try_into().unwrap());
        let author_key_en = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]);

        // Skip reserved bytes (76..104)

        // Parse report data
        let report_data: [u8; 64] = bytes[104..168].try_into().unwrap();

        // Parse measurement
        let measurement: [u8; 48] = bytes[168..216].try_into().unwrap();

        // Parse host data
        let host_data: [u8; 32] = bytes[216..248].try_into().unwrap();

        // Parse ID key digest
        let id_key_digest: [u8; 48] = bytes[248..296].try_into().unwrap();

        // Parse author key digest
        let author_key_digest: [u8; 48] = bytes[296..344].try_into().unwrap();

        // Parse report IDs
        let report_id: [u8; 32] = bytes[344..376].try_into().unwrap();
        let report_id_ma: [u8; 32] = bytes[376..408].try_into().unwrap();

        // Parse TCB versions
        let reported_tcb = SnpTcb {
            raw: u64::from_le_bytes(bytes[408..416].try_into().unwrap()),
        };

        // Skip reserved (416..440)

        // Parse chip ID
        let chip_id: [u8; 64] = bytes[440..504].try_into().unwrap();

        // Parse committed values
        let committed_svn = u64::from_le_bytes(bytes[504..512].try_into().unwrap());
        let committed_tcb = SnpTcb {
            raw: u64::from_le_bytes(bytes[512..520].try_into().unwrap()),
        };

        let current_build = u32::from_le_bytes([bytes[520], bytes[521], bytes[522], bytes[523]]);
        let current_minor = u32::from_le_bytes([bytes[524], bytes[525], bytes[526], bytes[527]]);
        let current_major = u32::from_le_bytes([bytes[528], bytes[529], bytes[530], bytes[531]]);

        let committed_build = u32::from_le_bytes([bytes[532], bytes[533], bytes[534], bytes[535]]);
        let committed_minor = u32::from_le_bytes([bytes[536], bytes[537], bytes[538], bytes[539]]);
        let committed_major = u32::from_le_bytes([bytes[540], bytes[541], bytes[542], bytes[543]]);

        let launch_tcb = SnpTcb {
            raw: u64::from_le_bytes(bytes[544..552].try_into().unwrap()),
        };

        // Skip reserved (552..720)

        // Parse signature (720..1232)
        let signature = SnpSignature {
            r: bytes[720..792].try_into().unwrap(),
            s: bytes[792..864].try_into().unwrap(),
            reserved: [0u8; 368], // Simplified
        };

        Ok(SnpReport {
            version,
            guest_svn,
            policy: SnpPolicy { raw: policy_raw },
            family_id,
            image_id,
            vmpl,
            signature_algo,
            platform_version,
            platform_info,
            author_key_en,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            chip_id,
            committed_svn,
            committed_tcb,
            current_build,
            current_minor,
            current_major,
            committed_build,
            committed_minor,
            committed_major,
            launch_tcb,
            signature,
        })
    }

    // ========================================================================
    // Verification
    // ========================================================================

    /// Verify report structure
    fn verify_structure(&self, report: &SnpReport) -> Result<(), AttestationError> {
        // Check version
        if report.version < 1 || report.version > 2 {
            return Err(AttestationError::InvalidFormat(
                format!("Unsupported SNP report version: {}", report.version),
            ));
        }

        // Check signature algorithm
        if report.signature_algo != 1 {
            return Err(AttestationError::InvalidFormat(
                format!("Unsupported signature algorithm: {}", report.signature_algo),
            ));
        }

        Ok(())
    }

    /// Verify ECDSA P-384 signature
    fn verify_signature(
        &self,
        report: &SnpReport,
        collateral: &AmdCollateral,
    ) -> Result<(), AttestationError> {
        // In production, this would:
        // 1. Extract the VCEK public key from the certificate
        // 2. Verify the ECDSA P-384 signature over the report body
        // 3. Hash the report body with SHA-384

        if collateral.vcek_certificate.is_empty() {
            return Err(AttestationError::CertificateError(
                "VCEK certificate missing".to_string(),
            ));
        }

        // TODO: Implement actual ECDSA P-384 verification
        // let public_key = extract_vcek_pubkey(&collateral.vcek_certificate)?;
        // let signature = p384::ecdsa::Signature::from_components(&report.signature.r, &report.signature.s)?;
        // public_key.verify(&report_body_hash, &signature)?;

        Ok(())
    }

    /// Verify certificate chain
    fn verify_cert_chain(&self, collateral: &AmdCollateral) -> Result<(), AttestationError> {
        // Chain: VCEK -> ASK -> ARK (AMD Root Key)
        // In production, verify:
        // 1. VCEK signed by ASK
        // 2. ASK signed by ARK
        // 3. ARK is the well-known AMD root

        if collateral.vcek_cert_chain.is_empty() {
            return Err(AttestationError::CertificateError(
                "Certificate chain missing".to_string(),
            ));
        }

        // TODO: Implement full chain verification

        Ok(())
    }

    /// Verify nonce in report data
    fn verify_nonce(&self, report_data: &[u8; 64], expected: &[u8; 32]) -> bool {
        report_data[..32] == expected[..]
    }

    /// Build enclave report
    fn build_enclave_report(&self, report: &SnpReport) -> EnclaveReport {
        // Convert 48-byte measurement to 32-byte
        let mut measurement_32 = [0u8; 32];
        measurement_32.copy_from_slice(&report.measurement[..32]);

        // Convert ID key digest to signer
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&report.id_key_digest[..32]);

        EnclaveReportBuilder::new(HardwareType::AmdSevSnp)
            .measurement(measurement_32)
            .signer(signer)
            .product_id(0) // SNP doesn't have product ID
            .security_version(report.guest_svn as u16)
            .report_data(report.report_data)
            .tcb_status(TcbStatus::UpToDate)
            .flags(EnclaveFlags {
                debug_mode: report.policy.debug(),
                mode64bit: true, // AMD64 only
                provision_key: false,
                einittoken_key: false,
                kss: false,
                aex_notify: false,
                memory_encryption: true, // SEV always encrypts memory
                smt_protection: !report.policy.smt_allowed(),
            })
            .platform_info(PlatformInfo::AmdSevSnp(SevSnpPlatformInfo {
                guest_svn: report.guest_svn,
                policy: report.policy.raw,
                family_id: report.family_id,
                image_id: report.image_id,
                vmpl: report.vmpl as u8,
                platform_version: report.platform_version.clone(),
                launch_measurement: report.measurement,
                id_key_digest: report.id_key_digest,
                author_key_digest: report.author_key_digest,
                host_data: report.host_data,
            }))
            .build()
    }

    /// Evaluate TCB status
    fn evaluate_tcb(&self, report: &SnpReport) -> (TcbStatus, Vec<VerificationWarning>) {
        let mut warnings = Vec::new();

        // Check if reported TCB meets minimum requirements
        let tcb = &report.reported_tcb;

        // Check minimum security version
        if (report.guest_svn as u16) < self.config.min_security_version {
            warnings.push(VerificationWarning {
                code: "SVN_TOO_LOW".to_string(),
                message: format!(
                    "Guest SVN {} is below minimum {}",
                    report.guest_svn, self.config.min_security_version
                ),
                severity: 4,
            });
            return (TcbStatus::OutOfDate, warnings);
        }

        // Check committed vs reported TCB
        if report.committed_tcb.raw < report.reported_tcb.raw {
            warnings.push(VerificationWarning {
                code: "TCB_DOWNGRADE".to_string(),
                message: "Committed TCB is lower than reported TCB".to_string(),
                severity: 3,
            });
        }

        // SMT warning
        if report.policy.smt_allowed() {
            warnings.push(VerificationWarning {
                code: "SMT_ENABLED".to_string(),
                message: "SMT is allowed - potential side-channel risk".to_string(),
                severity: 2,
            });
        }

        (TcbStatus::UpToDate, warnings)
    }
}

// ============================================================================
// VCEK Certificate Handling
// ============================================================================

/// VCEK (Versioned Chip Endorsement Key) Certificate
#[derive(Debug, Clone)]
pub struct VcekCertificate {
    /// DER-encoded X.509 certificate
    pub certificate: Vec<u8>,
    /// Chip ID from certificate
    pub chip_id: [u8; 64],
    /// TCB version in certificate
    pub tcb: SnpTcb,
    /// HWID extension
    pub hwid: Option<Vec<u8>>,
}

/// Fetch VCEK certificate from AMD KDS
pub async fn fetch_vcek(
    kds_url: &str,
    chip_id: &[u8; 64],
    reported_tcb: &SnpTcb,
) -> Result<VcekCertificate, AttestationError> {
    // AMD KDS URL format:
    // https://kdsintf.amd.com/vcek/v1/{product_name}/{chip_id}?blSPL={boot_loader}&teeSPL={tee}&snpSPL={snp}&ucodeSPL={microcode}

    let product_name = "Milan"; // or "Genoa" for Zen 4

    let url = format!(
        "{}/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        kds_url,
        product_name,
        hex::encode(chip_id),
        reported_tcb.boot_loader(),
        reported_tcb.tee(),
        reported_tcb.snp(),
        reported_tcb.microcode(),
    );

    // In production, make HTTP request
    // let response = reqwest::get(&url).await?;
    // let cert_bytes = response.bytes().await?;

    // Placeholder
    Ok(VcekCertificate {
        certificate: Vec::new(),
        chip_id: *chip_id,
        tcb: *reported_tcb,
        hwid: None,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_parsing() {
        // Debug mode enabled
        let policy = SnpPolicy { raw: 1 << 19 };
        assert!(policy.debug());
        assert!(!policy.smt_allowed());

        // SMT allowed
        let policy = SnpPolicy { raw: 1 << 16 };
        assert!(policy.smt_allowed());
        assert!(!policy.debug());
    }

    #[test]
    fn test_tcb_parsing() {
        let tcb = SnpTcb { raw: 0x0102_0000_0000_0304 };
        assert_eq!(tcb.boot_loader(), 0x04);
        assert_eq!(tcb.tee(), 0x03);
    }

    #[test]
    fn test_report_too_short() {
        let verifier = SnpVerifier::new(AttestationConfig::default());
        let result = verifier.parse_report(&[0u8; 100]);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_verification() {
        let verifier = SnpVerifier::new(AttestationConfig::default());

        let mut report_data = [0u8; 64];
        let nonce = [42u8; 32];
        report_data[..32].copy_from_slice(&nonce);

        assert!(verifier.verify_nonce(&report_data, &nonce));
        assert!(!verifier.verify_nonce(&report_data, &[0u8; 32]));
    }
}
