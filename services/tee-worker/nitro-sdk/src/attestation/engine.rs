//! # Attestation Engine
//!
//! The unified verification engine that handles all TEE attestation types.
//! This is the "brain" of the attestation module - it routes quotes to the
//! appropriate platform verifier and produces unified EnclaveReport outputs.

use super::*;
use crate::compliance::Jurisdiction;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

// ============================================================================
// Attestation Engine
// ============================================================================

/// The unified attestation verification engine
///
/// # Architecture
///
/// The engine provides a single entry point for verifying attestation quotes
/// from any supported TEE platform. It:
///
/// 1. Auto-detects the quote format (SGX, SEV, Nitro, etc.)
/// 2. Routes to the appropriate platform verifier
/// 3. Fetches and caches attestation collateral
/// 4. Produces a unified EnclaveReport
///
/// # Example
///
/// ```rust,ignore
/// let engine = AttestationEngine::new(AttestationConfig::production());
///
/// // Verify any quote type
/// let result = engine.verify(&quote_bytes, &nonce)?;
///
/// if result.verified {
///     let report = result.report.unwrap();
///     println!("Enclave: {}", hex::encode(&report.measurement));
///     println!("TCB: {:?}", report.tcb_status);
/// }
/// ```
pub struct AttestationEngine {
    /// Configuration
    config: AttestationConfig,

    /// Collateral cache
    cache: Arc<RwLock<CollateralCache>>,

    /// Intel SGX verifier
    sgx_verifier: Option<IntelSgxVerifier>,

    /// AMD SEV verifier
    sev_verifier: Option<AmdSevVerifier>,

    /// AWS Nitro verifier
    nitro_verifier: Option<AwsNitroVerifier>,

    /// ARM TrustZone verifier
    trustzone_verifier: Option<ArmTrustZoneVerifier>,

    /// Geo-location resolver
    geo_resolver: Option<GeoResolver>,

    /// Metrics collector
    metrics: AttestationMetrics,
}

impl AttestationEngine {
    /// Create a new attestation engine with configuration
    pub fn new(config: AttestationConfig) -> Self {
        AttestationEngine {
            config: config.clone(),
            cache: Arc::new(RwLock::new(CollateralCache::new(config.cache_ttl))),
            sgx_verifier: Some(IntelSgxVerifier::new(&config)),
            sev_verifier: Some(AmdSevVerifier::new(&config)),
            nitro_verifier: Some(AwsNitroVerifier::new(&config)),
            trustzone_verifier: Some(ArmTrustZoneVerifier::new(&config)),
            geo_resolver: Some(GeoResolver::new()),
            metrics: AttestationMetrics::new(),
        }
    }

    /// Create engine with default configuration
    pub fn default() -> Self {
        Self::new(AttestationConfig::default())
    }

    /// Create engine for production use
    pub fn production() -> Self {
        Self::new(AttestationConfig::production())
    }

    /// Create engine for development/testing
    pub fn development() -> Self {
        Self::new(AttestationConfig::development())
    }

    // ========================================================================
    // Primary Verification API
    // ========================================================================

    /// Verify an attestation quote
    ///
    /// This is the primary entry point. It auto-detects the quote type
    /// and routes to the appropriate verifier.
    ///
    /// # Arguments
    ///
    /// * `quote` - Raw attestation quote bytes
    /// * `nonce` - Expected nonce in report data (for freshness)
    ///
    /// # Returns
    ///
    /// * `VerificationResult` - Contains verification status and report
    pub fn verify(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let start_time = std::time::Instant::now();

        // Detect quote type
        let quote_type = self.detect_quote_type(quote)?;

        // Route to appropriate verifier
        let result = match quote_type {
            QuoteType::IntelSgxDcap => self.verify_sgx_dcap(quote, nonce)?,
            QuoteType::IntelSgxEpid => {
                return Err(AttestationError::InvalidFormat(
                    "Unsupported attestation quote format".to_string(),
                ));
            }
            QuoteType::IntelTdx => self.verify_tdx(quote, nonce)?,
            QuoteType::AmdSevSnp => self.verify_sev_snp(quote, nonce)?,
            QuoteType::AwsNitro => self.verify_nitro(quote, nonce)?,
            QuoteType::ArmCca => self.verify_arm_cca(quote, nonce)?,
            QuoteType::Unknown => {
                return Err(AttestationError::InvalidFormat(
                    "Unknown quote format".to_string(),
                ));
            }
        };

        // Record metrics
        self.metrics
            .record_verification(quote_type, result.verified, start_time.elapsed());

        Ok(result)
    }

    /// Verify with additional configuration options
    pub fn verify_with_options(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
        options: VerificationOptions,
    ) -> Result<VerificationResult, AttestationError> {
        let mut result = self.verify(quote, nonce)?;

        // Apply additional validations
        if let Some(ref report) = result.report {
            // Check expected measurements
            if let Some(ref expected) = options.expected_measurements {
                if !expected.is_empty() && !report.verify_measurement(expected) {
                    result.verified = false;
                    result.warnings.push(VerificationWarning {
                        code: "MEASUREMENT_MISMATCH".to_string(),
                        message: "Enclave measurement does not match expected values".to_string(),
                        severity: 5,
                    });
                }
            }

            // Check expected signers
            if let Some(ref expected) = options.expected_signers {
                if !expected.is_empty() && !report.verify_signer(expected) {
                    result.verified = false;
                    result.warnings.push(VerificationWarning {
                        code: "SIGNER_MISMATCH".to_string(),
                        message: "Enclave signer does not match expected values".to_string(),
                        severity: 5,
                    });
                }
            }

            // Check minimum security version
            if let Some(min_svn) = options.min_security_version {
                if report.security_version < min_svn {
                    result.verified = false;
                    result.warnings.push(VerificationWarning {
                        code: "SVN_TOO_LOW".to_string(),
                        message: format!(
                            "Security version {} is below minimum {}",
                            report.security_version, min_svn
                        ),
                        severity: 4,
                    });
                }
            }

            // Check production mode
            if options.require_production && report.flags.debug_mode {
                result.verified = false;
                result.warnings.push(VerificationWarning {
                    code: "DEBUG_MODE".to_string(),
                    message: "Enclave is in debug mode".to_string(),
                    severity: 5,
                });
            }
        }

        Ok(result)
    }

    /// Batch verify multiple quotes
    pub fn verify_batch(
        &self,
        quotes: &[(Vec<u8>, [u8; 32])],
    ) -> Vec<Result<VerificationResult, AttestationError>> {
        quotes
            .iter()
            .map(|(quote, nonce)| self.verify(quote, nonce))
            .collect()
    }

    // ========================================================================
    // Quote Type Detection
    // ========================================================================

    /// Detect the type of attestation quote
    fn detect_quote_type(&self, quote: &[u8]) -> Result<QuoteType, AttestationError> {
        if quote.len() < 4 {
            return Err(AttestationError::InvalidFormat(
                "Quote too short".to_string(),
            ));
        }

        // Intel SGX / TDX quote header parsing (version + attestation key type).
        // This is intentionally stricter than simple version-byte heuristics.
        if quote.len() >= 48 {
            let version = u16::from_le_bytes([quote[0], quote[1]]);
            let att_key_type = u16::from_le_bytes([quote[2], quote[3]]);

            // Intel SGX EPID (legacy)
            if (version == 2 || version == 3) && (att_key_type == 0 || att_key_type == 1) {
                return Ok(QuoteType::IntelSgxEpid);
            }

            // Intel SGX DCAP Quote v3 (ECDSA)
            if version == 3 && (att_key_type == 2 || att_key_type == 3) {
                return Ok(QuoteType::IntelSgxDcap);
            }

            // Intel TDX quote v4/v5 (ECDSA-based attestation key)
            if (version == 4 || version == 5) && (att_key_type == 2 || att_key_type == 3) {
                return Ok(QuoteType::IntelTdx);
            }
        }

        // AMD SEV-SNP attestation report
        if quote.len() >= 0x2A0 {
            let version = u32::from_le_bytes([quote[0], quote[1], quote[2], quote[3]]);
            if (1..=3).contains(&version) {
                return Ok(QuoteType::AmdSevSnp);
            }
        }

        // AWS Nitro uses COSE/CBOR format
        if quote.len() >= 16 {
            let looks_like_cose_sign1 = quote[0] == 0xD2 || quote[0] == 0x84;
            let has_nitro_markers = quote.windows(b"module_id".len()).any(|w| w == b"module_id")
                || quote.windows(b"pcrs".len()).any(|w| w == b"pcrs");
            if looks_like_cose_sign1 && has_nitro_markers {
                return Ok(QuoteType::AwsNitro);
            }
        }

        // ARM CCA Realm attestation
        if quote.len() >= 16 {
            // Check for CCA token magic
            if &quote[0..4] == b"CCA\x00" {
                return Ok(QuoteType::ArmCca);
            }
        }

        Ok(QuoteType::Unknown)
    }

    // ========================================================================
    // Platform-Specific Verifiers
    // ========================================================================

    /// Verify Intel SGX DCAP quote
    fn verify_sgx_dcap(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let verifier = self
            .sgx_verifier
            .as_ref()
            .ok_or_else(|| AttestationError::UnsupportedHardware(HardwareType::IntelSGX))?;

        // Fetch collateral
        let collateral = self.get_or_fetch_collateral(CollateralType::IntelSgx, quote)?;

        // Verify the quote
        verifier.verify(quote, nonce, &collateral)
    }

    /// Verify Intel TDX quote
    fn verify_tdx(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let verifier = self
            .sgx_verifier
            .as_ref()
            .ok_or_else(|| AttestationError::UnsupportedHardware(HardwareType::IntelTdx))?;

        // TDX uses similar verification path as SGX
        let collateral = self.get_or_fetch_collateral(CollateralType::IntelTdx, quote)?;

        verifier.verify_tdx(quote, nonce, &collateral)
    }

    /// Verify AMD SEV-SNP attestation
    fn verify_sev_snp(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let verifier = self
            .sev_verifier
            .as_ref()
            .ok_or_else(|| AttestationError::UnsupportedHardware(HardwareType::AmdSevSnp))?;

        // Fetch AMD KDS certificates
        let collateral = self.get_or_fetch_collateral(CollateralType::AmdSev, quote)?;

        verifier.verify(quote, nonce, &collateral)
    }

    /// Verify AWS Nitro attestation
    fn verify_nitro(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let verifier = self
            .nitro_verifier
            .as_ref()
            .ok_or_else(|| AttestationError::UnsupportedHardware(HardwareType::AwsNitro))?;

        // Nitro includes certificate chain in document
        verifier.verify(quote, nonce)
    }

    /// Verify ARM CCA attestation
    fn verify_arm_cca(
        &self,
        quote: &[u8],
        nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        let verifier = self
            .trustzone_verifier
            .as_ref()
            .ok_or_else(|| AttestationError::UnsupportedHardware(HardwareType::ArmCca))?;

        verifier.verify_cca(quote, nonce)
    }

    // ========================================================================
    // Collateral Management
    // ========================================================================

    /// Get collateral from cache or fetch from network
    fn get_or_fetch_collateral(
        &self,
        collateral_type: CollateralType,
        quote: &[u8],
    ) -> Result<AttestationCollateral, AttestationError> {
        // Try cache first
        {
            let cache = self.cache.read().unwrap();
            if let Some(collateral) = cache.get(&collateral_type, quote) {
                return Ok(collateral);
            }
        }

        // Fetch from network
        let collateral = self.fetch_collateral(collateral_type, quote)?;

        // Store in cache
        if self.config.enable_caching {
            let mut cache = self.cache.write().unwrap();
            cache.insert(collateral_type, quote, collateral.clone());
        }

        Ok(collateral)
    }

    /// Fetch collateral from remote service
    fn fetch_collateral(
        &self,
        collateral_type: CollateralType,
        quote: &[u8],
    ) -> Result<AttestationCollateral, AttestationError> {
        match collateral_type {
            CollateralType::IntelSgx | CollateralType::IntelTdx => {
                self.fetch_intel_collateral(quote)
            }
            CollateralType::AmdSev => self.fetch_amd_collateral(quote),
            CollateralType::Nitro => {
                // Nitro includes certificates in the document
                Ok(AttestationCollateral::Nitro(NitroCollateral {
                    root_certificate: Vec::new(), // Embedded in AWS SDK
                }))
            }
            CollateralType::ArmCca => self.fetch_arm_collateral(quote),
        }
    }

    /// Fetch Intel PCCS collateral
    fn fetch_intel_collateral(
        &self,
        quote: &[u8],
    ) -> Result<AttestationCollateral, AttestationError> {
        let _pccs_url =
            self.config.intel_pccs_url.as_ref().ok_or_else(|| {
                AttestationError::NetworkError("PCCS URL not configured".to_string())
            })?;

        // Extract FMSPC from quote
        let fmspc = Self::extract_fmspc(quote)?;

        // In production, this would make HTTP requests to PCCS
        // For now, return a placeholder
        Ok(AttestationCollateral::Intel(IntelCollateral {
            pck_certificate: Vec::new(),
            pck_cert_chain: Vec::new(),
            tcb_info: Vec::new(),
            tcb_info_signature: Vec::new(),
            qe_identity: Vec::new(),
            qe_identity_signature: Vec::new(),
            root_ca_crl: Vec::new(),
            pck_crl: Vec::new(),
            fmspc: fmspc.to_vec(),
        }))
    }

    /// Fetch AMD KDS collateral
    fn fetch_amd_collateral(
        &self,
        _quote: &[u8],
    ) -> Result<AttestationCollateral, AttestationError> {
        let _kds_url = self.config.amd_kds_url.as_ref().ok_or_else(|| {
            AttestationError::NetworkError("AMD KDS URL not configured".to_string())
        })?;

        // In production, this would fetch from AMD KDS
        Ok(AttestationCollateral::Amd(AmdCollateral {
            vcek_certificate: Vec::new(),
            vcek_cert_chain: Vec::new(),
            crl: Vec::new(),
        }))
    }

    /// Fetch ARM CCA collateral
    fn fetch_arm_collateral(
        &self,
        _quote: &[u8],
    ) -> Result<AttestationCollateral, AttestationError> {
        // ARM CCA verification is more platform-specific
        Ok(AttestationCollateral::Arm(ArmCollateral {
            platform_token: Vec::new(),
            realm_token: Vec::new(),
        }))
    }

    /// Extract FMSPC from SGX quote
    fn extract_fmspc(quote: &[u8]) -> Result<[u8; 6], AttestationError> {
        // FMSPC is in the certification data of the quote
        // Location depends on quote version
        if quote.len() < 432 {
            return Err(AttestationError::InvalidFormat(
                "Quote too short to contain FMSPC".to_string(),
            ));
        }

        // Simplified extraction - in production would parse full quote structure
        let mut fmspc = [0u8; 6];
        fmspc.copy_from_slice(&quote[426..432]);
        Ok(fmspc)
    }

    // ========================================================================
    // Geo-Location
    // ========================================================================

    /// Resolve geographic location for an attestation
    pub fn resolve_geo(&self, report: &EnclaveReport) -> Option<GeoBinding> {
        self.geo_resolver.as_ref()?.resolve(report)
    }

    /// Verify attestation is from expected jurisdiction
    pub fn verify_jurisdiction(
        &self,
        report: &EnclaveReport,
        expected: &Jurisdiction,
    ) -> Result<bool, AttestationError> {
        let geo = self.resolve_geo(report).ok_or_else(|| {
            AttestationError::NetworkError("Could not resolve geo-location".to_string())
        })?;

        Ok(&geo.jurisdiction == expected)
    }

    // ========================================================================
    // Metrics
    // ========================================================================

    /// Get attestation metrics
    pub fn metrics(&self) -> &AttestationMetrics {
        &self.metrics
    }

    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = AttestationMetrics::new();
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Quote type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuoteType {
    /// Intel SGX DCAP ECDSA quote.
    IntelSgxDcap,
    /// Legacy Intel SGX EPID quote (unsupported for production verification).
    IntelSgxEpid,
    /// Intel TDX quote.
    IntelTdx,
    /// AMD SEV-SNP attestation report/quote.
    AmdSevSnp,
    /// AWS Nitro Enclaves COSE/CBOR attestation document.
    AwsNitro,
    /// ARM CCA / TrustZone token.
    ArmCca,
    /// Unrecognized or ambiguous quote format.
    Unknown,
}

/// Verification options
#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Expected MRENCLAVE values
    pub expected_measurements: Option<Vec<[u8; 32]>>,
    /// Expected MRSIGNER values
    pub expected_signers: Option<Vec<[u8; 32]>>,
    /// Minimum security version
    pub min_security_version: Option<u16>,
    /// Require production mode
    pub require_production: bool,
}

/// Collateral type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CollateralType {
    /// Collateral required for Intel SGX DCAP quotes.
    IntelSgx,
    /// Collateral required for Intel TDX quotes.
    IntelTdx,
    /// Collateral required for AMD SEV-SNP quotes.
    AmdSev,
    /// Collateral required for AWS Nitro attestation.
    Nitro,
    /// Collateral required for ARM CCA attestation.
    ArmCca,
}

/// Attestation collateral
#[derive(Debug, Clone)]
pub enum AttestationCollateral {
    /// Intel PCCS/DCAP collateral bundle.
    Intel(IntelCollateral),
    /// AMD KDS/VCEK collateral bundle.
    Amd(AmdCollateral),
    /// AWS Nitro root trust material.
    Nitro(NitroCollateral),
    /// ARM platform and realm collateral.
    Arm(ArmCollateral),
}

/// Intel attestation collateral
#[derive(Debug, Clone)]
pub struct IntelCollateral {
    /// PCK certificate bytes.
    pub pck_certificate: Vec<u8>,
    /// PCK certificate chain bytes.
    pub pck_cert_chain: Vec<u8>,
    /// TCB info JSON/blob.
    pub tcb_info: Vec<u8>,
    /// Signature over the TCB info payload.
    pub tcb_info_signature: Vec<u8>,
    /// QE identity JSON/blob.
    pub qe_identity: Vec<u8>,
    /// Signature over the QE identity payload.
    pub qe_identity_signature: Vec<u8>,
    /// Intel root CA CRL bytes.
    pub root_ca_crl: Vec<u8>,
    /// PCK CRL bytes.
    pub pck_crl: Vec<u8>,
    /// FMSPC identifier bytes used for collateral lookup.
    pub fmspc: Vec<u8>,
}

/// AMD attestation collateral
#[derive(Debug, Clone)]
pub struct AmdCollateral {
    /// VCEK certificate bytes.
    pub vcek_certificate: Vec<u8>,
    /// VCEK certificate chain bytes.
    pub vcek_cert_chain: Vec<u8>,
    /// AMD revocation list / CRL bytes.
    pub crl: Vec<u8>,
}

/// AWS Nitro collateral
#[derive(Debug, Clone)]
pub struct NitroCollateral {
    /// AWS Nitro root certificate bytes.
    pub root_certificate: Vec<u8>,
}

/// ARM attestation collateral
#[derive(Debug, Clone)]
pub struct ArmCollateral {
    /// Platform attestation token bytes.
    pub platform_token: Vec<u8>,
    /// Realm attestation token bytes.
    pub realm_token: Vec<u8>,
}

// ============================================================================
// Collateral Cache
// ============================================================================

/// Cache for attestation collateral
struct CollateralCache {
    entries: HashMap<CollateralCacheKey, CachedCollateral>,
    ttl: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CollateralCacheKey {
    collateral_type: CollateralType,
    identifier: Vec<u8>,
}

struct CachedCollateral {
    collateral: AttestationCollateral,
    fetched_at: SystemTime,
}

impl CollateralCache {
    fn new(ttl: Duration) -> Self {
        CollateralCache {
            entries: HashMap::new(),
            ttl,
        }
    }

    fn get(&self, collateral_type: &CollateralType, quote: &[u8]) -> Option<AttestationCollateral> {
        let key = CollateralCacheKey {
            collateral_type: *collateral_type,
            identifier: Self::extract_identifier(quote),
        };

        let entry = self.entries.get(&key)?;

        // Check if expired
        let elapsed = SystemTime::now()
            .duration_since(entry.fetched_at)
            .unwrap_or(Duration::MAX);

        if elapsed > self.ttl {
            return None;
        }

        Some(entry.collateral.clone())
    }

    fn insert(
        &mut self,
        collateral_type: CollateralType,
        quote: &[u8],
        collateral: AttestationCollateral,
    ) {
        let key = CollateralCacheKey {
            collateral_type,
            identifier: Self::extract_identifier(quote),
        };

        self.entries.insert(
            key,
            CachedCollateral {
                collateral,
                fetched_at: SystemTime::now(),
            },
        );
    }

    fn extract_identifier(quote: &[u8]) -> Vec<u8> {
        // Use first 64 bytes as identifier (contains FMSPC, etc.)
        if quote.len() >= 64 {
            quote[..64].to_vec()
        } else {
            quote.to_vec()
        }
    }
}

// ============================================================================
// Geo Resolver
// ============================================================================

/// Geographic location resolver
pub struct GeoResolver {
    // In production, would include geo-IP database, cloud provider APIs
}

impl GeoResolver {
    fn new() -> Self {
        GeoResolver {}
    }

    fn resolve(&self, _report: &EnclaveReport) -> Option<GeoBinding> {
        // In production, would:
        // 1. Check cloud provider attestation for region
        // 2. Verify IP geolocation
        // 3. Cross-reference with known datacenter IDs

        // Placeholder
        Some(GeoBinding {
            jurisdiction: Jurisdiction::Global,
            datacenter_id: "unknown".to_string(),
            provider: "unknown".to_string(),
            country_code: "XX".to_string(),
            region: "unknown".to_string(),
            verification_method: GeoVerificationMethod::ManualConfiguration,
        })
    }
}

// ============================================================================
// Metrics
// ============================================================================

/// Attestation metrics
#[derive(Debug, Clone)]
pub struct AttestationMetrics {
    /// Total verification attempts across all quote types.
    pub total_verifications: u64,
    /// Number of successful verifications.
    pub successful_verifications: u64,
    /// Number of failed verifications.
    pub failed_verifications: u64,
    /// Per-quote-type verification counters.
    pub verifications_by_type: HashMap<QuoteType, u64>,
    /// Rolling average verification latency in milliseconds.
    pub average_verification_time_ms: f64,
    /// Collateral cache hit count.
    pub cache_hits: u64,
    /// Collateral cache miss count.
    pub cache_misses: u64,
}

impl AttestationMetrics {
    fn new() -> Self {
        AttestationMetrics {
            total_verifications: 0,
            successful_verifications: 0,
            failed_verifications: 0,
            verifications_by_type: HashMap::new(),
            average_verification_time_ms: 0.0,
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    fn record_verification(&self, _quote_type: QuoteType, _success: bool, _duration: Duration) {
        // In production, would update metrics atomically
    }
}

// ============================================================================
// Platform Verifiers (Stubs - Full implementation in separate files)
// ============================================================================

/// Intel SGX DCAP verifier
pub struct IntelSgxVerifier {
    _config: AttestationConfig,
}

impl IntelSgxVerifier {
    /// Create a stub SGX verifier wrapper (full implementation is in `intel_sgx.rs`).
    pub fn new(config: &AttestationConfig) -> Self {
        IntelSgxVerifier {
            _config: config.clone(),
        }
    }

    /// Verify an Intel SGX DCAP quote.
    ///
    /// This stub returns `Not implemented` in the lightweight engine path.
    pub fn verify(
        &self,
        _quote: &[u8],
        _nonce: &[u8; 32],
        _collateral: &AttestationCollateral,
    ) -> Result<VerificationResult, AttestationError> {
        // Full implementation in intel_sgx.rs
        Err(AttestationError::IntelDcap("Not implemented".to_string()))
    }

    /// Verify an Intel TDX quote.
    ///
    /// This stub returns `Not implemented` in the lightweight engine path.
    pub fn verify_tdx(
        &self,
        _quote: &[u8],
        _nonce: &[u8; 32],
        _collateral: &AttestationCollateral,
    ) -> Result<VerificationResult, AttestationError> {
        Err(AttestationError::IntelDcap(
            "TDX not implemented".to_string(),
        ))
    }
}

/// AMD SEV-SNP verifier
pub struct AmdSevVerifier {
    _config: AttestationConfig,
}

impl AmdSevVerifier {
    /// Create a stub AMD SEV-SNP verifier wrapper (full implementation is in `amd_sev.rs`).
    pub fn new(config: &AttestationConfig) -> Self {
        AmdSevVerifier {
            _config: config.clone(),
        }
    }

    /// Verify an AMD SEV-SNP attestation quote/report.
    ///
    /// This stub returns `Not implemented` in the lightweight engine path.
    pub fn verify(
        &self,
        _quote: &[u8],
        _nonce: &[u8; 32],
        _collateral: &AttestationCollateral,
    ) -> Result<VerificationResult, AttestationError> {
        Err(AttestationError::AmdSev("Not implemented".to_string()))
    }
}

/// AWS Nitro verifier
pub struct AwsNitroVerifier {
    _config: AttestationConfig,
}

impl AwsNitroVerifier {
    /// Create a stub AWS Nitro verifier wrapper (full implementation is in `aws_nitro.rs`).
    pub fn new(config: &AttestationConfig) -> Self {
        AwsNitroVerifier {
            _config: config.clone(),
        }
    }

    /// Verify an AWS Nitro COSE/CBOR attestation document.
    ///
    /// This stub returns `Not implemented` in the lightweight engine path.
    pub fn verify(
        &self,
        _document: &[u8],
        _nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        Err(AttestationError::AwsNitro("Not implemented".to_string()))
    }
}

/// ARM TrustZone verifier
pub struct ArmTrustZoneVerifier {
    _config: AttestationConfig,
}

impl ArmTrustZoneVerifier {
    /// Create a stub ARM CCA verifier wrapper.
    pub fn new(config: &AttestationConfig) -> Self {
        ArmTrustZoneVerifier {
            _config: config.clone(),
        }
    }

    /// Verify an ARM CCA realm/platform token pair.
    ///
    /// This stub returns `Not implemented` in the lightweight engine path.
    pub fn verify_cca(
        &self,
        _token: &[u8],
        _nonce: &[u8; 32],
    ) -> Result<VerificationResult, AttestationError> {
        Err(AttestationError::ArmTrustZone(
            "Not implemented".to_string(),
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = AttestationEngine::default();
        assert!(engine.sgx_verifier.is_some());
        assert!(engine.sev_verifier.is_some());
        assert!(engine.nitro_verifier.is_some());
    }

    #[test]
    fn test_quote_type_detection() {
        let engine = AttestationEngine::default();

        // Empty quote
        assert!(engine.detect_quote_type(&[]).is_err());

        // Short quote
        assert_eq!(
            engine.detect_quote_type(&[0, 0, 0, 0]).unwrap(),
            QuoteType::Unknown
        );
    }

    #[test]
    fn test_quote_type_detection_uses_intel_header_fields() {
        let engine = AttestationEngine::default();

        let mut sgx_dcap = vec![0u8; 64];
        sgx_dcap[0..2].copy_from_slice(&3u16.to_le_bytes());
        sgx_dcap[2..4].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            engine.detect_quote_type(&sgx_dcap).unwrap(),
            QuoteType::IntelSgxDcap
        );

        let mut sgx_epid = vec![0u8; 64];
        sgx_epid[0..2].copy_from_slice(&3u16.to_le_bytes());
        sgx_epid[2..4].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            engine.detect_quote_type(&sgx_epid).unwrap(),
            QuoteType::IntelSgxEpid
        );

        let mut tdx = vec![0u8; 64];
        tdx[0..2].copy_from_slice(&4u16.to_le_bytes());
        tdx[2..4].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(engine.detect_quote_type(&tdx).unwrap(), QuoteType::IntelTdx);
    }

    #[test]
    fn test_nitro_detection_requires_cose_and_nitro_markers() {
        let engine = AttestationEngine::default();

        let mut marker_only = vec![0u8; 32];
        marker_only[0] = 0x01; // not COSE Sign1/array marker
        marker_only[8..8 + "module_id".len()].copy_from_slice(b"module_id");
        assert_eq!(
            engine.detect_quote_type(&marker_only).unwrap(),
            QuoteType::Unknown
        );

        let mut cose_only = vec![0u8; 32];
        cose_only[0] = 0xD2; // COSE tag marker
        assert_eq!(
            engine.detect_quote_type(&cose_only).unwrap(),
            QuoteType::Unknown
        );

        let mut nitro = vec![0u8; 32];
        nitro[0] = 0xD2;
        nitro[8..8 + "module_id".len()].copy_from_slice(b"module_id");
        assert_eq!(
            engine.detect_quote_type(&nitro).unwrap(),
            QuoteType::AwsNitro
        );
    }

    #[test]
    fn test_epid_quotes_return_generic_unsupported_format_error() {
        let engine = AttestationEngine::default();
        let mut epid = vec![0u8; 64];
        epid[0..2].copy_from_slice(&3u16.to_le_bytes());
        epid[2..4].copy_from_slice(&1u16.to_le_bytes()); // SGX EPID

        let err = engine.verify(&epid, &[0u8; 32]).unwrap_err();
        let rendered = err.to_string();

        assert!(
            rendered.contains("Unsupported attestation quote format"),
            "unexpected error message: {rendered}"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("epid"),
            "error leaked EPID-specific detail: {rendered}"
        );
    }

    #[test]
    fn test_verification_options() {
        let options = VerificationOptions {
            expected_measurements: Some(vec![[1u8; 32]]),
            expected_signers: Some(vec![[2u8; 32]]),
            min_security_version: Some(10),
            require_production: true,
        };

        assert!(options.expected_measurements.is_some());
        assert!(options.require_production);
    }

    #[test]
    fn test_collateral_cache() {
        let mut cache = CollateralCache::new(Duration::from_secs(3600));

        let collateral = AttestationCollateral::Nitro(NitroCollateral {
            root_certificate: vec![1, 2, 3],
        });

        cache.insert(CollateralType::Nitro, &[1, 2, 3, 4], collateral.clone());

        let retrieved = cache.get(&CollateralType::Nitro, &[1, 2, 3, 4]);
        assert!(retrieved.is_some());
    }
}
